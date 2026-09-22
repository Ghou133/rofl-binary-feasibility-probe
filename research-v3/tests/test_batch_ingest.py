import sys
import tempfile
import unittest
import hashlib
import json
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import batch_ingest  # noqa: E402
from core import ReplayStore  # noqa: E402


class BatchIngestTests(unittest.TestCase):
    @staticmethod
    def _write_json(path, value):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def _protection_run_side_effect(
        self, replays, *, on_event_count=1, shield_damage_count=0,
        shield_scan_replay_count=None,
    ):
        replay_count = len(replays)

        def selected_rows(total):
            return [total if index == 0 else 0 for index in range(replay_count)]

        def run(command, *, cwd, log_path):
            script = Path(command[1]).name
            if script == "export_selected_packets.js":
                output = Path(command[command.index("--output") + 1])
                packet_id = int(command[command.index("--packet-id") + 1])
                total = on_event_count if packet_id == 158 else shield_damage_count
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text("{}\n" * total, encoding="utf-8")
                counts = selected_rows(total)
                self._write_json(Path(f"{output}.manifest.json"), {
                    "packet_ids": [packet_id],
                    "selected_packet_count": total,
                    "replay_count": replay_count,
                    "replays": [
                        {
                            "sha256": replay["sha256"],
                            "selected_packet_count": count,
                            "parser_error_count": 0,
                        }
                        for replay, count in zip(replays, counts)
                    ],
                })
                return
            output = Path(command[command.index("--output") + 1])
            summary = Path(command[command.index("--summary") + 1])
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("", encoding="utf-8")
            if script == "decode_on_event_protection_v4.py":
                self._write_json(summary, {
                    "input_event_count": on_event_count,
                    "deserialize_success_count": on_event_count,
                    "fully_consumed_count": on_event_count,
                    "output_event_count": on_event_count,
                })
                return
            if script == "decode_shield_damage_v4.py":
                self._write_json(summary, {
                    "input_event_count": shield_damage_count,
                    "scan_replay_count": (
                        replay_count if shield_scan_replay_count is None
                        else shield_scan_replay_count
                    ),
                    "scan_selected_packet_count": shield_damage_count,
                    "scan_parser_error_count": 0,
                    "scan_replays": [
                        {"replay_sha256": replay["sha256"]}
                        for replay in replays
                    ],
                    "deserialize_success_count": shield_damage_count,
                    "fully_consumed_count": shield_damage_count,
                    "network_fields_agree_count": shield_damage_count,
                    "target_matches_raw_param_count": shield_damage_count,
                })
                return
            self.fail(f"unexpected command: {command}")

        return run

    def test_discovery_hash_and_inventory_are_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replay = root / "HN1-123.rofl"
            replay.write_bytes(b"replay")
            (root / "ignore.txt").write_text("x", encoding="utf-8")
            self.assertEqual(batch_ingest.discover_replays(root), [replay])
            rows = batch_ingest.inventory_replays(
                [replay], version_reader=lambda _path: "16.15.801.3452"
            )
            self.assertEqual(rows[0]["game_id"], "123")
            self.assertEqual(rows[0]["sha256"], batch_ingest.sha256_file(replay))

    def test_unsupported_patch_is_recorded_without_decode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            canonical_manifest = root / "canonical_manifest.json"
            self._write_json(canonical_manifest, {"replays": []})
            replay = root / "HN1-999.rofl"
            replay.write_bytes(b"unsupported")
            db = root / "research.duckdb"
            fake_inventory = [{
                "path": str(replay), "sha256": "f" * 64,
                "patch": "99.1.0", "game_id": "999",
            }]
            with mock.patch.object(batch_ingest, "inventory_replays", return_value=fake_inventory):
                result = batch_ingest.ingest_replay_directory(
                    root, db_path=db, canonical_manifest=canonical_manifest,
                    output_root=root / "batch"
                )
            self.assertEqual(result["status"], "COMPLETED_WITH_REJECTIONS")
            store = ReplayStore(db)
            with store.connect() as con:
                reason = con.execute("SELECT reason FROM ingest_rejections").fetchone()[0]
            self.assertEqual(reason, "UNSUPPORTED_REPLAY_VERSION")

    def test_same_sha_in_one_batch_is_ingested_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            canonical_manifest = root / "canonical_manifest.json"
            self._write_json(canonical_manifest, {"replays": []})
            first = root / "HN1-100.rofl"
            second = root / "HN1-101.rofl"
            first.write_bytes(b"same replay")
            second.write_bytes(b"same replay")
            db = root / "research.duckdb"
            duplicate_sha = "a" * 64
            fake_inventory = [
                {"path": str(first), "sha256": duplicate_sha,
                 "patch": "99.1.0", "game_id": "100"},
                {"path": str(second), "sha256": duplicate_sha,
                 "patch": "99.1.0", "game_id": "101"},
            ]
            with mock.patch.object(batch_ingest, "inventory_replays", return_value=fake_inventory):
                result = batch_ingest.ingest_replay_directory(
                    root, db_path=db, canonical_manifest=canonical_manifest,
                    output_root=root / "batch"
                )
            self.assertEqual(result["discovered"], 2)
            self.assertEqual(result["unique_by_sha"], 1)
            self.assertEqual(result["duplicate_in_batch"], 1)
            self.assertEqual(result["unsupported"], 1)
            store = ReplayStore(db)
            with store.connect() as con:
                self.assertEqual(con.execute("SELECT count(*) FROM ingest_rejections").fetchone()[0], 1)

    def test_existing_only_batch_skips_publish_and_database_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replay = root / "HN1-100.rofl"
            replay.write_bytes(b"already ingested")
            db = root / "research.duckdb"
            replay_sha = "a" * 64
            ReplayStore(db).init()
            with ReplayStore(db).connect() as con:
                con.execute(
                    "INSERT INTO replays (game_id, replay_sha256, patch, replay_label, status) "
                    "VALUES ('100', ?, '16.15.801.3452', 'HN1-100', 'VERIFIED')",
                    [replay_sha],
                )
                con.execute("CHECKPOINT")
            before = hashlib.sha256(db.read_bytes()).hexdigest()
            fake_inventory = [{
                "path": str(replay), "sha256": replay_sha,
                "patch": "16.15.801.3452", "game_id": "100",
            }]
            with mock.patch.object(batch_ingest, "inventory_replays", return_value=fake_inventory), \
                    mock.patch.object(batch_ingest, "publish_all") as publish:
                result = batch_ingest.ingest_replay_directory(root, db_path=db, output_root=root / "batch")
            self.assertFalse(publish.called)
            self.assertEqual(result["discovered"], 1)
            self.assertEqual(result["unique_by_sha"], 1)
            self.assertEqual(result["duplicate_in_batch"], 0)
            self.assertEqual(result["already_ingested"], 1)
            self.assertEqual(result["publication"]["status"], "UNCHANGED_EXISTING_PUBLICATION")
            self.assertEqual(hashlib.sha256(db.read_bytes()).hexdigest(), before)

    def test_protection_v4_runs_both_decoders_and_accepts_zero_row_0017(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replay = root / "HN1-100.rofl"
            replay.write_bytes(b"replay")
            replay_row = {
                "path": str(replay), "sha256": "a" * 64,
                "patch": "16.15.801.3452", "game_id": "100",
            }
            with mock.patch.object(batch_ingest, "runtime_preflight"), \
                    mock.patch.object(batch_ingest.uuid, "uuid4", return_value="fixed"), \
                    mock.patch.object(
                        batch_ingest, "_run",
                        side_effect=self._protection_run_side_effect(
                            [replay_row], on_event_count=1, shield_damage_count=0,
                        ),
                    ) as run, \
                    mock.patch.object(
                        batch_ingest, "_run_json",
                        return_value={
                            "mode": "SELECTED_REPLAYS_SHARED_DECODER_ATTESTATION",
                            "backfilled_replay_count": 1,
                            "results": [{
                                "replay_sha256": replay_row["sha256"],
                                "profile_status": "DECODED",
                            }],
                        },
                    ) as run_json:
                result = batch_ingest._decode_protection_v4(
                    [replay_row], root / "batch", root / "unused.duckdb"
                )

            self.assertEqual(result["status"], "PROTECTION_V4_COMPLETE")
            self.assertEqual(result["decoder_statuses"], {
                "on_event": "DECODED", "shield_damage": "NO_PROTECTION_EVENT",
            })
            self.assertNotEqual(
                result["decoders"]["on_event"]["raw_packets"],
                result["decoders"]["shield_damage"]["raw_packets"],
            )
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(len(commands), 4)
            export_ids = [
                command[command.index("--packet-id") + 1]
                for command in commands
                if Path(command[1]).name == "export_selected_packets.js"
            ]
            self.assertEqual(export_ids, ["158", "23"])
            self.assertEqual(
                [Path(command[1]).name for command in commands[2:]],
                ["decode_on_event_protection_v4.py", "decode_shield_damage_v4.py"],
            )
            backfill_command = run_json.call_args.args[0]
            self.assertIn("--replay-sha256", backfill_command)
            self.assertNotIn("--all-database-replays", backfill_command)
            self.assertEqual(backfill_command.count("--decoded-jsonl"), 2)
            self.assertEqual(
                result["backfill"]["mode"],
                "SELECTED_REPLAYS_SHARED_DECODER_ATTESTATION",
            )

    def test_protection_v4_backfills_every_new_replay_with_both_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replays = [
                {
                    "path": str(root / f"HN1-{index}.rofl"),
                    "sha256": str(index) * 64,
                    "patch": "16.15.801.3452",
                    "game_id": str(index),
                }
                for index in (1, 2)
            ]
            with mock.patch.object(batch_ingest, "runtime_preflight"), \
                    mock.patch.object(batch_ingest.uuid, "uuid4", return_value="fixed"), \
                    mock.patch.object(
                        batch_ingest, "_run",
                        side_effect=self._protection_run_side_effect(
                            replays, on_event_count=0, shield_damage_count=0,
                        ),
                    ), \
                    mock.patch.object(
                        batch_ingest, "_run_json",
                        return_value={
                            "mode": "SELECTED_REPLAYS_SHARED_DECODER_ATTESTATION",
                            "backfilled_replay_count": 2,
                            "results": [
                            {"replay_sha256": replay["sha256"],
                             "profile_status": "NO_PROTECTION_EVENT"}
                            for replay in replays
                            ],
                        },
                    ) as run_json:
                result = batch_ingest._decode_protection_v4(
                    replays, root / "batch", root / "unused.duckdb"
                )

            self.assertEqual(result["status"], "PROTECTION_V4_COMPLETE")
            self.assertEqual(result["decoder_statuses"], {
                "on_event": "NO_PROTECTION_EVENT",
                "shield_damage": "NO_PROTECTION_EVENT",
            })
            self.assertEqual(result["backfill"]["backfilled_replay_count"], 2)
            self.assertEqual(run_json.call_count, 1)
            command = run_json.call_args.args[0]
            self.assertEqual(command.count("--replay-sha256"), 2)
            self.assertEqual(command.count("--decoded-jsonl"), 2)
            self.assertEqual(
                [command[index + 1] for index, value in enumerate(command)
                 if value == "--replay-sha256"],
                [replay["sha256"] for replay in replays],
            )

    def test_protection_v4_does_not_complete_when_combined_backfill_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replay = {
                "path": str(root / "HN1-100.rofl"), "sha256": "a" * 64,
                "patch": "16.15.801.3452", "game_id": "100",
            }
            with mock.patch.object(batch_ingest, "runtime_preflight"), \
                    mock.patch.object(batch_ingest.uuid, "uuid4", return_value="fixed"), \
                    mock.patch.object(
                        batch_ingest, "_run",
                        side_effect=self._protection_run_side_effect([replay]),
                    ), \
                    mock.patch.object(
                        batch_ingest, "_run_json",
                        return_value={
                            "mode": "SELECTED_REPLAYS_SHARED_DECODER_ATTESTATION",
                            "backfilled_replay_count": 1,
                            "results": [{
                                "replay_sha256": replay["sha256"],
                                "profile_status": "DECODER_UNAVAILABLE",
                            }],
                        },
                    ):
                with self.assertRaisesRegex(RuntimeError, "did not complete"):
                    batch_ingest._decode_protection_v4(
                        [replay], root / "batch", root / "unused.duckdb"
                    )

    def test_protection_v4_requires_complete_0017_scan_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replay = {
                "path": str(root / "HN1-100.rofl"), "sha256": "a" * 64,
                "patch": "16.15.801.3452", "game_id": "100",
            }
            with mock.patch.object(batch_ingest, "runtime_preflight"), \
                    mock.patch.object(batch_ingest.uuid, "uuid4", return_value="fixed"), \
                    mock.patch.object(
                        batch_ingest, "_run",
                        side_effect=self._protection_run_side_effect(
                            [replay], shield_scan_replay_count=0,
                        ),
                    ), \
                    mock.patch.object(batch_ingest, "_run_json") as run_json:
                with self.assertRaisesRegex(RuntimeError, "does not cover every replay"):
                    batch_ingest._decode_protection_v4(
                        [replay], root / "batch", root / "unused.duckdb"
                    )
            run_json.assert_not_called()


if __name__ == "__main__":
    unittest.main()
