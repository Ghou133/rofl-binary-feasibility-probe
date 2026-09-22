import csv
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

import duckdb


V4_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = V4_ROOT.parent
sys.path.insert(0, str(V4_ROOT))

from build_support_manual_review_queue import (  # noqa: E402
    build_dataset,
    champion_slug,
    format_replay_time,
)


SHA = "a" * 64
OTHER_SHA = "b" * 64
OLD_SHA = "c" * 64
UNRESOLVED_SHA = "d" * 64
MISSING_SHA = "e" * 64
PATCH = "16.15.801.3452"


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class SupportManualReviewQueueTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.db = self.root / "fixture.duckdb"
        self.metadata_root = self.root / "artifacts"
        self.replay_root = self.root / "replay"
        self.output = self.root / "output"
        self.metadata_root.mkdir()
        self.replay_root.mkdir()
        self.replay_path = self.replay_root / "fixture.rofl"
        self.replay_path.write_bytes(b"fixture replay")
        self._make_database()
        self._make_artifact_candidates()

    def tearDown(self):
        self.temporary.cleanup()

    def _make_database(self):
        with duckdb.connect(str(self.db)) as connection:
            connection.execute(
                (PROJECT_ROOT / "research-v3" / "schema.sql").read_text(
                    encoding="utf-8"
                )
            )
            connection.execute(
                (V4_ROOT / "schema.sql").read_text(encoding="utf-8")
            )
            connection.execute(
                """INSERT INTO replays
                   (game_id,replay_sha256,patch,replay_path,duration_ms,status)
                   VALUES ('game-a',?,?,?,?, 'RESEARCH_READY_COMPLETE')""",
                [SHA, PATCH, str(self.replay_path), 90000],
            )
            support_raw = json.dumps({
                "role_status": "VERIFIED_FROM_METADATA",
                "aggregate_stats": {"deaths": 1},
            })
            adc_raw = json.dumps({
                "role_status": "VERIFIED_FROM_METADATA",
                "aggregate_stats": {"deaths": 2},
            })
            enemy_raw = json.dumps({"role_status": "VERIFIED_FROM_METADATA"})
            participants = [
                ("support", 1, 101, "Milio", 100, "blue", "support", support_raw),
                ("adc", 2, 102, "Ashe", 100, "blue", "adc", adc_raw),
                ("enemy", 3, 103, "Zed", 200, "red", "mid", enemy_raw),
            ]
            for fact_id, pid, nid, champion, team_id, team, role, raw in participants:
                connection.execute(
                    """INSERT INTO participants
                       (fact_id,game_id,replay_sha256,patch,participant_id,
                        network_id,champion,team_id,team,role,confidence,status,
                        raw_provenance_json)
                       VALUES (?,'game-a',?,?,?,?,?,?,?,?,
                               'VERIFIED','VERIFIED_FROM_METADATA',?)""",
                    [fact_id, SHA, PATCH, pid, nid, champion, team_id, team, role, raw],
                )
            deaths = [
                ("death-1", 30000, 20000, "Zed"),
                ("death-2", 70000, 65000, "Zed"),
            ]
            for fact_id, death_time, combat_start, killer in deaths:
                connection.execute(
                    """INSERT INTO adc_deaths
                       (fact_id,game_id,replay_sha256,patch,adc,adc_participant_id,
                        support,support_participant_id,death_time_ms,
                        combat_start_ms,combat_duration_ms,killer,confidence,status)
                       VALUES (?,'game-a',?,?,'Ashe',2,'Milio',1,?,?,?, ?,
                               'VERIFIED','VERIFIED')""",
                    [
                        fact_id, SHA, PATCH, death_time, combat_start,
                        death_time - combat_start, killer,
                    ],
                )
                connection.execute(
                    """INSERT INTO death_events
                       (fact_id,game_id,replay_sha256,patch,replay_time_ms,
                        source_participant_id,target_participant_id,
                        source_champion,target_champion)
                       VALUES (?,'game-a',?,?,?,?,2,?,'Ashe')""",
                    [f"event-{fact_id}", SHA, PATCH, death_time, 3, killer],
                )
            damage = [
                ("damage-1", 25000, 40.0, "physical", True, "Zed"),
                ("damage-2", 26000, 50.0, "magic", None, "Lux"),
                ("damage-3", 29000, 20.0, "true", None, "Zed"),
                ("damage-4", 69000, 30.0, "physical", True, "Zed"),
            ]
            for fact_id, time_ms, amount, damage_type, basic, champion in damage:
                connection.execute(
                    """INSERT INTO damage_events
                       (fact_id,game_id,replay_sha256,patch,replay_time_ms,
                        source_participant_id,target_participant_id,
                        source_champion,target_champion,amount,damage_type,
                        is_basic_attack)
                       VALUES (?,'game-a',?,?,?,?,2,?,'Ashe',?,?,?)""",
                    [
                        fact_id, SHA, PATCH, time_ms, 3, champion,
                        amount, damage_type, basic,
                    ],
                )
            contributors = [
                ("contributor-1", "death-1", "Zed", 60.0),
                ("contributor-2", "death-1", "Lux", 50.0),
                ("contributor-3", "death-2", "Zed", 30.0),
            ]
            for fact_id, death_id, champion, amount in contributors:
                connection.execute(
                    """INSERT INTO adc_death_damage
                       (fact_id,game_id,replay_sha256,patch,adc_death_id,
                        attacker_champion,damage_amount)
                       VALUES (?,'game-a',?,?,?,?,?)""",
                    [fact_id, SHA, PATCH, death_id, champion, amount],
                )
            connection.execute(
                """INSERT INTO protection_v4_profiles
                   (replay_sha256,game_id,patch,profile_status,
                    on_event_decoder_status,shield_damage_decoder_status)
                   VALUES (?,'game-a',?,'DECODED','DECODED','DECODED')""",
                [SHA, PATCH],
            )
            protection_rows = [
                ("shield", SHA, 20000, "SHIELD_GENERATED", 101, 102, 50.0, True, None),
                ("shield-duplicate", SHA, 20000, "SHIELD_GENERATED", 101, 102, 50.0, False, None),
                ("heal", SHA, 29000, "HEAL_REPORTED", 101, 102, 20.0, True, 2),
                ("absorbed", SHA, 29500, "SHIELD_ABSORBED", None, 102, 5.0, True, None),
                ("cross-replay", OTHER_SHA, 29500, "SHIELD_GENERATED", 101, 102, 999.0, True, None),
            ]
            for row in protection_rows:
                connection.execute(
                    """INSERT INTO protection_events
                       (fact_id,replay_sha256,game_id,replay_time_ms,
                        protection_kind,source_network_id,target_network_id,
                        observed_amount,canonical,heal_group_size)
                       VALUES (?,?,'game-a',?,?,?,?,?,?,?)""",
                    row,
                )
            connection.execute(
                """INSERT INTO protection_state_transitions
                   (fact_id,replay_sha256,game_id,replay_time_ms,
                    transition_kind,target_network_id,observed_amount,absorbed_amount)
                   VALUES ('transition',?,'game-a',29500,'SHIELD_ABSORBED',102,5,5)""",
                [SHA],
            )
            connection.execute(
                """INSERT INTO temporary_hp_events
                   (fact_id,replay_sha256,game_id,replay_time_ms,target_network_id)
                   VALUES ('temporary',?,'game-a',28000,102)""",
                [SHA],
            )

    def _write_replay_analysis(self, folder, *, sha, source_path, players, decoder):
        folder.mkdir(parents=True)
        (folder / "replay_analysis.json").write_text(
            json.dumps({
                "source_path": str(source_path),
                "replay_sha256": sha,
                "patch": "15.23",
                "game_id": None,
                "metadata": {"game_length_ms": 80000, "players": players},
                "decoder": {"status": decoder},
            }),
            encoding="utf-8",
        )

    def _make_artifact_candidates(self):
        old_replay = self.root / "old.rofl"
        old_replay.write_bytes(b"old replay")
        matched_players = [
            {
                "metadata_index": 0, "champion": "Milio", "team_id": 100,
                "team": "blue", "role": "support",
                "role_status": "VERIFIED_FROM_METADATA",
            },
            {
                "metadata_index": 1, "champion": "Jinx", "team_id": 100,
                "team": "blue", "role": "adc",
                "role_status": "VERIFIED_FROM_METADATA",
                "aggregate_stats": {"deaths": 1},
            },
        ]
        self._write_replay_analysis(
            self.metadata_root / "old",
            sha=OLD_SHA,
            source_path=old_replay,
            players=matched_players,
            decoder="UNSUPPORTED_REPLAY_VERSION",
        )
        self._write_replay_analysis(
            self.metadata_root / "missing",
            sha=MISSING_SHA,
            source_path=self.root / "missing.rofl",
            players=matched_players,
            decoder="UNSUPPORTED_REPLAY_VERSION",
        )
        self._write_replay_analysis(
            self.metadata_root / "unresolved",
            sha=UNRESOLVED_SHA,
            source_path=self.root / "unresolved.rofl",
            players=[
                {
                    "metadata_index": 0, "champion": "Milio", "team_id": 100,
                    "team": "blue", "role": None, "role_status": "UNAVAILABLE",
                },
                {
                    "metadata_index": 1, "champion": "Jinx", "team_id": 100,
                    "team": "blue", "role": "adc",
                    "role_status": "VERIFIED_FROM_METADATA",
                },
            ],
            decoder="UNSUPPORTED_REPLAY_VERSION",
        )

    def test_helpers(self):
        self.assertEqual(format_replay_time(1_122_999), "18:42")
        self.assertEqual(format_replay_time(-1), "00:00")
        self.assertEqual(champion_slug("Renata Glasc"), "renata_glasc")

    def test_builds_read_only_queue_with_honest_nulls(self):
        before = file_sha256(self.db)
        result = build_dataset(
            db_path=self.db,
            metadata_root=self.metadata_root,
            replay_root=self.replay_root,
            output_dir=self.output,
            support_champion="Milio",
        )
        self.assertEqual(file_sha256(self.db), before)

        summary = result["summary"]
        self.assertEqual(summary["matching_replays"], 3)
        self.assertEqual(summary["local_replays"], 2)
        self.assertEqual(summary["usable_replays"], 1)
        self.assertEqual(summary["missing_replays"], 1)
        self.assertEqual(summary["unresolved_role_replays"], 1)
        self.assertEqual(summary["total_adc_deaths"], 2)
        self.assertEqual(summary["deaths_with_protection_v4_context"], 1)
        self.assertEqual(summary["deaths_with_shield_events"], 1)
        self.assertEqual(summary["deaths_with_heal_events"], 1)
        self.assertEqual(summary["deaths_with_reliable_support_attribution"], 1)
        self.assertEqual(summary["validation"]["exact_death_event_matches"], 2)
        self.assertEqual(summary["validation"]["duplicate_death_rows"], 0)

        first, second = result["rows"]
        self.assertEqual(first["review_window"], "00:10–00:40")
        self.assertEqual(first["protection_window_start"], "00:15")
        self.assertEqual(first["protection_event_count"], 3)
        self.assertEqual(first["shield_event_count"], 2)
        self.assertEqual(first["shield_generated_event_count"], 1)
        self.assertEqual(first["shield_absorption_event_count"], 1)
        self.assertEqual(first["heal_event_count"], 1)
        self.assertEqual(first["heal_report_row_count"], 2)
        self.assertEqual(first["temporary_hp_event_count"], 1)
        self.assertEqual(first["protection_state_transition_count"], 1)
        self.assertEqual(first["reported_shield_generated_amount"], 50.0)
        self.assertEqual(first["known_absorbed_shield_amount"], 5.0)
        self.assertEqual(first["reported_heal_amount"], 20.0)
        self.assertEqual(first["reported_heal_raw_row_amount_sum"], 40.0)
        self.assertEqual(first["support_attributed_protection_event_count"], 2)
        self.assertTrue(first["support_attribution_available"])
        self.assertEqual(first["total_incoming_damage"], 110.0)
        self.assertEqual(first["physical_damage"], 40.0)
        self.assertEqual(first["magic_damage"], 50.0)
        self.assertEqual(first["true_damage"], 20.0)
        self.assertIsNone(first["basic_attack_damage"])
        self.assertIsNone(first["basic_attack_share"])
        self.assertEqual(first["known_basic_attack_damage"], 40.0)
        self.assertAlmostEqual(first["top_contributor_damage_share"], 60 / 110)
        self.assertIsNone(first["assisting_champions"])
        self.assertEqual(first["manual_review_status"], "UNREVIEWED")
        self.assertEqual(first["manual_notes"], "")
        self.assertEqual(second["protection_event_count"], 0)
        self.assertEqual(second["reported_shield_generated_amount"], 0.0)

        csv_path = Path(summary["output_files"]["csv"])
        jsonl_path = Path(summary["output_files"]["jsonl"])
        summary_path = Path(summary["output_files"]["summary"])
        missing_path = Path(summary["output_files"]["missing_replays"])
        self.assertTrue(csv_path.is_file())
        self.assertTrue(jsonl_path.is_file())
        self.assertTrue(summary_path.is_file())
        self.assertTrue(missing_path.is_file())
        parsed = [
            json.loads(line)
            for line in jsonl_path.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(parsed), 2)
        self.assertIsNone(parsed[0]["effective_heal_amount"])
        with csv_path.open(encoding="utf-8-sig", newline="") as stream:
            csv_rows = list(csv.DictReader(stream))
        self.assertEqual(csv_rows[0]["manual_review_status"], "UNREVIEWED")
        self.assertEqual(csv_rows[0]["manual_notes"], "")


if __name__ == "__main__":
    unittest.main()
