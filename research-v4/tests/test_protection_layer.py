import json
import hashlib
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from protection_layer import backfill_protection as _backfill_protection  # noqa: E402

SHA = "a" * 64
IMAGE_SHA = "7ee788155b9ba61d10603694cffb095e66ab3c641f933e4e7b181000c69f61bb"


def backfill_protection(*args, **kwargs):
    """Unit fixtures inject the expensive Replay/decoder attestation boundary."""
    with patch("protection_layer._verify_bundle_from_replays", return_value=True):
        return _backfill_protection(*args, **kwargs)


def decoded(event_id, occurrence, *, time=1000, source=101, target=102, amount=25.0,
            blob="0102", packet_occurrence=None):
    return dedicated(event_id, occurrence, time=time, source=source,
                     target=target, amount=amount)


def dedicated(event_id, occurrence, *, time=1000, source=101, target=102, amount=25.0):
    size = 0x34 if event_id == 0x4B else 0x14
    parameter = bytearray(size)
    if event_id == 0x4B:
        struct.pack_into("<I", parameter, 0x04, target)
        struct.pack_into("<I", parameter, 0x14, source)
        struct.pack_into("<f", parameter, 0x18, amount)
        contract = ("OnCastHeal", "ParamsHeal", 0x7C044FE1, "HEAL_REPORTED_DIRECT",
                    "HEAL_EVENT", True)
    elif event_id == 0xED:
        struct.pack_into("<I", parameter, 0x08, source)
        struct.pack_into("<I", parameter, 0x0C, target)
        struct.pack_into("<f", parameter, 0x10, amount)
        contract = ("OnReceiveShield", "ShieldingParams", 0x8F7F3F4E,
                    "SHIELD_APPLICATION_DIRECT", "TARGET_ROUTE", True)
    else:
        struct.pack_into("<I", parameter, 0x08, source)
        struct.pack_into("<I", parameter, 0x0C, target)
        struct.pack_into("<f", parameter, 0x10, amount)
        contract = ("OnGrantShield", "ShieldingParams", 0x8F7F3F4E,
                    "SHIELD_APPLICATION_DIRECT", "SOURCE_ROUTE_DUPLICATE", False)
    payload = bytes.fromhex("deadbeef")
    raw = {
        "replay_path": "fixture.rofl", "replay_sha256": SHA,
        "chunk_index": 7, "chunk_id": 8, "chunk_stream": "game_chunk",
        "chunk_file_offset": 100, "compressed_body_offset": 101,
        "decompressed_block_offset": 102, "decompressed_payload_offset": 103,
        "replay_time_ms": time, "occurrence_index": occurrence,
        "packet_id": 0x009E, "payload_length": len(payload),
        "raw_param": 7, "raw_param_hex": "0x7",
        "raw_payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    amount_bits = struct.unpack("<I", struct.pack("<f", amount))[0]
    return {
        "schema_version": 1, "replay_path": raw["replay_path"],
        "replay_sha256": SHA, "replay_version": "16.15.801.3452",
        "replay_label": "fixture", "replay_time_ms": time, "event_id": event_id,
        "event_id_hex": f"0x{event_id:04x}", "event_name": contract[0],
        "parameter_type": contract[1], "expected_schema_id": contract[2],
        "expected_size": size, "event_kind": contract[3], "route_kind": contract[4],
        "canonical_route": contract[5], "semantic_status": "VERIFIED_DIRECT",
        "schema_id": contract[2], "schema_id_hex": f"0x{contract[2]:08x}",
        "schema_matches_expected": True, "parameter_size": size,
        "parameter_capacity": size, "parameter_size_matches_expected": True,
        "parameter_blob_hex": parameter.hex(),
        "parameter_blob_sha256": hashlib.sha256(parameter).hexdigest(),
        "source_network_id": source, "target_network_id": target,
        "amount": amount, "amount_bits_hex": f"0x{amount_bits:08x}",
        "amount_is_finite": True, "deserialize_return_al": 1,
        "fully_consumed": True, "outer_object_hex": "00" * 0x28,
        "raw_param": raw["raw_param"], "raw_param_hex": raw["raw_param_hex"],
        "raw_payload_hex": payload.hex(), "raw_payload_sha256": raw["raw_payload_sha256"],
        "decoder_profile": "rofl-16.15.801.3452-on-event-protection-v4",
        "decoder_runtime_image_sha256": IMAGE_SHA,
        "chunk_index": raw["chunk_index"], "chunk_id": raw["chunk_id"],
        "chunk_stream": raw["chunk_stream"], "chunk_file_offset": raw["chunk_file_offset"],
        "compressed_body_offset": raw["compressed_body_offset"],
        "decompressed_block_offset": raw["decompressed_block_offset"],
        "decompressed_payload_offset": raw["decompressed_payload_offset"],
        "occurrence_index": occurrence, "raw_packet_ref": raw,
    }


def semantic(event_id, occurrence, *, amount=25.0):
    size = 0x34 if event_id == 0x4B else 0x14
    return {
        "event_type": "heal" if event_id == 0x4B else "shield",
        "replay_sha256": SHA, "replay_time_ms": 1000,
        "protocol_event_id": event_id, "source_network_id": 101,
        "target_network_id": 102,
        "direct_heal_amount": amount if event_id == 0x4B else None,
        "generated_amount": amount if event_id != 0x4B else None,
        "event_params_size": size, "event_params_hex": f"semantic-{occurrence}",
        "event_params_sha256": f"semantic-params-{occurrence}",
        "raw_packet_ref": {
            "replay_sha256": SHA, "packet_id": 0x009E, "payload_length": size,
            "chunk_index": 1, "chunk_id": 1, "chunk_stream": "game_chunk",
            "decompressed_block_offset": occurrence,
            "decompressed_payload_offset": occurrence + 1,
            "occurrence_index": occurrence,
            "payload_sha256": f"semantic-payload-{occurrence}",
        },
    }


def shield_absorbed(occurrence, *, time=1000, target=102, amount=12.5):
    payload = bytes.fromhex("00112233445566778899")
    amount_bits = struct.unpack("<I", struct.pack("<f", amount))[0]
    raw = {
        "replay_path": "fixture.rofl", "replay_sha256": SHA,
        "chunk_index": 7, "chunk_id": 8, "chunk_stream": "game_chunk",
        "chunk_file_offset": 100, "compressed_body_offset": 101,
        "decompressed_block_offset": 200, "decompressed_payload_offset": 209,
        "replay_time_ms": time, "occurrence_index": occurrence,
        "packet_id": 0x0017, "payload_length": len(payload),
        "raw_param": target, "raw_param_hex": hex(target),
        "raw_payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    return {
        "replay_sha256": SHA, "packet_id": 0x0017,
        "replay_time_ms": time, "chunk_index": 7, "chunk_id": 8,
        "chunk_stream": "game_chunk", "decompressed_block_offset": 200,
        "decompressed_payload_offset": 209, "occurrence_index": occurrence,
        "event_kind": "SHIELD_ABSORBED_DIRECT",
        "semantic_status": "VERIFIED_DIRECT",
        "target_network_id": target, "shield_absorbed_amount": amount,
        "shield_absorbed_amount_bits_hex": f"0x{amount_bits:08x}",
        "network_fields_agree": True, "target_matches_raw_param": True,
        "deserialize_return_al": 1, "fully_consumed": True,
        "decoder_profile": "rofl-16.15.801.3452-unit-apply-shield-damage-v4",
        "decoder_runtime_image_sha256": IMAGE_SHA,
        "raw_param": target, "raw_param_hex": hex(target),
        "raw_payload_hex": payload.hex(),
        "raw_payload_sha256": raw["raw_payload_sha256"],
        "decoded_field_bytes_hex": {
            "field_14": struct.pack("<I", target).hex(),
            "field_18": struct.pack("<I", amount_bits).hex(),
        },
        "raw_packet_ref": raw,
    }


class ProtectionLayerTests(unittest.TestCase):
    def fixture_db(self, root):
        db = Path(root) / "fixture.duckdb"
        with duckdb.connect(str(db)) as con:
            con.execute("CREATE TABLE replays (game_id VARCHAR,replay_sha256 VARCHAR,patch VARCHAR)")
            con.execute("CREATE TABLE participants (participant_id INTEGER,network_id BIGINT,team_id INTEGER,champion VARCHAR,replay_sha256 VARCHAR)")
            con.execute("CREATE TABLE adc_deaths (fact_id VARCHAR,adc_participant_id INTEGER,combat_start_ms BIGINT,death_time_ms BIGINT,replay_sha256 VARCHAR)")
            con.execute("CREATE TABLE damage_events (replay_time_ms BIGINT,target_network_id BIGINT,amount DOUBLE,damage_type VARCHAR,is_basic_attack BOOLEAN,spell VARCHAR,replay_sha256 VARCHAR)")
            con.execute("CREATE TABLE spell_events (fact_id VARCHAR,source_network_id BIGINT,source_participant_id INTEGER,source_champion VARCHAR,spell_identifier VARCHAR,spell_slot VARCHAR,replay_time_ms BIGINT,raw_provenance_json JSON,replay_sha256 VARCHAR)")
            con.execute("INSERT INTO replays VALUES ('game', ?, '16.15.801.3452')", [SHA])
            con.execute("INSERT INTO participants VALUES (1,101,100,'Lulu',?),(2,102,100,'Ashe',?),(3,201,200,'Ahri',?)", [SHA, SHA, SHA])
            con.execute("INSERT INTO adc_deaths VALUES ('death',2,900,1100,?)", [SHA])
            con.execute("INSERT INTO damage_events VALUES (950,102,50,'MAGIC',false,'Q',?),(1000,102,25,'PHYSICAL',true,NULL,?)", [SHA, SHA])
        return db

    def write_rows(self, root, rows, name="decoded.jsonl"):
        path = Path(root) / name
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        return path

    def write_decoder_bundle(self, root, rows, *, packet_id, name):
        """Produce a complete, hash-bound export/decoder fixture pair."""
        path = self.write_rows(root, rows, name)
        raw = Path(root) / f"raw_{packet_id:04x}_{name}"
        raw.write_text("{}\n" * len(rows), encoding="utf-8")
        manifest = {
            "schema_version": 1, "target_replay_version": "16.15.801.3452",
            "output": str(raw.resolve()), "packet_ids": [packet_id],
            "selected_packet_count": len(rows), "packet_counts": {str(packet_id): len(rows)},
            "replay_count": 1, "replays": [{
                "path": "fixture.rofl", "sha256": SHA, "version": "16.15.801.3452",
                "selected_packet_count": len(rows), "parser_error_count": 0,
            }],
        }
        manifest_path = Path(f"{raw}.manifest.json")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        profile = (
            "rofl-16.15.801.3452-on-event-protection-v4"
            if packet_id == 0x009E else
            "rofl-16.15.801.3452-unit-apply-shield-damage-v4"
        )
        summary = {
            "schema_version": 1, "decoder_profile": profile,
            "decoder_runtime_image_sha256": IMAGE_SHA,
            "image_sha256": IMAGE_SHA, "client_opcode": f"0x{packet_id:04x}",
            "events_path": str(raw.resolve()),
            "events_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
            "events_manifest_path": str(manifest_path.resolve()),
            "events_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "output_path": str(path.resolve()),
            "output_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "input_event_count": len(rows),
            "deserialize_success_count": len(rows), "fully_consumed_count": len(rows),
            "output_event_count": len(rows), "output_replay_counts": {SHA: len(rows)} if rows else {},
            "scan_replay_count": 1,
            "scan_selected_packet_count": len(rows),
            "scan_parser_error_count": 0,
            "scan_replays": [{
                "replay_path": "fixture.rofl", "replay_sha256": SHA,
                "replay_version": "16.15.801.3452",
                "selected_packet_count": len(rows),
                "parser_error_count": 0,
            }],
        }
        if packet_id == 0x009E:
            summary.update({"schema_mismatch_count": 0, "parameter_size_mismatch_count": 0})
        else:
            summary.update({"network_fields_agree_count": len(rows), "target_matches_raw_param_count": len(rows)})
        path.with_suffix(".summary.json").write_text(
            json.dumps(summary), encoding="utf-8"
        )
        return path

    def write_on_event_summary(self, path, *, selected_packet_count=0):
        # Retained for the negative zero-row test; it deliberately cannot
        # attest a standalone decoded file without its export manifest.
        self.write_decoder_bundle(path.parent, [], packet_id=0x009E, name=path.name)

    def test_pairing_duplicates_order_null_honesty_and_adc_window(self):
        with tempfile.TemporaryDirectory() as root:
            db = self.fixture_db(root)
            # 0xee immediately precedes 0xed for same blob; two identical raw heals form one exact group.
            path = self.write_decoder_bundle(root, [
                decoded(0xEE, 10, amount=30), decoded(0xED, 11, amount=30),
                decoded(0x4B, 20, amount=10), decoded(0x4B, 21, amount=10),
                decoded(0x4B, 22, time=1200, amount=99),  # outside death window
            ], packet_id=0x009E, name="on_event.jsonl")
            shield = self.write_decoder_bundle(root, [], packet_id=0x0017, name="shield.jsonl")
            result = backfill_protection(db, replay_sha256=SHA, decoded_jsonl_paths=[path, shield])
            self.assertEqual(result["profile_status"], "DECODED")
            with duckdb.connect(str(db), read_only=True) as con:
                self.assertEqual(con.execute("SELECT count(*) FROM heal_events").fetchone()[0], 3)
                shield = con.execute("SELECT paired_source_route_fact_id,raw_amount,effective_amount FROM protection_events WHERE protection_kind='SHIELD_GENERATED'").fetchone()
                self.assertIsNotNone(shield[0]); self.assertEqual(shield[1:], (None, None))
                heal = con.execute("SELECT heal_group_size,canonical_first_raw_occurrence,observed_amount FROM protection_events WHERE protection_kind='HEAL_REPORTED' ORDER BY replay_time_ms").fetchall()
                self.assertEqual(heal, [(2, 20, 10.0), (1, 22, 99.0)])
                p = con.execute("SELECT chunk_index,chunk_id,raw_payload_hex,params_hex,raw_provenance_json FROM heal_events ORDER BY raw_occurrence_index LIMIT 1").fetchone()
                self.assertEqual(
                    p[:4], (7, 8, "deadbeef", dedicated(0x4B, 20, amount=10)["parameter_blob_hex"])
                ); self.assertIn("decompressed_payload_offset", p[4])
                context = con.execute("SELECT protection_kind,direct_heal_lower,direct_heal_upper FROM adc_death_protection ORDER BY protection_kind").fetchall()
                self.assertEqual(context, [("HEAL_REPORTED", 10.0, 20.0), ("SHIELD_GENERATED", None, None)])
                feature = con.execute("SELECT external_ally_shield_generated,external_ally_direct_heal_lower,external_ally_direct_heal_upper,direct_heal_exact,incoming_damage_event_count,shield_remaining,health_before,temporary_hp_before FROM adc_survival_features_v4").fetchone()
                self.assertEqual(feature[:5], (30.0, 10.0, 20.0, False, 2)); self.assertEqual(feature[5:], (None, None, None))

    def test_idempotence_and_statuses(self):
        with tempfile.TemporaryDirectory() as root:
            db = self.fixture_db(root); path = self.write_decoder_bundle(root, [decoded(0xED, 2)], packet_id=0x009E, name="on.jsonl")
            shield = self.write_decoder_bundle(root, [], packet_id=0x0017, name="shield.jsonl")
            first = backfill_protection(db, replay_sha256=SHA, decoded_jsonl_paths=[path, shield])
            second = backfill_protection(db, replay_sha256=SHA, decoded_jsonl_paths=[path, shield])
            self.assertEqual(first["table_counts"], second["table_counts"])
            with duckdb.connect(str(db), read_only=True) as con:
                self.assertEqual(con.execute("SELECT count(*) FROM protection_events").fetchone()[0], 1)
            unavailable = backfill_protection(db, replay_sha256=SHA)
            self.assertEqual(unavailable["profile_status"], "DECODER_UNAVAILABLE")
            with duckdb.connect(str(db), read_only=True) as con:
                self.assertEqual(con.execute("SELECT count(*) FROM adc_survival_features_v4").fetchone()[0], 0)
                self.assertEqual(con.execute("SELECT count(*) FROM adc_death_protection").fetchone()[0], 0)
            none_path = self.write_decoder_bundle(root, [], packet_id=0x009E, name="on_empty.jsonl")
            shield_empty = self.write_decoder_bundle(root, [], packet_id=0x0017, name="shield_empty.jsonl")
            none = backfill_protection(db, replay_sha256=SHA, decoded_jsonl_paths=[none_path])
            self.assertEqual(none["profile_status"], "DECODER_UNAVAILABLE")
            none = backfill_protection(db, replay_sha256=SHA, decoded_jsonl_paths=[none_path, shield_empty])
            self.assertEqual(none["profile_status"], "NO_PROTECTION_EVENT")
            unsupported = backfill_protection(db, replay_sha256="b" * 64, decoded_jsonl_paths=[none_path, shield_empty])
            self.assertEqual(unsupported["profile_status"], "PROTECTION_PROFILE_UNSUPPORTED")

    def test_only_dedicated_rows_are_accepted_without_filling_unknowns(self):
        with tempfile.TemporaryDirectory() as root:
            db = self.fixture_db(root)
            path = self.write_decoder_bundle(root, [dedicated(0xED, 1), dedicated(0x4B, 2)], packet_id=0x009E, name="on.jsonl")
            shield = self.write_decoder_bundle(root, [], packet_id=0x0017, name="shield.jsonl")
            result = backfill_protection(db, replay_sha256=SHA, decoded_jsonl_paths=[path, shield])
            self.assertEqual(result["profile_status"], "DECODED")
            semantic_path = Path(root) / "semantic.jsonl"
            semantic_path.write_text(
                "".join(json.dumps(row) + "\n" for row in [semantic(0xED, 3), semantic(0x4B, 4)]),
                encoding="utf-8",
            )
            result = backfill_protection(
                db, replay_sha256=SHA, decoded_jsonl_paths=[semantic_path]
            )
            self.assertEqual(result["profile_status"], "DECODER_UNAVAILABLE")
            with duckdb.connect(str(db), read_only=True) as con:
                self.assertEqual(con.execute("SELECT count(*) FROM protection_events").fetchone()[0], 0)

    def test_missing_blob_identity_never_groups_or_pairs(self):
        with tempfile.TemporaryDirectory() as root:
            db = self.fixture_db(root)
            rows = [decoded(0xEE, 10), decoded(0xED, 11), decoded(0x4B, 20), decoded(0x4B, 21)]
            for row in rows:
                row.pop("parameter_blob_hex")
                row.pop("parameter_blob_sha256")
            path = self.write_rows(root, rows)
            result = backfill_protection(db, replay_sha256=SHA, decoded_jsonl_paths=[path])
            self.assertEqual(result["profile_status"], "DECODER_UNAVAILABLE")
            with duckdb.connect(str(db), read_only=True) as con:
                self.assertEqual(con.execute("SELECT count(*) FROM protection_events").fetchone()[0], 0)

    def test_missing_amount_is_decoder_unavailable_not_zero(self):
        with tempfile.TemporaryDirectory() as root:
            db = self.fixture_db(root)
            row = decoded(0x4B, 1)
            row["amount"] = None
            path = self.write_rows(root, [row])
            result = backfill_protection(db, replay_sha256=SHA, decoded_jsonl_paths=[path])
            self.assertEqual(result["profile_status"], "DECODER_UNAVAILABLE")
            with duckdb.connect(str(db), read_only=True) as con:
                self.assertEqual(con.execute("SELECT count(*) FROM protection_events").fetchone()[0], 0)
                self.assertEqual(con.execute("SELECT count(*) FROM adc_survival_features_v4").fetchone()[0], 0)

    def test_unpinned_or_inconsistent_on_event_rows_are_decoder_unavailable(self):
        defects = {
            "missing_profile": lambda row: row.pop("decoder_profile"),
            "wrong_profile": lambda row: row.__setitem__("decoder_profile", "generic"),
            "wrong_image": lambda row: row.__setitem__("decoder_runtime_image_sha256", "0" * 64),
            "deserialize_failed": lambda row: row.__setitem__("deserialize_return_al", 0),
            "not_fully_consumed": lambda row: row.__setitem__("fully_consumed", False),
            "wrong_schema": lambda row: row.__setitem__("schema_id", 1),
            "wrong_size": lambda row: row.__setitem__("parameter_size", 1),
            "wrong_event_contract": lambda row: row.__setitem__("event_name", "Forged"),
            "raw_ref_mismatch": lambda row: row["raw_packet_ref"].__setitem__("replay_time_ms", 1),
            "payload_hash_mismatch": lambda row: row.__setitem__("raw_payload_sha256", "0" * 64),
            "parameter_hash_mismatch": lambda row: row.__setitem__("parameter_blob_sha256", "0" * 64),
            "amount_bits_mismatch": lambda row: row.__setitem__("amount_bits_hex", "0x00000000"),
            "generic_emulator": lambda row: row.__setitem__("decoded_fields", {
                "event_id": 0xED, "source_network_id": 101, "target_network_id": 102,
                "amount": 25.0, "event_params_size": 0x14,
            }),
            "semantic_input": lambda row: row.update({
                "event_type": "shield", "protocol_event_id": 0xED,
                "decoder_profile": None, "semantic_status": None,
            }),
        }
        for name, defect in defects.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                db = self.fixture_db(root)
                row = dedicated(0xED, 1)
                defect(row)
                path = self.write_rows(root, [row])
                result = backfill_protection(
                    db, replay_sha256=SHA, decoded_jsonl_paths=[path]
                )
                self.assertEqual(result["profile_status"], "DECODER_UNAVAILABLE")
                with duckdb.connect(str(db), read_only=True) as con:
                    self.assertEqual(
                        con.execute("SELECT count(*) FROM protection_events").fetchone()[0],
                        0,
                    )

    def test_on_event_zero_rows_require_pinned_manifest_scan_coverage(self):
        with tempfile.TemporaryDirectory() as root:
            db = self.fixture_db(root)
            unavailable = self.write_rows(root, [], "on_event_empty.jsonl")
            result = backfill_protection(
                db, replay_sha256=SHA, decoded_jsonl_paths=[unavailable]
            )
            self.assertEqual(result["profile_status"], "DECODER_UNAVAILABLE")
            self.write_on_event_summary(unavailable)
            covered = backfill_protection(
                db, replay_sha256=SHA, decoded_jsonl_paths=[unavailable]
            )
            self.assertEqual(covered["profile_status"], "DECODER_UNAVAILABLE")
            shield = self.write_decoder_bundle(root, [], packet_id=0x0017, name="shield_empty.jsonl")
            covered = backfill_protection(
                db, replay_sha256=SHA, decoded_jsonl_paths=[unavailable, shield]
            )
            self.assertEqual(covered["profile_status"], "NO_PROTECTION_EVENT")

    def test_attestation_rejects_missing_double_forged_and_cross_route_artifacts(self):
        defects = {
            "missing_summary": lambda on, _shield: on.with_suffix(".summary.json").unlink(),
            "double_summary": lambda on, _shield: Path(f"{on}.summary.json").write_text(
                on.with_suffix(".summary.json").read_text(encoding="utf-8"), encoding="utf-8"
            ),
            "forged_events_hash": lambda on, _shield: self._mutate_summary(
                on, "events_sha256", "0" * 64
            ),
            "forged_manifest_hash": lambda on, _shield: self._mutate_summary(
                on, "events_manifest_sha256", "0" * 64
            ),
            "cross_route_row": lambda on, shield: self._replace_output_with_cross_route(on, shield),
        }
        for name, defect in defects.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                db = self.fixture_db(root)
                on = self.write_decoder_bundle(root, [dedicated(0xED, 1)], packet_id=0x009E, name="on.jsonl")
                shield = self.write_decoder_bundle(root, [shield_absorbed(2)], packet_id=0x0017, name="shield.jsonl")
                defect(on, shield)
                result = backfill_protection(db, replay_sha256=SHA, decoded_jsonl_paths=[on, shield])
                self.assertEqual(result["profile_status"], "DECODER_UNAVAILABLE")
                with duckdb.connect(str(db), read_only=True) as con:
                    self.assertEqual(con.execute("SELECT count(*) FROM protection_events").fetchone()[0], 0)

    def test_self_consistent_forged_bundle_is_rejected_by_production_verifier(self):
        with tempfile.TemporaryDirectory() as root:
            db = self.fixture_db(root)
            on = self.write_decoder_bundle(
                root, [dedicated(0xED, 1, amount=9999)],
                packet_id=0x009E, name="forged.jsonl",
            )
            shield = self.write_decoder_bundle(
                root, [], packet_id=0x0017, name="shield.jsonl",
            )
            result = _backfill_protection(
                db, replay_sha256=SHA, decoded_jsonl_paths=[on, shield],
            )
            self.assertEqual(result["profile_status"], "DECODER_UNAVAILABLE")
            with duckdb.connect(str(db), read_only=True) as con:
                self.assertEqual(con.execute("SELECT count(*) FROM protection_events").fetchone()[0], 0)

    def test_on_event_decoder_rejects_unpinned_runtime_image(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            image = root / "wrong-image.bin"
            image.write_bytes(b"not-the-pinned-runtime-image")
            events = root / "events.jsonl"
            events.write_text("", encoding="utf-8")
            result = subprocess.run([
                sys.executable, str(ROOT.parent / "scripts" / "decode_on_event_protection_v4.py"),
                "--image", str(image), "--events", str(events),
                "--output", str(root / "decoded.jsonl"),
            ], cwd=ROOT.parent, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("PROTECTION_PROFILE_UNSUPPORTED", result.stderr)

    @staticmethod
    def _mutate_summary(path, key, value):
        summary_path = path.with_suffix(".summary.json")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary[key] = value
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

    @staticmethod
    def _replace_output_with_cross_route(on_path, shield_path):
        on_path.write_text(shield_path.read_text(encoding="utf-8"), encoding="utf-8")
        summary_path = on_path.with_suffix(".summary.json")
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["output_sha256"] = hashlib.sha256(on_path.read_bytes()).hexdigest()
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

    def test_direct_shield_absorption_and_unattributed_adc_context(self):
        with tempfile.TemporaryDirectory() as root:
            db = self.fixture_db(root)
            path = self.write_decoder_bundle(root, [shield_absorbed(1)], packet_id=0x0017, name="shield_damage_decoded.jsonl")
            on_event = self.write_decoder_bundle(root, [], packet_id=0x009E, name="on_event_empty.jsonl")
            result = backfill_protection(db, replay_sha256=SHA, decoded_jsonl_paths=[on_event, path])
            self.assertEqual(result["profile_status"], "DECODED")
            with duckdb.connect(str(db), read_only=True) as con:
                transition = con.execute(
                    "SELECT transition_kind,absorbed_amount FROM protection_state_transitions"
                ).fetchone()
                self.assertEqual(transition, ("SHIELD_ABSORBED", 12.5))
                context = con.execute(
                    "SELECT protection_kind,observed_amount,source_is_external_ally FROM adc_death_protection"
                ).fetchone()
                self.assertEqual(context, ("SHIELD_ABSORBED", 12.5, None))
                feature = con.execute(
                    "SELECT external_ally_shield_generated,external_ally_direct_heal_lower,direct_heal_exact,shield_absorbed FROM adc_survival_features_v4"
                ).fetchone()
                self.assertEqual(feature, (0.0, 0.0, True, 12.5))


if __name__ == "__main__":
    unittest.main()
