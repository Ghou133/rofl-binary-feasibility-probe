import hashlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import duckdb


V4_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = V4_ROOT.parent
sys.path.insert(0, str(V4_ROOT))

from verify_v4 import (  # noqa: E402
    SUPPORTED_PATCH,
    V3_TABLE_COUNTS,
    V4_FINGERPRINT_COLUMNS,
    VerificationExpectations,
    main,
    render,
    verify,
)


SHA = "a" * 64
SYNTHETIC_EMULATOR_BYTES = b"# synthetic verifier fixture; never executed\n"
SYNTHETIC_EMULATOR_SHA256 = (
    "87357141b14ab1d35b0c12b1729a611f9475ac732fea4592cc946ce33830fbf8"
)


def file_sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def fixture_expectations():
    v3_counts = {table: 0 for table in V3_TABLE_COUNTS}
    v3_counts.update({"replays": 1, "participants": 1})
    return VerificationExpectations(
        v3_table_counts=v3_counts,
        v3_replay_facts={
            SHA: {
                "game_id": "game", "patch": SUPPORTED_PATCH,
                "participants": 1, "death_events": 0, "damage_events": 0,
                "spell_events": 0, "buff_events": 0, "adc_deaths": 0,
            }
        },
        v4_only_replays={},
        profile_status_counts={"DECODED": 1},
        on_event_status_counts={"DECODED": 1},
        shield_damage_status_counts={"DECODED": 1},
        profile_decoded_row_count=4,
        profile_protection_row_count=4,
        heal_event_count=1,
        shield_event_id_counts={"23": 1, "237": 1, "238": 1},
        protection_kind_counts={
            "HEAL_REPORTED": 1, "SHIELD_ABSORBED": 1,
            "SHIELD_GENERATED": 1,
        },
        transition_kind_counts={"SHIELD_ABSORBED": 1},
        paired_shield_count=1,
        inventory_rows=1,
        inventory_casts=1,
        inventory_targets=1,
        inventory_buff_candidates=1,
        inventory_damage_windows=1,
        adc_survival_features=0,
        absorption_amounts=(5.0,),
        emulator_sha256=SYNTHETIC_EMULATOR_SHA256,
    )


def make_fixture(root):
    db = Path(root) / "fixture.duckdb"
    with duckdb.connect(str(db)) as connection:
        connection.execute(
            (PROJECT_ROOT / "research-v3" / "schema.sql").read_text(
                encoding="utf-8"
            )
        )
        connection.execute(
            (V4_ROOT / "schema.sql").read_text(encoding="utf-8")
        )
        connection.execute(
            "INSERT INTO replays (game_id,replay_sha256,patch) VALUES (?,?,?)",
            ["game", SHA, SUPPORTED_PATCH],
        )
        connection.execute(
            """INSERT INTO participants
               (fact_id,game_id,replay_sha256,patch,participant_id,network_id)
               VALUES ('participant','game',?,?,1,101)""",
            [SHA, SUPPORTED_PATCH],
        )
        profiles = [
            "rofl-16.15.801.3452-on-event-protection-v4",
            "rofl-16.15.801.3452-unit-apply-shield-damage-v4",
        ]
        connection.execute(
            """INSERT INTO protection_v4_profiles
               (replay_sha256,game_id,patch,profile_status,decoder_profile,
                decoded_row_count,protection_row_count,details_json,
                v4_schema_version,on_event_decoder_status,
                shield_damage_decoder_status,decoder_profiles_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                SHA, "game", SUPPORTED_PATCH, "DECODED", "+".join(profiles),
                4, 4, json.dumps({"v4_only_replay": False}), 2, "DECODED",
                "DECODED", json.dumps(profiles),
            ],
        )
        connection.execute(
            """INSERT INTO heal_events
               (fact_id,replay_sha256,game_id,replay_time_ms,event_id,
                source_network_id,target_network_id,observed_amount)
               VALUES ('heal',?,'game',100,75,101,102,10)""",
            [SHA],
        )
        connection.execute(
            """INSERT INTO shield_state_events
               (fact_id,replay_sha256,game_id,replay_time_ms,event_id,
                source_network_id,target_network_id,observed_amount)
               VALUES
               ('receive',?,'game',100,237,101,102,20),
               ('grant',?,'game',100,238,101,102,20),
               ('absorb',?,'game',101,23,NULL,102,5)""",
            [SHA, SHA, SHA],
        )
        connection.execute(
            """INSERT INTO protection_events
               (fact_id,replay_sha256,game_id,replay_time_ms,protection_kind,
                source_network_id,target_network_id,observed_amount,canonical,
                paired_source_route_fact_id)
               VALUES
               ('heal-canonical',?,'game',100,'HEAL_REPORTED',101,102,10,true,NULL),
               ('shield-canonical',?,'game',100,'SHIELD_GENERATED',101,102,20,true,'grant'),
               ('absorb-canonical',?,'game',101,'SHIELD_ABSORBED',NULL,102,5,true,NULL)""",
            [SHA, SHA, SHA],
        )
        connection.execute(
            """INSERT INTO protection_state_transitions
               (fact_id,replay_sha256,game_id,replay_time_ms,transition_kind,
                source_network_id,target_network_id,observed_amount,absorbed_amount)
               VALUES ('transition',?,'game',101,'SHIELD_ABSORBED',NULL,102,5,5)""",
            [SHA],
        )
        connection.execute(
            """INSERT INTO protection_spell_inventory
               (fact_id,replay_sha256,game_id,cast_count,target_count,
                buff_candidate_count,damage_window_count)
               VALUES ('inventory',?,'game',1,1,1,1)""",
            [SHA],
        )
    return db


def make_synthetic_emulator(root):
    emulator = Path(root) / "synthetic_emulator.py"
    emulator.write_bytes(SYNTHETIC_EMULATOR_BYTES)
    if file_sha256(emulator) != SYNTHETIC_EMULATOR_SHA256:
        raise AssertionError("synthetic emulator fixture hash drifted")
    return emulator


class VerifyV4Tests(unittest.TestCase):
    def test_synthetic_complete_database_passes_without_mutation(self):
        with tempfile.TemporaryDirectory() as root:
            db = make_fixture(root)
            emulator = make_synthetic_emulator(root)
            before = file_sha256(db)
            result = verify(
                db, emulator_path=emulator,
                expectations=fixture_expectations(),
            )
            repeated = verify(
                db, emulator_path=emulator,
                expectations=fixture_expectations(),
            )
            after = file_sha256(db)
            self.assertEqual(result["status"], "PROTECTION_V4_COMPLETE")
            self.assertEqual(result["failures"], [])
            self.assertEqual(result, repeated)
            self.assertEqual(before, after)
            self.assertEqual(render(result), render(repeated))
            fingerprints = result["summary"]["semantic_fingerprints"]
            self.assertEqual(set(fingerprints), set(V4_FINGERPRINT_COLUMNS))
            self.assertNotIn(
                "created_at", fingerprints["protection_v4_profiles"]["columns"]
            )
            self.assertEqual(
                result["summary"]["v4"]["adc_death_protection"],
                {"row_count": 0, "kind_distribution": {}},
            )

    def test_absorption_source_fabrication_fails(self):
        with tempfile.TemporaryDirectory() as root:
            db = make_fixture(root)
            emulator = make_synthetic_emulator(root)
            before = verify(
                db, emulator_path=emulator,
                expectations=fixture_expectations(),
            )
            with duckdb.connect(str(db)) as connection:
                connection.execute(
                    """UPDATE protection_events SET source_network_id=999
                       WHERE protection_kind='SHIELD_ABSORBED'"""
                )
            result = verify(
                db, emulator_path=emulator,
                expectations=fixture_expectations(),
            )
            self.assertEqual(result["status"], "FAIL")
            self.assertIn(
                "null_honesty.invalid_absorption_source_attribution",
                result["failures"],
            )
            self.assertNotEqual(
                before["summary"]["semantic_fingerprints"]["protection_events"]["sha256"],
                result["summary"]["semantic_fingerprints"]["protection_events"]["sha256"],
            )

    def test_cli_missing_database_is_nonzero_and_writes_json(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "result.json"
            with redirect_stdout(io.StringIO()):
                code = main([
                    "--db", str(Path(root) / "missing.duckdb"),
                    "--output", str(output),
                ])
            self.assertEqual(code, 1)
            written = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(written["status"], "FAIL")
            self.assertIn("database_file", written["failures"])

    def test_output_cannot_overwrite_database_path(self):
        with tempfile.TemporaryDirectory() as root:
            protected = Path(root) / "database.duckdb"
            with redirect_stdout(io.StringIO()):
                code = main([
                    "--db", str(protected), "--output", str(protected),
                ])
            self.assertEqual(code, 1)
            self.assertFalse(protected.exists())


if __name__ == "__main__":
    unittest.main()
