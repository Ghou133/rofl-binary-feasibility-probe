import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import ReplayStore  # noqa: E402
from position_context import participant_network_id  # noqa: E402
from research_layer import (  # noqa: E402
    materialize_research_layer,
    publish_all,
    research_status,
    sha256_file,
    write_first_research_report,
    write_research_status,
)


REPLAY = "a" * 64
PATCH = "16.15.801.3452"


class ResearchLayerTests(unittest.TestCase):
    def test_materializes_direct_wards_and_derived_position_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "research.duckdb"
            store = ReplayStore(db)
            store.init()
            with store.connect() as con:
                con.execute(
                    "INSERT INTO replays (game_id,replay_sha256,patch,confidence,status) "
                    "VALUES ('1',?,?, 'VERIFIED','READY')", [REPLAY, PATCH]
                )
                players = [
                    (1, "Ashe", 100, "adc"),
                    (2, "Lulu", 100, "support"),
                    (6, "LeeSin", 200, "jungle"),
                    (7, "Ahri", 200, "mid"),
                ]
                for participant_id, champion, team, role in players:
                    con.execute("""
                        INSERT INTO participants
                        (fact_id,game_id,replay_sha256,patch,participant_id,network_id,
                         champion,team_id,role,decoder_profile,confidence,status,
                         raw_provenance_json)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, [
                        f"p{participant_id}", "1", REPLAY, PATCH, participant_id,
                        participant_network_id(participant_id), champion, team, role,
                        "metadata", "VERIFIED", "VERIFIED_FROM_METADATA", "{}",
                    ])
                for timestamp in (1_000, 5_000, 7_000, 8_000, 9_000, 10_000):
                    for participant_id, x in ((1, 0), (2, 300), (6, 700), (7, 1500)):
                        con.execute("""
                            INSERT INTO hero_positions_1s
                            (fact_id,game_id,replay_sha256,patch,replay_time_ms,entity_id,
                             position_x,position_z,source_path_timestamp_ms,source_age_ms,
                             interpolation_method,position_status,raw_packet_ref,
                             decoder_profile,confidence,status,raw_provenance_json)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """, [
                            f"pos-{timestamp}-{participant_id}", "1", REPLAY, PATCH,
                            timestamp, participant_network_id(participant_id), x, 0,
                            timestamp - 100, 100,
                            "PATH_WAYPOINT_LINEAR_INTERPOLATION_WITH_TERMINAL_HOLD",
                            "VERIFIED_DERIVED", json.dumps({"packet_id": 721}),
                            "path-v1", "VERIFIED_DERIVED", "ENRICHED", "{}",
                        ])
                con.execute("""
                    INSERT INTO ward_spawns
                    (fact_id,game_id,replay_sha256,patch,replay_time_ms,owner_network_id,
                     entity_network_id,owner_participant_id,owner_team_id,ward_type,
                     generic_name,entity_name,position_x,position_y,position_height,
                     owner_mapping_confidence,decoder_profile,confidence,status,
                     raw_provenance_json)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, [
                    "ward-1", "1", REPLAY, PATCH, 1_000, participant_network_id(1),
                    99, 1, 100, "YELLOW_OR_SIGHT_WARD", "SightWard", "YellowTrinket",
                    777, 888, 4, "VERIFIED_DERIVED_NETWORK_ID_JOIN", "ward-v1",
                    "VERIFIED_DIRECT_OBJECT_WRITE_TRACE", "DECODED", "{}",
                ])
                con.execute("""
                    INSERT INTO ward_lifecycles
                    (fact_id,game_id,replay_sha256,patch,ward_network_id,spawn_time_ms,
                     remove_time_ms,duration_ms,decoder_profile,confidence,status,
                     raw_provenance_json)
                    VALUES ('life-1','1',?,?,99,1000,20000,19000,
                            'life-v1','VERIFIED_DERIVED','MATCHED','{}')
                """, [REPLAY, PATCH])
                death_raw = {
                    "attackers": [
                        {"participant_id": 6, "champion": "LeeSin", "network_id": participant_network_id(6),
                         "hit_count": 1, "damage_amount": 100, "first_hit_time_ms": 5_100,
                         "last_hit_time_ms": 5_100, "confidence": "VERIFIED_DERIVED"},
                        {"participant_id": 7, "champion": "Ahri", "network_id": participant_network_id(7),
                         "hit_count": 2, "damage_amount": 300, "first_hit_time_ms": 5_500,
                         "last_hit_time_ms": 9_900, "confidence": "VERIFIED_DERIVED"},
                    ]
                }
                con.execute("""
                    INSERT INTO adc_deaths
                    (fact_id,game_id,replay_sha256,patch,adc,adc_participant_id,support,
                     support_participant_id,death_time_ms,combat_start_ms,
                     combat_duration_ms,killer,decoder_profile,confidence,status,
                     raw_provenance_json)
                    VALUES ('death-1','1',?,?, 'Ashe',1,'Lulu',2,10000,5000,5000,
                            'Ahri','adc-v1','VERIFIED_DERIVED','DERIVED',?)
                """, [REPLAY, PATCH, json.dumps(death_raw)])
                for index, attacker in enumerate(death_raw["attackers"]):
                    con.execute("""
                        INSERT INTO adc_death_damage
                        (fact_id,game_id,replay_sha256,patch,adc_death_id,
                         attacker_participant_id,attacker_champion,attacker_network_id,
                         hit_count,damage_amount,first_hit_time_ms,last_hit_time_ms,
                         decoder_profile,confidence,status,raw_provenance_json)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, [
                        f"damage-{index}", "1", REPLAY, PATCH, "death-1",
                        attacker["participant_id"], attacker["champion"], attacker["network_id"],
                        attacker["hit_count"], attacker["damage_amount"],
                        attacker["first_hit_time_ms"], attacker["last_hit_time_ms"],
                        "adc-v1", "VERIFIED_DERIVED", "DERIVED", json.dumps(attacker),
                    ])

            result = materialize_research_layer(db, max_position_age_ms=500)
            self.assertEqual(result["table_counts"]["ward_research_events"], 1)
            self.assertEqual(result["table_counts"]["adc_death_position_context"], 4)
            self.assertEqual(result["table_counts"]["ward_death_context"], 4)
            with store.connect() as con:
                ward = con.execute("""
                    SELECT spawn_position_status,actual_x,actual_y,owner_champion,
                           enemy_jungler_champion,owner_position_source_age_ms
                    FROM ward_research_events
                """).fetchone()
                self.assertEqual(ward[:5], (
                    "ENTITY_SPAWN_DIRECT", 777.0, 888.0, "Ashe", "LeeSin"
                ))
                self.assertEqual(ward[5], 100)
                feature = con.execute("""
                    SELECT time_to_die_ms,attacker_count,largest_damage_attacker,
                           support_distance_death,enemy_count_death_900
                    FROM adc_death_features
                """).fetchone()
                self.assertEqual(feature, (5000, 2, "Ahri", 300.0, 1))
            status = research_status(db)
            self.assertEqual(status["ward"]["direct_position_count"], 1)
            self.assertEqual(status["positions"]["position_status"], "VERIFIED_DERIVED")
            status_path = write_research_status(db, Path(tmp) / "status.json")
            report_path = write_first_research_report(db, Path(tmp) / "report.md")
            self.assertTrue(status_path.is_file())
            self.assertIn("SANITY ONLY", report_path.read_text(encoding="utf-8"))
            publication = publish_all(db, max_position_age_ms=500)
            manifest_path = Path(publication["publication_manifest"])
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["database"]["sha256"], sha256_file(db))
            self.assertEqual(manifest["status"]["path"], "research_status.json")
            self.assertEqual(manifest["report"]["path"], "FIRST_RESEARCH_SANITY_REPORT.md")
            self.assertTrue(manifest["parquet"]["adc_death_features"]["size_bytes"] > 0)
            published_status = json.loads((db.parent / "research_status.json").read_text(encoding="utf-8"))
            self.assertEqual(published_status["database_sha256"], sha256_file(db))
            self.assertIn(sha256_file(db), (db.parent / "FIRST_RESEARCH_SANITY_REPORT.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
