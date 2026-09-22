import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from position_context import (  # noqa: E402
    PositionIndex,
    build_adc_death_position_context,
    build_ward_death_context,
    build_ward_position_context,
    participant_id_from_network_id,
    participant_network_id,
)


REPLAY = "a" * 64


def participants():
    return [
        {"replay_sha256": REPLAY, "participant_id": 1, "team_id": 100,
         "role": "adc", "champion": "Ashe"},
        {"replay_sha256": REPLAY, "participant_id": 2, "team_id": 100,
         "role": "support", "champion": "Lulu"},
        {"replay_sha256": REPLAY, "participant_id": 6, "team_id": 200,
         "role": "jungle", "champion": "LeeSin"},
        {"replay_sha256": REPLAY, "participant_id": 7, "team_id": 200,
         "role": "mid", "champion": "Ahri"},
    ]


def position(participant_id, timestamp, source_timestamp, x, y):
    return {
        "replay_sha256": REPLAY,
        "entity_id": participant_network_id(participant_id),
        "timestamp_ms": timestamp,
        "source_path_timestamp_ms": source_timestamp,
        "position_xz": [x, y],
        "coordinate_transform_status": "VERIFIED_CURRENT_CALIBRATION",
        "raw_packet_ref": {"packet_id": 721, "raw_payload_sha256": "b" * 64},
    }


class PositionContextTests(unittest.TestCase):
    def test_network_id_mapping_is_exact(self):
        self.assertEqual(participant_network_id(1), 0x400000AE)
        self.assertEqual(participant_id_from_network_id(0x400000B7), 10)
        self.assertIsNone(participant_id_from_network_id(0))

    def test_lookup_never_looks_ahead_and_marks_stale_source(self):
        index = PositionIndex([
            position(1, 1_000, 900, 10, 10),
            position(1, 2_000, 1_100, 20, 20),
        ])
        selected = index.lookup(REPLAY, participant_network_id(1), 1_500, 500)
        self.assertEqual(selected["x"], 10)
        self.assertEqual(selected["source_age_ms"], 600)
        self.assertFalse(selected["usable"])
        self.assertEqual(selected["position_status"], "VERIFIED_DERIVED")

    def test_adc_context_counts_and_features(self):
        rows = []
        for checkpoint in (5_000, 8_000, 9_000, 10_000):
            rows.extend([
                position(1, checkpoint, checkpoint - 100, 0, 0),
                position(2, checkpoint, checkpoint - 100, 300, 0),
                position(6, checkpoint, checkpoint - 100, 700, 0),
                position(7, checkpoint, checkpoint - 100, 1_500, 0),
            ])
        deaths = [{
            "game_id": "1", "replay_sha256": REPLAY, "patch": "16.15.801.3452",
            "adc_participant_id": 1, "death_time_ms": 10_000, "combat_start_ms": 5_000,
            "attackers": [
                {"participant_id": 6, "damage_amount": 100, "first_hit_time_ms": 5_100},
                {"participant_id": 7, "damage_amount": 300, "first_hit_time_ms": 5_500},
            ],
        }]
        contexts, features = build_adc_death_position_context(
            deaths, participants(), rows, max_position_age_ms=500
        )
        self.assertEqual(len(contexts), 4)
        death = next(row for row in contexts if row["checkpoint"] == "death")
        self.assertEqual(death["support_distance"], 300)
        self.assertEqual(death["enemy_count_within_900"], 1)
        self.assertEqual(features[0]["largest_damage_attacker_participant_id"], 7)
        self.assertEqual(features[0]["time_to_die_ms"], 5_000)

    def test_ward_context_uses_actual_coordinates_and_owner_join(self):
        rows = [
            position(1, 1_000, 900, 100, 100),
            position(2, 1_000, 900, 120, 100),
            position(6, 1_000, 900, 500, 100),
        ]
        wards = [{
            "replay_sha256": REPLAY, "replay_time_ms": 1_000,
            "ward_network_id": 99, "owner_network_id": participant_network_id(1),
            "position": {"x": 777, "y": 888},
        }]
        result = build_ward_position_context(wards, participants(), rows, 500)
        self.assertEqual(result[0]["owner_participant_id"], 1)
        self.assertEqual(result[0]["owner_position"]["x"], 100)
        self.assertEqual(result[0]["distance_reference"], "WARD_ACTUAL_POSITION")
        self.assertAlmostEqual(result[0]["nearest_enemy_distance"], 835.2682203939044)

    def test_ward_death_context_separates_confirmed_and_uncertain(self):
        rows = [
            position(1, 9_000, 8_900, 0, 0),
            position(6, 9_000, 8_900, 1_000, 0),
        ]
        deaths = [{
            "game_id": "1", "replay_sha256": REPLAY,
            "adc_participant_id": 1, "death_time_ms": 10_000,
        }]
        wards = [
            {"replay_sha256": REPLAY, "ward_network_id": 1, "spawn_time_ms": 1_000,
             "owner_team_id": 100, "actual_x": 100, "actual_y": 0},
            {"replay_sha256": REPLAY, "ward_network_id": 2, "spawn_time_ms": 1_000,
             "owner_team_id": 200, "actual_x": 200, "actual_y": 0},
        ]
        lifecycles = [{
            "replay_sha256": REPLAY, "ward_network_id": 1,
            "spawn_time_ms": 1_000, "remove_time_ms": 20_000,
        }]
        result = build_ward_death_context(
            deaths, participants(), rows, wards, lifecycles,
            max_position_age_ms=500, offsets_ms=(1_000,),
        )
        self.assertEqual(result[0]["nearby_allied_wards"], 1)
        self.assertEqual(result[0]["nearby_enemy_wards"], 0)
        self.assertEqual(result[0]["nearby_enemy_wards_uncertain"], 1)
        self.assertEqual(result[0]["gank_corridor_status"], "VERIFIED_DERIVED_GEOMETRY")
        self.assertEqual(result[0]["allied_ward_gank_corridor_count"], 1)


if __name__ == "__main__":
    unittest.main()
