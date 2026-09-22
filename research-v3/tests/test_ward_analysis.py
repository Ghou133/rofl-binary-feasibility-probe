import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "ward_analysis.py"
SPEC = importlib.util.spec_from_file_location("ward_analysis", MODULE_PATH)
ward = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(ward)


def rows():
    return [
        {"game_id": "one", "timestamp_ms": 30_000, "minute": 0.5, "ward_network_id": 1, "ward_type": "YELLOW_OR_SIGHT_WARD", "owner_participant": 1, "owner_champion": "Lulu", "owner_role": "support", "owner_team": 100, "enemy_jungler_champion": "LeeSin", "actual_x": 100.0, "actual_y": 100.0, "height": 4, "spawn_position_status": "VERIFIED_DIRECT", "map_region": None},
        {"game_id": "one", "timestamp_ms": 90_000, "minute": 1.5, "ward_network_id": 2, "ward_type": "CONTROL_WARD", "owner_participant": 6, "owner_champion": "Ahri", "owner_role": "mid", "owner_team": 200, "enemy_jungler_champion": "Viego", "actual_x": 150.0, "actual_y": 150.0, "height": 5, "spawn_position_status": "VERIFIED_DIRECT", "map_region": None},
        {"game_id": "one", "timestamp_ms": 150_000, "minute": 2.5, "ward_network_id": 3, "ward_type": "FARSIGHT_WARD", "owner_participant": 2, "owner_champion": "Jinx", "owner_role": "adc", "owner_team": 100, "enemy_jungler_champion": "LeeSin", "actual_x": 2200.0, "actual_y": 2200.0, "height": 6, "spawn_position_status": "VERIFIED_DIRECT", "map_region": None},
    ]


class WardResearchTests(unittest.TestCase):
    def test_filters_compose_and_do_not_mutate_source(self):
        source = rows()
        result = ward.filter_ward_rows(source, {"team": "ally", "viewer_team": 100, "role": "support", "champion": "lulu", "ward_type": "yellow_or_sight_ward", "min_minute": 0, "max_minute": 1})
        self.assertEqual([row["ward_network_id"] for row in result], [1])
        self.assertEqual(source[0]["actual_x"], 100.0)
        self.assertEqual(ward.row_perspective(source[1], 100), "enemy")

    def test_cli_ward_type_alias_and_enemy_jungler_filter(self):
        selected = ward.filter_ward_rows(rows(), {
            "ward_type": "yellow", "enemy_jungler": "leesin"
        })
        self.assertEqual([row["ward_network_id"] for row in selected], [1])

    def test_no_castspell_coordinate_substitution(self):
        cast_only = {"event_type": "ward_cast", "cast_target_x": 9999, "cast_target_y": 8888, "actual_x": None, "actual_y": None, "spawn_position_status": "UNAVAILABLE"}
        self.assertIsNone(ward.wardspawn_coordinates(cast_only))
        analysis = ward.analyze_ward_rows([cast_only], cell_size=100)
        self.assertEqual(analysis["spatial_row_count"], 0)
        self.assertEqual(analysis["grid"], [])

    def test_grid_and_deterministic_hotspots(self):
        analysis = ward.analyze_ward_rows(rows(), cell_size=1000, hotspot_radius_cells=1)
        self.assertEqual([(cell["cell_x_index"], cell["cell_y_index"], cell["count"]) for cell in analysis["grid"]], [(0, 0, 2), (2, 2, 1)])
        self.assertEqual([item["count"] for item in analysis["hotspots"]], [2, 1])
        self.assertEqual(analysis["hotspots"][0]["center"], {"x": 125.0, "y": 125.0})
        self.assertEqual(analysis["hotspots"][0]["team_distribution"], {"100": 1, "200": 1})
        self.assertEqual(analysis["hotspots"][0]["minute_distribution"], {"0": 1, "1": 1})

    def test_local_density_hotspots_split_connected_chain_without_overlap(self):
        chain = [
            {
                "ward_network_id": index,
                "ward_type": "CONTROL_WARD" if index % 2 else "YELLOW_OR_SIGHT_WARD",
                "owner_role": "support" if index % 2 else "mid",
                "owner_team": 100 if index % 2 else 200,
                "minute": float(index),
                "actual_x": index * 100.0 + 50.0,
                "actual_y": 50.0,
                "spawn_position_status": "VERIFIED_DIRECT",
            }
            for index in range(13)
        ]
        hotspots = ward.cluster_hotspots(chain, cell_size=100, radius_cells=1)

        self.assertEqual(hotspots, ward.cluster_hotspots(reversed(chain), cell_size=100, radius_cells=1))
        self.assertGreater(len(hotspots), 1)
        self.assertLess(max(hotspot["count"] for hotspot in hotspots), len(chain) / 2)
        assigned_cells = [
            (cell["cell_x_index"], cell["cell_y_index"])
            for hotspot in hotspots
            for cell in hotspot["cells"]
        ]
        self.assertEqual(set(assigned_cells), {(index, 0) for index in range(13)})
        self.assertEqual(len(assigned_cells), len(set(assigned_cells)))
        self.assertEqual(sum(hotspot["count"] for hotspot in hotspots), len(chain))
        self.assertAlmostEqual(sum(hotspot["percentage"] for hotspot in hotspots), 100.0)
        for distribution in ("ward_type_distribution", "minute_distribution", "time_distribution", "role_distribution", "team_distribution"):
            self.assertEqual(sum(sum(hotspot[distribution].values()) for hotspot in hotspots), len(chain))

    def test_polygon_boundaries_are_inclusive_and_region_labels_are_additive(self):
        polygon = [[0, 0], [10, 0], [10, 10], [0, 10]]
        self.assertTrue(ward.point_in_polygon(0, 5, polygon))
        self.assertTrue(ward.point_in_polygon(10, 10, polygon))
        self.assertFalse(ward.point_in_polygon(10.1, 5, polygon))
        region_map = {"schema_version": 1, "regions": [{"id": "edge", "priority": 1, "polygon": polygon, "bounds": {"x_min": 0, "x_max": 10, "y_min": 0, "y_max": 10}}]}
        source = rows()[:1]
        source[0]["actual_x"], source[0]["actual_y"] = 0, 5
        annotated = ward.assign_regions(source, region_map)
        self.assertEqual(annotated[0]["map_region"], "edge")
        self.assertEqual((annotated[0]["actual_x"], annotated[0]["actual_y"]), (0, 5))

    def test_duckdb_query_and_csv_parquet_exports(self):
        import duckdb
        connection = duckdb.connect()
        connection.execute("CREATE TABLE ward_research_events (game_id VARCHAR, timestamp_ms BIGINT, minute DOUBLE, ward_network_id BIGINT, ward_type VARCHAR, owner_participant BIGINT, owner_champion VARCHAR, owner_role VARCHAR, owner_team BIGINT, enemy_jungler_champion VARCHAR, actual_x DOUBLE, actual_y DOUBLE, height DOUBLE, spawn_position_status VARCHAR)")
        connection.executemany("INSERT INTO ward_research_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [[row.get(key) for key in ["game_id", "timestamp_ms", "minute", "ward_network_id", "ward_type", "owner_participant", "owner_champion", "owner_role", "owner_team", "enemy_jungler_champion", "actual_x", "actual_y", "height", "spawn_position_status"]] for row in rows()])
        selected = ward.query_ward_rows(connection, filters={"team": 100, "min_minute": 0, "max_minute": 2})
        self.assertEqual([row["ward_network_id"] for row in selected], [1])
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            csv_path = ward.write_query_output(selected, base / "wards.csv")
            parquet_path = ward.write_query_output(selected, base / "wards.parquet")
            with csv_path.open(newline="", encoding="utf-8") as handle:
                self.assertEqual(list(csv.DictReader(handle))[0]["ward_network_id"], "1")
            self.assertEqual(connection.execute("SELECT count(*) FROM read_parquet(?)", [str(parquet_path)]).fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
