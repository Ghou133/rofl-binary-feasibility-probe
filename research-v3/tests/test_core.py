import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import ReplayStore, iter_jsonl  # noqa: E402


class CoreTests(unittest.TestCase):
    def test_schema_initializes_all_required_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ReplayStore(Path(tmp) / "test.duckdb")
            store.init()
            tables = set(store.status()["table_counts"])
            required = {
                "replays", "participants", "death_events", "damage_events", "spell_events",
                "buff_events", "ward_spawns", "ward_lifecycles", "hero_paths",
                "hero_positions_1s", "adc_deaths", "adc_death_damage",
                "adc_death_support_actions", "adc_death_position_context",
                "ward_position_context", "ward_research_events", "map_regions", "ward_heatmap_cells", "ward_hotspots",
                "adc_death_features", "ward_death_context", "ingest_runs", "ingest_rejections",
            }
            self.assertTrue(required <= tables)

    def test_jsonl_iterator_preserves_nulls_and_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text('{"a":null}\n{"a":2}\n', encoding="utf-8")
            stream = iter_jsonl(path)
            self.assertNotIsInstance(stream, list)
            self.assertEqual(next(stream), (1, {"a": None}))
            self.assertEqual(next(stream), (2, {"a": 2}))
            stream.close()

    def test_export_writes_nonempty_parquet(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ReplayStore(Path(tmp) / "test.duckdb")
            store.init()
            exports = store.export(["replays"], Path(tmp) / "parquet")
            self.assertGreater(Path(exports["replays"]).stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
