import hashlib
import collections
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import analyze_entity_item_deep_recovery_v2 as recovery


class EntityItemDeepRecoveryPureTests(unittest.TestCase):
    def test_participant_transform(self):
        self.assertEqual(recovery.participant_id(0x400000AE), 1)
        self.assertEqual(recovery.participant_id(0x400000B7), 10)

    def test_second_selector_transform_known_rows(self):
        self.assertEqual(recovery.decode_second_selector_byte(0xF1), 0)
        self.assertEqual(recovery.decode_second_selector_byte(0xC1), 2)
        self.assertEqual(recovery.decode_second_selector_u16(0xF1D6), 35)

    def test_route_key_location(self):
        self.assertEqual(
            recovery.route_key_location("11191024308:46:274437:274443:1203"),
            (46, 274437, 274443),
        )

    def test_stack_aware_undo_expected_delta(self):
        prior = collections.Counter({2003: 2})
        self.assertEqual(
            recovery.apply_undo_expected_delta(prior, 2003, 0),
            collections.Counter({2003: 1}),
        )

    def test_undo_directional_delta_allows_returned_recipe_components(self):
        prior = collections.Counter({4645: 1})
        incoming = collections.Counter({1058: 1, 3145: 1})
        self.assertTrue(
            recovery.undo_directional_delta_support(prior, incoming, 4645, 0)
        )
        self.assertNotEqual(
            recovery.apply_undo_expected_delta(prior, 4645, 0), incoming
        )

    def test_undo_directional_delta_rejects_3363_to_3340_alias_residual(self):
        prior = collections.Counter({3363: 1})
        incoming = collections.Counter({3340: 1})
        self.assertFalse(
            recovery.undo_directional_delta_support(prior, incoming, 0, 3363)
        )

    def test_snapshot_comparison_detects_stack_only_change(self):
        common = {
            "game_id": "g",
            "participant": 1,
            "phase": 1,
            "chunk": 1,
            "block": 1,
            "payload": 1,
            "source": {},
        }
        events = [
            {
                **common,
                "time": 1,
                "kind": "snapshot",
                "uid": "first",
                "slots": {0: {"item_id": 2003, "stack_count": 2}},
            },
            {
                **common,
                "time": 2,
                "kind": "snapshot",
                "uid": "second",
                "slots": {0: {"item_id": 2003, "stack_count": 1}},
            },
        ]
        summary, _, captures = recovery.simulate_inventory_state(events)
        self.assertEqual(summary["snapshot_comparison_counts"]["mismatch"], 1)
        self.assertEqual(captures["second"]["differing_slots"], [0])

    def test_protected_path_guard_rejects_without_access(self):
        with self.assertRaises(RuntimeError):
            recovery.reject_protected_path(
                Path("C:/never-access/Jungle Objective Holdout/secret.rofl")
            )


class EntityItemDeepRecoveryExactImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = recovery.IMAGE.read_bytes()
        if hashlib.sha256(cls.image).hexdigest() != recovery.IMAGE_SHA256:
            raise AssertionError("exact runtime image hash mismatch")
        cls.tables = recovery.build_helper_tables(cls.image)

    def test_first_selector_transform_known_swap_rows(self):
        self.assertEqual(recovery.decode_first_selector_byte(0x86, self.image), 1)
        self.assertEqual(recovery.decode_first_selector_byte(0x42, self.image), 0)

    def test_inline_inventory_record_decodes_known_anchor(self):
        row = {
            "decoded_fields": {
                "inventory_records_0x18": [
                    {
                        "item_id_encoded_u32_0x1c": 0x424267CD,
                        "slot_index_encoded_u8_0x22": 0xF1,
                        "stack_count_encoded_u8_0x78": 0x89,
                    }
                ]
            }
        }
        self.assertEqual(
            recovery.decode_snapshot(row, self.tables),
            {0: {"item_id": 1054, "stack_count": 1}},
        )

    def test_use_item_known_row_domains(self):
        row = {
            "decoded_fields": {
                "encoded_use_state_0x10": 0xC9,
                "encoded_item_value_0x12": 0x3F3F,
                "encoded_item_selector_0x14": 0x27,
            }
        }
        decoded = recovery.decode_use_item(row, self.tables)
        self.assertIn(decoded["selector"], range(10))
        self.assertIn(decoded["use_state"], (0, 1))
        self.assertIn(decoded["item_storage_value"], range(5))

    def test_shop_item_substitution_known_row(self):
        row = {
            "decoded_fields": {
                "encoded_substitution_source_u32_0x10": 0x42423C03,
                "encoded_substitution_target_u32_0x14": 0xF1F109A5,
            }
        }
        self.assertEqual(
            recovery.decode_shop_item_substitution(row, self.image),
            {"source_item_id": 2420, "target_item_id": 2421},
        )


if __name__ == "__main__":
    unittest.main()
