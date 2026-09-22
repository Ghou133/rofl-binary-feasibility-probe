import json
from pathlib import Path
import sys
import unittest


RESEARCH_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = RESEARCH_ROOT.parent
sys.path.insert(0, str(RESEARCH_ROOT))

from combat_attribution import (  # noqa: E402
    ExactCastIndex,
    capability_status,
    enrich_damage_event,
    enrich_damage_events,
    protection_amounts_unavailable,
    resolve_spell_dictionary_entry,
)


REPLAY = "a" * 64
PROFILE = "rofl-16.15.801.3452-unit-apply-damage-unicorn-v1"


def damage(field_1c=100, field_20=5, field_21=0, timestamp=1_000,
           source=11, target=22):
    return {
        "replay_time_ms": timestamp,
        "source_network_id": source,
        "target_network_id": target,
        "source_champion": "Ashe",
        "decoder_profile": PROFILE,
        "raw_packet_ref": {"replay_sha256": REPLAY, "packet_id": 650},
        "protocol_fields": {
            "field_1c": field_1c,
            "field_20": field_20,
            "field_21": field_21,
        },
    }


def dictionary(script_name="AsheBasicAttack", slot=None, key=100):
    return {
        "patch": "16.15",
        "by_hash": {
            f"0x{key:08x}": [{
                "spell_key": key,
                "script_name": script_name,
                "champion_name": "Ashe",
                "spell_slot": slot,
                "phase": "ENGINE_CAST",
                "source": "COMMUNITYDRAGON_16_15_BIN",
            }],
        },
    }


def cast(timestamp=1_000, source=11, target=22, key=100,
         identifier="AsheBasicAttack"):
    return {
        "replay_time_ms": timestamp,
        "source_network_id": source,
        "spell_key": key,
        "spell_identifier": identifier,
        "spell_slot": None,
        "targets": [{"network_id": target}],
        "raw_packet_ref": {"replay_sha256": REPLAY, "packet_id": 1113},
        "player_cast_group_id": "cast-1",
    }


class CombatAttributionTests(unittest.TestCase):
    def test_damage_type_mapping_is_direct_and_unknown_code_is_not_guessed(self):
        names = []
        for code in (0, 1, 2):
            row = enrich_damage_event(damage(field_21=code))
            names.append(row["damage_type"])
            self.assertEqual(row["damage_type_status"], "VERIFIED_DIRECT")
        self.assertEqual(names, ["physical", "magic", "true"])

        unknown = enrich_damage_event(damage(field_21=9))
        self.assertIsNone(unknown["damage_type"])
        self.assertEqual(unknown["damage_type_status"], "NOT_PROVEN")

    def test_dictionary_attribution_and_basic_attack_are_true_only(self):
        source = damage(field_20=5, field_21=0)
        row = enrich_damage_event(source, dictionary())
        self.assertIsNot(row, source)
        self.assertEqual(row["spell"], "AsheBasicAttack")
        self.assertEqual(row["spell_attribution_status"], "VERIFIED_DERIVED")
        self.assertIs(row["is_basic_attack"], True)
        self.assertIsNone(row["is_critical"])

        ability = enrich_damage_event(
            damage(field_1c=200, field_20=5, field_21=1),
            dictionary("AsheVolley", "W", 200),
        )
        self.assertEqual(ability["spell"], "AsheVolley")
        self.assertIsNone(ability["is_basic_attack"])

        internal_child = dictionary("FizzWBasicAttack", "W")
        internal_child["by_hash"]["0x00000064"][0]["phase"] = "INTERNAL_CHILD"
        child = enrich_damage_event(source, internal_child)
        self.assertEqual(child["spell"], "FizzWBasicAttack")
        self.assertIsNone(child["is_basic_attack"])
        self.assertEqual(child["basic_attack_status"], "UNAVAILABLE")

    def test_critical_code_is_positive_only(self):
        critical = enrich_damage_event(
            damage(field_20=3), dictionary("AsheCritAttack")
        )
        self.assertIs(critical["is_critical"], True)
        self.assertEqual(critical["critical_status"], "VERIFIED_DERIVED")

        unmapped = enrich_damage_event(damage(field_20=4), dictionary())
        self.assertIsNone(unmapped["is_critical"])
        self.assertEqual(unmapped["critical_status"], "UNAVAILABLE")

    def test_exact_cast_match_rejects_nearest_wrong_target_and_duplicates(self):
        event = damage()
        index = ExactCastIndex([
            cast(timestamp=999),
            cast(timestamp=1_000, target=23),
        ])
        self.assertIsNone(index.match(event))

        exact = ExactCastIndex([cast()])
        self.assertEqual(exact.match(event)["player_cast_group_id"], "cast-1")

        duplicate = ExactCastIndex([cast(), cast()])
        self.assertIsNone(duplicate.match(event))

    def test_exact_cast_fallback_requires_full_identity(self):
        row = enrich_damage_events(
            [damage(field_1c=777)],
            [cast(key=777, identifier="StrictIdentitySpell")],
            {},
        )[0]
        self.assertEqual(row["spell"], "StrictIdentitySpell")
        self.assertEqual(
            row["spell_attribution_method"],
            "EXACT_REPLAY_TIME_SOURCE_TARGET_AND_SPELL_KEY",
        )

        rejected = enrich_damage_events(
            [damage(field_1c=777)],
            [cast(timestamp=999, key=777, identifier="NearestSpell")],
            {},
        )[0]
        self.assertIsNone(rejected["spell"])

    def test_dictionary_collision_and_new_patch_remain_unavailable(self):
        collision = dictionary()
        collision["by_hash"]["0x00000064"].append({
            "spell_key": 100,
            "script_name": "OtherBasicAttack",
            "champion_name": "Other",
        })
        # Champion metadata safely disambiguates this collision.
        resolved = resolve_spell_dictionary_entry(100, collision, "Ashe")
        self.assertEqual(resolved["script_name"], "AsheBasicAttack")
        self.assertIsNone(resolve_spell_dictionary_entry(100, collision))

        unsupported = damage()
        unsupported["patch"] = "16.16.1.1"
        row = enrich_damage_event(unsupported, dictionary())
        self.assertIsNone(row["damage_type"])
        self.assertEqual(row["damage_type_status"], "UNSUPPORTED_REPLAY_VERSION")

        wrong_dictionary_patch = dictionary()
        wrong_dictionary_patch["patch"] = "16.16"
        row = enrich_damage_event(damage(), wrong_dictionary_patch)
        self.assertIsNone(row["spell"])
        self.assertEqual(row["spell_attribution_status"], "UNAVAILABLE")

    def test_protection_amounts_stay_null_and_not_theoretical(self):
        row = protection_amounts_unavailable()
        self.assertEqual(row["protection_amount_status"], "UNAVAILABLE")
        self.assertFalse(row["theoretical_model_used"])
        for key in (
            "shield_generated_amount", "shield_absorbed_amount",
            "heal_actual_amount", "temporary_hp_amount",
        ):
            self.assertIsNone(row[key])
        self.assertEqual(capability_status()["heal_actual"]["status"], "UNAVAILABLE")

    @unittest.skipUnless(
        (PROJECT_ROOT / "artifacts" / "review_bundle" / "oracle" / "sgp-details.json").exists()
        and (PROJECT_ROOT / "artifacts" / "final_run" / "replays"
             / "HN1-11177593199" / "damage_events.jsonl").exists(),
        "full frozen holdout artifacts are not in this package",
    )
    def test_frozen_holdout_damage_type_totals_match_oracle(self):
        oracle_path = (
            PROJECT_ROOT / "artifacts" / "review_bundle" / "oracle"
            / "sgp-details.json"
        )
        damage_path = (
            PROJECT_ROOT / "artifacts" / "final_run" / "replays"
            / "HN1-11177593199" / "damage_events.jsonl"
        )
        oracle = json.loads(oracle_path.read_text(encoding="utf-8"))["json"]
        final_frames = oracle["frames"][-1]["participantFrames"]
        decoded = {str(participant_id): [0.0, 0.0, 0.0]
                   for participant_id in range(1, 11)}
        with damage_path.open("r", encoding="utf-8") as stream:
            for line in stream:
                event = json.loads(line)
                participant_id = str(event["source_participant_id"])
                code = event["protocol_fields"]["field_21"]
                decoded[participant_id][code] += event["amount"]

        oracle_keys = (
            "physicalDamageDoneToChampions",
            "magicDamageDoneToChampions",
            "trueDamageDoneToChampions",
        )
        for participant_id, values in decoded.items():
            stats = final_frames[participant_id]["damageStats"]
            for code, key in enumerate(oracle_keys):
                # Details stores integer totals; replay damage preserves f32.
                self.assertLess(abs(values[code] - stats[key]), 1.1)


if __name__ == "__main__":
    unittest.main()
