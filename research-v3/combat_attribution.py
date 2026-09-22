"""Evidence-bounded combat enrichment for replay patch 16.15.801.3452.

The source damage packet remains the authority for timestamp, source, target,
amount, and the raw protocol fields.  This module adds only interpretations
that have an explicit replay/runtime evidence path.  It never uses Match
Details as a decoder input and never performs nearest-cast attribution.
"""

from __future__ import annotations

from collections import defaultdict
import json
from pathlib import Path
import re


SUPPORTED_PATCH = "16.15.801.3452"
SUPPORTED_DICTIONARY_PATCHES = frozenset(("16.15", SUPPORTED_PATCH))

# Exact UnitApplyDamage object field +0x21.  The mapping is independently
# checked against the frozen holdout's per-participant damage-type totals.
DAMAGE_TYPE_BY_CODE = {
    0: "physical",
    1: "magic",
    2: "true",
}

# Exact UnitApplyDamage object field +0x20.  The current client consumer's
# result jump table sends code 3 to the physical/magic/true critical float-text
# branch.  Other codes remain unclassified because the complete current-build
# DamageResultType enum has not been recovered.
CRITICAL_RESULT_CODE = 3

_BASIC_ATTACK_NAME = re.compile(r"(?:basicattack|critattack)", re.IGNORECASE)
_CRITICAL_ATTACK_NAME = re.compile(r"critattack", re.IGNORECASE)

PROTECTION_AMOUNT_FIELDS = (
    "shield_generated_amount",
    "shield_absorbed_amount",
    "heal_actual_amount",
    "temporary_hp_amount",
)


def load_spell_dictionary(path):
    """Load the fixed 16.15 CommunityDragon/ELF-hash dictionary."""
    with Path(path).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def _protocol_fields(event):
    value = event.get("protocol_fields")
    return value if isinstance(value, dict) else {}


def _replay_identity(event):
    raw_ref = event.get("raw_packet_ref")
    raw_ref = raw_ref if isinstance(raw_ref, dict) else {}
    return (
        event.get("replay_sha256")
        or raw_ref.get("replay_sha256")
        or event.get("game_id")
        or event.get("match_id")
    )


def _is_supported_event(event):
    patch = event.get("patch")
    if patch is not None:
        return patch == SUPPORTED_PATCH
    profile = event.get("decoder_profile") or ""
    return SUPPORTED_PATCH in profile


def _dictionary_map(spell_dictionary):
    if not isinstance(spell_dictionary, dict):
        return {}
    value = spell_dictionary.get("by_hash", spell_dictionary)
    return value if isinstance(value, dict) else {}


def _dictionary_is_supported(spell_dictionary):
    return (
        isinstance(spell_dictionary, dict)
        and spell_dictionary.get("patch") in SUPPORTED_DICTIONARY_PATCHES
    )


def _candidate_list(value):
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    return []


def _normalized_name(value):
    if not isinstance(value, str):
        return None
    return re.sub(r"[^a-z0-9]", "", value.lower())


def resolve_spell_dictionary_entry(spell_key, spell_dictionary,
                                   source_champion=None):
    """Resolve a damage spell key only when the dictionary result is unique.

    A collision is not guessed.  Champion metadata may disambiguate a real
    collision, but generic and conflicting candidates remain unavailable.
    """
    if not isinstance(spell_key, int) or isinstance(spell_key, bool):
        return None
    candidates = _candidate_list(
        _dictionary_map(spell_dictionary).get(f"0x{spell_key:08x}")
    )
    if len(candidates) == 1:
        return dict(candidates[0])
    if not candidates:
        return None

    champion = _normalized_name(source_champion)
    if champion:
        matches = []
        for candidate in candidates:
            names = {
                _normalized_name(candidate.get("champion_name")),
                _normalized_name(candidate.get("champion_alias")),
            }
            if champion in names:
                matches.append(candidate)
        if len(matches) == 1:
            return dict(matches[0])
    return None


def is_explicit_basic_attack_script(script_name):
    """Return True only for an explicitly named basic/critical attack script."""
    return bool(isinstance(script_name, str) and _BASIC_ATTACK_NAME.search(script_name))


def is_explicit_critical_attack_script(script_name):
    return bool(
        isinstance(script_name, str) and _CRITICAL_ATTACK_NAME.search(script_name)
    )


def is_verified_basic_attack_entry(entry):
    """Accept only a unique, explicit engine-cast attack script identity.

    Internal child scripts can be caused by a basic attack without proving
    that the individual damage row is the attack itself, so they remain NULL.
    """
    return bool(
        isinstance(entry, dict)
        and entry.get("phase") == "ENGINE_CAST"
        and is_explicit_basic_attack_script(entry.get("script_name"))
    )


class ExactCastIndex:
    """Index casts for identity joins, never for nearest-event matching.

    A match requires exact replay, millisecond timestamp, source network ID,
    spell key, and target network ID, followed by a uniqueness check.
    """

    def __init__(self, spell_events):
        grouped = defaultdict(list)
        for event in spell_events or ():
            timestamp_ms = event.get("replay_time_ms", event.get("timestamp_ms"))
            source_network_id = event.get(
                "source_network_id", event.get("caster_network_id")
            )
            spell_key = event.get("spell_key")
            if not all(isinstance(value, int) and not isinstance(value, bool)
                       for value in (timestamp_ms, source_network_id, spell_key)):
                continue
            grouped[
                (_replay_identity(event), timestamp_ms, source_network_id, spell_key)
            ].append(event)
        self._events = grouped

    @staticmethod
    def _target_ids(event):
        targets = event.get("targets")
        if not isinstance(targets, list):
            return set()
        return {
            row.get("network_id")
            for row in targets
            if isinstance(row, dict) and isinstance(row.get("network_id"), int)
        }

    def match(self, damage_event):
        fields = _protocol_fields(damage_event)
        timestamp_ms = damage_event.get(
            "replay_time_ms", damage_event.get("timestamp_ms")
        )
        source_network_id = damage_event.get("source_network_id")
        target_network_id = damage_event.get("target_network_id")
        spell_key = fields.get("field_1c")
        if not all(isinstance(value, int) and not isinstance(value, bool) for value in (
            timestamp_ms, source_network_id, target_network_id, spell_key
        )):
            return None
        candidates = self._events.get((
            _replay_identity(damage_event),
            timestamp_ms,
            source_network_id,
            spell_key,
        ), ())
        candidates = [
            event for event in candidates
            if target_network_id in self._target_ids(event)
        ]
        return candidates[0] if len(candidates) == 1 else None


def protection_amounts_unavailable():
    """Return the only currently valid observed-amount representation."""
    result = {field: None for field in PROTECTION_AMOUNT_FIELDS}
    result.update({
        "protection_amount_status": "UNAVAILABLE",
        "protection_amount_method": "NO_VERIFIED_REPLAY_AMOUNT_FIELD",
        "theoretical_model_used": False,
    })
    return result


def enrich_damage_event(event, spell_dictionary=None, exact_cast_index=None):
    """Return a copy of one damage event with conservative V3 enrichments."""
    output = dict(event)
    field_confidence = dict(output.get("field_confidence") or {})
    fields = _protocol_fields(event)

    if not _is_supported_event(event):
        output.update({
            "damage_type": None,
            "damage_type_code": fields.get("field_21"),
            "damage_type_status": "UNSUPPORTED_REPLAY_VERSION",
            "spell": None,
            "spell_identifier": None,
            "spell_slot": None,
            "spell_attribution_status": "UNSUPPORTED_REPLAY_VERSION",
            "is_basic_attack": None,
            "basic_attack_status": "UNSUPPORTED_REPLAY_VERSION",
            "is_critical": None,
            "critical_status": "UNSUPPORTED_REPLAY_VERSION",
        })
        output["field_confidence"] = field_confidence
        return output

    damage_type_code = fields.get("field_21")
    damage_type = DAMAGE_TYPE_BY_CODE.get(damage_type_code)
    output["damage_type_code"] = damage_type_code
    output["damage_type"] = damage_type
    output["damage_type_status"] = (
        "VERIFIED_DIRECT" if damage_type is not None else "NOT_PROVEN"
    )
    output["damage_type_method"] = (
        "UNIT_APPLY_DAMAGE_FIELD_21"
        if damage_type is not None else "NO_CURRENT_MAPPING"
    )
    field_confidence["damage_type"] = output["damage_type_status"]

    damage_spell_key = fields.get("field_1c")
    output["damage_spell_key"] = damage_spell_key
    output["damage_spell_key_hex"] = (
        f"0x{damage_spell_key:08x}"
        if isinstance(damage_spell_key, int) and not isinstance(damage_spell_key, bool)
        else None
    )
    if isinstance(damage_spell_key, int) and not isinstance(damage_spell_key, bool):
        field_confidence["damage_spell_key"] = "VERIFIED_DIRECT"

    dictionary_entry = None
    if _dictionary_is_supported(spell_dictionary):
        dictionary_entry = resolve_spell_dictionary_entry(
            damage_spell_key,
            spell_dictionary,
            event.get("source_champion"),
        )
    matched_cast = exact_cast_index.match(event) if exact_cast_index else None

    if dictionary_entry:
        output["spell"] = dictionary_entry.get("script_name")
        output["spell_identifier"] = dictionary_entry.get("script_name")
        output["spell_slot"] = dictionary_entry.get("spell_slot")
        output["spell_phase"] = dictionary_entry.get("phase")
        output["spell_dictionary_source"] = dictionary_entry.get("source")
        output["spell_attribution_status"] = "VERIFIED_DERIVED"
        output["spell_attribution_method"] = (
            "DAMAGE_FIELD_1C_UNIQUE_16_15_DICTIONARY"
        )
    elif matched_cast and matched_cast.get("spell_identifier"):
        output["spell"] = matched_cast.get("spell_identifier")
        output["spell_identifier"] = matched_cast.get("spell_identifier")
        output["spell_slot"] = matched_cast.get("spell_slot")
        output["spell_phase"] = matched_cast.get("spell_phase")
        output["spell_dictionary_source"] = matched_cast.get(
            "spell_dictionary_source"
        )
        output["spell_attribution_status"] = "VERIFIED_DERIVED"
        output["spell_attribution_method"] = (
            "EXACT_REPLAY_TIME_SOURCE_TARGET_AND_SPELL_KEY"
        )
    else:
        output["spell"] = None
        output["spell_identifier"] = None
        output["spell_slot"] = None
        output["spell_phase"] = None
        output["spell_dictionary_source"] = None
        output["spell_attribution_status"] = "UNAVAILABLE"
        output["spell_attribution_method"] = "NO_UNIQUE_IDENTITY_MAPPING"

    if matched_cast:
        output["matched_cast_group_id"] = matched_cast.get("player_cast_group_id")
        output["matched_cast_raw_packet_ref"] = matched_cast.get("raw_packet_ref")
        output["exact_cast_identity_status"] = "VERIFIED_DERIVED"
    else:
        output["matched_cast_group_id"] = None
        output["matched_cast_raw_packet_ref"] = None
        output["exact_cast_identity_status"] = "UNAVAILABLE"

    if output["spell_attribution_status"] == "VERIFIED_DERIVED":
        field_confidence["spell"] = "VERIFIED_DERIVED"
        field_confidence["spell_slot"] = (
            "VERIFIED_DERIVED" if output.get("spell_slot") is not None
            else "UNAVAILABLE"
        )
    else:
        field_confidence["spell"] = "UNAVAILABLE"
        field_confidence["spell_slot"] = "UNAVAILABLE"

    if is_verified_basic_attack_entry(dictionary_entry):
        output["is_basic_attack"] = True
        output["basic_attack_status"] = "VERIFIED_DERIVED"
        output["basic_attack_method"] = (
            "UNIQUE_EXPLICIT_ENGINE_CAST_BASIC_OR_CRIT_ATTACK_SCRIPT"
        )
        field_confidence["is_basic_attack"] = "VERIFIED_DERIVED"
    else:
        # Absence of an explicit attack name is not evidence of False.
        output["is_basic_attack"] = None
        output["basic_attack_status"] = "UNAVAILABLE"
        output["basic_attack_method"] = "NO_EXPLICIT_ATTACK_IDENTITY"
        field_confidence["is_basic_attack"] = "UNAVAILABLE"

    damage_result_code = fields.get("field_20")
    output["damage_result_code"] = damage_result_code
    if damage_result_code == CRITICAL_RESULT_CODE:
        output["is_critical"] = True
        output["critical_status"] = "VERIFIED_DERIVED"
        output["critical_method"] = (
            "UNIT_APPLY_DAMAGE_FIELD_20_CODE_3_CURRENT_CLIENT_CRITICAL_BRANCH"
        )
        field_confidence["is_critical"] = "VERIFIED_DERIVED"
    else:
        # The remaining current-build result codes are deliberately not mapped
        # to False until the complete enum is independently recovered.
        output["is_critical"] = None
        output["critical_status"] = "UNAVAILABLE"
        output["critical_method"] = "NONCRITICAL_CODES_NOT_FULLY_MAPPED"
        field_confidence["is_critical"] = "UNAVAILABLE"

    output["field_confidence"] = field_confidence
    return output


def enrich_damage_events(damage_events, spell_events=(), spell_dictionary=None):
    """Enrich a replay/batch while retaining exact-cast uniqueness rules."""
    exact_cast_index = ExactCastIndex(spell_events)
    return [
        enrich_damage_event(event, spell_dictionary, exact_cast_index)
        for event in damage_events
    ]


def capability_status():
    """Machine-readable status used by V3 status/report generation."""
    return {
        "damage_type": {
            "status": "VERIFIED_DIRECT",
            "method": "UnitApplyDamage field_21: 0 physical, 1 magic, 2 true",
        },
        "spell_attribution": {
            "status": "VERIFIED_DERIVED_PARTIAL",
            "method": "field_1c unique 16.15 dictionary; exact cast identity optional",
        },
        "basic_attack": {
            "status": "VERIFIED_DERIVED_PARTIAL_TRUE_ONLY",
            "method": "unique explicit ENGINE_CAST BasicAttack/CritAttack identity",
        },
        "critical": {
            "status": "VERIFIED_DERIVED_PARTIAL_TRUE_ONLY",
            "method": (
                "field_20 code 3 current-client critical float-text branch; "
                "other codes remain NULL"
            ),
        },
        "shield_generated": {"status": "UNAVAILABLE", "amount": None},
        "shield_absorbed": {"status": "UNAVAILABLE", "amount": None},
        "heal_actual": {"status": "UNAVAILABLE", "amount": None},
        "temporary_hp": {"status": "UNAVAILABLE", "amount": None},
    }
