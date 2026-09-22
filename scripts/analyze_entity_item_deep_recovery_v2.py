#!/usr/bin/env python3
"""Exact-build Entity + Item/Economy deep-recovery evidence analysis.

This analyzer is deliberately closed over explicit, already-published safe inputs.
It never discovers replay files and rejects any path containing ``holdout``.
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from emulate_exact_packet_decoder import (  # noqa: E402
    ExactPacketEmulator,
    IMAGE_BASE,
    RUNTIME_PROFILES,
)


BUILD = "16.16.805.0442"
IMAGE_SHA256 = "0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55"
SAFE_REPLAYS = {
    "11191024308": "1ff3b2d4321bbe4f6bf79bff767305bbf4fa59e42c9524c91f3c3b9421733349",
    "11191203388": "e54e1950949761bb75df509bd91a6823c3d08569a1f530410cb38fb5e07e3633",
    "11191271422": "a5a5580f1a4546fb627b53cf3921a9cf0f3086f15964410e054809a87a3be399",
    "11191336852": "25dff9e58855cfc2afdca6b1df2cc43aaa2da1ddc9823b63993ecfc456eb0e75",
}

OUT_DIR = ROOT / "artifacts" / "full_semantic_deep_recovery_v2" / "entity_item"
IMAGE = ROOT / "artifacts" / "new_build_rofl_compatibility_gate_v1" / "runtime" / "league_16.16.805.0442.memory.bin"
OBSERVED_MAP = ROOT / "artifacts" / "hero_combat_state_v2" / "runtime" / "observed_packet_callback_route_map_16_16.json"
STATIC_TRACE = ROOT / "artifacts" / "hero_combat_state_v2" / "runtime" / "hero_combat_state_runtime_trace_16_16.json"
UNKNOWN_MINING = ROOT / "artifacts" / "full_semantic_deep_recovery_v2" / "unknown_mining" / "high_frequency_unknown_deep_mining.json"
SUPPORT_QUEST_AUDIT = ROOT / "artifacts" / "full_semantic_deep_recovery_v2" / "unknown_mining" / "route_0064_support_quest_audit.json"
SUPPORT_QUEST_AUDIT_SHA256 = "b5e3a5568b8760d4dee861d4b52c758d125b020132a5f08bad5634e0f9e99d75"
ITEM_BASE = ROOT / "artifacts" / "full_semantic_baseline_v1" / "runtime_candidates"
ITEM_ALIGNED = ITEM_BASE / "packet_0137_04b3_item_route_aligned_16_16.jsonl"
DETAILS_EVENTS = ITEM_BASE / "packet_0137_04b3_item_details_events_16_16.jsonl"
INVENTORY_MANIFEST = OUT_DIR / "hero_inventory_route_shape_sample_16_16.jsonl.manifest.json"

P006C = OUT_DIR / "packet_006c_native_decoded_16_16.jsonl"
P01E8 = OUT_DIR / "packet_01e8_native_decoded_16_16.jsonl"
P02EA = OUT_DIR / "packet_02ea_native_decoded_16_16.jsonl"
P0310 = OUT_DIR / "packet_0310_native_decoded_all_16_16.jsonl"
P0311 = OUT_DIR / "packet_0311_native_decoded_16_16.jsonl"
P0405_SAMPLE = OUT_DIR / "packet_0405_shape_native_decoded_16_16.jsonl"
P041B = OUT_DIR / "packet_041b_native_decoded_16_16.jsonl"
P005A = OUT_DIR / "packet_005a_native_decoded_16_16.jsonl"
P005A_PROFILE = OUT_DIR / "packet_005a_static_profile.json"
P005A_DECODE_SUMMARY = OUT_DIR / "packet_005a_native_decode_summary_16_16.json"

SUMMARY_OUT = OUT_DIR / "entity_item_deep_recovery_summary_16_16.json"
TAXONOMY_OUT = OUT_DIR / "entity_route_taxonomy_16_16.json"
ALIGNMENT_OUT = OUT_DIR / "entity_item_transition_alignment_16_16.jsonl"
REPORT_OUT = OUT_DIR / "ENTITY_ITEM_DEEP_RECOVERY_REPORT.md"
HASHES_OUT = OUT_DIR / "entity_item_deep_recovery_hashes_16_16.json"


def reject_protected_path(path: Path) -> None:
    if "holdout" in str(path).casefold():
        raise RuntimeError(f"protected Holdout path rejected without access: {path}")


def validate_explicit_paths(paths: Iterable[Path]) -> None:
    for path in paths:
        reject_protected_path(path)
        if not path.is_file():
            raise FileNotFoundError(path)


def load_json(path: Path) -> Any:
    reject_protected_path(path)
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def load_jsonl(path: Path, validate_replays: bool = True) -> list[dict[str, Any]]:
    reject_protected_path(path)
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if validate_replays and "replay_label" in row:
                validate_replay_row(row, path, line_number)
            rows.append(row)
    return rows


def validate_replay_row(row: dict[str, Any], path: Path, line_number: int) -> None:
    label = str(row.get("replay_label"))
    expected_sha = SAFE_REPLAYS.get(label)
    if expected_sha is None:
        raise RuntimeError(f"non-allowlisted replay at {path}:{line_number}: {label}")
    if row.get("replay_sha256") != expected_sha:
        raise RuntimeError(f"replay hash mismatch at {path}:{line_number}")
    if row.get("replay_version") != BUILD:
        raise RuntimeError(f"build mismatch at {path}:{line_number}")


def sha256_file(path: Path) -> str:
    reject_protected_path(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def line_count(path: Path) -> int:
    reject_protected_path(path)
    count = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            count += block.count(b"\n")
    return count


def participant_id(raw_param: int) -> int:
    return (int(raw_param) & 0xFF) - 0xAD


def rotate_right_8(value: int, bits: int) -> int:
    value &= 0xFF
    return ((value >> bits) | (value << (8 - bits))) & 0xFF


def decode_second_selector_byte(encoded: int) -> int:
    value = rotate_right_8((~encoded) & 0xFF, 1)
    value = (value + 0x7E) & 0xFF
    value ^= 0x28
    value = rotate_right_8(value, 2)
    return (value - 0x6B) & 0xFF


def decode_first_selector_byte(encoded: int, image: bytes) -> int:
    table_rva = 0x01A331A0
    index = (int(encoded) + 0x77) & 0xFF
    return (image[table_rva + index] + 0x2B) & 0xFF


def decode_second_selector_u16(encoded: int) -> int:
    return (
        decode_second_selector_byte(encoded & 0xFF)
        | (decode_second_selector_byte((encoded >> 8) & 0xFF) << 8)
    )


def decode_per_byte(encoded: int, width: int, transform: Any) -> int:
    result = 0
    for index in range(width):
        result |= transform((int(encoded) >> (index * 8)) & 0xFF) << (index * 8)
    return result


def decode_shop_item_substitution(row: dict[str, Any], image: bytes) -> dict[str, int]:
    fields = row["decoded_fields"]
    source = decode_per_byte(
        fields["encoded_substitution_source_u32_0x10"],
        4,
        lambda value: decode_first_selector_byte(value, image),
    )
    target = decode_per_byte(
        fields["encoded_substitution_target_u32_0x14"],
        4,
        decode_second_selector_byte,
    )
    return {"source_item_id": source, "target_item_id": target}


def decode_le_with_table(encoded: int, width: int, table: bytes) -> int:
    result = 0
    for index in range(width):
        result |= table[(int(encoded) >> (index * 8)) & 0xFF] << (index * 8)
    return result


def counter_dict(counter: collections.Counter[Any]) -> dict[str, int]:
    def sort_key(item: tuple[Any, int]) -> tuple[int, str]:
        key = item[0]
        if isinstance(key, int):
            return (0, f"{key:020d}")
        return (1, str(key))

    return {str(key): value for key, value in sorted(counter.items(), key=sort_key)}


def top_counter(counter: collections.Counter[Any], count: int = 12) -> list[dict[str, Any]]:
    return [{"value": key, "count": value} for key, value in counter.most_common(count)]


def route_key_location(route_key: str) -> tuple[int, int, int]:
    parts = route_key.split(":")
    return int(parts[1]), int(parts[2]), int(parts[3])


def event_uid(row: dict[str, Any]) -> str:
    return ":".join(
        str(value)
        for value in (
            row.get("packet_type"),
            row.get("replay_label"),
            row.get("chunk_index"),
            row.get("decompressed_block_offset"),
            row.get("decompressed_payload_offset"),
            row.get("raw_param"),
        )
    )


def build_helper_tables(image: bytes) -> dict[int, bytes]:
    emulator = ExactPacketEmulator(image, RUNTIME_PROFILES[BUILD])
    helper_rvas = (0x002EB0E0, 0x002EB120, 0x002EB090)
    return {
        rva: bytes(
            emulator.call(IMAGE_BASE + rva, rcx=value) & 0xFF
            for value in range(0x100)
        )
        for rva in helper_rvas
    }


def decode_snapshot(
    row: dict[str, Any],
    tables: dict[int, bytes],
) -> dict[int, dict[str, int]] | None:
    fields = row.get("decoded_fields")
    if fields is None:
        return None
    result: dict[int, dict[str, int]] = {}
    for record in fields["inventory_records_0x18"]:
        item_id = decode_le_with_table(
            record["item_id_encoded_u32_0x1c"], 4, tables[0x002EB0E0]
        )
        slot = decode_le_with_table(
            record["slot_index_encoded_u8_0x22"], 1, tables[0x002EB120]
        )
        stack = decode_le_with_table(
            record["stack_count_encoded_u8_0x78"], 1, tables[0x002EB090]
        )
        if not 0 <= slot <= 9:
            raise RuntimeError(f"snapshot slot outside 0..9: {slot}")
        if item_id:
            result[slot] = {"item_id": item_id, "stack_count": stack}
    return result


def item_multiset(slots: dict[int, dict[str, int]]) -> collections.Counter[int]:
    result: collections.Counter[int] = collections.Counter()
    for value in slots.values():
        result[value["item_id"]] += max(1, value.get("stack_count", 1))
    return result


def compact_snapshot(slots: dict[int, dict[str, int]] | None) -> list[dict[str, int]] | None:
    if slots is None:
        return None
    return [
        {"slot": slot, **value}
        for slot, value in sorted(slots.items())
    ]


def expand_compact_snapshot(
    values: list[dict[str, int]] | None,
) -> dict[int, dict[str, int]] | None:
    if values is None:
        return None
    return {
        value["slot"]: {
            "item_id": value["item_id"],
            "stack_count": value.get("stack_count", 1),
        }
        for value in values
    }


def analyze_snapshots(
    rows_by_route: dict[str, list[dict[str, Any]]],
    tables: dict[int, bytes],
) -> tuple[dict[str, Any], dict[str, dict[int, dict[str, int]]]]:
    decoded: dict[str, dict[int, dict[str, int]]] = {}
    route_summaries: dict[str, Any] = {}
    for route in ("0x0311", "0x02ea"):
        rows = rows_by_route[route]
        success = [row for row in rows if row.get("decoded_fields") is not None]
        error_rows = [row for row in rows if "emulation_error" in row]
        record_counts: collections.Counter[int] = collections.Counter()
        stream_counts: collections.Counter[str] = collections.Counter()
        unknown_outer: collections.Counter[int] = collections.Counter()
        all_item_ids: collections.Counter[int] = collections.Counter()
        all_slots: collections.Counter[int] = collections.Counter()
        for row in success:
            slots = decode_snapshot(row, tables)
            assert slots is not None
            decoded[event_uid(row)] = slots
            record_counts[len(row["decoded_fields"]["inventory_records_0x18"])] += 1
            stream_counts[row["chunk_stream"]] += 1
            unknown_outer[
                decode_le_with_table(
                    row["decoded_fields"]["inventory_unknown_u32_0x28"],
                    4,
                    tables[0x002EB0E0],
                )
            ] += 1
            for slot, value in slots.items():
                all_slots[slot] += 1
                all_item_ids[value["item_id"]] += 1
        route_summaries[route] = {
            "route_name": (
                "PKT_S2C_SetInventory_Broadcast_s"
                if route == "0x0311"
                else "PKT_S2C_SetInventory_MapView_s"
            ),
            "event_count": len(rows),
            "native_full_consume_count": len(success),
            "native_emulation_error_count": len(error_rows),
            "record_count_distribution": counter_dict(record_counts),
            "successful_stream_distribution": counter_dict(stream_counts),
            "decoded_outer_u32_0x28_distribution": counter_dict(unknown_outer),
            "occupied_slot_distribution": counter_dict(all_slots),
            "distinct_occupied_item_id_count": len(all_item_ids),
            "top_occupied_item_ids": top_counter(all_item_ids),
            "static_exactness": {
                "vector_offset": "outer+0x18",
                "record_stride": 160,
                "inline_item_offset": "record+0x10",
                "item_id_offset": "record+0x1c",
                "slot_offset": "record+0x22",
                "stack_offset": "record+0x78",
                "apply_receive_rva": "0x00336240 -> 0x0033d900",
                "apply_behavior": "reset ten inventory slots, then iterate records",
            },
        }
    return route_summaries, decoded


def analyze_route_differential(
    aligned: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    additions = [row for row in aligned if row["route"] == "0x0137"]
    removals = [row for row in aligned if row["route"] == "0x04b3"]
    add_groups: dict[tuple[str, int, int], list[dict[str, Any]]] = collections.defaultdict(list)
    remove_groups: dict[tuple[str, int, int], list[dict[str, Any]]] = collections.defaultdict(list)
    for row in additions:
        add_groups[(row["game_id"], row["subject_participant_candidate"], row["replay_time_ms"])].append(row)
    for row in removals:
        remove_groups[(row["game_id"], row["subject_participant_candidate"], row["replay_time_ms"])].append(row)

    add_class_counts = collections.Counter(row["classification"] for row in additions)
    remove_class_counts = collections.Counter(row["classification"] for row in removals)
    extras = [row for row in additions if row["classification"] != "exact_details_purchase"]
    removal_extras = [row for row in removals if row["classification"] != "exact_details_sale_time_subject"]
    sales = [row for row in removals if row["classification"] == "exact_details_sale_time_subject"]

    extra_decomposition = collections.Counter()
    compact_rows: list[dict[str, Any]] = []
    for row in extras:
        key = (row["game_id"], row["subject_participant_candidate"], row["replay_time_ms"])
        if row["classification"] == "purchase_group_extra_or_item_mismatch":
            category = "purchase_group_extra_or_item_mismatch"
        elif row["replay_time_ms"] == 0:
            category = "time_zero_initial_sync"
        elif remove_groups.get(key):
            category = "no_details_paired_same_time_removal"
        else:
            category = "no_details_unpaired_set_refresh_or_automatic_addition"
        extra_decomposition[category] += 1
        compact_rows.append(
            {
                "kind": "route_extra",
                "route": "0x0137",
                "route_key": row["route_key"],
                "game_id": row["game_id"],
                "participant_id": row["subject_participant_candidate"],
                "timestamp_ms": row["replay_time_ms"],
                "item_id": row["item_id_candidate"],
                "slot": row["slot_index_candidate"],
                "source_classification": row["classification"],
                "deep_classification": category,
                "same_time_remove_count": len(remove_groups.get(key, [])),
            }
        )

    removal_extra_with_add = 0
    for row in removal_extras:
        key = (row["game_id"], row["subject_participant_candidate"], row["replay_time_ms"])
        same_time_adds = add_groups.get(key, [])
        removal_extra_with_add += bool(same_time_adds)
        compact_rows.append(
            {
                "kind": "route_extra",
                "route": "0x04b3",
                "route_key": row["route_key"],
                "game_id": row["game_id"],
                "participant_id": row["subject_participant_candidate"],
                "timestamp_ms": row["replay_time_ms"],
                "slot": row["slot_index_candidate"],
                "source_classification": row["classification"],
                "same_time_add_count": len(same_time_adds),
                "same_time_add_item_ids": [candidate["item_id_candidate"] for candidate in same_time_adds],
            }
        )

    sale_with_add = sum(
        bool(add_groups.get((row["game_id"], row["subject_participant_candidate"], row["replay_time_ms"])))
        for row in sales
    )
    matched_purchase_with_removal = sum(
        bool(remove_groups.get((row["game_id"], row["subject_participant_candidate"], row["replay_time_ms"])))
        for row in additions
        if row["classification"] == "exact_details_purchase"
    )
    mismatch_rows = [row for row in extras if row["classification"] == "purchase_group_extra_or_item_mismatch"]
    result = {
        "route_counts": {"0x0137": len(additions), "0x04b3": len(removals)},
        "route_class_counts": {
            "0x0137": counter_dict(add_class_counts),
            "0x04b3": counter_dict(remove_class_counts),
        },
        "0x0137_extra_count": len(extras),
        "0x0137_extra_exact_decomposition": counter_dict(extra_decomposition),
        "0x0137_mismatch_item_id_distribution": counter_dict(
            collections.Counter(row["item_id_candidate"] for row in mismatch_rows)
        ),
        "0x0137_exact_purchase_rows_paired_same_time_removal": matched_purchase_with_removal,
        "0x0137_exact_purchase_rows_unpaired": add_class_counts["exact_details_purchase"] - matched_purchase_with_removal,
        "0x04b3_non_sale_extra_count": len(removal_extras),
        "0x04b3_non_sale_extras_with_same_time_0x0137": removal_extra_with_add,
        "0x04b3_sales_count": len(sales),
        "0x04b3_sales_with_same_time_0x0137": sale_with_add,
        "transition_carrier_conclusion": (
            "0x0137/0x04b3 are inventory state-transition carriers. RTTI names remain exact, "
            "but interpreting every row as an external buy/sell event is rejected."
        ),
    }
    expected = {
        "0x0137_extra": 447,
        "mismatch": 41,
        "time_zero": 48,
        "paired_no_details": 258,
        "unpaired_no_details": 100,
        "0x04b3_extra": 953,
        "0x04b3_extra_paired": 953,
        "sales": 60,
        "sales_paired": 0,
    }
    actual = {
        "0x0137_extra": len(extras),
        "mismatch": extra_decomposition["purchase_group_extra_or_item_mismatch"],
        "time_zero": extra_decomposition["time_zero_initial_sync"],
        "paired_no_details": extra_decomposition["no_details_paired_same_time_removal"],
        "unpaired_no_details": extra_decomposition["no_details_unpaired_set_refresh_or_automatic_addition"],
        "0x04b3_extra": len(removal_extras),
        "0x04b3_extra_paired": removal_extra_with_add,
        "sales": len(sales),
        "sales_paired": sale_with_add,
    }
    if actual != expected:
        raise RuntimeError(f"item differential invariant changed: expected={expected}, actual={actual}")
    return result, compact_rows


def decode_use_item(
    row: dict[str, Any],
    tables: dict[int, bytes],
) -> dict[str, int]:
    fields = row["decoded_fields"]
    encoded_value = fields["encoded_item_value_0x12"]
    return {
        "selector": tables[0x002EB0E0][fields["encoded_item_selector_0x14"]],
        "use_state": tables[0x002EB120][fields["encoded_use_state_0x10"]],
        "item_storage_value": decode_le_with_table(encoded_value, 2, tables[0x002EB090]),
    }


def analyze_missing_purchase_use_path(
    details: list[dict[str, Any]],
    aligned: list[dict[str, Any]],
    use_rows: list[dict[str, Any]],
    tables: dict[int, bytes],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    matched_purchase_ids = {
        row["matched_details_event"]["event_id"]
        for row in aligned
        if row["route"] == "0x0137" and row.get("matched_details_event")
    }
    player_purchases = [
        row for row in details
        if row["type"] == "ITEM_PURCHASED" and 1 <= row["participant_id"] <= 10
    ]
    missing = [row for row in player_purchases if row["event_id"] not in matched_purchase_ids]
    if len(missing) != 14:
        raise RuntimeError(f"expected 14 unmatched player purchases, got {len(missing)}")
    use_by_game_subject: dict[tuple[str, int], list[dict[str, Any]]] = collections.defaultdict(list)
    decoded_domains = [collections.Counter(), collections.Counter(), collections.Counter()]
    for row in use_rows:
        use_by_game_subject[(row["replay_label"], participant_id(row["raw_param"]))].append(row)
        decoded = decode_use_item(row, tables)
        decoded_domains[0][decoded["selector"]] += 1
        decoded_domains[1][decoded["use_state"]] += 1
        decoded_domains[2][decoded["item_storage_value"]] += 1

    output_rows: list[dict[str, Any]] = []
    matched_count = 0
    exact_count = 0
    for event in missing:
        candidates = sorted(
            use_by_game_subject.get((event["game_id"], event["participant_id"]), []),
            key=lambda row: (
                abs(row["replay_time_ms"] - event["timestamp_ms"]),
                row["chunk_index"],
                row["decompressed_block_offset"],
            ),
        )
        candidate = candidates[0] if candidates else None
        delta = (
            abs(candidate["replay_time_ms"] - event["timestamp_ms"])
            if candidate is not None else None
        )
        accepted = candidate is not None and delta is not None and delta <= 1
        matched_count += accepted
        exact_count += accepted and delta == 0
        output_rows.append(
            {
                "kind": "missing_purchase_use_path",
                "details_event_id": event["event_id"],
                "game_id": event["game_id"],
                "participant_id": event["participant_id"],
                "timestamp_ms": event["timestamp_ms"],
                "item_id": event["item_id"],
                "matched_0x041b": bool(accepted),
                "delta_ms": delta if accepted else None,
                "0x041b_event_uid": event_uid(candidate) if accepted else None,
                "0x041b_decoded": decode_use_item(candidate, tables) if accepted else None,
            }
        )
    special_ids = {2138, 2139, 2140}
    special_purchases = [row for row in player_purchases if row["item_id"] in special_ids]
    result = {
        "player_details_purchase_count": len(player_purchases),
        "matched_by_0x0137_count": len(matched_purchase_ids),
        "unmatched_player_purchase_count": len(missing),
        "unmatched_item_id_distribution": counter_dict(
            collections.Counter(row["item_id"] for row in missing)
        ),
        "special_2138_2139_2140_total_count": len(special_purchases),
        "special_matched_0x0137_count": sum(
            row["event_id"] in matched_purchase_ids for row in special_purchases
        ),
        "missing_matched_same_subject_within_1ms_0x041b": matched_count,
        "missing_matched_exact_time_0x041b": exact_count,
        "0x041b_native_event_count": len(use_rows),
        "0x041b_native_full_consume_count": sum(row.get("fully_consumed") is True for row in use_rows),
        "0x041b_decoded_selector_distribution": counter_dict(decoded_domains[0]),
        "0x041b_decoded_use_state_distribution": counter_dict(decoded_domains[1]),
        "0x041b_decoded_item_storage_value_distribution": counter_dict(decoded_domains[2]),
        "interpretation": (
            "The 14 player purchase misses are all adjacent to PKT_UseItemAns_s. "
            "This supports an immediate-use/inventoryless consumable path; 0x041b does not expose an item-id field."
        ),
        "promotion": "BOUNDED_DERIVED_CANDIDATE_ONLY",
    }
    if matched_count != 14:
        raise RuntimeError(f"expected 14/14 missing purchases near 0x041b, got {matched_count}")
    return result, output_rows


def analyze_swap_and_charges(
    swap_rows: list[dict[str, Any]],
    charge_rows: list[dict[str, Any]],
    image: bytes,
) -> tuple[dict[str, Any], dict[str, Any]]:
    swap_pairs: collections.Counter[tuple[int, int]] = collections.Counter()
    for row in swap_rows:
        fields = row["decoded_fields"]
        first = decode_first_selector_byte(fields["encoded_first_selector_0x10"], image)
        second = decode_second_selector_byte(fields["encoded_second_selector_0x11"])
        swap_pairs[(first, second)] += 1
    charge_selectors: collections.Counter[int] = collections.Counter()
    charge_values: collections.Counter[int] = collections.Counter()
    for row in charge_rows:
        fields = row["decoded_fields"]
        selector = decode_first_selector_byte(fields["encoded_lookup_selector_0x10"], image)
        value = decode_second_selector_u16(fields["encoded_assigned_u16_0x12"])
        charge_selectors[selector] += 1
        charge_values[value] += 1
    swap_summary = {
        "route": "0x01e8 PKT_SwapItemAns_s",
        "event_count": len(swap_rows),
        "native_full_consume_count": sum(row.get("fully_consumed") is True for row in swap_rows),
        "selector_domain": sorted({value for pair in swap_pairs for value in pair}),
        "pair_distribution": [
            {"first": first, "second": second, "count": count}
            for (first, second), count in swap_pairs.most_common()
        ],
        "static_transform": {
            "first": "(image_table[(encoded+0x77)&0xff]+0x2b)&0xff; table RVA 0x01a331a0",
            "second": "ror2(((ror1(~encoded)+0x7e)^0x28))-0x6b",
        },
        "promotion": "PROMOTE_EXACT_INVENTORY_SWAP_ROUTE",
    }
    charge_summary = {
        "route": "0x0310 PKT_S2C_SetItemCharges_s",
        "event_count": len(charge_rows),
        "native_full_consume_count": sum(row.get("fully_consumed") is True for row in charge_rows),
        "selector_distribution": counter_dict(charge_selectors),
        "selector_domain": sorted(charge_selectors),
        "value_distinct_count": len(charge_values),
        "value_min": min(charge_values),
        "value_max": max(charge_values),
        "value_top": top_counter(charge_values, 20),
        "static_storage_write": "receive 0x00336250 writes transformed u16 to selected item object+0xb2",
        "promotion": "PROMOTE_EXACT_STORAGE_ROUTE; RETAIN_BUSINESS_FIELD_LABEL_BOUNDARY",
    }
    if swap_summary["selector_domain"] != list(range(6)):
        raise RuntimeError(f"unexpected swap selector domain: {swap_summary['selector_domain']}")
    if charge_summary["selector_domain"] != [0, 1, 2, 3, 4, 5, 8]:
        raise RuntimeError(f"unexpected charge selector domain: {charge_summary['selector_domain']}")
    return swap_summary, charge_summary


def analyze_shop_item_substitutions(
    rows: list[dict[str, Any]],
    image: bytes,
) -> tuple[dict[str, Any], dict[int, int]]:
    pairs: collections.Counter[tuple[int, int]] = collections.Counter()
    for row in rows:
        decoded = decode_shop_item_substitution(row, image)
        source = decoded["source_item_id"]
        target = decoded["target_item_id"]
        if source == 0 or target == 0:
            raise RuntimeError("0x005a callback rejects zero substitution endpoints")
        pairs[(source, target)] += 1
    mapping: dict[int, int] = {}
    for source, target in pairs:
        previous = mapping.setdefault(source, target)
        if previous != target:
            raise RuntimeError(f"conflicting shop substitution for {source}: {previous} vs {target}")
    expected = {(2420, 2421): 6, (1001, 2422): 2}
    if dict(pairs) != expected:
        raise RuntimeError(f"0x005a substitution invariant changed: {dict(pairs)}")
    return {
        "route": "0x005a PKT_S2C_ShopItemSubstitutionSet_Broadcast_s",
        "event_count": len(rows),
        "native_full_consume_count": sum(row.get("fully_consumed") is True for row in rows),
        "decoded_pair_distribution": [
            {"source_item_id": source, "target_item_id": target, "count": count}
            for (source, target), count in sorted(pairs.items())
        ],
        "static_exactness": {
            "callback_owner": "HeroInventoryClient",
            "receive_rva": "0x00336ce0",
            "constructor_rva": "0x00e9f110",
            "deserialize_rva": "0x01012230",
            "source_transform": "per-byte image-table transform used by the first SwapItem selector",
            "target_transform": "per-byte rotate/complement transform used by the second SwapItem selector",
            "receive_behavior": "reject zero endpoints, then insert source->target into the inventory substitution map",
        },
        "undo_3363_to_3340_explained": False,
        "undo_boundary": (
            "The exact map contains only 2420->2421 and 1001->2422. It cannot be used to normalize "
            "the residual 3363->3340 undo snapshot difference."
        ),
        "promotion": "PROMOTE_EXACT_SHOP_ITEM_SUBSTITUTION_MAP_ROUTE",
    }, mapping


def canonical_substitution_item(item_id: int, mapping: dict[int, int]) -> int:
    seen: set[int] = set()
    current = item_id
    while current in mapping and current not in seen:
        seen.add(current)
        current = mapping[current]
    return current


def canonicalize_item_counter(
    counter: collections.Counter[int],
    mapping: dict[int, int],
) -> collections.Counter[int]:
    result: collections.Counter[int] = collections.Counter()
    for item_id, count in counter.items():
        result[canonical_substitution_item(item_id, mapping)] += count
    return result


def apply_undo_expected_delta(
    prior: collections.Counter[int],
    before_id: int,
    after_id: int,
) -> collections.Counter[int] | None:
    expected = collections.Counter(prior)
    if before_id:
        if expected[before_id] <= 0:
            return None
        expected[before_id] -= 1
        if expected[before_id] == 0:
            del expected[before_id]
    if after_id:
        expected[after_id] += 1
    return expected


def undo_directional_delta_support(
    prior: collections.Counter[int],
    incoming: collections.Counter[int],
    before_id: int,
    after_id: int,
) -> bool:
    """Validate only the item directions asserted by a DETAILS undo row.

    An undo can decompose a completed item and return several recipe components.
    Those additional inventory changes are real, but DETAILS exposes only its
    before/after pair. Whole-multiset equality is therefore a useful diagnostic,
    not a sound requirement for the derived undo transition.
    """
    if not before_id and not after_id:
        return False
    if before_id == after_id:
        return prior[before_id] == incoming[before_id]
    before_supported = not before_id or incoming[before_id] < prior[before_id]
    after_supported = not after_id or incoming[after_id] > prior[after_id]
    return before_supported and after_supported


def build_state_events(
    aligned: list[dict[str, Any]],
    set_rows: list[dict[str, Any]],
    swap_rows: list[dict[str, Any]],
    snapshot_rows: list[dict[str, Any]],
    decoded_snapshots: dict[str, dict[int, dict[str, int]]],
    image: bytes,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in aligned:
        chunk, block, payload = route_key_location(row["route_key"])
        common = {
            "game_id": row["game_id"],
            "participant": row["subject_participant_candidate"],
            "time": row["replay_time_ms"],
            "phase": 1,
            "chunk": chunk,
            "block": block,
            "payload": payload,
            "source": row,
        }
        if row["route"] == "0x0137":
            events.append(
                {
                    **common,
                    "kind": "set",
                    "item": row["item_id_candidate"],
                    "slot": row["slot_index_candidate"],
                    "stack": row["stack_count_candidate"],
                }
            )
        else:
            events.append({**common, "kind": "remove", "slot": row["slot_index_candidate"]})
    for row in set_rows:
        fields = row["decoded_fields"]
        events.append(
            {
                "game_id": row["replay_label"],
                "participant": participant_id(row["raw_param"]),
                "time": row["replay_time_ms"],
                "phase": 1,
                "chunk": row["chunk_index"],
                "block": row["decompressed_block_offset"],
                "payload": row["decompressed_payload_offset"],
                "kind": "set",
                "item": fields["item_id_0x1c"],
                "slot": fields["slot_index_0x22"],
                "stack": fields["stack_count_0x78"],
                "source": row,
            }
        )
    for row in swap_rows:
        fields = row["decoded_fields"]
        events.append(
            {
                "game_id": row["replay_label"],
                "participant": participant_id(row["raw_param"]),
                "time": row["replay_time_ms"],
                "phase": 1,
                "chunk": row["chunk_index"],
                "block": row["decompressed_block_offset"],
                "payload": row["decompressed_payload_offset"],
                "kind": "swap",
                "first": decode_first_selector_byte(fields["encoded_first_selector_0x10"], image),
                "second": decode_second_selector_byte(fields["encoded_second_selector_0x11"]),
                "source": row,
            }
        )
    for row in snapshot_rows:
        # Keyframes are an independent replay reconstruction surface, not live
        # mutations in the game-chunk transaction stream.  They can lag live
        # 0x02ea/0x0137/0x04b3/0x01e8 state (and did so in all three initially
        # mismatched sale identities), so injecting them here would corrupt the
        # chronological state rather than improve it.
        if row["chunk_stream"] != "game_chunk":
            continue
        uid = event_uid(row)
        slots = decoded_snapshots.get(uid)
        if slots is None:
            continue
        events.append(
            {
                "game_id": row["replay_label"],
                "participant": participant_id(row["raw_param"]),
                "time": row["replay_time_ms"],
                "phase": 1,
                "chunk": row["chunk_index"],
                "block": row["decompressed_block_offset"],
                "payload": row["decompressed_payload_offset"],
                "kind": "snapshot",
                "slots": slots,
                "source": row,
                "uid": uid,
            }
        )
    return events


def simulate_inventory_state(
    events: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    states: dict[tuple[str, int], dict[str, Any]] = collections.defaultdict(
        lambda: {"slots": {}, "complete": False, "anchor": None}
    )
    removal_capture: dict[str, dict[str, Any]] = {}
    snapshot_capture: dict[str, dict[str, Any]] = {}
    snapshot_comparisons = collections.Counter()
    mismatch_slot_counts: collections.Counter[int] = collections.Counter()
    for event in sorted(
        events,
        key=lambda item: (
            item["game_id"], item["time"], item["phase"], item["chunk"], item["block"], item["payload"]
        ),
    ):
        state = states[(event["game_id"], event["participant"])]
        slots: dict[int, dict[str, int]] = state["slots"]
        if event["kind"] == "snapshot":
            incoming: dict[int, dict[str, int]] = event["slots"]
            differing_slots = sorted(
                slot for slot in range(10)
                if slots.get(slot) != incoming.get(slot)
            )
            before_complete = state["complete"]
            if before_complete:
                if differing_slots:
                    snapshot_comparisons["mismatch"] += 1
                    mismatch_slot_counts[len(differing_slots)] += 1
                else:
                    snapshot_comparisons["exact"] += 1
            else:
                snapshot_comparisons["prior_incomplete"] += 1
            snapshot_capture[event["uid"]] = {
                "prior_complete": before_complete,
                "prior_slots": compact_snapshot(dict(slots)),
                "incoming_slots": compact_snapshot(incoming),
                "differing_slots": differing_slots,
            }
            state["slots"] = {slot: dict(value) for slot, value in incoming.items()}
            state["complete"] = True
            state["anchor"] = event["uid"]
        elif event["kind"] == "set":
            if event["item"]:
                slots[event["slot"]] = {
                    "item_id": event["item"],
                    "stack_count": event.get("stack", 1),
                }
            else:
                slots.pop(event["slot"], None)
        elif event["kind"] == "remove":
            row = event["source"]
            prior = slots.get(event["slot"])
            removal_capture[row["route_key"]] = {
                "prior_item_id": prior.get("item_id") if prior else None,
                "prior_stack_count": prior.get("stack_count") if prior else None,
                "state_complete": state["complete"],
                "anchor": state["anchor"],
            }
            slots.pop(event["slot"], None)
        elif event["kind"] == "swap":
            first = slots.pop(event["first"], None)
            second = slots.pop(event["second"], None)
            if second is not None:
                slots[event["first"]] = second
            if first is not None:
                slots[event["second"]] = first
        else:
            raise AssertionError(event["kind"])
    summary = {
        "state_event_count": len(events),
        "snapshot_comparison_counts": counter_dict(snapshot_comparisons),
        "snapshot_mismatch_slot_count_distribution": counter_dict(mismatch_slot_counts),
        "boundary": (
            "Only game-chunk snapshots are authoritative reset points for the live transition stream. "
            "Keyframe snapshots are retained as an independent reconstruction surface and never injected. "
            "Mismatches before a live reset remain evidence of unrecovered membership-changing routes/order."
        ),
    }
    return summary, removal_capture, snapshot_capture


def analyze_sales_state(
    aligned: list[dict[str, Any]],
    removal_capture: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    sales = [row for row in aligned if row["classification"] == "exact_details_sale_time_subject"]
    output: list[dict[str, Any]] = []
    new_matches = 0
    known_prior = 0
    complete_prior = 0
    old_matches = 0
    for row in sales:
        details_item = row["matched_details_event"]["item_id"]
        prior = removal_capture.get(row["route_key"], {})
        prior_item = prior.get("prior_item_id")
        old_candidate = row.get("bounded_two_route_prior_slot_item_candidate")
        old_matches += bool(old_candidate and old_candidate.get("item_id") == details_item)
        known_prior += prior_item is not None
        complete_prior += bool(prior.get("state_complete"))
        new_matches += prior_item == details_item
        output.append(
            {
                "kind": "sale_state",
                "route_key": row["route_key"],
                "details_event_id": row["matched_details_event"]["event_id"],
                "game_id": row["game_id"],
                "participant_id": row["subject_participant_candidate"],
                "timestamp_ms": row["replay_time_ms"],
                "slot": row["slot_index_candidate"],
                "details_item_id": details_item,
                "old_two_route_prior_item_id": old_candidate.get("item_id") if old_candidate else None,
                "deep_state_prior_item_id": prior_item,
                "deep_state_complete": bool(prior.get("state_complete")),
                "deep_state_matches_details": prior_item == details_item,
            }
        )
    if len(sales) != 60 or known_prior != 60 or new_matches != 60:
        raise RuntimeError(
            f"sale state invariant changed: sales={len(sales)} known={known_prior} matches={new_matches}"
        )
    return {
        "sale_count": len(sales),
        "old_0x0137_0x04b3_only_identity_match_count": old_matches,
        "deep_state_known_prior_item_count": known_prior,
        "deep_state_complete_prior_count": complete_prior,
        "deep_state_identity_match_count": new_matches,
        "promotion_boundary": (
            "The safe-corpus DETAILS-aligned sale subset closes at 60/60 prior identities. "
            "Do not generalize that result into a universal 0x04b3 ITEM_SOLD event."
        ),
    }, output


def analyze_undo_snapshots(
    details: list[dict[str, Any]],
    snapshot_rows: list[dict[str, Any]],
    decoded_snapshots: dict[str, dict[int, dict[str, int]]],
    snapshot_capture: dict[str, dict[str, Any]],
    substitution_mapping: dict[int, int],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    undos = [row for row in details if row["type"] == "ITEM_UNDO"]
    by_subject: dict[tuple[str, int], list[dict[str, Any]]] = collections.defaultdict(list)
    for row in snapshot_rows:
        by_subject[(row["replay_label"], participant_id(row["raw_param"]))].append(row)
    output: list[dict[str, Any]] = []
    within_one = 0
    exact = 0
    decoded_count = 0
    state_presence_support = 0
    state_capture_count = 0
    complete_state_capture_count = 0
    strict_whole_multiset_exact = 0
    direct_directional_support_count = 0
    normalized_directional_support_count = 0
    unresolved_directional_rows: list[dict[str, Any]] = []
    route_counts: collections.Counter[str] = collections.Counter()
    for undo in undos:
        candidates = sorted(
            by_subject.get((undo["game_id"], undo["participant_id"]), []),
            key=lambda row: (
                abs(row["replay_time_ms"] - undo["timestamp_ms"]),
                row["chunk_index"], row["decompressed_block_offset"],
            ),
        )
        row = candidates[0] if candidates else None
        delta = abs(row["replay_time_ms"] - undo["timestamp_ms"]) if row else None
        accepted = row is not None and delta is not None and delta <= 1
        within_one += accepted
        exact += accepted and delta == 0
        slots = decoded_snapshots.get(event_uid(row)) if accepted else None
        decoded_count += slots is not None
        current = item_multiset(slots) if slots is not None else collections.Counter()
        before_id = undo["before_id"]
        after_id = undo["after_id"]
        if slots is None:
            presence_support = None
        elif before_id == 0 and after_id != 0:
            presence_support = current[after_id] > 0
        elif before_id != 0 and after_id == 0:
            presence_support = current[before_id] == 0
        else:
            presence_support = current[before_id] == 0 and current[after_id] > 0
        state_presence_support += presence_support is True
        if accepted:
            route_counts[row["packet_type"]] += 1
        uid = event_uid(row) if accepted else None
        capture = snapshot_capture.get(uid) if uid else None
        prior_slots = expand_compact_snapshot(capture.get("prior_slots")) if capture else None
        incoming_slots = expand_compact_snapshot(capture.get("incoming_slots")) if capture else None
        if capture and prior_slots is not None and incoming_slots is not None:
            state_capture_count += 1
            complete_state_capture_count += bool(capture["prior_complete"])
            prior_counter = item_multiset(prior_slots)
            incoming_counter = item_multiset(incoming_slots)
            expected_counter = apply_undo_expected_delta(prior_counter, before_id, after_id)
            strict_whole_multiset_match = (
                expected_counter == incoming_counter if expected_counter is not None else False
            )
            direct_support = undo_directional_delta_support(
                prior_counter, incoming_counter, before_id, after_id
            )

            normalized_prior = canonicalize_item_counter(prior_counter, substitution_mapping)
            normalized_incoming = canonicalize_item_counter(incoming_counter, substitution_mapping)
            normalized_expected = apply_undo_expected_delta(
                normalized_prior,
                canonical_substitution_item(before_id, substitution_mapping),
                canonical_substitution_item(after_id, substitution_mapping),
            )
            normalized_strict_whole_multiset_match = (
                normalized_expected == normalized_incoming if normalized_expected is not None else False
            )
            normalized_support = undo_directional_delta_support(
                normalized_prior,
                normalized_incoming,
                canonical_substitution_item(before_id, substitution_mapping),
                canonical_substitution_item(after_id, substitution_mapping),
            )
            strict_whole_multiset_exact += strict_whole_multiset_match
            direct_directional_support_count += direct_support
            normalized_directional_support_count += normalized_support
            if not normalized_support:
                unresolved_directional_rows.append(
                    {
                        "details_event_id": undo["event_id"],
                        "game_id": undo["game_id"],
                        "participant_id": undo["participant_id"],
                        "timestamp_ms": undo["timestamp_ms"],
                        "before_id": before_id,
                        "after_id": after_id,
                        "prior_item_multiset": counter_dict(prior_counter),
                        "expected_item_multiset": (
                            counter_dict(expected_counter) if expected_counter is not None else None
                        ),
                        "incoming_item_multiset": counter_dict(incoming_counter),
                    }
                )
        else:
            strict_whole_multiset_match = None
            normalized_strict_whole_multiset_match = None
            direct_support = None
            normalized_support = None
        output.append(
            {
                "kind": "undo_snapshot_path",
                "details_event_id": undo["event_id"],
                "game_id": undo["game_id"],
                "participant_id": undo["participant_id"],
                "timestamp_ms": undo["timestamp_ms"],
                "before_id": before_id,
                "after_id": after_id,
                "gold_gain": undo["gold_gain"],
                "matched_snapshot": bool(accepted),
                "delta_ms": delta if accepted else None,
                "snapshot_route": row["packet_type"] if accepted else None,
                "snapshot_event_uid": uid,
                "snapshot_native_decoded": slots is not None,
                "snapshot_items": compact_snapshot(slots),
                "post_snapshot_presence_support": presence_support,
                "strict_whole_multiset_match_diagnostic": strict_whole_multiset_match,
                "normalized_strict_whole_multiset_match_diagnostic": normalized_strict_whole_multiset_match,
                "details_directional_delta_support": direct_support,
                "shop_substitution_normalized_directional_delta_support": normalized_support,
                "pre_reset_state_comparison": capture,
            }
        )
    if within_one != 52:
        raise RuntimeError(f"expected 52/52 undo-to-snapshot adjacency, got {within_one}")
    if state_capture_count != 52 or normalized_directional_support_count != 51:
        raise RuntimeError(
            "undo directional invariant changed: "
            f"captures={state_capture_count} normalized_support={normalized_directional_support_count}"
        )
    return {
        "details_undo_count": len(undos),
        "same_subject_snapshot_within_1ms_count": within_one,
        "exact_time_snapshot_count": exact,
        "matched_snapshot_route_distribution": counter_dict(route_counts),
        "matched_snapshot_native_decoded_count": decoded_count,
        "post_snapshot_presence_support_count": state_presence_support,
        "pre_reset_state_capture_count": state_capture_count,
        "complete_pre_reset_state_capture_count": complete_state_capture_count,
        "strict_whole_multiset_exact_count_diagnostic": strict_whole_multiset_exact,
        "direct_details_directional_delta_support_count": direct_directional_support_count,
        "shop_substitution_normalized_directional_delta_support_count": normalized_directional_support_count,
        "unresolved_directional_delta_count": len(unresolved_directional_rows),
        "unresolved_directional_delta_rows": unresolved_directional_rows,
        "generic_snapshot_route_negative_count": len(snapshot_rows) - within_one,
        "conclusion": (
            "ITEM_UNDO is recoverable as a DETAILS-aligned derived transition with exact generic-snapshot adjacency. "
            "The declared before/after direction closes 51/52; whole-multiset equality remains diagnostic because recipe undo returns components. "
            "The one conserved directional counterexample is logical 3363 restoration versus physical 3340. "
            "0x0311/0x02ea are generic SetInventory carriers with many non-undo negatives and must not be renamed ITEM_UNDO."
        ),
        "promotion": "DERIVED_UNDO_TRANSITION_CANDIDATE; REJECT_ROUTE_RENAME",
    }, output


def analyze_set_item(rows: list[dict[str, Any]]) -> dict[str, Any]:
    item_ids = collections.Counter(row["decoded_fields"]["item_id_0x1c"] for row in rows)
    slots = collections.Counter(row["decoded_fields"]["slot_index_0x22"] for row in rows)
    stacks = collections.Counter(row["decoded_fields"]["stack_count_0x78"] for row in rows)
    time_zero = sum(row["replay_time_ms"] == 0 for row in rows)
    return {
        "route": "0x006c PKT_SetItem_s",
        "event_count": len(rows),
        "native_full_consume_count": sum(row.get("fully_consumed") is True for row in rows),
        "time_zero_count": time_zero,
        "item_id_distribution": counter_dict(item_ids),
        "slot_distribution": counter_dict(slots),
        "stack_distribution": counter_dict(stacks),
        "undo_count_coincidence_rejected": (
            "53 packet rows are not the 52 DETAILS undo events; 40 are time-zero participant syncs, "
            "and every decoded row targets special slot 8 with trinket-family IDs."
        ),
        "promotion": "PROMOTE_EXACT_SET_ITEM_SPECIAL_SLOT_ROUTE",
    }


def analyze_support_quest_inventory_crossref(
    audit: dict[str, Any],
    snapshot_rows: list[dict[str, Any]],
    decoded_snapshots: dict[str, dict[int, dict[str, int]]],
) -> dict[str, Any]:
    if audit.get("schema") != "ROUTE_0064_SUPPORT_QUEST_STAGE_AUDIT_V2":
        raise RuntimeError("unexpected 0x0064 audit schema")
    if audit.get("exact_build") != BUILD or not audit.get("exact_build_only"):
        raise RuntimeError("0x0064 audit is not exact-build closed")
    utility_subjects = {
        (entry["replay_label"], roster["participant_id"])
        for entry in audit["current_build_replays"]["safe_p0"]
        for roster in entry["roster"]
        if roster["team_position"] == "UTILITY"
    }
    if len(utility_subjects) != 8:
        raise RuntimeError(f"expected 8 safe-P0 utility subjects, got {len(utility_subjects)}")

    relevant_ids = (3865, 3866, 3867)
    route_item_counts: dict[str, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    stream_item_counts: dict[str, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    subject_times: dict[tuple[str, int], dict[int, list[int]]] = collections.defaultdict(
        lambda: collections.defaultdict(list)
    )
    nonutility_occurrences: list[dict[str, Any]] = []
    for row in snapshot_rows:
        slots = decoded_snapshots.get(event_uid(row))
        if slots is None:
            continue
        subject = (row["replay_label"], participant_id(row["raw_param"]))
        for item_id in relevant_ids:
            if not any(value["item_id"] == item_id for value in slots.values()):
                continue
            route_item_counts[row["packet_type"]][item_id] += 1
            stream_item_counts[row["chunk_stream"]][item_id] += 1
            subject_times[subject][item_id].append(row["replay_time_ms"])
            if subject not in utility_subjects:
                nonutility_occurrences.append(
                    {
                        "game_id": subject[0],
                        "participant_id": subject[1],
                        "item_id": item_id,
                        "timestamp_ms": row["replay_time_ms"],
                    }
                )

    trajectories: list[dict[str, Any]] = []
    for game_id, participant in sorted(utility_subjects):
        times_by_item = subject_times.get((game_id, participant), {})
        trajectories.append(
            {
                "game_id": game_id,
                "participant_id": participant,
                "items": {
                    str(item_id): {
                        "snapshot_count": len(times_by_item.get(item_id, [])),
                        "first_timestamp_ms": min(times_by_item[item_id]) if times_by_item.get(item_id) else None,
                        "last_timestamp_ms": max(times_by_item[item_id]) if times_by_item.get(item_id) else None,
                    }
                    for item_id in relevant_ids
                },
            }
        )

    expected_route_counts = {
        "0x0311": {3865: 59, 3866: 45, 3867: 0},
        "0x02ea": {3865: 10, 3866: 12, 3867: 0},
    }
    actual_route_counts = {
        route: {item_id: route_item_counts[route][item_id] for item_id in relevant_ids}
        for route in ("0x0311", "0x02ea")
    }
    if actual_route_counts != expected_route_counts:
        raise RuntimeError(
            f"support quest inventory crossref invariant changed: {actual_route_counts}"
        )
    if nonutility_occurrences:
        raise RuntimeError("support quest inventory items appeared on a non-UTILITY participant")

    alignment = audit["details_ground_truth_alignment"]
    decision = audit["route_decisions"][0]
    if alignment["matched_alignment_count"] != 16 or not alignment["all_pass"]:
        raise RuntimeError("0x0064 DETAILS transition alignment is incomplete")
    if decision["decision"] != "PROMOTE" or decision["evidence_grade"] != "VERIFIED_DERIVED":
        raise RuntimeError("0x0064 bounded promotion decision changed")
    return {
        "route": "0x0064",
        "imported_audit_sha256": SUPPORT_QUEST_AUDIT_SHA256,
        "import_mode": "READ_ONLY_AGGREGATE_CROSS_REFERENCE; NO_REPLAY_DISCOVERY_OR_RAW_0x0064_DECODE",
        "audit_semantic_name": audit["recovered_bounded_structure"]["semantic_name"],
        "audit_evidence_grade": audit["recovered_bounded_structure"]["evidence_grade"],
        "audit_promotion_scope": decision["promotion_scope"],
        "audit_details_transition_alignment": {
            "matched": alignment["matched_alignment_count"],
            "expected": alignment["expected_alignment_count"],
            "lag_min_ms": alignment["lag_after_details_anchor_ms"]["min"],
            "lag_max_ms": alignment["lag_after_details_anchor_ms"]["max"],
        },
        "inventory_snapshot_item_presence_by_route": {
            route: {str(item_id): count for item_id, count in counts.items()}
            for route, counts in actual_route_counts.items()
        },
        "inventory_snapshot_item_presence_by_stream": {
            stream: {str(item_id): stream_item_counts[stream][item_id] for item_id in relevant_ids}
            for stream in sorted(stream_item_counts)
        },
        "inventory_snapshot_utility_subject_count": len(utility_subjects),
        "inventory_snapshot_nonutility_occurrence_count": 0,
        "utility_subject_trajectories": trajectories,
        "independent_crossref": (
            "0311/02ea snapshots independently place 3865 and then 3866 only on all eight safe-P0 "
            "UTILITY participants; 3867 is absent from every decoded snapshot, consistent with a "
            "consumed/nonpersistent final transition rather than a durable inventory stage."
        ),
        "decision": "PROMOTE_VERIFIED_DERIVED_WITH_ORIGINAL_CANONICAL_UTILITY_SCOPE",
        "runtime_identity_boundary": (
            "0x0064 callback/factory/deserializer identity, byte 0, three-byte rows, and noncanonical "
            "groups remain UNKNOWN exactly as conserved by the imported audit."
        ),
    }


def compact_observed_route(row: dict[str, Any] | None) -> dict[str, Any]:
    if row is None:
        return {"observed": False}
    payloads = collections.Counter(
        {entry["payload_length"]: entry["count"] for entry in row["payload_size_distribution"]}
    )
    return {
        "observed": True,
        "observed_count": row["observed_count"],
        "top_payload_lengths": top_counter(payloads),
        "callback_mapping_status": row["callback_mapping_status"],
        "callback_names": row["callback_names"],
        "callbacks": row["callbacks"],
        "factory_packets": row["factory_packets"],
    }


def build_entity_taxonomy(
    observed_map: dict[str, Any],
    static_trace: dict[str, Any],
    unknown_mining: dict[str, Any],
) -> dict[str, Any]:
    observed_by_id = {row["packet_id"]: row for row in observed_map["routes"]}
    trace_entries: dict[int, list[dict[str, Any]]] = collections.defaultdict(list)
    for row in static_trace["callback_registration_inventory"]["entries"]:
        trace_entries[row["registration_id"]].append(row)

    specs = [
        (0x008A, "missile_lifecycle", "specialized forced missile creation", "STATIC_EXACT_SPECIALIZED_ROUTE"),
        (0x0182, "missile_lifecycle", "delayed missile spawn", "STATIC_EXACT_SPECIALIZED_ROUTE"),
        (0x0465, "missile_replication", "missile replication", "STATIC_EXACT_ROUTE; FIELDS_UNRECOVERED"),
        (0x02E0, "missile_lifecycle", "client missile destruction", "STATIC_EXACT_SPECIALIZED_ROUTE"),
        (0x0472, "companion_pet", "hero companion spawned", "STATIC_EXACT_ROUTE; OWNER/TEMPLATE_FIELDS_UNRECOVERED"),
        (0x04A2, "unit_lifecycle", "unit destruction", "STATIC_EXACT_ROUTE; GENERIC_CREATE_COUNTERPART_UNAVAILABLE"),
        (0x032F, "character_template_mutation", "character-data change on AIBase/AnimatedBuilding", "STATIC_EXACT_MUTATION_ROUTE"),
        (0x0316, "character_template_mutation", "pop character data", "STATIC_EXACT_MUTATION_ROUTE"),
        (0x01B3, "character_template_mutation", "set secondary character data", "STATIC_EXACT_MUTATION_ROUTE"),
        (0x034C, "npc_neutral", "neutral camp leash-state mutation on AIMinion", "STATIC_EXACT_NPC_ROUTE"),
        (0x011A, "structure", "turret flags", "STATIC_EXACT_STRUCTURE_ROUTE"),
        (0x042D, "structure", "dampener switch states", "STATIC_EXACT_STRUCTURE_ROUTE"),
        (0x0433, "structure", "building death", "STATIC_EXACT_STRUCTURE_ROUTE"),
        (0x01DC, "replication_visibility", "replicate fields", "STATIC_EXACT_ROUTE; FIELD_SCHEMA_UNRECOVERED"),
        (0x04DF, "replication_visibility", "replicate field", "REGISTRATION_EXACT; ABOVE_DIRECT_FACTORY_MAXIMUM"),
        (0x0302, "replication_visibility", "enter team visibility", "STATIC_EXACT_VISIBILITY_ROUTE"),
        (0x021D, "replication_visibility", "leave visibility", "STATIC_EXACT_VISIBILITY_ROUTE"),
    ]
    routes: list[dict[str, Any]] = []
    for packet_id, category, interpretation, decision in specs:
        entries = trace_entries.get(packet_id, [])
        routes.append(
            {
                "packet_id": packet_id,
                "packet_id_hex": f"0x{packet_id:04x}",
                "category": category,
                "bounded_interpretation": interpretation,
                "decision": decision,
                "registration_entries": [
                    {
                        "name": entry["name"],
                        "callback_owner_type": entry.get("callback_owner_type"),
                        "receive_rva": entry.get("callback_receive_target_rva_hex"),
                        "registration_id": entry["registration_id_hex"],
                        "factory_status": entry["factory_status"],
                        "factory_packet": entry.get("factory_packet"),
                    }
                    for entry in entries
                ],
                "observed_route": compact_observed_route(observed_by_id.get(packet_id)),
            }
        )

    unknown_routes = {row["packet_id"]: row for row in unknown_mining["routes"]}
    pair_relation = next(
        row for row in unknown_mining["cross_route_relationships"]
        if {row["left_packet_discriminator"], row["right_packet_discriminator"]} == {"0x0092", "0x00b9"}
    )
    marker_route = unknown_routes[0x00B9]
    pair = {
        "routes": ["0x00b9", "0x0092"],
        "full_observed_counts": {
            "0x00b9": observed_by_id[0x00B9]["observed_count"],
            "0x0092": observed_by_id[0x0092]["observed_count"],
        },
        "sampled_counts": {
            "0x00b9": marker_route["sample_count"],
            "0x0092": unknown_routes[0x0092]["sample_count"],
        },
        "same_replay_time_raw_param_multiset_intersection": pair_relation[
            "same_replay_time_raw_param_multiset_intersection"
        ],
        "same_replay_time_raw_param_jaccard": pair_relation[
            "same_replay_time_raw_param_jaccard"
        ],
        "0x00b9_payload_length_distribution": marker_route["payload"]["length_distribution"],
        "0x00b9_distinct_payload_hash_count": marker_route["payload"]["distinct_payload_hash_count"],
        "0x00b9_constant_payload": marker_route["payload"]["top_prefix2"][0],
        "supplemental_pair_order_from_parent_audit": {
            "same_chunk": "4954/4954",
            "0x00b9_always_precedes_0x0092": "4954/4954",
            "usual_block_offset_gap": 7,
            "rare_block_offset_gap": 10,
            "provenance": "parent UNKNOWN-mining audit; aggregate correlation is independently present in the hashed mining artifact",
        },
        "static_mapping": {
            "0x00b9": compact_observed_route(observed_by_id[0x00B9]),
            "0x0092": compact_observed_route(observed_by_id[0x0092]),
        },
        "conclusion": (
            "Treat 0x00b9 as a replication/component envelope marker paired to the variable 0x0092 payload family. "
            "Reject an independent 0x00b9 gameplay semantic. Replication-component identity remains a candidate "
            "until factory/deserializer/field evidence closes."
        ),
        "decision": "REJECT_INDEPENDENT_SEMANTIC; RETAIN_PAIRED_REPLICATION_ENVELOPE_CANDIDATE",
    }
    if pair["full_observed_counts"] != {"0x00b9": 54606, "0x0092": 54606}:
        raise RuntimeError("0x00b9/0x0092 full-count invariant changed")
    if pair_relation["same_replay_time_raw_param_multiset_intersection"] != 4954:
        raise RuntimeError("0x00b9/0x0092 sampled pair invariant changed")

    return {
        "schema": "ENTITY_ROUTE_TAXONOMY_DEEP_RECOVERY_V2",
        "build": BUILD,
        "runtime_image_sha256": IMAGE_SHA256,
        "source_inventory": {
            "descriptor_instance_count": static_trace["callback_registration_inventory"]["discovered_descriptor_instance_count"],
            "verified_registration_instance_count": static_trace["callback_registration_inventory"]["verified_registration_instance_count"],
            "verified_callback_receive_target_count": static_trace["callback_registration_inventory"]["verified_callback_receive_target_count"],
            "observed_route_count": observed_map["observed_route_count"],
        },
        "routes": routes,
        "paired_unknown_replication_candidate": pair,
        "generic_entity_create_template_identity_search": {
            "generic_create_route": "UNAVAILABLE",
            "generic_template_name_hash_owner_team_class_fields": "UNAVAILABLE",
            "bounded_positive_routes": [
                "specialized missile create/spawn/destroy",
                "companion spawn",
                "unit destroy",
                "character-data mutation",
                "NPC leash state",
                "structure mutation/death",
                "visibility/replication carriers",
            ],
            "exhaustion": (
                "The full callback-registration inventory and observed factory intersection were searched. "
                "No independently decoded generic entity create/template/name/hash/owner/team/class carrier closed."
            ),
            "decision": "EXHAUST_CURRENT_STATIC_SURFACE; NO_GENERIC_ENTITY_SEMANTIC_PROMOTION",
        },
        "promotion": {
            "safe": "promote exact-build structural route taxonomy (ID/name/owner/factory/deserializer evidence)",
            "unsafe": "do not emit normalized entity-create or owner/team/class events from names alone",
        },
    }


def write_json(path: Path, value: Any) -> None:
    reject_protected_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2, sort_keys=False)
        stream.write("\n")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    reject_protected_path(path)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")))
            stream.write("\n")
            count += 1
    return count


def build_report(summary: dict[str, Any], taxonomy: dict[str, Any]) -> str:
    differential = summary["item_route_differential"]
    missing = summary["missing_purchase_use_path"]
    undo = summary["undo_snapshot_path"]
    sales = summary["sale_identity_state_recovery"]
    snapshots = summary["inventory_snapshots"]
    substitutions = summary["shop_item_substitution_map"]
    support_quest = summary["support_quest_item_stage_snapshot_crossref"]
    pair = taxonomy["paired_unknown_replication_candidate"]
    return f"""# Entity + Item/Economy deep recovery — exact build {BUILD}

`PROJECT_CONTEXT_LOADED = YES`  
`ARCHITECTURE_GATE = PASS`

## Scope and safety

- Exact runtime image SHA-256: `{IMAGE_SHA256}`.
- Four explicit safe P0 replays only for native/item alignment; no replay discovery.
- Jungle Objective Holdout was not enumerated, read, hashed, decoded, tested, or consumed.
- Parser ownership remains replay protocol semantics only. This branch changes no shared manifest, API, schema, or governance document.

## Item/economy results

- `0x0137`: {differential['route_counts']['0x0137']} fully decoded rows, including exactly {differential['0x0137_extra_count']} DETAILS extras. The extras split into 41 purchase-group mismatches (all item 2055), 48 time-zero sync rows, 258 no-DETAILS rows paired with same-time removal, and 100 unpaired set/refresh/automatic additions.
- `0x04b3`: {differential['route_counts']['0x04b3']} fully decoded rows. All {differential['0x04b3_non_sale_extra_count']} non-sale rows have a same-subject, same-time `0x0137`; all {differential['0x04b3_sales_count']} sales do not. Therefore these are state-transition carriers, not pure external buy/sell streams.
- `0x006c`: {summary['set_item_special_slot']['event_count']}/{summary['set_item_special_slot']['native_full_consume_count']} full consume; every row targets slot 8 and the decoded IDs are the trinket/special-slot family. The apparent 53-vs-52 undo coincidence is rejected.
- `0x005a`: {substitutions['native_full_consume_count']}/{substitutions['event_count']} full consume with exact `HeroInventoryClient` map insertion. The only decoded pairs are `1001→2422` (2) and `2420→2421` (6); this exact map does not explain the separate `3363→3340` undo counterexample.
- `0x01e8`: {summary['inventory_swap']['event_count']}/{summary['inventory_swap']['native_full_consume_count']} full consume; both transformed selectors are exactly domain 0..5. This is an exact inventory swap carrier.
- `0x0310`: {summary['item_storage_value']['event_count']}/{summary['item_storage_value']['native_full_consume_count']} full consume; transformed selector domain is 0..5 plus 8, and the callback writes the transformed u16 to item object `+0xb2`.
- `0x0311`: {snapshots['0x0311']['native_full_consume_count']}/{snapshots['0x0311']['event_count']} native full consume; 154 real emulation failures remain explicit. `0x02ea`: {snapshots['0x02ea']['native_full_consume_count']}/{snapshots['0x02ea']['event_count']} full consume. Both share the exact 160-byte inventory-record implementation and reset/apply behavior.
- `0x0405`: {summary['item_group_data_boundary']['observed_count']} rows, all keyframe, with only shape-sampled native decode. It remains group-data/cooldown adjacency and is rejected as inventory membership.
- `0x0064`: import the independently hashed audit only. Its 16/16 DETAILS transition anchors remain `VERIFIED_DERIVED`; `0x0311/0x02ea` independently observe 3865 ({support_quest['inventory_snapshot_item_presence_by_route']['0x0311']['3865']}+{support_quest['inventory_snapshot_item_presence_by_route']['0x02ea']['3865']}) and 3866 ({support_quest['inventory_snapshot_item_presence_by_route']['0x0311']['3866']}+{support_quest['inventory_snapshot_item_presence_by_route']['0x02ea']['3866']}) exclusively on all eight UTILITY participants, while 3867 never persists in a decoded inventory snapshot. Preserve the original canonical-ten-row/UTILITY-only promotion scope and all runtime/noncanonical unknowns.

### Missing purchase and undo routes

- The 14 unmatched player purchases (2138×3, 2139×7, 2140×4) all align to same-subject `0x041b PKT_UseItemAns_s` within 1 ms ({missing['missing_matched_exact_time_0x041b']} exact). The route itself decoded {missing['0x041b_native_full_consume_count']}/{missing['0x041b_native_event_count']} and has bounded domains selector 0..9, state 0/1, value 0..4. Promote only an immediate-use/inventoryless consumable candidate; `0x041b` has no decoded item-id.
- All {undo['details_undo_count']} DETAILS `ITEM_UNDO` events align to same-subject `0x0311/0x02ea` snapshots within 1 ms ({undo['exact_time_snapshot_count']} exact). Stack-aware direction checks on the declared before/after pair match {undo['direct_details_directional_delta_support_count']}/{undo['details_undo_count']}; exact shop-substitution normalization remains {undo['shop_substitution_normalized_directional_delta_support_count']}/{undo['details_undo_count']}. Whole-multiset equality is diagnostic only because undoing completed recipes legitimately returns additional components ({undo['strict_whole_multiset_exact_count_diagnostic']}/{undo['details_undo_count']} exact). The single conserved directional residual restores logical 3363 while the physical snapshot changes 3363→3340. These routes also contain {undo['generic_snapshot_route_negative_count']} non-undo negatives, so a route rename remains rejected.
- Inventory state recovery improves sale prior-identity matching from {sales['old_0x0137_0x04b3_only_identity_match_count']}/{sales['sale_count']} to an exact {sales['deep_state_identity_match_count']}/{sales['sale_count']} with all {sales['deep_state_known_prior_item_count']} prior identities known. No sale-identity mismatch remains on the safe corpus.

## Entity taxonomy results

- The exact-image surface contains {taxonomy['source_inventory']['descriptor_instance_count']} descriptor instances, {taxonomy['source_inventory']['verified_registration_instance_count']} verified registrations, and {taxonomy['source_inventory']['verified_callback_receive_target_count']} receive targets.
- Exact structural routes close specialized missile create/spawn/replication/destroy, companion spawn, unit destroy, character-data mutations, neutral-minion state, turret/dampener/building state, and visibility/replication carriers. Their packet ID/name/owner/factory/deserializer taxonomy is promotable as exact-build structural metadata only.
- No independently decoded generic entity create/template/name/hash/owner/team/class carrier closes on the full registration/factory surface. That search is exhausted at the current evidence level.
- `0x00b9` and `0x0092` have equal full observed counts ({pair['full_observed_counts']['0x00b9']} each) and a sampled {pair['same_replay_time_raw_param_multiset_intersection']}/{pair['sampled_counts']['0x00b9']} same replay/time/raw-param bijection. `0x00b9` is always the constant one-byte payload `91` and precedes the variable `0x0092` record. Reject independent `0x00b9` semantics; retain only a paired replication/component-envelope candidate.

## Promotion / reject / exhaust

- **Promote structural exactness:** SetInventory Broadcast/MapView layouts, ShopItemSubstitutionSet, SwapItem selectors, special-slot SetItem, SetItemCharges storage flow, and the entity route taxonomy.
- **Promote bounded derived results:** the canonical/UTILITY-only support quest stage snapshot. Keep the immediate-use path for 2138/2139/2140 and DETAILS-aligned undo state transitions as candidates only.
- **Reject:** universal buy/sell interpretation of every `0x0137/0x04b3`, `0x006c == ITEM_UNDO`, `0x0311/0x02ea == ITEM_UNDO`, `0x0405` as membership, and `0x00b9` as an independent gameplay semantic.
- **Exhausted/unavailable:** generic entity creation plus decoded template/name/hash/owner/team/class fields on the current exact-image static surface.
"""


def main() -> None:
    input_paths = [
        IMAGE, OBSERVED_MAP, STATIC_TRACE, UNKNOWN_MINING, SUPPORT_QUEST_AUDIT,
        ITEM_ALIGNED, DETAILS_EVENTS, INVENTORY_MANIFEST, P005A, P005A_PROFILE,
        P005A_DECODE_SUMMARY, P006C, P01E8, P02EA, P0310, P0311, P0405_SAMPLE, P041B,
    ]
    validate_explicit_paths(input_paths)
    image = IMAGE.read_bytes()
    if hashlib.sha256(image).hexdigest() != IMAGE_SHA256:
        raise RuntimeError("exact runtime image hash mismatch")
    tables = build_helper_tables(image)

    observed_map = load_json(OBSERVED_MAP)
    static_trace = load_json(STATIC_TRACE)
    unknown_mining = load_json(UNKNOWN_MINING)
    support_quest_audit = load_json(SUPPORT_QUEST_AUDIT)
    inventory_manifest = load_json(INVENTORY_MANIFEST)
    aligned = load_jsonl(ITEM_ALIGNED, validate_replays=False)
    details = load_jsonl(DETAILS_EVENTS, validate_replays=False)
    rows006c = load_jsonl(P006C)
    rows005a = load_jsonl(P005A)
    rows01e8 = load_jsonl(P01E8)
    rows02ea = load_jsonl(P02EA)
    rows0310 = load_jsonl(P0310)
    rows0311 = load_jsonl(P0311)
    rows041b = load_jsonl(P041B)
    rows0405 = load_jsonl(P0405_SAMPLE)

    if observed_map["build"] != BUILD or static_trace["build"] != BUILD:
        raise RuntimeError("static evidence build mismatch")
    if static_trace["image"]["sha256"] != IMAGE_SHA256:
        raise RuntimeError("static trace image mismatch")
    if inventory_manifest["target_replay_version"] != BUILD:
        raise RuntimeError("inventory manifest build mismatch")
    if sha256_file(SUPPORT_QUEST_AUDIT) != SUPPORT_QUEST_AUDIT_SHA256:
        raise RuntimeError("0x0064 support quest audit hash mismatch")

    rows_by_route = {"0x0311": rows0311, "0x02ea": rows02ea}
    snapshot_summary, decoded_snapshots = analyze_snapshots(rows_by_route, tables)
    differential, alignment_rows = analyze_route_differential(aligned)
    missing_summary, missing_rows = analyze_missing_purchase_use_path(
        details, aligned, rows041b, tables
    )
    swap_summary, charge_summary = analyze_swap_and_charges(rows01e8, rows0310, image)
    substitution_summary, substitution_mapping = analyze_shop_item_substitutions(rows005a, image)
    set_summary = analyze_set_item(rows006c)

    snapshot_rows = rows0311 + rows02ea
    state_events = build_state_events(
        aligned, rows006c, rows01e8, snapshot_rows, decoded_snapshots, image
    )
    state_summary, removal_capture, snapshot_capture = simulate_inventory_state(state_events)
    state_summary["successful_keyframe_snapshots_excluded_from_live_state"] = sum(
        row.get("decoded_fields") is not None and row["chunk_stream"] == "keyframe"
        for row in snapshot_rows
    )
    state_summary["successful_game_chunk_snapshots_used_as_live_resets"] = sum(
        row.get("decoded_fields") is not None and row["chunk_stream"] == "game_chunk"
        for row in snapshot_rows
    )
    state_summary["keyframe_exclusion_reason"] = (
        "Keyframe 0x0311 rows can lag the live game stream. Injecting them caused three sale-state "
        "counterexamples; retaining them as non-mutating observations restores exact 60/60 sale identity."
    )
    sale_summary, sale_rows = analyze_sales_state(aligned, removal_capture)
    undo_summary, undo_rows = analyze_undo_snapshots(
        details, snapshot_rows, decoded_snapshots, snapshot_capture, substitution_mapping
    )
    support_quest_crossref = analyze_support_quest_inventory_crossref(
        support_quest_audit, snapshot_rows, decoded_snapshots
    )

    taxonomy = build_entity_taxonomy(observed_map, static_trace, unknown_mining)
    write_json(TAXONOMY_OUT, taxonomy)

    summary = {
        "schema": "ENTITY_ITEM_DEEP_RECOVERY_V2",
        "build": BUILD,
        "runtime_image_sha256": IMAGE_SHA256,
        "project_context_loaded": True,
        "architecture_gate": "PASS",
        "scope_and_safety": {
            "safe_replay_labels": sorted(SAFE_REPLAYS),
            "safe_replay_hashes": SAFE_REPLAYS,
            "explicit_input_only": True,
            "directory_replay_discovery": False,
            "protected_holdout_enumerated": False,
            "protected_holdout_read": False,
            "protected_holdout_hashed": False,
            "protected_holdout_decoded": False,
            "protected_holdout_tested": False,
            "protected_holdout_consumed": False,
            "nearest_build_fallback": "FORBIDDEN",
        },
        "item_route_differential": differential,
        "set_item_special_slot": set_summary,
        "shop_item_substitution_map": substitution_summary,
        "inventory_snapshots": snapshot_summary,
        "inventory_swap": swap_summary,
        "item_storage_value": charge_summary,
        "missing_purchase_use_path": missing_summary,
        "inventory_state_simulation": state_summary,
        "sale_identity_state_recovery": sale_summary,
        "undo_snapshot_path": undo_summary,
        "support_quest_item_stage_snapshot_crossref": support_quest_crossref,
        "item_group_data_boundary": {
            "route": "0x0405 PKT_S2C_SetItemGroupData_Broadcast_s",
            "observed_count": inventory_manifest["packet_counts"]["1029"],
            "stream_distribution": inventory_manifest["stream_counts_by_packet"]["1029"],
            "shape_sample_count": len(rows0405),
            "shape_sample_native_full_consume_count": sum(row.get("fully_consumed") is True for row in rows0405),
            "decision": "REJECT_INVENTORY_MEMBERSHIP; RETAIN_GROUP_DATA_COOLDOWN_ADJACENCY",
        },
        "promotion_decisions": [
            {
                "capability": "inventory_snapshot_exact_layout",
                "decision": "PROMOTE",
                "basis": "shared inline native layout, reset/apply callback, native decode, independent 0x0137 field anchor",
            },
            {
                "capability": "inventory_swap_exact_route",
                "decision": "PROMOTE",
                "basis": "RTTI identity, receive transforms, 258/258 native decode, exact slot domain",
            },
            {
                "capability": "shop_item_substitution_map",
                "decision": "PROMOTE",
                "basis": "exact RTTI/callback/deserializer chain, 8/8 native decode, deterministic two-pair map",
            },
            {
                "capability": "support_quest_item_stage_snapshot",
                "decision": "PROMOTE_BOUNDED_VERIFIED_DERIVED",
                "basis": "hashed 0x0064 audit plus independent 0311/02ea inventory presence on all eight UTILITY participants",
            },
            {
                "capability": "item_use_purchase_miss_path",
                "decision": "CANDIDATE_ONLY",
                "basis": "14/14 DETAILS adjacency plus exact UseItem route; no item-id field",
            },
            {
                "capability": "inventory_undo",
                "decision": "DERIVED_CANDIDATE_ONLY",
                "basis": "52/52 DETAILS-to-snapshot adjacency with large generic-route negative set",
            },
            {
                "capability": "pure_buy_sell_routes",
                "decision": "REJECT",
                "basis": "447/953 exact transition-carrier extras",
            },
        ],
        "route_decisions": [
            {
                "route": "0x005a",
                "decision": "PROMOTE",
                "claim": "EXACT_SHOP_ITEM_SUBSTITUTION_MAP",
                "evidence_exhausted": True,
                "next_required_evidence": [],
            },
            {
                "route": "0x006c",
                "decision": "PROMOTE",
                "claim": "EXACT_SPECIAL_SLOT_SET_ITEM_CARRIER; REJECT_ITEM_UNDO_ALIAS",
                "evidence_exhausted": True,
                "next_required_evidence": [],
            },
            {
                "route": "0x0064",
                "decision": "PROMOTE",
                "claim": "SUPPORT_QUEST_ITEM_STAGE_SNAPSHOT_CANONICAL_UTILITY_SCOPE_ONLY",
                "evidence_exhausted": False,
                "next_required_evidence": [
                    "runtime callback/factory/deserializer identity and byte-0 meaning",
                    "classification of three-byte and noncanonical groups",
                ],
            },
            {
                "route": "0x01e8",
                "decision": "PROMOTE",
                "claim": "EXACT_INVENTORY_SWAP_CARRIER_AND_SLOT_SELECTORS",
                "evidence_exhausted": True,
                "next_required_evidence": [],
            },
            {
                "route": "0x0137/0x04b3",
                "decision": "REPURPOSE",
                "claim": "INVENTORY_STATE_TRANSITION_CARRIERS_NOT_UNIVERSAL_BUY_SELL",
                "evidence_exhausted": False,
                "next_required_evidence": [
                    "independent causes for the 100 unpaired additions and 269 unclassified removals"
                ],
            },
            {
                "route": "0x0310",
                "decision": "PROMOTE",
                "claim": "EXACT_ITEM_STORAGE_VALUE_UPDATE_CARRIER",
                "evidence_exhausted": True,
                "next_required_evidence": [],
            },
            {
                "route": "0x0311/0x02ea",
                "decision": "PROMOTE",
                "claim": "GENERIC_EXACT_SET_INVENTORY_SNAPSHOT_LAYOUT",
                "evidence_exhausted": False,
                "next_required_evidence": ["close the 154 conserved native-emulation failures on 0x0311"],
            },
            {
                "route": "0x0405",
                "decision": "REPURPOSE",
                "claim": "ITEM_GROUP_DATA_OR_COOLDOWN_ADJACENCY; REJECT_INVENTORY_MEMBERSHIP",
                "evidence_exhausted": False,
                "next_required_evidence": ["full native decode beyond the bounded shape sample"],
            },
            {
                "route": "0x041b",
                "decision": "KEEP_CANDIDATE",
                "claim": "IMMEDIATE_USE_OR_INVENTORYLESS_CONSUMABLE_PATH_FOR_2138_2139_2140",
                "evidence_exhausted": False,
                "next_required_evidence": ["an independent item-id-bearing route or runtime object link"],
            },
            {
                "route": "0x00b9/0x0092",
                "decision": "KEEP_CANDIDATE",
                "claim": "PAIRED_REPLICATION_OR_COMPONENT_ENVELOPE",
                "evidence_exhausted": False,
                "next_required_evidence": ["factory/deserializer identity and field-level component evidence"],
            },
            {
                "route": "specialized_entity_route_set",
                "decision": "PROMOTE",
                "claim": "EXACT_BUILD_PACKET_NAME_OWNER_FACTORY_DESERIALIZER_TAXONOMY",
                "evidence_exhausted": True,
                "next_required_evidence": [],
            },
        ],
        "capability_decisions": [
            {
                "capability": "inventory_snapshot_exact_layout",
                "decision": "PROMOTE",
                "scope": "0x0311_BROADCAST_AND_0x02ea_MAPVIEW_160_BYTE_RECORDS",
                "evidence_exhausted": False,
                "next_required_evidence": ["close the 154 conserved native-emulation failures on 0x0311"],
            },
            {
                "capability": "sale_prior_item_identity",
                "decision": "PROMOTE",
                "scope": "DETAILS_ALIGNED_0x04b3_SALES_WITH_RECOVERED_LIVE_STATE",
                "evidence_exhausted": True,
                "next_required_evidence": [],
            },
            {
                "capability": "inventory_undo_transition",
                "decision": "KEEP_CANDIDATE",
                "scope": "DETAILS_ALIGNED_DERIVED_TRANSITION_ONLY; NO_ROUTE_RENAME",
                "evidence_exhausted": False,
                "next_required_evidence": [
                    "independent explanation for the single 3363 logical restoration versus 3340 physical snapshot"
                ],
            },
            {
                "capability": "immediate_use_purchase_miss_path",
                "decision": "KEEP_CANDIDATE",
                "scope": "DETAILS_2138_2139_2140_TO_0x041b_ADJACENCY_ONLY",
                "evidence_exhausted": False,
                "next_required_evidence": ["independent item identity carried by the use route or linked runtime object"],
            },
            {
                "capability": "support_quest_item_stage_snapshot",
                "decision": "PROMOTE",
                "scope": "CANONICAL_TEN_ROW_GROUPS_AND_UTILITY_SLOTS_ONLY",
                "evidence_exhausted": False,
                "next_required_evidence": [
                    "runtime callback/factory/deserializer identity and byte-0 meaning",
                    "classification of three-byte and noncanonical groups",
                ],
            },
            {
                "capability": "universal_buy_sell_events_from_0x0137_0x04b3",
                "decision": "REJECT",
                "scope": "ALL_ROUTE_ROWS",
                "evidence_exhausted": True,
                "next_required_evidence": [],
            },
            {
                "capability": "entity_structural_taxonomy",
                "decision": "PROMOTE",
                "scope": "EXACT_BUILD_PACKET_NAME_OWNER_FACTORY_DESERIALIZER_METADATA",
                "evidence_exhausted": True,
                "next_required_evidence": [],
            },
            {
                "capability": "generic_normalized_entity_events",
                "decision": "REJECT",
                "scope": "ENTITY_CREATE_TEMPLATE_NAME_HASH_OWNER_TEAM_CLASS",
                "evidence_exhausted": True,
                "next_required_evidence": ["a new independent runtime or deserializer surface beyond the exhausted registrations"],
            },
        ],
        "domain_decisions": [
            {
                "domain": "item_economy_protocol_semantics",
                "decision": "PROMOTE",
                "scope": "EXACT_LAYOUTS_AND_BOUNDED_DERIVED_CROSS_REFERENCES_ONLY",
                "evidence_exhausted": False,
                "next_required_evidence": ["close conserved undo and 0137/04b3 cause-level residuals"],
            },
            {
                "domain": "entity_protocol_structural_taxonomy",
                "decision": "PROMOTE",
                "scope": "SPECIALIZED_EXACT_ROUTES_ONLY",
                "evidence_exhausted": True,
                "next_required_evidence": [],
            },
            {
                "domain": "generic_entity_semantics",
                "decision": "REJECT",
                "scope": "NO_GENERIC_CREATE_OR_OWNER_TEAM_CLASS_EVENT",
                "evidence_exhausted": True,
                "next_required_evidence": ["new independent exact-build evidence surface"],
            },
        ],
    }
    write_json(SUMMARY_OUT, summary)

    combined_alignment = alignment_rows + missing_rows + sale_rows + undo_rows
    combined_alignment.sort(
        key=lambda row: (
            row.get("game_id", ""),
            row.get("timestamp_ms", -1),
            row.get("participant_id", -1),
            row["kind"],
            row.get("route_key", ""),
        )
    )
    alignment_count = write_jsonl(ALIGNMENT_OUT, combined_alignment)
    REPORT_OUT.write_text(build_report(summary, taxonomy), encoding="utf-8", newline="\n")

    hash_inputs = input_paths + [Path(__file__), ROOT / "tests" / "test_entity_item_deep_recovery_v2.py"]
    hash_outputs = [SUMMARY_OUT, TAXONOMY_OUT, ALIGNMENT_OUT, REPORT_OUT]
    hashes = {
        "schema": "ENTITY_ITEM_DEEP_RECOVERY_HASH_MANIFEST_V2",
        "build": BUILD,
        "runtime_image_sha256": IMAGE_SHA256,
        "alignment_row_count": alignment_count,
        "inputs": [
            {
                "path": str(path.resolve()),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "line_count": line_count(path) if path.suffix in {".json", ".jsonl", ".py"} else None,
            }
            for path in hash_inputs
        ],
        "outputs": [
            {
                "path": str(path.resolve()),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "line_count": line_count(path),
            }
            for path in hash_outputs
        ],
        "protected_holdout_access": {
            "enumerated": False,
            "read": False,
            "hashed": False,
            "decoded": False,
            "tested": False,
            "consumed": False,
        },
    }
    write_json(HASHES_OUT, hashes)
    print(json.dumps({
        "summary": str(SUMMARY_OUT),
        "taxonomy": str(TAXONOMY_OUT),
        "alignment": str(ALIGNMENT_OUT),
        "alignment_row_count": alignment_count,
        "report": str(REPORT_OUT),
        "hashes": str(HASHES_OUT),
    }, indent=2))


if __name__ == "__main__":
    main()
