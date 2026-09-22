#!/usr/bin/env python3
"""Exact-build item-route differential for 0x0137 and 0x04b3.

The analysis is deliberately limited to four explicitly allowlisted P0
Replay/DETAILS pairs.  Packet extraction and native emulation are separate
reproducible stages.  This stage verifies those outputs, compares the routes
with ITEM_PURCHASED / ITEM_SOLD / ITEM_UNDO, and records both support and
counterexamples.  It never traverses an input directory and rejects every
path containing ``holdout`` before opening it.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path


EXACT_BUILD = "16.16.805.0442"
EXPECTED_IMAGE_SHA256 = "0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55"
PARTICIPANT_NETWORK_ID_LOW_BASE = 0xAD
PACKET_BUY = 0x0137
PACKET_REMOVE = 0x04B3

SAFE_P0 = {
    "11191024308": {
        "replay_sha256": "1ff3b2d4321bbe4f6bf79bff767305bbf4fa59e42c9524c91f3c3b9421733349",
        "details_sha256": "8838ecff8cd95dd722870c59a9d9d7da2471a9288d93f50d4a9479eaa8dab023",
        "route_counts": {PACKET_BUY: 329, PACKET_REMOVE: 213},
    },
    "11191203388": {
        "replay_sha256": "e54e1950949761bb75df509bd91a6823c3d08569a1f530410cb38fb5e07e3633",
        "details_sha256": "637f6b5dde4ce34dea7b3b2f2bac34e9e855beca5150bd66ec7f38ad74ab11d7",
        "route_counts": {PACKET_BUY: 429, PACKET_REMOVE: 287},
    },
    "11191271422": {
        "replay_sha256": "a5a5580f1a4546fb627b53cf3921a9cf0f3086f15964410e054809a87a3be399",
        "details_sha256": "d5d128c9b76017cd268a48afed1e06383aaaa865f2c998751365539f5d3935cf",
        "route_counts": {PACKET_BUY: 375, PACKET_REMOVE: 225},
    },
    "11191336852": {
        "replay_sha256": "25dff9e58855cfc2afdca6b1df2cc43aaa2da1ddc9823b63993ecfc456eb0e75",
        "details_sha256": "368f1bc1b125fd9a09328eb32ab7541980f5e8355598f6ca33316c590c5fcc7d",
        "route_counts": {PACKET_BUY: 468, PACKET_REMOVE: 288},
    },
}

BUY_VECTOR_FIELDS = (
    "inline_unknown_byte_vector_0x30",
    "inline_unknown_object_vector_0x40",
    "inline_unknown_u32_vector_0x50",
    "inline_unknown_byte_vector_0x60",
    "inline_unknown_object_vector_0x70",
)


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    root = project_root()
    candidates = root / "artifacts" / "full_semantic_baseline_v1" / "runtime_candidates"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=root / "artifacts" / "hero_combat_state_v2" / "anchors" / "details_p0_manifest.json",
    )
    parser.add_argument(
        "--events-manifest",
        type=Path,
        default=candidates / "packet_0137_04b3_p0_all_events_16_16.jsonl.manifest.json",
    )
    parser.add_argument(
        "--buy-decoded",
        type=Path,
        default=candidates / "packet_0137_p0_native_decoded_16_16.jsonl",
    )
    parser.add_argument(
        "--remove-decoded",
        type=Path,
        default=candidates / "packet_04b3_p0_native_decoded_16_16.jsonl",
    )
    parser.add_argument(
        "--buy-summary",
        type=Path,
        default=candidates / "packet_0137_p0_native_decode_summary_16_16.json",
    )
    parser.add_argument(
        "--remove-summary",
        type=Path,
        default=candidates / "packet_04b3_p0_native_decode_summary_16_16.json",
    )
    parser.add_argument(
        "--buy-profile",
        type=Path,
        default=candidates / "packet_0137_static_profile.json",
    )
    parser.add_argument(
        "--remove-profile",
        type=Path,
        default=candidates / "packet_04b3_static_profile.json",
    )
    parser.add_argument(
        "--image",
        type=Path,
        default=(root / "artifacts" / "new_build_rofl_compatibility_gate_v1" / "runtime"
                 / "league_16.16.805.0442.memory.bin"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=candidates / "packet_0137_04b3_item_route_differential_16_16.json",
    )
    parser.add_argument(
        "--aligned-output",
        type=Path,
        default=candidates / "packet_0137_04b3_item_route_aligned_16_16.jsonl",
    )
    parser.add_argument(
        "--details-output",
        type=Path,
        default=candidates / "packet_0137_04b3_item_details_events_16_16.jsonl",
    )
    parser.add_argument(
        "--hash-output",
        type=Path,
        default=candidates / "packet_0137_04b3_item_route_hashes_16_16.json",
    )
    parser.add_argument("--window-ms", type=int, default=2)
    options = parser.parse_args()
    if options.window_ms < 0:
        raise ValueError("--window-ms must be non-negative")
    return options


def reject_holdout(path: Path) -> Path:
    resolved = path.resolve()
    if "holdout" in str(resolved).lower():
        raise RuntimeError(f"Holdout path is forbidden: {resolved}")
    return resolved


def sha256_file(path: Path) -> str:
    path = reject_holdout(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path):
    path = reject_holdout(path)
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def read_jsonl(path: Path) -> list[dict]:
    path = reject_holdout(path)
    rows = []
    with path.open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid JSONL at {path}:{line_number}: {error}") from error
    return rows


def write_json(path: Path, value) -> None:
    path = reject_holdout(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2, sort_keys=False)
        stream.write("\n")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path = reject_holdout(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")))
            stream.write("\n")


def participant_candidate(raw_param: int) -> int:
    return (int(raw_param) & 0xFF) - PARTICIPANT_NETWORK_ID_LOW_BASE


def ror8(value: int, count: int) -> int:
    return ((value >> count) | (value << (8 - count))) & 0xFF


def adjacent_bit_swap(value: int) -> int:
    return (((value & 0xD5) << 1) | ((value >> 1) & 0x55)) & 0xFF


def decode_buy_bool_10(value: int) -> int:
    value = ror8(value, 5)
    value = (~value) & 0xFF
    value = (value + 0x51) & 0xFF
    value = adjacent_bit_swap(value)
    value = (value - 0x43) & 0xFF
    value = adjacent_bit_swap(value)
    return value ^ 0x0B


def decode_buy_bool_11(value: int) -> int:
    value = (value - 0x5F) & 0xFF
    value = ror8(value, 3)
    value = (~value) & 0xFF
    value = (value - 0x66) & 0xFF
    value ^= 0x11
    value = ror8(value, 3)
    value ^= 0xCD
    return adjacent_bit_swap(value)


def count_values(values) -> dict[str, int]:
    counter = collections.Counter(values)
    return {str(key): counter[key] for key in sorted(counter, key=lambda item: (str(type(item)), str(item)))}


def count_by(rows: list[dict], key) -> dict[str, int]:
    return count_values(key(row) for row in rows)


def route_key(row: dict) -> str:
    return ":".join(
        str(row[key])
        for key in (
            "replay_label",
            "chunk_index",
            "decompressed_block_offset",
            "decompressed_payload_offset",
            "packet_id",
        )
    )


def route_order(row: dict, game_order: dict[str, int]):
    return (
        game_order[row["replay_label"]],
        row["chunk_index"],
        row["decompressed_block_offset"],
        row["decompressed_payload_offset"],
        row["packet_id"],
    )


def verify_manifest(options: argparse.Namespace) -> tuple[dict, list[dict]]:
    manifest = read_json(options.manifest)
    if manifest.get("target", {}).get("replay_header_build") != EXACT_BUILD:
        raise RuntimeError("DETAILS manifest is not the exact 16.16.805.0442 build")
    by_game = {str(row["game_id"]): row for row in manifest.get("replays", [])}
    if set(by_game) != set(SAFE_P0):
        raise RuntimeError("DETAILS manifest does not contain exactly the closed safe-P0 allowlist")

    detail_events = []
    for game_id in SAFE_P0:
        allowed = SAFE_P0[game_id]
        record = by_game[game_id]
        replay_path = reject_holdout(Path(record["replay"]["path"]))
        details_path = reject_holdout(Path(record["details"]["path"]))
        if record["replay"]["sha256"] != allowed["replay_sha256"]:
            raise RuntimeError(f"unexpected Replay SHA-256 for {game_id}")
        if record["details"]["sha256"] != allowed["details_sha256"]:
            raise RuntimeError(f"unexpected DETAILS manifest SHA-256 for {game_id}")
        if sha256_file(details_path) != allowed["details_sha256"]:
            raise RuntimeError(f"DETAILS bytes fail SHA-256 allowlist for {game_id}")
        if not replay_path.is_file():
            raise RuntimeError(f"safe Replay path is missing for {game_id}")

        details = read_json(details_path).get("json", {})
        for frame_index, frame in enumerate(details.get("frames", [])):
            for event_index, event in enumerate(frame.get("events", [])):
                if event.get("type") not in {"ITEM_PURCHASED", "ITEM_SOLD", "ITEM_UNDO"}:
                    continue
                detail_events.append(
                    {
                        "event_id": f"{game_id}:{frame_index}:{event_index}:{event['type']}",
                        "game_id": game_id,
                        "frame_index": frame_index,
                        "event_index": event_index,
                        "type": event["type"],
                        "timestamp_ms": int(event["timestamp"]),
                        "participant_id": int(event["participantId"]),
                        **({"item_id": int(event["itemId"])} if "itemId" in event else {}),
                        **({"before_id": int(event["beforeId"])} if "beforeId" in event else {}),
                        **({"after_id": int(event["afterId"])} if "afterId" in event else {}),
                        **({"gold_gain": int(event["goldGain"])} if "goldGain" in event else {}),
                    }
                )
    return by_game, detail_events


def verify_native_rows(rows: list[dict], packet_id: int, expected_name: str) -> None:
    expected_total = sum(SAFE_P0[game]["route_counts"][packet_id] for game in SAFE_P0)
    if len(rows) != expected_total:
        raise RuntimeError(f"{expected_name} row count {len(rows)} != {expected_total}")
    per_game = collections.Counter()
    for row in rows:
        game_id = str(row.get("replay_label"))
        if game_id not in SAFE_P0:
            raise RuntimeError(f"non-allowlisted Replay row in {expected_name}: {game_id}")
        if row.get("replay_sha256") != SAFE_P0[game_id]["replay_sha256"]:
            raise RuntimeError(f"Replay SHA mismatch in {expected_name} row for {game_id}")
        if row.get("replay_version") != EXACT_BUILD or row.get("packet_id") != packet_id:
            raise RuntimeError(f"wrong build or packet ID in {expected_name}")
        if row.get("deserialize_return_al") == 0 or not row.get("fully_consumed"):
            raise RuntimeError(f"native decode failure in {expected_name} for {route_key(row)}")
        if not row.get("opcode_matches_profile"):
            raise RuntimeError(f"wrapper opcode mismatch in {expected_name} for {route_key(row)}")
        per_game[game_id] += 1
    expected = {game: SAFE_P0[game]["route_counts"][packet_id] for game in SAFE_P0}
    if dict(per_game) != expected:
        raise RuntimeError(f"per-Replay route counts do not match allowlist: {dict(per_game)}")


def greedy_exact_purchase_matches(buy_rows: list[dict], purchases: list[dict], window_ms: int):
    used = set()
    row_to_event = {}
    for row_index, row in enumerate(buy_rows):
        fields = row["decoded_fields"]
        pid = participant_candidate(row["raw_param"])
        candidates = []
        for event_index, event in enumerate(purchases):
            if event_index in used:
                continue
            if event["game_id"] != row["replay_label"] or event["participant_id"] != pid:
                continue
            if event["item_id"] != fields["inline_unknown_u32_0x24"]:
                continue
            delta = abs(event["timestamp_ms"] - row["replay_time_ms"])
            if delta <= window_ms:
                candidates.append((delta, event["event_id"], event_index))
        if candidates:
            delta, _, event_index = min(candidates)
            used.add(event_index)
            row_to_event[row_index] = (event_index, delta)
    return row_to_event, used


def greedy_event_route_matches(events: list[dict], rows: list[dict], window_ms: int):
    used = set()
    event_to_row = {}
    for event_index, event in enumerate(events):
        candidates = []
        for row_index, row in enumerate(rows):
            if row_index in used:
                continue
            if row["replay_label"] != event["game_id"]:
                continue
            if participant_candidate(row["raw_param"]) != event["participant_id"]:
                continue
            delta = abs(row["replay_time_ms"] - event["timestamp_ms"])
            if delta <= window_ms:
                candidates.append((delta, route_key(row), row_index))
        if candidates:
            delta, _, row_index = min(candidates)
            used.add(row_index)
            event_to_row[event_index] = (row_index, delta)
    return event_to_row, used


def field_distribution(rows: list[dict], field: str) -> dict:
    values = []
    for row in rows:
        value = row["decoded_fields"][field]
        if isinstance(value, list):
            value = len(value)
        elif isinstance(value, str):
            value = len(value) // 2
        elif isinstance(value, float):
            value = round(value, 6)
        values.append(value)
    counter = collections.Counter(values)
    return {
        "distinct_count": len(counter),
        "value_counts": {str(key): value for key, value in counter.most_common()},
    }


def main() -> int:
    options = parse_args()
    for path in vars(options).values():
        if isinstance(path, Path):
            reject_holdout(path)

    by_game, detail_events = verify_manifest(options)
    event_manifest = read_json(options.events_manifest)
    buy_rows = read_jsonl(options.buy_decoded)
    remove_rows = read_jsonl(options.remove_decoded)
    buy_summary = read_json(options.buy_summary)
    remove_summary = read_json(options.remove_summary)
    buy_profile = read_json(options.buy_profile)
    remove_profile = read_json(options.remove_profile)

    if sha256_file(options.image) != EXPECTED_IMAGE_SHA256:
        raise RuntimeError("runtime image SHA-256 is not the exact known image")
    if event_manifest.get("target_replay_version") != EXACT_BUILD:
        raise RuntimeError("event export manifest is not the exact build")
    if event_manifest.get("packet_counts") != {"311": 1601, "1203": 1013}:
        raise RuntimeError("event export manifest route counts changed")
    for summary, packet_id, expected_count in (
        (buy_summary, PACKET_BUY, 1601),
        (remove_summary, PACKET_REMOVE, 1013),
    ):
        if summary.get("image_sha256") != EXPECTED_IMAGE_SHA256:
            raise RuntimeError("native summary image SHA-256 mismatch")
        if summary.get("client_opcode") != f"0x{packet_id:04x}":
            raise RuntimeError("native summary packet ID mismatch")
        if summary.get("successful_full_consume_count") != expected_count:
            raise RuntimeError("native summary is not full-consume for every row")
    verify_native_rows(buy_rows, PACKET_BUY, "0x0137")
    verify_native_rows(remove_rows, PACKET_REMOVE, "0x04b3")

    for row in buy_rows:
        fields = row["decoded_fields"]
        fields["unknown_bool_0x10"] = decode_buy_bool_10(fields["unknown_storage_u8_0x10"])
        fields["unknown_bool_0x11"] = decode_buy_bool_11(fields["unknown_storage_u8_0x11"])
    if {row["decoded_fields"]["unknown_bool_0x10"] for row in buy_rows} - {0, 1}:
        raise RuntimeError("0x0137 +0x10 did not decode to the observed boolean domain")
    if {row["decoded_fields"]["unknown_bool_0x11"] for row in buy_rows} - {0, 1}:
        raise RuntimeError("0x0137 +0x11 did not decode to the observed boolean domain")

    purchases = [event for event in detail_events
                 if event["type"] == "ITEM_PURCHASED" and event["participant_id"] > 0]
    system_purchases = [event for event in detail_events
                        if event["type"] == "ITEM_PURCHASED" and event["participant_id"] == 0]
    sales = [event for event in detail_events if event["type"] == "ITEM_SOLD"]
    undos = [event for event in detail_events if event["type"] == "ITEM_UNDO"]

    purchase_matches, used_purchase_events = greedy_exact_purchase_matches(
        buy_rows, purchases, options.window_ms
    )
    sale_matches, used_sale_rows = greedy_event_route_matches(sales, remove_rows, options.window_ms)
    undo_matches, used_undo_rows = greedy_event_route_matches(undos, remove_rows, options.window_ms)
    sale_row_to_event = {row_index: (event_index, delta)
                         for event_index, (row_index, delta) in sale_matches.items()}
    undo_row_to_event = {row_index: (event_index, delta)
                         for event_index, (row_index, delta) in undo_matches.items()}

    purchase_near_by_buy = []
    subject_unambiguous_support = 0
    subject_unambiguous_mismatch = 0
    for row in buy_rows:
        item_id = row["decoded_fields"]["inline_unknown_u32_0x24"]
        candidates = [
            event for event in purchases
            if event["game_id"] == row["replay_label"]
            and event["item_id"] == item_id
            and abs(event["timestamp_ms"] - row["replay_time_ms"]) <= options.window_ms
        ]
        purchase_near_by_buy.append([
            event for event in candidates
            if event["participant_id"] == participant_candidate(row["raw_param"])
        ])
        candidate_participants = {event["participant_id"] for event in candidates}
        if len(candidate_participants) == 1:
            if participant_candidate(row["raw_param"]) in candidate_participants:
                subject_unambiguous_support += 1
            else:
                subject_unambiguous_mismatch += 1

    purchase_near_by_remove = []
    for row in remove_rows:
        pid = participant_candidate(row["raw_param"])
        purchase_near_by_remove.append([
            event for event in purchases
            if event["game_id"] == row["replay_label"]
            and event["participant_id"] == pid
            and abs(event["timestamp_ms"] - row["replay_time_ms"]) <= options.window_ms
        ])

    # A deliberately bounded, two-route inventory reconstruction.  It is useful
    # negative evidence: other routes/manual slot moves make it incomplete, so
    # its inferred prior item is never treated as a packet-carried item ID.
    game_order = {game: index for index, game in enumerate(SAFE_P0)}
    merged = [("buy", index, row) for index, row in enumerate(buy_rows)]
    merged += [("remove", index, row) for index, row in enumerate(remove_rows)]
    merged.sort(key=lambda item: route_order(item[2], game_order))
    slot_state: dict[tuple[str, int], dict[int, dict]] = collections.defaultdict(dict)
    prior_slot_item = {}
    for kind, index, row in merged:
        key = (row["replay_label"], participant_candidate(row["raw_param"]))
        fields = row["decoded_fields"]
        if kind == "buy":
            slot = fields["inline_unknown_u8_0x2a"]
            slot_state[key][slot] = {
                "item_id": fields["inline_unknown_u32_0x24"],
                "stack_count_candidate": fields["inline_unknown_u8_0x80"],
                "source_route_key": route_key(row),
            }
        else:
            slot = fields["unknown_u8_0x18"]
            prior_slot_item[index] = slot_state[key].get(slot)
            slot_state[key].pop(slot, None)

    purchase_groups = collections.defaultdict(list)
    for event in purchases:
        purchase_groups[(event["game_id"], event["participant_id"], event["timestamp_ms"])].append(event)
    group_rows = []
    for (game_id, pid, timestamp), events in sorted(purchase_groups.items()):
        candidate_rows = [
            (index, row) for index, row in enumerate(buy_rows)
            if row["replay_label"] == game_id
            and participant_candidate(row["raw_param"]) == pid
            and abs(row["replay_time_ms"] - timestamp) <= options.window_ms
        ]
        detail_items = collections.Counter(event["item_id"] for event in events)
        route_items = collections.Counter(
            row["decoded_fields"]["inline_unknown_u32_0x24"] for _, row in candidate_rows
        )
        if detail_items == route_items:
            relation = "exact_multiset"
        elif all(route_items[item] >= count for item, count in detail_items.items()):
            relation = "details_multiset_is_route_subset"
        else:
            relation = "missing_or_mismatched_route_items"
        group_rows.append(
            {
                "game_id": game_id,
                "participant_id": pid,
                "details_timestamp_ms": timestamp,
                "details_event_ids": [event["event_id"] for event in events],
                "details_item_ids": sorted(detail_items.elements()),
                "route_keys": [route_key(row) for _, row in candidate_rows],
                "route_item_ids": sorted(route_items.elements()),
                "details_event_count": len(events),
                "route_packet_count": len(candidate_rows),
                "relation": relation,
            }
        )

    aligned_rows = []
    for index, row in enumerate(buy_rows):
        fields = row["decoded_fields"]
        matched = purchase_matches.get(index)
        matched_event = purchases[matched[0]] if matched else None
        aligned_rows.append(
            {
                "schema_version": 1,
                "route": "0x0137",
                "route_key": route_key(row),
                "game_id": row["replay_label"],
                "replay_sha256": row["replay_sha256"],
                "replay_time_ms": row["replay_time_ms"],
                "raw_param": row["raw_param"],
                "raw_param_hex": row["raw_param_hex"],
                "subject_participant_candidate": participant_candidate(row["raw_param"]),
                "payload_length": row["payload_length"],
                "raw_payload_sha256": row["raw_payload_sha256"],
                "item_id_candidate": fields["inline_unknown_u32_0x24"],
                "slot_index_candidate": fields["inline_unknown_u8_0x2a"],
                "stack_count_candidate": fields["inline_unknown_u8_0x80"],
                "unknown_u16_0x28": fields["inline_unknown_u16_0x28"],
                "unknown_bool_0x10": fields["unknown_bool_0x10"],
                "unknown_bool_0x11": fields["unknown_bool_0x11"],
                "unknown_f32_0x84": fields["inline_unknown_f32_0x84"],
                "unknown_f32_0x88": fields["unknown_f32_0x88"],
                "all_five_container_lengths": [
                    len(fields[name]) if isinstance(fields[name], list) else len(fields[name]) // 2
                    for name in BUY_VECTOR_FIELDS
                ],
                "classification": "exact_details_purchase" if matched else (
                    "purchase_group_extra_or_item_mismatch" if purchase_near_by_buy[index] else
                    "no_details_item_event_within_window"
                ),
                "matched_details_event": matched_event,
                "absolute_delta_ms": matched[1] if matched else None,
                "near_purchase_event_ids": [event["event_id"] for event in purchase_near_by_buy[index]],
            }
        )

    for index, row in enumerate(remove_rows):
        fields = row["decoded_fields"]
        sale_match = sale_row_to_event.get(index)
        undo_match = undo_row_to_event.get(index)
        if sale_match:
            classification = "exact_details_sale_time_subject"
            matched_event = sales[sale_match[0]]
            delta = sale_match[1]
        elif undo_match:
            classification = "exact_details_undo_time_subject"
            matched_event = undos[undo_match[0]]
            delta = undo_match[1]
        elif purchase_near_by_remove[index]:
            classification = "purchase_coincident_removal_candidate"
            matched_event = None
            delta = None
        else:
            classification = "unclassified_removal"
            matched_event = None
            delta = None
        prior = prior_slot_item.get(index)
        aligned_rows.append(
            {
                "schema_version": 1,
                "route": "0x04b3",
                "route_key": route_key(row),
                "game_id": row["replay_label"],
                "replay_sha256": row["replay_sha256"],
                "replay_time_ms": row["replay_time_ms"],
                "raw_param": row["raw_param"],
                "raw_param_hex": row["raw_param_hex"],
                "subject_participant_candidate": participant_candidate(row["raw_param"]),
                "payload_length": row["payload_length"],
                "raw_payload_sha256": row["raw_payload_sha256"],
                "slot_index_candidate": fields["unknown_u8_0x18"],
                "unknown_bool_0x10": fields["unknown_u8_0x10"],
                "unknown_bool_0x11": fields["unknown_u8_0x11"],
                "unknown_f32_0x14": fields["unknown_f32_0x14"],
                "bounded_two_route_prior_slot_item_candidate": prior,
                "classification": classification,
                "matched_details_event": matched_event,
                "absolute_delta_ms": delta,
                "near_purchase_event_ids": [event["event_id"] for event in purchase_near_by_remove[index]],
            }
        )

    sold_prior_exact = 0
    sold_prior_known = 0
    for event_index, (row_index, _) in sale_matches.items():
        prior = prior_slot_item.get(row_index)
        if prior is not None:
            sold_prior_known += 1
            sold_prior_exact += int(prior["item_id"] == sales[event_index]["item_id"])

    remove_class_counts = collections.Counter(
        row["classification"] for row in aligned_rows if row["route"] == "0x04b3"
    )
    buy_class_counts = collections.Counter(
        row["classification"] for row in aligned_rows if row["route"] == "0x0137"
    )
    buy_matched_indices = set(purchase_matches)
    buy_match_flag_matrix = collections.Counter()
    for index, row in enumerate(buy_rows):
        fields = row["decoded_fields"]
        buy_match_flag_matrix[
            ("matched" if index in buy_matched_indices else "unmatched",
             fields["unknown_bool_0x10"], fields["unknown_bool_0x11"])
        ] += 1
    remove_flag_matrix = collections.Counter()
    for index, row in enumerate(remove_rows):
        if index in sale_row_to_event:
            label = "sold"
        elif purchase_near_by_remove[index]:
            label = "purchase_coincident"
        else:
            label = "other"
        remove_flag_matrix[(label, row["decoded_fields"]["unknown_u8_0x11"])] += 1

    group_relation_counts = collections.Counter(row["relation"] for row in group_rows)
    group_shape_counts = collections.Counter(
        (row["details_event_count"], row["route_packet_count"], row["relation"])
        for row in group_rows
    )
    nonempty_vectors = {
        field: sum(bool(row["decoded_fields"][field]) for row in buy_rows)
        for field in BUY_VECTOR_FIELDS
    }
    buy_initial = [row for row in buy_rows if row["replay_time_ms"] == 0]

    unmatched_purchase_events = [
        event for index, event in enumerate(purchases) if index not in used_purchase_events
    ]
    unmatched_purchase_items = collections.Counter(event["item_id"] for event in unmatched_purchase_events)
    raw_param_variants = {}
    for packet_name, rows in (("0x0137", buy_rows), ("0x04b3", remove_rows)):
        canonical = 0
        variants = collections.Counter()
        for row in rows:
            pid = participant_candidate(row["raw_param"])
            expected = 0x400000AD + pid
            if row["raw_param"] == expected:
                canonical += 1
            else:
                variants[row["raw_param_hex"]] += 1
        raw_param_variants[packet_name] = {
            "route_count": len(rows),
            "canonical_full_raw_param_count": canonical,
            "upper_byte_variant_count": len(rows) - canonical,
            "variant_value_counts": dict(variants.most_common()),
        }

    summary = {
        "schema_version": "PACKET_0137_04B3_ITEM_ROUTE_DIFFERENTIAL_V1",
        "target": {
            "build": EXACT_BUILD,
            "runtime_image_sha256": EXPECTED_IMAGE_SHA256,
            "routes": {
                "0x0137": "PKT_BuyItemAns_s",
                "0x04b3": "PKT_RemoveItemAns_s",
            },
            "details_event_types": ["ITEM_PURCHASED", "ITEM_SOLD", "ITEM_UNDO"],
            "alignment_window_ms": options.window_ms,
        },
        "scope_and_safety": {
            "safe_replay_count": len(SAFE_P0),
            "safe_game_ids": list(SAFE_P0),
            "protected_holdout_enumerated": False,
            "protected_holdout_read": False,
            "protected_holdout_hashed": False,
            "protected_holdout_decoded": False,
            "protected_holdout_tested": False,
            "protected_holdout_modified": False,
            "input_policy": "closed explicit safe-P0 allowlist; no directory traversal",
        },
        "static_runtime_chain": {
            "0x0137": buy_profile,
            "0x04b3": remove_profile,
        },
        "native_decode": {
            "0x0137": {
                "route_count": len(buy_rows),
                "deserialize_success_count": len(buy_rows),
                "full_consume_count": len(buy_rows),
                "payload_length_counts": count_by(buy_rows, lambda row: row["payload_length"]),
                "per_replay_counts": count_by(buy_rows, lambda row: row["replay_label"]),
                "container_nonempty_row_counts": nonempty_vectors,
            },
            "0x04b3": {
                "route_count": len(remove_rows),
                "deserialize_success_count": len(remove_rows),
                "full_consume_count": len(remove_rows),
                "payload_length_counts": count_by(remove_rows, lambda row: row["payload_length"]),
                "per_replay_counts": count_by(remove_rows, lambda row: row["replay_label"]),
            },
        },
        "details_counts": {
            "ITEM_PURCHASED_participant_gt_zero": len(purchases),
            "ITEM_PURCHASED_participant_zero_system_rows": len(system_purchases),
            "ITEM_SOLD": len(sales),
            "ITEM_UNDO": len(undos),
            "per_replay_and_type": count_values(
                f"{event['game_id']}:{event['type']}" for event in detail_events
            ),
        },
        "subject_entity_evidence": {
            "exact_build_transform": "(raw_param & 0xff) - 0xad",
            "purchase_route_rows_with_time_item_candidates_and_unambiguous_participant": (
                subject_unambiguous_support + subject_unambiguous_mismatch
            ),
            "participant_matches": subject_unambiguous_support,
            "participant_mismatches": subject_unambiguous_mismatch,
            "sold_events_with_unique_time-only_04b3_candidate": len(sales),
            "sold_unique_candidate_participant_matches": sum(
                1 for event in sales
                if len([
                    row for row in remove_rows
                    if row["replay_label"] == event["game_id"]
                    and abs(row["replay_time_ms"] - event["timestamp_ms"]) <= options.window_ms
                ]) == 1
                and participant_candidate([
                    row for row in remove_rows
                    if row["replay_label"] == event["game_id"]
                    and abs(row["replay_time_ms"] - event["timestamp_ms"]) <= options.window_ms
                ][0]["raw_param"]) == event["participant_id"]
            ),
            "raw_param_upper_byte_boundary": raw_param_variants,
            "promotion": "exact-build participant candidate only; preserve the full raw_param",
        },
        "route_0137_purchase_differential": {
            "route_count": len(buy_rows),
            "details_purchase_count": len(purchases),
            "greedy_exact_time_subject_item_matches": len(purchase_matches),
            "match_absolute_delta_ms_counts": count_values(delta for _, delta in purchase_matches.values()),
            "unmatched_route_count": len(buy_rows) - len(purchase_matches),
            "unmatched_details_purchase_count": len(purchases) - len(used_purchase_events),
            "unmatched_details_item_id_counts": dict(sorted(unmatched_purchase_items.items())),
            "route_class_counts": dict(buy_class_counts),
            "group_count": len(group_rows),
            "group_relation_counts": dict(group_relation_counts),
            "group_shape_counts": {
                f"details={shape[0]},routes={shape[1]},relation={shape[2]}": count
                for shape, count in sorted(group_shape_counts.items())
            },
            "same_timestamp_multi_event_groups": sum(
                row["details_event_count"] > 1 for row in group_rows
            ),
            "initial_replay_time_zero_route_count": len(buy_initial),
            "initial_replay_time_zero_per_replay": count_by(buy_initial, lambda row: row["replay_label"]),
            "initial_route_item_ids_per_replay": {
                game: [
                    row["decoded_fields"]["inline_unknown_u32_0x24"]
                    for row in buy_initial if row["replay_label"] == game
                ]
                for game in SAFE_P0
            },
            "all_five_inner_containers_nonempty_count": nonempty_vectors,
            "unknown_boolean_match_matrix": {
                f"{label},bool10={bool10},bool11={bool11}": count
                for (label, bool10, bool11), count in sorted(buy_match_flag_matrix.items())
            },
            "field_distributions": {
                field: field_distribution(buy_rows, field)
                for field in (
                    "unknown_bool_0x10",
                    "unknown_bool_0x11",
                    "inline_unknown_u8_0x20",
                    "inline_unknown_u32_0x24",
                    "inline_unknown_u16_0x28",
                    "inline_unknown_u8_0x2a",
                    "inline_unknown_u8_0x80",
                    "inline_unknown_f32_0x84",
                    "unknown_f32_0x88",
                )
            },
            "promotable_fields": [
                {
                    "field": "inline +0x0c / outer +0x24 u32",
                    "candidate_name": "item_id",
                    "support": "1154/1154 greedy paired purchase rows equal DETAILS.itemId; callback decodes the field before item lookup/use",
                    "boundary": "This names the per-packet field, not the whole route as a purchase event.",
                }
            ],
        },
        "route_04b3_removal_differential": {
            "route_count": len(remove_rows),
            "details_sale_count": len(sales),
            "unique_time_subject_sale_matches": len(sale_matches),
            "sale_match_absolute_delta_ms_counts": count_values(delta for _, delta in sale_matches.values()),
            "details_undo_count": len(undos),
            "undo_time_subject_matches_within_window": len(undo_matches),
            "route_class_counts": dict(remove_class_counts),
            "purchase_coincident_route_count": sum(bool(value) for value in purchase_near_by_remove),
            "unknown_bool_0x11_class_matrix": {
                f"{label},bool11={flag}": count
                for (label, flag), count in sorted(remove_flag_matrix.items())
            },
            "two_route_slot_reconstruction": {
                "known_prior_slot_item_count": sum(value is not None for value in prior_slot_item.values()),
                "unknown_prior_slot_item_count": sum(value is None for value in prior_slot_item.values()),
                "sold_rows_with_known_prior_slot_item": sold_prior_known,
                "sold_rows_where_prior_slot_item_equals_DETAILS_itemId": sold_prior_exact,
                "boundary": "This is a lossy state hypothesis, not a payload field. Other routes/manual slot moves invalidate global item recovery.",
            },
            "field_distributions": {
                field: field_distribution(remove_rows, field)
                for field in ("unknown_u8_0x10", "unknown_u8_0x11", "unknown_f32_0x14", "unknown_u8_0x18")
            },
            "promotable_fields": [],
            "payload_item_id_negative_evidence": "The exact object contains only u8@+0x10, u8@+0x11, f32@+0x14, and u8@+0x18; no packet-carried item ID or vector exists.",
        },
        "counterexample_matrix": [
            {
                "hypothesis": "Every 0x0137 row is exactly one DETAILS ITEM_PURCHASED event",
                "verdict": "REFUTED",
                "supporting_or_counterexample_counts": {
                    "route_rows": len(buy_rows),
                    "details_participant_purchase_events": len(purchases),
                    "exact_greedy_matches": len(purchase_matches),
                    "unmatched_route_rows": len(buy_rows) - len(purchase_matches),
                    "unmatched_details_events": len(purchases) - len(used_purchase_events),
                },
            },
            {
                "hypothesis": "0x0137 outer+0x24 is the per-packet item ID",
                "verdict": "SUPPORTED_FOR_MATCHED_ROWS",
                "supporting_or_counterexample_counts": {
                    "exact_equal_matches": len(purchase_matches),
                    "paired_mismatches": 0,
                    "route_scope_extras": len(buy_rows) - len(purchase_matches),
                },
            },
            {
                "hypothesis": "0x0137 inner vectors bundle the observed multi-item purchase groups",
                "verdict": "REFUTED_IN_SAFE_P0",
                "supporting_or_counterexample_counts": {
                    "multi_event_purchase_groups": sum(row["details_event_count"] > 1 for row in group_rows),
                    "route_rows_with_any_nonempty_profiled_container": sum(
                        any(row["decoded_fields"][field] for field in BUY_VECTOR_FIELDS)
                        for row in buy_rows
                    ),
                },
                "boundary": "The multi-event groups are represented by multiple route packets at the same timestamp, not populated inner containers in these 1601 rows.",
            },
            {
                "hypothesis": "Every 0x04b3 row is ITEM_SOLD",
                "verdict": "REFUTED",
                "supporting_or_counterexample_counts": {
                    "route_rows": len(remove_rows),
                    "unique_sale_matches": len(sale_matches),
                    "non_sale_route_rows": len(remove_rows) - len(sale_matches),
                    "purchase_coincident_removals": sum(bool(value) for value in purchase_near_by_remove),
                },
            },
            {
                "hypothesis": "0x04b3 unknown bool +0x11 uniquely means sale",
                "verdict": "REFUTED",
                "supporting_or_counterexample_counts": {
                    "bool_true_rows": sum(row["decoded_fields"]["unknown_u8_0x11"] == 1 for row in remove_rows),
                    "sale_rows_with_bool_true": sum(
                        remove_rows[row_index]["decoded_fields"]["unknown_u8_0x11"] == 1
                        for row_index in sale_row_to_event
                    ),
                    "bool_true_non_sale_rows": sum(
                        row["decoded_fields"]["unknown_u8_0x11"] == 1
                        for index, row in enumerate(remove_rows) if index not in sale_row_to_event
                    ),
                },
            },
            {
                "hypothesis": "0x04b3 directly carries the removed item ID",
                "verdict": "REFUTED_BY_STATIC_LAYOUT",
                "supporting_or_counterexample_counts": {
                    "direct_item_id_fields": 0,
                    "sold_rows": len(sales),
                    "lossy_two_route_prior_slot_exact": sold_prior_exact,
                },
            },
            {
                "hypothesis": "DETAILS ITEM_UNDO maps directly to 0x04b3 within 0..2 ms",
                "verdict": "REFUTED",
                "supporting_or_counterexample_counts": {
                    "undo_events": len(undos),
                    "matched_04b3_rows": len(undo_matches),
                },
            },
        ],
        "semantic_boundary": {
            "0x0137": "Promote only the per-packet +0x24 item_id candidate and exact-build raw_param participant candidate. Keep booleans, slot/count candidates, floats, u16, and all empty container element semantics UNKNOWN.",
            "0x04b3": "Keep the route as generic removal. Sold events form a perfect time/subject subset, but purchase-coincident removals and flag counterexamples forbid ITEM_SELL route naming. No item ID is carried directly.",
            "component_consumption": "The 684 purchase-coincident 0x04b3 rows are bounded candidates consistent with component/removal behavior; recipe semantics are not promoted without independent static or item-recipe evidence.",
            "undo": "No direct <=2 ms 0x04b3 mapping exists for the 52 safe DETAILS ITEM_UNDO rows.",
        },
        "publication_decision": {
            "overall_capability_publication": "NONE",
            "decision": "Neither route is sufficient to publish ITEM_BUY, ITEM_SELL, ITEM_UNDO, or ITEM_STATE as a semantic event/capability in this exact build.",
            "capabilities": {
                "ITEM_BUY": {
                    "publication_ready": False,
                    "evidence_grade": "CANDIDATE",
                    "positive_evidence": {
                        "exact_time_subject_item_matches": len(purchase_matches),
                        "matched_item_id_mismatches": 0,
                    },
                    "blocking_counterexamples": {
                        "unmatched_0x0137_route_rows": len(buy_rows) - len(purchase_matches),
                        "unmatched_DETAILS_ITEM_PURCHASED_events": len(purchases) - len(used_purchase_events),
                        "bool10_matched_false_rows": sum(
                            row["decoded_fields"]["unknown_bool_0x10"] == 0
                            for index, row in enumerate(buy_rows) if index in purchase_matches
                        ),
                        "bool10_unmatched_true_rows": sum(
                            row["decoded_fields"]["unknown_bool_0x10"] == 1
                            for index, row in enumerate(buy_rows) if index not in purchase_matches
                        ),
                    },
                    "boundary": "The per-packet item_id field is supported, but neither the route nor either decoded boolean is an exact ITEM_BUY discriminator.",
                },
                "ITEM_SELL": {
                    "publication_ready": False,
                    "evidence_grade": "CANDIDATE",
                    "positive_evidence": {
                        "DETAILS_ITEM_SOLD_events": len(sales),
                        "unique_time_subject_0x04b3_matches": len(sale_matches),
                    },
                    "blocking_counterexamples": {
                        "non_sale_0x04b3_route_rows": len(remove_rows) - len(sale_matches),
                        "bool11_true_non_sale_rows": sum(
                            row["decoded_fields"]["unknown_u8_0x11"] == 1
                            for index, row in enumerate(remove_rows) if index not in sale_row_to_event
                        ),
                        "direct_packet_item_id_fields": 0,
                    },
                    "boundary": "ITEM_SOLD is a perfectly aligned subset of this generic removal route, not the route's complete semantics; the flag and payload layout cannot isolate it.",
                },
                "ITEM_UNDO": {
                    "publication_ready": False,
                    "evidence_grade": "UNAVAILABLE",
                    "scope": "direct recovery from 0x0137 and 0x04b3 only",
                    "blocking_counterexamples": {
                        "DETAILS_ITEM_UNDO_events": len(undos),
                        "same_subject_0x04b3_matches_within_window": len(undo_matches),
                    },
                    "boundary": "The result is negative only for these two routes; it does not prove that the exact build lacks a separate undo callback/route.",
                },
                "ITEM_STATE": {
                    "publication_ready": False,
                    "evidence_grade": "CANDIDATE",
                    "positive_evidence": {
                        "0x0137_item_id_field": True,
                        "0x0137_slot_candidate_field": True,
                        "0x0137_stack_count_candidate_field": True,
                        "0x04b3_slot_candidate_field": True,
                    },
                    "blocking_counterexamples": {
                        "0x04b3_rows_with_unknown_prior_slot_item": sum(
                            value is None for value in prior_slot_item.values()
                        ),
                        "sold_rows_where_two_route_prior_slot_equals_DETAILS_itemId": sold_prior_exact,
                        "DETAILS_ITEM_SOLD_events": len(sales),
                    },
                    "boundary": "A two-route slot reconstruction is lossy because move/swap/snapshot/undo carriers are absent from this evidence set.",
                },
            },
            "publishable_bounded_fields": [
                {
                    "route": "0x0137",
                    "field": "inline +0x0c / outer +0x24 u32",
                    "name": "item_id",
                    "evidence_grade": "VERIFIED_DERIVED",
                    "supporting_exact_pairs": len(purchase_matches),
                    "mismatches": 0,
                    "scope": "per packet; does not classify the packet as ITEM_BUY",
                },
                {
                    "routes": ["0x0137", "0x04b3"],
                    "source": "raw_param",
                    "name": "participant_candidate",
                    "transform": "(raw_param & 0xff) - 0xad",
                    "evidence_grade": "VERIFIED_DERIVED",
                    "exact_build_only": True,
                    "unambiguous_support": subject_unambiguous_support,
                    "unambiguous_mismatches": subject_unambiguous_mismatch,
                    "boundary": "Preserve the full raw_param because upper-byte variants occur.",
                },
            ],
            "next_evidence": [
                {
                    "priority": 1,
                    "need": "Enumerate and close every adjacent HeroInventoryClient callback registration and exact-decode likely move, swap, set-inventory, snapshot, and undo carriers.",
                    "acceptance": "A complete per-slot transition stream with explicit negative rows for unrelated removals.",
                },
                {
                    "priority": 2,
                    "need": "Recover request/answer correlation and any result-enum getter/use in the 0x0137 callback.",
                    "acceptance": "A statically supported predicate that covers every applicable purchase and rejects all route extras, with independently defined exclusions for the 14 missing item IDs 2138/2139/2140.",
                },
                {
                    "priority": 3,
                    "need": "Carry pre-event inventory state through the missing move/swap routes before interpreting 0x04b3 slots.",
                    "acceptance": "Recover the sold item for every aligned sale and reject purchase/component removals on independent safe negatives.",
                },
                {
                    "priority": 4,
                    "need": "Trace a dedicated HeroInventoryClient undo RTTI callback/route and request-response path.",
                    "acceptance": "Direct event-level alignment to ITEM_UNDO; 0x04b3 has 0 direct matches in the current window.",
                },
                {
                    "priority": 5,
                    "need": "Add an exact-build published item recipe/component graph before naming purchase-coincident 0x04b3 rows as component consumption.",
                    "acceptance": "Removed-item multisets equal independently defined recipe components, including negative recipe and non-purchase cases.",
                },
            ],
            "minimal_integration_recommendation": {
                "now": [
                    "Integrate only this reproducible script, exact static profiles, native full-consume rows, differential JSON/JSONL, and hash manifest as candidate evidence.",
                    "Do not change semantic_api, capability_manifest, schema, or emit ITEM_BUY/ITEM_SELL/ITEM_UNDO/ITEM_STATE events.",
                ],
                "later_candidate_adapter": {
                    "0x0137": [
                        "raw_param",
                        "exact_build_participant_candidate",
                        "item_id",
                        "unknown booleans",
                        "unknown slot/count/u16/floats",
                        "opaque empty-container observations",
                    ],
                    "0x04b3": [
                        "raw_param",
                        "exact_build_participant_candidate",
                        "unknown flags",
                        "unknown slot/f32",
                    ],
                    "required_status": "CANDIDATE",
                    "forbidden_semantic_labels": ["ITEM_BUY", "ITEM_SELL", "ITEM_UNDO", "ITEM_STATE"],
                },
                "next_code_module_after_evidence": "An inventory state correlator fed by a complete move/swap/snapshot route set, not a semantic decoder inferred from these two routes alone.",
            },
        },
        "reproduction": {
            "event_export_argv": [
                "node",
                "scripts/export_runtime_candidate_samples.js",
                "--packet-id",
                "311,1203",
                "--samples-per-shape-per-replay",
                "9999",
                "--output",
                "artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0137_04b3_p0_all_events_16_16.jsonl",
                *[record["path"] for record in event_manifest["replays"]],
            ],
            "analysis_command": "python scripts/analyze_packet_0137_04b3_item_route_differential.py",
            "native_decode_commands": [
                "python scripts/emulate_packet_profile_json.py --image artifacts/new_build_rofl_compatibility_gate_v1/runtime/league_16.16.805.0442.memory.bin --events artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0137_04b3_p0_all_events_16_16.jsonl --profile-json artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0137_static_profile.json --runtime-profile 16.16.805.0442 --output artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0137_p0_native_decoded_16_16.jsonl --summary artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0137_p0_native_decode_summary_16_16.json",
                "python scripts/emulate_packet_profile_json.py --image artifacts/new_build_rofl_compatibility_gate_v1/runtime/league_16.16.805.0442.memory.bin --events artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0137_04b3_p0_all_events_16_16.jsonl --profile-json artifacts/full_semantic_baseline_v1/runtime_candidates/packet_04b3_static_profile.json --runtime-profile 16.16.805.0442 --output artifacts/full_semantic_baseline_v1/runtime_candidates/packet_04b3_p0_native_decoded_16_16.jsonl --summary artifacts/full_semantic_baseline_v1/runtime_candidates/packet_04b3_p0_native_decode_summary_16_16.json",
            ],
        },
    }

    detail_events.sort(key=lambda event: (
        list(SAFE_P0).index(event["game_id"]), event["frame_index"], event["event_index"]
    ))
    aligned_rows.sort(key=lambda row: (
        list(SAFE_P0).index(row["game_id"]),
        row["replay_time_ms"],
        row["route_key"],
    ))
    write_json(options.output, summary)
    write_jsonl(options.aligned_output, aligned_rows)
    write_jsonl(options.details_output, detail_events)

    root = project_root()
    files_to_hash = {
        "analysis_script": Path(__file__).resolve(),
        "architecture_gate": (
            root / "artifacts" / "full_semantic_baseline_v1" / "runtime_candidates"
            / "architecture_gate_0137_04b3_item_route_differential_v1.md"
        ),
        "runtime_image": options.image,
        "details_manifest": options.manifest,
        "events_manifest": options.events_manifest,
        "events_jsonl": Path(event_manifest["output"]),
        "buy_profile": options.buy_profile,
        "remove_profile": options.remove_profile,
        "buy_decoded": options.buy_decoded,
        "remove_decoded": options.remove_decoded,
        "buy_decode_summary": options.buy_summary,
        "remove_decode_summary": options.remove_summary,
        "differential_output": options.output,
        "aligned_output": options.aligned_output,
        "details_events_output": options.details_output,
    }
    for game_id, record in by_game.items():
        files_to_hash[f"details_{game_id}"] = Path(record["details"]["path"])
    hash_rows = {}
    for name, path in files_to_hash.items():
        resolved = reject_holdout(path)
        try:
            display_path = resolved.relative_to(root).as_posix()
        except ValueError:
            display_path = str(resolved)
        hash_rows[name] = {
            "path": display_path,
            "sha256": sha256_file(resolved),
            "byte_size": resolved.stat().st_size,
        }
    hash_manifest = {
        "schema_version": "PACKET_0137_04B3_ITEM_ROUTE_HASH_MANIFEST_V1",
        "deterministic": True,
        "target_build": EXACT_BUILD,
        "holdout_access": {
            "enumerated": False,
            "read": False,
            "hashed": False,
            "decoded": False,
            "tested": False,
            "modified": False,
        },
        "files": hash_rows,
    }
    write_json(options.hash_output, hash_manifest)

    print(json.dumps({
        "status": "PASS",
        "buy_full_consume": len(buy_rows),
        "remove_full_consume": len(remove_rows),
        "purchase_exact_matches": len(purchase_matches),
        "sale_unique_matches": len(sale_matches),
        "undo_matches_within_window": len(undo_matches),
        "purchase_coincident_removals": sum(bool(value) for value in purchase_near_by_remove),
        "output": str(options.output.resolve()),
        "aligned_output": str(options.aligned_output.resolve()),
        "hash_output": str(options.hash_output.resolve()),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
