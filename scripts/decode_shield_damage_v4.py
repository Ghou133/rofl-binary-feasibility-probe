#!/usr/bin/env python3
"""Decode current-client PKT_UnitApplyShieldDamage_s (opcode 0x0017).

This decoder is deliberately V4-only.  It reuses the frozen exact-packet
emulator without changing it, applies the field transforms used by the
current-client callback, and optionally correlates each row to the first
same-target UnitApplyDamage packet that follows at the same Replay timestamp.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import struct
import sys
from pathlib import Path
from typing import Any, Iterable

from emulate_exact_packet_decoder import ExactPacketEmulator


PROFILE = {
    "client_opcode": 0x0017,
    # The inline factory initializes the object.  For isolated deserializer
    # emulation, the RET at the end of the adjacent tiny initializer is a
    # deterministic no-op entry; the deserializer writes every payload field.
    "constructor_rva": 0x002CD334,
    "deserialize_rva": 0x00F1DB80,
    "object_size": 0x20,
    "fields": [],
}

EXPECTED_IMAGE_SHA256 = (
    "7ee788155b9ba61d10603694cffb095e66ab3c641f933e4e7b181000c69f61bb"
)
FIELD_DECODE_TABLE_RVA = 0x01A27940
DECODER_PROFILE = "rofl-16.15.801.3452-unit-apply-shield-damage-v4"

ORDER_FIELDS = (
    "chunk_index",
    "chunk_id",
    "chunk_stream",
    "chunk_file_offset",
    "compressed_body_offset",
    "decompressed_block_offset",
    "decompressed_payload_offset",
    "replay_time_ms",
    "occurrence_index",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--events", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary")
    parser.add_argument(
        "--damage-events",
        help="Optional decoded UnitApplyDamage JSONL for strict neighbor correlation.",
    )
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def rotate_left_8(value: int, count: int) -> int:
    return ((value << count) | (value >> (8 - count))) & 0xFF


def rotate_right_8(value: int, count: int) -> int:
    return ((value >> count) | (value << (8 - count))) & 0xFF


def interleave_transform(value: int) -> int:
    return ((((value & 0xD5) << 1) & 0xFF) | ((value >> 1) & 0x55)) & 0xFF


def decode_field_10(encoded: bytes, table: bytes) -> bytes:
    decoded = bytearray()
    for value in encoded:
        value = (value + 0x64) & 0xFF
        value = table[value]
        value = table[value ^ 0x19]
        decoded.append((value + 0x71) & 0xFF)
    return bytes(decoded)


def decode_field_14(encoded: bytes, table: bytes) -> bytes:
    decoded = bytearray()
    for value in encoded:
        value ^= 0xCD
        value = rotate_right_8(value, 4)
        value = rotate_left_8(value, 3)
        value = table[value]
        value = rotate_right_8(value, 4)
        value = (value + 0x0A) & 0xFF
        decoded.append((~value) & 0xFF)
    return bytes(decoded)


def decode_field_18(encoded: bytes) -> bytes:
    return bytes(
        (((interleave_transform(value) + 0x7F) & 0xFF) ^ 0x4D)
        for value in encoded
    )


def decode_field_1c(encoded: bytes, table: bytes) -> bytes:
    decoded = bytearray()
    for value in encoded:
        value ^= 0x45
        value = rotate_left_8(value, 1)
        value = table[value]
        value = (value + 0x4B) & 0xFF
        value = rotate_right_8(value, 3)
        decoded.append(interleave_transform(value))
    return bytes(decoded)


def run_self_test(table: bytes) -> dict[str, bool]:
    checks = {
        "field_10_zero": (
            decode_field_10(bytes.fromhex("48484848"), table).hex()
            == "00000000"
        ),
        "field_14_target_b6": (
            decode_field_14(bytes.fromhex("459797f5"), table).hex()
            == "b6000040"
        ),
        "field_18_amount_375": (
            decode_field_18(bytes.fromhex("8caebb4f")).hex() == "8691bb43"
        ),
        "field_1c_target_b6": (
            decode_field_1c(bytes.fromhex("366e6ed4"), table).hex()
            == "b6000040"
        ),
    }
    failed = [name for name, passed in checks.items() if not passed]
    if failed:
        raise AssertionError(f"shield-damage transform self-test failed: {failed}")
    return checks


def _integer(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _damage_fields(row: dict[str, Any]) -> dict[str, Any]:
    fields = row.get("decoded_fields")
    return fields if isinstance(fields, dict) else row


def load_damage_candidates(paths: Iterable[str]) -> dict[tuple[Any, ...], list[dict[str, Any]]]:
    candidates: dict[tuple[Any, ...], list[dict[str, Any]]] = collections.defaultdict(list)
    for path in paths:
        with Path(path).open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                row = json.loads(line)
                fields = _damage_fields(row)
                target = _integer(fields.get("target_network_id"))
                key = (
                    row.get("replay_sha256"),
                    row.get("chunk_index"),
                    row.get("replay_time_ms"),
                    target,
                )
                candidates[key].append(row)
    for rows in candidates.values():
        rows.sort(
            key=lambda row: (
                row.get("decompressed_block_offset") is None,
                row.get("decompressed_block_offset"),
                row.get("decompressed_payload_offset") is None,
                row.get("decompressed_payload_offset"),
                row.get("occurrence_index") is None,
                row.get("occurrence_index"),
            )
        )
    return candidates


def correlate_damage(
    row: dict[str, Any],
    damage_candidates: dict[tuple[Any, ...], list[dict[str, Any]]],
) -> dict[str, Any] | None:
    key = (
        row.get("replay_sha256"),
        row.get("chunk_index"),
        row.get("replay_time_ms"),
        row.get("target_network_id"),
    )
    shield_offset = row.get("decompressed_block_offset")
    if shield_offset is None:
        return None
    following = [
        candidate
        for candidate in damage_candidates.get(key, [])
        if candidate.get("decompressed_block_offset") is not None
        and candidate["decompressed_block_offset"] > shield_offset
    ]
    if not following:
        return None
    candidate = following[0]
    fields = _damage_fields(candidate)
    damage_amount = fields.get("amount")
    combined = (
        row["shield_absorbed_amount"] + float(damage_amount)
        if damage_amount is not None
        else None
    )
    return {
        "relation": "FIRST_SAME_TARGET_SAME_TIMESTAMP_FOLLOWING_UNIT_APPLY_DAMAGE",
        "semantic_status": "VERIFIED_ORDERED_NEIGHBOR",
        "source_network_id": _integer(fields.get("source_network_id")),
        "target_network_id": _integer(fields.get("target_network_id")),
        "unit_apply_damage_amount": damage_amount,
        "combined_shield_plus_unit_apply_damage_amount": combined,
        "combined_amount_status": "DERIVED_SUM_OF_TWO_DIRECT_PACKET_AMOUNTS",
        "chunk_index": candidate.get("chunk_index"),
        "decompressed_block_offset": candidate.get("decompressed_block_offset"),
        "decompressed_payload_offset": candidate.get("decompressed_payload_offset"),
        "damage_occurrence_index": candidate.get("occurrence_index"),
        "block_offset_delta": candidate["decompressed_block_offset"] - shield_offset,
        "raw_payload_sha256": candidate.get("raw_payload_sha256"),
        "raw_payload_hex": candidate.get("raw_payload_hex"),
    }


def decode_row(
    emulator: ExactPacketEmulator,
    event: dict[str, Any],
    table: bytes,
    image_sha256: str,
) -> dict[str, Any]:
    decoded = emulator.decode(
        bytes.fromhex(event["raw_payload_hex"]),
        PROFILE,
        packet_id=_integer(event.get("packet_id")),
        raw_param=_integer(event.get("raw_param")),
    )
    object_bytes = bytes.fromhex(decoded["object_hex"])
    field_10_bytes = decode_field_10(object_bytes[0x10:0x14], table)
    field_14_bytes = decode_field_14(object_bytes[0x14:0x18], table)
    field_18_bytes = decode_field_18(object_bytes[0x18:0x1C])
    field_1c_bytes = decode_field_1c(object_bytes[0x1C:0x20], table)
    field_10 = struct.unpack("<I", field_10_bytes)[0]
    field_14 = struct.unpack("<I", field_14_bytes)[0]
    amount = struct.unpack("<f", field_18_bytes)[0]
    field_1c = struct.unpack("<I", field_1c_bytes)[0]
    raw_target = _integer(event.get("raw_param"))
    if not math.isfinite(amount):
        raise RuntimeError("decoded shield-damage amount is non-finite")

    source = {key: event.get(key) for key in ORDER_FIELDS}
    source.update(
        {
            "replay_path": event.get("replay_path"),
            "replay_sha256": event.get("replay_sha256"),
            "replay_version": event.get("replay_version"),
            "replay_label": event.get("replay_label"),
        }
    )
    return {
        "schema_version": 1,
        **source,
        "packet_id": 0x0017,
        "packet_id_hex": "0x0017",
        "packet_type_name": "PKT_UnitApplyShieldDamage_s",
        "event_kind": "SHIELD_ABSORBED_DIRECT",
        "semantic_status": "VERIFIED_DIRECT",
        "target_network_id": field_1c,
        "target_network_id_hex": f"0x{field_1c:08x}",
        "network_id_field_14": field_14,
        "network_id_field_14_hex": f"0x{field_14:08x}",
        "protocol_field_10": field_10,
        "shield_absorbed_amount": amount,
        "shield_absorbed_amount_bits_hex": f"0x{struct.unpack('<I', field_18_bytes)[0]:08x}",
        "network_fields_agree": field_14 == field_1c,
        "target_matches_raw_param": raw_target == field_1c,
        "deserialize_return_al": decoded["deserialize_return_al"],
        "bytes_consumed": decoded["bytes_consumed"],
        "fully_consumed": decoded["fully_consumed"],
        "outer_object_hex": decoded["object_hex"],
        "decoded_field_bytes_hex": {
            "field_10": field_10_bytes.hex(),
            "field_14": field_14_bytes.hex(),
            "field_18": field_18_bytes.hex(),
            "field_1c": field_1c_bytes.hex(),
        },
        "raw_param": raw_target,
        "raw_param_hex": event.get("raw_param_hex"),
        "raw_payload_hex": event.get("raw_payload_hex"),
        "raw_payload_sha256": event.get("raw_payload_sha256"),
        "raw_packet_ref": {
            key: event.get(key)
            for key in (
                "replay_path",
                "replay_sha256",
                *ORDER_FIELDS,
                "packet_id",
                "payload_length",
                "raw_param",
                "raw_param_hex",
                "raw_payload_sha256",
            )
        },
        "decoder_profile": DECODER_PROFILE,
        "decoder_runtime_image_sha256": image_sha256,
        "static_client_chain": {
            "factory_inline_construction_rva": "0x00ede2f8",
            "opcode_write_rva": "0x00ede31b",
            "packet_vtable_rva": "0x01b108a8",
            "deserializer_rva": "0x00f1db80",
            "callback_rva": "0x0029edd0",
            "rtti_getter_rva": "0x002ca9c0",
            "rtti_descriptor_rva": "0x01e7be40",
        },
    }


def main() -> None:
    options = parse_args()
    image = Path(options.image).read_bytes()
    image_sha256 = hashlib.sha256(image).hexdigest()
    if image_sha256 != EXPECTED_IMAGE_SHA256:
        raise RuntimeError(
            "PROTECTION_PROFILE_UNSUPPORTED: runtime image hash does not match "
            f"the verified 16.15.801.3452 image ({image_sha256})"
        )
    table = image[FIELD_DECODE_TABLE_RVA:FIELD_DECODE_TABLE_RVA + 0x100]
    if len(table) != 0x100:
        raise RuntimeError("runtime image does not contain the field-decode table")
    self_test = run_self_test(table)
    if options.self_test:
        print(json.dumps({"self_test": self_test}, indent=2))

    damage_candidates = load_damage_candidates(
        [options.damage_events] if options.damage_events else []
    )
    event_manifest_path = Path(f"{options.events}.manifest.json")
    event_manifest = (
        json.loads(event_manifest_path.read_text(encoding="utf-8"))
        if event_manifest_path.exists()
        else None
    )
    if not isinstance(event_manifest, dict) or (
        event_manifest.get("schema_version") != 1
        or event_manifest.get("target_replay_version") != "16.15.801.3452"
        or event_manifest.get("packet_ids") != [PROFILE["client_opcode"]]
        or Path(event_manifest.get("output", "")).resolve() != Path(options.events).resolve()
        or not isinstance(event_manifest.get("replays"), list)
    ):
        raise RuntimeError("0x0017 decoder requires a valid export manifest bound to --events")
    emulator = ExactPacketEmulator(image)
    rows: list[dict[str, Any]] = []
    with Path(options.events).open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            if _integer(event.get("packet_id")) != PROFILE["client_opcode"]:
                raise ValueError(
                    f"line {line_number} has packet {event.get('packet_id')}; expected 0x0017"
                )
            row = decode_row(emulator, event, table, image_sha256)
            neighbor = correlate_damage(row, damage_candidates)
            if neighbor is not None:
                row["related_unit_apply_damage"] = neighbor
            rows.append(row)
    if (
        event_manifest.get("selected_packet_count") != len(rows)
        or event_manifest.get("packet_counts") != {str(PROFILE["client_opcode"]): len(rows)}
    ):
        raise RuntimeError(
            "input manifest selected_packet_count does not match decoded rows"
        )

    output_path = Path(options.output).resolve()
    summary_path = Path(options.summary or f"{options.output}.summary.json").resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")))
            stream.write("\n")

    field_10_counts = collections.Counter(row["protocol_field_10"] for row in rows)
    summary = {
        "schema_version": 1,
        "method": (
            "Frozen Unicorn exact-packet emulator plus exact callback field "
            "transforms recovered from the current client"
        ),
        "image_path": os.path.abspath(options.image),
        "image_sha256": image_sha256,
        "decoder_runtime_image_sha256": image_sha256,
        "events_path": os.path.abspath(options.events),
        "events_sha256": hashlib.sha256(Path(options.events).read_bytes()).hexdigest(),
        "events_manifest_path": (
            str(event_manifest_path.resolve()) if event_manifest is not None else None
        ),
        "events_manifest_sha256": (
            hashlib.sha256(event_manifest_path.read_bytes()).hexdigest()
            if event_manifest is not None else None
        ),
        "damage_events_path": (
            os.path.abspath(options.damage_events) if options.damage_events else None
        ),
        "damage_events_sha256": (
            hashlib.sha256(Path(options.damage_events).read_bytes()).hexdigest()
            if options.damage_events else None
        ),
        "output_path": str(output_path),
        "decoder_profile": DECODER_PROFILE,
        "client_opcode": "0x0017",
        "packet_type_name": "PKT_UnitApplyShieldDamage_s",
        "constructor_noop_rva": "0x002cd334",
        "deserialize_rva": "0x00f1db80",
        "callback_rva": "0x0029edd0",
        "self_test": self_test,
        "input_event_count": len(rows),
        "scan_replay_count": (
            event_manifest.get("replay_count") if event_manifest is not None else None
        ),
        "scan_selected_packet_count": (
            event_manifest.get("selected_packet_count")
            if event_manifest is not None else None
        ),
        "scan_parser_error_count": (
            sum(item.get("parser_error_count", 0) for item in event_manifest.get("replays", []))
            if event_manifest is not None else None
        ),
        "scan_replays": (
            [
                {
                    "replay_sha256": item.get("sha256"),
                    "replay_path": item.get("path"),
                    "replay_version": item.get("version"),
                    "selected_packet_count": item.get("selected_packet_count"),
                    "parser_error_count": item.get("parser_error_count"),
                }
                for item in event_manifest.get("replays", [])
            ]
            if event_manifest is not None else None
        ),
        "deserialize_success_count": sum(
            row["deserialize_return_al"] != 0 for row in rows
        ),
        "fully_consumed_count": sum(row["fully_consumed"] for row in rows),
        "network_fields_agree_count": sum(row["network_fields_agree"] for row in rows),
        "target_matches_raw_param_count": sum(
            row["target_matches_raw_param"] for row in rows
        ),
        "damage_neighbor_correlation_count": sum(
            "related_unit_apply_damage" in row for row in rows
        ),
        "protocol_field_10_counts": {
            str(key): value for key, value in sorted(field_10_counts.items())
        },
        "shield_absorbed_amounts": [row["shield_absorbed_amount"] for row in rows],
        "output_event_count": len(rows),
        "output_replay_counts": dict(sorted(collections.Counter(
            row["replay_sha256"] for row in rows
        ).items())),
        "semantic_contract": {
            "shield_absorbed_amount": "VERIFIED_DIRECT",
            "target_network_id": "VERIFIED_DIRECT",
            "related_unit_apply_damage_amount": "VERIFIED_DIRECT_NEIGHBOR",
            "combined_shield_plus_unit_apply_damage_amount": "VERIFIED_DERIVED_SUM",
            "protocol_field_10": "UNRESOLVED",
        },
        "output_sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
    }
    with summary_path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(summary, stream, ensure_ascii=True, indent=2)
        stream.write("\n")
    print(json.dumps({**summary, "summary_path": str(summary_path)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(1)
