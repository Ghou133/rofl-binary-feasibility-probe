#!/usr/bin/env python3

"""Decode exact-build 16.16 PKT_OnEvent_s storage for deep recovery.

The output is deliberately research-only.  Event-name strings and the matching
16.15 event IDs/layouts are treated as hypotheses until exact-build anchors and
counterexamples are evaluated by the companion analysis.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import math
import pathlib
import struct
import sys
from typing import Any


BUILD = "16.16.805.0442"
EXPECTED_IMAGE_SHA256 = (
    "0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55"
)
PROFILE = {
    "client_opcode": 0x0371,
    "constructor_rva": 0x00E7E630,
    "deserialize_rva": 0x00FCC3F0,
    "object_size": 0x30,
    "fields": [
        {"name": "event_id_storage", "offset": 0x10, "type": "u32"},
        {"name": "parameter_blob", "offset": 0x18, "type": "byte_vector_hex"},
        {"name": "dispatch_code_storage", "offset": 0x28, "type": "u16"},
    ],
}

# Cross-build hypotheses only.  Exact 16.16 strings exist in the runtime, but
# the string and the prior ID/layout are not by themselves promotion authority.
EVENT_HYPOTHESES = {
    0x004B: {
        "runtime_event_name": "OnCastHeal",
        "parameter_type": "ParamsHeal",
        "expected_schema_id": 0x7C044FE1,
        "expected_parameter_size": 0x34,
        "candidate_kind": "HEAL_REPORTED_CANDIDATE",
    },
    0x00ED: {
        "runtime_event_name": "OnReceiveShield",
        "parameter_type": "ShieldingParams",
        "expected_schema_id": 0x8F7F3F4E,
        "expected_parameter_size": 0x14,
        "candidate_kind": "SHIELD_RECEIVE_CANDIDATE",
    },
    0x00EE: {
        "runtime_event_name": "OnGrantShield",
        "parameter_type": "ShieldingParams",
        "expected_schema_id": 0x8F7F3F4E,
        "expected_parameter_size": 0x14,
        "candidate_kind": "SHIELD_GRANT_CANDIDATE",
    },
    0x00EF: {
        "runtime_event_name": "OnDamageShielded",
        "parameter_type": "DamageShieldedParams",
        "expected_schema_id": None,
        "expected_parameter_size": None,
        "candidate_kind": "DAMAGE_SHIELDED_LAYOUT_UNKNOWN",
    },
}

ORDER_FIELDS = (
    "chunk_index", "chunk_id", "chunk_stream", "chunk_stream_tag",
    "chunk_file_offset", "compressed_body_offset", "decompressed_block_offset",
    "decompressed_payload_offset", "replay_time_ms", "occurrence_index",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--events", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--summary")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--progress-every", type=int, default=10000)
    return parser.parse_args()


def reject_holdout(value: str, label: str) -> pathlib.Path:
    resolved = pathlib.Path(value).resolve()
    if "holdout" in str(resolved).lower():
        raise ValueError(f"{label} must not reference protected Holdout content: {resolved}")
    return resolved


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_emulator_module(script_root: pathlib.Path):
    source = script_root / "emulate_exact_packet_decoder.py"
    specification = importlib.util.spec_from_file_location("exact_packet_emulator_reuse", source)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load exact emulator: {source}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module, source


def rotate_right_8(value: int, count: int) -> int:
    return ((value >> count) | (value << (8 - count))) & 0xFF


def swap_adjacent_bits(value: int) -> int:
    return (((value & 0xD5) << 1) | ((value >> 1) & 0x55)) & 0xFF


def decode_event_id(storage: int) -> int:
    output = bytearray()
    for value in storage.to_bytes(4, "little"):
        value ^= 0x50
        value = rotate_right_8(value, 5)
        value ^= 0xED
        value = rotate_right_8(value, 2)
        output.append(swap_adjacent_bits(value))
    return int.from_bytes(output, "little")


def decode_dispatch_code(storage: int) -> int:
    output = bytearray()
    for value in storage.to_bytes(2, "little"):
        value ^= 0x47
        value = rotate_right_8(value, 4)
        value = (value - 0x2A) & 0xFF
        value ^= 0x43
        value = (value - 0x11) & 0xFF
        output.append(value)
    return int.from_bytes(output, "little")


def decode_candidate_fields(event_id: int, parameter_bytes: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if event_id == 0x004B and len(parameter_bytes) == 0x34:
        amount_bits = struct.unpack_from("<I", parameter_bytes, 0x18)[0]
        result.update({
            "target_network_id_candidate": struct.unpack_from("<I", parameter_bytes, 0x04)[0],
            "source_network_id_candidate": struct.unpack_from("<I", parameter_bytes, 0x14)[0],
            "amount_candidate": struct.unpack_from("<f", parameter_bytes, 0x18)[0],
            "amount_bits_hex": f"0x{amount_bits:08x}",
            "unresolved_u32_fields": {
                f"0x{offset:02x}": struct.unpack_from("<I", parameter_bytes, offset)[0]
                for offset in (0x00, 0x08, 0x0C, 0x10, 0x1C, 0x20, 0x24, 0x28, 0x2C, 0x30)
            },
        })
    elif event_id in (0x00ED, 0x00EE) and len(parameter_bytes) == 0x14:
        amount_bits = struct.unpack_from("<I", parameter_bytes, 0x10)[0]
        result.update({
            "source_network_id_candidate": struct.unpack_from("<I", parameter_bytes, 0x08)[0],
            "target_network_id_candidate": struct.unpack_from("<I", parameter_bytes, 0x0C)[0],
            "amount_candidate": struct.unpack_from("<f", parameter_bytes, 0x10)[0],
            "amount_bits_hex": f"0x{amount_bits:08x}",
            "unresolved_u32_fields": {
                "0x00": struct.unpack_from("<I", parameter_bytes, 0x00)[0],
                "0x04": struct.unpack_from("<I", parameter_bytes, 0x04)[0],
            },
        })
    return result


def histogram(counter: collections.Counter) -> dict[str, int]:
    return {str(key): counter[key] for key in sorted(counter, key=lambda item: str(item))}


def runtime_string_evidence(image: bytes) -> dict[str, Any]:
    names = sorted({
        hypothesis["runtime_event_name"]
        for hypothesis in EVENT_HYPOTHESES.values()
    } | {
        hypothesis["parameter_type"]
        for hypothesis in EVENT_HYPOTHESES.values()
    })
    evidence = {}
    for name in names:
        needle = name.encode("ascii")
        offsets = []
        cursor = 0
        while True:
            found = image.find(needle, cursor)
            if found < 0:
                break
            offsets.append(f"0x{found:08x}")
            cursor = found + 1
        evidence[name] = {"present": bool(offsets), "rva_hex": offsets}
    return evidence


def main() -> None:
    options = parse_args()
    if options.limit is not None and options.limit < 1:
        raise ValueError("--limit must be positive")
    image_path = reject_holdout(options.image, "--image")
    events_path = reject_holdout(options.events, "--events")
    output_path = reject_holdout(options.output, "--output")
    summary_path = reject_holdout(options.summary or f"{options.output}.summary.json", "--summary")
    image = image_path.read_bytes()
    image_sha256 = hashlib.sha256(image).hexdigest()
    if image_sha256 != EXPECTED_IMAGE_SHA256:
        raise RuntimeError(f"exact image SHA mismatch: {image_sha256}")

    emulator_module, emulator_source = load_emulator_module(pathlib.Path(__file__).resolve().parent)
    emulator = emulator_module.ExactPacketEmulator(
        image,
        emulator_module.RUNTIME_PROFILES[BUILD],
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    counts = collections.Counter()
    event_counts = collections.Counter()
    event_size_counts = collections.Counter()
    replay_counts = collections.Counter()
    dispatch_counts = collections.Counter()
    amount_sign_counts = collections.Counter()
    entity_shape_counts = collections.Counter()
    selected_rows: list[dict[str, Any]] = []

    with events_path.open(encoding="utf-8-sig") as source, output_path.open(
        "w", encoding="utf-8", newline="\n",
    ) as destination:
        for line_number, line in enumerate(source, start=1):
            if options.limit is not None and counts["input_route_rows"] >= options.limit:
                break
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get("packet_id") != PROFILE["client_opcode"]:
                continue
            if event.get("replay_version") != BUILD:
                raise ValueError(f"line {line_number} has wrong build")
            decoded = emulator.decode(
                bytes.fromhex(event["raw_payload_hex"]),
                PROFILE,
                packet_id=event["packet_id"],
                raw_param=event["raw_param"],
            )
            fields = decoded["decoded_fields"]
            schema_id = decode_event_id(fields["event_id_storage"])
            event_id = decode_dispatch_code(fields["dispatch_code_storage"])
            parameter_bytes = bytes.fromhex(fields["parameter_blob"])
            hypothesis = EVENT_HYPOTHESES.get(event_id)
            counts["input_route_rows"] += 1
            counts["deserialize_success_rows"] += int(decoded["deserialize_return_al"] != 0)
            counts["fully_consumed_rows"] += int(decoded["fully_consumed"])
            event_counts[event_id] += 1
            event_size_counts[(event_id, len(parameter_bytes))] += 1
            replay_counts[event["replay_label"]] += 1
            dispatch_counts[event_id] += 1
            if hypothesis is None:
                continue

            candidate_fields = decode_candidate_fields(event_id, parameter_bytes)
            row = {
                "schema_version": 1,
                "build": BUILD,
                "replay_path": event["replay_path"],
                "replay_sha256": event["replay_sha256"],
                "replay_label": event["replay_label"],
                **{key: event.get(key) for key in ORDER_FIELDS},
                "packet_id": event["packet_id"],
                "event_id": event_id,
                "event_id_hex": f"0x{event_id:04x}",
                "schema_id": schema_id,
                "schema_id_hex": f"0x{schema_id:08x}",
                **hypothesis,
                "schema_id_matches_cross_build_hypothesis": (
                    hypothesis["expected_schema_id"] is None
                    or hypothesis["expected_schema_id"] == schema_id
                ),
                "parameter_size": len(parameter_bytes),
                "parameter_size_matches_cross_build_hypothesis": (
                    hypothesis["expected_parameter_size"] is None
                    or hypothesis["expected_parameter_size"] == len(parameter_bytes)
                ),
                "parameter_blob_hex": parameter_bytes.hex(),
                "parameter_blob_sha256": hashlib.sha256(parameter_bytes).hexdigest(),
                **candidate_fields,
                "evidence_grade": "CANDIDATE_EXACT_BUILD_STRUCTURE_PLUS_CROSS_BUILD_LAYOUT",
                "semantic_boundary": (
                    "Runtime string presence, prior-build ID/layout continuity, and plausible "
                    "values do not alone publish heal/shield semantics."
                ),
            }
            amount = row.get("amount_candidate")
            if amount is not None:
                sign = "nonfinite" if not math.isfinite(amount) else (
                    "positive" if amount > 0 else "zero" if amount == 0 else "negative"
                )
                amount_sign_counts[(event_id, sign)] += 1
            for field_name in ("source_network_id_candidate", "target_network_id_candidate"):
                value = row.get(field_name)
                if value is not None:
                    shape = "champion" if 0x400000AE <= value <= 0x400000B7 else (
                        "network_id_like" if 0x40000000 <= value <= 0x4FFFFFFF else "other"
                    )
                    entity_shape_counts[(event_id, field_name, shape)] += 1
            selected_rows.append(row)
            destination.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n")
            if options.progress_every and counts["input_route_rows"] % options.progress_every == 0:
                print(f"decoded {counts['input_route_rows']} OnEvent rows", file=sys.stderr)

    pair_counts = collections.Counter()
    previous = None
    for row in selected_rows:
        if (
            previous is not None
            and previous["event_id"] == 0x00EE
            and row["event_id"] == 0x00ED
            and previous["replay_sha256"] == row["replay_sha256"]
            and previous["replay_time_ms"] == row["replay_time_ms"]
            and previous["parameter_blob_hex"] == row["parameter_blob_hex"]
            and row["occurrence_index"] - previous["occurrence_index"] == 1
        ):
            pair_counts["grant_then_receive_exact_blob"] += 1
        previous = row

    summary = {
        "schema_version": 1,
        "analysis": "rofl-16.16-on-event-deep-recovery-v1",
        "build": BUILD,
        "status": "PASS" if (
            counts["input_route_rows"] == counts["deserialize_success_rows"]
            == counts["fully_consumed_rows"]
        ) else "FAIL",
        "runtime_image": {"path": str(image_path), "sha256": image_sha256},
        "emulator_source": {"path": str(emulator_source), "sha256": sha256_file(emulator_source)},
        "input": {"path": str(events_path), "sha256": sha256_file(events_path)},
        "output": {"path": str(output_path), "sha256": sha256_file(output_path)},
        "profile": {
            "packet_id_hex": "0x0371",
            "runtime_name": "PKT_OnEvent_s",
            "constructor_rva_hex": "0x00e7e630",
            "deserializer_rva_hex": "0x00fcc3f0",
            "object_size_hex": "0x30",
            "callback_rva_hex": "0x0049b050",
        },
        **counts,
        "selected_candidate_rows": len(selected_rows),
        "event_id_counts": {f"0x{key:04x}": value for key, value in event_counts.most_common()},
        "event_id_parameter_size_counts": {
            f"0x{event_id:04x}:{size}": count
            for (event_id, size), count in sorted(event_size_counts.items())
        },
        "dispatch_event_id_counts": {
            f"0x{key:04x}": value for key, value in dispatch_counts.most_common()
        },
        "replay_counts": dict(sorted(replay_counts.items())),
        "amount_sign_counts": {
            f"0x{event_id:04x}:{sign}": count
            for (event_id, sign), count in sorted(amount_sign_counts.items())
        },
        "entity_shape_counts": {
            f"0x{event_id:04x}:{field}:{shape}": count
            for (event_id, field, shape), count in sorted(entity_shape_counts.items())
        },
        "sequence_pair_counts": dict(pair_counts),
        "runtime_string_evidence": runtime_string_evidence(image),
        "hypotheses": {f"0x{key:04x}": value for key, value in EVENT_HYPOTHESES.items()},
        "decision": {
            "operation_and_layout": "KEEP_CANDIDATE_PENDING_EXACT_BUILD_ANCHOR_VALIDATION",
            "damage_shielded": "KEEP_UNKNOWN_LAYOUT",
            "public_semantic_promotion": False,
        },
        "holdout_boundary": {
            "path_guard": "reject every explicit input/output path containing case-insensitive 'holdout'",
            "read": False, "enumerate": False, "hash": False,
            "decode": False, "test": False, "consume": False,
        },
    }
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="ascii")
    print(json.dumps({**summary, "summary_path": str(summary_path)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # pragma: no cover - CLI boundary
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        raise
