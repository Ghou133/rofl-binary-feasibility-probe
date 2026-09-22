#!/usr/bin/env python3

"""Capture exact-build BuffManager callback arguments and cast business fields.

This script executes the 16.16 packet constructors/deserializers and the exact
receive-side transform code.  BuffManager methods are intercepted at their
entry before any live client state is dereferenced.  Field labels stay
structural/candidate-only until the companion sequence analysis validates them.
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

from unicorn import UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RAX,
    UC_X86_REG_RDX,
    UC_X86_REG_RSP,
    UC_X86_REG_XMM0,
    UC_X86_REG_XMM1,
    UC_X86_REG_XMM2,
    UC_X86_REG_XMM3,
)


BUILD = "16.16.805.0442"
EXPECTED_IMAGE_SHA256 = (
    "0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55"
)
IMAGE_BASE = 0x140000000
BUSINESS_OBJECT_ADDRESS = 0x200010000

ROUTES: dict[int, dict[str, Any]] = {
    0x0123: {
        "operation_candidate": "BUFF_UPDATE_COUNT_ROUTE",
        "runtime_name": "PKT_NPC_BuffUpdateCount_s",
        "constructor_rva": 0x00E7D240,
        "deserialize_rva": 0x010A90A0,
        "object_size": 0x24,
        "callback_rva": 0x008CD160,
        "final_rva": 0x008CC240,
    },
    0x0326: {
        "operation_candidate": "BUFF_ADD_ROUTE",
        "runtime_name": "PKT_NPC_BuffAdd2_s",
        "constructor_rva": 0x00E7C7E0,
        "deserialize_rva": 0x010A3C10,
        "object_size": 0x68,
        "callback_rva": 0x008CCC70,
        "final_rva": 0x008CB730,
    },
    0x041F: {
        "operation_candidate": "BUFF_UPDATE_NUM_COUNTER_ROUTE",
        "runtime_name": "PKT_NPC_BuffUpdateNumCounter_s",
        "constructor_rva": 0x00E7D420,
        "deserialize_rva": 0x010A9CB0,
        "object_size": 0x1C,
        "callback_rva": 0x008CD2A0,
        "final_rva": 0x008CC3F0,
    },
    0x043C: {
        "operation_candidate": "BUFF_REPLACE_ROUTE",
        "runtime_name": "PKT_NPC_BuffReplace_s",
        "constructor_rva": 0x00E7D030,
        "deserialize_rva": 0x010A7DA0,
        "object_size": 0x20,
        "callback_rva": 0x008CD030,
        "final_rva": 0x008CC070,
    },
    0x045B: {
        "operation_candidate": "BUFF_REMOVE_ROUTE",
        "runtime_name": "PKT_NPC_BuffRemove2_s",
        "constructor_rva": 0x00E7CE30,
        "deserialize_rva": 0x010A6EF0,
        "object_size": 0x1C,
        "callback_rva": 0x008CCFA0,
        "final_rva": 0x008CBD00,
    },
    0x01CF: {
        "operation_candidate": "CAST_ANSWER_ROUTE",
        "runtime_name": "PKT_NPC_CastSpellAns_s",
        "constructor_rva": 0x00E7D5C0,
        "deserialize_rva": 0x010AA640,
        "object_size": 0x138,
        "business_constructor_rva": 0x0087B150,
        "business_translate_rva": 0x008B2730,
        "business_source_offset": 0x10,
        "business_object_size": 0x194,
    },
}

EXACT_CAST_STUBS = {
    "id_lookup": 0x00576A50,
    "object_lookup": 0x00573C40,
    "optional_noop": 0x0099D0B0,
    "spell_table_check_false": 0x0096B290,
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
    parser.add_argument("--limit-per-route", type=int)
    parser.add_argument("--progress-every", type=int, default=25000)
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
    specification = importlib.util.spec_from_file_location("exact_packet_emulator_deep", source)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load exact emulator: {source}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module, source


def low_f32(value: int) -> float | None:
    decoded = struct.unpack("<f", struct.pack("<I", value & 0xFFFFFFFF))[0]
    return decoded if math.isfinite(decoded) else None


def read_u32(blob: bytes, offset: int) -> int:
    return struct.unpack_from("<I", blob, offset)[0]


def read_f32(blob: bytes, offset: int) -> float | None:
    value = struct.unpack_from("<f", blob, offset)[0]
    return value if math.isfinite(value) else None


def vector3(blob: bytes, offset: int) -> list[float] | None:
    value = struct.unpack_from("<fff", blob, offset)
    return list(value) if all(math.isfinite(item) for item in value) else None


def shape_network_id(value: int) -> str:
    if 0x400000AE <= value <= 0x400000B7:
        return "champion"
    if 0x40000000 <= value <= 0x4FFFFFFF:
        return "network_id_like"
    return "other"


class CallbackCapture:
    def __init__(self, emulator: Any):
        self.exact = emulator
        self.current_packet_id: int | None = None
        self.capture: dict[str, Any] | None = None
        for route in ROUTES.values():
            final_rva = route.get("final_rva")
            if final_rva is None:
                continue
            emulator.emulator.hook_add(
                UC_HOOK_CODE,
                self._capture_final,
                begin=IMAGE_BASE + final_rva,
                end=IMAGE_BASE + final_rva,
            )

    def _capture_final(self, _uc: Any, address: int, _size: int, _user_data: Any) -> None:
        packet_id = self.current_packet_id
        if packet_id is None:
            raise RuntimeError(f"unexpected callback capture at 0x{address:x}")
        uc = self.exact.emulator
        rsp = uc.reg_read(UC_X86_REG_RSP)
        rdx = uc.reg_read(UC_X86_REG_RDX)
        capture = {
            "final_entry_rva_hex": f"0x{address - IMAGE_BASE:08x}",
            "rdx_u64": rdx,
            "rdx_low_u32": rdx & 0xFFFFFFFF,
            "r8_u64": uc.reg_read(UC_X86_REG_R8),
            "r8_low_u32": uc.reg_read(UC_X86_REG_R8) & 0xFFFFFFFF,
            "r9_u64": uc.reg_read(UC_X86_REG_R9),
            "r9_low_u32": uc.reg_read(UC_X86_REG_R9) & 0xFFFFFFFF,
            "xmm0_low_f32": low_f32(uc.reg_read(UC_X86_REG_XMM0)),
            "xmm1_low_f32": low_f32(uc.reg_read(UC_X86_REG_XMM1)),
            "xmm2_low_f32": low_f32(uc.reg_read(UC_X86_REG_XMM2)),
            "xmm3_low_f32": low_f32(uc.reg_read(UC_X86_REG_XMM3)),
            "callee_stack_hex": bytes(uc.mem_read(rsp, 0x60)).hex(),
        }
        if packet_id == 0x0326:
            structure = bytes(uc.mem_read(rdx, 0x40))
            capture["argument_struct_hex"] = structure.hex()
            capture["argument_struct_bytes_00_03"] = list(structure[:4])
            capture["argument_struct_u32"] = {
                f"0x{offset:02x}": read_u32(structure, offset)
                for offset in range(0, 0x28, 4)
            }
            capture["argument_struct_f32"] = {
                f"0x{offset:02x}": read_f32(structure, offset)
                for offset in range(0, 0x28, 4)
            }
        self.capture = capture
        uc.reg_write(UC_X86_REG_RAX, 1)
        self.exact._return_from_stub()

    def execute(self, packet_id: int, callback_rva: int) -> dict[str, Any]:
        self.current_packet_id = packet_id
        self.capture = None
        self.exact.emulator.mem_write(BUSINESS_OBJECT_ADDRESS, b"\x00" * 0x200)
        self.exact.call(
            IMAGE_BASE + callback_rva,
            rcx=BUSINESS_OBJECT_ADDRESS,
            rdx=0x200000000,
        )
        capture = self.capture
        self.current_packet_id = None
        if capture is None:
            raise RuntimeError(f"route 0x{packet_id:04x} did not reach final callback")
        return capture


def install_exact_cast_stubs(emulator: Any) -> None:
    uc = emulator.emulator
    uc.hook_add(
        UC_HOOK_CODE,
        emulator._business_id_lookup,
        begin=IMAGE_BASE + EXACT_CAST_STUBS["id_lookup"],
        end=IMAGE_BASE + EXACT_CAST_STUBS["id_lookup"],
    )
    uc.hook_add(
        UC_HOOK_CODE,
        emulator._business_object_lookup,
        begin=IMAGE_BASE + EXACT_CAST_STUBS["object_lookup"],
        end=IMAGE_BASE + EXACT_CAST_STUBS["object_lookup"],
    )

    def return_zero(_uc: Any, _address: int, _size: int, _user_data: Any) -> None:
        uc.reg_write(UC_X86_REG_RAX, 0)
        emulator._return_from_stub()

    for name in ("optional_noop", "spell_table_check_false"):
        address = IMAGE_BASE + EXACT_CAST_STUBS[name]
        uc.hook_add(UC_HOOK_CODE, return_zero, begin=address, end=address)


def parse_cast_business(emulator: Any, business: bytes) -> dict[str, Any]:
    return {
        "spell_key_candidate": read_u32(business, 0x14),
        "caster_name_exact_translator": emulator.read_emulated_string(business, 0x20),
        "caster_network_id_candidate": read_u32(business, 0xA0),
        "chain_owner_network_id_candidate": read_u32(business, 0xA4),
        "network_id_candidate_0xac": read_u32(business, 0xAC),
        "network_id_candidate_0x168": read_u32(business, 0x168),
        "slot_or_enum_candidate_0x154": read_u32(business, 0x154),
        "time_seconds_candidate_0x164": read_f32(business, 0x164),
        "vector3_candidates": {
            f"0x{offset:03x}": vector3(business, offset)
            for offset in (0xD0, 0xDC, 0xE8, 0xF4, 0x100, 0x10C)
        },
    }


def parse_buff_capture(packet_id: int, capture: dict[str, Any]) -> dict[str, Any]:
    stack = bytes.fromhex(capture["callee_stack_hex"])
    if packet_id == 0x0123:
        return {
            "slot_candidate": capture["rdx_low_u32"] & 0xFF,
            "count_candidate": capture["r8_low_u32"] & 0xFF,
            "network_or_hash_candidate": capture["r9_low_u32"],
            "time_candidate_a": read_f32(stack, 0x28),
            "time_candidate_b": read_f32(stack, 0x30),
        }
    if packet_id == 0x041F:
        return {
            "u32_candidate_a": capture["rdx_low_u32"],
            "u32_candidate_b": capture["r8_low_u32"],
            "counter_candidate_a": capture["r9_low_u32"] & 0xFF,
            "counter_candidate_b": stack[0x28],
        }
    if packet_id == 0x043C:
        return {
            "slot_candidate": capture["rdx_low_u32"] & 0xFF,
            "network_or_hash_candidate": capture["r8_low_u32"],
            "time_candidate_a": read_f32(stack, 0x28),
            "time_candidate_b": capture["xmm3_low_f32"],
        }
    if packet_id == 0x045B:
        return {
            "slot_candidate": capture["rdx_low_u32"] & 0xFF,
            "network_or_hash_candidate": capture["r8_low_u32"],
            "time_candidate": capture["xmm3_low_f32"],
        }
    if packet_id == 0x0326:
        structure = bytes.fromhex(capture["argument_struct_hex"])
        return {
            "slot_candidate": structure[0],
            "byte_candidates_01_03": list(structure[1:4]),
            "u32_candidates": {
                f"0x{offset:02x}": read_u32(structure, offset)
                for offset in (0x04, 0x08, 0x14, 0x18, 0x1C, 0x20, 0x24)
            },
            "time_or_float_candidates": {
                f"0x{offset:02x}": read_f32(structure, offset)
                for offset in (0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24)
            },
        }
    raise AssertionError(packet_id)


def main() -> None:
    options = parse_args()
    if options.limit_per_route is not None and options.limit_per_route < 1:
        raise ValueError("--limit-per-route must be positive")
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
        image, emulator_module.RUNTIME_PROFILES[BUILD],
    )
    install_exact_cast_stubs(emulator)
    callback_capture = CallbackCapture(emulator)
    profiles = {
        packet_id: {
            "client_opcode": packet_id,
            "constructor_rva": route["constructor_rva"],
            "deserialize_rva": route["deserialize_rva"],
            "object_size": route["object_size"],
            "fields": [],
            **({
                "business_constructor_rva": route["business_constructor_rva"],
                "business_translate_rva": route["business_translate_rva"],
                "business_source_offset": route["business_source_offset"],
                "business_object_size": route["business_object_size"],
            } if packet_id == 0x01CF else {}),
        }
        for packet_id, route in ROUTES.items()
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    counts = collections.Counter()
    route_counts = collections.Counter()
    route_full_counts = collections.Counter()
    target_shapes = collections.Counter()
    candidate_shapes = collections.Counter()
    replay_route_counts = collections.Counter()

    with events_path.open(encoding="utf-8-sig") as source, output_path.open(
        "w", encoding="utf-8", newline="\n",
    ) as destination:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            packet_id = event.get("packet_id")
            if packet_id not in ROUTES:
                continue
            if (
                options.limit_per_route is not None
                and route_counts[packet_id] >= options.limit_per_route
            ):
                continue
            if event.get("replay_version") != BUILD:
                raise ValueError(f"line {line_number} has wrong build")
            decoded = emulator.decode(
                bytes.fromhex(event["raw_payload_hex"]),
                profiles[packet_id],
                packet_id=packet_id,
                raw_param=event["raw_param"],
            )
            counts["selected_route_rows"] += 1
            counts["deserialize_success_rows"] += int(decoded["deserialize_return_al"] != 0)
            counts["fully_consumed_rows"] += int(decoded["fully_consumed"])
            route_counts[packet_id] += 1
            route_full_counts[packet_id] += int(decoded["fully_consumed"])
            replay_route_counts[(event["replay_label"], packet_id)] += 1
            target_shape = shape_network_id(event["raw_param"])
            target_shapes[(packet_id, target_shape)] += 1

            row = {
                "schema_version": 1,
                "build": BUILD,
                "replay_path": event["replay_path"],
                "replay_sha256": event["replay_sha256"],
                "replay_label": event["replay_label"],
                **{key: event.get(key) for key in ORDER_FIELDS},
                "packet_id": packet_id,
                "packet_id_hex": f"0x{packet_id:04x}",
                "runtime_name": ROUTES[packet_id]["runtime_name"],
                "operation_candidate": ROUTES[packet_id]["operation_candidate"],
                "target_network_id_candidate": event["raw_param"],
                "target_shape": target_shape,
                "deserialize_return_al": decoded["deserialize_return_al"],
                "fully_consumed": decoded["fully_consumed"],
                "packet_object_sha256": hashlib.sha256(
                    bytes.fromhex(decoded["object_hex"])
                ).hexdigest(),
                "evidence_boundary": (
                    "Route/argument structure is exact-build evidence; candidate field labels "
                    "require cross-route sequence validation and do not imply gameplay causality."
                ),
            }
            if packet_id == 0x01CF:
                business = bytes.fromhex(decoded["business_object_hex"])
                cast_fields = parse_cast_business(emulator, business)
                row.update(cast_fields)
                row["business_object_sha256"] = hashlib.sha256(business).hexdigest()
                for field_name in (
                    "caster_network_id_candidate", "chain_owner_network_id_candidate",
                    "network_id_candidate_0xac", "network_id_candidate_0x168",
                ):
                    candidate_shapes[(field_name, shape_network_id(row[field_name]))] += 1
            else:
                capture = callback_capture.execute(packet_id, ROUTES[packet_id]["callback_rva"])
                row["callback_capture"] = capture
                row.update(parse_buff_capture(packet_id, capture))
            destination.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n")
            if options.progress_every and counts["selected_route_rows"] % options.progress_every == 0:
                print(f"decoded {counts['selected_route_rows']} buff/spell callback rows", file=sys.stderr)

    summary = {
        "schema_version": 1,
        "analysis": "rofl-16.16-buff-spell-callback-deep-recovery-v1",
        "build": BUILD,
        "status": "PASS" if (
            counts["selected_route_rows"] == counts["deserialize_success_rows"]
            == counts["fully_consumed_rows"]
        ) else "FAIL",
        "runtime_image": {"path": str(image_path), "sha256": image_sha256},
        "emulator_source": {"path": str(emulator_source), "sha256": sha256_file(emulator_source)},
        "input": {"path": str(events_path), "sha256": sha256_file(events_path)},
        "output": {"path": str(output_path), "sha256": sha256_file(output_path)},
        **counts,
        "route_counts": {f"0x{key:04x}": value for key, value in sorted(route_counts.items())},
        "route_full_consume_counts": {
            f"0x{key:04x}": value for key, value in sorted(route_full_counts.items())
        },
        "target_shape_counts": {
            f"0x{packet_id:04x}:{shape}": count
            for (packet_id, shape), count in sorted(target_shapes.items())
        },
        "cast_candidate_shape_counts": {
            f"{field}:{shape}": count
            for (field, shape), count in sorted(candidate_shapes.items())
        },
        "replay_route_counts": {
            f"{replay}:0x{packet_id:04x}": count
            for (replay, packet_id), count in sorted(replay_route_counts.items())
        },
        "routes": {
            f"0x{packet_id:04x}": {
                key: (f"0x{value:08x}" if key.endswith("_rva") else value)
                for key, value in route.items()
            }
            for packet_id, route in ROUTES.items()
        },
        "exact_cast_stubs": {
            key: f"0x{value:08x}" for key, value in EXACT_CAST_STUBS.items()
        },
        "decision": {
            "route_operation": "EXACT_BUILD_ROUTE_VERIFIED",
            "argument_semantics": "KEEP_CANDIDATE_PENDING_SEQUENCE_DIFFERENTIAL",
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
