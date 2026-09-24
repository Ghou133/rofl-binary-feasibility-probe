#!/usr/bin/env python3
"""Decode exact-image HN 16.19 BuffAdd2 packet scalars as raw candidates.

The caller owns Replay framing and packet provenance. This helper executes the
exact constructor and deserializer, then applies only byte transforms observed
in the exact callback. It does not determine packet owner, buff identity,
application or lifecycle.
"""

import argparse
import hashlib
import json
import math
import string
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from decode_mapview_inventory_16_19 import (  # noqa: E402
    make_emulator, read_image,
)


REPLAY_VERSION = "16.19.820.7193"
MAX_INPUT_BYTES = 12_000_000
MAX_PACKETS = 50_000
OBSERVED_LENGTHS = frozenset((14, 15, *range(17, 33)))
OPAQUE_VECTOR_KEYFRAME_LENGTH = 41
OPAQUE_VECTOR_RAW_PARAM = 0x400000B3
OPAQUE_VECTOR_ELEMENT_BYTES = 40
OPAQUE_VECTOR_ELEMENT_VTABLE_RVA = 0x01BAE6C8
PROFILE = {
    "constructor_rva": 0x00EA0D10,
    "deserialize_rva": 0x010DCCE0,
    "object_size": 0x60,
    "fields": [],
}

# These offsets and helper calls are read directly from the exact callback at
# RVA 0x008f4520. The names are structural and make no semantic assignment.
SCALARS = (
    ("offset_0x10_u32", 0x10, "u32", 0x008758E0),
    ("offset_0x14_f32", 0x14, "f32", 0x00875710),
    ("offset_0x1c_f32", 0x1C, "f32", 0x008756E0),
    ("offset_0x24_u32", 0x24, "u32", 0x00875840),
    ("offset_0x28_u8", 0x28, "u8", 0x008757E0),
    ("offset_0x30_u32", 0x30, "u32", 0x00875690),
)


def read_input():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    request = json.loads(raw)
    if not isinstance(request, dict) or request.get("replay_version") != REPLAY_VERSION:
        raise ValueError(f"replay_version must be exactly {REPLAY_VERSION}")
    packets = request.get("packets")
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f"packets must be an array with at most {MAX_PACKETS} entries")
    return packets


def validate_packet(packet):
    if not isinstance(packet, dict):
        raise ValueError("packet must be an object")
    stream_tag = packet.get("stream_tag")
    if type(stream_tag) is not int or stream_tag not in (1, 2):
        raise ValueError("stream_tag must be game (1) or keyframe (2)")
    raw_param = packet.get("raw_param")
    if type(raw_param) is not int or not 0 <= raw_param <= 0xFFFFFFFF:
        raise ValueError("raw_param must be an unsigned 32-bit integer")
    payload_hex = packet.get("payload_hex")
    if not isinstance(payload_hex, str) or len(payload_hex) % 2:
        raise ValueError("payload_hex must be even-length hexadecimal text")
    if any(char not in string.hexdigits for char in payload_hex):
        raise ValueError("payload_hex contains non-hexadecimal characters")
    payload_length = len(payload_hex) // 2
    if payload_length not in OBSERVED_LENGTHS and not (
        stream_tag == 2 and raw_param == OPAQUE_VECTOR_RAW_PARAM
        and payload_length == OPAQUE_VECTOR_KEYFRAME_LENGTH
    ):
        raise ValueError("payload length is outside the observed HN BuffAdd2 shapes")
    return stream_tag, raw_param, bytes.fromhex(payload_hex)


def failed(message, return_al=None, consumed=None):
    return {
        "status": "FAILED",
        "deserialize_return_al": return_al,
        "bytes_consumed": consumed,
        "decoded_scalar_fields": None,
        "raw_object_scalar_bytes_hex": None,
        "raw_object_hex": None,
        "opaque_vector_0x38_candidate": None,
        "error": message,
    }


def byte_tables(emulator):
    tables = {}
    for _, _, _, helper in SCALARS:
        if helper not in tables:
            table = emulator.decode_bytes(bytes(range(256)), helper)
            if len(table) != 256 or len(set(table)) != 256:
                raise ValueError(f"callback byte helper {helper:#x} is not bijective")
            tables[helper] = table
    return tables


def decode_packet(emulator, context, tables, stream_tag, raw_param, payload):
    context["raw_param"] = raw_param
    decoded = emulator.decode(payload, PROFILE)
    return_al = decoded["deserialize_return_al"]
    consumed = decoded["bytes_consumed"]
    if return_al != 1 or consumed != len(payload) or not decoded["fully_consumed"]:
        return failed("deserializer did not succeed with full payload consumption",
                      return_al, consumed)
    obj = bytes.fromhex(decoded["object_hex"])
    if len(obj) != PROFILE["object_size"]:
        return failed("runtime object size differs", return_al, consumed)
    first_pointer, first_count, first_capacity = struct.unpack_from("<QII", obj, 0x38)
    second_pointer, second_count, second_capacity = struct.unpack_from("<QII", obj, 0x48)
    opaque_vector = None
    if (len(payload) == OPAQUE_VECTOR_KEYFRAME_LENGTH and stream_tag == 2
            and raw_param == OPAQUE_VECTOR_RAW_PARAM):
        # The pinned deserializer calls 0x010A2CE0 for this vector; that
        # routine steps through 40-byte polymorphic elements. The three
        # observed keyframe packets have exactly one. Do not interpret it.
        from emulate_exact_packet_decoder import HEAP_BASE, HEAP_SIZE, IMAGE_BASE

        if (first_count, first_capacity) != (1, 1) or not first_pointer:
            return failed("unobserved opaque vector count", return_al, consumed)
        if (second_pointer, second_count, second_capacity) != (0, 0, 0):
            return failed("unobserved second object vector", return_al, consumed)
        if (first_pointer % 8 or first_pointer < HEAP_BASE
                or first_pointer + OPAQUE_VECTOR_ELEMENT_BYTES > emulator.heap_cursor
                or emulator.heap_cursor > HEAP_BASE + HEAP_SIZE):
            return failed("opaque vector pointer is outside allocated emulator heap",
                          return_al, consumed)
        element = bytes(emulator.emulator.mem_read(
            first_pointer, OPAQUE_VECTOR_ELEMENT_BYTES
        ))
        element_vtable = struct.unpack_from("<Q", element)[0]
        if element_vtable != IMAGE_BASE + OPAQUE_VECTOR_ELEMENT_VTABLE_RVA:
            return failed("opaque vector element has an unobserved vtable",
                          return_al, consumed)
        opaque_vector = {
            "element_count": 1,
            "element_size_bytes": OPAQUE_VECTOR_ELEMENT_BYTES,
            "element_vtable_rva": f"0x{OPAQUE_VECTOR_ELEMENT_VTABLE_RVA:08x}",
        }
    elif (first_pointer, first_count, first_capacity) != (0, 0, 0) or (
        second_pointer, second_count, second_capacity
    ) != (0, 0, 0):
        return failed("unobserved nonempty object vector", return_al, consumed)
    values = {}
    raw = {}
    for name, offset, kind, helper in SCALARS:
        size = 1 if kind == "u8" else 4
        encoded = obj[offset:offset + size]
        unpacked = encoded.translate(tables[helper])
        value = unpacked[0] if kind == "u8" else struct.unpack(
            "<f" if kind == "f32" else "<I", unpacked
        )[0]
        if kind == "f32" and not math.isfinite(value):
            return failed(f"{name} is not a finite float", return_al, consumed)
        values[name] = value
        raw[name] = encoded.hex()
    return {
        "status": "DECODED",
        "deserialize_return_al": return_al,
        "bytes_consumed": consumed,
        "decoded_scalar_fields": values,
        "raw_object_scalar_bytes_hex": raw,
        "raw_object_hex": obj.hex(),
        "opaque_vector_0x38_candidate": opaque_vector,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_input()
        image, digest = read_image(options.image)
        emulator, context = make_emulator(image)
        tables = byte_tables(emulator)
        results = []
        for index, packet in enumerate(packets):
            try:
                stream_tag, raw_param, payload = validate_packet(packet)
            except ValueError as error:
                row = failed(str(error))
                row.update(input_index=index, stream_tag=None, raw_param=None,
                           raw_payload_sha256=None)
                results.append(row)
                continue
            binding = {
                "input_index": index,
                "stream_tag": stream_tag,
                "raw_param": raw_param,
                "raw_payload_sha256": hashlib.sha256(payload).hexdigest(),
            }
            try:
                row = decode_packet(emulator, context, tables, stream_tag, raw_param, payload)
                row.update(binding)
                results.append(row)
                if row["status"] != "DECODED":
                    emulator, context = make_emulator(image)
            except Exception as error:
                row = failed(f"exact runtime emulation failed: {error}")
                row.update(binding)
                results.append(row)
                emulator, context = make_emulator(image)
        json.dump({"status": "PASS", "runtime_image_sha256": digest,
                   "results": results}, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except Exception as error:
        print(f"BuffAdd2 exact runtime decoder error: {error}", file=sys.stderr)
        json.dump({"status": "ERROR", "runtime_image_sha256": digest,
                   "results": [], "error": str(error)},
                  sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
