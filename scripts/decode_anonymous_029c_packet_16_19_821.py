#!/usr/bin/env python3
"""Exact KR 821 anonymous 0x029c packet-local native u32 witness.

This deliberately does not assign a packet name, actor, target, or effect.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from decode_mapview_inventory_16_19_821 import IMAGE_BASE, make_emulator

BUILD = "16.19.821.7343"
IMAGE_SIZE = 48_488_448
IMAGE_SHA256 = "35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325"
PACKET_ID = 0x029c
FACTORY_TABLE_RVA = 0xf0e4bc
FACTORY_CASE_RVA = 0xf06643
CONSTRUCTOR_RVA = 0xe9abf0
VTABLE_RVA = 0x1ba3c88
DESERIALIZER_RVA = 0xf88030
PROTECTION_TABLE_RVA = 0x1bad570
PROTECTION_TABLE_SHA256 = "ae15d606869d66dc47309b26cb489e01bf841e9dd57d540683e2dc7f5e394588"
PROFILE = {"constructor_rva": CONSTRUCTOR_RVA, "deserialize_rva": DESERIALIZER_RVA,
           "object_size": 0x18, "fields": []}
PREFIXES = frozenset({0x70, 0x76, 0x78, 0x7a, 0x7c, 0x7e})
MAX_INPUT_BYTES = 512 * 1024
MAX_PACKETS = 10_000


def ror8(value, count):
    return ((value >> count) | (value << (8 - count))) & 255


def rol8(value, count):
    return ((value << count) | (value >> (8 - count))) & 255


def byte_inverse(table):
    def protect(value):
        intermediate = table[table[rol8(value, 1)]]
        intermediate = ror8((intermediate - 0x72) & 255, 5)
        return (((intermediate & 0xd5) << 1)
                | ((intermediate >> 1) & 0x55)) & 255

    inverse = {protect(value): value for value in range(256)}
    if len(inverse) != 256 or protect(0) != 0xe3 or protect(255) != 0x18:
        raise ValueError("exact 821 0x029c protection transform differs")
    return inverse


def observed_payload(payload):
    return (payload == b"\x72"
            or (len(payload) in (3, 4) and payload[0] in PREFIXES))


def read_image(path):
    if not path.is_file() or path.stat().st_size != IMAGE_SIZE:
        raise ValueError("exact 821 mapped runtime image is missing or has the wrong size")
    image = path.read_bytes()
    image_sha = hashlib.sha256(image).hexdigest()
    if image_sha != IMAGE_SHA256:
        raise ValueError(f"exact 821 runtime image SHA-256 mismatch: {image_sha}")
    if (struct.unpack_from("<I", image, FACTORY_TABLE_RVA + PACKET_ID * 4)[0]
            != FACTORY_CASE_RVA
            or image[CONSTRUCTOR_RVA + 7:CONSTRUCTOR_RVA + 13]
            != bytes.fromhex("66c741089c02")
            or struct.unpack_from("<Q", image, VTABLE_RVA + 8)[0]
            != IMAGE_BASE + DESERIALIZER_RVA):
        raise ValueError("exact 821 0x029c factory, constructor or vtable differs")
    table = image[PROTECTION_TABLE_RVA:PROTECTION_TABLE_RVA + 256]
    if hashlib.sha256(table).hexdigest() != PROTECTION_TABLE_SHA256:
        raise ValueError("exact 821 0x029c protection table differs")
    return image, image_sha, byte_inverse(table)


def read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("native request exceeds 512 KiB")
    request = json.loads(raw)
    if (not isinstance(request, dict) or request.get("replay_version") != BUILD
            or request.get("packet_id") != PACKET_ID):
        raise ValueError("exact build or packet route differs")
    packets = request.get("packets")
    if not isinstance(packets, list) or not 1 <= len(packets) <= MAX_PACKETS:
        raise ValueError("native request requires 1..10000 packets")
    result = []
    for pair in packets:
        if (not isinstance(pair, list) or len(pair) != 2
                or type(pair[0]) is not int or not 0 <= pair[0] <= 0xffffffff
                or not isinstance(pair[1], str)
                or not re.fullmatch(r"(?:[0-9a-f]{2})+", pair[1])):
            raise ValueError("0x029c raw parameter or payload encoding differs")
        payload = bytes.fromhex(pair[1])
        if not observed_payload(payload):
            raise ValueError("0x029c payload has an unobserved shape")
        result.append((pair[0], payload))
    return result


def input_hash(packets):
    digest = hashlib.sha256()
    for raw_param, payload in packets:
        digest.update(struct.pack("<II", raw_param, len(payload)))
        digest.update(payload)
    return digest.hexdigest()


def output_hash(rows):
    digest = hashlib.sha256()
    for row in rows:
        digest.update(bytes.fromhex(row["native_protected_selector_byte_hex"]))
        digest.update(bytes.fromhex(row["native_protected_u32_hex"]))
        digest.update(struct.pack("<I", row["anonymous_u32_candidate"]))
    return digest.hexdigest()


def decode_one(emulator, context, inverse, raw_param, payload):
    context["raw_param"] = raw_param
    native = emulator.decode(payload, PROFILE)
    if (native["deserialize_return_al"] != 1
            or not native["fully_consumed"]
            or native["bytes_consumed"] != len(payload)):
        raise ValueError("native deserializer did not fully consume 0x029c packet")
    obj = bytes.fromhex(native["object_hex"])
    if (len(obj) != 0x18
            or struct.unpack_from("<Q", obj)[0] != IMAGE_BASE + VTABLE_RVA
            or struct.unpack_from("<H", obj, 8)[0] != PACKET_ID
            or struct.unpack_from("<I", obj, 0x0c)[0] != raw_param):
        raise ValueError("native 0x029c object identity differs from Replay framing")
    if obj[0x10] != 0x3e:
        raise ValueError("native 0x029c selector differs from observed zero")
    protected = obj[0x14:0x18]
    value = struct.unpack("<I", bytes(inverse[byte] for byte in protected))[0]
    if not ((payload == b"\x72" and value == 0xffffffff)
            or (payload != b"\x72" and value >> 24 == 0x40)):
        raise ValueError("native 0x029c u32 differs from observed class")
    return {
        "native_protected_selector_byte_hex": f"{obj[0x10]:02x}",
        "native_selector_u8": 0,
        "native_protected_u32_hex": protected.hex(),
        "anonymous_u32_candidate": value,
        "anonymous_u32_is_sentinel": value == 0xffffffff,
        "raw_payload_sha256": hashlib.sha256(payload).hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    options = parser.parse_args()
    packets = read_request()
    image, image_sha, inverse = read_image(options.image)
    emulator, context = make_emulator(image)
    rows = []
    first_failure = None
    for index, (raw_param, payload) in enumerate(packets):
        try:
            rows.append(decode_one(emulator, context, inverse, raw_param, payload))
        except Exception as error:
            first_failure = {"index": index, "reason": f"{type(error).__name__}: {error}"}
            break
    print(json.dumps({
        "replay_version": BUILD, "runtime_image_sha256": image_sha,
        "packet_id": PACKET_ID, "packet_count": len(packets),
        "input_sha256": input_hash(packets),
        "native_output_sha256": output_hash(rows) if first_failure is None else None,
        "native_full_success_count": len(rows), "first_failure": first_failure,
        "rows": rows if first_failure is None else [],
    }, separators=(",", ":")))
    return 0 if first_failure is None else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"821 anonymous 0x029c native witness error: {error}", file=sys.stderr)
        raise SystemExit(1)
