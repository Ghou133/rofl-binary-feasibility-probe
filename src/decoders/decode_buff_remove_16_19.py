#!/usr/bin/env python3
"""Decode exact-image 16.19 HN BuffRemove2 packet fields as candidates.

The caller owns ROFL framing and provenance. This helper decodes only the
observed 0x043c packet object's three scalar fields. It does not establish a
buff owner, name, type, or lifecycle transition.
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
    IMAGE_SHA256, make_emulator, read_image,
)


REPLAY_VERSION = "16.19.820.7193"
MAX_INPUT_BYTES = 12_000_000
MAX_PACKETS = 50_000
MAX_PAYLOAD_BYTES = 64

# All RVAs below belong exclusively to the image with IMAGE_SHA256. The exact
# callback at 0x008f4840 uses these helpers before passing the three fields to
# BuffManagerClient; these are not inherited from an earlier patch.
PROFILE = {
    "constructor_rva": 0x00EA1360,
    "deserialize_rva": 0x010E0030,
    "object_size": 0x1C,
    "fields": [],
}
TIME_HELPER_RVA = 0x008758A0
SLOT_HELPER_RVA = 0x008757E0
LOOKUP_HELPER_RVA = 0x008757A0


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
    raw_param = packet.get("raw_param")
    if type(raw_param) is not int or not 0 <= raw_param <= 0xFFFFFFFF:
        raise ValueError("raw_param must be an unsigned 32-bit integer")
    payload_hex = packet.get("payload_hex")
    if not isinstance(payload_hex, str) or not payload_hex or len(payload_hex) % 2:
        raise ValueError("payload_hex must be nonempty even-length hexadecimal text")
    if len(payload_hex) // 2 > MAX_PAYLOAD_BYTES:
        raise ValueError(f"payload exceeds {MAX_PAYLOAD_BYTES} bytes")
    if any(char not in string.hexdigits for char in payload_hex):
        raise ValueError("payload_hex contains non-hexadecimal characters")
    return raw_param, bytes.fromhex(payload_hex)


def failed(message, return_al=None, consumed=None):
    return {
        "status": "FAILED",
        "deserialize_return_al": return_al,
        "bytes_consumed": consumed,
        "decoded_time_f32_seconds": None,
        "slot_index_u8": None,
        "lookup_token_u32": None,
        "raw_object_time_bytes_hex": None,
        "raw_object_slot_byte_hex": None,
        "raw_object_lookup_bytes_hex": None,
        "error": message,
    }


def decode_packet(emulator, context, raw_param, payload):
    context["raw_param"] = raw_param
    decoded = emulator.decode(payload, PROFILE)
    return_al = decoded["deserialize_return_al"]
    consumed = decoded["bytes_consumed"]
    if return_al != 1 or consumed != len(payload) or not decoded["fully_consumed"]:
        return failed(
            "deserializer did not succeed with full payload consumption",
            return_al, consumed,
        )
    obj = bytes.fromhex(decoded["object_hex"])
    raw_time = obj[0x10:0x14]
    raw_slot = obj[0x14:0x15]
    raw_lookup = obj[0x18:0x1C]
    time_seconds = struct.unpack(
        "<f", emulator.decode_bytes(raw_time, TIME_HELPER_RVA)
    )[0]
    if not math.isfinite(time_seconds):
        return failed("decoded float is not finite", return_al, consumed)
    slot = emulator.decode_bytes(raw_slot, SLOT_HELPER_RVA)[0]
    lookup_token = struct.unpack(
        "<I", emulator.decode_bytes(raw_lookup, LOOKUP_HELPER_RVA)
    )[0]
    return {
        "status": "DECODED",
        "deserialize_return_al": return_al,
        "bytes_consumed": consumed,
        "decoded_time_f32_seconds": time_seconds,
        "slot_index_u8": slot,
        "lookup_token_u32": lookup_token,
        "raw_object_time_bytes_hex": raw_time.hex(),
        "raw_object_slot_byte_hex": raw_slot.hex(),
        "raw_object_lookup_bytes_hex": raw_lookup.hex(),
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
        results = []
        for index, packet in enumerate(packets):
            try:
                raw_param, payload = validate_packet(packet)
            except ValueError as error:
                result = failed(str(error))
                result.update(input_index=index, raw_param=None, raw_payload_sha256=None)
                results.append(result)
                continue
            binding = {
                "input_index": index,
                "raw_param": raw_param,
                "raw_payload_sha256": hashlib.sha256(payload).hexdigest(),
            }
            try:
                result = decode_packet(emulator, context, raw_param, payload)
                result.update(binding)
                results.append(result)
                if result["status"] != "DECODED":
                    emulator, context = make_emulator(image)
            except Exception as error:
                result = failed(f"exact runtime emulation failed: {error}")
                result.update(binding)
                results.append(result)
                emulator, context = make_emulator(image)
        json.dump(
            {"status": "PASS", "runtime_image_sha256": digest, "results": results},
            sys.stdout, separators=(",", ":"),
        )
        sys.stdout.write("\n")
        return 0
    except Exception as error:
        print(f"BuffRemove2 exact runtime decoder error: {error}", file=sys.stderr)
        json.dump(
            {"status": "ERROR", "runtime_image_sha256": digest,
             "results": [], "error": str(error)},
            sys.stdout, separators=(",", ":"),
        )
        sys.stdout.write("\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
