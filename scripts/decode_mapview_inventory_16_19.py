#!/usr/bin/env python3
"""Exact-runtime candidate decoder for 16.19 HN MapView inventory packets.

Input framing and packet provenance belong to the caller. This helper receives
already selected 0x0420 payloads and their replay block raw_param values.
"""

import argparse
import hashlib
import json
import struct
import string
import sys
from pathlib import Path


REPLAY_VERSION = "16.19.820.7193"
IMAGE_SHA256 = "7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d"
MAX_INPUT_BYTES = 2_000_000
MAX_PACKETS = 256
MAX_PAYLOAD_BYTES = 4096
MAX_RECORDS = 10
MAX_IMAGE_BYTES = 64 * 1024 * 1024

# These offsets belong only to the image whose SHA-256 is IMAGE_SHA256.
IMAGE_BASE = 0x140000000
ALLOC_RVA = 0x11D15D0
FREE_RVA = 0x11D1600
BASE_PARAM_DECODE_RVA = 0x126FF40
CONSTRUCTOR_RVA = 0xEC15A0
DESERIALIZER_RVA = 0x1043550
OBJECT_SIZE = 0x40
VECTOR_OFFSET = 0x20
RECORD_SIZE = 0xB0
SLOT_OFFSET = 0x28
SLOT_BYTE_HELPER_RVA = 0x251C80
FLAG_OFFSET = 0x40
FLAG_BYTE_HELPER_RVA = 0x251D30
ITEM_ID_OFFSET = 0x5C
ITEM_ID_BYTE_HELPER_RVA = 0x251D50


def decode_failure(message, *, deserialize_return_al=None, bytes_consumed=None):
    return {
        "status": "FAILED",
        "deserialize_return_al": deserialize_return_al,
        "bytes_consumed": bytes_consumed,
        "record_count": None,
        "records": [],
        "error": message,
    }


def read_input():
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("input must be a JSON object")
    if document.get("replay_version") != REPLAY_VERSION:
        raise ValueError(f"replay_version must be exactly {REPLAY_VERSION}")
    packets = document.get("packets")
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError(f"packets must be an array with at most {MAX_PACKETS} entries")
    return packets


def read_image(path):
    if path.stat().st_size > MAX_IMAGE_BYTES:
        raise ValueError("runtime image exceeds bounded size")
    image = path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != IMAGE_SHA256:
        raise ValueError(f"runtime image SHA-256 mismatch: {digest}")
    return image, digest


def validate_packet(packet):
    if not isinstance(packet, dict):
        raise ValueError("packet must be an object")
    raw_param = packet.get("raw_param")
    if type(raw_param) is not int or not 0 < raw_param <= 0xFFFFFFFF:
        raise ValueError("raw_param must be a nonzero unsigned 32-bit integer")
    payload_hex = packet.get("payload_hex")
    if not isinstance(payload_hex, str) or len(payload_hex) % 2:
        raise ValueError("payload_hex must be even-length hexadecimal text")
    if len(payload_hex) // 2 > MAX_PAYLOAD_BYTES:
        raise ValueError(f"payload exceeds {MAX_PAYLOAD_BYTES} bytes")
    if any(character not in string.hexdigits for character in payload_hex):
        raise ValueError("payload_hex contains non-hexadecimal characters")
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as exc:
        raise ValueError("payload_hex contains non-hexadecimal characters") from exc
    if not payload:
        raise ValueError("payload must not be empty")
    return raw_param, payload


def make_emulator(image):
    try:
        from unicorn import UC_HOOK_CODE
        from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RCX
        from emulate_exact_packet_decoder import ExactPacketEmulator
    except ImportError as exc:
        raise RuntimeError("exact-runtime decoder requires the installed unicorn dependency") from exc

    # The existing emulator supplies memory and allocator stubs. No 16.15 or
    # 16.16 image RVA or profile is inherited by this exact-build route.
    runtime = {
        "runtime_alloc_rva": ALLOC_RVA,
        "runtime_free_rva": FREE_RVA,
        "runtime_memset_leaf_rva": None,
        "enable_legacy_business_stubs": False,
    }
    emulator = ExactPacketEmulator(image, runtime)
    context = {"raw_param": 0}

    def base_param_from_replay_block(uc, _address, _size, _user_data):
        # ROFL framing keeps raw_param outside payload. Supply that exact value
        # to the client's base packet deserializer without synthesizing wire.
        object_address = uc.reg_read(UC_X86_REG_RCX)
        uc.mem_write(object_address + 0x0C, struct.pack("<I", context["raw_param"]))
        uc.reg_write(UC_X86_REG_RAX, 1)
        emulator._return_from_stub()

    emulator.emulator.hook_add(
        UC_HOOK_CODE,
        base_param_from_replay_block,
        begin=IMAGE_BASE + BASE_PARAM_DECODE_RVA,
        end=IMAGE_BASE + BASE_PARAM_DECODE_RVA,
    )
    return emulator, context


def decode_packet(emulator, context, raw_param, payload):
    from emulate_exact_packet_decoder import OBJECT_ADDRESS

    context["raw_param"] = raw_param
    profile = {
        "constructor_rva": CONSTRUCTOR_RVA,
        "deserialize_rva": DESERIALIZER_RVA,
        "object_size": OBJECT_SIZE,
        "fields": [],
    }
    result = emulator.decode(payload, profile)
    return_al = result["deserialize_return_al"]
    consumed = result["bytes_consumed"]
    if not return_al or not result["fully_consumed"]:
        return decode_failure(
            "deserializer did not succeed with full payload consumption",
            deserialize_return_al=return_al,
            bytes_consumed=consumed,
        )

    object_bytes = bytes(emulator.emulator.mem_read(OBJECT_ADDRESS, OBJECT_SIZE))
    pointer, count, capacity = struct.unpack_from("<QII", object_bytes, VECTOR_OFFSET)
    if count > MAX_RECORDS or count > capacity:
        return decode_failure(
            "record count exceeds bounded inventory vector",
            deserialize_return_al=return_al,
            bytes_consumed=consumed,
        )
    records = []
    for index in range(count):
        record = bytes(emulator.emulator.mem_read(pointer + index * RECORD_SIZE, RECORD_SIZE))
        slot = emulator.decode_bytes(record[SLOT_OFFSET:SLOT_OFFSET + 1], SLOT_BYTE_HELPER_RVA)[0]
        flag = emulator.decode_bytes(record[FLAG_OFFSET:FLAG_OFFSET + 1], FLAG_BYTE_HELPER_RVA)[0]
        item_id = struct.unpack(
            "<I", emulator.decode_bytes(record[ITEM_ID_OFFSET:ITEM_ID_OFFSET + 4], ITEM_ID_BYTE_HELPER_RVA)
        )[0]
        if slot > 9 or item_id == 0:
            return decode_failure(
                "decoded slot or item ID is outside observed MapView record bounds",
                deserialize_return_al=return_al,
                bytes_consumed=consumed,
            )
        records.append({
            "record_index": index,
            "slot": slot,
            "item_id": item_id,
            "flag": flag,
            "raw_slot_byte_hex": record[SLOT_OFFSET:SLOT_OFFSET + 1].hex(),
            "raw_item_id_bytes_hex": record[ITEM_ID_OFFSET:ITEM_ID_OFFSET + 4].hex(),
        })
    if len({record["slot"] for record in records}) != len(records):
        return decode_failure(
            "duplicate slot in one MapView vector",
            deserialize_return_al=return_al,
            bytes_consumed=consumed,
        )
    return {
        "status": "DECODED",
        "deserialize_return_al": return_al,
        "bytes_consumed": consumed,
        "record_count": count,
        "records": records,
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
            except ValueError as exc:
                failed = decode_failure(str(exc))
                failed.update(input_index=index, raw_param=None, raw_payload_sha256=None)
                results.append(failed)
                continue
            binding = {
                "input_index": index,
                "raw_param": raw_param,
                "raw_payload_sha256": hashlib.sha256(payload).hexdigest(),
            }
            try:
                decoded = decode_packet(emulator, context, raw_param, payload)
                decoded.update(binding)
                results.append(decoded)
                if decoded["status"] != "DECODED":
                    emulator, context = make_emulator(image)
            except Exception as exc:
                failed = decode_failure(f"exact-runtime emulation failed: {exc}")
                failed.update(binding)
                results.append(failed)
                emulator, context = make_emulator(image)
        output = {"status": "PASS", "runtime_image_sha256": digest, "results": results}
        json.dump(output, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except Exception as exc:
        print(f"MapView exact-runtime decoder error: {exc}", file=sys.stderr)
        output = {"status": "ERROR", "runtime_image_sha256": digest, "results": [], "error": str(exc)}
        json.dump(output, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
