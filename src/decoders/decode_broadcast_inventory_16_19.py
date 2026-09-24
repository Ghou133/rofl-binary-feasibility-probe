#!/usr/bin/env python3
"""Exact HN 16.19 SetInventory Broadcast packet fields, candidate only.

Replay framing and packet provenance belong to the caller. The runtime image
executes the packet and record deserializers; the TLS mapping supplies only the
Windows CRT thread epoch needed by the captured image's static initialization.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from decode_mapview_inventory_16_19 import (  # noqa: E402
    IMAGE_SHA256, REPLAY_VERSION, read_image, validate_packet, make_emulator,
    SLOT_OFFSET, SLOT_BYTE_HELPER_RVA, FLAG_OFFSET, FLAG_BYTE_HELPER_RVA,
    ITEM_ID_OFFSET, ITEM_ID_BYTE_HELPER_RVA,
)
PACKET_LIMIT = 512
INPUT_BYTE_LIMIT = 2_000_000
MAX_RECORDS = 10
RECORD_SIZE = 0xB0
RECORD_VTABLE_RVA = 0x1BAB770
CONSTRUCTOR_RVA = 0xEC1560
DESERIALIZER_RVA = 0x1043430
OBJECT_SIZE = 0x30
VECTOR_OFFSET = 0x20


def failed(message, *, deserialize_return_al=None, bytes_consumed=None):
    return {
        "status": "FAILED", "deserialize_return_al": deserialize_return_al,
        "bytes_consumed": bytes_consumed, "record_count": None,
        "records": [], "error": message,
    }


def read_request():
    raw = sys.stdin.buffer.read(INPUT_BYTE_LIMIT + 1)
    if len(raw) > INPUT_BYTE_LIMIT:
        raise ValueError("Broadcast runtime input exceeds byte limit")
    document = json.loads(raw)
    if not isinstance(document, dict) or document.get("replay_version") != REPLAY_VERSION:
        raise ValueError(f"replay_version must be {REPLAY_VERSION}")
    packets = document.get("packets")
    if not isinstance(packets, list) or len(packets) > PACKET_LIMIT:
        raise ValueError(f"packets must contain at most {PACKET_LIMIT} entries")
    return packets


def make_broadcast_emulator(image):
    try:
        from unicorn.x86_const import UC_X86_REG_GS_BASE
    except ImportError as exc:
        raise RuntimeError(
            "exact-runtime decoder requires the installed unicorn dependency"
        ) from exc
    # The reused HN MapView emulator provides the exact allocator and base
    # packet raw_param bridge. Both routes use the same 0xEC14A0 embedded
    # vector constructor and 0x10643F0 record deserializer in this image.
    emulator, context = make_emulator(image)
    teb = 0x400000000
    tls_array = teb + 0x1000
    tls_block = teb + 0x2000
    emulator.emulator.mem_map(teb, 0x4000)
    emulator.emulator.reg_write(UC_X86_REG_GS_BASE, teb)
    emulator.emulator.mem_write(teb + 0x58, struct.pack("<Q", tls_array))
    emulator.emulator.mem_write(tls_array, struct.pack("<Q", tls_block))
    # The captured image has TLS index 0 and an initialized CRT guard
    # (-2147482027). An epoch of -1 selects that image's completed-init path;
    # packet and record fields still come only from executed runtime code.
    if struct.unpack_from("<I", image, 0x208E418)[0] != 0:
        raise ValueError("pinned image TLS index differs")
    if struct.unpack_from("<i", image, 0x2041420)[0] != -2147482027:
        raise ValueError("pinned image CRT guard differs")
    emulator.emulator.mem_write(tls_block + 0x140, struct.pack("<i", -1))
    return emulator, context


def decode_packet(emulator, context, raw_param, payload):
    from emulate_exact_packet_decoder import IMAGE_BASE, OBJECT_ADDRESS

    context["raw_param"] = raw_param
    profile = {"constructor_rva": CONSTRUCTOR_RVA,
        "deserialize_rva": DESERIALIZER_RVA, "object_size": OBJECT_SIZE,
        "fields": []}
    decoded = emulator.decode(payload, profile)
    al = decoded["deserialize_return_al"]
    consumed = decoded["bytes_consumed"]
    if al != 1 or consumed != len(payload) or not decoded["fully_consumed"]:
        return failed("deserializer did not succeed with full payload consumption",
            deserialize_return_al=al, bytes_consumed=consumed)
    packet_object = bytes(emulator.emulator.mem_read(OBJECT_ADDRESS, OBJECT_SIZE))
    pointer, count, capacity = struct.unpack_from("<QII", packet_object, VECTOR_OFFSET)
    if count < 1 or count > MAX_RECORDS or count > capacity:
        return failed("record count outside bounded Broadcast vector",
            deserialize_return_al=al, bytes_consumed=consumed)
    records = []
    slots = set()
    for index in range(count):
        record = bytes(emulator.emulator.mem_read(pointer + index * RECORD_SIZE, RECORD_SIZE))
        if struct.unpack_from("<Q", record)[0] != IMAGE_BASE + RECORD_VTABLE_RVA:
            return failed("record vtable differs from pinned HN record parser",
                deserialize_return_al=al, bytes_consumed=consumed)
        raw_slot = record[SLOT_OFFSET:SLOT_OFFSET + 1]
        raw_flag = record[FLAG_OFFSET:FLAG_OFFSET + 1]
        raw_item = record[ITEM_ID_OFFSET:ITEM_ID_OFFSET + 4]
        slot = emulator.decode_bytes(raw_slot, SLOT_BYTE_HELPER_RVA)[0]
        flag = emulator.decode_bytes(raw_flag, FLAG_BYTE_HELPER_RVA)[0]
        item_key = struct.unpack("<I", emulator.decode_bytes(
            raw_item, ITEM_ID_BYTE_HELPER_RVA))[0]
        if (slot > 9 or slot in slots or flag not in (0, 1, 2)
                or (item_key == 0) != (flag == 0)):
            return failed("record fields outside observed HN Broadcast bounds",
                deserialize_return_al=al, bytes_consumed=consumed)
        slots.add(slot)
        records.append({"record_index": index, "slot": slot,
            "item_key_u32": item_key, "flag": flag,
            "raw_slot_byte_hex": raw_slot.hex(),
            "raw_flag_byte_hex": raw_flag.hex(),
            "raw_item_key_bytes_hex": raw_item.hex()})
    return {"status": "DECODED", "deserialize_return_al": al,
        "bytes_consumed": consumed, "record_count": count, "records": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, required=True)
    options = parser.parse_args()
    digest = None
    try:
        packets = read_request()
        image, digest = read_image(options.image)
        emulator, context = make_broadcast_emulator(image)
        results = []
        for index, packet in enumerate(packets):
            try:
                raw_param, payload = validate_packet(packet)
            except ValueError as exc:
                result = failed(str(exc))
                result.update(input_index=index, raw_param=None,
                    raw_payload_sha256=None)
                results.append(result)
                continue
            binding = {"input_index": index, "raw_param": raw_param,
                "raw_payload_sha256": hashlib.sha256(payload).hexdigest()}
            try:
                result = decode_packet(emulator, context, raw_param, payload)
                result.update(binding)
                results.append(result)
                if result["status"] != "DECODED":
                    emulator, context = make_broadcast_emulator(image)
            except Exception as exc:
                result = failed(f"exact-runtime emulation failed: {exc}")
                result.update(binding)
                results.append(result)
                emulator, context = make_broadcast_emulator(image)
        json.dump({"status": "PASS", "runtime_image_sha256": digest,
            "results": results}, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except Exception as exc:
        print(f"Broadcast exact-runtime decoder error: {exc}", file=sys.stderr)
        json.dump({"status": "ERROR", "runtime_image_sha256": digest,
            "results": [], "error": str(exc)}, sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
