#!/usr/bin/env python3
"""Decode exact-runtime 16.19 PKT_SetItem_s packet fields as candidates.

The caller owns ROFL framing and provenance. A decoded row describes the one
item record carried by a packet; it does not describe an item transaction.
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

from decode_mapview_inventory_16_19 import (
    IMAGE_SHA256,
    REPLAY_VERSION,
    make_emulator,
    read_image,
    read_input,
    validate_packet,
)


# Only the image with IMAGE_SHA256 supplies these RVAs and object offsets.
CONSTRUCTOR_RVA = 0xED1020
DESERIALIZER_RVA = 0x1058EA0
OBJECT_SIZE = 0x90
SLOT_OFFSET = 0x28
SLOT_BYTE_HELPER_RVA = 0x251C80
FLAG_OFFSET = 0x40
FLAG_BYTE_HELPER_RVA = 0x251D30
ITEM_ID_OFFSET = 0x5C
ITEM_ID_BYTE_HELPER_RVA = 0x251D50

PROFILE = {
    "constructor_rva": CONSTRUCTOR_RVA,
    "deserialize_rva": DESERIALIZER_RVA,
    "object_size": OBJECT_SIZE,
    "fields": [],
}


def failed(message, *, deserialize_return_al=None, bytes_consumed=None):
    return {
        "status": "FAILED",
        "deserialize_return_al": deserialize_return_al,
        "bytes_consumed": bytes_consumed,
        "slot": None,
        "item_id": None,
        "flag": None,
        "raw_slot_byte_hex": None,
        "raw_item_id_bytes_hex": None,
        "error": message,
    }


def decode_packet(emulator, context, raw_param, payload):
    from emulate_exact_packet_decoder import OBJECT_ADDRESS

    context["raw_param"] = raw_param
    decoded = emulator.decode(payload, PROFILE)
    return_al = decoded["deserialize_return_al"]
    consumed = decoded["bytes_consumed"]
    if return_al != 1 or consumed != len(payload) or not decoded["fully_consumed"]:
        return failed(
            "deserializer did not succeed with full payload consumption",
            deserialize_return_al=return_al,
            bytes_consumed=consumed,
        )

    packet_object = bytes(emulator.emulator.mem_read(OBJECT_ADDRESS, OBJECT_SIZE))
    raw_slot = packet_object[SLOT_OFFSET:SLOT_OFFSET + 1]
    raw_flag = packet_object[FLAG_OFFSET:FLAG_OFFSET + 1]
    raw_item_id = packet_object[ITEM_ID_OFFSET:ITEM_ID_OFFSET + 4]
    slot = emulator.decode_bytes(raw_slot, SLOT_BYTE_HELPER_RVA)[0]
    flag = emulator.decode_bytes(raw_flag, FLAG_BYTE_HELPER_RVA)[0]
    item_id = struct.unpack(
        "<I", emulator.decode_bytes(raw_item_id, ITEM_ID_BYTE_HELPER_RVA)
    )[0]
    if slot > 9 or item_id == 0:
        return failed(
            "decoded slot or item ID is outside bounded SetItem record values",
            deserialize_return_al=return_al,
            bytes_consumed=consumed,
        )
    return {
        "status": "DECODED",
        "deserialize_return_al": return_al,
        "bytes_consumed": consumed,
        "slot": slot,
        "item_id": item_id,
        "flag": flag,
        "raw_slot_byte_hex": raw_slot.hex(),
        "raw_item_id_bytes_hex": raw_item_id.hex(),
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
                result = failed(str(exc))
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
            except Exception as exc:
                result = failed(f"exact-runtime emulation failed: {exc}")
                result.update(binding)
                results.append(result)
                emulator, context = make_emulator(image)
        json.dump(
            {"status": "PASS", "runtime_image_sha256": digest, "results": results},
            sys.stdout,
            separators=(",", ":"),
        )
        sys.stdout.write("\n")
        return 0
    except Exception as exc:
        print(f"SetItem exact-runtime decoder error: {exc}", file=sys.stderr)
        json.dump(
            {"status": "ERROR", "runtime_image_sha256": digest,
             "results": [], "error": str(exc)},
            sys.stdout,
            separators=(",", ":"),
        )
        sys.stdout.write("\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
