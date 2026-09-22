#!/usr/bin/env python3
"""Exact-build P0 semantic differential for packet 0x0112.

This script consumes only the four explicitly allowlisted P0 Replay/DETAILS
pairs.  Replay packet extraction and native deserialization are intentionally
separate, reproducible stages; this stage verifies their evidence and compares
every profiled scalar/fixed-word field with the independently sourced DETAILS
CHAMPION_KILL facts.

It never traverses an input directory.  Every input path is explicit, and any
path containing ``holdout`` is rejected before it is opened.
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


EXACT_BUILD = "16.16.805.0442"
PACKET_ID = 0x0112
PACKET_NAME = "PKT_NPC_Hero_Die_s"
EXPECTED_IMAGE_SHA256 = "0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55"
CANONICAL_PARTICIPANT_NETWORK_ID_BASE = 0x400000AD
LOOKUP_TABLE_18_RVA = 0x01B0FC50
LOOKUP_TABLE_50_RVA = 0x01B0FD50

# This is deliberately a closed allowlist, rather than trusting an arbitrary
# manifest supplied on the command line.
SAFE_P0 = {
    "11191024308": {
        "replay_sha256": "1ff3b2d4321bbe4f6bf79bff767305bbf4fa59e42c9524c91f3c3b9421733349",
        "details_sha256": "8838ecff8cd95dd722870c59a9d9d7da2471a9288d93f50d4a9479eaa8dab023",
        "packet_count": 64,
    },
    "11191203388": {
        "replay_sha256": "e54e1950949761bb75df509bd91a6823c3d08569a1f530410cb38fb5e07e3633",
        "details_sha256": "637f6b5dde4ce34dea7b3b2f2bac34e9e855beca5150bd66ec7f38ad74ab11d7",
        "packet_count": 96,
    },
    "11191271422": {
        "replay_sha256": "a5a5580f1a4546fb627b53cf3921a9cf0f3086f15964410e054809a87a3be399",
        "details_sha256": "d5d128c9b76017cd268a48afed1e06383aaaa865f2c998751365539f5d3935cf",
        "packet_count": 79,
    },
    "11191336852": {
        "replay_sha256": "25dff9e58855cfc2afdca6b1df2cc43aaa2da1ddc9823b63993ecfc456eb0e75",
        "details_sha256": "368f1bc1b125fd9a09328eb32ab7541980f5e8355598f6ca33316c590c5fcc7d",
        "packet_count": 62,
    },
}

EXPECTED_FIELD_LAYOUT = {
    "unknown_u32_0x10": (0x10, "u32"),
    "unknown_u8_0x14": (0x14, "u8"),
    "unknown_u32_0x18": (0x18, "u32"),
    "unknown_u32_0x1c": (0x1C, "u32"),
    "unknown_u32_0x28": (0x28, "u32"),
    "unknown_vec3_word_0x2c": (0x2C, "u32"),
    "unknown_vec3_word_0x30": (0x30, "u32"),
    "unknown_vec3_word_0x34": (0x34, "u32"),
    "unknown_u8_0x38": (0x38, "u8"),
    "unknown_u32_0x3c": (0x3C, "u32"),
    "unknown_u32_0x40": (0x40, "u32"),
    "unknown_u32_0x44": (0x44, "u32"),
    "unknown_u8_0x48": (0x48, "u8"),
    "unknown_u32_0x4c": (0x4C, "u32"),
    "unknown_vec3_word_0x50": (0x50, "u32"),
    "unknown_vec3_word_0x54": (0x54, "u32"),
    "unknown_vec3_word_0x58": (0x58, "u32"),
}


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_args() -> argparse.Namespace:
    root = project_root()
    candidates = root / "artifacts" / "full_semantic_baseline_v1" / "runtime_candidates"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        default=root / "artifacts" / "hero_combat_state_v2" / "anchors" / "details_p0_manifest.json",
        type=Path,
    )
    parser.add_argument(
        "--events-manifest",
        default=candidates / "packet_0112_p0_all_events_16_16.jsonl.manifest.json",
        type=Path,
    )
    parser.add_argument(
        "--decoded",
        default=candidates / "packet_0112_p0_native_decoded_16_16.jsonl",
        type=Path,
    )
    parser.add_argument(
        "--decode-summary",
        default=candidates / "packet_0112_p0_native_decode_summary_16_16.json",
        type=Path,
    )
    parser.add_argument(
        "--profile",
        default=candidates / "packet_0112_static_profile.json",
        type=Path,
    )
    parser.add_argument(
        "--image",
        default=(
            root
            / "artifacts"
            / "new_build_rofl_compatibility_gate_v1"
            / "runtime"
            / "league_16.16.805.0442.memory.bin"
        ),
        type=Path,
    )
    parser.add_argument(
        "--output",
        default=candidates / "packet_0112_p0_semantic_differential_16_16.json",
        type=Path,
    )
    parser.add_argument(
        "--aligned-output",
        default=candidates / "packet_0112_p0_semantic_aligned_16_16.jsonl",
        type=Path,
    )
    parser.add_argument(
        "--hash-output",
        default=candidates / "packet_0112_p0_semantic_differential_hashes_16_16.json",
        type=Path,
    )
    parser.add_argument("--window-ms", default=2, type=int)
    options = parser.parse_args()
    if options.window_ms < 0:
        raise ValueError("--window-ms must be non-negative")
    return options


def reject_holdout(path: Path) -> Path:
    resolved = path.resolve()
    if "holdout" in str(resolved).lower():
        raise RuntimeError(f"Holdout path is forbidden: {resolved}")
    return resolved


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    reject_holdout(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path):
    reject_holdout(path)
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def read_jsonl(path: Path) -> list[dict]:
    reject_holdout(path)
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
    reject_holdout(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2)
        stream.write("\n")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    reject_holdout(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=True, separators=(",", ":")))
            stream.write("\n")


def ror8(value: int, count: int) -> int:
    count %= 8
    return ((value >> count) | (value << (8 - count))) & 0xFF


def adjacent_bit_swap(value: int) -> int:
    return (((value & 0xD5) << 1) | ((value >> 1) & 0x55)) & 0xFF


def inverse_permutation(forward, name: str) -> list[int]:
    inverse = [-1] * 256
    for plain in range(256):
        encoded = forward(plain)
        if inverse[encoded] != -1:
            raise RuntimeError(f"{name} is not a byte permutation")
        inverse[encoded] = plain
    if any(value < 0 for value in inverse):
        raise RuntimeError(f"{name} does not cover all byte values")
    return inverse


def transform_u32(value: int, table: list[int]) -> int:
    raw = bytearray(struct.pack("<I", value & 0xFFFFFFFF))
    for index, encoded in enumerate(raw):
        raw[index] = table[encoded]
    return struct.unpack("<I", raw)[0]


def build_storage_inverses(image: bytes) -> tuple[dict[str, list[int]], dict]:
    table18 = image[LOOKUP_TABLE_18_RVA:LOOKUP_TABLE_18_RVA + 0x100]
    table50 = image[LOOKUP_TABLE_50_RVA:LOOKUP_TABLE_50_RVA + 0x100]
    if len(table18) != 0x100 or len(table50) != 0x100:
        raise RuntimeError("runtime lookup tables fall outside the exact image")

    def encode_10(value: int) -> int:
        value = (value + 0x58) & 0xFF
        value = (~value) & 0xFF
        value = ror8(value, 4)
        value = (value + 0x77) & 0xFF
        return (~value) & 0xFF

    def encode_18(value: int) -> int:
        value = table18[value]
        value = ror8(value, 7)
        value = (value - 0x70) & 0xFF
        value = adjacent_bit_swap(value)
        value = ror8(value, 7)
        return value ^ 0x02

    def encode_28(value: int) -> int:
        value = (value - 0x51) & 0xFF
        value ^= 0xE0
        value = ror8(value, 2)
        value ^= 0x9F
        return ror8(value, 2)

    def encode_3c(value: int) -> int:
        value = adjacent_bit_swap(value)
        value = ror8(value, 3)
        value = ((value << 5) | (value >> 3)) & 0xFF
        value = table18[value]
        value ^= 0x59
        return (value + 0x32) & 0xFF

    # 0xe63d40 decrypts existing 12-byte storage before invoking its leaf
    # decoder.  This direction therefore maps storage byte -> plain byte.
    def decrypt_50(value: int) -> int:
        value = ror8(value, 2)
        value = (~value) & 0xFF
        value = (value - 0x47) & 0xFF
        value ^= 0x8D
        value = table50[value]
        value = (~value) & 0xFF
        value = adjacent_bit_swap(value)
        return ror8(value, 7)

    inverses = {
        "0x10": inverse_permutation(encode_10, "0xe632e0 post-transform"),
        "0x18": inverse_permutation(encode_18, "0xe639c0 post-transform"),
        "0x28": inverse_permutation(encode_28, "0xe63600 post-transform"),
        "0x3c": inverse_permutation(encode_3c, "0xe630b0 post-transform"),
        "0x50": [decrypt_50(value) for value in range(256)],
    }
    evidence = {
        "0x10": {
            "helper_rva": "0x00e632e0",
            "inverse_kind": "inverse of exact post-decode byte permutation",
        },
        "0x18": {
            "helper_rva": "0x00e639c0",
            "lookup_table_rva": f"0x{LOOKUP_TABLE_18_RVA:08x}",
            "lookup_table_sha256": sha256_bytes(table18),
            "inverse_kind": "inverse of exact post-decode byte permutation",
        },
        "0x28": {
            "helper_rva": "0x00e63600",
            "inverse_kind": "inverse of exact post-decode byte permutation",
        },
        "0x3c": {
            "helper_rva": "0x00e630b0",
            "lookup_table_rva": f"0x{LOOKUP_TABLE_18_RVA:08x}",
            "lookup_table_sha256": sha256_bytes(table18),
            "inverse_kind": "inverse of exact post-decode byte permutation",
        },
        "0x50..0x58": {
            "helper_rva": "0x00e63d40",
            "lookup_table_rva": f"0x{LOOKUP_TABLE_50_RVA:08x}",
            "lookup_table_sha256": sha256_bytes(table50),
            "inverse_kind": "exact helper pre-update storage decryption",
        },
    }
    return inverses, evidence


def float32_from_u32(value: int):
    result = struct.unpack("<f", struct.pack("<I", value & 0xFFFFFFFF))[0]
    return result if math.isfinite(result) else None


def validate_profile(profile_bundle: dict) -> tuple[dict, str]:
    profile = profile_bundle.get("profile", profile_bundle)
    expected = {
        "client_opcode": PACKET_ID,
        "constructor_rva": 0x00E7DA60,
        "deserialize_rva": 0x00EF7800,
        "object_size": 0x5C,
    }
    for key, wanted in expected.items():
        actual = profile.get(key)
        if isinstance(actual, str):
            actual = int(actual, 0)
        if actual != wanted:
            raise RuntimeError(f"profile {key}={actual!r}, expected {wanted:#x}")
    fields = {
        item["name"]: (int(item["offset"]), item["type"])
        for item in profile.get("fields", [])
    }
    if fields != EXPECTED_FIELD_LAYOUT:
        raise RuntimeError("0x0112 profile field layout does not match the audited layout")
    return profile, profile.get("id", "unknown")


def validate_safe_manifest(manifest: dict) -> tuple[dict[str, dict], dict[str, str]]:
    entries = manifest.get("replays", [])
    found = {str(entry.get("game_id")): entry for entry in entries}
    if set(found) != set(SAFE_P0):
        raise RuntimeError(
            f"P0 manifest games {sorted(found)} do not equal closed allowlist {sorted(SAFE_P0)}"
        )
    by_replay_sha = {}
    details_paths = {}
    for game_id, expected in SAFE_P0.items():
        entry = found[game_id]
        replay = entry.get("replay", {})
        details = entry.get("details", {})
        if entry.get("replay_build") != EXACT_BUILD:
            raise RuntimeError(f"wrong exact build for game {game_id}")
        if replay.get("sha256") != expected["replay_sha256"]:
            raise RuntimeError(f"wrong Replay SHA-256 for safe game {game_id}")
        if details.get("sha256") != expected["details_sha256"]:
            raise RuntimeError(f"wrong DETAILS SHA-256 for safe game {game_id}")
        replay_path = reject_holdout(Path(replay["path"]))
        details_path = reject_holdout(Path(details["path"]))
        by_replay_sha[expected["replay_sha256"]] = {
            "game_id": game_id,
            "entry": entry,
            "replay_path": str(replay_path),
            "details_path": str(details_path),
        }
        details_paths[game_id] = str(details_path)
    return by_replay_sha, details_paths


def load_details_events(by_replay_sha: dict[str, dict]) -> tuple[list[dict], list[dict]]:
    events = []
    provenance = []
    for replay_sha, safe in by_replay_sha.items():
        game_id = safe["game_id"]
        expected = SAFE_P0[game_id]
        details_path = Path(safe["details_path"])
        actual_sha = sha256_file(details_path)
        if actual_sha != expected["details_sha256"]:
            raise RuntimeError(f"DETAILS file hash mismatch for safe game {game_id}")
        wrapper = read_json(details_path)
        body = wrapper.get("json", {})
        if str(body.get("gameId")) != game_id:
            raise RuntimeError(f"DETAILS gameId mismatch for safe game {game_id}")
        count = 0
        for frame_index, frame in enumerate(body.get("frames", [])):
            for event_index, event in enumerate(frame.get("events", [])):
                if event.get("type") != "CHAMPION_KILL":
                    continue
                victim = event.get("victimId")
                killer = event.get("killerId")
                if not isinstance(victim, int) or not 1 <= victim <= 10:
                    raise RuntimeError(f"invalid victimId in safe game {game_id}")
                if not isinstance(killer, int) or not 1 <= killer <= 10:
                    raise RuntimeError(f"invalid killerId in safe game {game_id}")
                assists_present = "assistingParticipantIds" in event
                assists = event.get("assistingParticipantIds", [])
                if not isinstance(assists, list) or any(
                    not isinstance(value, int) or not 1 <= value <= 10 for value in assists
                ):
                    raise RuntimeError(f"invalid assistingParticipantIds in safe game {game_id}")
                if len(set(assists)) != len(assists):
                    raise RuntimeError(f"duplicate assistingParticipantIds in safe game {game_id}")
                position = event.get("position") or {}
                events.append({
                    "game_id": game_id,
                    "replay_sha256": replay_sha,
                    "timestamp_ms": int(event["timestamp"]),
                    "victim_id": victim,
                    "killer_id": killer,
                    "assists": list(assists),
                    "assists_property_present": assists_present,
                    "bounty": event.get("bounty"),
                    "shutdown_bounty": event.get("shutdownBounty"),
                    "kill_streak_length": event.get("killStreakLength"),
                    "position_x": position.get("x"),
                    "position_y": position.get("y"),
                    "details_event_json_path": f"$.json.frames[{frame_index}].events[{event_index}]",
                })
                count += 1
        if count != expected["packet_count"]:
            raise RuntimeError(
                f"safe game {game_id} has {count} CHAMPION_KILL events; "
                f"expected {expected['packet_count']}"
            )
        provenance.append({
            "game_id": game_id,
            "replay_sha256": replay_sha,
            "replay_path": safe["replay_path"],
            "details_path": str(details_path),
            "details_sha256": actual_sha,
            "champion_kill_count": count,
        })
    return events, provenance


def validate_native_rows(
    rows: list[dict],
    allowed: dict[str, dict],
    image_sha: str,
    profile_sha: str,
) -> dict:
    expected_total = sum(value["packet_count"] for value in SAFE_P0.values())
    if len(rows) != expected_total:
        raise RuntimeError(f"native decoded row count={len(rows)}, expected {expected_total}")
    per_replay = collections.Counter()
    payload_lengths = collections.Counter()
    for row_index, row in enumerate(rows):
        replay_sha = row.get("replay_sha256")
        if replay_sha not in allowed:
            raise RuntimeError(f"decoded row {row_index} is outside the closed Replay allowlist")
        if row.get("replay_version") != EXACT_BUILD or row.get("packet_id") != PACKET_ID:
            raise RuntimeError(f"decoded row {row_index} has wrong build/packet")
        if row.get("decoder_runtime_image_sha256") != image_sha:
            raise RuntimeError(f"decoded row {row_index} has wrong native image hash")
        if row.get("decoder_profile_sha256") != profile_sha:
            raise RuntimeError(f"decoded row {row_index} has wrong profile hash")
        if row.get("deserialize_return_al", 0) == 0 or not row.get("fully_consumed"):
            raise RuntimeError(f"decoded row {row_index} was not a successful full-consume")
        if row.get("decoded_opcode") != PACKET_ID or not row.get("opcode_matches_profile"):
            raise RuntimeError(f"decoded row {row_index} wrapper opcode mismatch")
        raw_payload = bytes.fromhex(row["raw_payload_hex"])
        if len(raw_payload) != row.get("payload_length"):
            raise RuntimeError(f"decoded row {row_index} payload length mismatch")
        if sha256_bytes(raw_payload) != row.get("raw_payload_sha256"):
            raise RuntimeError(f"decoded row {row_index} payload SHA-256 mismatch")
        decoded_fields = row.get("decoded_fields", {})
        if set(decoded_fields) != set(EXPECTED_FIELD_LAYOUT):
            raise RuntimeError(f"decoded row {row_index} field set mismatch")
        per_replay[replay_sha] += 1
        payload_lengths[int(row["payload_length"])] += 1
    for replay_sha, safe in allowed.items():
        expected = SAFE_P0[safe["game_id"]]["packet_count"]
        if per_replay[replay_sha] != expected:
            raise RuntimeError(f"native row count mismatch for safe game {safe['game_id']}")
    return {
        "event_count": len(rows),
        "deserialize_success_count": len(rows),
        "fully_consumed_count": len(rows),
        "successful_full_consume_count": len(rows),
        "per_replay_counts": dict(sorted(per_replay.items())),
        "payload_length_counts": {
            str(key): value for key, value in sorted(payload_lengths.items())
        },
    }


def derive_views(fields: dict, inverses: dict[str, list[int]]) -> dict[str, int]:
    views = {f"storage::{name}": int(value) for name, value in fields.items()}
    views.update({
        "helper_inverse_u32_0x10": transform_u32(fields["unknown_u32_0x10"], inverses["0x10"]),
        "helper_inverse_u32_0x18": transform_u32(fields["unknown_u32_0x18"], inverses["0x18"]),
        "helper_inverse_u32_0x28": transform_u32(fields["unknown_u32_0x28"], inverses["0x28"]),
        "helper_inverse_u32_0x3c": transform_u32(fields["unknown_u32_0x3c"], inverses["0x3c"]),
        "helper_inverse_word_0x50": transform_u32(fields["unknown_vec3_word_0x50"], inverses["0x50"]),
        "helper_inverse_word_0x54": transform_u32(fields["unknown_vec3_word_0x54"], inverses["0x50"]),
        "helper_inverse_word_0x58": transform_u32(fields["unknown_vec3_word_0x58"], inverses["0x50"]),
    })
    return views


def align_rows(
    native_rows: list[dict],
    details_events: list[dict],
    allowed: dict[str, dict],
    inverses: dict[str, list[int]],
    window_ms: int,
) -> tuple[list[dict], dict]:
    used = set()
    aligned = []
    ambiguity_count = 0
    for row_index, row in enumerate(native_rows):
        victim = (int(row["raw_param"]) & 0xFF) - 0xAD
        candidates = []
        for details_index, event in enumerate(details_events):
            if details_index in used:
                continue
            if event["replay_sha256"] != row["replay_sha256"]:
                continue
            if event["victim_id"] != victim:
                continue
            delta = abs(event["timestamp_ms"] - int(row["replay_time_ms"]))
            if delta <= window_ms:
                candidates.append((delta, details_index, event))
        candidates.sort(key=lambda item: (item[0], item[1]))
        if not candidates:
            raise RuntimeError(
                f"no DETAILS match for decoded row {row_index}: "
                f"time={row['replay_time_ms']} victim={victim}"
            )
        best_delta = candidates[0][0]
        best_candidates = [item for item in candidates if item[0] == best_delta]
        if len(best_candidates) != 1:
            ambiguity_count += 1
            raise RuntimeError(f"ambiguous DETAILS match for decoded row {row_index}")
        _, details_index, event = best_candidates[0]
        used.add(details_index)
        views = derive_views(row["decoded_fields"], inverses)
        aligned.append({
            "row_index": row_index,
            "game_id": allowed[row["replay_sha256"]]["game_id"],
            "replay_sha256": row["replay_sha256"],
            "replay_build": row["replay_version"],
            "route_timestamp_ms": int(row["replay_time_ms"]),
            "details_timestamp_ms": event["timestamp_ms"],
            "timestamp_absolute_delta_ms": best_delta,
            "packet_id": PACKET_ID,
            "payload_length": int(row["payload_length"]),
            "raw_param": int(row["raw_param"]) & 0xFFFFFFFF,
            "raw_param_hex": f"0x{int(row['raw_param']) & 0xFFFFFFFF:08x}",
            "raw_payload_sha256": row["raw_payload_sha256"],
            "victim_participant_from_raw_param": victim,
            "details": event,
            "native_views": views,
        })
    if len(used) != len(details_events):
        raise RuntimeError(f"{len(details_events) - len(used)} DETAILS events were unmatched")
    delta_counts = collections.Counter(
        row["timestamp_absolute_delta_ms"] for row in aligned
    )
    route_canonical_count = sum(
        row["raw_param"]
        == CANONICAL_PARTICIPANT_NETWORK_ID_BASE + row["details"]["victim_id"]
        for row in aligned
    )
    return aligned, {
        "window_ms": window_ms,
        "route_count": len(native_rows),
        "details_count": len(details_events),
        "matched_count": len(aligned),
        "ambiguous_match_count": ambiguity_count,
        "unmatched_route_count": len(native_rows) - len(aligned),
        "unmatched_details_count": len(details_events) - len(used),
        "timestamp_absolute_delta_ms": {
            "min": min(delta_counts),
            "max": max(delta_counts),
            "counts": {str(key): value for key, value in sorted(delta_counts.items())},
        },
        "victim_low_byte_mapping_match_count": sum(
            row["victim_participant_from_raw_param"] == row["details"]["victim_id"]
            for row in aligned
        ),
        "raw_param_exact_canonical_victim_network_id_count": route_canonical_count,
        "raw_param_noncanonical_upper_byte_variant_count": len(aligned) - route_canonical_count,
    }


def value_summary(values: list[int], type_name: str) -> dict:
    counts = collections.Counter(values)
    width = 2 if type_name == "u8" else 8
    summary = {
        "observation_count": len(values),
        "unique_count": len(counts),
        "min": min(values),
        "max": max(values),
        "zero_count": counts[0],
        "one_count": counts[1],
        "all_ones_count": counts[0xFF if type_name == "u8" else 0xFFFFFFFF],
        "constant": len(counts) == 1,
        "top_values": [
            {
                "value": value,
                "hex": f"0x{value:0{width}x}",
                "count": count,
            }
            for value, count in counts.most_common(12)
        ],
    }
    if type_name == "u32":
        repeated_byte_count = 0
        repeated_byte_values = collections.Counter()
        floats = []
        for value in values:
            raw = struct.pack("<I", value & 0xFFFFFFFF)
            if len(set(raw)) == 1:
                repeated_byte_count += 1
                repeated_byte_values[value] += 1
            float_value = float32_from_u32(value)
            if float_value is not None:
                floats.append(float_value)
        summary["repeated_byte_pattern_count"] = repeated_byte_count
        summary["repeated_byte_patterns"] = [
            {"hex": f"0x{value:08x}", "count": count}
            for value, count in repeated_byte_values.most_common(8)
        ]
        summary["float32_view"] = {
            "finite_count": len(floats),
            "nonfinite_count": len(values) - len(floats),
            "min": min(floats) if floats else None,
            "max": max(floats) if floats else None,
        }
    return summary


def event_targets(event: dict) -> dict[str, int]:
    assists = event["assists"]
    assist_bitmask = sum(1 << (participant - 1) for participant in set(assists))
    return {
        "victim_participant_id": event["victim_id"],
        "killer_participant_id": event["killer_id"],
        "canonical_victim_network_id": (
            CANONICAL_PARTICIPANT_NETWORK_ID_BASE + event["victim_id"]
        ),
        "canonical_killer_network_id": (
            CANONICAL_PARTICIPANT_NETWORK_ID_BASE + event["killer_id"]
        ),
        "assist_count": len(assists),
        "assist_bitmask_pid1_lsb": assist_bitmask,
        "has_assists_boolean": int(bool(assists)),
        "no_assists_boolean": int(not assists),
        "bounty": int(event["bounty"]),
        "shutdown_bounty": int(event["shutdown_bounty"]),
        "kill_streak_length": int(event["kill_streak_length"]),
        "position_x": int(event["position_x"]),
        "position_y": int(event["position_y"]),
    }


def first_mismatch_record(row: dict, actual: int, expected) -> dict:
    return {
        "game_id": row["game_id"],
        "route_timestamp_ms": row["route_timestamp_ms"],
        "details_event_json_path": row["details"]["details_event_json_path"],
        "actual": actual,
        "expected": expected,
    }


def equality_relation(
    aligned: list[dict],
    view_name: str,
    target_name: str,
    predicate=None,
) -> dict:
    applicable = [row for row in aligned if predicate is None or predicate(row["details"])]
    matches = 0
    first_mismatch = None
    for row in applicable:
        actual = row["native_views"][view_name]
        if target_name == "sole_assist_participant_id":
            expected = row["details"]["assists"][0]
        elif target_name == "canonical_sole_assist_network_id":
            expected = (
                CANONICAL_PARTICIPANT_NETWORK_ID_BASE
                + row["details"]["assists"][0]
            )
        else:
            expected = event_targets(row["details"])[target_name]
        if actual == expected:
            matches += 1
        elif first_mismatch is None:
            first_mismatch = first_mismatch_record(row, actual, expected)
    return {
        "matches": matches,
        "applicable": len(applicable),
        "all_applicable_match": bool(applicable) and matches == len(applicable),
        "first_mismatch": first_mismatch,
    }


def functional_mapping(aligned: list[dict], view_name: str, target_name: str) -> dict:
    mapping = {}
    repeated_observation_count = 0
    conflicting_observation_count = 0
    conflicting_values = set()
    for row in aligned:
        value = row["native_views"][view_name]
        if target_name == "assist_set":
            target = tuple(sorted(row["details"]["assists"]))
        else:
            target = event_targets(row["details"])[target_name]
        if value in mapping:
            repeated_observation_count += 1
            if mapping[value] != target:
                conflicting_observation_count += 1
                conflicting_values.add(value)
        else:
            mapping[value] = target
    return {
        "distinct_field_values": len(mapping),
        "repeated_observation_count": repeated_observation_count,
        "conflicting_observation_count": conflicting_observation_count,
        "conflicting_field_value_count": len(conflicting_values),
        "is_deterministic_on_observed_repeats": conflicting_observation_count == 0,
    }


def build_scalar_matrix(aligned: list[dict]) -> tuple[list[dict], dict[str, dict]]:
    view_names = list(aligned[0]["native_views"])
    field_types = {
        f"storage::{name}": type_name
        for name, (_, type_name) in EXPECTED_FIELD_LAYOUT.items()
    }
    for name in view_names:
        field_types.setdefault(name, "u32")
    relations = [
        "victim_participant_id",
        "killer_participant_id",
        "canonical_victim_network_id",
        "canonical_killer_network_id",
        "assist_count",
        "assist_bitmask_pid1_lsb",
        "has_assists_boolean",
        "no_assists_boolean",
        "bounty",
        "shutdown_bounty",
        "kill_streak_length",
        "position_x",
        "position_y",
    ]
    matrix = []
    summaries = {}
    for view_name in view_names:
        values = [row["native_views"][view_name] for row in aligned]
        type_name = field_types[view_name]
        summaries[view_name] = value_summary(values, type_name)
        exact = {
            relation: equality_relation(aligned, view_name, relation)
            for relation in relations
        }
        exact["sole_assist_participant_id"] = equality_relation(
            aligned,
            view_name,
            "sole_assist_participant_id",
            predicate=lambda event: len(event["assists"]) == 1,
        )
        exact["canonical_sole_assist_network_id"] = equality_relation(
            aligned,
            view_name,
            "canonical_sole_assist_network_id",
            predicate=lambda event: len(event["assists"]) == 1,
        )

        low_byte_direct = {}
        low_byte_minus_ad = {}
        for target_name, event_key in (
            ("victim_participant_id", "victim_id"),
            ("killer_participant_id", "killer_id"),
        ):
            direct_matches = sum(
                (row["native_views"][view_name] & 0xFF) == row["details"][event_key]
                for row in aligned
            )
            mapped_matches = sum(
                ((row["native_views"][view_name] & 0xFF) - 0xAD)
                == row["details"][event_key]
                for row in aligned
            )
            low_byte_direct[target_name] = {
                "matches": direct_matches,
                "applicable": len(aligned),
                "all_applicable_match": direct_matches == len(aligned),
            }
            low_byte_minus_ad[target_name] = {
                "matches": mapped_matches,
                "applicable": len(aligned),
                "all_applicable_match": mapped_matches == len(aligned),
            }

        assist_rows = [row for row in aligned if row["details"]["assists"]]
        any_assist_exact = sum(
            row["native_views"][view_name] in row["details"]["assists"]
            for row in assist_rows
        )
        any_assist_low_direct = sum(
            (row["native_views"][view_name] & 0xFF) in row["details"]["assists"]
            for row in assist_rows
        )
        any_assist_low_minus_ad = sum(
            ((row["native_views"][view_name] & 0xFF) - 0xAD)
            in row["details"]["assists"]
            for row in assist_rows
        )

        matrix.append({
            "view": view_name,
            "type": type_name,
            "exact_equality": exact,
            "low_byte_direct_participant": low_byte_direct,
            "low_byte_minus_0xad_participant": low_byte_minus_ad,
            "any_assist_membership": {
                "applicable_nonempty_assist_rows": len(assist_rows),
                "exact_value_matches": any_assist_exact,
                "low_byte_direct_matches": any_assist_low_direct,
                "low_byte_minus_0xad_matches": any_assist_low_minus_ad,
            },
            "observed_functional_mapping": {
                "killer_participant_id": functional_mapping(
                    aligned, view_name, "killer_participant_id"
                ),
                "victim_participant_id": functional_mapping(
                    aligned, view_name, "victim_participant_id"
                ),
                "assist_count": functional_mapping(aligned, view_name, "assist_count"),
                "assist_set": functional_mapping(aligned, view_name, "assist_set"),
            },
        })
    return matrix, summaries


def participant_set(values: list[int], mode: str) -> list[int]:
    result = set()
    for value in values:
        if mode == "direct":
            candidate = value
        elif mode == "low_byte":
            candidate = value & 0xFF
        elif mode == "low_byte_minus_0xad":
            candidate = (value & 0xFF) - 0xAD
        elif mode == "canonical_network_id":
            candidate = value - CANONICAL_PARTICIPANT_NETWORK_ID_BASE
        else:
            raise KeyError(mode)
        if 1 <= candidate <= 10:
            result.add(candidate)
    return sorted(result)


def build_triplet_matrix(aligned: list[dict]) -> list[dict]:
    groups = {
        "storage_words_0x2c_0x34": [
            "storage::unknown_vec3_word_0x2c",
            "storage::unknown_vec3_word_0x30",
            "storage::unknown_vec3_word_0x34",
        ],
        "storage_words_0x50_0x58": [
            "storage::unknown_vec3_word_0x50",
            "storage::unknown_vec3_word_0x54",
            "storage::unknown_vec3_word_0x58",
        ],
        "helper_inverse_words_0x50_0x58": [
            "helper_inverse_word_0x50",
            "helper_inverse_word_0x54",
            "helper_inverse_word_0x58",
        ],
    }
    output = []
    for group_name, view_names in groups.items():
        rows = []
        unique = collections.Counter()
        for row in aligned:
            values = [row["native_views"][name] for name in view_names]
            unique[tuple(values)] += 1
            rows.append((row, values))
        comparisons = {}
        for mode in (
            "direct",
            "low_byte",
            "low_byte_minus_0xad",
            "canonical_network_id",
        ):
            assist_match = 0
            killer_plus_assist_match = 0
            first_assist_mismatch = None
            for row, values in rows:
                candidate = participant_set(values, mode)
                assists = sorted(row["details"]["assists"])
                killer_plus = sorted(set([row["details"]["killer_id"], *assists]))
                if candidate == assists:
                    assist_match += 1
                elif first_assist_mismatch is None:
                    first_assist_mismatch = first_mismatch_record(row, candidate, assists)
                if candidate == killer_plus:
                    killer_plus_assist_match += 1
            comparisons[mode] = {
                "assist_set_exact_matches": assist_match,
                "killer_plus_assist_set_exact_matches": killer_plus_assist_match,
                "applicable": len(rows),
                "first_assist_set_mismatch": first_assist_mismatch,
            }
        nonzero_count_matches = sum(
            sum(value != 0 for value in values) == len(row["details"]["assists"])
            for row, values in rows
        )
        exact_position_prefix_xy = sum(
            values[0] == row["details"]["position_x"]
            and values[1] == row["details"]["position_y"]
            for row, values in rows
        )
        float_position_prefix_xy = sum(
            float32_from_u32(values[0]) == row["details"]["position_x"]
            and float32_from_u32(values[1]) == row["details"]["position_y"]
            for row, values in rows
        )
        output.append({
            "group": group_name,
            "shape": "fixed_three_u32_words_no_pointer_count_capacity",
            "view_names": view_names,
            "observation_count": len(rows),
            "unique_triplet_count": len(unique),
            "all_zero_triplet_count": unique[(0, 0, 0)],
            "top_triplets": [
                {
                    "values": list(values),
                    "hex": [f"0x{value:08x}" for value in values],
                    "count": count,
                }
                for values, count in unique.most_common(8)
            ],
            "participant_set_comparisons": comparisons,
            "nonzero_element_count_equals_assist_count": {
                "matches": nonzero_count_matches,
                "applicable": len(rows),
            },
            "position_prefix_xy_comparisons": {
                "exact_u32_matches": exact_position_prefix_xy,
                "float32_exact_matches": float_position_prefix_xy,
                "applicable": len(rows),
            },
        })
    return output


def build_assist_distribution(aligned: list[dict]) -> dict:
    counts = collections.Counter(len(row["details"]["assists"]) for row in aligned)
    property_present = sum(
        row["details"]["assists_property_present"] for row in aligned
    )
    return {
        "assist_count_distribution": {
            str(key): value for key, value in sorted(counts.items())
        },
        "nonempty_assist_event_count": sum(
            bool(row["details"]["assists"]) for row in aligned
        ),
        "zero_assist_event_count": counts[0],
        "assistingParticipantIds_property_present_count": property_present,
        "property_absent_normalized_to_empty_count": len(aligned) - property_present,
        "unique_assist_set_count": len({
            tuple(sorted(row["details"]["assists"])) for row in aligned
        }),
    }


def build_per_killer_support(aligned: list[dict]) -> list[dict]:
    output = []
    for killer_id in range(1, 11):
        rows = [row for row in aligned if row["details"]["killer_id"] == killer_id]
        expected = CANONICAL_PARTICIPANT_NETWORK_ID_BASE + killer_id
        values = collections.Counter(
            row["native_views"]["helper_inverse_u32_0x18"] for row in rows
        )
        output.append({
            "killer_participant_id": killer_id,
            "observation_count": len(rows),
            "expected_canonical_network_id": expected,
            "expected_canonical_network_id_hex": f"0x{expected:08x}",
            "matching_count": values[expected],
            "observed_values": [
                {"value": value, "hex": f"0x{value:08x}", "count": count}
                for value, count in values.most_common()
            ],
        })
    return output


def summarize_negative_assist_evidence(
    scalar_matrix: list[dict],
    triplet_matrix: list[dict],
    aligned: list[dict],
) -> dict:
    def best_exact(relation: str) -> dict:
        candidates = [
            {
                "view": row["view"],
                **row["exact_equality"][relation],
            }
            for row in scalar_matrix
        ]
        return max(candidates, key=lambda item: item["matches"])

    any_assist_candidates = []
    for row in scalar_matrix:
        surface = row["any_assist_membership"]
        for representation in (
            "exact_value_matches",
            "low_byte_direct_matches",
            "low_byte_minus_0xad_matches",
        ):
            any_assist_candidates.append({
                "view": row["view"],
                "representation": representation,
                "matches": surface[representation],
                "applicable": surface["applicable_nonempty_assist_rows"],
            })
    best_triplet = None
    for group in triplet_matrix:
        for mode, values in group["participant_set_comparisons"].items():
            candidate = {
                "group": group["group"],
                "representation": mode,
                "matches": values["assist_set_exact_matches"],
                "applicable": values["applicable"],
                "first_mismatch": values["first_assist_set_mismatch"],
            }
            if best_triplet is None or candidate["matches"] > best_triplet["matches"]:
                best_triplet = candidate
    nonempty = sum(bool(row["details"]["assists"]) for row in aligned)
    return {
        "independent_positive_and_negative_surface": {
            "nonempty_assist_events": nonempty,
            "zero_assist_events": len(aligned) - nonempty,
            "sole_assist_events": sum(
                len(row["details"]["assists"]) == 1 for row in aligned
            ),
            "multi_assist_events": sum(
                len(row["details"]["assists"]) > 1 for row in aligned
            ),
        },
        "best_scalar_exact_assist_count": best_exact("assist_count"),
        "best_scalar_exact_assist_bitmask": best_exact("assist_bitmask_pid1_lsb"),
        "best_scalar_exact_has_assists_boolean": best_exact("has_assists_boolean"),
        "best_scalar_exact_no_assists_boolean": best_exact("no_assists_boolean"),
        "best_scalar_sole_assist_id": best_exact("sole_assist_participant_id"),
        "best_scalar_any_assist_membership": max(
            any_assist_candidates,
            key=lambda item: item["matches"],
        ),
        "best_fixed_triplet_assist_set": best_triplet,
        "constant_zero_counterevidence": {
            "outer_u32_0x1c_zero_count": sum(
                row["native_views"]["storage::unknown_u32_0x1c"] == 0
                for row in aligned
            ),
            "helper_inverse_0x50_0x58_all_zero_count": sum(
                all(row["native_views"][f"helper_inverse_word_0x{offset:x}"] == 0
                    for offset in (0x50, 0x54, 0x58))
                for row in aligned
            ),
            "nonempty_assist_events_refuting_zero_as_assist_list": nonempty,
        },
        "conclusion": (
            "No scalar, count, boolean, bitmask, single-assist, membership, or fixed-triplet "
            "assist representation reaches the declared promotion threshold."
        ),
    }


def compact_aligned_rows(aligned: list[dict]) -> list[dict]:
    return [{
        "schema_version": 1,
        "game_id": row["game_id"],
        "replay_sha256": row["replay_sha256"],
        "replay_build": row["replay_build"],
        "route_timestamp_ms": row["route_timestamp_ms"],
        "details_timestamp_ms": row["details_timestamp_ms"],
        "timestamp_absolute_delta_ms": row["timestamp_absolute_delta_ms"],
        "packet_id": row["packet_id"],
        "packet_id_hex": f"0x{row['packet_id']:04x}",
        "payload_length": row["payload_length"],
        "raw_param": row["raw_param"],
        "raw_param_hex": row["raw_param_hex"],
        "raw_payload_sha256": row["raw_payload_sha256"],
        "details_event_json_path": row["details"]["details_event_json_path"],
        "details_victim_id": row["details"]["victim_id"],
        "details_killer_id": row["details"]["killer_id"],
        "details_assisting_participant_ids": row["details"]["assists"],
        "details_assists_property_present": row["details"]["assists_property_present"],
        "native_views": row["native_views"],
    } for row in aligned]


def main() -> None:
    options = parse_args()
    input_paths = [
        options.manifest,
        options.events_manifest,
        options.decoded,
        options.decode_summary,
        options.profile,
        options.image,
        options.output,
        options.aligned_output,
        options.hash_output,
    ]
    for path in input_paths:
        reject_holdout(path)

    manifest = read_json(options.manifest)
    allowed, _ = validate_safe_manifest(manifest)
    profile_bundle = read_json(options.profile)
    profile, profile_id = validate_profile(profile_bundle)
    profile_sha = sha256_file(options.profile)
    image_sha = sha256_file(options.image)
    if image_sha != EXPECTED_IMAGE_SHA256:
        raise RuntimeError("exact runtime image SHA-256 mismatch")
    image = options.image.read_bytes()
    inverses, inverse_evidence = build_storage_inverses(image)

    event_manifest = read_json(options.events_manifest)
    if event_manifest.get("target_replay_version") != EXACT_BUILD:
        raise RuntimeError("event manifest exact build mismatch")
    if event_manifest.get("packet_counts", {}).get(str(PACKET_ID)) != 301:
        raise RuntimeError("event manifest does not attest all 301 route rows")
    event_replay_shas = {entry["sha256"] for entry in event_manifest.get("replays", [])}
    if event_replay_shas != set(allowed):
        raise RuntimeError("event manifest Replay set differs from closed allowlist")
    event_path = reject_holdout(Path(event_manifest["output"]))
    if not event_path.is_file():
        raise RuntimeError(f"event JSONL is missing: {event_path}")
    event_sha = sha256_file(event_path)

    decode_summary = read_json(options.decode_summary)
    if decode_summary.get("image_sha256") != image_sha:
        raise RuntimeError("decode summary image hash mismatch")
    if decode_summary.get("profile_sha256") != profile_sha:
        raise RuntimeError("decode summary profile hash mismatch")
    if Path(decode_summary.get("events_path", "")).resolve() != event_path:
        raise RuntimeError("decode summary event path differs from the attested event manifest")
    if any(decode_summary.get(key) != 301 for key in (
        "event_count",
        "deserialize_success_count",
        "fully_consumed_count",
        "successful_full_consume_count",
    )):
        raise RuntimeError("decode summary does not attest 301/301 full-consume")
    if decode_summary.get("emulation_errors"):
        raise RuntimeError("decode summary contains emulation errors")

    native_rows = read_jsonl(options.decoded)
    native_summary = validate_native_rows(
        native_rows,
        allowed,
        image_sha,
        profile_sha,
    )
    details_events, safe_input_provenance = load_details_events(allowed)
    aligned, alignment = align_rows(
        native_rows,
        details_events,
        allowed,
        inverses,
        options.window_ms,
    )
    scalar_matrix, field_summaries = build_scalar_matrix(aligned)
    triplet_matrix = build_triplet_matrix(aligned)
    assist_distribution = build_assist_distribution(aligned)
    negative_assist_evidence = summarize_negative_assist_evidence(
        scalar_matrix,
        triplet_matrix,
        aligned,
    )

    killer_network_matches = sum(
        row["native_views"]["helper_inverse_u32_0x18"]
        == CANONICAL_PARTICIPANT_NETWORK_ID_BASE + row["details"]["killer_id"]
        for row in aligned
    )
    killer_participant_matches = sum(
        (
            row["native_views"]["helper_inverse_u32_0x18"] & 0xFF
        ) - 0xAD == row["details"]["killer_id"]
        for row in aligned
    )
    storage_roundtrip_distinct = len({
        row["native_views"]["storage::unknown_u32_0x18"] for row in aligned
    })

    report = {
        "schema": "ROFL_16_16_PACKET_0112_P0_SEMANTIC_DIFFERENTIAL_V1",
        "schema_version": 1,
        "status": "PASS" if killer_network_matches == 301 else "FAIL",
        "exact_build": EXACT_BUILD,
        "packet_id": PACKET_ID,
        "packet_id_hex": f"0x{PACKET_ID:04x}",
        "runtime_type_name": PACKET_NAME,
        "scope": (
            "Closed four-Replay P0 allowlist; exact native decode plus independent "
            "DETAILS CHAMPION_KILL differential. No Holdout input is traversed or consumed."
        ),
        "promotion_rule": (
            "Only 301/301 unconditional support, or an explicitly defined applicable "
            "subset with independent negative examples, may be proposed for promotion."
        ),
        "reproduction_commands_from_project_root": [
            (
                "node scripts/export_runtime_candidate_samples.js "
                "--output artifacts/full_semantic_baseline_v1/runtime_candidates/"
                "packet_0112_p0_all_events_16_16.jsonl "
                "--samples-per-shape-per-replay 9999 --packet-id 274 "
                + " ".join(
                    json.dumps(item["replay_path"])
                    for item in safe_input_provenance
                )
            ),
            (
                "python scripts/emulate_packet_profile_json.py "
                "--image artifacts/new_build_rofl_compatibility_gate_v1/runtime/"
                "league_16.16.805.0442.memory.bin "
                "--events artifacts/full_semantic_baseline_v1/runtime_candidates/"
                "packet_0112_p0_all_events_16_16.jsonl "
                "--profile-json artifacts/full_semantic_baseline_v1/runtime_candidates/"
                "packet_0112_static_profile.json --runtime-profile 16.16.805.0442 "
                "--output artifacts/full_semantic_baseline_v1/runtime_candidates/"
                "packet_0112_p0_native_decoded_16_16.jsonl "
                "--summary artifacts/full_semantic_baseline_v1/runtime_candidates/"
                "packet_0112_p0_native_decode_summary_16_16.json"
            ),
            "python scripts/analyze_packet_0112_p0_semantic_differential.py",
        ],
        "native_decode": native_summary,
        "alignment": alignment,
        "details_assist_surface": assist_distribution,
        "negative_assist_evidence_summary": negative_assist_evidence,
        "storage_inverse_evidence": inverse_evidence,
        "field_value_summaries": field_summaries,
        "scalar_support_and_refutation_matrix": scalar_matrix,
        "fixed_triplet_support_and_refutation_matrix": triplet_matrix,
        "promotion_assessment": {
            "proposed": [
                {
                    "field": "outer +0x18",
                    "storage_view": "storage::unknown_u32_0x18",
                    "semantic_view": "helper_inverse_u32_0x18",
                    "semantic_candidate": "killer_network_id",
                    "evidence_grade": "EXACT_BUILD_PAIRED_CANDIDATE_DIRECT",
                    "helper_rva": "0x00e639c0",
                    "lookup_table_rva": f"0x{LOOKUP_TABLE_18_RVA:08x}",
                    "relation": "helper_inverse_u32_0x18 == 0x400000ad + DETAILS.killerId",
                    "matches": killer_network_matches,
                    "applicable": len(aligned),
                    "distinct_encoded_storage_values": storage_roundtrip_distinct,
                    "distinct_killer_participant_ids": len({
                        row["details"]["killer_id"] for row in aligned
                    }),
                    "per_killer_support": build_per_killer_support(aligned),
                    "boundary": (
                        "Exact build only. DETAILS is an independent oracle. This report "
                        "proposes review; it does not modify or publish a decoder/manifest."
                    ),
                },
                {
                    "field": "outer +0x18 derived",
                    "semantic_candidate": "killer_participant_id",
                    "relation": (
                        "(helper_inverse_u32_0x18 & 0xff) - 0xad == DETAILS.killerId"
                    ),
                    "matches": killer_participant_matches,
                    "applicable": len(aligned),
                    "boundary": "Derived exact-build participant mapping only.",
                },
            ],
            "reaffirmed_outer_route_fact": {
                "field": "packet raw_param",
                "semantic_candidate": "victim_participant_id",
                "relation": "(raw_param & 0xff) - 0xad == DETAILS.victimId",
                "matches": alignment["victim_low_byte_mapping_match_count"],
                "applicable": len(aligned),
                "raw_param_exact_canonical_network_id_matches": alignment[
                    "raw_param_exact_canonical_victim_network_id_count"
                ],
                "raw_param_upper_byte_variant_count": alignment[
                    "raw_param_noncanonical_upper_byte_variant_count"
                ],
                "boundary": "Preserve complete raw_param; upper-byte semantics remain UNKNOWN.",
            },
            "retained_unknown": [
                {
                    "surface": "assistingParticipantIds",
                    "reason": (
                        "No scalar equality/participant transform, count/bitmask/boolean, "
                        "or fixed-triplet participant-set representation reaches the "
                        "declared promotion threshold. Static layout contains no dynamic "
                        "vector header for an assist list."
                    ),
                },
                {
                    "surface": "all fields except outer +0x18 and the already verified raw_param mapping",
                    "reason": (
                        "The exhaustive matrix supplies mismatches or only opaque/constant "
                        "storage evidence; no additional DETAILS victim/killer/assist "
                        "relation reaches the promotion threshold."
                    ),
                },
            ],
        },
        "provenance": {
            "safe_inputs": safe_input_provenance,
            "details_manifest": {
                "path": str(options.manifest.resolve()),
                "sha256": sha256_file(options.manifest),
            },
            "events_manifest": {
                "path": str(options.events_manifest.resolve()),
                "sha256": sha256_file(options.events_manifest),
            },
            "all_route_events_jsonl": {
                "path": str(event_path),
                "sha256": event_sha,
                "event_count": event_manifest["selected_packet_count"],
            },
            "native_decoded_jsonl": {
                "path": str(options.decoded.resolve()),
                "sha256": sha256_file(options.decoded),
            },
            "native_decode_summary": {
                "path": str(options.decode_summary.resolve()),
                "sha256": sha256_file(options.decode_summary),
            },
            "runtime_profile": {
                "path": str(options.profile.resolve()),
                "sha256": profile_sha,
                "profile_id": profile_id,
                "constructor_rva": profile["constructor_rva"],
                "deserialize_rva": profile["deserialize_rva"],
                "object_size": profile["object_size"],
            },
            "runtime_image": {
                "path": str(options.image.resolve()),
                "sha256": image_sha,
            },
        },
        "protected_holdout": {
            "enumerated": False,
            "read": False,
            "hashed": False,
            "decoded": False,
            "tested": False,
            "modified": False,
            "consumed": False,
        },
    }

    aligned_rows = compact_aligned_rows(aligned)
    write_jsonl(options.aligned_output, aligned_rows)
    write_json(options.output, report)
    hash_manifest = {
        "schema_version": 1,
        "exact_build": EXACT_BUILD,
        "packet_id_hex": f"0x{PACKET_ID:04x}",
        "files": [
            {"path": str(Path(__file__).resolve()), "sha256": sha256_file(Path(__file__))},
            {"path": str(options.output.resolve()), "sha256": sha256_file(options.output)},
            {
                "path": str(options.aligned_output.resolve()),
                "sha256": sha256_file(options.aligned_output),
            },
            {"path": str(options.decoded.resolve()), "sha256": sha256_file(options.decoded)},
            {
                "path": str(options.decode_summary.resolve()),
                "sha256": sha256_file(options.decode_summary),
            },
            {
                "path": str(options.events_manifest.resolve()),
                "sha256": sha256_file(options.events_manifest),
            },
            {"path": str(event_path), "sha256": event_sha},
            {
                "path": str(options.manifest.resolve()),
                "sha256": sha256_file(options.manifest),
            },
            {"path": str(options.profile.resolve()), "sha256": profile_sha},
            {"path": str(options.image.resolve()), "sha256": image_sha},
        ],
        "safe_details_files": [
            {
                "game_id": item["game_id"],
                "path": item["details_path"],
                "sha256": item["details_sha256"],
            }
            for item in safe_input_provenance
        ],
        "protected_holdout": {
            "enumerated": False,
            "read": False,
            "hashed": False,
            "decoded": False,
            "tested": False,
            "modified": False,
            "consumed": False,
        },
    }
    write_json(options.hash_output, hash_manifest)
    print(json.dumps({
        "status": report["status"],
        "native_full_consume": native_summary["successful_full_consume_count"],
        "aligned": alignment["matched_count"],
        "killer_network_id_matches": killer_network_matches,
        "killer_participant_id_matches": killer_participant_matches,
        "output": str(options.output.resolve()),
        "output_sha256": sha256_file(options.output),
        "aligned_output": str(options.aligned_output.resolve()),
        "aligned_output_sha256": sha256_file(options.aligned_output),
        "hash_output": str(options.hash_output.resolve()),
        "hash_output_sha256": sha256_file(options.hash_output),
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        raise
