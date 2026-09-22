#!/usr/bin/env python3

"""Reproduce exact-build callback/factory/layout evidence for selected 16.16 routes.

This script is intentionally evidence-only.  It reads one exact unpacked runtime
image plus already-exported bounded shape samples/emulation summaries, and writes
one private runtime-candidate artifact.  It does not publish decoder or semantic
API claims.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import importlib.util
import json
import pathlib
import sys
from typing import Any

import pefile


BUILD = "16.16.805.0442"
EXPECTED_IMAGE_SHA256 = (
    "0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55"
)
FACTORY_RVA = 0x00ED97B0
IMAGE_BASE = 0x140000000

ROUTES: dict[int, dict[str, Any]] = {
    0x0112: {
        "name": "PKT_NPC_Hero_Die_s",
        "profile": "packet_0112_static_profile.json",
        "summary": "packet_0112_shape_emulation_summary_16_16.json",
        "decoded": "packet_0112_shape_decoded_16_16.jsonl",
        "expected": (0x00EDDA4F, 0x00E7DA60, 0x01B10810, 0x00EF7800, 0x5C),
        "helper_calls": {
            0x00EF7800: [0x00E632E0, 0x00E639C0, 0x00E54AD0, 0x00E63D40],
            0x00EF39E0: [
                0x00E63600, 0x00E667B0, 0x00E526A0, 0x00E630B0,
                0x00E53DD0, 0x00E65540, 0x00E511F0, 0x00E555F0,
            ],
        },
    },
    0x0123: {
        "name": "PKT_NPC_BuffUpdateCount_s",
        "profile": "packet_0123_static_profile.json",
        "summary": "packet_0123_shape_emulation_summary_16_16.json",
        "decoded": "packet_0123_shape_decoded_16_16.jsonl",
        "expected": (0x00EDDDF7, 0x00E7D240, 0x01B16C48, 0x010A90A0, 0x24),
        "helper_calls": {
            0x010A90A0: [0x0106A760, 0x0106BF10, 0x0106D9E0, 0x0106E950, 0x0106C1A0],
        },
    },
    0x01CF: {
        "name": "PKT_NPC_CastSpellAns_s",
        "profile": "packet_01cf_static_profile.json",
        "summary": "packet_01cf_shape_emulation_summary_16_16.json",
        "decoded": "packet_01cf_shape_decoded_16_16.jsonl",
        "expected": (0x00EE00D7, 0x00E7D5C0, 0x01B17100, 0x010AA640, 0x138),
        "helper_calls": {0x010AA640: [0x0106C930]},
    },
    0x0310: {
        "name": "PKT_S2C_SetItemCharges_s",
        "profile": "packet_0310_static_profile.json",
        "summary": "packet_0310_shape_emulation_summary_16_16.json",
        "decoded": "packet_0310_shape_decoded_16_16.jsonl",
        "expected": (0x00EE40C4, 0x00E9BCD0, 0x01B13D60, 0x0100CC70, 0x14),
        "helper_calls": {0x0100CC70: [0x00F942E0, 0x00F85C00]},
    },
    0x0326: {
        "name": "PKT_NPC_BuffAdd2_s",
        "profile": "packet_0326_static_profile.json",
        "summary": "packet_0326_shape_emulation_summary_16_16.json",
        "decoded": "packet_0326_shape_decoded_16_16.jsonl",
        "expected": (0x00EE4559, 0x00E7C7E0, 0x01B16AB0, 0x010A3C10, 0x68),
        "helper_calls": {
            0x010A3C10: [
                0x0105E8C0, 0x0106A580, 0x0106BF10, 0x0105F0B0,
                0x0105CB60, 0x01063940, 0x010675B0, 0x01061450,
                0x0106A810, 0x0105C700, 0x01061110, 0x0105C010,
                0x011136C0, 0x01119810,
            ],
        },
    },
    0x0405: {
        "name": "PKT_S2C_SetItemGroupData_Broadcast_s",
        "profile": "packet_0405_static_profile.json",
        "summary": "packet_0405_shape_emulation_summary_16_16.json",
        "decoded": "packet_0405_shape_decoded_16_16.jsonl",
        "expected": (0x00EE73B5, 0x00E9BF80, 0x01B13F38, 0x0100DD30, 0x28),
        "helper_calls": {
            0x0100D590: [0x00F82460, 0x00F95FD0, 0x00F95640, 0x00F95690],
        },
    },
    0x041F: {
        "name": "PKT_NPC_BuffUpdateNumCounter_s",
        "profile": "packet_041f_static_profile.json",
        "summary": "packet_041f_shape_emulation_summary_16_16.json",
        "decoded": "packet_041f_shape_decoded_16_16.jsonl",
        "expected": (0x00EE795E, 0x00E7D420, 0x01B16CD0, 0x010A9CB0, 0x1C),
        "helper_calls": {0x010A9CB0: [0x0106D290, 0x01060E40, 0x0106BF10]},
    },
    0x045B: {
        "name": "PKT_NPC_BuffRemove2_s",
        "profile": "packet_045b_static_profile.json",
        "summary": "packet_045b_shape_emulation_summary_16_16.json",
        "decoded": "packet_045b_shape_decoded_16_16.jsonl",
        "expected": (0x00EE839C, 0x00E7CE30, 0x01B16BC0, 0x010A6EF0, 0x1C),
        "helper_calls": {0x010A6EF0: [0x010639D0, 0x01060E40, 0x0106BF10]},
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--samples-manifest", required=True)
    parser.add_argument("--candidate-dir", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def reject_holdout(path: pathlib.Path) -> pathlib.Path:
    resolved = path.resolve()
    if "holdout" in str(resolved).lower():
        raise ValueError(f"Holdout paths are prohibited: {resolved}")
    return resolved


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: pathlib.Path) -> Any:
    with path.open(encoding="utf-8-sig") as stream:
        return json.load(stream)


def parse_integer(value: Any) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


def load_trace_module(script_dir: pathlib.Path):
    trace_path = script_dir / "trace_hero_combat_state_runtime.py"
    specification = importlib.util.spec_from_file_location(
        "hero_combat_state_runtime_trace_reuse", trace_path,
    )
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load reusable runtime tracer: {trace_path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module, trace_path


def compact_callback(module, descriptor: dict, registration: dict) -> dict:
    receive = descriptor.get("callback_receive_target")
    manager = descriptor["callback_manager_table"]
    return {
        "name": descriptor["name"],
        "callback_owner_type": descriptor.get("callback_owner_type"),
        "mangled_callback_type": descriptor["mangled_callback_type"],
        "type_descriptor_rva_hex": descriptor["type_descriptor"]["rva_hex"],
        "type_descriptor_accessor_rva_hex": descriptor[
            "type_descriptor_accessor"
        ]["rva_hex"],
        "callback_manager_table_rva_hex": manager["rva_hex"],
        "callback_manager_entries_rva_hex": manager["entries_rva_hex"],
        "construction_xref": descriptor["construction_xref"],
        "callback_receive_target_rva_hex": receive["rva_hex"] if receive else None,
        "callback_receive_target_function": receive["function"] if receive else None,
        "callback_receive_target_evidence": receive["evidence"] if receive else None,
        "registration": {
            "path_kind": registration["path_kind"],
            "packet_id_hex": registration["packet_id_hex"],
            "packet_id_write": registration["packet_id_write"],
            "construction_function": registration["construction_function"],
            "registration_thunk_function": registration.get(
                "registration_thunk_function"
            ),
            "generic_registration_rva_hex": registration[
                "generic_registration_rva_hex"
            ],
            "generic_registration_call": registration[
                "generic_registration_call"
            ],
        },
    }


def direct_call_evidence(module, static, function_rva: int, targets: list[int]) -> dict:
    owner = static.function_for(function_rva)
    if owner is None or owner[0] != function_rva:
        raise ValueError(f"helper owner is not an exact pdata function: {function_rva:#x}")
    calls: dict[int, list] = collections.defaultdict(list)
    for instruction in static.disassemble_function(owner):
        target = module.direct_call_target(instruction)
        if target is not None:
            calls[target].append(module.instruction_record(instruction))
    evidence = {}
    for target in targets:
        if not module.is_executable(target, static.executable):
            raise ValueError(f"non-executable helper target: {target:#x}")
        if target not in calls:
            raise ValueError(
                f"function {function_rva:#x} does not directly call expected helper {target:#x}"
            )
        evidence[f"0x{target:08x}"] = calls[target]
    return {
        "function": module.function_record(owner),
        "expected_helpers_all_directly_called": True,
        "helper_call_sites": evidence,
    }


def field_storage_size(field: dict) -> int:
    if field["type"] in ("object_vector_records", "object_vector_hex", "byte_vector_hex"):
        return 16
    return {
        "u8": 1,
        "u16": 2,
        "u32": 4,
        "u64": 8,
        "i32": 4,
        "f32": 4,
        "f64": 8,
    }[field["type"]]


def summarize_decoded_samples(path: pathlib.Path) -> dict:
    event_count = 0
    scalar_counts: dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter
    )
    vector_counts: dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter
    )
    vector_vtables: dict[str, set[str]] = collections.defaultdict(set)
    with path.open(encoding="utf-8-sig") as stream:
        for line in stream:
            if not line.strip():
                continue
            row = json.loads(line)
            event_count += 1
            for name, value in row.get("decoded_fields", {}).items():
                if isinstance(value, list):
                    vector_counts[name][len(value)] += 1
                    for record in value:
                        raw = bytes.fromhex(record.get("object_hex", ""))
                        if len(raw) >= 8:
                            vtable_va = int.from_bytes(raw[:8], "little")
                            vector_vtables[name].add(
                                f"0x{vtable_va - IMAGE_BASE:08x}"
                            )
                elif isinstance(value, (int, str, bool)) or value is None:
                    scalar_counts[name][json.dumps(value, sort_keys=True)] += 1
    scalar_profiles = {}
    for name, counts in sorted(scalar_counts.items()):
        scalar_profiles[name] = {
            "unique_count": len(counts),
            "top_values": [
                {"value_json": value, "count": count}
                for value, count in counts.most_common(12)
            ],
        }
    vector_profiles = {}
    for name, counts in sorted(vector_counts.items()):
        vector_profiles[name] = {
            "element_count_distribution": {
                str(count): frequency for count, frequency in sorted(counts.items())
            },
            "observed_element_vtable_rvas": sorted(vector_vtables[name]),
        }
    return {
        "event_count": event_count,
        "scalar_storage_profiles": scalar_profiles,
        "vector_storage_profiles": vector_profiles,
        "boundary": "Values are native post-deserialize encoded/opaque storage samples, not business semantics.",
    }


def main() -> None:
    options = parse_args()
    image_path = reject_holdout(pathlib.Path(options.image))
    sample_manifest_path = reject_holdout(pathlib.Path(options.samples_manifest))
    candidate_dir = reject_holdout(pathlib.Path(options.candidate_dir))
    output_path = reject_holdout(pathlib.Path(options.output))

    image_sha256 = sha256_file(image_path)
    if image_sha256 != EXPECTED_IMAGE_SHA256:
        raise ValueError(
            f"exact image SHA mismatch: {image_sha256} != {EXPECTED_IMAGE_SHA256}"
        )
    image = image_path.read_bytes()
    module, reused_trace_path = load_trace_module(pathlib.Path(__file__).resolve().parent)
    static = module.StaticImage(image, pefile.PE(data=image, fast_load=False))

    instances = module.discover_callback_descriptor_instances(image)
    instances_by_name: dict[str, list[dict]] = collections.defaultdict(list)
    for instance in instances:
        instances_by_name[instance["name"]].append(instance)

    callbacks_by_id: dict[int, list[dict]] = collections.defaultdict(list)
    for packet_id, route in ROUTES.items():
        matching = instances_by_name.get(route["name"], [])
        if not matching:
            raise ValueError(f"callback RTTI not found: {route['name']}")
        for instance in matching:
            descriptor = module.locate_callback_descriptor(
                static,
                route["name"],
                string_start_override=instance["string_start_rva"],
            )
            registration = module.locate_registration(static, descriptor)
            if registration["packet_id"] != packet_id:
                raise ValueError(
                    f"{route['name']} registered {registration['packet_id']:#x}, "
                    f"expected {packet_id:#x}"
                )
            callbacks_by_id[packet_id].append(
                compact_callback(module, descriptor, registration)
            )

    factory = module.locate_factory(static, set(ROUTES), FACTORY_RVA)
    factory_records = {
        packet_id: module.analyze_factory_case(static, factory, packet_id)
        for packet_id in ROUTES
    }
    sample_manifest = load_json(sample_manifest_path)
    if sample_manifest["target_replay_version"] != BUILD:
        raise ValueError("sample manifest build mismatch")

    route_records = []
    all_route_checks = []
    input_files = [image_path, sample_manifest_path, reused_trace_path]
    for packet_id, route in sorted(ROUTES.items()):
        profile_path = reject_holdout(candidate_dir / route["profile"])
        summary_path = reject_holdout(candidate_dir / route["summary"])
        decoded_path = reject_holdout(candidate_dir / route["decoded"])
        input_files.extend((profile_path, summary_path, decoded_path))
        profile_bundle = load_json(profile_path)
        profile = profile_bundle["profile"]
        summary = load_json(summary_path)
        factory_record = factory_records[packet_id]
        case_rva, ctor_rva, vtable_rva, deser_rva, object_size = route["expected"]
        checks = {
            "profile_packet_id_matches": parse_integer(profile["client_opcode"]) == packet_id,
            "profile_constructor_matches": parse_integer(profile["constructor_rva"]) == ctor_rva,
            "profile_deserializer_matches": parse_integer(profile["deserialize_rva"]) == deser_rva,
            "profile_object_size_matches": parse_integer(profile["object_size"]) == object_size,
            "factory_case_matches": factory_record["case"]["rva"] == case_rva,
            "factory_constructor_matches": factory_record["constructor"]["rva"] == ctor_rva,
            "factory_vtable_matches": factory_record["packet_object_vtable"]["rva"] == vtable_rva,
            "factory_deserializer_matches": factory_record["deserializer"]["rva"] == deser_rva,
            "factory_object_size_matches": factory_record["allocation_size"] == object_size,
            "profile_fields_fit_object": all(
                field["offset"] + field_storage_size(field) <= object_size
                for field in profile["fields"]
            ),
            "sample_count_matches_manifest": summary["event_count"]
                == sample_manifest["selected_packet_counts"][str(packet_id)],
            "all_samples_deserialize_success": summary["deserialize_success_count"]
                == summary["event_count"],
            "all_samples_fully_consumed": summary["fully_consumed_count"]
                == summary["event_count"],
            "no_emulation_errors": not summary["emulation_errors"],
        }
        if not all(checks.values()):
            raise ValueError(f"route {packet_id:#x} checks failed: {checks}")
        all_route_checks.append(all(checks.values()))
        helper_evidence = {
            f"0x{function_rva:08x}": direct_call_evidence(
                module, static, function_rva, helper_targets,
            )
            for function_rva, helper_targets in route["helper_calls"].items()
        }
        vtable = factory_record["packet_object_vtable"]
        route_records.append({
            "packet_id": packet_id,
            "packet_id_hex": f"0x{packet_id:04x}",
            "callback_name": route["name"],
            "evidence_class": "VERIFIED_EXACT_BUILD_STATIC_PLUS_BOUNDED_NATIVE_EMULATION",
            "callbacks": callbacks_by_id[packet_id],
            "factory": {
                "factory_function": module.function_record(factory["function"]),
                "switch_rva_hex": f"0x{factory['switch_rva']:08x}",
                "jump_table_rva_hex": f"0x{factory['table_rva']:08x}",
                "case_rva_hex": factory_record["case"]["rva_hex"],
                "allocation_size": factory_record["allocation_size"],
                "constructor_rva_hex": factory_record["constructor"]["rva_hex"],
                "constructor_function": factory_record["constructor"]["function"],
                "packet_object_vtable_rva_hex": vtable["rva_hex"],
                "packet_object_vtable_entries_rva_hex": vtable["entries_rva_hex"],
                "deserializer_rva_hex": factory_record["deserializer"]["rva_hex"],
                "deserializer_function": factory_record["deserializer"]["function"],
                "object_size": vtable["slot_2_returned_object_size"],
            },
            "static_layout_profile": profile_bundle,
            "helper_call_evidence": helper_evidence,
            "observed_inventory": {
                "packet_count": sample_manifest["packet_counts"][str(packet_id)],
                "stream_counts": sample_manifest["stream_counts_by_packet"][str(packet_id)],
                "payload_length_counts": sample_manifest[
                    "payload_counts_by_packet"
                ][str(packet_id)],
                "corpus_replay_count": sample_manifest["replay_count"],
                "parser_error_count": sum(
                    replay["parser_error_count"] for replay in sample_manifest["replays"]
                ),
            },
            "bounded_exact_native_emulation": {
                "method": summary["method"],
                "runtime_profile": summary["runtime_profile"],
                "sample_policy": sample_manifest["sample_policy"],
                "event_count": summary["event_count"],
                "deserialize_success_count": summary["deserialize_success_count"],
                "fully_consumed_count": summary["fully_consumed_count"],
                "successful_full_consume_count": summary[
                    "successful_full_consume_count"
                ],
                "emulation_errors": summary["emulation_errors"],
                "profile_sha256": summary["profile_sha256"],
                "summary_sha256": sha256_file(summary_path),
                "decoded_samples_sha256": sha256_file(decoded_path),
                "storage_sample_profiles": summarize_decoded_samples(decoded_path),
            },
            "checks": checks,
            "semantic_boundary": (
                "RTTI names and native storage shapes are reported verbatim. "
                "Opaque fields are not promoted to inventory/item/buff/spell business semantics."
            ),
        })

    result = {
        "schema_version": 1,
        "analysis": "buff_spell_item_runtime_candidates_exact_16_16",
        "build": BUILD,
        "image": {
            "path": str(image_path),
            "sha256": image_sha256,
            "size": len(image),
        },
        "reused_static_analysis_code": {
            "path": str(reused_trace_path),
            "sha256": sha256_file(reused_trace_path),
        },
        "factory": {
            "function": module.function_record(factory["function"]),
            "switch_rva_hex": f"0x{factory['switch_rva']:08x}",
            "jump_table_rva_hex": f"0x{factory['table_rva']:08x}",
            "maximum_direct_index": factory["maximum_id"],
        },
        "routes": route_records,
        "checks": {
            "route_count": len(route_records),
            "all_route_checks_pass": all(all_route_checks),
            "all_requested_callback_names_found": len(route_records) == len(ROUTES),
            "duplicate_callback_owners_preserved": len(callbacks_by_id[0x01CF]) == 2,
        },
        "input_sha256": {
            str(path): sha256_file(path) for path in dict.fromkeys(input_files)
        },
        "holdout_boundary": {
            "path_guard": "reject any explicit input/output path containing case-insensitive 'holdout'",
            "statement": (
                "No Holdout content was read, enumerated, hashed, decoded, tested, "
                "modified, or consumed by this analysis."
            ),
        },
        "publication_boundary": (
            "Private runtime candidate only; no semantic API, capability manifest, "
            "decoder registry, or documentation promotion."
        ),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, ensure_ascii=True, indent=2)
        stream.write("\n")
    print(json.dumps({
        "output": str(output_path),
        "route_count": len(route_records),
        "all_route_checks_pass": result["checks"]["all_route_checks_pass"],
        "output_sha256": sha256_file(output_path),
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        raise
