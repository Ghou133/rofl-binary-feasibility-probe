#!/usr/bin/env python3
"""Enumerate exact-build StatFormulaOutputs selector/lane consumers.

This is a static, evidence-only probe.  It accepts only the SHA-pinned mapped
16.16 runtime image, rejects Holdout-like paths, and never assigns a stat name
from numeric resemblance, strings, hashes, RTTI, or reflection proximity alone.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct
import sys
from collections import Counter
from typing import Any

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import (
    X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_DL, X86_REG_EDX,
    X86_REG_R8, X86_REG_R8B, X86_REG_R8D, X86_REG_RDX, X86_REG_RIP,
)


BUILD = "16.16.805.0442"
IMAGE_BASE = 0x140000000
EXPECTED_IMAGE_SHA256 = "0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55"
WRAPPER_RVA = 0x0028B630
ACCESSOR_RVA = 0x0028B670
LOOKUP_RVA = 0x00995C40
STAT_TERMS = (
    "Health", "MaxHealth", "Armor", "SpellBlock", "MagicResist",
    "AttackDamage", "AbilityPower", "AttackSpeed", "MoveSpeed",
    "HealthRegen", "Mana", "ManaRegen", "Crit", "AbilityHaste",
    "FlatArmorPen", "PercentArmorPen", "MagicPen",
)


def hx(value: int | None, width: int = 8) -> str | None:
    return None if value is None else f"0x{value:0{width}x}"


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


def fnv1a32(data: bytes) -> int:
    value = 0x811C9DC5
    for byte in data:
        value = ((value ^ byte) * 0x01000193) & 0xFFFFFFFF
    return value


def fnv1a64(data: bytes) -> int:
    value = 0xCBF29CE484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value


def function_ranges(image: bytes, pe: pefile.PE) -> list[tuple[int, int, int]]:
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    rows = []
    for offset in range(directory.VirtualAddress, directory.VirtualAddress + directory.Size, 12):
        begin, end, unwind = struct.unpack_from("<III", image, offset)
        if begin < end <= len(image):
            rows.append((begin, end, unwind))
    return sorted(rows)


def executable_ranges(image: bytes, pe: pefile.PE) -> list[dict[str, Any]]:
    rows = []
    for section in pe.sections:
        start = section.VirtualAddress
        size = max(section.Misc_VirtualSize, section.SizeOfRawData)
        end = min(start + size, len(image))
        if section.Characteristics & 0x20000000:
            rows.append({
                "name": section.Name.rstrip(b"\0").decode("ascii", "replace"),
                "start_rva": start,
                "end_rva": end,
            })
    return rows


def containing_function(functions: list[tuple[int, int, int]], rva: int):
    matches = [row for row in functions if row[0] <= rva < row[1]]
    return min(matches, key=lambda row: row[1] - row[0]) if matches else None


def function_record(row) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "begin_rva": row[0], "begin_rva_hex": hx(row[0]),
        "end_rva": row[1], "end_rva_hex": hx(row[1]),
        "size": row[1] - row[0], "unwind_rva_hex": hx(row[2]),
    }


def instruction_record(insn) -> dict[str, Any]:
    return {
        "rva": insn.address - IMAGE_BASE,
        "rva_hex": hx(insn.address - IMAGE_BASE),
        "bytes": insn.bytes.hex(), "mnemonic": insn.mnemonic,
        "operands": insn.op_str,
    }


def verify_mana_chain_records(
    records: dict[int, dict[str, Any]],
    format_literal_rva: int,
    token_literal_rva: int,
) -> dict[str, Any]:
    """Fail-closed proof of the selector-11 value/CFG path into its formatter.

    PDATA adjacency is intentionally absent from the acceptance conditions.  The
    fallthrough address comes from the conditional-branch instruction bytes, and
    the value path is checked instruction by instruction.
    """
    expected = {
        0x00B36BB1: ("lea", "r9, [rsp + 0x30]", "lookup_output_pointer"),
        0x00B36BB6: ("xor", "r8d, r8d", "lane_zero"),
        0x00B36BB9: ("mov", "dl, 0xb", "selector_11"),
        0x00B36BBE: ("call", "0x140995c40", "selector_lane_lookup"),
        0x00B36BC3: ("movss", "xmm7, dword ptr [rsp + 0x30]", "lookup_output_load"),
        0x00B36BC9: ("maxss", "xmm7, dword ptr [rdi + 0x15f0]", "clamp_or_floor"),
        0x00B36BD1: ("comiss", "xmm7, xmm6", "positive_path_test"),
        0x00B36BDC: ("jbe", "0x140b36d09", "formatter_skip_branch"),
        0x00B36C22: ("cvtps2pd", "xmm2, xmm7", "float_to_double_argument"),
        0x00B36C32: ("lea", f"rdx, [rip + 0x{format_literal_rva - (0x00B36C32 + 7):x}]", "format_literal_argument"),
        0x00B36C40: ("lea", "rcx, [rbp + 0x180]", "formatted_buffer_argument"),
        0x00B36C58: ("movq", "r8, xmm2", "double_argument_bits"),
        0x00B36C5D: ("call", "0x1411aaaa0", "numeric_formatter_call"),
        0x00B36C62: ("mov", "r8, qword ptr [rbp + 0x180]", "formatted_value_load"),
        0x00B36C69: ("lea", f"rdx, [rip + 0x{token_literal_rva - (0x00B36C69 + 7):x}]", "localization_token_argument"),
        0x00B36C7D: ("call", "0x1411b1ec0", "localized_consumer_call"),
    }
    steps = []
    for rva, (mnemonic, operands, role) in expected.items():
        row = records.get(rva)
        passed = bool(row and row["mnemonic"] == mnemonic and row["operands"] == operands)
        steps.append({
            "role": role, "rva_hex": hx(rva), "expected_mnemonic": mnemonic,
            "expected_operands": operands, "observed": row, "pass": passed,
        })
    branch = records.get(0x00B36BDC)
    branch_fallthrough = None
    if branch:
        branch_fallthrough = 0x00B36BDC + len(bytes.fromhex(branch["bytes"]))
    cfg_checks = {
        "conditional_branch_fallthrough_is_formatter_fragment": branch_fallthrough == 0x00B36BE2,
        "formatter_fragment_is_not_the_skip_branch_target": bool(
            branch and branch["operands"] != f"0x{IMAGE_BASE + 0x00B36BE2:x}"
        ),
        "formatter_fragment_contains_value_conversion": 0x00B36C22 in records,
        "formatter_and_localization_calls_are_reachable_after_fallthrough": (
            branch_fallthrough == 0x00B36BE2
            and 0x00B36C5D in records and 0x00B36C7D in records
        ),
    }
    value_flow_checks = {
        "lookup_r9_points_to_rsp_30": next(step["pass"] for step in steps if step["role"] == "lookup_output_pointer"),
        "lookup_output_loaded_from_rsp_30_into_xmm7": next(step["pass"] for step in steps if step["role"] == "lookup_output_load"),
        "clamp_preserves_xmm7_dependency": next(step["pass"] for step in steps if step["role"] == "clamp_or_floor"),
        "xmm7_converted_to_xmm2_then_r8_formatter_argument": all(
            next(step["pass"] for step in steps if step["role"] == role)
            for role in ("float_to_double_argument", "double_argument_bits")
        ),
        "format_literal_and_numeric_formatter_call_verified": all(
            next(step["pass"] for step in steps if step["role"] == role)
            for role in ("format_literal_argument", "numeric_formatter_call")
        ),
        "formatted_value_flows_with_localization_token_to_consumer": all(
            next(step["pass"] for step in steps if step["role"] == role)
            for role in ("formatted_value_load", "localization_token_argument", "localized_consumer_call")
        ),
    }
    verified = all(step["pass"] for step in steps) and all(cfg_checks.values()) \
        and all(value_flow_checks.values())
    return {
        "status": "VERIFIED_EXPLICIT_CFG_AND_VALUE_FLOW" if verified else "FAILED_CLOSED",
        "verified": verified,
        "cfg_entry": {"branch_rva_hex": "0x00b36bdc", "fallthrough_rva_hex": hx(branch_fallthrough),
                      "skip_target_rva_hex": "0x00b36d09"},
        "cfg_checks": cfg_checks,
        "value_flow_checks": value_flow_checks,
        "instruction_steps": steps,
        "boundary": "PDATA adjacency and literal proximity are not acceptance conditions.",
    }


def direct_call_target(insn) -> int | None:
    if (insn.mnemonic == "call" and insn.operands
            and insn.operands[0].type == X86_OP_IMM):
        return insn.operands[0].imm - IMAGE_BASE
    return None


class StaticImage:
    def __init__(self, image: bytes, pe: pefile.PE):
        self.image = image
        self.pe = pe
        self.functions = function_ranges(image, pe)
        self.executable = executable_ranges(image, pe)
        self.decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        self.decoder.detail = True

    def disassemble_function(self, row):
        return list(self.decoder.disasm(self.image[row[0]:row[1]], IMAGE_BASE + row[0]))

    def direct_callers(self, target: int) -> list[dict[str, Any]]:
        rows = []
        for section in self.executable:
            cursor = section["start_rva"]
            while True:
                source = self.image.find(b"\xe8", cursor, section["end_rva"])
                if source < 0 or source + 5 > section["end_rva"]:
                    break
                cursor = source + 1
                destination = source + 5 + struct.unpack_from("<i", self.image, source + 1)[0]
                if destination != target:
                    continue
                owner = containing_function(self.functions, source)
                if owner is None:
                    continue
                insn = next((candidate for candidate in self.disassemble_function(owner)
                             if candidate.address - IMAGE_BASE == source), None)
                if insn is None or direct_call_target(insn) != target:
                    continue
                rows.append({
                    "call": instruction_record(insn),
                    "owner_function": function_record(owner),
                    "section": section["name"],
                })
        return sorted(rows, key=lambda row: row["call"]["rva"])


def _written_constant(insn, registers: set[int]) -> int | None | str:
    if len(insn.operands) != 2 or insn.operands[0].type != X86_OP_REG:
        return None
    if insn.operands[0].reg not in registers:
        return None
    if insn.mnemonic == "xor" and insn.operands[1].type == X86_OP_REG \
            and insn.operands[1].reg == insn.operands[0].reg:
        return 0
    if insn.mnemonic == "mov" and insn.operands[1].type == X86_OP_IMM:
        return insn.operands[1].imm & 0xFF
    return "DYNAMIC_OR_CLOBBERED"


def recover_call_arguments(insns: list, call_index: int) -> dict[str, Any]:
    """Bounded local backwards slice for the Windows x64 DL/R8B arguments."""
    selector = None
    lane = None
    selector_source = None
    lane_source = None
    lower = max(0, call_index - 32)
    for insn in reversed(insns[lower:call_index]):
        if selector is None:
            value = _written_constant(insn, {X86_REG_DL, X86_REG_EDX, X86_REG_RDX})
            if value is not None:
                selector, selector_source = value, instruction_record(insn)
        if lane is None:
            value = _written_constant(insn, {X86_REG_R8B, X86_REG_R8D, X86_REG_R8})
            if value is not None:
                lane, lane_source = value, instruction_record(insn)
        if selector is not None and lane is not None:
            break
    def status(value):
        return "STATIC_CONSTANT" if isinstance(value, int) else "DYNAMIC_OR_UNRESOLVED"
    return {
        "selector": selector if isinstance(selector, int) else None,
        "selector_status": status(selector), "selector_source": selector_source,
        "lane": lane if isinstance(lane, int) else None,
        "lane_status": status(lane), "lane_source": lane_source,
        "slice_instruction_limit": 32,
    }


def enumerate_consumers(static: StaticImage, target: int) -> list[dict[str, Any]]:
    result = []
    for caller in static.direct_callers(target):
        owner = containing_function(static.functions, caller["call"]["rva"])
        insns = static.disassemble_function(owner)
        index = next(i for i, insn in enumerate(insns)
                     if insn.address - IMAGE_BASE == caller["call"]["rva"])
        before = insns[max(0, index - 16):index]
        after = insns[index + 1:index + 9]
        result.append({
            **caller,
            "arguments": recover_call_arguments(insns, index),
            "context_before": [instruction_record(insn) for insn in before],
            "context_after": [instruction_record(insn) for insn in after],
        })
    return result


def occurrences(image: bytes, needle: bytes) -> list[int]:
    result = []
    cursor = 0
    while True:
        found = image.find(needle, cursor)
        if found < 0:
            return result
        result.append(found)
        cursor = found + 1


def section_for(pe: pefile.PE, rva: int) -> str | None:
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + max(section.Misc_VirtualSize, section.SizeOfRawData)
        if start <= rva < end:
            return section.Name.rstrip(b"\0").decode("ascii", "replace")
    return None


def semantic_xrefs(static: StaticImage, targets: set[int]) -> dict[int, list[dict[str, Any]]]:
    absolute = {IMAGE_BASE + rva: rva for rva in targets}
    result = {rva: [] for rva in targets}
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    decoder.skipdata = True
    for section in static.executable:
        for insn in decoder.disasm(
                static.image[section["start_rva"]:section["end_rva"]],
                IMAGE_BASE + section["start_rva"]):
            if insn.id == 0:
                continue
            for operand in insn.operands:
                destination = None
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    destination = insn.address + insn.size + operand.mem.disp
                elif operand.type == X86_OP_IMM:
                    destination = operand.imm & 0xFFFFFFFFFFFFFFFF
                target = absolute.get(destination)
                if target is not None:
                    result[target].append({
                        **instruction_record(insn), "section": section["name"],
                        "owner_function": function_record(containing_function(
                            static.functions, insn.address - IMAGE_BASE)),
                    })
    return result


def build_term_inventory(static: StaticImage) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    image = static.image
    raw: dict[str, dict[str, Any]] = {}
    all_string_targets: set[int] = set()
    for term in STAT_TERMS:
        ascii_hits = occurrences(image, term.encode("ascii") + b"\0")
        utf16_hits = occurrences(image, term.encode("utf-16le") + b"\0\0")
        all_string_targets.update(ascii_hits)
        all_string_targets.update(utf16_hits)
        hashes = {
            "fnv1a32_exact": fnv1a32(term.encode("ascii")),
            "fnv1a32_lower": fnv1a32(term.lower().encode("ascii")),
            "fnv1a64_exact": fnv1a64(term.encode("ascii")),
            "fnv1a64_lower": fnv1a64(term.lower().encode("ascii")),
        }
        hash_hits = {}
        for name, value in hashes.items():
            width = 4 if "32" in name else 8
            found = occurrences(image, value.to_bytes(width, "little"))
            hash_hits[name] = {
                "value_hex": hx(value, width * 2),
                "occurrences": [{"rva_hex": hx(rva), "section": section_for(static.pe, rva)}
                                for rva in found],
            }
        raw[term] = {
            "term": term,
            "ascii_occurrences": ascii_hits,
            "utf16le_occurrences": utf16_hits,
            "hash_search": hash_hits,
        }
    special_literals = {
        "localization_token": b"@ManaRegen@\0",
        "numeric_format": b"%0.f\0",
    }
    special_hits = {
        name: occurrences(image, literal) for name, literal in special_literals.items()
    }
    all_string_targets.update(
        rva for hits in special_hits.values() for rva in hits
    )
    xrefs = semantic_xrefs(static, all_string_targets)
    rows = []
    for term in STAT_TERMS:
        entry = raw[term]
        for encoding_key in ("ascii_occurrences", "utf16le_occurrences"):
            entry[encoding_key] = [{
                "rva": rva, "rva_hex": hx(rva), "section": section_for(static.pe, rva),
                "executable_xrefs": xrefs.get(rva, []),
                "nearby_rtti_marker": image[max(0, rva - 0x100):rva + 0x100].find(b".?A") >= 0,
                "classification": "STRING_OR_METADATA_CANDIDATE_NOT_SELECTOR_PROOF",
            } for rva in entry[encoding_key]]
        entry["status"] = (
            "VERIFIED_STRING_PRESENCE_ONLY" if entry["ascii_occurrences"] or entry["utf16le_occurrences"]
            else "NOT_FOUND_AS_EXACT_TERMINATED_LITERAL"
        )
        rows.append(entry)
    special = {
        name: {
            "literal": special_literals[name][:-1].decode("ascii"),
            "occurrences": [{
                "rva": rva, "rva_hex": hx(rva), "section": section_for(static.pe, rva),
                "executable_xrefs": xrefs.get(rva, []),
            } for rva in hits],
        }
        for name, hits in special_hits.items()
    }
    return rows, special


def analyze(image_path: pathlib.Path) -> dict[str, Any]:
    image_path = reject_holdout(image_path)
    image = image_path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    if digest != EXPECTED_IMAGE_SHA256:
        raise ValueError(f"exact image SHA mismatch: {digest} != {EXPECTED_IMAGE_SHA256}")
    pe = pefile.PE(data=image, fast_load=False)
    if pe.OPTIONAL_HEADER.ImageBase != IMAGE_BASE:
        raise ValueError(f"unexpected image base: {pe.OPTIONAL_HEADER.ImageBase:#x}")
    static = StaticImage(image, pe)
    wrapper = enumerate_consumers(static, WRAPPER_RVA)
    accessor = enumerate_consumers(static, ACCESSOR_RVA)
    lookup = enumerate_consumers(static, LOOKUP_RVA)
    constant_pairs = Counter(
        (row["arguments"]["selector"], row["arguments"]["lane"])
        for row in lookup
        if row["arguments"]["selector"] is not None and row["arguments"]["lane"] is not None
    )
    mana_rows = [row for row in lookup if row["arguments"]["selector"] == 11
                 and row["arguments"]["lane"] == 0]
    term_inventory, mana_literals = build_term_inventory(static)
    mana_format_hits = mana_literals["numeric_format"]["occurrences"]
    mana_token_hits = mana_literals["localization_token"]["occurrences"]
    mana_slice = list(static.decoder.disasm(
        image[0x00B36B69:0x00B36D2F], IMAGE_BASE + 0x00B36B69,
    ))
    mana_records = {
        insn.address - IMAGE_BASE: instruction_record(insn) for insn in mana_slice
    }
    mana_flow_proof = (
        verify_mana_chain_records(
            mana_records, mana_format_hits[0]["rva"], mana_token_hits[0]["rva"],
        ) if len(mana_rows) == 1 and len(mana_format_hits) == 1 and len(mana_token_hits) == 1
        else {"status": "FAILED_CLOSED", "verified": False,
              "reason": "expected unique selector-11 call and unique literals"}
    )
    mana_chain_verified = mana_flow_proof["verified"]
    literal_rows = [
        occurrence
        for term in term_inventory
        for key in ("ascii_occurrences", "utf16le_occurrences")
        for occurrence in term[key]
    ]
    return {
        "schema": "STAT_SELECTOR_RUNTIME_CONSUMER_TRACE_V1",
        "build": BUILD,
        "image": {"path": str(image_path), "sha256": digest, "size": len(image),
                  "image_base_hex": hx(IMAGE_BASE, 16)},
        "reader": {
            "wrapper_rva_hex": hx(WRAPPER_RVA), "accessor_rva_hex": hx(ACCESSOR_RVA),
            "lookup_rva_hex": hx(LOOKUP_RVA),
            "argument_contract": {"selector": "DL_U8", "lane": "R8B_U8", "output": "R9_FLOAT32_POINTER"},
        },
        "caller_enumeration": {
            "wrapper": wrapper, "storage_accessor": accessor, "selector_lane_lookup": lookup,
            "counts": {"wrapper": len(wrapper), "storage_accessor": len(accessor), "selector_lane_lookup": len(lookup)},
            "constant_selector_lane_pairs": [
                {"selector": pair[0], "lane": pair[1], "call_site_count": count,
                 "status": "CANDIDATE_ARGUMENT_PAIR_UNLESS_SEMANTIC_CONSUMER_PROVES_NAME"}
                for pair, count in sorted(constant_pairs.items())
            ],
        },
        "mana_regen_neighborhood": {
            "status": "VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING" if mana_chain_verified else "UNKNOWN",
            "semantic": "MANA_REGEN" if mana_chain_verified else None,
            "selector": 11 if mana_chain_verified else None, "lane": 0 if mana_chain_verified else None,
            "matching_lookup_calls": mana_rows,
            "literal_chain": mana_literals,
            "control_flow_and_value_flow_proof": mana_flow_proof,
            "boundary": "The name is promoted only when selector/lane, literal xrefs, explicit CFG reachability, and lookup-output-to-formatter/localization value-flow all pass.",
        },
        "stat_string_hash_enum_reflection_search": term_inventory,
        "selector_enum_table_search": {
            "status": "PARTIAL_NO_FULL_ENUM_OR_SELECTOR_TO_STAT_TABLE_RECOVERED",
            "verified_entries": ([{"selector": 11, "lane": 0, "semantic": "MANA_REGEN"}]
                                 if mana_chain_verified else []),
            "candidate_constant_pairs": [
                {"selector": pair[0], "lane": pair[1], "call_site_count": count}
                for pair, count in sorted(constant_pairs.items())
            ],
            "unknown_dynamic_selector_call_count": sum(
                row["arguments"]["selector"] is None for row in lookup
            ),
        },
        "reflection_search_summary": {
            "terminated_literal_occurrence_count": len(literal_rows),
            "literal_occurrences_with_executable_xrefs": sum(
                bool(row["executable_xrefs"]) for row in literal_rows
            ),
            "literal_occurrences_near_rtti_marker": sum(
                row["nearby_rtti_marker"] for row in literal_rows
            ),
            "selector_mapping_promotions_from_reflection_only": 0,
            "status": "CANDIDATE_METADATA_ONLY_NO_SELECTOR_ENUM_EDGE",
        },
        "semantic_classification_policy": {
            "VERIFIED": "direct selector/lane argument plus an unambiguous semantic consumer/formatter chain",
            "CANDIDATE": "static constant or metadata association lacking the full semantic consumer proof",
            "UNKNOWN": "dynamic/unresolved argument or no semantic edge",
            "numeric_resemblance_is_sufficient": False,
        },
        "protected_holdout": {"enumerated": False, "read": False, "hashed": False,
                              "decoded": False, "tested": False, "consumed": False},
        "publication_boundary": "Private exact-build static evidence; no capability or semantic API promotion.",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> None:
    options = parse_args()
    image_path = reject_holdout(pathlib.Path(options.image))
    output_path = reject_holdout(pathlib.Path(options.output))
    result = analyze(image_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="ascii")
    print(json.dumps({
        "output": str(output_path), "output_sha256": sha256_file(output_path),
        "caller_counts": result["caller_enumeration"]["counts"],
        "constant_selector_lane_pairs": result["caller_enumeration"]["constant_selector_lane_pairs"],
        "mana_regen_status": result["mana_regen_neighborhood"]["status"],
    }, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        raise
