#!/usr/bin/env python3
"""Extract exact-build root CharacterRecord stats from installed champion WADs."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import sys
from types import SimpleNamespace
from typing import Any


CANONICAL_BUILD = "16.16.805.0442"
SCHEMA = "ROFL_EXACT_BUILD_CHAMPION_STATS_V1"
BUILD_METADATA_NAMES = ("build-metadata.json", "build_metadata.json", "version.json")


def reject_holdout(path: pathlib.Path) -> pathlib.Path:
    """Reject both lexical and realpath Holdout references before use."""
    raw = pathlib.Path(path)
    if "holdout" in str(raw.absolute()).lower():
        raise ValueError(f"Holdout paths are prohibited: {raw}")
    resolved = raw.resolve(strict=False)
    if "holdout" in str(resolved).lower():
        raise ValueError(f"realpath resolves into prohibited Holdout: {resolved}")
    return resolved


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonicalize_build(value: str) -> str:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", value or "")
    if not match:
        raise ValueError(f"build must have four numeric components: {value!r}")
    major, minor, branch, revision = match.groups()
    if len(revision) > 4:
        raise ValueError(f"build revision exceeds four digits: {value!r}")
    return f"{int(major)}.{int(minor)}.{int(branch)}.{int(revision):04d}"


def _pe_file_version(executable: pathlib.Path) -> str:
    try:
        import pefile
    except ImportError as error:
        raise RuntimeError(
            "no JSON build metadata and pefile is unavailable for executable version metadata"
        ) from error
    pe = pefile.PE(str(executable), fast_load=False)
    try:
        fixed = pe.VS_FIXEDFILEINFO[0]
        parts = (
            fixed.FileVersionMS >> 16,
            fixed.FileVersionMS & 0xFFFF,
            fixed.FileVersionLS >> 16,
            fixed.FileVersionLS & 0xFFFF,
        )
        return ".".join(str(part) for part in parts)
    finally:
        pe.close()


def read_build_metadata(game_root: pathlib.Path) -> dict[str, Any]:
    for name in BUILD_METADATA_NAMES:
        candidate = reject_holdout(game_root / name)
        if not candidate.is_file():
            continue
        raw = candidate.read_bytes()
        document = json.loads(raw.decode("utf-8-sig"))
        observed = next((document.get(key) for key in (
            "file_version", "product_version", "game_version", "version", "build"
        ) if isinstance(document.get(key), str)), None)
        if observed is None:
            raise RuntimeError(f"{candidate} contains no explicit version string")
        return {
            "kind": "JSON_BUILD_METADATA",
            "path": str(candidate),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "observed_form": observed,
        }
    executable = reject_holdout(game_root / "League of Legends.exe")
    if not executable.is_file():
        raise RuntimeError(
            "explicit build metadata is required (build-metadata.json or League of Legends.exe)"
        )
    return {
        "kind": "PE_FIXED_FILE_INFO",
        "path": str(executable),
        "sha256": sha256_file(executable),
        "observed_form": _pe_file_version(executable),
    }


def verify_build(game_root: pathlib.Path, requested_build: str) -> dict[str, Any]:
    requested_canonical = canonicalize_build(requested_build)
    if requested_canonical != CANONICAL_BUILD:
        raise RuntimeError(
            f"unsupported exact build: {requested_build} -> {requested_canonical}; "
            f"required {CANONICAL_BUILD}"
        )
    metadata = read_build_metadata(game_root)
    observed_canonical = canonicalize_build(metadata["observed_form"])
    if observed_canonical != requested_canonical:
        raise RuntimeError(
            "exact build metadata mismatch: "
            f"observed {metadata['observed_form']} -> {observed_canonical}, "
            f"requested {requested_build} -> {requested_canonical}"
        )
    return {
        **metadata,
        "requested_form": requested_build,
        "requested_canonical": requested_canonical,
        "observed_canonical": observed_canonical,
        "reconciliation": (
            f"{metadata['observed_form']} == {observed_canonical}"
            if metadata["observed_form"] != observed_canonical
            else "ALREADY_CANONICAL"
        ),
        "status": "EXACT_BUILD_MATCH",
    }


def load_cdtb(cdtb_pythonpath: pathlib.Path, hashes_dir: pathlib.Path):
    cdtb_pythonpath = reject_holdout(cdtb_pythonpath)
    hashes_dir = reject_holdout(hashes_dir)
    if not cdtb_pythonpath.is_dir():
        raise RuntimeError(f"CDTB Python path is not a directory: {cdtb_pythonpath}")
    if not hashes_dir.is_dir():
        raise RuntimeError(f"CDTB hashes directory is not a directory: {hashes_dir}")
    os.environ["CDTB_HASHES_DIR"] = str(hashes_dir)
    sys.path.insert(0, str(cdtb_pythonpath))
    try:
        from cdtb.binfile import BinFile, compute_binhash
        from cdtb.hashes import HashFile
        from cdtb.wad import Wad
    except ImportError as error:
        raise RuntimeError(f"unable to import CDTB APIs from {cdtb_pythonpath}: {error}") from error
    game_hashes_path = hashes_dir / "hashes.game.txt"
    game_hashes = HashFile(game_hashes_path).load()
    return SimpleNamespace(
        Wad=Wad,
        BinFile=BinFile,
        compute_binhash=compute_binhash,
        game_hashes=game_hashes,
    )


def champion_wad_directory(game_root: pathlib.Path) -> pathlib.Path:
    candidates = (
        game_root / "DATA" / "FINAL" / "Champions",
        game_root / "Data" / "FINAL" / "Champions",
        game_root / "Champions",
    )
    matches = []
    seen = set()
    for candidate in candidates:
        if not candidate.is_dir():
            continue
        resolved = reject_holdout(candidate)
        if not resolved.is_relative_to(game_root.resolve()):
            raise RuntimeError(f"Champions directory escapes game root: {resolved}")
        key = os.path.normcase(str(resolved))
        if key not in seen:
            seen.add(key)
            matches.append(candidate)
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one nonlocalized Champions directory, found {len(matches)}"
        )
    return matches[0]


def enumerate_nonlocalized_wads(game_root: pathlib.Path) -> list[pathlib.Path]:
    directory = champion_wad_directory(game_root)
    rows = [reject_holdout(path) for path in directory.glob("*.wad.client")
            if path.name[:-len(".wad.client")].count(".") == 0]
    if any(path.parent != directory.resolve() for path in rows):
        raise RuntimeError("champion WAD symlink escapes the direct Champions directory")
    rows.sort(key=lambda path: path.name.lower())
    if not rows:
        raise RuntimeError(f"no nonlocalized champion WADs found in {directory}")
    return rows


def hash_sources(hashes_dir: pathlib.Path) -> list[dict[str, Any]]:
    required = (
        "hashes.game.txt", "hashes.binentries.txt", "hashes.bintypes.txt",
        "hashes.binfields.txt", "hashes.binhashes.txt",
    )
    rows = []
    for name in required:
        path = reject_holdout(hashes_dir / name)
        if not path.is_file():
            raise RuntimeError(f"required CDTB hash source is missing: {path}")
        rows.append({"name": name, "path": str(path), "sha256": sha256_file(path)})
    return rows


def _unwrap_modifiable(value: Any) -> tuple[Any, str | None]:
    """Return the exact baseValue carried by a BIN ModifiableFloat, if present."""
    if hasattr(value, "getv"):
        base_value = value.getv("baseValue", None)
        if base_value is not None:
            return base_value, "baseValue"
    if isinstance(value, dict) and value.get("baseValue") is not None:
        return value["baseValue"], "baseValue"
    return value, None


def _field(record, aliases: tuple[str, ...]) -> dict[str, Any]:
    for alias in aliases:
        value = record.getv(alias, None)
        if value is not None:
            normalized, wrapper_field = _unwrap_modifiable(value)
            result = {"value": normalized, "source_field": alias, "missing": False}
            if wrapper_field is not None:
                result["source_wrapper_field"] = wrapper_field
            return result
    return {"value": None, "source_field": None, "missing": True,
            "candidate_fields": list(aliases)}


def _nested_field(record, container_aliases: tuple[str, ...],
                  field_aliases: tuple[str, ...]) -> dict[str, Any]:
    for container_alias in container_aliases:
        container = record.getv(container_alias, None)
        if container is None or not hasattr(container, "getv"):
            continue
        result = _field(container, field_aliases)
        if not result["missing"]:
            result["source_container_field"] = container_alias
            return result
    return {"value": None, "source_field": None, "missing": True,
            "candidate_container_fields": list(container_aliases),
            "candidate_fields": list(field_aliases)}


def _resource(resource, prefix: str) -> tuple[dict[str, Any], list[str]]:
    fields = {
        "type": _field(resource, ("arType", "mType")) if resource else {
            "value": None, "source_field": None, "missing": True,
            "candidate_fields": ["arType", "mType"]},
        "base": _field(resource, ("arBase", "mBase")) if resource else {
            "value": None, "source_field": None, "missing": True,
            "candidate_fields": ["arBase", "mBase"]},
        "per_level": _field(resource, ("arPerLevel", "mPerLevel")) if resource else {
            "value": None, "source_field": None, "missing": True,
            "candidate_fields": ["arPerLevel", "mPerLevel"]},
        "base_regen": _field(resource, ("arBaseStaticRegen", "mBaseStaticRegen"))
        if resource else {"value": None, "source_field": None, "missing": True,
                          "candidate_fields": ["arBaseStaticRegen", "mBaseStaticRegen"]},
        "regen_per_level": _field(resource, ("arRegenPerLevel", "mRegenPerLevel"))
        if resource else {"value": None, "source_field": None, "missing": True,
                          "candidate_fields": ["arRegenPerLevel", "mRegenPerLevel"]},
    }
    missing = [f"{prefix}.{name}" for name, value in fields.items() if value["missing"]]
    return fields, missing


def normalize_character_record(record) -> tuple[dict[str, Any], list[str]]:
    normalized = {
        "health": {
            "base": _field(record, ("baseHPModifiable", "mBaseHP", "baseHP")),
            "per_level": _field(
                record, ("hpPerLevelModifiable", "mHPPerLevel", "hpPerLevel")),
        },
        "health_regen": {
            "base": _field(record, (
                "baseStaticHPRegenModifiable", "mBaseStaticHPRegen", "baseStaticHPRegen")),
            "per_level": _field(record, (
                "hpRegenPerLevelModifiable", "mHPRegenPerLevel", "hpRegenPerLevel")),
        },
        "armor": {
            "base": _field(record, ("baseArmorModifiable", "mBaseArmor", "baseArmor")),
            "per_level": _field(
                record, ("armorPerLevelModifiable", "mArmorPerLevel", "armorPerLevel")),
        },
        "magic_resist": {
            "base": _field(record, ("baseMR", "mBaseSpellBlock", "baseSpellBlock")),
            "per_level": _field(
                record, ("mrPerLevel", "mSpellBlockPerLevel", "spellBlockPerLevel")),
        },
        "attack_damage": {
            "base": _field(record, (
                "baseDamageModifiable", "mBaseDamage", "baseDamage")),
            "per_level": _field(record, (
                "damagePerLevelModifiable", "mDamagePerLevel", "damagePerLevel")),
        },
        "attack_speed": {
            "base_modifier": _field(record, (
                "attackSpeedModifiable", "mAttackSpeedMod", "attackSpeedMod")),
            "ratio": _field(record, (
                "attackSpeedRatioModifiable", "mAttackSpeedRatio", "attackSpeedRatio")),
            "per_level_percent": _field(record, (
                "attackSpeedPerLevelModifiable", "mAttackSpeedPerLevel", "attackSpeedPerLevel")),
            "delay_offset_percent": _field(
                record, ("mAttackDelayOffsetPercent", "attackDelayOffsetPercent")),
            "delay_cast_offset_percent": _nested_field(
                record, ("basicAttack",),
                ("mAttackDelayCastOffsetPercent", "attackDelayCastOffsetPercent")),
        },
        "movement_speed": {
            "base": _field(record, (
                "baseMoveSpeedModifiable", "mMoveSpeed", "moveSpeed")),
        },
    }
    missing = []
    for family, fields in normalized.items():
        missing.extend(f"{family}.{name}" for name, value in fields.items() if value["missing"])
    primary = record.getv("primaryAbilityResource", None)
    secondary = record.getv("secondaryAbilityResource", None)
    primary_fields, primary_missing = _resource(primary, "resources.primary")
    secondary_fields, secondary_missing = _resource(secondary, "resources.secondary")
    normalized["resources"] = {
        "primary": {"present": primary is not None, **primary_fields},
        "secondary": {"present": secondary is not None, **secondary_fields},
    }
    missing.extend(primary_missing)
    missing.extend(secondary_missing)
    return normalized, sorted(missing)


def extract_champion(wad_path: pathlib.Path, cdtb_api) -> dict[str, Any]:
    champion = wad_path.name[:-len(".wad.client")]
    champion_lower = champion.lower()
    root_bin_path = f"data/characters/{champion_lower}/{champion_lower}.bin"
    root_record_path = f"Characters/{champion}/CharacterRecords/Root"
    wad_sha256 = sha256_file(wad_path)
    wad = cdtb_api.Wad(str(wad_path), hashes=cdtb_api.game_hashes)
    members = [member for member in wad.files if
               isinstance(member.path, str) and member.path.lower() == root_bin_path]
    if len(members) != 1:
        raise RuntimeError(
            f"{wad_path.name}: expected exactly one root champion BIN {root_bin_path}, "
            f"found {len(members)}"
        )
    with wad_path.open("rb") as stream:
        root_bin = wad.read_file_data(stream, members[0])
    if root_bin is None:
        raise RuntimeError(f"{wad_path.name}: root champion BIN could not be read")
    root_bin_sha256 = hashlib.sha256(root_bin).hexdigest()
    parsed = cdtb_api.BinFile(io.BytesIO(root_bin))
    expected_path_hash = cdtb_api.compute_binhash(root_record_path)
    records = [entry for entry in parsed.entries if entry.path.h == expected_path_hash]
    if len(records) != 1:
        raise RuntimeError(
            f"{wad_path.name}: expected one root CharacterRecord {root_record_path}, "
            f"found {len(records)}"
        )
    record = records[0]
    expected_type_hash = cdtb_api.compute_binhash("CharacterRecord")
    if record.type.h != expected_type_hash:
        raise RuntimeError(f"{wad_path.name}: root entry is not CharacterRecord")
    normalized, missing = normalize_character_record(record)
    return {
        "champion_wad_name": champion,
        "character_name": record.getv("mCharacterName", champion),
        "wad": {"path": str(wad_path), "sha256": wad_sha256},
        "root_bin": {
            "wad_member_path": root_bin_path,
            "path_hash_hex": f"{members[0].path_hash:016x}",
            "sha256": root_bin_sha256,
            "byte_size": len(root_bin),
        },
        "root_character_record": {
            "entry_path": root_record_path,
            "entry_path_hash_hex": f"{expected_path_hash:08x}",
            "type": "CharacterRecord",
            "type_hash_hex": f"{expected_type_hash:08x}",
            "all_fields": record.to_serializable(),
        },
        "normalized_stats": normalized,
        "missing_fields": missing,
    }


def build_report(game_root: pathlib.Path, hashes_dir: pathlib.Path, requested_build: str,
                 cdtb_api, build_binding: dict[str, Any] | None = None) -> dict[str, Any]:
    build = build_binding or verify_build(game_root, requested_build)
    wads = enumerate_nonlocalized_wads(game_root)
    champions = [extract_champion(path, cdtb_api) for path in wads]
    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "status": "EXACT_BUILD_EXTRACTED",
        "exact_build": CANONICAL_BUILD,
        "build_binding": build,
        "scope": {
            "wad_directory": str(champion_wad_directory(game_root)),
            "enumeration": "NONLOCALIZED_CHAMPIONS_DIRECT_CHILDREN_ONLY",
            "wad_pattern": "*.wad.client WITH NO LOCALE/DOT SUFFIX",
            "parsed_member_per_wad": "data/characters/<champion>/<champion>.bin ONLY",
            "parsed_entry_per_bin": "Characters/<champion>/CharacterRecords/Root ONLY",
        },
        "source_hashes": {
            "build_metadata": {key: build[key] for key in ("path", "sha256", "kind")},
            "cdtb_hash_files": hash_sources(hashes_dir),
            "champion_wads": [champion["wad"] for champion in champions],
        },
        "champion_count": len(champions),
        "champions": champions,
        "missing_field_count": sum(len(champion["missing_fields"]) for champion in champions),
        "protected_holdout": {
            "enumerated": False, "read": False, "hashed": False,
            "decoded": False, "tested": False, "consumed": False,
        },
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--game-root", required=True)
    parser.add_argument("--cdtb-pythonpath", required=True)
    parser.add_argument("--hashes-dir", required=True)
    parser.add_argument("--build", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    game_root = reject_holdout(pathlib.Path(args.game_root))
    cdtb_pythonpath = reject_holdout(pathlib.Path(args.cdtb_pythonpath))
    hashes_dir = reject_holdout(pathlib.Path(args.hashes_dir))
    output = reject_holdout(pathlib.Path(args.output))
    build_binding = verify_build(game_root, args.build)
    api = load_cdtb(cdtb_pythonpath, hashes_dir)
    report = build_report(game_root, hashes_dir, args.build, api, build_binding)
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    output.write_text(serialized, encoding="ascii", newline="\n")
    print(json.dumps({
        "output": str(output),
        "output_sha256": hashlib.sha256(serialized.encode("ascii")).hexdigest(),
        "exact_build": report["exact_build"],
        "champion_count": report["champion_count"],
        "missing_field_count": report["missing_field_count"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        raise
