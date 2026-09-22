"""Build and validate the portable source-and-evidence AI handoff archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "dist" / "rofl-analyzer-ai-handoff.zip"
MAX_ARCHIVE_BYTES = 25 * 1024 * 1024
FIXED_TIMESTAMP = (2026, 8, 12, 0, 0, 0)

SOURCE_ROOTS = (
    "src", "scripts", "test", "docs", "handoff-evidence", "research-v3", "research-v4",
)
ROOT_FILES = (
    ".gitignore",
    "AGENTS.md",
    "AI_HANDOFF.md",
    "ARCHITECTURE.md",
    "CLEANUP_REPORT.md",
    "LICENSE",
    "PROJECT_CHARTER.md",
    "PUBLIC_RELEASE_SOURCE_HASHES.json",
    "README.md",
    "ROADMAP.md",
    "SOURCE_FROZEN_DURING_MIGRATION.md",
    "THIRD_PARTY_AND_DATA_NOTICE.md",
    "VALIDATION_STATUS.md",
    "package.json",
    "project_contract.json",
    "requirements.txt",
    "rofl-research.cmd",
    "run_rofl_analyzer.bat",
)

EVIDENCE_FILES = (
    "artifacts/replay_manifest.portable.json",
    "artifacts/protection_v4_publication/adc_protection_summary.json",
    "artifacts/protection_v4_publication/corpus_counts_and_distributions.json",
    "artifacts/protection_v4_publication/idempotence.json",
    "artifacts/protection_v4_publication/profiles.csv",
    "artifacts/protection_v4_publication/profiles.json",
    "artifacts/protection_v4_publication/protection_spell_inventory.csv",
    "artifacts/protection_v4_publication/protection_spell_inventory.json",
    "artifacts/protection_v4_publication/regression_summary.json",
    "artifacts/protection_v4_publication/shield_absorption_samples.json",
    "artifacts/protection_v4_publication/source_scope.json",
    "artifacts/protection_v4_publication/unavailable_fields_and_null_honesty.json",
    "artifacts/protection_v4_publication/validation_scope.json",
    "artifacts/protection_v4_publication/verifier_summary.json",
    "artifacts/protection_v4_probe/protection_v4_field_contract.json",
    "artifacts/protection_v4_probe/on_event_protection_field_contract.json",
    "artifacts/v2_ward_spawn/current_ward_emulation_summary.json",
    "artifacts/v2_ward_spawn/ward_spawn_profile_16_15.json",
)
EVIDENCE_FILE_SET = frozenset({
    *("artifacts/replay_manifest.json"
      if relative == "artifacts/replay_manifest.portable.json" else relative
      for relative in EVIDENCE_FILES),
})

EXCLUDED_PREFIXES = (
    ".git/",
    ".omo/",
    "artifacts/",
    "dist/",
    "replay/",
    "research-v3/output/",
)
EXCLUDED_SUFFIXES = (
    ".bin",
    ".duckdb",
    ".duckdb.wal",
    ".memory.bin",
    ".pyc",
    ".rofl",
    ".zip",
)
EXCLUDED_COMPONENTS = {"__pycache__", ".pytest_cache"}
DELIBERATE_EXCLUSIONS = [
    "replay/ and every .rofl input",
    "research-v3/output/ and every DuckDB/Parquet publication",
    "artifacts/runtime_probe/league_16.15.801.3452.memory.bin",
    "full decoder JSONL, raw packet corpora, stage/extract directories and old archives",
    "Match Details, oracle payloads, Riot IDs, PUUIDs and player-identifying metadata",
    "local .git and .omo review history",
]

TEXT_EXTENSIONS = {
    ".bat", ".cmd", ".csv", ".gitignore", ".js", ".json", ".jsonl",
    ".md", ".ps1", ".py", ".sql", ".txt",
}
FORBIDDEN_PATTERNS = (
    ("absolute Windows user path", re.compile(rb"[A-Za-z]:[/\\]Users[/\\]", re.I)),
    ("workspace username", re.compile(rb"(?<![0-9])" + bytes((50, 54, 53, 54, 48)) + rb"(?![0-9])")),
    ("LCU credential option", re.compile(b"remoting-auth" + b"-token", re.I)),
    ("PUUID payload", re.compile(rb'"puuid"\s*:', re.I)),
    ("Riot ID payload", re.compile(rb'"riot_id_(?:game_name|tag_line)"\s*:', re.I)),
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_name(name: str) -> str:
    pure = PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts or "\\" in name:
        raise RuntimeError(f"unsafe archive name: {name!r}")
    return pure.as_posix()


def is_excluded(relative: str) -> bool:
    relative = relative.replace("\\", "/")
    pure = PurePosixPath(relative)
    return (
        any(relative == prefix.rstrip("/") or relative.startswith(prefix)
            for prefix in EXCLUDED_PREFIXES)
        or any(part in EXCLUDED_COMPONENTS for part in pure.parts)
        or any(relative.lower().endswith(suffix) for suffix in EXCLUDED_SUFFIXES)
    )


def iter_sources() -> Iterable[Path]:
    selected: dict[str, Path] = {}
    for root_file in ROOT_FILES:
        path = ROOT / root_file
        if not path.is_file():
            raise FileNotFoundError(path)
        selected[root_file] = path

    for directory_name in SOURCE_ROOTS:
        directory = ROOT / directory_name
        if not directory.is_dir():
            raise FileNotFoundError(directory)
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(ROOT).as_posix()
            if is_excluded(relative):
                continue
            selected[relative] = path

    for relative in EVIDENCE_FILES:
        path = ROOT / Path(*PurePosixPath(relative).parts)
        if not path.is_file():
            raise FileNotFoundError(path)
        selected[relative] = path

    for relative, path in sorted(selected.items()):
        safe_name(relative)
        yield path


def archive_name(path: Path) -> str:
    relative = path.relative_to(ROOT).as_posix()
    if relative == "artifacts/replay_manifest.portable.json":
        return "artifacts/replay_manifest.json"
    return relative


def scan_text_payload(relative: str, data: bytes) -> None:
    if Path(relative).suffix.lower() not in TEXT_EXTENSIONS and relative != ".gitignore":
        return
    for label, pattern in FORBIDDEN_PATTERNS:
        if pattern.search(data):
            raise RuntimeError(f"forbidden {label} in portable payload: {relative}")


def build_manifest(files: dict[str, dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "package": "rofl-analyzer-ai-handoff",
        "verification_mode": "SOURCE_AND_BOUNDED_EVIDENCE",
        "raw_redecode_performed": False,
        "closed_payload": True,
        "file_count": len(files),
        "manifest_self_exclusion": (
            "package_manifest.json is excluded from files to avoid a recursive self-hash."
        ),
        "deliberately_excluded": DELIBERATE_EXCLUSIONS,
        "files": files,
    }


def write_archive(output: Path) -> dict[str, object]:
    source_rows = []
    files: dict[str, dict[str, object]] = {}
    for path in iter_sources():
        relative = archive_name(path)
        data = path.read_bytes()
        scan_text_payload(relative, data)
        files[relative] = {"size": len(data), "sha256": sha256_bytes(data)}
        source_rows.append((relative, data))

    manifest_bytes = (
        json.dumps(build_manifest(files), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    source_rows.append(("package_manifest.json", manifest_bytes))

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    if temporary.exists():
        temporary.unlink()
    try:
        with zipfile.ZipFile(
            temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9,
        ) as archive:
            for relative, data in sorted(source_rows):
                info = zipfile.ZipInfo(safe_name(relative), FIXED_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = (0o100644 & 0xFFFF) << 16
                info.flag_bits |= 0x800
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        if temporary.stat().st_size > MAX_ARCHIVE_BYTES:
            raise RuntimeError(f"archive exceeds {MAX_ARCHIVE_BYTES} bytes")
        temporary.replace(output)
    finally:
        if temporary.exists():
            temporary.unlink()
    result = validate_archive(output)
    manifest_sidecar = output.with_suffix(".manifest.json")
    sha256_sidecar = output.with_suffix(output.suffix + ".sha256")
    manifest_sidecar.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    sha256_sidecar.write_text(
        f"{result['sha256']}  {output.name}\n",
        encoding="ascii",
    )
    result["manifest_sidecar"] = manifest_sidecar.name
    result["sha256_sidecar"] = sha256_sidecar.name
    return result


def validate_archive(archive_path: Path) -> dict[str, object]:
    if not archive_path.is_file():
        raise FileNotFoundError(archive_path)
    if archive_path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise RuntimeError("archive exceeds portable size limit")
    with zipfile.ZipFile(archive_path, "r") as archive:
        infos = archive.infolist()
        names = [safe_name(info.filename) for info in infos]
        if len(names) != len(set(names)) or any(info.is_dir() for info in infos):
            raise RuntimeError("archive has duplicate names or directory entries")
        if "package_manifest.json" not in names:
            raise RuntimeError("archive has no package_manifest.json")
        manifest = json.loads(archive.read("package_manifest.json").decode("utf-8"))
        if manifest.get("verification_mode") != "SOURCE_AND_BOUNDED_EVIDENCE":
            raise RuntimeError("unexpected verification mode")
        files = manifest.get("files")
        if not isinstance(files, dict) or manifest.get("file_count") != len(files):
            raise RuntimeError("invalid closed manifest")
        expected_names = sorted([*files, "package_manifest.json"])
        if sorted(names) != expected_names:
            raise RuntimeError("archive entries do not match the closed manifest")
        for relative, expected in files.items():
            safe_name(relative)
            if is_excluded(relative) and relative not in EVIDENCE_FILE_SET:
                raise RuntimeError(f"excluded path in archive: {relative}")
            data = archive.read(relative)
            scan_text_payload(relative, data)
            if len(data) != expected.get("size") or sha256_bytes(data) != expected.get("sha256"):
                raise RuntimeError(f"payload hash mismatch: {relative}")

    # Fresh extraction proves the manifest does not rely on unsafe archive names.
    with tempfile.TemporaryDirectory(prefix="rofl-handoff-verify-") as directory:
        root = Path(directory).resolve()
        with zipfile.ZipFile(archive_path, "r") as archive:
            for info in archive.infolist():
                destination = (root / Path(*PurePosixPath(info.filename).parts)).resolve()
                if root not in destination.parents:
                    raise RuntimeError(f"unsafe extraction path: {info.filename}")
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(info.filename))
        extracted = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
        if extracted != expected_names:
            raise RuntimeError("fresh extraction file set mismatch")

    return {
        "schema_version": 1,
        "status": "PASS",
        "archive": archive_path.name,
        "size_bytes": archive_path.stat().st_size,
        "sha256": sha256_file(archive_path),
        "entry_count": len(expected_names),
        "payload_file_count": len(files),
        "verification_mode": manifest["verification_mode"],
        "raw_redecode_performed": False,
        "closed_payload": True,
        "fresh_extract_verified": True,
        "forbidden_content_scan": "PASS",
        "deliberately_excluded": manifest["deliberately_excluded"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--validate", type=Path)
    args = parser.parse_args()
    result = validate_archive(args.validate.resolve()) if args.validate else write_archive(args.output.resolve())
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
