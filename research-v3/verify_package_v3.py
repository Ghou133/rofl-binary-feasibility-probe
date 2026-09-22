"""Verify a fresh V3 review-lite extraction without opening its DuckDB file."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath
from typing import Any


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and ":" not in path.parts[0]


def verify(package_root: str | Path) -> dict[str, Any]:
    root = Path(package_root).resolve()
    checks: dict[str, dict[str, Any]] = {}

    def record(name: str, actual: Any, expected: Any = None,
               condition: bool | None = None) -> None:
        passed = actual == expected if condition is None else bool(condition)
        checks[name] = {"pass": passed, "actual": actual, "expected": expected}

    manifest_path = root / "v3_package_manifest.json"
    record("v3_manifest", str(manifest_path), condition=manifest_path.is_file())
    if not manifest_path.is_file():
        return {"status": "FAIL", "checks": checks, "failures": list(checks)}
    try:
        v3 = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        record("v3_manifest_json", str(error), condition=False)
        return {"status": "FAIL", "checks": checks, "failures": list(checks)}

    added = v3.get("v3_added_files")
    record("v3_added_files_mapping", type(added).__name__, "dict", condition=isinstance(added, dict))
    if isinstance(added, dict):
        record("v3_added_file_count", v3.get("v3_added_file_count"), len(added))
        unsafe = sorted(name for name in added if not safe_relative(name))
        record("v3_added_paths_safe", unsafe, [], condition=not unsafe)
        for relative, expected in sorted(added.items()):
            if not safe_relative(relative):
                continue
            metadata_valid = (
                isinstance(expected, dict)
                and isinstance(expected.get("size"), int)
                and expected["size"] >= 0
                and isinstance(expected.get("sha256"), str)
                and len(expected["sha256"]) == 64
            )
            record(f"v3_added_metadata:{relative}", expected, condition=metadata_valid)
            candidate = root.joinpath(*PurePosixPath(relative).parts)
            inside_root = candidate.resolve().is_relative_to(root)
            record(f"v3_added_inside_root:{relative}", str(candidate), condition=inside_root)
            exists = inside_root and candidate.is_file()
            record(f"v3_added_exists:{relative}", str(candidate), condition=exists)
            if exists and metadata_valid:
                record(f"v3_added_size:{relative}", candidate.stat().st_size, expected.get("size"))
                record(f"v3_added_sha256:{relative}", sha256_file(candidate), expected.get("sha256"))

    wal_files = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.wal") if path.is_file()
    )
    record("no_wal_files", wal_files, [], condition=not wal_files)

    base_manifest_path = root / "package_manifest.json"
    base_files: dict[str, Any] | None = None
    record("v2_base_manifest", str(base_manifest_path), condition=base_manifest_path.is_file())
    if base_manifest_path.is_file():
        try:
            base = json.loads(base_manifest_path.read_text(encoding="utf-8"))
            base_files = base.get("files")
            record("v2_base_files_mapping", type(base_files).__name__, "dict", condition=isinstance(base_files, dict))
            if isinstance(base_files, dict):
                unsafe_base = sorted(name for name in base_files if not safe_relative(name))
                record("v2_base_paths_safe", unsafe_base, [], condition=not unsafe_base)
                overlap = sorted(set(base_files) & set(added or {}))
                record("v2_base_not_overlaid", overlap, [], condition=not overlap)
                for relative, expected in sorted(base_files.items()):
                    if not safe_relative(relative):
                        continue
                    metadata_valid = (
                        isinstance(expected, dict)
                        and isinstance(expected.get("size"), int)
                        and expected["size"] >= 0
                        and isinstance(expected.get("sha256"), str)
                        and len(expected["sha256"]) == 64
                    )
                    record(f"v2_base_metadata:{relative}", expected, condition=metadata_valid)
                    candidate = root.joinpath(*PurePosixPath(relative).parts)
                    inside_root = candidate.resolve().is_relative_to(root)
                    record(f"v2_base_inside_root:{relative}", str(candidate), condition=inside_root)
                    exists = inside_root and candidate.is_file()
                    record(f"v2_base_exists:{relative}", str(candidate), condition=exists)
                    if exists and metadata_valid:
                        record(f"v2_base_size:{relative}", candidate.stat().st_size, expected.get("size"))
                        record(f"v2_base_sha256:{relative}", sha256_file(candidate), expected.get("sha256"))
        except (OSError, json.JSONDecodeError) as error:
            record("v2_base_manifest_json", str(error), condition=False)

    if isinstance(added, dict) and isinstance(base_files, dict):
        declared = set(base_files) | set(added) | {
            "package_manifest.json", "v3_package_manifest.json",
        }
        actual_files = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*") if path.is_file()
        }
        undeclared = sorted(actual_files - declared)
        record("no_undeclared_files", undeclared, [], condition=not undeclared)

    failures = sorted(name for name, value in checks.items() if not value["pass"])
    return {"status": "PASS" if not failures else "FAIL", "checks": checks, "failures": failures}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", default=".")
    parser.add_argument("--output", help="optional JSON evidence output")
    args = parser.parse_args(argv)
    result = verify(args.package_root)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
