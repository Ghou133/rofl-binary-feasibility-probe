"""Report all unsafe public-source files before the expensive regression suite.

Uses exactly the release packager's selection and content checks. No exclusions,
redaction exemptions, decoder rules or missing-private-input policies are changed.
"""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import package_handoff as package


def inspect_sources():
    problems = []
    checked = 0
    for path in package.iter_sources():
        relative = package.archive_name(path)
        checked += 1
        try:
            package.scan_text_payload(relative, path.read_bytes())
        except RuntimeError as exc:
            # The packager's error identifies the path and rule, not private bytes.
            problems.append({"path": relative, "error": str(exc)})
    return {"status": "FAIL" if problems else "PASS", "checked_files": checked,
            "problems": problems, "scope": "SOURCE_ONLY"}


def main():
    try:
        result = inspect_sources()
    except (OSError, RuntimeError, ValueError) as exc:
        result = {"status": "FAIL", "error": str(exc), "scope": "SOURCE_ONLY"}
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
