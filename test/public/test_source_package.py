"""Synthetic packaging tests; no private replay, runtime image or evidence is read."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "package_handoff", Path(__file__).resolve().parents[2] / "scripts" / "package_handoff.py",
)
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)


class SourcePackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rofl-package-unit-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        patch = mock.patch.object(packager, "ROOT", self.root)
        patch.start()
        self.addCleanup(patch.stop)
        for relative in packager.ROOT_FILES:
            self.write(relative, b"synthetic source fixture\n")
        for relative in packager.SOURCE_ROOTS:
            self.write(relative + "/fixture.txt", b"synthetic source fixture\n")
        self.output = self.root / "dist" / "test.zip"

    def write(self, relative, data):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def add_evidence(self):
        # These are unit-test bytes, never claimed to be historical evidence.
        for relative in packager.EVIDENCE_FILES:
            self.write(relative, b"synthetic evidence fixture\n")

    def entries(self):
        with zipfile.ZipFile(self.output) as archive:
            return {name: archive.read(name) for name in archive.namelist()}

    def rewrite(self, entries):
        with zipfile.ZipFile(self.output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in entries.items():
                archive.writestr(name, content)

    def test_source_package_needs_no_local_artifacts(self):
        result = packager.write_archive(self.output)
        self.assertEqual(result["verification_mode"], "SOURCE_ONLY")
        self.assertFalse(result["raw_redecode_performed"])
        self.assertTrue(result["fresh_extract_verified"])
        self.assertFalse((self.root / "artifacts").exists())
        self.assertTrue(self.output.with_suffix(".manifest.json").is_file())
        self.assertTrue(self.output.with_suffix(".zip.sha256").is_file())

    def test_source_mode_never_includes_even_present_allowlisted_evidence(self):
        self.add_evidence()
        packager.write_archive(self.output)
        self.assertFalse(any(name.startswith("artifacts/") for name in self.entries()))

    def test_examples_tests_and_optional_ci_are_included(self):
        self.write("examples/example.js", b"// synthetic example\n")
        self.write("tests/test_example.py", b"# synthetic test\n")
        self.write(".github/workflows/public.yml", b"# synthetic workflow\n")
        packager.write_archive(self.output)
        names = self.entries()
        for name in ("examples/example.js", "tests/test_example.py", ".github/workflows/public.yml"):
            self.assertIn(name, names)

    def test_binary_cache_and_environment_payloads_are_excluded(self):
        for name in ("src/secret.env.bin", "src/.env", "scripts/.env.local", "test/a.rofl",
                     "test/a.parquet", "test/a.dll", "test/__pycache__/a.pyc"):
            self.write(name, b"excluded bytes")
        packager.write_archive(self.output)
        names = self.entries()
        self.assertNotIn("src/.env", names)
        self.assertFalse(any(name.endswith((".bin", ".rofl", ".parquet", ".dll", ".pyc"))
                             for name in names))

    def test_explicit_evidence_mode_fails_before_creating_archive_when_input_is_missing(self):
        with self.assertRaisesRegex(FileNotFoundError, "requires local inputs"):
            packager.write_archive(self.output, with_evidence=True)
        self.assertFalse(self.output.exists())

    def test_explicit_evidence_mode_keeps_distinct_scope_and_historical_alias(self):
        self.add_evidence()
        result = packager.write_archive(self.output, with_evidence=True)
        self.assertEqual(result["verification_mode"], "SOURCE_AND_BOUNDED_EVIDENCE")
        self.assertFalse(result["raw_redecode_performed"])
        names = self.entries()
        self.assertIn("artifacts/replay_manifest.json", names)
        self.assertNotIn("artifacts/replay_manifest.portable.json", names)
        self.assertTrue(packager.EVIDENCE_FILE_SET.issubset(names))

    def test_source_mode_validator_rejects_allowlisted_artifact_injection(self):
        packager.write_archive(self.output)
        entries = self.entries()
        name = "artifacts/replay_manifest.json"
        entries[name] = b"synthetic injection"
        manifest = json.loads(entries["package_manifest.json"])
        manifest["files"][name] = {"size": len(entries[name]), "sha256": packager.sha256_bytes(entries[name])}
        manifest["file_count"] += 1
        entries["package_manifest.json"] = json.dumps(manifest).encode()
        self.rewrite(entries)
        with self.assertRaisesRegex(RuntimeError, "excluded path"):
            packager.validate_archive(self.output)

    def test_missing_evidence_cannot_be_hidden_by_changing_the_mode(self):
        packager.write_archive(self.output)
        entries = self.entries()
        manifest = json.loads(entries["package_manifest.json"])
        manifest["verification_mode"] = "SOURCE_AND_BOUNDED_EVIDENCE"
        entries["package_manifest.json"] = json.dumps(manifest).encode()
        self.rewrite(entries)
        with self.assertRaisesRegex(RuntimeError, "missing required evidence"):
            packager.validate_archive(self.output)

    def test_tampered_bytes_fail_closed_manifest_hash(self):
        packager.write_archive(self.output)
        entries = self.entries()
        entries["README.md"] = b"tampered bytes"
        self.rewrite(entries)
        with self.assertRaisesRegex(RuntimeError, "payload hash mismatch"):
            packager.validate_archive(self.output)

    def test_unsafe_and_ambiguous_names_are_rejected(self):
        for name in ("", ".", "../x", "/x", "a/../x", "a\\x", "a//x", "./x",
                     "C:x", "a/x:stream", "a/x.", "a/x ", "a/\x01x"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                packager.safe_name(name)

    def test_duplicate_zip_entries_are_rejected(self):
        packager.write_archive(self.output)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.output, "a") as archive:
                archive.writestr("README.md", b"duplicate")
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            packager.validate_archive(self.output)

    def test_unpacked_zip_size_is_bounded_before_reading_payloads(self):
        packager.write_archive(self.output)
        with mock.patch.object(packager, "MAX_UNPACKED_BYTES", 1):
            with self.assertRaisesRegex(RuntimeError, "unpacked payload"):
                packager.validate_archive(self.output)

    def test_symlink_source_cannot_publish_outside_bytes(self):
        target = self.write("outside.txt", b"must not be published")
        link = self.root / "src" / "linked.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            packager.write_archive(self.output)

    def test_forbidden_text_still_blocks_a_source_package(self):
        private_path = b"C:" + b"/" + b"Users/" + b"example/private.txt"
        self.write("src/fixture.txt", private_path)
        with self.assertRaisesRegex(RuntimeError, "forbidden"):
            packager.write_archive(self.output)

    def test_failed_build_does_not_replace_previous_valid_archive(self):
        packager.write_archive(self.output)
        previous = self.output.read_bytes()
        self.write("src/fixture.txt", b"changed source")
        with mock.patch.object(packager, "validate_archive", side_effect=RuntimeError("unit rejection")):
            with self.assertRaisesRegex(RuntimeError, "unit rejection"):
                packager.write_archive(self.output)
        self.assertEqual(self.output.read_bytes(), previous)
        self.assertFalse(self.output.with_suffix(".zip.tmp").exists())

    def test_repeated_builds_are_byte_deterministic(self):
        first = packager.write_archive(self.output)["sha256"]
        second = packager.write_archive(self.output)["sha256"]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
