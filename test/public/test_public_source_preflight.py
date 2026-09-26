import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("public_source_preflight", ROOT / "scripts/check_public_sources.py")
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


class PublicSourcePreflightTests(unittest.TestCase):
    def test_reports_every_bad_file_without_disclosing_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / name for name in ("one.js", "two.js", "good.js")]
            # Deliberately synthetic input to the privacy scanner, not a local
            # path used to find real data. No literal private path is published.
            bad = "const sample = '" + "Z:" + "/Users/" + "synthetic-user/private';"
            paths[0].write_text(bad)
            paths[1].write_text(bad)
            paths[2].write_text("'use strict';\n")
            with patch.object(preflight.package, "ROOT", root), \
                    patch.object(preflight.package, "iter_sources", return_value=iter(paths)):
                result = preflight.inspect_sources()
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(result["checked_files"], 3)
            self.assertEqual([p["path"] for p in result["problems"]], ["one.js", "two.js"])
            self.assertNotIn("synthetic-user", str(result))

    def test_valid_source_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "clean.js"
            path.write_text("const root = process.env.ROFL_KR_821_REPLAY_DIR;\n")
            with patch.object(preflight.package, "ROOT", root), \
                    patch.object(preflight.package, "iter_sources", return_value=iter([path])):
                self.assertEqual(preflight.inspect_sources()["status"], "PASS")

    def test_source_selection_failure_remains_fatal(self):
        with patch.object(preflight.package, "iter_sources", side_effect=FileNotFoundError("required source")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(preflight.main(), 1)


if __name__ == "__main__":
    unittest.main()
