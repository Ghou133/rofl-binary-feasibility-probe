import hashlib
import json
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import duckdb


ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent
sys.path.insert(0, str(ROOT))

import verify_v3  # noqa: E402
from core import ReplayStore  # noqa: E402


def _artifact(path: Path, root: Path) -> dict[str, object]:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "path": str(path.relative_to(root)),
        "sha256": digest,
        "size_bytes": path.stat().st_size,
    }


def _manifest_checks(root: Path, manifest_tables: set[str], parquet_files: set[str]) -> dict[str, dict[str, object]]:
    """Run only the publication-artifact portion of the independent gate."""
    db = root / "research.duckdb"
    status = root / "research_status.json"
    report = root / "FIRST_RESEARCH_SANITY_REPORT.md"
    parquet_dir = root / "parquet"
    parquet_dir.mkdir(parents=True)
    db.write_bytes(b"database")
    status.write_text("{}", encoding="utf-8")
    report.write_text("report", encoding="utf-8")
    for table in parquet_files:
        (parquet_dir / f"{table}.parquet").write_bytes(table.encode("utf-8"))
    manifest = {
        "database": _artifact(db, root),
        "status": _artifact(status, root),
        "report": _artifact(report, root),
        "parquet": {
            table: (_artifact(parquet_dir / f"{table}.parquet", root)
                    if (parquet_dir / f"{table}.parquet").is_file()
                    else {"path": f"parquet/{table}.parquet", "sha256": "", "size_bytes": 0})
            for table in manifest_tables
        },
    }
    manifest_path = root / "publication_manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    checks: dict[str, dict[str, object]] = {}
    verify_v3._verify_manifest(
        checks,
        db_path=db,
        status_path=status,
        report_path=report,
        parquet_dir=parquet_dir,
        manifest_path=manifest_path,
    )
    return checks


def _additive_v4_compatibility_fixture(
    root: Path, *, mutate_table: str | None = None,
) -> tuple[dict[str, object], dict[str, dict[str, object]]]:
    """Build a frozen miniature V3 publication, then append the exact V4 schema."""
    db = root / "research.duckdb"
    status = root / "research_status.json"
    report = root / "FIRST_RESEARCH_SANITY_REPORT.md"
    parquet_dir = root / "parquet"
    parquet_dir.mkdir(parents=True)

    with duckdb.connect(str(db)) as con:
        for table in verify_v3.RESEARCH_EXPORT_TABLES:
            con.execute(f'CREATE TABLE "{table}" (row_id INTEGER, payload VARCHAR)')
            con.executemany(
                f'INSERT INTO "{table}" VALUES (?, ?)',
                [(1, f"{table}-first"), (2, f"{table}-second")],
            )
        con.execute("CREATE TABLE ingest_runs (run_id VARCHAR)")
        con.execute("CREATE TABLE ingest_rejections (rejection_id VARCHAR)")
        for table in verify_v3.RESEARCH_EXPORT_TABLES:
            parquet_path = str(parquet_dir / f"{table}.parquet").replace("'", "''")
            con.execute(
                f'''COPY "{table}" TO '{parquet_path}' (FORMAT PARQUET)'''
            )
        con.execute("CHECKPOINT")

    frozen_database_hash = verify_v3.sha256_file(db)
    status.write_text(
        json.dumps({"database_sha256": frozen_database_hash}), encoding="utf-8"
    )
    report.write_text(f"N=10 SANITY ONLY {frozen_database_hash}\n", encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "database": _artifact(db, root),
        "status": _artifact(status, root),
        "report": _artifact(report, root),
        "parquet": {
            table: _artifact(parquet_dir / f"{table}.parquet", root)
            for table in verify_v3.RESEARCH_EXPORT_TABLES
        },
    }
    manifest_path = root / "publication_manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with duckdb.connect(str(db)) as con:
        con.execute(
            (PROJECT_ROOT / "research-v4" / "schema.sql").read_text(
                encoding="utf-8"
            )
        )
        if mutate_table is not None:
            con.execute(
                f'''UPDATE "{mutate_table}" SET payload='mutated-after-publication'
                    WHERE row_id=1'''
            )
        con.execute("CHECKPOINT")

    checks: dict[str, dict[str, object]] = {}
    verify_v3._verify_manifest(
        checks,
        db_path=db,
        status_path=status,
        report_path=report,
        parquet_dir=parquet_dir,
        manifest_path=manifest_path,
    )
    with duckdb.connect(str(db), read_only=True) as con:
        tables = {row[0] for row in con.execute("SHOW TABLES").fetchall()}
        compatibility = verify_v3._verify_additive_v4_compatibility(
            con,
            tables=tables,
            parquet_dir=parquet_dir,
            publication_checks=checks,
        )
    return compatibility, checks


class VerifyV3Tests(unittest.TestCase):
    def test_complete_additive_v4_schema_with_exact_v3_parquet_surface_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            compatibility, checks = _additive_v4_compatibility_fixture(Path(tmp))

            self.assertFalse(checks["publication_database_sha256"]["pass"])
            self.assertTrue(compatibility["pass"])
            self.assertEqual(
                compatibility["classification"],
                verify_v3.ADDITIVE_V4_CLASSIFICATION,
            )
            self.assertTrue(compatibility["table_surface"]["pass"])
            self.assertTrue(compatibility["parquet_verification"]["pass"])
            self.assertTrue(
                all(row["pass"] for row in compatibility["v4_schema"].values())
            )
            for diagnostic in compatibility["v3_tables"].values():
                self.assertTrue(diagnostic["schema_matches"])
                self.assertEqual(diagnostic["database_minus_parquet"], 0)
                self.assertEqual(diagnostic["parquet_minus_database"], 0)

    def test_additive_v4_container_rejects_precise_v3_row_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            compatibility, _ = _additive_v4_compatibility_fixture(
                Path(tmp), mutate_table="damage_events"
            )

            self.assertFalse(compatibility["pass"])
            self.assertIsNone(compatibility["classification"])
            diagnostic = compatibility["v3_tables"]["damage_events"]
            self.assertTrue(diagnostic["schema_matches"])
            self.assertEqual(diagnostic["database_minus_parquet"], 1)
            self.assertEqual(diagnostic["parquet_minus_database"], 1)
            self.assertFalse(diagnostic["pass"])
            self.assertTrue(
                all(
                    row["pass"]
                    for table, row in compatibility["v3_tables"].items()
                    if table != "damage_events"
                )
            )

    def test_publication_manifest_omission_fails_exact_key_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            expected = set(verify_v3.RESEARCH_EXPORT_TABLES)
            missing = next(iter(expected))
            checks = _manifest_checks(root, expected - {missing}, expected)

            self.assertFalse(checks["publication_parquet_manifest_keys"]["pass"])
            self.assertTrue(checks["publication_parquet_directory_files"]["pass"])
            self.assertFalse(checks[f"publication_parquet_{missing}_entry"]["pass"])
            present = next(iter(expected - {missing}))
            self.assertTrue(checks[f"publication_parquet_{present}_sha256"]["pass"])
            self.assertTrue(checks[f"publication_parquet_{present}_size"]["pass"])

    def test_publication_manifest_and_directory_extra_fail_exact_key_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            expected = set(verify_v3.RESEARCH_EXPORT_TABLES)
            extra = "unexpected_export"
            manifest_extra = _manifest_checks(
                root / "manifest-extra", expected | {extra}, expected
            )
            directory_extra = _manifest_checks(
                root / "directory-extra", expected, expected | {extra}
            )

            self.assertFalse(manifest_extra["publication_parquet_manifest_keys"]["pass"])
            self.assertTrue(manifest_extra["publication_parquet_directory_files"]["pass"])
            self.assertTrue(directory_extra["publication_parquet_manifest_keys"]["pass"])
            self.assertFalse(directory_extra["publication_parquet_directory_files"]["pass"])

    def test_adc_context_join_uses_composite_id_and_validates_checkpoint_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest_dir = Path(tmp) / "artifacts"
            manifest_dir.mkdir()
            (manifest_dir / "replay_manifest.json").write_text(
                json.dumps({"replays": []}), encoding="utf-8"
            )
            db = Path(tmp) / "adc-fixture.duckdb"
            replay_sha = "a" * 64
            context_id = f"{replay_sha}:10000:9"
            with duckdb.connect(str(db)) as con:
                # The context id intentionally differs from adc_deaths.fact_id.
                con.execute("""
                    CREATE TABLE adc_deaths (
                        fact_id VARCHAR, replay_sha256 VARCHAR, death_time_ms BIGINT,
                        combat_start_ms BIGINT, adc_participant_id INTEGER
                    )
                """)
                con.execute("""
                    CREATE TABLE adc_death_position_context (
                        fact_id VARCHAR, adc_death_id VARCHAR, checkpoint VARCHAR,
                        checkpoint_time_ms BIGINT, adc_position_timestamp_ms BIGINT,
                        adc_source_path_timestamp_ms BIGINT, adc_sample_age_ms BIGINT,
                        adc_source_age_ms BIGINT, adc_position_freshness VARCHAR,
                        adc_position_usable BOOLEAN, max_position_age_ms BIGINT
                    )
                """)
                # Minimal companion tables required by verify()'s unconditional
                # materialization-quality queries.
                con.execute("""
                    CREATE TABLE ward_research_events (
                        ward_type VARCHAR, owner_role VARCHAR, owner_participant INTEGER,
                        owner_team INTEGER, spawn_position_status VARCHAR,
                        replay_sha256 VARCHAR, patch VARCHAR, raw_provenance_json JSON
                    )
                """)
                con.execute("""
                    CREATE TABLE hero_positions_1s (
                        position_status VARCHAR, source_age_ms BIGINT,
                        raw_packet_ref JSON, interpolation_method VARCHAR,
                        replay_sha256 VARCHAR, patch VARCHAR, raw_provenance_json JSON
                    )
                """)
                con.execute("""
                    CREATE TABLE damage_events (
                        replay_sha256 VARCHAR, patch VARCHAR, raw_provenance_json JSON
                    )
                """)
                con.execute("INSERT INTO adc_deaths VALUES ('death-fact-1', ?, 10000, 7000, 9)", [replay_sha])
                rows = [
                    ("context-fact-0", context_id, "combat_start", 7000),
                    ("context-fact-1", context_id, "death_minus_3s", 7000),
                    # Wrong time must be observed through the composite join.
                    ("context-fact-2", context_id, "death_minus_1s", 9001),
                    ("context-fact-3", context_id, "death", 10000),
                ]
                con.executemany("""
                    INSERT INTO adc_death_position_context
                    VALUES (?, ?, ?, ?, NULL, NULL, NULL, NULL, 'MISSING', false, 2000)
                """, rows)

            with mock.patch.object(verify_v3, "ROOT", Path(tmp)):
                result = verify_v3.verify(db)

            self.assertTrue(result["checks"]["adc_exactly_four_checkpoints_per_death"]["pass"])
            self.assertFalse(result["checks"]["adc_checkpoint_names_and_times"]["pass"])
            self.assertTrue(result["checks"]["adc_checkpoint_names_unique"]["pass"])

    def test_default_sibling_publication_manifest_rejects_stale_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest_dir = root / "artifacts"
            manifest_dir.mkdir()
            (manifest_dir / "replay_manifest.json").write_text(
                json.dumps({"replays": []}), encoding="utf-8"
            )
            db = root / "research.duckdb"
            ReplayStore(db).init()
            with duckdb.connect(str(db)) as con:
                con.execute("CREATE TABLE probe (value INTEGER)")
                con.execute("INSERT INTO probe VALUES (1)")
                con.execute("CHECKPOINT")
            database_hash = verify_v3.sha256_file(db)
            status = root / "research_status.json"
            status.write_text(json.dumps({"database_sha256": database_hash}), encoding="utf-8")
            report = root / "FIRST_RESEARCH_SANITY_REPORT.md"
            report.write_text(f"N=10 SANITY ONLY {database_hash}\n", encoding="utf-8")
            manifest = {
                "schema_version": 1,
                "database": _artifact(db, root),
                "status": _artifact(status, root),
                "report": _artifact(report, root),
                "parquet": {},
            }
            (root / "publication_manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8"
            )
            with duckdb.connect(str(db)) as con:
                con.execute("INSERT INTO probe VALUES (2)")
                con.execute("CHECKPOINT")

            with mock.patch.object(verify_v3, "ROOT", root):
                result = verify_v3.verify(db)

            self.assertEqual(result["checks"]["publication_database_sha256"]["pass"], False)
            self.assertEqual(result["checks"]["status_database_sha256"]["pass"], False)
            self.assertEqual(result["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
