"""Independent local gate for a hash-bound V3 research publication."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import duckdb


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "research-v3" / "output" / "replay_research.duckdb"
PUBLICATION_STATUS_NAME = "research_status.json"
PUBLICATION_REPORT_NAME = "FIRST_RESEARCH_SANITY_REPORT.md"
PUBLICATION_PARQUET_NAME = "parquet"
PUBLICATION_MANIFEST_NAME = "publication_manifest.json"

# Keep the publication gate bound to the complete research export surface.
# This mirrors research_layer.RESEARCH_EXPORT_TABLES without importing the
# materialization layer into this independent verifier.
RESEARCH_EXPORT_TABLES = (
    "replays", "participants", "death_events", "damage_events", "spell_events",
    "buff_events", "ward_spawns", "ward_lifecycles", "hero_paths",
    "hero_positions_1s", "adc_deaths", "adc_death_damage",
    "adc_death_support_actions", "ward_research_events",
    "ward_position_context", "map_regions", "ward_heatmap_cells",
    "ward_hotspots", "adc_death_position_context", "adc_death_features",
    "ward_death_context",
)

V3_CONTAINER_TABLES = frozenset((*RESEARCH_EXPORT_TABLES, "ingest_runs", "ingest_rejections"))
ADDITIVE_V4_CLASSIFICATION = "EXPECTED_ADDITIVE_V4_CONTAINER_CHANGE"
EXPECTED_CONTAINER_DIVERGENCE_CHECKS = frozenset({
    "publication_database_sha256",
    "publication_database_size",
    "status_database_sha256",
    "report_database_sha256",
})

# The accepted additive schema is intentionally embedded in this independent
# V3 verifier.  Reading a mutable V4 schema file at verification time would let
# an unrelated schema change redefine what the frozen V3 gate accepts.
_STATE_EVENT_SCHEMA = (
    ("fact_id", "VARCHAR"),
    ("replay_sha256", "VARCHAR"),
    ("game_id", "VARCHAR"),
    ("replay_time_ms", "BIGINT"),
    ("event_id", "INTEGER"),
    ("source_network_id", "BIGINT"),
    ("target_network_id", "BIGINT"),
    ("observed_amount", "DOUBLE"),
    ("health_before", "DOUBLE"),
    ("health_after", "DOUBLE"),
    ("temporary_hp_before", "DOUBLE"),
    ("temporary_hp_after", "DOUBLE"),
    ("raw_amount", "DOUBLE"),
    ("effective_amount", "DOUBLE"),
    ("overheal_amount", "DOUBLE"),
    ("chunk_index", "BIGINT"),
    ("chunk_id", "BIGINT"),
    ("chunk_stream", "VARCHAR"),
    ("chunk_file_offset", "BIGINT"),
    ("compressed_body_offset", "BIGINT"),
    ("decompressed_block_offset", "BIGINT"),
    ("decompressed_payload_offset", "BIGINT"),
    ("global_occurrence_index", "BIGINT"),
    ("raw_occurrence_index", "BIGINT"),
    ("packet_occurrence_index", "BIGINT"),
    ("raw_param", "BIGINT"),
    ("raw_param_hex", "VARCHAR"),
    ("raw_payload_length", "BIGINT"),
    ("raw_payload_sha256", "VARCHAR"),
    ("raw_payload_hex", "VARCHAR"),
    ("params_length", "BIGINT"),
    ("params_sha256", "VARCHAR"),
    ("params_hex", "VARCHAR"),
    ("raw_provenance_json", "JSON"),
)

V4_TABLE_SCHEMAS: Mapping[str, tuple[tuple[str, str], ...]] = {
    "protection_v4_profiles": (
        ("replay_sha256", "VARCHAR"),
        ("game_id", "VARCHAR"),
        ("patch", "VARCHAR"),
        ("profile_status", "VARCHAR"),
        ("decoder_profile", "VARCHAR"),
        ("decoded_row_count", "BIGINT"),
        ("protection_row_count", "BIGINT"),
        ("details_json", "JSON"),
        ("created_at", "TIMESTAMP"),
        ("v4_schema_version", "INTEGER"),
        ("on_event_decoder_status", "VARCHAR"),
        ("shield_damage_decoder_status", "VARCHAR"),
        ("decoder_profiles_json", "JSON"),
    ),
    "health_state_events": _STATE_EVENT_SCHEMA,
    "shield_state_events": _STATE_EVENT_SCHEMA,
    "heal_events": _STATE_EVENT_SCHEMA,
    "temporary_hp_events": _STATE_EVENT_SCHEMA,
    "protection_events": (
        ("fact_id", "VARCHAR"),
        ("replay_sha256", "VARCHAR"),
        ("game_id", "VARCHAR"),
        ("replay_time_ms", "BIGINT"),
        ("protection_kind", "VARCHAR"),
        ("source_network_id", "BIGINT"),
        ("target_network_id", "BIGINT"),
        ("observed_amount", "DOUBLE"),
        ("raw_amount", "DOUBLE"),
        ("effective_amount", "DOUBLE"),
        ("overheal_amount", "DOUBLE"),
        ("canonical", "BOOLEAN"),
        ("heal_group_size", "BIGINT"),
        ("canonical_first_raw_occurrence", "BIGINT"),
        ("paired_source_route_fact_id", "VARCHAR"),
        ("chunk_index", "BIGINT"),
        ("chunk_id", "BIGINT"),
        ("chunk_stream", "VARCHAR"),
        ("chunk_file_offset", "BIGINT"),
        ("compressed_body_offset", "BIGINT"),
        ("decompressed_block_offset", "BIGINT"),
        ("decompressed_payload_offset", "BIGINT"),
        ("global_occurrence_index", "BIGINT"),
        ("raw_occurrence_index", "BIGINT"),
        ("packet_occurrence_index", "BIGINT"),
        ("raw_param", "BIGINT"),
        ("raw_param_hex", "VARCHAR"),
        ("raw_payload_length", "BIGINT"),
        ("raw_payload_sha256", "VARCHAR"),
        ("raw_payload_hex", "VARCHAR"),
        ("params_length", "BIGINT"),
        ("params_sha256", "VARCHAR"),
        ("params_hex", "VARCHAR"),
        ("raw_provenance_json", "JSON"),
    ),
    "protection_state_transitions": (
        ("fact_id", "VARCHAR"),
        ("replay_sha256", "VARCHAR"),
        ("game_id", "VARCHAR"),
        ("replay_time_ms", "BIGINT"),
        ("transition_kind", "VARCHAR"),
        ("source_network_id", "BIGINT"),
        ("target_network_id", "BIGINT"),
        ("observed_amount", "DOUBLE"),
        ("remaining_amount", "DOUBLE"),
        ("absorbed_amount", "DOUBLE"),
        ("unused_amount", "DOUBLE"),
        ("raw_provenance_json", "JSON"),
    ),
    "protection_spell_inventory": (
        ("fact_id", "VARCHAR"),
        ("replay_sha256", "VARCHAR"),
        ("game_id", "VARCHAR"),
        ("source_network_id", "BIGINT"),
        ("source_participant_id", "INTEGER"),
        ("champion", "VARCHAR"),
        ("spell_identifier", "VARCHAR"),
        ("spell_slot", "VARCHAR"),
        ("protection_cast_kind", "VARCHAR"),
        ("replay_time_ms", "BIGINT"),
        ("raw_provenance_json", "JSON"),
        ("cast_count", "BIGINT"),
        ("target_count", "BIGINT"),
        ("buff_candidate_count", "BIGINT"),
        ("damage_window_count", "BIGINT"),
        ("first_cast_ms", "BIGINT"),
        ("last_cast_ms", "BIGINT"),
    ),
    "adc_death_protection": (
        ("fact_id", "VARCHAR"),
        ("replay_sha256", "VARCHAR"),
        ("game_id", "VARCHAR"),
        ("adc_death_id", "VARCHAR"),
        ("replay_time_ms", "BIGINT"),
        ("protection_kind", "VARCHAR"),
        ("source_network_id", "BIGINT"),
        ("source_participant_id", "INTEGER"),
        ("target_network_id", "BIGINT"),
        ("observed_amount", "DOUBLE"),
        ("direct_heal_lower", "DOUBLE"),
        ("direct_heal_upper", "DOUBLE"),
        ("raw_amount", "DOUBLE"),
        ("effective_amount", "DOUBLE"),
        ("overheal_amount", "DOUBLE"),
        ("source_is_external_ally", "BOOLEAN"),
        ("raw_provenance_json", "JSON"),
    ),
    "adc_survival_features_v4": (
        ("fact_id", "VARCHAR"),
        ("replay_sha256", "VARCHAR"),
        ("game_id", "VARCHAR"),
        ("adc_death_id", "VARCHAR"),
        ("combat_start_ms", "BIGINT"),
        ("death_time_ms", "BIGINT"),
        ("external_ally_shield_generated", "DOUBLE"),
        ("external_ally_direct_heal_lower", "DOUBLE"),
        ("external_ally_direct_heal_upper", "DOUBLE"),
        ("direct_heal_exact", "BOOLEAN"),
        ("incoming_damage_event_count", "BIGINT"),
        ("incoming_damage_amount", "DOUBLE"),
        ("incoming_damage_type_json", "JSON"),
        ("incoming_basic_attack_count", "BIGINT"),
        ("incoming_spell_damage_count", "BIGINT"),
        ("shield_remaining", "DOUBLE"),
        ("shield_absorbed", "DOUBLE"),
        ("shield_unused", "DOUBLE"),
        ("health_before", "DOUBLE"),
        ("health_after", "DOUBLE"),
        ("temporary_hp_before", "DOUBLE"),
        ("temporary_hp_after", "DOUBLE"),
        ("raw_provenance_json", "JSON"),
    ),
}
V4_CONTAINER_TABLES = frozenset(V4_TABLE_SCHEMAS)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _publication_paths(db_path: Path) -> dict[str, Path]:
    root = db_path.parent
    return {
        "status": root / PUBLICATION_STATUS_NAME,
        "report": root / PUBLICATION_REPORT_NAME,
        "parquet": root / PUBLICATION_PARQUET_NAME,
        "manifest": root / PUBLICATION_MANIFEST_NAME,
    }


def _manifest_artifact_path(root: Path, entry: Mapping[str, Any]) -> Path | None:
    value = entry.get("path")
    if not isinstance(value, str) or not value:
        return None
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def _verify_manifest(
    checks: dict[str, dict[str, Any]], *, db_path: Path, status_path: Path,
    report_path: Path, parquet_dir: Path, manifest_path: Path,
    database_sha256: str | None = None, database_size: int | None = None,
) -> dict[str, Any] | None:
    def record(name: str, actual: Any, expected: Any = None,
               condition: bool | None = None) -> None:
        passed = (actual == expected) if condition is None else bool(condition)
        checks[name] = {"pass": passed, "actual": actual, "expected": expected}

    record("publication_manifest_file", str(manifest_path), condition=manifest_path.is_file())
    if not manifest_path.is_file():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        record("publication_manifest_json", str(exc), "valid JSON", condition=False)
        return None
    record("publication_manifest_json", "valid JSON", "valid JSON")
    root = db_path.parent.resolve()
    database = manifest.get("database") if isinstance(manifest, dict) else None
    record("publication_manifest_database_entry", database, condition=isinstance(database, dict))
    if isinstance(database, dict):
        recorded_db = _manifest_artifact_path(root, database)
        record("publication_database_path", str(recorded_db) if recorded_db else None,
               str(db_path), condition=recorded_db == db_path)
        actual_db_hash = (database_sha256 if database_sha256 is not None
                          else sha256_file(db_path) if db_path.is_file() else None)
        record("publication_database_sha256", actual_db_hash, database.get("sha256"))
        actual_db_size = (database_size if database_size is not None
                          else db_path.stat().st_size if db_path.is_file() else None)
        record("publication_database_size", actual_db_size,
               database.get("size_bytes"))

    for name, selected in (("status", status_path), ("report", report_path)):
        entry = manifest.get(name) if isinstance(manifest, dict) else None
        record(f"publication_{name}_entry", entry, condition=isinstance(entry, dict))
        if not isinstance(entry, dict):
            continue
        recorded = _manifest_artifact_path(root, entry)
        record(f"publication_{name}_path", str(recorded) if recorded else None,
               str(selected), condition=recorded == selected)
        record(f"publication_{name}_sha256", sha256_file(selected) if selected.is_file() else None,
               entry.get("sha256"))
        record(f"publication_{name}_size", selected.stat().st_size if selected.is_file() else None,
               entry.get("size_bytes"))

    parquet = manifest.get("parquet") if isinstance(manifest, dict) else None
    record("publication_parquet_entries", parquet, condition=isinstance(parquet, dict) and bool(parquet))
    expected_tables = set(RESEARCH_EXPORT_TABLES)
    manifest_tables = set(parquet) if isinstance(parquet, dict) else set()
    record("publication_parquet_manifest_keys", sorted(manifest_tables),
           sorted(expected_tables), condition=manifest_tables == expected_tables)
    actual_tables = {
        path.stem for path in parquet_dir.glob("*.parquet") if path.is_file()
    }
    record("publication_parquet_directory_files", sorted(actual_tables),
           sorted(expected_tables), condition=actual_tables == expected_tables)

    # Iterate over the expected surface so an omitted manifest entry cannot
    # evade its per-artifact path, hash, and size checks.
    for table in sorted(expected_tables):
        entry = parquet.get(table) if isinstance(parquet, dict) else None
        name = f"publication_parquet_{table}"
        path = _manifest_artifact_path(root, entry) if isinstance(entry, dict) else None
        expected_path = parquet_dir / f"{table}.parquet"
        record(f"{name}_entry", entry, condition=isinstance(entry, dict))
        record(f"{name}_path", str(path) if path else None,
               str(expected_path), condition=path == expected_path)
        record(f"{name}_sha256", sha256_file(path) if path and path.is_file() else None,
               entry.get("sha256") if isinstance(entry, dict) else None)
        record(f"{name}_size", path.stat().st_size if path and path.is_file() else None,
               entry.get("size_bytes") if isinstance(entry, dict) else None)
    return manifest if isinstance(manifest, dict) else None


def _relation_schema(
    connection: duckdb.DuckDBPyConnection, table: str,
) -> tuple[tuple[str, str], ...]:
    escaped = table.replace("'", "''")
    return tuple(
        (str(row[1]), str(row[2]))
        for row in connection.execute(f"PRAGMA table_info('{escaped}')").fetchall()
    )


def _parquet_schema(
    connection: duckdb.DuckDBPyConnection, path: Path,
) -> tuple[tuple[str, str], ...]:
    return tuple(
        (str(row[0]), str(row[1]))
        for row in connection.execute(
            "DESCRIBE SELECT * FROM read_parquet(?)", [str(path)]
        ).fetchall()
    )


def _schema_json(schema: tuple[tuple[str, str], ...]) -> list[dict[str, Any]]:
    return [
        {"ordinal": ordinal, "name": name, "type": column_type}
        for ordinal, (name, column_type) in enumerate(schema)
    ]


def _schema_differences(
    actual: tuple[tuple[str, str], ...],
    expected: tuple[tuple[str, str], ...],
) -> list[dict[str, Any]]:
    differences: list[dict[str, Any]] = []
    for ordinal in range(max(len(actual), len(expected))):
        actual_column = actual[ordinal] if ordinal < len(actual) else None
        expected_column = expected[ordinal] if ordinal < len(expected) else None
        if actual_column != expected_column:
            differences.append({
                "ordinal": ordinal,
                "actual": ({"name": actual_column[0], "type": actual_column[1]}
                           if actual_column else None),
                "expected": ({"name": expected_column[0], "type": expected_column[1]}
                             if expected_column else None),
            })
    return differences


def _parquet_publication_failures(
    publication_checks: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    required = {
        "publication_manifest_file",
        "publication_manifest_json",
        "publication_parquet_entries",
        "publication_parquet_manifest_keys",
        "publication_parquet_directory_files",
    }
    for table in RESEARCH_EXPORT_TABLES:
        prefix = f"publication_parquet_{table}"
        required.update({
            f"{prefix}_entry", f"{prefix}_path",
            f"{prefix}_sha256", f"{prefix}_size",
        })
    return sorted(
        name for name in required
        if publication_checks.get(name, {}).get("pass") is not True
    )


def _verify_additive_v4_compatibility(
    connection: duckdb.DuckDBPyConnection,
    *,
    tables: set[str] | frozenset[str],
    parquet_dir: str | Path,
    publication_checks: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Prove that a changed container is exactly frozen V3 plus recognized V4.

    This focused helper deliberately does not inspect status/report hash text or
    the fixed V3 semantic checks.  ``verify`` combines this database proof with
    those external gates before accepting a changed publication container.
    """
    parquet_dir = Path(parquet_dir).resolve()
    actual_tables = set(tables)
    expected_tables = set(V3_CONTAINER_TABLES | V4_CONTAINER_TABLES)
    missing_tables = sorted(expected_tables - actual_tables)
    unexpected_tables = sorted(actual_tables - expected_tables)
    table_surface = {
        "pass": not missing_tables and not unexpected_tables,
        "actual": sorted(actual_tables),
        "expected": sorted(expected_tables),
        "missing": missing_tables,
        "unexpected": unexpected_tables,
    }

    v4_schema: dict[str, dict[str, Any]] = {}
    for table, expected_schema in sorted(V4_TABLE_SCHEMAS.items()):
        actual_schema = _relation_schema(connection, table) if table in actual_tables else ()
        matches = actual_schema == expected_schema
        v4_schema[table] = {
            "pass": matches,
            "schema_matches": matches,
            "actual_schema": _schema_json(actual_schema),
            "expected_schema": _schema_json(expected_schema),
            "schema_differences": _schema_differences(actual_schema, expected_schema),
        }

    parquet_failures = _parquet_publication_failures(publication_checks)
    parquet_verification = {
        "pass": not parquet_failures,
        "failed_or_missing_checks": parquet_failures,
    }

    v3_tables: dict[str, dict[str, Any]] = {}
    for table in sorted(RESEARCH_EXPORT_TABLES):
        parquet_path = parquet_dir / f"{table}.parquet"
        diagnostic: dict[str, Any] = {
            "pass": False,
            "schema_matches": False,
            "database_schema": [],
            "parquet_schema": [],
            "schema_differences": [],
            "database_minus_parquet": None,
            "parquet_minus_database": None,
        }
        try:
            database_schema = (_relation_schema(connection, table)
                               if table in actual_tables else ())
            parquet_schema = _parquet_schema(connection, parquet_path)
            schema_matches = database_schema == parquet_schema and table in actual_tables
            diagnostic.update({
                "schema_matches": schema_matches,
                "database_schema": _schema_json(database_schema),
                "parquet_schema": _schema_json(parquet_schema),
                "schema_differences": _schema_differences(
                    database_schema, parquet_schema
                ),
            })
            if schema_matches:
                quoted_table = '"' + table.replace('"', '""') + '"'
                database_minus_parquet = int(connection.execute(
                    f"""SELECT count(*) FROM (
                        SELECT * FROM {quoted_table}
                        EXCEPT ALL
                        SELECT * FROM read_parquet(?)
                    ) AS database_only""",
                    [str(parquet_path)],
                ).fetchone()[0])
                parquet_minus_database = int(connection.execute(
                    f"""SELECT count(*) FROM (
                        SELECT * FROM read_parquet(?)
                        EXCEPT ALL
                        SELECT * FROM {quoted_table}
                    ) AS parquet_only""",
                    [str(parquet_path)],
                ).fetchone()[0])
                diagnostic.update({
                    "database_minus_parquet": database_minus_parquet,
                    "parquet_minus_database": parquet_minus_database,
                    "pass": database_minus_parquet == 0 and parquet_minus_database == 0,
                })
        except Exception as exc:  # Keep compatibility diagnostics machine-readable.
            diagnostic["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
        v3_tables[table] = diagnostic

    passed = (
        table_surface["pass"]
        and parquet_verification["pass"]
        and all(value["pass"] for value in v4_schema.values())
        and all(value["pass"] for value in v3_tables.values())
    )
    return {
        "pass": passed,
        "classification": ADDITIVE_V4_CLASSIFICATION if passed else None,
        "table_surface": table_surface,
        "v4_schema": v4_schema,
        "parquet_verification": parquet_verification,
        "v3_tables": v3_tables,
    }


def _provenance_errors(connection: duckdb.DuckDBPyConnection, table: str) -> dict[str, int]:
    """Validate the table-specific source references present in the V3 schema."""
    errors = {"not_json_object": 0, "empty_object": 0, "replay_sha_mismatch": 0,
              "patch_mismatch": 0, "source_ref_missing": 0,
              "source_ref_not_object": 0, "source_sha_mismatch": 0,
              "source_locator_missing": 0}
    rows = connection.execute(
        f'SELECT replay_sha256,patch,raw_provenance_json FROM "{table}"'
    ).fetchall()
    for replay_sha, patch, raw in rows:
        try:
            provenance = json.loads(raw) if isinstance(raw, str) else raw
        except (TypeError, json.JSONDecodeError):
            errors["not_json_object"] += 1
            continue
        if not isinstance(provenance, dict):
            errors["not_json_object"] += 1
            continue
        if not provenance:
            errors["empty_object"] += 1
            continue
        if "replay_sha256" in provenance and provenance["replay_sha256"] != replay_sha:
            errors["replay_sha_mismatch"] += 1
        if "patch" in provenance and provenance["patch"] != patch:
            errors["patch_mismatch"] += 1
        if table == "hero_paths":
            # The ingest wrapper preserves the source object under ``source``;
            # its occurrence and record indexes remain at the wrapper level.
            source = provenance.get("source")
            if not isinstance(source, dict):
                errors["source_ref_not_object"] += 1
            elif source.get("replay_sha256") != replay_sha:
                errors["source_sha_mismatch"] += 1
            if any(provenance.get(key) is None for key in (
                "raw_packet_occurrence_index", "record_index",
            )):
                errors["source_locator_missing"] += 1
            continue
        source_key = "spawn_raw_packet_ref" if table == "ward_lifecycles" else "raw_packet_ref"
        source_ref = provenance.get(source_key)
        if source_ref is None:
            errors["source_ref_missing"] += 1
        elif not isinstance(source_ref, dict):
            errors["source_ref_not_object"] += 1
        else:
            if source_ref.get("replay_sha256") != replay_sha:
                errors["source_sha_mismatch"] += 1
            if any(source_ref.get(key) in (None, "") for key in (
                "chunk_index", "decompressed_block_offset", "packet_id",
            )):
                errors["source_locator_missing"] += 1
    return errors


def verify(
    db_path: str | Path = DEFAULT_DB,
    *, status_path: str | Path | None = None, report_path: str | Path | None = None,
    parquet_dir: str | Path | None = None, publication_manifest_path: str | Path | None = None,
) -> dict[str, Any]:
    db_path = Path(db_path).resolve()
    defaults = _publication_paths(db_path)
    status_path = Path(status_path).resolve() if status_path else defaults["status"]
    report_path = Path(report_path).resolve() if report_path else defaults["report"]
    parquet_dir = Path(parquet_dir).resolve() if parquet_dir else defaults["parquet"]
    manifest_path = (Path(publication_manifest_path).resolve()
                     if publication_manifest_path else defaults["manifest"])
    checks: dict[str, dict[str, Any]] = {}

    def record(name: str, actual: Any, expected: Any = None,
               condition: bool | None = None) -> None:
        passed = (actual == expected) if condition is None else bool(condition)
        checks[name] = {"pass": passed, "actual": actual, "expected": expected}

    record("database_file", str(db_path), condition=db_path.is_file())
    if not db_path.is_file():
        failures = [name for name, value in checks.items() if not value["pass"]]
        return {"status": "FAIL", "database": {"path": str(db_path)}, "checks": checks,
                "failures": failures}

    current_database_sha256 = sha256_file(db_path)
    current_database_size = db_path.stat().st_size
    publication_manifest = _verify_manifest(
        checks, db_path=db_path, status_path=status_path,
        report_path=report_path, parquet_dir=parquet_dir,
        manifest_path=manifest_path,
        database_sha256=current_database_sha256,
        database_size=current_database_size,
    )
    database_entry = (publication_manifest.get("database")
                      if isinstance(publication_manifest, dict) else None)
    frozen_database_sha256 = (database_entry.get("sha256")
                              if isinstance(database_entry, dict) else None)
    frozen_database_size = (database_entry.get("size_bytes")
                            if isinstance(database_entry, dict) else None)
    frozen_metadata_valid = (
        isinstance(frozen_database_sha256, str)
        and len(frozen_database_sha256) == 64
        and all(character in "0123456789abcdefABCDEF"
                for character in frozen_database_sha256)
        and isinstance(frozen_database_size, int)
        and not isinstance(frozen_database_size, bool)
        and frozen_database_size >= 0
    )
    exact_frozen_container = (
        frozen_metadata_valid
        and current_database_sha256 == frozen_database_sha256
        and current_database_size == frozen_database_size
    )
    compatibility: dict[str, Any] | None = None

    replay_manifest = json.loads(
        (ROOT / "artifacts" / "replay_manifest.json").read_text(encoding="utf-8")
    )
    expected = {
        "death_events": sum(row["death_event_count"] for row in replay_manifest["replays"]),
        "damage_events": sum(row["damage_event_count"] for row in replay_manifest["replays"]),
        "spell_events": sum(row["spell_event_count"] for row in replay_manifest["replays"]),
        "buff_events": sum(row["buff_event_count"] for row in replay_manifest["replays"]),
        "adc_deaths": sum(row["adc_death_count"] for row in replay_manifest["replays"]),
    }
    with duckdb.connect(str(db_path), read_only=True) as connection:
        tables = {row[0] for row in connection.execute("SHOW TABLES").fetchall()}
        required = {
            "replays", "participants", "death_events", "damage_events", "spell_events",
            "buff_events", "ward_spawns", "ward_lifecycles", "hero_paths",
            "hero_positions_1s", "ward_research_events", "ward_position_context",
            "ward_heatmap_cells", "ward_hotspots", "adc_deaths", "adc_death_damage",
            "adc_death_support_actions", "adc_death_position_context", "adc_death_features",
            "ward_death_context", "map_regions", "ingest_runs", "ingest_rejections",
        }
        record("required_tables", sorted(required - tables), [], condition=required <= tables)
        counts = {table: connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
                  for table in tables}
        record("replays", counts.get("replays"), 10)
        record("participants", counts.get("participants"), 100)
        for table, value in expected.items():
            record(table, counts.get(table), value)
        record("ward_spawns", counts.get("ward_spawns"), 1357)
        record("ward_research_events", counts.get("ward_research_events"), 1357)
        record("ward_lifecycles", counts.get("ward_lifecycles"), 637)
        record("hero_paths", counts.get("hero_paths"), 459906)
        record("hero_positions_1s", counts.get("hero_positions_1s"), 159765)
        record("adc_checkpoint_rows", counts.get("adc_death_position_context"),
               counts.get("adc_deaths", 0) * 4)
        record("adc_feature_rows", counts.get("adc_death_features"), counts.get("adc_deaths", 0))
        record("ward_death_lookback_rows", counts.get("ward_death_context"),
               counts.get("adc_deaths", 0) * 4)

        ward_types = dict(connection.execute("""
            SELECT ward_type,count(*) FROM ward_research_events GROUP BY ward_type
        """).fetchall())
        record("ward_type_distribution", ward_types, {
            "YELLOW_OR_SIGHT_WARD": 923, "CONTROL_WARD": 174,
            "FARSIGHT_WARD": 98, "OTHER_WARD": 162,
        })
        ward_quality = connection.execute("""
            SELECT count(*) FILTER (WHERE spawn_position_status='ENTITY_SPAWN_DIRECT'),
                   count(owner_participant),count(owner_team),
                   count(*) FILTER (WHERE owner_participant IS NULL)
            FROM ward_research_events
        """).fetchone()
        record("ward_direct_positions", ward_quality[0], 1357)
        record("ward_participant_mapping", ward_quality[1], 1195)
        record("ward_team_mapping", ward_quality[2], 1195)
        record("ward_unmapped", ward_quality[3], 162)

        position_quality = connection.execute("""
            SELECT count(*) FILTER (WHERE position_status='VERIFIED_DERIVED'),
                   count(*) FILTER (WHERE position_status='VERIFIED_DIRECT'),
                   count(*) FILTER (WHERE source_age_ms<0),
                   count(raw_packet_ref),count(interpolation_method)
            FROM hero_positions_1s
        """).fetchone()
        record("positions_verified_derived", position_quality[0], 159765)
        record("positions_not_direct", position_quality[1], 0)
        record("positions_nonnegative_age", position_quality[2], 0)
        record("positions_raw_packet_ref", position_quality[3], 159765)
        record("positions_interpolation_method", position_quality[4], 159765)

        damage_columns = {row[1] for row in connection.execute(
            "PRAGMA table_info('damage_events')"
        ).fetchall()}
        if {"damage_type", "spell", "is_basic_attack", "is_critical"} <= damage_columns:
            damage_types = dict(connection.execute("""
                SELECT damage_type,count(*) FROM damage_events GROUP BY damage_type
            """).fetchall())
            record("damage_type_distribution", damage_types, {
                "physical": 11423, "magic": 12799, "true": 3403,
            })
            combat = connection.execute("""
                SELECT count(spell),count(*) FILTER (WHERE is_basic_attack=true),
                       count(*) FILTER (WHERE is_critical=true)
                FROM damage_events
            """).fetchone()
            record("spell_attribution_rows", combat[0], 18516)
            record("basic_attack_true_rows", combat[1], 3798)
            record("critical_true_rows", combat[2], 1273)
        else:
            record("damage_v3_materialized_columns", sorted(damage_columns),
                   condition=False)
        record("ward_query_support_yellow", connection.execute("""
            SELECT count(*) FROM ward_research_events
            WHERE owner_role='support' AND ward_type='YELLOW_OR_SIGHT_WARD'
        """).fetchone()[0], condition=connection.execute("""
            SELECT count(*) FROM ward_research_events
            WHERE owner_role='support' AND ward_type='YELLOW_OR_SIGHT_WARD'
        """).fetchone()[0] > 0)
        record("heatmap_materialized", counts.get("ward_heatmap_cells"),
               condition=counts.get("ward_heatmap_cells", 0) > 0)
        record("hotspots_materialized", counts.get("ward_hotspots"),
               condition=counts.get("ward_hotspots", 0) > 0)
        record("map_regions_versioned", counts.get("map_regions"),
               condition=counts.get("map_regions", 0) >= 10)

        adc_context_columns = {row[1] for row in connection.execute(
            "PRAGMA table_info('adc_death_position_context')"
        ).fetchall()} if "adc_death_position_context" in tables else set()
        required_adc_context_columns = {
            "adc_death_id", "checkpoint", "checkpoint_time_ms",
            "adc_position_timestamp_ms", "adc_source_path_timestamp_ms",
            "adc_sample_age_ms", "adc_source_age_ms", "adc_position_freshness",
            "adc_position_usable", "max_position_age_ms",
        }
        if {"adc_deaths", "adc_death_position_context"} <= tables and required_adc_context_columns <= adc_context_columns:
            # ``adc_death_id`` is the stable context id emitted by the research
            # layer (replay hash, death time, ADC participant), not adc_deaths.fact_id.
            # Keep this expression explicit so verifier joins cannot silently turn
            # into an empty inner join when the two id namespaces differ.
            bad_cardinality = connection.execute("""
                WITH deaths AS (
                    SELECT d.fact_id,
                           CAST(d.replay_sha256 AS VARCHAR) || ':' ||
                           CAST(d.death_time_ms AS VARCHAR) || ':' ||
                           CAST(d.adc_participant_id AS VARCHAR) AS context_id
                    FROM adc_deaths d
                )
                SELECT count(*) FROM (
                    SELECT d.fact_id
                    FROM deaths d
                    LEFT JOIN adc_death_position_context c
                      ON c.adc_death_id = d.context_id
                    GROUP BY d.fact_id
                    HAVING count(c.fact_id) != 4
                        OR count(DISTINCT c.checkpoint) != 4
                ) bad
            """).fetchone()[0]
            record("adc_exactly_four_checkpoints_per_death", bad_cardinality, 0)
            bad_names_times = connection.execute("""
                WITH deaths AS (
                    SELECT d.fact_id, d.death_time_ms, d.combat_start_ms,
                           CAST(d.replay_sha256 AS VARCHAR) || ':' ||
                           CAST(d.death_time_ms AS VARCHAR) || ':' ||
                           CAST(d.adc_participant_id AS VARCHAR) AS context_id
                    FROM adc_deaths d
                )
                SELECT count(*) FROM adc_death_position_context c
                JOIN deaths d ON c.adc_death_id = d.context_id
                WHERE c.checkpoint IS NULL
                   OR c.checkpoint NOT IN ('combat_start','death_minus_3s','death_minus_1s','death')
                   OR c.checkpoint_time_ms IS DISTINCT FROM CASE c.checkpoint
                       WHEN 'combat_start' THEN coalesce(d.combat_start_ms,d.death_time_ms)
                       WHEN 'death_minus_3s' THEN greatest(0,d.death_time_ms-3000)
                       WHEN 'death_minus_1s' THEN greatest(0,d.death_time_ms-1000)
                       WHEN 'death' THEN d.death_time_ms END
            """).fetchone()[0]
            record("adc_checkpoint_names_and_times", bad_names_times, 0)
            duplicate_names = connection.execute("""
                WITH deaths AS (
                    SELECT d.fact_id,
                           CAST(d.replay_sha256 AS VARCHAR) || ':' ||
                           CAST(d.death_time_ms AS VARCHAR) || ':' ||
                           CAST(d.adc_participant_id AS VARCHAR) AS context_id
                    FROM adc_deaths d
                )
                SELECT count(*) FROM (
                  SELECT d.fact_id
                  FROM deaths d
                  JOIN adc_death_position_context c ON c.adc_death_id = d.context_id
                  GROUP BY d.fact_id HAVING count(DISTINCT c.checkpoint) != 4
                )
            """).fetchone()[0]
            record("adc_checkpoint_names_unique", duplicate_names, 0)
            bad_position_semantics = connection.execute("""
                SELECT count(*) FROM adc_death_position_context
                WHERE (adc_position_timestamp_ms IS NULL AND
                       (adc_position_freshness != 'MISSING' OR adc_position_usable IS DISTINCT FROM false
                        OR adc_sample_age_ms IS NOT NULL OR adc_source_age_ms IS NOT NULL))
                   OR (adc_position_timestamp_ms IS NOT NULL AND
                       (adc_position_timestamp_ms > checkpoint_time_ms
                        OR adc_source_path_timestamp_ms IS NULL
                        OR adc_source_path_timestamp_ms > checkpoint_time_ms
                        OR adc_sample_age_ms != checkpoint_time_ms-adc_position_timestamp_ms
                        OR adc_source_age_ms != checkpoint_time_ms-adc_source_path_timestamp_ms
                        OR (adc_source_age_ms <= max_position_age_ms AND
                            (adc_position_freshness != 'FRESH' OR adc_position_usable IS DISTINCT FROM true))
                        OR (adc_source_age_ms > max_position_age_ms AND
                            (adc_position_freshness != 'STALE_SOURCE_PATH' OR adc_position_usable IS DISTINCT FROM false))))
            """).fetchone()[0]
            record("adc_no_lookahead_and_freshness_semantics", bad_position_semantics, 0)
        else:
            record("adc_checkpoint_materialized_columns", sorted(adc_context_columns),
                   condition=False)

        for table in (
            "death_events", "damage_events", "spell_events", "buff_events", "ward_spawns",
            "ward_lifecycles", "hero_paths", "hero_positions_1s",
        ):
            if table in tables:
                errors = _provenance_errors(connection, table)
                record(f"{table}_provenance_valid", errors, {key: 0 for key in errors})

        if not exact_frozen_container:
            compatibility = _verify_additive_v4_compatibility(
                connection,
                tables=tables,
                parquet_dir=parquet_dir,
                publication_checks=checks,
            )

    record("research_status_file", str(status_path), condition=status_path.is_file())
    record("first_report_file", str(report_path), condition=report_path.is_file())
    status_database_sha256: Any = None
    if status_path.is_file():
        try:
            status = json.loads(status_path.read_text(encoding="utf-8"))
            if not isinstance(status, dict):
                record("status_json", type(status).__name__, "JSON object",
                       condition=False)
            else:
                status_database_sha256 = status.get("database_sha256")
                record("status_database_sha256", status_database_sha256,
                       current_database_sha256)
                record("status_replay_count", status.get("replay_count"), 10)
                protection = status.get("protection")
                record(
                    "protection_theoretical_false",
                    (protection.get("theoretical_values_used")
                     if isinstance(protection, dict) else None),
                    False,
                )
        except (OSError, json.JSONDecodeError):
            record("status_json", "invalid JSON", "valid JSON", condition=False)
    report: str | None = None
    if report_path.is_file():
        report = report_path.read_text(encoding="utf-8")
        record("report_database_sha256", current_database_sha256 in report, True)
        record("report_sanity_disclaimer", "N=10" in report and "SANITY ONLY" in report, True)

    if compatibility is not None:
        frozen_references = {
            "status": {
                "pass": (frozen_metadata_valid
                         and status_database_sha256 == frozen_database_sha256),
                "actual": status_database_sha256,
                "expected": frozen_database_sha256,
            },
            "report": {
                "pass": (frozen_metadata_valid
                         and isinstance(report, str)
                         and frozen_database_sha256 in report),
                "actual": (frozen_database_sha256 in report
                           if isinstance(report, str)
                           and isinstance(frozen_database_sha256, str) else False),
                "expected": True,
            },
        }
        non_container_failures = sorted(
            name for name, value in checks.items()
            if not value["pass"] and name not in EXPECTED_CONTAINER_DIVERGENCE_CHECKS
        )
        database_compatibility_pass = bool(compatibility["pass"])
        compatibility.update({
            "database_compatibility_pass": database_compatibility_pass,
            "frozen_database_metadata": {
                "pass": frozen_metadata_valid,
                "sha256": frozen_database_sha256,
                "bytes": frozen_database_size,
            },
            "frozen_references": frozen_references,
            "non_container_failures": non_container_failures,
        })
        compatibility_pass = (
            database_compatibility_pass
            and frozen_metadata_valid
            and all(value["pass"] for value in frozen_references.values())
            and not non_container_failures
        )
        compatibility["pass"] = compatibility_pass
        compatibility["classification"] = (
            ADDITIVE_V4_CLASSIFICATION if compatibility_pass else None
        )
        checks["additive_v4_container_compatibility"] = {
            "pass": compatibility_pass,
            "actual": compatibility,
            "expected": ADDITIVE_V4_CLASSIFICATION,
        }
        if compatibility_pass:
            for name in EXPECTED_CONTAINER_DIVERGENCE_CHECKS:
                check = checks[name]
                check["pass"] = True
                check["classification"] = ADDITIVE_V4_CLASSIFICATION

    failures = [name for name, value in checks.items() if not value["pass"]]
    database_metadata: dict[str, Any] = {
        "path": str(db_path),
        "bytes": current_database_size,
        "sha256": current_database_sha256,
        "current": {
            "bytes": current_database_size,
            "sha256": current_database_sha256,
        },
        "frozen": {
            "bytes": frozen_database_size,
            "sha256": frozen_database_sha256,
        },
        "container_classification": (
            "FROZEN_V3_CONTAINER_MATCH" if exact_frozen_container
            else compatibility.get("classification") if compatibility else None
        ),
    }
    return {
        "status": "PASS" if not failures else "FAIL",
        "database": database_metadata,
        "checks": checks, "failures": failures,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--status")
    parser.add_argument("--report")
    parser.add_argument("--parquet-dir")
    parser.add_argument("--publication-manifest")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    result = verify(args.db, status_path=args.status, report_path=args.report,
                    parquet_dir=args.parquet_dir,
                    publication_manifest_path=args.publication_manifest)
    rendered = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
