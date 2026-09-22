#!/usr/bin/env python3
"""Build and validate the deterministic Protection V4 lite review package.

The build reads the research database through DuckDB's read-only mode.  The
database, Replay files, runtime image, and exhaustive packet JSONL files are
never copied into the package.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "research-v3" / "output" / "replay_research.duckdb"
DEFAULT_VERIFY = ROOT / "artifacts" / "protection_v4_probe" / "protection_v4_verify_attested_run2.json"
DEFAULT_IDEMPOTENCE_RUN1 = (
    ROOT / "artifacts" / "protection_v4_probe" / "protection_v4_verify_attested_run1.json"
)
DEFAULT_IDEMPOTENCE_RUN2 = (
    ROOT / "artifacts" / "protection_v4_probe" / "protection_v4_verify_attested_run2.json"
)
DEFAULT_REGRESSION_ATTESTATION = (
    ROOT / "artifacts" / "protection_v4_probe" / "protection_v4_regression_attested.json"
)
DEFAULT_OUTPUT = ROOT / "artifacts" / "protection_v4_publication"
DEFAULT_ZIP = ROOT / "protection-v4-independent-review-lite.zip"
DEFAULT_EXTERNAL_MANIFEST = ROOT / "protection-v4-independent-review-lite.manifest.json"
DEFAULT_ZIP_HASH = ROOT / "protection-v4-independent-review-lite.zip.sha256"
DEFAULT_MANIFEST_HASH = ROOT / "protection-v4-independent-review-lite.manifest.json.sha256"
COMPLETION_REPORT = ROOT / "docs" / "PROTECTION_V4_COMPLETION_REPORT.md"
PACKAGE_EVIDENCE = ROOT / ".omo" / "evidence" / "protection-v4-publication-package.md"

FIXED_ZIP_TIMESTAMP = (2026, 8, 11, 0, 0, 0)
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
FROZEN_EMULATOR_SHA256 = "c3959b3163c391a97ee0d6fc63641ad1f4507fbbe6dab87cd647e9a174fca6e7"

EXPECTED_V3_COUNTS = {
    "replays": 10,
    "participants": 100,
    "adc_deaths": 120,
    "damage_events": 27625,
    "death_events": 546,
    "spell_events": 32290,
    "buff_events": 312813,
    "hero_paths": 459906,
    "hero_positions_1s": 159765,
    "ward_spawns": 1357,
    "ward_research_events": 1357,
    "ward_position_context": 1357,
    "ward_lifecycles": 637,
    "ward_hotspots": 34,
    "ward_heatmap_cells": 1137,
    "ward_death_context": 480,
    "adc_death_damage": 255,
    "adc_death_features": 120,
    "adc_death_position_context": 480,
    "adc_death_support_actions": 281,
    "map_regions": 28,
    "ingest_runs": 2,
    "ingest_rejections": 0,
}

REQUIRED_REGRESSION_IDS = {
    "npm_test",
    "ward_spawn_current",
    "verify_v2",
    "research_v3_unit",
    "research_v3_verify",
    "research_v4_unit",
    "research_v4_verify",
    "independent_code_review",
    "independent_qa",
    "final_gate_review",
}

SEMANTIC_FINGERPRINT_TABLES = {
    "protection_v4_profiles",
    "health_state_events",
    "shield_state_events",
    "heal_events",
    "temporary_hp_events",
    "protection_events",
    "protection_state_transitions",
    "protection_spell_inventory",
    "adc_death_protection",
    "adc_survival_features_v4",
}

EXACT_UNAVAILABLE_FIELDS = [
    "health.current_hp",
    "health.max_hp",
    "heal.raw_heal",
    "heal.effective_heal",
    "heal.overheal",
    "shield.remaining",
    "shield.unused",
    "shield.absorption.source",
    "shield.absorption.caster",
    "shield.absorption.spell",
    "shield.absorption.shield_instance",
    "shield.consumption_order",
    "temporary_hp.amount",
    "temporary_hp.start",
    "temporary_hp.end",
    "temporary_max_hp.modification",
    "total_external_protection",
]

FORBIDDEN_ARCHIVE_MARKERS = (
    ".duckdb",
    ".rofl",
    ".zip",
    ".7z",
    "on_event_protection_decoded_all14.jsonl",
    "packet_009e_all14.jsonl",
    "packet_009e_decoded_all14.jsonl",
    "hn1-11184800649_damage_decoded.jsonl",
    "hn1-11184800649_packet_028a.jsonl",
    "janna_all_packet_shapes.json",
    "league_16.15.801.3452.memory.bin",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.rstrip() + "\n", encoding="utf-8", newline="\n")


def write_csv(path: Path, columns: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(columns), lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column) for column in columns})


def safe_relative(path: Path, root: Path = ROOT) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def parse_json_value(value: Any) -> Any:
    if value is None or isinstance(value, (dict, list, int, float, bool)):
        return value
    try:
        return json.loads(str(value))
    except (TypeError, json.JSONDecodeError):
        return value


def query_dicts(connection: Any, sql: str, parameters: Sequence[Any] = ()) -> list[dict[str, Any]]:
    cursor = connection.execute(sql, list(parameters))
    columns = [item[0] for item in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def scalar(connection: Any, sql: str, parameters: Sequence[Any] = ()) -> Any:
    return connection.execute(sql, list(parameters)).fetchone()[0]


def assert_equal(failures: list[str], name: str, actual: Any, expected: Any) -> None:
    if actual != expected:
        failures.append(f"{name}: actual={actual!r}, expected={expected!r}")


def load_idempotence_evidence(
    run1_path: Path,
    run2_path: Path,
    *,
    allow_pending: bool,
) -> dict[str, Any]:
    """Load two independently written verifier artifacts and compare all 10 tables.

    A missing artifact may be represented only as PENDING for a draft publication.
    A mismatched or malformed pair is always a hard error; it is never converted to
    a passing self-assertion.
    """
    if run1_path.resolve() == run2_path.resolve():
        raise RuntimeError("Idempotence run1 and run2 must be distinct files")
    expected_name_markers = ((run1_path, "attested_run1"), (run2_path, "attested_run2"))
    for path, marker in expected_name_markers:
        if marker not in path.name.lower():
            raise RuntimeError(
                f"Idempotence evidence file must be explicitly named with {marker!r}: {path}"
            )
    missing = [path for path in (run1_path, run2_path) if not path.is_file()]
    if missing:
        if not allow_pending:
            raise FileNotFoundError(
                "Final publication requires both attested idempotence verifier artifacts: "
                + ", ".join(str(path) for path in missing)
            )
        return {
            "schema_version": 1,
            "status": "PENDING",
            "reason": "Both independently produced attested verifier artifacts are required.",
            "required_inputs": [safe_relative(run1_path), safe_relative(run2_path)],
            "missing_inputs": [safe_relative(path) for path in missing],
            "all_semantic_fingerprints_equal": None,
        }

    runs: list[tuple[Path, dict[str, Any]]] = []
    for path in (run1_path, run2_path):
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("status") != "PROTECTION_V4_COMPLETE" or value.get("failures") != []:
            raise RuntimeError(
                f"Idempotence verifier artifact is not a clean PASS: {path} "
                f"status={value.get('status')!r} failures={value.get('failures')!r}"
            )
        fingerprints = value.get("summary", {}).get("semantic_fingerprints")
        if not isinstance(fingerprints, dict):
            raise RuntimeError(f"Missing semantic_fingerprints in {path}")
        actual_tables = set(fingerprints)
        if actual_tables != SEMANTIC_FINGERPRINT_TABLES:
            raise RuntimeError(
                f"Semantic fingerprint table set mismatch in {path}: "
                f"actual={sorted(actual_tables)!r} expected={sorted(SEMANTIC_FINGERPRINT_TABLES)!r}"
            )
        for table, entry in fingerprints.items():
            if not isinstance(entry, dict):
                raise RuntimeError(f"Invalid semantic fingerprint entry {table!r} in {path}")
            if not isinstance(entry.get("row_count"), int) or entry["row_count"] < 0:
                raise RuntimeError(f"Invalid row_count for {table!r} in {path}")
            digest = entry.get("sha256")
            if not isinstance(digest, str) or len(digest) != 64:
                raise RuntimeError(f"Invalid sha256 for {table!r} in {path}")
            if not isinstance(entry.get("columns"), list):
                raise RuntimeError(f"Invalid columns for {table!r} in {path}")
        runs.append((path, value))

    run1_fingerprints = runs[0][1]["summary"]["semantic_fingerprints"]
    run2_fingerprints = runs[1][1]["summary"]["semantic_fingerprints"]
    comparisons: dict[str, Any] = {}
    mismatches: list[str] = []
    for table in sorted(SEMANTIC_FINGERPRINT_TABLES):
        before = run1_fingerprints[table]
        after = run2_fingerprints[table]
        row_count_equal = before["row_count"] == after["row_count"]
        sha256_equal = before["sha256"] == after["sha256"]
        columns_equal = before["columns"] == after["columns"]
        equal = row_count_equal and sha256_equal and columns_equal
        comparisons[table] = {
            "run1": before,
            "run2": after,
            "row_count_equal": row_count_equal,
            "sha256_equal": sha256_equal,
            "columns_equal": columns_equal,
            "equal": equal,
        }
        if not equal:
            mismatches.append(table)
    if mismatches:
        raise RuntimeError(
            "Attested consecutive-backfill semantic fingerprints differ for: "
            + ", ".join(mismatches)
        )

    return {
        "schema_version": 1,
        "status": "PASS",
        "method": (
            "Two independently written verifier JSON artifacts captured after consecutive full attested "
            "backfills; all 10 semantic projections compare row_count, sha256, and ordered columns."
        ),
        "sources": {
            "run1": {
                "path": safe_relative(run1_path),
                "size_bytes": run1_path.stat().st_size,
                "sha256": sha256_file(run1_path),
            },
            "run2": {
                "path": safe_relative(run2_path),
                "size_bytes": run2_path.stat().st_size,
                "sha256": sha256_file(run2_path),
            },
        },
        "table_count": len(comparisons),
        "comparisons": comparisons,
        "all_semantic_fingerprints_equal": True,
    }


def _resolve_attested_evidence(entry: Mapping[str, Any], attestation_path: Path) -> dict[str, Any]:
    evidence = entry.get("evidence")
    if not isinstance(evidence, dict):
        raise RuntimeError(f"Regression entry {entry.get('id')!r} lacks an evidence object")
    relative = evidence.get("path")
    expected_hash = evidence.get("sha256")
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise RuntimeError(f"Unsafe regression evidence path for {entry.get('id')!r}: {relative!r}")
    source = ROOT / relative
    if not source.is_file():
        raise FileNotFoundError(
            f"Regression evidence file for {entry.get('id')!r} does not exist: {source} "
            f"(attestation {attestation_path})"
        )
    actual_hash = sha256_file(source)
    if not isinstance(expected_hash, str) or actual_hash != expected_hash:
        raise RuntimeError(
            f"Regression evidence hash mismatch for {entry.get('id')!r}: "
            f"actual={actual_hash!r} expected={expected_hash!r}"
        )
    expected_size = evidence.get("size_bytes")
    actual_size = source.stat().st_size
    if expected_size is not None and expected_size != actual_size:
        raise RuntimeError(
            f"Regression evidence size mismatch for {entry.get('id')!r}: "
            f"actual={actual_size!r} expected={expected_size!r}"
        )
    return {"path": relative.replace("\\", "/"), "size_bytes": actual_size, "sha256": actual_hash}


def load_regression_attestation(path: Path, *, allow_pending: bool) -> dict[str, Any]:
    """Validate a hash-bound final regression/review attestation supplied by root."""
    if not path.is_file():
        if not allow_pending:
            raise FileNotFoundError(f"Final publication requires regression attestation: {path}")
        return {
            "schema_version": 1,
            "status": "PENDING",
            "reason": "Hash-bound final regression, code review, QA, and gate evidence is not available yet.",
            "required_input": safe_relative(path),
            "required_ids": sorted(REQUIRED_REGRESSION_IDS),
        }

    value = json.loads(path.read_text(encoding="utf-8"))
    rows = value.get("commands") or value.get("checks")
    if isinstance(rows, dict):
        rows = [dict(entry, id=identifier) for identifier, entry in rows.items()]
    if not isinstance(rows, list):
        raise RuntimeError(f"Regression attestation must contain commands/checks: {path}")
    indexed: dict[str, dict[str, Any]] = {}
    for raw in rows:
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str):
            raise RuntimeError(f"Invalid regression attestation entry in {path}: {raw!r}")
        identifier = raw["id"]
        if identifier in indexed:
            raise RuntimeError(f"Duplicate regression attestation id {identifier!r} in {path}")
        row = dict(raw)
        row["evidence"] = _resolve_attested_evidence(row, path)
        indexed[identifier] = row
    missing_ids = REQUIRED_REGRESSION_IDS - set(indexed)
    if missing_ids:
        raise RuntimeError(f"Regression attestation is missing required ids: {sorted(missing_ids)!r}")

    required_rows = [indexed[identifier] for identifier in sorted(REQUIRED_REGRESSION_IDS)]
    failed_ids = [row["id"] for row in required_rows if row.get("status") != "PASS"]
    declared_status = value.get("status")
    computed_status = "PASS" if not failed_ids else "FAIL"
    if declared_status != computed_status:
        raise RuntimeError(
            f"Regression attestation declared status {declared_status!r} disagrees with "
            f"required-entry status {computed_status!r}"
        )
    return {
        "schema_version": 1,
        "status": computed_status,
        "source": {
            "path": safe_relative(path),
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        },
        "required_ids": sorted(REQUIRED_REGRESSION_IDS),
        "failed_ids": failed_ids,
        "commands": required_rows,
        "metadata": value.get("metadata", {}),
    }


def load_snapshot(db_path: Path, verify_path: Path) -> dict[str, Any]:
    """Read and validate the final V4 database state without mutating it."""
    if not db_path.is_file():
        raise FileNotFoundError(db_path)
    if not verify_path.is_file():
        raise FileNotFoundError(verify_path)

    verify = json.loads(verify_path.read_text(encoding="utf-8"))
    try:
        import duckdb  # Imported lazily so package-only validation needs no DuckDB.
    except ImportError as exc:  # pragma: no cover - environment-specific guard
        raise RuntimeError("DuckDB is required only for publication export generation") from exc

    connection = duckdb.connect(str(db_path), read_only=True)
    try:
        connection.execute("BEGIN TRANSACTION")
        profiles = query_dicts(
            connection,
            """SELECT replay_sha256,game_id,patch,profile_status,decoder_profile,
                      decoded_row_count,protection_row_count,v4_schema_version,
                      on_event_decoder_status,shield_damage_decoder_status,
                      decoder_profiles_json
                 FROM protection_v4_profiles ORDER BY game_id,replay_sha256""",
        )
        for row in profiles:
            row["decoder_profiles"] = parse_json_value(row.pop("decoder_profiles_json"))

        inventory = query_dicts(
            connection,
            """SELECT fact_id,replay_sha256,game_id,champion,spell_identifier,
                      spell_slot,protection_cast_kind,cast_count,target_count,
                      buff_candidate_count,damage_window_count,first_cast_ms,last_cast_ms
                 FROM protection_spell_inventory
                ORDER BY game_id,champion,spell_identifier,fact_id""",
        )
        inventory_by_champion = query_dicts(
            connection,
            """SELECT champion,count(*) AS rows,sum(cast_count) AS casts,
                      sum(target_count) AS targets,sum(buff_candidate_count) AS buff_candidates,
                      sum(damage_window_count) AS damage_windows
                 FROM protection_spell_inventory GROUP BY champion ORDER BY champion""",
        )
        inventory_by_kind = query_dicts(
            connection,
            """SELECT protection_cast_kind,count(*) AS rows,sum(cast_count) AS casts,
                      sum(target_count) AS targets,sum(buff_candidate_count) AS buff_candidates,
                      sum(damage_window_count) AS damage_windows
                 FROM protection_spell_inventory
                GROUP BY protection_cast_kind ORDER BY protection_cast_kind""",
        )

        table_names = [
            "protection_v4_profiles", "health_state_events", "shield_state_events",
            "heal_events", "temporary_hp_events", "protection_events",
            "protection_state_transitions", "protection_spell_inventory",
            "adc_death_protection", "adc_survival_features_v4",
        ]
        table_counts = {name: scalar(connection, f"SELECT count(*) FROM {name}") for name in table_names}

        shield_event_rows = query_dicts(
            connection,
            """SELECT event_id,count(*) AS rows,count(source_network_id) AS source_rows,
                      count(target_network_id) AS target_rows,count(observed_amount) AS amount_rows,
                      sum(observed_amount) AS observed_amount_sum,
                      min(observed_amount) AS observed_amount_min,
                      max(observed_amount) AS observed_amount_max
                 FROM shield_state_events GROUP BY event_id ORDER BY event_id""",
        )
        protection_rows = query_dicts(
            connection,
            """SELECT protection_kind,count(*) AS rows,count(source_network_id) AS source_rows,
                      count(target_network_id) AS target_rows,count(observed_amount) AS amount_rows,
                      count(raw_amount) AS raw_amount_rows,count(effective_amount) AS effective_amount_rows,
                      count(overheal_amount) AS overheal_amount_rows,sum(observed_amount) AS observed_amount_sum,
                      sum(coalesce(heal_group_size,0)) AS represented_raw_rows
                 FROM protection_events GROUP BY protection_kind ORDER BY protection_kind""",
        )
        transition_rows = query_dicts(
            connection,
            """SELECT transition_kind,count(*) AS rows,count(source_network_id) AS source_rows,
                      count(target_network_id) AS target_rows,count(observed_amount) AS amount_rows,
                      count(remaining_amount) AS remaining_rows,count(absorbed_amount) AS absorbed_rows,
                      count(unused_amount) AS unused_rows,sum(absorbed_amount) AS absorbed_amount_sum
                 FROM protection_state_transitions GROUP BY transition_kind ORDER BY transition_kind""",
        )
        profile_status = query_dicts(
            connection,
            """SELECT profile_status,on_event_decoder_status,shield_damage_decoder_status,
                      count(*) AS profiles FROM protection_v4_profiles
                 GROUP BY profile_status,on_event_decoder_status,shield_damage_decoder_status
                 ORDER BY profile_status,on_event_decoder_status,shield_damage_decoder_status""",
        )

        raw_heal = query_dicts(
            connection,
            """SELECT count(*) AS rows,count(source_network_id) AS source_rows,
                      count(target_network_id) AS target_rows,count(observed_amount) AS amount_rows,
                      count(raw_amount) AS raw_amount_rows,count(effective_amount) AS effective_amount_rows,
                      count(overheal_amount) AS overheal_amount_rows,sum(observed_amount) AS observed_amount_sum,
                      min(observed_amount) AS observed_amount_min,max(observed_amount) AS observed_amount_max
                 FROM heal_events""",
        )[0]

        adc_kind = query_dicts(
            connection,
            """SELECT protection_kind,count(*) AS rows,count(DISTINCT adc_death_id) AS deaths,
                      count(observed_amount) AS observed_amount_rows,
                      sum(observed_amount) AS observed_amount_sum,
                      sum(direct_heal_lower) AS direct_heal_lower_sum,
                      sum(direct_heal_upper) AS direct_heal_upper_sum,
                      count(raw_amount) AS raw_amount_rows,
                      count(effective_amount) AS effective_amount_rows,
                      count(overheal_amount) AS overheal_amount_rows
                 FROM adc_death_protection GROUP BY protection_kind ORDER BY protection_kind""",
        )
        adc_summary = query_dicts(
            connection,
            """SELECT count(*) AS feature_rows,count(DISTINCT adc_death_id) AS distinct_deaths,
                      sum(CASE WHEN coalesce(external_ally_shield_generated,0)>0 THEN 1 ELSE 0 END)
                          AS positive_shield_deaths,
                      sum(CASE WHEN coalesce(external_ally_direct_heal_upper,0)>0 THEN 1 ELSE 0 END)
                          AS positive_heal_deaths,
                      sum(CASE WHEN coalesce(external_ally_shield_generated,0)>0
                                    OR coalesce(external_ally_direct_heal_upper,0)>0 THEN 1 ELSE 0 END)
                          AS positive_any_protection_deaths,
                      sum(coalesce(shield_absorbed,0)) AS shield_absorbed_sum,
                      sum(CASE WHEN coalesce(shield_absorbed,0)>0 THEN 1 ELSE 0 END)
                          AS positive_absorption_deaths,
                      count(*) FILTER (WHERE shield_remaining IS NOT NULL) AS shield_remaining_rows,
                      count(*) FILTER (WHERE shield_unused IS NOT NULL) AS shield_unused_rows,
                      count(*) FILTER (WHERE health_before IS NOT NULL) AS health_before_rows,
                      count(*) FILTER (WHERE health_after IS NOT NULL) AS health_after_rows,
                      count(*) FILTER (WHERE temporary_hp_before IS NOT NULL) AS temporary_hp_before_rows,
                      count(*) FILTER (WHERE temporary_hp_after IS NOT NULL) AS temporary_hp_after_rows
                 FROM adc_survival_features_v4""",
        )[0]
        adc_protection_summary = query_dicts(
            connection,
            """SELECT count(*) AS rows,count(DISTINCT adc_death_id) AS distinct_deaths
                 FROM adc_death_protection""",
        )[0]

        absorption_rows = query_dicts(
            connection,
            """SELECT fact_id,replay_sha256,game_id,replay_time_ms,transition_kind,
                      source_network_id,target_network_id,observed_amount,remaining_amount,
                      absorbed_amount,unused_amount,raw_provenance_json
                 FROM protection_state_transitions
                WHERE transition_kind='SHIELD_ABSORBED'
                ORDER BY replay_time_ms,fact_id""",
        )
        for row in absorption_rows:
            row["raw_provenance"] = parse_json_value(row.pop("raw_provenance_json"))

        connection.execute("ROLLBACK")
    finally:
        connection.close()

    failures: list[str] = []
    assert_equal(failures, "verify.status", verify.get("status"), "PROTECTION_V4_COMPLETE")
    assert_equal(failures, "verify.failures", verify.get("failures"), [])
    assert_equal(failures, "profiles", table_counts["protection_v4_profiles"], 14)
    assert_equal(failures, "heal_events", table_counts["heal_events"], 81652)
    assert_equal(failures, "shield_state_events", table_counts["shield_state_events"], 9834)
    assert_equal(failures, "protection_events", table_counts["protection_events"], 82497)
    assert_equal(failures, "transitions", table_counts["protection_state_transitions"], 2)
    assert_equal(failures, "inventory rows", table_counts["protection_spell_inventory"], 25)
    assert_equal(failures, "adc_death_protection", table_counts["adc_death_protection"], 128)
    assert_equal(failures, "adc features", table_counts["adc_survival_features_v4"], 120)
    assert_equal(failures, "health rows", table_counts["health_state_events"], 0)
    assert_equal(failures, "temporary HP rows", table_counts["temporary_hp_events"], 0)

    shield_counts = {str(row["event_id"]): row["rows"] for row in shield_event_rows}
    assert_equal(failures, "shield event counts", shield_counts, {"23": 2, "237": 5080, "238": 4752})
    protection_counts = {row["protection_kind"]: row["rows"] for row in protection_rows}
    assert_equal(
        failures, "canonical protection counts", protection_counts,
        {"HEAL_REPORTED": 77415, "SHIELD_ABSORBED": 2, "SHIELD_GENERATED": 5080},
    )
    inventory_totals = {
        "rows": len(inventory),
        "casts": sum(row["cast_count"] for row in inventory),
        "targets": sum(row["target_count"] for row in inventory),
        "buff_candidates": sum(row["buff_candidate_count"] for row in inventory),
        "damage_windows": sum(row["damage_window_count"] for row in inventory),
    }
    assert_equal(
        failures, "inventory totals", inventory_totals,
        {"rows": 25, "casts": 1055, "targets": 1097, "buff_candidates": 1128, "damage_windows": 87},
    )
    assert_equal(failures, "adc protection distinct deaths", adc_protection_summary["distinct_deaths"], 40)
    assert_equal(failures, "adc positive deaths", adc_summary["positive_any_protection_deaths"], 40)
    assert_equal(failures, "adc positive shield deaths", adc_summary["positive_shield_deaths"], 27)
    assert_equal(failures, "adc positive heal deaths", adc_summary["positive_heal_deaths"], 23)
    assert_equal(failures, "adc absorption deaths", adc_summary["positive_absorption_deaths"], 0)
    assert_equal(
        failures, "absorption amounts", sorted(row["absorbed_amount"] for row in absorption_rows),
        [30.030563354492188, 375.13690185546875],
    )

    verify_v3_counts = verify.get("summary", {}).get("v3", {}).get("table_counts", {})
    for name, expected in EXPECTED_V3_COUNTS.items():
        assert_equal(failures, f"v3.{name}", verify_v3_counts.get(name), expected)
    assert_equal(
        failures, "frozen emulator hash",
        sha256_file(ROOT / "scripts" / "emulate_exact_packet_decoder.py"),
        FROZEN_EMULATOR_SHA256,
    )
    if failures:
        raise RuntimeError("Publication precondition failure(s):\n- " + "\n- ".join(failures))

    v3_replay_shas = set(verify.get("summary", {}).get("v3", {}).get("replay_facts", {}))
    v4_only_profiles = verify.get("summary", {}).get("profiles", {}).get("v4_only_profiles", {})
    for row in profiles:
        row["in_frozen_v3"] = row["replay_sha256"] in v3_replay_shas
        row["v4_only_profile"] = row["replay_sha256"] in v4_only_profiles

    return {
        "verify": verify,
        "verify_path": verify_path,
        "db_path": db_path,
        "db_size_bytes": db_path.stat().st_size,
        "profiles": profiles,
        "profile_status": profile_status,
        "inventory": inventory,
        "inventory_totals": inventory_totals,
        "inventory_by_champion": inventory_by_champion,
        "inventory_by_kind": inventory_by_kind,
        "table_counts": table_counts,
        "shield_event_rows": shield_event_rows,
        "protection_rows": protection_rows,
        "transition_rows": transition_rows,
        "raw_heal": raw_heal,
        "adc_kind": adc_kind,
        "adc_summary": adc_summary,
        "adc_protection_summary": adc_protection_summary,
        "absorption_rows": absorption_rows,
        "v3_replay_shas": v3_replay_shas,
        "v4_only_profiles": v4_only_profiles,
    }


def build_absorption_samples(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    champion_by_target = {1073742006: "Samira", 1073742003: "Gnar"}
    samples: list[dict[str, Any]] = []
    for row in snapshot["absorption_rows"]:
        provenance = row.get("raw_provenance") or {}
        decoded = provenance.get("raw") or provenance.get("decoded_row") or provenance
        neighbor = decoded.get("related_unit_apply_damage") or {}
        target = row["target_network_id"]
        samples.append({
            "replay_sha256": row["replay_sha256"],
            "game_id": row["game_id"],
            "replay_time_ms": row["replay_time_ms"],
            "target_network_id": target,
            "target_network_id_hex": f"0x{target:08x}",
            "target_champion": champion_by_target.get(target),
            "shield_absorbed_amount": row["absorbed_amount"],
            "shield_absorbed_status": "VERIFIED_DIRECT_TARGET_TOTAL",
            "specific_shield_source_network_id": None,
            "specific_shield_instance_id": None,
            "source_attribution_status": "UNAVAILABLE",
            "raw_payload_sha256": decoded.get("raw_payload_sha256"),
            "raw_payload_hex": decoded.get("raw_payload_hex"),
            "chunk_index": decoded.get("chunk_index"),
            "decompressed_block_offset": decoded.get("decompressed_block_offset"),
            "decompressed_payload_offset": decoded.get("decompressed_payload_offset"),
            "related_damage": {
                "relation": neighbor.get("relation"),
                "status": neighbor.get("semantic_status"),
                "source_network_id": neighbor.get("source_network_id"),
                "target_network_id": neighbor.get("target_network_id"),
                "unit_apply_damage_amount": neighbor.get("unit_apply_damage_amount"),
                "combined_shield_plus_damage_amount": neighbor.get(
                    "combined_shield_plus_unit_apply_damage_amount"
                ),
                "combined_amount_status": neighbor.get("combined_amount_status"),
                "block_offset_delta": neighbor.get("block_offset_delta"),
                "raw_payload_sha256": neighbor.get("raw_payload_sha256"),
            },
            "in_frozen_v3_replay_set": row["replay_sha256"] in snapshot["v3_replay_shas"],
            "in_frozen_adc_death_context": False,
        })
    return samples


def build_payloads(
    snapshot: Mapping[str, Any],
    release_status: str,
    idempotence_evidence: Mapping[str, Any],
    regression_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    verify = snapshot["verify"]
    verify_summary = verify["summary"]
    absorption_samples = build_absorption_samples(snapshot)
    table_counts = snapshot["table_counts"]
    v4_only = snapshot["v4_only_profiles"]

    profiles_payload = {
        "schema_version": 1,
        "status": "PASS",
        "source_database": safe_relative(snapshot["db_path"]),
        "source_database_size_bytes": snapshot["db_size_bytes"],
        "source_database_packaged": False,
        "profile_count": len(snapshot["profiles"]),
        "frozen_v3_profile_count": sum(row["in_frozen_v3"] for row in snapshot["profiles"]),
        "v4_only_profile_count": sum(row["v4_only_profile"] for row in snapshot["profiles"]),
        "v4_only_profiles": v4_only,
        "status_distribution": snapshot["profile_status"],
        "profiles": snapshot["profiles"],
    }
    inventory_payload = {
        "schema_version": 1,
        "status": "PASS",
        "totals": snapshot["inventory_totals"],
        "by_champion": snapshot["inventory_by_champion"],
        "by_cast_kind": snapshot["inventory_by_kind"],
        "rows": snapshot["inventory"],
        "scope_note": "Nami and Sona are absent from the frozen 10-Replay inventory; no zero rows were fabricated.",
    }
    counts_payload = {
        "schema_version": 1,
        "status": "PASS",
        "profiles": len(snapshot["profiles"]),
        "table_counts": table_counts,
        "raw_shield_state_rows": {
            "total": table_counts["shield_state_events"],
            "distribution": snapshot["shield_event_rows"],
            "meaning": {
                "23": "direct target-total shield absorption from opcode 0x0017",
                "237": "0x00ed OnReceiveShield; canonical generated shield route",
                "238": "0x00ee OnGrantShield; duplicate non-canonical route",
            },
        },
        "heal_rows": {
            "raw_rows_preserved": table_counts["heal_events"],
            "exact_full_blob_group_representatives": 77415,
            "interpretation": "77,415 is a lower-bound exact-blob grouping, not proof that the other raw rows are duplicates.",
            "field_completeness": snapshot["raw_heal"],
        },
        "canonical_protection_events": snapshot["protection_rows"],
        "state_transitions": snapshot["transition_rows"],
        "inventory_totals": snapshot["inventory_totals"],
        "v3_frozen_table_counts": verify_summary["v3"]["table_counts"],
    }
    adc_payload = {
        "schema_version": 1,
        "status": "PASS",
        "feature_rows": snapshot["adc_summary"]["feature_rows"],
        "distinct_adc_deaths_with_feature_row": snapshot["adc_summary"]["distinct_deaths"],
        "adc_death_protection_rows": snapshot["adc_protection_summary"]["rows"],
        "distinct_adc_deaths_with_positive_reported_protection": snapshot["adc_protection_summary"][
            "distinct_deaths"
        ],
        "positive_any_protection_deaths": snapshot["adc_summary"]["positive_any_protection_deaths"],
        "positive_shield_generated_deaths": snapshot["adc_summary"]["positive_shield_deaths"],
        "positive_heal_report_deaths": snapshot["adc_summary"]["positive_heal_deaths"],
        "positive_direct_absorption_deaths": snapshot["adc_summary"]["positive_absorption_deaths"],
        "kind_distribution": snapshot["adc_kind"],
        "direct_absorption_scope_note": (
            "Both 0x0017 rows occur in V4-only Replay HN1-11184800649, outside the frozen V3 adc_deaths table; "
            "therefore no frozen ADC death receives direct absorption context."
        ),
        "unavailable_feature_non_null_counts": {
            key: snapshot["adc_summary"][key]
            for key in (
                "shield_remaining_rows", "shield_unused_rows", "health_before_rows",
                "health_after_rows", "temporary_hp_before_rows", "temporary_hp_after_rows",
            )
        },
    }
    unavailable_payload = {
        "schema_version": 1,
        "status": "PASS",
        "required_behavior": "All unavailable values remain NULL; decoder unavailable is never reinterpreted as zero.",
        "exact_unavailable_fields": EXACT_UNAVAILABLE_FIELDS,
        "additional_unavailable_semantics": [
            "heal.reported_amount raw-versus-effective classification",
            "shield.remove_time and expiry/removal remainder",
            "packet.0x00ef DamageShieldedParams layout",
        ],
        "null_honesty_verifier": verify_summary["null_honesty"],
        "database_zero_row_surfaces": {
            "health_state_events": table_counts["health_state_events"],
            "temporary_hp_events": table_counts["temporary_hp_events"],
        },
        "authoritative_contract": "artifacts/protection_v4_probe/protection_v4_field_contract.json",
    }
    idempotence_payload = dict(idempotence_evidence)
    if idempotence_payload.get("status") == "PASS":
        run2_fingerprints = {
            table: value["run2"] for table, value in idempotence_payload["comparisons"].items()
        }
        database_mismatches = {
            table: {
                "database_row_count": table_counts[table],
                "attested_run2_row_count": entry["row_count"],
            }
            for table, entry in run2_fingerprints.items()
            if table_counts[table] != entry["row_count"]
        }
        if database_mismatches:
            raise RuntimeError(
                "Current read-only database row counts do not match attested run2: "
                + json.dumps(database_mismatches, sort_keys=True)
            )
        idempotence_payload["current_database_row_counts_match_attested_run2"] = True
    regression_payload = dict(regression_evidence)
    regression_payload["release_status"] = release_status
    regression_payload["v4_verifier_artifact"] = {
        "path": safe_relative(snapshot["verify_path"]),
        "sha256": sha256_file(snapshot["verify_path"]),
        "status": verify["status"],
        "failures": verify["failures"],
    }
    regression_payload["review_gate_note"] = (
        "Archive publication is permitted only after the hash-bound regression, independent code review, "
        "QA, and final gate attestation is PASS."
    )
    validation_scope = {
        "schema_version": 1,
        "status": "PASS",
        "real_replay_corpus": {
            "replays": 14,
            "on_event_packets": 103249,
            "on_event_fully_consumed": 103249,
            "raw_castspell_linked_anchors": 10,
            "shield_absorption_packets": 2,
            "shield_absorption_fully_consumed": 2,
            "same_target_same_timestamp_damage_neighbors": 2,
        },
        "frozen_v3_runtime_regression": {"matches": 1000, "total": 1000, "status": "PASS"},
        "holdout_scope": (
            "Four V4-only Replays extend beyond the frozen 10-Replay V3 database corpus; they are external-corpus "
            "validation, not a blinded statistical holdout."
        ),
        "controlled_replay": {
            "available": False,
            "used": False,
            "reason": "Direct packet amount fields were recovered and validated on real Replays; no synthetic formula value was used.",
        },
        "oracle_policy": "Match details and public mechanics were validation-only and never generated protection amounts.",
    }
    verifier_payload = {
        "schema_version": 1,
        "status": verify["status"],
        "failures": verify["failures"],
        "source_sha256": sha256_file(snapshot["verify_path"]),
        "profiles": verify_summary["profiles"],
        "v4": verify_summary["v4"],
        "null_honesty": verify_summary["null_honesty"],
        "v3_table_counts": verify_summary["v3"]["table_counts"],
    }
    source_scope = {
        "schema_version": 1,
        "status": "PASS",
        "git_diff_status": "NOT_AVAILABLE_REPOSITORY_HAS_NO_TRACKED_BASELINE",
        "substitute": "The package contains the relevant source/test files and the closed payload manifest hashes every file.",
        "frozen_v3_decoder": {
            "path": "scripts/emulate_exact_packet_decoder.py",
            "sha256": FROZEN_EMULATOR_SHA256,
        },
        "additive_v4_boundaries": [
            "research-v4/",
            "scripts/decode_on_event_protection_v4.py",
            "scripts/decode_shield_damage_v4.py",
            "research-v3/batch_ingest.py",
            "src/semantic_pipeline.js",
            "src/decoders/rofl_16_15_801_3452.js",
        ],
    }
    return {
        "profiles.json": profiles_payload,
        "protection_spell_inventory.json": inventory_payload,
        "corpus_counts_and_distributions.json": counts_payload,
        "shield_absorption_samples.json": {
            "schema_version": 1, "status": "PASS", "sample_count": len(absorption_samples),
            "samples": absorption_samples,
        },
        "adc_protection_summary.json": adc_payload,
        "unavailable_fields_and_null_honesty.json": unavailable_payload,
        "idempotence.json": idempotence_payload,
        "regression_summary.json": regression_payload,
        "validation_scope.json": validation_scope,
        "verifier_summary.json": verifier_payload,
        "source_scope.json": source_scope,
    }


def completion_report_text(snapshot: Mapping[str, Any], payloads: Mapping[str, Any], release_status: str) -> str:
    adc = payloads["adc_protection_summary.json"]
    unavailable = payloads["unavailable_fields_and_null_honesty.json"]
    regression = payloads["regression_summary.json"]
    inventory = snapshot["inventory_totals"]
    if release_status == "PROTECTION_V4_COMPLETE":
        release_note = (
            "Both completion routes are satisfied with real Replay-observed amounts: direct shield generation "
            "and target-total absorption, plus a direct reported heal amount. The final regression and review gates "
            "must be evidenced outside this self-referential archive hash."
        )
    else:
        release_note = (
            "Draft publication state. Protocol/data verification and regressions are recorded, but final archive "
            "publication is intentionally blocked until the independent code/QA/final gate is explicitly clear."
        )

    regression_rows = regression.get("commands") or []
    if regression_rows:
        test_lines = "\n".join(
            f"- `{row.get('command', row['id'])}` — **{row['status']}**: "
            f"{row.get('result', row.get('summary', 'see hash-bound evidence'))}"
            for row in regression_rows
        )
    else:
        test_lines = (
            f"- Final hash-bound regression/review attestation: **{regression.get('status', 'PENDING')}**. "
            f"Required input: `{regression.get('required_input', 'not yet supplied')}`."
        )
    unavailable_lines = "\n".join(f"- `{field}`" for field in unavailable["exact_unavailable_fields"])
    v3_counts = snapshot["verify"]["summary"]["v3"]["table_counts"]
    return f"""# Protection Telemetry V4 completion report

## A. STATUS

`{release_status}`

{release_note}

The protocol/data result meets Route A and Route B: `0x00ed` exposes direct shield generation,
`0x0017` exposes direct target-total shield absorption, and `0x004b` exposes a direct reported
heal amount. No Wiki formula or Match Details value is used as Replay telemetry.

## B. HEALTH STATE

- `health_state_events`: **0 rows**.
- Current HP and max HP remain unavailable and therefore `NULL`.
- No HP increase is relabeled as healing, regeneration, temporary HP, or max-HP change.

## C. SHIELD

- **generated**: **5,080** canonical `0x00ed OnReceiveShield` events, direct source, target,
  timestamp, raw order, and generated amount. The **4,752** `0x00ee OnGrantShield` rows are exact
  immediately preceding duplicate routes and are retained only in the raw shield-state surface.
- **remaining**: unavailable; `NULL`.
- **absorbed**: **2** direct `0x0017 PKT_UnitApplyShieldDamage_s` target-total events and **2**
  state transitions. Amounts are `375.13690185546875` and `30.030563354492188`. Target is direct;
  source and shield instance are unavailable. Both are in V4-only Replay `HN1-11184800649`.
- **unused**: unavailable; `NULL`.

Raw shield-state total: **9,834** = 5,080 receive + 4,752 grant + 2 absorption rows.

## D. HEAL

- Direct reported heal rows: **81,652**, each with direct source, target, timestamp, raw order,
  and reported amount.
- Exact full-parameter-blob representatives: **77,415**. This is a conservative grouping lower
  bound, not permission to discard the other raw rows.
- **raw**: unavailable; the reported amount has not been proven pre-overheal.
- **effective**: unavailable because HP-before/after telemetry is unavailable.
- **overheal**: unavailable because raw/effective separation is unavailable.

## E. TEMPORARY HP

- `temporary_hp_events`: **0 rows**.
- The inventory contains 33 temporary-HP candidate casts, but amount/start/end and temporary
  max-HP modification are unavailable. They remain `NULL`.

## F. ADC PROTECTION

- `adc_survival_features_v4`: **{adc['feature_rows']}** rows for all frozen ADC deaths.
- `adc_death_protection`: **{adc['adc_death_protection_rows']}** rows across
  **{adc['distinct_adc_deaths_with_positive_reported_protection']}** distinct ADC deaths.
- Distribution: **87** `HEAL_REPORTED` rows across 23 deaths and **41** `SHIELD_GENERATED`
  rows across 28 deaths.
- **{adc['positive_any_protection_deaths']}** deaths have any positive reported protection;
  27 have positive generated shield and 23 have a positive heal-report upper bound.
- Direct absorption context in frozen ADC deaths: **0**. Both direct absorption samples are in a
  V4-only Replay that is not present in the frozen `adc_deaths` table.

## G. V3 REGRESSION

- Frozen decoder SHA-256: `{FROZEN_EMULATOR_SHA256}`.
- V3 runtime packet regression: **1,000 / 1,000 exact matches**.
- Final hash-bound regression/review attestation: **{regression.get('status', 'PENDING')}**.
- Exact final test counts, V3 verifier classification, and their log hashes are accepted only from
  the attested regression input; this report does not hard-code a prior run's result.
- Frozen baseline counts remain exact, including replays={v3_counts['replays']},
  damage_events={v3_counts['damage_events']}, spell_events={v3_counts['spell_events']},
  buff_events={v3_counts['buff_events']}, ward_spawns={v3_counts['ward_spawns']}, and
  adc_deaths={v3_counts['adc_deaths']}.

## H. TESTS

{test_lines}

The selected V4 verifier artifact reports `{snapshot['verify']['status']}` with
`{len(snapshot['verify']['failures'])}` failures. Archive release status is separately gated by
Section A so a passing data verifier cannot silently override a pending independent code/QA/final
review.

## I. REVIEW PACKAGE

- Target: `protection-v4-independent-review-lite.zip`, hard limit **20 MiB**.
- The archive is written only when `--release-status PROTECTION_V4_COMPLETE` is explicit.
- `package_manifest.json` is a closed payload manifest covering every archive file except itself;
  its self-exclusion is documented to avoid recursive hashing.
- The external adjacent manifest covers the archive and the internal manifest. Adjacent SHA-256
  files cover both the archive and external manifest.
- The builder writes the archive twice with fixed timestamps, sorted paths, fixed permissions,
  and compression settings; byte-identical SHA-256 is required.
- Explicit exclusions: DuckDB, `.rofl`, runtime memory images, exhaustive `0x009e`/OnEvent JSONL,
  decoded full damage JSONL, and existing archives.

The exact archive hash/size are published only in the adjacent external manifest; embedding the
archive hash inside the archive would be self-referential.

## J. STILL-UNAVAILABLE FIELDS

{unavailable_lines}

Also unavailable: raw-versus-effective semantics for `heal.reported_amount`, shield removal
time/remainder, and the unobserved `0x00ef DamageShieldedParams` layout. These fields must remain
`NULL` or explicitly `UNAVAILABLE`; they must never become zero through decoder failure or
missing evidence.

Inventory evidence: **{inventory['rows']} rows / {inventory['casts']} casts /
{inventory['targets']} target references / {inventory['buff_candidates']} Buff candidates /
{inventory['damage_windows']} damage windows**.
"""


def review_start_text(release_status: str) -> str:
    return f"""# Protection V4 independent review: start here

Release status: `{release_status}`

Review in this order:

1. `docs/PROTECTION_V4_COMPLETION_REPORT.md` for the required A-J result.
2. `docs/PROTECTION_V4_CAPABILITY_MATRIX.md` and
   `artifacts/protection_v4_probe/protection_v4_field_contract.json` for the authoritative
   field/null contract.
3. `artifacts/protection_v4_publication/` for compact database exports, idempotence,
   regression, validation scope, and source-scope evidence.
4. The two V4 reverse-engineering reports and current-client static selections.
5. `artifacts/protection_v4_probe/protection_raw_anchors.json` and the two compact
   `0x0017` samples for raw-to-semantic traceability.
6. `package_manifest.json` for the closed payload file set and SHA-256 values.

After extraction, verify the closed payload without DuckDB:

```powershell
python research-v4/export_review_artifacts.py --validate-extracted .
```

The DuckDB, Replays, runtime memory image, and exhaustive packet JSONLs are deliberately excluded.
They are not needed to audit the published source, contracts, bounded evidence, and database
summaries. Re-decoding the full corpus requires those external inputs.
"""


def code_source_paths() -> list[Path]:
    paths: set[Path] = {ROOT / "package.json"}
    for directory, suffixes in (
        (ROOT / "src", {".js"}),
        (ROOT / "test", {".js"}),
        (ROOT / "research-v3", {".py", ".sql", ".md"}),
        (ROOT / "research-v4", {".py", ".sql", ".md"}),
    ):
        for path in directory.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in suffixes:
                continue
            relative = path.relative_to(directory).as_posix()
            if relative.startswith("output/") or "/__pycache__/" in f"/{relative}/":
                continue
            paths.add(path)
    for relative in (
        "scripts/emulate_exact_packet_decoder.py",
        "scripts/decode_on_event_protection_v4.py",
        "scripts/decode_shield_damage_v4.py",
        "scripts/build_protection_v4_raw_anchors.py",
        "scripts/export_selected_packets.js",
    ):
        paths.add(ROOT / relative)
    return sorted(paths, key=lambda path: safe_relative(path))


def evidence_source_paths() -> list[Path]:
    relative_paths = [
        "docs/PROTECTION_V4_COMPLETION_REPORT.md",
        "docs/PROTECTION_V4_CAPABILITY_MATRIX.md",
        "docs/PROTECTION_V4_ON_EVENT_RE_REPORT.md",
        "docs/PROTECTION_V4_SHIELD_DAMAGE_RE_REPORT.md",
        "docs/V2_REGRESSION.md",
        "artifacts/protection_v4_probe/protection_v4_field_contract.json",
        "artifacts/protection_v4_probe/on_event_protection_field_contract.json",
        "artifacts/protection_v4_probe/on_event_protection_decoded_all14.summary.json",
        "artifacts/protection_v4_probe/protection_raw_anchors.json",
        "artifacts/protection_v4_probe/packet_0017_all14.jsonl",
        "artifacts/protection_v4_probe/packet_0017_all14.jsonl.manifest.json",
        "artifacts/protection_v4_probe/shield_damage_decoded_all14.jsonl",
        "artifacts/protection_v4_probe/shield_damage_decoded_all14.summary.json",
        "artifacts/protection_v4_probe/HN1-11184800649_damage_decoded_summary.json",
        "artifacts/protection_v4_probe/v3_regression_unit_apply_damage_runtime_validation.summary.json",
        "artifacts/protection_v4_probe/protection_v4_verify_attested_run1.json",
        "artifacts/protection_v4_probe/protection_v4_verify_attested_run2.json",
        "artifacts/protection_v4_probe/protection_v4_regression_attested.json",
        "artifacts/protection_v4_probe/on_event_constructor_probe.json",
        "artifacts/protection_v4_probe/on_event_registration_consumer_disassembly.json",
        "artifacts/protection_v4_probe/protection_event_registration_disassembly.json",
        "artifacts/protection_v4_probe/protection_event_handler_exact_entries.json",
        "artifacts/protection_v4_probe/params_heal_handler.json",
        "artifacts/protection_v4_probe/shield_damage_deserializer_f1db80.json",
        "artifacts/protection_v4_probe/shield_damage_callback_29ed80.json",
        "artifacts/protection_v4_probe/shield_damage_factory_case_ede280.json",
        "artifacts/runtime_probe/buff_validation_summary.json",
        "artifacts/runtime_probe/buff_lifecycle_anchors.json",
        ".omo/evidence/protection-v4-validation.json",
        ".omo/evidence/protection-v4-attestation-boundary.md",
        ".omo/evidence/protection-v4-code-review.md",
        ".omo/evidence/semantic_absorption_integration-code-review.md",
    ]
    paths = [ROOT / relative for relative in relative_paths]
    # Include later V4 QA/review/gate artifacts automatically when their names are explicit.
    evidence_dir = ROOT / ".omo" / "evidence"
    for pattern in ("protection-v4-*.md", "protection-v4-*.json"):
        paths.extend(
            path for path in evidence_dir.glob(pattern)
            if path.name not in {
                "protection-v4-publication-package.md",
                # This report is necessarily generated after the archive exists;
                # including it would create a stale/self-referential archive hash.
                "protection-v4-final-gate-postpackage.md",
            }
        )
    final_qa = evidence_dir / "protection-v4-final-qa"
    for name in (
        "regression-npm-test.log",
        "regression-v3-tests.log",
        "regression-v4-tests-final.log",
        "scenario-adversarial-tests.log",
        "scenario1-js-result.json",
        "scenario2-query-final.json",
        "scenario3-after.json",
        "scenario4-summary-final.json",
        "scenario4-verify-v4-final.json",
        "scenario5-summary-final.json",
        "scenario5-verify-v3-final.json",
    ):
        candidate = final_qa / name
        if candidate.is_file():
            paths.append(candidate)
    return sorted(set(paths), key=lambda path: safe_relative(path))


def publication_payload_paths(output_dir: Path) -> list[Path]:
    excluded = {
        "lite_package_payload_manifest.json",
        "build_validation.json",
        "publication_file_hashes.json",
    }
    return sorted(
        [path for path in output_dir.iterdir() if path.is_file() and path.name not in excluded],
        key=lambda path: path.name,
    )


def role_for(relative: str) -> str:
    if relative == "AI_HANDOFF.md":
        return "review-entrypoint"
    if relative.startswith("research-v4/") or relative.startswith("research-v3/"):
        return "source-or-test"
    if relative.startswith("src/") or relative.startswith("test/") or relative == "package.json":
        return "source-or-test"
    if relative.startswith("scripts/"):
        return "decoder-or-build-source"
    if relative.startswith("docs/"):
        return "report-or-contract"
    if relative.startswith("artifacts/protection_v4_publication/"):
        return "compact-publication-export"
    if "static" in relative or relative.endswith("disassembly.json") or "handler" in relative:
        return "current-client-static-evidence"
    if relative.startswith(".omo/evidence/"):
        return "review-or-validation-evidence"
    return "bounded-protocol-evidence"


def prepare_output_directory(output_dir: Path) -> None:
    resolved = output_dir.resolve()
    expected_parent = (ROOT / "artifacts").resolve()
    if resolved.parent != expected_parent or not resolved.name.startswith("protection_v4_publication"):
        raise RuntimeError(f"Refusing to replace unexpected output directory: {resolved}")
    if resolved.exists():
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True, exist_ok=True)


def write_publication_artifacts(
    snapshot: Mapping[str, Any],
    output_dir: Path,
    release_status: str,
    idempotence_evidence: Mapping[str, Any],
    regression_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    prepare_output_directory(output_dir)
    payloads = build_payloads(
        snapshot, release_status, idempotence_evidence, regression_evidence
    )
    for name, value in payloads.items():
        write_json(output_dir / name, value)

    profile_columns = [
        "replay_sha256", "game_id", "patch", "profile_status", "decoded_row_count",
        "protection_row_count", "v4_schema_version", "on_event_decoder_status",
        "shield_damage_decoder_status", "in_frozen_v3", "v4_only_profile",
    ]
    write_csv(output_dir / "profiles.csv", profile_columns, snapshot["profiles"])
    inventory_columns = [
        "fact_id", "replay_sha256", "game_id", "champion", "spell_identifier", "spell_slot",
        "protection_cast_kind", "cast_count", "target_count", "buff_candidate_count",
        "damage_window_count", "first_cast_ms", "last_cast_ms",
    ]
    write_csv(output_dir / "protection_spell_inventory.csv", inventory_columns, snapshot["inventory"])
    write_text(output_dir / "review_start_here.md", review_start_text(release_status))

    source_inventory = {
        "schema_version": 1,
        "status": "PASS",
        "git_diff_status": "NOT_AVAILABLE_REPOSITORY_HAS_NO_TRACKED_BASELINE",
        "file_count": 0,
        "files": {},
    }
    for path in code_source_paths():
        if not path.is_file():
            raise FileNotFoundError(path)
        relative = safe_relative(path)
        source_inventory["files"][relative] = {
            "size_bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    source_inventory["file_count"] = len(source_inventory["files"])
    write_json(output_dir / "source_file_inventory.json", source_inventory)

    write_text(COMPLETION_REPORT, completion_report_text(snapshot, payloads, release_status))
    return payloads


def archive_path_is_forbidden(relative: str) -> bool:
    lowered = relative.lower()
    return any(marker in lowered for marker in FORBIDDEN_ARCHIVE_MARKERS)


def validate_archive_name(relative: str) -> None:
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise RuntimeError(f"Unsafe archive path: {relative!r}")
    if "\\" in relative:
        raise RuntimeError(f"Archive path must use forward slashes: {relative!r}")
    if archive_path_is_forbidden(relative):
        raise RuntimeError(f"Forbidden file selected for lite archive: {relative!r}")


def copy_stage_file(stage_root: Path, source: Path, relative: str) -> dict[str, Any]:
    validate_archive_name(relative)
    if not source.is_file():
        raise FileNotFoundError(source)
    data = source.read_bytes()
    destination = stage_root / Path(*PurePosixPath(relative).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return {"size_bytes": len(data), "sha256": sha256_bytes(data), "role": role_for(relative)}


def stage_review_payload(
    stage_root: Path,
    output_dir: Path,
    release_status: str,
    payloads: Mapping[str, Any],
) -> dict[str, Any]:
    selected: dict[str, Path] = {}
    referenced: list[Path] = []
    idempotence = payloads.get("idempotence.json", {})
    for source_entry in (idempotence.get("sources") or {}).values():
        if isinstance(source_entry, dict) and isinstance(source_entry.get("path"), str):
            referenced.append(ROOT / source_entry["path"])
    regression = payloads.get("regression_summary.json", {})
    regression_source = regression.get("source")
    if isinstance(regression_source, dict) and isinstance(regression_source.get("path"), str):
        referenced.append(ROOT / regression_source["path"])
    for row in regression.get("commands") or []:
        evidence = row.get("evidence") if isinstance(row, dict) else None
        if isinstance(evidence, dict) and isinstance(evidence.get("path"), str):
            referenced.append(ROOT / evidence["path"])

    all_sources = (
        code_source_paths()
        + evidence_source_paths()
        + publication_payload_paths(output_dir)
        + referenced
    )
    for source in all_sources:
        if not source.is_file():
            raise FileNotFoundError(f"Required review payload file is missing: {source}")
        relative = safe_relative(source)
        prior = selected.get(relative)
        if prior is not None and prior.resolve() != source.resolve():
            raise RuntimeError(f"Duplicate archive path {relative!r}: {prior} and {source}")
        selected[relative] = source

    review_entry = stage_root / "AI_HANDOFF.md"
    write_text(review_entry, review_start_text(release_status))
    files: dict[str, Any] = {
        "AI_HANDOFF.md": {
            "size_bytes": review_entry.stat().st_size,
            "sha256": sha256_file(review_entry),
            "role": "review-entrypoint",
        }
    }
    for relative, source in sorted(selected.items()):
        files[relative] = copy_stage_file(stage_root, source, relative)

    manifest = {
        "schema_version": 1,
        "package": "protection-v4-independent-review-lite",
        "status": "PASS",
        "release_status": release_status,
        "closed_payload": True,
        "file_count_excluding_manifest": len(files),
        "manifest_path": "package_manifest.json",
        "manifest_self_exclusion": (
            "package_manifest.json is intentionally excluded from files to avoid a recursive self-hash; "
            "the adjacent external publication manifest records its exact hash and size."
        ),
        "deterministic_zip_policy": {
            "entry_order": "lexicographic POSIX path",
            "entry_timestamp": "2026-08-11T00:00:00",
            "entry_mode": "0644 regular file",
            "compression": "DEFLATE level 9",
            "directory_entries": False,
        },
        "deliberately_excluded": [
            "research-v3/output/replay_research.duckdb and every other DuckDB",
            "all .rofl Replay files",
            "runtime memory image league_16.15.801.3452.memory.bin",
            "on_event_protection_decoded_all14.jsonl",
            "packet_009e_all14.jsonl and packet_009e_decoded_all14.jsonl",
            "full decoded damage JSONL and other large packet corpora",
            "all pre-existing archives",
        ],
        "files": files,
    }
    write_json(stage_root / "package_manifest.json", manifest)
    actual_files = sorted(
        path.relative_to(stage_root).as_posix() for path in stage_root.rglob("*") if path.is_file()
    )
    expected_files = sorted([*files, "package_manifest.json"])
    if actual_files != expected_files:
        raise RuntimeError(
            f"Stage is not a closed payload: actual={actual_files!r}, expected={expected_files!r}"
        )
    return manifest


def write_deterministic_zip(stage_root: Path, zip_path: Path) -> None:
    if zip_path.exists():
        zip_path.unlink()
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    source_files = sorted(
        (path.relative_to(stage_root).as_posix(), path)
        for path in stage_root.rglob("*")
        if path.is_file()
    )
    with zipfile.ZipFile(
        zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=True
    ) as archive:
        for relative, source in source_files:
            validate_archive_name(relative)
            info = zipfile.ZipInfo(relative, FIXED_ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100644 & 0xFFFF) << 16
            info.flag_bits |= 0x800
            archive.writestr(info, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def validate_zip_archive(zip_path: Path) -> dict[str, Any]:
    if not zip_path.is_file():
        raise FileNotFoundError(zip_path)
    size_bytes = zip_path.stat().st_size
    if size_bytes > MAX_ARCHIVE_BYTES:
        raise RuntimeError(f"Archive exceeds 20 MiB: {size_bytes} bytes")
    with zipfile.ZipFile(zip_path, "r") as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise RuntimeError("Archive contains duplicate entry names")
        if any(info.is_dir() for info in infos):
            raise RuntimeError("Archive contains directory entries; deterministic policy allows files only")
        for name in names:
            validate_archive_name(name)
        if "package_manifest.json" not in names:
            raise RuntimeError("Archive is missing package_manifest.json")
        manifest_bytes = archive.read("package_manifest.json")
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        file_entries = manifest.get("files")
        if not isinstance(file_entries, dict):
            raise RuntimeError("Internal manifest files object is invalid")
        expected_names = sorted([*file_entries, "package_manifest.json"])
        if sorted(names) != expected_names:
            raise RuntimeError("Archive entry set does not exactly match the closed internal manifest")
        mismatches: list[dict[str, Any]] = []
        for name, expected in file_entries.items():
            data = archive.read(name)
            actual = {"size_bytes": len(data), "sha256": sha256_bytes(data)}
            if actual["size_bytes"] != expected.get("size_bytes") or actual["sha256"] != expected.get("sha256"):
                mismatches.append({"path": name, "actual": actual, "expected": expected})
        if mismatches:
            raise RuntimeError(f"Archive payload hash mismatch(es): {mismatches!r}")
    return {
        "status": "PASS",
        "path": zip_path.name,
        "size_bytes": size_bytes,
        "sha256": sha256_file(zip_path),
        "entry_count": len(names),
        "payload_file_count": len(file_entries),
        "internal_manifest": {
            "archive_path": "package_manifest.json",
            "size_bytes": len(manifest_bytes),
            "sha256": sha256_bytes(manifest_bytes),
        },
        "closed_payload": True,
        "forbidden_file_absence": True,
        "within_20_mib": True,
    }


def validate_extracted_package(root: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest_path = root / "package_manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest.get("files")
    if not isinstance(entries, dict):
        raise RuntimeError("Internal manifest files object is invalid")
    actual_names = sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())
    expected_names = sorted([*entries, "package_manifest.json"])
    if actual_names != expected_names:
        raise RuntimeError("Extracted file set does not exactly match the closed internal manifest")
    for relative, expected in entries.items():
        validate_archive_name(relative)
        source = root / Path(*PurePosixPath(relative).parts)
        if source.stat().st_size != expected.get("size_bytes") or sha256_file(source) != expected.get("sha256"):
            raise RuntimeError(f"Extracted payload mismatch: {relative}")
    return {
        "status": "PASS",
        "root": str(root),
        "payload_file_count": len(entries),
        "closed_payload": True,
        "forbidden_file_absence": True,
    }


def write_sha256_sidecar(path: Path, digest: str, target_name: str) -> None:
    write_text(path, f"{digest}  {target_name}")


def build_final_package(
    *,
    output_dir: Path,
    zip_path: Path,
    external_manifest_path: Path,
    zip_hash_path: Path,
    manifest_hash_path: Path,
    release_status: str,
    payloads: Mapping[str, Any],
) -> dict[str, Any]:
    if release_status != "PROTECTION_V4_COMPLETE":
        raise RuntimeError("Final ZIP publication requires explicit PROTECTION_V4_COMPLETE")
    idempotence = payloads["idempotence.json"]
    regression = payloads["regression_summary.json"]
    if idempotence.get("status") != "PASS" or not idempotence.get("all_semantic_fingerprints_equal"):
        raise RuntimeError("Final ZIP publication requires real attested run1/run2 idempotence PASS")
    if regression.get("status") != "PASS" or regression.get("failed_ids"):
        raise RuntimeError("Final ZIP publication requires hash-bound regression/review attestation PASS")

    owned_outputs = [
        zip_path, external_manifest_path, zip_hash_path, manifest_hash_path, PACKAGE_EVIDENCE,
    ]
    for path in owned_outputs:
        if path.exists():
            path.unlink()

    artifacts_root = (ROOT / "artifacts").resolve()
    try:
        with (
            tempfile.TemporaryDirectory(
                prefix="protection-v4-review-stage-a-", dir=artifacts_root
            ) as first_stage_name,
            tempfile.TemporaryDirectory(
                prefix="protection-v4-review-stage-b-", dir=artifacts_root
            ) as second_stage_name,
            tempfile.TemporaryDirectory(
                prefix="protection-v4-second-build-", dir=artifacts_root
            ) as second_output_name,
        ):
            first_stage = Path(first_stage_name)
            second_stage = Path(second_stage_name)
            internal_manifest = stage_review_payload(
                first_stage, output_dir, release_status, payloads
            )
            second_internal_manifest = stage_review_payload(
                second_stage, output_dir, release_status, payloads
            )
            internal_manifest_path = first_stage / "package_manifest.json"
            second_internal_manifest_path = second_stage / "package_manifest.json"
            internal_manifest_bytes = internal_manifest_path.read_bytes()
            second_internal_manifest_bytes = second_internal_manifest_path.read_bytes()
            if internal_manifest_bytes != second_internal_manifest_bytes:
                raise RuntimeError("Independent staging passes produced different payload manifests")
            if internal_manifest != second_internal_manifest:
                raise RuntimeError("Independent staging manifest objects differ")
            shutil.copyfile(
                internal_manifest_path, output_dir / "lite_package_payload_manifest.json"
            )

            second_zip = Path(second_output_name) / zip_path.name
            write_deterministic_zip(first_stage, zip_path)
            write_deterministic_zip(second_stage, second_zip)
            first_validation = validate_zip_archive(zip_path)
            second_validation = validate_zip_archive(second_zip)
            if first_validation["sha256"] != second_validation["sha256"]:
                raise RuntimeError(
                    "Two deterministic builds are not byte-identical: "
                    f"{first_validation['sha256']} != {second_validation['sha256']}"
                )
            if zip_path.read_bytes() != second_zip.read_bytes():
                raise RuntimeError("Two deterministic builds have unequal bytes despite hash comparison")

            build_validation = {
                "schema_version": 1,
                "status": "PASS",
                "release_status": release_status,
                "archive": first_validation,
                "second_independent_build": second_validation,
                "independent_staging_manifests_equal": True,
                "byte_identical": True,
                "sha256_identical": True,
                "max_archive_bytes": MAX_ARCHIVE_BYTES,
                "forbidden_markers": list(FORBIDDEN_ARCHIVE_MARKERS),
                "internal_manifest_file_count_excluding_manifest": internal_manifest[
                    "file_count_excluding_manifest"
                ],
                "internal_manifest_self_exclusion_documented": True,
            }
            write_json(output_dir / "build_validation.json", build_validation)

            publication_hashes = {
                safe_relative(path): {
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                }
                for path in sorted(output_dir.iterdir(), key=lambda value: value.name)
                if path.is_file() and path.name != "publication_file_hashes.json"
            }
            write_json(output_dir / "publication_file_hashes.json", {
                "schema_version": 1,
                "status": "PASS",
                "self_exclusion": (
                    "publication_file_hashes.json is excluded from its own files map to avoid recursion."
                ),
                "file_count_excluding_self": len(publication_hashes),
                "files": publication_hashes,
            })

            external_manifest = {
                "schema_version": 1,
                "status": "PASS",
                "release_status": release_status,
                "archive": first_validation,
                "internal_payload_manifest": {
                    "archive_path": "package_manifest.json",
                    "extracted_copy_path": safe_relative(
                        output_dir / "lite_package_payload_manifest.json"
                    ),
                    "size_bytes": len(internal_manifest_bytes),
                    "sha256": sha256_bytes(internal_manifest_bytes),
                    "self_exclusion_documented": True,
                },
                "publication_file_hashes": {
                    "path": safe_relative(output_dir / "publication_file_hashes.json"),
                    "size_bytes": (output_dir / "publication_file_hashes.json").stat().st_size,
                    "sha256": sha256_file(output_dir / "publication_file_hashes.json"),
                },
                "determinism": {
                    "build_count": 2,
                    "byte_identical": True,
                    "sha256_identical": True,
                    "sha256": first_validation["sha256"],
                },
                "external_manifest_self_exclusion": (
                    "This manifest does not hash itself; its adjacent .sha256 sidecar does."
                ),
            }
            write_json(external_manifest_path, external_manifest)
            write_sha256_sidecar(zip_hash_path, first_validation["sha256"], zip_path.name)
            external_hash = sha256_file(external_manifest_path)
            write_sha256_sidecar(
                manifest_hash_path, external_hash, external_manifest_path.name
            )

            evidence_text = f"""# Protection V4 publication package evidence

- Status: PASS
- Archive: `{zip_path.name}`
- Size: {first_validation['size_bytes']} bytes (limit {MAX_ARCHIVE_BYTES})
- SHA-256: `{first_validation['sha256']}`
- Entries: {first_validation['entry_count']}
- Closed payload manifest: PASS; {first_validation['payload_file_count']} payload files
- Forbidden-file absence: PASS
- Two independent deterministic builds byte-identical: PASS
- Internal manifest SHA-256: `{first_validation['internal_manifest']['sha256']}`
- External manifest: `{external_manifest_path.name}`
"""
            evidence_path = PACKAGE_EVIDENCE
            write_text(evidence_path, evidence_text)
            return {
                "status": "PASS",
                "archive": first_validation,
                "external_manifest": {
                    "path": external_manifest_path.name,
                    "sha256": external_hash,
                },
                "zip_hash_sidecar": zip_hash_path.name,
                "manifest_hash_sidecar": manifest_hash_path.name,
                "deterministic_builds_equal": True,
                "evidence_path": safe_relative(evidence_path),
            }
    except Exception:
        for path in owned_outputs:
            if path.exists():
                path.unlink()
        raise


def describe_required_inputs() -> dict[str, Any]:
    return {
        "status": "INPUTS_REQUIRED_BEFORE_FINAL_PUBLICATION",
        "database": safe_relative(DEFAULT_DB),
        "attested_v4_verifier_run1": safe_relative(DEFAULT_IDEMPOTENCE_RUN1),
        "attested_v4_verifier_run2": safe_relative(DEFAULT_IDEMPOTENCE_RUN2),
        "final_verify_input": safe_relative(DEFAULT_VERIFY),
        "regression_attestation": {
            "path": safe_relative(DEFAULT_REGRESSION_ATTESTATION),
            "required_ids": sorted(REQUIRED_REGRESSION_IDS),
            "entry_schema": {
                "id": "one required id",
                "command": "exact executed command or review label",
                "status": "PASS",
                "result": "bounded observed result",
                "evidence": {
                    "path": "repository-relative evidence path",
                    "size_bytes": "integer",
                    "sha256": "64 lowercase hex characters",
                },
            },
            "top_level_schema": {
                "schema_version": 1,
                "status": "PASS only when every required entry is PASS",
                "commands": "array of entry_schema objects",
                "metadata": "optional object",
            },
        },
        "final_build_command": (
            "python -B research-v4/export_review_artifacts.py "
            "--release-status PROTECTION_V4_COMPLETE"
        ),
        "draft_command_before_run2": (
            "python -B research-v4/export_review_artifacts.py "
            "--release-status PENDING_FINAL_QA_REVIEW "
            "--verify artifacts/protection_v4_probe/protection_v4_verify_attested_run1.json"
        ),
        "policy": (
            "The final command refuses ZIP output unless both real attested verifier runs match "
            "across all 10 semantic fingerprints and the hash-bound regression/review attestation is PASS."
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--verify", type=Path, default=DEFAULT_VERIFY)
    parser.add_argument("--idempotence-run1", type=Path, default=DEFAULT_IDEMPOTENCE_RUN1)
    parser.add_argument("--idempotence-run2", type=Path, default=DEFAULT_IDEMPOTENCE_RUN2)
    parser.add_argument("--regression-attestation", type=Path, default=DEFAULT_REGRESSION_ATTESTATION)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--zip", dest="zip_path", type=Path, default=DEFAULT_ZIP)
    parser.add_argument("--external-manifest", type=Path, default=DEFAULT_EXTERNAL_MANIFEST)
    parser.add_argument("--zip-hash", type=Path, default=DEFAULT_ZIP_HASH)
    parser.add_argument("--manifest-hash", type=Path, default=DEFAULT_MANIFEST_HASH)
    parser.add_argument(
        "--release-status",
        choices=("PENDING_FINAL_QA_REVIEW", "PROTECTION_V4_COMPLETE"),
        default="PENDING_FINAL_QA_REVIEW",
    )
    parser.add_argument("--validate-zip", type=Path)
    parser.add_argument("--validate-extracted", type=Path)
    parser.add_argument("--describe-inputs", action="store_true")
    options = parser.parse_args(argv)

    if options.describe_inputs:
        print(json.dumps(describe_required_inputs(), indent=2, sort_keys=True))
        return 0
    if options.validate_zip:
        print(json.dumps(validate_zip_archive(options.validate_zip), indent=2, sort_keys=True))
        return 0
    if options.validate_extracted:
        print(json.dumps(validate_extracted_package(options.validate_extracted), indent=2, sort_keys=True))
        return 0

    final_release = options.release_status == "PROTECTION_V4_COMPLETE"
    idempotence = load_idempotence_evidence(
        options.idempotence_run1.resolve(),
        options.idempotence_run2.resolve(),
        allow_pending=not final_release,
    )
    regression = load_regression_attestation(
        options.regression_attestation.resolve(), allow_pending=not final_release
    )
    if final_release and options.verify.resolve() != options.idempotence_run2.resolve():
        raise RuntimeError("Final --verify must be the exact attested idempotence run2 artifact")
    snapshot = load_snapshot(options.db.resolve(), options.verify.resolve())
    payloads = write_publication_artifacts(
        snapshot,
        options.output_dir.resolve(),
        options.release_status,
        idempotence,
        regression,
    )
    result: dict[str, Any] = {
        "status": options.release_status,
        "completion_report": str(COMPLETION_REPORT.resolve()),
        "publication_output": str(options.output_dir.resolve()),
        "idempotence_status": idempotence["status"],
        "regression_attestation_status": regression["status"],
        "final_zip_written": False,
    }
    if final_release:
        try:
            result["package"] = build_final_package(
                output_dir=options.output_dir.resolve(),
                zip_path=options.zip_path.resolve(),
                external_manifest_path=options.external_manifest.resolve(),
                zip_hash_path=options.zip_hash.resolve(),
                manifest_hash_path=options.manifest_hash.resolve(),
                release_status=options.release_status,
                payloads=payloads,
            )
            result["final_zip_written"] = True
        except Exception:
            write_publication_artifacts(
                snapshot,
                options.output_dir.resolve(),
                "PENDING_FINAL_QA_REVIEW",
                idempotence,
                regression,
            )
            raise
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
