"""Materialize the V3 research-facing DuckDB tables and publications.

The base ingest preserves decoded facts.  This module builds stable research
surfaces on top of those facts while keeping direct and derived semantics
explicit.  In particular, WardSpawn coordinates remain direct packet object
writes and one-second hero positions remain VERIFIED_DERIVED.
"""

from __future__ import annotations

import json
import hashlib
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import duckdb

try:
    from .core import DEFAULT_DB, compact_json, stable_id
    from .position_context import (
        DEFAULT_MAX_POSITION_AGE_MS,
        PositionIndex,
        build_adc_death_position_context,
        build_ward_death_context,
        build_ward_position_context,
        participant_network_id,
    )
    from .ward_analysis import analyze_ward_rows, assign_regions, load_region_map
    from .combat_attribution import (
        capability_status as combat_capability_status,
        enrich_damage_events, load_spell_dictionary,
    )
except ImportError:  # direct: python research-v3/research_layer.py
    from core import DEFAULT_DB, compact_json, stable_id
    from position_context import (
        DEFAULT_MAX_POSITION_AGE_MS,
        PositionIndex,
        build_adc_death_position_context,
        build_ward_death_context,
        build_ward_position_context,
        participant_network_id,
    )
    from ward_analysis import analyze_ward_rows, assign_regions, load_region_map
    from combat_attribution import (
        capability_status as combat_capability_status,
        enrich_damage_events, load_spell_dictionary,
    )


OUTPUT_DIR = Path(__file__).resolve().parent / "output"
DEFAULT_STATUS_PATH = OUTPUT_DIR / "research_status.json"
DEFAULT_REPORT_PATH = OUTPUT_DIR / "FIRST_RESEARCH_SANITY_REPORT.md"
DEFAULT_PARQUET_DIR = OUTPUT_DIR / "parquet"
DEFAULT_PUBLICATION_MANIFEST_PATH = OUTPUT_DIR / "publication_manifest.json"
DEFAULT_GRID_CELL_SIZES = (100.0, 200.0)
DEFAULT_HOTSPOT_CELL_SIZE = 1000.0
SPELL_DICTIONARY_PATH = (
    Path(__file__).resolve().parent.parent / "artifacts" / "runtime_probe"
    / "spell_dictionary_16.15.json"
)

RESEARCH_EXPORT_TABLES = (
    "replays", "participants", "death_events", "damage_events", "spell_events",
    "buff_events", "ward_spawns", "ward_lifecycles", "hero_paths",
    "hero_positions_1s", "adc_deaths", "adc_death_damage",
    "adc_death_support_actions", "ward_research_events",
    "ward_position_context", "map_regions", "ward_heatmap_cells",
    "ward_hotspots", "adc_death_position_context", "adc_death_features",
    "ward_death_context",
)


def sha256_file(path: str | Path) -> str:
    """Return the SHA-256 of a publication artifact without loading it all at once."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def publication_paths(db_path: str | Path) -> dict[str, Path]:
    """Keep every publication artifact beside the database it describes."""
    db_path = Path(db_path).resolve()
    root = db_path.parent
    return {
        "status": root / DEFAULT_STATUS_PATH.name,
        "report": root / DEFAULT_REPORT_PATH.name,
        "parquet": root / DEFAULT_PARQUET_DIR.name,
        "manifest": root / DEFAULT_PUBLICATION_MANIFEST_PATH.name,
    }


def _json(value: Any) -> Any:
    if value is None or isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return value


def _dict_rows(connection: duckdb.DuckDBPyConnection, sql: str,
               parameters: Sequence[Any] | None = None) -> list[dict[str, Any]]:
    cursor = connection.execute(sql, list(parameters or ()))
    columns = [item[0] for item in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _percentile(sorted_values: Sequence[float], fraction: float) -> float | None:
    if not sorted_values:
        return None
    index = (len(sorted_values) - 1) * fraction
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return float(sorted_values[lower])
    weight = index - lower
    return float(sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight)


def _distribution(rows: Iterable[Mapping[str, Any]], key: str) -> dict[str, int]:
    values = Counter("UNKNOWN" if row.get(key) is None else str(row.get(key)) for row in rows)
    return dict(sorted(values.items(), key=lambda item: (-item[1], item[0])))


def _ensure_position_semantics(connection: duckdb.DuckDBPyConnection) -> None:
    """Migrate an early V3 base DB without re-decoding the immutable stream."""
    columns = {
        row[1] for row in connection.execute(
            "PRAGMA table_info('hero_positions_1s')"
        ).fetchall()
    }
    additions = {
        "source_age_ms": "BIGINT",
        "interpolation_method": "VARCHAR",
        "position_status": "VARCHAR",
        "raw_packet_ref": "JSON",
    }
    for column, data_type in additions.items():
        if column not in columns:
            connection.execute(
                f"ALTER TABLE hero_positions_1s ADD COLUMN {column} {data_type}"
            )
    connection.execute("""
        UPDATE hero_positions_1s SET
          source_age_ms = coalesce(source_age_ms, replay_time_ms-source_path_timestamp_ms),
          interpolation_method =
            'PATH_WAYPOINT_LINEAR_INTERPOLATION_WITH_TERMINAL_HOLD',
          position_status = 'VERIFIED_DERIVED',
          raw_packet_ref = coalesce(
            raw_packet_ref, json_extract(raw_provenance_json, '$.raw_packet_ref')
          ),
          confidence = 'VERIFIED_DERIVED'
    """)


def _ensure_damage_semantics(connection: duckdb.DuckDBPyConnection) -> dict[str, int]:
    """Apply packet-field combat interpretations without a Details input."""
    columns = {
        row[1] for row in connection.execute(
            "PRAGMA table_info('damage_events')"
        ).fetchall()
    }
    additions = {
        "damage_type_code": "INTEGER",
        "damage_type_status": "VARCHAR",
        "damage_spell_key": "BIGINT",
        "spell_attribution_status": "VARCHAR",
        "basic_attack_status": "VARCHAR",
        "is_critical": "BOOLEAN",
        "critical_status": "VARCHAR",
    }
    for column, data_type in additions.items():
        if column not in columns:
            connection.execute(
                f"ALTER TABLE damage_events ADD COLUMN {column} {data_type}"
            )
    damage_rows = _dict_rows(connection, """
        SELECT fact_id,game_id,replay_sha256,patch,replay_time_ms,
               source_network_id,target_network_id,source_participant_id,
               target_participant_id,source_champion,target_champion,amount,
               decoder_profile,confidence,status,raw_provenance_json
        FROM damage_events ORDER BY replay_sha256,replay_time_ms,fact_id
    """)
    spells = _dict_rows(connection, """
        SELECT replay_sha256,patch,raw_provenance_json FROM spell_events
        ORDER BY replay_sha256,replay_time_ms,fact_id
    """)
    normalized_damage = []
    for row in damage_rows:
        raw = _json(row.pop("raw_provenance_json", None)) or {}
        raw.update({key: value for key, value in row.items() if key != "fact_id"})
        raw["_v3_fact_id"] = row["fact_id"]
        normalized_damage.append(raw)
    normalized_spells = []
    for row in spells:
        raw = _json(row.get("raw_provenance_json")) or {}
        raw.setdefault("replay_sha256", row.get("replay_sha256"))
        raw.setdefault("patch", row.get("patch"))
        normalized_spells.append(raw)
    spell_dictionary = (
        load_spell_dictionary(SPELL_DICTIONARY_PATH)
        if SPELL_DICTIONARY_PATH.is_file() else {}
    )
    enriched = enrich_damage_events(
        normalized_damage, normalized_spells, spell_dictionary
    )
    updates = []
    for row in enriched:
        updates.append((
            row.get("damage_type"), row.get("spell"), row.get("spell_slot"),
            row.get("is_basic_attack"), row.get("damage_type_code"),
            row.get("damage_type_status"), row.get("damage_spell_key"),
            row.get("spell_attribution_status"), row.get("basic_attack_status"),
            row.get("is_critical"), row.get("critical_status"), compact_json(row),
            row["_v3_fact_id"],
        ))
    if updates:
        connection.executemany("""
            UPDATE damage_events SET damage_type=?,spell=?,spell_slot=?,
              is_basic_attack=?,damage_type_code=?,damage_type_status=?,
              damage_spell_key=?,spell_attribution_status=?,basic_attack_status=?,
              is_critical=?,critical_status=?,raw_provenance_json=?
            WHERE fact_id=?
        """, updates)
    return {
        "damage_events": len(enriched),
        "damage_type": sum(row.get("damage_type") is not None for row in enriched),
        "spell_attribution": sum(row.get("spell") is not None for row in enriched),
        "basic_attack_true": sum(row.get("is_basic_attack") is True for row in enriched),
        "critical_true": sum(row.get("is_critical") is True for row in enriched),
    }


def _time_bucket(timestamp_ms: int | float | None) -> str:
    minute = float(timestamp_ms or 0) / 60_000.0
    if minute < 5:
        return "0-5"
    if minute < 10:
        return "5-10"
    if minute < 15:
        return "10-15"
    if minute < 20:
        return "15-20"
    return "20+"


def _load_inputs(connection: duckdb.DuckDBPyConnection) -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]],
    list[dict[str, Any]], list[dict[str, Any]],
]:
    participants = _dict_rows(connection, """
        SELECT game_id,replay_sha256,patch,participant_id,network_id,champion,
               team_id,team,role,confidence,status,raw_provenance_json
        FROM participants ORDER BY replay_sha256,participant_id
    """)
    for row in participants:
        row["raw_provenance"] = _json(row.pop("raw_provenance_json", None))

    positions = _dict_rows(connection, """
        SELECT replay_sha256,entity_id,replay_time_ms AS timestamp_ms,
               position_x AS x,position_z AS y,source_path_timestamp_ms,
               source_age_ms,interpolation_method,position_status,raw_packet_ref,
               raw_provenance_json
        FROM hero_positions_1s ORDER BY replay_sha256,entity_id,replay_time_ms
    """)
    for row in positions:
        row["position_xz"] = [row.get("x"), row.get("y")]
        row["raw_packet_ref"] = _json(row.get("raw_packet_ref"))
        row["source_raw_packet_ref"] = row["raw_packet_ref"]
        row["interpolation"] = row.get("interpolation_method") or (
            "PATH_WAYPOINT_LINEAR_INTERPOLATION_WITH_TERMINAL_HOLD"
        )
        row["raw_provenance"] = _json(row.pop("raw_provenance_json", None))

    wards = _dict_rows(connection, """
        SELECT fact_id,game_id,replay_sha256,patch,replay_time_ms,
               owner_network_id,entity_network_id AS ward_network_id,
               owner_participant_id,owner_team_id,ward_type,generic_name,
               entity_name,position_x AS actual_x,position_y AS actual_y,
               position_height AS height,owner_mapping_confidence,
               decoder_profile,confidence,status,raw_provenance_json
        FROM ward_spawns ORDER BY replay_sha256,replay_time_ms,entity_network_id
    """)
    for row in wards:
        row["spawn_time_ms"] = row["replay_time_ms"]
        row["position"] = {"x": row.get("actual_x"), "y": row.get("actual_y")}
        row["raw_provenance"] = _json(row.pop("raw_provenance_json", None))

    lifecycles = _dict_rows(connection, """
        SELECT fact_id,game_id,replay_sha256,patch,ward_network_id,spawn_time_ms,
               remove_time_ms,duration_ms,removal_reason,match_rule,
               coordinate_error,decoder_profile,confidence,status,
               raw_provenance_json
        FROM ward_lifecycles ORDER BY replay_sha256,spawn_time_ms,ward_network_id
    """)
    for row in lifecycles:
        row["raw_provenance"] = _json(row.pop("raw_provenance_json", None))

    adc_deaths = _dict_rows(connection, """
        SELECT fact_id,game_id,replay_sha256,patch,adc,adc_participant_id,
               support,support_participant_id,death_time_ms,combat_start_ms,
               combat_duration_ms,killer,raw_provenance_json
        FROM adc_deaths ORDER BY replay_sha256,death_time_ms,adc_participant_id
    """)
    attackers = defaultdict(list)
    for row in _dict_rows(connection, """
        SELECT adc_death_id,attacker_participant_id AS participant_id,
               attacker_champion AS champion,attacker_network_id AS network_id,
               hit_count,damage_amount,first_hit_time_ms,last_hit_time_ms,
               confidence,raw_provenance_json
        FROM adc_death_damage ORDER BY adc_death_id,first_hit_time_ms
    """):
        row["raw_provenance"] = _json(row.pop("raw_provenance_json", None))
        attackers[row.pop("adc_death_id")].append(row)
    for row in adc_deaths:
        raw = _json(row.pop("raw_provenance_json", None)) or {}
        row.update({key: value for key, value in raw.items() if key not in row})
        row["attackers"] = attackers.get(row["fact_id"], raw.get("attackers", []))
        row["raw_provenance"] = raw
    return participants, positions, wards, lifecycles, adc_deaths


def _replace_ward_tables(
    connection: duckdb.DuckDBPyConnection,
    participants: list[dict[str, Any]],
    positions: list[dict[str, Any]],
    wards: list[dict[str, Any]],
    lifecycles: list[dict[str, Any]],
    max_position_age_ms: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    participant_map = {
        (row["replay_sha256"], row["participant_id"]): row for row in participants
    }
    lifecycle_map = {
        (row["replay_sha256"], row["ward_network_id"]): row for row in lifecycles
    }
    jungler_map = {
        (row["replay_sha256"], row["team_id"]): row
        for row in participants if row.get("role") == "jungle"
    }
    position_index = PositionIndex(positions)
    context_rows = build_ward_position_context(
        wards, participants, position_index, max_position_age_ms
    )
    context_map = {
        (row["replay_sha256"], row["ward_network_id"]): row for row in context_rows
    }
    research_rows = []
    flattened_context = []
    for ward in wards:
        key = (ward["replay_sha256"], ward["ward_network_id"])
        owner = participant_map.get((ward["replay_sha256"], ward.get("owner_participant_id")))
        lifecycle = lifecycle_map.get(key)
        context = context_map.get(key, {})
        owner_position = position_index.lookup(
            ward["replay_sha256"],
            participant_network_id(ward.get("owner_participant_id")),
            ward["replay_time_ms"], max_position_age_ms,
        ) if ward.get("owner_participant_id") else None
        owner_team = owner.get("team_id") if owner else ward.get("owner_team_id")
        enemy_team = 200 if owner_team == 100 else 100 if owner_team == 200 else None
        enemy_jungler = jungler_map.get((ward["replay_sha256"], enemy_team))
        enemy_jungler_position = context.get("enemy_jungler_position") or {}
        allied_adc_position = context.get("allied_adc_position") or {}
        allied_support_position = context.get("allied_support_position") or {}
        flattened = {
            "fact_id": stable_id("ward_position_context_v3", *key),
            "game_id": ward["game_id"], "replay_sha256": ward["replay_sha256"],
            "patch": ward["patch"], "ward_network_id": ward["ward_network_id"],
            "timestamp_ms": ward["replay_time_ms"],
            "owner_participant_id": ward.get("owner_participant_id"),
            "owner_position_x": owner_position.get("x") if owner_position else None,
            "owner_position_y": owner_position.get("y") if owner_position else None,
            "owner_position_timestamp_ms": owner_position.get("position_timestamp_ms") if owner_position else None,
            "owner_source_path_timestamp_ms": owner_position.get("source_path_timestamp_ms") if owner_position else None,
            "owner_sample_age_ms": owner_position.get("sample_age_ms") if owner_position else None,
            "owner_source_age_ms": owner_position.get("source_age_ms") if owner_position else None,
            "owner_position_freshness": owner_position.get("freshness_status") if owner_position else "MISSING",
            "owner_position_usable": bool(owner_position and owner_position.get("usable")),
            "enemy_jungler_participant_id": enemy_jungler.get("participant_id") if enemy_jungler else None,
            "enemy_jungler_champion": enemy_jungler.get("champion") if enemy_jungler else None,
            "enemy_jungler_position_x": enemy_jungler_position.get("x"),
            "enemy_jungler_position_y": enemy_jungler_position.get("y"),
            "enemy_jungler_source_age_ms": enemy_jungler_position.get("source_age_ms"),
            "enemy_jungler_distance": context.get("enemy_jungler_distance"),
            "allied_adc_position_x": allied_adc_position.get("x"),
            "allied_adc_position_y": allied_adc_position.get("y"),
            "allied_adc_source_age_ms": allied_adc_position.get("source_age_ms"),
            "allied_support_position_x": allied_support_position.get("x"),
            "allied_support_position_y": allied_support_position.get("y"),
            "allied_support_source_age_ms": allied_support_position.get("source_age_ms"),
            "nearest_enemy_distance": context.get("nearest_enemy_distance"),
            "nearby_enemy_count": context.get("nearby_enemy_count"),
            "nearby_ally_count": context.get("nearby_ally_count"),
            "nearby_radius": context.get("nearby_radius", 1600),
            "distance_reference": context.get("distance_reference"),
            "max_position_age_ms": max_position_age_ms,
            "position_status": "VERIFIED_DERIVED",
            "decoder_profile": "path-position-context-v3",
            "confidence": "VERIFIED_DERIVED",
            "status": "FRESH" if owner_position and owner_position.get("usable") else "STALE_OR_MISSING",
            "raw_provenance_json": compact_json({
                "ward_fact_id": ward["fact_id"], "context": context,
                "owner_position": owner_position,
            }),
        }
        flattened_context.append(flattened)
        research_rows.append({
            "fact_id": ward["fact_id"], "game_id": ward["game_id"],
            "replay_sha256": ward["replay_sha256"], "patch": ward["patch"],
            "timestamp_ms": ward["replay_time_ms"],
            "minute": ward["replay_time_ms"] / 60_000.0,
            "time_bucket": _time_bucket(ward["replay_time_ms"]),
            "ward_network_id": ward["ward_network_id"], "ward_type": ward.get("ward_type"),
            "owner_network_id": ward.get("owner_network_id"),
            "owner_participant": owner.get("participant_id") if owner else None,
            "owner_champion": owner.get("champion") if owner else None,
            "owner_role": owner.get("role") if owner else None,
            "owner_team": owner.get("team_id") if owner else None,
            "enemy_jungler_champion": enemy_jungler.get("champion") if enemy_jungler else None,
            "actual_x": ward.get("actual_x"), "actual_y": ward.get("actual_y"),
            "height": ward.get("height"),
            "spawn_position_status": "ENTITY_SPAWN_DIRECT",
            "remove_time_ms": lifecycle.get("remove_time_ms") if lifecycle else None,
            "lifetime_ms": lifecycle.get("duration_ms") if lifecycle else None,
            "lifecycle_status": "VERIFIED_DERIVED" if lifecycle else "UNAVAILABLE",
            "owner_mapping_confidence": ward.get("owner_mapping_confidence"),
            "map_region": None,
            "owner_position_x": flattened["owner_position_x"],
            "owner_position_y": flattened["owner_position_y"],
            "owner_position_source_age_ms": flattened["owner_source_age_ms"],
            "owner_position_freshness": flattened["owner_position_freshness"],
            "nearest_enemy_distance": flattened["nearest_enemy_distance"],
            "enemy_jungler_distance": flattened["enemy_jungler_distance"],
            "allied_adc_position_x": flattened["allied_adc_position_x"],
            "allied_adc_position_y": flattened["allied_adc_position_y"],
            "allied_support_position_x": flattened["allied_support_position_x"],
            "allied_support_position_y": flattened["allied_support_position_y"],
            "nearby_enemy_count": flattened["nearby_enemy_count"],
            "nearby_ally_count": flattened["nearby_ally_count"],
            "distance_reference": flattened["distance_reference"],
            "max_position_age_ms": max_position_age_ms,
            "decoder_profile": ward.get("decoder_profile"),
            "confidence": ward.get("confidence"), "status": ward.get("status"),
            "raw_provenance_json": compact_json({
                "ward_spawn": ward.get("raw_provenance"),
                "lifecycle": lifecycle.get("raw_provenance") if lifecycle else None,
                "position_context_fact_id": flattened["fact_id"],
            }),
        })
    research_rows = assign_regions(research_rows)

    connection.execute("DROP TABLE IF EXISTS ward_position_context")
    connection.execute("""
        CREATE TABLE ward_position_context (
          fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
          ward_network_id BIGINT, timestamp_ms BIGINT, owner_participant_id INTEGER,
          owner_position_x DOUBLE, owner_position_y DOUBLE, owner_position_timestamp_ms BIGINT,
          owner_source_path_timestamp_ms BIGINT, owner_sample_age_ms BIGINT,
          owner_source_age_ms BIGINT, owner_position_freshness VARCHAR,
          owner_position_usable BOOLEAN, enemy_jungler_participant_id INTEGER,
          enemy_jungler_champion VARCHAR, enemy_jungler_position_x DOUBLE,
          enemy_jungler_position_y DOUBLE, enemy_jungler_source_age_ms BIGINT,
          enemy_jungler_distance DOUBLE, allied_adc_position_x DOUBLE,
          allied_adc_position_y DOUBLE, allied_adc_source_age_ms BIGINT,
          allied_support_position_x DOUBLE, allied_support_position_y DOUBLE,
          allied_support_source_age_ms BIGINT, nearest_enemy_distance DOUBLE,
          nearby_enemy_count INTEGER, nearby_ally_count INTEGER, nearby_radius DOUBLE,
          distance_reference VARCHAR,
          max_position_age_ms BIGINT, position_status VARCHAR, decoder_profile VARCHAR,
          confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
        )
    """)
    context_columns = list(flattened_context[0]) if flattened_context else []
    if flattened_context:
        connection.executemany(
            f"INSERT INTO ward_position_context VALUES ({','.join('?' for _ in context_columns)})",
            [[row[column] for column in context_columns] for row in flattened_context],
        )

    connection.execute("DROP TABLE IF EXISTS ward_research_events")
    connection.execute("""
        CREATE TABLE ward_research_events (
          fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
          timestamp_ms BIGINT, minute DOUBLE, time_bucket VARCHAR, ward_network_id BIGINT,
          ward_type VARCHAR, owner_network_id BIGINT, owner_participant INTEGER,
          owner_champion VARCHAR, owner_role VARCHAR, owner_team INTEGER,
          enemy_jungler_champion VARCHAR, actual_x DOUBLE, actual_y DOUBLE, height DOUBLE,
          spawn_position_status VARCHAR, remove_time_ms BIGINT, lifetime_ms BIGINT,
          lifecycle_status VARCHAR, owner_mapping_confidence VARCHAR, map_region VARCHAR,
          owner_position_x DOUBLE, owner_position_y DOUBLE,
          owner_position_source_age_ms BIGINT, owner_position_freshness VARCHAR,
          nearest_enemy_distance DOUBLE, enemy_jungler_distance DOUBLE,
          allied_adc_position_x DOUBLE, allied_adc_position_y DOUBLE,
          allied_support_position_x DOUBLE, allied_support_position_y DOUBLE,
          nearby_enemy_count INTEGER, nearby_ally_count INTEGER,
          distance_reference VARCHAR,
          max_position_age_ms BIGINT, decoder_profile VARCHAR, confidence VARCHAR,
          status VARCHAR, raw_provenance_json JSON
        )
    """)
    research_columns = list(research_rows[0]) if research_rows else []
    if research_rows:
        connection.executemany(
            f"INSERT INTO ward_research_events VALUES ({','.join('?' for _ in research_columns)})",
            [[row[column] for column in research_columns] for row in research_rows],
        )
    return research_rows, flattened_context


def _replace_adc_tables(
    connection: duckdb.DuckDBPyConnection,
    participants: list[dict[str, Any]],
    positions: list[dict[str, Any]],
    wards: list[dict[str, Any]],
    lifecycles: list[dict[str, Any]],
    adc_deaths: list[dict[str, Any]],
    max_position_age_ms: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    index = PositionIndex(positions)
    context_rows, feature_rows = build_adc_death_position_context(
        adc_deaths, participants, index, max_position_age_ms
    )
    ward_death_rows = build_ward_death_context(
        adc_deaths, participants, index, wards, lifecycles,
        max_position_age_ms=max_position_age_ms,
    )
    participant_map = {
        (row["replay_sha256"], row["participant_id"]): row for row in participants
    }
    death_map = {
        f"{row['replay_sha256']}:{int(row['death_time_ms'])}:{row['adc_participant_id']}": row
        for row in adc_deaths
    }
    flattened_context = []
    for row in context_rows:
        subject = row.get("subject_position") or {}
        support = row.get("support_position") or {}
        flattened_context.append({
            "fact_id": stable_id("adc_position_context_v3", row["death_context_id"], row["checkpoint"]),
            "game_id": row.get("game_id"), "replay_sha256": row["replay_sha256"],
            "patch": row.get("patch"), "adc_death_id": row["death_context_id"],
            "adc_participant_id": row.get("adc_participant_id"),
            "checkpoint": row["checkpoint"], "checkpoint_time_ms": row["checkpoint_time_ms"],
            "adc_position_x": subject.get("x"), "adc_position_y": subject.get("y"),
            "adc_position_timestamp_ms": subject.get("position_timestamp_ms"),
            "adc_source_path_timestamp_ms": subject.get("source_path_timestamp_ms"),
            "adc_sample_age_ms": subject.get("sample_age_ms"),
            "adc_source_age_ms": subject.get("source_age_ms"),
            "adc_position_freshness": subject.get("freshness_status", "MISSING"),
            "adc_position_usable": row.get("subject_position_usable", False),
            "support_participant_id": row.get("support_participant_id"),
            "support_position_x": support.get("x"), "support_position_y": support.get("y"),
            "support_source_age_ms": support.get("source_age_ms"),
            "support_position_freshness": support.get("freshness_status", "MISSING"),
            "support_distance": row.get("support_distance"),
            "nearest_enemy_distance": row.get("nearest_enemy_distance"),
            "enemy_count_within_600": row.get("enemy_count_within_600"),
            "enemy_count_within_900": row.get("enemy_count_within_900"),
            "enemy_count_within_1200": row.get("enemy_count_within_1200"),
            "enemy_count_within_1600": row.get("enemy_count_within_1600"),
            "ally_count_within_600": row.get("ally_count_within_600"),
            "ally_count_within_900": row.get("ally_count_within_900"),
            "ally_count_within_1200": row.get("ally_count_within_1200"),
            "ally_count_within_1600": row.get("ally_count_within_1600"),
            "max_position_age_ms": max_position_age_ms,
            "position_status": "VERIFIED_DERIVED",
            "decoder_profile": "path-position-context-v3", "confidence": "VERIFIED_DERIVED",
            "status": "FRESH" if row.get("subject_position_usable") else "STALE_OR_MISSING",
            "raw_provenance_json": compact_json(row),
        })
    flattened_features = []
    for row in feature_rows:
        first = participant_map.get((row["replay_sha256"], row.get("first_attacker_participant_id")))
        largest = participant_map.get((row["replay_sha256"], row.get("largest_damage_attacker_participant_id")))
        flattened_features.append({
            "fact_id": stable_id("adc_death_features_v3", row["death_context_id"]),
            "game_id": row.get("game_id"), "replay_sha256": row["replay_sha256"],
            "patch": row.get("patch"), "adc_death_id": row["death_context_id"],
            "adc_participant_id": row.get("adc_participant_id"),
            "death_time_ms": row.get("death_time_ms"), "time_to_die_ms": row.get("time_to_die_ms"),
            "attacker_count": row.get("attacker_count"),
            "damage_by_attacker_json": compact_json(row.get("damage_by_attacker", [])),
            "first_attacker_participant_id": row.get("first_attacker_participant_id"),
            "first_attacker": first.get("champion") if first else None,
            "largest_damage_attacker_participant_id": row.get("largest_damage_attacker_participant_id"),
            "largest_damage_attacker": largest.get("champion") if largest else None,
            "support_distance_start": row.get("support_distance_start"),
            "support_distance_death": row.get("support_distance_death"),
            "nearest_enemy_start": row.get("nearest_enemy_start"),
            "nearest_enemy_death": row.get("nearest_enemy_death"),
            "enemy_count_start": row.get("enemy_count_start_1600"),
            "enemy_count_death": row.get("enemy_count_death_1600"),
            "ally_count_start": row.get("ally_count_start_1600"),
            "ally_count_death": row.get("ally_count_death_1600"),
            "enemy_count_start_600": row.get("enemy_count_start_600"),
            "enemy_count_death_600": row.get("enemy_count_death_600"),
            "enemy_count_start_900": row.get("enemy_count_start_900"),
            "enemy_count_death_900": row.get("enemy_count_death_900"),
            "enemy_count_start_1200": row.get("enemy_count_start_1200"),
            "enemy_count_death_1200": row.get("enemy_count_death_1200"),
            "enemy_count_start_1600": row.get("enemy_count_start_1600"),
            "enemy_count_death_1600": row.get("enemy_count_death_1600"),
            "ally_count_start_600": row.get("ally_count_start_600"),
            "ally_count_death_600": row.get("ally_count_death_600"),
            "ally_count_start_900": row.get("ally_count_start_900"),
            "ally_count_death_900": row.get("ally_count_death_900"),
            "ally_count_start_1200": row.get("ally_count_start_1200"),
            "ally_count_death_1200": row.get("ally_count_death_1200"),
            "ally_count_start_1600": row.get("ally_count_start_1600"),
            "ally_count_death_1600": row.get("ally_count_death_1600"),
            "max_position_age_ms": max_position_age_ms,
            "decoder_profile": "adc-death-position-features-v3",
            "confidence": "VERIFIED_DERIVED", "status": row.get("position_context_status"),
            "raw_provenance_json": compact_json(row),
        })
    flattened_ward_death = []
    for row in ward_death_rows:
        adc_position = row.get("adc_position") or {}
        enemy_jungler_position = row.get("enemy_jungler_position") or {}
        death = death_map.get(row["death_context_id"], {})
        flattened_ward_death.append({
            "fact_id": stable_id("ward_death_context_v3", row["death_context_id"], row["lookback_ms"]),
            "game_id": row.get("game_id"), "replay_sha256": row["replay_sha256"],
            "patch": death.get("patch"), "adc_death_id": row["death_context_id"],
            "adc_participant_id": row.get("adc_participant_id"),
            "death_time_ms": row.get("death_time_ms"), "lookback_ms": row.get("lookback_ms"),
            "context_time_ms": row.get("context_time_ms"),
            "adc_position_x": adc_position.get("x"), "adc_position_y": adc_position.get("y"),
            "adc_position_source_age_ms": adc_position.get("source_age_ms"),
            "adc_position_status": row.get("position_status"),
            "enemy_jungler_participant_id": row.get("enemy_jungler_participant_id"),
            "enemy_jungler_position_x": enemy_jungler_position.get("x"),
            "enemy_jungler_position_y": enemy_jungler_position.get("y"),
            "enemy_jungler_position_source_age_ms": enemy_jungler_position.get("source_age_ms"),
            "nearby_radius": row.get("nearby_radius"),
            "nearby_allied_wards": row.get("nearby_allied_wards"),
            "nearby_enemy_wards": row.get("nearby_enemy_wards"),
            "nearby_allied_wards_uncertain": row.get("nearby_allied_wards_uncertain"),
            "nearby_enemy_wards_uncertain": row.get("nearby_enemy_wards_uncertain"),
            "nearest_allied_ward_distance": row.get("nearest_allied_ward_distance"),
            "nearest_enemy_ward_distance": row.get("nearest_enemy_ward_distance"),
            "nearest_allied_ward_distance_uncertain": row.get("nearest_allied_ward_distance_uncertain"),
            "nearest_enemy_ward_distance_uncertain": row.get("nearest_enemy_ward_distance_uncertain"),
            "unknown_team_ward_count": row.get("unknown_team_ward_count"),
            "lifecycle_policy": row.get("lifecycle_policy"),
            "gank_corridor_radius": row.get("gank_corridor_radius"),
            "gank_corridor_definition": row.get("gank_corridor_definition"),
            "gank_corridor_status": row.get("gank_corridor_status"),
            "allied_ward_gank_corridor_count": row.get("allied_ward_gank_corridor_count"),
            "allied_ward_gank_corridor_count_uncertain": row.get("allied_ward_gank_corridor_count_uncertain"),
            "nearest_allied_ward_gank_corridor_distance": row.get("nearest_allied_ward_gank_corridor_distance"),
            "nearest_allied_ward_gank_corridor_distance_uncertain": row.get("nearest_allied_ward_gank_corridor_distance_uncertain"),
            "max_position_age_ms": max_position_age_ms,
            "decoder_profile": "ward-adc-death-context-v3",
            "confidence": "VERIFIED_DERIVED", "status": row.get("position_status"),
            "raw_provenance_json": compact_json(row),
        })

    table_specs = {
        "adc_death_position_context": ("""
          fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
          adc_death_id VARCHAR, adc_participant_id INTEGER, checkpoint VARCHAR,
          checkpoint_time_ms BIGINT, adc_position_x DOUBLE, adc_position_y DOUBLE,
          adc_position_timestamp_ms BIGINT, adc_source_path_timestamp_ms BIGINT,
          adc_sample_age_ms BIGINT, adc_source_age_ms BIGINT,
          adc_position_freshness VARCHAR, adc_position_usable BOOLEAN,
          support_participant_id INTEGER, support_position_x DOUBLE,
          support_position_y DOUBLE, support_source_age_ms BIGINT,
          support_position_freshness VARCHAR, support_distance DOUBLE,
          nearest_enemy_distance DOUBLE, enemy_count_within_600 INTEGER,
          enemy_count_within_900 INTEGER, enemy_count_within_1200 INTEGER,
          enemy_count_within_1600 INTEGER, ally_count_within_600 INTEGER,
          ally_count_within_900 INTEGER, ally_count_within_1200 INTEGER,
          ally_count_within_1600 INTEGER, max_position_age_ms BIGINT,
          position_status VARCHAR, decoder_profile VARCHAR, confidence VARCHAR,
          status VARCHAR, raw_provenance_json JSON
        """, flattened_context),
        "adc_death_features": ("""
          fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
          adc_death_id VARCHAR, adc_participant_id INTEGER, death_time_ms BIGINT,
          time_to_die_ms BIGINT, attacker_count INTEGER, damage_by_attacker_json JSON,
          first_attacker_participant_id INTEGER, first_attacker VARCHAR,
          largest_damage_attacker_participant_id INTEGER, largest_damage_attacker VARCHAR,
          support_distance_start DOUBLE, support_distance_death DOUBLE,
          nearest_enemy_start DOUBLE, nearest_enemy_death DOUBLE,
          enemy_count_start INTEGER, enemy_count_death INTEGER,
          ally_count_start INTEGER, ally_count_death INTEGER,
          enemy_count_start_600 INTEGER, enemy_count_death_600 INTEGER,
          enemy_count_start_900 INTEGER, enemy_count_death_900 INTEGER,
          enemy_count_start_1200 INTEGER, enemy_count_death_1200 INTEGER,
          enemy_count_start_1600 INTEGER, enemy_count_death_1600 INTEGER,
          ally_count_start_600 INTEGER, ally_count_death_600 INTEGER,
          ally_count_start_900 INTEGER, ally_count_death_900 INTEGER,
          ally_count_start_1200 INTEGER, ally_count_death_1200 INTEGER,
          ally_count_start_1600 INTEGER, ally_count_death_1600 INTEGER,
          max_position_age_ms BIGINT, decoder_profile VARCHAR, confidence VARCHAR,
          status VARCHAR, raw_provenance_json JSON
        """, flattened_features),
        "ward_death_context": ("""
          fact_id VARCHAR PRIMARY KEY, game_id VARCHAR, replay_sha256 VARCHAR, patch VARCHAR,
          adc_death_id VARCHAR, adc_participant_id INTEGER, death_time_ms BIGINT,
          lookback_ms BIGINT, context_time_ms BIGINT, adc_position_x DOUBLE,
          adc_position_y DOUBLE, adc_position_source_age_ms BIGINT,
          adc_position_status VARCHAR, enemy_jungler_participant_id INTEGER,
          enemy_jungler_position_x DOUBLE, enemy_jungler_position_y DOUBLE,
          enemy_jungler_position_source_age_ms BIGINT, nearby_radius DOUBLE,
          nearby_allied_wards INTEGER, nearby_enemy_wards INTEGER,
          nearby_allied_wards_uncertain INTEGER, nearby_enemy_wards_uncertain INTEGER,
          nearest_allied_ward_distance DOUBLE, nearest_enemy_ward_distance DOUBLE,
          nearest_allied_ward_distance_uncertain DOUBLE,
          nearest_enemy_ward_distance_uncertain DOUBLE, unknown_team_ward_count INTEGER,
          lifecycle_policy VARCHAR, gank_corridor_radius DOUBLE,
          gank_corridor_definition VARCHAR, gank_corridor_status VARCHAR,
          allied_ward_gank_corridor_count INTEGER,
          allied_ward_gank_corridor_count_uncertain INTEGER,
          nearest_allied_ward_gank_corridor_distance DOUBLE,
          nearest_allied_ward_gank_corridor_distance_uncertain DOUBLE,
          max_position_age_ms BIGINT, decoder_profile VARCHAR,
          confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
        """, flattened_ward_death),
    }
    for table, (definition, rows) in table_specs.items():
        connection.execute(f"DROP TABLE IF EXISTS {table}")
        connection.execute(f"CREATE TABLE {table} ({definition})")
        if rows:
            columns = list(rows[0])
            connection.executemany(
                f"INSERT INTO {table} VALUES ({','.join('?' for _ in columns)})",
                [[row[column] for column in columns] for row in rows],
            )
    return flattened_context, flattened_features, flattened_ward_death


def _replace_spatial_tables(
    connection: duckdb.DuckDBPyConnection,
    ward_rows: list[dict[str, Any]],
    grid_cell_sizes: Sequence[float],
    hotspot_cell_size: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    region_map = load_region_map()
    game_ids_json = compact_json(sorted({row["game_id"] for row in ward_rows}))
    replay_sha256s_json = compact_json(sorted({row["replay_sha256"] for row in ward_rows}))
    connection.execute("DROP TABLE IF EXISTS map_regions")
    connection.execute("""
      CREATE TABLE map_regions (
        fact_id VARCHAR PRIMARY KEY, region_set VARCHAR, schema_version INTEGER,
        map_name VARCHAR, region_id VARCHAR, region_name VARCHAR, priority INTEGER,
        polygon_json JSON, bounds_json JSON, coordinate_status VARCHAR,
        decoder_profile VARCHAR, confidence VARCHAR, status VARCHAR,
        raw_provenance_json JSON
      )
    """)
    region_rows = []
    for region in region_map["regions"]:
        region_rows.append((
            stable_id("map_region", region_map["region_set"], region["id"]),
            region_map["region_set"], region_map["schema_version"],
            region_map.get("map_name"), region["id"], region.get("label"),
            region.get("priority"), compact_json(region.get("polygon")),
            compact_json(region.get("bounds")), "RAW_COORDINATES_PRESERVED",
            "summoners-rift-map-regions-v1", "APPROXIMATE_EDITABLE",
            region_map.get("status"), compact_json(region),
        ))
    if region_rows:
        connection.executemany(
            "INSERT INTO map_regions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", region_rows
        )

    heatmap_rows = []
    for cell_size in grid_cell_sizes:
        analysis = analyze_ward_rows(ward_rows, cell_size=cell_size)
        for cell in analysis["grid"]:
            heatmap_rows.append({
                "fact_id": stable_id("ward_heatmap", cell_size, cell["cell_x_index"], cell["cell_y_index"]),
                "scope": "CORPUS", "game_ids_json": game_ids_json,
                "replay_sha256s_json": replay_sha256s_json,
                "patch": "16.15.801.3452", "cell_size": cell_size,
                "cell_x_index": cell["cell_x_index"], "cell_y_index": cell["cell_y_index"],
                "cell_x": cell["cell_x"], "cell_y": cell["cell_y"],
                "ward_count": cell["count"], "percentage": cell["percentage"],
                "decoder_profile": "ward-grid-heatmap-v3", "confidence": "VERIFIED_DERIVED",
                "status": "MATERIALIZED", "raw_provenance_json": compact_json({
                    "input_table": "ward_research_events", "coordinate_policy": analysis["coordinate_policy"]
                }),
            })
    hotspot_analysis = analyze_ward_rows(
        ward_rows, cell_size=hotspot_cell_size, hotspot_radius_cells=1
    )
    hotspot_rows = []
    for hotspot in hotspot_analysis["hotspots"]:
        hotspot_rows.append({
            "fact_id": stable_id("ward_hotspot", hotspot_cell_size, hotspot["hotspot_id"]),
            "scope": "CORPUS", "game_ids_json": game_ids_json,
            "replay_sha256s_json": replay_sha256s_json, "patch": "16.15.801.3452",
            "hotspot_id": hotspot["hotspot_id"], "cell_size": hotspot_cell_size,
            "radius_cells": hotspot["radius_cells"],
            "center_x": hotspot["center"]["x"], "center_y": hotspot["center"]["y"],
            "ward_count": hotspot["count"], "percentage": hotspot["percentage"],
            "ward_type_distribution_json": compact_json(hotspot["ward_type_distribution"]),
            "time_distribution_json": compact_json(hotspot["time_distribution"]),
            "role_distribution_json": compact_json(hotspot["role_distribution"]),
            "team_distribution_json": compact_json(hotspot["team_distribution"]),
            "decoder_profile": "ward-spatial-hotspot-v3", "confidence": "VERIFIED_DERIVED",
            "status": "MATERIALIZED", "raw_provenance_json": compact_json(hotspot),
        })

    table_specs = {
        "ward_heatmap_cells": ("""
          fact_id VARCHAR PRIMARY KEY, scope VARCHAR, game_ids_json JSON,
          replay_sha256s_json JSON, patch VARCHAR, cell_size DOUBLE,
          cell_x_index INTEGER, cell_y_index INTEGER, cell_x DOUBLE, cell_y DOUBLE,
          ward_count BIGINT, percentage DOUBLE, decoder_profile VARCHAR,
          confidence VARCHAR, status VARCHAR, raw_provenance_json JSON
        """, heatmap_rows),
        "ward_hotspots": ("""
          fact_id VARCHAR PRIMARY KEY, scope VARCHAR, game_ids_json JSON,
          replay_sha256s_json JSON, patch VARCHAR, hotspot_id VARCHAR,
          cell_size DOUBLE, radius_cells INTEGER, center_x DOUBLE, center_y DOUBLE,
          ward_count BIGINT, percentage DOUBLE, ward_type_distribution_json JSON,
          time_distribution_json JSON, role_distribution_json JSON,
          team_distribution_json JSON, decoder_profile VARCHAR, confidence VARCHAR,
          status VARCHAR, raw_provenance_json JSON
        """, hotspot_rows),
    }
    for table, (definition, rows) in table_specs.items():
        connection.execute(f"DROP TABLE IF EXISTS {table}")
        connection.execute(f"CREATE TABLE {table} ({definition})")
        if rows:
            columns = list(rows[0])
            connection.executemany(
                f"INSERT INTO {table} VALUES ({','.join('?' for _ in columns)})",
                [[row[column] for column in columns] for row in rows],
            )
    return heatmap_rows, hotspot_rows


def materialize_research_layer(
    db_path: str | Path = DEFAULT_DB,
    *,
    max_position_age_ms: int = DEFAULT_MAX_POSITION_AGE_MS,
    grid_cell_sizes: Sequence[float] = DEFAULT_GRID_CELL_SIZES,
    hotspot_cell_size: float = DEFAULT_HOTSPOT_CELL_SIZE,
) -> dict[str, Any]:
    """Replace all derived V3 tables from immutable base facts."""
    if max_position_age_ms < 0:
        raise ValueError("max_position_age_ms must be non-negative")
    db_path = Path(db_path).resolve()
    with duckdb.connect(str(db_path)) as connection:
        _ensure_position_semantics(connection)
        combat_counts = _ensure_damage_semantics(connection)
        participants, positions, wards, lifecycles, adc_deaths = _load_inputs(connection)
        ward_rows, ward_context = _replace_ward_tables(
            connection, participants, positions, wards, lifecycles,
            max_position_age_ms,
        )
        adc_context, adc_features, ward_death = _replace_adc_tables(
            connection, participants, positions, wards, lifecycles, adc_deaths,
            max_position_age_ms,
        )
        heatmap, hotspots = _replace_spatial_tables(
            connection, ward_rows, grid_cell_sizes, hotspot_cell_size,
        )
    return {
        "db_path": str(db_path), "max_position_age_ms": max_position_age_ms,
        "table_counts": {
            "ward_research_events": len(ward_rows),
            "ward_position_context": len(ward_context),
            "adc_death_position_context": len(adc_context),
            "adc_death_features": len(adc_features),
            "ward_death_context": len(ward_death),
            "ward_heatmap_cells": len(heatmap), "ward_hotspots": len(hotspots),
        },
        "combat_enrichment": combat_counts,
    }


def research_status(db_path: str | Path = DEFAULT_DB) -> dict[str, Any]:
    db_path = Path(db_path).resolve()
    with duckdb.connect(str(db_path), read_only=True) as connection:
        tables = {row[0] for row in connection.execute("SHOW TABLES").fetchall()}
        counts = {
            table: connection.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
            for table in sorted(tables)
        }
        ages = sorted(
            row[0] for row in connection.execute(
                "SELECT source_age_ms FROM hero_positions_1s WHERE source_age_ms IS NOT NULL"
            ).fetchall()
        )
        freshness = {
            "total": len(ages),
            "le_500_ms": sum(value <= 500 for value in ages),
            "le_1000_ms": sum(value <= 1000 for value in ages),
            "le_2000_ms": sum(value <= 2000 for value in ages),
            "le_5000_ms": sum(value <= 5000 for value in ages),
            "gt_5000_ms": sum(value > 5000 for value in ages),
            "p50_ms": _percentile(ages, 0.50), "p90_ms": _percentile(ages, 0.90),
            "p95_ms": _percentile(ages, 0.95), "p99_ms": _percentile(ages, 0.99),
            "max_ms": max(ages) if ages else None,
        }
        ward_mapping = connection.execute("""
            SELECT count(*), count(owner_participant), count(owner_team),
                   count(*) FILTER (WHERE spawn_position_status='ENTITY_SPAWN_DIRECT')
            FROM ward_research_events
        """).fetchone() if "ward_research_events" in tables else (0, 0, 0, 0)
        ward_types = dict(connection.execute("""
            SELECT ward_type,count(*) FROM ward_research_events
            GROUP BY ward_type ORDER BY count(*) DESC,ward_type
        """).fetchall()) if "ward_research_events" in tables else {}
        context_success = connection.execute("""
            SELECT count(*) FILTER (WHERE status='VERIFIED_DERIVED'), count(*)
            FROM adc_death_features
        """).fetchone() if "adc_death_features" in tables else (0, 0)
        combat_coverage = connection.execute("""
            SELECT count(*),count(damage_type),count(spell),
                   count(*) FILTER (WHERE is_basic_attack=true),
                   count(*) FILTER (WHERE is_critical=true)
            FROM damage_events
        """).fetchone() if "damage_events" in tables else (0, 0, 0, 0, 0)
        damage_v3 = combat_capability_status()
        damage_v3["coverage"] = {
            "damage_events": combat_coverage[0],
            "damage_type_rows": combat_coverage[1],
            "spell_attribution_rows": combat_coverage[2],
            "basic_attack_true_rows": combat_coverage[3],
            "critical_true_rows": combat_coverage[4],
        }
        unsupported = _dict_rows(connection, """
            SELECT game_id,replay_sha256,patch,reason FROM ingest_rejections
            WHERE reason='UNSUPPORTED_REPLAY_VERSION' ORDER BY created_at
        """) if "ingest_rejections" in tables else []
        confidence_breakdown = {}
        for table in (
            "death_events", "damage_events", "spell_events", "buff_events",
            "ward_spawns", "ward_lifecycles", "hero_paths", "hero_positions_1s",
            "adc_death_features",
        ):
            if table in tables:
                confidence_breakdown[table] = dict(connection.execute(
                    f'SELECT coalesce(confidence,\'NULL\'),count(*) FROM "{table}" GROUP BY confidence'
                ).fetchall())
        status = {
            "status": "RESEARCH_PLATFORM_V3_MATERIALIZED",
            "database": str(db_path),
            "database_sha256": sha256_file(db_path),
            "replay_count": counts.get("replays", 0),
            "games": counts.get("replays", 0), "participants": counts.get("participants", 0),
            "deaths": counts.get("death_events", 0),
            "damage_events": counts.get("damage_events", 0),
            "spell_events": counts.get("spell_events", 0),
            "buff_events": counts.get("buff_events", 0),
            "ward_spawns": counts.get("ward_spawns", 0),
            "ward_lifecycles": counts.get("ward_lifecycles", 0),
            "hero_paths": counts.get("hero_paths", 0),
            "hero_positions": counts.get("hero_positions_1s", 0),
            "adc_deaths": counts.get("adc_deaths", 0),
            "rejected_events": counts.get("ingest_rejections", 0),
            "unsupported_patches": unsupported,
            "table_counts": counts,
            "ward": {
                "total": ward_mapping[0], "participant_mapping_count": ward_mapping[1],
                "team_mapping_count": ward_mapping[2], "direct_position_count": ward_mapping[3],
                "participant_mapping_coverage": ward_mapping[1] / ward_mapping[0] if ward_mapping[0] else 0,
                "team_mapping_coverage": ward_mapping[2] / ward_mapping[0] if ward_mapping[0] else 0,
                "types": ward_types,
            },
            "positions": {
                "position_status": "VERIFIED_DERIVED",
                "interpolation_method": "PATH_WAYPOINT_LINEAR_INTERPOLATION_WITH_TERMINAL_HOLD",
                "freshness": freshness,
            },
            "adc": {
                "death_features": context_success[1],
                "complete_position_context": context_success[0],
                "checkpoint_rows": counts.get("adc_death_position_context", 0),
            },
            "damage_v3": damage_v3,
            "protection": {
                "shield_generated": "UNAVAILABLE",
                "shield_absorbed": "UNAVAILABLE",
                "heal_actual": "UNAVAILABLE",
                "temporary_hp": "UNAVAILABLE",
                "theoretical_values_used": False,
            },
            "confidence_breakdown": confidence_breakdown,
        }
    return status


def write_research_status(
    db_path: str | Path = DEFAULT_DB,
    output_path: str | Path | None = None,
) -> Path:
    db_path = Path(db_path).resolve()
    if output_path is None:
        output_path = publication_paths(db_path)["status"]
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(research_status(db_path), indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


def _markdown_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    rendered = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        rendered.append("| " + " | ".join("" if value is None else str(value) for value in row) + " |")
    return "\n".join(rendered)


def write_first_research_report(
    db_path: str | Path = DEFAULT_DB,
    output_path: str | Path | None = None,
) -> Path:
    db_path = Path(db_path).resolve()
    if output_path is None:
        output_path = publication_paths(db_path)["report"]
    output_path = Path(output_path).resolve()
    with duckdb.connect(str(db_path), read_only=True) as connection:
        replay_count = connection.execute("SELECT count(*) FROM replays").fetchone()[0]
        ward_total = connection.execute("SELECT count(*) FROM ward_research_events").fetchone()[0]
        ward_types = connection.execute("""
            SELECT coalesce(ward_type,'UNKNOWN'),count(*) FROM ward_research_events
            GROUP BY ward_type ORDER BY count(*) DESC,ward_type
        """).fetchall()
        ward_teams = connection.execute("""
            SELECT coalesce(cast(owner_team AS VARCHAR),'UNKNOWN'),count(*)
            FROM ward_research_events GROUP BY owner_team ORDER BY count(*) DESC
        """).fetchall()
        ward_roles = connection.execute("""
            SELECT coalesce(owner_role,'UNKNOWN'),count(*) FROM ward_research_events
            GROUP BY owner_role ORDER BY count(*) DESC,owner_role
        """).fetchall()
        ward_times = connection.execute("""
            SELECT time_bucket,count(*) FROM ward_research_events GROUP BY time_bucket
            ORDER BY CASE time_bucket WHEN '0-5' THEN 1 WHEN '5-10' THEN 2
             WHEN '10-15' THEN 3 WHEN '15-20' THEN 4 ELSE 5 END
        """).fetchall()
        hotspots = connection.execute("""
            SELECT hotspot_id,round(center_x,1),round(center_y,1),ward_count,
                   round(percentage,2),ward_type_distribution_json
            FROM ward_hotspots ORDER BY ward_count DESC,hotspot_id LIMIT 10
        """).fetchall()
        adc = connection.execute("""
            SELECT count(*), round(avg(time_to_die_ms),1),
                   round(median(time_to_die_ms),1), round(avg(attacker_count),2),
                   round(avg(support_distance_death),1), round(avg(enemy_count_death),2)
            FROM adc_death_features
        """).fetchone()
        adc_context = connection.execute("""
            SELECT count(*) FILTER (WHERE status='VERIFIED_DERIVED'),count(*)
            FROM adc_death_features
        """).fetchone()
        support_regions = connection.execute("""
            SELECT coalesce(map_region,'unassigned'),count(*) FROM ward_research_events
            WHERE owner_role='support' GROUP BY map_region ORDER BY count(*) DESC LIMIT 10
        """).fetchall()
        adc_regions = connection.execute("""
            SELECT coalesce(map_region,'unassigned'),count(*) FROM ward_research_events
            WHERE owner_role='adc' GROUP BY map_region ORDER BY count(*) DESC LIMIT 10
        """).fetchall()
    lines = [
        "# FIRST RESEARCH SANITY REPORT",
        "",
        f"**N={replay_count}, SANITY ONLY - not suitable for population-level conclusions.**",
        "",
        f"Database SHA-256: `{sha256_file(db_path)}`",
        "",
        "Ward coordinates are `ENTITY_SPAWN_DIRECT`. Hero positions are "
        "`VERIFIED_DERIVED`; the default freshness limit is 2000 ms.",
        "",
        "## Ward",
        "",
        f"Observed Ward entities: **{ward_total}**.",
        "",
        "### Type",
        "",
        _markdown_table(("ward_type", "count"), ward_types),
        "",
        "### Team",
        "",
        _markdown_table(("owner_team", "count"), ward_teams),
        "",
        "### Role",
        "",
        _markdown_table(("owner_role", "count"), ward_roles),
        "",
        "### Time bucket",
        "",
        _markdown_table(("minute bucket", "count"), ward_times),
        "",
        "### Top spatial hotspots",
        "",
        _markdown_table(("hotspot", "center_x", "center_y", "count", "%", "ward types"), hotspots),
        "",
        "### Common support regions",
        "",
        _markdown_table(("map_region", "count"), support_regions),
        "",
        "### Common ADC ward regions",
        "",
        _markdown_table(("map_region", "count"), adc_regions),
        "",
        "## ADC",
        "",
        _markdown_table(
            ("deaths", "avg combat ms", "median combat ms", "avg attackers", "avg support distance at death", "avg enemies within 1600 at death"),
            (adc,),
        ),
        "",
        f"Complete start+death position context: **{adc_context[0]}/{adc_context[1]}**. "
        "Missing or stale positions are excluded from distance and count statistics.",
        "",
        "## Evidence boundary",
        "",
        "Damage type is mapped from UnitApplyDamage `field_21`. Spell, basic-attack, "
        "and critical attribution are derived only under strict partial-coverage rules. "
        "Protection amounts remain unavailable; theoretical values are not presented as replay observations.",
        "",
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path


def export_research_parquet(
    db_path: str | Path = DEFAULT_DB,
    output_dir: str | Path | None = None,
    tables: Sequence[str] = RESEARCH_EXPORT_TABLES,
) -> dict[str, str]:
    db_path = Path(db_path).resolve()
    if output_dir is None:
        output_dir = publication_paths(db_path)["parquet"]
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    exports: dict[str, str] = {}
    with duckdb.connect(str(db_path), read_only=True) as connection:
        available = {row[0] for row in connection.execute("SHOW TABLES").fetchall()}
        for table in tables:
            if table not in available:
                continue
            target = output_dir / f"{table}.parquet"
            escaped = str(target).replace("'", "''")
            connection.execute(
                f'COPY (SELECT * FROM "{table}") TO \'{escaped}\' '
                "(FORMAT PARQUET, COMPRESSION ZSTD)"
            )
            exports[table] = str(target)
    return exports


def _checkpoint_database(db_path: Path) -> None:
    """Flush DuckDB before recording the immutable publication identity."""
    with duckdb.connect(str(db_path)) as connection:
        connection.execute("CHECKPOINT")


def _artifact_record(path: Path, *, relative_to: Path) -> dict[str, Any]:
    return {
        "path": str(path.resolve().relative_to(relative_to.resolve())),
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def write_publication_manifest(
    db_path: str | Path,
    *,
    status_path: str | Path,
    report_path: str | Path,
    parquet: Mapping[str, str | Path],
    output_path: str | Path | None = None,
) -> Path:
    """Write the final, hash-bound inventory for a publication bundle."""
    db_path = Path(db_path).resolve()
    root = db_path.parent
    status_path = Path(status_path).resolve()
    report_path = Path(report_path).resolve()
    if output_path is None:
        output_path = publication_paths(db_path)["manifest"]
    output_path = Path(output_path).resolve()
    payload = {
        "schema_version": 1,
        "database": _artifact_record(db_path, relative_to=root),
        "status": _artifact_record(status_path, relative_to=root),
        "report": _artifact_record(report_path, relative_to=root),
        "parquet": {
            table: _artifact_record(Path(path).resolve(), relative_to=root)
            for table, path in sorted(parquet.items())
        },
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output_path


def publish_all(
    db_path: str | Path = DEFAULT_DB,
    *, max_position_age_ms: int = DEFAULT_MAX_POSITION_AGE_MS,
) -> dict[str, Any]:
    result = materialize_research_layer(
        db_path, max_position_age_ms=max_position_age_ms
    )
    db_path = Path(db_path).resolve()
    paths = publication_paths(db_path)
    # No operation after this point opens a writable DuckDB connection.
    _checkpoint_database(db_path)
    parquet = export_research_parquet(db_path, paths["parquet"])
    status_path = write_research_status(db_path, paths["status"])
    report_path = write_first_research_report(db_path, paths["report"])
    manifest_path = write_publication_manifest(
        db_path, status_path=status_path, report_path=report_path,
        parquet=parquet, output_path=paths["manifest"],
    )
    result["research_status"] = str(status_path)
    result["report"] = str(report_path)
    result["parquet"] = parquet
    result["publication_manifest"] = str(manifest_path)
    return result


__all__ = [
    "DEFAULT_STATUS_PATH", "DEFAULT_REPORT_PATH", "DEFAULT_PARQUET_DIR",
    "DEFAULT_PUBLICATION_MANIFEST_PATH", "publication_paths", "sha256_file",
    "RESEARCH_EXPORT_TABLES", "materialize_research_layer", "research_status",
    "write_research_status", "write_first_research_report",
    "export_research_parquet", "write_publication_manifest", "publish_all",
]
