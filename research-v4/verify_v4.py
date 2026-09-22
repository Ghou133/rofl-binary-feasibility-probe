"""Read-only completion gate for Protection Telemetry V4.

The V4 database is additive, so its file hash cannot equal the frozen V3
publication hash.  This verifier instead binds the database to the complete
V3 row-count/replay baseline, the frozen packet-emulator source hash, and the
observed V4 protection facts.  It never opens DuckDB in write mode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import duckdb


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "research-v3" / "output" / "replay_research.duckdb"
DEFAULT_EMULATOR = ROOT / "scripts" / "emulate_exact_packet_decoder.py"
EXPECTED_EMULATOR_SHA256 = (
    "c3959b3163c391a97ee0d6fc63641ad1f4507fbbe6dab87cd647e9a174fca6e7"
)
SUPPORTED_PATCH = "16.15.801.3452"
ON_EVENT_DECODER_PROFILE = "rofl-16.15.801.3452-on-event-protection-v4"
SHIELD_DAMAGE_DECODER_PROFILE = (
    "rofl-16.15.801.3452-unit-apply-shield-damage-v4"
)


V3_TABLE_COUNTS = {
    "adc_death_damage": 255,
    "adc_death_features": 120,
    "adc_death_position_context": 480,
    "adc_death_support_actions": 281,
    "adc_deaths": 120,
    "buff_events": 312813,
    "damage_events": 27625,
    "death_events": 546,
    "hero_paths": 459906,
    "hero_positions_1s": 159765,
    "ingest_rejections": 0,
    "ingest_runs": 2,
    "map_regions": 28,
    "participants": 100,
    "replays": 10,
    "spell_events": 32290,
    "ward_death_context": 480,
    "ward_heatmap_cells": 1137,
    "ward_hotspots": 34,
    "ward_lifecycles": 637,
    "ward_position_context": 1357,
    "ward_research_events": 1357,
    "ward_spawns": 1357,
}

# Exact V3 facts from artifacts/replay_manifest.json at V3 acceptance time.
V3_REPLAY_FACTS = {
    "b911ddc894b50569eb6664518e4862f90740e0f84eb127ecfe2f3f6712be5233": {
        "game_id": "11154791609", "patch": SUPPORTED_PATCH, "participants": 10,
        "death_events": 71, "damage_events": 2638, "spell_events": 4179,
        "buff_events": 33595, "adc_deaths": 17,
    },
    "4b803c3084266a8774f878aa96932b46fc372a14735d7d290a6f6d0c61719b18": {
        "game_id": "11158122245", "patch": SUPPORTED_PATCH, "participants": 10,
        "death_events": 48, "damage_events": 1878, "spell_events": 3057,
        "buff_events": 32302, "adc_deaths": 9,
    },
    "1a7e1b9b82ad412fc7e0bf47f2e9c10e27d699c07721c21b02e4e97ae94b7bf1": {
        "game_id": "11158276256", "patch": SUPPORTED_PATCH, "participants": 10,
        "death_events": 64, "damage_events": 3385, "spell_events": 3833,
        "buff_events": 35942, "adc_deaths": 12,
    },
    "f3ad2680d408c6420442818f318d6e2985b72069c44293c731e9df584461bf7d": {
        "game_id": "11172852368", "patch": SUPPORTED_PATCH, "participants": 10,
        "death_events": 62, "damage_events": 3010, "spell_events": 3786,
        "buff_events": 31723, "adc_deaths": 16,
    },
    "6f7ce6386ee3ec7649a67a38b46f955d46f677964483e3ed3e8c8692d2f0f862": {
        "game_id": "11177593199", "patch": SUPPORTED_PATCH, "participants": 10,
        "death_events": 45, "damage_events": 1998, "spell_events": 3473,
        "buff_events": 27598, "adc_deaths": 8,
    },
    "b1ad57465c854a316a4db9b4ae0f99c591f489bc1e112560b5b43c3cdc3539f2": {
        "game_id": "11181624190", "patch": SUPPORTED_PATCH, "participants": 10,
        "death_events": 48, "damage_events": 4110, "spell_events": 3010,
        "buff_events": 38413, "adc_deaths": 13,
    },
    "2c29ebc22002a0f27d1ea2d29e327818a0d99e364d6a86f7da9f78d5741e85df": {
        "game_id": "11181764186", "patch": SUPPORTED_PATCH, "participants": 10,
        "death_events": 32, "damage_events": 1968, "spell_events": 2083,
        "buff_events": 19333, "adc_deaths": 9,
    },
    "0f722823a66f75782b6f151c0ac3ffc5def38d45d739b004ea80e65c0c28539c": {
        "game_id": "11181836652", "patch": SUPPORTED_PATCH, "participants": 10,
        "death_events": 43, "damage_events": 2024, "spell_events": 2537,
        "buff_events": 21383, "adc_deaths": 11,
    },
    "73e27be62b48f8faabe631d9e133d021ff87ef84b1e9f5afddcae374f2c7774b": {
        "game_id": "11181975536", "patch": SUPPORTED_PATCH, "participants": 10,
        "death_events": 50, "damage_events": 3176, "spell_events": 3062,
        "buff_events": 34448, "adc_deaths": 7,
    },
    "a034653ee757a41af561963bf32f20f765b5f0849e2bb98727da99e9f3305bb6": {
        "game_id": "11182120623", "patch": SUPPORTED_PATCH, "participants": 10,
        "death_events": 83, "damage_events": 3438, "spell_events": 3270,
        "buff_events": 38076, "adc_deaths": 18,
    },
}

V4_ONLY_REPLAYS = {
    "34eacdc66bb52b8b62b94b578d4c45e619088d74bc32fc37270a4c4394dc2885":
        "11184413613",
    "4a3cc77c1228ade02cb9e17a3412a626887f63f2ae7263e45fbb0d185562b6f5":
        "11184671361",
    "bc8c79d34809ba24bb1a011457d9844a5f6b222e5ff29fbdf152347899850c52":
        "11184800649",
    "bd720c264ca96f7b8df1536253157c5ee1dff1e18c7c638c111163df917342d8":
        "11185011797",
}


@dataclass(frozen=True)
class VerificationExpectations:
    v3_table_counts: Mapping[str, int]
    v3_replay_facts: Mapping[str, Mapping[str, Any]]
    v4_only_replays: Mapping[str, str]
    profile_status_counts: Mapping[str, int]
    on_event_status_counts: Mapping[str, int]
    shield_damage_status_counts: Mapping[str, int]
    profile_decoded_row_count: int
    profile_protection_row_count: int
    heal_event_count: int
    shield_event_id_counts: Mapping[str, int]
    protection_kind_counts: Mapping[str, int]
    transition_kind_counts: Mapping[str, int]
    paired_shield_count: int
    inventory_rows: int
    inventory_casts: int
    inventory_targets: int
    inventory_buff_candidates: int
    inventory_damage_windows: int
    adc_survival_features: int
    absorption_amounts: Sequence[float]
    emulator_sha256: str = EXPECTED_EMULATOR_SHA256

    @property
    def profile_shas(self) -> set[str]:
        return set(self.v3_replay_facts) | set(self.v4_only_replays)


DEFAULT_EXPECTATIONS = VerificationExpectations(
    v3_table_counts=V3_TABLE_COUNTS,
    v3_replay_facts=V3_REPLAY_FACTS,
    v4_only_replays=V4_ONLY_REPLAYS,
    profile_status_counts={"DECODED": 14},
    on_event_status_counts={"DECODED": 14},
    shield_damage_status_counts={"DECODED": 1, "NO_PROTECTION_EVENT": 13},
    # The profile stores selected decoded JSONL rows (91,484 OnEvent rows plus
    # two shield-damage rows), while the decoder summary separately proves all
    # 103,249 raw 0x009e packets fully consumed.
    profile_decoded_row_count=91486,
    profile_protection_row_count=91486,
    heal_event_count=81652,
    shield_event_id_counts={"23": 2, "237": 5080, "238": 4752},
    protection_kind_counts={
        "HEAL_REPORTED": 77415,
        "SHIELD_ABSORBED": 2,
        "SHIELD_GENERATED": 5080,
    },
    transition_kind_counts={"SHIELD_ABSORBED": 2},
    paired_shield_count=4752,
    inventory_rows=25,
    inventory_casts=1055,
    inventory_targets=1097,
    inventory_buff_candidates=1128,
    inventory_damage_windows=87,
    adc_survival_features=120,
    absorption_amounts=(30.030563354492188, 375.13690185546875),
)


REQUIRED_V4_COLUMNS = {
    "protection_v4_profiles": {
        "replay_sha256", "game_id", "patch", "profile_status",
        "decoded_row_count", "protection_row_count", "details_json",
        "v4_schema_version", "on_event_decoder_status",
        "shield_damage_decoder_status", "decoder_profile",
        "decoder_profiles_json",
    },
    "health_state_events": {"replay_sha256"},
    "shield_state_events": {
        "replay_sha256", "event_id", "source_network_id", "target_network_id",
        "observed_amount", "health_before", "health_after", "temporary_hp_before",
        "temporary_hp_after", "raw_amount", "effective_amount", "overheal_amount",
    },
    "heal_events": {
        "replay_sha256", "event_id", "source_network_id", "target_network_id",
        "observed_amount", "health_before", "health_after", "temporary_hp_before",
        "temporary_hp_after", "raw_amount", "effective_amount", "overheal_amount",
    },
    "temporary_hp_events": {"replay_sha256"},
    "protection_events": {
        "replay_sha256", "protection_kind", "source_network_id",
        "target_network_id", "observed_amount", "raw_amount", "effective_amount",
        "overheal_amount", "canonical", "paired_source_route_fact_id",
    },
    "protection_state_transitions": {
        "replay_sha256", "transition_kind", "source_network_id",
        "target_network_id", "observed_amount", "remaining_amount",
        "absorbed_amount", "unused_amount",
    },
    "protection_spell_inventory": {
        "replay_sha256", "cast_count", "target_count", "buff_candidate_count",
        "damage_window_count",
    },
    "adc_death_protection": {
        "replay_sha256", "protection_kind", "source_network_id",
        "source_participant_id", "target_network_id", "raw_amount",
        "effective_amount", "overheal_amount", "source_is_external_ally",
    },
    "adc_survival_features_v4": {
        "replay_sha256", "adc_death_id", "shield_remaining", "shield_absorbed",
        "shield_unused", "health_before", "health_after", "temporary_hp_before",
        "temporary_hp_after",
    },
}

RAW_EVENT_FINGERPRINT_COLUMNS = (
    "fact_id", "replay_sha256", "game_id", "replay_time_ms", "event_id",
    "source_network_id", "target_network_id", "observed_amount",
    "health_before", "health_after", "temporary_hp_before",
    "temporary_hp_after", "raw_amount", "effective_amount", "overheal_amount",
    "chunk_index", "chunk_id", "chunk_stream", "chunk_file_offset",
    "compressed_body_offset", "decompressed_block_offset",
    "decompressed_payload_offset", "global_occurrence_index",
    "raw_occurrence_index", "packet_occurrence_index", "raw_param",
    "raw_param_hex", "raw_payload_length", "raw_payload_sha256",
    "params_length", "params_sha256",
)

# These are comparison artifacts, not hardcoded acceptance hashes.  Large raw
# hex/provenance objects are excluded; their stable packet/parameter hashes and
# ordering locators remain included.
V4_FINGERPRINT_COLUMNS = {
    "protection_v4_profiles": (
        "replay_sha256", "game_id", "patch", "profile_status",
        "decoder_profile", "decoded_row_count", "protection_row_count",
        "details_json", "v4_schema_version", "on_event_decoder_status",
        "shield_damage_decoder_status", "decoder_profiles_json",
    ),
    "health_state_events": RAW_EVENT_FINGERPRINT_COLUMNS,
    "shield_state_events": RAW_EVENT_FINGERPRINT_COLUMNS,
    "heal_events": RAW_EVENT_FINGERPRINT_COLUMNS,
    "temporary_hp_events": RAW_EVENT_FINGERPRINT_COLUMNS,
    "protection_events": (
        "fact_id", "replay_sha256", "game_id", "replay_time_ms",
        "protection_kind", "source_network_id", "target_network_id",
        "observed_amount", "raw_amount", "effective_amount", "overheal_amount",
        "canonical", "heal_group_size", "canonical_first_raw_occurrence",
        "paired_source_route_fact_id", "chunk_index", "chunk_id",
        "chunk_stream", "chunk_file_offset", "compressed_body_offset",
        "decompressed_block_offset", "decompressed_payload_offset",
        "global_occurrence_index", "raw_occurrence_index",
        "packet_occurrence_index", "raw_param", "raw_param_hex",
        "raw_payload_length", "raw_payload_sha256", "params_length",
        "params_sha256",
    ),
    "protection_state_transitions": (
        "fact_id", "replay_sha256", "game_id", "replay_time_ms",
        "transition_kind", "source_network_id", "target_network_id",
        "observed_amount", "remaining_amount", "absorbed_amount",
        "unused_amount",
    ),
    "protection_spell_inventory": (
        "fact_id", "replay_sha256", "game_id", "source_network_id",
        "source_participant_id", "champion", "spell_identifier", "spell_slot",
        "protection_cast_kind", "replay_time_ms", "cast_count", "target_count",
        "buff_candidate_count", "damage_window_count", "first_cast_ms",
        "last_cast_ms",
    ),
    "adc_death_protection": (
        "fact_id", "replay_sha256", "game_id", "adc_death_id",
        "replay_time_ms", "protection_kind", "source_network_id",
        "source_participant_id", "target_network_id", "observed_amount",
        "direct_heal_lower", "direct_heal_upper", "raw_amount",
        "effective_amount", "overheal_amount", "source_is_external_ally",
    ),
    "adc_survival_features_v4": (
        "fact_id", "replay_sha256", "game_id", "adc_death_id",
        "combat_start_ms", "death_time_ms", "external_ally_shield_generated",
        "external_ally_direct_heal_lower", "external_ally_direct_heal_upper",
        "direct_heal_exact", "incoming_damage_event_count",
        "incoming_damage_amount", "incoming_damage_type_json",
        "incoming_basic_attack_count", "incoming_spell_damage_count",
        "shield_remaining", "shield_absorbed", "shield_unused", "health_before",
        "health_after", "temporary_hp_before", "temporary_hp_after",
    ),
}

# A missing fingerprint column is a schema failure, not a reason to silently
# hash a weaker surface.
REQUIRED_V4_COLUMNS = {
    table: set(REQUIRED_V4_COLUMNS[table]) | set(columns)
    for table, columns in V4_FINGERPRINT_COLUMNS.items()
}

REPLAY_FACT_TABLES = (
    "participants", "death_events", "damage_events", "spell_events",
    "buff_events", "adc_deaths",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _json_value(value: Any) -> Any:
    """Normalize DuckDB/Python values for stable JSON and equality checks."""
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in sorted(
            value.items(), key=lambda pair: str(pair[0])
        )}
    if isinstance(value, (list, tuple, set)):
        items = [_json_value(item) for item in value]
        return sorted(items) if isinstance(value, set) else items
    if isinstance(value, Path):
        return str(value)
    return value


class Checks:
    def __init__(self) -> None:
        self.values: dict[str, dict[str, Any]] = {}

    def record(
        self, name: str, actual: Any, expected: Any = None,
        *, condition: bool | None = None,
    ) -> None:
        actual = _json_value(actual)
        expected = _json_value(expected)
        passed = actual == expected if condition is None else bool(condition)
        self.values[name] = {
            "actual": actual, "expected": expected, "pass": passed,
        }


def _distribution(
    connection: duckdb.DuckDBPyConnection, table: str, column: str,
) -> dict[str, int]:
    rows = connection.execute(
        f'SELECT "{column}", count(*) FROM "{table}" GROUP BY 1 ORDER BY 1'
    ).fetchall()
    return {str(key): int(count) for key, count in rows}


def _columns(
    connection: duckdb.DuckDBPyConnection, table: str,
) -> set[str]:
    return {
        row[1] for row in connection.execute(
            f"PRAGMA table_info('{table}')"
        ).fetchall()
    }


def _parse_json_object(raw: Any) -> dict[str, Any]:
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _parse_json_list(raw: Any) -> list[Any]:
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, json.JSONDecodeError):
        return []
    return value if isinstance(value, list) else []


def _fingerprint_value(column: str, value: Any) -> Any:
    if value is None:
        return None
    if column.endswith("_json"):
        try:
            decoded = json.loads(value) if isinstance(value, str) else value
        except (TypeError, json.JSONDecodeError):
            decoded = value
        return _json_value(decoded)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    return _json_value(value)


def _semantic_fingerprints(
    connection: duckdb.DuckDBPyConnection,
) -> dict[str, dict[str, Any]]:
    fingerprints: dict[str, dict[str, Any]] = {}
    for table, columns in sorted(V4_FINGERPRINT_COLUMNS.items()):
        order_column = "replay_sha256" if table == "protection_v4_profiles" else "fact_id"
        selected = ",".join(f'"{column}"' for column in columns)
        cursor = connection.execute(
            f'SELECT {selected} FROM "{table}" ORDER BY "{order_column}"'
        )
        digest = hashlib.sha256()
        digest.update(json.dumps(
            list(columns), ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8"))
        digest.update(b"\n")
        row_count = 0
        while rows := cursor.fetchmany(4096):
            for row in rows:
                normalized = [
                    _fingerprint_value(column, value)
                    for column, value in zip(columns, row)
                ]
                digest.update(json.dumps(
                    normalized, ensure_ascii=False, separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8"))
                digest.update(b"\n")
                row_count += 1
        fingerprints[table] = {
            "columns": list(columns),
            "row_count": row_count,
            "sha256": digest.hexdigest(),
        }
    return fingerprints


def _verify_v3(
    connection: duckdb.DuckDBPyConnection,
    checks: Checks,
    expectations: VerificationExpectations,
) -> dict[str, Any]:
    actual_counts: dict[str, int] = {}
    for table, expected in sorted(expectations.v3_table_counts.items()):
        actual = connection.execute(
            f'SELECT count(*) FROM "{table}"'
        ).fetchone()[0]
        actual_counts[table] = int(actual)
        checks.record(f"v3_table_count.{table}", actual, expected)

    replay_rows = connection.execute(
        "SELECT replay_sha256,game_id,patch FROM replays ORDER BY replay_sha256"
    ).fetchall()
    replay_facts: dict[str, dict[str, Any]] = {
        sha: {"game_id": game_id, "patch": patch}
        for sha, game_id, patch in replay_rows
    }
    for table in REPLAY_FACT_TABLES:
        counts = dict(connection.execute(
            f'SELECT replay_sha256,count(*) FROM "{table}" GROUP BY 1'
        ).fetchall())
        for sha in set(replay_facts) | set(counts):
            replay_facts.setdefault(sha, {})[table] = int(counts.get(sha, 0))
    replay_facts = {
        sha: replay_facts[sha] for sha in sorted(replay_facts)
    }
    expected_replay_facts = {
        sha: dict(values)
        for sha, values in sorted(expectations.v3_replay_facts.items())
    }
    checks.record("v3_replay_facts", replay_facts, expected_replay_facts)
    return {"table_counts": actual_counts, "replay_facts": replay_facts}


def _verify_profiles(
    connection: duckdb.DuckDBPyConnection,
    checks: Checks,
    expectations: VerificationExpectations,
) -> dict[str, Any]:
    rows = connection.execute("""
        SELECT replay_sha256,game_id,patch,profile_status,decoded_row_count,
               protection_row_count,details_json,v4_schema_version,
               on_event_decoder_status,shield_damage_decoder_status,
               decoder_profile,decoder_profiles_json
        FROM protection_v4_profiles ORDER BY replay_sha256
    """).fetchall()
    profile_shas = [row[0] for row in rows]
    checks.record("v4_profile_shas", profile_shas, sorted(expectations.profile_shas))
    checks.record(
        "v4_profile_status_distribution",
        _distribution(connection, "protection_v4_profiles", "profile_status"),
        expectations.profile_status_counts,
    )
    checks.record(
        "v4_on_event_status_distribution",
        _distribution(
            connection, "protection_v4_profiles", "on_event_decoder_status"
        ),
        expectations.on_event_status_counts,
    )
    checks.record(
        "v4_shield_damage_status_distribution",
        _distribution(
            connection, "protection_v4_profiles", "shield_damage_decoder_status"
        ),
        expectations.shield_damage_status_counts,
    )
    decoded_total, protection_total = connection.execute("""
        SELECT coalesce(sum(decoded_row_count),0),
               coalesce(sum(protection_row_count),0)
        FROM protection_v4_profiles
    """).fetchone()
    checks.record(
        "v4_profile_decoded_row_count", decoded_total,
        expectations.profile_decoded_row_count,
    )
    checks.record(
        "v4_profile_protection_row_count", protection_total,
        expectations.profile_protection_row_count,
    )

    expected_profiles = [ON_EVENT_DECODER_PROFILE, SHIELD_DAMAGE_DECODER_PROFILE]
    expected_joined = "+".join(expected_profiles)
    bad_contract = 0
    details_v4_only: dict[str, str] = {}
    profile_game_ids: dict[str, str | None] = {}
    for row in rows:
        (sha, game_id, patch, _status, _decoded, _protection, raw_details,
         schema_version, _on_event_status, _shield_status, decoder_profile,
         raw_decoder_profiles) = row
        profile_game_ids[sha] = game_id
        details = _parse_json_object(raw_details)
        decoder_profiles = _parse_json_list(raw_decoder_profiles)
        if details.get("v4_only_replay") is True:
            details_v4_only[sha] = game_id
        if (
            patch != SUPPORTED_PATCH
            or schema_version != 2
            or decoder_profile != expected_joined
            or decoder_profiles != expected_profiles
        ):
            bad_contract += 1
    checks.record("v4_profile_decoder_contract_errors", bad_contract, 0)
    checks.record(
        "v4_only_profiles_details", details_v4_only,
        expectations.v4_only_replays,
    )
    join_v4_only = dict(connection.execute("""
        SELECT p.replay_sha256,p.game_id
        FROM protection_v4_profiles p
        LEFT JOIN replays r USING (replay_sha256)
        WHERE r.replay_sha256 IS NULL
        ORDER BY p.replay_sha256
    """).fetchall())
    checks.record(
        "v4_only_profiles_not_in_frozen_v3", join_v4_only,
        expectations.v4_only_replays,
    )

    expected_game_ids = {
        sha: values["game_id"]
        for sha, values in expectations.v3_replay_facts.items()
    } | dict(expectations.v4_only_replays)
    checks.record("v4_profile_game_ids", profile_game_ids, expected_game_ids)
    return {
        "profile_count": len(rows),
        "profile_shas": profile_shas,
        "v4_only_profiles": join_v4_only,
    }


def _verify_v4_facts(
    connection: duckdb.DuckDBPyConnection,
    checks: Checks,
    expectations: VerificationExpectations,
) -> dict[str, Any]:
    heal_count = connection.execute("SELECT count(*) FROM heal_events").fetchone()[0]
    checks.record("v4_heal_events", heal_count, expectations.heal_event_count)
    shield_distribution = _distribution(
        connection, "shield_state_events", "event_id"
    )
    checks.record(
        "v4_shield_state_event_ids", shield_distribution,
        expectations.shield_event_id_counts,
    )
    protection_distribution = _distribution(
        connection, "protection_events", "protection_kind"
    )
    checks.record(
        "v4_protection_kind_distribution", protection_distribution,
        expectations.protection_kind_counts,
    )
    checks.record(
        "v4_noncanonical_protection_rows",
        connection.execute(
            "SELECT count(*) FROM protection_events WHERE canonical IS DISTINCT FROM true"
        ).fetchone()[0],
        0,
    )
    paired = connection.execute("""
        SELECT count(*) FROM protection_events
        WHERE protection_kind='SHIELD_GENERATED'
          AND paired_source_route_fact_id IS NOT NULL
    """).fetchone()[0]
    checks.record("v4_paired_shield_routes", paired, expectations.paired_shield_count)
    transition_distribution = _distribution(
        connection, "protection_state_transitions", "transition_kind"
    )
    checks.record(
        "v4_transition_kind_distribution", transition_distribution,
        expectations.transition_kind_counts,
    )
    inventory = connection.execute("""
        SELECT count(*),coalesce(sum(cast_count),0),coalesce(sum(target_count),0),
               coalesce(sum(buff_candidate_count),0),
               coalesce(sum(damage_window_count),0)
        FROM protection_spell_inventory
    """).fetchone()
    inventory_actual = {
        "rows": int(inventory[0]), "casts": int(inventory[1]),
        "targets": int(inventory[2]), "buff_candidates": int(inventory[3]),
        "damage_windows": int(inventory[4]),
    }
    inventory_expected = {
        "rows": expectations.inventory_rows,
        "casts": expectations.inventory_casts,
        "targets": expectations.inventory_targets,
        "buff_candidates": expectations.inventory_buff_candidates,
        "damage_windows": expectations.inventory_damage_windows,
    }
    checks.record("v4_protection_spell_inventory", inventory_actual, inventory_expected)

    feature_count, distinct_deaths = connection.execute("""
        SELECT count(*),count(DISTINCT adc_death_id)
        FROM adc_survival_features_v4
    """).fetchone()
    checks.record(
        "v4_adc_survival_features", int(feature_count),
        expectations.adc_survival_features,
    )
    checks.record(
        "v4_adc_survival_distinct_deaths", int(distinct_deaths),
        expectations.adc_survival_features,
    )
    checks.record(
        "v4_adc_survival_orphans",
        connection.execute("""
            SELECT count(*) FROM adc_survival_features_v4 f
            LEFT JOIN adc_deaths d ON d.fact_id=f.adc_death_id
            WHERE d.fact_id IS NULL
        """).fetchone()[0],
        0,
    )

    adc_protection_count = connection.execute(
        "SELECT count(*) FROM adc_death_protection"
    ).fetchone()[0]
    adc_protection_distribution = _distribution(
        connection, "adc_death_protection", "protection_kind"
    )

    absorption_amounts = [row[0] for row in connection.execute("""
        SELECT observed_amount FROM protection_events
        WHERE protection_kind='SHIELD_ABSORBED' ORDER BY observed_amount
    """).fetchall()]
    checks.record(
        "v4_absorption_amounts", absorption_amounts,
        list(expectations.absorption_amounts),
    )

    profile_shas = set(expectations.profile_shas)
    for table in REQUIRED_V4_COLUMNS:
        orphan_count = connection.execute(
            f'''SELECT count(*) FROM "{table}" value
                LEFT JOIN protection_v4_profiles profile USING (replay_sha256)
                WHERE profile.replay_sha256 IS NULL'''
        ).fetchone()[0]
        checks.record(f"v4_profile_orphans.{table}", orphan_count, 0)
        unexpected = {
            row[0] for row in connection.execute(
                f'SELECT DISTINCT replay_sha256 FROM "{table}"'
            ).fetchall()
            if row[0] is not None and row[0] not in profile_shas
        }
        checks.record(f"v4_unexpected_replays.{table}", unexpected, set())

    return {
        "heal_events": int(heal_count),
        "shield_event_ids": shield_distribution,
        "protection_kinds": protection_distribution,
        "transitions": transition_distribution,
        "inventory": inventory_actual,
        "adc_death_protection": {
            "row_count": int(adc_protection_count),
            "kind_distribution": adc_protection_distribution,
        },
        "adc_survival_features": int(feature_count),
        "absorption_amounts": absorption_amounts,
    }


def _verify_null_honesty(
    connection: duckdb.DuckDBPyConnection, checks: Checks,
) -> dict[str, int]:
    queries = {
        "health_state_rows": "SELECT count(*) FROM health_state_events",
        "temporary_hp_rows": "SELECT count(*) FROM temporary_hp_events",
        "heal_unavailable_values": """
            SELECT count(*) FROM heal_events
            WHERE health_before IS NOT NULL OR health_after IS NOT NULL
               OR temporary_hp_before IS NOT NULL OR temporary_hp_after IS NOT NULL
               OR raw_amount IS NOT NULL OR effective_amount IS NOT NULL
               OR overheal_amount IS NOT NULL
        """,
        "shield_unavailable_values": """
            SELECT count(*) FROM shield_state_events
            WHERE health_before IS NOT NULL OR health_after IS NOT NULL
               OR temporary_hp_before IS NOT NULL OR temporary_hp_after IS NOT NULL
               OR raw_amount IS NOT NULL OR effective_amount IS NOT NULL
               OR overheal_amount IS NOT NULL
        """,
        "protection_unavailable_values": """
            SELECT count(*) FROM protection_events
            WHERE raw_amount IS NOT NULL OR effective_amount IS NOT NULL
               OR overheal_amount IS NOT NULL
        """,
        "transition_unavailable_values": """
            SELECT count(*) FROM protection_state_transitions
            WHERE remaining_amount IS NOT NULL OR unused_amount IS NOT NULL
        """,
        "adc_protection_unavailable_values": """
            SELECT count(*) FROM adc_death_protection
            WHERE raw_amount IS NOT NULL OR effective_amount IS NOT NULL
               OR overheal_amount IS NOT NULL
        """,
        "adc_survival_unavailable_values": """
            SELECT count(*) FROM adc_survival_features_v4
            WHERE shield_remaining IS NOT NULL OR shield_unused IS NOT NULL
               OR health_before IS NOT NULL OR health_after IS NOT NULL
               OR temporary_hp_before IS NOT NULL OR temporary_hp_after IS NOT NULL
        """,
        "invalid_heal_direct_fields": """
            SELECT count(*) FROM heal_events
            WHERE event_id != 75 OR source_network_id IS NULL
               OR target_network_id IS NULL OR observed_amount IS NULL
        """,
        "invalid_shield_direct_fields": """
            SELECT count(*) FROM shield_state_events
            WHERE target_network_id IS NULL OR observed_amount IS NULL
               OR (event_id IN (237,238) AND source_network_id IS NULL)
               OR (event_id=23 AND source_network_id IS NOT NULL)
        """,
        "invalid_absorption_source_attribution": """
            SELECT count(*) FROM protection_events
            WHERE protection_kind='SHIELD_ABSORBED'
              AND (source_network_id IS NOT NULL OR target_network_id IS NULL)
        """,
        "invalid_absorption_transition_attribution": """
            SELECT count(*) FROM protection_state_transitions
            WHERE transition_kind='SHIELD_ABSORBED'
              AND (source_network_id IS NOT NULL OR target_network_id IS NULL
                   OR observed_amount IS NULL OR absorbed_amount IS NULL)
        """,
        "invalid_adc_absorption_attribution": """
            SELECT count(*) FROM adc_death_protection
            WHERE protection_kind='SHIELD_ABSORBED'
              AND (source_network_id IS NOT NULL
                   OR source_participant_id IS NOT NULL
                   OR source_is_external_ally IS NOT NULL)
        """,
    }
    results: dict[str, int] = {}
    for name, sql in queries.items():
        actual = int(connection.execute(sql).fetchone()[0])
        results[name] = actual
        checks.record(f"null_honesty.{name}", actual, 0)
    return results


def verify(
    db_path: str | Path = DEFAULT_DB,
    *,
    emulator_path: str | Path = DEFAULT_EMULATOR,
    expectations: VerificationExpectations = DEFAULT_EXPECTATIONS,
) -> dict[str, Any]:
    db_path = Path(db_path).resolve()
    emulator_path = Path(emulator_path).resolve()
    checks = Checks()
    summary: dict[str, Any] = {}

    checks.record(
        "database_file", str(db_path), condition=db_path.is_file(),
        expected="existing DuckDB file",
    )
    checks.record(
        "frozen_emulator_file", str(emulator_path),
        condition=emulator_path.is_file(), expected="existing file",
    )
    emulator_hash = sha256_file(emulator_path) if emulator_path.is_file() else None
    checks.record(
        "frozen_emulator_sha256", emulator_hash, expectations.emulator_sha256,
    )

    if db_path.is_file():
        try:
            with duckdb.connect(str(db_path), read_only=True) as connection:
                tables = {row[0] for row in connection.execute("SHOW TABLES").fetchall()}
                required_tables = (
                    set(expectations.v3_table_counts) | set(REQUIRED_V4_COLUMNS)
                )
                missing_tables = sorted(required_tables - tables)
                checks.record("required_tables", missing_tables, [])
                missing_columns: dict[str, list[str]] = {}
                if not missing_tables:
                    basic_columns = {
                        "replays": {"replay_sha256", "game_id", "patch"},
                        **{
                            table: {"replay_sha256"}
                            for table in REPLAY_FACT_TABLES
                        },
                        "adc_deaths": {"fact_id", "replay_sha256"},
                    }
                    for table, required in (
                        basic_columns | REQUIRED_V4_COLUMNS
                    ).items():
                        missing = sorted(required - _columns(connection, table))
                        if missing:
                            missing_columns[table] = missing
                checks.record("required_columns", missing_columns, {})
                if not missing_tables and not missing_columns:
                    summary["v3"] = _verify_v3(connection, checks, expectations)
                    summary["profiles"] = _verify_profiles(
                        connection, checks, expectations
                    )
                    summary["v4"] = _verify_v4_facts(
                        connection, checks, expectations
                    )
                    summary["null_honesty"] = _verify_null_honesty(
                        connection, checks
                    )
                    summary["semantic_fingerprints"] = _semantic_fingerprints(
                        connection
                    )
                checks.record("database_read_only_queries", "completed", "completed")
        except Exception as exc:  # Keep CLI output machine-readable on locks/schema faults.
            checks.record(
                "database_read_only_queries",
                {"error_type": type(exc).__name__},
                "completed",
                condition=False,
            )

    failures = sorted(
        name for name, value in checks.values.items() if not value["pass"]
    )
    passed = not failures
    return {
        "schema_version": 1,
        "status": "PROTECTION_V4_COMPLETE" if passed else "FAIL",
        "database": {"path": str(db_path), "read_only": True},
        "emulator": {
            "path": str(emulator_path),
            "sha256": emulator_hash,
            "expected_sha256": expectations.emulator_sha256,
        },
        "checks": checks.values,
        "failures": failures,
        "summary": summary,
    }


def render(result: Mapping[str, Any]) -> str:
    return json.dumps(
        result, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--emulator", default=str(DEFAULT_EMULATOR))
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    result = verify(args.db, emulator_path=args.emulator)
    output_path = Path(args.output).resolve() if args.output else None
    protected_paths = {
        Path(args.db).resolve(): "database",
        Path(args.emulator).resolve(): "emulator",
    }
    output_conflict = protected_paths.get(output_path) if output_path else None
    if output_conflict:
        result["checks"]["output_path_safety"] = {
            "actual": str(output_path),
            "expected": f"path distinct from {output_conflict}",
            "pass": False,
        }
        result["failures"] = sorted(
            set(result["failures"]) | {"output_path_safety"}
        )
        result["status"] = "FAIL"
    output = render(result)
    print(output, end="")
    if output_path and not output_conflict:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
    return 0 if result["status"] == "PROTECTION_V4_COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
