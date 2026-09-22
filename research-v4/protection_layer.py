"""Lossless, additive materialization of decoded OnEvent (0x009e) protection rows."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import struct
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import duckdb

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "research-v3" / "output" / "replay_research.duckdb"
SUPPORTED_PATCH = "16.15.801.3452"
EXPECTED_RUNTIME_IMAGE_SHA256 = "7ee788155b9ba61d10603694cffb095e66ab3c641f933e4e7b181000c69f61bb"
RUNTIME_IMAGE = ROOT / "artifacts" / "runtime_probe" / "league_16.15.801.3452.memory.bin"
ON_EVENT_DECODER_PROFILE = "rofl-16.15.801.3452-on-event-protection-v4"
SHIELD_DAMAGE_DECODER_PROFILE = "rofl-16.15.801.3452-unit-apply-shield-damage-v4"
DECODER_STREAMS = {
    ON_EVENT_DECODER_PROFILE: {"packet_id": 0x009E, "requires_network_checks": False},
    SHIELD_DAMAGE_DECODER_PROFILE: {"packet_id": 0x0017, "requires_network_checks": True},
}
ON_EVENT_CONTRACTS = {
    0x4B: {
        "event_name": "OnCastHeal", "parameter_type": "ParamsHeal",
        "expected_schema_id": 0x7C044FE1, "expected_size": 0x34,
        "event_kind": "HEAL_REPORTED_DIRECT", "route_kind": "HEAL_EVENT",
        "canonical_route": True,
    },
    0xED: {
        "event_name": "OnReceiveShield", "parameter_type": "ShieldingParams",
        "expected_schema_id": 0x8F7F3F4E, "expected_size": 0x14,
        "event_kind": "SHIELD_APPLICATION_DIRECT", "route_kind": "TARGET_ROUTE",
        "canonical_route": True,
    },
    0xEE: {
        "event_name": "OnGrantShield", "parameter_type": "ShieldingParams",
        "expected_schema_id": 0x8F7F3F4E, "expected_size": 0x14,
        "event_kind": "SHIELD_APPLICATION_DIRECT",
        "route_kind": "SOURCE_ROUTE_DUPLICATE", "canonical_route": False,
    },
}
ON_EVENT_RAW_REF_FIELDS = (
    "replay_path", "replay_sha256", "chunk_index", "chunk_id", "chunk_stream",
    "chunk_file_offset", "compressed_body_offset", "decompressed_block_offset",
    "decompressed_payload_offset", "replay_time_ms", "occurrence_index",
    "packet_id", "payload_length", "raw_param", "raw_param_hex",
    "raw_payload_sha256",
)
V4_TABLES = (
    "adc_survival_features_v4", "adc_death_protection", "protection_spell_inventory",
    "protection_state_transitions", "protection_events", "temporary_hp_events",
    "heal_events", "shield_state_events", "health_state_events", "protection_v4_profiles",
)


def _id(*parts: Any) -> str:
    return hashlib.sha256("\x1f".join(map(str, parts)).encode()).hexdigest()


def _json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, sort_keys=True)


def _get(row: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in row and row[name] is not None:
            return row[name]
    return None


def _integer(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def _event_id(fields: dict[str, Any]) -> int | None:
    return _integer(_get(fields, "event_id"))


def _normalized_fields(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize generic-emulator, dedicated-V4, and semantic JSONL rows."""
    decoded = row.get("decoded_fields")
    if isinstance(decoded, dict):
        return decoded
    packet_id = _integer(
        _get(row, "packet_id", "decoded_opcode") or _get(_raw_ref(row), "packet_id")
    )
    if packet_id == 0x0017 or row.get("event_kind") == "SHIELD_ABSORBED_DIRECT":
        return {
            "event_id": 0x0017,
            "source_network_id": None,
            "target_network_id": _get(row, "target_network_id"),
            "amount": _get(row, "shield_absorbed_amount"),
            "amount_bits_hex": _get(row, "shield_absorbed_amount_bits_hex"),
            "event_params_size": None,
            "event_params_sha256": None,
            "event_params_hex": None,
        }
    event_id = _get(row, "event_id", "protocol_event_id")
    if event_id is None and isinstance(row.get("route_event_ids"), list):
        routes = row["route_event_ids"]
        event_id = 0xED if 0xED in routes else (routes[0] if routes else None)
    if event_id is None:
        return {}
    event_id = _integer(event_id)
    amount = _get(row, "amount")
    if amount is None:
        amount = _get(row, "direct_heal_amount") if event_id == 0x4B else _get(
            row, "generated_amount"
        )
    return {
        "event_id": event_id,
        "source_network_id": _get(row, "source_network_id"),
        "target_network_id": _get(row, "target_network_id"),
        "amount": amount,
        "amount_bits_hex": _get(row, "amount_bits_hex"),
        "event_params_size": _get(row, "parameter_size", "event_params_size"),
        "event_params_sha256": _get(
            row, "parameter_blob_sha256", "event_params_sha256"
        ),
        "event_params_hex": _get(row, "parameter_blob_hex", "event_params_hex"),
    }


def _raw_ref(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("raw_packet_ref")
    return raw if isinstance(raw, dict) else {}


def _packet_id(row: dict[str, Any]) -> int | None:
    return _integer(_get(row, "packet_id", "decoded_opcode",) or _get(_raw_ref(row), "packet_id"))


def _is_structural_protection_row(row: dict[str, Any]) -> bool:
    fields = _normalized_fields(row)
    event_id = _event_id(fields)
    size = _integer(_get(fields, "event_params_size", "params_size"))
    if _packet_id(row) == 0x0017 and event_id == 0x0017:
        return True
    return (event_id == 0x4B and size == 0x34) or (
        event_id in (0xED, 0xEE) and size == 0x14
    )


def _is_protection_row(row: dict[str, Any]) -> bool:
    """Accept only verified layouts with directly observed finite amounts."""
    fields = _normalized_fields(row)
    if not _is_structural_protection_row(row):
        return False
    amount = _get(fields, "amount")
    try:
        valid_amount = amount is not None and math.isfinite(float(amount)) and float(amount) >= 0
    except (TypeError, ValueError):
        valid_amount = False
    if not valid_amount or _integer(_get(fields, "target_network_id", "target")) is None:
        return False
    if _packet_id(row) == 0x0017:
        raw = _raw_ref(row)
        payload = _valid_hex(row.get("raw_payload_hex"))
        field_bytes = row.get("decoded_field_bytes_hex")
        amount_bits = _get(fields, "amount_bits_hex")
        try:
            amount = float(_get(fields, "amount"))
            expected_bits = struct.unpack("<I", struct.pack("<f", amount))[0]
            decoded_amount = _valid_hex(field_bytes.get("field_18")) if isinstance(field_bytes, dict) else None
            decoded_target = _valid_hex(field_bytes.get("field_14")) if isinstance(field_bytes, dict) else None
        except (TypeError, ValueError, struct.error, OverflowError):
            return False
        return (
            row.get("event_kind") == "SHIELD_ABSORBED_DIRECT"
            and row.get("semantic_status") == "VERIFIED_DIRECT"
            and row.get("decoder_profile") == SHIELD_DAMAGE_DECODER_PROFILE
            and row.get("decoder_runtime_image_sha256") == EXPECTED_RUNTIME_IMAGE_SHA256
            and row.get("deserialize_return_al") not in (None, 0)
            and row.get("fully_consumed") is True
            and row.get("network_fields_agree") is True
            and row.get("target_matches_raw_param") is True
            and raw
            and _packet_id(row) == 0x0017
            and _integer(raw.get("packet_id")) == 0x0017
            and all(field in raw and raw[field] is not None for field in ON_EVENT_RAW_REF_FIELDS)
            and all(
                field not in row or row[field] is None or row[field] == raw[field]
                for field in ON_EVENT_RAW_REF_FIELDS
                if field not in ("packet_id", "payload_length")
            )
            and payload is not None
            and len(payload) == _integer(raw.get("payload_length"))
            and row.get("raw_payload_sha256") == hashlib.sha256(payload).hexdigest()
            and row.get("raw_payload_sha256") == raw.get("raw_payload_sha256")
            and _same_integer(row.get("raw_param"), row.get("raw_param_hex"))
            and _same_integer(raw.get("raw_param"), raw.get("raw_param_hex"))
            and _same_integer(row.get("raw_param"), _get(fields, "target_network_id"))
            and math.isfinite(amount) and amount >= 0
            and amount_bits == f"0x{expected_bits:08x}"
            and decoded_amount is not None and len(decoded_amount) == 4
            and struct.unpack("<I", decoded_amount)[0] == expected_bits
            and decoded_target is not None and len(decoded_target) == 4
            and _same_integer(_get(fields, "target_network_id"), struct.unpack("<I", decoded_target)[0])
        )
    return _is_pinned_on_event_row(row, fields)


def _valid_hex(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _same_integer(left: Any, right: Any) -> bool:
    try:
        return _integer(left) == _integer(right)
    except (TypeError, ValueError):
        return False


def _is_pinned_on_event_row(row: dict[str, Any], fields: dict[str, Any]) -> bool:
    """Require the exact dedicated decoder contract for standalone 0x009e input."""
    # Generic-emulator and semantic rows use decoded_fields or a looser schema.
    if isinstance(row.get("decoded_fields"), dict) or row.get("schema_version") != 1:
        return False
    event_id = _event_id(fields)
    contract = ON_EVENT_CONTRACTS.get(event_id)
    raw = _raw_ref(row)
    if not contract or not raw:
        return False
    try:
        if (
            _packet_id(row) != 0x009E
            or _integer(raw.get("packet_id")) != 0x009E
            or row.get("decoder_profile") != ON_EVENT_DECODER_PROFILE
            or row.get("decoder_runtime_image_sha256") != EXPECTED_RUNTIME_IMAGE_SHA256
            or row.get("replay_version") != SUPPORTED_PATCH
            or row.get("semantic_status") != "VERIFIED_DIRECT"
            or row.get("deserialize_return_al") in (None, 0)
            or row.get("fully_consumed") is not True
            or row.get("schema_matches_expected") is not True
            or row.get("parameter_size_matches_expected") is not True
            or row.get("amount_is_finite") is not True
            or _integer(row.get("schema_id")) != contract["expected_schema_id"]
            or _integer(row.get("expected_schema_id")) != contract["expected_schema_id"]
            or _integer(_get(fields, "event_params_size")) != contract["expected_size"]
            or _integer(row.get("expected_size")) != contract["expected_size"]
            or row.get("event_id_hex") != f"0x{event_id:04x}"
            or row.get("schema_id_hex") != f"0x{contract['expected_schema_id']:08x}"
            or row.get("event_name") != contract["event_name"]
            or row.get("parameter_type") != contract["parameter_type"]
            or row.get("event_kind") != contract["event_kind"]
            or row.get("route_kind") != contract["route_kind"]
            or row.get("canonical_route") is not contract["canonical_route"]
        ):
            return False
    except (TypeError, ValueError):
        return False
    if any(field not in raw or raw[field] is None for field in ON_EVENT_RAW_REF_FIELDS):
        return False
    if any(
        field not in row or row[field] is None or row[field] != raw[field]
        for field in ON_EVENT_RAW_REF_FIELDS
        if field not in ("packet_id", "payload_length")
    ):
        return False
    parameter_bytes = _valid_hex(row.get("parameter_blob_hex"))
    payload_bytes = _valid_hex(row.get("raw_payload_hex"))
    outer_object = _valid_hex(row.get("outer_object_hex"))
    if not parameter_bytes or payload_bytes is None or not outer_object:
        return False
    if (
        len(parameter_bytes) != contract["expected_size"]
        or row.get("parameter_blob_sha256") != hashlib.sha256(parameter_bytes).hexdigest()
        or len(payload_bytes) != _integer(raw.get("payload_length"))
        or row.get("raw_payload_sha256") != hashlib.sha256(payload_bytes).hexdigest()
        or row.get("raw_payload_sha256") != raw.get("raw_payload_sha256")
        or not _same_integer(row.get("raw_param"), row.get("raw_param_hex"))
        or not _same_integer(raw.get("raw_param"), raw.get("raw_param_hex"))
    ):
        return False
    try:
        if event_id == 0x4B:
            target, source, amount_bits = (
                struct.unpack_from("<I", parameter_bytes, 0x04)[0],
                struct.unpack_from("<I", parameter_bytes, 0x14)[0],
                struct.unpack_from("<I", parameter_bytes, 0x18)[0],
            )
        else:
            source, target, amount_bits = (
                struct.unpack_from("<I", parameter_bytes, 0x08)[0],
                struct.unpack_from("<I", parameter_bytes, 0x0C)[0],
                struct.unpack_from("<I", parameter_bytes, 0x10)[0],
            )
        amount = float(row.get("amount"))
        expected_bits = struct.unpack("<I", struct.pack("<f", amount))[0]
    except (TypeError, ValueError, struct.error, OverflowError):
        return False
    return (
        math.isfinite(amount)
        and amount >= 0
        and row.get("amount_bits_hex") == f"0x{amount_bits:08x}"
        and amount_bits == expected_bits
        and _same_integer(row.get("source_network_id"), source)
        and _same_integer(row.get("target_network_id"), target)
    )


def _provenance(row: dict[str, Any], fields: dict[str, Any]) -> dict[str, Any]:
    """Preserve the complete decoded line plus canonical aliases for auditing."""
    raw = _raw_ref(row)
    raw_occ = _get(
        row, "raw_occurrence_index", "raw_packet_occurrence_index", "occurrence_index"
    )
    if raw_occ is None:
        raw_occ = _get(raw, "raw_occurrence_index", "occurrence_index")
    def source(*names: str) -> Any:
        value = _get(row, *names)
        return value if value is not None else _get(raw, *names)
    return {
        "chunk_index": source("chunk_index"), "chunk_id": source("chunk_id"),
        "chunk_stream": source("chunk_stream", "stream"),
        "chunk_file_offset": source("chunk_file_offset", "file_offset"),
        "compressed_body_offset": source("compressed_body_offset", "compressed_offset"),
        "decompressed_block_offset": source("decompressed_block_offset"),
        "decompressed_payload_offset": source("decompressed_payload_offset"),
        "global_occurrence_index": source("global_occurrence_index", "occurrence_index"),
        "raw_occurrence_index": raw_occ,
        "packet_occurrence_index": source("packet_occurrence_index", "packet_occurrence", "record_index"),
        "raw_param": source("raw_param", "param"), "raw_param_hex": source("raw_param_hex"),
        "raw_payload_length": source("payload_length", "raw_payload_length"),
        "raw_payload_sha256": source("raw_payload_sha256", "payload_sha256"),
        "raw_payload_hex": source("raw_payload_hex", "payload_hex"),
        "params_length": _get(fields, "event_params_size", "params_size"),
        "params_sha256": _get(fields, "event_params_sha256", "params_sha256"),
        "params_hex": _get(fields, "event_params_hex", "params_hex"),
        "decoded_row": row,
    }


def _base_values(fact_id: str, sha: str, game_id: str | None, row: dict[str, Any], fields: dict[str, Any], amount: float | None) -> tuple[Any, ...]:
    p = _provenance(row, fields)
    return (fact_id, sha, game_id, _get(row, "replay_time_ms", "timestamp_ms"), _event_id(fields),
            _integer(_get(fields, "source_network_id", "source")), _integer(_get(fields, "target_network_id", "target")), amount,
            None, None, None, None, None, None, None,
            p["chunk_index"], p["chunk_id"], p["chunk_stream"], p["chunk_file_offset"],
            p["compressed_body_offset"], p["decompressed_block_offset"], p["decompressed_payload_offset"],
            p["global_occurrence_index"], p["raw_occurrence_index"], p["packet_occurrence_index"],
            p["raw_param"], p["raw_param_hex"], p["raw_payload_length"], p["raw_payload_sha256"],
            p["raw_payload_hex"], p["params_length"], p["params_sha256"], p["params_hex"], _json(p))


def init_v4(connection: duckdb.DuckDBPyConnection) -> None:
    connection.execute(Path(__file__).with_name("schema.sql").read_text(encoding="utf-8"))
    # Migrate only additive V4 tables created by earlier local V4 iterations.
    connection.execute("DROP INDEX IF EXISTS idx_v4_adc_protection")
    for statement in (
        "ALTER TABLE protection_v4_profiles ADD COLUMN IF NOT EXISTS v4_schema_version INTEGER DEFAULT 2",
        "ALTER TABLE protection_v4_profiles ADD COLUMN IF NOT EXISTS on_event_decoder_status VARCHAR",
        "ALTER TABLE protection_v4_profiles ADD COLUMN IF NOT EXISTS shield_damage_decoder_status VARCHAR",
        "ALTER TABLE protection_v4_profiles ADD COLUMN IF NOT EXISTS decoder_profiles_json JSON",
        "ALTER TABLE protection_spell_inventory ADD COLUMN IF NOT EXISTS cast_count BIGINT",
        "ALTER TABLE protection_spell_inventory ADD COLUMN IF NOT EXISTS target_count BIGINT",
        "ALTER TABLE protection_spell_inventory ADD COLUMN IF NOT EXISTS buff_candidate_count BIGINT",
        "ALTER TABLE protection_spell_inventory ADD COLUMN IF NOT EXISTS damage_window_count BIGINT",
        "ALTER TABLE protection_spell_inventory ADD COLUMN IF NOT EXISTS first_cast_ms BIGINT",
        "ALTER TABLE protection_spell_inventory ADD COLUMN IF NOT EXISTS last_cast_ms BIGINT",
        "ALTER TABLE adc_death_protection ALTER COLUMN source_is_external_ally DROP NOT NULL",
    ):
        connection.execute(statement)
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_v4_adc_protection ON adc_death_protection(adc_death_id, replay_time_ms)"
    )


def _iter_jsonl(paths: Iterable[str | Path]) -> Iterable[dict[str, Any]]:
    for path in paths:
        with Path(path).open(encoding="utf-8") as stream:
            for line in stream:
                if line.strip():
                    yield json.loads(line)


def _rows_for_target(rows: Iterable[dict[str, Any]], sha: str) -> list[dict[str, Any]]:
    return [
        row for row in rows
        if _get(row, "replay_sha256") == sha and _packet_id(row) in (0x009E, 0x0017)
    ]


def _delete_target(connection: duckdb.DuckDBPyConnection, sha: str) -> None:
    for table in V4_TABLES:
        connection.execute(f"DELETE FROM {table} WHERE replay_sha256=?", [sha])


def _participants(connection: duckdb.DuckDBPyConnection, sha: str) -> dict[int, dict[str, Any]]:
    rows = connection.execute("SELECT participant_id,network_id,team_id,champion FROM participants WHERE replay_sha256=?", [sha]).fetchall()
    return {r[1]: {"participant_id": r[0], "team_id": r[2], "champion": r[3]} for r in rows if r[1] is not None}


def _bulk_insert(
    connection: duckdb.DuckDBPyConnection, table: str, values: list[tuple[Any, ...]],
) -> None:
    """Stage one Python batch as JSONL, then let DuckDB import it vectorially."""
    if not values:
        return
    columns = [row[1] for row in connection.execute(
        f"PRAGMA table_info('{table}')"
    ).fetchall()]
    if any(len(value) != len(columns) for value in values):
        raise ValueError(f"{table} bulk insert value count does not match schema")
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".jsonl", delete=False
    ) as stream:
        staging_path = Path(stream.name)
        for value in values:
            stream.write(_json(dict(zip(columns, value))) + "\n")
    selected = ",".join(f'"{column}"' for column in columns)
    try:
        connection.execute(
            f"INSERT INTO {table} ({selected}) SELECT {selected} "
            "FROM read_json_auto(?)",
            [str(staging_path)],
        )
    finally:
        staging_path.unlink(missing_ok=True)


def _insert_raw_events(connection: duckdb.DuckDBPyConnection, sha: str, game_id: str | None, rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    heals: list[dict[str, Any]] = []
    targets: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    absorptions: list[dict[str, Any]] = []
    heal_values: list[tuple[Any, ...]] = []
    shield_values: list[tuple[Any, ...]] = []
    for index, row in enumerate(rows):
        fields = _normalized_fields(row)
        event_id = _event_id(fields)
        if event_id not in (0x0017, 0x4B, 0xED, 0xEE):
            continue
        amount = _get(fields, "amount")
        amount = float(amount) if amount is not None else None
        raw = _raw_ref(row)
        occurrence = _get(
            row, "raw_occurrence_index", "raw_packet_occurrence_index", "occurrence_index"
        )
        if occurrence is None:
            occurrence = _get(raw, "raw_occurrence_index", "occurrence_index")
        fact_id = _id("v4-raw", sha, index, occurrence, event_id)
        record = {"row": row, "fields": fields, "fact_id": fact_id, "amount": amount, "index": index,
                  "time": _get(row, "replay_time_ms", "timestamp_ms"), "occ": occurrence,
                  "params": _get(fields, "event_params_hex", "params_hex"),
                  "params_sha256": _get(fields, "event_params_sha256", "params_sha256")}
        base = _base_values(fact_id, sha, game_id, row, fields, amount)
        if event_id == 0x4B:
            heal_values.append(base)
            heals.append(record)
        elif event_id == 0x0017:
            shield_values.append(base)
            absorptions.append(record)
        else:
            shield_values.append(base)
            (targets if event_id == 0xED else sources).append(record)
    _bulk_insert(connection, "heal_events", heal_values)
    _bulk_insert(connection, "shield_state_events", shield_values)
    return heals, targets, sources, absorptions


def _insert_protection_events(connection: duckdb.DuckDBPyConnection, sha: str, game_id: str | None, heals: list[dict[str, Any]], targets: list[dict[str, Any]], sources: list[dict[str, Any]], absorptions: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    source_by_key = {
        (x["time"], x["params_sha256"], x["params"], x["occ"]): x
        for x in sources
        if x["occ"] is not None and x["params"] is not None and x["params_sha256"] is not None
    }
    canonical_shields: list[dict[str, Any]] = []
    canonical_heals: list[dict[str, Any]] = []
    protection_values: list[tuple[Any, ...]] = []
    transition_values: list[list[Any]] = []
    for target in targets:
        paired = None
        if (
            isinstance(target["occ"], int)
            and target["params"] is not None
            and target["params_sha256"] is not None
        ):
            paired = source_by_key.get(
                (
                    target["time"], target["params_sha256"], target["params"],
                    target["occ"] - 1,
                )
            )
        values = _base_values(target["fact_id"], sha, game_id, target["row"], target["fields"], target["amount"])
        # Use the first 8 base items, then V4 semantic columns, then provenance tail.
        row = values[:4] + ("SHIELD_GENERATED",) + values[5:8] + (None, None, None, True, None, None, paired["fact_id"] if paired else None) + values[15:]
        protection_values.append(row)
        target["paired"] = paired
        canonical_shields.append(target)
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for heal in heals:
        if heal["params"] is not None and heal["params_sha256"] is not None:
            key = ("EXACT_BLOB", heal["time"], heal["params_sha256"], heal["params"])
        else:
            key = ("NO_BLOB_IDENTITY", heal["fact_id"])
        groups[key].append(heal)
    for grouped in groups.values():
        grouped.sort(key=lambda item: (item["occ"] is None, item["occ"], item["index"]))
        first = grouped[0]
        values = _base_values(first["fact_id"], sha, game_id, first["row"], first["fields"], first["amount"])
        row = values[:4] + ("HEAL_REPORTED",) + values[5:8] + (None, None, None, True, len(grouped), first["occ"], None) + values[15:]
        protection_values.append(row)
        first["group"] = grouped
        canonical_heals.append(first)
    for absorption in absorptions:
        values = _base_values(
            absorption["fact_id"], sha, game_id, absorption["row"],
            absorption["fields"], absorption["amount"],
        )
        row = values[:4] + ("SHIELD_ABSORBED",) + values[5:8] + (None, None, None, True, None, None, None) + values[15:]
        protection_values.append(row)
        transition_values.append(
            [
                _id("v4-shield-absorbed-transition", absorption["fact_id"]), sha,
                game_id, absorption["time"], "SHIELD_ABSORBED", None,
                _integer(_get(absorption["fields"], "target_network_id", "target")),
                absorption["amount"], None, absorption["amount"], None,
                _json({"protection_event_fact_id": absorption["fact_id"], "raw": absorption["row"]}),
            ]
        )
    _bulk_insert(connection, "protection_events", protection_values)
    _bulk_insert(connection, "protection_state_transitions", transition_values)
    return canonical_shields, canonical_heals, absorptions


def _inventory(connection: duckdb.DuckDBPyConnection, sha: str, game_id: str | None) -> None:
    """Aggregate V3-observed protection casts without inventing amounts."""
    try:
        rows = connection.execute(
            """SELECT fact_id,source_network_id,source_participant_id,source_champion,
                      spell_identifier,spell_slot,replay_time_ms,target_network_id,
                      target_count,raw_provenance_json
               FROM spell_events WHERE replay_sha256=?""",
            [sha],
        ).fetchall()
        buff_rows = connection.execute(
            "SELECT replay_time_ms,source_network_id,target_network_id FROM buff_events WHERE replay_sha256=?",
            [sha],
        ).fetchall()
        damage_rows = connection.execute(
            "SELECT replay_time_ms,target_network_id FROM damage_events WHERE replay_sha256=?",
            [sha],
        ).fetchall()
    except duckdb.Error:
        return
    buffs_by_time_source: dict[tuple[Any, Any], list[Any]] = defaultdict(list)
    for time, source, target in buff_rows:
        buffs_by_time_source[(time, source)].append(target)
    damage_by_target: dict[Any, list[int]] = defaultdict(list)
    for time, target in damage_rows:
        if time is not None:
            damage_by_target[target].append(time)
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        raw = json.loads(row[9]) if isinstance(row[9], str) else (row[9] or {})
        kind = raw.get("protection_cast_kind")
        if not kind:
            continue
        key = (row[1], row[2], row[3], row[4], row[5], kind)
        group = groups.setdefault(
            key,
            {
                "cast_fact_ids": [], "cast_count": 0, "target_count": 0,
                "buff_candidate_count": 0, "damage_window_count": 0,
                "first_cast_ms": row[6], "last_cast_ms": row[6],
            },
        )
        group["cast_fact_ids"].append(row[0])
        group["cast_count"] += 1
        group["target_count"] += row[8] or (1 if row[7] is not None else 0)
        same_time_buffs = buffs_by_time_source.get((row[6], row[1]), [])
        group["buff_candidate_count"] += sum(
            row[7] is None or target == row[7] for target in same_time_buffs
        )
        if row[7] is not None and any(
            abs(time - row[6]) <= 100 for time in damage_by_target.get(row[7], [])
        ):
            group["damage_window_count"] += 1
        group["first_cast_ms"] = min(group["first_cast_ms"], row[6])
        group["last_cast_ms"] = max(group["last_cast_ms"], row[6])
    for key, group in groups.items():
        source, participant, champion, spell, slot, kind = key
        provenance = {
            "source": "V3_VERIFIED_DIRECT_CAST_SPELL_CLASSIFICATION",
            "amount_inference": "NONE",
            "buff_candidate_rule": "EXACT_TIMESTAMP_SOURCE_AND_COMPATIBLE_TARGET",
            "damage_window_rule": "TARGET_DAMAGE_WITHIN_100MS_OF_CAST",
            **group,
        }
        connection.execute(
            """INSERT INTO protection_spell_inventory
               (fact_id,replay_sha256,game_id,source_network_id,source_participant_id,
                champion,spell_identifier,spell_slot,protection_cast_kind,replay_time_ms,
                raw_provenance_json,cast_count,target_count,buff_candidate_count,
                damage_window_count,first_cast_ms,last_cast_ms)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [
                _id("v4-spell-inventory", sha, *key), sha, game_id, source,
                participant, champion, spell, slot, kind, group["first_cast_ms"],
                _json(provenance), group["cast_count"], group["target_count"],
                group["buff_candidate_count"], group["damage_window_count"],
                group["first_cast_ms"], group["last_cast_ms"],
            ],
        )


def _adc_contexts(connection: duckdb.DuckDBPyConnection, sha: str, game_id: str | None, participants: dict[int, dict[str, Any]], shields: list[dict[str, Any]], heals: list[dict[str, Any]], absorptions: list[dict[str, Any]], *, on_event_available: bool, shield_damage_available: bool) -> None:
    try:
        deaths = connection.execute("SELECT fact_id,adc_participant_id,combat_start_ms,death_time_ms FROM adc_deaths WHERE replay_sha256=?", [sha]).fetchall()
        damage = connection.execute("SELECT replay_time_ms,target_network_id,amount,damage_type,is_basic_attack,spell FROM damage_events WHERE replay_sha256=?", [sha]).fetchall()
    except duckdb.CatalogException:
        return
    for death_id, adc_pid, start, death_time in deaths:
        adc = next((p for p in participants.values() if p["participant_id"] == adc_pid), None)
        if not adc:
            continue
        target = next((network for network, p in participants.items() if p is adc), None)
        contexts: list[tuple[str, dict[str, Any], float | None, float | None, float | None]] = []
        for event in shields:
            f = event["fields"]; source = _integer(_get(f, "source_network_id", "source")); recipient = _integer(_get(f, "target_network_id", "target"))
            ally = participants.get(source)
            if recipient == target and ally and source != target and ally["team_id"] == adc["team_id"] and start <= event["time"] <= death_time:
                contexts.append(("SHIELD_GENERATED", event, event["amount"], None, None))
        for event in heals:
            f = event["fields"]; source = _integer(_get(f, "source_network_id", "source")); recipient = _integer(_get(f, "target_network_id", "target"))
            ally = participants.get(source); grouped = event["group"]
            if recipient == target and ally and source != target and ally["team_id"] == adc["team_id"] and start <= event["time"] <= death_time:
                lower = event["amount"]
                upper = sum(item["amount"] for item in grouped)
                contexts.append(("HEAL_REPORTED", event, None, lower, upper))
        for kind, event, shield_value, low, high in contexts:
            f = event["fields"]; source = _integer(_get(f, "source_network_id", "source"))
            connection.execute("INSERT INTO adc_death_protection VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
                _id("v4-adc-context", death_id, event["fact_id"]), sha, game_id, death_id, event["time"], kind, source,
                participants[source]["participant_id"], target, shield_value, low, high, None, None, None, True,
                _json({"protection_event_fact_id": event["fact_id"], "raw": event["row"]})])
        death_absorptions = [
            event for event in absorptions
            if _integer(_get(event["fields"], "target_network_id", "target")) == target
            and start <= event["time"] <= death_time
        ]
        for event in death_absorptions:
            connection.execute("INSERT INTO adc_death_protection VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
                _id("v4-adc-context", death_id, event["fact_id"]), sha, game_id,
                death_id, event["time"], "SHIELD_ABSORBED", None, None, target,
                event["amount"], None, None, None, None, None, None,
                _json({
                    "protection_event_fact_id": event["fact_id"],
                    "source_attribution_status": "UNATTRIBUTED_TARGET_TOTAL",
                    "raw": event["row"],
                }),
            ])
        shield_total = (
            sum(item[2] for item in contexts if item[0] == "SHIELD_GENERATED")
            if on_event_available else None
        )
        lower_total = (
            sum(item[3] for item in contexts if item[0] == "HEAL_REPORTED")
            if on_event_available else None
        )
        upper_total = (
            sum(item[4] for item in contexts if item[0] == "HEAL_REPORTED")
            if on_event_available else None
        )
        absorbed_total = (
            sum(event["amount"] for event in death_absorptions)
            if shield_damage_available
            else None
        )
        incoming = [r for r in damage if r[1] == target and start <= r[0] <= death_time]
        damage_total = (
            sum(r[2] for r in incoming)
            if all(r[2] is not None for r in incoming)
            else None
        )
        type_counts = dict(Counter((r[3] or "UNKNOWN") for r in incoming))
        connection.execute("INSERT INTO adc_survival_features_v4 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", [
            _id("v4-adc-feature", death_id), sha, game_id, death_id, start, death_time, shield_total, lower_total, upper_total,
            (lower_total == upper_total) if on_event_available else None,
            len(incoming), damage_total, _json(type_counts), sum(bool(r[4]) for r in incoming),
            sum(r[5] is not None for r in incoming), None, absorbed_total, None, None, None, None, None,
            _json({
                "external_context_count": len(contexts),
                "unattributed_target_shield_absorption_count": len(death_absorptions),
                "on_event_available": on_event_available,
                "shield_damage_available": shield_damage_available,
                "damage_event_count": len(incoming),
            })])


def _summary_paths(path: Path) -> list[Path]:
    return [
        candidate for candidate in (
            Path(f"{path}.summary.json"), path.with_suffix(".summary.json")
        ) if candidate.exists()
    ]


def _stream_for_rows(rows: list[dict[str, Any]]) -> str | None:
    packet_ids = {_packet_id(row) for row in rows}
    matches = [
        profile for profile, stream in DECODER_STREAMS.items()
        if packet_ids == {stream["packet_id"]}
    ]
    return matches[0] if len(matches) == 1 else None


def _validate_decoder_bundle(
    path: Path, rows: list[dict[str, Any]], summary: dict[str, Any],
) -> tuple[str, list[str]] | None:
    """Validate one decoded file, its hash-bound summary, and export manifest."""
    profile = summary.get("decoder_profile")
    stream = DECODER_STREAMS.get(profile)
    if stream is None:
        return None
    manifest_value = summary.get("events_manifest_path")
    if not isinstance(manifest_value, str):
        return None
    try:
        manifest_path = Path(manifest_value).resolve()
        manifest_bytes = manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        events_path = Path(summary["events_path"]).resolve()
        events_bytes = events_path.read_bytes()
        scan_replays = summary["scan_replays"]
        manifest_replays = manifest["replays"]
        if not isinstance(scan_replays, list) or not isinstance(manifest_replays, list):
            return None
        manifest_output = Path(manifest["output"]).resolve()
        if (
            summary.get("schema_version") != 1
            or _get(summary, "decoder_runtime_image_sha256", "image_sha256")
            != EXPECTED_RUNTIME_IMAGE_SHA256
            or _integer(summary.get("client_opcode")) != stream["packet_id"]
            or summary.get("output_path") != str(path.resolve())
            or summary.get("output_sha256") != hashlib.sha256(path.read_bytes()).hexdigest()
            or summary.get("events_path") != str(events_path)
            or summary.get("events_sha256") != hashlib.sha256(events_bytes).hexdigest()
            or summary.get("events_manifest_path") != str(manifest_path)
            or summary.get("events_manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest()
            or manifest.get("packet_ids") != [stream["packet_id"]]
            or manifest.get("schema_version") != 1
            or manifest.get("target_replay_version") != SUPPORTED_PATCH
            or manifest_output != events_path
            or manifest.get("replay_count") != len(manifest_replays)
            or len(rows) != int(summary.get("output_event_count"))
        ):
            return None
        if _stream_for_rows(rows) not in (None, profile):
            return None
        if rows and _stream_for_rows(rows) != profile:
            return None
        if any(row.get("decoder_profile") != profile for row in rows):
            return None
        manifest_selected = sum(int(item["selected_packet_count"]) for item in manifest_replays)
        manifest_errors = sum(int(item["parser_error_count"]) for item in manifest_replays)
        manifest_shas = [item["sha256"] for item in manifest_replays]
        if (
            len(manifest_shas) != len(set(manifest_shas))
            or any(item.get("version") != SUPPORTED_PATCH for item in manifest_replays)
            or manifest.get("selected_packet_count") != manifest_selected
            or manifest.get("packet_counts") != {str(stream["packet_id"]): manifest_selected}
            or manifest_errors != 0
            or int(summary.get("scan_replay_count")) != len(manifest_replays)
            or int(summary.get("scan_selected_packet_count")) != manifest_selected
            or int(summary.get("scan_parser_error_count")) != manifest_errors
            or int(summary.get("input_event_count")) != manifest_selected
            or int(summary.get("deserialize_success_count")) != manifest_selected
            or int(summary.get("fully_consumed_count")) != manifest_selected
            or len(scan_replays) != len(manifest_replays)
        ):
            return None
        expected_scan_replays = [
            {
                "replay_sha256": item["sha256"],
                "replay_path": item["path"],
                "replay_version": item["version"],
                "selected_packet_count": item["selected_packet_count"],
                "parser_error_count": item["parser_error_count"],
            }
            for item in manifest_replays
        ]
        if scan_replays != expected_scan_replays:
            return None
        output_replay_counts = summary.get("output_replay_counts")
        actual_output_replay_counts = dict(Counter(
            _get(row, "replay_sha256") for row in rows
        ))
        if (
            not isinstance(output_replay_counts, dict)
            or output_replay_counts != actual_output_replay_counts
            or any(sha not in manifest_shas for sha in output_replay_counts)
        ):
            return None
        # A decoder output is an all-or-nothing attested route: unknown rows,
        # cross-route rows, or a row which no longer passes its byte-level
        # contract invalidate the whole artifact, not just that one row.
        if any(_stream_for_rows([row]) != profile or not _is_protection_row(row) for row in rows):
            return None
        if stream["requires_network_checks"] and len(rows) != manifest_selected:
            return None
        if stream["requires_network_checks"] and any(
            int(summary.get(field)) != manifest_selected
            for field in ("network_fields_agree_count", "target_matches_raw_param_count")
        ):
            return None
        if profile == ON_EVENT_DECODER_PROFILE and (
            int(summary.get("schema_mismatch_count", 0)) != 0
            or int(summary.get("parameter_size_mismatch_count", 0)) != 0
        ):
            return None
        if not _verify_bundle_from_replays(path, rows, summary, manifest):
            return None
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return profile, manifest_shas


def _canonical_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Ignore only the verifier's temporary output filename."""
    return {**manifest, "output": "<verified-export>"}


def _canonical_rerun_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Compare decoder contracts while ignoring temporary artifact locations."""
    ignored = {
        "image_path", "events_path", "events_sha256", "events_manifest_path",
        "events_manifest_sha256", "output_path", "output_sha256",
    }
    return {key: value for key, value in summary.items() if key not in ignored}


def _verify_bundle_from_replays(
    path: Path, rows: list[dict[str, Any]], summary: dict[str, Any],
    manifest: dict[str, Any],
) -> bool:
    """Reparse the real Replays and rerun the pinned decoder before acceptance."""
    del rows  # The byte-identical rerun below is the stronger check.
    try:
        image = RUNTIME_IMAGE.resolve()
        if (
            not image.is_file()
            or hashlib.sha256(image.read_bytes()).hexdigest()
            != EXPECTED_RUNTIME_IMAGE_SHA256
        ):
            return False
        replay_paths = [Path(item["path"]).resolve() for item in manifest["replays"]]
        if not replay_paths or any(not replay.is_file() for replay in replay_paths):
            return False
        profile = summary["decoder_profile"]
        stream = DECODER_STREAMS[profile]
        damage_path = summary.get("damage_events_path")
        damage_sha = summary.get("damage_events_sha256")
        if profile == SHIELD_DAMAGE_DECODER_PROFILE:
            if (damage_path is None) != (damage_sha is None):
                return False
            if damage_path is not None:
                damage_file = Path(damage_path).resolve()
                if (
                    not damage_file.is_file()
                    or hashlib.sha256(damage_file.read_bytes()).hexdigest() != damage_sha
                ):
                    return False
        with tempfile.TemporaryDirectory(prefix="protection-v4-verify-") as root:
            root_path = Path(root)
            raw = root_path / f"packet_{stream['packet_id']:04x}.jsonl"
            rerun_output = root_path / "decoded.jsonl"
            rerun_summary_path = root_path / "decoded.summary.json"
            export_command = [
                "node", str(ROOT / "scripts" / "export_selected_packets.js"),
                "--output", str(raw), "--packet-id", str(stream["packet_id"]),
                *map(str, replay_paths),
            ]
            subprocess.run(
                export_command, cwd=ROOT, check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            supplied_events = Path(summary["events_path"]).resolve()
            if raw.read_bytes() != supplied_events.read_bytes():
                return False
            rerun_manifest = json.loads(Path(f"{raw}.manifest.json").read_text(encoding="utf-8"))
            if _canonical_manifest(rerun_manifest) != _canonical_manifest(manifest):
                return False
            decoder = (
                ROOT / "scripts" / "decode_on_event_protection_v4.py"
                if profile == ON_EVENT_DECODER_PROFILE else
                ROOT / "scripts" / "decode_shield_damage_v4.py"
            )
            decode_command = [
                sys.executable, str(decoder), "--image", str(image),
                "--events", str(raw), "--output", str(rerun_output),
                "--summary", str(rerun_summary_path),
            ]
            if profile == SHIELD_DAMAGE_DECODER_PROFILE and damage_path is not None:
                decode_command.extend(["--damage-events", str(Path(damage_path).resolve())])
            subprocess.run(
                decode_command, cwd=ROOT, check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            if rerun_output.read_bytes() != path.read_bytes():
                return False
            rerun_summary = json.loads(rerun_summary_path.read_text(encoding="utf-8"))
            return _canonical_rerun_summary(rerun_summary) == _canonical_rerun_summary(summary)
    except (
        KeyError, OSError, TypeError, ValueError, json.JSONDecodeError,
        subprocess.CalledProcessError,
    ):
        return False


def _load_decoder_artifacts(paths: Iterable[str | Path]) -> list[tuple[Path, list[dict[str, Any]] | None, dict[str, Any] | None, tuple[str, list[str]] | None]]:
    """Read each JSONL/sidecar once; callers may reuse the result per replay."""
    artifacts = []
    seen: set[Path] = set()
    for raw_path in paths:
        path = Path(raw_path).resolve()
        if path in seen:
            artifacts.append((path, None, None, None))
            continue
        seen.add(path)
        try:
            rows = list(_iter_jsonl([path]))
        except (OSError, json.JSONDecodeError):
            artifacts.append((path, None, None, None))
            continue
        summaries = _summary_paths(path)
        summary: dict[str, Any] | None = None
        if len(summaries) == 1:
            try:
                loaded = json.loads(summaries[0].read_text(encoding="utf-8"))
                summary = loaded if isinstance(loaded, dict) else None
            except (OSError, json.JSONDecodeError):
                summary = None
        artifacts.append((path, rows, summary, _validate_decoder_bundle(
            path, rows, summary
        ) if summary else None))
    return artifacts


def _validated_decoded_inputs(
    paths: Iterable[str | Path], replay_sha256: str,
    *, artifacts: list[tuple[Path, list[dict[str, Any]] | None, dict[str, Any] | None, tuple[str, list[str]] | None]] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, bool], bool]:
    """Return only decoder/manifest-bound rows and per-stream target coverage."""
    trusted_rows: list[dict[str, Any]] = []
    coverage = {profile: False for profile in DECODER_STREAMS}
    invalid = False
    for _path, rows, summary, bundle in artifacts if artifacts is not None else _load_decoder_artifacts(paths):
        if rows is None:
            return [], coverage, True
        if bundle is None:
            row_shas = {_get(row, "replay_sha256") for row in rows}
            # A malformed sidecar is unsafe for every replay it claims to scan.
            if summary and isinstance(summary.get("scan_replays"), list):
                row_shas.update(
                    item.get("replay_sha256") for item in summary["scan_replays"]
                    if isinstance(item, dict)
                )
            if replay_sha256 in row_shas or not row_shas:
                invalid = True
            continue
        profile, covered_shas = bundle
        target_rows = [row for row in rows if _get(row, "replay_sha256") == replay_sha256]
        if replay_sha256 in covered_shas:
            coverage[profile] = True
        if target_rows:
            trusted_rows.extend(target_rows)
        # A decoded row for the target must be represented exactly once in the scan.
        if target_rows and covered_shas.count(replay_sha256) != 1:
            invalid = True
    return trusted_rows, coverage, invalid


def _backfill_decoded(
    connection: duckdb.DuckDBPyConnection,
    *,
    replay_sha256: str,
    decoded: list[dict[str, Any]],
    input_paths: list[str | Path],
    allow_v4_only_replay: bool = False,
    validated_input: tuple[list[dict[str, Any]], dict[str, bool], bool] | None = None,
) -> dict[str, Any]:
    decoded, decoder_coverage, decoder_input_invalid = (
        validated_input if validated_input is not None else _validated_decoded_inputs(input_paths, replay_sha256)
    ) if input_paths else ([], {profile: False for profile in DECODER_STREAMS}, False)
    replay = connection.execute(
        "SELECT game_id,patch FROM replays WHERE replay_sha256=?", [replay_sha256]
    ).fetchone()
    game_id, patch = replay if replay else (None, None)
    v4_only_replay = False
    if replay is None and allow_v4_only_replay and decoded:
        declared_patches = {
            _get(row, "replay_version", "patch") for row in decoded
            if _get(row, "replay_version", "patch") is not None
        }
        if declared_patches == {SUPPORTED_PATCH}:
            label = _get(decoded[0], "replay_label")
            game_id = label.rsplit("-", 1)[-1] if isinstance(label, str) else None
            patch = SUPPORTED_PATCH
            v4_only_replay = True
    structural = [row for row in decoded if _is_structural_protection_row(row)]
    candidates = [row for row in decoded if _is_protection_row(row)]
    invalid_structural_count = len(structural) - len(candidates)
    valid_on_event = [row for row in candidates if _packet_id(row) == 0x009E]
    valid_shield_damage = [row for row in candidates if _packet_id(row) == 0x0017]
    on_event_available = decoder_coverage[ON_EVENT_DECODER_PROFILE]
    shield_damage_available = decoder_coverage[SHIELD_DAMAGE_DECODER_PROFILE]
    on_event_status = (
        "DECODED" if valid_on_event
        else "NO_PROTECTION_EVENT" if on_event_available
        else "DECODER_UNAVAILABLE"
    )
    shield_damage_status = (
        "DECODED" if valid_shield_damage
        else "NO_PROTECTION_EVENT" if shield_damage_available
        else "DECODER_UNAVAILABLE"
    )
    if (not replay and not v4_only_replay) or patch != SUPPORTED_PATCH:
        status = "PROTECTION_PROFILE_UNSUPPORTED"
    elif (
        not input_paths
        or decoder_input_invalid
        or invalid_structural_count
        or not (on_event_available and shield_damage_available)
    ):
        status = "DECODER_UNAVAILABLE"
    elif not candidates:
        status = "NO_PROTECTION_EVENT"
    else:
        status = "DECODED"
    connection.execute("BEGIN TRANSACTION")
    try:
        _delete_target(connection, replay_sha256)
        participants = _participants(connection, replay_sha256)
        accepted_candidates = candidates if status == "DECODED" else []
        heals, targets, sources, absorptions = _insert_raw_events(
            connection, replay_sha256, game_id, accepted_candidates
        )
        shields, canonical_heals, canonical_absorptions = _insert_protection_events(
            connection, replay_sha256, game_id, heals, targets, sources, absorptions
        )
        if status in ("DECODED", "NO_PROTECTION_EVENT"):
            _inventory(connection, replay_sha256, game_id)
            _adc_contexts(
                connection, replay_sha256, game_id, participants, shields,
                canonical_heals, canonical_absorptions,
                on_event_available=on_event_available,
                shield_damage_available=shield_damage_available,
            )
        decoder_profiles = []
        if on_event_available:
            decoder_profiles.append(ON_EVENT_DECODER_PROFILE)
        if shield_damage_available:
            decoder_profiles.append(SHIELD_DAMAGE_DECODER_PROFILE)
        connection.execute("""
            INSERT INTO protection_v4_profiles
            (replay_sha256,game_id,patch,profile_status,decoder_profile,
             decoded_row_count,protection_row_count,details_json,v4_schema_version,
             on_event_decoder_status,shield_damage_decoder_status,decoder_profiles_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, [replay_sha256, game_id, patch, status,
              "+".join(decoder_profiles) if decoder_profiles else None,
              len(decoded), len(candidates), _json({
                  "input_paths": [str(p) for p in input_paths],
                  "structural_protection_row_count": len(structural),
                  "invalid_structural_row_count": invalid_structural_count,
                  "on_event_candidate_count": len(valid_on_event),
                  "shield_damage_candidate_count": len(valid_shield_damage),
                  "decoder_input_invalid": decoder_input_invalid,
                  "v4_only_replay": v4_only_replay,
              }), 2, on_event_status, shield_damage_status,
              _json(decoder_profiles)])
        connection.execute("COMMIT")
    except Exception:
        connection.execute("ROLLBACK")
        raise
    counts = {
        table: connection.execute(
            f"SELECT count(*) FROM {table} WHERE replay_sha256=?", [replay_sha256]
        ).fetchone()[0]
        for table in V4_TABLES
    }
    return {
        "replay_sha256": replay_sha256,
        "profile_status": status,
        "v4_only_replay": v4_only_replay,
        "table_counts": counts,
    }


def backfill_protection(
    db_path: str | Path = DEFAULT_DB,
    *,
    replay_sha256: str,
    decoded_jsonl_paths: Iterable[str | Path] | None = None,
) -> dict[str, Any]:
    """Replace only the target replay's V4 facts in one transaction."""
    paths = list(decoded_jsonl_paths or ())
    artifacts = _load_decoder_artifacts(paths) if paths else []
    validated_input = _validated_decoded_inputs(paths, replay_sha256, artifacts=artifacts) if paths else None
    with duckdb.connect(str(Path(db_path))) as connection:
        init_v4(connection)
        return _backfill_decoded(
            connection,
            replay_sha256=replay_sha256,
            decoded=validated_input[0] if validated_input else [],
            input_paths=paths,
            validated_input=validated_input,
        )


def backfill_selected_protection(
    db_path: str | Path = DEFAULT_DB,
    *,
    replay_sha256s: Iterable[str],
    decoded_jsonl_paths: Iterable[str | Path],
) -> dict[str, Any]:
    """Verify shared bundles once, then transactionally rebuild selected replays."""
    targets = list(dict.fromkeys(replay_sha256s))
    paths = list(decoded_jsonl_paths)
    if not targets or not paths:
        raise ValueError("replay_sha256s and decoded_jsonl_paths must not be empty")
    artifacts = _load_decoder_artifacts(paths)
    with duckdb.connect(str(Path(db_path))) as connection:
        init_v4(connection)
        results = []
        for sha in targets:
            validated_input = _validated_decoded_inputs(paths, sha, artifacts=artifacts)
            results.append(_backfill_decoded(
                connection,
                replay_sha256=sha,
                decoded=validated_input[0],
                input_paths=paths,
                validated_input=validated_input,
            ))
    return {
        "mode": "SELECTED_REPLAYS_SHARED_DECODER_ATTESTATION",
        "backfilled_replay_count": len(results),
        "results": results,
    }


def backfill_all_protection(
    db_path: str | Path = DEFAULT_DB,
    *,
    decoded_jsonl_paths: Iterable[str | Path],
) -> dict[str, Any]:
    """Scan shared decoder outputs once and backfill every covered DB replay."""
    paths = list(decoded_jsonl_paths)
    if not paths:
        raise ValueError("decoded_jsonl_paths must not be empty")
    db_path = Path(db_path)
    with duckdb.connect(str(db_path)) as connection:
        init_v4(connection)
        replay_rows = connection.execute(
            "SELECT replay_sha256 FROM replays WHERE patch=?", [SUPPORTED_PATCH]
        ).fetchall()
        database_replays = {row[0] for row in replay_rows}
        artifacts = _load_decoder_artifacts(paths)
        rows_by_sha: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for _path, rows, _summary, _bundle in artifacts:
            if rows is None:
                continue
            for row in rows:
                sha = _get(row, "replay_sha256")
                if sha and _packet_id(row) in (0x009E, 0x0017):
                    rows_by_sha[sha].append(row)
        all_replays = database_replays | set(rows_by_sha)
        results = [
            _backfill_decoded(
                connection,
                replay_sha256=sha,
                decoded=rows_by_sha[sha],
                input_paths=paths,
                allow_v4_only_replay=sha not in database_replays,
                validated_input=_validated_decoded_inputs(paths, sha, artifacts=artifacts),
            )
            for sha in sorted(all_replays)
        ]
    return {
        "database": str(db_path.resolve()),
        "covered_database_replay_count": sum(bool(rows_by_sha[sha]) for sha in database_replays),
        "decoded_replay_count": len(rows_by_sha),
        "backfilled_replay_count": len(results),
        "v4_only_replay_count": sum(result["v4_only_replay"] for result in results),
        "database_replay_count": len(database_replays),
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=str(DEFAULT_DB))
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--replay-sha256", action="append")
    target.add_argument("--all-database-replays", action="store_true")
    parser.add_argument("--decoded-jsonl", action="append", default=[])
    args = parser.parse_args()
    result = backfill_all_protection(
        args.db, decoded_jsonl_paths=args.decoded_jsonl
    ) if args.all_database_replays else backfill_protection(
        args.db,
        replay_sha256=args.replay_sha256[0],
        decoded_jsonl_paths=args.decoded_jsonl,
    ) if len(args.replay_sha256) == 1 else backfill_selected_protection(
        args.db,
        replay_sha256s=args.replay_sha256,
        decoded_jsonl_paths=args.decoded_jsonl,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
