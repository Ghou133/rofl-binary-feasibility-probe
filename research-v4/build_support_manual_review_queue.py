"""Build a read-only ADC-death Replay review queue for one support champion.

The queue intentionally contains only objective, already-decoded facts.  It
does not classify fights, infer protection sources, or mutate the research
database.  Replay metadata artifacts are scanned in addition to DuckDB so a
locally available but unsupported/un-ingested target Replay is still visible
in the inventory.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass, field
import json
import math
from pathlib import Path
import re
from typing import Any, Iterable

import duckdb


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = PROJECT_ROOT / "research-v3" / "output" / "replay_research.duckdb"
DEFAULT_METADATA_ROOT = PROJECT_ROOT / "artifacts"
DEFAULT_REPLAY_ROOT = PROJECT_ROOT / "replay"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "artifacts" / "support_manual_review"

SUPPORTED_PROFILE_STATUSES = frozenset(("DECODED", "NO_PROTECTION_EVENT"))
VERIFIED_ROLE_STATUSES = frozenset(("VERIFIED_FROM_METADATA",))

MANUAL_COLUMNS = (
    "manual_review_status",
    "manual_fight_type",
    "manual_support_present",
    "manual_adc_isolated",
    "manual_enemy_assassin_engage",
    "manual_standard_2v2",
    "manual_teamfight",
    "manual_support_shield_cast_count",
    "manual_support_heal_cast_count",
    "manual_observed_shield_amount",
    "manual_observed_heal_amount",
    "manual_notes",
)

OUTPUT_COLUMNS = (
    "review_id",
    "replay_sha256",
    "replay_path",
    "patch",
    "game_id",
    "replay_duration_ms",
    "target_support_champion",
    "support_participant_id",
    "support_network_id",
    "support_team_id",
    "support_team",
    "adc_champion",
    "adc_participant_id",
    "adc_network_id",
    "adc_team_id",
    "adc_team",
    "role_resolution_status",
    "adc_death_id",
    "death_index_in_replay",
    "death_timestamp_ms",
    "death_timestamp_seconds",
    "death_time",
    "review_start_ms",
    "review_start",
    "review_end_ms",
    "review_end",
    "review_window",
    "combat_start_ms",
    "killer_champion",
    "assisting_champions",
    "assisting_champions_status",
    "damage_event_count",
    "total_incoming_damage",
    "physical_damage",
    "magic_damage",
    "true_damage",
    "basic_attack_damage",
    "basic_attack_share",
    "known_basic_attack_damage",
    "known_basic_attack_share_lower_bound",
    "basic_attack_attribution_status",
    "top_damage_contributor",
    "top_contributor_damage",
    "top_contributor_damage_share",
    "protection_window_start_ms",
    "protection_window_start",
    "protection_window_end_ms",
    "protection_window_end",
    "protection_v4_profile_status",
    "on_event_decoder_status",
    "shield_damage_decoder_status",
    "protection_context_status",
    "protection_event_count",
    "shield_event_count",
    "shield_generated_event_count",
    "shield_absorption_event_count",
    "heal_event_count",
    "heal_report_row_count",
    "temporary_hp_event_count",
    "temporary_hp_event_count_status",
    "protection_state_transition_count",
    "reported_shield_generated_amount",
    "known_absorbed_shield_amount",
    "reported_heal_amount",
    "reported_heal_amount_status",
    "reported_heal_raw_row_amount_sum",
    "raw_heal_amount",
    "effective_heal_amount",
    "overheal_amount",
    "shield_remaining_amount",
    "shield_unused_amount",
    "support_attribution_available",
    "support_attribution_status",
    "support_attributed_protection_event_count",
    "support_attributed_shield_count",
    "support_attributed_heal_count",
    "support_attributed_reported_shield_amount",
    "support_attributed_reported_heal_amount",
    "support_attributed_known_amount",
    "support_attributed_known_amount_status",
    *MANUAL_COLUMNS,
)

MISSING_COLUMNS = (
    "target_support_champion",
    "replay_sha256",
    "game_id",
    "patch",
    "replay_path",
    "support_participant_id",
    "support_team",
    "adc_champion",
    "adc_participant_id",
    "adc_team",
    "reason",
    "metadata_sources",
)


@dataclass
class Candidate:
    key: str
    replay_sha256: str | None
    game_id: str | None
    patch: str | None
    target_support_champion: str
    support_participant_id: int | None = None
    support_network_id: int | None = None
    support_team_id: int | None = None
    support_team: str | None = None
    adc_champion: str | None = None
    adc_participant_id: int | None = None
    adc_network_id: int | None = None
    adc_team_id: int | None = None
    adc_team: str | None = None
    adc_metadata_deaths: int | None = None
    role_resolution_status: str = "ROLE_UNRESOLVED"
    replay_paths: list[str] = field(default_factory=list)
    metadata_sources: list[str] = field(default_factory=list)
    database_replay: bool = False
    database_status: str | None = None
    artifact_decoder_status: str | None = None
    replay_duration_ms: int | None = None
    replay_path: str | None = None
    replay_exists: bool = False
    usability_status: str | None = None

    @property
    def matched(self) -> bool:
        return self.role_resolution_status == "MATCHED_SUPPORT_ADC"


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _clean_champion(value: Any) -> str:
    return str(value or "").strip().casefold()


def champion_slug(champion: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", champion.strip().casefold()).strip("_")
    if not slug:
        raise ValueError("support champion must contain at least one letter or digit")
    return slug


def format_replay_time(milliseconds: int | None) -> str | None:
    if milliseconds is None:
        return None
    total_seconds = max(0, int(milliseconds)) // 1000
    minutes, seconds = divmod(total_seconds, 60)
    return f"{minutes:02d}:{seconds:02d}"


def _nonnegative_seconds(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise argparse.ArgumentTypeError("value must be a finite non-negative number")
    return parsed


def _milliseconds(seconds: float) -> int:
    return int(round(seconds * 1000.0))


def _role_verified(player: dict[str, Any]) -> bool:
    return player.get("role_status") in VERIFIED_ROLE_STATUSES


def _metadata_death_count(player: dict[str, Any]) -> int | None:
    stats = player.get("aggregate_stats")
    if not isinstance(stats, dict):
        return None
    value = stats.get("deaths")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _candidate_from_players(
    *,
    players: list[dict[str, Any]],
    target: str,
    replay_sha256: str | None,
    game_id: str | None,
    patch: str | None,
    replay_paths: Iterable[str],
    source: str,
    database_replay: bool = False,
    database_status: str | None = None,
    decoder_status: str | None = None,
    duration_ms: int | None = None,
) -> Candidate | None:
    target_players = [
        player for player in players
        if _clean_champion(player.get("champion")) == _clean_champion(target)
    ]
    if not target_players:
        return None

    verified_supports = [
        player for player in target_players
        if _role_verified(player) and _clean_champion(player.get("role")) == "support"
    ]
    unresolved_targets = [player for player in target_players if not _role_verified(player)]

    # A verified non-support appearance is not a target support Replay.
    if not verified_supports and not unresolved_targets:
        return None

    key = replay_sha256 or f"source:{source}"
    common = dict(
        key=key,
        replay_sha256=replay_sha256,
        game_id=str(game_id) if game_id is not None else None,
        patch=str(patch) if patch is not None else None,
        target_support_champion=target,
        replay_paths=[str(path) for path in replay_paths if path],
        metadata_sources=[source],
        database_replay=database_replay,
        database_status=database_status,
        artifact_decoder_status=decoder_status,
        replay_duration_ms=duration_ms,
    )

    if len(verified_supports) != 1:
        target_player = (verified_supports or unresolved_targets)[0]
        return Candidate(
            **common,
            support_participant_id=target_player.get("participant_id"),
            support_network_id=target_player.get("network_id"),
            support_team_id=target_player.get("team_id"),
            support_team=target_player.get("team"),
        )

    support = verified_supports[0]
    adcs = [
        player for player in players
        if player.get("team_id") == support.get("team_id")
        and _role_verified(player)
        and _clean_champion(player.get("role")) == "adc"
    ]
    if len(adcs) != 1:
        return Candidate(
            **common,
            support_participant_id=support.get("participant_id"),
            support_network_id=support.get("network_id"),
            support_team_id=support.get("team_id"),
            support_team=support.get("team"),
        )

    adc = adcs[0]
    return Candidate(
        **common,
        support_participant_id=support.get("participant_id"),
        support_network_id=support.get("network_id"),
        support_team_id=support.get("team_id"),
        support_team=support.get("team"),
        adc_champion=adc.get("champion"),
        adc_participant_id=adc.get("participant_id"),
        adc_network_id=adc.get("network_id"),
        adc_team_id=adc.get("team_id"),
        adc_team=adc.get("team"),
        adc_metadata_deaths=_metadata_death_count(adc),
        role_resolution_status="MATCHED_SUPPORT_ADC",
    )


def _db_candidates(
    connection: duckdb.DuckDBPyConnection, target: str
) -> list[Candidate]:
    rows = connection.execute(
        """SELECT p.game_id,p.replay_sha256,p.participant_id,p.network_id,
                  p.champion,p.team_id,p.team,p.role,p.confidence,p.status,
                  p.raw_provenance_json,r.patch,r.replay_path,r.duration_ms,r.status
             FROM participants p
             JOIN replays r ON r.replay_sha256=p.replay_sha256
            ORDER BY p.replay_sha256,p.participant_id"""
    ).fetchall()
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        raw = _json_object(row[10])
        player = {
            "participant_id": row[2],
            "network_id": row[3],
            "champion": row[4],
            "team_id": row[5],
            "team": row[6],
            "role": row[7],
            "confidence": row[8],
            "role_status": raw.get("role_status") or row[9],
            "aggregate_stats": raw.get("aggregate_stats"),
        }
        group = grouped.setdefault(row[1], {
            "game_id": row[0],
            "sha": row[1],
            "patch": row[11],
            "path": row[12],
            "duration_ms": row[13],
            "status": row[14],
            "players": [],
        })
        group["players"].append(player)

    candidates = []
    for group in grouped.values():
        candidate = _candidate_from_players(
            players=group["players"],
            target=target,
            replay_sha256=group["sha"],
            game_id=group["game_id"],
            patch=group["patch"],
            replay_paths=(group["path"],),
            source="DUCKDB:participants+replays",
            database_replay=True,
            database_status=group["status"],
            duration_ms=group["duration_ms"],
        )
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _artifact_candidates(metadata_root: Path, target: str) -> list[Candidate]:
    if not metadata_root.exists():
        return []
    candidates = []
    for path in sorted(metadata_root.rglob("replay_analysis.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        metadata = data.get("metadata")
        players_raw = metadata.get("players") if isinstance(metadata, dict) else None
        if not isinstance(players_raw, list):
            continue
        players = []
        for item in players_raw:
            if not isinstance(item, dict):
                continue
            metadata_index = item.get("metadata_index")
            participant_id = (
                metadata_index + 1
                if isinstance(metadata_index, int) and not isinstance(metadata_index, bool)
                else None
            )
            players.append({
                **item,
                "participant_id": participant_id,
                "network_id": None,
            })
        decoder = data.get("decoder")
        decoder_status = decoder.get("status") if isinstance(decoder, dict) else None
        duration = metadata.get("game_length_ms") if isinstance(metadata, dict) else None
        candidate = _candidate_from_players(
            players=players,
            target=target,
            replay_sha256=data.get("replay_sha256"),
            game_id=data.get("game_id"),
            patch=data.get("patch"),
            replay_paths=(data.get("source_path"),),
            source=str(path.resolve()),
            decoder_status=decoder_status,
            duration_ms=duration,
        )
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _merge_candidate(existing: Candidate, incoming: Candidate) -> Candidate:
    if existing.matched and incoming.matched:
        identity_fields = (
            "support_participant_id", "support_team_id", "adc_participant_id",
            "adc_team_id", "adc_champion",
        )
        conflicts = [
            name for name in identity_fields
            if getattr(existing, name) is not None
            and getattr(incoming, name) is not None
            and getattr(existing, name) != getattr(incoming, name)
        ]
        if conflicts:
            raise RuntimeError(
                f"conflicting participant metadata for {existing.key}: {conflicts}"
            )
    primary, secondary = (
        (existing, incoming)
        if existing.matched or not incoming.matched
        else (incoming, existing)
    )
    for name in (
        "replay_sha256", "game_id", "patch", "support_participant_id",
        "support_network_id", "support_team_id", "support_team", "adc_champion",
        "adc_participant_id", "adc_network_id", "adc_team_id", "adc_team",
        "adc_metadata_deaths", "database_status", "artifact_decoder_status",
        "replay_duration_ms",
    ):
        if getattr(primary, name) is None:
            setattr(primary, name, getattr(secondary, name))
    primary.database_replay = primary.database_replay or secondary.database_replay
    primary.replay_paths = list(dict.fromkeys(primary.replay_paths + secondary.replay_paths))
    primary.metadata_sources = list(
        dict.fromkeys(primary.metadata_sources + secondary.metadata_sources)
    )
    return primary


def _resolve_replay_path(
    candidate: Candidate, project_root: Path, replay_root: Path
) -> None:
    possible: list[Path] = []
    for value in candidate.replay_paths:
        path = Path(value)
        possible.append(path if path.is_absolute() else project_root / path)
        possible.append(replay_root / path.name)
    unique: list[Path] = []
    seen: set[str] = set()
    for path in possible:
        key = str(path.resolve(strict=False)).casefold()
        if key not in seen:
            seen.add(key)
            unique.append(path)
    existing = next((path.resolve() for path in unique if path.is_file()), None)
    if existing is not None:
        candidate.replay_path = str(existing)
        candidate.replay_exists = True
    elif unique:
        candidate.replay_path = str(unique[0].resolve(strict=False))
        candidate.replay_exists = False


def discover_candidates(
    connection: duckdb.DuckDBPyConnection,
    *,
    target: str,
    metadata_root: Path,
    replay_root: Path,
    project_root: Path = PROJECT_ROOT,
) -> list[Candidate]:
    merged: dict[str, Candidate] = {}
    for candidate in _db_candidates(connection, target) + _artifact_candidates(
        metadata_root, target
    ):
        if candidate.key in merged:
            merged[candidate.key] = _merge_candidate(merged[candidate.key], candidate)
        else:
            merged[candidate.key] = candidate
    for candidate in merged.values():
        _resolve_replay_path(candidate, project_root, replay_root)
        if not candidate.matched:
            candidate.usability_status = "ROLE_UNRESOLVED"
        elif not candidate.replay_exists:
            candidate.usability_status = "REPLAY_FILE_MISSING"
        elif not candidate.database_replay:
            candidate.usability_status = (
                candidate.artifact_decoder_status or "NO_DATABASE_SEMANTIC_FACTS"
            )
        elif candidate.database_status != "RESEARCH_READY_COMPLETE":
            candidate.usability_status = candidate.database_status or "DATABASE_NOT_READY"
        else:
            candidate.usability_status = "USABLE"
    return sorted(
        merged.values(),
        key=lambda item: (
            item.game_id is None,
            item.game_id or "",
            item.replay_sha256 or item.key,
        ),
    )


def _profile_context(
    connection: duckdb.DuckDBPyConnection,
    candidate: Candidate,
    death_time_ms: int,
    protection_pre_ms: int,
) -> dict[str, Any]:
    start = max(0, death_time_ms - protection_pre_ms)
    profile = connection.execute(
        """SELECT profile_status,on_event_decoder_status,
                  shield_damage_decoder_status
             FROM protection_v4_profiles WHERE replay_sha256=?""",
        [candidate.replay_sha256],
    ).fetchone()
    base = {
        "protection_window_start_ms": start,
        "protection_window_start": format_replay_time(start),
        "protection_window_end_ms": death_time_ms,
        "protection_window_end": format_replay_time(death_time_ms),
        "protection_v4_profile_status": profile[0] if profile else None,
        "on_event_decoder_status": profile[1] if profile else None,
        "shield_damage_decoder_status": profile[2] if profile else None,
        "protection_context_status": "V4_PROFILE_UNAVAILABLE",
        "protection_event_count": None,
        "shield_event_count": None,
        "shield_generated_event_count": None,
        "shield_absorption_event_count": None,
        "heal_event_count": None,
        "heal_report_row_count": None,
        "temporary_hp_event_count": None,
        "temporary_hp_event_count_status": "CAPABILITY_UNAVAILABLE",
        "protection_state_transition_count": None,
        "reported_shield_generated_amount": None,
        "known_absorbed_shield_amount": None,
        "reported_heal_amount": None,
        "reported_heal_amount_status": "UNAVAILABLE",
        "reported_heal_raw_row_amount_sum": None,
        "raw_heal_amount": None,
        "effective_heal_amount": None,
        "overheal_amount": None,
        "shield_remaining_amount": None,
        "shield_unused_amount": None,
        "support_attribution_available": False,
        "support_attribution_status": "V4_SOURCE_ATTRIBUTION_UNAVAILABLE",
        "support_attributed_protection_event_count": None,
        "support_attributed_shield_count": None,
        "support_attributed_heal_count": None,
        "support_attributed_reported_shield_amount": None,
        "support_attributed_reported_heal_amount": None,
        "support_attributed_known_amount": None,
        "support_attributed_known_amount_status": (
            "NOT_COMBINED_DIFFERENT_REPORTED_SEMANTICS"
        ),
        "_protection_fact_ids": (),
    }
    if profile is None:
        return base

    on_event_available = profile[1] in SUPPORTED_PROFILE_STATUSES
    shield_damage_available = profile[2] in SUPPORTED_PROFILE_STATUSES
    events = connection.execute(
        """SELECT fact_id,protection_kind,source_network_id,observed_amount,
                  coalesce(heal_group_size,1)
             FROM protection_events
            WHERE replay_sha256=? AND target_network_id=? AND canonical=TRUE
              AND replay_time_ms BETWEEN ? AND ?
            ORDER BY replay_time_ms,raw_occurrence_index,fact_id""",
        [candidate.replay_sha256, candidate.adc_network_id, start, death_time_ms],
    ).fetchall()
    fact_ids = [row[0] for row in events]
    if len(fact_ids) != len(set(fact_ids)):
        raise RuntimeError(
            f"duplicate protection fact IDs in death window for {candidate.replay_sha256}"
        )
    transitions = connection.execute(
        """SELECT fact_id,transition_kind,absorbed_amount
             FROM protection_state_transitions
            WHERE replay_sha256=? AND target_network_id=?
              AND replay_time_ms BETWEEN ? AND ?
            ORDER BY replay_time_ms,fact_id""",
        [candidate.replay_sha256, candidate.adc_network_id, start, death_time_ms],
    ).fetchall()
    temporary_hp_count = connection.execute(
        """SELECT count(*) FROM temporary_hp_events
            WHERE replay_sha256=? AND target_network_id=?
              AND replay_time_ms BETWEEN ? AND ?""",
        [candidate.replay_sha256, candidate.adc_network_id, start, death_time_ms],
    ).fetchone()[0]

    shields = [row for row in events if row[1] == "SHIELD_GENERATED"]
    heals = [row for row in events if row[1] == "HEAL_REPORTED"]
    absorptions = [row for row in events if row[1] == "SHIELD_ABSORBED"]
    support_events = [
        row for row in events
        if row[1] in ("SHIELD_GENERATED", "HEAL_REPORTED")
        and row[2] == candidate.support_network_id
    ]
    support_shields = [row for row in support_events if row[1] == "SHIELD_GENERATED"]
    support_heals = [row for row in support_events if row[1] == "HEAL_REPORTED"]

    def amount_sum(rows: Iterable[tuple[Any, ...]], multiplier: bool = False) -> float | None:
        rows = list(rows)
        if not rows:
            return 0.0
        if any(row[3] is None for row in rows):
            return None
        return float(sum(
            float(row[3]) * (int(row[4]) if multiplier else 1)
            for row in rows
        ))

    absorbed_values = [
        row[2] for row in transitions
        if row[1] == "SHIELD_ABSORBED" and row[2] is not None
    ]
    if not absorbed_values:
        absorbed_values = [row[3] for row in absorptions if row[3] is not None]

    known_event_count = len(events)
    base.update({
        "protection_context_status": (
            "OBSERVED_EVENTS_IN_WINDOW" if events or transitions
            else "SUPPORTED_NO_EVENT_IN_WINDOW"
        ),
        "protection_event_count": known_event_count,
        "shield_event_count": (
            len(shields) + len(absorptions)
            if on_event_available and shield_damage_available else None
        ),
        "shield_generated_event_count": (
            len(shields) if on_event_available else None
        ),
        "shield_absorption_event_count": (
            len(absorptions) if shield_damage_available else None
        ),
        "heal_event_count": len(heals) if on_event_available else None,
        "heal_report_row_count": (
            sum(int(row[4]) for row in heals) if on_event_available else None
        ),
        # V4 currently has no recovered temporary-HP event surface.  This is a
        # literal table-row count, not a claim that no temporary HP occurred.
        "temporary_hp_event_count": int(temporary_hp_count),
        "temporary_hp_event_count_status": "V4_TABLE_ROWS_ONLY_CAPABILITY_UNAVAILABLE",
        "protection_state_transition_count": (
            len(transitions) if shield_damage_available else None
        ),
        "reported_shield_generated_amount": (
            amount_sum(shields) if on_event_available else None
        ),
        "known_absorbed_shield_amount": (
            float(sum(absorbed_values)) if shield_damage_available else None
        ),
        "reported_heal_amount": amount_sum(heals) if on_event_available else None,
        "reported_heal_amount_status": (
            "CANONICAL_GROUP_LOWER_BOUND_REPORTED_AMOUNT"
            if on_event_available else "UNAVAILABLE"
        ),
        "reported_heal_raw_row_amount_sum": (
            amount_sum(heals, multiplier=True) if on_event_available else None
        ),
        "support_attribution_available": bool(support_events),
        "support_attribution_status": (
            "DIRECT_SOURCE_MATCH_PRESENT" if support_events
            else (
                "NO_DIRECT_TARGET_SUPPORT_EVENT_IN_WINDOW"
                if on_event_available else "V4_SOURCE_ATTRIBUTION_UNAVAILABLE"
            )
        ),
        "support_attributed_protection_event_count": (
            len(support_events) if on_event_available else None
        ),
        "support_attributed_shield_count": (
            len(support_shields) if on_event_available else None
        ),
        "support_attributed_heal_count": (
            len(support_heals) if on_event_available else None
        ),
        "support_attributed_reported_shield_amount": (
            amount_sum(support_shields) if on_event_available else None
        ),
        "support_attributed_reported_heal_amount": (
            amount_sum(support_heals) if on_event_available else None
        ),
        "_protection_fact_ids": tuple(fact_ids),
    })
    return base


def _damage_context(
    connection: duckdb.DuckDBPyConnection,
    candidate: Candidate,
    death_id: str,
    combat_start_ms: int,
    death_time_ms: int,
) -> dict[str, Any]:
    rows = connection.execute(
        """SELECT fact_id,amount,damage_type,is_basic_attack
             FROM damage_events
            WHERE replay_sha256=? AND target_participant_id=?
              AND replay_time_ms BETWEEN ? AND ?
            ORDER BY replay_time_ms,fact_id""",
        [
            candidate.replay_sha256,
            candidate.adc_participant_id,
            combat_start_ms,
            death_time_ms,
        ],
    ).fetchall()
    amounts_complete = all(row[1] is not None for row in rows)
    types_complete = all(row[2] in ("physical", "magic", "true") for row in rows)
    total = float(sum(float(row[1]) for row in rows)) if amounts_complete else None

    typed: dict[str, float | None] = {}
    for kind in ("physical", "magic", "true"):
        typed[kind] = (
            float(sum(float(row[1]) for row in rows if row[2] == kind))
            if amounts_complete and types_complete else None
        )

    known_basic = (
        float(sum(float(row[1]) for row in rows if row[3] is True))
        if amounts_complete else None
    )
    basic_complete = all(row[3] is not None for row in rows)
    exact_basic = known_basic if basic_complete else None
    exact_share = (
        exact_basic / total
        if exact_basic is not None and total not in (None, 0.0) else None
    )
    lower_bound_share = (
        known_basic / total
        if known_basic is not None and total not in (None, 0.0) else None
    )

    contributors = connection.execute(
        """SELECT attacker_champion,damage_amount
             FROM adc_death_damage WHERE adc_death_id=?
            ORDER BY damage_amount DESC NULLS LAST,attacker_champion""",
        [death_id],
    ).fetchall()
    top_name = contributors[0][0] if contributors else None
    top_amount = (
        float(contributors[0][1])
        if contributors and contributors[0][1] is not None else None
    )
    top_share = (
        top_amount / total
        if top_amount is not None and total not in (None, 0.0) else None
    )
    return {
        "damage_event_count": len(rows),
        "total_incoming_damage": total,
        "physical_damage": typed["physical"],
        "magic_damage": typed["magic"],
        "true_damage": typed["true"],
        "basic_attack_damage": exact_basic,
        "basic_attack_share": exact_share,
        "known_basic_attack_damage": known_basic,
        "known_basic_attack_share_lower_bound": lower_bound_share,
        "basic_attack_attribution_status": (
            "EXACT" if basic_complete
            else "VERIFIED_DERIVED_PARTIAL_TRUE_ONLY"
        ),
        "top_damage_contributor": top_name,
        "top_contributor_damage": top_amount,
        "top_contributor_damage_share": top_share,
        # The frozen schema has damage contributors, not the game's assist list.
        "assisting_champions": None,
        "assisting_champions_status": "UNAVAILABLE_NO_RELIABLE_ASSIST_FIELD",
    }


def _death_rows(
    connection: duckdb.DuckDBPyConnection,
    candidates: list[Candidate],
    *,
    pre_ms: int,
    post_ms: int,
    protection_pre_ms: int,
    only_replay_sha256: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rows: list[dict[str, Any]] = []
    validation = {
        "exact_death_event_matches": 0,
        "same_team_bindings": 0,
        "duplicate_death_rows": 0,
        "duplicate_protection_event_refs": 0,
        "protection_cross_replay_rows": 0,
    }
    seen_deaths: set[str] = set()
    for candidate in candidates:
        if candidate.usability_status != "USABLE":
            continue
        if only_replay_sha256 and candidate.replay_sha256 not in only_replay_sha256:
            continue
        if candidate.support_team_id != candidate.adc_team_id:
            raise RuntimeError(f"support/ADC team mismatch for {candidate.key}")
        deaths = connection.execute(
            """SELECT fact_id,death_time_ms,combat_start_ms,killer,adc,support
                 FROM adc_deaths
                WHERE replay_sha256=? AND adc_participant_id=?
                  AND support_participant_id=?
                ORDER BY death_time_ms,fact_id""",
            [
                candidate.replay_sha256,
                candidate.adc_participant_id,
                candidate.support_participant_id,
            ],
        ).fetchall()
        if (
            candidate.adc_metadata_deaths is not None
            and len(deaths) != candidate.adc_metadata_deaths
        ):
            raise RuntimeError(
                f"ADC death count mismatch for {candidate.key}: metadata="
                f"{candidate.adc_metadata_deaths}, database={len(deaths)}"
            )
        for death_index, death in enumerate(deaths, start=1):
            death_id, death_time, combat_start, killer, adc, support = death
            if death_id in seen_deaths:
                validation["duplicate_death_rows"] += 1
                continue
            seen_deaths.add(death_id)
            death_matches = connection.execute(
                """SELECT source_champion FROM death_events
                    WHERE replay_sha256=? AND target_participant_id=?
                      AND replay_time_ms=?""",
                [candidate.replay_sha256, candidate.adc_participant_id, death_time],
            ).fetchall()
            if len(death_matches) != 1:
                raise RuntimeError(
                    f"death event identity mismatch for {candidate.key} at {death_time}ms"
                )
            if (
                killer is not None and death_matches[0][0] is not None
                and _clean_champion(killer) != _clean_champion(death_matches[0][0])
            ):
                raise RuntimeError(
                    f"killer mismatch for {candidate.key} at {death_time}ms"
                )
            if _clean_champion(adc) != _clean_champion(candidate.adc_champion):
                raise RuntimeError(f"ADC champion mismatch for {candidate.key}")
            if _clean_champion(support) != _clean_champion(
                candidate.target_support_champion
            ):
                raise RuntimeError(f"support champion mismatch for {candidate.key}")

            review_start_ms = max(0, int(death_time) - pre_ms)
            review_end_ms = int(death_time) + post_ms
            if candidate.replay_duration_ms is not None:
                review_end_ms = min(review_end_ms, int(candidate.replay_duration_ms))
            protection = _profile_context(
                connection, candidate, int(death_time), protection_pre_ms
            )
            fact_ids = protection.pop("_protection_fact_ids")
            if len(fact_ids) != len(set(fact_ids)):
                validation["duplicate_protection_event_refs"] += 1
            damage = _damage_context(
                connection,
                candidate,
                death_id,
                int(combat_start),
                int(death_time),
            )
            row = {
                "review_id": death_id,
                "replay_sha256": candidate.replay_sha256,
                "replay_path": candidate.replay_path,
                "patch": candidate.patch,
                "game_id": candidate.game_id,
                "replay_duration_ms": candidate.replay_duration_ms,
                "target_support_champion": candidate.target_support_champion,
                "support_participant_id": candidate.support_participant_id,
                "support_network_id": candidate.support_network_id,
                "support_team_id": candidate.support_team_id,
                "support_team": candidate.support_team,
                "adc_champion": candidate.adc_champion,
                "adc_participant_id": candidate.adc_participant_id,
                "adc_network_id": candidate.adc_network_id,
                "adc_team_id": candidate.adc_team_id,
                "adc_team": candidate.adc_team,
                "role_resolution_status": candidate.role_resolution_status,
                "adc_death_id": death_id,
                "death_index_in_replay": death_index,
                "death_timestamp_ms": int(death_time),
                "death_timestamp_seconds": int(death_time) / 1000.0,
                "death_time": format_replay_time(int(death_time)),
                "review_start_ms": review_start_ms,
                "review_start": format_replay_time(review_start_ms),
                "review_end_ms": review_end_ms,
                "review_end": format_replay_time(review_end_ms),
                "review_window": (
                    f"{format_replay_time(review_start_ms)}–"
                    f"{format_replay_time(review_end_ms)}"
                ),
                "combat_start_ms": int(combat_start),
                "killer_champion": killer,
                **damage,
                **protection,
                "manual_review_status": "UNREVIEWED",
                **{name: "" for name in MANUAL_COLUMNS if name != "manual_review_status"},
            }
            rows.append(row)
            validation["exact_death_event_matches"] += 1
            validation["same_team_bindings"] += 1
    rows.sort(key=lambda row: (
        row["game_id"] or "", row["replay_sha256"], row["death_timestamp_ms"]
    ))
    return rows, validation


def _csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return value


def _atomic_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding=encoding, newline="")
    temporary.replace(path)


def write_csv(path: Path, rows: list[dict[str, Any]], columns: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(columns), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key)) for key in writer.fieldnames})
    temporary.replace(path)


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    content = "".join(
        json.dumps(row, ensure_ascii=False, sort_keys=False, separators=(",", ":"))
        + "\n"
        for row in rows
    )
    _atomic_write_text(path, content)


def _missing_row(candidate: Candidate) -> dict[str, Any]:
    return {
        "target_support_champion": candidate.target_support_champion,
        "replay_sha256": candidate.replay_sha256,
        "game_id": candidate.game_id,
        "patch": candidate.patch,
        "replay_path": candidate.replay_path,
        "support_participant_id": candidate.support_participant_id,
        "support_team": candidate.support_team,
        "adc_champion": candidate.adc_champion,
        "adc_participant_id": candidate.adc_participant_id,
        "adc_team": candidate.adc_team,
        "reason": "REPLAY_FILE_MISSING",
        "metadata_sources": candidate.metadata_sources,
    }


def build_dataset(
    *,
    db_path: Path,
    metadata_root: Path,
    replay_root: Path,
    output_dir: Path,
    support_champion: str = "Lulu",
    pre_seconds: float = 20.0,
    post_seconds: float = 10.0,
    protection_pre_seconds: float = 15.0,
    only_replay_sha256: set[str] | None = None,
) -> dict[str, Any]:
    db_path = db_path.resolve()
    if not db_path.is_file():
        raise FileNotFoundError(f"DuckDB not found: {db_path}")
    slug = champion_slug(support_champion)
    with duckdb.connect(str(db_path), read_only=True) as connection:
        candidates = discover_candidates(
            connection,
            target=support_champion,
            metadata_root=metadata_root,
            replay_root=replay_root,
            project_root=PROJECT_ROOT,
        )
        rows, validation = _death_rows(
            connection,
            candidates,
            pre_ms=_milliseconds(pre_seconds),
            post_ms=_milliseconds(post_seconds),
            protection_pre_ms=_milliseconds(protection_pre_seconds),
            only_replay_sha256=only_replay_sha256,
        )

    matched = [candidate for candidate in candidates if candidate.matched]
    missing = [candidate for candidate in matched if not candidate.replay_exists]
    unresolved = [candidate for candidate in candidates if not candidate.matched]
    usable = [candidate for candidate in matched if candidate.usability_status == "USABLE"]
    selected_usable = [
        candidate for candidate in usable
        if not only_replay_sha256 or candidate.replay_sha256 in only_replay_sha256
    ]
    unusable_reason_counts: dict[str, int] = {}
    for candidate in matched:
        if candidate.usability_status == "USABLE":
            continue
        reason = candidate.usability_status or "UNKNOWN"
        unusable_reason_counts[reason] = unusable_reason_counts.get(reason, 0) + 1

    summary = {
        "dataset": "Soft Support Manual Review Dataset V1",
        "target_support_champion": support_champion,
        "database_access_mode": "read_only",
        "parameters": {
            "pre_seconds": pre_seconds,
            "post_seconds": post_seconds,
            "protection_pre_seconds": protection_pre_seconds,
            "replay_filter": sorted(only_replay_sha256 or ()),
        },
        "matching_replays": len(matched),
        "local_replays": sum(candidate.replay_exists for candidate in matched),
        "usable_replays": len(usable),
        "selected_usable_replays": len(selected_usable),
        "missing_replays": len(missing),
        "unresolved_role_replays": len(unresolved),
        "unusable_replays": len(matched) - len(usable),
        "unusable_replay_reason_counts": dict(sorted(unusable_reason_counts.items())),
        "total_adc_deaths": len(rows),
        "deaths_with_protection_v4_profile": sum(
            row["protection_v4_profile_status"] is not None for row in rows
        ),
        "deaths_with_protection_v4_context": sum(
            (row["protection_event_count"] or 0) > 0
            or (row["protection_state_transition_count"] or 0) > 0
            for row in rows
        ),
        "deaths_with_shield_events": sum(
            (row["shield_event_count"] or 0) > 0 for row in rows
        ),
        "deaths_with_heal_events": sum(
            (row["heal_event_count"] or 0) > 0 for row in rows
        ),
        "deaths_with_reliable_support_attribution": sum(
            row["support_attribution_available"] is True for row in rows
        ),
        "deaths_requiring_manual_review": sum(
            row["manual_review_status"] == "UNREVIEWED" for row in rows
        ),
        "validation": {
            **validation,
            "output_row_count": len(rows),
            "unique_output_death_ids": len({row["adc_death_id"] for row in rows}),
        },
    }

    csv_path = output_dir / f"{slug}_adc_death_review.csv"
    jsonl_path = output_dir / f"{slug}_adc_death_review.jsonl"
    summary_path = output_dir / f"{slug}_adc_death_review_summary.json"
    write_csv(csv_path, rows, OUTPUT_COLUMNS)
    write_jsonl(jsonl_path, rows)
    _atomic_write_text(
        summary_path,
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )

    missing_path = output_dir / "missing_target_replays.csv"
    if missing:
        write_csv(missing_path, [_missing_row(candidate) for candidate in missing], MISSING_COLUMNS)

    summary["output_files"] = {
        "csv": str(csv_path.resolve()),
        "jsonl": str(jsonl_path.resolve()),
        "summary": str(summary_path.resolve()),
        "missing_replays": str(missing_path.resolve()) if missing else None,
    }
    # Re-write after adding output paths; these paths are objective run metadata.
    _atomic_write_text(
        summary_path,
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )
    return {"summary": summary, "rows": rows, "candidates": candidates}


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--db", type=Path, default=DEFAULT_DB)
    value.add_argument("--metadata-root", type=Path, default=DEFAULT_METADATA_ROOT)
    value.add_argument("--replay-root", type=Path, default=DEFAULT_REPLAY_ROOT)
    value.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    value.add_argument("--support-champion", default="Lulu")
    value.add_argument("--pre-seconds", type=_nonnegative_seconds, default=20.0)
    value.add_argument("--post-seconds", type=_nonnegative_seconds, default=10.0)
    value.add_argument(
        "--protection-pre-seconds", type=_nonnegative_seconds, default=15.0
    )
    value.add_argument(
        "--only-replay-sha256",
        action="append",
        default=[],
        help="development-only filter; may be repeated",
    )
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    result = build_dataset(
        db_path=args.db,
        metadata_root=args.metadata_root,
        replay_root=args.replay_root,
        output_dir=args.output_dir,
        support_champion=args.support_champion,
        pre_seconds=args.pre_seconds,
        post_seconds=args.post_seconds,
        protection_pre_seconds=args.protection_pre_seconds,
        only_replay_sha256=set(args.only_replay_sha256) or None,
    )
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
