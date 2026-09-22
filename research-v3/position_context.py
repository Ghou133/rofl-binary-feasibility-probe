"""Conservative position joins for the V3 research layer.

Hero positions are derived from verified PathPacket waypoints.  This module
never upgrades them to direct observations and never looks ahead in time.
"""

from __future__ import annotations

from bisect import bisect_right
from collections import defaultdict
from math import hypot


PARTICIPANT_NETWORK_ID_BASE = 0x400000AD
DEFAULT_MAX_POSITION_AGE_MS = 2_000
DEFAULT_RADII = (600, 900, 1_200, 1_600)
ADC_CHECKPOINTS = (
    ("combat_start", None),
    ("death_minus_3s", -3_000),
    ("death_minus_1s", -1_000),
    ("death", 0),
)
WARD_DEATH_OFFSETS_MS = (10_000, 30_000, 60_000, 120_000)


def participant_network_id(participant_id):
    if not isinstance(participant_id, int) or not 1 <= participant_id <= 10:
        return None
    return PARTICIPANT_NETWORK_ID_BASE + participant_id


def participant_id_from_network_id(network_id):
    if not isinstance(network_id, int):
        return None
    participant_id = network_id - PARTICIPANT_NETWORK_ID_BASE
    return participant_id if 1 <= participant_id <= 10 else None


class PositionIndex:
    """Index one-second derived positions by replay and entity."""

    def __init__(self, rows):
        grouped = defaultdict(list)
        for row in rows:
            replay_sha256 = row.get("replay_sha256")
            entity_id = row.get("entity_id", row.get("network_id"))
            timestamp_ms = row.get("timestamp_ms", row.get("replay_time_ms"))
            if not replay_sha256 or not isinstance(entity_id, int):
                continue
            if not isinstance(timestamp_ms, (int, float)) or timestamp_ms < 0:
                continue
            grouped[(replay_sha256, entity_id)].append(row)
        self._rows = {}
        self._timestamps = {}
        for key, values in grouped.items():
            values.sort(key=lambda row: (
                row.get("timestamp_ms", row.get("replay_time_ms", 0)),
                row.get("source_path_timestamp_ms", 0),
            ))
            self._rows[key] = values
            self._timestamps[key] = [
                row.get("timestamp_ms", row.get("replay_time_ms")) for row in values
            ]

    def lookup(self, replay_sha256, entity_id, at_ms,
               max_source_age_ms=DEFAULT_MAX_POSITION_AGE_MS):
        """Return the latest non-lookahead position and its freshness state."""
        key = (replay_sha256, entity_id)
        timestamps = self._timestamps.get(key)
        if not timestamps or not isinstance(at_ms, (int, float)):
            return None
        index = bisect_right(timestamps, at_ms) - 1
        if index < 0:
            return None
        row = self._rows[key][index]
        timestamp_ms = row.get("timestamp_ms", row.get("replay_time_ms"))
        source_timestamp_ms = row.get("source_path_timestamp_ms")
        position = row.get("position_xz")
        if not isinstance(position, (list, tuple)) or len(position) != 2:
            x, y = row.get("x"), row.get("y", row.get("z"))
        else:
            x, y = position
        if not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
            return None
        if not isinstance(source_timestamp_ms, (int, float)):
            return None
        sample_age_ms = at_ms - timestamp_ms
        source_age_ms = at_ms - source_timestamp_ms
        if sample_age_ms < 0 or source_age_ms < 0:
            return None
        usable = max_source_age_ms is None or source_age_ms <= max_source_age_ms
        raw_packet_ref = row.get("source_raw_packet_ref", row.get("raw_packet_ref"))
        return {
            "x": float(x),
            "y": float(y),
            "position_timestamp_ms": int(timestamp_ms),
            "source_path_timestamp_ms": int(source_timestamp_ms),
            "sample_age_ms": int(sample_age_ms),
            "source_age_ms": int(source_age_ms),
            "max_position_age_ms": max_source_age_ms,
            "position_status": "VERIFIED_DERIVED",
            "interpolation_method": row.get(
                "interpolation", "LINEAR_ALONG_DECODED_WAYPOINTS"
            ),
            "freshness_status": "FRESH" if usable else "STALE_SOURCE_PATH",
            "usable": bool(usable),
            "raw_packet_ref": raw_packet_ref,
        }


def _participants_by_replay(rows):
    result = defaultdict(dict)
    for row in rows:
        replay_sha256 = row.get("replay_sha256")
        participant_id = row.get("participant_id")
        if not replay_sha256 or not isinstance(participant_id, int):
            continue
        normalized = dict(row)
        normalized.setdefault("network_id", participant_network_id(participant_id))
        result[replay_sha256][participant_id] = normalized
    return result


def _distance(left, right):
    if not left or not right:
        return None
    return hypot(left["x"] - right["x"], left["y"] - right["y"])


def _point_segment_distance(point, start, end):
    """Euclidean distance to a closed segment; inputs use x/y mappings."""
    if not point or not start or not end:
        return None
    dx, dy = end["x"] - start["x"], end["y"] - start["y"]
    length_squared = dx * dx + dy * dy
    if length_squared == 0:
        return _distance(point, start)
    projection = (
        (point["x"] - start["x"]) * dx
        + (point["y"] - start["y"]) * dy
    ) / length_squared
    projection = max(0.0, min(1.0, projection))
    nearest = {"x": start["x"] + projection * dx,
               "y": start["y"] + projection * dy}
    return _distance(point, nearest)


def _usable_position(index, replay_sha256, participant, at_ms, max_age_ms):
    if not participant:
        return None
    position = index.lookup(
        replay_sha256,
        participant.get("network_id", participant_network_id(participant.get("participant_id"))),
        at_ms,
        max_age_ms,
    )
    return position if position and position["usable"] else None


def _snapshot(index, replay_sha256, participants, at_ms, max_age_ms):
    result = {}
    for participant_id, participant in participants.items():
        result[participant_id] = index.lookup(
            replay_sha256,
            participant.get("network_id", participant_network_id(participant_id)),
            at_ms,
            max_age_ms,
        )
    return result


def _checkpoint_context(index, replay_sha256, participants, subject_id, at_ms,
                        max_age_ms, radii):
    subject = participants.get(subject_id)
    subject_team = subject.get("team_id") if subject else None
    snapshot = _snapshot(index, replay_sha256, participants, at_ms, max_age_ms)
    subject_position = snapshot.get(subject_id)
    usable_subject = subject_position if subject_position and subject_position["usable"] else None
    enemies = []
    allies = []
    if usable_subject and subject_team is not None:
        for participant_id, participant in participants.items():
            if participant_id == subject_id:
                continue
            position = snapshot.get(participant_id)
            if not position or not position["usable"]:
                continue
            distance = _distance(usable_subject, position)
            entry = (participant_id, participant, position, distance)
            if participant.get("team_id") == subject_team:
                allies.append(entry)
            elif participant.get("team_id") is not None:
                enemies.append(entry)
    support = next((row for row in participants.values()
                    if row.get("team_id") == subject_team and row.get("role") == "support"), None)
    support_position = snapshot.get(support.get("participant_id")) if support else None
    support_usable = support_position if support_position and support_position["usable"] else None
    enemy_distances = [entry[3] for entry in enemies]
    result = {
        "at_ms": int(at_ms),
        "subject_position": subject_position,
        "subject_position_usable": bool(usable_subject),
        "support_participant_id": support.get("participant_id") if support else None,
        "support_position": support_position,
        "support_distance": _distance(usable_subject, support_usable),
        "nearest_enemy_distance": min(enemy_distances) if enemy_distances else None,
        "usable_ally_position_count": len(allies),
        "usable_enemy_position_count": len(enemies),
    }
    for radius in radii:
        result[f"enemy_count_within_{radius}"] = sum(
            distance <= radius for _, _, _, distance in enemies
        )
        result[f"ally_count_within_{radius}"] = sum(
            distance <= radius for _, _, _, distance in allies
        )
    return result


def build_ward_position_context(wards, participants, position_rows,
                                max_position_age_ms=DEFAULT_MAX_POSITION_AGE_MS,
                                nearby_radius=1_600):
    """Derive owner/team context for every actual WardSpawn row."""
    participant_map = _participants_by_replay(participants)
    position_index = position_rows if isinstance(position_rows, PositionIndex) else PositionIndex(position_rows)
    output = []
    for ward in wards:
        replay_sha256 = ward.get("replay_sha256") or ward.get("raw_packet_ref", {}).get("replay_sha256")
        at_ms = ward.get("spawn_time_ms", ward.get("replay_time_ms", ward.get("timestamp_ms")))
        if not replay_sha256 or not isinstance(at_ms, (int, float)):
            continue
        replay_participants = participant_map.get(replay_sha256, {})
        owner_participant_id = ward.get("owner_participant_id")
        if owner_participant_id is None:
            owner_participant_id = participant_id_from_network_id(ward.get("owner_network_id"))
        owner = replay_participants.get(owner_participant_id)
        owner_team = owner.get("team_id") if owner else ward.get("owner_team_id")
        owner_position = _usable_position(
            position_index, replay_sha256, owner, at_ms, max_position_age_ms
        )
        actual_x = ward.get(
            "actual_x", ward.get("x", (ward.get("position") or {}).get("x"))
        )
        actual_y = ward.get(
            "actual_y", ward.get("y", (ward.get("position") or {}).get("y"))
        )
        ward_position = (
            {"x": float(actual_x), "y": float(actual_y)}
            if isinstance(actual_x, (int, float))
            and isinstance(actual_y, (int, float)) else None
        )
        distance_reference = ward_position or owner_position
        snapshot = _snapshot(
            position_index, replay_sha256, replay_participants, at_ms, max_position_age_ms
        )
        allies, enemies = [], []
        for participant_id, participant in replay_participants.items():
            position = snapshot.get(participant_id)
            if not distance_reference or not position or not position["usable"]:
                continue
            distance = _distance(distance_reference, position)
            if participant.get("team_id") == owner_team:
                allies.append((participant, position, distance))
            elif participant.get("team_id") is not None and owner_team is not None:
                enemies.append((participant, position, distance))
        enemy_jungler = next((row for row in replay_participants.values()
                              if row.get("team_id") != owner_team
                              and row.get("role") == "jungle"), None)
        allied_adc = next((row for row in replay_participants.values()
                           if row.get("team_id") == owner_team and row.get("role") == "adc"), None)
        allied_support = next((row for row in replay_participants.values()
                               if row.get("team_id") == owner_team
                               and row.get("role") == "support"), None)
        jungler_position = _usable_position(
            position_index, replay_sha256, enemy_jungler, at_ms, max_position_age_ms
        )
        output.append({
            "replay_sha256": replay_sha256,
            "ward_network_id": ward.get("ward_network_id", ward.get("entity_network_id")),
            "timestamp_ms": int(at_ms),
            "owner_participant_id": owner_participant_id,
            "owner_position": owner_position,
            "nearest_enemy_distance": min((entry[2] for entry in enemies), default=None),
            "enemy_jungler_position": jungler_position,
            "enemy_jungler_distance": _distance(distance_reference, jungler_position),
            "allied_adc_position": _usable_position(
                position_index, replay_sha256, allied_adc, at_ms, max_position_age_ms
            ),
            "allied_support_position": _usable_position(
                position_index, replay_sha256, allied_support, at_ms, max_position_age_ms
            ),
            "nearby_enemy_count": sum(entry[2] <= nearby_radius for entry in enemies),
            "nearby_ally_count": sum(entry[2] <= nearby_radius for entry in allies),
            "nearby_radius": nearby_radius,
            "distance_reference": (
                "WARD_ACTUAL_POSITION" if ward_position
                else "OWNER_POSITION_FALLBACK"
            ),
            "max_position_age_ms": max_position_age_ms,
            "position_status": "VERIFIED_DERIVED",
        })
    return output


def build_adc_death_position_context(adc_deaths, participants, position_rows,
                                     max_position_age_ms=DEFAULT_MAX_POSITION_AGE_MS,
                                     radii=DEFAULT_RADII):
    """Return checkpoint rows plus one factual feature row per ADC death."""
    participant_map = _participants_by_replay(participants)
    position_index = position_rows if isinstance(position_rows, PositionIndex) else PositionIndex(position_rows)
    context_rows = []
    feature_rows = []
    for death_index, death in enumerate(adc_deaths):
        replay_sha256 = death.get("replay_sha256")
        death_time_ms = death.get("death_time_ms")
        combat_start_ms = death.get("combat_start_ms")
        adc_id = death.get("adc_participant_id")
        if not replay_sha256 or not isinstance(death_time_ms, (int, float)):
            continue
        if not isinstance(combat_start_ms, (int, float)):
            combat_start_ms = death_time_ms
        replay_participants = participant_map.get(replay_sha256, {})
        checkpoint_map = {}
        for checkpoint, offset in ADC_CHECKPOINTS:
            at_ms = combat_start_ms if offset is None else max(0, death_time_ms + offset)
            context = _checkpoint_context(
                position_index, replay_sha256, replay_participants, adc_id,
                at_ms, max_position_age_ms, radii,
            )
            context_row = {
                "death_context_id": f"{replay_sha256}:{int(death_time_ms)}:{adc_id}",
                "game_id": death.get("game_id", death.get("match_id")),
                "replay_sha256": replay_sha256,
                "patch": death.get("patch"),
                "adc_participant_id": adc_id,
                "checkpoint": checkpoint,
                "checkpoint_time_ms": int(at_ms),
                "max_position_age_ms": max_position_age_ms,
                "position_status": "VERIFIED_DERIVED",
                **context,
            }
            checkpoint_map[checkpoint] = context_row
            context_rows.append(context_row)
        attackers = death.get("attackers") or []
        first_attacker = min(
            attackers,
            key=lambda row: row.get("first_hit_time_ms", float("inf")),
            default=None,
        )
        largest_attacker = max(
            attackers,
            key=lambda row: row.get("damage_amount", float("-inf")),
            default=None,
        )
        start = checkpoint_map["combat_start"]
        end = checkpoint_map["death"]
        feature = {
            "death_context_id": start["death_context_id"],
            "game_id": start["game_id"],
            "replay_sha256": replay_sha256,
            "patch": death.get("patch"),
            "adc_participant_id": adc_id,
            "death_time_ms": int(death_time_ms),
            "time_to_die_ms": int(death_time_ms - combat_start_ms),
            "attacker_count": death.get("attacker_count", len(attackers)),
            "damage_by_attacker": [
                {
                    "participant_id": row.get("participant_id"),
                    "champion": row.get("champion"),
                    "damage_amount": row.get("damage_amount"),
                    "hit_count": row.get("hit_count"),
                }
                for row in attackers
            ],
            "first_attacker_participant_id": first_attacker.get("participant_id") if first_attacker else None,
            "largest_damage_attacker_participant_id": largest_attacker.get("participant_id") if largest_attacker else None,
            "support_distance_start": start.get("support_distance"),
            "support_distance_death": end.get("support_distance"),
            "nearest_enemy_start": start.get("nearest_enemy_distance"),
            "nearest_enemy_death": end.get("nearest_enemy_distance"),
            "position_context_status": (
                "VERIFIED_DERIVED" if start["subject_position_usable"]
                and end["subject_position_usable"] else "PARTIAL_STALE_OR_MISSING"
            ),
            "max_position_age_ms": max_position_age_ms,
        }
        for radius in radii:
            feature[f"enemy_count_start_{radius}"] = start[f"enemy_count_within_{radius}"]
            feature[f"enemy_count_death_{radius}"] = end[f"enemy_count_within_{radius}"]
            feature[f"ally_count_start_{radius}"] = start[f"ally_count_within_{radius}"]
            feature[f"ally_count_death_{radius}"] = end[f"ally_count_within_{radius}"]
        feature_rows.append(feature)
    return context_rows, feature_rows


def build_ward_death_context(adc_deaths, participants, position_rows, wards,
                             lifecycles, max_position_age_ms=DEFAULT_MAX_POSITION_AGE_MS,
                             nearby_radius=1_600,
                             gank_corridor_radius=900,
                             offsets_ms=WARD_DEATH_OFFSETS_MS):
    """Measure confirmed and uncertain Ward coverage before each ADC death."""
    participant_map = _participants_by_replay(participants)
    position_index = position_rows if isinstance(position_rows, PositionIndex) else PositionIndex(position_rows)
    lifecycle_map = {
        (row.get("replay_sha256") or row.get("spawn_raw_packet_ref", {}).get("replay_sha256"),
         row.get("ward_network_id")): row
        for row in lifecycles
    }
    wards_by_replay = defaultdict(list)
    for ward in wards:
        replay_sha256 = ward.get("replay_sha256") or ward.get("raw_packet_ref", {}).get("replay_sha256")
        if replay_sha256:
            wards_by_replay[replay_sha256].append(ward)
    output = []
    for death in adc_deaths:
        replay_sha256 = death.get("replay_sha256")
        death_time_ms = death.get("death_time_ms")
        adc_id = death.get("adc_participant_id")
        if not replay_sha256 or not isinstance(death_time_ms, (int, float)):
            continue
        participants_for_replay = participant_map.get(replay_sha256, {})
        adc = participants_for_replay.get(adc_id)
        adc_team = adc.get("team_id") if adc else None
        enemy_jungler = next((
            participant for participant in participants_for_replay.values()
            if participant.get("team_id") is not None
            and participant.get("team_id") != adc_team
            and participant.get("role") == "jungle"
        ), None)
        for offset_ms in offsets_ms:
            at_ms = max(0, death_time_ms - offset_ms)
            adc_position = _usable_position(
                position_index, replay_sha256, adc, at_ms, max_position_age_ms
            )
            enemy_jungler_position = _usable_position(
                position_index, replay_sha256, enemy_jungler, at_ms,
                max_position_age_ms,
            )
            distances = {
                "allied_confirmed": [], "enemy_confirmed": [],
                "allied_uncertain": [], "enemy_uncertain": [],
            }
            unknown_team_count = 0
            corridor_distances = {"confirmed": [], "uncertain": []}
            for ward in wards_by_replay.get(replay_sha256, []):
                spawn_time_ms = ward.get("spawn_time_ms", ward.get("replay_time_ms", ward.get("timestamp_ms")))
                if not isinstance(spawn_time_ms, (int, float)) or spawn_time_ms > at_ms:
                    continue
                lifecycle = lifecycle_map.get((replay_sha256, ward.get(
                    "ward_network_id", ward.get("entity_network_id")
                )))
                if lifecycle:
                    remove_time_ms = lifecycle.get("remove_time_ms")
                    if isinstance(remove_time_ms, (int, float)) and remove_time_ms <= at_ms:
                        continue
                    activity = "confirmed"
                else:
                    activity = "uncertain"
                owner_team = ward.get("owner_team_id", ward.get("owner_team"))
                if owner_team is None:
                    owner_id = ward.get("owner_participant_id")
                    if owner_id is None:
                        owner_id = participant_id_from_network_id(ward.get("owner_network_id"))
                    owner = participants_for_replay.get(owner_id)
                    owner_team = owner.get("team_id") if owner else None
                x = ward.get("actual_x", ward.get("x", ward.get("position", {}).get("x")))
                y = ward.get("actual_y", ward.get("y", ward.get("position", {}).get("y")))
                if not adc_position or not isinstance(x, (int, float)) or not isinstance(y, (int, float)):
                    continue
                distance = hypot(adc_position["x"] - x, adc_position["y"] - y)
                if owner_team is None or adc_team is None:
                    unknown_team_count += 1
                    continue
                side = "allied" if owner_team == adc_team else "enemy"
                distances[f"{side}_{activity}"].append(distance)
                if side == "allied" and enemy_jungler_position:
                    corridor_distance = _point_segment_distance(
                        {"x": float(x), "y": float(y)},
                        enemy_jungler_position, adc_position,
                    )
                    if corridor_distance is not None:
                        corridor_distances[activity].append(corridor_distance)
            row = {
                "death_context_id": f"{replay_sha256}:{int(death_time_ms)}:{adc_id}",
                "game_id": death.get("game_id", death.get("match_id")),
                "replay_sha256": replay_sha256,
                "adc_participant_id": adc_id,
                "death_time_ms": int(death_time_ms),
                "lookback_ms": int(offset_ms),
                "context_time_ms": int(at_ms),
                "nearby_radius": nearby_radius,
                "max_position_age_ms": max_position_age_ms,
                "adc_position": adc_position,
                "enemy_jungler_participant_id": (
                    enemy_jungler.get("participant_id") if enemy_jungler else None
                ),
                "enemy_jungler_position": enemy_jungler_position,
                "position_status": "VERIFIED_DERIVED" if adc_position else "STALE_OR_MISSING",
                "unknown_team_ward_count": unknown_team_count,
                "lifecycle_policy": "CONFIRMED_ONLY_WHEN_REMOVE_BOUND_IS_KNOWN; OTHERWISE_UNCERTAIN",
                "gank_corridor_radius": gank_corridor_radius,
                "gank_corridor_definition": "ENEMY_JUNGLER_TO_ADC_STRAIGHT_SEGMENT",
                "gank_corridor_status": (
                    "VERIFIED_DERIVED_GEOMETRY"
                    if adc_position and enemy_jungler_position
                    else "STALE_OR_MISSING_POSITION"
                ),
                "allied_ward_gank_corridor_count": sum(
                    value <= gank_corridor_radius
                    for value in corridor_distances["confirmed"]
                ),
                "allied_ward_gank_corridor_count_uncertain": sum(
                    value <= gank_corridor_radius
                    for value in corridor_distances["uncertain"]
                ),
                "nearest_allied_ward_gank_corridor_distance": (
                    min(corridor_distances["confirmed"])
                    if corridor_distances["confirmed"] else None
                ),
                "nearest_allied_ward_gank_corridor_distance_uncertain": (
                    min(corridor_distances["uncertain"])
                    if corridor_distances["uncertain"] else None
                ),
            }
            for side in ("allied", "enemy"):
                confirmed = distances[f"{side}_confirmed"]
                uncertain = distances[f"{side}_uncertain"]
                row[f"nearby_{side}_wards"] = sum(value <= nearby_radius for value in confirmed)
                row[f"nearby_{side}_wards_uncertain"] = sum(
                    value <= nearby_radius for value in uncertain
                )
                row[f"nearest_{side}_ward_distance"] = min(confirmed) if confirmed else None
                row[f"nearest_{side}_ward_distance_uncertain"] = (
                    min(uncertain) if uncertain else None
                )
            output.append(row)
    return output
