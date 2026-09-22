#!/usr/bin/env python3

"""Sequence/counterexample analysis for exact-build buff/spell/damage recovery.

No temporal match is promoted to causality.  Exact identities, route ownership,
field-use evidence, aggregate anchors, and counterexamples are reported
separately so downstream review can choose a safe semantic boundary.
"""

from __future__ import annotations

import argparse
import bisect
import collections
import hashlib
import json
import math
import pathlib
import statistics
from typing import Any, Iterable


BUILD = "16.16.805.0442"
WINDOWS_MS = (50, 100, 250, 500, 1000, 2000)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--buff-spell", required=True)
    parser.add_argument("--on-event", required=True)
    parser.add_argument("--damage", required=True)
    parser.add_argument("--neighbors", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--spell-dictionary", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--witnesses")
    return parser.parse_args()


def reject_holdout(value: str, label: str) -> pathlib.Path:
    resolved = pathlib.Path(value).resolve()
    if "holdout" in str(resolved).lower():
        raise ValueError(f"{label} must not reference protected Holdout content: {resolved}")
    return resolved


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def jsonl(path: pathlib.Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            if row.get("build", row.get("replay_version")) != BUILD:
                raise ValueError(f"{path}:{line_number} has wrong build")
            yield row


def percentile_summary(values: list[float]) -> dict[str, Any]:
    finite = sorted(value for value in values if math.isfinite(value))
    if not finite:
        return {"count": 0}

    def at(fraction: float) -> float:
        return finite[min(len(finite) - 1, round((len(finite) - 1) * fraction))]

    return {
        "count": len(finite),
        "min": finite[0],
        "p50": at(0.50),
        "p95": at(0.95),
        "p99": at(0.99),
        "max": finite[-1],
        "mean": statistics.fmean(finite),
    }


def counter_json(counter: collections.Counter, formatter=str) -> dict[str, int]:
    return {formatter(key): value for key, value in sorted(counter.items(), key=lambda item: str(item[0]))}


def is_network_id(value: int) -> bool:
    return 0x40000000 <= value <= 0x4FFFFFFF


def normalize_name(value: str | None) -> str:
    return "".join(character.lower() for character in (value or "") if character.isalnum())


def load_metadata(manifest_path: pathlib.Path) -> tuple[dict, dict, dict]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    player_by_replay_id = {}
    team_by_replay_id = {}
    champion_names = {}
    for replay in manifest["replays"]:
        label = pathlib.Path(replay["path"]).stem
        for player in replay["players"]:
            key = (label, player["champion_network_id"])
            player_by_replay_id[key] = player
            team_by_replay_id[key] = player["team_id"]
            champion_names[key] = player["champion"]
    return manifest, player_by_replay_id, team_by_replay_id | {}


def analyze_buff_and_cast(
    path: pathlib.Path,
    player_by_replay_id: dict,
    dictionary_by_hash: dict,
    witnesses: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    counts = collections.Counter()
    add_field_shapes = collections.Counter()
    add_field_target_equal = collections.Counter()
    add_field_champion = collections.Counter()
    add_byte_histograms = collections.Counter()
    buff_slots = collections.Counter()
    buff_hashes = collections.Counter()
    hash_dictionary_hits = collections.Counter()
    last_add: dict[tuple[str, int, int], dict[str, Any]] = {}
    remove_match_offsets = collections.Counter()
    remove_prior_add = 0
    remove_without_add = 0
    update_prior_add = collections.Counter()
    count_value_histograms = collections.Counter()
    exact_cast_remove_matches = collections.Counter()
    recent_casts_by_replay_hash: dict[tuple[str, int], list[tuple[int, int, int]]] = collections.defaultdict(list)
    cast_time_residual_ms: list[float] = []
    add_time_residuals: dict[str, list[float]] = collections.defaultdict(list)
    update_time_residuals: dict[str, list[float]] = collections.defaultdict(list)
    remove_time_residual_ms: list[float] = []
    cast_key_counts = collections.Counter()
    caster_name_matches = collections.Counter()
    caster_relation_counts = collections.Counter()
    cast_slots = collections.Counter()
    cast_rows: list[dict[str, Any]] = []
    exact_hash_witnesses = 0
    add_time_relations = collections.Counter()

    for row in jsonl(path):
        counts[f"route_0x{row['packet_id']:04x}"] += 1
        replay = row["replay_label"]
        time_ms = row["replay_time_ms"]
        packet_id = row["packet_id"]
        route_entity = row["target_network_id_candidate"]
        if packet_id == 0x0326:
            slot = row["slot_candidate"]
            fields = row["u32_candidates"]
            byte_candidates = row["byte_candidates_01_03"]
            float_fields = row["time_or_float_candidates"]
            buff_slots[(packet_id, slot)] += 1
            for offset, value in fields.items():
                shape = "network" if is_network_id(value) else "scalar"
                add_field_shapes[(offset, shape)] += 1
                add_field_target_equal[offset] += int(value == route_entity)
                add_field_champion[offset] += int((replay, value) in player_by_replay_id)
            for byte_offset, value in zip(("0x01", "0x02", "0x03"), byte_candidates):
                add_byte_histograms[(byte_offset, value)] += 1
            name_hash = fields["0x04"]
            buff_hashes[(packet_id, name_hash)] += 1
            hash_dictionary_hits["add_hash_0x04_total"] += 1
            hash_dictionary_hits["add_hash_0x04_dictionary_hit"] += int(
                f"0x{name_hash:08x}" in dictionary_by_hash
            )
            for offset in ("0x0c", "0x10"):
                value = float_fields.get(offset)
                if value is not None:
                    add_time_residuals[offset].append(value * 1000.0 - time_ms)
            start_candidate = float_fields.get("0x0c")
            end_candidate = float_fields.get("0x10")
            if start_candidate is not None and end_candidate is not None:
                add_time_relations["finite_pairs"] += 1
                add_time_relations["end_ge_start"] += int(end_candidate >= start_candidate)
                add_time_relations["start_le_replay_time_plus_1ms"] += int(
                    start_candidate * 1000.0 <= time_ms + 1.0
                )
                add_time_relations["start_within_1ms_of_replay"] += int(
                    abs(start_candidate * 1000.0 - time_ms) <= 1.0
                )
                add_time_relations["end_ge_replay_time_minus_1ms"] += int(
                    end_candidate * 1000.0 >= time_ms - 1.0
                )
            last_add[(replay, route_entity, slot)] = {
                "time_ms": time_ms,
                "fields": fields,
                "hash": name_hash,
                "byte_candidates": byte_candidates,
                "seen_count_update": False,
            }
        elif packet_id == 0x045B:
            slot = row["slot_candidate"]
            name_hash = row["network_or_hash_candidate"]
            buff_slots[(packet_id, slot)] += 1
            buff_hashes[(packet_id, name_hash)] += 1
            hash_dictionary_hits["remove_hash_total"] += 1
            hash_dictionary_hits["remove_hash_dictionary_hit"] += int(
                f"0x{name_hash:08x}" in dictionary_by_hash
            )
            time_candidate = row.get("time_candidate")
            if time_candidate is not None:
                remove_time_residual_ms.append(time_candidate * 1000.0 - time_ms)
            prior = last_add.get((replay, route_entity, slot))
            if prior is None:
                remove_without_add += 1
            else:
                remove_prior_add += 1
                for offset, value in prior["fields"].items():
                    remove_match_offsets[offset] += int(value == name_hash)
                if prior["hash"] == name_hash and exact_hash_witnesses < 12:
                    witnesses.append({
                        "kind": "BUFF_ADD_REMOVE_EXACT_HASH_SLOT_ENTITY",
                        "replay": replay,
                        "entity": route_entity,
                        "slot": slot,
                        "add_time_ms": prior["time_ms"],
                        "remove_time_ms": time_ms,
                        "hash": name_hash,
                    })
                    exact_hash_witnesses += 1
                # The remove operation closes this active route-entity/slot
                # state.  Keeping it would let a later duplicate/remove match
                # stale evidence and inflate the sequence result.
                last_add.pop((replay, route_entity, slot), None)
            recent = recent_casts_by_replay_hash.get((replay, name_hash), [])
            if recent:
                index = bisect.bisect_right([item[0] for item in recent], time_ms) - 1
                if index >= 0:
                    delta = time_ms - recent[index][0]
                    for window in WINDOWS_MS:
                        exact_cast_remove_matches[f"within_{window}ms"] += int(0 <= delta <= window)
        elif packet_id in (0x0123, 0x043C):
            slot = row["slot_candidate"]
            buff_slots[(packet_id, slot)] += 1
            prior = last_add.get((replay, route_entity, slot))
            update_prior_add[f"0x{packet_id:04x}:total"] += 1
            update_prior_add[f"0x{packet_id:04x}:prior_add_same_entity_slot"] += int(prior is not None)
            if prior is not None:
                update_prior_add[f"0x{packet_id:04x}:source_equals_add_0x20"] += int(
                    row["network_or_hash_candidate"] == prior["fields"]["0x20"]
                )
                if packet_id == 0x0123:
                    count_value = row["count_candidate"]
                    count_value_histograms[("0x0123:r8_low_byte", count_value)] += 1
                    for byte_offset, byte_value in zip(
                        ("0x01", "0x02", "0x03"), prior["byte_candidates"]
                    ):
                        update_prior_add[
                            f"0x0123:count_equals_add_byte_{byte_offset}"
                        ] += int(count_value == byte_value)
                    if not prior["seen_count_update"]:
                        update_prior_add["0x0123:first_count_update_after_add"] += 1
                        for byte_offset, byte_value in zip(
                            ("0x01", "0x02", "0x03"), prior["byte_candidates"]
                        ):
                            update_prior_add[
                                f"0x0123:first_count_equals_add_byte_{byte_offset}"
                            ] += int(count_value == byte_value)
                        prior["seen_count_update"] = True
            for label in ("time_candidate_a", "time_candidate_b"):
                value = row.get(label)
                if value is not None:
                    update_time_residuals[f"0x{packet_id:04x}:{label}"].append(
                        value * 1000.0 - time_ms
                    )
        elif packet_id == 0x041F:
            slot = row["counter_candidate_a"]
            buff_slots[(packet_id, slot)] += 1
            count_value_histograms[("0x041f:r8_u32", row["u32_candidate_b"])] += 1
            count_value_histograms[("0x041f:stack_byte", row["counter_candidate_b"])] += 1
            prior = last_add.get((replay, route_entity, slot))
            update_prior_add["0x041f:total"] += 1
            update_prior_add["0x041f:prior_add_same_entity_slot"] += int(prior is not None)
            if prior is not None:
                update_prior_add["0x041f:u32_a_equals_add_hash"] += int(
                    row["u32_candidate_a"] == prior["hash"]
                )
        elif packet_id == 0x01CF:
            key = row["spell_key_candidate"]
            caster = row["caster_network_id_candidate"]
            chain_owner = row["chain_owner_network_id_candidate"]
            cast_key_counts[key] += 1
            cast_slots[row["slot_or_enum_candidate_0x154"]] += 1
            caster_relation_counts["raw_param_equals_caster"] += int(route_entity == caster)
            caster_relation_counts["caster_equals_chain_owner"] += int(caster == chain_owner)
            caster_relation_counts["total"] += 1
            player = player_by_replay_id.get((replay, caster))
            if player is None:
                caster_name_matches["caster_not_participant"] += 1
            else:
                name_matches = normalize_name(player["champion"]) == normalize_name(
                    row["caster_name_exact_translator"]
                )
                caster_name_matches["participant_name_match"] += int(name_matches)
                caster_name_matches["participant_name_mismatch"] += int(not name_matches)
            cast_seconds = row.get("time_seconds_candidate_0x164")
            if cast_seconds is not None:
                cast_residual = cast_seconds * 1000.0 - time_ms
                cast_time_residual_ms.append(cast_residual)
                caster_relation_counts["cast_time_within_1ms_of_replay"] += int(
                    abs(cast_residual) <= 1.0
                )
            dictionary_entries = dictionary_by_hash.get(f"0x{key:08x}", [])
            hash_dictionary_hits["cast_key_total"] += 1
            hash_dictionary_hits["cast_key_dictionary_hit"] += int(bool(dictionary_entries))
            if player is not None and dictionary_entries:
                champion_match = any(
                    normalize_name(entry.get("champion_alias", ""))
                    == normalize_name(player["champion"])
                    for entry in dictionary_entries
                )
                hash_dictionary_hits["cast_key_dictionary_champion_match"] += int(champion_match)
            recent_casts_by_replay_hash[(replay, key)].append((time_ms, caster, route_entity))
            cast_rows.append({
                "replay": replay,
                "time_ms": time_ms,
                "caster": caster,
                "chain_owner": chain_owner,
                "route_entity": route_entity,
                "key": key,
                "candidate_ac": row["network_id_candidate_0xac"],
                "candidate_168": row["network_id_candidate_0x168"],
                "slot": row["slot_or_enum_candidate_0x154"],
                "name": row["caster_name_exact_translator"],
            })

    buff_summary = {
        "route_counts": counter_json(counts),
        "add_field_shape_counts": counter_json(
            add_field_shapes, lambda key: f"{key[0]}:{key[1]}"
        ),
        "add_field_equals_route_entity_counts": counter_json(add_field_target_equal),
        "add_field_participant_id_counts": counter_json(add_field_champion),
        "add_byte_candidate_histograms": {
            offset: [
                {"value": value, "count": count}
                for (candidate_offset, value), count in add_byte_histograms.most_common()
                if candidate_offset == offset
            ]
            for offset in ("0x01", "0x02", "0x03")
        },
        "slot_histogram_top": [
            {"route": f"0x{packet_id:04x}", "slot": slot, "count": count}
            for (packet_id, slot), count in buff_slots.most_common(50)
        ],
        "add_remove_same_entity_slot": {
            "remove_with_prior_add": remove_prior_add,
            "remove_without_prior_add": remove_without_add,
            "prior_add_field_exact_hash_matches": counter_json(remove_match_offsets),
        },
        "update_same_entity_slot_prior_add": counter_json(update_prior_add),
        "count_or_stack_candidate_histograms_top": [
            {"field": field, "value": value, "count": count}
            for (field, value), count in count_value_histograms.most_common(80)
        ],
        "time_field_residual_ms": {
            "add": {key: percentile_summary(value) for key, value in sorted(add_time_residuals.items())},
            "update": {
                key: percentile_summary(value) for key, value in sorted(update_time_residuals.items())
            },
            "remove": percentile_summary(remove_time_residual_ms),
            "add_pair_relations": counter_json(add_time_relations),
        },
        "exact_cast_key_to_later_remove_hash": counter_json(exact_cast_remove_matches),
        "hash_dictionary_16_15_side_evidence": counter_json(hash_dictionary_hits),
        "decision": {
            "operation_routes": "PROMOTE_EXACT_RUNTIME_ROUTE_OPERATION",
            "add_slot": "PROMOTE_STRUCTURAL_ARGUMENT_FIELD",
            "add_hash_0x04": "PROMOTE_IF_SEQUENCE_EXACT_MATCH_DOMINATES",
            "route_entity": "PROMOTE_AS_BUFF_MANAGER_ROUTING_ENTITY_NOT_GAMEPLAY_TARGET_NAME",
            "add_source_0x20": "PROMOTE_STRUCTURAL_SOURCE_CANDIDATE_WITH_PARTICIPANT_ANCHOR",
            "update_source": "PROMOTE_IF_EXACT_PRIOR_ADD_0x20_MATCH_DOMINATES",
            "041f_hash_slot_counter": "PROMOTE_IF_PRIOR_ADD_HASH_AND_SLOT_SEQUENCE_CONVERGE",
            "stack_or_count": "KEEP_STRUCTURAL_CANDIDATE_UNLESS_FIRST_UPDATE_SEQUENCE_DISCRIMINATES_ADD_BYTE",
            "time_fields": "REPORT_BY_RESIDUAL;_DO_NOT_ASSUME_DURATION_OR_EXPIRY",
        },
    }
    cast_summary = {
        "row_count": len(cast_rows),
        "unique_spell_key_count": len(cast_key_counts),
        "top_spell_keys": [
            {"spell_key": key, "spell_key_hex": f"0x{key:08x}", "count": count}
            for key, count in cast_key_counts.most_common(30)
        ],
        "slot_or_enum_histogram": counter_json(cast_slots),
        "caster_relations": counter_json(caster_relation_counts),
        "caster_name_participant_anchor": counter_json(caster_name_matches),
        "cast_time_minus_replay_time_ms": percentile_summary(cast_time_residual_ms),
        "decision": {
            "cast_occurrence_caster_key_time": "PROMOTE_EXACT_TRANSLATOR_FIELDS",
            "caster_name": "PROMOTE_ONLY_WITH_PARTICIPANT_ID_NAME_ANCHOR",
            "spell_dictionary": "CROSS_BUILD_SIDE_EVIDENCE_ONLY",
            "ability_or_damage_causality": "NOT_PROMOTED_BY_THIS_SECTION",
        },
    }
    return {"buff": buff_summary, "cast": cast_summary}, cast_rows


def analyze_damage(
    path: pathlib.Path,
    player_by_replay_id: dict,
    dictionary_by_hash: dict,
) -> tuple[dict[str, Any], dict[tuple[str, int], list[dict[str, Any]]]]:
    counts = collections.Counter()
    type_counts = collections.Counter()
    amount_sign = collections.Counter()
    key_hits = collections.Counter()
    by_source: dict[tuple[str, int], list[dict[str, Any]]] = collections.defaultdict(list)
    for row in jsonl(path):
        fields = row["decoded_fields"]
        source = fields["field_10_u32"]
        target = fields["field_14_u32"]
        amount = fields["field_24_f32"]
        key = fields["field_30_u32"]
        replay = row["replay_label"]
        counts["rows"] += 1
        counts["source_is_participant"] += int((replay, source) in player_by_replay_id)
        counts["target_is_participant"] += int((replay, target) in player_by_replay_id)
        counts["raw_param_equals_target"] += int(row["raw_param"] == target)
        type_counts[fields["field_28_u8"]] += 1
        sign = "positive" if amount > 0 else "zero" if amount == 0 else "negative"
        amount_sign[sign] += 1
        key_hits["total"] += 1
        key_hits["dictionary_16_15_hit"] += int(f"0x{key:08x}" in dictionary_by_hash)
        by_source[(replay, source)].append({
            "time_ms": row["replay_time_ms"],
            "target": target,
            "amount": amount,
            "key": key,
            "type": fields["field_28_u8"],
        })
    for events in by_source.values():
        events.sort(key=lambda event: event["time_ms"])
    return {
        "shape_counts": counter_json(counts),
        "type_field_histogram": counter_json(type_counts),
        "amount_sign_counts": counter_json(amount_sign),
        "damage_key_dictionary_16_15_side_evidence": counter_json(key_hits),
        "decision": {
            "source_target_amount": "PROMOTE_STRUCTURAL_FIELDS_WITH_PARTICIPANT_AND_ROUTING_ANCHORS",
            "field_30": "PROMOTE_AS_NUMERIC_DAMAGE_KEY_ONLY",
            "field_28": "KEEP_NUMERIC_TYPE_UNTIL_INDEPENDENT_TYPE_ANCHOR",
            "source_kind_or_ability": "KEEP_CANDIDATE",
        },
    }, by_source


def correlate_cast_damage(
    casts: list[dict[str, Any]],
    damages: dict[tuple[str, int], list[dict[str, Any]]],
    witnesses: list[dict[str, Any]],
) -> dict[str, Any]:
    counts = collections.Counter()
    match_multiplicity = collections.Counter()
    exact_witness_count = 0
    no_damage_witness_count = 0
    for cast in casts:
        events = damages.get((cast["replay"], cast["caster"]), [])
        owner_events = damages.get((cast["replay"], cast["chain_owner"]), [])
        times = [event["time_ms"] for event in events]
        owner_times = [event["time_ms"] for event in owner_events]
        position = bisect.bisect_left(times, cast["time_ms"])
        owner_position = bisect.bisect_left(owner_times, cast["time_ms"])
        for window in WINDOWS_MS:
            end = bisect.bisect_right(times, cast["time_ms"] + window)
            candidates = events[position:end]
            owner_end = bisect.bisect_right(owner_times, cast["time_ms"] + window)
            owner_candidates = owner_events[owner_position:owner_end]
            counts[f"cast_total_{window}ms"] += 1
            counts[f"cast_any_same_source_damage_{window}ms"] += int(bool(candidates))
            exact = [event for event in candidates if event["key"] == cast["key"]]
            owner_exact = [
                event for event in owner_candidates if event["key"] == cast["key"]
            ]
            counts[f"cast_any_exact_key_damage_{window}ms"] += int(bool(exact))
            counts[f"cast_any_chain_owner_damage_{window}ms"] += int(bool(owner_candidates))
            counts[f"cast_any_exact_key_chain_owner_damage_{window}ms"] += int(bool(owner_exact))
            counts[f"cast_any_exact_key_caster_or_chain_owner_damage_{window}ms"] += int(
                bool(exact or owner_exact)
            )
            match_multiplicity[(window, len(candidates), len(exact))] += 1
        end_2000 = bisect.bisect_right(times, cast["time_ms"] + 2000)
        candidates_2000 = events[position:end_2000]
        owner_end_2000 = bisect.bisect_right(owner_times, cast["time_ms"] + 2000)
        owner_candidates_2000 = owner_events[owner_position:owner_end_2000]
        exact_2000 = [event for event in candidates_2000 if event["key"] == cast["key"]]
        owner_exact_2000 = [
            event for event in owner_candidates_2000 if event["key"] == cast["key"]
        ]
        if (exact_2000 or owner_exact_2000) and exact_witness_count < 12:
            event = (exact_2000 or owner_exact_2000)[0]
            witnesses.append({
                "kind": "CAST_DAMAGE_EXACT_NUMERIC_KEY_NEIGHBOR",
                "replay": cast["replay"],
                "caster": cast["caster"],
                "chain_owner": cast["chain_owner"],
                "matched_source_role": (
                    "caster" if exact_2000 else "chain_owner"
                ),
                "cast_time_ms": cast["time_ms"],
                "damage_time_ms": event["time_ms"],
                "delta_ms": event["time_ms"] - cast["time_ms"],
                "key": cast["key"],
                "damage_target": event["target"],
                "semantic_boundary": "Exact key and source/time neighborhood; causality still not asserted.",
            })
            exact_witness_count += 1
        elif not candidates_2000 and not owner_candidates_2000 and no_damage_witness_count < 12:
            witnesses.append({
                "kind": "CAST_WITHOUT_SAME_SOURCE_DAMAGE_2S_COUNTEREXAMPLE",
                "replay": cast["replay"],
                "caster": cast["caster"],
                "cast_time_ms": cast["time_ms"],
                "key": cast["key"],
            })
            no_damage_witness_count += 1

    damage_counts = collections.Counter()
    casts_by_source: dict[tuple[str, int], list[dict[str, Any]]] = collections.defaultdict(list)
    casts_by_chain_owner: dict[tuple[str, int], list[dict[str, Any]]] = collections.defaultdict(list)
    for cast in casts:
        casts_by_source[(cast["replay"], cast["caster"])].append(cast)
        casts_by_chain_owner[(cast["replay"], cast["chain_owner"])].append(cast)
    for key, events in damages.items():
        source_casts = casts_by_source.get(key, [])
        owner_casts = casts_by_chain_owner.get(key, [])
        source_casts.sort(key=lambda item: item["time_ms"])
        owner_casts.sort(key=lambda item: item["time_ms"])
        times = [item["time_ms"] for item in source_casts]
        owner_times = [item["time_ms"] for item in owner_casts]
        for event in events:
            for window in WINDOWS_MS:
                left = bisect.bisect_left(times, event["time_ms"] - window)
                right = bisect.bisect_right(times, event["time_ms"])
                candidates = source_casts[left:right]
                owner_left = bisect.bisect_left(owner_times, event["time_ms"] - window)
                owner_right = bisect.bisect_right(owner_times, event["time_ms"])
                owner_candidates = owner_casts[owner_left:owner_right]
                damage_counts[f"damage_total_{window}ms"] += 1
                damage_counts[f"damage_prior_same_source_cast_{window}ms"] += int(bool(candidates))
                damage_counts[f"damage_prior_exact_key_cast_{window}ms"] += int(any(
                    item["key"] == event["key"] for item in candidates
                ))
                damage_counts[f"damage_prior_chain_owner_cast_{window}ms"] += int(
                    bool(owner_candidates)
                )
                damage_counts[f"damage_prior_exact_key_chain_owner_cast_{window}ms"] += int(any(
                    item["key"] == event["key"] for item in owner_candidates
                ))
                damage_counts[
                    f"damage_prior_exact_key_caster_or_chain_owner_cast_{window}ms"
                ] += int(any(
                    item["key"] == event["key"]
                    for item in candidates + owner_candidates
                ))
    return {
        "cast_forward_counts": counter_json(counts),
        "damage_backward_counts": counter_json(damage_counts),
        "candidate_multiplicity_top": [
            {
                "window_ms": key[0],
                "same_source_candidate_count": key[1],
                "exact_key_candidate_count": key[2],
                "cast_count": value,
            }
            for key, value in match_multiplicity.most_common(40)
        ],
        "decision": {
            "exact_key_and_source_neighborhood": "KEEP_ATTRIBUTION_CANDIDATE",
            "near_time_only": "REJECT_AS_CAUSAL_PROOF",
            "unmatched_casts_and_damage": "RETAIN_AS_COUNTEREXAMPLES",
        },
    }


def analyze_on_event(
    path: pathlib.Path,
    player_by_replay_id: dict,
    team_by_replay_id: dict,
) -> dict[str, Any]:
    counts = collections.Counter()
    amounts_by_replay_source = collections.defaultdict(float)
    amounts_by_replay_source_event = collections.defaultdict(float)
    blob_multisets: dict[tuple, collections.Counter] = collections.defaultdict(collections.Counter)
    amount_values: dict[int, list[float]] = collections.defaultdict(list)
    for row in jsonl(path):
        event_id = row["event_id"]
        replay = row["replay_label"]
        source = row.get("source_network_id_candidate")
        target = row.get("target_network_id_candidate")
        amount = row.get("amount_candidate")
        counts[f"event_0x{event_id:04x}"] += 1
        counts[f"event_0x{event_id:04x}:schema_match"] += int(
            row["schema_id_matches_cross_build_hypothesis"]
        )
        counts[f"event_0x{event_id:04x}:size_match"] += int(
            row["parameter_size_matches_cross_build_hypothesis"]
        )
        if source is not None:
            counts[f"event_0x{event_id:04x}:source_participant"] += int(
                (replay, source) in player_by_replay_id
            )
        if target is not None:
            counts[f"event_0x{event_id:04x}:target_participant"] += int(
                (replay, target) in player_by_replay_id
            )
        source_team = team_by_replay_id.get((replay, source))
        target_team = team_by_replay_id.get((replay, target))
        if source_team is not None and target_team is not None:
            counts[f"event_0x{event_id:04x}:same_team"] += int(source_team == target_team)
            counts[f"event_0x{event_id:04x}:opposing_team"] += int(source_team != target_team)
        counts[f"event_0x{event_id:04x}:self_target"] += int(source == target)
        if amount is not None:
            amounts_by_replay_source[(replay, source)] += amount
            amounts_by_replay_source_event[(replay, source, event_id)] += amount
            amount_values[event_id].append(amount)
        if event_id in (0x00ED, 0x00EE):
            key = (replay, row["replay_time_ms"], row["parameter_blob_sha256"])
            blob_multisets[key][event_id] += 1

    exact_pair_count = sum(
        min(counter[0x00ED], counter[0x00EE]) for counter in blob_multisets.values()
    )
    unpaired_receive = sum(
        max(0, counter[0x00ED] - counter[0x00EE]) for counter in blob_multisets.values()
    )
    unpaired_grant = sum(
        max(0, counter[0x00EE] - counter[0x00ED]) for counter in blob_multisets.values()
    )
    aggregate_rows = []
    anchor_counts = collections.Counter()
    anchor_ratios: dict[int, list[float]] = collections.defaultdict(list)
    for (replay, source, event_id), raw_sum in sorted(amounts_by_replay_source_event.items()):
        player = player_by_replay_id.get((replay, source))
        if player is None:
            aggregate_rows.append({
                "replay": replay,
                "source": source,
                "event_id_hex": f"0x{event_id:04x}",
                "raw_event_amount_sum": raw_sum,
                "participant": False,
            })
            continue
        stats = player["aggregate_stats"]
        anchor_name = (
            "total_heal" if event_id == 0x004B
            else "total_damage_shielded_on_teammates"
        )
        anchor = stats[anchor_name]
        anchor_counts[f"0x{event_id:04x}:participant_sources"] += 1
        anchor_counts[f"0x{event_id:04x}:positive_raw_zero_anchor"] += int(
            raw_sum > 0 and anchor == 0
        )
        if anchor:
            ratio = raw_sum / anchor
            anchor_ratios[event_id].append(ratio)
            relative_error = abs(raw_sum - anchor) / anchor
            anchor_counts[f"0x{event_id:04x}:within_5pct_anchor"] += int(relative_error <= 0.05)
            anchor_counts[f"0x{event_id:04x}:within_10pct_anchor"] += int(relative_error <= 0.10)
            anchor_counts[f"0x{event_id:04x}:within_25pct_anchor"] += int(relative_error <= 0.25)
        aggregate_rows.append({
            "replay": replay,
            "source": source,
            "champion": player["champion"],
            "event_id_hex": f"0x{event_id:04x}",
            "raw_event_amount_sum": raw_sum,
            "summary_anchor_name": anchor_name,
            "summary_anchor": anchor,
            "raw_minus_anchor": raw_sum - anchor,
            "raw_to_anchor_ratio": raw_sum / anchor if anchor else None,
            "participant": True,
        })
    return {
        "shape_and_team_counts": counter_json(counts),
        "amount_distributions": {
            f"0x{event_id:04x}": percentile_summary(values)
            for event_id, values in sorted(amount_values.items())
        },
        "shield_grant_receive_exact_blob_multiset": {
            "exact_pair_count": exact_pair_count,
            "unpaired_receive_count": unpaired_receive,
            "unpaired_grant_count": unpaired_grant,
            "canonicalization_recommendation": "retain receive 0x00ed; drop exact duplicate grant 0x00ee",
        },
        "summary_anchor_comparison": {
            "counts": counter_json(anchor_counts),
            "raw_to_anchor_ratio_distributions": {
                f"0x{event_id:04x}": percentile_summary(values)
                for event_id, values in sorted(anchor_ratios.items())
            },
            "boundary": (
                "Heal closeness supports a reported/gross heal route. Shield divergence and "
                "positive raw sums with zero absorbed-on-teammates anchors reject an absorbed "
                "or remaining-shield interpretation."
            ),
        },
        "per_source_raw_amount_vs_summary_anchor": aggregate_rows,
        "decision": {
            "event_id_schema_size_operation": "PROMOTE_EXACT_BUILD_EVENT_OPERATION",
            "source_target_amount_layout": "PROMOTE_WITH_RUNTIME_SCHEMA_AND_PARTICIPANT_ANCHORS",
            "heal_amount_stage": "REPORTED_OR_GROSS_AMOUNT;REJECT_EFFECTIVE_HEAL_CLAIM",
            "shield_amount_stage": "APPLICATION_OR_GENERATED_AMOUNT;REJECT_REMAINING_OR_ABSORBED_CLAIM",
            "damage_shielded": "EVIDENCE_EXHAUSTED_NO_0x00ef_AND_NO_0x01e1_ROWS_IN_CORPUS",
        },
    }


def analyze_neighbors(path: pathlib.Path, casts: list[dict[str, Any]]) -> dict[str, Any]:
    packet_counts = collections.Counter()
    payload_counts = collections.Counter()
    replay_events: dict[str, list[tuple[int, int, int, int, str]]] = collections.defaultdict(list)
    pair_0199 = collections.Counter()
    previous_0199: dict[str, tuple[int, int, int, str]] = {}
    for row in jsonl(path):
        packet_id = row["packet_id"]
        replay = row["replay_label"]
        time_ms = row["replay_time_ms"]
        raw_param = row["raw_param"]
        length = row["payload_length"]
        payload_hash = row["raw_payload_sha256"]
        packet_counts[packet_id] += 1
        payload_counts[(packet_id, length)] += 1
        if packet_id in (0x008A, 0x0135, 0x02E0, 0x02E1, 0x0465):
            replay_events[replay].append((time_ms, packet_id, raw_param, length, payload_hash))
        if packet_id == 0x0199:
            prior = previous_0199.get(replay)
            if prior is not None:
                prior_time, prior_length, prior_param, _prior_hash = prior
                pair_0199["adjacent_0199_pairs"] += 1
                pair_0199["alternating_2_3_length"] += int(
                    (prior_length, length) in ((2, 3), (3, 2))
                )
                pair_0199["same_time"] += int(prior_time == time_ms)
                pair_0199["same_raw_param"] += int(prior_param == raw_param)
            previous_0199[replay] = (time_ms, length, raw_param, payload_hash)

    lifecycle = collections.Counter()
    cast_missile = collections.Counter()
    by_replay_times: dict[str, list[int]] = {}
    for replay, events in replay_events.items():
        events.sort()
        by_replay_times[replay] = [event[0] for event in events]
        last_by_param: dict[int, tuple[int, int]] = {}
        for time_ms, packet_id, raw_param, _length, _hash in events:
            prior = last_by_param.get(raw_param)
            if prior is not None:
                prior_time, prior_packet = prior
                lifecycle[f"0x{prior_packet:04x}->0x{packet_id:04x}:same_param"] += 1
                lifecycle[f"0x{prior_packet:04x}->0x{packet_id:04x}:same_param_same_time"] += int(
                    prior_time == time_ms
                )
            last_by_param[raw_param] = (time_ms, packet_id)
    for cast in casts:
        events = replay_events.get(cast["replay"], [])
        times = by_replay_times.get(cast["replay"], [])
        left = bisect.bisect_left(times, cast["time_ms"])
        for window in WINDOWS_MS:
            right = bisect.bisect_right(times, cast["time_ms"] + window)
            candidates = events[left:right]
            cast_missile[f"cast_total_{window}ms"] += 1
            cast_missile[f"cast_any_missile_route_{window}ms"] += int(bool(candidates))
            cast_missile[f"cast_ambiguous_multiple_missile_routes_{window}ms"] += int(
                len(candidates) > 1
            )
    return {
        "route_counts": counter_json(packet_counts, lambda key: f"0x{key:04x}"),
        "payload_size_counts": counter_json(
            payload_counts, lambda key: f"0x{key[0]:04x}:{key[1]}"
        ),
        "packet_0199_negative_control": counter_json(pair_0199),
        "missile_same_param_lifecycle_transitions": counter_json(lifecycle),
        "cast_to_missile_route_neighborhood": counter_json(cast_missile),
        "decision": {
            "missile_routes": "PROMOTE_RUNTIME_LIFECYCLE_ROUTE_NAMES_ONLY",
            "cast_missile_attribution": "KEEP_CANDIDATE_NEAR_TIME_IS_NOT_CAUSALITY",
            "packet_0199": "REJECT_GAMEPLAY_SPELL_SEMANTIC;PAIRED_LOW_ENTROPY_NEGATIVE_CONTROL",
            "shield_damage_0x01e1": "BOUNDED_ABSENCE_ZERO_ROWS_NOT_PROTOCOL_NONEXISTENCE",
        },
    }


def main() -> None:
    options = parse_args()
    paths = {
        "buff_spell": reject_holdout(options.buff_spell, "--buff-spell"),
        "on_event": reject_holdout(options.on_event, "--on-event"),
        "damage": reject_holdout(options.damage, "--damage"),
        "neighbors": reject_holdout(options.neighbors, "--neighbors"),
        "manifest": reject_holdout(options.manifest, "--manifest"),
        "spell_dictionary": reject_holdout(options.spell_dictionary, "--spell-dictionary"),
        "output": reject_holdout(options.output, "--output"),
        "witnesses": reject_holdout(
            options.witnesses or f"{options.output}.witnesses.jsonl", "--witnesses"
        ),
    }
    manifest, player_by_replay_id, team_by_replay_id = load_metadata(paths["manifest"])
    dictionary = json.loads(paths["spell_dictionary"].read_text(encoding="utf-8-sig"))
    dictionary_by_hash = dictionary["by_hash"]
    witnesses: list[dict[str, Any]] = []

    buff_cast, casts = analyze_buff_and_cast(
        paths["buff_spell"], player_by_replay_id, dictionary_by_hash, witnesses
    )
    damage, damages = analyze_damage(
        paths["damage"], player_by_replay_id, dictionary_by_hash
    )
    cast_damage = correlate_cast_damage(casts, damages, witnesses)
    on_event = analyze_on_event(paths["on_event"], player_by_replay_id, team_by_replay_id)
    neighbors = analyze_neighbors(paths["neighbors"], casts)

    paths["witnesses"].parent.mkdir(parents=True, exist_ok=True)
    with paths["witnesses"].open("w", encoding="utf-8", newline="\n") as stream:
        for witness in witnesses:
            stream.write(json.dumps(witness, ensure_ascii=True, separators=(",", ":")) + "\n")
    summary = {
        "schema_version": 1,
        "analysis": "rofl-full-semantic-deep-recovery-v2-buff-spell-damage-v1",
        "build": BUILD,
        "status": "PASS",
        "inputs": {
            key: {"path": str(path), "sha256": sha256_file(path)}
            for key, path in paths.items()
            if key not in ("output", "witnesses")
        },
        "metadata_replays": len(manifest["replays"]),
        **buff_cast,
        "damage": damage,
        "cast_damage_attribution": cast_damage,
        "heal_shield_on_event": on_event,
        "missile_and_negative_controls": neighbors,
        "saturation": {
            "promotion": [
                "exact runtime route operations for buff add/update/replace/remove, cast answer, OnEvent heal/shield, and missile lifecycle",
                "exact cast translator caster/key/time fields with participant and replay-time anchors",
                "OnEvent source/target/amount structural layouts for 0x004b/0x00ed/0x00ee",
                "damage source/target/amount and numeric damage key fields",
            ],
            "reject": [
                "RTTI/runtime string alone as semantic proof",
                "near-time correlation alone as cast-to-damage or cast-to-missile causality",
                "heal amount as effective post-overheal amount",
                "shield amount as remaining or absorbed amount",
                "0x0199 as gameplay spell route",
            ],
            "exhausted_or_bounded_absence": [
                "OnDamageShielded 0x00ef layout absent in latest-four OnEvent rows",
                "UnitApplyShieldDamage 0x01e1 absent in latest-four selected rows",
                "damage source-kind and public ability identity remain unresolved without independent exact-build anchors",
            ],
        },
        "witnesses": {
            "path": str(paths["witnesses"]),
            "sha256": sha256_file(paths["witnesses"]),
            "count": len(witnesses),
        },
        "holdout_boundary": {
            "path_guard": "reject every explicit input/output path containing case-insensitive 'holdout'",
            "read": False, "enumerate": False, "hash": False,
            "decode": False, "test": False, "consume": False,
        },
    }
    paths["output"].parent.mkdir(parents=True, exist_ok=True)
    paths["output"].write_text(
        json.dumps(summary, indent=2, ensure_ascii=True) + "\n", encoding="ascii"
    )
    print(json.dumps({
        "output": str(paths["output"]),
        "output_sha256": sha256_file(paths["output"]),
        "witnesses": str(paths["witnesses"]),
        "witness_count": len(witnesses),
        "status": summary["status"],
    }, indent=2))


if __name__ == "__main__":
    main()
