#!/usr/bin/env python3
"""Validate exact-build runtime packet profiles against exported Replay blocks.

This validator is deliberately build-pinned.  It executes the 16.16 client
constructor and deserializer from the captured module image and never falls
back to a neighbouring build profile.
"""

from __future__ import annotations

import argparse
import bisect
import collections
import hashlib
import json
import math
import pathlib
import struct
import sys
import time

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import emulate_exact_packet_decoder as exact  # noqa: E402
import migrate_path_packet_16_15 as legacy_path  # noqa: E402


REPLAY_VERSION = '16.16.805.0442'
RUNTIME_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55'
BASE_PACKET_VTABLE_RVA = 0x01A23AB0
BASE_PACKET_SERIALIZE_RVA = 0x0124C2E0
BASE_PACKET_DECODE_RVA = 0x0122E820
RUNTIME_ALLOC_RVA = 0x011928C0
MEMSET_AVX_LEAF_RVA = 0x019D9662

LEVEL_PROFILE = {
    'id': 'rofl-16.16.805.0442-level-transition-unicorn-v1',
    'client_opcode': 0x0314,
    'constructor_rva': 0x00E7DE60,
    'object_vtable_rva': 0x01B10668,
    'vtable_rva': 0x01B10678,
    'deserialize_rva': 0x00EF8520,
    'object_size': 0x14,
    'fields': [
        {'name': 'raw_field_10', 'offset': 0x10, 'type': 'u8'},
        {'name': 'raw_field_11', 'offset': 0x11, 'type': 'u8'},
    ],
}

PATH_PROFILE = {
    'id': 'rofl-16.16.805.0442-path-packet-unicorn-v1',
    'client_opcode': 0x00F6,
    'constructor_rva': 0x00EAD060,
    'object_vtable_rva': 0x01B13988,
    'vtable_rva': 0x01B13998,
    'deserialize_rva': 0x0102A170,
    'object_size': 0x2C,
    'payload_pointer_offset': 0x18,
    'payload_size_offset': 0x20,
    'fields': [],
}

WARD_PROFILE = {
    'id': 'rofl-16.16.805.0442-ward-spawn-unicorn-v1',
    'client_opcode': 0x049A,
    'constructor_rva': 0x00EABB20,
    'factory_rva': 0x00ED97B0,
    'factory_case_rva': 0x00EE9116,
    'factory_constructor_callsite_rva': 0x00EE9128,
    'vtable_rva': 0x01B14570,
    'deserialize_rva': 0x01025D50,
    'rejected_deserialize_candidate_rva': 0x00FC7770,
    'object_size': 0x90,
    'codec_singleton_pointer_rva': 0x01EE9D08,
    'codec_singleton_enable_offset': 0x70,
}


class Build1616Emulator(exact.ExactPacketEmulator):
    """ExactPacketEmulator with the two migrated 16.16 runtime leaf hooks."""

    def __init__(self, image: bytes):
        # ExactPacketEmulator now owns build-specific allocator, base-header and
        # memset selection through an explicit runtime profile.  Passing the
        # profile is essential: mutating the historical module constants no
        # longer changes the base class' selected serializer/decoder.
        super().__init__(image, exact.RUNTIME_PROFILES[REPLAY_VERSION])

    def _memset_avx_leaf(self, _emulator, _address, _size, _user_data):
        destination = self.emulator.reg_read(exact.UC_X86_REG_RCX)
        value = self.emulator.reg_read(exact.UC_X86_REG_RDX) & 0xFF
        length = self.emulator.reg_read(exact.UC_X86_REG_R8)
        if length > exact.HEAP_SIZE:
            raise RuntimeError(f'memset length exceeds emulated heap: {length}')
        if length:
            self.emulator.mem_write(destination, bytes([value]) * length)
        self.emulator.reg_write(exact.UC_X86_REG_RAX, destination)
        self._return_from_stub()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def load_packet_manifest(packet_path: pathlib.Path, expected_packet_id: int) -> dict:
    manifest_path = pathlib.Path(f'{packet_path}.manifest.json')
    if not manifest_path.is_file():
        raise RuntimeError(f'missing packet export manifest: {manifest_path}')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    if manifest.get('schema_version') != 1:
        raise RuntimeError(f"unsupported packet manifest schema: {manifest.get('schema_version')!r}")
    manifest_output = manifest.get('output')
    if not isinstance(manifest_output, str) or pathlib.Path(manifest_output).resolve() != packet_path:
        raise RuntimeError('packet manifest output path does not name the validated packet file')
    if manifest.get('target_replay_version') != REPLAY_VERSION:
        raise RuntimeError(
            'packet manifest replay version mismatch: '
            f"{manifest.get('target_replay_version')!r}"
        )
    if manifest.get('packet_ids') != [expected_packet_id]:
        raise RuntimeError(
            f"packet manifest IDs must be exactly [{expected_packet_id}], "
            f"got {manifest.get('packet_ids')!r}"
        )
    if not isinstance(manifest.get('selected_packet_count'), int):
        raise RuntimeError('packet manifest selected_packet_count must be an integer')
    replay_shas = {}
    replay_packet_counts = {}
    for replay in manifest.get('replays', []):
        label = pathlib.Path(replay.get('path', '')).stem
        replay_sha = replay.get('sha256')
        if (not label or replay.get('version') != REPLAY_VERSION
                or not _is_sha256(replay_sha)
                or int(replay.get('parser_error_count', -1)) != 0):
            raise RuntimeError(f'invalid Replay provenance in packet manifest: {replay!r}')
        if label in replay_shas and replay_shas[label] != replay_sha:
            raise RuntimeError(f'conflicting Replay SHA-256 values for label {label}')
        replay_packet_count = replay.get('selected_packet_count')
        if not isinstance(replay_packet_count, int) or replay_packet_count < 0:
            raise RuntimeError(f'invalid selected packet count for Replay {label}')
        replay_shas[label] = replay_sha
        replay_packet_counts[label] = replay_packet_count
    if not replay_shas:
        raise RuntimeError('packet manifest must name at least one strictly parsed Replay')
    if manifest.get('replay_count') != len(replay_shas):
        raise RuntimeError('packet manifest replay_count disagrees with Replay provenance rows')
    if sum(replay_packet_counts.values()) != manifest['selected_packet_count']:
        raise RuntimeError('per-Replay packet counts do not sum to selected_packet_count')
    packet_counts = manifest.get('packet_counts', {})
    if packet_counts.get(str(expected_packet_id)) != manifest['selected_packet_count']:
        raise RuntimeError('manifest route count disagrees with selected_packet_count')
    return {
        'path': str(manifest_path),
        'selected_packet_count': manifest['selected_packet_count'],
        'replay_count': len(replay_shas),
        'replay_shas': replay_shas,
        'replay_packet_counts': replay_packet_counts,
    }


def validate_packet_row(
        row: dict, expected_packet_id: int, manifest: dict, line_number: int) -> bytes:
    if row.get('replay_version') != REPLAY_VERSION:
        raise ValueError(f'line {line_number}: wrong replay_version')
    if row.get('packet_id') != expected_packet_id:
        raise ValueError(f'line {line_number}: wrong packet_id')
    label = row.get('replay_label')
    if label not in manifest['replay_shas']:
        raise ValueError(f'line {line_number}: Replay label is absent from manifest')
    if row.get('replay_sha256') != manifest['replay_shas'][label]:
        raise ValueError(f'line {line_number}: Replay SHA-256 disagrees with manifest')
    raw_hex = row.get('raw_payload_hex')
    if not isinstance(raw_hex, str):
        raise ValueError(f'line {line_number}: raw_payload_hex must be a string')
    try:
        payload = bytes.fromhex(raw_hex)
    except ValueError as error:
        raise ValueError(f'line {line_number}: invalid raw_payload_hex') from error
    if row.get('payload_length') != len(payload):
        raise ValueError(f'line {line_number}: payload_length mismatch')
    payload_sha = hashlib.sha256(payload).hexdigest()
    if row.get('raw_payload_sha256') != payload_sha:
        raise ValueError(f'line {line_number}: raw payload SHA-256 mismatch')
    for field in (
            'replay_time_ms', 'raw_param', 'chunk_index',
            'decompressed_block_offset', 'occurrence_index'):
        if not isinstance(row.get(field), int) or row[field] < 0:
            raise ValueError(f'line {line_number}: {field} must be a non-negative integer')
    if row.get('chunk_stream') not in (1, 'game_chunk'):
        raise ValueError(f'line {line_number}: expected game stream 1/game_chunk')
    return payload


def path_structural_gate(counters, failures: list[dict], manifest_count_verified: bool) -> bool:
    return bool(
        not failures
        and manifest_count_verified
        and counters['packet_count'] > 0
        and counters['hero_record_count'] > 0
        and counters['packet_count'] == counters['deserialize_success_count']
        and counters['packet_count'] == counters['fully_consumed_count']
        and counters['packet_count'] == counters['plaintext_fully_consumed_count']
    )


def level_structural_gate(
        selected_count: int, decoded: list[dict], full_rows: list[dict],
        input_failures: list[dict], infrastructure_failures: list[dict],
        manifest_count_verified: bool) -> bool:
    return bool(
        selected_count > 0
        and len(decoded) == selected_count
        and len(full_rows) == len(decoded)
        and not input_failures
        and not infrastructure_failures
        and manifest_count_verified
    )


def participant_from_raw_param(raw_param: int) -> int | None:
    if 0x400000AE <= raw_param <= 0x400000B7:
        return raw_param - 0x400000AD
    return None


def read_level_anchors(details_root: pathlib.Path, labels: set[str]) -> dict[str, list[dict]]:
    anchors: dict[str, list[dict]] = {}
    for label in sorted(labels):
        matches = sorted(details_root.glob(f'{label}-*.json'))
        if len(matches) != 1:
            raise RuntimeError(
                f'expected exactly one DETAILS file for {label}, found {len(matches)}'
            )
        document = json.loads(matches[0].read_text(encoding='utf-8'))
        details = document.get('json', document)
        rows = []
        for frame in details.get('frames', []):
            for event in frame.get('events', []):
                if event.get('type') != 'LEVEL_UP':
                    continue
                rows.append({
                    'anchor_index': len(rows),
                    'replay_label': label,
                    'timestamp_ms': int(event['timestamp']),
                    'participant_id': int(event['participantId']),
                    'level_after': int(event['level']),
                })
        anchors[label] = rows
    return anchors


def nearest_unused_anchor(
        row: dict, anchors: dict[str, list[dict]], used: set[tuple[str, int]],
        window_ms: int = 2) -> dict | None:
    candidates = [
        anchor for anchor in anchors.get(row['replay_label'], [])
        if anchor['participant_id'] == row['participant_id']
        and (row['replay_label'], anchor['anchor_index']) not in used
        and abs(anchor['timestamp_ms'] - row['replay_time_ms']) <= window_ms
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda item: (
        abs(item['timestamp_ms'] - row['replay_time_ms']),
        item['timestamp_ms'], item['anchor_index']))


def write_json(path: pathlib.Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def percentile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * probability)))
    return ordered[index]


def error_summary(values: list[float]) -> dict:
    return {
        'count': len(values),
        'p50': percentile(values, 0.50),
        'p95': percentile(values, 0.95),
        'max': max(values) if values else None,
    }


def interpolate_waypoints(event: dict, timestamp_ms: int, key: str) -> list[float]:
    waypoints = event[key]
    if len(waypoints) == 1 or event['speed'] <= 0:
        return waypoints[0]
    remaining = max(0.0, (timestamp_ms - event['replay_time_ms']) / 1000.0)
    for first, second in zip(waypoints, waypoints[1:]):
        distance = math.hypot(second[0] - first[0], second[1] - first[1])
        duration = distance / event['speed'] if event['speed'] else 0.0
        if remaining <= duration:
            ratio = remaining / duration if duration else 0.0
            return [
                first[0] + (second[0] - first[0]) * ratio,
                first[1] + (second[1] - first[1]) * ratio,
            ]
        remaining -= duration
    return waypoints[-1]


def read_position_anchors(details_root: pathlib.Path, labels: set[str], max_time_ms: int) -> list[dict]:
    anchors = []
    for label in sorted(labels):
        matches = sorted(details_root.glob(f'{label}-*.json'))
        if len(matches) != 1:
            raise RuntimeError(
                f'expected exactly one DETAILS file for {label}, found {len(matches)}'
            )
        document = json.loads(matches[0].read_text(encoding='utf-8'))
        details = document.get('json', document)
        for frame in details.get('frames', []):
            timestamp_ms = int(frame['timestamp'])
            if timestamp_ms > max_time_ms:
                continue
            for participant_key, participant in frame.get('participantFrames', {}).items():
                position = participant.get('position')
                if not position:
                    continue
                participant_id = int(participant_key)
                anchors.append({
                    'replay_label': label,
                    'timestamp_ms': timestamp_ms,
                    'participant_id': participant_id,
                    'entity_network_id': 0x400000AD + participant_id,
                    'actual_x': float(position['x']),
                    'actual_z': float(position['y']),
                })
    return anchors


def validate_path(args) -> dict:
    runtime_path = pathlib.Path(args.runtime_image).resolve()
    packet_path = pathlib.Path(args.packets).resolve()
    output_dir = pathlib.Path(args.output).resolve()
    runtime_sha = sha256_file(runtime_path)
    if runtime_sha != RUNTIME_SHA256:
        raise RuntimeError(f'wrong runtime image sha256: {runtime_sha}')
    manifest = load_packet_manifest(packet_path, PATH_PROFILE['client_opcode'])

    emulator = Build1616Emulator(runtime_path.read_bytes())
    counters = collections.Counter()
    failures = []
    hero_events: dict[tuple[str, int], list[dict]] = collections.defaultdict(list)
    replay_shas = {}
    input_rows_by_replay = collections.Counter()
    source_packet_keys = set()
    started = time.perf_counter()
    with packet_path.open('r', encoding='utf-8') as handle:
        for line_number, line in enumerate(handle, 1):
            if args.limit is not None and counters['packet_count'] >= args.limit:
                break
            if not line.strip():
                continue
            counters['input_row_count'] += 1
            try:
                raw = json.loads(line)
                payload = validate_packet_row(
                    raw, PATH_PROFILE['client_opcode'], manifest, line_number,
                )
                source_key = (
                    raw['replay_label'], raw['chunk_index'],
                    raw['decompressed_block_offset'], raw['packet_id'],
                )
                if source_key in source_packet_keys:
                    raise ValueError(f'line {line_number}: duplicate source packet reference')
                source_packet_keys.add(source_key)
                input_rows_by_replay[raw['replay_label']] += 1
                counters['valid_input_row_count'] += 1
            except Exception as error:
                failures.append({
                    'line_number': line_number,
                    'failure_kind': 'INPUT_PROVENANCE',
                    'error': str(error),
                })
                continue
            counters['packet_count'] += 1
            replay_shas[raw['replay_label']] = raw['replay_sha256']
            try:
                decoded = emulator.decode(
                    payload,
                    PATH_PROFILE,
                    packet_id=PATH_PROFILE['client_opcode'],
                    raw_param=int(raw['raw_param']),
                )
                if decoded['deserialize_return_al'] != 1 or not decoded['fully_consumed']:
                    raise RuntimeError(
                        f"decoder result AL={decoded['deserialize_return_al']} "
                        f"fully_consumed={decoded['fully_consumed']}"
                    )
                object_bytes = bytes.fromhex(decoded['object_hex'])
                pointer = struct.unpack_from('<Q', object_bytes, 0x18)[0]
                size = struct.unpack_from('<I', object_bytes, 0x20)[0]
                if not (size > 0 and exact.HEAP_BASE <= pointer
                        and pointer + size <= exact.HEAP_BASE + exact.HEAP_SIZE):
                    raise RuntimeError(f'invalid decoded path payload pointer=0x{pointer:x} size={size}')
                plaintext = bytes(emulator.emulator.mem_read(pointer, size))
                parsed = legacy_path.historical_compatible_parse(plaintext)
                if not parsed['parser_fully_consumed']:
                    raise RuntimeError('path plaintext grammar did not fully consume')
                counters['deserialize_success_count'] += 1
                counters['fully_consumed_count'] += 1
                counters['plaintext_fully_consumed_count'] += 1
                counters['record_count'] += parsed['record_count']
                for record_index, record in enumerate(parsed['records']):
                    entity_id = int(record['entity_id'])
                    if not 0x400000AE <= entity_id <= 0x400000B7:
                        continue
                    direct = [legacy_path.candidate_position(item)
                              for item in record['encoded_waypoints']]
                    swapped = [[
                        legacy_path.signed_u16(item[1]) * 2 + 7358,
                        legacy_path.signed_u16(item[0]) * 2 + 7412,
                    ] for item in record['encoded_waypoints']]
                    event = {
                        'schema_version': 1,
                        'event_type': 'hero_path',
                        'game_version': REPLAY_VERSION,
                        'patch': '16.16',
                        'build_profile': PATH_PROFILE['id'],
                        'replay_label': raw['replay_label'],
                        'replay_sha256': raw['replay_sha256'],
                        'replay_time_ms': raw['replay_time_ms'],
                        'participant_id': entity_id - 0x400000AD,
                        'entity_network_id': entity_id,
                        'speed': record['speed'],
                        'encoded_waypoints': record['encoded_waypoints'],
                        'waypoints_xz': direct,
                        'swapped_waypoints_xz': swapped,
                        'raw_packet_ref': {
                            'replay_sha256': raw['replay_sha256'],
                            'packet_id': raw['packet_id'],
                            'chunk_index': raw['chunk_index'],
                            'decompressed_block_offset': raw['decompressed_block_offset'],
                            'payload_length': raw['payload_length'],
                            'raw_param': raw['raw_param'],
                            'raw_payload_sha256': raw['raw_payload_sha256'],
                            'record_index': record_index,
                        },
                    }
                    hero_events[(raw['replay_label'], entity_id)].append(event)
                    counters['hero_record_count'] += 1
            except Exception as error:
                failures.append({
                    'line_number': line_number,
                    'failure_kind': 'RUNTIME_DECODE',
                    'replay_label': raw.get('replay_label'),
                    'replay_time_ms': raw.get('replay_time_ms'),
                    'error': str(error),
                })

    input_order_chronological = all(
        all(current['replay_time_ms'] >= previous['replay_time_ms']
            for previous, current in zip(events, events[1:]))
        for events in hero_events.values()
    )
    for events in hero_events.values():
        events.sort(key=lambda item: (
            item['replay_time_ms'],
            item['raw_packet_ref']['chunk_index'],
            item['raw_packet_ref']['decompressed_block_offset'],
            item['raw_packet_ref']['record_index'],
        ))
    chronological_series = all(
        all(current['replay_time_ms'] >= previous['replay_time_ms']
            for previous, current in zip(events, events[1:]))
        for events in hero_events.values()
    )
    participants_by_replay: dict[str, set[int]] = collections.defaultdict(set)
    participant_event_counts: dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter
    )
    replay_waypoint_counts = collections.Counter()
    replay_map_sane_counts = collections.Counter()
    waypoint_count = 0
    map_sane_waypoint_count = 0
    for events in hero_events.values():
        for event in events:
            participants_by_replay[event['replay_label']].add(event['participant_id'])
            participant_event_counts[event['replay_label']][event['participant_id']] += 1
            for waypoint in event['waypoints_xz']:
                waypoint_count += 1
                replay_waypoint_counts[event['replay_label']] += 1
                map_sane_waypoint_count += int(
                    0 <= waypoint[0] <= 16000 and 0 <= waypoint[1] <= 16000
                )
                replay_map_sane_counts[event['replay_label']] += int(
                    0 <= waypoint[0] <= 16000 and 0 <= waypoint[1] <= 16000
                )
    labels = set(replay_shas)
    max_time_ms = args.max_anchor_time_ms
    anchors = read_position_anchors(
        pathlib.Path(args.details_root).resolve(), labels, max_time_ms,
    ) if args.details_root else []
    matches = []
    for anchor in anchors:
        events = hero_events.get((anchor['replay_label'], anchor['entity_network_id']), [])
        if not events:
            continue
        timestamps = [event['replay_time_ms'] for event in events]
        index = bisect.bisect_right(timestamps, anchor['timestamp_ms']) - 1
        if index < 0 and timestamps[0] - anchor['timestamp_ms'] <= 250:
            index = 0
        if index < 0:
            continue
        event = events[index]
        direct = interpolate_waypoints(event, anchor['timestamp_ms'], 'waypoints_xz')
        swapped = interpolate_waypoints(event, anchor['timestamp_ms'], 'swapped_waypoints_xz')
        direct_error = math.hypot(
            direct[0] - anchor['actual_x'], direct[1] - anchor['actual_z'])
        swapped_error = math.hypot(
            swapped[0] - anchor['actual_x'], swapped[1] - anchor['actual_z'])
        matches.append({
            **anchor,
            'source_path_timestamp_ms': event['replay_time_ms'],
            'source_age_ms': anchor['timestamp_ms'] - event['replay_time_ms'],
            'decoded_x': direct[0],
            'decoded_z': direct[1],
            'direct_error': direct_error,
            'swapped_error': swapped_error,
        })

    direct_errors = [row['direct_error'] for row in matches]
    swapped_errors = [row['swapped_error'] for row in matches]
    direct_summary = error_summary(direct_errors)
    swapped_summary = error_summary(swapped_errors)
    source_age_summary = error_summary([row['source_age_ms'] for row in matches])
    per_replay_errors = {
        label: error_summary([
            row['direct_error'] for row in matches if row['replay_label'] == label
        ])
        for label in sorted(labels)
    }
    per_replay_map_sanity = {
        label: (
            replay_map_sane_counts[label] / replay_waypoint_counts[label]
            if replay_waypoint_counts[label] else 0.0
        )
        for label in sorted(labels)
    }
    anchors_by_participant: dict[str, collections.Counter] = collections.defaultdict(
        collections.Counter
    )
    for anchor in anchors:
        anchors_by_participant[anchor['replay_label']][anchor['participant_id']] += 1
    replay_match_count = len({row['replay_label'] for row in matches})
    position_match_ratio = len(matches) / len(anchors) if anchors else 0.0
    source_age_verified = bool(matches) and all(
        -250 <= row['source_age_ms'] <= 61000 for row in matches
    )
    per_replay_error_verified = bool(labels) and all(
        summary['p95'] is not None and summary['p95'] <= 750
        for summary in per_replay_errors.values()
    )
    transform_verified = bool(
        len(matches) >= 100
        and replay_match_count >= 5
        and position_match_ratio >= 0.95
        and source_age_verified
        and per_replay_error_verified
        and direct_summary['p95'] is not None
        and direct_summary['p95'] <= 500
        and swapped_summary['p50'] is not None
        and direct_summary['p50'] < swapped_summary['p50'] * 0.25
    )
    ten_participant_replays = sum(
        len(participants) == 10 for participants in participants_by_replay.values()
    )
    map_sanity_ratio = (
        map_sane_waypoint_count / waypoint_count if waypoint_count else 0.0
    )
    participant_coverage_verified = bool(labels) and all(
        participants_by_replay[label] == set(range(1, 11))
        and all(participant_event_counts[label][participant_id] > 0
                for participant_id in range(1, 11))
        and all(anchors_by_participant[label][participant_id] >= 3
                for participant_id in range(1, 11))
        for label in labels
    )
    per_replay_map_sanity_verified = bool(labels) and all(
        ratio >= 0.99 for ratio in per_replay_map_sanity.values()
    )
    observed_replay_counts = {
        label: input_rows_by_replay[label]
        for label in manifest['replay_packet_counts']
    }
    manifest_count_verified = (
        counters['valid_input_row_count'] == manifest['selected_packet_count']
        and observed_replay_counts == manifest['replay_packet_counts']
        if args.limit is None
        else counters['valid_input_row_count'] == args.limit
    )
    structural_verified = path_structural_gate(
        counters, failures, manifest_count_verified,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    hero_path = output_dir / 'hero_path_events.jsonl'
    with hero_path.open('w', encoding='utf-8', newline='\n') as handle:
        for key in sorted(hero_events):
            for row in hero_events[key]:
                compact = dict(row)
                compact.pop('swapped_waypoints_xz', None)
                handle.write(json.dumps(compact, sort_keys=True) + '\n')
    match_path = output_dir / 'hero_path_position_matches.jsonl'
    with match_path.open('w', encoding='utf-8', newline='\n') as handle:
        for row in matches:
            handle.write(json.dumps(row, sort_keys=True) + '\n')
    status = 'PASS' if (
        structural_verified
        and (args.decode_only or (
            transform_verified and chronological_series and input_order_chronological
            and participant_coverage_verified and ten_participant_replays == len(labels)
            and len(labels) >= 5 and map_sanity_ratio >= 0.99
            and per_replay_map_sanity_verified
        ))
    ) else 'FAIL'
    summary = {
        'schema_version': 1,
        'status': status,
        'game_version': REPLAY_VERSION,
        'patch': '16.16',
        'build_profile': PATH_PROFILE['id'],
        'runtime_image_sha256': runtime_sha,
        'profile': PATH_PROFILE,
        'packet_manifest': {
            'path': manifest['path'],
            'declared_packet_count': manifest['selected_packet_count'],
            'declared_replay_count': manifest['replay_count'],
            'observed_replay_packet_counts': observed_replay_counts,
            'per_replay_count_validation': (
                'FULL_MATCH' if args.limit is None
                and observed_replay_counts == manifest['replay_packet_counts']
                else 'BOUNDED_NOT_APPLICABLE' if args.limit is not None else 'MISMATCH'
            ),
            'count_validation': (
                'FULL_MATCH' if args.limit is None and manifest_count_verified
                else 'BOUNDED_LIMIT_MATCH' if manifest_count_verified else 'MISMATCH'
            ),
        },
        'replay_count': len(labels),
        **dict(counters),
        'input_provenance_failure_count': sum(
            row.get('failure_kind') == 'INPUT_PROVENANCE' for row in failures
        ),
        'infrastructure_failure_count': sum(
            row.get('failure_kind') == 'RUNTIME_DECODE' for row in failures
        ),
        'details_position_anchor_count': len(anchors),
        'position_match_count': len(matches),
        'position_match_replay_count': replay_match_count,
        'participant_coverage': {
            'per_replay': {
                label: sorted(participants)
                for label, participants in sorted(participants_by_replay.items())
            },
            'event_count_per_participant': {
                label: dict(sorted(counts.items()))
                for label, counts in sorted(participant_event_counts.items())
            },
            'details_anchor_count_per_participant': {
                label: dict(sorted(counts.items()))
                for label, counts in sorted(anchors_by_participant.items())
            },
            'ten_participant_replay_count': ten_participant_replays,
            'status': 'PASS' if participant_coverage_verified else 'FAIL',
        },
        'chronological_consistency': chronological_series,
        'input_order_chronological_consistency': input_order_chronological,
        'trajectory_continuity': {
            'validation': 'DETAILS_POSITION_ANCHOR_ERROR',
            'p95_error': direct_summary['p95'],
            'per_replay_direct_error': per_replay_errors,
            'source_age_ms': source_age_summary,
            'source_age_acceptance_ms': [-250, 61000],
            'position_match_ratio': position_match_ratio,
            'status': 'PASS' if transform_verified else 'FAIL',
        },
        'current_map_sanity': {
            'bounds_xz': [0, 16000],
            'waypoint_count': waypoint_count,
            'in_bounds_waypoint_count': map_sane_waypoint_count,
            'in_bounds_ratio': map_sanity_ratio,
            'per_replay_in_bounds_ratio': per_replay_map_sanity,
            'status': 'PASS' if map_sanity_ratio >= 0.99
            and per_replay_map_sanity_verified else 'FAIL',
        },
        'coordinate_transform': {
            'x': 'signed_u16(encoded_x) * 2 + 7358',
            'z': 'signed_u16(encoded_y) * 2 + 7412',
            'direct_error': direct_summary,
            'swapped_axis_error': swapped_summary,
            'acceptance_rule': (
                '>=100 matches across >=5 replays; direct p95<=500; '
                'each replay p95<=750; direct p50 < 25% swapped p50; '
                '>=95% anchor coverage; source age -250..61000ms'
            ),
            'status': 'VERIFIED_CURRENT_CALIBRATION' if transform_verified else 'UNVERIFIED',
        },
        'elapsed_seconds': time.perf_counter() - started,
        'hero_path_events_jsonl': str(hero_path),
        'position_matches_jsonl': str(match_path),
    }
    write_json(output_dir / 'hero_path_validation_summary.json', summary)
    write_json(output_dir / 'hero_path_infrastructure_failures.json', failures)
    return summary


def validate_level(args) -> dict:
    runtime_path = pathlib.Path(args.runtime_image).resolve()
    packet_path = pathlib.Path(args.packets).resolve()
    output_dir = pathlib.Path(args.output).resolve()
    runtime_sha = sha256_file(runtime_path)
    if runtime_sha != RUNTIME_SHA256:
        raise RuntimeError(f'wrong runtime image sha256: {runtime_sha}')
    manifest = load_packet_manifest(packet_path, LEVEL_PROFILE['client_opcode'])

    image = runtime_path.read_bytes()
    emulator = Build1616Emulator(image)
    decoded = []
    input_failures = []
    infrastructure_failures = []
    input_row_count = 0
    valid_input_row_count = 0
    input_rows_by_replay = collections.Counter()
    source_packet_keys = set()
    selected_count = 0
    started = time.perf_counter()
    with packet_path.open('r', encoding='utf-8') as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            input_row_count += 1
            try:
                row = json.loads(line)
                payload = validate_packet_row(
                    row, LEVEL_PROFILE['client_opcode'], manifest, line_number,
                )
                source_key = (
                    row['replay_label'], row['chunk_index'],
                    row['decompressed_block_offset'], row['packet_id'],
                )
                if source_key in source_packet_keys:
                    raise ValueError(f'line {line_number}: duplicate source packet reference')
                source_packet_keys.add(source_key)
                input_rows_by_replay[row['replay_label']] += 1
                valid_input_row_count += 1
            except Exception as error:
                input_failures.append({
                    'line_number': line_number,
                    'failure_kind': 'INPUT_PROVENANCE',
                    'error': str(error),
                })
                continue
            participant_id = participant_from_raw_param(int(row['raw_param']))
            if participant_id is None:
                continue
            if args.limit is not None and selected_count >= args.limit:
                break
            selected_count += 1
            try:
                result = emulator.decode(
                    payload,
                    LEVEL_PROFILE,
                    packet_id=LEVEL_PROFILE['client_opcode'],
                    raw_param=int(row['raw_param']),
                )
            except Exception as error:  # evidence output must retain every infrastructure failure
                infrastructure_failures.append({
                    'line_number': line_number,
                    'replay_label': row.get('replay_label'),
                    'replay_time_ms': row.get('replay_time_ms'),
                    'error': str(error),
                })
                continue
            decoded.append({
                'schema_version': 1,
                'build_profile': LEVEL_PROFILE['id'],
                'game_version': REPLAY_VERSION,
                'patch': '16.16',
                'replay_label': row['replay_label'],
                'replay_sha256': row['replay_sha256'],
                'replay_time_ms': row['replay_time_ms'],
                'participant_id': participant_id,
                'entity_network_id': int(row['raw_param']),
                'raw_param': int(row['raw_param']),
                'payload_length': row['payload_length'],
                'raw_payload_sha256': row['raw_payload_sha256'],
                'packet_id': row['packet_id'],
                'chunk_index': row['chunk_index'],
                'decompressed_block_offset': row['decompressed_block_offset'],
                'deserialize_return_al': result['deserialize_return_al'],
                'fully_consumed': result['fully_consumed'],
                'bytes_consumed': result['bytes_consumed'],
                'wrapper_bytes_consumed': result['wrapper_bytes_consumed'],
                'decoded_opcode': result['decoded_opcode'],
                **result['decoded_fields'],
            })

    anchors = {}
    matched = []
    if args.details_root:
        labels = {row['replay_label'] for row in decoded}
        anchors = read_level_anchors(pathlib.Path(args.details_root).resolve(), labels)
        used_anchors: set[tuple[str, int]] = set()
        ordered_rows = sorted(decoded, key=lambda row: (
            row['replay_label'], row['participant_id'], row['replay_time_ms'],
            row['chunk_index'], row['decompressed_block_offset'],
        ))
        for row in ordered_rows:
            if row['deserialize_return_al'] != 1 or not row['fully_consumed']:
                continue
            anchor = nearest_unused_anchor(row, anchors, used_anchors)
            if anchor is None:
                continue
            used_anchors.add((row['replay_label'], anchor['anchor_index']))
            matched.append({
                **row,
                'anchor_index': anchor['anchor_index'],
                'anchor_timestamp_ms': anchor['timestamp_ms'],
                'anchor_delta_ms': row['replay_time_ms'] - anchor['timestamp_ms'],
                'level_after': anchor['level_after'],
            })

    mapping_evidence: dict[str, collections.Counter] = {}
    for row in matched:
        key = f"{row['raw_field_10']}:{row['raw_field_11']}"
        mapping_evidence.setdefault(key, collections.Counter())[row['level_after']] += 1
    mapping = {}
    conflicting_pairs = []
    for key, counts in sorted(mapping_evidence.items()):
        if len(counts) == 1:
            mapping[key] = next(iter(counts))
        else:
            conflicting_pairs.append({'raw_pair': key, 'levels': dict(sorted(counts.items()))})

    field_10_evidence: dict[int, collections.Counter] = {}
    for row in matched:
        field_10_evidence.setdefault(row['raw_field_10'], collections.Counter())[
            row['level_after']
        ] += 1
    field_10_mapping = {}
    field_10_counts = {}
    field_10_conflicts = []
    for raw_value, counts in sorted(field_10_evidence.items()):
        field_10_counts[str(raw_value)] = dict(sorted(counts.items()))
        if len(counts) == 1:
            field_10_mapping[str(raw_value)] = next(iter(counts))
        else:
            field_10_conflicts.append({
                'raw_field_10': raw_value,
                'levels': dict(sorted(counts.items())),
            })

    sequences: dict[tuple[str, int], list[dict]] = collections.defaultdict(list)
    for row in matched:
        sequences[(row['replay_label'], row['participant_id'])].append(row)
    non_monotonic_sequences = []
    for (label, participant_id), rows in sorted(sequences.items()):
        rows.sort(key=lambda item: (
            item['replay_time_ms'], item['chunk_index'],
            item['decompressed_block_offset'],
        ))
        if any(
            current['level_after'] <= previous['level_after']
            or current['replay_time_ms'] <= previous['replay_time_ms']
            for previous, current in zip(rows, rows[1:])
        ):
            non_monotonic_sequences.append({
                'replay_label': label,
                'participant_id': participant_id,
            })
    unique_anchor_keys = {
        (row['replay_label'], row['anchor_index']) for row in matched
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    decoded_path = output_dir / 'level_transition_decoded.jsonl'
    with decoded_path.open('w', encoding='utf-8', newline='\n') as handle:
        for row in decoded:
            handle.write(json.dumps(row, sort_keys=True) + '\n')
    matched_path = output_dir / 'level_transition_anchor_matches.jsonl'
    with matched_path.open('w', encoding='utf-8', newline='\n') as handle:
        for row in matched:
            handle.write(json.dumps(row, sort_keys=True) + '\n')

    success_rows = [row for row in decoded if row['deserialize_return_al'] == 1]
    full_rows = [row for row in success_rows if row['fully_consumed']]
    anchor_count = sum(len(rows) for rows in anchors.values())
    anchor_ratio = len(matched) / anchor_count if anchor_count else 0.0
    details_replay_count = sum(bool(rows) for rows in anchors.values())
    p0_level_counts = collections.Counter(row['level_after'] for row in matched)
    p0_levels_verified = all(p0_level_counts[level] >= 100 for level in (2, 3, 4))
    observed_replay_counts = {
        label: input_rows_by_replay[label]
        for label in manifest['replay_packet_counts']
    }
    manifest_count_verified = (
        valid_input_row_count == manifest['selected_packet_count']
        and observed_replay_counts == manifest['replay_packet_counts']
        if args.limit is None
        else selected_count == args.limit
    )
    structural_verified = level_structural_gate(
        selected_count, decoded, full_rows, input_failures,
        infrastructure_failures, manifest_count_verified,
    )
    semantic_verified = bool(
        anchor_count >= 100
        and details_replay_count >= 10
        and anchor_ratio >= 0.95
        and len(sequences) >= 100
        and p0_levels_verified
        and not conflicting_pairs
        and not field_10_conflicts
        and not non_monotonic_sequences
    )
    summary = {
        'schema_version': 1,
        'status': 'PASS' if (
            structural_verified and (args.decode_only or semantic_verified)
        ) else 'FAIL',
        'game_version': REPLAY_VERSION,
        'patch': '16.16',
        'build_profile': LEVEL_PROFILE['id'],
        'runtime_image_sha256': runtime_sha,
        'profile': LEVEL_PROFILE,
        'packet_manifest': {
            'path': manifest['path'],
            'declared_packet_count': manifest['selected_packet_count'],
            'declared_replay_count': manifest['replay_count'],
            'observed_replay_packet_counts': observed_replay_counts,
            'per_replay_count_validation': (
                'FULL_MATCH' if args.limit is None
                and observed_replay_counts == manifest['replay_packet_counts']
                else 'BOUNDED_NOT_APPLICABLE' if args.limit is not None else 'MISMATCH'
            ),
            'count_validation': (
                'FULL_MATCH' if args.limit is None and manifest_count_verified
                else 'BOUNDED_LIMIT_MATCH' if manifest_count_verified else 'MISMATCH'
            ),
        },
        'input_rows': input_row_count,
        'valid_input_rows': valid_input_row_count,
        'packet_rows_selected': selected_count,
        'decoded_rows': len(decoded),
        'deserialize_success_rows': len(success_rows),
        'fully_consumed_success_rows': len(full_rows),
        'input_provenance_failure_count': len(input_failures),
        'infrastructure_failure_count': len(infrastructure_failures),
        'details_level_anchor_count': anchor_count,
        'details_replay_count': details_replay_count,
        'matched_anchor_rows': len(matched),
        'matched_unique_anchor_count': len(unique_anchor_keys),
        'duplicate_matched_packet_rows': len(matched) - len(unique_anchor_keys),
        'matched_anchor_ratio': anchor_ratio if anchor_count else None,
        'unmatched_fully_consumed_rows': len(full_rows) - len(matched),
        'required_p0_level_counts': {
            str(level): p0_level_counts[level] for level in (2, 3, 4)
        },
        'required_p0_levels_status': 'PASS' if p0_levels_verified else 'FAIL',
        'raw_pair_level_after_mapping': mapping,
        'conflicting_raw_pairs': conflicting_pairs,
        'raw_field_10_level_after_mapping': field_10_mapping,
        'raw_field_10_level_counts': field_10_counts,
        'raw_field_10_conflicts': field_10_conflicts,
        'participant_sequence_count': len(sequences),
        'non_monotonic_participant_sequences': non_monotonic_sequences,
        'acceptance_gates': {
            'structural_nonempty_full_consume': structural_verified,
            'anchor_count_gte_100': anchor_count >= 100,
            'details_replay_count_gte_10': details_replay_count >= 10,
            'unique_anchor_coverage_gte_95_percent': anchor_ratio >= 0.95,
            'participant_sequence_count_gte_100': len(sequences) >= 100,
            'p0_levels_2_3_4_each_gte_100': p0_levels_verified,
            'conflict_free_monotonic_mapping': (
                not conflicting_pairs and not field_10_conflicts
                and not non_monotonic_sequences
            ),
        },
        'elapsed_seconds': time.perf_counter() - started,
        'decoded_jsonl': str(decoded_path),
        'anchor_matches_jsonl': str(matched_path),
    }
    write_json(output_dir / 'level_transition_validation_summary.json', summary)
    write_json(output_dir / 'level_transition_input_failures.json', input_failures)
    write_json(output_dir / 'level_transition_infrastructure_failures.json', infrastructure_failures)
    return summary


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError('--limit must be an integer') from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError('--limit must be positive')
    return parsed


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--capability', choices=('hero_path', 'level_transition', 'ward_spawn'),
        default='level_transition',
    )
    parser.add_argument('--runtime-image', required=True)
    parser.add_argument('--packets', required=True)
    parser.add_argument('--details-root')
    parser.add_argument('--participants')
    parser.add_argument('--output', required=True)
    parser.add_argument('--limit', type=positive_int)
    parser.add_argument('--max-anchor-time-ms', type=int, default=130000)
    parser.add_argument('--decode-only', action='store_true')
    return parser.parse_args()


def main():
    args = parse_args()
    if args.capability == 'hero_path':
        summary = validate_path(args)
    elif args.capability == 'level_transition':
        summary = validate_level(args)
    else:
        if not args.participants:
            raise RuntimeError('--participants is required for ward_spawn')
        import decode_ward_spawn_16_16 as ward
        ward_options = argparse.Namespace(
            runtime_image=pathlib.Path(args.runtime_image),
            packets=pathlib.Path(args.packets),
            participants=pathlib.Path(args.participants),
            output=pathlib.Path(args.output),
            limit=args.limit,
            progress_every=1000,
            validation_scope='CORPUS_RELEASE_GATE',
        )
        summary = ward.validate(ward_options)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
