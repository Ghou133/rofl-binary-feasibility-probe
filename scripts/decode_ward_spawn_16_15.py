#!/usr/bin/env python3

"""Decode every 16.15 packet 0x0353 and validate WardSpawn against CastSpell."""

import argparse
import hashlib
import json
import math
import os
import statistics
import struct
import sys
from collections import Counter, defaultdict

import emulate_exact_packet_decoder as exact
from emulate_ward_spawn_candidates import CANDIDATES, WardTraceEmulator


PACKET_ID = 0x0353
WARD_TOKENS = ('ward', 'trinket', 'jammer', 'totem', 'farsight')
CORPSE_TOKEN = 'corpse'


def args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--packets', required=True)
    parser.add_argument('--casts-root', required=True)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--match-window-ms', type=float, default=2000.0)
    parser.add_argument('--progress-every', type=int, default=1000)
    return parser.parse_args()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def unique_writes(offset_writes, offset, size):
    events = []
    seen = set()
    for event in offset_writes.get(offset, []):
        if event['write_offset'] != offset or event['write_size'] != size:
            continue
        key = event['sequence']
        if key not in seen:
            seen.add(key)
            events.append(event)
    return events


def selected_write(offset_writes, offset, size, selection):
    events = unique_writes(offset_writes, offset, size)
    event = (events[0] if selection == 'first' else events[-1]) if events else None
    if event is None:
        return None, None
    return int(event['write_value_hex'], 16), {
        'offset': f'0x{offset:02x}',
        'size': size,
        'selection': f'{selection}_size_{size}_write',
        'sequence': event['sequence'],
        'instruction_rva': event['instruction_rva'],
        'value_hex': event['write_value_hex'],
    }


def as_float(value):
    if value is None:
        return None
    result = struct.unpack('<f', struct.pack('<I', value & 0xffffffff))[0]
    return result if math.isfinite(result) else None


def read_string(emulator, pointer, length):
    if pointer is None or length is None or length < 0 or length > 4096:
        return None
    if pointer < exact.HEAP_BASE or pointer + length > exact.HEAP_BASE + exact.HEAP_SIZE:
        return None
    try:
        raw = bytes(emulator.emulator.mem_read(pointer, length))
        return raw.decode('utf-8', errors='replace')
    except Exception:
        return None


def recover_fields(emulator):
    writes = emulator.offset_writes
    x_raw, x_ev = selected_write(writes, 0x18, 4, 'last')
    h_raw, h_ev = selected_write(writes, 0x1c, 4, 'last')
    y_raw, y_ev = selected_write(writes, 0x20, 4, 'last')
    owner, owner_ev = selected_write(writes, 0x30, 4, 'first')
    entity, entity_ev = selected_write(writes, 0x44, 4, 'first')
    generic_ptr, generic_ptr_ev = selected_write(writes, 0x50, 8, 'first')
    generic_len, generic_len_ev = selected_write(writes, 0x58, 4, 'first')
    entity_ptr, entity_ptr_ev = selected_write(writes, 0x78, 8, 'first')
    entity_len, entity_len_ev = selected_write(writes, 0x80, 4, 'first')
    generic_name = read_string(emulator, generic_ptr, generic_len)
    entity_name = read_string(emulator, entity_ptr, entity_len)
    names = [name for name in (generic_name, entity_name) if name]
    lowered = ' '.join(names).lower()
    is_corpse = CORPSE_TOKEN in lowered
    is_ward = any(token in lowered for token in WARD_TOKENS) and not is_corpse
    return {
        'position': {'x': as_float(x_raw), 'height': as_float(h_raw), 'y': as_float(y_raw)},
        'owner_network_id': owner,
        'entity_network_id': entity,
        'generic_name': generic_name,
        'entity_name': entity_name,
        'is_ward_spawn': is_ward,
        'is_corpse': is_corpse,
        'field_confidence': {
            'position': 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
            'owner_network_id': 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
            'entity_network_id': 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
            'generic_name': 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
            'entity_name': 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
        },
        'write_evidence': {
            'position_x': x_ev, 'position_height': h_ev, 'position_y': y_ev,
            'owner_network_id': owner_ev, 'entity_network_id': entity_ev,
            'generic_name_pointer': generic_ptr_ev, 'generic_name_length': generic_len_ev,
            'entity_name_pointer': entity_ptr_ev, 'entity_name_length': entity_len_ev,
        },
    }


def replay_key(path):
    return os.path.splitext(os.path.basename(path))[0]


def load_casts(root):
    casts = []
    hashes = {}
    for directory in sorted(os.listdir(root)):
        path = os.path.join(root, directory, 'spell_events.jsonl')
        if not os.path.isfile(path):
            continue
        hashes[os.path.abspath(path)] = sha256_file(path)
        with open(path, encoding='utf-8') as stream:
            for line_number, line in enumerate(stream, 1):
                row = json.loads(line)
                if row.get('spell_identifier') != 'TrinketTotemLvl1':
                    continue
                casts.append({
                    'replay_label': directory,
                    'replay_time_ms': row['replay_time_ms'],
                    'owner_network_id': row['caster_network_id'],
                    'participant_id': row.get('caster_participant_id'),
                    'team_id': row.get('caster_team_id'),
                    'cast_start_x': row['target_position'][0],
                    'cast_start_y': row['target_position'][2],
                    'cast_end_x': row['target_position_end'][0],
                    'cast_end_y': row['target_position_end'][2],
                    'raw_packet_ref': row['raw_packet_ref'],
                    'source_artifact': os.path.abspath(path),
                    'source_line': line_number,
                })
    return casts, hashes


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def distribution(values, include_thresholds=False):
    if not values:
        return {'count': 0, 'mean': None, 'p50': None, 'p90': None, 'p95': None, 'max': None}
    result = {
        'count': len(values), 'mean': statistics.fmean(values),
        'p50': percentile(values, .50), 'p90': percentile(values, .90),
        'p95': percentile(values, .95), 'max': max(values),
    }
    if include_thresholds:
        result['exact_count'] = sum(value == 0 for value in values)
        result['exact_percent'] = result['exact_count'] * 100 / len(values)
        for threshold in (10, 25, 50, 100):
            count = sum(value <= threshold for value in values)
            result[f'le_{threshold}_count'] = count
            result[f'le_{threshold}_percent'] = count * 100 / len(values)
    return result


def classify_ward(row):
    value = f"{row.get('generic_name') or ''} {row.get('entity_name') or ''}".lower()
    if 'farsight' in value or 'bluetrinket' in value:
        return 'FARSIGHT_WARD'
    if 'jammer' in value or 'controlward' in value:
        return 'CONTROL_WARD'
    if 'yellowtrinket' in value or 'trinkettotem' in value or 'sightward' in value:
        return 'YELLOW_OR_SIGHT_WARD'
    return 'OTHER_WARD'


def match_casts(casts, wards, window_ms):
    by_owner = defaultdict(list)
    for index, ward in enumerate(wards):
        by_owner[(ward['replay_label'], ward['owner_network_id'])].append(index)
    used = set()
    matches = []
    for cast_index, cast in enumerate(casts):
        candidates = []
        for ward_index in by_owner[(cast['replay_label'], cast['owner_network_id'])]:
            if ward_index in used:
                continue
            ward = wards[ward_index]
            delta = ward['replay_time_ms'] - cast['replay_time_ms']
            if -100.0 <= delta <= window_ms:
                candidates.append((abs(delta), ward_index, delta))
        if not candidates:
            continue
        _, ward_index, delta = min(candidates)
        used.add(ward_index)
        ward = wards[ward_index]
        start_distance = math.hypot(
            ward['position']['x'] - cast['cast_start_x'],
            ward['position']['y'] - cast['cast_start_y'])
        end_distance = math.hypot(
            ward['position']['x'] - cast['cast_end_x'],
            ward['position']['y'] - cast['cast_end_y'])
        ward['owner_participant_id'] = cast['participant_id']
        ward['owner_team_id'] = cast['team_id']
        ward['owner_participant_confidence'] = 'VERIFIED_DERIVED_FROM_MATCHED_CASTSPELL'
        ward['owner_team_confidence'] = 'VERIFIED_DERIVED_FROM_MATCHED_CASTSPELL'
        matches.append({
            'cast_index': cast_index, 'spawn_index': ward_index,
            'replay_label': cast['replay_label'],
            'owner_network_id': cast['owner_network_id'],
            'ward_network_id': ward['entity_network_id'],
            'ward_type': ward['ward_type'],
            'cast_time_ms': cast['replay_time_ms'], 'spawn_time_ms': ward['replay_time_ms'],
            'timestamp_delta_ms': delta,
            'coordinate_error_start_like': start_distance,
            'coordinate_error_end_like': end_distance,
            'cast_start_like_position': [cast['cast_start_x'], cast['cast_start_y']],
            'cast_end_like_position': [cast['cast_end_x'], cast['cast_end_y']],
            'spawn_position': [ward['position']['x'], ward['position']['y']],
            'cast_raw_packet_ref': cast['raw_packet_ref'],
            'spawn_raw_packet_ref': ward['raw_packet_ref'],
        })
    return matches, used


def build_lifecycle(wards, corpses):
    corpse_used = set()
    lifecycle = []
    for ward_index, ward in enumerate(wards):
        candidates = []
        for corpse_index, corpse in enumerate(corpses):
            if corpse_index in corpse_used or corpse['replay_label'] != ward['replay_label']:
                continue
            delta = corpse['replay_time_ms'] - ward['replay_time_ms']
            if delta < 0:
                continue
            same_id = corpse['entity_network_id'] == ward['entity_network_id']
            distance = math.hypot(
                corpse['position']['x'] - ward['position']['x'],
                corpse['position']['y'] - ward['position']['y'],
            )
            same_owner = (ward['owner_network_id'] != 0
                          and corpse['owner_network_id'] == ward['owner_network_id'])
            if same_id:
                candidates.append((0, delta, distance, corpse_index, 'SAME_NETWORK_ID'))
            elif distance <= 5.0 and same_owner:
                candidates.append((1, delta, distance, corpse_index,
                                   'SAME_OWNER_UNIQUE_COORDINATE_TIME_DERIVED'))
            elif distance <= 5.0:
                candidates.append((2, delta, distance, corpse_index,
                                   'UNIQUE_COORDINATE_TIME_DERIVED'))
        chosen = None
        for rank in (0, 1, 2):
            ranked = sorted((item for item in candidates if item[0] == rank), key=lambda item: item[1])
            if ranked:
                coordinate = ranked
                if coordinate:
                    best = coordinate[0]
                    # Fallback is accepted only when no competing corpse is equally plausible.
                    if rank == 0 or len(coordinate) == 1 or coordinate[1][1] - best[1] > 1000:
                        chosen = best
                if chosen:
                    break
        if chosen:
            _, delta, distance, corpse_index, rule = chosen
            corpse_used.add(corpse_index)
            corpse = corpses[corpse_index]
            lifecycle.append({
                'ward_network_id': ward['entity_network_id'], 'replay_label': ward['replay_label'],
                'spawn_time_ms': ward['replay_time_ms'], 'remove_time_ms': corpse['replay_time_ms'],
                'duration_ms': delta, 'removal_reason': 'CORPSE_PACKET_DERIVED',
                'match_rule': rule, 'coordinate_error': distance,
                'spawn_raw_packet_ref': ward['raw_packet_ref'],
                'remove_raw_packet_ref': corpse['raw_packet_ref'],
            })
    return lifecycle, corpse_used


def write_json(path, value):
    with open(path, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2)
        stream.write('\n')


def write_jsonl(path, rows):
    with open(path, 'w', encoding='utf-8', newline='\n') as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n')


def main():
    options = args()
    os.makedirs(options.output_dir, exist_ok=True)
    image = open(options.image, 'rb').read()
    candidate = CANDIDATES['exact_16_15_801']
    profile = {**candidate, 'fields': []}
    emulator = WardTraceEmulator(image, candidate)
    decoded_rows = []
    failures = []
    counters = Counter()
    with open(options.packets, encoding='utf-8') as stream:
        for line_number, line in enumerate(stream, 1):
            source = json.loads(line)
            counters['input_packets'] += 1
            if source['packet_id'] != PACKET_ID:
                raise ValueError(f'line {line_number}: expected packet {PACKET_ID}')
            try:
                decoded = emulator.decode(
                    bytes.fromhex(source['raw_payload_hex']), profile,
                    packet_id=source['packet_id'], raw_param=source['raw_param'],
                )
                counters['decoder_accepted'] += int(decoded['deserialize_return_al'] != 0)
                if decoded['deserialize_return_al'] == 0:
                    continue
                fields = recover_fields(emulator)
                row = {
                    'schema_version': 1, 'event_type': 'entity_spawn_semantic',
                    'replay_label': source['replay_label'],
                    'replay_time_ms': source['replay_time_ms'],
                    **fields,
                    'decoder_profile': 'rofl-16.15.801.3452-ward-spawn-unicorn-v1',
                    'decoder_return_al': decoded['deserialize_return_al'],
                    'fully_consumed': decoded['fully_consumed'],
                    'raw_packet_ref': {key: source[key] for key in (
                        'replay_path', 'replay_sha256', 'chunk_index', 'chunk_id', 'chunk_stream',
                        'chunk_file_offset', 'compressed_body_offset', 'decompressed_block_offset',
                        'decompressed_payload_offset', 'occurrence_index', 'packet_id', 'payload_length',
                        'raw_param', 'raw_param_hex', 'raw_payload_sha256')},
                }
                decoded_rows.append(row)
            except Exception as error:
                failures.append({'source_line': line_number, 'error_type': type(error).__name__, 'message': str(error)})
            if options.progress_every and line_number % options.progress_every == 0:
                print(f'{line_number}: decoded={len(decoded_rows)} failures={len(failures)}', file=sys.stderr, flush=True)

    wards = []
    corpses = []
    for row in decoded_rows:
        if row['is_ward_spawn']:
            row['event_type'] = 'ward_spawn'
            row['ward_type'] = classify_ward(row)
            wards.append(row)
        if row['is_corpse']:
            row['event_type'] = 'entity_corpse'
            corpses.append(row)

    casts, cast_hashes = load_casts(options.casts_root)
    owner_map = {}
    for cast in casts:
        key = (cast['replay_label'], cast['owner_network_id'])
        value = (cast['participant_id'], cast['team_id'])
        if key in owner_map and owner_map[key] != value:
            raise ValueError(f'inconsistent CastSpell owner mapping for {key}')
        owner_map[key] = value
    for ward in wards:
        mapping = owner_map.get((ward['replay_label'], ward['owner_network_id']))
        if mapping:
            ward['owner_participant_id'], ward['owner_team_id'] = mapping
            ward['owner_participant_confidence'] = 'VERIFIED_DERIVED_FROM_CASTSPELL_OWNER_MAP'
            ward['owner_team_confidence'] = 'VERIFIED_DERIVED_FROM_CASTSPELL_OWNER_MAP'
    matches, used_wards = match_casts(casts, wards, options.match_window_ms)
    lifecycle, used_corpses = build_lifecycle(wards, corpses)
    match_path = os.path.join(options.output_dir, 'cast_spawn_matches.jsonl')
    ward_path = os.path.join(options.output_dir, 'ward_spawns.jsonl')
    all_path = os.path.join(options.output_dir, 'all_entity_events.jsonl')
    corpse_path = os.path.join(options.output_dir, 'corpse_events.jsonl')
    lifecycle_path = os.path.join(options.output_dir, 'ward_lifecycle.jsonl')
    for path, rows in ((all_path, decoded_rows), (ward_path, wards), (corpse_path, corpses),
                       (match_path, matches), (lifecycle_path, lifecycle)):
        write_jsonl(path, rows)
    deltas = [item['timestamp_delta_ms'] for item in matches]
    start_distances = [item['coordinate_error_start_like'] for item in matches]
    end_distances = [item['coordinate_error_end_like'] for item in matches]
    lifecycle_durations = [item['duration_ms'] for item in lifecycle]
    summary = {
        'schema_version': 1,
        'status': 'PASS' if len(matches) >= 100 else 'FAIL',
        'target_replay_version': '16.15.801.3452',
        'profile': {'packet_id': PACKET_ID, 'packet_id_hex': '0x0353',
                    'constructor_rva': '0x00eb0640', 'deserialize_rva': '0x0103b1c0',
                    'deserialize_end_rva': '0x0103d737', 'object_size': 0x90},
        'method': 'Exact runtime Unicorn execution; fields recovered only from current object write trace',
        'field_selection': {
            'position': 'last size-4 plaintext writes at +0x18/+0x1c/+0x20',
            'owner_network_id': 'first size-4 plaintext write at +0x30',
            'entity_network_id': 'first size-4 plaintext write at +0x44',
            'generic_name': 'pointer/length writes at +0x50/+0x58',
            'entity_name': 'pointer/length writes at +0x78/+0x80'},
        'counts': {
            **counters, 'infrastructure_failures': len(failures),
            'semantic_entity_events': len(decoded_rows), 'ward_spawns': len(wards),
            'corpse_events': len(corpses), 'trinket_casts': len(casts),
            'cast_spawn_matches': len(matches), 'unmatched_casts': len(casts) - len(matches),
            'unmatched_spawns': len(wards) - len(used_wards),
            'lifecycle_matches': len(lifecycle), 'unmatched_corpses': len(corpses) - len(used_corpses)},
        'ward_type_counts': dict(sorted(Counter(row['ward_type'] for row in wards).items())),
        'lifecycle_match_rule_counts': dict(sorted(Counter(row['match_rule'] for row in lifecycle).items())),
        'lifecycle_duration_ms': distribution(lifecycle_durations),
        'timestamp_delta_ms': distribution(deltas),
        'coordinate_euclidean_error_start_like_target_position': distribution(start_distances, True),
        'coordinate_euclidean_error_end_like_target_position_end': distribution(end_distances, True),
        'match_rule': f'same replay and owner network id; one-to-one nearest timestamp in [-100,{options.match_window_ms}] ms',
        'owner_mapping': 'participant/team are VERIFIED_DERIVED_FROM_MATCHED_CASTSPELL; never inputs to spawn decoding',
        'coordinate_independence': 'spawn coordinates come only from +0x18/+0x20 object write trace; both CastSpell vectors are validation-only',
        'proxy_decision': ('CAST_TARGET_POSITION_END_AS_WARD_POSITION_PROXY=VERIFIED_DERIVED_WITH_REPORTED_ERROR_PROFILE'
                           if end_distances and percentile(end_distances, .95) <= 50
                           and sum(value <= 50 for value in end_distances) / len(end_distances) >= .95 else
                           'CAST_TARGET_POSITION_END_AS_WARD_POSITION_PROXY=NOT_VERIFIED'),
        'lifecycle_rule': 'Corpse name; same network ID preferred, else <=5 units same-owner then same-replay time-ordered unique match; ambiguous fallback rejected',
        'input_artifacts': {
            'runtime_image': os.path.abspath(options.image), 'runtime_image_sha256': hashlib.sha256(image).hexdigest(),
            'selected_packets': os.path.abspath(options.packets), 'selected_packets_sha256': sha256_file(options.packets),
            'selected_packets_manifest': os.path.abspath(options.packets + '.manifest.json'),
            'selected_packets_manifest_sha256': sha256_file(options.packets + '.manifest.json'),
            'cast_artifact_sha256': cast_hashes},
        'output_artifacts': {name: os.path.abspath(path) for name, path in (
            ('all_entity_events', all_path), ('ward_spawns', ward_path), ('corpse_events', corpse_path),
            ('cast_spawn_matches', match_path), ('ward_lifecycle', lifecycle_path))},
        'failures': failures[:100],
    }
    summary['output_sha256'] = {name: sha256_file(path) for name, path in summary['output_artifacts'].items()}
    summary_path = os.path.join(options.output_dir, 'summary.json')
    write_json(summary_path, summary)
    print(json.dumps({'summary': os.path.abspath(summary_path), 'status': summary['status'], 'counts': summary['counts'],
                      'timestamp_delta_ms': summary['timestamp_delta_ms'],
                      'coordinate_error_start_like': summary['coordinate_euclidean_error_start_like_target_position'],
                      'coordinate_error_end_like': summary['coordinate_euclidean_error_end_like_target_position_end']}, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)
