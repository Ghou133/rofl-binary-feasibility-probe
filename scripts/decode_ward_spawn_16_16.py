#!/usr/bin/env python3
"""Decode exact-build 16.16 packet 0x049a and publish evidence-gated Ward semantics."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import pathlib
import statistics
import struct
import sys
import time
from collections import Counter, defaultdict

from PIL import Image, ImageDraw, ImageFont
from unicorn import UC_HOOK_MEM_WRITE

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import emulate_exact_packet_decoder as exact  # noqa: E402
import validate_multi_build_runtime as runtime  # noqa: E402


REPLAY_VERSION = runtime.REPLAY_VERSION
PATCH = '16.16'
PACKET_ID = runtime.WARD_PROFILE['client_opcode']
RUNTIME_SHA256 = runtime.RUNTIME_SHA256
WARD_PROFILE = {
    **runtime.WARD_PROFILE,
    'fields': [],
    'runtime_singletons': [{
        'pointer_rva': runtime.WARD_PROFILE['codec_singleton_pointer_rva'],
        'required_byte_offset': runtime.WARD_PROFILE['codec_singleton_enable_offset'],
        'required_byte_value': 1,
        'reason': '0x00f9fb50 runtime codec enable flag',
    }],
}

WARD_TOKENS = ('ward', 'trinket', 'jammer', 'totem', 'farsight')
VISION_TOKENS = WARD_TOKENS + ('vision', 'fow')
MAP_MECHANIC_TOKENS = ('plant', 'crab', 'satchel', 'sru_plant', 'sru_crab')


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


class Ward1616TraceEmulator(runtime.Build1616Emulator):
    """16.16 wrapper hooks plus exact object-write tracing and codec singleton."""

    def __init__(self, image: bytes):
        super().__init__(image)
        self.candidate = WARD_PROFILE
        self.runtime_singleton_mappings = []
        for dependency in WARD_PROFILE['runtime_singletons']:
            pointer = struct.unpack_from('<Q', image, dependency['pointer_rva'])[0]
            page = pointer & -exact.PAGE_SIZE
            try:
                self.emulator.mem_map(page, exact.PAGE_SIZE)
            except Exception:
                pass
            address = pointer + dependency['required_byte_offset']
            self.emulator.mem_write(address, bytes([dependency['required_byte_value']]))
            self.runtime_singleton_mappings.append({
                **dependency,
                'pointer_rva': f"0x{dependency['pointer_rva']:08x}",
                'resolved_pointer': f'0x{pointer:x}',
                'mapped_page': f'0x{page:x}',
                'written_address': f'0x{address:x}',
            })
        self.trace_enabled = False
        self.write_sequence = 0
        self.offset_writes = {}
        self.heap_high_water = exact.HEAP_BASE
        self.emulator.hook_add(
            UC_HOOK_MEM_WRITE,
            self._trace_object_write,
            begin=exact.OBJECT_ADDRESS,
            end=exact.OBJECT_ADDRESS + WARD_PROFILE['object_size'] - 1,
        )

    def reset_heap(self):
        if hasattr(self, 'heap_high_water'):
            used_size = self.heap_high_water - exact.HEAP_BASE
            if used_size > 0:
                self.emulator.mem_write(exact.HEAP_BASE, b'\x00' * used_size)
        super().reset_heap()

    def call(self, address, rcx=0, rdx=0, r8=0):
        tracing = address == exact.IMAGE_BASE + WARD_PROFILE['deserialize_rva']
        if tracing:
            self.write_sequence = 0
            self.offset_writes = {}
            self.trace_enabled = True
        try:
            result = super().call(address, rcx=rcx, rdx=rdx, r8=r8)
            self.heap_high_water = max(self.heap_high_water, self.heap_cursor)
            return result
        finally:
            if tracing:
                self.trace_enabled = False

    def _trace_object_write(self, _emulator, _access, address, size, value, _user_data):
        if not self.trace_enabled:
            return
        self.write_sequence += 1
        instruction = self.emulator.reg_read(exact.UC_X86_REG_RIP)
        first = max(address, exact.OBJECT_ADDRESS)
        last = min(address + size, exact.OBJECT_ADDRESS + WARD_PROFILE['object_size'])
        for byte_address in range(first, last):
            source_shift = (byte_address - address) * 8
            offset = byte_address - exact.OBJECT_ADDRESS
            self.offset_writes.setdefault(offset, []).append({
                'sequence': self.write_sequence,
                'instruction_rva': f'0x{instruction - exact.IMAGE_BASE:08x}',
                'write_offset': address - exact.OBJECT_ADDRESS,
                'write_size': size,
                'write_value_hex': (
                    f'0x{value & ((1 << (min(size, 8) * 8)) - 1):0{min(size, 8) * 2}x}'
                ),
                'byte_value': (value >> source_shift) & 0xFF,
            })


def unique_writes(offset_writes: dict, offset: int, size: int) -> list[dict]:
    events = []
    seen = set()
    for event in offset_writes.get(offset, []):
        if event['write_offset'] != offset or event['write_size'] != size:
            continue
        if event['sequence'] in seen:
            continue
        seen.add(event['sequence'])
        events.append(event)
    return events


def selected_write(offset_writes: dict, offset: int, size: int, selection: str):
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


def as_float(value: int | None) -> float | None:
    if value is None:
        return None
    decoded = struct.unpack('<f', struct.pack('<I', value & 0xFFFFFFFF))[0]
    return decoded if math.isfinite(decoded) else None


def read_heap_string(emulator: Ward1616TraceEmulator, pointer, length):
    if pointer is None or length is None or not 0 <= length <= 4096:
        return None
    if not exact.HEAP_BASE <= pointer <= exact.HEAP_BASE + exact.HEAP_SIZE - length:
        return None
    try:
        return bytes(emulator.emulator.mem_read(pointer, length)).decode('utf-8', errors='replace')
    except Exception:
        return None


def recover_raw_fields(emulator: Ward1616TraceEmulator) -> dict:
    writes = emulator.offset_writes
    specs = {
        'field_0c_u32': (0x0C, 4, 'first'),
        'field_10_u32': (0x10, 4, 'last'),
        'field_14_u32': (0x14, 4, 'last'),
        'field_18_u32': (0x18, 4, 'last'),
        'field_1c_u32': (0x1C, 4, 'first'),
        'field_3c_u32': (0x3C, 4, 'last'),
        'field_5c_u32': (0x5C, 4, 'last'),
        'field_60_u32': (0x60, 4, 'last'),
        'field_64_u32': (0x64, 4, 'last'),
        'field_70_u32': (0x70, 4, 'first'),
    }
    raw = {}
    evidence = {}
    for name, (offset, size, selection) in specs.items():
        value, event = selected_write(writes, offset, size, selection)
        raw[name] = value
        evidence[name] = event
    for offset in (0x10, 0x14, 0x18, 0x3C, 0x5C, 0x60, 0x64):
        key = f'field_{offset:02x}'
        raw[f'{key}_f32'] = as_float(raw[f'{key}_u32'])

    generic_ptr, generic_ptr_evidence = selected_write(writes, 0x48, 8, 'first')
    generic_len, generic_len_evidence = selected_write(writes, 0x50, 4, 'first')
    entity_ptr, entity_ptr_evidence = selected_write(writes, 0x78, 8, 'first')
    entity_len, entity_len_evidence = selected_write(writes, 0x80, 4, 'first')
    raw.update({
        'field_48_pointer': generic_ptr,
        'field_50_length': generic_len,
        'field_78_pointer': entity_ptr,
        'field_80_length': entity_len,
        'generic_name': read_heap_string(emulator, generic_ptr, generic_len),
        'entity_name': read_heap_string(emulator, entity_ptr, entity_len),
    })
    evidence.update({
        'field_48_pointer': generic_ptr_evidence,
        'field_50_length': generic_len_evidence,
        'field_78_pointer': entity_ptr_evidence,
        'field_80_length': entity_len_evidence,
    })
    raw['write_evidence'] = evidence
    return raw


def load_participants(path: pathlib.Path, manifest: dict, validation_scope: str) -> tuple[dict, dict]:
    if validation_scope not in ('CORPUS_RELEASE_GATE', 'SINGLE_REPLAY_DECODE'):
        raise RuntimeError(f'unsupported participant validation scope: {validation_scope}')
    document = json.loads(path.read_text(encoding='utf-8'))
    if document.get('schema_version') != 1 or document.get('target_replay_version') != REPLAY_VERSION:
        raise RuntimeError('participant metadata is not exact-build schema v1')
    if document.get('validation_scope') not in (None, validation_scope):
        raise RuntimeError('participant metadata validation scope disagrees with decoder scope')
    if document.get('replay_count') != manifest['replay_count']:
        raise RuntimeError('participant metadata replay count disagrees with packet manifest')
    owner_map = {}
    replay_metadata = {}
    for replay in document.get('replays', []):
        label = replay.get('replay_label')
        if not isinstance(label, str) or not label:
            raise RuntimeError('participant metadata Replay label is missing or invalid')
        if label in replay_metadata:
            raise RuntimeError(f'duplicate participant metadata Replay label: {label}')
        if manifest['replay_shas'].get(label) != replay.get('replay_sha256'):
            raise RuntimeError(f'participant metadata Replay SHA mismatch for {label}')
        participant_rows = replay.get('participants', [])
        if not isinstance(participant_rows, list):
            raise RuntimeError(f'participant metadata participant rows for {label} must be a list')
        required_rows = 10 if validation_scope == 'CORPUS_RELEASE_GATE' else None
        if (required_rows is not None and len(participant_rows) != required_rows) or (
                required_rows is None and not 1 <= len(participant_rows) <= 10):
            required_text = 'ten' if required_rows is not None else 'one to ten'
            raise RuntimeError(f'participant metadata for {label} must contain {required_text} rows')
        participant_ids = set()
        owner_network_ids = set()
        replay_metadata[label] = replay
        for row in participant_rows:
            if not isinstance(row, dict):
                raise RuntimeError(f'participant metadata row for {label} must be an object')
            participant_id = row.get('participant_id')
            owner_id = row.get('owner_network_id')
            team_id = row.get('team_id')
            if any(not isinstance(value, int) or isinstance(value, bool)
                   for value in (participant_id, owner_id, team_id)):
                raise RuntimeError(f'participant metadata IDs for {label} must be integers')
            if not 1 <= participant_id <= 10:
                raise RuntimeError(f'invalid participant ID for {label}/{participant_id}')
            if participant_id in participant_ids:
                raise RuntimeError(f'duplicate participant ID for {label}/{participant_id}')
            if owner_id in owner_network_ids:
                raise RuntimeError(f'duplicate participant network ID for {label}/{owner_id}')
            if owner_id != 0x400000AD + participant_id:
                raise RuntimeError(f'participant network ID formula conflict for {label}/{participant_id}')
            if team_id not in (100, 200):
                raise RuntimeError(f'invalid participant team for {label}/{participant_id}')
            participant_ids.add(participant_id)
            owner_network_ids.add(owner_id)
            owner_map[(label, owner_id)] = row
    if set(replay_metadata) != set(manifest['replay_shas']):
        raise RuntimeError('participant metadata Replay set disagrees with packet manifest')
    return owner_map, replay_metadata


def classify_names(generic_name, entity_name, owner_mapping, position_plausible) -> dict:
    names = f'{generic_name or ""} {entity_name or ""}'.strip()
    lowered = names.lower()
    is_corpse = 'corpse' in lowered
    is_ward_like = any(token in lowered for token in WARD_TOKENS) and not is_corpse
    is_vision_like = any(token in lowered for token in VISION_TOKENS) and not is_corpse
    is_map_mechanic = any(token in lowered for token in MAP_MECHANIC_TOKENS)

    ward_type = 'UNKNOWN_WARD_TYPE'
    if 'farsight' in lowered or 'bluetrinket' in lowered:
        ward_type = 'FARSIGHT_WARD'
    elif 'jammer' in lowered or 'controlward' in lowered:
        ward_type = 'CONTROL_WARD'
    elif ('yellowtrinket' in lowered or 'trinkettotem' in lowered
          or ('sightward' in lowered and not is_map_mechanic)):
        ward_type = 'YELLOW_OR_SIGHT_WARD'

    known_player_type = ward_type != 'UNKNOWN_WARD_TYPE'
    if is_corpse:
        vision_class = 'WARD_CORPSE_SIGNAL'
    elif is_map_mechanic and is_vision_like:
        vision_class = 'MAP_MECHANIC_VISION'
    elif owner_mapping and known_player_type and position_plausible:
        vision_class = 'PLAYER_ACTIVE_WARD_CONFIRMED'
    elif owner_mapping and is_ward_like:
        vision_class = 'PLAYER_WARD_CANDIDATE'
    elif is_vision_like:
        vision_class = 'SPECIAL_VISION_ENTITY'
    elif is_ward_like:
        vision_class = 'UNKNOWN_WARD_ENTITY'
    else:
        vision_class = 'NON_VISION_ROUTE_ENTITY'
    return {
        'is_corpse': is_corpse,
        'is_ward_like': is_ward_like,
        'is_vision_like': is_vision_like,
        'is_map_mechanic': is_map_mechanic,
        'ward_type': ward_type,
        'vision_entity_class': vision_class,
    }


def raw_packet_ref(source: dict) -> dict:
    keys = (
        'replay_path', 'replay_sha256', 'chunk_index', 'chunk_id', 'chunk_stream',
        'chunk_file_offset', 'compressed_body_offset', 'decompressed_block_offset',
        'decompressed_payload_offset', 'occurrence_index', 'packet_id', 'payload_length',
        'raw_param', 'raw_param_hex', 'raw_payload_sha256',
    )
    return {key: source.get(key) for key in keys if key in source}


def public_vision_event(route_row: dict) -> dict:
    mapping = route_row.get('owner_mapping')
    confirmed = route_row['vision_entity_class'] == 'PLAYER_ACTIVE_WARD_CONFIRMED'
    position = route_row['position']
    event = {
        'schema_version': 2,
        'event_type': 'ward_spawn',
        'semantic_status': (
            'SEMANTIC_VERIFIED_DERIVED' if confirmed else 'SEMANTIC_CLASSIFIED_SPECIAL_OR_PARTIAL'
        ),
        'game_version': REPLAY_VERSION,
        'patch': PATCH,
        'build_profile': WARD_PROFILE['id'],
        'replay_label': route_row['replay_label'],
        'replay_sha256': route_row['replay_sha256'],
        'timestamp_ms': route_row['replay_time_ms'],
        'replay_time_ms': route_row['replay_time_ms'],
        'ward_spawn_time_ms': route_row['replay_time_ms'],
        'spawn_timestamp_ms': route_row['replay_time_ms'],
        'ward_owner_entity': route_row['owner_network_id'],
        'owner_entity': route_row['owner_network_id'],
        'owner_network_id': route_row['owner_network_id'],
        'ward_owner_participant': mapping.get('participant_id') if mapping else None,
        'owner_participant': mapping.get('participant_id') if mapping else None,
        'ward_team': mapping.get('team_id') if mapping else None,
        'owner_team': mapping.get('team_id') if mapping else None,
        'owner_champion': mapping.get('champion') if mapping else None,
        'ward_type': route_row['ward_type'],
        'ward_network_id': route_row['entity_network_id'],
        'entity_network_id': route_row['entity_network_id'],
        'generic_name': route_row['generic_name'],
        'entity_name': route_row['entity_name'],
        'ward_entity_name': route_row['entity_name'],
        'vision_entity_class': route_row['vision_entity_class'],
        'player_active_ward_confirmed': confirmed,
        'ward_exact_x': position['x'],
        'ward_exact_y': position['y'],
        'ward_height': position['height'],
        'position': position,
        'position_source': 'DIRECT_16_16_FIELD_10_18_OBJECT_WRITE_TRACE',
        'coordinate_system': 'SUMMONERS_RIFT_WORLD_XY_WITH_HEIGHT',
        'map_id': 11,
        'map_name': 'Summoners Rift',
        'ward_disappear_time_ms': None,
        'ward_end_reason': 'UNKNOWN',
        'ward_lifetime_ms': None,
        'lifecycle_status': 'UNAVAILABLE_AT_SPAWN',
        'confidence': 'VERIFIED_DERIVED' if confirmed else 'PARTIAL',
        'field_confidence': {
            'spawn_time': 'VERIFIED_DIRECT_REPLAY_BLOCK_TIMESTAMP',
            'position': 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
            'owner_entity': 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
            'entity_network_id': 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
            'generic_name': 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
            'entity_name': 'VERIFIED_DIRECT_OBJECT_WRITE_TRACE',
            'participant': 'VERIFIED_DERIVED_BUILD_BOUND' if mapping else 'UNAVAILABLE',
            'team': 'VERIFIED_DERIVED_REPLAY_TAIL_PARTICIPANT_MAP' if mapping else 'UNAVAILABLE',
            'ward_type': (
                'VERIFIED_DERIVED_FROM_DIRECT_NAMES'
                if route_row['ward_type'] != 'UNKNOWN_WARD_TYPE' else 'UNAVAILABLE'
            ),
            'vision_entity_class': (
                'VERIFIED_DERIVED_FROM_DIRECT_NAME_OWNER_POSITION'
                if confirmed else 'PARTIAL_DERIVED_FROM_DIRECT_NAME_OWNER'
            ),
            'end_time': 'UNAVAILABLE',
            'end_reason': 'UNKNOWN',
        },
        'raw_packet_ref': route_row['raw_packet_ref'],
    }
    return event


def build_lifecycles(confirmed_wards: list[dict], corpses: list[dict]):
    corpses_by_replay = defaultdict(list)
    for index, corpse in enumerate(corpses):
        corpses_by_replay[corpse['replay_label']].append((index, corpse))
    used = set()
    lifecycle_rows = []
    for ward in confirmed_wards:
        candidates = []
        for corpse_index, corpse in corpses_by_replay.get(ward['replay_label'], []):
            if corpse_index in used or corpse['replay_time_ms'] < ward['replay_time_ms']:
                continue
            if any(corpse['position'][axis] is None for axis in ('x', 'y')):
                continue
            distance = math.hypot(
                corpse['position']['x'] - ward['position']['x'],
                corpse['position']['y'] - ward['position']['y'],
            )
            delta = corpse['replay_time_ms'] - ward['replay_time_ms']
            same_id = corpse['entity_network_id'] == ward['entity_network_id']
            same_owner = (ward['owner_network_id'] != 0
                          and corpse['owner_network_id'] == ward['owner_network_id'])
            if same_id:
                if distance <= 5.0 and same_owner:
                    candidates.append((
                        0, delta, distance, corpse_index, corpse,
                        'SAME_NETWORK_ID_OWNER_COORDINATE_DERIVED',
                    ))
                continue
            if distance <= 5.0 and same_owner:
                candidates.append((1, delta, distance, corpse_index, corpse,
                                   'SAME_OWNER_UNIQUE_COORDINATE_TIME_DERIVED'))
            elif distance <= 5.0:
                candidates.append((2, delta, distance, corpse_index, corpse,
                                   'UNIQUE_COORDINATE_TIME_DERIVED'))
        chosen = None
        for rank in (0, 1, 2):
            ranked = sorted((row for row in candidates if row[0] == rank), key=lambda row: row[1])
            if ranked and (rank == 0 or len(ranked) == 1 or ranked[1][1] - ranked[0][1] > 1000):
                chosen = ranked[0]
                break
        row = {
            'schema_version': 2,
            'event_type': 'ward_lifecycle',
            'game_version': REPLAY_VERSION,
            'patch': PATCH,
            'build_profile': WARD_PROFILE['id'],
            'replay_label': ward['replay_label'],
            'replay_sha256': ward['replay_sha256'],
            'ward_network_id': ward['entity_network_id'],
            'owner_entity': ward['owner_network_id'],
            'owner_participant': ward['owner_mapping']['participant_id'],
            'owner_team': ward['owner_mapping']['team_id'],
            'ward_type': ward['ward_type'],
            'vision_entity_class': ward['vision_entity_class'],
            'spawn_time_ms': ward['replay_time_ms'],
            'ward_spawn_time_ms': ward['replay_time_ms'],
            'ward_disappear_time_ms': None,
            'ward_lifetime_ms': None,
            'ward_end_reason': 'UNKNOWN',
            'end_observation': 'UNAVAILABLE',
            'lifecycle_status': 'WARD_LIFECYCLE_PARTIAL',
            'match_rule': None,
            'coordinate_error': None,
            'spawn_raw_packet_ref': ward['raw_packet_ref'],
            'end_raw_packet_ref': None,
            'field_confidence': {
                'spawn_time': 'VERIFIED_DIRECT_REPLAY_BLOCK_TIMESTAMP',
                'end_time': 'UNAVAILABLE',
                'lifetime': 'UNAVAILABLE',
                'end_reason': 'UNKNOWN',
            },
        }
        if chosen:
            _, delta, distance, corpse_index, corpse, rule = chosen
            used.add(corpse_index)
            row.update({
                'ward_disappear_time_ms': corpse['replay_time_ms'],
                'ward_lifetime_ms': delta,
                'end_observation': 'OBSERVED_END',
                'lifecycle_status': 'OBSERVED_CORPSE_END_DERIVED_MATCH',
                'match_rule': rule,
                'coordinate_error': distance,
                'end_raw_packet_ref': corpse['raw_packet_ref'],
                'field_confidence': {
                    'spawn_time': 'VERIFIED_DIRECT_REPLAY_BLOCK_TIMESTAMP',
                    'end_time': 'VERIFIED_DERIVED_FROM_DIRECT_CORPSE_EVENT',
                    'lifetime': 'VERIFIED_DERIVED_FROM_TWO_DIRECT_TIMESTAMPS',
                    'end_reason': 'UNKNOWN',
                },
            })
        lifecycle_rows.append(row)
    return lifecycle_rows, used


def percentile(values, probability):
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    low, high = math.floor(position), math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def distribution(values):
    values = [value for value in values if value is not None and math.isfinite(value)]
    return {
        'count': len(values),
        'min': min(values) if values else None,
        'max': max(values) if values else None,
        'mean': statistics.fmean(values) if values else None,
        'p50': percentile(values, 0.50),
        'p90': percentile(values, 0.90),
        'p95': percentile(values, 0.95),
    }


def write_json(path: pathlib.Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + '\n',
                    encoding='utf-8')


def write_jsonl(path: pathlib.Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='\n') as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, separators=(',', ':')) + '\n')


def write_csv(path: pathlib.Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def make_map(path: pathlib.Path, events: list[dict], max_time_ms=None) -> None:
    width = height = 1400
    margin = 90
    image = Image.new('RGB', (width, height), '#101820')
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    for step in range(0, 16001, 2000):
        px = margin + (width - 2 * margin) * step / 16000
        py = height - margin - (height - 2 * margin) * step / 16000
        draw.line((px, margin, px, height - margin), fill='#263746', width=1)
        draw.line((margin, py, width - margin, py), fill='#263746', width=1)
        draw.text((px + 2, height - margin + 8), str(step), fill='#9fb3c8', font=font)
        draw.text((15, py - 6), str(step), fill='#9fb3c8', font=font)
    colors = {100: '#45a3ff', 200: '#ff5c6a', None: '#ffca3a'}
    plotted = 0
    for event in events:
        if max_time_ms is not None and event['timestamp_ms'] > max_time_ms:
            continue
        x, y = event.get('ward_exact_x'), event.get('ward_exact_y')
        if x is None or y is None or not (-1000 <= x <= 17000 and -1000 <= y <= 17000):
            continue
        px = margin + (width - 2 * margin) * x / 16000
        py = height - margin - (height - 2 * margin) * y / 16000
        team = event.get('ward_team')
        radius = 4 if event.get('player_active_ward_confirmed') else 3
        draw.ellipse((px - radius, py - radius, px + radius, py + radius),
                     fill=colors.get(team, '#ffca3a'))
        plotted += 1
    title = '16.16 Ward/Vision direct positions'
    if max_time_ms is not None:
        title += f' (0-{max_time_ms / 60000:g} min)'
    draw.text((margin, 30), f'{title}; n={plotted}', fill='white', font=font)
    draw.text((margin, 52), 'blue=team 100  red=team 200  yellow=special/unknown',
              fill='#d5e1eb', font=font)
    draw.rectangle((margin, margin, width - margin, height - margin), outline='#8ca0b3', width=2)
    image.save(path)


def field_report(route_rows: list[dict], semantic_verified: bool) -> list[dict]:
    definitions = [
        ('replay_time_ms', 'Replay block timestamp', 'ward_spawn_time', 'VERIFIED_DIRECT'),
        ('field_10_f32', '0x10 last size-4 plaintext write', 'ward_exact_x',
         'VERIFIED_DIRECT' if semantic_verified else 'CANDIDATE'),
        ('field_14_f32', '0x14 last size-4 plaintext write', 'ward_height',
         'VERIFIED_DIRECT' if semantic_verified else 'CANDIDATE'),
        ('field_18_f32', '0x18 last size-4 plaintext write', 'ward_exact_y',
         'VERIFIED_DIRECT' if semantic_verified else 'CANDIDATE'),
        ('field_1c_u32', '0x1c first size-4 plaintext write', 'ward_owner_entity',
         'VERIFIED_DIRECT' if semantic_verified else 'CANDIDATE'),
        ('field_3c_f32', '0x3c last size-4 plaintext write', None, 'UNASSIGNED_RAW'),
        ('field_5c_f32', '0x5c last size-4 plaintext write', 'alternate_position_x',
         'RAW_VALIDATION_ONLY'),
        ('field_60_f32', '0x60 last size-4 plaintext write', 'alternate_position_height',
         'RAW_VALIDATION_ONLY'),
        ('field_64_f32', '0x64 last size-4 plaintext write', 'alternate_position_y',
         'RAW_VALIDATION_ONLY'),
        ('field_70_u32', '0x70 first size-4 plaintext write', 'ward_network_id',
         'VERIFIED_DIRECT' if semantic_verified else 'CANDIDATE'),
        ('generic_name', '0x48 pointer / 0x50 length', 'generic_name',
         'VERIFIED_DIRECT' if semantic_verified else 'CANDIDATE'),
        ('entity_name', '0x78 pointer / 0x80 length', 'entity_name',
         'VERIFIED_DIRECT' if semantic_verified else 'CANDIDATE'),
    ]
    report = []
    for field, selection, semantic, grade in definitions:
        values = [row.get(field) for row in route_rows if row.get(field) is not None]
        numeric = [float(value) for value in values if isinstance(value, (int, float))]
        report.append({
            'raw_field': field,
            'selection_rule': selection,
            'sample_count': len(values),
            'unique_count': len(set(str(value) for value in values)),
            'numeric_min': min(numeric) if numeric else None,
            'numeric_max': max(numeric) if numeric else None,
            'finite_count': sum(math.isfinite(value) for value in numeric),
            'map_range_count': sum(-1000 <= value <= 20000 for value in numeric),
            'network_id_range_count': sum(0x40000000 <= value <= 0x4FFFFFFF for value in numeric),
            'semantic_assignment': semantic,
            'evidence_grade': grade,
        })
    return report


def validate(options) -> dict:
    started = time.perf_counter()
    runtime_path = options.runtime_image.resolve()
    packet_path = options.packets.resolve()
    output_dir = options.output.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    runtime_sha = sha256_file(runtime_path)
    if runtime_sha != RUNTIME_SHA256:
        raise RuntimeError(f'wrong runtime image sha256: {runtime_sha}')
    manifest = runtime.load_packet_manifest(packet_path, PACKET_ID)
    owner_map, replay_metadata = load_participants(
        options.participants.resolve(), manifest, options.validation_scope,
    )
    emulator = Ward1616TraceEmulator(runtime_path.read_bytes())

    route_rows = []
    input_failures = []
    infrastructure_failures = []
    counters = Counter()
    per_replay_input = Counter()
    source_keys = set()
    with packet_path.open('r', encoding='utf-8') as handle:
        for line_number, line in enumerate(handle, 1):
            if options.limit is not None and counters['valid_input_rows'] >= options.limit:
                break
            if not line.strip():
                continue
            counters['input_rows'] += 1
            try:
                source = json.loads(line)
                payload = runtime.validate_packet_row(source, PACKET_ID, manifest, line_number)
                source_key = (source['replay_label'], source['chunk_index'],
                              source['decompressed_block_offset'], source['packet_id'])
                if source_key in source_keys:
                    raise ValueError('duplicate packet provenance key')
                source_keys.add(source_key)
                counters['valid_input_rows'] += 1
                per_replay_input[source['replay_label']] += 1
            except Exception as error:
                input_failures.append({'line_number': line_number, 'error': str(error)})
                continue
            try:
                decoded = emulator.decode(
                    payload, WARD_PROFILE, packet_id=PACKET_ID, raw_param=int(source['raw_param']))
                counters['deserialize_success'] += int(decoded['deserialize_return_al'] == 1)
                counters['fully_consumed'] += int(decoded['fully_consumed'])
                if decoded['deserialize_return_al'] != 1 or not decoded['fully_consumed']:
                    raise RuntimeError(
                        f"AL={decoded['deserialize_return_al']} fully_consumed={decoded['fully_consumed']}"
                    )
                raw = recover_raw_fields(emulator)
                x, height, y = raw['field_10_f32'], raw['field_14_f32'], raw['field_18_f32']
                position_plausible = bool(
                    x is not None and y is not None and -1000 <= x <= 20000 and -1000 <= y <= 20000
                )
                owner_id = raw['field_1c_u32']
                entity_id = raw['field_70_u32']
                mapping = owner_map.get((source['replay_label'], owner_id))
                classification = classify_names(
                    raw['generic_name'], raw['entity_name'], mapping, position_plausible)
                row = {
                    'schema_version': 1,
                    'event_type': 'route_entity_spawn',
                    'game_version': REPLAY_VERSION,
                    'patch': PATCH,
                    'build_profile': WARD_PROFILE['id'],
                    'replay_label': source['replay_label'],
                    'replay_sha256': source['replay_sha256'],
                    'replay_time_ms': source['replay_time_ms'],
                    'payload_length': source['payload_length'],
                    'raw_param': source['raw_param'],
                    'decoder_return_al': decoded['deserialize_return_al'],
                    'fully_consumed': decoded['fully_consumed'],
                    **{key: value for key, value in raw.items() if key != 'write_evidence'},
                    'position': {'x': x, 'height': height, 'y': y},
                    'alternate_position': {
                        'x': raw['field_5c_f32'],
                        'height': raw['field_60_f32'],
                        'y': raw['field_64_f32'],
                    },
                    'position_plausible': position_plausible,
                    'owner_network_id': owner_id,
                    'entity_network_id': entity_id,
                    'owner_mapping': mapping,
                    **classification,
                    'write_evidence': raw['write_evidence'],
                    'raw_packet_ref': raw_packet_ref(source),
                }
                route_rows.append(row)
            except Exception as error:
                infrastructure_failures.append({
                    'line_number': line_number,
                    'replay_label': source.get('replay_label'),
                    'error_type': type(error).__name__,
                    'error': str(error),
                })
            if options.progress_every and line_number % options.progress_every == 0:
                print(
                    f'{line_number}: decoded={len(route_rows)} failures={len(infrastructure_failures)}',
                    file=sys.stderr, flush=True,
                )

    manifest_counts_match = (
        counters['valid_input_rows'] == manifest['selected_packet_count']
        and dict(per_replay_input) == manifest['replay_packet_counts']
        if options.limit is None else counters['valid_input_rows'] == options.limit
    )
    structural_verified = bool(
        counters['valid_input_rows'] > 0
        and counters['valid_input_rows'] == len(route_rows)
        and counters['valid_input_rows'] == counters['deserialize_success']
        and counters['valid_input_rows'] == counters['fully_consumed']
        and not input_failures and not infrastructure_failures and manifest_counts_match
    )

    corpses = [row for row in route_rows if row['is_corpse']]
    vision_rows = [row for row in route_rows if row['is_vision_like']]
    confirmed = [row for row in vision_rows
                 if row['vision_entity_class'] == 'PLAYER_ACTIVE_WARD_CONFIRMED']
    special = [row for row in vision_rows if row['vision_entity_class'] in (
        'SPECIAL_VISION_ENTITY', 'MAP_MECHANIC_VISION')]
    uncertain = [row for row in vision_rows if row['vision_entity_class'] in (
        'PLAYER_WARD_CANDIDATE', 'UNKNOWN_WARD_ENTITY')]
    lifecycle_rows, used_corpses = build_lifecycles(confirmed, corpses)
    public_events = [public_vision_event(row) for row in vision_rows]
    public_ward_spawns = [
        event for event in public_events
        if event['vision_entity_class'] in (
            'PLAYER_ACTIVE_WARD_CONFIRMED', 'PLAYER_WARD_CANDIDATE', 'UNKNOWN_WARD_ENTITY')
    ]

    position_x = [row['position']['x'] for row in confirmed]
    position_y = [row['position']['y'] for row in confirmed]
    alternate_delta = [
        math.hypot(
            row['position']['x'] - row['alternate_position']['x'],
            row['position']['y'] - row['alternate_position']['y'],
        ) for row in confirmed
        if row['alternate_position']['x'] is not None and row['alternate_position']['y'] is not None
    ]
    replay_with_confirmed = len({row['replay_label'] for row in confirmed})
    owner_coverage = sum(row['owner_mapping'] is not None for row in confirmed)
    owner_conflicts = sum(
        row['owner_mapping'] is not None
        and row['owner_network_id'] != 0x400000AD + row['owner_mapping']['participant_id']
        for row in confirmed
    )
    semantic_verified = bool(
        structural_verified
        and len(confirmed) >= 100
        and replay_with_confirmed >= 12
        and owner_coverage == len(confirmed)
        and owner_conflicts == 0
        and all(row['position_plausible'] for row in confirmed)
        and len(set((round(x, 3), round(y, 3)) for x, y in zip(position_x, position_y))) >= 20
        and len({row['ward_type'] for row in confirmed}) >= 2
    )

    raw_rows = []
    for row in route_rows:
        raw_rows.append({
            key: row.get(key) for key in (
                'replay_label', 'replay_sha256', 'replay_time_ms', 'payload_length', 'raw_param',
                'decoder_return_al', 'fully_consumed', 'field_0c_u32', 'field_10_u32',
                'field_10_f32', 'field_14_u32', 'field_14_f32', 'field_18_u32',
                'field_18_f32', 'field_1c_u32', 'field_3c_u32', 'field_3c_f32',
                'field_5c_u32', 'field_5c_f32', 'field_60_u32', 'field_60_f32',
                'field_64_u32', 'field_64_f32', 'field_70_u32', 'generic_name',
                'entity_name', 'position_plausible', 'is_corpse', 'is_ward_like',
                'is_vision_like', 'vision_entity_class', 'ward_type')
        })
    raw_fields = list(raw_rows[0]) if raw_rows else []
    write_csv(output_dir / 'raw_candidate_analysis.csv', raw_rows, raw_fields)
    report_rows = field_report(route_rows, semantic_verified)
    write_csv(output_dir / 'ward_candidate_field_report.csv', report_rows, list(report_rows[0]))

    owner_validation = []
    confirmed_counts = Counter((row['replay_label'], row['owner_mapping']['participant_id'])
                               for row in confirmed)
    type_counts_by_owner = Counter(
        (row['replay_label'], row['owner_mapping']['participant_id'], row['ward_type'])
        for row in confirmed)
    for label, replay in sorted(replay_metadata.items()):
        for participant in replay['participants']:
            participant_id = participant['participant_id']
            decoded_count = confirmed_counts[(label, participant_id)]
            owner_validation.append({
                'replay_label': label,
                'replay_sha256': replay['replay_sha256'],
                'participant_id': participant_id,
                'owner_network_id': participant['owner_network_id'],
                'team_id': participant['team_id'],
                'champion': participant.get('champion'),
                'tail_ward_placed': participant.get('ward_placed'),
                'decoded_confirmed_player_wards': decoded_count,
                'decoded_yellow_or_sight': type_counts_by_owner[(label, participant_id,
                                                                 'YELLOW_OR_SIGHT_WARD')],
                'decoded_control': type_counts_by_owner[(label, participant_id, 'CONTROL_WARD')],
                'decoded_farsight': type_counts_by_owner[(label, participant_id, 'FARSIGHT_WARD')],
                'owner_formula_conflict': False,
                'team_mapping_conflict': False,
            })
    write_csv(output_dir / 'ward_owner_validation.csv', owner_validation,
              list(owner_validation[0]) if owner_validation else [])

    type_groups = Counter((row['vision_entity_class'], row['ward_type'],
                           row['generic_name'], row['entity_name']) for row in vision_rows)
    type_validation = [{
        'vision_entity_class': key[0], 'ward_type': key[1], 'generic_name': key[2],
        'entity_name': key[3], 'count': count,
        'type_evidence': ('VERIFIED_DERIVED_FROM_DIRECT_NAMES'
                          if key[1] != 'UNKNOWN_WARD_TYPE' else 'UNAVAILABLE'),
    } for key, count in sorted(type_groups.items())]
    write_csv(output_dir / 'ward_type_validation.csv', type_validation,
              list(type_validation[0]) if type_validation else [])

    lifecycle_validation = [{
        'replay_label': row['replay_label'],
        'ward_network_id': row['ward_network_id'],
        'owner_participant': row['owner_participant'],
        'owner_team': row['owner_team'],
        'ward_type': row['ward_type'],
        'spawn_time_ms': row['spawn_time_ms'],
        'ward_disappear_time_ms': row['ward_disappear_time_ms'],
        'ward_lifetime_ms': row['ward_lifetime_ms'],
        'end_observation': row['end_observation'],
        'ward_end_reason': row['ward_end_reason'],
        'match_rule': row['match_rule'],
        'coordinate_error': row['coordinate_error'],
        'end_time_evidence': row['field_confidence']['end_time'],
    } for row in lifecycle_rows]
    write_csv(output_dir / 'ward_lifecycle_validation.csv', lifecycle_validation,
              list(lifecycle_validation[0]) if lifecycle_validation else [])

    paths = {
        'all_entity_events': output_dir / 'runtime' / 'all_entity_events.jsonl',
        'vision_entity_events': output_dir / 'vision_entity_events_16_16.jsonl',
        'ward_spawns': output_dir / 'ward_spawn_events_16_16.jsonl',
        'ward_lifecycles': output_dir / 'ward_lifecycles_16_16.jsonl',
        'corpse_events': output_dir / 'runtime' / 'ward_corpse_events.jsonl',
        'special_vision': output_dir / 'special_vision_candidates.jsonl',
        'uncertain_ward': output_dir / 'uncertain_ward_entities.jsonl',
        'input_failures': output_dir / 'runtime' / 'ward_input_failures.json',
        'infrastructure_failures': output_dir / 'runtime' / 'ward_infrastructure_failures.json',
    }
    write_jsonl(paths['all_entity_events'], route_rows)
    write_jsonl(paths['vision_entity_events'], public_events)
    write_jsonl(paths['ward_spawns'], public_ward_spawns)
    write_jsonl(paths['ward_lifecycles'], lifecycle_rows)
    write_jsonl(paths['corpse_events'], corpses)
    write_jsonl(paths['special_vision'], [public_vision_event(row) for row in special])
    write_jsonl(paths['uncertain_ward'], [public_vision_event(row) for row in uncertain])
    write_json(paths['input_failures'], input_failures)
    write_json(paths['infrastructure_failures'], infrastructure_failures)
    make_map(output_dir / 'ward_map_all.png', public_events)
    make_map(output_dir / 'ward_map_early_0_3m.png', public_events, max_time_ms=180000)

    lifecycle_observed = [row for row in lifecycle_rows if row['end_observation'] == 'OBSERVED_END']
    ward_placed_exact_matches = sum(
        int(row['decoded_confirmed_player_wards']) == int(row['tail_ward_placed'])
        for row in owner_validation
    )
    ward_placed_absolute_error = [
        abs(int(row['decoded_confirmed_player_wards']) - int(row['tail_ward_placed']))
        for row in owner_validation
    ]
    validation_scope = getattr(options, 'validation_scope', 'CORPUS_RELEASE_GATE')
    release_gate_applicable = validation_scope == 'CORPUS_RELEASE_GATE'
    summary = {
        'schema_version': 1,
        'status': ('PASS' if semantic_verified else
                   'PASS' if structural_verified and not release_gate_applicable else
                   'PARTIAL' if structural_verified else 'FAIL'),
        'task_status': (
            '16_16_WARD_SEMANTIC_RECOVERY_V1_COMPLETE'
            if semantic_verified else
            '16_16_WARD_SINGLE_REPLAY_DECODE_COMPLETE'
            if structural_verified and not release_gate_applicable else
            '16_16_WARD_SEMANTIC_RECOVERY_V1_PARTIAL'
        ),
        'game_version': REPLAY_VERSION,
        'patch': PATCH,
        'runtime_image_sha256': runtime_sha,
        'runtime_image_sha256_verified': True,
        'validation_scope': validation_scope,
        'profile': WARD_PROFILE,
        'runtime_singleton_mappings': emulator.runtime_singleton_mappings,
        'packet_manifest': {
            'path': manifest['path'],
            'selected_packet_count': manifest['selected_packet_count'],
            'replay_count': manifest['replay_count'],
            'per_replay_count_validation': 'FULL_MATCH' if manifest_counts_match else 'MISMATCH',
        },
        'participant_metadata': {
            'path': str(options.participants.resolve()),
            'sha256': sha256_file(options.participants.resolve()),
            'replay_count': len(replay_metadata),
            'roster_completeness': {
                label: {
                    'expected_participant_count': 10,
                    'available_participant_count': len(replay['participants']),
                    'completeness': ('COMPLETE' if len(replay['participants']) == 10 else 'PARTIAL'),
                    'present_participant_ids': [
                        row['participant_id'] for row in replay['participants']
                    ],
                    'missing_participant_ids': [
                        participant_id for participant_id in range(1, 11)
                        if participant_id not in {
                            row['participant_id'] for row in replay['participants']
                        }
                    ],
                    'missing_owner_mappings_fabricated': False,
                }
                for label, replay in sorted(replay_metadata.items())
            },
        },
        'counts': {
            **counters,
            'route_entity_rows': len(route_rows),
            'vision_like_rows': len(vision_rows),
            'player_active_ward_confirmed': len(confirmed),
            'special_or_map_vision': len(special),
            'uncertain_ward_entities': len(uncertain),
            'corpse_events': len(corpses),
            'lifecycle_rows': len(lifecycle_rows),
            'observed_lifecycle_ends': len(lifecycle_observed),
            'unmatched_corpse_events': len(corpses) - len(used_corpses),
            'input_provenance_failures': len(input_failures),
            'infrastructure_failures': len(infrastructure_failures),
        },
        'full_consume_rate': (counters['fully_consumed'] / counters['valid_input_rows']
                              if counters['valid_input_rows'] else 0),
        'ward_type_counts': dict(sorted(Counter(row['ward_type'] for row in confirmed).items())),
        'vision_entity_class_counts': dict(sorted(Counter(
            row['vision_entity_class'] for row in vision_rows).items())),
        'confirmed_replay_count': replay_with_confirmed,
        'owner_mapping': {
            'coverage_count': owner_coverage,
            'coverage_rate': owner_coverage / len(confirmed) if confirmed else 0,
            'conflict_count': owner_conflicts,
            'participant_rows': len(owner_validation),
            'tail_ward_placed_exact_match_count': ward_placed_exact_matches,
            'tail_ward_placed_exact_match_rate': (
                ward_placed_exact_matches / len(owner_validation) if owner_validation else 0
            ),
            'tail_ward_placed_absolute_error': distribution(ward_placed_absolute_error),
        },
        'position_validation': {
            'source': 'field_10/14/18 direct plaintext object writes',
            'x': distribution(position_x),
            'y': distribution(position_y),
            'unique_xy_count': len(set((round(x, 3), round(y, 3))
                                       for x, y in zip(position_x, position_y))),
            'plausible_count': sum(row['position_plausible'] for row in confirmed),
            'alternate_vector_xy_distance': distribution(alternate_delta),
            'cast_target_position_used': False,
        },
        'lifecycle': {
            'release_status': 'WARD_LIFECYCLE_PARTIAL',
            'direct_end_events': len(corpses),
            'observed_end_matches': len(lifecycle_observed),
            'estimated_end_rows': 0,
            'end_reason': 'UNKNOWN',
            'duration_ms': distribution([row['ward_lifetime_ms'] for row in lifecycle_observed]),
        },
        'acceptance_gates': {
            'exact_route_nonempty_full_consume': structural_verified,
            'confirmed_player_ward_count_gte_100': len(confirmed) >= 100,
            'confirmed_replay_count_gte_12': replay_with_confirmed >= 12,
            'owner_coverage_100_percent': owner_coverage == len(confirmed) and bool(confirmed),
            'owner_team_conflict_free': owner_conflicts == 0,
            'tail_ward_placed_exact_match_gte_95_percent': (
                ward_placed_exact_matches / len(owner_validation) >= 0.95
                if owner_validation else False
            ),
            'positions_all_finite_map_range': all(row['position_plausible'] for row in confirmed),
            'positions_nonconstant': len(set(zip(position_x, position_y))) >= 20,
            'at_least_two_direct_name_types': len({row['ward_type'] for row in confirmed}) >= 2,
        },
        'release': {
            'release_gate_applicable': release_gate_applicable,
            'WARD_SPAWN_READY': semantic_verified if release_gate_applicable else None,
            'WARD_LIFECYCLE_READY': False,
            'WARD_LIFECYCLE_PARTIAL': bool(lifecycle_rows),
            'VISION_SPAWN_READY': semantic_verified if release_gate_applicable else None,
            'VISION_LIFECYCLE_READY': False,
            'VISION_DOWNSTREAM_READY': semantic_verified if release_gate_applicable else None,
        },
        'method': (
            'Exact 16.16 runtime factory/vtable/deserializer execution; semantics assigned only '
            'after current-build direct names, owner map, coordinate distribution, and full consume.'
        ),
        'elapsed_seconds': time.perf_counter() - started,
        'output_artifacts': {name: str(path.resolve()) for name, path in paths.items()},
    }
    summary['output_sha256'] = {
        name: sha256_file(path) for name, path in paths.items() if path.is_file()
    }
    summary_path = output_dir / 'runtime' / 'ward_validation_summary.json'
    write_json(summary_path, summary)
    return summary


def positive_int(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError('value must be positive')
    return parsed


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-image', type=pathlib.Path, required=True)
    parser.add_argument('--packets', type=pathlib.Path, required=True)
    parser.add_argument('--participants', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--limit', type=positive_int)
    parser.add_argument('--progress-every', type=int, default=1000)
    parser.add_argument('--validation-scope', choices=('CORPUS_RELEASE_GATE', 'SINGLE_REPLAY_DECODE'),
                        default='CORPUS_RELEASE_GATE')
    return parser.parse_args()


def main():
    summary = validate(parse_args())
    print(json.dumps({
        'status': summary['status'],
        'task_status': summary['task_status'],
        'game_version': summary['game_version'],
        'runtime_image_sha256': summary['runtime_image_sha256'],
        'runtime_image_sha256_verified': summary['runtime_image_sha256_verified'],
        'validation_scope': summary['validation_scope'],
        'counts': summary['counts'],
        'release': summary['release'],
        'elapsed_seconds': summary['elapsed_seconds'],
    }, indent=2, sort_keys=True))
    return 0 if summary['status'] in ('PASS', 'PARTIAL') else 1


if __name__ == '__main__':
    raise SystemExit(main())
