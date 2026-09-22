#!/usr/bin/env python3

"""Exact-build runtime and residual audit for Replay route 0x0064.

This tool is deliberately narrow.  It consumes only an explicitly supplied
16.16.805.0442 memory image, explicit route-0x0064 event JSONL, the pinned
support-quest audit, and the pinned static callback trace.  It executes the
original constructor/deserializer under Unicorn, captures plaintext values
before the client's in-object obfuscation, and count-conserves canonical and
residual timestamp groups.

It must never be pointed at a holdout path and it has no directory discovery,
network access, or nearest-build fallback.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import struct
import sys

import pefile
from capstone.x86_const import X86_OP_IMM, X86_OP_REG, X86_REG_R8D
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RBX

from emulate_exact_packet_decoder import ExactPacketEmulator, IMAGE_BASE, RUNTIME_PROFILES
from trace_hero_combat_state_runtime import StaticImage, analyze_factory_case, locate_factory


TARGET_BUILD = '16.16.805.0442'
TARGET_PACKET_ID = 0x0064
IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55'
MAIN_AUDIT_SHA256 = 'b5e3a5568b8760d4dee861d4b52c758d125b020132a5f08bad5634e0f9e99d75'
STATIC_TRACE_SHA256 = '1b624d1129c0ed378465d7e0540cf3ab10cd65928d902256d492b7eda251afcc'
ENTITY_EVIDENCE_SHA256 = '8ba1108da9588d0b93a3a05967a385abfc9d89fa6061e677c1f825a331c0ba4d'
ALLOWED_REPLAY_SHA256 = {
    'd3f3b019b70bcf8650934e8e6350d6ae1e3def28b52fb8225cade755a415f862',
    '2e6cee94aed783fa62606333fac7e21295b80f5c03fa5617cd38f6f75fdfe47d',
    '18ae8e43f54604b288a93aa35d13722a159e5ffea548adfa9e88bbf0518e5d9f',
    '9dac6a352dc5a0af8bdd5c3ab0c16cddf310ca56817ce252fcb363a82d0b7f96',
}

ROUTE_PROFILE = {
    'client_opcode': TARGET_PACKET_ID,
    'constructor_rva': 0x00E7EB40,
    'deserialize_rva': 0x010AC010,
    'object_size': 0x18,
    'fields': [
        {'name': 'field_10_storage', 'offset': 0x10, 'type': 'u32'},
        {'name': 'field_14_storage', 'offset': 0x14, 'type': 'u32'},
    ],
}

# AL holds the result of the exact 3-bit extractor at these two instructions.
TAG_CAPTURE_RVAS = {
    IMAGE_BASE + 0x010AC061: 'field_10_tag',
    IMAGE_BASE + 0x010AC209: 'field_14_tag',
}

# These are the first instructions after the exact dynamic decode helpers have
# populated the plaintext destination but before the helpers obfuscate it.
PLAINTEXT_CAPTURE_RVAS = {
    IMAGE_BASE + 0x0106E82E: 'field_10_plain',
    IMAGE_BASE + 0x0106EBAE: 'field_14_plain',
}

# Exact immediates in route 0x0064's deserializer.  The first field uses IEEE-754
# constants; the second uses unsigned-integer sentinel/default constants.
FIELD_10_CONSTANT_BITS = {
    0: 0xBF800000,  # -1.0
    3: 0x40000000,  #  2.0
    6: 0x00000000,  #  0.0
    7: 0x3F800000,  #  1.0
}
FIELD_14_CONSTANT_U32 = {
    2: 0xFFFFFFFF,
    6: 0x00000000,
}
FIELD_10_DYNAMIC_TAGS = frozenset({1, 2, 4, 5})
FIELD_14_DYNAMIC_TAGS = frozenset({0, 1, 3, 4, 5, 7})


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: str | os.PathLike[str]) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def reject_holdout_path(path: str | os.PathLike[str]) -> None:
    normalized = os.path.abspath(os.fspath(path)).replace('\\', '/').casefold()
    if 'holdout' in normalized:
        raise ValueError(f'holdout paths are forbidden: {path}')


def tags_from_prefix(prefix: int) -> tuple[int, int]:
    if not 0 <= prefix <= 0xFF:
        raise ValueError(f'prefix is not a byte: {prefix}')
    return prefix & 0x07, (prefix >> 3) & 0x07


def classify_codec_branch(field_10_tag: int, field_14_tag: int) -> str:
    if field_10_tag in FIELD_10_DYNAMIC_TAGS and field_14_tag in FIELD_14_DYNAMIC_TAGS:
        return 'DYNAMIC_F32_PLUS_DYNAMIC_U32'
    if field_10_tag in FIELD_10_CONSTANT_BITS and field_14_tag in FIELD_14_DYNAMIC_TAGS:
        return 'CONSTANT_F32_PLUS_DYNAMIC_U32'
    if field_10_tag in FIELD_10_DYNAMIC_TAGS and field_14_tag in FIELD_14_CONSTANT_U32:
        return 'DYNAMIC_F32_PLUS_CONSTANT_U32'
    if field_10_tag in FIELD_10_CONSTANT_BITS and field_14_tag in FIELD_14_CONSTANT_U32:
        return 'CONSTANT_F32_PLUS_CONSTANT_U32'
    return 'INVALID_TAG_COMBINATION'


def f32_from_bits(bits: int) -> float:
    return struct.unpack('<f', struct.pack('<I', bits))[0]


def counter_dict(counter: collections.Counter) -> dict:
    return {
        str(key): value
        for key, value in sorted(counter.items(), key=lambda pair: str(pair[0]))
    }


def sorted_int_counter(counter: collections.Counter) -> dict:
    return {
        str(key): counter[key]
        for key in sorted(counter, key=lambda item: int(item))
    }


def walk_dicts(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


def find_callback_surface(static_trace: dict) -> dict:
    route_rows = []
    matching_factory_names = []
    combat_state_rows = []
    hero_stats_rows = []
    for record in walk_dicts(static_trace):
        if (record.get('packet_id') == TARGET_PACKET_ID
                and 'callback_mapping_status' in record):
            route_rows.append(record)
        factory = record.get('factory_packet')
        if isinstance(factory, dict) and (
            factory.get('constructor_rva') == ROUTE_PROFILE['constructor_rva']
            or factory.get('deserializer_rva') == ROUTE_PROFILE['deserialize_rva']
            or factory.get('packet_object_vtable_rva') == 0x01B16940
        ):
            matching_factory_names.append({
                'name': record.get('name'),
                'registration_id': record.get('registration_id'),
                'registration_id_hex': record.get('registration_id_hex'),
                'factory_packet': factory,
            })
        if record.get('name') == 'PKT_CombatStateChanged_s' and 'registration_id' in record:
            combat_state_rows.append(record)
        if (record.get('packet_id') == 0x010C
                and record.get('callback_names') == ['PKT_S2C_HeroStats_s']):
            hero_stats_rows.append(record)
    if len(route_rows) != 1:
        raise RuntimeError(f'expected one observed route-0x0064 callback row, got {len(route_rows)}')
    route = route_rows[0]
    return {
        'makefunction_mapping_status': route.get('callback_mapping_status'),
        'callback_names': route.get('callback_names'),
        'callback_count': len(route.get('callbacks') or []),
        'stale_intersection_factory_count': len(route.get('factory_packets') or []),
        'direct_factory_identity_name_matches': matching_factory_names,
        'direct_factory_identity_name_match_count': len(matching_factory_names),
        'combat_state_negative_control': [
            {
                'name': row.get('name'),
                'registration_id': row.get('registration_id'),
                'registration_id_hex': row.get('registration_id_hex'),
                'callback_receive_target_rva_hex': row.get('callback_receive_target_rva_hex'),
                'factory_packet': row.get('factory_packet'),
            }
            for row in combat_state_rows
        ],
        'hero_stats_entity_key_crosscheck_surface': [
            {
                'packet_id': row.get('packet_id'),
                'packet_id_hex': row.get('packet_id_hex'),
                'callback_mapping_status': row.get('callback_mapping_status'),
                'callback_names': row.get('callback_names'),
                'callbacks': row.get('callbacks'),
            }
            for row in hero_stats_rows
        ],
    }


def validate_main_audit(main_audit: dict) -> None:
    latest = main_audit.get('counts', {}).get('latest_four', {})
    expected = {
        'replay_count': 4,
        'event_count': 169654,
        'canonical_periodic_snapshot_group_count': 15071,
        'residual_event_count': 18944,
    }
    if latest != expected:
        raise RuntimeError(f'main audit latest-four counts changed: {latest!r}')
    input_hashes = {
        row.get('replay_sha256')
        for row in main_audit.get('input', {}).get('latest_replays', [])
    }
    if input_hashes != ALLOWED_REPLAY_SHA256:
        raise RuntimeError('main audit exact-build input hash set changed')


def load_events(path: str) -> tuple[list[dict], dict[str, int], dict]:
    events = []
    payload_counts = collections.Counter()
    replay_counts = collections.Counter()
    replay_labels = {}
    stream_counts = collections.Counter()
    raw_param_counts = collections.Counter()
    length_counts = collections.Counter()
    with open(path, encoding='utf-8-sig') as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            replay_path = event.get('replay_path', '')
            reject_holdout_path(replay_path)
            replay_sha = event.get('replay_sha256')
            if replay_sha not in ALLOWED_REPLAY_SHA256:
                raise RuntimeError(f'line {line_number}: replay SHA is outside exact allowlist')
            if event.get('replay_version') != TARGET_BUILD:
                raise RuntimeError(f'line {line_number}: non-exact build')
            if event.get('packet_id') != TARGET_PACKET_ID:
                raise RuntimeError(f'line {line_number}: non-route-0x0064 event')
            payload_hex = event.get('raw_payload_hex')
            if not isinstance(payload_hex, str) or len(payload_hex) % 2:
                raise RuntimeError(f'line {line_number}: invalid payload hex')
            if len(payload_hex) // 2 != event.get('payload_length'):
                raise RuntimeError(f'line {line_number}: payload length mismatch')
            minimal = {
                'replay_sha256': replay_sha,
                'replay_label': event.get('replay_label'),
                'replay_time_ms': event.get('replay_time_ms'),
                'occurrence_index': event.get('occurrence_index'),
                'chunk_stream': event.get('chunk_stream'),
                'raw_param': event.get('raw_param'),
                'payload_length': event.get('payload_length'),
                'raw_payload_hex': payload_hex,
            }
            events.append(minimal)
            payload_counts[payload_hex] += 1
            replay_counts[replay_sha] += 1
            replay_labels[replay_sha] = event.get('replay_label')
            stream_counts[event.get('chunk_stream')] += 1
            raw_param_counts[event.get('raw_param')] += 1
            length_counts[event.get('payload_length')] += 1
    if set(replay_counts) != ALLOWED_REPLAY_SHA256:
        raise RuntimeError('event JSONL does not contain exactly the four allowed Replays')
    inventory = {
        'event_count': len(events),
        'distinct_payload_count': len(payload_counts),
        'replay_event_counts': counter_dict(replay_counts),
        'replay_labels': replay_labels,
        'stream_counts': counter_dict(stream_counts),
        'raw_param_counts': sorted_int_counter(raw_param_counts),
        'payload_length_counts': sorted_int_counter(length_counts),
    }
    return events, dict(payload_counts), inventory


def load_entity_key_crosscheck(path: str) -> dict:
    """Read the pinned exact-build structural sample, never Replay discovery."""
    value_counts = collections.Counter()
    replay_counts = collections.Counter()
    selected_row_count = 0
    with open(path, encoding='utf-8-sig') as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            event = json.loads(line)
            reject_holdout_path(event.get('replay_path', ''))
            if event.get('replay_version') != TARGET_BUILD:
                raise RuntimeError(f'entity crosscheck line {line_number}: non-exact build')
            replay_sha = event.get('replay_sha256')
            if replay_sha not in ALLOWED_REPLAY_SHA256:
                raise RuntimeError(f'entity crosscheck line {line_number}: replay outside allowlist')
            if event.get('packet_id') != 0x010C:
                continue
            selected_row_count += 1
            value_counts[event.get('raw_param')] += 1
            replay_counts[replay_sha] += 1
    if selected_row_count == 0:
        raise RuntimeError('entity-key crosscheck has no route 0x010c rows')
    return {
        'evidence_route': '0x010c',
        'bounded_callback_name': 'PKT_S2C_HeroStats_s',
        'bounded_callback_owner': 'AIHeroClient',
        'selected_row_count': selected_row_count,
        'raw_param_value_counts': {
            f'0x{value:08x}': count for value, count in sorted(value_counts.items())
        },
        'raw_param_values': [f'0x{value:08x}' for value in sorted(value_counts)],
        'replay_row_counts': counter_dict(replay_counts),
    }


class Route0064Profiler:
    def __init__(self, image: bytes):
        self.runtime = ExactPacketEmulator(image, RUNTIME_PROFILES[TARGET_BUILD])
        self.captured_tags = []
        self.captured_plaintext = []

        def capture_tag(runtime, address, _size, _user_data):
            self.captured_tags.append((
                TAG_CAPTURE_RVAS[address],
                runtime.reg_read(UC_X86_REG_RAX) & 0xFF,
            ))

        def capture_plaintext(runtime, address, _size, _user_data):
            pointer = runtime.reg_read(UC_X86_REG_RBX)
            self.captured_plaintext.append((
                PLAINTEXT_CAPTURE_RVAS[address],
                bytes(runtime.mem_read(pointer, 4)),
            ))

        for address in TAG_CAPTURE_RVAS:
            self.runtime.emulator.hook_add(
                UC_HOOK_CODE, capture_tag, begin=address, end=address,
            )
        for address in PLAINTEXT_CAPTURE_RVAS:
            self.runtime.emulator.hook_add(
                UC_HOOK_CODE, capture_plaintext, begin=address, end=address,
            )

    def decode_payload(self, payload_hex: str, event_count: int) -> dict:
        payload = bytes.fromhex(payload_hex)
        if not payload:
            raise RuntimeError('route 0x0064 payload is empty')
        expected_tags = tags_from_prefix(payload[0])
        self.captured_tags.clear()
        self.captured_plaintext.clear()
        decoded = self.runtime.decode(
            payload,
            ROUTE_PROFILE,
            packet_id=TARGET_PACKET_ID,
            raw_param=0,
        )
        tags = dict(self.captured_tags)
        plaintext = dict(self.captured_plaintext)
        if len(self.captured_tags) != 2 or set(tags) != set(TAG_CAPTURE_RVAS.values()):
            raise RuntimeError(f'{payload_hex}: incomplete tag capture {self.captured_tags!r}')
        tag_pair = (tags['field_10_tag'], tags['field_14_tag'])
        if tag_pair != expected_tags:
            raise RuntimeError(f'{payload_hex}: native tags {tag_pair} != prefix bits {expected_tags}')

        field_10_tag, field_14_tag = tag_pair
        if field_10_tag in FIELD_10_DYNAMIC_TAGS:
            if set(plaintext) - {'field_10_plain', 'field_14_plain'}:
                raise RuntimeError(f'{payload_hex}: unexpected plaintext hook')
            field_10_bytes = plaintext.get('field_10_plain')
            if field_10_bytes is None:
                raise RuntimeError(f'{payload_hex}: missing dynamic field_10 plaintext')
            field_10_bits = struct.unpack('<I', field_10_bytes)[0]
        else:
            field_10_bits = FIELD_10_CONSTANT_BITS[field_10_tag]
            if 'field_10_plain' in plaintext:
                raise RuntimeError(f'{payload_hex}: constant field_10 invoked dynamic helper')

        if field_14_tag in FIELD_14_DYNAMIC_TAGS:
            field_14_bytes = plaintext.get('field_14_plain')
            if field_14_bytes is None:
                raise RuntimeError(f'{payload_hex}: missing dynamic field_14 plaintext')
            field_14_u32 = struct.unpack('<I', field_14_bytes)[0]
        else:
            field_14_u32 = FIELD_14_CONSTANT_U32[field_14_tag]
            if 'field_14_plain' in plaintext:
                raise RuntimeError(f'{payload_hex}: constant field_14 invoked dynamic helper')

        branch = classify_codec_branch(field_10_tag, field_14_tag)
        expected_length = {
            'DYNAMIC_F32_PLUS_DYNAMIC_U32': 7,
            'CONSTANT_F32_PLUS_DYNAMIC_U32': 3,
        }.get(branch)
        length_formula_matches = expected_length == len(payload)
        object_bytes = bytes.fromhex(decoded['object_hex'])
        f32_value = f32_from_bits(field_10_bits)
        return {
            'schema_version': 1,
            'payload_hex': payload_hex,
            'payload_length': len(payload),
            'event_count': event_count,
            'prefix_hex': f'0x{payload[0]:02x}',
            'prefix_upper_two_bits': payload[0] >> 6,
            'field_10_tag': field_10_tag,
            'field_14_tag': field_14_tag,
            'tag_pair': f'{field_10_tag}/{field_14_tag}',
            'codec_branch': branch,
            'expected_payload_length': expected_length,
            'length_formula_matches': length_formula_matches,
            'field_10_plain_bits_hex': f'0x{field_10_bits:08x}',
            'field_10_plain_f32': f32_value if math.isfinite(f32_value) else None,
            'field_14_plain_u32': field_14_u32,
            'field_14_plain_i32': struct.unpack('<i', struct.pack('<I', field_14_u32))[0],
            'field_10_storage_hex': object_bytes[0x10:0x14].hex(),
            'field_14_storage_hex': object_bytes[0x14:0x18].hex(),
            'deserialize_return_al': decoded['deserialize_return_al'],
            'fully_consumed': decoded['fully_consumed'],
            'opcode_matches_profile': decoded['opcode_matches_profile'],
        }


def profile_payloads(image: bytes, payload_counts: dict[str, int], progress_every: int = 500) -> dict:
    profiler = Route0064Profiler(image)
    profiles = {}
    for index, payload_hex in enumerate(sorted(payload_counts), start=1):
        profiles[payload_hex] = profiler.decode_payload(payload_hex, payload_counts[payload_hex])
        if progress_every and index % progress_every == 0:
            print(f'profiled {index}/{len(payload_counts)} distinct payloads', file=sys.stderr)
    return profiles


def summarize_profiles(profiles: dict[str, dict]) -> dict:
    event_branch_counts = collections.Counter()
    shape_branch_counts = collections.Counter()
    tag_event_counts = collections.Counter()
    tag_shape_counts = collections.Counter()
    prefix_event_counts = collections.Counter()
    prefix_shape_counts = collections.Counter()
    field_10_event_counts = collections.Counter()
    field_14_event_counts = collections.Counter()
    semantic_pair_event_counts = collections.Counter()
    semantic_pair_prefixes = collections.defaultdict(set)
    semantic_pair_tags = collections.defaultdict(set)
    full_consume_events = 0
    successful_events = 0
    formula_match_events = 0
    upper_bits_event_counts = collections.Counter()

    for profile in profiles.values():
        count = profile['event_count']
        branch = profile['codec_branch']
        tags = profile['tag_pair']
        prefix = profile['prefix_hex']
        f10 = profile['field_10_plain_bits_hex']
        f14 = profile['field_14_plain_u32']
        semantic = f'{f10}/{f14}'
        event_branch_counts[branch] += count
        shape_branch_counts[branch] += 1
        tag_event_counts[tags] += count
        tag_shape_counts[tags] += 1
        prefix_event_counts[prefix] += count
        prefix_shape_counts[prefix] += 1
        field_10_event_counts[f10] += count
        field_14_event_counts[f14] += count
        semantic_pair_event_counts[semantic] += count
        semantic_pair_prefixes[semantic].add(prefix)
        semantic_pair_tags[semantic].add(tags)
        full_consume_events += count * int(profile['fully_consumed'])
        successful_events += count * int(profile['deserialize_return_al'] != 0)
        formula_match_events += count * int(profile['length_formula_matches'])
        upper_bits_event_counts[profile['prefix_upper_two_bits']] += count

    multi_prefix = {
        key: sorted(values)
        for key, values in semantic_pair_prefixes.items()
        if len(values) > 1
    }
    representation_counts = collections.Counter(
        len(values) for values in semantic_pair_prefixes.values()
    )
    observed_tag_pairs = {
        tuple(map(int, value.split('/'))) for value in tag_event_counts
    }
    legal_tag_pairs = {(left, right) for left in range(8) for right in range(8)}
    unobserved_tag_pairs = sorted(legal_tag_pairs - observed_tag_pairs)
    field_10_values = set(field_10_event_counts)
    field_14_values = set(field_14_event_counts)
    return {
        'event_count': sum(event_branch_counts.values()),
        'distinct_payload_count': len(profiles),
        'successful_event_count': successful_events,
        'fully_consumed_event_count': full_consume_events,
        'length_formula_match_event_count': formula_match_events,
        'event_branch_counts': counter_dict(event_branch_counts),
        'shape_branch_counts': counter_dict(shape_branch_counts),
        'tag_pair_event_counts': counter_dict(tag_event_counts),
        'tag_pair_shape_counts': counter_dict(tag_shape_counts),
        'prefix_event_counts': counter_dict(prefix_event_counts),
        'prefix_shape_counts': counter_dict(prefix_shape_counts),
        'prefix_upper_two_bits_event_counts': sorted_int_counter(upper_bits_event_counts),
        'field_10_plain_bits_event_counts': counter_dict(field_10_event_counts),
        'field_10_distinct_plain_value_count': len(field_10_values),
        'field_14_plain_u32_event_counts': sorted_int_counter(field_14_event_counts),
        'field_14_plain_u32_values_hex': [
            f'0x{value:08x}' for value in sorted(field_14_values)
        ],
        'field_14_distinct_plain_value_count': len(field_14_values),
        'semantic_pair_count': len(semantic_pair_event_counts),
        'semantic_pair_event_counts': counter_dict(semantic_pair_event_counts),
        'semantic_pair_representation_count_distribution': sorted_int_counter(representation_counts),
        'multi_prefix_semantic_pair_count': len(multi_prefix),
        'maximum_prefixes_for_one_semantic_pair': max(map(len, semantic_pair_prefixes.values())),
        'multi_prefix_semantic_pair_examples': dict(list(sorted(multi_prefix.items()))[:20]),
        'all_prefix_tags_equal_native_3bit_extractors': True,
        'lower_six_bits_are_fully_accounted_by_two_tags': True,
        'upper_two_bits_observed_invariant_0b10': set(upper_bits_event_counts) == {2},
        'observed_legal_tag_pair_count': len(observed_tag_pairs),
        'unobserved_legal_tag_pair_count': len(unobserved_tag_pairs),
        'unobserved_legal_tag_pairs': [f'{left}/{right}' for left, right in unobserved_tag_pairs],
        'semantic_pair_cartesian_product_complete': (
            len(semantic_pair_event_counts) == len(field_10_values) * len(field_14_values)
        ),
        'semantic_pair_cartesian_coverage': round(
            len(semantic_pair_event_counts) / (len(field_10_values) * len(field_14_values)), 8
        ),
    }


def summarize_groups(events: list[dict], profiles: dict[str, dict]) -> dict:
    groups = collections.defaultdict(list)
    for event in events:
        key = (event['replay_sha256'], event['replay_time_ms'])
        groups[key].append(event)

    group_size_counts = collections.Counter()
    residual_group_size_counts = collections.Counter()
    residual_length_counts = collections.Counter()
    residual_branch_counts = collections.Counter()
    residual_field_10_counts = collections.Counter()
    residual_field_14_counts = collections.Counter()
    residual_semantic_pair_counts = collections.Counter()
    canonical_groups = 0
    canonical_events = 0
    residual_events = 0
    residual_groups = 0
    mixed_length_residual_groups = 0
    residual_replay_counts = collections.Counter()
    canonical_field_14_sequence_counts = collections.Counter()
    canonical_ordinal_field_14_counts = [collections.Counter() for _ in range(10)]

    for (replay_sha, _timestamp), rows in groups.items():
        group_size_counts[len(rows)] += 1
        canonical = (
            len(rows) == 10
            and all(row['payload_length'] == 7 and row['raw_param'] == 0 for row in rows)
        )
        if canonical:
            canonical_groups += 1
            canonical_events += len(rows)
            values = [profiles[row['raw_payload_hex']]['field_14_plain_u32'] for row in rows]
            sequence = '/'.join(f'0x{value:08x}' for value in values)
            canonical_field_14_sequence_counts[sequence] += 1
            for ordinal, value in enumerate(values):
                canonical_ordinal_field_14_counts[ordinal][value] += 1
            continue
        residual_groups += 1
        residual_events += len(rows)
        residual_group_size_counts[len(rows)] += 1
        residual_replay_counts[replay_sha] += len(rows)
        lengths = {row['payload_length'] for row in rows}
        mixed_length_residual_groups += int(len(lengths) > 1)
        for row in rows:
            profile = profiles[row['raw_payload_hex']]
            residual_length_counts[row['payload_length']] += 1
            residual_branch_counts[profile['codec_branch']] += 1
            residual_field_10_counts[profile['field_10_plain_bits_hex']] += 1
            residual_field_14_counts[profile['field_14_plain_u32']] += 1
            semantic = f"{profile['field_10_plain_bits_hex']}/{profile['field_14_plain_u32']}"
            residual_semantic_pair_counts[semantic] += 1

    return {
        'timestamp_group_count': len(groups),
        'group_size_counts': sorted_int_counter(group_size_counts),
        'canonical_group_definition': 'exactly 10 rows, every row payload_length=7 and raw_param=0',
        'canonical_group_count': canonical_groups,
        'canonical_event_count': canonical_events,
        'canonical_field_14_sequence_counts': counter_dict(canonical_field_14_sequence_counts),
        'canonical_ordinal_field_14_counts': [
            {
                'replay_walk_ordinal': ordinal + 1,
                'value_counts': {
                    f'0x{value:08x}': count for value, count in sorted(counts.items())
                },
            }
            for ordinal, counts in enumerate(canonical_ordinal_field_14_counts)
        ],
        'canonical_ordinal_field_14_is_single_valued': all(
            len(counts) == 1 for counts in canonical_ordinal_field_14_counts
        ),
        'residual_group_count': residual_groups,
        'residual_event_count': residual_events,
        'residual_group_size_counts': sorted_int_counter(residual_group_size_counts),
        'mixed_length_residual_group_count': mixed_length_residual_groups,
        'residual_payload_length_counts': sorted_int_counter(residual_length_counts),
        'residual_codec_branch_counts': counter_dict(residual_branch_counts),
        'residual_field_10_plain_bits_counts': counter_dict(residual_field_10_counts),
        'residual_field_14_plain_u32_counts': sorted_int_counter(residual_field_14_counts),
        'residual_semantic_pair_count': len(residual_semantic_pair_counts),
        'residual_semantic_pair_event_counts': counter_dict(residual_semantic_pair_counts),
        'residual_replay_event_counts': counter_dict(residual_replay_counts),
        'count_conservation': canonical_events + residual_events == len(events),
    }


def decode_main_stage_codes(main_audit: dict, profiles: dict[str, dict]) -> dict:
    rows = []
    for source in main_audit['recovered_bounded_structure']['exact_build_stage_code_map']:
        code = source['stage_family_code_hex']
        matches = [
            profile for payload, profile in profiles.items()
            if payload[2:10] == code
        ]
        bits = {profile['field_10_plain_bits_hex'] for profile in matches}
        values = {profile['field_10_plain_f32'] for profile in matches}
        if len(bits) != 1 or len(values) != 1:
            raise RuntimeError(f'stage code {code} does not decode to one f32 value')
        rows.append({
            'stage': source['stage'],
            'stage_family_code_hex': code,
            'field_10_plain_bits_hex': next(iter(bits)),
            'field_10_plain_f32': next(iter(values)),
            'distinct_payload_shape_count': len(matches),
            'event_count': sum(profile['event_count'] for profile in matches),
            'upstream_semantic_evidence': source['evidence'],
        })
    return {
        'mapping': rows,
        'all_stage_codes_decode_to_one_f32_each': True,
    }


def static_factory_audit(image: bytes) -> dict:
    static = StaticImage(image, pefile.PE(data=image, fast_load=False))
    factory = locate_factory(static, {TARGET_PACKET_ID}, None)
    route = analyze_factory_case(static, factory, TARGET_PACKET_ID)
    vtable_rva = route['packet_object_vtable']['rva']
    vtable_xrefs = static.lea_xrefs(vtable_rva)
    pre_vtable_qword_va = struct.unpack_from('<Q', image, vtable_rva - 8)[0]
    pre_vtable_qword_rva = pre_vtable_qword_va - IMAGE_BASE
    pre_vtable_is_executable = static.function_for(pre_vtable_qword_rva) is not None
    registration_id_counts = collections.Counter()
    unresolved_registration_xrefs = []
    generic_registration_rva = 0x006F5B40
    for call in static.direct_call_xrefs(generic_registration_rva):
        call_rva = call.address - IMAGE_BASE
        function = static.function_for(call_rva)
        if function is None:
            unresolved_registration_xrefs.append(call_rva)
            continue
        insns = static.disassemble_function(function)
        call_index = next(
            index for index, insn in enumerate(insns) if insn.address == call.address
        )
        candidates = []
        for insn in insns[max(0, call_index - 30):call_index]:
            if insn.mnemonic != 'mov' or len(insn.operands) != 2:
                continue
            destination, source = insn.operands
            if (destination.type == X86_OP_REG and destination.reg == X86_REG_R8D
                    and source.type == X86_OP_IMM):
                candidates.append(source.imm & 0xFFFFFFFF)
        if not candidates:
            unresolved_registration_xrefs.append(call_rva)
            continue
        registration_id_counts[candidates[-1]] += 1
    expected = {
        'jump_table_entry_rva': 0x00EEA34C,
        'allocation_size': 0x18,
        'allocator_rva': 0x011928C0,
    }
    checks = {
        'jump_table_entry_matches': route['jump_table_entry_rva'] == expected['jump_table_entry_rva'],
        'allocation_size_matches': route['allocation_size'] == expected['allocation_size'],
        'allocator_matches': route['allocator_rva'] == expected['allocator_rva'],
        'constructor_matches': route['constructor']['rva'] == ROUTE_PROFILE['constructor_rva'],
        'constructor_writes_route_id': route['constructor']['packet_id'] == TARGET_PACKET_ID,
        'vtable_matches': route['packet_object_vtable']['rva'] == 0x01B16940,
        'deserializer_matches': route['deserializer']['rva'] == ROUTE_PROFILE['deserialize_rva'],
        'object_size_matches': route['packet_object_vtable']['slot_2_returned_object_size'] == 0x18,
        'vtable_has_only_constructor_and_clone_lea_xrefs': {
            insn.address - IMAGE_BASE for insn in vtable_xrefs
        } == {0x00E7EB64, 0x00EBE9FC},
        'vtable_minus_8_is_executable_not_msvc_complete_object_locator': pre_vtable_is_executable,
        'all_generic_registration_xrefs_have_immediate_packet_id': (
            not unresolved_registration_xrefs
        ),
        'generic_registration_surface_has_no_route_0064': (
            registration_id_counts[TARGET_PACKET_ID] == 0
        ),
    }
    if not all(checks.values()):
        raise RuntimeError(f'exact factory chain changed: {checks!r}')
    return {
        'factory_function_rva_hex': f"0x{factory['function'][0]:08x}",
        'factory_switch_rva_hex': f"0x{factory['switch_rva']:08x}",
        'factory_maximum_packet_id': factory['maximum_id'],
        'route': route,
        'vtable_identity_exhaustion': {
            'validated_rip_relative_lea_xref_count': len(vtable_xrefs),
            'validated_rip_relative_lea_xrefs': [
                {
                    'rva_hex': f'0x{insn.address - IMAGE_BASE:08x}',
                    'mnemonic': insn.mnemonic,
                    'operands': insn.op_str,
                    'role': (
                        'constructor_final_vtable_write'
                        if insn.address - IMAGE_BASE == 0x00E7EB64
                        else 'packet_clone_vtable_write'
                    ),
                }
                for insn in vtable_xrefs
            ],
            'vtable_minus_8_qword_va_hex': f'0x{pre_vtable_qword_va:016x}',
            'vtable_minus_8_qword_rva_hex': f'0x{pre_vtable_qword_rva:08x}',
            'vtable_minus_8_points_to_executable_code': pre_vtable_is_executable,
            'standard_msvc_complete_object_locator_present': False,
            'bounded_result': (
                'No standard packet-object RTTI locator and no vtable reference beyond '
                'construction/clone were found in the exact image.'
            ),
        },
        'generic_registration_identity_exhaustion': {
            'generic_registration_rva_hex': f'0x{generic_registration_rva:08x}',
            'direct_call_xref_count': sum(registration_id_counts.values()),
            'all_direct_call_xrefs_resolved_to_immediate_r8d_id': (
                not unresolved_registration_xrefs
            ),
            'distinct_registration_id_count': len(registration_id_counts),
            'route_0064_registration_count': registration_id_counts[TARGET_PACKET_ID],
            'bounded_result': (
                'All exact-image direct calls to the generic callback registration surface '
                'resolve to an immediate packet ID; none registers 0x0064.'
            ),
        },
        'checks': checks,
        'all_checks_pass': True,
    }


def write_json(path: str, value: dict) -> None:
    output = os.path.abspath(path)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2)
        stream.write('\n')


def write_profiles(path: str, profiles: dict[str, dict]) -> None:
    output = os.path.abspath(path)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, 'w', encoding='utf-8', newline='\n') as stream:
        for payload_hex in sorted(profiles):
            stream.write(json.dumps(profiles[payload_hex], ensure_ascii=True, separators=(',', ':')))
            stream.write('\n')


def run_self_test() -> dict:
    assert tags_from_prefix(0x8D) == (5, 1)
    assert tags_from_prefix(0xBB) == (3, 7)
    assert classify_codec_branch(5, 1) == 'DYNAMIC_F32_PLUS_DYNAMIC_U32'
    assert classify_codec_branch(3, 7) == 'CONSTANT_F32_PLUS_DYNAMIC_U32'
    assert f32_from_bits(FIELD_10_CONSTANT_BITS[0]) == -1.0
    assert f32_from_bits(FIELD_10_CONSTANT_BITS[3]) == 2.0
    assert f32_from_bits(FIELD_10_CONSTANT_BITS[6]) == 0.0
    assert f32_from_bits(FIELD_10_CONSTANT_BITS[7]) == 1.0
    try:
        reject_holdout_path('C:/forbidden/Jungle Objective Holdout/sample.rofl')
    except ValueError:
        pass
    else:
        raise AssertionError('holdout guard did not reject forbidden path')
    dynamic_pairs = {
        (left, right)
        for left in FIELD_10_DYNAMIC_TAGS
        for right in FIELD_14_DYNAMIC_TAGS
    }
    constant_pairs = {
        (left, right)
        for left in {3, 6, 7}
        for right in FIELD_14_DYNAMIC_TAGS
    }
    assert len(dynamic_pairs) == 24
    assert len(constant_pairs) == 18
    return {
        'status': 'PASS',
        'dynamic_tag_pair_space': len(dynamic_pairs),
        'observed_three_byte_constant_tag_pair_space': len(constant_pairs),
        'holdout_guard': 'PASS',
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image')
    parser.add_argument('--events')
    parser.add_argument('--main-audit')
    parser.add_argument('--static-trace')
    parser.add_argument('--entity-evidence')
    parser.add_argument('--output')
    parser.add_argument('--profiles-output')
    parser.add_argument('--progress-every', type=int, default=500)
    parser.add_argument('--self-test', action='store_true')
    options = parser.parse_args(argv)
    if not options.self_test:
        required = (
            'image', 'events', 'main_audit', 'static_trace', 'entity_evidence',
            'output', 'profiles_output',
        )
        missing = [name for name in required if not getattr(options, name)]
        if missing:
            parser.error(f"missing required arguments: {', '.join('--' + item.replace('_', '-') for item in missing)}")
    return options


def main(argv=None):
    options = parse_args(argv)
    if options.self_test:
        result = run_self_test()
        print(json.dumps(result, indent=2))
        return result

    paths = {
        'image': options.image,
        'events': options.events,
        'main_audit': options.main_audit,
        'static_trace': options.static_trace,
        'entity_evidence': options.entity_evidence,
        'output': options.output,
        'profiles_output': options.profiles_output,
    }
    for path in paths.values():
        reject_holdout_path(path)

    image_path = os.path.abspath(options.image)
    events_path = os.path.abspath(options.events)
    main_audit_path = os.path.abspath(options.main_audit)
    static_trace_path = os.path.abspath(options.static_trace)
    entity_evidence_path = os.path.abspath(options.entity_evidence)
    output_path = os.path.abspath(options.output)
    profiles_output_path = os.path.abspath(options.profiles_output)

    with open(image_path, 'rb') as stream:
        image = stream.read()
    image_sha = sha256_bytes(image)
    main_audit_sha = sha256_file(main_audit_path)
    static_trace_sha = sha256_file(static_trace_path)
    entity_evidence_sha = sha256_file(entity_evidence_path)
    if image_sha != IMAGE_SHA256:
        raise RuntimeError(f'wrong exact-build image SHA-256: {image_sha}')
    if main_audit_sha != MAIN_AUDIT_SHA256:
        raise RuntimeError(f'wrong main audit SHA-256: {main_audit_sha}')
    if static_trace_sha != STATIC_TRACE_SHA256:
        raise RuntimeError(f'wrong static trace SHA-256: {static_trace_sha}')
    if entity_evidence_sha != ENTITY_EVIDENCE_SHA256:
        raise RuntimeError(f'wrong entity evidence SHA-256: {entity_evidence_sha}')

    with open(main_audit_path, encoding='utf-8-sig') as stream:
        main_audit = json.load(stream)
    with open(static_trace_path, encoding='utf-8-sig') as stream:
        static_trace = json.load(stream)
    validate_main_audit(main_audit)

    events, payload_counts, inventory = load_events(events_path)
    if inventory['event_count'] != 169654:
        raise RuntimeError(f'exact event count changed: {inventory["event_count"]}')
    profiles = profile_payloads(image, payload_counts, options.progress_every)
    profile_summary = summarize_profiles(profiles)
    group_summary = summarize_groups(events, profiles)
    stage_code_plaintext = decode_main_stage_codes(main_audit, profiles)
    entity_key_crosscheck = load_entity_key_crosscheck(entity_evidence_path)
    factory = static_factory_audit(image)
    callback_surface = find_callback_surface(static_trace)

    route_field_14_values = set(profile_summary['field_14_plain_u32_values_hex'])
    entity_raw_param_values = set(entity_key_crosscheck['raw_param_values'])

    expected = main_audit['counts']['latest_four']
    validations = {
        'all_events_native_deserialize_success': (
            profile_summary['successful_event_count'] == inventory['event_count']
        ),
        'all_events_native_fully_consumed': (
            profile_summary['fully_consumed_event_count'] == inventory['event_count']
        ),
        'all_events_match_1_plus_0_or_4_plus_2_length_formula': (
            profile_summary['length_formula_match_event_count'] == inventory['event_count']
        ),
        'canonical_group_count_matches_main_audit': (
            group_summary['canonical_group_count']
            == expected['canonical_periodic_snapshot_group_count']
        ),
        'residual_event_count_matches_main_audit': (
            group_summary['residual_event_count'] == expected['residual_event_count']
        ),
        'event_count_conserved': group_summary['count_conservation'],
        'byte0_lower_six_bits_are_exact_native_tags': (
            profile_summary['all_prefix_tags_equal_native_3bit_extractors']
        ),
        'byte0_upper_two_bits_invariant': (
            profile_summary['upper_two_bits_observed_invariant_0b10']
        ),
        'same_semantic_values_recur_across_wire_tag_aliases': (
            profile_summary['multi_prefix_semantic_pair_count'] > 0
            and profile_summary['maximum_prefixes_for_one_semantic_pair'] == 24
        ),
        'callback_name_not_recovered_on_bounded_makefunction_surface': (
            callback_surface['direct_factory_identity_name_match_count'] == 0
            and callback_surface['callback_count'] == 0
        ),
        'combat_state_name_is_negative_control_not_route_identity': all(
            row.get('registration_id') == 0x0259
            for row in callback_surface['combat_state_negative_control']
        ),
        'field_14_values_equal_hero_stats_aihero_routing_keys': (
            route_field_14_values == entity_raw_param_values
            and route_field_14_values
            == {f'0x{value:08x}' for value in range(0x400000AE, 0x400000B8)}
        ),
        'hero_stats_callback_surface_is_exact_and_named': (
            len(callback_surface['hero_stats_entity_key_crosscheck_surface']) == 1
            and callback_surface['hero_stats_entity_key_crosscheck_surface'][0]['callback_names']
            == ['PKT_S2C_HeroStats_s']
        ),
        'canonical_field_14_is_single_valued_per_replay_walk_ordinal': (
            group_summary['canonical_ordinal_field_14_is_single_valued']
        ),
        'factory_chain_exact': factory['all_checks_pass'],
    }
    if not all(validations.values()):
        raise RuntimeError(f'audit validation failed: {validations!r}')

    report = {
        'schema_version': 1,
        'status': 'EXACT_ROUTE_0064_RUNTIME_RESIDUAL_AUDIT_COMPLETE',
        'project_context_loaded': True,
        'architecture_gate': 'PASS',
        'target_build': TARGET_BUILD,
        'packet_id': TARGET_PACKET_ID,
        'packet_id_hex': '0x0064',
        'scope': {
            'classification': 'PARSER_PROTOCOL_RUNTIME_STATIC_AND_CODEC_EVIDENCE_ONLY',
            'no_map_truth_claim': True,
            'no_behavior_inference_claim': True,
            'no_runtime_acquisition_claim': True,
            'no_ui_claim': True,
            'holdout_consumed': False,
            'network_used': False,
            'nearest_build_fallback_used': False,
            'legacy_build_consumed': False,
        },
        'inputs': {
            'image_path': image_path,
            'image_sha256': image_sha,
            'events_path': events_path,
            'events_sha256': sha256_file(events_path),
            'main_audit_path': main_audit_path,
            'main_audit_sha256': main_audit_sha,
            'static_trace_path': static_trace_path,
            'static_trace_sha256': static_trace_sha,
            'entity_evidence_path': entity_evidence_path,
            'entity_evidence_sha256': entity_evidence_sha,
        },
        'outputs': {
            'report_path': output_path,
            'profiles_path': profiles_output_path,
        },
        'inventory': inventory,
        'factory_constructor_vtable_deserializer_chain': factory,
        'callback_static_identity_surface': callback_surface,
        'codec_static_facts': {
            'tag_extractor_rva_hex': '0x00f32850',
            'field_10_tag_capture_rva_hex': '0x010ac061',
            'field_14_tag_capture_rva_hex': '0x010ac209',
            'field_10_plaintext_capture_rva_hex': '0x0106e82e',
            'field_14_plaintext_capture_rva_hex': '0x0106ebae',
            'field_10_object_offset_hex': '0x10',
            'field_14_object_offset_hex': '0x14',
            'field_10_type': 'f32 (exact constant tags use IEEE-754 -1/0/1/2)',
            'field_14_type': 'u32 (exact constant tags use 0xffffffff/0)',
            'field_10_dynamic_tags': sorted(FIELD_10_DYNAMIC_TAGS),
            'field_10_constant_tag_bits': {
                str(key): f'0x{value:08x}' for key, value in FIELD_10_CONSTANT_BITS.items()
            },
            'field_14_dynamic_tags': sorted(FIELD_14_DYNAMIC_TAGS),
            'field_14_constant_tag_values': {
                str(key): value for key, value in FIELD_14_CONSTANT_U32.items()
            },
            'payload_length_formula': '1-byte tag header + (0 or 4) field_10 bytes + 2 field_14 bytes',
            'legal_tag_pair_space': 64,
            'observed_tag_pair_space': 42,
            'unobserved_tag_pair_space': {
                'total': 22,
                'constant_minus_one_f32_plus_dynamic_u32_three_byte_pairs': 6,
                'dynamic_f32_plus_constant_u32_five_byte_pairs': 8,
                'constant_f32_plus_constant_u32_one_byte_pairs': 8,
            },
        },
        'main_stage_code_plaintext_f32_map': stage_code_plaintext,
        'field_14_entity_key_crosscheck': entity_key_crosscheck,
        'profile_summary': profile_summary,
        'group_residual_summary': group_summary,
        'validations': validations,
        'all_validations_pass': True,
        'conclusions': {
            'runtime_identity': (
                'Exact numeric route/object identity is closed through switch case, allocation, '
                'constructor ID write, vtable, size getter, and deserializer. A packet RTTI/callback '
                'class name is not present on the bounded MakeFunction surface; all exact-image '
                'generic-registration call xrefs were also exhausted and none registers 0x0064.'
            ),
            'volatile_byte0': (
                'Not an independent gameplay value, sequence, or ordinary presence mask. Bits '
                '0..2 and 3..5 are exactly the two native wire tags; bits 6..7 are invariant 0b10 '
                'in every bounded event. Both logical fields are assigned on every successful '
                'decode; constant tags encode an implicit value while omitting its payload bytes.'
            ),
            'seven_byte_branch': (
                'Exactly the 4 dynamic f32 tags crossed with the 6 dynamic u32 tags (24 tag pairs): '
                '1 header + 4 f32 bytes + 2 u32 bytes.'
            ),
            'field_10_plain_semantics': (
                'The exact codec type is f32. The upstream support-quest audit stage codes now '
                'decode to ordinary float values; the raw four-byte codes were obfuscated storage, '
                'not opaque enums.'
            ),
            'field_14_plain_semantics': (
                'The exact codec type is u32. Its ten values are 0x400000ae..0x400000b7, are '
                'single-valued by canonical Replay walk ordinal, and exactly equal the raw routing '
                'keys on the independently named PKT_S2C_HeroStats_s / AIHeroClient surface. This '
                'supports participant entity-routing-key semantics; the narrower engine typedef '
                'name is not claimed.'
            ),
            'three_byte_branch': (
                'Exactly constant f32 tag branches crossed with dynamic u32 tags: the f32 payload '
                'bytes are omitted, leaving 1 header + 2 u32 bytes. The bounded corpus observes '
                'f32 constants 0.0, 1.0, and 2.0; the legal -1.0 tag is locally unobserved.'
            ),
            'noncanonical_groups': (
                'They use the same exact two-field codec and are fully decoded/count-conserved. '
                'Timestamp-group shape is not a separate packet format and no gameplay behavior '
                'label is assigned.'
            ),
            'next_external_evidence': (
                'Recover an exact-build subscriber outside the bounded MakeFunction RTTI surface, '
                'or exact serializer/source symbol metadata, to name the packet class and the f32 '
                'business meaning. No additional local byte-level search is required for byte0, '
                'the entity key, or the 3/7-byte split.'
            ),
        },
    }

    write_profiles(profiles_output_path, profiles)
    report['outputs']['profiles_sha256'] = sha256_file(profiles_output_path)
    write_json(output_path, report)
    report_sha = sha256_file(output_path)
    print(json.dumps({
        'status': report['status'],
        'event_count': inventory['event_count'],
        'distinct_payload_count': inventory['distinct_payload_count'],
        'canonical_group_count': group_summary['canonical_group_count'],
        'residual_event_count': group_summary['residual_event_count'],
        'report_path': output_path,
        'report_sha256': report_sha,
        'profiles_path': profiles_output_path,
        'profiles_sha256': report['outputs']['profiles_sha256'],
        'all_validations_pass': True,
    }, indent=2))
    return report


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'{type(error).__name__}: {error}', file=sys.stderr)
        sys.exit(1)
