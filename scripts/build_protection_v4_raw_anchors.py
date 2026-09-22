#!/usr/bin/env python3

import argparse
import collections
import hashlib
import json
import os


ANCHOR_SPECS = (
    {
        'anchor_id': 'lulu_e_nilah_shield',
        'replay_label': 'HN1-11154791609',
        'occurrence_index': 361,
        'caster_champion': 'Lulu',
        'spell_identifier': 'LuluE',
    },
    {
        'anchor_id': 'karma_e_tristana_shield',
        'replay_label': 'HN1-11154791609',
        'occurrence_index': 410,
        'caster_champion': 'Karma',
        'spell_identifier': 'KarmaSolKimShield',
    },
    {
        'anchor_id': 'janna_e_caitlyn_shield',
        'replay_label': 'HN1-11158276256',
        'occurrence_index': 14692,
        'caster_champion': 'Janna',
        'spell_identifier': 'EyeOfTheStorm',
    },
    {
        'anchor_id': 'yuumi_e_self_shield',
        'replay_label': 'HN1-11172852368',
        'occurrence_index': 25231,
        'caster_champion': 'Yuumi',
        'spell_identifier': 'YuumiE',
    },
    {
        'anchor_id': 'seraphine_w_receive_only_shield',
        'replay_label': 'HN1-11177593199',
        'occurrence_index': 33908,
        'caster_champion': 'Seraphine',
        'spell_identifier': 'SeraphineW',
    },
    {
        'anchor_id': 'milio_e_xerath_shield',
        'replay_label': 'HN1-11181975536',
        'occurrence_index': 56926,
        'caster_champion': 'Milio',
        'spell_identifier': 'MilioE',
    },
    {
        'anchor_id': 'soraka_w_senna_multi_effect_heal',
        'replay_label': 'HN1-11177593199',
        'occurrence_index': 34679,
        'caster_champion': 'Soraka',
        'spell_identifier': 'SorakaW',
    },
    {
        'anchor_id': 'soraka_r_senna_heal',
        'replay_label': 'HN1-11177593199',
        'occurrence_index': 33550,
        'caster_champion': 'Soraka',
        'spell_identifier': 'SorakaR',
    },
    {
        'anchor_id': 'milio_w_xerath_heal',
        'replay_label': 'HN1-11181975536',
        'occurrence_index': 57296,
        'caster_champion': 'Milio',
        'spell_identifier': 'MilioW',
    },
    {
        'anchor_id': 'milio_r_xerath_heal',
        'replay_label': 'HN1-11181975536',
        'occurrence_index': 58902,
        'caster_champion': 'Milio',
        'spell_identifier': 'MilioR',
    },
)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Build compact, cross-linked V4 heal/shield RAW anchors.',
    )
    parser.add_argument('--decoded', required=True)
    parser.add_argument('--replays-root', required=True)
    parser.add_argument('--output', required=True)
    return parser.parse_args()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def read_jsonl(path):
    with open(path, encoding='utf-8') as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def compact_packet_ref(row):
    reference = row.get('raw_packet_ref') or {}
    keys = (
        'source_path',
        'replay_path',
        'replay_sha256',
        'chunk_index',
        'chunk_id',
        'chunk_stream',
        'chunk_file_offset',
        'compressed_body_offset',
        'decompressed_block_offset',
        'decompressed_payload_offset',
        'replay_time_ms',
        'occurrence_index',
        'packet_id',
        'payload_length',
        'payload_sha256',
        'raw_param',
        'raw_param_hex',
    )
    return {key: reference.get(key) for key in keys if key in reference}


def compact_protection_event(row, include_raw=True):
    result = {
        'replay_time_ms': row['replay_time_ms'],
        'occurrence_index': row['occurrence_index'],
        'event_id_hex': row['event_id_hex'],
        'event_name': row['event_name'],
        'parameter_type': row['parameter_type'],
        'schema_id_hex': row['schema_id_hex'],
        'parameter_size': row['parameter_size'],
        'source_network_id_hex': row['source_network_id_hex'],
        'target_network_id_hex': row['target_network_id_hex'],
        'amount': row['amount'],
        'amount_bits_hex': row['amount_bits_hex'],
        'parameter_blob_hex': row['parameter_blob_hex'],
        'parameter_blob_sha256': row['parameter_blob_sha256'],
        'semantic_status': row['semantic_status'],
        'route_kind': row['route_kind'],
        'canonical_route': row['canonical_route'],
        'raw_packet_ref': compact_packet_ref(row),
    }
    if row['event_id'] == 0x4B:
        result['amount_interpretation'] = row['heal_amount_interpretation']
    else:
        result['amount_interpretation'] = row['shield_amount_interpretation']
    if include_raw:
        result.update({
            'raw_param': row.get('raw_param'),
            'raw_param_hex': row.get('raw_param_hex'),
            'raw_payload_hex': row.get('raw_payload_hex'),
            'raw_payload_sha256': row.get('raw_payload_sha256'),
            'outer_object_hex': row.get('outer_object_hex'),
        })
    return result


def compact_spell(row):
    return {
        'replay_time_ms': row['replay_time_ms'],
        'caster_network_id_hex': f"0x{row['caster_network_id']:08x}",
        'caster_champion': row.get('caster_champion'),
        'spell_slot': row.get('spell_slot'),
        'spell_identifier': row.get('spell_identifier'),
        'protection_cast_kind': row.get('protection_cast_kind'),
        'targets': [
            {
                'network_id_hex': f"0x{target['network_id']:08x}",
                'participant_id': target.get('participant_id'),
                'champion': target.get('champion'),
                'entity_type': target.get('entity_type'),
            }
            for target in row.get('targets') or []
        ],
        'semantic_status': row.get('semantic_status'),
        'raw_packet_ref': compact_packet_ref(row),
        'raw_param': row.get('raw_param'),
        'raw_param_hex': row.get('raw_param_hex'),
        'raw_payload_hex': row.get('raw_payload_hex'),
        'raw_payload_sha256': row.get('raw_payload_sha256'),
    }


def compact_buff(row):
    source_id = row.get('source_network_id')
    target_id = row.get('target_network_id')
    return {
        'replay_time_ms': row['replay_time_ms'],
        'buff_operation': row.get('buff_operation'),
        'source_network_id_hex': (
            f'0x{source_id:08x}' if source_id is not None else None
        ),
        'target_network_id_hex': (
            f'0x{target_id:08x}' if target_id is not None else None
        ),
        'buff_slot': row.get('buff_slot'),
        'buff_name_hash_hex': row.get('buff_name_hash_hex'),
        'stack_count': row.get('stack_count'),
        'duration_seconds': row.get('duration_seconds'),
        'origin_spell_identifier': row.get('origin_spell_identifier'),
        'semantic_status': row.get('semantic_status'),
        'raw_packet_ref': compact_packet_ref(row),
        'raw_param': row.get('raw_param'),
        'raw_param_hex': row.get('raw_param_hex'),
        'raw_payload_hex': row.get('raw_payload_hex'),
        'raw_payload_sha256': row.get('raw_payload_sha256'),
    }


def select_spell(spells, spec, event):
    candidates = [
        row
        for row in spells
        if row.get('replay_time_ms') == event['replay_time_ms']
        and row.get('caster_network_id') == event['source_network_id']
        and row.get('caster_champion') == spec['caster_champion']
        and row.get('spell_identifier') == spec['spell_identifier']
    ]
    if not candidates:
        raise RuntimeError(f"no exact CastSpell match for {spec['anchor_id']}")
    unique = {}
    for row in candidates:
        unique.setdefault(row.get('raw_payload_sha256'), row)
    candidates = list(unique.values())
    candidates.sort(
        key=lambda row: (
            event['target_network_id'] not in {
                target.get('network_id') for target in row.get('targets') or []
            },
            (row.get('raw_packet_ref') or {}).get('decompressed_payload_offset', 0),
        ),
    )
    return candidates[0]


def select_buffs(buffs, event, spell_identifier):
    same_time_source = [
        row
        for row in buffs
        if row.get('replay_time_ms') == event['replay_time_ms']
        and row.get('source_network_id') == event['source_network_id']
    ]
    named = [
        row
        for row in same_time_source
        if row.get('origin_spell_identifier') == spell_identifier
    ]
    selected = named or [
        row
        for row in same_time_source
        if row.get('target_network_id') == event['target_network_id']
    ]
    selected.sort(
        key=lambda row: (
            (row.get('raw_packet_ref') or {}).get('chunk_index', 0),
            (row.get('raw_packet_ref') or {}).get('decompressed_payload_offset', 0),
        ),
    )
    return selected


def main():
    options = parse_args()
    decoded_path = os.path.abspath(options.decoded)
    replays_root = os.path.abspath(options.replays_root)
    output_path = os.path.abspath(options.output)

    rows = list(read_jsonl(decoded_path))
    by_key = {
        (row['replay_label'], row['occurrence_index']): row
        for row in rows
    }
    by_time = collections.defaultdict(list)
    for row in rows:
        by_time[(row['replay_label'], row['replay_time_ms'])].append(row)

    replay_cache = {}
    anchors = []
    for spec in ANCHOR_SPECS:
        key = (spec['replay_label'], spec['occurrence_index'])
        event = by_key.get(key)
        if event is None:
            raise RuntimeError(f"missing selected event for {spec['anchor_id']}: {key}")
        replay_label = spec['replay_label']
        if replay_label not in replay_cache:
            replay_dir = os.path.join(replays_root, replay_label)
            replay_cache[replay_label] = {
                'spells': list(read_jsonl(os.path.join(replay_dir, 'spell_events.jsonl'))),
                'buffs': list(read_jsonl(os.path.join(replay_dir, 'buff_events.jsonl'))),
            }
        spell = select_spell(replay_cache[replay_label]['spells'], spec, event)
        target_ids = {
            target.get('network_id') for target in spell.get('targets') or []
        }
        if event['target_network_id'] not in target_ids:
            raise RuntimeError(f"CastSpell target mismatch for {spec['anchor_id']}")
        buffs = select_buffs(
            replay_cache[replay_label]['buffs'],
            event,
            spec['spell_identifier'],
        )

        route_pair = None
        if event['event_id'] == 0xED:
            prior = by_key.get((replay_label, event['occurrence_index'] - 1))
            if (
                prior is not None
                and prior['event_id'] == 0xEE
                and prior['replay_time_ms'] == event['replay_time_ms']
                and prior['parameter_blob_hex'] == event['parameter_blob_hex']
            ):
                route_pair = compact_protection_event(prior)

        same_time = [
            compact_protection_event(row, include_raw=False)
            for row in by_time[(replay_label, event['replay_time_ms'])]
            if row['source_network_id'] == event['source_network_id']
            and row['occurrence_index'] != event['occurrence_index']
        ]
        same_time.sort(key=lambda row: row['occurrence_index'])

        anchors.append({
            'anchor_id': spec['anchor_id'],
            'replay_label': replay_label,
            'protection_event': compact_protection_event(event),
            'paired_grant_route_event': route_pair,
            'same_time_related_protection_events': same_time,
            'exact_same_time_cast_spell': compact_spell(spell),
            'exact_same_time_buff_events': [compact_buff(row) for row in buffs],
            'validation': {
                'timestamp_exact': spell['replay_time_ms'] == event['replay_time_ms'],
                'caster_exact': spell['caster_network_id'] == event['source_network_id'],
                'target_present_in_cast_targets': event['target_network_id'] in target_ids,
                'schema_matches_expected': event['schema_matches_expected'],
                'parameter_size_matches_expected': (
                    event['parameter_size_matches_expected']
                ),
                'fully_consumed': event['fully_consumed'],
                'shield_route_pair_status': (
                    'EXACT_GRANT_THEN_RECEIVE_OCCURRENCE_DELTA_1'
                    if route_pair is not None
                    else (
                        'RECEIVE_ONLY_NO_GRANT_TWIN'
                        if event['event_id'] == 0xED
                        else 'NOT_APPLICABLE'
                    )
                ),
                'buff_match_status': (
                    'EXACT_SAME_TIME_SOURCE_AND_SPELL_OR_TARGET'
                    if buffs
                    else 'NO_EXACT_SAME_TIME_RELEVANT_BUFF_ROW'
                ),
            },
        })

    event_counts = collections.Counter(
        anchor['protection_event']['event_name'] for anchor in anchors
    )
    result = {
        'schema_version': 1,
        'status': 'PASS',
        'method': (
            'Fixed diverse anchors selected from the full exact PKT_OnEvent_s '
            'decode and joined only by exact replay timestamp, source, target, '
            'and decoded CastSpell identity.'
        ),
        'decoded_path': decoded_path,
        'decoded_sha256': sha256_file(decoded_path),
        'replays_root': replays_root,
        'anchor_count': len(anchors),
        'event_counts': dict(sorted(event_counts.items())),
        'all_exact_timestamp_cast_matches': all(
            anchor['validation']['timestamp_exact'] for anchor in anchors
        ),
        'all_exact_caster_matches': all(
            anchor['validation']['caster_exact'] for anchor in anchors
        ),
        'all_cast_target_matches': all(
            anchor['validation']['target_present_in_cast_targets']
            for anchor in anchors
        ),
        'limitations': [
            'Heal amount is DIRECT_REPORTED_AMOUNT; raw versus effective versus overheal is unresolved.',
            'Shield amount is direct application/generated amount; remaining, absorbed, and unused are unavailable.',
            'Buff rows validate lifecycle/caster/target correlation only and do not carry protection magnitude.',
            'No OnDamageShielded (0x00ef) row exists in the 14-replay corpus.',
        ],
        'anchors': anchors,
    }
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, ensure_ascii=True, indent=2)
        stream.write('\n')
    print(json.dumps({
        'status': result['status'],
        'anchor_count': result['anchor_count'],
        'event_counts': result['event_counts'],
        'all_exact_timestamp_cast_matches': result['all_exact_timestamp_cast_matches'],
        'all_exact_caster_matches': result['all_exact_caster_matches'],
        'all_cast_target_matches': result['all_cast_target_matches'],
        'output_path': output_path,
        'output_sha256': sha256_file(output_path),
    }, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(f'{type(error).__name__}: {error}')
