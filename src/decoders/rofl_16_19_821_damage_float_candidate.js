'use strict';

const { replaySourceError } = require('./replay_source_integrity');
const { assessHeroStatsTail821, scanHeroStatsPackets821 } =
  require('./rofl_16_19_821_hero_stats_candidate');
const {
  RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256, decodeRuntimeCountByte,
} = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const EVIDENCE_STATUS = 'CANDIDATE_821_NATIVE_KEYFRAME_F32_AND_REPLAY_TAIL';
const COMMON_LIMITS = Object.freeze([
  'Exact 821 native 0x0089 decoding fully consumes all 3270 observed bodies into a 1260-byte transformed vector; these offset labels remain Replay-tail candidates.',
  'Cumulative keyframe snapshots do not identify individual damage events, targets, sources, mitigation actions, or exact event times.',
  'Replay tail gaps are measured and retained without interpolation; final snapshots need not equal final tails.',
]);

function field(tailField, blobOffset, valueKey, floorKey, exactFinalMatches) {
  return Object.freeze({
    replay_tail_field: tailField,
    blob_f32le_offset_candidate: blobOffset,
    raw_payload_byte_offsets: Object.freeze(Array.from({ length: 4 }, (_, i) =>
      1262 - blobOffset - i).reverse()),
    value_key: valueKey,
    floor_key: floorKey,
    final_floor_matches_in_110_series: exactFinalMatches,
  });
}

const FIELDS = Object.freeze({
  damage_to_champions: field('TOTAL_DAMAGE_DEALT_TO_CHAMPIONS', 0x1e0,
    'damage_to_champions_raw_f32_candidate', 'damage_to_champions_floor_candidate', 53),
  total_damage_taken: field('TOTAL_DAMAGE_TAKEN', 0x1f0,
    'total_damage_taken_raw_f32_candidate', 'total_damage_taken_floor_candidate', 44),
  total_damage_dealt: field('TOTAL_DAMAGE_DEALT', 0x1d0,
    'total_damage_dealt_raw_f32_candidate', 'total_damage_dealt_floor_candidate', 40),
  damage_taken_from_champions: field('TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS', 0x200,
    'damage_taken_from_champions_raw_f32_candidate',
    'damage_taken_from_champions_floor_candidate', 55),
  damage_self_mitigated: field('TOTAL_DAMAGE_SELF_MITIGATED', 0x208,
    'damage_self_mitigated_raw_f32_candidate',
    'damage_self_mitigated_floor_candidate', 45),
  building_or_turret_damage: field('TOTAL_DAMAGE_DEALT_TO_BUILDINGS', 0x210,
    'building_or_turret_damage_raw_f32_candidate',
    'building_or_turret_damage_floor_candidate', 82),
  objective_damage: field('TOTAL_DAMAGE_DEALT_TO_OBJECTIVES', 0x218,
    'objective_damage_raw_f32_candidate', 'objective_damage_floor_candidate', 82),
});

function profile(capability, slug, fields) {
  return Object.freeze({
    id: `rofl-16.19.821.7343-kr-${slug}-keyframe-f32-candidate-v1`,
    replay_version: BUILD,
    capability,
    status: 'CANDIDATE',
    enabled: true,
    replay_block_packet_id: 0x0089,
    stream_tags: Object.freeze([2]),
    payload_length: 1263,
    payload_prefix_hex: '6700de',
    fields: Object.freeze(fields),
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    evidence_scope: '11 exact-build KR Replays, 327 keyframes, 3270 hero packets and 110 participant sequences; each selected f32 starts at zero, is finite nonnegative, monotone and bounded by its corresponding Replay tail; all five offsets rank first among 315 aligned f32 candidates by final-tail absolute error',
    known_limits: COMMON_LIMITS,
  });
}

const PROFILES = Object.freeze({
  hero_damage_totals_snapshot: profile('hero_damage_totals_snapshot', 'hero-damage-totals',
    [FIELDS.damage_to_champions, FIELDS.total_damage_dealt, FIELDS.total_damage_taken]),
  hero_damage_taken_from_champions_snapshot: profile(
    'hero_damage_taken_from_champions_snapshot', 'hero-damage-taken-from-champions',
    [FIELDS.damage_taken_from_champions]),
  hero_damage_self_mitigated_snapshot: profile(
    'hero_damage_self_mitigated_snapshot', 'hero-damage-self-mitigated',
    [FIELDS.damage_self_mitigated]),
  hero_structure_objective_damage_snapshot: Object.freeze({
    ...profile('hero_structure_objective_damage_snapshot',
      'hero-structure-objective-damage',
      [FIELDS.building_or_turret_damage, FIELDS.objective_damage]),
    mirror_blob_f32le_offset_candidate: 0x214,
    mirror_replay_tail_field: 'TOTAL_DAMAGE_DEALT_TO_TURRETS',
    evidence_scope: '11 exact-build KR Replays, 327 keyframes and 3270 hero packets; 110 zero-start, finite, monotone, tail-bounded participant sequences; final floors match 82/110 building and 82/110 objective tails. Vector 0x210 and 0x214 mirror in all observed packets; BUILDINGS and TURRETS tails coincide for all 110 participants.',
    known_limits: Object.freeze([...COMMON_LIMITS,
      'The two mirrored structure offsets and equal BUILDINGS/TURRETS tails do not distinguish building damage from turret damage. This capability requires their equality and keeps the field label ambiguous.',
      'The objective total is a snapshot; it does not identify the target objective or a single attack.',
    ]),
  }),
});

function assessHeroDamageSnapshotTail821(replay, capability) {
  const selected = PROFILES[capability];
  if (!selected) return { status: 'UNSUPPORTED',
    error: `unknown 821 damage snapshot capability: ${capability}` };
  const values_by_tail_field = {};
  for (const selectedField of selected.fields) {
    const assessed = assessHeroStatsTail821(replay, selectedField.replay_tail_field);
    if (assessed.status !== 'PASS') return assessed;
    values_by_tail_field[selectedField.replay_tail_field] = assessed.values;
  }
  if (selected.mirror_replay_tail_field) {
    const assessed = assessHeroStatsTail821(replay, selected.mirror_replay_tail_field);
    if (assessed.status !== 'PASS') return assessed;
    const primary = values_by_tail_field[selected.fields[0].replay_tail_field];
    if (assessed.values.some((value, index) => value !== primary[index])) {
      return { status: 'UNSUPPORTED',
        error: 'Replay tail BUILDINGS and TURRETS differ; the observed 821 mirror cannot distinguish them' };
    }
    values_by_tail_field[selected.mirror_replay_tail_field] = assessed.values;
  }
  return { status: 'PASS', values_by_tail_field };
}

function decodeField(payload, selectedField) {
  const offset = selectedField.blob_f32le_offset_candidate;
  const rawOffsets = Array.from({ length: 4 }, (_, i) => 1262 - offset - i);
  const decoded = Buffer.from(rawOffsets.map((rawOffset) =>
    decodeRuntimeCountByte(payload[rawOffset])));
  return {
    value: decoded.readFloatLE(0),
    raw_hex: Buffer.from(rawOffsets.slice().reverse()
      .map((rawOffset) => payload[rawOffset])).toString('hex'),
  };
}

function decodeHeroDamageSnapshotCandidates821(replay, capability, precollected = null) {
  const selected = PROFILES[capability];
  if (!selected) return { status: 'UNSUPPORTED', event_count: null, events: null,
    error: `unknown 821 damage snapshot capability: ${capability}` };
  const base = {
    profile_id: selected.id,
    input_packet_id: 0x0089,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    runtime_image_used: false,
    runtime_image_status: 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED',
    known_limits: [...selected.known_limits],
  };
  const fail = (status, error, details = {}) => ({
    ...base, status, event_count: null, events: null, error, ...details,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `${capability} candidate supports only ${BUILD}`);
  }
  if (precollected === null) {
    let sourceError;
    try { sourceError = replaySourceError(replay); } catch (error) { sourceError = error.message; }
    if (sourceError) return fail('DECODE_FAILED', `Replay source failed: ${sourceError}`);
  }
  const tails = assessHeroDamageSnapshotTail821(replay, capability);
  if (tails.status !== 'PASS') return fail(tails.status, tails.error);
  const collected = scanHeroStatsPackets821(replay, precollected, capability);
  if (collected.status !== 'PASS') {
    return fail(collected.status, collected.error, collected.details);
  }
  const { frames, scan } = collected;
  const previous = Object.fromEntries(selected.fields.map((selectedField) =>
    [selectedField.replay_tail_field, Array(10).fill(null)]));
  const previousTimes = Array(10).fill(null);
  const previousRefs = Array(10).fill(null);
  const events = [];
  for (const frame of frames) {
    for (const row of frame) {
      const { block, participantId, ref } = row;
      const index = participantId - 1;
      const event = {
        event_type: `${capability.toUpperCase()}_CANDIDATE`,
        game_version: BUILD,
        patch: '16.19',
        build_profile: selected.id,
        replay_sha256: replay.source_sha256,
        replay_time_ms: block.timestamp_ms,
        hero_raw_param: row.rawParam,
        participant_id_candidate: participantId,
        raw_payload_field_bytes_hex: {},
        observation_kind: 'KEYFRAME_SNAPSHOT',
        confidence: 'CANDIDATE',
        semantic_status: EVIDENCE_STATUS,
        field_confidence: {
          replay_time_ms: 'VERIFIED_DIRECT',
          hero_raw_param: 'VERIFIED_DIRECT',
          participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
          raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
        },
        raw_packet_ref: ref,
        known_limits: [...selected.known_limits],
      };
      for (const selectedField of selected.fields) {
        const tailField = selectedField.replay_tail_field;
        const { value, raw_hex } = decodeField(block.payload, selectedField);
        const floor = Math.floor(value);
        const mismatch = (error) => fail('DECODE_FAILED', error, {
          ...scan, first_unmatched_packet_ref: ref,
        });
        if (!Number.isFinite(value) || value < 0 || !Number.isSafeInteger(floor)) {
          return mismatch(`${tailField} f32 is not finite, nonnegative, and safely bounded`);
        }
        if (previous[tailField][index] === null && value !== 0) {
          return mismatch(`participant ${participantId} first ${tailField} f32 differs from observed zero start`);
        }
        if (previous[tailField][index] !== null && value < previous[tailField][index]) {
          return mismatch(`participant ${participantId} has decreasing ${tailField} f32`);
        }
        if (floor > tails.values_by_tail_field[tailField][index]) {
          return mismatch(`participant ${participantId} exceeds Replay tail ${tailField}`);
        }
        previous[tailField][index] = value;
        event.raw_payload_field_bytes_hex[tailField] = raw_hex;
        event[selectedField.value_key] = value;
        event[selectedField.floor_key] = floor;
        event.field_confidence[selectedField.value_key] = EVIDENCE_STATUS;
        event.field_confidence[selectedField.floor_key] = EVIDENCE_STATUS;
      }
      if (selected.mirror_blob_f32le_offset_candidate !== undefined) {
        const mirrored = decodeField(block.payload, {
          blob_f32le_offset_candidate: selected.mirror_blob_f32le_offset_candidate,
        });
        const primary = event[FIELDS.building_or_turret_damage.value_key];
        if (!Number.isFinite(mirrored.value) || mirrored.value !== primary) {
          return fail('DECODE_FAILED', '0x210/0x214 structure f32 mirror differs', {
            ...scan, first_unmatched_packet_ref: ref,
          });
        }
        event.raw_payload_field_bytes_hex.MIRROR_0x214 = mirrored.raw_hex;
        event.structure_damage_mirror_raw_f32_candidate = mirrored.value;
        event.field_confidence.structure_damage_mirror_raw_f32_candidate =
          EVIDENCE_STATUS;
      }
      previousTimes[index] = block.timestamp_ms;
      previousRefs[index] = ref;
      events.push(event);
    }
  }
  const rawGameLength = replay?.tail?.metadata?.gameLength;
  const gameLengthMs = Number.isSafeInteger(rawGameLength) && rawGameLength >= 0
    ? rawGameLength : null;
  if (gameLengthMs !== null && previousTimes.some((time) => time > gameLengthMs)) {
    return fail('DECODE_FAILED', '0x0089 keyframe timestamp exceeds Replay tail gameLength', scan);
  }
  const tailGaps = [];
  const totalUnobservedTailGapByField = {};
  for (const selectedField of selected.fields) {
    const tailField = selectedField.replay_tail_field;
    totalUnobservedTailGapByField[tailField] = 0;
    for (let index = 0; index < 10; index += 1) {
      const lastValue = previous[tailField][index];
      const finalTail = tails.values_by_tail_field[tailField][index];
      const gap = finalTail - Math.floor(lastValue);
      totalUnobservedTailGapByField[tailField] += gap;
      tailGaps.push({
        replay_tail_field: tailField,
        participant_id_candidate: index + 1,
        last_snapshot_replay_time_ms: previousTimes[index],
        last_snapshot_raw_f32_candidate: lastValue,
        last_snapshot_floor_candidate: Math.floor(lastValue),
        final_replay_tail: finalTail,
        unobserved_tail_gap: gap,
        unobserved_tail_time_ms: gameLengthMs === null ? null
          : gameLengthMs - previousTimes[index],
        last_raw_packet_ref: previousRefs[index],
      });
    }
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS, ...scan,
    event_count: events.length,
    observed_participant_count: 10,
    final_replay_tails_by_field: tails.values_by_tail_field,
    observed_final_raw_f32_by_field: previous,
    tail_gaps: tailGaps,
    total_unobserved_tail_gap_by_field: totalUnobservedTailGapByField,
    events,
  };
}

module.exports = {
  PROFILES,
  assessHeroDamageSnapshotTail821,
  decodeHeroDamageSnapshotCandidates821,
};
