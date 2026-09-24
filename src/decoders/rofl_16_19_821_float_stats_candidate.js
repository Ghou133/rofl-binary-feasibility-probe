'use strict';

const { replaySourceError } = require('./replay_source_integrity');
const { assessHeroStatsTail821, scanHeroStatsPackets821 } =
  require('./rofl_16_19_821_hero_stats_candidate');
const {
  RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256, decodeRuntimeCountByte,
} = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const EVIDENCE_STATUS = 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL';
const COMMON_LIMITS = Object.freeze([
  'Experimental cumulative keyframe snapshots; no individual event, target, or cause is inferred.',
  'Exact 821 native 0x0089 decoding fully consumes all 3270 observed bodies into a 1260-byte transformed vector; these float field labels remain Replay-tail candidates.',
  'Decoded f32 values and their floors remain candidates tied to numeric Replay tails; final gaps are retained without interpolation.',
]);

function profile(capability, suffix, blobOffset, tailField, valueKey, floorKey,
  firstValue, allowDecrease, exactFinalMatches, extraLimit, requireInteger = false) {
  return Object.freeze({
    id: `rofl-16.19.821.7343-kr-${suffix}-keyframe-f32-candidate-v1`,
    replay_version: BUILD,
    capability,
    status: 'CANDIDATE',
    enabled: true,
    replay_block_packet_id: 0x0089,
    stream_tags: Object.freeze([2]),
    payload_length: 1263,
    payload_prefix_hex: '6700de',
    blob_f32le_offset_candidate: blobOffset,
    raw_payload_byte_offsets: Object.freeze(Array.from({ length: 4 }, (_, i) =>
      1262 - blobOffset - i).reverse()),
    replay_tail_field: tailField,
    value_key: valueKey,
    floor_key: floorKey,
    first_value: firstValue,
    allow_decrease: allowDecrease,
    require_integer: requireInteger,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    evidence_scope: `11 KR exact-build Replays, 327 keyframes, 3270 hero packets; 110 finite, first-value, tail-bound sequences; ${exactFinalMatches}/110 final floor matches`,
    known_limits: Object.freeze([...COMMON_LIMITS, extraLimit]),
  });
}

const JUNGLE_FIELDS = Object.freeze([
  Object.freeze({ blob_f32le_offset_candidate: 0x40,
    replay_tail_field: 'NEUTRAL_MINIONS_KILLED',
    value_key: 'jungle_minions_killed_raw_f32_candidate',
    floor_key: 'jungle_minions_killed_floor_candidate' }),
  Object.freeze({ blob_f32le_offset_candidate: 0x44,
    replay_tail_field: 'NEUTRAL_MINIONS_KILLED_YOUR_JUNGLE',
    value_key: 'your_jungle_minions_killed_raw_f32_candidate',
    floor_key: 'your_jungle_minions_killed_floor_candidate' }),
  Object.freeze({ blob_f32le_offset_candidate: 0x48,
    replay_tail_field: 'NEUTRAL_MINIONS_KILLED_ENEMY_JUNGLE',
    value_key: 'enemy_jungle_minions_killed_raw_f32_candidate',
    floor_key: 'enemy_jungle_minions_killed_floor_candidate' }),
]);

const PROFILES = Object.freeze({
  hero_minions_killed_snapshot: profile('hero_minions_killed_snapshot', 'minions-killed',
    0x3c, 'MINIONS_KILLED', 'minions_killed_raw_f32_candidate',
    'minions_killed_floor_candidate', 0, false, 73,
    'All 3270 observed f32 values are integral; this standard MINIONS_KILLED candidate is distinct from the Missions_MinionsKilled count at 0x378 and does not identify individual last hits.', true),
  hero_jungle_minions_killed_snapshot: Object.freeze({
    ...profile('hero_jungle_minions_killed_snapshot', 'jungle-minions-killed',
      0x40, 'NEUTRAL_MINIONS_KILLED',
      'jungle_minions_killed_raw_f32_candidate',
      'jungle_minions_killed_floor_candidate', 0, false, 102,
      'Three distinct Replay-tail candidates at f32LE offsets 0x40/0x44/0x48 correlate with total, own-jungle, and enemy-jungle neutral minions; fractional f32 values are retained and only their floors are compared with integer tails.'),
    fields: JUNGLE_FIELDS,
    replay_tail_fields: Object.freeze(JUNGLE_FIELDS.map((field) => field.replay_tail_field)),
    evidence_scope: '11 KR exact-build Replays, 327 keyframes, 3270 hero packets; all 110 participant sequences per field start at zero, are monotone and tail-bound; final floor matches are 102/110 total, 103/110 own jungle, 108/110 enemy jungle',
  }),
  hero_experience_snapshot: profile('hero_experience_snapshot', 'experience',
    0x28, 'EXP', 'experience_raw_f32_candidate', 'experience_floor_candidate',
    0, false, 52, 'EXP is a candidate cumulative value; no experience source or level threshold is inferred.'),
  hero_vision_score_snapshot: profile('hero_vision_score_snapshot', 'vision-score',
    0x1b0, 'VISION_SCORE', 'vision_score_raw_f32_candidate',
    'vision_score_floor_candidate', 0, false, 84,
    'VISION_SCORE is a candidate total; no ward, reveal, or vision action is inferred.'),
  hero_gold_earned_snapshot: profile('hero_gold_earned_snapshot', 'gold-earned',
    0x38, 'GOLD_EARNED', 'gold_earned_raw_f32_candidate',
    'gold_earned_floor_candidate', 500, false, 0,
    'All 110 first snapshots equal 500 and no final snapshot equals the GOLD_EARNED tail; the measured gaps are retained.'),
  hero_gold_spent_snapshot: profile('hero_gold_spent_snapshot', 'gold-spent',
    0x34, 'GOLD_SPENT', 'gold_spent_raw_f32_candidate',
    'gold_spent_floor_candidate', 0, true, 92,
    'One decrease was observed among 110 participant sequences; it is retained without inferring refund, sale, or purchase.'),
});

function assessHeroFloatSnapshotTail821(replay, capability) {
  const selected = PROFILES[capability];
  if (!selected) return { status: 'UNSUPPORTED',
    error: `unknown 821 float snapshot capability: ${capability}` };
  if (!selected.fields) return assessHeroStatsTail821(replay, selected.replay_tail_field);
  const assessments = selected.fields.map((field) =>
    assessHeroStatsTail821(replay, field.replay_tail_field));
  const failure = assessments.find((row) => row.status !== 'PASS');
  if (failure) return { ...failure, required_fields: assessments };
  return { ...assessments[0], required_fields: assessments,
    values_by_tail: Object.fromEntries(assessments.map((row) =>
      [row.field, row.values])) };
}

function assessHeroJungleMinionsTail821(replay) {
  return assessHeroFloatSnapshotTail821(replay, 'hero_jungle_minions_killed_snapshot');
}

function decodeHeroFloatSnapshotCandidates821(replay, capability, precollected = null) {
  const selected = PROFILES[capability];
  if (!selected) return { status: 'UNSUPPORTED', event_count: null, events: null,
    error: `unknown 821 float snapshot capability: ${capability}` };
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
    const sourceError = replaySourceError(replay);
    if (sourceError) return fail('DECODE_FAILED', `Replay source failed: ${sourceError}`);
  }
  const assessed = assessHeroFloatSnapshotTail821(replay, capability);
  if (assessed.status !== 'PASS') return fail(assessed.status, assessed.error);
  const collected = scanHeroStatsPackets821(replay, precollected, capability);
  if (collected.status !== 'PASS') {
    return fail(collected.status, collected.error, collected.details);
  }
  const { frames, scan } = collected;
  const fields = selected.fields ?? [selected];
  const previousByField = Object.fromEntries(fields.map((field) =>
    [field.value_key, Array(10).fill(null)]));
  const previous = previousByField[selected.value_key];
  const previousTime = Array(10).fill(null);
  const previousRef = Array(10).fill(null);
  const descents = [];
  const events = [];
  for (const frame of frames) {
    for (const row of frame) {
      const { block, participantId, ref } = row;
      const index = participantId - 1;
      const mismatch = (error) => fail('DECODE_FAILED', error, {
        ...scan, first_unmatched_packet_ref: ref,
      });
      const values = {};
      const rawFieldBytes = {};
      const valueConfidence = {};
      let decreasedSincePrevious = false;
      for (const field of fields) {
        const rawOffsets = Array.from({ length: 4 }, (_, i) =>
          1262 - field.blob_f32le_offset_candidate - i);
        const decoded = Buffer.from(rawOffsets.map((offset) =>
          decodeRuntimeCountByte(block.payload[offset])));
        const value = decoded.readFloatLE(0);
        const floor = Math.floor(value);
        const prior = previousByField[field.value_key][index];
        const tailValues = assessed.values_by_tail?.[field.replay_tail_field]
          ?? assessed.values;
        if (!Number.isFinite(value) || value < 0 || !Number.isSafeInteger(floor)) {
          return mismatch(`${field.replay_tail_field} f32 is not finite, nonnegative, and safely bounded`);
        }
        if (selected.require_integer && !Number.isInteger(value)) {
          return mismatch(`${field.replay_tail_field} f32 is not integral in the observed profile`);
        }
        if (prior === null && value !== selected.first_value) {
          return mismatch(`participant ${participantId} first ${field.replay_tail_field} f32 differs from observed profile`);
        }
        const decreased = prior !== null && value < prior;
        if (decreased && !selected.allow_decrease) {
          return mismatch(`participant ${participantId} has decreasing ${field.replay_tail_field} f32`);
        }
        if (floor > tailValues[index]) {
          return mismatch(`participant ${participantId} exceeds Replay tail ${field.replay_tail_field}`);
        }
        if (decreased) descents.push({ participant_id_candidate: participantId,
          replay_time_ms: block.timestamp_ms, previous_f32: prior,
          observed_f32: value, raw_packet_ref: ref });
        decreasedSincePrevious ||= decreased;
        previousByField[field.value_key][index] = value;
        values[field.value_key] = value;
        values[field.floor_key] = floor;
        valueConfidence[field.value_key] = EVIDENCE_STATUS;
        valueConfidence[field.floor_key] = EVIDENCE_STATUS;
        rawFieldBytes[field.replay_tail_field] = Buffer.from(rawOffsets.slice().reverse()
          .map((offset) => block.payload[offset])).toString('hex');
      }
      previousTime[index] = block.timestamp_ms;
      previousRef[index] = ref;
      events.push({
        event_type: `${capability.toUpperCase()}_CANDIDATE`,
        game_version: BUILD,
        patch: '16.19',
        build_profile: selected.id,
        replay_sha256: replay.source_sha256,
        replay_time_ms: block.timestamp_ms,
        hero_raw_param: row.rawParam,
        participant_id_candidate: participantId,
        raw_payload_field_bytes_hex: selected.fields ? rawFieldBytes
          : rawFieldBytes[selected.replay_tail_field],
        ...values,
        decreased_since_previous_snapshot: decreasedSincePrevious,
        observation_kind: 'KEYFRAME_SNAPSHOT',
        confidence: 'CANDIDATE',
        semantic_status: EVIDENCE_STATUS,
        field_confidence: {
          replay_time_ms: 'VERIFIED_DIRECT',
          hero_raw_param: 'VERIFIED_DIRECT',
          participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
          raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
          ...valueConfidence,
          decreased_since_previous_snapshot: EVIDENCE_STATUS,
        },
        raw_packet_ref: ref,
        known_limits: [...selected.known_limits],
      });
    }
  }
  const rawGameLength = replay?.tail?.metadata?.gameLength;
  const gameLengthMs = Number.isSafeInteger(rawGameLength) && rawGameLength >= 0
    ? rawGameLength : null;
  if (gameLengthMs !== null && previousTime.some((time) => time > gameLengthMs)) {
    return fail('DECODE_FAILED', '0x0089 keyframe timestamp exceeds Replay tail gameLength', scan);
  }
  const tailGaps = assessed.values.map((finalValue, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: previousTime[index],
    last_snapshot_raw_f32_candidate: previous[index],
    last_snapshot_floor_candidate: Math.floor(previous[index]),
    final_replay_tail: finalValue,
    unobserved_tail_gap: finalValue - Math.floor(previous[index]),
    unobserved_tail_time_ms: gameLengthMs === null ? null
      : gameLengthMs - previousTime[index],
    last_raw_packet_ref: previousRef[index],
  }));
  if (selected.fields) {
    for (const gap of tailGaps) {
      const index = gap.participant_id_candidate - 1;
      gap.final_neutral_minions_killed_tail = gap.final_replay_tail;
      for (const field of selected.fields.slice(1)) {
        const finalValue = assessed.values_by_tail[field.replay_tail_field][index];
        const lastValue = previousByField[field.value_key][index];
        const prefix = field === selected.fields[1] ? 'your_jungle' : 'enemy_jungle';
        gap[`last_snapshot_${field.value_key}`] = lastValue;
        gap[`last_snapshot_${field.floor_key}`] = Math.floor(lastValue);
        gap[`final_${field.replay_tail_field.toLowerCase()}_tail`] = finalValue;
        gap[`unobserved_${prefix}_tail_gap`] = finalValue - Math.floor(lastValue);
      }
    }
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS, ...scan,
    event_count: events.length,
    observed_participant_count: 10,
    descent_count: descents.length,
    descent_observations: descents,
    final_replay_tails: assessed.values,
    observed_final_raw_f32: previous,
    ...(selected.fields ? {
      final_replay_tails_by_field: assessed.values_by_tail,
      observed_final_raw_f32_by_field: Object.fromEntries(selected.fields.map((field) =>
        [field.replay_tail_field, previousByField[field.value_key]])),
      total_unobserved_your_jungle_tail_gap: tailGaps.reduce((sum, row) =>
        sum + row.unobserved_your_jungle_tail_gap, 0),
      total_unobserved_enemy_jungle_tail_gap: tailGaps.reduce((sum, row) =>
        sum + row.unobserved_enemy_jungle_tail_gap, 0),
    } : {}),
    tail_gaps: tailGaps,
    total_unobserved_tail_gap: tailGaps.reduce((sum, row) =>
      sum + row.unobserved_tail_gap, 0),
    events,
  };
}

module.exports = {
  PROFILES,
  HERO_JUNGLE_MINIONS_KILLED_SNAPSHOT_821_CANDIDATE_PROFILE:
    PROFILES.hero_jungle_minions_killed_snapshot,
  assessHeroFloatSnapshotTail821,
  assessHeroJungleMinionsTail821,
  decodeHeroFloatSnapshotCandidates821,
};
