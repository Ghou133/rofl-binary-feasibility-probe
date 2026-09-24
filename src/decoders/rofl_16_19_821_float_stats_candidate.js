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
  'Experimental cumulative keyframe snapshots; no individual gain, spend, vision, or level event is inferred.',
  'Exact 821 native 0x0089 decoding fully consumes all 3270 observed bodies into a 1260-byte transformed vector; these float field labels remain Replay-tail candidates.',
  'Decoded f32 values and their floors remain candidates tied to numeric Replay tails; final gaps are retained without interpolation.',
]);

function profile(capability, suffix, blobOffset, tailField, valueKey, floorKey,
  firstValue, allowDecrease, exactFinalMatches, extraLimit) {
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
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    evidence_scope: `11 KR exact-build Replays, 327 keyframes, 3270 hero packets; 110 finite, first-value, tail-bound sequences; ${exactFinalMatches}/110 final floor matches`,
    known_limits: Object.freeze([...COMMON_LIMITS, extraLimit]),
  });
}

const PROFILES = Object.freeze({
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
  return assessHeroStatsTail821(replay, selected.replay_tail_field);
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
  const previous = Array(10).fill(null);
  const previousTime = Array(10).fill(null);
  const previousRef = Array(10).fill(null);
  const descents = [];
  const events = [];
  for (const frame of frames) {
    for (const row of frame) {
      const { block, participantId, ref } = row;
      const index = participantId - 1;
      const rawOffsets = Array.from({ length: 4 }, (_, i) =>
        1262 - selected.blob_f32le_offset_candidate - i);
      const decoded = Buffer.from(rawOffsets.map((offset) =>
        decodeRuntimeCountByte(block.payload[offset])));
      const value = decoded.readFloatLE(0);
      const floor = Math.floor(value);
      const mismatch = (error) => fail('DECODE_FAILED', error, {
        ...scan, first_unmatched_packet_ref: ref,
      });
      if (!Number.isFinite(value) || value < 0 || !Number.isSafeInteger(floor)) {
        return mismatch(`${selected.replay_tail_field} f32 is not finite, nonnegative, and safely bounded`);
      }
      if (previous[index] === null && value !== selected.first_value) {
        return mismatch(`participant ${participantId} first ${selected.replay_tail_field} f32 differs from observed profile`);
      }
      const decreased = previous[index] !== null && value < previous[index];
      if (decreased && !selected.allow_decrease) {
        return mismatch(`participant ${participantId} has decreasing ${selected.replay_tail_field} f32`);
      }
      if (floor > assessed.values[index]) {
        return mismatch(`participant ${participantId} exceeds Replay tail ${selected.replay_tail_field}`);
      }
      if (decreased) descents.push({ participant_id_candidate: participantId,
        replay_time_ms: block.timestamp_ms, previous_f32: previous[index],
        observed_f32: value, raw_packet_ref: ref });
      previous[index] = value;
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
        raw_payload_field_bytes_hex: Buffer.from(rawOffsets.slice().reverse()
          .map((offset) => block.payload[offset])).toString('hex'),
        [selected.value_key]: value,
        [selected.floor_key]: floor,
        decreased_since_previous_snapshot: decreased,
        observation_kind: 'KEYFRAME_SNAPSHOT',
        confidence: 'CANDIDATE',
        semantic_status: EVIDENCE_STATUS,
        field_confidence: {
          replay_time_ms: 'VERIFIED_DIRECT',
          hero_raw_param: 'VERIFIED_DIRECT',
          participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
          raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
          [selected.value_key]: EVIDENCE_STATUS,
          [selected.floor_key]: EVIDENCE_STATUS,
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
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS, ...scan,
    event_count: events.length,
    observed_participant_count: 10,
    descent_count: descents.length,
    descent_observations: descents,
    final_replay_tails: assessed.values,
    observed_final_raw_f32: previous,
    tail_gaps: tailGaps,
    total_unobserved_tail_gap: tailGaps.reduce((sum, row) =>
      sum + row.unobserved_tail_gap, 0),
    events,
  };
}

module.exports = {
  PROFILES,
  assessHeroFloatSnapshotTail821,
  decodeHeroFloatSnapshotCandidates821,
};
