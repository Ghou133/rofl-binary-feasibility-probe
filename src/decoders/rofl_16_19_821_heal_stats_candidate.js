'use strict';

const { replaySourceError } = require('./replay_source_integrity');
const { assessHeroStatsTail821, scanHeroStatsPackets821 } =
  require('./rofl_16_19_821_hero_stats_candidate');
const {
  RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256, decodeRuntimeCountByte,
} = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const EVIDENCE_STATUS = 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_U32_AND_REPLAY_TAIL';
const COMMON_LIMITS = Object.freeze([
  'Exact 821 native 0x0089 decoding fully consumes all 3270 observed bodies into a 1260-byte transformed vector; the individual field labels remain Replay-tail candidates.',
  'Values are cumulative keyframe snapshots, not individual healing events or exact healing times.',
  'Replay-tail gaps are retained without interpolation.',
]);

function profile(capability, suffix, blobOffset, tailField, valueKey,
  exactFinalMatches, extraLimit) {
  return Object.freeze({
    id: `rofl-16.19.821.7343-kr-${suffix}-keyframe-u32-candidate-v1`,
    replay_version: BUILD,
    capability,
    status: 'CANDIDATE',
    enabled: true,
    replay_block_packet_id: 0x0089,
    stream_tags: Object.freeze([2]),
    payload_length: 1263,
    payload_prefix_hex: '6700de',
    blob_u32le_offset_candidate: blobOffset,
    raw_payload_byte_offsets: Object.freeze(Array.from({ length: 4 }, (_, i) =>
      1262 - blobOffset - i).reverse()),
    replay_tail_field: tailField,
    value_key: valueKey,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    evidence_scope: `11 KR exact-build Replays, 327 keyframes, 3270 hero packets; 110 zero-start, monotone, tail-bound participant sequences; ${exactFinalMatches}/110 final matches`,
    known_limits: Object.freeze([...COMMON_LIMITS, extraLimit]),
  });
}

const PROFILES = Object.freeze({
  hero_total_heal_snapshot: profile('hero_total_heal_snapshot', 'total-heal',
    0x234, 'TOTAL_HEAL', 'total_heal_candidate', 57,
    'TOTAL_HEAL is a reported aggregate; no effective healing, overheal, target, or source is inferred.'),
  hero_total_units_healed_snapshot: profile('hero_total_units_healed_snapshot',
    'total-units-healed', 0x23c, 'TOTAL_UNITS_HEALED',
    'total_units_healed_candidate', 109,
    'TOTAL_UNITS_HEALED is a reported counter; no individual recipient or heal event is inferred.'),
});

function assessHeroHealSnapshotTail821(replay, capability) {
  const selected = PROFILES[capability];
  if (!selected) return { status: 'UNSUPPORTED',
    error: `unknown 821 heal snapshot capability: ${capability}` };
  return assessHeroStatsTail821(replay, selected.replay_tail_field);
}

function decodeHeroHealSnapshotCandidates821(replay, capability, precollected = null) {
  const selected = PROFILES[capability];
  if (!selected) return { status: 'UNSUPPORTED', event_count: null, events: null,
    error: `unknown 821 heal snapshot capability: ${capability}` };
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
  const tail = assessHeroHealSnapshotTail821(replay, capability);
  if (tail.status !== 'PASS') return fail(tail.status, tail.error);
  const collected = scanHeroStatsPackets821(replay, precollected, capability);
  if (collected.status !== 'PASS') {
    return fail(collected.status, collected.error, collected.details);
  }
  const { frames, scan } = collected;
  const previous = Array(10).fill(null);
  const previousTimes = Array(10).fill(null);
  const previousRefs = Array(10).fill(null);
  const events = [];
  for (const frame of frames) {
    for (const row of frame) {
      const { block, rawParam, participantId, ref } = row;
      const index = participantId - 1;
      const rawOffsets = Array.from({ length: 4 }, (_, i) =>
        1262 - selected.blob_u32le_offset_candidate - i);
      const bytes = Buffer.from(rawOffsets.map((offset) =>
        decodeRuntimeCountByte(block.payload[offset])));
      const value = bytes.readUInt32LE(0);
      const mismatch = (error) => fail('DECODE_FAILED', error, {
        ...scan, first_unmatched_packet_ref: ref,
      });
      if (previous[index] === null && value !== 0) {
        return mismatch(`participant ${participantId} first ${selected.replay_tail_field} count is not zero`);
      }
      if (previous[index] !== null && value < previous[index]) {
        return mismatch(`participant ${participantId} has decreasing observed ${selected.replay_tail_field}`);
      }
      if (value > tail.values[index]) {
        return mismatch(`participant ${participantId} exceeds Replay tail ${selected.replay_tail_field}`);
      }
      previous[index] = value;
      previousTimes[index] = block.timestamp_ms;
      previousRefs[index] = ref;
      events.push({
        event_type: `${capability.toUpperCase()}_CANDIDATE`,
        game_version: BUILD,
        patch: '16.19',
        build_profile: selected.id,
        replay_sha256: replay.source_sha256,
        replay_time_ms: block.timestamp_ms,
        hero_raw_param: rawParam,
        participant_id_candidate: participantId,
        raw_payload_field_bytes_hex: Buffer.from(rawOffsets.slice().reverse()
          .map((offset) => block.payload[offset])).toString('hex'),
        [selected.value_key]: value,
        observation_kind: 'KEYFRAME_SNAPSHOT',
        confidence: 'CANDIDATE',
        semantic_status: EVIDENCE_STATUS,
        field_confidence: {
          replay_time_ms: 'VERIFIED_DIRECT',
          hero_raw_param: 'VERIFIED_DIRECT',
          participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
          raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
          [selected.value_key]: EVIDENCE_STATUS,
        },
        raw_packet_ref: ref,
        known_limits: [...selected.known_limits],
      });
    }
  }
  const rawGameLength = replay?.tail?.metadata?.gameLength;
  const gameLengthMs = Number.isSafeInteger(rawGameLength) && rawGameLength >= 0
    ? rawGameLength : null;
  if (gameLengthMs !== null && previousTimes.some((time) => time > gameLengthMs)) {
    return fail('DECODE_FAILED', '0x0089 keyframe timestamp exceeds Replay tail gameLength', scan);
  }
  const tailGaps = tail.values.map((finalValue, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: previousTimes[index],
    last_snapshot_value_candidate: previous[index],
    final_replay_tail: finalValue,
    unobserved_tail_gap: finalValue - previous[index],
    unobserved_tail_time_ms: gameLengthMs === null ? null
      : gameLengthMs - previousTimes[index],
    last_raw_packet_ref: previousRefs[index],
  }));
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS, ...scan,
    event_count: events.length,
    observed_participant_count: 10,
    final_replay_tails: tail.values,
    observed_final_values: previous,
    tail_gaps: tailGaps,
    total_unobserved_tail_gap: tailGaps.reduce((sum, row) =>
      sum + row.unobserved_tail_gap, 0),
    events,
  };
}

module.exports = {
  PROFILES,
  assessHeroHealSnapshotTail821,
  decodeHeroHealSnapshotCandidates821,
};
