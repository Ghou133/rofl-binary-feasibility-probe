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
  'Exact 821 native 0x0089 decoding fully consumes all 3270 observed bodies into a 1260-byte transformed vector; individual field labels remain Replay-tail candidates.',
  'Cumulative keyframe snapshots do not identify individual events, sources, targets, or exact event times.',
  'The last keyframe can precede the Replay tail; gaps are measured without interpolation.',
]);

function profile(capability, suffix, offset, tailField, valueKey, floorKey, equalCount,
  extraLimit) {
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
    blob_f32le_offset_candidate: offset,
    raw_payload_byte_offsets: Object.freeze(Array.from({ length: 4 }, (_, i) =>
      1262 - offset - i).reverse()),
    replay_tail_field: tailField,
    value_key: valueKey,
    floor_key: floorKey,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    evidence_scope: `11 KR exact-build Replays, 327 keyframes, 3270 hero packets; 110 zero-start, monotone, finite and tail-bounded sequences; ${equalCount}/110 final floors match Replay tails`,
    known_limits: Object.freeze([...COMMON_LIMITS, extraLimit]),
  });
}

const PROFILES = Object.freeze({
  hero_epic_monster_damage_snapshot: profile('hero_epic_monster_damage_snapshot',
    'epic-monster-damage', 0x21c, 'TOTAL_DAMAGE_DEALT_TO_EPIC_MONSTERS',
    'epic_monster_damage_raw_f32_candidate', 'epic_monster_damage_floor_candidate',
    110, 'This total cannot attribute damage to a particular epic monster or action.'),
  hero_crowd_control_time_snapshot: profile('hero_crowd_control_time_snapshot',
    'crowd-control-time', 0x230, 'TOTAL_TIME_CROWD_CONTROL_DEALT_TO_CHAMPIONS',
    'crowd_control_time_raw_f32_candidate', 'crowd_control_time_floor_candidate',
    59, 'The Replay tail names crowd-control time; no duration unit, target, spell, or individual crowd-control event is inferred.'),
});

function assessHeroEpicCcSnapshotTail821(replay, capability) {
  const selected = PROFILES[capability];
  if (!selected) return { status: 'UNSUPPORTED',
    error: `unknown 821 epic/crowd-control capability: ${capability}` };
  return assessHeroStatsTail821(replay, selected.replay_tail_field);
}

function decodeHeroEpicCcSnapshotCandidates821(replay, capability, precollected = null) {
  const selected = PROFILES[capability];
  if (!selected) return { status: 'UNSUPPORTED', event_count: null, events: null,
    error: `unknown 821 epic/crowd-control capability: ${capability}` };
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
  const tail = assessHeroEpicCcSnapshotTail821(replay, capability);
  if (tail.status !== 'PASS') return fail(tail.status, tail.error);
  const collected = scanHeroStatsPackets821(replay, precollected, capability);
  if (collected.status !== 'PASS') {
    return fail(collected.status, collected.error, collected.details);
  }
  const { frames, scan } = collected;
  const previous = Array(10).fill(null);
  const previousTime = Array(10).fill(null);
  const previousRef = Array(10).fill(null);
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
      if (previous[index] === null && value !== 0) {
        return mismatch(`participant ${participantId} first ${selected.replay_tail_field} f32 is not zero`);
      }
      if (previous[index] !== null && value < previous[index]) {
        return mismatch(`participant ${participantId} has decreasing ${selected.replay_tail_field} f32`);
      }
      if (floor > tail.values[index]) {
        return mismatch(`participant ${participantId} exceeds Replay tail ${selected.replay_tail_field}`);
      }
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
  const tailGaps = tail.values.map((finalValue, index) => ({
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
    final_replay_tails: tail.values,
    observed_final_raw_f32: previous,
    tail_gaps: tailGaps,
    total_unobserved_tail_gap: tailGaps.reduce((sum, row) =>
      sum + row.unobserved_tail_gap, 0),
    events,
  };
}

module.exports = {
  PROFILES,
  assessHeroEpicCcSnapshotTail821,
  decodeHeroEpicCcSnapshotCandidates821,
};
