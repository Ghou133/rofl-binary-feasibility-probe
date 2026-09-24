'use strict';

const { replaySourceError } = require('./replay_source_integrity');
const { assessHeroStatsTail821, scanHeroStatsPackets821 } =
  require('./rofl_16_19_821_hero_stats_candidate');
const {
  RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256, decodeRuntimeCountByte,
} = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const EVIDENCE_STATUS = 'CANDIDATE_821_RUNTIME_KEYFRAME_BYTE_AND_REPLAY_TAIL';
const WARD_FIELDS = Object.freeze([
  Object.freeze({ field: 'WARD_PLACED_DETECTOR', key: 'ward_placed_detector', low_offset: 834 }),
  Object.freeze({ field: 'WARD_KILLED', key: 'ward_killed', low_offset: 838 }),
  Object.freeze({ field: 'WARD_PLACED', key: 'ward_placed', low_offset: 842 }),
]);
const CANNON_FIELDS = Object.freeze([
  Object.freeze({ field: 'Missions_CannonMinionsKilled',
    key: 'missions_cannon_minions_killed', low_offset: 450 }),
]);

const HERO_WARD_STATS_SNAPSHOT_821_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-hero-ward-stats-keyframe-candidate-v1',
  replay_version: BUILD,
  capability: 'hero_ward_stats_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: 0x0089,
  stream_tags: Object.freeze([2]),
  payload_length: 1263,
  payload_prefix_hex: '6700de',
  fields: WARD_FIELDS,
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: '11 KR exact-build Replays, 327 keyframes, 3270 hero packets; all 110 participant sequences zero-start, monotone and tail-bound for each of three ward counts',
  known_limits: Object.freeze([
    'Experimental keyframe snapshots only; ward placement, removal, detector type, position, and lifecycle events are not inferred.',
    'The three encoded low bytes at 834, 838 and 842 correlate with distinct Replay tail fields; their decoded upper three bytes are zero in the observed corpus.',
    'Factory 0x0089 consumes only 5 of 1263 observed keyframe bytes; carrier-to-object and field-offset binding remains unconfirmed.',
    'Only observed values below 256 are accepted, and final Replay-tail gaps remain uninterpolated.',
  ]),
});

const HERO_MISSIONS_CANNON_MINIONS_KILLED_SNAPSHOT_821_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-hero-missions-cannon-minions-keyframe-candidate-v1',
  replay_version: BUILD,
  capability: 'hero_missions_cannon_minions_killed_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: 0x0089,
  stream_tags: Object.freeze([2]),
  payload_length: 1263,
  payload_prefix_hex: '6700de',
  fields: CANNON_FIELDS,
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: '11 KR exact-build Replays, 327 keyframes, 3270 hero packets; 110 zero-start, monotone, tail-bound sequences, 93 final values equal Missions_CannonMinionsKilled',
  known_limits: Object.freeze([
    'This candidate is tied only to the Replay tail field Missions_CannonMinionsKilled, not to a general lane minion count or a per-kill event.',
    'Factory 0x0089 consumes only 5 of 1263 observed keyframe bytes; carrier-to-object and field-offset binding remains unconfirmed.',
    'The encoded low byte at 450 correlates with the tail field; its decoded upper three bytes are zero in the observed corpus.',
    'Only observed values below 256 are accepted, and final Replay-tail gaps remain uninterpolated.',
  ]),
});

function assessHeroWardStatsTail821(replay) {
  return { required_fields: WARD_FIELDS.map(({ field }) => {
    const assessment = assessHeroStatsTail821(replay, field);
    return { field, status: assessment.status, error: assessment.error ?? null };
  }) };
}

function assessHeroMissionsCannonMinionsTail821(replay) {
  return assessHeroStatsTail821(replay, CANNON_FIELDS[0].field);
}

function decodeAuxiliaryCounters821(replay, profile, precollected = null) {
  const base = {
    profile_id: profile.id,
    input_packet_id: 0x0089,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    runtime_image_used: false,
    runtime_image_status: 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED',
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, details = {}) => ({
    ...base, status, event_count: null, events: null, error, ...details,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `${profile.capability} candidate supports only ${BUILD}`);
  }
  if (precollected === null) {
    const sourceError = replaySourceError(replay);
    if (sourceError) return fail('DECODE_FAILED', `Replay source failed: ${sourceError}`);
  }
  const assessed = Object.fromEntries(profile.fields.map(({ field }) => [
    field, assessHeroStatsTail821(replay, field),
  ]));
  for (const field of profile.fields) {
    const result = assessed[field.field];
    if (result.status !== 'PASS') return fail(result.status, result.error);
  }
  const collected = scanHeroStatsPackets821(replay, precollected, profile.capability);
  if (collected.status !== 'PASS') {
    return fail(collected.status, collected.error, collected.details);
  }
  const { frames, scan } = collected;
  const previous = Object.fromEntries(profile.fields.map(({ key }) => [key, Array(10).fill(null)]));
  const previousTimes = Array(10).fill(null);
  const previousRefs = Array(10).fill(null);
  const observations = [];
  for (const frame of frames) {
    for (const row of frame) {
      const { block, participantId, ref } = row;
      const index = participantId - 1;
      const values = {};
      const rawBytes = {};
      for (const field of profile.fields) {
        const mismatch = (message) => fail('DECODE_FAILED', message, {
          ...scan, first_unmatched_packet_ref: ref,
        });
        const upper = [1, 2, 3].map((distance) =>
          decodeRuntimeCountByte(block.payload[field.low_offset - distance]));
        if (upper.some((value) => value !== 0)) {
          return mismatch(`${field.field} decoded upper bytes are nonzero; observed byte scope exceeded`);
        }
        const rawByte = block.payload[field.low_offset];
        const value = decodeRuntimeCountByte(rawByte);
        if (previous[field.key][index] === null && value !== 0) {
          return mismatch(`participant ${participantId} first observed ${field.field} value is not zero`);
        }
        if (previous[field.key][index] !== null && value < previous[field.key][index]) {
          return mismatch(`participant ${participantId} has decreasing observed ${field.field} value`);
        }
        if (value > assessed[field.field].values[index]) {
          return mismatch(`participant ${participantId} exceeds Replay tail ${field.field}`);
        }
        values[`${field.key}_candidate`] = value;
        rawBytes[`raw_${field.key}_byte`] = rawByte;
      }
      for (const field of profile.fields) previous[field.key][index] = values[`${field.key}_candidate`];
      previousTimes[index] = block.timestamp_ms;
      previousRefs[index] = ref;
      observations.push({ row, values, rawBytes });
    }
  }
  const rawGameLength = replay?.tail?.metadata?.gameLength;
  const gameLengthMs = Number.isSafeInteger(rawGameLength) && rawGameLength >= 0
    ? rawGameLength : null;
  if (gameLengthMs !== null && previousTimes.some((time) => time > gameLengthMs)) {
    return fail('DECODE_FAILED', '0x0089 keyframe timestamp exceeds Replay tail gameLength', scan);
  }
  const tailGapsByField = Object.fromEntries(profile.fields.map(({ field, key }) => [key,
    assessed[field].values.map((finalValue, index) => ({
      participant_id_candidate: index + 1,
      last_snapshot_replay_time_ms: previousTimes[index],
      last_snapshot_candidate: previous[key][index],
      final_replay_tail: finalValue,
      unobserved_tail_gap: finalValue - previous[key][index],
      unobserved_tail_time_ms: gameLengthMs === null ? null : gameLengthMs - previousTimes[index],
      last_raw_packet_ref: previousRefs[index],
    })),
  ]));
  const events = observations.map(({ row, values, rawBytes }) => ({
    event_type: profile.capability === 'hero_ward_stats_snapshot'
      ? 'HERO_WARD_STATS_SNAPSHOT_CANDIDATE'
      : 'HERO_MISSIONS_CANNON_MINIONS_KILLED_SNAPSHOT_CANDIDATE',
    game_version: BUILD,
    patch: '16.19',
    build_profile: profile.id,
    replay_sha256: replay.source_sha256,
    replay_time_ms: row.block.timestamp_ms,
    hero_raw_param: row.rawParam,
    participant_id_candidate: row.participantId,
    ...rawBytes,
    ...values,
    observation_kind: 'KEYFRAME_SNAPSHOT',
    confidence: 'CANDIDATE',
    semantic_status: EVIDENCE_STATUS,
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      hero_raw_param: 'VERIFIED_DIRECT',
      participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
      ...Object.fromEntries(profile.fields.flatMap(({ key }) => [
        [`raw_${key}_byte`, 'VERIFIED_DIRECT'],
        [`${key}_candidate`, EVIDENCE_STATUS],
      ])),
    },
    raw_packet_ref: row.ref,
    known_limits: [...profile.known_limits],
  }));
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS, ...scan,
    event_count: events.length,
    observed_participant_count: 10,
    final_replay_tails_by_field: Object.fromEntries(profile.fields.map(({ field, key }) => [
      key, assessed[field].values,
    ])),
    observed_max_by_field: previous,
    tail_gaps_by_field: tailGapsByField,
    tail_gap_totals_by_field: Object.fromEntries(profile.fields.map(({ key }) => [key,
      tailGapsByField[key].reduce((sum, gap) => sum + gap.unobserved_tail_gap, 0),
    ])),
    events,
  };
}

function decodeHeroWardStatsSnapshotCandidates821(replay, precollected = null) {
  return decodeAuxiliaryCounters821(replay,
    HERO_WARD_STATS_SNAPSHOT_821_CANDIDATE_PROFILE, precollected);
}

function decodeHeroMissionsCannonMinionsKilledSnapshotCandidates821(replay, precollected = null) {
  return decodeAuxiliaryCounters821(replay,
    HERO_MISSIONS_CANNON_MINIONS_KILLED_SNAPSHOT_821_CANDIDATE_PROFILE, precollected);
}

module.exports = {
  HERO_WARD_STATS_SNAPSHOT_821_CANDIDATE_PROFILE,
  HERO_MISSIONS_CANNON_MINIONS_KILLED_SNAPSHOT_821_CANDIDATE_PROFILE,
  assessHeroWardStatsTail821,
  assessHeroMissionsCannonMinionsTail821,
  decodeHeroWardStatsSnapshotCandidates821,
  decodeHeroMissionsCannonMinionsKilledSnapshotCandidates821,
};
