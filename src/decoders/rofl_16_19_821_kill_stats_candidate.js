'use strict';

const { replaySourceError } = require('./replay_source_integrity');
const { assessHeroStatsTail821, scanHeroStatsPackets821 } =
  require('./rofl_16_19_821_hero_stats_candidate');
const {
  RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256, decodeRuntimeCountByte,
} = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'hero_kill_stats_snapshot';
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_KR_821_RUNTIME_VECTOR_SIX_KILL_STATS_TAIL_CORRELATION';
const QUADRA_STATUS = 'CANDIDATE_SPARSE_ONE_POSITIVE_KR_821_TAIL_CORRELATION';
const FIELDS = Object.freeze([
  Object.freeze({ tail_field: 'LARGEST_KILLING_SPREE', value_key: 'largest_killing_spree_candidate', offset: 0x58 }),
  Object.freeze({ tail_field: 'KILLING_SPREES', value_key: 'killing_sprees_candidate', offset: 0x5c }),
  Object.freeze({ tail_field: 'LARGEST_MULTI_KILL', value_key: 'largest_multi_kill_candidate', offset: 0x60 }),
  Object.freeze({ tail_field: 'DOUBLE_KILLS', value_key: 'double_kills_candidate', offset: 0x64 }),
  Object.freeze({ tail_field: 'TRIPLE_KILLS', value_key: 'triple_kills_candidate', offset: 0x68 }),
  Object.freeze({ tail_field: 'QUADRA_KILLS', value_key: 'quadra_kills_candidate', offset: 0x6c }),
]);

const HERO_KILL_STATS_SNAPSHOT_821_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-hero-kill-stats-keyframe-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: 0x0089,
  stream_tags: Object.freeze([2]),
  payload_length: 1263,
  payload_prefix_hex: '6700de',
  blob_u32le_offsets_candidate: Object.freeze(Object.fromEntries(
    FIELDS.map(({ tail_field, offset }) => [tail_field, offset]))),
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: '11 KR exact-build Replays, 327 keyframes, 3270 hero packets; all 110 participant sequences start at zero, remain monotone and tail-bound; final exact matches 102/106/108/107/110/110 across the six fields',
  known_limits: Object.freeze([
    'The exact 821 native 0x0089 path fully consumes each observed body into a 1260-byte vector; labels at selected offsets remain Replay-tail candidates.',
    'The aligned four-byte slots are read as u32LE, but observed values 0..12 cannot distinguish a u32 field width from overlapping u16 or u8 reads.',
    'QUADRA_KILLS is sparse: only one of 110 participants has a positive tail and observed snapshot. PENTA_KILLS and UNREAL_KILLS have no positive tails in these Replays and are not exposed.',
    'Keyframes are cumulative snapshots; individual kill events, kill times, participants in a kill, targets and causes are not inferred.',
    'Final gaps from the Replay tails are retained without interpolation or a hard maximum.',
  ]),
});

function assessHeroKillStatsTail821(replay) {
  const assessed = FIELDS.map(({ tail_field: field }) =>
    assessHeroStatsTail821(replay, field));
  const requiredFields = assessed.map((row, index) => ({
    field: FIELDS[index].tail_field,
    status: row.status,
    error: row.error ?? row.missing_input ?? null,
  }));
  const failure = requiredFields.find((row) => row.status !== 'PASS');
  if (failure) return { ...failure, required_fields: requiredFields };
  return { status: 'PASS', required_fields: requiredFields,
    valuesByField: Object.fromEntries(FIELDS.map(({ tail_field }, index) =>
      [tail_field, assessed[index].values])) };
}

function decodeField(block, offset) {
  const decoded = Buffer.allocUnsafe(4);
  const rawAscending = Buffer.allocUnsafe(4);
  for (let byte = 0; byte < 4; byte += 1) {
    const raw = block.payload[1262 - offset - byte];
    decoded[byte] = decodeRuntimeCountByte(raw);
    rawAscending[3 - byte] = raw;
  }
  return { value: decoded.readUInt32LE(0),
    raw_payload_field_bytes_hex: rawAscending.toString('hex'),
    decoded_field_bytes_hex: decoded.toString('hex') };
}

function decodeHeroKillStatsSnapshotCandidates821(replay, precollected = null) {
  const profile = HERO_KILL_STATS_SNAPSHOT_821_CANDIDATE_PROFILE;
  const base = {
    profile_id: profile.id,
    input_packet_id: profile.replay_block_packet_id,
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
    return fail('UNSUPPORTED', `${CAPABILITY} candidate supports only ${BUILD}`);
  }
  if (precollected === null) {
    let sourceError;
    try { sourceError = replaySourceError(replay); }
    catch (error) { sourceError = error.message; }
    if (sourceError) return fail('DECODE_FAILED', `Replay source failed: ${sourceError}`);
  }
  const tail = assessHeroKillStatsTail821(replay);
  if (tail.status !== 'PASS') return fail(tail.status, tail.error);
  const collected = scanHeroStatsPackets821(replay, precollected, CAPABILITY);
  if (collected.status !== 'PASS') {
    return fail(collected.status, collected.error, collected.details);
  }
  const { frames, scan } = collected;
  const previous = Object.fromEntries(FIELDS.map(({ value_key }) =>
    [value_key, Array(10).fill(null)]));
  const previousTimes = Array(10).fill(null);
  const previousRefs = Array(10).fill(null);
  const events = [];
  for (const frame of frames) for (const row of frame) {
    const { block, rawParam, participantId, ref } = row;
    const index = participantId - 1;
    const mismatch = (error) => fail('DECODE_FAILED', error, {
      ...scan, first_unmatched_packet_ref: ref,
    });
    const values = {};
    const rawBytes = {};
    const decodedBytes = {};
    const confidence = {};
    for (const { tail_field: field, value_key: key, offset } of FIELDS) {
      const decoded = decodeField(block, offset);
      const value = decoded.value;
      if (previous[key][index] === null && value !== 0) {
        return mismatch(`participant ${participantId} first ${field} candidate is not zero`);
      }
      if (previous[key][index] !== null && value < previous[key][index]) {
        return mismatch(`participant ${participantId} has decreasing ${field} candidate`);
      }
      if (value > tail.valuesByField[field][index]) {
        return mismatch(`participant ${participantId} exceeds Replay tail ${field}`);
      }
      previous[key][index] = value;
      values[key] = value;
      rawBytes[field] = decoded.raw_payload_field_bytes_hex;
      decodedBytes[field] = decoded.decoded_field_bytes_hex;
      confidence[key] = field === 'QUADRA_KILLS' ? QUADRA_STATUS : EVIDENCE_STATUS;
    }
    previousTimes[index] = block.timestamp_ms;
    previousRefs[index] = ref;
    events.push({
      event_type: 'HERO_KILL_STATS_SNAPSHOT_CANDIDATE',
      game_version: BUILD,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: block.timestamp_ms,
      hero_raw_param: rawParam,
      participant_id_candidate: participantId,
      ...values,
      raw_payload_field_bytes_hex: rawBytes,
      decoded_field_bytes_hex: decodedBytes,
      observation_kind: 'KEYFRAME_SNAPSHOT',
      confidence: 'CANDIDATE',
      semantic_status: EVIDENCE_STATUS,
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        hero_raw_param: 'VERIFIED_DIRECT',
        participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
        raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
        decoded_field_bytes_hex: 'CANDIDATE_EXACT_821_RUNTIME_TRANSFORM',
        ...confidence,
      },
      raw_packet_ref: ref,
      known_limits: [...profile.known_limits],
    });
  }
  const rawGameLength = replay?.tail?.metadata?.gameLength;
  const gameLengthMs = Number.isSafeInteger(rawGameLength) && rawGameLength >= 0
    ? rawGameLength : null;
  if (gameLengthMs !== null && previousTimes.some((time) => time > gameLengthMs)) {
    return fail('DECODE_FAILED', '0x0089 keyframe timestamp exceeds Replay tail gameLength', scan);
  }
  const tailGaps = Array.from({ length: 10 }, (_, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: previousTimes[index],
    field_gaps: Object.fromEntries(FIELDS.map(({ tail_field: field, value_key: key }) => [
      field, {
        last_snapshot_candidate: previous[key][index],
        final_tail: tail.valuesByField[field][index],
        unobserved_tail_gap: tail.valuesByField[field][index] - previous[key][index],
      },
    ])),
    unobserved_tail_time_ms: gameLengthMs === null ? null
      : gameLengthMs - previousTimes[index],
    last_raw_packet_ref: previousRefs[index],
  }));
  return {
    ...base,
    status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS, ...scan,
    event_count: events.length,
    observed_participant_count: 10,
    final_tail_values: tail.valuesByField,
    observed_last_values: previous,
    tail_gaps: tailGaps,
    tail_gap_totals: Object.fromEntries(FIELDS.map(({ tail_field: field }) => [
      field, tailGaps.reduce((sum, row) =>
        sum + row.field_gaps[field].unobserved_tail_gap, 0),
    ])),
    events,
  };
}

module.exports = {
  HERO_KILL_STATS_SNAPSHOT_821_CANDIDATE_PROFILE,
  assessHeroKillStatsTail821,
  decodeHeroKillStatsSnapshotCandidates821,
};
