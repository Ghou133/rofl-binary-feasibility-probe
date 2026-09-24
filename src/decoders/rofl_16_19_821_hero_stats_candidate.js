'use strict';

const crypto = require('node:crypto');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');

const REPLAY_VERSION = '16.19.821.7343';
const PACKET_ID = 0x0089;
const HERO_PARAM_FIRST = 0x400000ae;
const HERO_PARAM_LAST = 0x400000b7;
const PAYLOAD_LENGTH = 1263;
const RAW_DEATHS_BYTE_INDEX = 1182;
const PAYLOAD_PREFIX_HEX = '6700de';
const ENCODED_BYTE_FOR_DEATH_COUNT = Object.freeze([
  0x97, 0xcc, 0x55, 0xf1, 0x6f, 0x8d, 0x58,
  0x02, 0xb7, 0xde, 0x3f, 0xb6, 0xbe,
]);
const DEATH_COUNT_BY_ENCODED_BYTE = new Map(
  ENCODED_BYTE_FOR_DEATH_COUNT.map((encoded, count) => [encoded, count]));
const EVIDENCE_STATUS = 'CANDIDATE_EXACT_KR_821_RAW_BYTE_DEATH_COUNT_TAIL_CORRELATION';

// This profile decodes one observed raw byte. It does not decode the 1260-byte
// HeroStats blob or reuse the 16.19.820.7193 runtime lookup table.
const HERO_DEATHS_SNAPSHOT_821_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-hero-deaths-raw-byte-keyframe-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_deaths_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  stream_tags: Object.freeze([2]),
  hero_raw_param_first: HERO_PARAM_FIRST,
  hero_raw_param_last: HERO_PARAM_LAST,
  payload_length: PAYLOAD_LENGTH,
  payload_prefix_hex: PAYLOAD_PREFIX_HEX,
  raw_deaths_byte_index: RAW_DEATHS_BYTE_INDEX,
  encoded_byte_for_death_count_candidate: ENCODED_BYTE_FOR_DEATH_COUNT,
  evidence_runtime_image_sha256: null,
  evidence_scope: '11 exact 16.19.821.7343 KR Replays, 327 keyframes and 3270 route packets; 110 participant sequences start at zero and are monotone; 82 final values equal NUM_DEATHS tails and 28 lag by one',
  known_limits: Object.freeze([
    'Only the observed 0x0089 keyframe raw byte is interpreted as a death-count candidate; the rest of the payload remains opaque.',
    'The finite codebook covers candidate counts 0 through 12 only. An unrecognized encoded byte fails closed.',
    'No exact 16.19.821.7343 runtime image or deserializer proof is available.',
    'Keyframe counts are snapshots, not individual death events or exact death times.',
    'The Replay tail can exceed the last keyframe by one; the gap is retained without interpolation.',
  ]),
});

function assessHeroDeathsSnapshotTail821(replay) {
  const field = 'NUM_DEATHS';
  if (replay?.header?.version !== REPLAY_VERSION) {
    return { field, status: 'UNSUPPORTED',
      error: `candidate supports only ${REPLAY_VERSION}` };
  }
  const stats = replay?.tail?.stats;
  if (!Array.isArray(stats)) {
    return { field, status: 'MISSING_INPUT',
      error: 'Replay tail statsJson participant rows are missing' };
  }
  if (stats.length !== 10) {
    return { field, status: 'UNSUPPORTED',
      error: `candidate scope requires 10 participants; got ${stats.length}` };
  }
  const rawValues = stats.map((row) => row?.NUM_DEATHS);
  if (rawValues.some((value) => value === undefined || value === null || value === '')) {
    return { field, status: 'MISSING_INPUT',
      error: 'Replay tail NUM_DEATHS is missing for one or more participants' };
  }
  if (rawValues.some((value) =>
    !(typeof value === 'string' && /^\d+$/.test(value))
    && !(Number.isSafeInteger(value) && value >= 0))) {
    return { field, status: 'UNSUPPORTED',
      error: 'Replay tail NUM_DEATHS must contain nonnegative integers' };
  }
  const values = rawValues.map(Number);
  if (values.some((value) => !Number.isSafeInteger(value))) {
    return { field, status: 'UNSUPPORTED',
      error: 'Replay tail NUM_DEATHS must contain safe integers' };
  }
  return { field, status: 'PASS', values };
}

function packetRef(replay, block, chunk) {
  return {
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256 ?? null,
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id,
    replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function decodeHeroDeathsSnapshotCandidates821(replay, precollected = null) {
  const profile = HERO_DEATHS_SNAPSHOT_821_CANDIDATE_PROFILE;
  const base = { profile_id: profile.id, input_packet_id: PACKET_ID };
  const fail = (status, error, details = {}) => ({
    ...base, status, event_count: null, events: null, error, ...details,
  });
  if (replay?.header?.version !== REPLAY_VERSION) {
    return fail('UNSUPPORTED', `hero_deaths_snapshot candidate supports only ${REPLAY_VERSION}`);
  }
  let sourceError = null;
  if (precollected === null) {
    try {
      sourceError = replaySourceError(replay);
    } catch (error) {
      sourceError = error.message;
    }
  }
  if (sourceError) return fail('DECODE_FAILED', `Replay source failed: ${sourceError}`);

  const tail = assessHeroDeathsSnapshotTail821(replay);
  if (tail.status !== 'PASS') return fail(tail.status, tail.error);

  const keyframeChunks = replay.chunks.filter((chunk) => chunk.stream_tag === 2);
  const byChunk = new Map(keyframeChunks.map((chunk) => [chunk.index, []]));
  const startKeyframeRows = [];
  let walk;
  if (precollected !== null) {
    const scan = rowsFor821Capability(replay, precollected, 'hero_deaths_snapshot');
    if (scan.error) return fail('DECODE_FAILED', scan.error);
    for (const { block, chunk } of scan.rows) {
      if (chunk.stream_tag === 2) byChunk.get(chunk.index).push({ block, chunk });
      else startKeyframeRows.push({ block, chunk });
    }
    walk = { block_count: scan.scanned_block_count };
  } else {
    try {
      walk = walkBlocks(replay, (block, chunk) => {
        if (block.packet_id !== PACKET_ID) return;
        if (chunk.stream_tag === 2) byChunk.get(chunk.index).push({ block, chunk });
        else startKeyframeRows.push({ block, chunk });
      }, { includeStreams: [2, 3], strict: true });
    } catch (error) {
      return fail('DECODE_FAILED', `Replay keyframe framing failed: ${error.message}`);
    }
  }
  const inputCount = [...byChunk.values()].reduce((count, rows) => count + rows.length, 0);
  const scan = { input_count: inputCount, scanned_block_count: walk.block_count,
    keyframe_count: keyframeChunks.length };
  if (startKeyframeRows.length > 0) {
    const { block, chunk } = startKeyframeRows[0];
    return fail('DECODE_FAILED', '0x0089 packet in start_keyframe is outside the observed KR profile', {
      ...scan, first_unmatched_packet_ref: packetRef(replay, block, chunk),
    });
  }
  if (inputCount === 0) {
    return fail('PROFILE_UNAVAILABLE', 'KR 0x0089 keyframe route is absent from this Replay', scan);
  }

  const previous = Array(10).fill(null);
  const previousTimes = Array(10).fill(null);
  const previousRefs = Array(10).fill(null);
  const observations = [];
  for (const chunk of keyframeChunks) {
    const rows = byChunk.get(chunk.index);
    if (rows.length !== 10) {
      return fail('DECODE_FAILED', `keyframe chunk ${chunk.index} has ${rows.length} 0x0089 hero packets; expected 10`, scan);
    }
    const byParticipant = new Map();
    let timestamp = null;
    for (const row of rows) {
      const { block } = row;
      const ref = packetRef(replay, block, chunk);
      const rawParam = block.param >>> 0;
      if (rawParam < HERO_PARAM_FIRST || rawParam > HERO_PARAM_LAST) {
        return fail('DECODE_FAILED', `0x0089 has unsupported raw param 0x${rawParam.toString(16)}`, {
          ...scan, first_unmatched_packet_ref: ref,
        });
      }
      if (block.payload_length !== PAYLOAD_LENGTH
          || block.payload.length !== PAYLOAD_LENGTH
          || block.payload.subarray(0, 3).toString('hex') !== PAYLOAD_PREFIX_HEX) {
        return fail('DECODE_FAILED', '0x0089 payload differs from KR 821 length or prefix', {
          ...scan, first_unmatched_packet_ref: ref,
        });
      }
      if (!Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0
          || (timestamp !== null && block.timestamp_ms !== timestamp)) {
        return fail('DECODE_FAILED', '0x0089 keyframe has invalid or inconsistent Replay time', {
          ...scan, first_unmatched_packet_ref: ref,
        });
      }
      timestamp = block.timestamp_ms;
      const participantId = rawParam - HERO_PARAM_FIRST + 1;
      if (byParticipant.has(participantId)) {
        return fail('DECODE_FAILED', `0x0089 keyframe duplicates participant ${participantId}`, {
          ...scan, first_unmatched_packet_ref: ref,
        });
      }
      const rawByte = block.payload[RAW_DEATHS_BYTE_INDEX];
      if (!DEATH_COUNT_BY_ENCODED_BYTE.has(rawByte)) {
        return fail('DECODE_FAILED', `0x0089 byte ${RAW_DEATHS_BYTE_INDEX} has unknown code 0x${rawByte.toString(16).padStart(2, '0')}`, {
          ...scan, first_unmatched_packet_ref: ref,
        });
      }
      const value = DEATH_COUNT_BY_ENCODED_BYTE.get(rawByte);
      const index = participantId - 1;
      if (previous[index] === null && value !== 0) {
        return fail('DECODE_FAILED', `participant ${participantId} first observed death count is not zero`, {
          ...scan, first_unmatched_packet_ref: ref,
        });
      }
      if (previous[index] !== null && value < previous[index]) {
        return fail('DECODE_FAILED', `participant ${participantId} has decreasing observed death count`, {
          ...scan, first_unmatched_packet_ref: ref,
        });
      }
      if (previousTimes[index] !== null && block.timestamp_ms < previousTimes[index]) {
        return fail('DECODE_FAILED', `participant ${participantId} Replay time decreased`, {
          ...scan, first_unmatched_packet_ref: ref,
        });
      }
      if (value > tail.values[index]) {
        return fail('DECODE_FAILED', `participant ${participantId} exceeds Replay tail NUM_DEATHS`, {
          ...scan, first_unmatched_packet_ref: ref,
        });
      }
      byParticipant.set(participantId, { block, chunk, rawParam, rawByte, value, ref });
    }
    for (let participantId = 1; participantId <= 10; participantId += 1) {
      const row = byParticipant.get(participantId);
      if (!row) return fail('DECODE_FAILED', `0x0089 keyframe lacks participant ${participantId}`, scan);
      const index = participantId - 1;
      previous[index] = row.value;
      previousTimes[index] = row.block.timestamp_ms;
      previousRefs[index] = row.ref;
      observations.push({ ...row, participantId });
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
    last_snapshot_deaths_candidate: previous[index],
    final_num_deaths_tail: finalValue,
    unobserved_tail_gap: finalValue - previous[index],
    unobserved_tail_time_ms: gameLengthMs === null ? null : gameLengthMs - previousTimes[index],
    last_raw_packet_ref: previousRefs[index],
  }));
  const invalidGap = tailGaps.find((gap) => gap.unobserved_tail_gap < 0
    || gap.unobserved_tail_gap > 1);
  if (invalidGap) {
    return fail('DECODE_FAILED', `participant ${invalidGap.participant_id_candidate} final death-count tail gap is outside 0..1`, {
      ...scan, first_unmatched_packet_ref: invalidGap.last_raw_packet_ref,
    });
  }
  const events = observations.map((row) => ({
    event_type: 'HERO_DEATHS_SNAPSHOT_CANDIDATE',
    game_version: REPLAY_VERSION,
    patch: '16.19',
    build_profile: profile.id,
    replay_sha256: replay.source_sha256,
    replay_time_ms: row.block.timestamp_ms,
    hero_raw_param: row.rawParam,
    participant_id_candidate: row.participantId,
    raw_deaths_byte: row.rawByte,
    deaths_candidate: row.value,
    observation_kind: 'KEYFRAME_SNAPSHOT',
    confidence: 'CANDIDATE',
    semantic_status: EVIDENCE_STATUS,
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      hero_raw_param: 'VERIFIED_DIRECT',
      raw_deaths_byte: 'VERIFIED_DIRECT',
      participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
      deaths_candidate: EVIDENCE_STATUS,
    },
    raw_packet_ref: row.ref,
    known_limits: [...profile.known_limits],
  }));
  return {
    ...base,
    status: 'CANDIDATE',
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: null,
    ...scan,
    event_count: events.length,
    observed_participant_count: 10,
    final_num_deaths: tail.values,
    observed_max_deaths: previous,
    tail_gaps: tailGaps,
    tail_gap_total: tailGaps.reduce((sum, gap) => sum + gap.unobserved_tail_gap, 0),
    events,
  };
}

module.exports = {
  HERO_DEATHS_SNAPSHOT_821_CANDIDATE_PROFILE,
  assessHeroDeathsSnapshotTail821,
  decodeHeroDeathsSnapshotCandidates821,
};
