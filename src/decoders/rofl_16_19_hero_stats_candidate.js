'use strict';

const crypto = require('node:crypto');

const { walkBlocks } = require('../rofl');

const REPLAY_VERSION = '16.19.820.7193';
const PACKET_ID = 0x0276;
const HERO_PARAM_FIRST = 0x400000ae;
const HERO_PARAM_LAST = 0x400000b7;
const BLOB_LENGTH = 1260;
const PAYLOAD_LENGTH = BLOB_LENGTH + 3;
const EXPERIENCE_OFFSET = 0x28;
const MINIONS_KILLED_OFFSET = 0x3c;
const RUNTIME_IMAGE_SHA256 = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';
const LOOKUP_TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';

// Exact 256-byte table at RVA 0x1ba7600 of the captured 16.19.820.7193 image.
// The deserializer at RVA 0xf33290 uses this table before reversing the blob.
const LOOKUP_TABLE = Buffer.from([
  'd75682dc83028f2935042171799e927fcb976a5105c76fe640637e345b470778',
  '5a96b8b92c995e6ed1754161245f4aaa4bcf0ed4865dba1d3f2bdf62f0330055',
  'cafc19acf3662369bceb46f89c50874d6d108e88be1bb5da4e1a13cc2209ada4',
  '9d30a6e57dfac91712c2fde1bbe70b98bfbd1137c07cf795b6dd49f4812a9f1c',
  'fb8d9a727b577a43b3a953e459202fa8f67436a085f1a7147031840cb2a5dbe8',
  '16ae3d25b1cd9b0367155cea1f39a1440a8b76de606593f264d5c1c84c064fb7',
  'edfee0f9a2184891ce1e3cb46c425494e328e90127ec0d45ff26efe28aabd9f5',
  '08c4af32c56b80c6c358eea33e2d0f893ab0d2d33873d8d08c7790523bd62e68',
].join(''), 'hex');

if (LOOKUP_TABLE.length !== 256
  || crypto.createHash('sha256').update(LOOKUP_TABLE).digest('hex') !== LOOKUP_TABLE_SHA256) {
  throw new Error('exact-build HeroStats lookup table identity mismatch');
}

const HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-hero-minions-killed-keyframe-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_minions_killed_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  stream_tags: Object.freeze([2, 3]),
  hero_raw_param_first: HERO_PARAM_FIRST,
  hero_raw_param_last: HERO_PARAM_LAST,
  payload_length: PAYLOAD_LENGTH,
  decoded_blob_length: BLOB_LENGTH,
  minions_killed_f32le_offset: MINIONS_KILLED_OFFSET,
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: 'exact HN runtime HeroStats deserializer and one HN Replay with 350 keyframe snapshots',
  known_limits: Object.freeze([
    'Only observed keyframe 0x0276 snapshots are emitted; no minion kill event or intervening value is inferred.',
    'The offset 0x3c interpretation and hero participant mapping remain candidates from one HN Replay.',
    'The Replay tail can exceed the last observed snapshot; tail gaps are reported without interpolation.',
  ]),
});

const HERO_EXPERIENCE_SNAPSHOT_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-hero-experience-keyframe-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_experience_snapshot',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: PACKET_ID,
  stream_tags: Object.freeze([2, 3]),
  hero_raw_param_first: HERO_PARAM_FIRST,
  hero_raw_param_last: HERO_PARAM_LAST,
  payload_length: PAYLOAD_LENGTH,
  decoded_blob_length: BLOB_LENGTH,
  experience_f32le_offset_candidate: EXPERIENCE_OFFSET,
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  lookup_table_sha256: LOOKUP_TABLE_SHA256,
  evidence_scope: 'exact HN runtime HeroStats deserializer; offset 0x28 correlates with EXP in one HN Replay with 350 keyframe snapshots',
  known_limits: Object.freeze([
    'Only observed keyframe 0x0276 snapshots are emitted; no experience-gain event or intervening value is inferred.',
    'The offset 0x28 experience interpretation and hero participant mapping remain candidates from one HN Replay, not exact-runtime field semantics.',
    'The Replay tail can exceed the last observed floor(snapshot); tail gaps are reported without interpolation.',
  ]),
});

function decodeHeroStatsByte(encoded) {
  const x = LOOKUP_TABLE[encoded];
  let y = (((x & 0xd5) << 1) | ((x >>> 1) & 0x55)) & 0xff;
  y = ((y >>> 5) | (y << 3)) & 0xff;
  y = (y + 0x7e) & 0xff;
  return ((~y) - 0x5a) & 0xff;
}

function decodeHeroStatsBlob(payload) {
  if (!Buffer.isBuffer(payload) || payload.length !== PAYLOAD_LENGTH) {
    return { status: 'DECODE_FAILED', error: `HeroStats payload must contain exactly ${PAYLOAD_LENGTH} bytes` };
  }
  if (payload[0] !== 0x1c || payload[1] !== 0xa6 || payload[2] !== 0xe8) {
    return { status: 'DECODE_FAILED', error: 'HeroStats selector or encoded varint prefix differs from the exact HN profile' };
  }
  const firstVarintByte = decodeHeroStatsByte(payload[1]);
  const secondVarintByte = decodeHeroStatsByte(payload[2]);
  if ((firstVarintByte & 0x80) === 0 || (secondVarintByte & 0x80) !== 0
    || ((firstVarintByte & 0x7f) | (secondVarintByte << 7)) !== BLOB_LENGTH) {
    return { status: 'DECODE_FAILED', error: 'HeroStats decoded varint length differs from the exact HN profile' };
  }
  const blob = Buffer.allocUnsafe(BLOB_LENGTH);
  for (let index = 0; index < BLOB_LENGTH; index += 1) {
    blob[BLOB_LENGTH - 1 - index] = decodeHeroStatsByte(payload[index + 3]);
  }
  return { status: 'PASS', blob };
}

function decodeHeroMinionsKilledPayload(payload) {
  const decoded = decodeHeroStatsBlob(payload);
  if (decoded.status !== 'PASS') return decoded;
  const value = decoded.blob.readFloatLE(MINIONS_KILLED_OFFSET);
  if (!Number.isSafeInteger(value) || value < 0) {
    return { status: 'DECODE_FAILED', error: 'HeroStats offset 0x3c is not a finite nonnegative integer f32' };
  }
  return { status: 'PASS', minions_killed_candidate: value };
}

function decodeHeroExperiencePayload(payload) {
  const decoded = decodeHeroStatsBlob(payload);
  if (decoded.status !== 'PASS') return decoded;
  const value = decoded.blob.readFloatLE(EXPERIENCE_OFFSET);
  if (!Number.isFinite(value) || value < 0 || !Number.isSafeInteger(Math.floor(value))) {
    return { status: 'DECODE_FAILED', error: 'HeroStats offset 0x28 is not a finite nonnegative safe-range f32 experience candidate' };
  }
  return { status: 'PASS', experience_points_candidate: value,
    experience_floor_candidate: Math.floor(value) };
}

function assessHeroStatsTail(replay, field) {
  const stats = replay?.tail?.stats;
  if (!Array.isArray(stats)) {
    return { field, status: 'MISSING_INPUT',
      error: 'Replay tail statsJson participant rows are missing' };
  }
  if (stats.length !== 10) {
    return { field, status: 'UNSUPPORTED',
      error: `candidate scope requires 10 participants; got ${stats.length}` };
  }
  const rawValues = stats.map((row) => row?.[field]);
  if (rawValues.some((value) => value === undefined || value === null || value === '')) {
    return { field, status: 'MISSING_INPUT',
      error: `Replay tail ${field} is missing for one or more participants` };
  }
  if (rawValues.some((value) =>
    !(typeof value === 'string' && /^\d+$/.test(value))
    && !(Number.isSafeInteger(value) && value >= 0))) {
    return { field, status: 'UNSUPPORTED',
      error: `Replay tail ${field} must be nonnegative integers` };
  }
  const values = rawValues.map(Number);
  if (values.some((value) => !Number.isSafeInteger(value))) {
    return { field, status: 'UNSUPPORTED',
      error: `Replay tail ${field} must be safe integers` };
  }
  return { field, status: 'PASS', values };
}

function assessHeroMinionsKilledSnapshotTail(replay) {
  return assessHeroStatsTail(replay, 'MINIONS_KILLED');
}

function assessHeroExperienceSnapshotTail(replay) {
  return assessHeroStatsTail(replay, 'EXP');
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

function collectHeroStatsSnapshotCandidates(replay, spec) {
  const { profile } = spec;
  const base = { profile_id: profile.id, input_packet_id: PACKET_ID };
  if (replay?.header?.version !== REPLAY_VERSION) {
    return { ...base, status: 'UNSUPPORTED', event_count: null, input_count: null,
      scanned_block_count: null, events: null,
      error: `${profile.capability} candidate supports only ${REPLAY_VERSION}` };
  }
  const rows = [];
  let walk;
  try {
    walk = walkBlocks(replay, (block, chunk) => {
      if (block.packet_id === PACKET_ID) rows.push({ block, chunk });
    }, { includeStreams: [2, 3], strict: true });
  } catch (error) {
    return { ...base, status: 'DECODE_FAILED', event_count: null, input_count: null,
      scanned_block_count: null, events: null, error: `Replay keyframe framing failed: ${error.message}` };
  }
  if (rows.length === 0) {
    return { ...base, status: 'PROFILE_UNAVAILABLE', event_count: null, input_count: null,
      scanned_block_count: walk.block_count, events: null,
      error: 'HN HeroStats 0x0276 keyframe route is absent from this Replay' };
  }
  const hasHnFingerprint = rows.some(({ block }) => block.payload_length === PAYLOAD_LENGTH
    && block.payload[0] === 0x1c && block.payload[1] === 0xa6 && block.payload[2] === 0xe8);
  if (!hasHnFingerprint) {
    return { ...base, status: 'PROFILE_UNAVAILABLE', event_count: null, input_count: null,
      scanned_block_count: walk.block_count, observed_raw_route_count: rows.length, events: null,
      error: '0x0276 keyframe route is present, but no packet matches the exact HN HeroStats payload fingerprint' };
  }
  const inputCount = rows.length;
  const fail = (error) => ({ ...base, status: 'DECODE_FAILED', event_count: null,
    input_count: inputCount, scanned_block_count: walk.block_count, events: null, error });
  const tail = spec.assessTail(replay);
  if (tail.status !== 'PASS') {
    return { ...base, status: tail.status, event_count: null, input_count: inputCount,
      scanned_block_count: walk.block_count, events: null, error: tail.error };
  }
  rows.sort((left, right) => left.block.timestamp_ms - right.block.timestamp_ms
    || (left.block.param >>> 0) - (right.block.param >>> 0)
    || left.chunk.index - right.chunk.index || left.block.offset - right.block.offset);
  const previous = Array(10).fill(null);
  const lastTimes = Array(10).fill(null);
  const observations = [];
  let timestamp = null;
  let currentGroup = new Set();
  let keyframeTimestampCount = 0;
  for (const { block, chunk } of rows) {
    const rawParam = block.param >>> 0;
    if (rawParam < HERO_PARAM_FIRST || rawParam > HERO_PARAM_LAST) {
      return fail(`HN HeroStats route has unsupported raw param 0x${rawParam.toString(16)}`);
    }
    if (!Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0) {
      return fail('HN HeroStats route has invalid Replay timestamp');
    }
    if (block.timestamp_ms !== timestamp) {
      if (timestamp !== null && currentGroup.size !== 10) {
        return fail(`HN HeroStats keyframe at ${timestamp} ms lacks one or more hero params`);
      }
      timestamp = block.timestamp_ms;
      currentGroup = new Set();
      keyframeTimestampCount += 1;
    }
    const participantId = rawParam - HERO_PARAM_FIRST + 1;
    if (currentGroup.has(participantId)) {
      return fail(`HN HeroStats keyframe duplicates participant ${participantId} at ${timestamp} ms`);
    }
    currentGroup.add(participantId);
    const decoded = spec.decodePayload(block.payload);
    if (decoded.status !== 'PASS') {
      return fail(`${decoded.error} at ${block.timestamp_ms} ms, participant ${participantId}`);
    }
    const value = decoded[spec.valueKey];
    if (previous[participantId - 1] !== null && value < previous[participantId - 1]) {
      return fail(`HN participant ${participantId} has a decreasing observed ${tail.field} snapshot`);
    }
    if (spec.tailProjection(value) > tail.values[participantId - 1]) {
      return fail(`HN participant ${participantId} exceeds Replay tail ${tail.field}`);
    }
    previous[participantId - 1] = value;
    lastTimes[participantId - 1] = block.timestamp_ms;
    observations.push({ block, chunk, rawParam, participantId, value,
      rawPacketRef: packetRef(replay, block, chunk) });
  }
  if (currentGroup.size !== 10) {
    return fail(`HN HeroStats keyframe at ${timestamp} ms lacks one or more hero params`);
  }
  const gameLength = replay?.tail?.metadata?.gameLength;
  const gameLengthMs = Number.isSafeInteger(gameLength) && gameLength >= 0 ? gameLength : null;
  if (gameLengthMs !== null && lastTimes.some((time) => gameLengthMs - time < 0)) {
    return fail('HN HeroStats keyframe timestamp exceeds Replay tail gameLength');
  }
  return {
    ...base,
    status: 'CANDIDATE',
    event_count: observations.length,
    input_count: inputCount,
    scanned_block_count: walk.block_count,
    keyframe_timestamp_count: keyframeTimestampCount,
    observed_participant_count: previous.filter((value) => value !== null).length,
    observations,
    previous,
    lastTimes,
    tailValues: tail.values,
    gameLengthMs,
  };
}

function snapshotEvent(replay, profile, observation, semanticStatus, valueFields, fieldConfidence) {
  return {
    event_type: `HERO_${profile.capability === 'hero_experience_snapshot' ? 'EXPERIENCE' : 'MINIONS_KILLED'}_SNAPSHOT_CANDIDATE`,
    game_version: REPLAY_VERSION,
    patch: '16.19',
    build_profile: profile.id,
    replay_sha256: replay.source_sha256 ?? null,
    replay_time_ms: observation.block.timestamp_ms,
    hero_raw_param: observation.rawParam,
    participant_id_candidate: observation.participantId,
    ...valueFields,
    observation_kind: 'KEYFRAME_SNAPSHOT',
    confidence: 'CANDIDATE',
    semantic_status: semanticStatus,
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      hero_raw_param: 'VERIFIED_DIRECT',
      participant_id_candidate: 'CANDIDATE',
      ...fieldConfidence,
    },
    raw_packet_ref: observation.rawPacketRef,
    known_limits: [...profile.known_limits],
  };
}

function decodeHeroMinionsKilledSnapshotCandidates(replay) {
  const profile = HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE;
  const collected = collectHeroStatsSnapshotCandidates(replay, {
    profile,
    assessTail: assessHeroMinionsKilledSnapshotTail,
    decodePayload: decodeHeroMinionsKilledPayload,
    valueKey: 'minions_killed_candidate',
    tailProjection: (value) => value,
  });
  if (collected.status !== 'CANDIDATE') return collected;
  const { observations, previous, lastTimes, tailValues, gameLengthMs, ...base } = collected;
  const tailGaps = tailValues.map((finalValue, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: lastTimes[index],
    last_snapshot_minions_killed_candidate: previous[index],
    final_minions_killed_tail: finalValue,
    unobserved_tail_gap: finalValue - previous[index],
    unobserved_tail_time_ms: gameLengthMs === null ? null : gameLengthMs - lastTimes[index],
  }));
  return {
    ...base,
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_KEYFRAME_FIELD_AND_TAIL_BOUND',
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    final_minions_killed: tailValues,
    observed_max_minions_killed: previous,
    tail_gaps: tailGaps,
    tail_gap_total: tailGaps.reduce((sum, gap) => sum + gap.unobserved_tail_gap, 0),
    events: observations.map((observation) => snapshotEvent(replay, profile, observation,
      'CANDIDATE_EXACT_RUNTIME_KEYFRAME_FIELD_AND_TAIL_BOUND',
      { minions_killed_candidate: observation.value },
      { minions_killed_candidate: 'CANDIDATE_EXACT_RUNTIME_FIELD' })),
  };
}

function decodeHeroExperienceSnapshotCandidates(replay) {
  const profile = HERO_EXPERIENCE_SNAPSHOT_CANDIDATE_PROFILE;
  const collected = collectHeroStatsSnapshotCandidates(replay, {
    profile,
    assessTail: assessHeroExperienceSnapshotTail,
    decodePayload: decodeHeroExperiencePayload,
    valueKey: 'experience_points_candidate',
    tailProjection: Math.floor,
  });
  if (collected.status !== 'CANDIDATE') return collected;
  const { observations, previous, lastTimes, tailValues, gameLengthMs, ...base } = collected;
  const tailGaps = tailValues.map((finalValue, index) => ({
    participant_id_candidate: index + 1,
    last_snapshot_replay_time_ms: lastTimes[index],
    last_snapshot_experience_points_candidate: previous[index],
    last_snapshot_experience_floor_candidate: Math.floor(previous[index]),
    final_experience_tail: finalValue,
    unobserved_tail_floor_gap: finalValue - Math.floor(previous[index]),
    unobserved_tail_time_ms: gameLengthMs === null ? null : gameLengthMs - lastTimes[index],
  }));
  return {
    ...base,
    evidence_status: 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_FIELD_CORRELATION',
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    final_experience: tailValues,
    observed_max_experience_points: previous,
    observed_max_experience_floor: previous.map(Math.floor),
    tail_gaps: tailGaps,
    tail_gap_total: tailGaps.reduce((sum, gap) => sum + gap.unobserved_tail_floor_gap, 0),
    events: observations.map((observation) => snapshotEvent(replay, profile, observation,
      'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_FIELD_CORRELATION',
      { experience_points_candidate: observation.value,
        experience_floor_candidate: Math.floor(observation.value) },
      { experience_points_candidate: 'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION',
        experience_floor_candidate: 'DERIVED_FROM_CANDIDATE' })),
  };
}

module.exports = {
  HERO_EXPERIENCE_SNAPSHOT_CANDIDATE_PROFILE,
  HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE,
  assessHeroExperienceSnapshotTail,
  assessHeroMinionsKilledSnapshotTail,
  decodeHeroStatsByte,
  decodeHeroExperiencePayload,
  decodeHeroExperienceSnapshotCandidates,
  decodeHeroMinionsKilledPayload,
  decodeHeroMinionsKilledSnapshotCandidates,
};
