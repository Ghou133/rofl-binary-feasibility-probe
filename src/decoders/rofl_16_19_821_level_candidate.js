'use strict';

const crypto = require('node:crypto');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');

const REPLAY_VERSION_821 = '16.19.821.7343';

// The level-byte codebook was calibrated on two exact-build KR Replays and
// checked against nine others. First-byte shape includes all eleven observed
// Replays. This is a byte-to-tail correlation, not a runtime field transform.
const LEVEL_BY_LAST_PAYLOAD_BYTE = Object.freeze({
  0x75: 3, 0x80: 4, 0x0b: 5, 0x46: 6, 0x16: 7, 0xd4: 8,
  0xb6: 9, 0xfc: 10, 0x1e: 11, 0x4b: 12, 0xed: 13,
  0x3c: 14, 0xd1: 15, 0xac: 16, 0x1c: 17, 0x11: 18, 0x28: 19,
});
const OBSERVED_TWO_BYTE_PREFIXES = new Set([0xe1, 0xe2, 0xe4, 0xe7, 0xf9, 0xfa, 0xfc, 0xff]);

const HERO_LEVEL_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-level-route-tail-candidate-v1',
  replay_version: REPLAY_VERSION_821,
  capability: 'hero_level_state',
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: 0x0197,
  participant_mapping: 'only 0x400000ae..b7 and 0x400001ae..b7; low byte aligns to Replay tail participant 1..10',
  evidence_scope: 'two calibration and nine independent KR exact-build Replays; observed payload codebook 1..19',
  evidence_runtime_image_sha256: null,
  known_limits: Object.freeze([
    'Experimental exact-build Replay-tail candidate, not a published level capability.',
    'Level 1..19 values use an observed raw-payload codebook, not an 821 runtime field transform.',
    'Level 20 code 0x4d in one Replay is unclassified; that Replay fails closed without candidate events.',
    'An adjacent 0x400002ae packet in one Replay is retained as an unclassified route lead, not a mapped hero packet.',
    'Repeated packets are observations, not extra level transitions; gaps are reported without reconstruction.',
    'No experience, level-before, complete level timeline, or level causation is inferred.',
  ]),
});

function assessHeroLevelTail821(replay) {
  const stats = replay?.tail?.stats;
  if (!Array.isArray(stats)) {
    return { status: 'MISSING_INPUT', missing_input: 'Replay tail statsJson participant rows' };
  }
  if (stats.length !== 10) {
    return { status: 'UNSUPPORTED', error: `candidate scope requires 10 participants; got ${stats.length}` };
  }
  const values = stats.map((row) => row?.LEVEL);
  if (values.some((value) => value === undefined || value === null || value === '')) {
    return { status: 'MISSING_INPUT', missing_input: 'Replay tail LEVEL for all 10 participants' };
  }
  if (values.some((value) =>
    !(typeof value === 'string' && /^\d+$/.test(value))
    && !(Number.isSafeInteger(value) && value >= 1))) {
    return { status: 'UNSUPPORTED', error: 'Replay tail LEVEL must be positive integers' };
  }
  const levels = values.map(Number);
  if (levels.some((value) => !Number.isSafeInteger(value) || value < 1 || value > 20)) {
    return { status: 'UNSUPPORTED', error: 'Replay tail LEVEL is outside the bounded 1..20 candidate scope' };
  }
  return { status: 'PASS', levels };
}

function participantFrom821LevelRawParam(rawParam) {
  if (!Number.isInteger(rawParam) || rawParam < 0 || rawParam > 0xffffffff) return null;
  const inObservedFamily = (rawParam >= 0x400000ae && rawParam <= 0x400000b7)
    || (rawParam >= 0x400001ae && rawParam <= 0x400001b7);
  return inObservedFamily ? (rawParam & 0xff) - 0xad : null;
}

function isAdjacentUnclassifiedParam(rawParam) {
  return rawParam >= 0x400002ae && rawParam <= 0x400002b7;
}

function packetRef(replay, source) {
  const { block, chunk } = source;
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
    raw_payload_hex: block.payload.toString('hex'),
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function decodeLevelCode(payload) {
  if (payload.length === 1) {
    if (payload[0] === 0xde) return { level: 1, code: 0xde };
    if (payload[0] === 0xe5) return { level: 2, code: 0xe5 };
    return null;
  }
  if (payload.length !== 2 || !OBSERVED_TWO_BYTE_PREFIXES.has(payload[0])) return null;
  const level = LEVEL_BY_LAST_PAYLOAD_BYTE[payload[1]];
  return level === undefined ? null : { level, code: payload[1] };
}

function decodeHeroLevelCandidates821(replay) {
  const profile = HERO_LEVEL_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: profile.replay_block_packet_id,
    runtime_image_used: false,
    runtime_image_status: 'NOT_REQUIRED_ROUTE_TAIL_CANDIDATE',
    evidence_runtime_image_sha256: null,
    known_limits: [...profile.known_limits],
  };
  if (replay?.header?.version !== REPLAY_VERSION_821) {
    return { ...base, status: 'UNSUPPORTED', event_count: null, input_count: null,
      events: null, error: `hero_level_state candidate supports only ${REPLAY_VERSION_821}` };
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) {
    return { ...base, status: 'DECODE_FAILED', event_count: null, input_count: null,
      events: null, error: `Replay source integrity failed: ${sourceError}` };
  }

  const rows = [];
  const adjacent = [];
  let walked;
  try {
    walked = walkBlocks(replay, (block, chunk) => {
      if (chunk.stream_tag !== profile.stream_tag || block.packet_id !== profile.replay_block_packet_id) return;
      if (participantFrom821LevelRawParam(block.param) !== null) rows.push({ block, chunk });
      else if (isAdjacentUnclassifiedParam(block.param)) adjacent.push({ block, chunk });
    }, { strict: true });
  } catch (error) {
    return { ...base, status: 'DECODE_FAILED', event_count: null, input_count: null,
      events: null, error: `Replay framing failed: ${error.message}` };
  }
  const common = {
    ...base,
    input_count: rows.length,
    scanned_block_count: walked.block_count,
    unclassified_adjacent_prefix_count: adjacent.length,
    unclassified_adjacent_prefix_refs: adjacent.map((row) => packetRef(replay, row)),
  };
  if (rows.length === 0) {
    return { ...common, status: 'PROFILE_UNAVAILABLE', event_count: null,
      events: null, error: 'no 821 level route packets in the two observed hero raw-param families' };
  }
  const fail = (error, rejected = null) => ({
    ...common, status: 'DECODE_FAILED', event_count: null, events: null, error,
    ...(rejected ? { rejected_packet_ref: packetRef(replay, rejected) } : {}),
  });
  const tail = assessHeroLevelTail821(replay);
  if (tail.status !== 'PASS') {
    return { ...common, ...tail, event_count: null, events: null };
  }

  const sorted = [...rows].sort((left, right) => left.block.timestamp_ms - right.block.timestamp_ms
    || left.chunk.index - right.chunk.index || left.block.offset - right.block.offset);
  const lastLevel = Array(10).fill(null);
  const seenLevels = Array.from({ length: 10 }, () => new Set());
  const decoded = [];
  let repeatedCount = 0;
  for (const row of sorted) {
    const participantId = participantFrom821LevelRawParam(row.block.param);
    const payload = decodeLevelCode(row.block.payload);
    if (!payload) {
      return fail(`unclassified 821 level payload ${row.block.payload.toString('hex')} at ${row.block.timestamp_ms} ms`, row);
    }
    const index = participantId - 1;
    const previous = lastLevel[index];
    if (previous !== null && payload.level < previous) {
      return fail(`participant ${participantId} has a decreasing observed level`, row);
    }
    if (payload.level > tail.levels[index]) {
      return fail(`participant ${participantId} exceeds Replay tail LEVEL`, row);
    }
    const repeated = previous !== null && payload.level === previous;
    if (repeated) repeatedCount += 1;
    lastLevel[index] = payload.level;
    seenLevels[index].add(payload.level);
    decoded.push({ row, participantId, payload, repeated });
  }
  if (lastLevel.some((level, index) => level !== tail.levels[index])) {
    return fail('last observed participant levels do not match Replay tail LEVEL');
  }
  const missingLevels = tail.levels.map((finalLevel, index) => {
    const missing = [];
    for (let level = 2; level <= finalLevel; level += 1) {
      if (!seenLevels[index].has(level)) missing.push(level);
    }
    return missing;
  });
  const events = decoded.map(({ row, participantId, payload, repeated }) => ({
    event_type: 'HERO_LEVEL_STATE_CANDIDATE',
    game_version: REPLAY_VERSION_821,
    patch: '16.19',
    build_profile: profile.id,
    replay_sha256: replay.source_sha256 ?? null,
    replay_time_ms: row.block.timestamp_ms,
    hero_raw_param: row.block.param >>> 0,
    participant_id_candidate: participantId,
    level_after_candidate: payload.level,
    observation_kind: repeated ? 'REPEATED_LEVEL_OBSERVATION'
      : payload.level === 1 ? 'LEVEL_ONE_OBSERVATION' : 'HIGHER_LEVEL_OBSERVATION',
    raw_payload_code_hex: `0x${payload.code.toString(16).padStart(2, '0')}`,
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_821_REPLAY_TAIL_LEVEL_CODEBOOK',
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      hero_raw_param: 'VERIFIED_DIRECT',
      participant_id_candidate: 'CANDIDATE_REPLAY_TAIL_ALIGNMENT',
      level_after_candidate: 'CANDIDATE_REPLAY_TAIL_CODEBOOK',
    },
    raw_packet_ref: packetRef(replay, row),
    known_limits: [...profile.known_limits],
  }));
  return {
    ...common,
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_821_REPLAY_TAIL_LEVEL_CODEBOOK',
    event_count: events.length,
    final_levels: tail.levels,
    observed_max_levels: lastLevel,
    missing_level_updates: missingLevels,
    missing_level_update_count: missingLevels.reduce((sum, missing) => sum + missing.length, 0),
    repeated_level_observation_count: repeatedCount,
    level_one_packet_count: events.filter((event) => event.observation_kind === 'LEVEL_ONE_OBSERVATION').length,
    events,
  };
}

module.exports = {
  REPLAY_VERSION_821,
  HERO_LEVEL_CANDIDATE_PROFILE_821,
  LEVEL_BY_LAST_PAYLOAD_BYTE,
  assessHeroLevelTail821,
  decodeHeroLevelCandidates821,
};
