'use strict';

const crypto = require('node:crypto');

const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const {
  REPLAY_VERSION_821,
  decodeHeroDeathCandidates821,
} = require('./rofl_16_19_821_7343');

// The route and its timing are Replay observations. There is no 821 runtime
// image or payload interpretation behind this candidate.
const HERO_RESPAWN_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-return-route-tail-candidate-v1',
  replay_version: REPLAY_VERSION_821,
  capability: 'hero_respawn',
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: 0x0048,
  corroborating_replay_block_packet_id: 0x018d,
  evidence_scope: 'eleven KR exact-build 821.7343 Replays; 607 observed route pairs and 110 participant dead-time tail checks',
  evidence_runtime_image_sha256: null,
  known_limits: Object.freeze([
    'Experimental exact-build Replay-tail route candidate, not a published respawn capability.',
    '0x0048 is correlated with a prior matched death and aggregate TOTAL_TIME_SPENT_DEAD; no 821 runtime deserializer was available.',
    '0x0048 and 0x018d payload bytes are retained as raw evidence; their fields are unclassified.',
    'Unpaired final deaths have no observed return time; no return or timer is predicted.',
    'The 0x018d route has additional packets and cannot independently select returns.',
    'No death-timer, killer, assist, health, or behavior semantics are inferred.',
  ]),
});

function participantFromHeroParam(rawParam) {
  if (!Number.isInteger(rawParam) || rawParam < 0 || rawParam > 0xffffffff) return null;
  if (rawParam < 0x400000ae || rawParam > 0x400000b7) return null;
  return (rawParam & 0xff) - 0xad;
}

function assessHeroRespawnTail821(replay) {
  const stats = replay?.tail?.stats;
  if (!Array.isArray(stats)) {
    return { status: 'MISSING_INPUT', missing_input: 'Replay tail statsJson participant rows' };
  }
  if (stats.length !== 10) {
    return { status: 'UNSUPPORTED', error: `candidate scope requires 10 participants; got ${stats.length}` };
  }
  const values = stats.map((row) => row?.TOTAL_TIME_SPENT_DEAD);
  if (values.some((value) => value === undefined || value === null || value === '')) {
    return { status: 'MISSING_INPUT', missing_input: 'Replay tail TOTAL_TIME_SPENT_DEAD for all 10 participants' };
  }
  if (values.some((value) =>
    !(typeof value === 'string' && /^\d+$/.test(value))
    && !(Number.isSafeInteger(value) && value >= 0))) {
    return { status: 'UNSUPPORTED', error: 'Replay tail TOTAL_TIME_SPENT_DEAD must be nonnegative integers' };
  }
  const seconds = values.map(Number);
  if (seconds.some((value) => !Number.isSafeInteger(value))) {
    return { status: 'UNSUPPORTED', error: 'Replay tail TOTAL_TIME_SPENT_DEAD must be safe integers' };
  }
  const gameLength = replay?.tail?.metadata?.gameLength;
  if (!Number.isSafeInteger(gameLength) || gameLength < 0) {
    return { status: 'MISSING_INPUT', missing_input: 'Replay tail gameLength for observed final deaths' };
  }
  return { status: 'PASS', seconds, game_length_ms: gameLength };
}

function packetRef(replay, source, role) {
  const { block, chunk } = source;
  return {
    role,
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

function decodeHeroRespawnCandidates821(replay) {
  const profile = HERO_RESPAWN_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    depends_on: 'hero_death',
    input_packet_id: profile.replay_block_packet_id,
    evidence_runtime_image_sha256: null,
    runtime_image_used: false,
    runtime_image_status: 'NOT_REQUIRED_ROUTE_TAIL_CANDIDATE',
    known_limits: [...profile.known_limits],
  };
  const unavailable = (status, error, missingInput = null) => ({
    ...base, status, event_count: null, input_count: null, events: null,
    ...(error ? { error } : {}),
    ...(missingInput ? { missing_input: missingInput } : {}),
  });
  if (replay?.header?.version !== REPLAY_VERSION_821) {
    return unavailable('UNSUPPORTED', `hero_respawn candidate supports only ${REPLAY_VERSION_821}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return unavailable('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);

  const deathOutcome = decodeHeroDeathCandidates821(replay);
  if (deathOutcome.status !== 'CANDIDATE') {
    return unavailable(deathOutcome.status,
      deathOutcome.error ? `hero_respawn requires matched 821 death cores: ${deathOutcome.error}` : null,
      deathOutcome.missing_input ?? null);
  }
  const tail = assessHeroRespawnTail821(replay);
  if (tail.status !== 'PASS') {
    return unavailable(tail.status, tail.error ?? null, tail.missing_input ?? null);
  }

  const returns = [];
  const support = [];
  let walked;
  try {
    walked = walkBlocks(replay, (block, chunk) => {
      if (chunk.stream_tag !== profile.stream_tag) return;
      if (block.packet_id === profile.replay_block_packet_id) returns.push({ block, chunk });
      if (block.packet_id === profile.corroborating_replay_block_packet_id) {
        support.push({ block, chunk });
      }
    }, { strict: true });
  } catch (error) {
    return unavailable('DECODE_FAILED', `Replay framing failed: ${error.message}`);
  }
  const common = {
    ...base,
    input_count: returns.length,
    supporting_packet_count: support.length,
    scanned_block_count: walked.block_count,
    matched_death_core_count: deathOutcome.event_count,
  };
  if (returns.length === 0) {
    return { ...common, status: 'PROFILE_UNAVAILABLE', event_count: null, events: null,
      error: 'no 821 exact-build 0x0048 return route was observed' };
  }
  const fail = (error) => ({ ...common, status: 'DECODE_FAILED', event_count: null,
    events: null, error });
  if (returns.some(({ block }) => ![9, 13].includes(block.payload_length)
      || participantFromHeroParam(block.param) === null)) {
    return fail('0x0048 payload length or full hero raw-param family differs from the observed 821 fingerprint');
  }

  const supportByKey = new Map();
  const packetKey = ({ block, chunk }) =>
    `${chunk.index}/${block.timestamp_ms}/${block.param >>> 0}`;
  for (const row of support) {
    const key = packetKey(row);
    const group = supportByKey.get(key) ?? [];
    group.push(row);
    supportByKey.set(key, group);
  }

  const deaths = deathOutcome.events.map((event) => ({
    event,
    participant_id: event.victim_participant_id,
    replay_time_ms: event.replay_time_ms,
  }));
  const usedDeaths = new Set();
  const usedSupport = new Set();
  const sumsMs = Array(10).fill(0);
  const matched = [];
  const sortedReturns = [...returns].sort((left, right) =>
    left.block.timestamp_ms - right.block.timestamp_ms
    || left.chunk.index - right.chunk.index
    || left.block.offset - right.block.offset);
  for (const row of sortedReturns) {
    const person = participantFromHeroParam(row.block.param);
    if (!Number.isSafeInteger(row.block.timestamp_ms) || row.block.timestamp_ms < 0
        || row.block.timestamp_ms > tail.game_length_ms) {
      return fail('0x0048 timestamp lies outside Replay time bounds');
    }
    const eligible = deaths.filter(({ event, participant_id, replay_time_ms }) =>
      participant_id === person && replay_time_ms < row.block.timestamp_ms
      && !usedDeaths.has(event));
    if (eligible.length !== 1) {
      return fail(`0x0048 has ${eligible.length} unmatched prior death cores for participant ${person}`);
    }
    const death = eligible[0];
    const coTimed = supportByKey.get(packetKey(row)) ?? [];
    if (coTimed.length !== 1 || coTimed[0].block.offset >= row.block.offset) {
      return fail('0x0048 lacks a unique preceding co-timed 0x018d with the same full raw param');
    }
    usedDeaths.add(death.event);
    usedSupport.add(coTimed[0]);
    const intervalMs = row.block.timestamp_ms - death.replay_time_ms;
    sumsMs[person - 1] += intervalMs;
    if (!Number.isSafeInteger(sumsMs[person - 1])) {
      return fail('candidate elapsed-time sum exceeds safe integer range');
    }
    matched.push({ row, coTimed: coTimed[0], death: death.event });
  }

  const terminalDeaths = deaths.filter(({ event }) => !usedDeaths.has(event));
  if (terminalDeaths.some(({ participant_id, replay_time_ms }) =>
    replay_time_ms > tail.game_length_ms
    || deaths.some((other) => other.participant_id === participant_id
      && other.replay_time_ms > replay_time_ms))) {
    return fail('unpaired death is not the participant\'s final matched death within Replay time');
  }
  const floorSeconds = sumsMs.map((ms) => Math.floor(ms / 1000));
  if (floorSeconds.some((seconds, index) => seconds !== tail.seconds[index])) {
    return fail('floor of paired death-to-0x0048 elapsed milliseconds does not match Replay tail TOTAL_TIME_SPENT_DEAD');
  }

  const events = matched.map(({ row, coTimed, death }) => {
    const refs = [
      packetRef(replay, row, 'candidate_observed_0x0048_return'),
      packetRef(replay, coTimed, 'co_timed_0x018d_support'),
      ...death.raw_packet_refs.map((ref) => ({ ...ref, role: `matched_death_${ref.role}` })),
    ];
    return {
      event_type: 'HERO_RESPAWN_CANDIDATE',
      game_version: REPLAY_VERSION_821,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: row.block.timestamp_ms,
      participant_id_candidate: death.victim_participant_id,
      return_raw_param: row.block.param >>> 0,
      matched_death_replay_time_ms_candidate: death.replay_time_ms,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_821_REPLAY_TAIL_DEAD_TIME_CORRELATION',
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        return_raw_param: 'VERIFIED_DIRECT',
        participant_id_candidate: 'CANDIDATE_REPLAY_TAIL_COUNTS_AND_DEAD_TIME',
        matched_death_replay_time_ms_candidate: 'CANDIDATE_MATCHED_DEATH_CORE',
      },
      raw_packet_ref: refs[0],
      raw_packet_refs: refs,
      known_limits: [...profile.known_limits],
    };
  });
  return {
    ...common,
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_821_REPLAY_TAIL_DEAD_TIME_CORRELATION',
    event_count: events.length,
    co_timed_0x018d_count: usedSupport.size,
    extra_0x018d_count: support.length - usedSupport.size,
    extra_0x018d_packet_refs: support.filter((row) => !usedSupport.has(row)).map((row) =>
      packetRef(replay, row, 'unclassified_extra_0x018d')),
    unpaired_final_death_count: terminalDeaths.length,
    unpaired_final_deaths: terminalDeaths.map(({ event }) => ({
      participant_id_candidate: event.victim_participant_id,
      death_replay_time_ms_candidate: event.replay_time_ms,
      replay_remaining_ms: tail.game_length_ms - event.replay_time_ms,
      raw_packet_refs: event.raw_packet_refs.map((ref) =>
        ({ ...ref, role: `unpaired_final_death_${ref.role}` })),
    })),
    final_total_time_spent_dead_seconds: tail.seconds,
    observed_floor_total_time_spent_dead_seconds: floorSeconds,
    events,
  };
}

module.exports = {
  HERO_RESPAWN_CANDIDATE_PROFILE_821,
  assessHeroRespawnTail821,
  decodeHeroRespawnCandidates821,
};
