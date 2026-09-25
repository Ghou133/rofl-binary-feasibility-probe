'use strict';

// Joins three independently decoded exact-build candidates. A joined row is
// still a candidate: the timer does not predict an observed return.
const crypto = require('node:crypto');
const { decompressChunk, parseBlockAt } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { HERO_ASSIST_CANDIDATE_PROFILE_821 } =
  require('./rofl_16_19_821_assist_candidate');
const { HERO_DEATH_TIMER_CANDIDATE_PROFILE_821 } =
  require('./rofl_16_19_821_death_timer_candidate');
const { HERO_RESPAWN_CANDIDATE_PROFILE_821 } =
  require('./rofl_16_19_821_respawn_candidate');
const { RUNTIME_IMAGE_SHA256 } = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const MAX_ROWS = 10_000;
const EVIDENCE_STATUS = 'CANDIDATE_821_DEATH_ASSIST_TIMER_RETURN_ASSOCIATION';

const HERO_DEATH_EPISODE_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-death-episode-candidate-v1',
  replay_version: BUILD,
  capability: 'hero_death_episode',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze(['hero_assist', 'hero_death_timer', 'hero_respawn']),
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays: 655 matched death and timer candidates, 607 observed return candidates, and 48 terminally unobserved returns',
  known_limits: Object.freeze([
    'Each row joins independent exact-build candidate outputs by their original 0x0259 packet reference; it does not establish a published death, assist, timer, or respawn semantic.',
    'An observed 0x0048 return time is reported only when independently decoded; a missing return remains unobserved before Replay end.',
    'The decoded timer does not predict return time. Two observed returns in the supplied KR corpus precede their timer values by many seconds.',
    'Victim, killer, and assisting participant labels remain Replay-tail candidate mappings; nonhero sources retain null killer and assist lists.',
    'Missing, duplicate, source-mismatched, or conflicting rows fail the entire association without partial episode rows.',
  ]),
});

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_ROWS;
}

function time(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function participant(value) {
  return Number.isSafeInteger(value) && value >= 1 && value <= 10;
}

function refPosition(ref) {
  return `${ref.chunk_index}/${ref.decompressed_block_offset}`;
}

function sameRef(left, right) {
  return left.source_path === right.source_path
    && left.replay_sha256 === right.replay_sha256
    && left.chunk_index === right.chunk_index
    && left.chunk_id === right.chunk_id
    && left.chunk_stream === right.chunk_stream
    && left.chunk_file_offset === right.chunk_file_offset
    && left.decompressed_block_offset === right.decompressed_block_offset
    && left.decompressed_payload_offset === right.decompressed_payload_offset
    && left.packet_id === right.packet_id
    && left.replay_time_ms === right.replay_time_ms
    && left.payload_length === right.payload_length
    && left.raw_param === right.raw_param
    && left.raw_payload_sha256 === right.raw_payload_sha256;
}

function validRef(replay, ref, expectedPacketId = null) {
  if (!ref || ref.source_path !== (replay.source_path ?? null)
      || ref.replay_sha256 !== replay.source_sha256
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id)
      || ref.chunk_stream !== 'game_chunk'
      || !Number.isSafeInteger(ref.chunk_file_offset)
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || ref.decompressed_block_offset < 0
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || ref.decompressed_payload_offset <= ref.decompressed_block_offset
      || !Number.isSafeInteger(ref.packet_id) || ref.packet_id < 0
      || (expectedPacketId !== null && ref.packet_id !== expectedPacketId)
      || !time(ref.replay_time_ms)
      || !Number.isSafeInteger(ref.payload_length) || ref.payload_length < 0
      || !Number.isSafeInteger(ref.raw_param) || ref.raw_param < 0
      || ref.raw_param > 0xffffffff || !sha(ref.raw_payload_sha256)) return false;
  const chunk = replay.chunks?.[ref.chunk_index];
  return !!chunk && chunk.index === ref.chunk_index
    && chunk.chunk_id === ref.chunk_id && chunk.stream === ref.chunk_stream
    && chunk.stream_tag === 1 && chunk.offset === ref.chunk_file_offset
    && Number.isSafeInteger(chunk.uncompressed_length)
    && ref.decompressed_payload_offset + ref.payload_length <= chunk.uncompressed_length;
}

function refsContain(replay, refs, target) {
  return Array.isArray(refs) && refs.length > 0 && refs.length <= 64
    && refs.every((ref) => validRef(replay, ref))
    && refs.filter((ref) => sameRef(ref, target)).length === 1;
}

function validOutcome(outcome, profile, packetId) {
  return outcome?.status === 'CANDIDATE'
    && outcome.profile_id === profile.id
    && outcome.evidence_runtime_image_sha256 === RUNTIME_IMAGE_SHA256
    && outcome.input_packet_id === packetId
    && Array.isArray(outcome.events)
    && count(outcome.event_count) && outcome.event_count > 0
    && outcome.event_count === outcome.events.length
    && count(outcome.input_count);
}

function verifyPacketRefs(replay, refs) {
  const expected = new Map();
  const neededChunks = new Set();
  for (const ref of refs) {
    const position = refPosition(ref);
    const prior = expected.get(position);
    if (prior && !sameRef(prior, ref)) {
      return { error: `conflicting raw packet references at ${position}` };
    }
    expected.set(position, ref);
    neededChunks.add(ref.chunk_index);
  }
  const verifiedCount = expected.size;
  try {
    for (const chunkIndex of neededChunks) {
      const chunk = replay.chunks[chunkIndex];
      const body = decompressChunk(replay.buffer, chunk);
      const state = { timestamp: 0, packet_id: 0, param: 0 };
      let cursor = 0;
      while (cursor < body.length) {
        const block = parseBlockAt(body, cursor, state);
        const position = `${chunkIndex}/${block.offset}`;
        const ref = expected.get(position);
        if (ref) {
          const payloadSha = crypto.createHash('sha256').update(block.payload).digest('hex');
          if (block.packet_id !== ref.packet_id
              || block.timestamp_ms !== ref.replay_time_ms
              || (block.param >>> 0) !== ref.raw_param
              || block.payload_offset !== ref.decompressed_payload_offset
              || block.payload_length !== ref.payload_length
              || payloadSha !== ref.raw_payload_sha256) {
            return { error: `raw packet reference differs from Replay block at ${position}` };
          }
          expected.delete(position);
        }
        cursor = block.next_offset;
      }
    }
  } catch (error) {
    return { error: `Replay packet scan failed: ${error.message}`, scan_error: true };
  }
  if (expected.size) {
    return { error: `raw packet reference is absent at ${expected.keys().next().value}` };
  }
  return { verified_count: verifiedCount };
}

function unionRefs(groups) {
  const refs = new Map();
  for (const group of groups) {
    for (const ref of group ?? []) {
      const position = refPosition(ref);
      const prior = refs.get(position);
      if (prior && !sameRef(prior, ref)) return null;
      if (!prior) refs.set(position, structuredClone(ref));
    }
  }
  return [...refs.values()];
}

function associateHeroDeathEpisodeCandidates821(replay, {
  heroAssistOutcome, heroDeathTimerOutcome, heroRespawnOutcome,
} = {}) {
  const profile = HERO_DEATH_EPISODE_821_PROFILE;
  const base = {
    profile_id: profile.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    depends_on: [...profile.depends_on],
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: status === 'INCONSISTENT' ? 'INCONSISTENT' : null,
    event_count: null, observed_return_count: null, terminal_unobserved_count: null,
    events: null, error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `episode association supports only ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) {
    return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  }
  if (!sha(replay.source_sha256)) {
    return fail('INCONSISTENT', 'Replay source SHA-256 is missing or malformed');
  }
  const gameLengthMs = replay?.tail?.metadata?.gameLength;
  if (!time(gameLengthMs)) {
    return fail('INCONSISTENT', 'Replay game length is unavailable or malformed');
  }
  const missing = [
    ...(!heroAssistOutcome ? ['hero_assist'] : []),
    ...(!heroDeathTimerOutcome ? ['hero_death_timer'] : []),
    ...(!heroRespawnOutcome ? ['hero_respawn'] : []),
  ];
  if (missing.length) {
    return fail('MISSING_INPUT', 'all three independently decoded outcomes are required',
      { missing_inputs: missing });
  }
  const assist = heroAssistOutcome;
  const timer = heroDeathTimerOutcome;
  const respawn = heroRespawnOutcome;
  if ([assist, timer, respawn].some((outcome) => outcome.status !== 'CANDIDATE')) {
    return fail('MISSING_INPUT', 'one or more candidate decoder outcomes are unavailable', {
      dependency_statuses: {
        hero_assist: assist.status ?? null,
        hero_death_timer: timer.status ?? null,
        hero_respawn: respawn.status ?? null,
      },
    });
  }
  if (!validOutcome(assist, HERO_ASSIST_CANDIDATE_PROFILE_821, 0x040a)
      || !validOutcome(timer, HERO_DEATH_TIMER_CANDIDATE_PROFILE_821, 0x0259)
      || !validOutcome(respawn, HERO_RESPAWN_CANDIDATE_PROFILE_821, 0x0048)
      || assist.matched_death_count !== assist.event_count
      || timer.matched_death_core_count !== assist.event_count
      || respawn.matched_death_core_count !== assist.event_count
      || respawn.event_count !== respawn.input_count
      || !count(respawn.unpaired_final_death_count)
      || !Array.isArray(respawn.unpaired_final_deaths)
      || respawn.unpaired_final_deaths.length !== respawn.unpaired_final_death_count
      || respawn.event_count + respawn.unpaired_final_death_count !== assist.event_count
      || !['MATCHED_USED', 'NOT_CHECKED'].includes(assist.native_child_identity_status)
      || (assist.native_child_identity_status === 'MATCHED_USED'
        && (assist.runtime_image_used !== true
          || assist.runtime_image_status !== 'MATCHED_USED'
          || assist.runtime_image_sha256 !== RUNTIME_IMAGE_SHA256))
      || (assist.native_child_identity_status === 'NOT_CHECKED'
        && assist.runtime_image_used !== false)
      || timer.runtime_image_used !== false
      || respawn.runtime_image_used !== false) {
    return fail('INCONSISTENT', 'exact-build candidate outcome identity, status, or counts differ');
  }
  const deathRows = new Map();
  const timerRows = new Map();
  const observedReturns = new Map();
  const terminalDeaths = new Map();
  const physicalRefs = [];
  for (const [index, row] of assist.events.entries()) {
    const ref = row?.raw_packet_ref;
    if (row?.event_type !== 'HERO_ASSIST_ATTRIBUTION_CANDIDATE'
        || row.game_version !== BUILD || row.build_profile !== HERO_ASSIST_CANDIDATE_PROFILE_821.id
        || row.replay_sha256 !== replay.source_sha256 || row.confidence !== 'CANDIDATE'
        || !time(row.replay_time_ms) || row.replay_time_ms > gameLengthMs
        || !participant(row.victim_participant_id_candidate)
        || !validRef(replay, ref, 0x0259) || ref.payload_length !== 5
        || ref.replay_time_ms !== row.replay_time_ms
        || !refsContain(replay, row.raw_packet_refs, ref)
        || (row.killer_participant_id_candidate !== null
          && !participant(row.killer_participant_id_candidate))) {
      return fail('INCONSISTENT', 'hero_assist row identity or source reference differs',
        { source: 'hero_assist', event_index: index });
    }
    const assists = row.assisting_participant_ids_candidate;
    if (row.killer_participant_id_candidate === null) {
      if (assists !== null || row.assist_pair_count !== null
          || row.assist_observation_status !== 'UNAVAILABLE_NONHERO_SOURCE') {
        return fail('INCONSISTENT', 'nonhero source has an inferred killer or assist list',
          { source: 'hero_assist', event_index: index });
      }
    } else if (row.killer_participant_id_candidate === row.victim_participant_id_candidate
        || row.assist_observation_status
          !== 'CANDIDATE_821_CO_TIMED_ASSIST_PAIR_TAIL_ALIGNMENT'
        || !Array.isArray(assists) || !count(row.assist_pair_count)
        || assists.length !== row.assist_pair_count
        || assists.some((value) => !participant(value)
          || value === row.victim_participant_id_candidate
          || value === row.killer_participant_id_candidate)
        || new Set(assists).size !== assists.length) {
      return fail('INCONSISTENT', 'hero assist participant list is malformed',
        { source: 'hero_assist', event_index: index });
    }
    const key = refPosition(ref);
    if (deathRows.has(key)) {
      return fail('INCONSISTENT', 'duplicate death primary packet reference',
        { source: 'hero_assist', event_index: index, packet_position: key });
    }
    deathRows.set(key, row);
    physicalRefs.push(...row.raw_packet_refs);
  }
  for (const [index, row] of timer.events.entries()) {
    const ref = row?.raw_packet_ref;
    const key = ref ? refPosition(ref) : null;
    const death = deathRows.get(key);
    if (row?.event_type !== 'HERO_DEATH_TIMER_CANDIDATE'
        || row.game_version !== BUILD
        || row.build_profile !== HERO_DEATH_TIMER_CANDIDATE_PROFILE_821.id
        || row.replay_sha256 !== replay.source_sha256 || row.confidence !== 'CANDIDATE'
        || !time(row.replay_time_ms) || row.replay_time_ms > gameLengthMs
        || !participant(row.victim_participant_id_candidate)
        || !Number.isFinite(row.timer_seconds_candidate) || row.timer_seconds_candidate <= 0
        || !validRef(replay, ref, 0x0259) || ref.payload_length !== 5
        || ref.replay_time_ms !== row.replay_time_ms
        || row.victim_raw_param !== ref.raw_param
        || !refsContain(replay, row.raw_packet_refs, ref)
        || !death || !sameRef(ref, death.raw_packet_ref)
        || row.victim_participant_id_candidate !== death.victim_participant_id_candidate
        || timerRows.has(key)) {
      return fail('INCONSISTENT', 'hero_death_timer row cannot uniquely match the death primary',
        { source: 'hero_death_timer', event_index: index, packet_position: key });
    }
    timerRows.set(key, row);
    physicalRefs.push(...row.raw_packet_refs);
  }
  if (timerRows.size !== deathRows.size) {
    return fail('INCONSISTENT', 'a death primary lacks its independently decoded timer');
  }
  for (const [index, row] of respawn.events.entries()) {
    const returnRef = row?.raw_packet_ref;
    const deathRefs = row?.raw_packet_refs?.filter((ref) => ref.packet_id === 0x0259) ?? [];
    const primary = deathRefs[0];
    const key = primary ? refPosition(primary) : null;
    const death = deathRows.get(key);
    if (row?.event_type !== 'HERO_RESPAWN_CANDIDATE'
        || row.game_version !== BUILD
        || row.build_profile !== HERO_RESPAWN_CANDIDATE_PROFILE_821.id
        || row.replay_sha256 !== replay.source_sha256 || row.confidence !== 'CANDIDATE'
        || !time(row.replay_time_ms) || row.replay_time_ms > gameLengthMs
        || !participant(row.participant_id_candidate)
        || !validRef(replay, returnRef, 0x0048)
        || returnRef.replay_time_ms !== row.replay_time_ms
        || !refsContain(replay, row.raw_packet_refs, returnRef)
        || deathRefs.length !== 1 || !validRef(replay, primary, 0x0259)
        || !death || !sameRef(primary, death.raw_packet_ref)
        || row.participant_id_candidate !== death.victim_participant_id_candidate
        || row.matched_death_replay_time_ms_candidate !== death.replay_time_ms
        || row.replay_time_ms <= death.replay_time_ms
        || row.observed_death_to_return_ms_candidate
          !== row.replay_time_ms - death.replay_time_ms
        || observedReturns.has(key)) {
      return fail('INCONSISTENT', 'hero_respawn row cannot uniquely match the death primary',
        { source: 'hero_respawn', event_index: index, packet_position: key });
    }
    observedReturns.set(key, row);
    physicalRefs.push(...row.raw_packet_refs);
  }
  for (const [index, row] of respawn.unpaired_final_deaths.entries()) {
    const primaryRefs = row?.raw_packet_refs?.filter((ref) => ref.packet_id === 0x0259) ?? [];
    const primary = primaryRefs[0];
    const key = primary ? refPosition(primary) : null;
    const death = deathRows.get(key);
    if (!participant(row?.participant_id_candidate)
        || !time(row.death_replay_time_ms_candidate)
        || !time(row.replay_remaining_ms)
        || row.death_replay_time_ms_candidate > gameLengthMs
        || row.replay_remaining_ms !== gameLengthMs - row.death_replay_time_ms_candidate
        || primaryRefs.length !== 1 || !validRef(replay, primary, 0x0259)
        || !Array.isArray(row.raw_packet_refs)
        || row.raw_packet_refs.some((ref) => !validRef(replay, ref))
        || !death || !sameRef(primary, death.raw_packet_ref)
        || row.participant_id_candidate !== death.victim_participant_id_candidate
        || row.death_replay_time_ms_candidate !== death.replay_time_ms
        || observedReturns.has(key) || terminalDeaths.has(key)) {
      return fail('INCONSISTENT', 'terminal death cannot uniquely match a death primary',
        { source: 'hero_respawn_terminal', event_index: index, packet_position: key });
    }
    terminalDeaths.set(key, row);
    physicalRefs.push(...row.raw_packet_refs);
  }
  if (observedReturns.size + terminalDeaths.size !== deathRows.size) {
    return fail('INCONSISTENT', 'observed and terminal returns do not partition all death primaries');
  }
  const checked = verifyPacketRefs(replay, physicalRefs);
  if (checked.error) {
    return fail(checked.scan_error ? 'DECODE_FAILED' : 'INCONSISTENT', checked.error);
  }
  const events = [];
  for (const [key, death] of deathRows) {
    const timerRow = timerRows.get(key);
    const returnRow = observedReturns.get(key) ?? null;
    const terminalRow = terminalDeaths.get(key) ?? null;
    if (!returnRow && !terminalRow) {
      return fail('INCONSISTENT', 'death primary has no observed or terminal return state',
        { packet_position: key });
    }
    const rawRefs = unionRefs([
      death.raw_packet_refs, timerRow.raw_packet_refs,
      returnRow?.raw_packet_refs ?? terminalRow.raw_packet_refs,
    ]);
    if (!rawRefs) {
      return fail('INCONSISTENT', 'source packet references conflict across candidate outcomes',
        { packet_position: key });
    }
    events.push({
      event_type: 'HERO_DEATH_EPISODE_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: death.replay_time_ms,
      victim_participant_id_candidate: death.victim_participant_id_candidate,
      killer_participant_id_candidate: death.killer_participant_id_candidate,
      assisting_participant_ids_candidate:
        death.assisting_participant_ids_candidate === null
          ? null : [...death.assisting_participant_ids_candidate],
      assist_observation_status: death.assist_observation_status,
      timer_seconds_candidate: timerRow.timer_seconds_candidate,
      return_observation_status: returnRow === null
        ? 'UNOBSERVED_BEFORE_REPLAY_END' : 'OBSERVED_RETURN',
      return_replay_time_ms_candidate: returnRow?.replay_time_ms ?? null,
      observed_death_to_return_ms_candidate:
        returnRow?.observed_death_to_return_ms_candidate ?? null,
      replay_remaining_ms: terminalRow?.replay_remaining_ms ?? null,
      native_child_identity_status: assist.native_child_identity_status,
      confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        victim_participant_id_candidate: 'CANDIDATE_821_DEATH_TAIL_ALIGNMENT',
        killer_participant_id_candidate: death.field_confidence
          ?.killer_participant_id_candidate ?? 'UNAVAILABLE',
        assisting_participant_ids_candidate: death.field_confidence
          ?.assisting_participant_ids_candidate ?? 'UNAVAILABLE',
        timer_seconds_candidate: 'CANDIDATE_EXACT_821_RUNTIME_FLOAT',
        return_replay_time_ms_candidate: returnRow === null ? 'UNAVAILABLE'
          : 'CANDIDATE_821_OBSERVED_RETURN_PACKET',
        observed_death_to_return_ms_candidate: returnRow === null ? 'UNAVAILABLE'
          : 'CANDIDATE_DIFFERENCE_OF_PAIRED_REPLAY_TIMES',
      },
      raw_packet_ref: structuredClone(death.raw_packet_ref),
      death_primary_raw_packet_ref: structuredClone(death.raw_packet_ref),
      return_raw_packet_ref: returnRow === null ? null
        : structuredClone(returnRow.raw_packet_ref),
      raw_packet_refs: rawRefs,
    });
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    replay_sha256: replay.source_sha256,
    death_count: deathRows.size,
    timer_count: timerRows.size,
    observed_return_count: observedReturns.size,
    terminal_unobserved_count: terminalDeaths.size,
    verified_raw_packet_count: checked.verified_count,
    event_count: events.length, events,
  };
}

module.exports = {
  HERO_DEATH_EPISODE_821_PROFILE,
  associateHeroDeathEpisodeCandidates821,
};
