'use strict';

const crypto = require('node:crypto');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const { analyzeReplay } = require('../analysis');
const { deathEvent } = require('../events');
const { walkBlocks } = require('../rofl');
const { analyzeReplayWithHeroStats } = require('./rofl_16_19_hero_stats_candidate');
const { replaySourceError } = require('./replay_source_integrity');

const REPLAY_VERSION = '16.19.820.7193';
const PROFILE_LIMITS = Object.freeze([
  'Route identity and victim mapping are experimental; a matching route fingerprint and death-count invariant are required for each Replay.',
  'Killer, assists, respawn time, and inner payload fields are unavailable.',
]);

const HERO_DEATH_CANDIDATE_PROFILES = Object.freeze([
  Object.freeze({
    id: 'rofl-16.19.820.7193-hn-death-route-triad-candidate-v1',
    replay_version: REPLAY_VERSION,
    capability: 'hero_death',
    status: 'CANDIDATE',
    enabled: true,
    stream_tag: 1,
    replay_block_packet_id: 0x02d6,
    paired_replay_block_packet_id: 0x04d9,
    corroborating_replay_block_packet_id: 0x0326,
    corroborating_param_mode: 'zero',
    corroborating_payload_minimum: 16,
    participant_mapping: '(raw_param & 0xff) - 0xad; upper bytes unknown',
    evidence_scope: 'one HN exact-build Replay; three co-timed routes and all ten final death totals',
    known_limits: PROFILE_LIMITS,
  }),
  Object.freeze({
    id: 'rofl-16.19.820.7193-kr-death-route-triad-candidate-v1',
    replay_version: REPLAY_VERSION,
    capability: 'hero_death',
    status: 'CANDIDATE',
    enabled: true,
    stream_tag: 1,
    replay_block_packet_id: 0x0259,
    paired_replay_block_packet_id: 0x0438,
    corroborating_replay_block_packet_id: 0x0396,
    corroborating_param_mode: 'victim_low_byte',
    corroborating_payload_length: 3,
    participant_mapping: '(raw_param & 0xff) - 0xad; upper bytes unknown',
    evidence_scope: 'two KR exact-build Replays; three co-timed routes and all ten final death totals per Replay',
    known_limits: PROFILE_LIMITS,
  }),
]);

const HERO_DEATH_TIMER_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-death-timer-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_death_timer',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: 0x02d6,
  hero_die_packet_id: 0x04d9,
  reincarnate_alive_packet_id: 0x0357,
  payload_length: 5,
  evidence_runtime_image_sha256: '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d',
  participant_mapping: '(raw_param & 0xff) - 0xad; upper bytes preserved',
  evidence_scope: 'exact 16.19 runtime callback/deserializer plus one HN Replay with 85 timed respawns',
  known_limits: Object.freeze([
    'HN route profile only; timing and participant mapping are candidate semantics from one Replay.',
    'The full raw param is preserved; its upper bytes can differ at reincarnation.',
    'This capability does not provide killer, assists, or a confirmed HeroDeath event.',
  ]),
});

const HERO_RESPAWN_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-hero-respawn-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_respawn',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: 0x0357,
  evidence_runtime_image_sha256: HERO_DEATH_TIMER_CANDIDATE_PROFILE.evidence_runtime_image_sha256,
  evidence_scope: 'exact HN reincarnate-alive route and one HN Replay with 85 timer-matched packets',
  known_limits: Object.freeze([
    'Only observed HN reincarnate-alive packets matched to a validated death timer are emitted.',
    'Participant identity and respawn semantics remain candidates from one Replay.',
    'Terminally censored deaths do not create synthetic respawn events.',
  ]),
});

const HERO_LEVEL_STATE_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-hero-level-state-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_level_state',
  status: 'CANDIDATE',
  enabled: true,
  replay_block_packet_id: 0x02b3,
  hero_raw_param_first: 0x400000ae,
  hero_raw_param_last: 0x400000b7,
  evidence_runtime_image_sha256: '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d',
  evidence_scope: 'exact HN runtime 0x02b3 deserializer and one HN Replay; observed level packets can have gaps',
  known_limits: Object.freeze([
    'Only levels present in HN route 0x02b3 are emitted; missing updates are not reconstructed.',
    'Participant mapping and level meaning remain candidate semantics from one Replay.',
    'No experience, level-before, or complete level timeline is inferred.',
  ]),
});

const HERO_INVENTORY_MAPVIEW_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-inventory-mapview-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_inventory_mapview',
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: 0x0420,
  packet_name: 'PKT_S2C_SetInventory_MapView_s',
  evidence_runtime_image_sha256: '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d',
  runtime_image_required: true,
  evidence_scope: 'exact HN runtime constructor/deserializer and 94 fully consumed packets in one HN Replay',
  known_limits: Object.freeze([
    'Only observed MapView records are emitted; no unseen slot contents are reconstructed.',
    'Slot, item-definition key, and hero participant mapping remain candidates from one HN Replay.',
    'No purchase, sale, swap, replacement, or complete inventory lifecycle is inferred.',
    'The exact captured runtime image and Python Unicorn are required for decoding.',
  ]),
});

const HERO_INVENTORY_SET_ITEM_CANDIDATE_PROFILE = Object.freeze({
  id: 'rofl-16.19.820.7193-hn-inventory-set-item-runtime-candidate-v1',
  replay_version: REPLAY_VERSION,
  capability: 'hero_inventory_set_item',
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: 0x03b7,
  packet_name: 'PKT_SetItem_s',
  payload_length: 7,
  evidence_runtime_image_sha256: HERO_INVENTORY_MAPVIEW_CANDIDATE_PROFILE.evidence_runtime_image_sha256,
  runtime_image_required: true,
  evidence_scope: 'exact HN runtime constructor/deserializer, 16 fully consumed packets, and 10 initial slot-8 MapView matches in one Replay',
  known_limits: Object.freeze([
    'Only observed SetItem packet fields are emitted; no purchase, sale, swap, or item transition is inferred.',
    'All 16 observed packets set slot 8, and six later packets repeat an existing item key.',
    'One raw param is outside the ten canonical hero params; its participant remains unavailable.',
    'The exact captured runtime image and Python Unicorn are required for decoding.',
  ]),
});

const TIMER_FLOAT_CODES = new Set([1, 2, 4, 6]);
const ROUTE_SCAN_SOURCE = new WeakMap();
const TIMER_OUTCOME_SOURCE = new WeakMap();

function bindTimerOutcome(result, replay) {
  TIMER_OUTCOME_SOURCE.set(result, {
    replay,
    source_path: replay?.source_path ?? null,
    source_sha256: replay?.source_sha256 ?? null,
    version: replay?.header?.version ?? null,
    // A public candidate result remains editable for consumers, but edits to
    // it cannot become the input for a later respawn projection.
    outcome: structuredClone(result),
  });
  return result;
}

function hasReplaySource(store, result, replay) {
  const source = result && typeof result === 'object' ? store.get(result) : null;
  return source?.replay === replay
    && source.source_path === (replay?.source_path ?? null)
    && source.source_sha256 === (replay?.source_sha256 ?? null)
    && source.version === (replay?.header?.version ?? null);
}

function bindRouteScan(scan, replay) {
  // The public value is only a token. Keeping the route Map in a private
  // WeakMap prevents callers from changing framed rows and reusing their
  // original Replay identity to manufacture candidate packet provenance.
  const token = Object.freeze({
    error: scan.error,
    scanned_block_count: scan.walk?.block_count ?? null,
  });
  ROUTE_SCAN_SOURCE.set(token, {
    replay,
    source_path: replay?.source_path ?? null,
    source_sha256: replay?.source_sha256 ?? null,
    version: replay?.header?.version ?? null,
    scan,
  });
  return token;
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

function participantIdFromDeathParam(rawParam) {
  if (!Number.isInteger(rawParam) || rawParam < 0 || rawParam > 0xffffffff) return null;
  const participantId = (rawParam & 0xff) - 0xad;
  return participantId >= 1 && participantId <= 10 ? participantId : null;
}

function finalDeathCounts(replay) {
  const stats = replay?.tail?.stats;
  if (!Array.isArray(stats)) {
    return { status: 'MISSING_INPUT', missing_input: 'Replay tail statsJson participant rows' };
  }
  if (stats.length !== 10) {
    return { status: 'UNSUPPORTED', error: `candidate scope requires 10 participants; got ${stats.length}` };
  }
  const rawCounts = stats.map((row) => row?.NUM_DEATHS);
  if (rawCounts.some((value) => value === undefined || value === null || value === '')) {
    return { status: 'MISSING_INPUT', missing_input: 'Replay tail NUM_DEATHS for all 10 participants' };
  }
  if (rawCounts.some((value) =>
    !(typeof value === 'string' && /^\d+$/.test(value))
    && !(Number.isSafeInteger(value) && value >= 0))) {
    return { status: 'UNSUPPORTED', error: 'Replay tail NUM_DEATHS must be nonnegative integers' };
  }
  const counts = rawCounts.map(Number);
  if (counts.some((count) => !Number.isSafeInteger(count))) {
    return { status: 'UNSUPPORTED', error: 'Replay tail NUM_DEATHS must be safe integers' };
  }
  return { status: 'PASS', counts, stats };
}

function sortPacketRows(rows, withParticipant) {
  return rows.sort((left, right) => left.block.timestamp_ms - right.block.timestamp_ms
    || (withParticipant ? participantIdFromDeathParam(left.block.param)
      - participantIdFromDeathParam(right.block.param) : 0)
    || left.chunk.index - right.chunk.index
    || left.block.offset - right.block.offset);
}

const CANDIDATE_ROUTE_PACKET_IDS = new Set([
  ...HERO_DEATH_CANDIDATE_PROFILES.flatMap((profile) => [
    profile.replay_block_packet_id,
    profile.paired_replay_block_packet_id,
    profile.corroborating_replay_block_packet_id,
  ]),
  HERO_DEATH_TIMER_CANDIDATE_PROFILE.reincarnate_alive_packet_id,
  HERO_LEVEL_STATE_CANDIDATE_PROFILE.replay_block_packet_id,
  HERO_INVENTORY_MAPVIEW_CANDIDATE_PROFILE.replay_block_packet_id,
  HERO_INVENTORY_SET_ITEM_CANDIDATE_PROFILE.replay_block_packet_id,
]);

function emptyCandidateRoutes() {
  return new Map([...CANDIDATE_ROUTE_PACKET_IDS].map((packetId) => [packetId, []]));
}

function retainCandidateRoute(routes, block, chunk) {
  if (!routes.has(block.packet_id)) return;
  if (!Buffer.isBuffer(block.payload) || block.payload.length !== block.payload_length) {
    throw new TypeError('candidate route observed block payload is invalid');
  }
  // The standalone walk can alias an uncompressed Replay buffer. Copy both
  // payload and chunk metadata so a later Replay mutation cannot rewrite a
  // route scan that was bound to the original source hash.
  routes.get(block.packet_id).push({
    block: { ...block, payload: Buffer.from(block.payload) },
    chunk: { ...chunk },
  });
}

function collectCandidateRoutes(replay) {
  const sourceError = replaySourceError(replay);
  if (sourceError) {
    return bindRouteScan({ routes: null, walk: null, error: sourceError }, replay);
  }
  const routes = emptyCandidateRoutes();
  try {
    const walk = walkBlocks(replay, (block, chunk) => {
      retainCandidateRoute(routes, block, chunk);
    }, { includeStreams: [1], strict: true });
    return bindRouteScan({ routes, walk, error: null }, replay);
  } catch (error) {
    return bindRouteScan({ routes: null, walk: null, error: error.message }, replay);
  }
}

function createCandidateRouteScanCollector(replay) {
  const routes = emptyCandidateRoutes();
  let gameBlockCount = 0;
  let finished = false;
  return Object.freeze({
    observe(block, chunk) {
      if (finished) throw new Error('candidate route scan collector is already finished');
      if (chunk?.stream_tag !== 1) return;
      gameBlockCount += 1;
      retainCandidateRoute(routes, block, chunk);
    },
    finish() {
      if (finished) throw new Error('candidate route scan collector is already finished');
      finished = true;
      const sourceError = replaySourceError(replay);
      return bindRouteScan({ routes: sourceError ? null : routes,
        walk: sourceError ? null : { block_count: gameBlockCount },
        error: sourceError }, replay);
    },
  });
}

function analyzeReplayWithCandidateRoutes(replay, options = {}, includeHeroStats = false) {
  const collector = createCandidateRouteScanCollector(replay);
  const inspected = includeHeroStats
    ? analyzeReplayWithHeroStats(replay, options, collector.observe)
    : { analysis: analyzeReplay(replay, {
      ...options, includeStreams: [1, 2, 3], onBlock: collector.observe,
    }), heroStatsScan: null };
  return {
    ...inspected,
    candidateRouteScan: inspected.analysis.block_errors.length === 0
      ? collector.finish() : null,
  };
}

function candidateRoutesForReplay(replay, collected) {
  const token = collected ?? collectCandidateRoutes(replay);
  if (hasReplaySource(ROUTE_SCAN_SOURCE, token, replay)) {
    return ROUTE_SCAN_SOURCE.get(token).scan;
  }
  return { routes: null, walk: null,
    error: 'candidate route scan belongs to a different Replay' };
}

function decodeHeroDeathCandidates(replay, collected = null) {
  if (replay?.header?.version !== REPLAY_VERSION) {
    return { status: 'UNSUPPORTED', event_count: null, input_count: null,
      error: `hero_death candidate supports only ${REPLAY_VERSION}` };
  }
  const scan = candidateRoutesForReplay(replay, collected);
  if (scan.error) {
    return { status: 'DECODE_FAILED', event_count: null, input_count: null,
      error: `Replay framing failed: ${scan.error}`, events: null };
  }
  const { routes, walk } = scan;

  const matchingProfiles = HERO_DEATH_CANDIDATE_PROFILES.filter((candidate) => [
    candidate.replay_block_packet_id,
    candidate.paired_replay_block_packet_id,
    candidate.corroborating_replay_block_packet_id,
  ].every((packetId) => routes.get(packetId).length > 0));
  if (matchingProfiles.length === 0) {
    return {
      status: 'PROFILE_UNAVAILABLE', event_count: null, input_count: null, events: null,
      scanned_block_count: walk.block_count,
      error: 'no exact-build experimental death route triad fingerprint matched this Replay',
    };
  }
  if (matchingProfiles.length > 1) {
    return {
      status: 'DECODE_FAILED', event_count: null, input_count: null, events: null,
      scanned_block_count: walk.block_count,
      error: 'multiple experimental death route triads matched this Replay',
    };
  }
  const profile = matchingProfiles[0];
  const primary = routes.get(profile.replay_block_packet_id);
  const paired = routes.get(profile.paired_replay_block_packet_id);
  const corroborating = routes.get(profile.corroborating_replay_block_packet_id);
  const inputCount = primary.length;
  const fail = (error) => ({
    status: 'DECODE_FAILED', event_count: null, input_count: inputCount,
    profile_id: profile.id,
    supporting_packet_count: primary.length + paired.length + corroborating.length,
    scanned_block_count: walk.block_count, error, events: null,
  });
  const finalCounts = finalDeathCounts(replay);
  if (finalCounts.status !== 'PASS') {
    return { ...finalCounts, profile_id: profile.id,
      event_count: null, input_count: inputCount, events: null };
  }
  if (primary.length !== paired.length || primary.length !== corroborating.length) {
    return fail(`death route triad counts differ: ${primary.length}, ${paired.length}, ${corroborating.length}`);
  }
  if (primary.some(({ block }) => block.payload_length !== 5)
      || paired.some(({ block }) => block.payload_length <= 5)
      || corroborating.some(({ block }) => profile.corroborating_payload_length === undefined
        ? block.payload_length < profile.corroborating_payload_minimum
        : block.payload_length !== profile.corroborating_payload_length)) {
    return fail('death route triad payload lengths no longer match the selected structural fingerprint');
  }
  if (primary.some(({ block }) => participantIdFromDeathParam(block.param) === null)
      || paired.some(({ block }) => participantIdFromDeathParam(block.param) === null)
      || (profile.corroborating_param_mode === 'victim_low_byte'
        && corroborating.some(({ block }) => participantIdFromDeathParam(block.param) === null))) {
    return fail('a death route raw param does not identify one of the ten participants');
  }
  if (profile.corroborating_param_mode === 'zero'
      && corroborating.some(({ block }) => (block.param >>> 0) !== 0)) {
    return fail('corroborating death route raw param is no longer zero');
  }

  sortPacketRows(primary, true);
  sortPacketRows(paired, true);
  sortPacketRows(corroborating, profile.corroborating_param_mode === 'victim_low_byte');
  if (primary.some((row, index) => index > 0
      && row.block.timestamp_ms === primary[index - 1].block.timestamp_ms
      && participantIdFromDeathParam(row.block.param)
        === participantIdFromDeathParam(primary[index - 1].block.param))) {
    return fail('same-millisecond deaths for one victim have ambiguous route pairing');
  }
  const corroboratingByTime = new Map();
  for (const row of corroborating) {
    const rows = corroboratingByTime.get(row.block.timestamp_ms) ?? [];
    rows.push(row);
    corroboratingByTime.set(row.block.timestamp_ms, rows);
  }
  const observedCounts = Array(10).fill(0);
  for (let index = 0; index < primary.length; index += 1) {
    const first = primary[index].block;
    const second = paired[index].block;
    const third = corroborating[index].block;
    if (first.timestamp_ms !== second.timestamp_ms
        || first.timestamp_ms !== third.timestamp_ms
        || (first.param >>> 0) !== (second.param >>> 0)
        || (profile.corroborating_param_mode === 'victim_low_byte'
          && participantIdFromDeathParam(first.param) !== participantIdFromDeathParam(third.param))) {
      return fail(`death route triad does not match at occurrence ${index}`);
    }
    observedCounts[participantIdFromDeathParam(first.param) - 1] += 1;
  }
  if (observedCounts.some((count, index) => count !== finalCounts.counts[index])) {
    return fail('death route victim counts do not match Replay tail NUM_DEATHS');
  }

  const events = primary.map((row, index) => {
    const participantId = participantIdFromDeathParam(row.block.param);
    const stat = finalCounts.stats[participantId - 1];
    const corroboratingGroup = corroboratingByTime.get(row.block.timestamp_ms);
    const sourceRows = profile.corroborating_param_mode === 'zero'
      ? [
        { row: paired[index], role: 'hero_die' },
        { row, role: 'death_timer_update' },
        ...corroboratingGroup.map((sourceRow) => ({
          row: sourceRow,
          role: corroboratingGroup.length === 1
            ? 'corroborating'
            : 'corroborating_timestamp_group',
        })),
      ]
      : [
        { row, role: 'candidate_primary' },
        { row: paired[index], role: 'candidate_paired' },
        { row: corroborating[index], role: 'corroborating' },
      ];
    const refs = sourceRows.map(({ row: sourceRow, role }) => ({
      ...packetRef(replay, sourceRow.block, sourceRow.chunk), role,
    }));
    return deathEvent({
      game_version: REPLAY_VERSION,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: row.block.timestamp_ms,
      timestamp_ms: row.block.timestamp_ms,
      victim_network_id: null,
      victim_raw_param: row.block.param >>> 0,
      victim_participant_id: participantId,
      victim_champion: stat.SKIN ?? null,
      victim_team_id: Number(stat.TEAM) || null,
      target_participant_id: participantId,
      target_champion: stat.SKIN ?? null,
      target_team_id: Number(stat.TEAM) || null,
      killer_network_id: null,
      killer_participant_id: null,
      assists: null,
      respawn_timestamp_ms: null,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_EXACT_BUILD_ROUTE_FINGERPRINT',
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        victim_raw_param: 'VERIFIED_DIRECT',
        victim_participant_id: 'CANDIDATE',
        victim_champion: 'CANDIDATE_FROM_REPLAY_TAIL',
        victim_team_id: 'CANDIDATE_FROM_REPLAY_TAIL',
        killer_network_id: 'UNAVAILABLE',
        assists: 'UNAVAILABLE',
        respawn_timestamp_ms: 'UNAVAILABLE',
      },
      raw_packet_ref: refs[0],
      raw_packet_refs: refs,
      corroboration_assignment: profile.corroborating_param_mode === 'zero'
        && corroboratingGroup.length > 1
        ? 'TIMESTAMP_GROUP_UNRESOLVED'
        : 'ONE_TO_ONE',
      corroborating_packet_group_size: profile.corroborating_param_mode === 'zero'
        ? corroboratingGroup.length : 1,
      known_limits: [...profile.known_limits],
    });
  });
  return {
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_BUILD_ROUTE_FINGERPRINT',
    profile_id: profile.id,
    event_count: events.length,
    input_count: primary.length,
    input_packet_id: profile.replay_block_packet_id,
    supporting_packet_count: primary.length + paired.length + corroborating.length,
    scanned_block_count: walk.block_count,
    final_death_counts: finalCounts.counts,
    observed_death_counts: observedCounts,
    events,
  };
}

function decodeHeroDeathTimerPayload(payload) {
  if (!Buffer.isBuffer(payload) || payload.length !== 5) return null;
  const first = payload[0];
  if ((first & 0xf8) !== 0x18 || !TIMER_FLOAT_CODES.has(first & 7)) return null;
  const decoded = Buffer.alloc(4);
  for (let index = 0; index < 4; index += 1) {
    const shifted = (((payload[index + 1] - 0x66) & 0xff) ^ 0x77);
    const swapped = ((shifted >>> 4) | (shifted << 4)) & 0xff;
    const mixed = (((swapped & 0xd5) << 1) | ((swapped >>> 1) & 0x55)) & 0xff;
    decoded[index] = (~mixed) & 0xff;
  }
  const seconds = decoded.readFloatLE(0);
  if (!Number.isFinite(seconds) || seconds <= 0) return null;
  return {
    float_code: first & 7,
    timer_seconds_candidate: seconds,
    decoded_float_bytes_hex: decoded.toString('hex'),
  };
}

function decodeHeroDeathTimerCandidates(replay, collected = null) {
  if (replay?.header?.version !== REPLAY_VERSION) {
    return { status: 'UNSUPPORTED', event_count: null, input_count: null, events: null,
      error: `hero_death_timer candidate supports only ${REPLAY_VERSION}` };
  }
  const scan = candidateRoutesForReplay(replay, collected);
  if (scan.error) {
    return { status: 'DECODE_FAILED', event_count: null, input_count: null, events: null,
      error: `Replay framing failed: ${scan.error}` };
  }
  const { routes, walk } = scan;
  const profile = HERO_DEATH_TIMER_CANDIDATE_PROFILE;
  const timers = [...routes.get(profile.replay_block_packet_id)];
  const heroDies = [...routes.get(profile.hero_die_packet_id)];
  const respawns = [...routes.get(profile.reincarnate_alive_packet_id)];
  const inputCount = timers.length;
  if (timers.length === 0 && heroDies.length === 0) {
    return { status: 'PROFILE_UNAVAILABLE', profile_id: profile.id,
      event_count: null, input_count: null, events: null,
      scanned_block_count: walk.block_count,
      error: 'HN death timer route pair is absent from this Replay' };
  }
  const fail = (error) => ({
    status: 'DECODE_FAILED', profile_id: profile.id,
    event_count: null, input_count: inputCount, events: null,
    supporting_packet_count: timers.length + heroDies.length + respawns.length,
    scanned_block_count: walk.block_count, error,
  });
  if (HERO_DEATH_CANDIDATE_PROFILES.slice(1).some((candidate) => [
    candidate.replay_block_packet_id,
    candidate.paired_replay_block_packet_id,
    candidate.corroborating_replay_block_packet_id,
  ].every((packetId) => routes.get(packetId).length > 0))) {
    return fail('HN death timer routes coexist with a different death route profile');
  }
  if (timers.length !== heroDies.length) {
    return fail(`HN death timer and Hero_Die route counts differ: ${timers.length}, ${heroDies.length}`);
  }
  if (timers.some(({ block }) => participantIdFromDeathParam(block.param) === null
      || !Number.isSafeInteger(block.timestamp_ms) || block.timestamp_ms < 0)) {
    return fail('HN death timer raw param or timestamp is outside the candidate scope');
  }
  if (heroDies.some(({ block }) => block.payload_length <= 5
      || participantIdFromDeathParam(block.param) === null)) {
    return fail('HN Hero_Die route payload or raw param is outside the candidate scope');
  }
  const decodedTimers = timers.map((row) => ({
    row, timer: decodeHeroDeathTimerPayload(row.block.payload),
  }));
  if (decodedTimers.some(({ timer }) => timer === null)) {
    return fail('HN death timer payload does not match the exact-runtime 5-byte float shape');
  }
  const sortRows = (left, right) => left.row.block.timestamp_ms - right.row.block.timestamp_ms
    || (left.row.block.param >>> 0) - (right.row.block.param >>> 0)
    || left.row.chunk.index - right.row.chunk.index
    || left.row.block.offset - right.row.block.offset;
  decodedTimers.sort(sortRows);
  const sortedDies = heroDies.map((row) => ({ row })).sort(sortRows);
  for (let index = 0; index < decodedTimers.length; index += 1) {
    const timerRow = decodedTimers[index].row.block;
    const dieRow = sortedDies[index].row.block;
    if (timerRow.timestamp_ms !== dieRow.timestamp_ms
        || (timerRow.param >>> 0) !== (dieRow.param >>> 0)) {
      return fail(`HN death timer and Hero_Die pairing differs at occurrence ${index}`);
    }
    if (index > 0 && timerRow.timestamp_ms === decodedTimers[index - 1].row.block.timestamp_ms
        && (timerRow.param >>> 0) === (decodedTimers[index - 1].row.block.param >>> 0)) {
      return fail('duplicate same-millisecond victim has ambiguous death timer pairing');
    }
  }
  const finalCounts = finalDeathCounts(replay);
  if (finalCounts.status !== 'PASS') {
    return { ...finalCounts, profile_id: profile.id,
      event_count: null, input_count: inputCount, events: null };
  }
  const observedCounts = Array(10).fill(0);
  for (const { row } of decodedTimers) {
    observedCounts[participantIdFromDeathParam(row.block.param) - 1] += 1;
  }
  if (observedCounts.some((count, index) => count !== finalCounts.counts[index])) {
    return fail('HN death timer victim counts do not match Replay tail NUM_DEATHS');
  }

  // The receive handler passes this float to AIBaseClient. A matching reincarnation
  // route and Replay duration bound the candidate interpretation as seconds.
  const matchedRespawns = new Map();
  const matchKinds = { exact_param: 0, unique_low_byte: 0 };
  let maximumResidualMs = 0;
  for (const respawn of respawns) {
    if (participantIdFromDeathParam(respawn.block.param) === null
        || respawn.block.payload_length < 9 || respawn.block.payload_length > 13) {
      return fail('HN reincarnation route payload or raw param is outside the candidate scope');
    }
    const participantId = participantIdFromDeathParam(respawn.block.param);
    const eligible = decodedTimers.filter(({ row, timer }, index) => {
      if (matchedRespawns.has(index)
          || participantIdFromDeathParam(row.block.param) !== participantId) return false;
      const residualMs = respawn.block.timestamp_ms - row.block.timestamp_ms
        - timer.timer_seconds_candidate * 1000;
      return residualMs >= 0 && residualMs <= 50;
    });
    if (eligible.length !== 1) {
      return fail(`HN reincarnation has ${eligible.length} eligible death timer matches`);
    }
    const match = eligible[0];
    const index = decodedTimers.indexOf(match);
    const residualMs = respawn.block.timestamp_ms - match.row.block.timestamp_ms
      - match.timer.timer_seconds_candidate * 1000;
    const kind = (respawn.block.param >>> 0) === (match.row.block.param >>> 0)
      ? 'exact_param' : 'unique_low_byte';
    matchKinds[kind] += 1;
    maximumResidualMs = Math.max(maximumResidualMs, residualMs);
    matchedRespawns.set(index, { row: respawn, match_kind: kind, residual_ms: residualMs });
  }
  const gameLength = replay?.tail?.metadata?.gameLength;
  const unmatched = decodedTimers.flatMap(({ row, timer }, index) =>
    matchedRespawns.has(index) ? [] : [{ row, timer }]);
  if (unmatched.length > 0 && !(Number.isSafeInteger(gameLength) && gameLength >= 0)) {
    return { status: 'MISSING_INPUT', profile_id: profile.id, event_count: null,
      input_count: inputCount, events: null,
      missing_input: 'Replay tail gameLength for unobserved final reincarnations' };
  }
  if (unmatched.length > 0 && decodedTimers.some(({ row }) =>
    row.block.timestamp_ms > gameLength)) {
    return fail('Replay tail gameLength precedes an observed death timer');
  }
  if (unmatched.some(({ row, timer }) =>
    row.block.timestamp_ms + timer.timer_seconds_candidate * 1000 <= gameLength)) {
    return fail('unmatched HN death timer predicts reincarnation before Replay end');
  }
  for (const [index, { row }] of decodedTimers.entries()) {
    const participantId = participantIdFromDeathParam(row.block.param);
    const nextDeath = decodedTimers.find(({ row: other }, otherIndex) =>
      otherIndex > index && participantIdFromDeathParam(other.block.param) === participantId);
    if (nextDeath && (!matchedRespawns.has(index)
        || matchedRespawns.get(index).row.block.timestamp_ms > nextDeath.row.block.timestamp_ms)) {
      return fail('participant has another death before a matched reincarnation');
    }
  }

  const events = decodedTimers.map(({ row, timer }, index) => {
    const heroDie = sortedDies[index].row;
    const respawn = matchedRespawns.get(index) ?? null;
    const refs = [
      { ...packetRef(replay, row.block, row.chunk), role: 'update_death_timer' },
      { ...packetRef(replay, heroDie.block, heroDie.chunk), role: 'hero_die' },
    ];
    if (respawn) refs.push({
      ...packetRef(replay, respawn.row.block, respawn.row.chunk),
      role: 'hero_reincarnate_alive',
    });
    return {
      event_type: 'HERO_DEATH_TIMER_CANDIDATE',
      game_version: REPLAY_VERSION,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: row.block.timestamp_ms,
      victim_raw_param: row.block.param >>> 0,
      victim_participant_id_candidate: participantIdFromDeathParam(row.block.param),
      timer_seconds_candidate: timer.timer_seconds_candidate,
      timer_float_code: timer.float_code,
      decoded_float_bytes_hex: timer.decoded_float_bytes_hex,
      respawn_replay_time_ms_candidate: respawn?.row.block.timestamp_ms ?? null,
      respawn_match_kind: respawn?.match_kind ?? null,
      respawn_timer_residual_ms: respawn?.residual_ms ?? null,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_EXACT_RUNTIME_FLOAT_AND_REPLAY_TIMING',
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        victim_raw_param: 'VERIFIED_DIRECT',
        victim_participant_id_candidate: 'CANDIDATE',
        timer_seconds_candidate: 'CANDIDATE_EXACT_RUNTIME_FLOAT',
        respawn_replay_time_ms_candidate: respawn ? 'CANDIDATE_CORROBORATION' : 'UNAVAILABLE',
      },
      raw_packet_ref: refs[0],
      raw_packet_refs: refs,
      known_limits: [...profile.known_limits],
    };
  });
  return bindTimerOutcome({
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_FLOAT_AND_REPLAY_TIMING',
    profile_id: profile.id,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    event_count: events.length,
    input_count: inputCount,
    input_packet_id: profile.replay_block_packet_id,
    supporting_packet_count: timers.length + heroDies.length + respawns.length,
    scanned_block_count: walk.block_count,
    final_death_counts: finalCounts.counts,
    observed_death_counts: observedCounts,
    respawn_match_count: matchedRespawns.size,
    exact_param_respawn_match_count: matchKinds.exact_param,
    unique_low_byte_respawn_match_count: matchKinds.unique_low_byte,
    unobserved_after_replay_end_count: unmatched.length,
    maximum_respawn_residual_ms: maximumResidualMs,
    events,
  }, replay);
}

function decodeHeroRespawnCandidates(replay, collected = null, timerOutcome = null) {
  const profile = HERO_RESPAWN_CANDIDATE_PROFILE;
  const scanToken = collected ?? collectCandidateRoutes(replay);
  const scan = candidateRoutesForReplay(replay, scanToken);
  if (scan.error) {
    return { status: 'DECODE_FAILED', profile_id: profile.id,
      event_count: null, input_count: null,
      input_packet_id: profile.replay_block_packet_id, events: null,
      error: `Replay framing or route source failed: ${scan.error}` };
  }
  const observedRawRouteCount = scan.routes.get(profile.replay_block_packet_id).length;
  if (timerOutcome?.status === 'CANDIDATE'
      && !hasReplaySource(TIMER_OUTCOME_SOURCE, timerOutcome, replay)) {
    return { status: 'DECODE_FAILED', profile_id: profile.id,
      event_count: null, input_count: observedRawRouteCount,
      input_packet_id: profile.replay_block_packet_id, events: null,
      error: 'death timer outcome belongs to a different Replay' };
  }
  const timer = timerOutcome?.status === 'CANDIDATE'
    ? TIMER_OUTCOME_SOURCE.get(timerOutcome).outcome
    : decodeHeroDeathTimerCandidates(replay, scanToken);
  if (timer.status !== 'CANDIDATE') {
    const unclassified = observedRawRouteCount > 0
      ? `${observedRawRouteCount} raw 0x0357 packets remain unclassified` : null;
    return {
      status: timer.status,
      profile_id: profile.id,
      depends_on: 'hero_death_timer',
      dependency_profile_id: timer.profile_id ?? null,
      event_count: null,
      input_count: observedRawRouteCount,
      input_packet_id: profile.replay_block_packet_id,
      raw_unclassified_packet_count: observedRawRouteCount,
      events: null,
      scanned_block_count: timer.scanned_block_count ?? null,
      error: [timer.error ? `HN respawn requires a valid death timer: ${timer.error}` : null,
        unclassified].filter(Boolean).join('; ') || undefined,
      missing_input: timer.missing_input ?? undefined,
    };
  }
  const events = [];
  for (const deathTimer of timer.events) {
    if (deathTimer.respawn_replay_time_ms_candidate === null) continue;
    const respawnRefs = deathTimer.raw_packet_refs.filter((ref) =>
      ref.role === 'hero_reincarnate_alive' && ref.packet_id === profile.replay_block_packet_id);
    if (respawnRefs.length !== 1
        || respawnRefs[0].replay_time_ms !== deathTimer.respawn_replay_time_ms_candidate) {
      return {
        status: 'DECODE_FAILED', profile_id: profile.id, depends_on: 'hero_death_timer',
        event_count: null, input_count: observedRawRouteCount,
        input_packet_id: profile.replay_block_packet_id, events: null,
        error: 'validated death timer is missing its unique observed reincarnation packet',
      };
    }
    const respawnRef = respawnRefs[0];
    events.push({
      event_type: 'HERO_RESPAWN_CANDIDATE',
      game_version: REPLAY_VERSION,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: respawnRef.replay_time_ms,
      respawn_raw_param: respawnRef.raw_param,
      participant_id_candidate: deathTimer.victim_participant_id_candidate,
      death_timer_replay_time_ms_candidate: deathTimer.replay_time_ms,
      timer_seconds_candidate: deathTimer.timer_seconds_candidate,
      respawn_match_kind: deathTimer.respawn_match_kind,
      respawn_timer_residual_ms: deathTimer.respawn_timer_residual_ms,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_EXACT_RUNTIME_ROUTE_AND_TIMER_MATCH',
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        respawn_raw_param: 'VERIFIED_DIRECT',
        participant_id_candidate: 'CANDIDATE',
        death_timer_replay_time_ms_candidate: 'CANDIDATE_CORROBORATION',
        timer_seconds_candidate: 'CANDIDATE_EXACT_RUNTIME_FLOAT',
      },
      raw_packet_ref: respawnRef,
      raw_packet_refs: [respawnRef, ...deathTimer.raw_packet_refs.filter((ref) =>
        ref.role !== 'hero_reincarnate_alive')],
      known_limits: [...profile.known_limits],
    });
  }
  if (events.length !== timer.respawn_match_count
      || events.length !== observedRawRouteCount) {
    return {
      status: 'DECODE_FAILED', profile_id: profile.id, depends_on: 'hero_death_timer',
      event_count: null, input_count: observedRawRouteCount,
      input_packet_id: profile.replay_block_packet_id, events: null,
      error: 'validated death timer and observed reincarnation counts differ',
    };
  }
  events.sort((left, right) => left.replay_time_ms - right.replay_time_ms
    || left.raw_packet_ref.chunk_index - right.raw_packet_ref.chunk_index
    || left.raw_packet_ref.decompressed_block_offset
      - right.raw_packet_ref.decompressed_block_offset);
  return {
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_ROUTE_AND_TIMER_MATCH',
    profile_id: profile.id,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    depends_on: 'hero_death_timer',
    dependency_profile_id: timer.profile_id,
    event_count: events.length,
    input_count: observedRawRouteCount,
    input_packet_id: profile.replay_block_packet_id,
    scanned_block_count: timer.scanned_block_count,
    unobserved_after_replay_end_count: timer.unobserved_after_replay_end_count,
    maximum_respawn_residual_ms: timer.maximum_respawn_residual_ms,
    events,
  };
}

function rotateLeftByte(value, count) {
  return ((value << count) | (value >>> (8 - count))) & 0xff;
}

function decodeHeroLevelPayload(payload) {
  if (!Buffer.isBuffer(payload) || payload.length < 1) return null;
  const code = payload[0] & 7;
  // In the exact 16.19 image, the 0x02b3 deserializer reads this three-bit
  // selector at RVA 0xf21d4c and writes object+0x10. Its one-byte helper at
  // 0xe85fc0 re-encodes the object field; its inverse below
  // recovers the field value from the second Replay payload byte.
  if (code === 3 && payload.length === 1) return { level_candidate: 1, code };
  if (code === 5 && payload.length === 1) return { level_candidate: 2, code };
  if (![0, 1, 2, 6].includes(code) || payload.length !== 2) return null;
  const encoded = payload[1];
  const step = (0x18 - rotateLeftByte(encoded, 3)) & 0xff;
  const level = (rotateLeftByte(step ^ 0x2d, 1) + 0x19) & 0xff;
  return { level_candidate: level, code };
}

function finalLevelValues(replay) {
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
  if (levels.some((value) => !Number.isSafeInteger(value) || value < 1 || value > 30)) {
    return { status: 'UNSUPPORTED', error: 'Replay tail LEVEL is outside the observed 1–30 candidate scope' };
  }
  return { status: 'PASS', levels };
}

function candidateTailStatAssessment(replay, capability) {
  const field = capability === 'hero_level_state' ? 'LEVEL'
    : ['hero_death', 'hero_death_timer', 'hero_respawn'].includes(capability) ? 'NUM_DEATHS' : null;
  if (!field) return null;
  const result = field === 'LEVEL' ? finalLevelValues(replay) : finalDeathCounts(replay);
  return { field, status: result.status, error: result.error ?? result.missing_input ?? null };
}

function decodeHeroLevelStateCandidates(replay, collected = null) {
  if (replay?.header?.version !== REPLAY_VERSION) {
    return { status: 'UNSUPPORTED', event_count: null, input_count: null, events: null,
      error: `hero_level_state candidate supports only ${REPLAY_VERSION}` };
  }
  const scan = candidateRoutesForReplay(replay, collected);
  if (scan.error) {
    return { status: 'DECODE_FAILED', event_count: null, input_count: null, events: null,
      error: `Replay framing failed: ${scan.error}` };
  }
  const profile = HERO_LEVEL_STATE_CANDIDATE_PROFILE;
  const { routes, walk } = scan;
  const rows = routes.get(profile.replay_block_packet_id).filter(({ block }) =>
    (block.param >>> 0) >= profile.hero_raw_param_first
    && (block.param >>> 0) <= profile.hero_raw_param_last);
  if (rows.length === 0) {
    return { status: 'PROFILE_UNAVAILABLE', profile_id: profile.id,
      event_count: null, input_count: null, events: null,
      scanned_block_count: walk.block_count,
      error: 'HN 0x02b3 hero-parameter level route is absent from this Replay' };
  }
  const inputCount = rows.length;
  const fail = (error) => ({
    status: 'DECODE_FAILED', profile_id: profile.id,
    event_count: null, input_count: inputCount, events: null,
    scanned_block_count: walk.block_count, error,
  });
  const final = finalLevelValues(replay);
  if (final.status !== 'PASS') {
    return { ...final, profile_id: profile.id,
      event_count: null, input_count: inputCount, events: null };
  }
  const sorted = [...rows].sort((left, right) => left.block.timestamp_ms - right.block.timestamp_ms
    || left.chunk.index - right.chunk.index || left.block.offset - right.block.offset);
  const lastLevel = Array(10).fill(null);
  const observedByPlayer = Array.from({ length: 10 }, () => new Set());
  const decoded = [];
  for (const row of sorted) {
    const participantId = (row.block.param >>> 0) - 0x400000ad;
    const payload = decodeHeroLevelPayload(row.block.payload);
    if (!payload || payload.level_candidate < 1 || payload.level_candidate > 30) {
      return fail(`HN level payload is outside the exact-runtime candidate shape at ${row.block.timestamp_ms} ms`);
    }
    const index = participantId - 1;
    const previous = lastLevel[index];
    if (previous !== null && payload.level_candidate <= previous) {
      return fail(`HN participant ${participantId} has a nonincreasing observed level`);
    }
    if (payload.level_candidate > final.levels[index]) {
      return fail(`HN participant ${participantId} exceeds Replay tail LEVEL`);
    }
    lastLevel[index] = payload.level_candidate;
    observedByPlayer[index].add(payload.level_candidate);
    decoded.push({ row, participantId, payload });
  }
  const missingLevelUpdates = final.levels.map((finalLevel, index) => {
    const missing = [];
    for (let level = 2; level <= finalLevel; level += 1) {
      if (!observedByPlayer[index].has(level)) missing.push(level);
    }
    return missing;
  });
  const events = decoded.map(({ row, participantId, payload }) => ({
    event_type: 'HERO_LEVEL_STATE_CANDIDATE',
    game_version: REPLAY_VERSION,
    patch: '16.19',
    build_profile: profile.id,
    replay_sha256: replay.source_sha256 ?? null,
    replay_time_ms: row.block.timestamp_ms,
    hero_raw_param: row.block.param >>> 0,
    participant_id_candidate: participantId,
    level_after_candidate: payload.level_candidate,
    observation_kind: payload.level_candidate === 1
      ? 'LEVEL_ONE_OBSERVATION' : 'HIGHER_LEVEL_OBSERVATION',
    payload_selector_code: payload.code,
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_FIELD_WITH_SEQUENCE_GAPS',
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT',
      hero_raw_param: 'VERIFIED_DIRECT',
      participant_id_candidate: 'CANDIDATE',
      level_after_candidate: 'CANDIDATE_EXACT_RUNTIME_FIELD',
    },
    raw_packet_ref: packetRef(replay, row.block, row.chunk),
    known_limits: [...profile.known_limits],
  }));
  return {
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_FIELD_WITH_SEQUENCE_GAPS',
    profile_id: profile.id,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    event_count: events.length,
    input_count: inputCount,
    input_packet_id: profile.replay_block_packet_id,
    scanned_block_count: walk.block_count,
    final_levels: final.levels,
    observed_max_levels: lastLevel,
    missing_level_updates: missingLevelUpdates,
    missing_level_update_count: missingLevelUpdates.reduce((sum, levels) => sum + levels.length, 0),
    level_one_packet_count: events.filter((event) =>
      event.observation_kind === 'LEVEL_ONE_OBSERVATION').length,
    events,
  };
}

function decodeHeroInventoryMapViewCandidates(replay, collected = null, options = {}) {
  const profile = HERO_INVENTORY_MAPVIEW_CANDIDATE_PROFILE;
  const base = { profile_id: profile.id, input_packet_id: profile.replay_block_packet_id };
  if (replay?.header?.version !== REPLAY_VERSION) {
    return { ...base, status: 'UNSUPPORTED', input_count: null, event_count: null,
      events: null, error: `inventory MapView candidate supports only ${REPLAY_VERSION}` };
  }
  const scan = candidateRoutesForReplay(replay, collected);
  if (scan.error) {
    return { ...base, status: 'DECODE_FAILED', input_count: null, event_count: null,
      events: null, error: `Replay framing or route source failed: ${scan.error}` };
  }
  const rows = scan.routes.get(profile.replay_block_packet_id);
  const inputCount = rows.length;
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: inputCount, event_count: null, events: null,
    scanned_block_count: scan.walk.block_count, error, ...extra,
  });
  if (inputCount === 0) {
    return fail('PROFILE_UNAVAILABLE', 'HN game-stream inventory MapView route 0x0420 is absent', {
      input_count: null, observed_raw_route_count: 0,
      runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    });
  }
  const isHeroParam = (row) => row.block.param >= 0x400000ae
    && row.block.param <= 0x400000b7;
  const heroParamCount = rows.filter(isHeroParam).length;
  if (heroParamCount !== inputCount) {
    return fail(heroParamCount === 0 ? 'PROFILE_UNAVAILABLE' : 'DECODE_FAILED',
      '0x0420 raw params do not consistently match the observed HN hero range',
      { ...(heroParamCount === 0 ? { input_count: null } : {}),
        observed_raw_route_count: inputCount, matching_hero_param_count: heroParamCount,
        runtime_image_status: 'NOT_CHECKED', runtime_image_used: false });
  }
  const imagePath = options.runtimeImagePath;
  if (typeof imagePath !== 'string' || !imagePath.trim()) {
    return fail('MISSING_INPUT', 'exact 16.19 HN runtime image is required', {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
      runtime_image_used: false,
    });
  }
  const resolvedImage = path.resolve(imagePath);
  try {
    if (!fs.statSync(resolvedImage).isFile()) {
      return fail('MISSING_INPUT', 'runtime image path is not a file', {
        missing_input: 'runtime_image', runtime_image_status: 'MISSING',
        runtime_image_used: false,
      });
    }
  } catch (error) {
    return fail('MISSING_INPUT', `runtime image cannot be read: ${error.message}`, {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
      runtime_image_used: false,
    });
  }
  if (inputCount > 256 || rows.some((row) => row.block.payload_length > 4096)) {
    return fail('UNSUPPORTED', 'inventory MapView runtime batch exceeds its packet or byte limit', {
      runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    });
  }
  const python = options.pythonExecutable || process.env.PYTHON || 'python';
  const script = path.resolve(__dirname, '..', '..', 'scripts',
    'decode_mapview_inventory_16_19.py');
  const request = {
    replay_version: REPLAY_VERSION,
    packets: rows.map(({ block }) => ({
      raw_param: block.param >>> 0,
      payload_hex: block.payload.toString('hex'),
    })),
  };
  const serializedRequest = JSON.stringify(request);
  if (Buffer.byteLength(serializedRequest, 'utf8') > 2_000_000) {
    return fail('UNSUPPORTED', 'inventory MapView runtime input exceeds its byte limit', {
      runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    });
  }
  const run = childProcess.spawnSync(python, ['-B', script, '--image', resolvedImage], {
    input: serializedRequest, encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024, timeout: 60000,
  });
  if (run.error || run.status !== 0) {
    const detail = String(run.error?.message || run.stderr || run.stdout
      || `Python exited ${run.status}`).trim();
    const missingPython = run.error?.code === 'ENOENT'
      || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
    const imageMismatch = /image SHA-256|image hash/i.test(detail);
    return fail(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
      `exact runtime MapView decoder failed: ${detail}`, {
        ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
        runtime_image_status: imageMismatch ? 'HASH_MISMATCH' : 'NOT_CHECKED',
        runtime_image_used: false,
      });
  }
  let decoded;
  try {
    decoded = JSON.parse(run.stdout);
  } catch (error) {
    return fail('DECODE_FAILED', `runtime MapView output is not JSON: ${error.message}`, {
      runtime_image_status: 'EXECUTION_FAILED', runtime_image_used: false,
    });
  }
  if (decoded?.status !== 'PASS'
      || decoded.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || !Array.isArray(decoded.results) || decoded.results.length !== inputCount) {
    return fail('DECODE_FAILED', 'runtime MapView output identity or packet count differs', {
      runtime_image_status: 'EXECUTION_FAILED', runtime_image_used: false,
    });
  }
  const packetRefs = rows.map((row) => packetRef(replay, row.block, row.chunk));
  const runtimePacketFailures = [];
  for (let packetIndex = 0; packetIndex < inputCount; packetIndex += 1) {
    const source = rows[packetIndex];
    const result = decoded.results[packetIndex];
    const rawRef = packetRefs[packetIndex];
    if (result?.input_index !== packetIndex
        || result.raw_payload_sha256 !== rawRef.raw_payload_sha256
        || result.raw_param !== (source.block.param >>> 0)) {
      return fail('DECODE_FAILED', `runtime MapView output does not match packet ${packetIndex}`, {
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        runtime_image_sha256: decoded.runtime_image_sha256,
        first_failed_packet_ref: rawRef,
      });
    }
    if (result.status !== 'DECODED'
        || result.deserialize_return_al !== 1
        || result.bytes_consumed !== source.block.payload_length
        || !Array.isArray(result.records)
        || !Number.isSafeInteger(result.record_count) || result.record_count < 0
        || result.record_count !== result.records.length
        || result.record_count > 10) {
      runtimePacketFailures.push({
        packet_index: packetIndex, raw_packet_ref: rawRef,
        runtime_status: result.status ?? null,
        deserialize_return_al: result.deserialize_return_al ?? null,
        bytes_consumed: result.bytes_consumed ?? null,
        record_count: result.record_count ?? null,
        error: String(result.error ?? 'invalid result').slice(0, 500),
      });
    }
  }
  if (runtimePacketFailures.length > 0) {
    return fail('DECODE_FAILED', `${runtimePacketFailures.length} runtime MapView packets did not fully decode`, {
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      runtime_image_sha256: decoded.runtime_image_sha256,
      first_failed_packet_ref: runtimePacketFailures[0].raw_packet_ref,
      failed_packet_count: runtimePacketFailures.length,
      failed_packet_results: runtimePacketFailures,
    });
  }
  const events = [];
  for (let packetIndex = 0; packetIndex < inputCount; packetIndex += 1) {
    const source = rows[packetIndex];
    const result = decoded.results[packetIndex];
    const rawRef = packetRefs[packetIndex];
    const slots = new Set();
    for (let recordIndex = 0; recordIndex < result.records.length; recordIndex += 1) {
      const record = result.records[recordIndex];
      if (record?.record_index !== recordIndex
          || !Number.isSafeInteger(record.slot) || record.slot < 0 || record.slot > 9
          || slots.has(record.slot)
          || !Number.isSafeInteger(record.item_id) || record.item_id < 1
          || record.item_id > 0xffffffff
          || !Number.isSafeInteger(record.flag) || record.flag < 0 || record.flag > 255
          || !/^[0-9a-f]{2}$/.test(record.raw_slot_byte_hex)
          || !/^[0-9a-f]{8}$/.test(record.raw_item_id_bytes_hex)) {
        return fail('DECODE_FAILED', `runtime MapView packet ${packetIndex} has an invalid slot record`, {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: decoded.runtime_image_sha256,
          first_failed_packet_ref: rawRef,
        });
      }
      slots.add(record.slot);
      events.push({
        event_type: 'HERO_INVENTORY_MAPVIEW_RECORD_CANDIDATE',
        game_version: REPLAY_VERSION,
        patch: '16.19',
        build_profile: profile.id,
        replay_sha256: replay.source_sha256 ?? null,
        replay_time_ms: source.block.timestamp_ms,
        hero_raw_param: source.block.param >>> 0,
        participant_id_candidate: participantIdFromDeathParam(source.block.param),
        packet_record_index: recordIndex,
        packet_record_count: result.record_count,
        slot_candidate: record.slot,
        item_id_candidate: record.item_id,
        emulated_flag_code: record.flag,
        emulated_object_slot_byte_hex: record.raw_slot_byte_hex,
        emulated_object_item_id_bytes_hex: record.raw_item_id_bytes_hex,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_MAPVIEW_ONE_REPLAY',
        field_confidence: {
          replay_time_ms: 'VERIFIED_DIRECT',
          hero_raw_param: 'VERIFIED_DIRECT',
          participant_id_candidate: 'CANDIDATE',
          slot_candidate: 'CANDIDATE_EXACT_RUNTIME_FIELD',
          item_id_candidate: 'CANDIDATE_EXACT_RUNTIME_ITEM_DEFINITION_KEY',
          emulated_flag_code: 'UNCLASSIFIED_RUNTIME_FIELD',
        },
        raw_packet_ref: rawRef,
        known_limits: [...profile.known_limits],
      });
    }
  }
  return {
    ...base,
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_MAPVIEW_ONE_REPLAY',
    input_count: inputCount,
    event_count: events.length,
    decoded_record_count: events.length,
    scanned_block_count: scan.walk.block_count,
    runtime_image_status: 'MATCHED_USED',
    runtime_image_used: true,
    runtime_image_sha256: decoded.runtime_image_sha256,
    events,
  };
}

function decodeHeroInventorySetItemCandidates(replay, collected = null, options = {}) {
  const profile = HERO_INVENTORY_SET_ITEM_CANDIDATE_PROFILE;
  const base = { profile_id: profile.id, input_packet_id: profile.replay_block_packet_id };
  if (replay?.header?.version !== REPLAY_VERSION) {
    return { ...base, status: 'UNSUPPORTED', input_count: null, event_count: null,
      events: null, error: `SetItem candidate supports only ${REPLAY_VERSION}` };
  }
  const scan = candidateRoutesForReplay(replay, collected);
  if (scan.error) {
    return { ...base, status: 'DECODE_FAILED', input_count: null, event_count: null,
      events: null, error: `Replay framing or route source failed: ${scan.error}` };
  }
  const rows = scan.routes.get(profile.replay_block_packet_id);
  const inputCount = rows.length;
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: inputCount, event_count: null, events: null,
    scanned_block_count: scan.walk.block_count, error, ...extra,
  });
  if (inputCount === 0) {
    return fail('PROFILE_UNAVAILABLE', 'HN game-stream SetItem route 0x03b7 is absent', {
      input_count: null, observed_raw_route_count: 0,
      runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    });
  }
  const hasObservedParamShape = ({ block }) => (block.param >>> 16) === 0x4000
    && (block.param & 0xff) >= 0xae && (block.param & 0xff) <= 0xb7;
  const shapeCount = rows.filter((row) => hasObservedParamShape(row)
    && row.block.payload_length === profile.payload_length).length;
  if (shapeCount !== inputCount) {
    return fail(shapeCount === 0 ? 'PROFILE_UNAVAILABLE' : 'DECODE_FAILED',
      '0x03b7 packets do not consistently match the observed HN SetItem framing', {
        ...(shapeCount === 0 ? { input_count: null } : {}),
        observed_raw_route_count: inputCount, matching_packet_count: shapeCount,
        runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
      });
  }
  const imagePath = options.runtimeImagePath;
  if (typeof imagePath !== 'string' || !imagePath.trim()) {
    return fail('MISSING_INPUT', 'exact 16.19 HN runtime image is required', {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING', runtime_image_used: false,
    });
  }
  const resolvedImage = path.resolve(imagePath);
  try {
    if (!fs.statSync(resolvedImage).isFile()) {
      return fail('MISSING_INPUT', 'runtime image path is not a file', {
        missing_input: 'runtime_image', runtime_image_status: 'MISSING', runtime_image_used: false,
      });
    }
  } catch (error) {
    return fail('MISSING_INPUT', `runtime image cannot be read: ${error.message}`, {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING', runtime_image_used: false,
    });
  }
  if (inputCount > 256) {
    return fail('UNSUPPORTED', 'SetItem runtime batch exceeds its packet limit', {
      runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    });
  }
  const request = {
    replay_version: REPLAY_VERSION,
    packets: rows.map(({ block }) => ({
      raw_param: block.param >>> 0,
      payload_hex: block.payload.toString('hex'),
    })),
  };
  const serializedRequest = JSON.stringify(request);
  if (Buffer.byteLength(serializedRequest, 'utf8') > 2_000_000) {
    return fail('UNSUPPORTED', 'SetItem runtime input exceeds its byte limit', {
      runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    });
  }
  const python = options.pythonExecutable || process.env.PYTHON || 'python';
  const script = path.resolve(__dirname, '..', '..', 'scripts', 'decode_setitem_16_19.py');
  const run = childProcess.spawnSync(python, ['-B', script, '--image', resolvedImage], {
    input: serializedRequest, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024,
    timeout: 60000,
  });
  if (run.error || run.status !== 0) {
    const detail = String(run.error?.message || run.stderr || run.stdout
      || `Python exited ${run.status}`).trim();
    const missingPython = run.error?.code === 'ENOENT'
      || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
    const imageMismatch = /image SHA-256|image hash/i.test(detail);
    return fail(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
      `exact runtime SetItem decoder failed: ${detail}`, {
        ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
        runtime_image_status: imageMismatch ? 'HASH_MISMATCH' : 'NOT_CHECKED',
        runtime_image_used: false,
      });
  }
  let decoded;
  try {
    decoded = JSON.parse(run.stdout);
  } catch (error) {
    return fail('DECODE_FAILED', `runtime SetItem output is not JSON: ${error.message}`, {
      runtime_image_status: 'EXECUTION_FAILED', runtime_image_used: false,
    });
  }
  if (decoded?.status !== 'PASS'
      || decoded.runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || !Array.isArray(decoded.results) || decoded.results.length !== inputCount) {
    return fail('DECODE_FAILED', 'runtime SetItem output identity or packet count differs', {
      runtime_image_status: 'EXECUTION_FAILED', runtime_image_used: false,
    });
  }
  const packetRefs = rows.map((row) => packetRef(replay, row.block, row.chunk));
  const failures = [];
  for (let index = 0; index < inputCount; index += 1) {
    const source = rows[index];
    const result = decoded.results[index];
    const rawRef = packetRefs[index];
    if (result?.input_index !== index
        || result.raw_param !== (source.block.param >>> 0)
        || result.raw_payload_sha256 !== rawRef.raw_payload_sha256) {
      return fail('DECODE_FAILED', `runtime SetItem output does not match packet ${index}`, {
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        runtime_image_sha256: decoded.runtime_image_sha256,
        first_failed_packet_ref: rawRef,
      });
    }
    if (result.status !== 'DECODED'
        || result.deserialize_return_al !== 1
        || result.bytes_consumed !== profile.payload_length
        || !Number.isSafeInteger(result.slot) || result.slot < 0 || result.slot > 9
        || !Number.isSafeInteger(result.item_id) || result.item_id < 1
        || result.item_id > 0xffffffff
        || !Number.isSafeInteger(result.flag) || result.flag < 0 || result.flag > 255
        || !/^[0-9a-f]{2}$/.test(result.raw_slot_byte_hex)
        || !/^[0-9a-f]{8}$/.test(result.raw_item_id_bytes_hex)) {
      failures.push({
        packet_index: index, raw_packet_ref: rawRef,
        runtime_status: result.status ?? null,
        deserialize_return_al: result.deserialize_return_al ?? null,
        bytes_consumed: result.bytes_consumed ?? null,
        error: String(result.error ?? 'invalid result').slice(0, 500),
      });
    }
  }
  if (failures.length > 0) {
    return fail('DECODE_FAILED', `${failures.length} runtime SetItem packets did not fully decode`, {
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      runtime_image_sha256: decoded.runtime_image_sha256,
      first_failed_packet_ref: failures[0].raw_packet_ref,
      failed_packet_count: failures.length,
      failed_packet_results: failures,
    });
  }
  const events = rows.map((source, index) => {
    const result = decoded.results[index];
    const rawParam = source.block.param >>> 0;
    const participantId = rawParam >= 0x400000ae && rawParam <= 0x400000b7
      ? participantIdFromDeathParam(rawParam) : null;
    return {
      event_type: 'HERO_INVENTORY_SET_ITEM_RECORD_CANDIDATE',
      game_version: REPLAY_VERSION, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: source.block.timestamp_ms,
      hero_raw_param: rawParam,
      participant_id_candidate: participantId,
      slot_candidate: result.slot,
      item_id_candidate: result.item_id,
      emulated_flag_code: result.flag,
      emulated_object_slot_byte_hex: result.raw_slot_byte_hex,
      emulated_object_item_id_bytes_hex: result.raw_item_id_bytes_hex,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_EXACT_RUNTIME_SET_ITEM_ONE_REPLAY',
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        hero_raw_param: 'VERIFIED_DIRECT',
        participant_id_candidate: participantId === null ? 'UNAVAILABLE' : 'CANDIDATE',
        slot_candidate: 'CANDIDATE_EXACT_RUNTIME_FIELD',
        item_id_candidate: 'CANDIDATE_EXACT_RUNTIME_ITEM_DEFINITION_KEY',
        emulated_flag_code: 'UNCLASSIFIED_RUNTIME_FIELD',
      },
      raw_packet_ref: packetRefs[index],
      known_limits: [...profile.known_limits],
    };
  });
  return {
    ...base, status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_SET_ITEM_ONE_REPLAY',
    input_count: inputCount, event_count: events.length,
    scanned_block_count: scan.walk.block_count,
    unmapped_raw_param_count: events.filter((event) => event.participant_id_candidate === null).length,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: decoded.runtime_image_sha256,
    events,
  };
}

module.exports = {
  REPLAY_VERSION,
  HERO_DEATH_CANDIDATE_PROFILES,
  HERO_DEATH_TIMER_CANDIDATE_PROFILE,
  HERO_RESPAWN_CANDIDATE_PROFILE,
  HERO_LEVEL_STATE_CANDIDATE_PROFILE,
  HERO_INVENTORY_MAPVIEW_CANDIDATE_PROFILE,
  HERO_INVENTORY_SET_ITEM_CANDIDATE_PROFILE,
  analyzeReplayWithCandidateRoutes,
  collectCandidateRoutes,
  decodeHeroDeathCandidates,
  decodeHeroDeathTimerCandidates,
  decodeHeroRespawnCandidates,
  decodeHeroDeathTimerPayload,
  decodeHeroLevelStateCandidates,
  decodeHeroInventoryMapViewCandidates,
  decodeHeroInventorySetItemCandidates,
  decodeHeroLevelPayload,
  candidateTailStatAssessment,
  participantIdFromDeathParam,
};
