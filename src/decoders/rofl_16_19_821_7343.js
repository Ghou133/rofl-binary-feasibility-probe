'use strict';

const crypto = require('node:crypto');

const { deathEvent } = require('../events');
const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { rowsFor821Capability } = require('./rofl_16_19_821_scan');
const { assessHeroChampionKillsSnapshotTail821 } =
  require('./rofl_16_19_821_hero_stats_candidate');
const { RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256, decodeHeroDieSourceId821 } =
  require('./rofl_16_19_821_runtime_bytes');

const REPLAY_VERSION_821 = '16.19.821.7343';

// The route core comes from eleven exact 821.7343 KR Replays. The optional
// 0x0438 source ID uses an exact-image static transform; its killer label
// remains conditional on the independent Replay-tail kill counts.
const HERO_DEATH_CANDIDATE_PROFILE_821 = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-death-route-tail-candidate-v1',
  replay_version: REPLAY_VERSION_821,
  capability: 'hero_death',
  status: 'CANDIDATE',
  enabled: true,
  stream_tag: 1,
  replay_block_packet_id: 0x0259,
  paired_replay_block_packet_id: 0x0438,
  corroborating_replay_block_packet_ids: Object.freeze([0x031b, 0x03d4]),
  participant_mapping: 'observed 821 raw_param families 0x400000ae..b7 and 0x400001ae..b7; low byte maps to Replay tail participant 1..10',
  evidence_scope: 'eleven KR exact-build 821.7343 Replays; unique three-route core and all ten final death totals per Replay',
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  source_id_lookup_table_sha256: LOOKUP_TABLE_SHA256,
  known_limits: Object.freeze([
    'Experimental exact-build Replay-tail route candidate, not a published death capability.',
    'Victim participant mapping is supported by final NUM_DEATHS counts, not an 821 runtime deserializer.',
    'The observed upper 0x100 raw-param bit and all 0x0259 payload fields remain unclassified.',
    'The 0x0438 source ID is runtime decoded; killer participant remains a candidate only after ten CHAMPIONS_KILLED tails align.',
    'Nonhero source IDs remain unmapped; this death route does not establish assist attribution, damage events, or complete combat semantics. Separate assist and damage candidates have independent gates.',
    'Core 0x0259/0x0438/0x031b must join uniquely; isolated 0x0259 is excluded and reported.',
    'Optional 0x03d4 was absent at one matched core in each of two observed Replays; omissions are reported.',
    'An unmatched paired or long route, ambiguous join, unexpected 0x03d4, or tail mismatch fails closed.',
  ]),
});

const ROUTE_IDS = Object.freeze([
  HERO_DEATH_CANDIDATE_PROFILE_821.replay_block_packet_id,
  HERO_DEATH_CANDIDATE_PROFILE_821.paired_replay_block_packet_id,
  ...HERO_DEATH_CANDIDATE_PROFILE_821.corroborating_replay_block_packet_ids,
]);

function assessHeroDeathTail821(replay) {
  const stats = replay?.tail?.stats;
  if (!Array.isArray(stats)) {
    return { status: 'MISSING_INPUT', missing_input: 'Replay tail statsJson participant rows' };
  }
  if (stats.length !== 10) {
    return { status: 'UNSUPPORTED', error: `candidate scope requires 10 participants; got ${stats.length}` };
  }
  const values = stats.map((row) => row?.NUM_DEATHS);
  if (values.some((value) => value === undefined || value === null || value === '')) {
    return { status: 'MISSING_INPUT', missing_input: 'Replay tail NUM_DEATHS for all 10 participants' };
  }
  if (values.some((value) =>
    !(typeof value === 'string' && /^\d+$/.test(value))
    && !(Number.isSafeInteger(value) && value >= 0))) {
    return { status: 'UNSUPPORTED', error: 'Replay tail NUM_DEATHS must be nonnegative integers' };
  }
  const counts = values.map(Number);
  if (counts.some((value) => !Number.isSafeInteger(value))) {
    return { status: 'UNSUPPORTED', error: 'Replay tail NUM_DEATHS must be safe integers' };
  }
  return { status: 'PASS', counts };
}

function participantFrom821RawParam(rawParam) {
  if (!Number.isInteger(rawParam) || rawParam < 0 || rawParam > 0xffffffff) return null;
  const inObservedFamily = (rawParam >= 0x400000ae && rawParam <= 0x400000b7)
    || (rawParam >= 0x400001ae && rawParam <= 0x400001b7);
  if (!inObservedFamily) return null;
  const lowByte = rawParam & 0xff;
  return lowByte >= 0xae && lowByte <= 0xb7 ? lowByte - 0xad : null;
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

function decodeHeroDeathCandidates821(replay, precollected = null) {
  const profile = HERO_DEATH_CANDIDATE_PROFILE_821;
  const base = {
    profile_id: profile.id,
    input_packet_id: profile.replay_block_packet_id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    source_id_lookup_table_sha256: LOOKUP_TABLE_SHA256,
    runtime_image_used: false,
    runtime_image_status: 'STATIC_821_HERO_DIE_SOURCE_TRANSFORM_EMBEDDED',
    known_limits: [...profile.known_limits],
  };
  if (replay?.header?.version !== REPLAY_VERSION_821) {
    return { ...base, status: 'UNSUPPORTED', event_count: null, input_count: null,
      events: null, error: `hero_death candidate supports only ${REPLAY_VERSION_821}` };
  }
  const sourceError = precollected === null ? replaySourceError(replay) : null;
  if (sourceError) {
    return { ...base, status: 'DECODE_FAILED', event_count: null, input_count: null,
      events: null, error: `Replay source integrity failed: ${sourceError}` };
  }

  const routes = new Map(ROUTE_IDS.map((id) => [id, []]));
  let walked;
  if (precollected !== null) {
    const scan = rowsFor821Capability(replay, precollected, 'hero_death');
    if (scan.error) {
      return { ...base, status: 'DECODE_FAILED', event_count: null, input_count: null,
        events: null, error: scan.error };
    }
    for (const row of scan.rows) routes.get(row.block.packet_id).push(row);
    walked = { block_count: scan.scanned_block_count };
  } else {
    try {
      // Decode every block stream strictly; retain only game-stream evidence.
      walked = walkBlocks(replay, (block, chunk) => {
        if (chunk.stream_tag === profile.stream_tag && routes.has(block.packet_id)) {
          routes.get(block.packet_id).push({ block, chunk });
        }
      }, { strict: true });
    } catch (error) {
      return { ...base, status: 'DECODE_FAILED', event_count: null, input_count: null,
        events: null, error: `Replay framing failed: ${error.message}` };
    }
  }

  const [primary, paired, longCorroboration, shortCorroboration] =
    ROUTE_IDS.map((id) => routes.get(id));
  const inputCount = primary.length;
  const supportingPacketCount = ROUTE_IDS.reduce((count, id) => count + routes.get(id).length, 0);
  const common = { ...base, input_count: inputCount,
    supporting_packet_count: supportingPacketCount, scanned_block_count: walked.block_count,
    observed_packet_counts_by_route: Object.fromEntries(ROUTE_IDS.map((id) => [
      `0x${id.toString(16).padStart(4, '0')}`, routes.get(id).length,
    ])) };
  if (supportingPacketCount === 0) {
    return { ...common, status: 'PROFILE_UNAVAILABLE', event_count: null, events: null,
      error: 'no 821 exact-build death route fingerprint was observed' };
  }
  const fail = (error) => ({ ...common, status: 'DECODE_FAILED', event_count: null,
    events: null, error });
  const tail = assessHeroDeathTail821(replay);
  if (tail.status !== 'PASS') {
    return { ...common, ...tail, event_count: null, events: null };
  }
  if (paired.length === 0 || primary.length === 0 || longCorroboration.length === 0) {
    return fail('required 821 core route is missing');
  }
  if (primary.some(({ block }) => block.payload_length !== 5)
      || paired.some(({ block }) => block.payload_length <= 5)
      || longCorroboration.some(({ block }) => block.payload_length <= 5)
      || shortCorroboration.some(({ block }) => ![3, 7].includes(block.payload_length))) {
    return fail('route payload lengths differ from the observed 821 structural fingerprint');
  }
  if (primary.some(({ block }) => participantFrom821RawParam(block.param) === null)
      || paired.some(({ block }) => participantFrom821RawParam(block.param) === null)
      || longCorroboration.some(({ block }) => (block.param >>> 0) !== 0)
      || shortCorroboration.some(({ block }) => (block.param >>> 0) !== 0)) {
    return fail('route raw params differ from the observed 821 structural fingerprint');
  }

  const timeKey = (source) => `${source.chunk.index}/${source.block.timestamp_ms}`;
  const pairKey = (source) => `${timeKey(source)}/${source.block.param >>> 0}`;
  const grouped = (rows, keyFor) => {
    const groups = new Map();
    for (const row of rows) {
      const key = keyFor(row);
      const group = groups.get(key) ?? [];
      group.push(row);
      groups.set(key, group);
    }
    return groups;
  };
  const primaryByPair = grouped(primary, pairKey);
  const pairedByPair = grouped(paired, pairKey);
  const longByTime = grouped(longCorroboration, timeKey);
  const shortByTime = grouped(shortCorroboration, timeKey);
  if ([primaryByPair, pairedByPair, longByTime, shortByTime]
    .some((groups) => [...groups.values()].some((group) => group.length !== 1))) {
    return fail('duplicate or ambiguous 821 route packet key');
  }

  const sortedPaired = [...paired].sort((left, right) =>
    left.chunk.index - right.chunk.index
    || left.block.timestamp_ms - right.block.timestamp_ms
    || left.block.offset - right.block.offset);
  const core = [];
  const usedPrimaryKeys = new Set();
  const usedTimes = new Set();
  const observedCounts = Array(10).fill(0);
  for (let index = 0; index < sortedPaired.length; index += 1) {
    const second = sortedPaired[index];
    const matchingPrimary = primaryByPair.get(pairKey(second));
    const matchingLong = longByTime.get(timeKey(second));
    if (!matchingPrimary || !matchingLong) {
      return fail(`unmatched required 821 core route at occurrence ${index}`);
    }
    if (usedTimes.has(timeKey(second))) {
      return fail('ambiguous same-chunk, same-millisecond core route pairing');
    }
    usedTimes.add(timeKey(second));
    usedPrimaryKeys.add(pairKey(second));
    const first = matchingPrimary[0];
    const third = matchingLong[0];
    const fourth = shortByTime.get(timeKey(second))?.[0] ?? null;
    observedCounts[participantFrom821RawParam(first.block.param) - 1] += 1;
    core.push({ first, second, third, fourth });
  }
  if (longByTime.size !== core.length) {
    return fail('unmatched 0x031b long corroborating route packet');
  }
  if ([...shortByTime.keys()].some((key) => !usedTimes.has(key))) {
    return fail('unexpected 0x03d4 packet outside a matched core');
  }
  if (observedCounts.some((count, index) => count !== tail.counts[index])) {
    return fail('observed victim counts do not match Replay tail NUM_DEATHS');
  }

  const unmatchedPrimary = primary.filter((row) => !usedPrimaryKeys.has(pairKey(row)));
  const missingShort = core.filter((row) => row.fourth === null);
  const decodedSources = core.map(({ second }) =>
    decodeHeroDieSourceId821(second.block.payload));
  const fullyDecodedSources = decodedSources.every((value) => value !== null);
  const sourceHeroCounts = Array(10).fill(0);
  for (const sourceId of decodedSources) {
    const participant = participantFrom821RawParam(sourceId);
    if (participant !== null) sourceHeroCounts[participant - 1] += 1;
  }
  const killTail = assessHeroChampionKillsSnapshotTail821(replay);
  const sourceTailAligned = fullyDecodedSources && killTail.status === 'PASS'
    && sourceHeroCounts.every((count, index) => count === killTail.values[index]);
  const sourceTailStatus = !fullyDecodedSources ? 'WIRE_SHAPE_UNAVAILABLE'
    : killTail.status !== 'PASS' ? killTail.status
      : sourceTailAligned ? 'CANDIDATE_ALIGNED' : 'TAIL_MISMATCH';
  const events = core.map(({ first, second, third, fourth }, index) => {
    const participantId = participantFrom821RawParam(first.block.param);
    const dieSourceId = decodedSources[index];
    const sourceParticipant = sourceTailAligned
      ? participantFrom821RawParam(dieSourceId) : null;
    const refs = [
      packetRef(replay, first, 'candidate_primary'),
      packetRef(replay, second, 'candidate_paired'),
      packetRef(replay, third, 'corroborating_core_co_timed'),
      ...(fourth ? [packetRef(replay, fourth, 'optional_corroborating_co_timed')] : []),
    ];
    return deathEvent({
      game_version: REPLAY_VERSION_821,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256 ?? null,
      replay_time_ms: first.block.timestamp_ms,
      timestamp_ms: first.block.timestamp_ms,
      victim_participant_id: participantId,
      target_participant_id: participantId,
      victim_raw_param: first.block.param >>> 0,
      victim_network_id: null,
      killer_network_id: null,
      killer_participant_id: null,
      die_source_network_id_candidate: dieSourceId,
      killer_participant_id_candidate: sourceParticipant,
      die_source_decode_status: dieSourceId === null
        ? 'WIRE_SHAPE_UNAVAILABLE' : 'EXACT_821_RUNTIME_WIRE_TRANSFORM',
      killer_alignment_status: sourceTailStatus,
      die_source_raw_packet_ref: refs[1],
      assists: null,
      respawn_timestamp_ms: null,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_821_REPLAY_TAIL_ROUTE_FINGERPRINT',
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        victim_raw_param: 'VERIFIED_DIRECT',
        victim_participant_id: 'CANDIDATE_REPLAY_TAIL_COUNTS',
        killer_network_id: 'UNAVAILABLE',
        die_source_network_id_candidate: dieSourceId === null ? 'UNAVAILABLE'
          : 'CANDIDATE_821_RUNTIME_HERO_DIE_SOURCE_WIRE',
        killer_participant_id_candidate: sourceParticipant === null ? 'UNAVAILABLE'
          : 'CANDIDATE_821_SOURCE_ID_KILL_TAIL_ALIGNMENT',
        die_source_raw_packet_ref: 'VERIFIED_DIRECT',
        assists: 'UNAVAILABLE',
        respawn_timestamp_ms: 'UNAVAILABLE',
      },
      raw_packet_ref: refs[0],
      raw_packet_refs: refs,
      optional_0x03d4_status: fourth ? 'PRESENT_UNIQUE' : 'ABSENT_OBSERVED',
      known_limits: [...profile.known_limits],
    });
  });
  return {
    ...common,
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_821_REPLAY_TAIL_ROUTE_FINGERPRINT',
    event_count: events.length,
    matched_core_count: core.length,
    matched_core_supporting_packet_count: core.reduce((count, row) =>
      count + (row.fourth ? 4 : 3), 0),
    unmatched_primary_count: unmatchedPrimary.length,
    unmatched_primary_packet_refs: unmatchedPrimary.map((row) =>
      packetRef(replay, row, 'unmatched_primary_excluded')),
    missing_optional_0x03d4_count: missingShort.length,
    missing_optional_0x03d4_primary_refs: missingShort.map((row) =>
      packetRef(replay, row.first, 'matched_core_missing_optional_corroboration')),
    hero_die_source_decoded_count: decodedSources.filter((value) => value !== null).length,
    hero_die_source_hero_family_count: decodedSources.filter((value) =>
      participantFrom821RawParam(value) !== null).length,
    hero_die_source_other_count: decodedSources.filter((value) =>
      value !== null && participantFrom821RawParam(value) === null).length,
    observed_champion_kills_by_source: fullyDecodedSources ? sourceHeroCounts : null,
    champion_kills_tail_alignment_status: sourceTailStatus,
    final_champion_kills_tails: killTail.status === 'PASS' ? killTail.values : null,
    final_death_counts: tail.counts,
    observed_death_counts: observedCounts,
    events,
  };
}

module.exports = {
  REPLAY_VERSION_821,
  HERO_DEATH_CANDIDATE_PROFILE_821,
  assessHeroDeathTail821,
  decodeHeroDeathCandidates821,
};
