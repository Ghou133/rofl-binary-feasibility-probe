'use strict';

// This joins two already decoded exact-build candidate routes. It neither
// decodes packets nor assigns gameplay roles to the OnChampionDie child fields.
const { isDeepStrictEqual } = require('node:util');
const { replaySourceError } = require('./replay_source_integrity');
const { CHAMPION_DIE_EVENT_PACKET_821_PROFILE } =
  require('./rofl_16_19_821_champion_die_event_packet_candidate');
const { HERO_DEATH_CANDIDATE_PROFILE_821 } =
  require('./rofl_16_19_821_7343');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const MAX_EVENTS = 10_000;
const CANDIDATE_STATUS = 'CANDIDATE_821_ON_CHAMPION_DIE_HERO_DIE_PACKET_PAIR';

const CHAMPION_DIE_HERO_DEATH_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-on-champion-die-hero-die-pair-candidate-v1',
  replay_version: BUILD,
  capability: 'champion_die_hero_death_pair',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze(['champion_die_event_packet', 'hero_death']),
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays; 655/655 unique same-Replay, same-chunk, same-ms OnChampionDie/Hero_Die candidate rows; child +0x04 equals decoded 0x0438 source ID and raw-param low bytes agree in all 655',
  known_limits: Object.freeze([
    'A packet-level candidate association is not proof of an effective death or a callback actor role.',
    'OnChampionDie raw_param and Hero_Die victim_raw_param differ in 322 of 655 observed pairs; only their low bytes are required to agree.',
    'The +0x04 field and decoded 0x0438 source ID are retained as existing candidate fields without assigning a killer role.',
    'Any missing, duplicated, or conflicting row fails the entire Replay association without emitting partial pairs.',
  ]),
});

function u32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_EVENTS;
}

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function observedParam(raw, highestNibble) {
  if (!u32(raw)) return false;
  const low = raw & 0xff;
  return low >= 0xae && low <= 0xb7
    && ((raw & 0xfffff0ff) >>> 0) === ((0x40000000 | low) >>> 0)
    && ((raw >>> 8) & 0xf) <= highestNibble;
}

function validRef(replay, ref, { packetId, payloadLength, rawParam, timeMs, role }) {
  if (!ref || (role !== undefined && ref.role !== role)
      || ref.replay_sha256 !== replay.source_sha256
      || ref.source_path !== (replay.source_path ?? null)
      || ref.packet_id !== packetId || ref.replay_time_ms !== timeMs
      || !u32(ref.raw_param) || ref.raw_param !== rawParam
      || ref.chunk_stream !== 'game_chunk'
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id)
      || !Number.isSafeInteger(ref.chunk_file_offset)
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || !Number.isSafeInteger(ref.payload_length)
      || !sha(ref.raw_payload_sha256)) return false;
  const chunk = replay.chunks?.[ref.chunk_index];
  if (!chunk || chunk.index !== ref.chunk_index || chunk.chunk_id !== ref.chunk_id
      || chunk.stream !== ref.chunk_stream || chunk.offset !== ref.chunk_file_offset
      || !Number.isSafeInteger(chunk.uncompressed_length)
      || ref.decompressed_block_offset < 0
      || ref.decompressed_payload_offset <= ref.decompressed_block_offset
      || ref.decompressed_payload_offset + ref.payload_length > chunk.uncompressed_length) {
    return false;
  }
  return Array.isArray(payloadLength) ? payloadLength.includes(ref.payload_length)
    : payloadLength === null ? ref.payload_length > 5
      : ref.payload_length === payloadLength;
}

function validDieRow(replay, row) {
  return row?.event_type === 'CHAMPION_DIE_EVENT_PACKET_CANDIDATE'
    && row.game_version === BUILD && row.build_profile === CHAMPION_DIE_EVENT_PACKET_821_PROFILE.id
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === 'CANDIDATE_EXACT_RUNTIME_ON_CHAMPION_DIE_PACKET'
    && row.replay_sha256 === replay.source_sha256
    && Number.isSafeInteger(row.replay_time_ms) && row.replay_time_ms >= 0
    && row.event_id === 0x0004 && row.event_name === 'OnChampionDie'
    && row.raw_event_id_hex === '0x4948'
    && observedParam(row.raw_param, 4)
    && u32(row.event_u32_0x04) && row.event_u32_0x04 !== 0
    && sha(row.event_blob_sha256)
    && validRef(replay, row.raw_packet_ref, {
      packetId: 0x040a, payloadLength: 116, rawParam: row.raw_param,
      timeMs: row.replay_time_ms,
    });
}

function validHeroRow(replay, row) {
  if (row?.event_type !== 'death' || row.game_version !== BUILD
      || row.build_profile !== HERO_DEATH_CANDIDATE_PROFILE_821.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== 'CANDIDATE_821_REPLAY_TAIL_ROUTE_FINGERPRINT'
      || row.replay_sha256 !== replay.source_sha256
      || !Number.isSafeInteger(row.replay_time_ms) || row.replay_time_ms < 0
      || !observedParam(row.victim_raw_param, 1)
      || !u32(row.die_source_network_id_candidate)
      || row.die_source_network_id_candidate === 0
      || row.die_source_decode_status !== 'EXACT_821_RUNTIME_WIRE_TRANSFORM'
      || !Array.isArray(row.raw_packet_refs)
      || ![3, 4].includes(row.raw_packet_refs.length)
      || !isDeepStrictEqual(row.raw_packet_ref, row.raw_packet_refs[0])
      || !isDeepStrictEqual(row.die_source_raw_packet_ref, row.raw_packet_refs[1])) {
    return false;
  }
  const [primary, paired, long, optional] = row.raw_packet_refs;
  const chunkIndex = primary?.chunk_index;
  if (row.raw_packet_refs.some((ref) => ref.chunk_index !== chunkIndex)) return false;
  return validRef(replay, primary, { packetId: 0x0259, payloadLength: 5,
    rawParam: row.victim_raw_param, timeMs: row.replay_time_ms, role: 'candidate_primary' })
    && validRef(replay, paired, { packetId: 0x0438, payloadLength: null,
      rawParam: row.victim_raw_param, timeMs: row.replay_time_ms, role: 'candidate_paired' })
    && validRef(replay, long, { packetId: 0x031b, payloadLength: null,
      rawParam: 0, timeMs: row.replay_time_ms, role: 'corroborating_core_co_timed' })
    && (!optional || validRef(replay, optional, { packetId: 0x03d4,
      payloadLength: [3, 7], rawParam: 0, timeMs: row.replay_time_ms,
      role: 'optional_corroborating_co_timed' }));
}

function pairKey(row, route) {
  const ref = route === 'die' ? row.raw_packet_ref : row.raw_packet_refs[0];
  return `${ref.chunk_index}/${row.replay_time_ms}`;
}

function associateChampionDieHeroDeathCandidates821(replay, {
  championDieEventPacketOutcome, heroDeathOutcome,
} = {}) {
  const profile = CHAMPION_DIE_HERO_DEATH_PAIR_821_PROFILE;
  const base = {
    profile_id: profile.id, evidence_runtime_image_sha256: IMAGE_SHA256,
    depends_on: [...profile.depends_on], known_limits: [...profile.known_limits],
  };
  const fail = (status, reason, diagnostics = {}) => ({
    ...base, status, evidence_status: status === 'INCONSISTENT' ? 'INCONSISTENT' : null,
    event_count: null, pair_count: null, events: null,
    on_champion_die_count: Array.isArray(championDieEventPacketOutcome?.events)
      ? championDieEventPacketOutcome.events.length : null,
    hero_death_count: Array.isArray(heroDeathOutcome?.events)
      ? heroDeathOutcome.events.length : null,
    error: reason, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `packet association supports only ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) {
    return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  }
  if (!sha(replay.source_sha256)) {
    return fail('INCONSISTENT', 'Replay source SHA-256 is missing or malformed');
  }
  if (!championDieEventPacketOutcome || !heroDeathOutcome) {
    return fail('MISSING_INPUT', 'both exact-build candidate decoder outcomes are required', {
      missing_inputs: [
        ...(!championDieEventPacketOutcome ? ['champion_die_event_packet'] : []),
        ...(!heroDeathOutcome ? ['hero_death'] : []),
      ],
    });
  }
  const die = championDieEventPacketOutcome;
  const hero = heroDeathOutcome;
  if (die.status !== 'CANDIDATE' || hero.status !== 'CANDIDATE') {
    return fail('MISSING_INPUT', 'one or both candidate decoder outcomes are unavailable', {
      champion_die_status: die.status ?? null, hero_death_status: hero.status ?? null,
    });
  }
  if (die.profile_id !== CHAMPION_DIE_EVENT_PACKET_821_PROFILE.id
      || die.evidence_runtime_image_sha256 !== IMAGE_SHA256
      || die.runtime_image_sha256 !== IMAGE_SHA256
      || die.runtime_image_status !== 'MATCHED_USED' || die.runtime_image_used !== true
      || die.input_packet_id !== 0x040a || die.child_event_id !== 0x0004
      || !Array.isArray(die.events) || !count(die.event_count)
      || die.event_count !== die.events.length
      || !count(die.observed_same_length_control_count)
      || !count(die.input_count)
      || die.input_count !== die.event_count + die.observed_same_length_control_count
      || hero.profile_id !== HERO_DEATH_CANDIDATE_PROFILE_821.id
      || hero.evidence_runtime_image_sha256 !== IMAGE_SHA256
      || hero.source_id_lookup_table_sha256
        !== HERO_DEATH_CANDIDATE_PROFILE_821.source_id_lookup_table_sha256
      || hero.runtime_image_status !== 'STATIC_821_HERO_DIE_SOURCE_TRANSFORM_EMBEDDED'
      || hero.runtime_image_used !== false
      || hero.input_packet_id !== 0x0259
      || !Array.isArray(hero.events) || !count(hero.event_count)
      || hero.event_count !== hero.events.length
      || !count(hero.matched_core_count) || hero.matched_core_count !== hero.event_count
      || !count(hero.unmatched_primary_count) || !count(hero.input_count)
      || hero.input_count !== hero.event_count + hero.unmatched_primary_count
      || !count(hero.hero_die_source_decoded_count)
      || hero.hero_die_source_decoded_count !== hero.event_count) {
    return fail('INCONSISTENT', 'exact-build candidate outcome identity or counts differ');
  }
  if (die.events.length === 0 || hero.events.length === 0) {
    return fail('MISSING_INPUT', 'both candidate routes require at least one event');
  }
  for (let index = 0; index < die.events.length; index += 1) {
    if (!validDieRow(replay, die.events[index])) {
      return fail('INCONSISTENT', 'OnChampionDie candidate row has invalid identity or raw packet reference',
        { route: 'champion_die_event_packet', event_index: index });
    }
  }
  for (let index = 0; index < hero.events.length; index += 1) {
    if (!validHeroRow(replay, hero.events[index])) {
      return fail('INCONSISTENT', 'Hero_Die candidate row has invalid identity or raw packet reference',
        { route: 'hero_death', event_index: index });
    }
  }
  const seenPacketPositions = new Set();
  for (const ref of [
    ...die.events.map((event) => event.raw_packet_ref),
    ...hero.events.flatMap((event) => event.raw_packet_refs),
  ]) {
    const position = `${ref.chunk_index}/${ref.decompressed_block_offset}`;
    if (seenPacketPositions.has(position)) {
      return fail('INCONSISTENT', 'candidate raw packet position is duplicated',
        { duplicate_packet_position: position });
    }
    seenPacketPositions.add(position);
  }
  const dieByKey = new Map();
  const heroByKey = new Map();
  const add = (map, row, route) => {
    const key = pairKey(row, route);
    if (map.has(key)) return key;
    map.set(key, row);
    return null;
  };
  for (const row of die.events) {
    const duplicate = add(dieByKey, row, 'die');
    if (duplicate) return fail('INCONSISTENT', 'duplicate OnChampionDie same-chunk, same-ms key',
      { duplicate_key: duplicate, route: 'champion_die_event_packet' });
  }
  for (const row of hero.events) {
    const duplicate = add(heroByKey, row, 'hero');
    if (duplicate) return fail('INCONSISTENT', 'duplicate Hero_Die same-chunk, same-ms key',
      { duplicate_key: duplicate, route: 'hero_death' });
  }
  const missingHeroKeys = [...dieByKey.keys()].filter((key) => !heroByKey.has(key));
  const missingDieKeys = [...heroByKey.keys()].filter((key) => !dieByKey.has(key));
  if (missingHeroKeys.length || missingDieKeys.length) {
    return fail('INCONSISTENT', 'same-chunk, same-ms candidate key sets differ', {
      unmatched_on_champion_die_count: missingHeroKeys.length,
      unmatched_hero_death_count: missingDieKeys.length,
      first_unmatched_on_champion_die_key: missingHeroKeys[0] ?? null,
      first_unmatched_hero_death_key: missingDieKeys[0] ?? null,
    });
  }
  const events = [];
  const rawDeltaCounts = new Map();
  let exactRawEqualCount = 0;
  const sorted = [...dieByKey.entries()].sort(([left], [right]) => {
    const [leftChunk, leftTime] = left.split('/').map(Number);
    const [rightChunk, rightTime] = right.split('/').map(Number);
    return leftChunk - rightChunk || leftTime - rightTime;
  });
  for (const [key, dieRow] of sorted) {
    const heroRow = heroByKey.get(key);
    const dieOffset = dieRow.raw_packet_ref.decompressed_block_offset;
    const primaryOffset = heroRow.raw_packet_refs[0].decompressed_block_offset;
    const pairedOffset = heroRow.raw_packet_refs[1].decompressed_block_offset;
    if (!(dieOffset < primaryOffset && primaryOffset < pairedOffset)) {
      return fail('INCONSISTENT', 'candidate packet order differs from observed child/primary/paired route', {
        key, on_champion_die_offset: dieOffset, hero_primary_offset: primaryOffset,
        hero_paired_offset: pairedOffset,
      });
    }
    if ((dieRow.raw_param & 0xff) !== (heroRow.victim_raw_param & 0xff)
        || dieRow.event_u32_0x04 !== heroRow.die_source_network_id_candidate) {
      return fail('INCONSISTENT', 'same-time candidate fields disagree', {
        key,
        on_champion_die_raw_param: dieRow.raw_param,
        hero_death_victim_raw_param: heroRow.victim_raw_param,
        on_champion_die_child_u32_0x04: dieRow.event_u32_0x04,
        hero_death_die_source_network_id_candidate:
          heroRow.die_source_network_id_candidate,
      });
    }
    const delta = (dieRow.raw_param ^ heroRow.victim_raw_param) >>> 0;
    const hex = `0x${delta.toString(16).padStart(8, '0')}`;
    rawDeltaCounts.set(hex, (rawDeltaCounts.get(hex) ?? 0) + 1);
    if (delta === 0) exactRawEqualCount += 1;
    const dieRef = structuredClone(dieRow.raw_packet_ref);
    const heroRefs = heroRow.raw_packet_refs.map((ref) => structuredClone(ref));
    events.push({
      event_type: 'CHAMPION_DIE_HERO_DEATH_PACKET_PAIR_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: dieRow.replay_time_ms,
      on_champion_die_child_event_id: 0x0004,
      on_champion_die_raw_param: dieRow.raw_param,
      on_champion_die_event_u32_0x04: dieRow.event_u32_0x04,
      hero_death_victim_raw_param: heroRow.victim_raw_param,
      hero_death_die_source_network_id_candidate:
        heroRow.die_source_network_id_candidate,
      raw_param_xor_delta: delta,
      raw_param_exact_equal: delta === 0,
      raw_packet_ref: dieRef,
      on_champion_die_raw_packet_ref: dieRef,
      hero_death_raw_packet_refs: heroRefs,
      raw_packet_refs: [dieRef, ...heroRefs],
      confidence: 'CANDIDATE', semantic_status: CANDIDATE_STATUS,
    });
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: CANDIDATE_STATUS,
    replay_sha256: replay.source_sha256,
    on_champion_die_count: die.events.length,
    hero_death_count: hero.events.length,
    pair_count: events.length, event_count: events.length,
    exact_raw_param_equal_count: exactRawEqualCount,
    raw_param_xor_delta_counts: Object.fromEntries([...rawDeltaCounts.entries()].sort()),
    events,
  };
}

module.exports = {
  CHAMPION_DIE_HERO_DEATH_PAIR_821_PROFILE,
  associateChampionDieHeroDeathCandidates821,
};
