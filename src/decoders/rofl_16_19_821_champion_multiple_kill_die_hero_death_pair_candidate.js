'use strict';

// Associates already decoded exact-build packet routes. The callback name and
// numeric equalities do not establish a gameplay effect or participant role.
const { replaySourceError } = require('./replay_source_integrity');
const { CHAMPION_MULTIPLE_KILL_EVENT_PACKET_821_PROFILE } =
  require('./rofl_16_19_821_champion_multiple_kill_event_packet_candidate');
const { associateChampionDieHeroDeathCandidates821 } =
  require('./rofl_16_19_821_champion_die_hero_death_pair_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const MAX_EVENTS = 10_000;
const CANDIDATE_STATUS = 'CANDIDATE_821_ON_CHAMPION_MULTIPLE_KILL_DIE_HERO_DIE_PACKET_GROUP';

const CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-on-champion-multiple-kill-die-hero-die-packet-group-candidate-v1',
  replay_version: BUILD,
  capability: 'champion_multiple_kill_die_hero_death_pair',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze([
    'champion_multiple_kill_event_packet', 'champion_die_event_packet', 'hero_death',
  ]),
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays; 653/653 OnChampionMultipleKill rows uniquely share Replay SHA/chunk/ms with verified OnChampionDie/Hero_Die pairs, with two anonymous field relations and packet order; 2 Die/Hero_Die pairs lack a MultipleKill row',
  known_limits: Object.freeze([
    'A packet group does not prove an effective multikill, killing streak, killer, victim, participant role, or game-state transition.',
    'The Multi callback +0x04 and +0x08 fields and +0x10 u32 list remain anonymous.',
    'Multi callback +0x04 equals the Hero_Die victim raw candidate after clearing bit 0x100 in all 653 observed groups; this is a packet-field relation only.',
    'OnChampionKill packet presence is not required: 72 of 653 Multi groups had no same-time Kill packet in the observed 11 Replays.',
    'Die/Hero_Die pairs without a MultipleKill row are counted but not emitted as MultipleKill packet groups.',
    'Any malformed, missing, duplicate, wrong-order, or conflicting MultipleKill match fails the entire Replay association without partial groups.',
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

function validMultiRef(replay, ref, row) {
  if (!ref || ref.source_path !== (replay.source_path ?? null)
      || ref.replay_sha256 !== replay.source_sha256
      || ref.packet_id !== 0x040a || ref.payload_length !== 88
      || ref.raw_param !== row.raw_param || ref.replay_time_ms !== row.replay_time_ms
      || ref.chunk_stream !== 'game_chunk'
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id)
      || !Number.isSafeInteger(ref.chunk_file_offset)
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || !sha(ref.raw_payload_sha256)) return false;
  const chunk = replay.chunks?.[ref.chunk_index];
  return !!chunk && chunk.index === ref.chunk_index
    && chunk.chunk_id === ref.chunk_id && chunk.stream === ref.chunk_stream
    && chunk.offset === ref.chunk_file_offset
    && Number.isSafeInteger(chunk.uncompressed_length)
    && ref.decompressed_block_offset >= 0
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.decompressed_payload_offset + ref.payload_length <= chunk.uncompressed_length;
}

function validMultiRow(replay, row) {
  return row?.event_type === 'CHAMPION_MULTIPLE_KILL_EVENT_PACKET_CANDIDATE'
    && row.game_version === BUILD
    && row.build_profile === CHAMPION_MULTIPLE_KILL_EVENT_PACKET_821_PROFILE.id
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === 'CANDIDATE_EXACT_RUNTIME_ON_CHAMPION_MULTIPLE_KILL_PACKET'
    && row.replay_sha256 === replay.source_sha256
    && Number.isSafeInteger(row.replay_time_ms) && row.replay_time_ms >= 0
    && row.event_id === 0x0009 && row.event_name === 'OnChampionMultipleKill'
    && row.raw_event_id_hex === '0x4989'
    && u32(row.raw_param) && row.raw_param !== 0
    && u32(row.event_u32_0x04) && row.event_u32_0x04 !== 0
    && u32(row.event_u32_0x08) && row.event_u32_0x08 >= 1 && row.event_u32_0x08 <= 4
    && u32(row.event_u32_0x0c) && row.event_u32_0x0c <= 4
    && Array.isArray(row.event_u32_list_0x10)
    && row.event_u32_list_0x10.length === row.event_u32_0x0c
    && row.event_u32_list_0x10.every((value) => u32(value) && value !== 0)
    && sha(row.event_blob_sha256)
    && validMultiRef(replay, row.raw_packet_ref, row);
}

function key(ref) {
  return `${ref.chunk_index}/${ref.replay_time_ms}`;
}

function position(ref) {
  return `${ref.chunk_index}/${ref.decompressed_block_offset}`;
}

function associateChampionMultipleKillDieHeroDeathCandidates821(replay, {
  championMultipleKillEventPacketOutcome, championDieEventPacketOutcome, heroDeathOutcome,
} = {}) {
  const profile = CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE;
  const base = {
    profile_id: profile.id, evidence_runtime_image_sha256: IMAGE_SHA256,
    depends_on: [...profile.depends_on], known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: status === 'INCONSISTENT' ? 'INCONSISTENT' : null,
    event_count: null, pair_count: null, events: null,
    on_champion_multiple_kill_count: Array.isArray(championMultipleKillEventPacketOutcome?.events)
      ? championMultipleKillEventPacketOutcome.events.length : null,
    on_champion_die_count: Array.isArray(championDieEventPacketOutcome?.events)
      ? championDieEventPacketOutcome.events.length : null,
    hero_death_count: Array.isArray(heroDeathOutcome?.events)
      ? heroDeathOutcome.events.length : null,
    error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `packet-group association supports only ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) {
    return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  }
  if (!sha(replay.source_sha256)) {
    return fail('INCONSISTENT', 'Replay source SHA-256 is missing or malformed');
  }
  const missing = [
    ...(!championMultipleKillEventPacketOutcome ? ['champion_multiple_kill_event_packet'] : []),
    ...(!championDieEventPacketOutcome ? ['champion_die_event_packet'] : []),
    ...(!heroDeathOutcome ? ['hero_death'] : []),
  ];
  if (missing.length) {
    return fail('MISSING_INPUT', 'all three exact-build candidate decoder outcomes are required', {
      missing_inputs: missing,
    });
  }
  const multi = championMultipleKillEventPacketOutcome;
  if (multi.status !== 'CANDIDATE'
      || championDieEventPacketOutcome.status !== 'CANDIDATE'
      || heroDeathOutcome.status !== 'CANDIDATE') {
    return fail('MISSING_INPUT', 'one or more candidate decoder outcomes are unavailable', {
      champion_multiple_kill_status: multi.status ?? null,
      champion_die_status: championDieEventPacketOutcome.status ?? null,
      hero_death_status: heroDeathOutcome.status ?? null,
    });
  }
  const dieHero = associateChampionDieHeroDeathCandidates821(replay, {
    championDieEventPacketOutcome, heroDeathOutcome,
  });
  if (dieHero.status !== 'CANDIDATE') {
    return fail(dieHero.status, `OnChampionDie/Hero_Die prerequisite: ${dieHero.error}`, {
      prerequisite_status: dieHero.status, prerequisite_diagnostics: dieHero.diagnostics,
    });
  }
  if (multi.profile_id !== CHAMPION_MULTIPLE_KILL_EVENT_PACKET_821_PROFILE.id
      || multi.evidence_runtime_image_sha256 !== IMAGE_SHA256
      || multi.runtime_image_sha256 !== IMAGE_SHA256
      || multi.runtime_image_status !== 'MATCHED_USED' || multi.runtime_image_used !== true
      || multi.input_packet_id !== 0x040a || multi.child_event_id !== 0x0009
      || !Array.isArray(multi.events) || !count(multi.event_count)
      || multi.event_count !== multi.events.length || multi.events.length === 0
      || !count(multi.input_count) || multi.input_count !== multi.event_count) {
    return fail('INCONSISTENT', 'OnChampionMultipleKill exact-build candidate outcome identity or counts differ');
  }
  const multiByKey = new Map();
  const seenPositions = new Set(dieHero.events.flatMap((event) =>
    event.raw_packet_refs.map(position)));
  for (let index = 0; index < multi.events.length; index += 1) {
    const row = multi.events[index];
    if (!validMultiRow(replay, row)) {
      return fail('INCONSISTENT', 'OnChampionMultipleKill candidate row has invalid identity or raw packet reference', {
        route: 'champion_multiple_kill_event_packet', event_index: index,
      });
    }
    const ref = row.raw_packet_ref;
    const packetPosition = position(ref);
    if (seenPositions.has(packetPosition)) {
      return fail('INCONSISTENT', 'candidate raw packet position is duplicated', {
        duplicate_packet_position: packetPosition,
      });
    }
    seenPositions.add(packetPosition);
    const groupKey = key(ref);
    if (multiByKey.has(groupKey)) {
      return fail('INCONSISTENT', 'duplicate OnChampionMultipleKill same-chunk, same-ms key', {
        duplicate_key: groupKey,
      });
    }
    multiByKey.set(groupKey, row);
  }
  const dieHeroByKey = new Map(dieHero.events.map((event) =>
    [key(event.on_champion_die_raw_packet_ref), event]));
  const missingKeys = [...multiByKey.keys()].filter((groupKey) => !dieHeroByKey.has(groupKey));
  if (missingKeys.length) {
    return fail('INCONSISTENT', 'OnChampionMultipleKill has no unique same-chunk, same-ms Die/Hero_Die counterpart', {
      unmatched_on_champion_multiple_kill_count: missingKeys.length,
      first_unmatched_on_champion_multiple_kill_key: missingKeys[0],
    });
  }
  const sorted = [...multiByKey.entries()].sort(([left], [right]) => {
    const [leftChunk, leftTime] = left.split('/').map(Number);
    const [rightChunk, rightTime] = right.split('/').map(Number);
    return leftChunk - rightChunk || leftTime - rightTime;
  });
  const events = [];
  const victimRawXorCounts = new Map();
  let exactVictimRawEqualCount = 0;
  for (const [groupKey, multiRow] of sorted) {
    const paired = dieHeroByKey.get(groupKey);
    const multiRef = multiRow.raw_packet_ref;
    const dieRef = paired.on_champion_die_raw_packet_ref;
    const heroRefs = paired.hero_death_raw_packet_refs;
    const dieOffset = dieRef.decompressed_block_offset;
    const multiOffset = multiRef.decompressed_block_offset;
    const heroPrimaryOffset = heroRefs[0].decompressed_block_offset;
    const heroPairedOffset = heroRefs[1].decompressed_block_offset;
    if (!(dieOffset < multiOffset && multiOffset < heroPrimaryOffset
          && heroPrimaryOffset < heroPairedOffset)) {
      return fail('INCONSISTENT', 'candidate packet order differs from observed Die/MultipleKill/Hero_Die route', {
        key: groupKey, on_champion_die_offset: dieOffset,
        on_champion_multiple_kill_offset: multiOffset,
        hero_primary_offset: heroPrimaryOffset, hero_paired_offset: heroPairedOffset,
      });
    }
    const multiKey = multiRow.event_u32_0x04;
    const heroVictimRaw = paired.hero_death_victim_raw_param;
    if (multiRow.raw_param !== paired.on_champion_die_event_u32_0x04
        || multiRow.raw_param !== paired.hero_death_die_source_network_id_candidate
        || (multiKey & ~0x100) !== (heroVictimRaw & ~0x100)
        || (multiKey & 0xff) !== (heroVictimRaw & 0xff)
        || (multiKey & 0xff) !== (paired.on_champion_die_raw_param & 0xff)) {
      return fail('INCONSISTENT', 'same-time candidate packet fields disagree', {
        key: groupKey,
        on_champion_multiple_kill_raw_param: multiRow.raw_param,
        on_champion_multiple_kill_child_u32_0x04: multiKey,
        on_champion_die_raw_param: paired.on_champion_die_raw_param,
        on_champion_die_child_u32_0x04: paired.on_champion_die_event_u32_0x04,
        hero_death_victim_raw_param: heroVictimRaw,
        hero_death_die_source_network_id_candidate:
          paired.hero_death_die_source_network_id_candidate,
      });
    }
    const xorDelta = (multiKey ^ heroVictimRaw) >>> 0;
    const xorHex = `0x${xorDelta.toString(16).padStart(8, '0')}`;
    victimRawXorCounts.set(xorHex, (victimRawXorCounts.get(xorHex) ?? 0) + 1);
    if (xorDelta === 0) exactVictimRawEqualCount += 1;
    const dieRefCopy = structuredClone(dieRef);
    const multiRefCopy = structuredClone(multiRef);
    const heroRefsCopy = heroRefs.map((ref) => structuredClone(ref));
    const allRefs = [dieRefCopy, multiRefCopy, ...heroRefsCopy]
      .sort((left, right) => left.decompressed_block_offset - right.decompressed_block_offset);
    events.push({
      event_type: 'CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256, replay_time_ms: multiRow.replay_time_ms,
      on_champion_multiple_kill_child_event_id: 0x0009,
      on_champion_multiple_kill_raw_param: multiRow.raw_param,
      on_champion_multiple_kill_event_u32_0x04: multiKey,
      on_champion_multiple_kill_event_u32_0x08: multiRow.event_u32_0x08,
      on_champion_multiple_kill_event_u32_0x0c: multiRow.event_u32_0x0c,
      on_champion_multiple_kill_event_u32_list_0x10:
        [...multiRow.event_u32_list_0x10],
      on_champion_die_child_event_id: 0x0004,
      on_champion_die_raw_param: paired.on_champion_die_raw_param,
      on_champion_die_event_u32_0x04: paired.on_champion_die_event_u32_0x04,
      hero_death_victim_raw_param: heroVictimRaw,
      hero_death_die_source_network_id_candidate:
        paired.hero_death_die_source_network_id_candidate,
      multi_0x04_xor_hero_raw_delta: xorDelta,
      multi_0x04_exact_hero_raw_equal: xorDelta === 0,
      raw_packet_ref: multiRefCopy,
      on_champion_multiple_kill_raw_packet_ref: multiRefCopy,
      on_champion_die_raw_packet_ref: dieRefCopy,
      hero_death_raw_packet_refs: heroRefsCopy,
      raw_packet_refs: allRefs,
      confidence: 'CANDIDATE', semantic_status: CANDIDATE_STATUS,
    });
  }
  const unpairedDieHeroCount = dieHero.pair_count - events.length;
  return {
    ...base, status: 'CANDIDATE', evidence_status: CANDIDATE_STATUS,
    replay_sha256: replay.source_sha256,
    on_champion_multiple_kill_count: multi.events.length,
    on_champion_die_count: championDieEventPacketOutcome.events.length,
    hero_death_count: heroDeathOutcome.events.length,
    unmatched_on_champion_multiple_kill_count: 0,
    unpaired_on_champion_die_count: unpairedDieHeroCount,
    unpaired_hero_death_count: unpairedDieHeroCount,
    pair_count: events.length, event_count: events.length,
    exact_multi_0x04_hero_raw_equal_count: exactVictimRawEqualCount,
    multi_0x04_xor_hero_raw_delta_counts:
      Object.fromEntries([...victimRawXorCounts.entries()].sort()),
    events,
  };
}

module.exports = {
  CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE,
  associateChampionMultipleKillDieHeroDeathCandidates821,
};
