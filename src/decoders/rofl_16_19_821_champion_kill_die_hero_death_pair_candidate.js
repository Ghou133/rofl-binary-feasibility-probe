'use strict';

// Associates three already decoded exact-build packet routes. The emitted
// group describes packet co-occurrence and anonymous field relations only.
const { replaySourceError } = require('./replay_source_integrity');
const { CHAMPION_KILL_EVENT_PACKET_CANDIDATE_PROFILE_821 } =
  require('./rofl_16_19_821_champion_kill_event_packet_candidate');
const { associateChampionDieHeroDeathCandidates821 } =
  require('./rofl_16_19_821_champion_die_hero_death_pair_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const MAX_EVENTS = 10_000;
const CANDIDATE_STATUS = 'CANDIDATE_821_ON_CHAMPION_KILL_DIE_HERO_DIE_PACKET_GROUP';

const CHAMPION_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-on-champion-kill-die-hero-die-packet-group-candidate-v1',
  replay_version: BUILD,
  capability: 'champion_kill_die_hero_death_pair',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze([
    'champion_kill_event_packet', 'champion_die_event_packet', 'hero_death',
  ]),
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays; 581/581 OnChampionKill rows uniquely share Replay SHA/chunk/ms with verified OnChampionDie/Hero_Die pairs, with both anonymous field relations and packet order; 74 Die/Hero pairs lack a Kill row',
  known_limits: Object.freeze([
    'A packet group is not proof of an effective kill, death, killer, victim, or participant role.',
    'The outer raw params, child +0x04 fields, and Hero_Die source value retain their upstream candidate meanings only.',
    'OnChampionKill child +0x04 equals the Hero_Die victim raw param after clearing bit 0x100 in the 581 observed groups; this is a packet-field relation, not a role assignment.',
    'Die/Hero pairs without a Kill row are counted but not emitted as Kill packet groups.',
    'Any malformed, missing, duplicate, wrong-order, or conflicting Kill match fails the entire Replay association without partial groups.',
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

function validKillRef(replay, ref, row) {
  if (!ref || ref.source_path !== (replay.source_path ?? null)
      || ref.replay_sha256 !== replay.source_sha256
      || ref.packet_id !== 0x040a || ref.payload_length !== 104
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

function validKillRow(replay, row) {
  return row?.event_type === 'CHAMPION_KILL_EVENT_PACKET_CANDIDATE'
    && row.game_version === BUILD
    && row.build_profile === CHAMPION_KILL_EVENT_PACKET_CANDIDATE_PROFILE_821.id
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD'
    && row.replay_sha256 === replay.source_sha256
    && Number.isSafeInteger(row.replay_time_ms) && row.replay_time_ms >= 0
    && row.child_event_id === 0x0007 && row.registered_event_name === 'OnChampionKill'
    && row.raw_event_id_hex === '0x49e8'
    && u32(row.raw_param) && row.raw_param !== 0
    && u32(row.event_u32_0x04) && row.event_u32_0x04 !== 0
    && u32(row.event_u32_0x58) && u32(row.event_u32_0x5c)
    && sha(row.event_blob_sha256)
    && validKillRef(replay, row.raw_packet_ref, row);
}

function key(ref) {
  return `${ref.chunk_index}/${ref.replay_time_ms}`;
}

function position(ref) {
  return `${ref.chunk_index}/${ref.decompressed_block_offset}`;
}

function associateChampionKillDieHeroDeathCandidates821(replay, {
  championKillEventPacketOutcome, championDieEventPacketOutcome, heroDeathOutcome,
} = {}) {
  const profile = CHAMPION_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE;
  const base = {
    profile_id: profile.id, evidence_runtime_image_sha256: IMAGE_SHA256,
    depends_on: [...profile.depends_on], known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: status === 'INCONSISTENT' ? 'INCONSISTENT' : null,
    event_count: null, pair_count: null, events: null,
    on_champion_kill_count: Array.isArray(championKillEventPacketOutcome?.events)
      ? championKillEventPacketOutcome.events.length : null,
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
    ...(!championKillEventPacketOutcome ? ['champion_kill_event_packet'] : []),
    ...(!championDieEventPacketOutcome ? ['champion_die_event_packet'] : []),
    ...(!heroDeathOutcome ? ['hero_death'] : []),
  ];
  if (missing.length) {
    return fail('MISSING_INPUT', 'all three exact-build candidate decoder outcomes are required', {
      missing_inputs: missing,
    });
  }
  const kill = championKillEventPacketOutcome;
  if (kill.status !== 'CANDIDATE'
      || championDieEventPacketOutcome.status !== 'CANDIDATE'
      || heroDeathOutcome.status !== 'CANDIDATE') {
    return fail('MISSING_INPUT', 'one or more candidate decoder outcomes are unavailable', {
      champion_kill_status: kill.status ?? null,
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
  if (kill.profile_id !== CHAMPION_KILL_EVENT_PACKET_CANDIDATE_PROFILE_821.id
      || kill.evidence_runtime_image_sha256 !== IMAGE_SHA256
      || kill.runtime_image_sha256 !== IMAGE_SHA256
      || kill.runtime_image_status !== 'MATCHED_USED' || kill.runtime_image_used !== true
      || kill.input_packet_id !== 0x040a || kill.child_event_id !== 0x0007
      || !Array.isArray(kill.events) || !count(kill.event_count)
      || kill.event_count !== kill.events.length || kill.events.length === 0
      || !count(kill.target_packet_count) || kill.target_packet_count !== kill.event_count
      || !count(kill.excluded_child_count) || !count(kill.input_count)
      || kill.input_count !== kill.target_packet_count + kill.excluded_child_count) {
    return fail('INCONSISTENT', 'OnChampionKill exact-build candidate outcome identity or counts differ');
  }
  const killByKey = new Map();
  const seenPositions = new Set(dieHero.events.flatMap((event) =>
    event.raw_packet_refs.map(position)));
  for (let index = 0; index < kill.events.length; index += 1) {
    const row = kill.events[index];
    if (!validKillRow(replay, row)) {
      return fail('INCONSISTENT', 'OnChampionKill candidate row has invalid identity or raw packet reference', {
        route: 'champion_kill_event_packet', event_index: index,
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
    if (killByKey.has(groupKey)) {
      return fail('INCONSISTENT', 'duplicate OnChampionKill same-chunk, same-ms key', {
        duplicate_key: groupKey,
      });
    }
    killByKey.set(groupKey, row);
  }
  const dieHeroByKey = new Map(dieHero.events.map((event) =>
    [key(event.on_champion_die_raw_packet_ref), event]));
  const missingKeys = [...killByKey.keys()].filter((groupKey) => !dieHeroByKey.has(groupKey));
  if (missingKeys.length) {
    return fail('INCONSISTENT', 'OnChampionKill has no unique same-chunk, same-ms Die/Hero counterpart', {
      unmatched_on_champion_kill_count: missingKeys.length,
      first_unmatched_on_champion_kill_key: missingKeys[0],
    });
  }
  const sorted = [...killByKey.entries()].sort(([left], [right]) => {
    const [leftChunk, leftTime] = left.split('/').map(Number);
    const [rightChunk, rightTime] = right.split('/').map(Number);
    return leftChunk - rightChunk || leftTime - rightTime;
  });
  const events = [];
  const victimRawXorCounts = new Map();
  let exactVictimRawEqualCount = 0;
  for (const [groupKey, killRow] of sorted) {
    const paired = dieHeroByKey.get(groupKey);
    const killRef = killRow.raw_packet_ref;
    const dieRef = paired.on_champion_die_raw_packet_ref;
    const heroRefs = paired.hero_death_raw_packet_refs;
    const dieOffset = dieRef.decompressed_block_offset;
    const killOffset = killRef.decompressed_block_offset;
    const heroPrimaryOffset = heroRefs[0].decompressed_block_offset;
    const heroPairedOffset = heroRefs[1].decompressed_block_offset;
    if (!(dieOffset < killOffset && killOffset < heroPrimaryOffset
          && heroPrimaryOffset < heroPairedOffset)) {
      return fail('INCONSISTENT', 'candidate packet order differs from observed Die/Kill/Hero_Die route', {
        key: groupKey, on_champion_die_offset: dieOffset,
        on_champion_kill_offset: killOffset,
        hero_primary_offset: heroPrimaryOffset, hero_paired_offset: heroPairedOffset,
      });
    }
    const killKey = killRow.event_u32_0x04;
    const heroVictimRaw = paired.hero_death_victim_raw_param;
    if (killRow.raw_param !== paired.on_champion_die_event_u32_0x04
        || killRow.raw_param !== paired.hero_death_die_source_network_id_candidate
        || (killKey & ~0x100) !== (heroVictimRaw & ~0x100)
        || (killKey & 0xff) !== (heroVictimRaw & 0xff)
        || (killKey & 0xff) !== (paired.on_champion_die_raw_param & 0xff)) {
      return fail('INCONSISTENT', 'same-time candidate packet fields disagree', {
        key: groupKey,
        on_champion_kill_raw_param: killRow.raw_param,
        on_champion_kill_child_u32_0x04: killKey,
        on_champion_die_raw_param: paired.on_champion_die_raw_param,
        on_champion_die_child_u32_0x04: paired.on_champion_die_event_u32_0x04,
        hero_death_victim_raw_param: heroVictimRaw,
        hero_death_die_source_network_id_candidate:
          paired.hero_death_die_source_network_id_candidate,
      });
    }
    const xorDelta = (killKey ^ heroVictimRaw) >>> 0;
    const xorHex = `0x${xorDelta.toString(16).padStart(8, '0')}`;
    victimRawXorCounts.set(xorHex, (victimRawXorCounts.get(xorHex) ?? 0) + 1);
    if (xorDelta === 0) exactVictimRawEqualCount += 1;
    const dieRefCopy = structuredClone(dieRef);
    const killRefCopy = structuredClone(killRef);
    const heroRefsCopy = heroRefs.map((ref) => structuredClone(ref));
    const allRefs = [dieRefCopy, killRefCopy, ...heroRefsCopy]
      .sort((left, right) => left.decompressed_block_offset - right.decompressed_block_offset);
    events.push({
      event_type: 'CHAMPION_KILL_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256, replay_time_ms: killRow.replay_time_ms,
      on_champion_kill_child_event_id: 0x0007,
      on_champion_kill_raw_param: killRow.raw_param,
      on_champion_kill_event_u32_0x04: killKey,
      on_champion_die_child_event_id: 0x0004,
      on_champion_die_raw_param: paired.on_champion_die_raw_param,
      on_champion_die_event_u32_0x04: paired.on_champion_die_event_u32_0x04,
      hero_death_victim_raw_param: heroVictimRaw,
      hero_death_die_source_network_id_candidate:
        paired.hero_death_die_source_network_id_candidate,
      kill_0x04_xor_hero_raw_delta: xorDelta,
      kill_0x04_exact_hero_raw_equal: xorDelta === 0,
      raw_packet_ref: killRefCopy,
      on_champion_kill_raw_packet_ref: killRefCopy,
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
    on_champion_kill_count: kill.events.length,
    on_champion_die_count: championDieEventPacketOutcome.events.length,
    hero_death_count: heroDeathOutcome.events.length,
    unmatched_on_champion_kill_count: 0,
    unpaired_on_champion_die_count: unpairedDieHeroCount,
    unpaired_hero_death_count: unpairedDieHeroCount,
    pair_count: events.length, event_count: events.length,
    exact_kill_0x04_hero_raw_equal_count: exactVictimRawEqualCount,
    kill_0x04_xor_hero_raw_delta_counts:
      Object.fromEntries([...victimRawXorCounts.entries()].sort()),
    events,
  };
}

module.exports = {
  CHAMPION_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE,
  associateChampionKillDieHeroDeathCandidates821,
};
