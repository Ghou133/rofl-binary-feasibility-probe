'use strict';

// Relates exact-build packet observations; the named child is not an observed
// gameplay shutdown effect and these equalities do not establish actor roles.
const { replaySourceError } = require('./replay_source_integrity');
const { ON_SHUTDOWN_EVENT_PACKET_821_PROFILE } =
  require('./rofl_16_19_821_on_shutdown_event_packet_candidate');
const { associateChampionDieHeroDeathCandidates821 } =
  require('./rofl_16_19_821_champion_die_hero_death_pair_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const MAX_EVENTS = 10_000;
const CANDIDATE_STATUS = 'CANDIDATE_821_ON_SHUTDOWN_DIE_HERO_DIE_PACKET_GROUP';

const ON_SHUTDOWN_DIE_HERO_DEATH_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-on-shutdown-die-hero-die-packet-group-candidate-v1',
  replay_version: BUILD,
  capability: 'on_shutdown_die_hero_death_pair',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze([
    'on_shutdown_event_packet', 'champion_die_event_packet', 'hero_death',
  ]),
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays; 72/72 native OnShutdown packets uniquely co-time with Die/Hero_Die pairs, with source and child-field equalities and packet order; the 72 also co-time with Multi rather than Kill packets in this observed input',
  known_limits: Object.freeze([
    'OnShutdown is an exact-image child label, not proof of a gameplay shutdown, kill, death, streak or transition.',
    'The source and victim values in this packet group retain only their upstream candidate meanings; actual actor roles and callback result are unknown.',
    'OnShutdown child +0x04 equals the Hero_Die victim raw param after clearing bit 0x100 in all 72 observed groups; this is a packet-field relation.',
    'The observed Multi/Kill route partition is evidence, not an enforced dependency of this three-capability packet group.',
    'Any missing, duplicate, wrong-order or conflicting same-time match fails the entire Replay association without partial groups.',
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

function key(ref) {
  return `${ref.chunk_index}/${ref.replay_time_ms}`;
}

function position(ref) {
  return `${ref.chunk_index}/${ref.decompressed_block_offset}`;
}

function validShutdownRef(replay, ref, row) {
  if (!ref || ref.source_path !== (replay.source_path ?? null)
      || ref.replay_sha256 !== replay.source_sha256
      || ref.packet_id !== 0x040a || ref.payload_length !== 105
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

function validShutdownRow(replay, row) {
  return row?.event_type === 'ON_SHUTDOWN_EVENT_PACKET_CANDIDATE'
    && row.game_version === BUILD
    && row.build_profile === ON_SHUTDOWN_EVENT_PACKET_821_PROFILE.id
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD'
    && row.replay_sha256 === replay.source_sha256
    && Number.isSafeInteger(row.replay_time_ms) && row.replay_time_ms >= 0
    && row.child_event_id === 0x00e8 && row.registered_event_name === 'OnShutdown'
    && row.raw_event_id_hex === '0x49af'
    && u32(row.raw_param) && row.raw_param !== 0
    && u32(row.event_u32_0x04) && row.event_u32_0x04 !== 0
    && u32(row.event_u32_0x58) && u32(row.event_u32_0x5c)
    && sha(row.event_blob_sha256)
    && validShutdownRef(replay, row.raw_packet_ref, row);
}

function associateOnShutdownDieHeroDeathCandidates821(replay, {
  onShutdownEventPacketOutcome, championDieEventPacketOutcome, heroDeathOutcome,
} = {}) {
  const profile = ON_SHUTDOWN_DIE_HERO_DEATH_PAIR_821_PROFILE;
  const base = {
    profile_id: profile.id, evidence_runtime_image_sha256: IMAGE_SHA256,
    depends_on: [...profile.depends_on], known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: status === 'INCONSISTENT' ? 'INCONSISTENT' : null,
    event_count: null, pair_count: null, events: null,
    on_shutdown_count: Array.isArray(onShutdownEventPacketOutcome?.events)
      ? onShutdownEventPacketOutcome.events.length : null,
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
    ...(!onShutdownEventPacketOutcome ? ['on_shutdown_event_packet'] : []),
    ...(!championDieEventPacketOutcome ? ['champion_die_event_packet'] : []),
    ...(!heroDeathOutcome ? ['hero_death'] : []),
  ];
  if (missing.length) {
    return fail('MISSING_INPUT', 'all three exact-build candidate decoder outcomes are required', {
      missing_inputs: missing,
    });
  }
  const shutdown = onShutdownEventPacketOutcome;
  if (shutdown.status !== 'CANDIDATE'
      || championDieEventPacketOutcome.status !== 'CANDIDATE'
      || heroDeathOutcome.status !== 'CANDIDATE') {
    return fail('MISSING_INPUT', 'one or more candidate decoder outcomes are unavailable', {
      on_shutdown_status: shutdown.status ?? null,
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
  if (shutdown.profile_id !== ON_SHUTDOWN_EVENT_PACKET_821_PROFILE.id
      || shutdown.evidence_runtime_image_sha256 !== IMAGE_SHA256
      || shutdown.runtime_image_sha256 !== IMAGE_SHA256
      || shutdown.runtime_image_status !== 'MATCHED_USED' || shutdown.runtime_image_used !== true
      || shutdown.input_packet_id !== 0x040a || shutdown.child_event_id !== 0x00e8
      || !Array.isArray(shutdown.events) || !count(shutdown.event_count)
      || shutdown.event_count !== shutdown.events.length || shutdown.events.length === 0
      || !count(shutdown.input_count) || shutdown.input_count !== shutdown.event_count) {
    return fail('INCONSISTENT', 'OnShutdown exact-build candidate outcome identity or counts differ');
  }
  const shutdownByKey = new Map();
  const seenPositions = new Set(dieHero.events.flatMap((event) =>
    event.raw_packet_refs.map(position)));
  for (let index = 0; index < shutdown.events.length; index += 1) {
    const row = shutdown.events[index];
    if (!validShutdownRow(replay, row)) {
      return fail('INCONSISTENT', 'OnShutdown candidate row has invalid identity or raw packet reference', {
        route: 'on_shutdown_event_packet', event_index: index,
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
    if (shutdownByKey.has(groupKey)) {
      return fail('INCONSISTENT', 'duplicate OnShutdown same-chunk, same-ms key', {
        duplicate_key: groupKey,
      });
    }
    shutdownByKey.set(groupKey, row);
  }
  const dieHeroByKey = new Map(dieHero.events.map((event) =>
    [key(event.on_champion_die_raw_packet_ref), event]));
  const missingKeys = [...shutdownByKey.keys()].filter((groupKey) => !dieHeroByKey.has(groupKey));
  if (missingKeys.length) {
    return fail('INCONSISTENT', 'OnShutdown has no unique same-chunk, same-ms Die/Hero_Die counterpart', {
      unmatched_on_shutdown_count: missingKeys.length,
      first_unmatched_on_shutdown_key: missingKeys[0],
    });
  }
  const sorted = [...shutdownByKey.entries()].sort(([left], [right]) => {
    const [leftChunk, leftTime] = left.split('/').map(Number);
    const [rightChunk, rightTime] = right.split('/').map(Number);
    return leftChunk - rightChunk || leftTime - rightTime;
  });
  const events = [];
  const victimRawXorCounts = new Map();
  let exactVictimRawEqualCount = 0;
  for (const [groupKey, shutdownRow] of sorted) {
    const paired = dieHeroByKey.get(groupKey);
    const shutdownRef = shutdownRow.raw_packet_ref;
    const dieRef = paired.on_champion_die_raw_packet_ref;
    const heroRefs = paired.hero_death_raw_packet_refs;
    const dieOffset = dieRef.decompressed_block_offset;
    const shutdownOffset = shutdownRef.decompressed_block_offset;
    const heroPrimaryOffset = heroRefs[0].decompressed_block_offset;
    const heroPairedOffset = heroRefs[1].decompressed_block_offset;
    if (!(dieOffset < shutdownOffset && shutdownOffset < heroPrimaryOffset
          && heroPrimaryOffset < heroPairedOffset)) {
      return fail('INCONSISTENT', 'candidate packet order differs from observed Die/Shutdown/Hero_Die route', {
        key: groupKey, on_champion_die_offset: dieOffset,
        on_shutdown_offset: shutdownOffset,
        hero_primary_offset: heroPrimaryOffset, hero_paired_offset: heroPairedOffset,
      });
    }
    const shutdownKey = shutdownRow.event_u32_0x04;
    const heroVictimRaw = paired.hero_death_victim_raw_param;
    if (shutdownRow.raw_param !== paired.on_champion_die_event_u32_0x04
        || shutdownRow.raw_param !== paired.hero_death_die_source_network_id_candidate
        || (shutdownKey & ~0x100) !== (heroVictimRaw & ~0x100)
        || (shutdownKey & 0xff) !== (heroVictimRaw & 0xff)
        || (shutdownKey & 0xff) !== (paired.on_champion_die_raw_param & 0xff)) {
      return fail('INCONSISTENT', 'same-time candidate packet fields disagree', {
        key: groupKey,
        on_shutdown_raw_param: shutdownRow.raw_param,
        on_shutdown_child_u32_0x04: shutdownKey,
        on_champion_die_raw_param: paired.on_champion_die_raw_param,
        on_champion_die_child_u32_0x04: paired.on_champion_die_event_u32_0x04,
        hero_death_victim_raw_param: heroVictimRaw,
        hero_death_die_source_network_id_candidate:
          paired.hero_death_die_source_network_id_candidate,
      });
    }
    const xorDelta = (shutdownKey ^ heroVictimRaw) >>> 0;
    const xorHex = `0x${xorDelta.toString(16).padStart(8, '0')}`;
    victimRawXorCounts.set(xorHex, (victimRawXorCounts.get(xorHex) ?? 0) + 1);
    if (xorDelta === 0) exactVictimRawEqualCount += 1;
    const dieRefCopy = structuredClone(dieRef);
    const shutdownRefCopy = structuredClone(shutdownRef);
    const heroRefsCopy = heroRefs.map((ref) => structuredClone(ref));
    const allRefs = [dieRefCopy, shutdownRefCopy, ...heroRefsCopy]
      .sort((left, right) => left.decompressed_block_offset - right.decompressed_block_offset);
    events.push({
      event_type: 'ON_SHUTDOWN_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256, replay_time_ms: shutdownRow.replay_time_ms,
      on_shutdown_child_event_id: 0x00e8,
      on_shutdown_raw_param: shutdownRow.raw_param,
      on_shutdown_event_u32_0x04: shutdownKey,
      on_shutdown_event_u32_0x58: shutdownRow.event_u32_0x58,
      on_shutdown_event_u32_0x5c: shutdownRow.event_u32_0x5c,
      on_champion_die_child_event_id: 0x0004,
      on_champion_die_raw_param: paired.on_champion_die_raw_param,
      on_champion_die_event_u32_0x04: paired.on_champion_die_event_u32_0x04,
      hero_death_victim_raw_param: heroVictimRaw,
      hero_death_die_source_network_id_candidate:
        paired.hero_death_die_source_network_id_candidate,
      shutdown_0x04_xor_hero_raw_delta: xorDelta,
      shutdown_0x04_exact_hero_raw_equal: xorDelta === 0,
      raw_packet_ref: shutdownRefCopy,
      on_shutdown_raw_packet_ref: shutdownRefCopy,
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
    on_shutdown_count: shutdown.events.length,
    on_champion_die_count: championDieEventPacketOutcome.events.length,
    hero_death_count: heroDeathOutcome.events.length,
    unmatched_on_shutdown_count: 0,
    unpaired_on_champion_die_count: unpairedDieHeroCount,
    unpaired_hero_death_count: unpairedDieHeroCount,
    pair_count: events.length, event_count: events.length,
    exact_shutdown_0x04_hero_raw_equal_count: exactVictimRawEqualCount,
    shutdown_0x04_xor_hero_raw_delta_counts:
      Object.fromEntries([...victimRawXorCounts.entries()].sort()),
    events,
  };
}

module.exports = {
  ON_SHUTDOWN_DIE_HERO_DEATH_PAIR_821_PROFILE,
  associateOnShutdownDieHeroDeathCandidates821,
};
