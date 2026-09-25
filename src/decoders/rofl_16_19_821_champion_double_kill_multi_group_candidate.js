'use strict';

// Joins exact-build packet candidates. The 0x000b name and anonymous Multi
// +0x08 value do not establish a gameplay double kill or participant roles.
const { replaySourceError } = require('./replay_source_integrity');
const { CHAMPION_DOUBLE_KILL_EVENT_PACKET_821_PROFILE } =
  require('./rofl_16_19_821_champion_double_kill_event_packet_candidate');
const { CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('./rofl_16_19_821_champion_multiple_kill_die_hero_death_pair_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const MAX_EVENTS = 10_000;
const CANDIDATE_STATUS = 'CANDIDATE_821_DOUBLE_KILL_NAMED_MULTI_DIE_HERO_PACKET_GROUP';
const MULTI_GROUP_STATUS = 'CANDIDATE_821_ON_CHAMPION_MULTIPLE_KILL_DIE_HERO_DIE_PACKET_GROUP';

const CHAMPION_DOUBLE_KILL_MULTI_GROUP_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-on-champion-double-kill-multi-die-hero-packet-group-candidate-v1',
  replay_version: BUILD,
  capability: 'champion_double_kill_multi_group',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze([
    'champion_double_kill_event_packet', 'champion_multiple_kill_die_hero_death_pair',
  ]),
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays; 63/63 native child 0x000b packets uniquely join Multi/Die/Hero packet groups at exact Replay SHA, chunk and millisecond; the joined Multi child anonymous +0x08 is 2 in all 63, and no other observed Multi group has that value',
  known_limits: Object.freeze([
    'OnChampionDoubleKill is an exact-image child label, not proof of an effective double kill or gameplay state transition.',
    'The Multi child +0x08 value 2 is an anonymous structural equality in these packet groups, not a confirmed kill count.',
    'No 0x000b native child-blob u32 is assigned a role; the registered callback reads through an unresolved context-object virtual accessor.',
    'The observed groups include 61 Kill packets and 2 OnShutdown packets, but neither is an input dependency of this association.',
    'Missing, duplicate, ambiguous, wrong-order, or conflicting candidate packets fail the entire Replay association without partial groups.',
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

function sameRef(left, right) {
  return position(left) === position(right)
    && left.raw_payload_sha256 === right.raw_payload_sha256
    && left.packet_id === right.packet_id
    && left.payload_length === right.payload_length
    && left.raw_param === right.raw_param;
}

function validRef(replay, ref, timeMs, chunkIndex) {
  if (!ref || ref.source_path !== (replay.source_path ?? null)
      || ref.replay_sha256 !== replay.source_sha256
      || ref.chunk_stream !== 'game_chunk'
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || (chunkIndex !== undefined && ref.chunk_index !== chunkIndex)
      || !Number.isSafeInteger(ref.chunk_id)
      || !Number.isSafeInteger(ref.chunk_file_offset)
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || !Number.isSafeInteger(ref.packet_id) || ref.packet_id < 0 || ref.packet_id > 0xffff
      || !Number.isSafeInteger(ref.payload_length) || ref.payload_length < 1
      || !u32(ref.raw_param) || ref.replay_time_ms !== timeMs
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

function validDoubleRow(replay, row) {
  const ref = row?.raw_packet_ref;
  return row?.event_type === 'CHAMPION_DOUBLE_KILL_EVENT_PACKET_CANDIDATE'
    && row.game_version === BUILD
    && row.build_profile === CHAMPION_DOUBLE_KILL_EVENT_PACKET_821_PROFILE.id
    && row.replay_sha256 === replay.source_sha256
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD'
    && Number.isSafeInteger(row.replay_time_ms) && row.replay_time_ms >= 0
    && row.child_event_id === 0x000b
    && row.registered_event_name === 'OnChampionDoubleKill'
    && row.raw_event_id_hex === '0x4968'
    && u32(row.raw_param) && row.raw_param !== 0
    && sha(row.event_blob_sha256)
    && validRef(replay, ref, row.replay_time_ms)
    && ref.packet_id === 0x040a && ref.payload_length === 104
    && ref.raw_param === row.raw_param;
}

function validMultiGroupRow(replay, row) {
  const multi = row?.on_champion_multiple_kill_raw_packet_ref;
  const die = row?.on_champion_die_raw_packet_ref;
  const hero = row?.hero_death_raw_packet_refs;
  const all = row?.raw_packet_refs;
  if (row?.event_type !== 'CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE'
      || row.game_version !== BUILD
      || row.build_profile !== CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE.id
      || row.replay_sha256 !== replay.source_sha256
      || row.confidence !== 'CANDIDATE' || row.semantic_status !== MULTI_GROUP_STATUS
      || !Number.isSafeInteger(row.replay_time_ms) || row.replay_time_ms < 0
      || row.on_champion_multiple_kill_child_event_id !== 0x0009
      || !u32(row.on_champion_multiple_kill_raw_param)
      || row.on_champion_multiple_kill_raw_param === 0
      || !u32(row.on_champion_multiple_kill_event_u32_0x08)
      || row.on_champion_multiple_kill_event_u32_0x08 < 1
      || row.on_champion_multiple_kill_event_u32_0x08 > 4
      || !u32(row.on_champion_die_event_u32_0x04)
      || !u32(row.hero_death_die_source_network_id_candidate)
      || !Array.isArray(hero) || hero.length < 2
      || !Array.isArray(all) || all.length < 4
      || !multi || !die) return false;
  const time = row.replay_time_ms;
  const chunkIndex = multi.chunk_index;
  if (!validRef(replay, multi, time, chunkIndex)
      || !validRef(replay, die, time, chunkIndex)
      || !hero.every((ref) => validRef(replay, ref, time, chunkIndex))
      || !all.every((ref) => validRef(replay, ref, time, chunkIndex))
      || !validRef(replay, row.raw_packet_ref, time, chunkIndex)
      || multi.packet_id !== 0x040a || multi.payload_length !== 88
      || die.packet_id !== 0x040a || die.payload_length !== 116
      || hero[0].packet_id !== 0x0259 || hero[0].payload_length !== 5
      || hero[1].packet_id !== 0x0438
      || !sameRef(row.raw_packet_ref, multi)
      || multi.raw_param !== row.on_champion_multiple_kill_raw_param
      || row.on_champion_die_event_u32_0x04 !== multi.raw_param
      || row.hero_death_die_source_network_id_candidate !== multi.raw_param) return false;
  const named = [die, multi, ...hero];
  const positions = new Set(all.map(position));
  if (positions.size !== all.length
      || !named.every((ref) => all.some((other) => sameRef(ref, other)))) return false;
  return die.decompressed_block_offset < multi.decompressed_block_offset
    && multi.decompressed_block_offset < hero[0].decompressed_block_offset
    && hero[0].decompressed_block_offset < hero[1].decompressed_block_offset;
}

function associateChampionDoubleKillMultiGroupCandidates821(replay, {
  championDoubleKillEventPacketOutcome, championMultipleKillDieHeroDeathPairOutcome,
} = {}) {
  const profile = CHAMPION_DOUBLE_KILL_MULTI_GROUP_821_PROFILE;
  const base = {
    profile_id: profile.id, evidence_runtime_image_sha256: IMAGE_SHA256,
    depends_on: [...profile.depends_on], known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: status === 'INCONSISTENT' ? 'INCONSISTENT' : null,
    event_count: null, pair_count: null, events: null,
    on_champion_double_kill_count:
      Array.isArray(championDoubleKillEventPacketOutcome?.events)
        ? championDoubleKillEventPacketOutcome.events.length : null,
    on_champion_multiple_kill_group_count:
      Array.isArray(championMultipleKillDieHeroDeathPairOutcome?.events)
        ? championMultipleKillDieHeroDeathPairOutcome.events.length : null,
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
    ...(!championDoubleKillEventPacketOutcome ? ['champion_double_kill_event_packet'] : []),
    ...(!championMultipleKillDieHeroDeathPairOutcome
      ? ['champion_multiple_kill_die_hero_death_pair'] : []),
  ];
  if (missing.length) {
    return fail('MISSING_INPUT', 'both exact-build candidate outcomes are required', {
      missing_inputs: missing,
    });
  }
  const child = championDoubleKillEventPacketOutcome;
  const grouped = championMultipleKillDieHeroDeathPairOutcome;
  if (child.status !== 'CANDIDATE' || grouped.status !== 'CANDIDATE') {
    return fail('MISSING_INPUT', 'one or more candidate outcomes are unavailable', {
      champion_double_kill_status: child.status ?? null,
      champion_multiple_kill_group_status: grouped.status ?? null,
    });
  }
  if (child.profile_id !== CHAMPION_DOUBLE_KILL_EVENT_PACKET_821_PROFILE.id
      || child.evidence_runtime_image_sha256 !== IMAGE_SHA256
      || child.runtime_image_sha256 !== IMAGE_SHA256
      || child.runtime_image_status !== 'MATCHED_USED' || child.runtime_image_used !== true
      || child.input_packet_id !== 0x040a || child.child_event_id !== 0x000b
      || !Array.isArray(child.events) || !count(child.event_count)
      || child.event_count !== child.events.length || child.events.length === 0
      || !count(child.input_count) || child.input_count < child.event_count
      || grouped.profile_id !== CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE.id
      || grouped.evidence_runtime_image_sha256 !== IMAGE_SHA256
      || grouped.evidence_status !== MULTI_GROUP_STATUS
      || grouped.replay_sha256 !== replay.source_sha256
      || !Array.isArray(grouped.events) || !count(grouped.event_count)
      || grouped.event_count !== grouped.events.length || grouped.events.length === 0
      || !count(grouped.pair_count) || grouped.pair_count !== grouped.event_count) {
    return fail('INCONSISTENT', 'exact-build candidate outcome identity or counts differ');
  }
  const doubleByKey = new Map();
  const seenPositions = new Set();
  for (let index = 0; index < child.events.length; index += 1) {
    const row = child.events[index];
    if (!validDoubleRow(replay, row)) {
      return fail('INCONSISTENT', 'OnChampionDoubleKill row has invalid identity or raw packet reference', {
        route: 'champion_double_kill_event_packet', event_index: index,
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
    if (doubleByKey.has(groupKey)) {
      return fail('INCONSISTENT', 'duplicate OnChampionDoubleKill same-chunk, same-ms key', {
        duplicate_key: groupKey,
      });
    }
    doubleByKey.set(groupKey, row);
  }
  const multiByKey = new Map();
  for (let index = 0; index < grouped.events.length; index += 1) {
    const row = grouped.events[index];
    if (!validMultiGroupRow(replay, row)) {
      return fail('INCONSISTENT', 'MultipleKill/Die/Hero group has invalid identity or raw packet references', {
        route: 'champion_multiple_kill_die_hero_death_pair', event_index: index,
      });
    }
    for (const ref of row.raw_packet_refs) {
      const packetPosition = position(ref);
      if (seenPositions.has(packetPosition)) {
        return fail('INCONSISTENT', 'candidate raw packet position is duplicated', {
          duplicate_packet_position: packetPosition,
        });
      }
      seenPositions.add(packetPosition);
    }
    const groupKey = key(row.on_champion_multiple_kill_raw_packet_ref);
    if (multiByKey.has(groupKey)) {
      return fail('INCONSISTENT', 'duplicate MultipleKill/Die/Hero same-chunk, same-ms key', {
        duplicate_key: groupKey,
      });
    }
    multiByKey.set(groupKey, row);
  }
  const unmatchedDoubleKeys = [...doubleByKey.keys()]
    .filter((groupKey) => !multiByKey.has(groupKey));
  const selectedMultiKeys = [...multiByKey.entries()]
    .filter(([, row]) => row.on_champion_multiple_kill_event_u32_0x08 === 2)
    .map(([groupKey]) => groupKey);
  const unpairedSelectedMultiKeys = selectedMultiKeys
    .filter((groupKey) => !doubleByKey.has(groupKey));
  if (unmatchedDoubleKeys.length || unpairedSelectedMultiKeys.length) {
    return fail('INCONSISTENT', 'OnChampionDoubleKill and Multi +0x08=2 keys are not one-to-one', {
      unmatched_on_champion_double_kill_count: unmatchedDoubleKeys.length,
      first_unmatched_on_champion_double_kill_key: unmatchedDoubleKeys[0] ?? null,
      unpaired_multi_u32_0x08_2_count: unpairedSelectedMultiKeys.length,
      first_unpaired_multi_u32_0x08_2_key: unpairedSelectedMultiKeys[0] ?? null,
    });
  }
  const sorted = [...doubleByKey.entries()].sort(([left], [right]) => {
    const [leftChunk, leftTime] = left.split('/').map(Number);
    const [rightChunk, rightTime] = right.split('/').map(Number);
    return leftChunk - rightChunk || leftTime - rightTime;
  });
  const events = [];
  for (const [groupKey, doubleRow] of sorted) {
    const multiRow = multiByKey.get(groupKey);
    const doubleRef = doubleRow.raw_packet_ref;
    const multiRef = multiRow.on_champion_multiple_kill_raw_packet_ref;
    const dieRef = multiRow.on_champion_die_raw_packet_ref;
    const heroRefs = multiRow.hero_death_raw_packet_refs;
    if (multiRow.on_champion_multiple_kill_event_u32_0x08 !== 2) {
      return fail('INCONSISTENT', 'matched Multi anonymous +0x08 differs from observed value 2', {
        key: groupKey,
        matched_multi_u32_0x08: multiRow.on_champion_multiple_kill_event_u32_0x08,
      });
    }
    if (!(dieRef.decompressed_block_offset < doubleRef.decompressed_block_offset
          && doubleRef.decompressed_block_offset < multiRef.decompressed_block_offset
          && multiRef.decompressed_block_offset < heroRefs[0].decompressed_block_offset)) {
      return fail('INCONSISTENT', 'candidate packet order differs from observed Die/0x000b/Multi/Hero_Die route', {
        key: groupKey,
        die_offset: dieRef.decompressed_block_offset,
        double_kill_named_offset: doubleRef.decompressed_block_offset,
        multi_offset: multiRef.decompressed_block_offset,
        hero_primary_offset: heroRefs[0].decompressed_block_offset,
      });
    }
    if (doubleRow.raw_param !== multiRow.on_champion_multiple_kill_raw_param) {
      return fail('INCONSISTENT', 'same-time candidate outer raw parameters disagree', {
        key: groupKey,
        double_kill_named_raw_param: doubleRow.raw_param,
        multi_raw_param: multiRow.on_champion_multiple_kill_raw_param,
      });
    }
    const doubleRefCopy = structuredClone(doubleRef);
    const multiRefCopy = structuredClone(multiRef);
    const dieRefCopy = structuredClone(dieRef);
    const heroRefsCopy = heroRefs.map((ref) => structuredClone(ref));
    const allRefs = [...multiRow.raw_packet_refs.map((ref) => structuredClone(ref)), doubleRefCopy]
      .sort((left, right) => left.decompressed_block_offset - right.decompressed_block_offset);
    events.push({
      event_type: 'CHAMPION_DOUBLE_KILL_MULTI_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256, replay_time_ms: doubleRow.replay_time_ms,
      on_champion_double_kill_child_event_id: 0x000b,
      on_champion_double_kill_registered_event_name: 'OnChampionDoubleKill',
      on_champion_double_kill_raw_param: doubleRow.raw_param,
      on_champion_double_kill_event_blob_sha256: doubleRow.event_blob_sha256,
      on_champion_multiple_kill_child_event_id: 0x0009,
      on_champion_multiple_kill_raw_param: multiRow.on_champion_multiple_kill_raw_param,
      on_champion_multiple_kill_opaque_u32_0x08:
        multiRow.on_champion_multiple_kill_event_u32_0x08,
      upstream_multi_group_profile_id: multiRow.build_profile,
      raw_packet_ref: doubleRefCopy,
      on_champion_double_kill_raw_packet_ref: doubleRefCopy,
      on_champion_multiple_kill_raw_packet_ref: multiRefCopy,
      on_champion_die_raw_packet_ref: dieRefCopy,
      hero_death_raw_packet_refs: heroRefsCopy,
      raw_packet_refs: allRefs,
      confidence: 'CANDIDATE', semantic_status: CANDIDATE_STATUS,
    });
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: CANDIDATE_STATUS,
    replay_sha256: replay.source_sha256,
    on_champion_double_kill_count: child.events.length,
    on_champion_multiple_kill_group_count: grouped.events.length,
    matched_multi_u32_0x08_2_count: selectedMultiKeys.length,
    excluded_other_multi_u32_0x08_count: grouped.events.length - selectedMultiKeys.length,
    unmatched_on_champion_double_kill_count: 0,
    unpaired_multi_u32_0x08_2_count: 0,
    pair_count: events.length, event_count: events.length, events,
  };
}

module.exports = {
  CHAMPION_DOUBLE_KILL_MULTI_GROUP_821_PROFILE,
  associateChampionDoubleKillMultiGroupCandidates821,
};
