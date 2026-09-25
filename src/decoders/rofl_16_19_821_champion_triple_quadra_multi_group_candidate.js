'use strict';

// Exact-build packet association only. Child names and the anonymous Multi
// +0x08 relation do not prove effective kills or participant roles.
const { replaySourceError } = require('./replay_source_integrity');
const { CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_821_PROFILE } =
  require('./rofl_16_19_821_champion_triple_quadra_event_packet_candidate');
const { CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('./rofl_16_19_821_champion_multiple_kill_die_hero_death_pair_candidate');
const { packetGroupCandidate821Internals: checks } =
  require('./rofl_16_19_821_champion_double_kill_multi_group_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const CANDIDATE_STATUS = 'CANDIDATE_821_TRIPLE_QUADRA_NAMED_MULTI_DIE_HERO_PACKET_GROUP';
const MULTI_GROUP_STATUS = 'CANDIDATE_821_ON_CHAMPION_MULTIPLE_KILL_DIE_HERO_DIE_PACKET_GROUP';
const CHILDREN = new Map([
  [0x000c, Object.freeze({ name: 'OnChampionTripleKill', rawEventIdHex: '0x49c8', multi08: 3 })],
  [0x000d, Object.freeze({ name: 'OnChampionQuadraKill', rawEventIdHex: '0x4988', multi08: 4 })],
]);

const CHAMPION_TRIPLE_QUADRA_MULTI_GROUP_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-on-champion-triple-quadra-multi-die-hero-packet-group-candidate-v1',
  replay_version: BUILD,
  capability: 'champion_triple_quadra_multi_group',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze([
    'champion_triple_quadra_event_packet', 'champion_multiple_kill_die_hero_death_pair',
  ]),
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays; 9 native child 0x000c and 1 child 0x000d packets uniquely share Replay SHA, chunk and millisecond with Multi/Die/Hero packet groups; joined anonymous Multi +0x08 values are 3 and 4 respectively',
  known_limits: Object.freeze([
    'The named children are exact-image labels, not evidence of effective triple or quadra kills or gameplay state changes.',
    'The Multi child +0x08 values are anonymous structural equalities in observed packet groups, not confirmed kill counts.',
    'No child-blob word is assigned a gameplay role, and actor or victim identity is not inferred.',
    'Missing, duplicate, ambiguous, wrong-order, or conflicting candidate packets fail the entire Replay association without partial groups.',
  ]),
});

function validNamedRow(replay, row) {
  const child = CHILDREN.get(row?.child_event_id);
  const ref = row?.raw_packet_ref;
  return !!child
    && row.event_type === 'CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_CANDIDATE'
    && row.game_version === BUILD
    && row.build_profile === CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_821_PROFILE.id
    && row.replay_sha256 === replay.source_sha256
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD'
    && Number.isSafeInteger(row.replay_time_ms) && row.replay_time_ms >= 0
    && row.registered_event_name === child.name
    && row.raw_event_id_hex === child.rawEventIdHex
    && checks.u32(row.raw_param) && row.raw_param !== 0
    && checks.sha(row.event_blob_sha256)
    && checks.validRef(replay, ref, row.replay_time_ms)
    && ref.packet_id === 0x040a && ref.payload_length === 104
    && ref.raw_param === row.raw_param;
}

function associateChampionTripleQuadraMultiGroupCandidates821(replay, {
  championTripleQuadraEventPacketOutcome, championMultipleKillDieHeroDeathPairOutcome,
} = {}) {
  const profile = CHAMPION_TRIPLE_QUADRA_MULTI_GROUP_821_PROFILE;
  const base = {
    profile_id: profile.id, evidence_runtime_image_sha256: IMAGE_SHA256,
    depends_on: [...profile.depends_on], known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: status === 'INCONSISTENT' ? 'INCONSISTENT' : null,
    event_count: null, pair_count: null, events: null,
    on_champion_triple_quadra_count:
      Array.isArray(championTripleQuadraEventPacketOutcome?.events)
        ? championTripleQuadraEventPacketOutcome.events.length : null,
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
  if (!checks.sha(replay.source_sha256)) {
    return fail('INCONSISTENT', 'Replay source SHA-256 is missing or malformed');
  }
  const missing = [
    ...(!championTripleQuadraEventPacketOutcome ? ['champion_triple_quadra_event_packet'] : []),
    ...(!championMultipleKillDieHeroDeathPairOutcome
      ? ['champion_multiple_kill_die_hero_death_pair'] : []),
  ];
  if (missing.length) {
    return fail('MISSING_INPUT', 'both exact-build candidate outcomes are required', {
      missing_inputs: missing,
    });
  }
  const child = championTripleQuadraEventPacketOutcome;
  const grouped = championMultipleKillDieHeroDeathPairOutcome;
  if (child.status !== 'CANDIDATE' || grouped.status !== 'CANDIDATE') {
    return fail('MISSING_INPUT', 'one or more candidate outcomes are unavailable', {
      champion_triple_quadra_status: child.status ?? null,
      champion_multiple_kill_group_status: grouped.status ?? null,
    });
  }
  if (child.profile_id !== CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_821_PROFILE.id
      || child.evidence_runtime_image_sha256 !== IMAGE_SHA256
      || child.runtime_image_sha256 !== IMAGE_SHA256
      || child.runtime_image_status !== 'MATCHED_USED' || child.runtime_image_used !== true
      || child.input_packet_id !== 0x040a
      || !Array.isArray(child.events) || !checks.count(child.event_count)
      || child.event_count !== child.events.length || child.events.length === 0
      || !checks.count(child.input_count) || child.input_count < child.event_count
      || !checks.count(child.target_packet_count)
      || child.target_packet_count !== child.event_count
      || grouped.profile_id !== CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE.id
      || grouped.evidence_runtime_image_sha256 !== IMAGE_SHA256
      || grouped.evidence_status !== MULTI_GROUP_STATUS
      || grouped.replay_sha256 !== replay.source_sha256
      || !Array.isArray(grouped.events) || !checks.count(grouped.event_count)
      || grouped.event_count !== grouped.events.length || grouped.events.length === 0
      || !checks.count(grouped.pair_count) || grouped.pair_count !== grouped.event_count) {
    return fail('INCONSISTENT', 'exact-build candidate outcome identity or counts differ');
  }
  const namedByKey = new Map();
  const seenPositions = new Set();
  for (let index = 0; index < child.events.length; index += 1) {
    const row = child.events[index];
    if (!validNamedRow(replay, row)) {
      return fail('INCONSISTENT', 'Triple/Quadra named row has invalid identity or raw packet reference', {
        route: 'champion_triple_quadra_event_packet', event_index: index,
      });
    }
    const ref = row.raw_packet_ref;
    const packetPosition = checks.position(ref);
    if (seenPositions.has(packetPosition)) {
      return fail('INCONSISTENT', 'candidate raw packet position is duplicated', {
        duplicate_packet_position: packetPosition,
      });
    }
    seenPositions.add(packetPosition);
    const groupKey = checks.key(ref);
    if (namedByKey.has(groupKey)) {
      return fail('INCONSISTENT', 'duplicate Triple/Quadra same-chunk, same-ms key', {
        duplicate_key: groupKey,
      });
    }
    namedByKey.set(groupKey, row);
  }
  const multiByKey = new Map();
  for (let index = 0; index < grouped.events.length; index += 1) {
    const row = grouped.events[index];
    if (!checks.validMultiGroupRow(replay, row)) {
      return fail('INCONSISTENT', 'MultipleKill/Die/Hero group has invalid identity or raw packet references', {
        route: 'champion_multiple_kill_die_hero_death_pair', event_index: index,
      });
    }
    for (const ref of row.raw_packet_refs) {
      const packetPosition = checks.position(ref);
      if (seenPositions.has(packetPosition)) {
        return fail('INCONSISTENT', 'candidate raw packet position is duplicated', {
          duplicate_packet_position: packetPosition,
        });
      }
      seenPositions.add(packetPosition);
    }
    const groupKey = checks.key(row.on_champion_multiple_kill_raw_packet_ref);
    if (multiByKey.has(groupKey)) {
      return fail('INCONSISTENT', 'duplicate MultipleKill/Die/Hero same-chunk, same-ms key', {
        duplicate_key: groupKey,
      });
    }
    multiByKey.set(groupKey, row);
  }
  const unmatchedNamedKeys = [...namedByKey.keys()]
    .filter((groupKey) => !multiByKey.has(groupKey));
  const selectedMultiKeys = [...multiByKey.entries()]
    .filter(([, row]) => row.on_champion_multiple_kill_event_u32_0x08 === 3
      || row.on_champion_multiple_kill_event_u32_0x08 === 4)
    .map(([groupKey]) => groupKey);
  const unpairedSelectedMultiKeys = selectedMultiKeys
    .filter((groupKey) => !namedByKey.has(groupKey));
  if (unmatchedNamedKeys.length || unpairedSelectedMultiKeys.length) {
    return fail('INCONSISTENT', 'Triple/Quadra named children and Multi +0x08=3/4 keys are not one-to-one', {
      unmatched_on_champion_triple_quadra_count: unmatchedNamedKeys.length,
      first_unmatched_on_champion_triple_quadra_key: unmatchedNamedKeys[0] ?? null,
      unpaired_multi_u32_0x08_3_or_4_count: unpairedSelectedMultiKeys.length,
      first_unpaired_multi_u32_0x08_3_or_4_key: unpairedSelectedMultiKeys[0] ?? null,
    });
  }
  const sorted = [...namedByKey.entries()].sort(([left], [right]) => {
    const [leftChunk, leftTime] = left.split('/').map(Number);
    const [rightChunk, rightTime] = right.split('/').map(Number);
    return leftChunk - rightChunk || leftTime - rightTime;
  });
  const events = [];
  for (const [groupKey, namedRow] of sorted) {
    const multiRow = multiByKey.get(groupKey);
    const namedRef = namedRow.raw_packet_ref;
    const multiRef = multiRow.on_champion_multiple_kill_raw_packet_ref;
    const dieRef = multiRow.on_champion_die_raw_packet_ref;
    const heroRefs = multiRow.hero_death_raw_packet_refs;
    const expected08 = CHILDREN.get(namedRow.child_event_id).multi08;
    if (multiRow.on_champion_multiple_kill_event_u32_0x08 !== expected08) {
      return fail('INCONSISTENT', 'matched Multi anonymous +0x08 differs from named child relation', {
        key: groupKey, named_child_event_id: namedRow.child_event_id,
        matched_multi_u32_0x08: multiRow.on_champion_multiple_kill_event_u32_0x08,
      });
    }
    if (!(dieRef.decompressed_block_offset < namedRef.decompressed_block_offset
          && namedRef.decompressed_block_offset < multiRef.decompressed_block_offset
          && multiRef.decompressed_block_offset < heroRefs[0].decompressed_block_offset)) {
      return fail('INCONSISTENT', 'candidate packet order differs from observed Die/named/Multi/Hero_Die route', {
        key: groupKey, die_offset: dieRef.decompressed_block_offset,
        named_offset: namedRef.decompressed_block_offset,
        multi_offset: multiRef.decompressed_block_offset,
        hero_primary_offset: heroRefs[0].decompressed_block_offset,
      });
    }
    if (namedRow.raw_param !== multiRow.on_champion_multiple_kill_raw_param) {
      return fail('INCONSISTENT', 'same-time candidate outer raw parameters disagree', {
        key: groupKey, named_raw_param: namedRow.raw_param,
        multi_raw_param: multiRow.on_champion_multiple_kill_raw_param,
      });
    }
    const namedRefCopy = structuredClone(namedRef);
    const multiRefCopy = structuredClone(multiRef);
    const dieRefCopy = structuredClone(dieRef);
    const heroRefsCopy = heroRefs.map((ref) => structuredClone(ref));
    const allRefs = [...multiRow.raw_packet_refs.map((ref) => structuredClone(ref)), namedRefCopy]
      .sort((left, right) => left.decompressed_block_offset - right.decompressed_block_offset);
    events.push({
      event_type: 'CHAMPION_TRIPLE_QUADRA_MULTI_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256, replay_time_ms: namedRow.replay_time_ms,
      on_champion_triple_quadra_child_event_id: namedRow.child_event_id,
      on_champion_triple_quadra_registered_event_name: namedRow.registered_event_name,
      on_champion_triple_quadra_raw_param: namedRow.raw_param,
      on_champion_triple_quadra_event_blob_sha256: namedRow.event_blob_sha256,
      on_champion_multiple_kill_child_event_id: 0x0009,
      on_champion_multiple_kill_raw_param: multiRow.on_champion_multiple_kill_raw_param,
      on_champion_multiple_kill_opaque_u32_0x08:
        multiRow.on_champion_multiple_kill_event_u32_0x08,
      upstream_multi_group_profile_id: multiRow.build_profile,
      raw_packet_ref: namedRefCopy,
      on_champion_triple_quadra_raw_packet_ref: namedRefCopy,
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
    on_champion_triple_quadra_count: child.events.length,
    on_champion_multiple_kill_group_count: grouped.events.length,
    matched_multi_u32_0x08_3_count: events.filter((row) =>
      row.on_champion_multiple_kill_opaque_u32_0x08 === 3).length,
    matched_multi_u32_0x08_4_count: events.filter((row) =>
      row.on_champion_multiple_kill_opaque_u32_0x08 === 4).length,
    excluded_other_multi_u32_0x08_count: grouped.events.length - selectedMultiKeys.length,
    unmatched_on_champion_triple_quadra_count: 0,
    unpaired_multi_u32_0x08_3_or_4_count: 0,
    pair_count: events.length, event_count: events.length, events,
  };
}

module.exports = {
  CHAMPION_TRIPLE_QUADRA_MULTI_GROUP_821_PROFILE,
  associateChampionTripleQuadraMultiGroupCandidates821,
};
