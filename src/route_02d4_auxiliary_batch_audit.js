'use strict';

const EXACT_BUILD = '16.16.805.0442';
const PACKET_ID = 0x02d4;
const SELECTED_CONTEXT_ROUTES = Object.freeze({
  DAMAGE_017F: 0x017f,
  HERO_PATH_00F6: 0x00f6,
  BUFF_UPDATE_COUNT_0123: 0x0123,
  BUFF_ADD_0326: 0x0326,
  BUFF_COUNTER_041F: 0x041f,
  BUFF_REPLACE_043C: 0x043c,
  BUFF_REMOVE_045B: 0x045b,
  CAST_01CF: 0x01cf,
  ITEM_CHARGE_0310: 0x0310,
  UNKNOWN_03AA: 0x03aa,
  PERIODIC_CLUSTER_0199: 0x0199,
  VARIABLE_BATCH_004A: 0x004a,
});

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function round(value, digits = 8) {
  if (value === null || value === undefined || !Number.isFinite(value)) return null;
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function quantile(values, fraction) {
  if (!values.length) return null;
  const sorted = [...values].sort((left, right) => left - right);
  const index = (sorted.length - 1) * fraction;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + ((sorted[upper] - sorted[lower]) * (index - lower));
}

function countRows(values, keyName, limit = null) {
  const counts = new Map();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  const rows = [...counts.entries()]
    .map(([value, count]) => ({ [keyName]: value, count }))
    .sort((left, right) => right.count - left.count
      || String(left[keyName]).localeCompare(String(right[keyName])));
  return limit === null ? rows : rows.slice(0, limit);
}

function isBroadNetworkEntity(value) {
  return value >= 0x40000000 && value <= 0x400fffff;
}

function isCanonicalHero(value) {
  return value >= 0x400000ae && value <= 0x400000b7;
}

function analyzeReplay(record) {
  for (const event of record.route_events) {
    invariant(event.packet_id === PACKET_ID, `unexpected packet ${event.packet_id}`);
    invariant(event.replay_version === EXACT_BUILD, `wrong build ${event.replay_version}`);
  }
  const grouped = new Map();
  for (const event of record.route_events) {
    if (!grouped.has(event.replay_time_ms)) grouped.set(event.replay_time_ms, []);
    grouped.get(event.replay_time_ms).push(event);
  }
  const groupRows = [...grouped.entries()].map(([timestamp, events]) => ({
    timestamp_ms: timestamp,
    event_count: events.length,
    raw_param_zero_count: events.filter((event) => event.raw_param === 0).length,
    payload_lengths: [...new Set(events.map((event) => event.payload_length))].sort((a, b) => a - b),
    context_packet_counts: record.time_context.get(timestamp) ?? {},
  })).sort((left, right) => left.timestamp_ms - right.timestamp_ms);
  const groupSizes = groupRows.map((row) => row.event_count);
  const rawParams = record.route_events.map((event) => event.raw_param >>> 0);
  const payloads = record.route_events.map((event) => event.raw_payload_hex);
  const firstBytes = payloads.map((payload) => Number.parseInt(payload.slice(0, 2), 16));
  const firstByteHighFive = firstBytes.map((value) => value & 0xf8);
  const constantHighFive = firstBytes.filter((value) => (value & 0xf8) === 0x28).length;
  const knownHighFive = firstByteHighFive.filter((value) => value === 0x28 || value === 0x20).length;
  const alternateHighFiveWitnesses = record.route_events.filter((event) =>
    (Number.parseInt(event.raw_payload_hex.slice(0, 2), 16) & 0xf8) === 0x20).slice(0, 32).map((event) => ({
    replay_time_ms: event.replay_time_ms,
    occurrence_index: event.occurrence_index,
    raw_param: event.raw_param,
    payload_length: event.payload_length,
    raw_payload_hex: event.raw_payload_hex,
    previous_same_timestamp_hex: event.previous_same_timestamp_hex,
    next_same_timestamp_hex: event.next_same_timestamp_hex,
  }));
  const context = Object.entries(SELECTED_CONTEXT_ROUTES).map(([label, packetId]) => {
    const packetHex = `0x${packetId.toString(16).padStart(4, '0')}`;
    const groups = groupRows.filter((row) => Number(row.context_packet_counts[packetHex] ?? 0) > 0);
    return {
      label,
      packet_id: packetId,
      packet_discriminator: packetHex,
      same_timestamp_group_count: groups.length,
      same_timestamp_group_rate: round(groups.length / groupRows.length),
      route_02d4_event_count_at_shared_timestamps: groups.reduce((sum, row) => sum + row.event_count, 0),
      route_02d4_event_rate_at_shared_timestamps: round(groups.reduce((sum, row) => sum + row.event_count, 0)
        / record.route_events.length),
    };
  });
  const damageContext = context.find((row) => row.packet_id === 0x017f);
  const pathContext = context.find((row) => row.packet_id === 0x00f6);
  const giantGroups = groupRows.filter((row) => row.event_count >= 100);
  return {
    replay_label: record.replay_label,
    replay_sha256: record.replay_sha256,
    counts: {
      event_count: record.route_events.length,
      timestamp_group_count: groupRows.length,
      singleton_group_count: groupRows.filter((row) => row.event_count === 1).length,
      multirow_group_count: groupRows.filter((row) => row.event_count > 1).length,
      giant_group_at_least_100_rows_count: giantGroups.length,
      maximum_group_size: groupSizes.length ? Math.max(...groupSizes) : null,
    },
    group_size: {
      min: groupSizes.length ? Math.min(...groupSizes) : null,
      p50: quantile(groupSizes, 0.5),
      p90: quantile(groupSizes, 0.9),
      p99: quantile(groupSizes, 0.99),
      max: groupSizes.length ? Math.max(...groupSizes) : null,
      distribution_top: countRows(groupSizes, 'event_count', 32),
    },
    raw_param: {
      zero_count: rawParams.filter((value) => value === 0).length,
      zero_rate: round(rawParams.filter((value) => value === 0).length / rawParams.length),
      canonical_hero_count: rawParams.filter(isCanonicalHero).length,
      canonical_hero_rate: round(rawParams.filter(isCanonicalHero).length / rawParams.length),
      broad_network_entity_count: rawParams.filter(isBroadNetworkEntity).length,
      broad_network_entity_rate: round(rawParams.filter(isBroadNetworkEntity).length / rawParams.length),
      distinct_count: new Set(rawParams).size,
      top_values: countRows(rawParams, 'raw_param', 20),
    },
    payload: {
      length_distribution: countRows(record.route_events.map((event) => event.payload_length), 'payload_length'),
      first_byte_distribution: countRows(firstBytes, 'first_byte', 16),
      first_byte_high_five_bit_distribution: countRows(firstByteHighFive, 'high_five_bits'),
      first_byte_high_five_bits_constant_0x28_count: constantHighFive,
      first_byte_high_five_bits_constant_0x28_rate: round(constantHighFive / firstBytes.length),
      first_byte_known_high_five_branch_count: knownHighFive,
      first_byte_known_high_five_branch_rate: round(knownHighFive / firstBytes.length),
      alternate_high_five_0x20_witnesses: alternateHighFiveWitnesses,
      one_byte_payload_distribution: countRows(record.route_events
        .filter((event) => event.payload_length === 1).map((event) => event.raw_payload_hex), 'payload_hex'),
      four_byte_last_byte_distribution: countRows(record.route_events
        .filter((event) => event.payload_length === 4)
        .map((event) => event.raw_payload_hex.slice(-2)), 'last_byte_hex', 32),
      distinct_payload_count: new Set(payloads).size,
    },
    immediate_neighbors: {
      previous_packet: countRows(record.route_events.map((event) => event.previous_packet_hex), 'packet_discriminator', 24),
      next_packet: countRows(record.route_events.map((event) => event.next_packet_hex), 'packet_discriminator', 24),
      previous_same_timestamp: countRows(record.route_events.map((event) =>
        event.previous_same_timestamp_hex ?? 'DIFFERENT_TIMESTAMP'), 'packet_discriminator', 24),
      next_same_timestamp: countRows(record.route_events.map((event) =>
        event.next_same_timestamp_hex ?? 'DIFFERENT_TIMESTAMP'), 'packet_discriminator', 24),
    },
    timestamp_context: context,
    negative_controls: {
      groups_without_damage: groupRows.length - damageContext.same_timestamp_group_count,
      groups_without_damage_rate: round(1 - damageContext.same_timestamp_group_rate),
      damage_context_group_rate: damageContext.same_timestamp_group_rate,
      hero_path_context_group_rate: pathContext.same_timestamp_group_rate,
      giant_groups: giantGroups.slice(0, 32).map((row) => ({
        timestamp_ms: row.timestamp_ms,
        event_count: row.event_count,
        raw_param_zero_count: row.raw_param_zero_count,
        payload_lengths: row.payload_lengths,
        damage_packet_count: Number(row.context_packet_counts['0x017f'] ?? 0),
        hero_path_packet_count: Number(row.context_packet_counts['0x00f6'] ?? 0),
        periodic_0199_packet_count: Number(row.context_packet_counts['0x0199'] ?? 0),
      })),
    },
  };
}

function aggregate(replays) {
  const eventCount = replays.reduce((sum, replay) => sum + replay.counts.event_count, 0);
  const groupCount = replays.reduce((sum, replay) => sum + replay.counts.timestamp_group_count, 0);
  const groupsWithoutDamage = replays.reduce((sum, replay) =>
    sum + replay.negative_controls.groups_without_damage, 0);
  const context = Object.entries(SELECTED_CONTEXT_ROUTES).map(([label, packetId]) => {
    const rows = replays.map((replay) => replay.timestamp_context.find((row) => row.packet_id === packetId));
    const sharedGroups = rows.reduce((sum, row) => sum + row.same_timestamp_group_count, 0);
    const sharedEvents = rows.reduce((sum, row) => sum + row.route_02d4_event_count_at_shared_timestamps, 0);
    return {
      label,
      packet_id: packetId,
      packet_discriminator: `0x${packetId.toString(16).padStart(4, '0')}`,
      same_timestamp_group_count: sharedGroups,
      same_timestamp_group_rate: round(sharedGroups / groupCount),
      route_02d4_event_count_at_shared_timestamps: sharedEvents,
      route_02d4_event_rate_at_shared_timestamps: round(sharedEvents / eventCount),
    };
  });
  return {
    replay_count: replays.length,
    event_count: eventCount,
    timestamp_group_count: groupCount,
    groups_without_damage: groupsWithoutDamage,
    groups_without_damage_rate: round(groupsWithoutDamage / groupCount),
    maximum_group_size: Math.max(...replays.map((replay) => replay.counts.maximum_group_size)),
    giant_group_at_least_100_rows_count: replays.reduce((sum, replay) =>
      sum + replay.counts.giant_group_at_least_100_rows_count, 0),
    context,
  };
}

function analyzeRoute02d4(records, expectedCount, sampledSemanticEvidence = null) {
  invariant(Array.isArray(records) && records.length > 0, 'explicit replay records are required');
  const replays = records.map(analyzeReplay);
  const counts = aggregate(replays);
  const damageContext = counts.context.find((row) => row.packet_id === 0x017f);
  const pathContext = counts.context.find((row) => row.packet_id === 0x00f6);
  const rawZeroCount = replays.reduce((sum, replay) => sum + replay.raw_param.zero_count, 0);
  const rawHeroCount = replays.reduce((sum, replay) => sum + replay.raw_param.canonical_hero_count, 0);
  const primaryHighFiveCount = replays.reduce((sum, replay) =>
    sum + replay.payload.first_byte_high_five_bits_constant_0x28_count, 0);
  const knownHighFiveCount = replays.reduce((sum, replay) =>
    sum + replay.payload.first_byte_known_high_five_branch_count, 0);
  const alternateHighFiveCount = knownHighFiveCount - primaryHighFiveCount;
  const giantRows = replays.flatMap((replay) => replay.negative_controls.giant_groups);
  const fullCountMatch = expectedCount === null || counts.event_count === expectedCount;
  const sampleRawMatchRate = sampledSemanticEvidence
    ?.entity_identifier_mining?.raw_param?.participant_low_byte_rate ?? null;
  const sampleDamageRawMatch = sampledSemanticEvidence
    ?.damage_neighborhood?.raw_param_matches_either_within_10ms_rate ?? null;
  const damageSpecificRejected = damageContext.same_timestamp_group_rate > 0.5
    && counts.groups_without_damage > 1000
    && sampleDamageRawMatch !== null
    && sampleDamageRawMatch < 0.05
    && giantRows.some((row) => row.event_count >= 100 && row.damage_packet_count < 10);
  const directEntityScalarRejected = rawZeroCount / counts.event_count > 0.8
    && rawHeroCount / counts.event_count < 0.1
    && counts.maximum_group_size >= 100;
  const structuralPass = fullCountMatch
    && replays.every((replay) => replay.payload.first_byte_known_high_five_branch_rate === 1)
    && counts.timestamp_group_count > 0;

  return {
    schema: 'ROUTE_02D4_AUXILIARY_BATCH_AUDIT_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    packet_id: PACKET_ID,
    packet_discriminator: '0x02d4',
    counts,
    replays,
    sampled_semantic_cross_check: sampledSemanticEvidence ? {
      sample_count: sampledSemanticEvidence.sample_count,
      sample_scope_warning: sampledSemanticEvidence.sample_policy_warning,
      damage_neighborhood: sampledSemanticEvidence.damage_neighborhood,
      raw_param_participant_low_byte_rate: sampleRawMatchRate,
      semantic_claim: null,
    } : null,
    recovered_bounded_structure: {
      evidence_grade: structuralPass ? 'VERIFIED_DIRECT' : 'CANDIDATE',
      payload_branch_lengths: [1, 3, 4],
      byte_0_high_five_bits: structuralPass ? {
        primary_branch: '0x28',
        primary_row_count: primaryHighFiveCount,
        alternate_branch: '0x20',
        alternate_row_count: alternateHighFiveCount,
        known_branch_coverage_count: knownHighFiveCount,
        known_branch_coverage_rate: round(knownHighFiveCount / counts.event_count),
      } : 'CANDIDATE',
      batching: 'VARIABLE_CARDINALITY_SAME_TIMESTAMP_RUNS_WITH_EXTREME_GROUPS',
      cross_domain_context: 'Frequently co-timed with Damage, HeroPath, Buff, Cast, Item-charge, and periodic cluster routes.',
      semantic_claim: null,
    },
    negative_evidence: {
      damage_specific_event_hypothesis_rejected: damageSpecificRejected,
      direct_entity_scalar_hypothesis_rejected: directEntityScalarRejected,
      rejected_hypotheses: [
        ...(damageSpecificRejected ? ['DAMAGE_EVENT', 'DAMAGE_SOURCE_OR_TARGET_EVENT'] : []),
        ...(directEntityScalarRejected ? [
          'DIRECT_CURRENT_HP', 'DIRECT_MAX_HP', 'DIRECT_ARMOR_OR_MAGIC_RESIST',
          'DIRECT_RESOURCE_SCALAR', 'ONE_PACKET_PER_ENTITY_UPDATE',
        ] : []),
      ],
      evidence: {
        groups_without_damage: counts.groups_without_damage,
        groups_without_damage_rate: counts.groups_without_damage_rate,
        maximum_same_timestamp_group_size: counts.maximum_group_size,
        giant_group_count: counts.giant_group_at_least_100_rows_count,
        sampled_raw_param_matches_damage_source_or_target_within_10ms_rate: sampleDamageRawMatch,
        exact_damage_context_group_rate: damageContext.same_timestamp_group_rate,
        exact_hero_path_context_group_rate: pathContext.same_timestamp_group_rate,
      },
    },
    validations: {
      inventory_count_match: fullCountMatch,
      exact_payload_high_bits_invariant: structuralPass,
      direct_damage_semantic_rejected: damageSpecificRejected,
      direct_entity_scalar_semantic_rejected: directEntityScalarRejected,
      all_pass: structuralPass && damageSpecificRejected && directEntityScalarRejected,
    },
    route_decisions: [{
      packet_id: PACKET_ID,
      packet_discriminator: '0x02d4',
      decision: structuralPass && damageSpecificRejected && directEntityScalarRejected
        ? 'REPURPOSE' : 'KEEP_CANDIDATE',
      hypothesis: 'CROSS_DOMAIN_BITPACKED_AUXILIARY_UPDATE_BATCH',
      evidence_grade: structuralPass ? 'VERIFIED_DIRECT' : 'CANDIDATE',
      supersedes_previous_decision: true,
      semantic_claim: null,
      positive_anchor_count: 0,
      counterexample_count: counts.groups_without_damage,
      evidence_exhausted: false,
      next_required_evidence: [
        'Recover the alternate dispatcher/registration surface that owns 0x02d4.',
        'Decode the 1/3/4-byte bit-packed branches before assigning any gameplay field.',
        'Use a controlled exact-build toggle or runtime plaintext consumer to distinguish replication metadata from visual/render state.',
      ],
    }],
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  };
}

module.exports = {
  EXACT_BUILD,
  PACKET_ID,
  SELECTED_CONTEXT_ROUTES,
  analyzeReplay,
  analyzeRoute02d4,
};
