'use strict';

const EXACT_BUILD = '16.16.805.0442';
const VARIABLE_BATCH_PACKET_ID = 0x004a;
const FIXED_CLUSTER_PACKET_ID = 0x0199;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function round(value, digits = 8) {
  if (value === null || value === undefined || !Number.isFinite(value)) return null;
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
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

function eventOrder(left, right) {
  return left.chunk_index - right.chunk_index
    || left.decompressed_block_offset - right.decompressed_block_offset
    || left.occurrence_index - right.occurrence_index;
}

function groupEvents(events) {
  const groups = new Map();
  for (const event of events) {
    const key = `${event.replay_sha256}:${event.replay_time_ms}`;
    if (!groups.has(key)) {
      groups.set(key, {
        replay_sha256: event.replay_sha256,
        replay_label: event.replay_label ?? null,
        replay_time_ms: event.replay_time_ms,
        variable: [],
        fixed: [],
      });
    }
    const group = groups.get(key);
    group[event.packet_id === VARIABLE_BATCH_PACKET_ID ? 'variable' : 'fixed'].push(event);
  }
  for (const group of groups.values()) {
    group.variable.sort(eventOrder);
    group.fixed.sort(eventOrder);
  }
  return [...groups.values()].sort((left, right) =>
    String(left.replay_sha256).localeCompare(String(right.replay_sha256))
    || left.replay_time_ms - right.replay_time_ms);
}

function analyzeBatchPair(events, expectedCounts = null) {
  const selected = events.filter((event) =>
    [VARIABLE_BATCH_PACKET_ID, FIXED_CLUSTER_PACKET_ID].includes(event.packet_id));
  for (const event of selected) {
    invariant(event.replay_version === EXACT_BUILD, `wrong build ${event.replay_version}`);
  }
  const variableEvents = selected.filter((event) => event.packet_id === VARIABLE_BATCH_PACKET_ID);
  const fixedEvents = selected.filter((event) => event.packet_id === FIXED_CLUSTER_PACKET_ID);
  const groups = groupEvents(selected);
  const variableGroups = groups.filter((group) => group.variable.length > 0);
  const fixedGroups = groups.filter((group) => group.fixed.length > 0);
  const pairedGroups = groups.filter((group) => group.variable.length > 0 && group.fixed.length > 0);
  const fixedTwelveGroups = fixedGroups.filter((group) => group.fixed.length === 12);
  let multisetIntersection = 0;
  let variableUnpairedRows = 0;
  let fixedUnpairedRows = 0;
  let variableBeforeFixedGroups = 0;
  let sameChunkGroups = 0;
  for (const group of groups) {
    multisetIntersection += Math.min(group.variable.length, group.fixed.length);
    variableUnpairedRows += Math.max(0, group.variable.length - group.fixed.length);
    fixedUnpairedRows += Math.max(0, group.fixed.length - group.variable.length);
    if (group.variable.length && group.fixed.length) {
      const lastVariable = group.variable[group.variable.length - 1];
      const firstFixed = group.fixed[0];
      if (lastVariable.chunk_index === firstFixed.chunk_index) sameChunkGroups += 1;
      if (eventOrder(lastVariable, firstFixed) < 0) variableBeforeFixedGroups += 1;
    }
  }
  const fixedPayloadPresence = new Map();
  for (const group of fixedGroups) {
    for (const payload of new Set(group.fixed.map((event) => event.raw_payload_hex))) {
      fixedPayloadPresence.set(payload, (fixedPayloadPresence.get(payload) ?? 0) + 1);
    }
  }
  const fixedPayloadGroupPresence = [...fixedPayloadPresence.entries()]
    .map(([payload_hex, group_count]) => ({
      payload_hex,
      group_count,
      group_rate: round(group_count / fixedGroups.length),
    }))
    .sort((left, right) => right.group_count - left.group_count
      || left.payload_hex.localeCompare(right.payload_hex));
  const replayKeys = [...new Set(selected.map((event) => event.replay_sha256))].sort();
  const perReplay = replayKeys.map((replaySha256) => {
    const replayGroups = groups.filter((group) => group.replay_sha256 === replaySha256);
    const variable = variableEvents.filter((event) => event.replay_sha256 === replaySha256);
    const fixed = fixedEvents.filter((event) => event.replay_sha256 === replaySha256);
    return {
      replay_sha256: replaySha256,
      replay_label: replayGroups[0]?.replay_label ?? null,
      variable_batch_event_count: variable.length,
      fixed_cluster_event_count: fixed.length,
      variable_timestamp_group_count: replayGroups.filter((group) => group.variable.length).length,
      fixed_timestamp_group_count: replayGroups.filter((group) => group.fixed.length).length,
      paired_timestamp_group_count: replayGroups.filter((group) => group.variable.length && group.fixed.length).length,
    };
  });
  const variableRawZeroCount = variableEvents.filter((event) => event.raw_param === 0).length;
  const inventoryPass = expectedCounts === null
    || (expectedCounts[VARIABLE_BATCH_PACKET_ID] === variableEvents.length
      && expectedCounts[FIXED_CLUSTER_PACKET_ID] === fixedEvents.length);
  const fixedTwelvePass = fixedGroups.length > 0 && fixedTwelveGroups.length === fixedGroups.length;
  const variableKeyContainment = variableGroups.length ? pairedGroups.length / variableGroups.length : 0;
  const orderingPass = pairedGroups.length > 0
    && variableBeforeFixedGroups === pairedGroups.length
    && sameChunkGroups === pairedGroups.length;
  const variableMostlyRawZero = variableEvents.length > 0
    && variableRawZeroCount / variableEvents.length > 0.999;
  const structuralBatchPass = inventoryPass && fixedTwelvePass
    && variableKeyContainment > 0.998 && orderingPass && variableMostlyRawZero;
  const nextRequiredEvidence = [
    'Recover the non-MakeFunction runtime dispatch and bounded decoder for both routes.',
    'Identify whether the twelve-row cluster is a trailer, control vector, or independent tick family using controlled runtime instrumentation.',
    'Decode the variable 0x004a payloads before assigning any entity, movement, combat, or world semantic.',
  ];

  return {
    schema: 'ROUTE_PAIR_004A_0199_BATCH_AUDIT_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    pair: {
      variable_batch_route: '0x004a',
      fixed_cluster_route: '0x0199',
    },
    counts: {
      variable_batch_event_count: variableEvents.length,
      fixed_cluster_event_count: fixedEvents.length,
      variable_timestamp_group_count: variableGroups.length,
      fixed_timestamp_group_count: fixedGroups.length,
      paired_timestamp_group_count: pairedGroups.length,
      fixed_twelve_row_group_count: fixedTwelveGroups.length,
      timestamp_multiset_row_intersection: multisetIntersection,
      variable_unpaired_row_count: variableUnpairedRows,
      fixed_unpaired_row_count: fixedUnpairedRows,
    },
    relationship: {
      variable_timestamp_group_containment_rate: round(variableKeyContainment),
      fixed_timestamp_group_containment_rate: round(pairedGroups.length / fixedGroups.length),
      row_multiset_containment_rate: round(multisetIntersection
        / Math.min(variableEvents.length, fixedEvents.length)),
      row_multiset_jaccard: round(multisetIntersection
        / (variableEvents.length + fixedEvents.length - multisetIntersection)),
      paired_groups_same_chunk_count: sameChunkGroups,
      variable_batch_before_fixed_cluster_group_count: variableBeforeFixedGroups,
      variable_batch_before_fixed_cluster_group_rate: round(variableBeforeFixedGroups / pairedGroups.length),
    },
    distributions: {
      variable_group_size: countRows(variableGroups.map((group) => group.variable.length), 'group_size'),
      fixed_group_size: countRows(fixedGroups.map((group) => group.fixed.length), 'group_size'),
      variable_payload_length: countRows(variableEvents.map((event) => event.payload_length), 'payload_length'),
      fixed_payload: countRows(fixedEvents.map((event) => event.raw_payload_hex), 'payload_hex'),
      fixed_payload_group_presence: fixedPayloadGroupPresence,
    },
    variable_batch_raw_param: {
      zero_count: variableRawZeroCount,
      nonzero_count: variableEvents.length - variableRawZeroCount,
      zero_rate: round(variableRawZeroCount / variableEvents.length),
      distinct_count: new Set(variableEvents.map((event) => event.raw_param)).size,
    },
    per_replay: perReplay,
    validations: {
      inventory_count_match: inventoryPass,
      every_fixed_cluster_timestamp_has_exactly_twelve_rows: fixedTwelvePass,
      variable_timestamp_groups_are_at_least_99_8_percent_contained: variableKeyContainment > 0.998,
      every_paired_group_is_same_chunk_and_variable_before_fixed: orderingPass,
      variable_batch_raw_param_is_over_99_9_percent_zero: variableMostlyRawZero,
      direct_scalar_state_hypothesis_rejected: structuralBatchPass,
      all_pass: structuralBatchPass,
    },
    negative_evidence: {
      rejected_hypotheses: structuralBatchPass ? [
        'DIRECT_CURRENT_HP_SCALAR',
        'DIRECT_MAX_HP_SCALAR',
        'DIRECT_ARMOR_SCALAR',
        'DIRECT_MAGIC_RESIST_SCALAR',
        'DIRECT_RESOURCE_SCALAR',
        'INDEPENDENT_0x0199_ENTITY_EVENT',
      ] : [],
      reason: structuralBatchPass
        ? '0x0199 is a fixed twelve-row timestamp cluster and 0x004a is a variable-cardinality mostly raw-zero batch that precedes it in every paired group; neither behaves as an independent per-entity numeric scalar.'
        : 'The exact structural batching thresholds were not met.',
      semantic_claim: null,
    },
    route_decisions: [
      {
        packet_id: VARIABLE_BATCH_PACKET_ID,
        packet_discriminator: '0x004a',
        decision: structuralBatchPass ? 'REPURPOSE' : 'KEEP_CANDIDATE',
        hypothesis: 'VARIABLE_CARDINALITY_OPAQUE_TICK_BATCH_FAMILY',
        evidence_grade: 'CANDIDATE',
        evidence_scope: 'EXACT_FULL_FOUR_REPLAY_CORPUS',
        supersedes_previous_decision: true,
        semantic_claim: null,
        positive_anchor_count: multisetIntersection,
        counterexample_count: variableUnpairedRows,
        evidence_exhausted: false,
        next_required_evidence: nextRequiredEvidence,
      },
      {
        packet_id: FIXED_CLUSTER_PACKET_ID,
        packet_discriminator: '0x0199',
        decision: structuralBatchPass ? 'REPURPOSE' : 'KEEP_CANDIDATE',
        hypothesis: 'FIXED_TWELVE_ROW_PERIODIC_CLUSTER_AFTER_0x004a_BATCH',
        evidence_grade: 'CANDIDATE',
        evidence_scope: 'EXACT_FULL_FOUR_REPLAY_CORPUS',
        supersedes_previous_decision: true,
        semantic_claim: null,
        positive_anchor_count: fixedEvents.length,
        counterexample_count: fixedGroups.length - fixedTwelveGroups.length,
        evidence_exhausted: false,
        next_required_evidence: nextRequiredEvidence,
      },
    ],
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
  FIXED_CLUSTER_PACKET_ID,
  VARIABLE_BATCH_PACKET_ID,
  analyzeBatchPair,
};
