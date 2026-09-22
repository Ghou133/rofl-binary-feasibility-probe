'use strict';

const crypto = require('node:crypto');

const EXACT_BUILD = '16.16.805.0442';
const PREFIX_PACKET_ID = 0x00b9;
const PAYLOAD_PACKET_ID = 0x0092;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function percentile(sorted, fraction) {
  if (!sorted.length) return null;
  return sorted[Math.floor((sorted.length - 1) * fraction)];
}

function countRows(values, keyName) {
  const counts = new Map();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return [...counts.entries()]
    .map(([value, count]) => ({ [keyName]: value, count }))
    .sort((left, right) => right.count - left.count || String(left[keyName]).localeCompare(String(right[keyName])));
}

function eventKey(event) {
  return `${event.replay_sha256}:${event.replay_time_ms}:${event.raw_param >>> 0}`;
}

function analyzePairEvents(events, expectedCounts = null) {
  const selected = events.filter((row) => [PREFIX_PACKET_ID, PAYLOAD_PACKET_ID].includes(row.packet_id));
  const byKey = new Map();
  const byRoute = new Map([[PREFIX_PACKET_ID, []], [PAYLOAD_PACKET_ID, []]]);
  for (const event of selected) {
    invariant(event.replay_version === EXACT_BUILD, `wrong build ${event.replay_version}`);
    byRoute.get(event.packet_id).push(event);
    const key = eventKey(event);
    if (!byKey.has(key)) byKey.set(key, { prefix: [], payload: [] });
    byKey.get(key)[event.packet_id === PREFIX_PACKET_ID ? 'prefix' : 'payload'].push(event);
  }
  let pairedCount = 0;
  let prefixOnlyCount = 0;
  let payloadOnlyCount = 0;
  let multiplicityMismatchCount = 0;
  let sameChunkCount = 0;
  let prefixBeforePayloadCount = 0;
  let immediateFilteredPairCount = 0;
  const offsetDeltas = [];
  for (const group of byKey.values()) {
    group.prefix.sort((left, right) => left.chunk_index - right.chunk_index
      || left.decompressed_block_offset - right.decompressed_block_offset);
    group.payload.sort((left, right) => left.chunk_index - right.chunk_index
      || left.decompressed_block_offset - right.decompressed_block_offset);
    if (!group.prefix.length) payloadOnlyCount += group.payload.length;
    else if (!group.payload.length) prefixOnlyCount += group.prefix.length;
    if (group.prefix.length !== group.payload.length) multiplicityMismatchCount += 1;
    const pairCount = Math.min(group.prefix.length, group.payload.length);
    for (let index = 0; index < pairCount; index += 1) {
      const prefix = group.prefix[index];
      const payload = group.payload[index];
      pairedCount += 1;
      if (prefix.chunk_index === payload.chunk_index) {
        sameChunkCount += 1;
        const delta = payload.decompressed_block_offset - prefix.decompressed_block_offset;
        offsetDeltas.push(delta);
        if (delta > 0) prefixBeforePayloadCount += 1;
        if (delta === 7 || delta === 10) immediateFilteredPairCount += 1;
      }
    }
  }
  offsetDeltas.sort((left, right) => left - right);
  const prefixEvents = byRoute.get(PREFIX_PACKET_ID);
  const payloadEvents = byRoute.get(PAYLOAD_PACKET_ID);
  const prefixPayloads = prefixEvents.map((row) => row.raw_payload_hex);
  const payloadLengths = payloadEvents.map((row) => row.payload_length);
  const payloadPrefixes = payloadEvents.map((row) => row.raw_payload_hex.slice(0, 4));
  const prefixCount = prefixEvents.length;
  const payloadCount = payloadEvents.length;
  const inventoryPass = expectedCounts === null
    || (expectedCounts[PREFIX_PACKET_ID] === prefixCount && expectedCounts[PAYLOAD_PACKET_ID] === payloadCount);
  const oneToOnePass = prefixCount === payloadCount
    && pairedCount === prefixCount
    && prefixOnlyCount === 0
    && payloadOnlyCount === 0
    && multiplicityMismatchCount === 0;
  const orderingPass = oneToOnePass
    && sameChunkCount === pairedCount
    && prefixBeforePayloadCount === pairedCount;
  const constantPrefixPass = new Set(prefixPayloads).size === 1
    && prefixPayloads[0] === '91';
  const nextRequiredEvidence = [
    'Recover the shared runtime callback/registration/deserializer path for the pair.',
    'Decode the 0x0092 payload container and identify its entity/template operation with independent anchors.',
  ];
  return {
    schema: 'REPLICATION_ROUTE_PAIR_AUDIT_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    pair: {
      prefix_marker_route: '0x00b9',
      payload_route: '0x0092',
    },
    counts: {
      prefix_route_count: prefixCount,
      payload_route_count: payloadCount,
      exact_replay_time_raw_param_pair_count: pairedCount,
      prefix_only_count: prefixOnlyCount,
      payload_only_count: payloadOnlyCount,
      multiplicity_mismatch_group_count: multiplicityMismatchCount,
    },
    validations: {
      inventory_count_match: inventoryPass,
      exact_one_to_one_key_match: oneToOnePass,
      same_chunk_prefix_before_payload: orderingPass,
      prefix_payload_constant_0x91: constantPrefixPass,
      all_pass: inventoryPass && oneToOnePass && orderingPass && constantPrefixPass,
    },
    ordering: {
      same_chunk_count: sameChunkCount,
      prefix_before_payload_count: prefixBeforePayloadCount,
      offset_delta_min: offsetDeltas[0] ?? null,
      offset_delta_p50: percentile(offsetDeltas, 0.5),
      offset_delta_p90: percentile(offsetDeltas, 0.9),
      offset_delta_max: offsetDeltas[offsetDeltas.length - 1] ?? null,
      delta_7_or_10_count: immediateFilteredPairCount,
      delta_7_or_10_rate: pairedCount ? immediateFilteredPairCount / pairedCount : null,
    },
    prefix_marker_payload: {
      distinct_payload_count: new Set(prefixPayloads).size,
      sha256: prefixPayloads.length
        ? crypto.createHash('sha256').update(Buffer.from(prefixPayloads[0], 'hex')).digest('hex')
        : null,
      value_hex: prefixPayloads.length ? prefixPayloads[0] : null,
    },
    paired_payload_route: {
      length_distribution: countRows(payloadLengths, 'payload_length'),
      prefix2_distribution: countRows(payloadPrefixes, 'prefix2_hex').slice(0, 32),
    },
    decision: {
      route_0x00b9: 'REPURPOSE_AS_STRUCTURAL_PREFIX_MARKER_CANDIDATE_FOR_0x0092_FAMILY',
      route_0x0092: 'KEEP_AS_ENTITY_SCOPED_OPAQUE_PAYLOAD_FAMILY_CANDIDATE',
      direct_numeric_state_hypothesis: 'REJECT',
      semantic_claim: null,
      evidence_grade: 'CANDIDATE',
      evidence_exhausted: false,
      next_required_evidence: nextRequiredEvidence,
    },
    route_decisions: [
      {
        packet_id: PREFIX_PACKET_ID,
        packet_discriminator: '0x00b9',
        decision: 'REPURPOSE',
        hypothesis: 'STRUCTURAL_PREFIX_MARKER_FOR_0x0092_FAMILY',
        evidence_grade: 'CANDIDATE',
        semantic_claim: null,
        evidence_scope: 'EXACT_FULL_FOUR_REPLAY_CORPUS',
        supersedes_previous_decision: true,
        positive_anchor_count: pairedCount,
        counterexample_count: prefixOnlyCount + multiplicityMismatchCount,
        evidence_exhausted: false,
        next_required_evidence: nextRequiredEvidence,
      },
      {
        packet_id: PAYLOAD_PACKET_ID,
        packet_discriminator: '0x0092',
        decision: 'KEEP_CANDIDATE',
        hypothesis: 'ENTITY_SCOPED_OPAQUE_REPLICATION_PAYLOAD_FAMILY',
        evidence_grade: 'CANDIDATE',
        semantic_claim: null,
        evidence_scope: 'EXACT_FULL_FOUR_REPLAY_CORPUS',
        supersedes_previous_decision: true,
        positive_anchor_count: pairedCount,
        counterexample_count: payloadOnlyCount + multiplicityMismatchCount,
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
  PAYLOAD_PACKET_ID,
  PREFIX_PACKET_ID,
  analyzePairEvents,
  eventKey,
};
