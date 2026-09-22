'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('./rofl');

const EXACT_BUILD = '16.16.805.0442';
const RUNTIME_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const ROUTE_IDS = Object.freeze([
  0x0255, 0x046d, 0x038d, 0x0274, 0x023f, 0x018c,
  0x01aa, 0x0178, 0x01c8, 0x02f2, 0x0232, 0x0008,
]);
const ROUTE_SET = new Set(ROUTE_IDS);
const SAFE_REPLAYS = Object.freeze({
  'HN1-11196935467.rofl': 'd3f3b019b70bcf8650934e8e6350d6ae1e3def28b52fb8225cade755a415f862',
  'HN1-11200496018.rofl': '2e6cee94aed783fa62606333fac7e21295b80f5c03fa5617cd38f6f75fdfe47d',
  'HN1-11201899481.rofl': '18ae8e43f54604b288a93aa35d13722a159e5ffea548adfa9e88bbf0518e5d9f',
  'HN1-11209393761.rofl': '9dac6a352dc5a0af8bdd5c3ab0c16cddf310ca56817ce252fcb363a82d0b7f96',
});

const ANCHOR_FAMILIES = Object.freeze({
  hero_path: Object.freeze([0x00f6]),
  verified_damage: Object.freeze([0x017f]),
  hero_death: Object.freeze([0x0074, 0x0112]),
  cast_spell: Object.freeze([0x01cf]),
  buff: Object.freeze([0x0123, 0x0326, 0x041f, 0x043c, 0x045b]),
  item: Object.freeze([0x005a, 0x0064, 0x006c, 0x01e8, 0x02ea, 0x0310, 0x0311]),
  scoreboard: Object.freeze([0x010c]),
});
const ANCHOR_BY_ID = new Map();
for (const [family, packetIds] of Object.entries(ANCHOR_FAMILIES)) {
  for (const packetId of packetIds) {
    if (!ANCHOR_BY_ID.has(packetId)) ANCHOR_BY_ID.set(packetId, []);
    ANCHOR_BY_ID.get(packetId).push(family);
  }
}

const ROUTE_CONFIG = Object.freeze({
  '0x0255': Object.freeze({
    decision: 'KEEP_CANDIDATE', domain: 'unmapped_entity_scoped_protected_record',
    hypothesis: 'SMALL_OPTIONAL_BRANCH_ENTITY_SCOPED_CARRIER_CANDIDATE',
    boundary: 'One- and six-byte wire branches do not identify a state bit, spell, combat scalar, or entity lifecycle operation.',
  }),
  '0x046d': Object.freeze({
    decision: 'KEEP_CANDIDATE', domain: 'unmapped_entity_scoped_protected_record',
    hypothesis: 'VARIABLE_SHORT_ENTITY_SCOPED_RECORD_CANDIDATE',
    boundary: 'Variable 12-17 byte payloads and a 40-byte packet object remain structural evidence only.',
  }),
  '0x038d': Object.freeze({
    decision: 'KEEP_CANDIDATE', domain: 'unmapped_entity_scoped_protected_record',
    hypothesis: 'SMALL_BITPACK_ENTITY_SCOPED_CARRIER_CANDIDATE',
    boundary: 'The one/two-byte branches do not name their protected flags or establish gameplay state.',
  }),
  '0x0274': Object.freeze({
    decision: 'KEEP_CANDIDATE', domain: 'unmapped_entity_scoped_protected_record',
    hypothesis: 'FIXED_WIRE_ENTITY_SCOPED_RECORD_CANDIDATE',
    boundary: 'A fixed 65-byte wire record is not a field dictionary or semantic snapshot contract.',
  }),
  '0x023f': Object.freeze({
    decision: 'KEEP_CANDIDATE', domain: 'unmapped_entity_scoped_protected_record',
    hypothesis: 'SMALL_BITPACK_ENTITY_SCOPED_CARRIER_CANDIDATE',
    boundary: 'The shared size family and protected branches do not identify a spell, buff, visibility, or combat role.',
  }),
  '0x018c': Object.freeze({
    decision: 'REPURPOSE', domain: 'generic_empty_payload_protocol_signal',
    hypothesis: 'SHARED_EMPTY_PAYLOAD_PROTOCOL_SIGNAL',
    boundary: 'The exact vtable/deserializer is shared by named leave-visibility and destroy-client-missile routes; empty-payload codec identity cannot select either semantic.',
  }),
  '0x01aa': Object.freeze({
    decision: 'KEEP_CANDIDATE', domain: 'unmapped_entity_scoped_protected_record',
    hypothesis: 'LARGE_VARIABLE_COMPOSITE_ENTITY_RECORD_CANDIDATE',
    boundary: 'The 200-byte object and 87-135 byte wire branches expose no verified field roles or owner type.',
  }),
  '0x0178': Object.freeze({
    decision: 'KEEP_CANDIDATE', domain: 'hero_bound_wide_snapshot_candidate',
    hypothesis: 'HERO_BOUND_WIDE_KEYFRAME_SNAPSHOT_CANDIDATE',
    boundary: 'Champion binding and a prior field-behavior profile do not establish HP, max HP, armor, MR, resource, or any other field role; the prior profile has no typed schema or independent anchors.',
  }),
  '0x01c8': Object.freeze({
    decision: 'KEEP_CANDIDATE', domain: 'hero_bound_wide_snapshot_candidate',
    hypothesis: 'HERO_OR_GLOBAL_VARIABLE_COMPOSITE_RECORD_CANDIDATE',
    boundary: 'Champion-like raw parameters and variable payloads remain insufficient for a hero-state or gameplay-field promotion.',
  }),
  '0x02f2': Object.freeze({
    decision: 'KEEP_CANDIDATE', domain: 'unmapped_global_protocol_record',
    hypothesis: 'HIGH_FREQUENCY_GLOBAL_VARIABLE_RECORD_CANDIDATE',
    boundary: 'Raw-param zero and recurrence do not identify time, telemetry, input, UI, or gameplay state.',
  }),
  '0x0232': Object.freeze({
    decision: 'KEEP_CANDIDATE', domain: 'unmapped_global_protocol_record',
    hypothesis: 'GLOBAL_SMALL_BRANCH_RECORD_CANDIDATE',
    boundary: 'Three/seven-byte global branches have no verified field or callback-owner semantics.',
  }),
  '0x0008': Object.freeze({
    decision: 'KEEP_CANDIDATE', domain: 'unmapped_global_protocol_record',
    hypothesis: 'GLOBAL_RECURRING_VARIABLE_RECORD_CANDIDATE',
    boundary: 'Packet ID 8 is also a ubiquitous machine-code immediate, so generic immediate matches cannot be promoted to a packet-specific receive callback.',
  }),
});

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function rejectProtectedPath(value) {
  const resolved = path.resolve(value);
  if (resolved.toLowerCase().includes('holdout')) {
    throw new Error(`protected Holdout path is forbidden: ${resolved}`);
  }
  return resolved;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sha256File(filePath) {
  return sha256(fs.readFileSync(rejectProtectedPath(filePath)));
}

function packetHex(packetId) {
  return `0x${Number(packetId).toString(16).padStart(4, '0')}`;
}

function rvaHex(rva) {
  return `0x${Number(rva).toString(16).padStart(8, '0')}`;
}

function round(value, digits = 8) {
  if (!Number.isFinite(value)) return null;
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}

function quantile(values, fraction) {
  if (!values.length) return null;
  const ordered = [...values].sort((left, right) => left - right);
  const position = (ordered.length - 1) * fraction;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return ordered[lower];
  return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower);
}

function increment(map, key, amount = 1) {
  const normalized = String(key);
  map.set(normalized, (map.get(normalized) || 0) + amount);
}

function sortedCounter(map, keyName = 'value', limit = null) {
  const rows = [...map.entries()]
    .map(([key, count]) => ({ [keyName]: /^-?\d+$/.test(key) ? Number(key) : key, count }))
    .sort((left, right) => right.count - left.count
      || String(left[keyName]).localeCompare(String(right[keyName])));
  return limit === null ? rows : rows.slice(0, limit);
}

function rawParamClass(value) {
  const numeric = Number(value) >>> 0;
  if (numeric === 0) return 'ZERO';
  if (numeric >= 0x400000ae && numeric <= 0x400000b7) return 'CANONICAL_HERO_NETWORK_ID';
  if (numeric >= 0x40000000 && numeric <= 0x4fffffff) return 'BROAD_NETWORK_ID';
  return 'OTHER_NONZERO';
}

function newRouteState(packetId) {
  return {
    packet_id: packetId,
    count: 0,
    events: [],
    per_replay: new Map(),
    streams: new Map(),
    lengths: new Map(),
    raw_params: new Map(),
    raw_param_classes: new Map(),
    payloads: new Map(),
    previous: new Map(),
    next: new Map(),
    previous_same_time: new Map(),
    next_same_time: new Map(),
    pending: null,
  };
}

function distinctPayloadRow(event, payload) {
  return {
    schema: 'RESIDUAL_P3_DISTINCT_PAYLOAD_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    replay_version: EXACT_BUILD,
    packet_id: event.packet_id,
    packet_discriminator: packetHex(event.packet_id),
    replay_sha256: event.replay_sha256,
    replay_time_ms: event.time,
    occurrence_index: event.occurrence_index,
    raw_param: event.raw_param,
    chunk_stream: event.stream,
    payload_length: payload.length,
    raw_payload_hex: payload.toString('hex'),
    raw_payload_sha256: event.payload_sha256,
    occurrence_count: 1,
    replay_occurrence_counts: { [event.replay_sha256]: 1 },
    stream_occurrence_counts: { [event.stream]: 1 },
    _raw_param_counts: new Map([[String(event.raw_param), 1]]),
  };
}

function updateDistinctPayload(row, event) {
  row.occurrence_count += 1;
  row.replay_occurrence_counts[event.replay_sha256] =
    (row.replay_occurrence_counts[event.replay_sha256] || 0) + 1;
  row.stream_occurrence_counts[event.stream] =
    (row.stream_occurrence_counts[event.stream] || 0) + 1;
  increment(row._raw_param_counts, event.raw_param);
}

function finalizeDistinctPayload(row) {
  row.raw_param_distinct_count = row._raw_param_counts.size;
  row.raw_param_top_values = sortedCounter(row._raw_param_counts, 'raw_param', 24);
  delete row._raw_param_counts;
  row.replay_occurrence_counts = Object.fromEntries(
    Object.entries(row.replay_occurrence_counts).sort(([left], [right]) => left.localeCompare(right)),
  );
  row.stream_occurrence_counts = Object.fromEntries(
    Object.entries(row.stream_occurrence_counts).sort(([left], [right]) => left.localeCompare(right)),
  );
  return row;
}

function collectReplay(replayPath, states, anchors) {
  const source = rejectProtectedPath(replayPath);
  const basename = path.basename(source);
  invariant(Object.hasOwn(SAFE_REPLAYS, basename), `replay outside explicit safe allowlist: ${basename}`);
  const replay = parseReplayFile(source);
  invariant(replay.source_sha256 === SAFE_REPLAYS[basename], `safe replay SHA-256 mismatch: ${basename}`);
  invariant(replay.header.version === EXACT_BUILD, `safe replay exact-build mismatch: ${basename}`);
  let previous = null;
  let occurrenceIndex = 0;
  const walk = walkBlocks(replay, (block, chunk) => {
    for (const state of states.values()) {
      if (!state.pending) continue;
      increment(state.next, packetHex(block.packet_id));
      increment(state.next_same_time,
        state.pending.time === block.timestamp_ms ? packetHex(block.packet_id) : 'DIFFERENT_TIMESTAMP');
      state.pending = null;
    }
    for (const family of ANCHOR_BY_ID.get(block.packet_id) || []) {
      const byReplay = anchors.get(family);
      if (!byReplay.has(replay.source_sha256)) byReplay.set(replay.source_sha256, []);
      byReplay.get(replay.source_sha256).push({
        time: block.timestamp_ms,
        raw_param: block.param >>> 0,
        packet_id: block.packet_id,
      });
    }
    const state = states.get(block.packet_id);
    if (state) {
      const payloadHash = sha256(block.payload);
      const event = {
        packet_id: block.packet_id,
        replay_sha256: replay.source_sha256,
        time: block.timestamp_ms,
        raw_param: block.param >>> 0,
        stream: chunk.stream,
        payload_length: block.payload_length,
        payload_sha256: payloadHash,
        occurrence_index: occurrenceIndex,
      };
      state.count += 1;
      state.events.push(event);
      increment(state.per_replay, event.replay_sha256);
      increment(state.streams, event.stream);
      increment(state.lengths, event.payload_length);
      increment(state.raw_params, event.raw_param);
      increment(state.raw_param_classes, rawParamClass(event.raw_param));
      increment(state.previous, previous ? packetHex(previous.packet_id) : 'START');
      increment(state.previous_same_time,
        previous && previous.time === event.time ? packetHex(previous.packet_id) : 'DIFFERENT_TIMESTAMP');
      if (!state.payloads.has(payloadHash)) {
        state.payloads.set(payloadHash, distinctPayloadRow(event, block.payload));
      } else {
        updateDistinctPayload(state.payloads.get(payloadHash), event);
      }
      state.pending = event;
    }
    previous = { packet_id: block.packet_id, time: block.timestamp_ms };
    occurrenceIndex += 1;
  }, { includeStreams: [1, 2, 3], strict: true });
  invariant(walk.errors.length === 0, `strict replay walk failed: ${basename}`);
  for (const state of states.values()) {
    if (!state.pending) continue;
    increment(state.next, 'END');
    increment(state.next_same_time, 'DIFFERENT_TIMESTAMP');
    state.pending = null;
  }
  return {
    path: source,
    basename,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header.version,
    block_count: walk.block_count,
  };
}

function nearestEvent(events, time) {
  if (!events || !events.length) return null;
  let low = 0;
  let high = events.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (events[middle].time < time) low = middle + 1;
    else high = middle;
  }
  const candidates = [];
  if (low < events.length) candidates.push(events[low]);
  if (low > 0) candidates.push(events[low - 1]);
  return candidates.sort((left, right) => Math.abs(left.time - time) - Math.abs(right.time - time)
    || left.time - right.time)[0];
}

function anchorCorrelation(events, byReplay) {
  const deltas = [];
  let exact = 0;
  let within10 = 0;
  let within50 = 0;
  let within500 = 0;
  let sameParam10 = 0;
  let shifted137 = 0;
  let shifted997 = 0;
  const farExamples = [];
  const cotimedParamMismatchExamples = [];
  for (const event of events) {
    const candidates = byReplay.get(event.replay_sha256) || [];
    const nearest = nearestEvent(candidates, event.time);
    if (!nearest) continue;
    const delta = Math.abs(nearest.time - event.time);
    deltas.push(delta);
    exact += Number(delta === 0);
    within10 += Number(delta <= 10);
    within50 += Number(delta <= 50);
    within500 += Number(delta <= 500);
    sameParam10 += Number(delta <= 10 && nearest.raw_param === event.raw_param);
    const control137 = nearestEvent(candidates, event.time + 137);
    const control997 = nearestEvent(candidates, event.time + 997);
    shifted137 += Number(control137 && Math.abs(control137.time - event.time - 137) <= 10);
    shifted997 += Number(control997 && Math.abs(control997.time - event.time - 997) <= 10);
    if (delta > 500 && farExamples.length < 12) {
      farExamples.push({ replay_sha256: event.replay_sha256, replay_time_ms: event.time,
        raw_param: event.raw_param, nearest_anchor_delta_ms: delta });
    }
    if (delta === 0 && nearest.raw_param !== event.raw_param && cotimedParamMismatchExamples.length < 12) {
      cotimedParamMismatchExamples.push({ replay_sha256: event.replay_sha256,
        replay_time_ms: event.time, raw_param: event.raw_param,
        anchor_raw_param: nearest.raw_param });
    }
  }
  const eligible = deltas.length;
  return {
    eligible_count: eligible,
    exact_time_count: exact,
    exact_time_rate: round(exact / Math.max(1, eligible)),
    within_10ms_count: within10,
    within_10ms_rate: round(within10 / Math.max(1, eligible)),
    within_50ms_count: within50,
    within_500ms_count: within500,
    far_over_500ms_count: eligible - within500,
    within_10ms_same_raw_param_count: sameParam10,
    nearest_delta_p50_ms: quantile(deltas, 0.5),
    nearest_delta_p90_ms: quantile(deltas, 0.9),
    shifted_137ms_within_10ms_count: shifted137,
    shifted_997ms_within_10ms_count: shifted997,
    enrichment_over_137ms_control: round((within10 + 1) / (shifted137 + 1)),
    enrichment_over_997ms_control: round((within10 + 1) / (shifted997 + 1)),
    far_counterexamples: farExamples,
    cotimed_raw_param_mismatch_examples: cotimedParamMismatchExamples,
    semantic_claim: null,
  };
}

function temporalSummary(events) {
  const byReplay = new Map();
  const timestampGroups = new Map();
  for (const event of events) {
    if (!byReplay.has(event.replay_sha256)) byReplay.set(event.replay_sha256, []);
    byReplay.get(event.replay_sha256).push(event);
    increment(timestampGroups, `${event.replay_sha256}:${event.time}`);
  }
  const deltas = [];
  let sameTime = 0;
  for (const rows of byReplay.values()) {
    rows.sort((left, right) => left.time - right.time || left.occurrence_index - right.occurrence_index);
    for (let index = 1; index < rows.length; index += 1) {
      const delta = rows[index].time - rows[index - 1].time;
      deltas.push(delta);
      sameTime += Number(delta === 0);
    }
  }
  const sizes = [...timestampGroups.values()];
  return {
    timestamp_group_count: timestampGroups.size,
    group_size_min: sizes.length ? Math.min(...sizes) : null,
    group_size_p50: quantile(sizes, 0.5),
    group_size_p90: quantile(sizes, 0.9),
    group_size_max: sizes.length ? Math.max(...sizes) : null,
    delta_p50_ms: quantile(deltas, 0.5),
    delta_p90_ms: quantile(deltas, 0.9),
    delta_p99_ms: quantile(deltas, 0.99),
    same_timestamp_transition_rate: round(sameTime / Math.max(1, deltas.length)),
  };
}

function summarizeRoute(state, anchors) {
  const payloadRows = [...state.payloads.values()]
    .map(finalizeDistinctPayload)
    .sort((left, right) => left.payload_length - right.payload_length
      || left.raw_payload_sha256.localeCompare(right.raw_payload_sha256));
  const occurrenceWeight = payloadRows.reduce((sum, row) => sum + row.occurrence_count, 0);
  const branches = new Map();
  for (const row of payloadRows) {
    const key = String(row.payload_length);
    if (!branches.has(key)) branches.set(key, { count: 0, distinct: 0 });
    branches.get(key).count += row.occurrence_count;
    branches.get(key).distinct += 1;
  }
  const correlations = {};
  for (const [family, byReplay] of anchors) correlations[family] = anchorCorrelation(state.events, byReplay);
  return {
    packet_id: state.packet_id,
    packet_discriminator: packetHex(state.packet_id),
    count: state.count,
    per_replay_count: sortedCounter(state.per_replay, 'replay_sha256'),
    stream_distribution: sortedCounter(state.streams, 'stream'),
    payload: {
      length_distribution: sortedCounter(state.lengths, 'payload_length'),
      distinct_payload_sha256_count: payloadRows.length,
      occurrence_weight_sum: occurrenceWeight,
      occurrence_weight_conserved: occurrenceWeight === state.count,
      branches: [...branches.entries()].map(([payloadLength, value]) => ({
        payload_length: Number(payloadLength), count: value.count,
        distinct_payload_count: value.distinct,
      })).sort((left, right) => left.payload_length - right.payload_length),
    },
    raw_param: {
      distinct_count: state.raw_params.size,
      class_distribution: sortedCounter(state.raw_param_classes, 'class'),
      top_values: sortedCounter(state.raw_params, 'raw_param', 24),
    },
    temporal: temporalSummary(state.events),
    immediate_neighbors: {
      previous: sortedCounter(state.previous, 'packet_discriminator', 24),
      next: sortedCounter(state.next, 'packet_discriminator', 24),
      previous_same_timestamp: sortedCounter(state.previous_same_time, 'packet_discriminator', 24),
      next_same_timestamp: sortedCounter(state.next_same_time, 'packet_discriminator', 24),
    },
    anchor_correlations_with_shifted_controls: correlations,
    distinct_payload_rows: payloadRows,
  };
}

function crossRouteMatrix(states) {
  const indexes = new Map();
  for (const [packetId, state] of states) {
    const times = new Map();
    for (const event of state.events) {
      const key = `${event.replay_sha256}:${event.time}`;
      if (!times.has(key)) times.set(key, new Set());
      times.get(key).add(event.raw_param);
    }
    indexes.set(packetId, times);
  }
  const rows = [];
  for (const [sourceId, source] of states) {
    for (const [targetId, targetIndex] of indexes) {
      if (sourceId === targetId) continue;
      let exact = 0;
      let exactParam = 0;
      for (const event of source.events) {
        const params = targetIndex.get(`${event.replay_sha256}:${event.time}`);
        if (!params) continue;
        exact += 1;
        exactParam += Number(params.has(event.raw_param));
      }
      if (!exact) continue;
      rows.push({
        source_route: packetHex(sourceId), target_route: packetHex(targetId),
        source_count: source.count, exact_time_count: exact,
        exact_time_rate: round(exact / Math.max(1, source.count)),
        exact_time_same_raw_param_count: exactParam,
        exact_time_same_raw_param_rate: round(exactParam / Math.max(1, source.count)),
      });
    }
  }
  return rows.sort((left, right) => right.exact_time_same_raw_param_rate - left.exact_time_same_raw_param_rate
    || right.exact_time_rate - left.exact_time_rate
    || left.source_route.localeCompare(right.source_route)
    || left.target_route.localeCompare(right.target_route));
}

function collectEvidence(replayPaths) {
  invariant(Array.isArray(replayPaths) && replayPaths.length === 4,
    'exactly four explicit safe replays are required');
  const states = new Map(ROUTE_IDS.map((packetId) => [packetId, newRouteState(packetId)]));
  const anchors = new Map(Object.keys(ANCHOR_FAMILIES).map((family) => [family, new Map()]));
  const replays = replayPaths.map((replayPath) => collectReplay(replayPath, states, anchors));
  invariant(new Set(replays.map((row) => row.replay_sha256)).size === 4,
    'safe replay inputs must be distinct');
  for (const byReplay of anchors.values()) {
    for (const rows of byReplay.values()) rows.sort((left, right) => left.time - right.time);
  }
  const routes = Object.fromEntries(ROUTE_IDS.map((packetId) => {
    const result = summarizeRoute(states.get(packetId), anchors);
    return [packetHex(packetId), result];
  }));
  const distinctPayloadRows = ROUTE_IDS.flatMap((packetId) => routes[packetHex(packetId)].distinct_payload_rows)
    .sort((left, right) => left.packet_id - right.packet_id
      || left.payload_length - right.payload_length
      || left.raw_payload_sha256.localeCompare(right.raw_payload_sha256));
  for (const route of Object.values(routes)) delete route.distinct_payload_rows;
  const anchorCounts = {};
  for (const [family, byReplay] of anchors) {
    anchorCounts[family] = [...byReplay.values()].reduce((sum, rows) => sum + rows.length, 0);
  }
  const canonical = {
    replays: replays.map(({ basename, replay_sha256: replaySha256, replay_version: replayVersion,
      block_count: blockCount }) => ({ basename, replay_sha256: replaySha256,
      replay_version: replayVersion, block_count: blockCount })),
    routes,
    anchor_counts: anchorCounts,
    cross_route_exact_time_matrix: crossRouteMatrix(states),
    distinct_payload_rows: distinctPayloadRows,
  };
  return {
    ...canonical,
    target_row_count: Object.values(routes).reduce((sum, route) => sum + route.count, 0),
    distinct_payload_row_count: distinctPayloadRows.length,
    deterministic_digest: sha256(Buffer.from(JSON.stringify(canonical), 'utf8')),
  };
}

function buildProfiles(staticRecovery) {
  return ROUTE_IDS.map((packetId) => {
    const packetType = packetHex(packetId);
    const runtime = staticRecovery.routes[packetType];
    invariant(runtime?.factory_chain, `static recovery missing ${packetType}`);
    const factory = runtime.factory_chain;
    return {
      schema: 'RESIDUAL_P3_EXACT_NATIVE_PROFILE_V2',
      schema_version: 2,
      exact_build: EXACT_BUILD,
      exact_runtime_image_sha256: RUNTIME_SHA256,
      static_identity: runtime,
      profile: {
        id: `residual-p3-${packetType.slice(2)}-exact-runtime-v2`,
        client_opcode: packetId,
        constructor_rva: Number(factory.constructor_rva),
        deserialize_rva: Number(factory.deserializer_rva),
        object_size: Number(factory.object_size),
        fields: [],
      },
    };
  });
}

function entropy(counter, total) {
  let result = 0;
  for (const count of counter.values()) {
    const probability = count / total;
    result -= probability * Math.log2(probability);
  }
  return round(result);
}

function storageLaneProfiles(rows, objectSize) {
  const result = [];
  for (let offset = 0x10; offset < objectSize; offset += 1) {
    const values = new Map();
    let weight = 0;
    for (const row of rows) {
      if (row.emulation_error || !row.object_hex) continue;
      const object = Buffer.from(row.object_hex, 'hex');
      if (offset >= object.length) continue;
      const occurrenceWeight = Number(row.occurrence_count || 1);
      increment(values, object[offset], occurrenceWeight);
      weight += occurrenceWeight;
    }
    if (!weight) continue;
    result.push({
      object_offset: rvaHex(offset),
      weighted_observation_count: weight,
      distinct_storage_value_count: values.size,
      entropy_bits: entropy(values, weight),
      top_storage_values: sortedCounter(values, 'value_u8', 8),
      semantic_role: null,
    });
  }
  return result;
}

function classifyNativeFailure(message) {
  const text = String(message || 'UNKNOWN_NATIVE_FAILURE');
  const rip = text.match(/rip=(0x[0-9a-f]+)/i)?.[1] || null;
  const address = text.match(/address=(0x[0-9a-f]+)/i)?.[1]
    || text.match(/at (0x[0-9a-f]+)/i)?.[1] || null;
  const external = /invalid memory access|read_unmapped|write_unmapped|unmapped|GS:|TLS|heap|UC_ERR/i.test(text);
  return {
    class: external ? 'EXTERNAL_RUNTIME_HEAP_TLS_OR_PROCESS_STATE' : 'UNCLASSIFIED_NATIVE_FAILURE',
    fault_rip: rip,
    missing_address: address,
    message: text,
  };
}

function analyzeNative(nativeRowsByRoute, evidence, staticRecovery) {
  const routes = {};
  for (const packetId of ROUTE_IDS) {
    const packetType = packetHex(packetId);
    const rows = nativeRowsByRoute[packetType] || [];
    const raw = evidence.routes[packetType];
    const objectSize = staticRecovery.routes[packetType].factory_chain.object_size;
    const attemptedWeight = rows.reduce((sum, row) => sum + Number(row.occurrence_count || 1), 0);
    const successful = rows.filter((row) => !row.emulation_error
      && row.deserialize_return_al !== 0 && row.fully_consumed === true
      && row.opcode_matches_profile === true);
    const successfulWeight = successful.reduce((sum, row) => sum + Number(row.occurrence_count || 1), 0);
    const failed = rows.filter((row) => !successful.includes(row));
    const failedWeight = failed.reduce((sum, row) => sum + Number(row.occurrence_count || 1), 0);
    const failureCounter = new Map();
    for (const row of failed) {
      const classified = classifyNativeFailure(row.emulation_error
        || `deserialize_return_al=${row.deserialize_return_al};fully_consumed=${row.fully_consumed}`);
      const key = JSON.stringify(classified);
      failureCounter.set(key, (failureCounter.get(key) || 0) + Number(row.occurrence_count || 1));
    }
    const failureClasses = [...failureCounter.entries()].map(([key, occurrenceWeight]) => ({
      ...JSON.parse(key), occurrence_weight: occurrenceWeight,
    })).sort((left, right) => right.occurrence_weight - left.occurrence_weight);
    routes[packetType] = {
      distinct_payload_attempt_count: rows.length,
      expected_distinct_payload_count: raw.payload.distinct_payload_sha256_count,
      all_distinct_payloads_attempted: rows.length === raw.payload.distinct_payload_sha256_count,
      full_inventory_occurrence_weight: raw.count,
      attempted_occurrence_weight: attemptedWeight,
      successful_full_consume_distinct_count: successful.length,
      successful_full_consume_occurrence_weight: successfulWeight,
      conserved_failure_distinct_count: failed.length,
      conserved_failure_occurrence_weight: failedWeight,
      full_occurrence_weight_conserved: attemptedWeight === raw.count
        && successfulWeight + failedWeight === raw.count,
      successful_full_consume_rate_by_occurrence_weight: round(successfulWeight / Math.max(1, raw.count)),
      all_failures_external_runtime_state: failed.length === 0
        || failureClasses.every((row) => row.class === 'EXTERNAL_RUNTIME_HEAP_TLS_OR_PROCESS_STATE'),
      failure_classes: failureClasses,
      failure_examples: failed.slice(0, 12).map((row) => ({
        raw_payload_sha256: row.raw_payload_sha256,
        payload_length: row.payload_length,
        occurrence_count: row.occurrence_count,
        emulation_error: row.emulation_error || null,
        deserialize_return_al: row.deserialize_return_al ?? null,
        fully_consumed: row.fully_consumed ?? null,
      })),
      protected_object_storage_lanes: storageLaneProfiles(successful, objectSize),
    };
  }
  return { routes };
}

function strongestPair(matrix, sourceRoute) {
  return matrix.find((row) => row.source_route === sourceRoute) || null;
}

function externalEvidence(runtime, native, config) {
  const pieces = [];
  if (runtime.receive_identity.status !== 'STATIC_CALLBACK_RTTI_AND_RECEIVE_TARGET_VERIFIED') {
    pieces.push('an authorized exact-build live heap capture containing the packet-specific callback-tree node and receive owner');
  }
  if (native.conserved_failure_occurrence_weight > 0) {
    pieces.push('the exact process heap/TLS/protection state spanning every recorded native fault RIP/address');
  }
  pieces.push(config.domain === 'hero_bound_wide_snapshot_candidate'
    ? 'a controlled one-property-at-a-time exact-build state oracle with plaintext field labels'
    : 'a controlled exact-build producer/consumer trace with a plaintext business-state oracle');
  return `${pieces.join(', ')}.`;
}

function buildDecisions(evidence, staticRecovery, nativeAnalysis, priorProfileBoundary) {
  const routeDecisions = ROUTE_IDS.map((packetId) => {
    const packetType = packetHex(packetId);
    const raw = evidence.routes[packetType];
    const runtime = staticRecovery.routes[packetType];
    const native = nativeAnalysis.routes[packetType];
    const config = ROUTE_CONFIG[packetType];
    invariant(config, `missing route decision config ${packetType}`);
    const localComplete = runtime.validations.all_factory_checks_pass
      && runtime.receive_identity.bounded_static_surfaces_exhausted
      && raw.payload.occurrence_weight_conserved
      && native.all_distinct_payloads_attempted
      && native.full_occurrence_weight_conserved
      && native.all_failures_external_runtime_state
      && (packetId !== 0x0178 || priorProfileBoundary?.semantic_claim === null);
    const requiredEvidence = externalEvidence(runtime, native, config);
    return {
      decision_id: `ROUTE_${packetType}_RESIDUAL_P3_WAVE_V2`,
      packet_id: packetId,
      packet_discriminator: packetType,
      decision: config.decision,
      domain: config.domain,
      capability: `EXACT_ROUTE_${packetType.slice(2).toUpperCase()}_STRUCTURAL_IDENTITY`,
      hypothesis: config.hypothesis,
      semantic_claim: null,
      structural_claim: `Exact-build ${runtime.factory_chain.object_size}-byte packet object with closed factory/constructor/vtable/deserializer identity; gameplay field roles remain unpublished.`,
      evidence_grade: 'VERIFIED_DIRECT_EXACT_BUILD_STRUCTURE_WITH_FULL_SAFE_INVENTORY',
      positive_anchor_count: raw.count,
      counterexample_count: raw.anchor_correlations_with_shifted_controls.verified_damage.far_over_500ms_count,
      counterexample: config.boundary,
      strongest_exact_time_route_relationship: strongestPair(
        evidence.cross_route_exact_time_matrix, packetType,
      ),
      exact_shared_codec_counterexamples: runtime.shared_codec_routes,
      prior_0178_profile_boundary: packetId === 0x0178 ? priorProfileBoundary : null,
      actual_reverse_engineering_executed: true,
      reverse_engineering_steps: [
        'EXPLICIT_SAFE_LATEST_FOUR_FULL_ROUTE_WALK',
        'ALL_DISTINCT_PAYLOAD_HASHES_WITH_OCCURRENCE_WEIGHT_CONSERVATION',
        'EXACT_FACTORY_CASE_ALLOCATION_CONSTRUCTOR_VTABLE_DESERIALIZER_RECOVERY',
        'MAKEFUNCTION_CALLBACK_RTTI_MAP_AND_FULL_PDATA_IMMEDIATE_REFERENCE_SCAN',
        'DOUBLE_EXACT_NATIVE_CONSTRUCTOR_PLUS_DESERIALIZER_EMULATION',
        'STREAM_ENTITY_TIME_NEIGHBOR_CROSS_ROUTE_AND_ANCHOR_COUNTEREXAMPLES',
      ],
      evidence_exhausted: localComplete,
      evidence_exhausted_scope: 'PINNED_EXACT_RUNTIME_EXPLICIT_SAFE_LATEST_FOUR_ALL_OCCURRENCES_AND_ALL_DISTINCT_PAYLOADS',
      exhaustion_basis: localComplete
        ? 'ALL_CURRENT_SAFE_LOCAL_STATIC_RAW_TEMPORAL_PROFILE_AND_NATIVE_HYPOTHESES_EXECUTED'
        : 'LOCAL_SURFACE_VALIDATION_REMAINS_INCOMPLETE',
      remaining_local_executable_steps: localComplete ? [] : [
        'Resolve the local static/native/prior-profile validation that remains false in this report.',
      ],
      actionable_hypotheses: localComplete ? [] : [
        'Repeat the failed local surface after correcting its exact-build validation.',
      ],
      next_required_evidence: localComplete ? [requiredEvidence] : [
        'Complete the reported local validation before declaring this route exhausted.',
      ],
      external_only_gate: {
        required: localComplete,
        local_safe_evidence_remaining: !localComplete,
        required_evidence: localComplete ? requiredEvidence : null,
      },
    };
  });
  const capabilityDecisions = routeDecisions.map((route) => ({
    decision_id: `CAPABILITY_${route.capability}_V2`,
    capability: route.capability,
    domain: route.domain,
    routes: [route.packet_discriminator],
    decision: 'PROMOTE',
    promotion_scope: 'RESEARCH_ARTIFACT_EXACT_BUILD_STRUCTURAL_IDENTITY_ONLY',
    semantic_claim: null,
    actual_reverse_engineering_executed: true,
    evidence_exhausted: route.evidence_exhausted,
    evidence_exhausted_scope: route.evidence_exhausted_scope,
    actionable_hypotheses: route.actionable_hypotheses,
    next_required_evidence: route.next_required_evidence,
    external_only_gate: route.external_only_gate,
  }));
  const domainDecisions = [...new Set(routeDecisions.map((row) => row.domain))].map((domain) => {
    const members = routeDecisions.filter((row) => row.domain === domain);
    const exhausted = members.every((row) => row.evidence_exhausted);
    const decision = domain === 'generic_empty_payload_protocol_signal' ? 'REPURPOSE' : 'KEEP_CANDIDATE';
    return {
      decision_id: `DOMAIN_${domain.toUpperCase()}_RESIDUAL_P3_V2`,
      domain,
      routes: members.map((row) => row.packet_discriminator),
      capabilities: members.map((row) => row.capability),
      decision,
      semantic_claim: null,
      actual_reverse_engineering_executed: true,
      evidence_exhausted: exhausted,
      evidence_exhausted_scope: 'PINNED_EXACT_RUNTIME_EXPLICIT_SAFE_LATEST_FOUR_ALL_OCCURRENCES_AND_ALL_DISTINCT_PAYLOADS',
      actionable_hypotheses: members.flatMap((row) => row.actionable_hypotheses),
      next_required_evidence: [...new Set(members.flatMap((row) => row.next_required_evidence))],
      external_only_gate: {
        required: exhausted,
        local_safe_evidence_remaining: !exhausted,
        required_route_count: members.length,
      },
    };
  });
  return {
    route_decisions: routeDecisions,
    capability_decisions: capabilityDecisions,
    domain_decisions: domainDecisions,
    decision_counts: Object.fromEntries(['PROMOTE', 'REPURPOSE', 'KEEP_CANDIDATE', 'REJECT']
      .map((decision) => [decision, routeDecisions.filter((row) => row.decision === decision).length])),
    all_routes_have_one_decision: routeDecisions.length === ROUTE_IDS.length
      && new Set(routeDecisions.map((row) => row.packet_id)).size === ROUTE_IDS.length,
    all_current_local_evidence_exhausted: routeDecisions.every((row) => row.evidence_exhausted)
      && capabilityDecisions.every((row) => row.evidence_exhausted)
      && domainDecisions.every((row) => row.evidence_exhausted),
  };
}

function validateDecisionBundle(bundle) {
  invariant(bundle.schema === 'RESIDUAL_P3_WAVE_MACHINE_DECISIONS_V2', 'decision schema mismatch');
  invariant(bundle.exact_build === EXACT_BUILD, 'decision exact-build mismatch');
  invariant(bundle.route_decisions.length === ROUTE_IDS.length, 'route decision count mismatch');
  invariant(new Set(bundle.route_decisions.map((row) => row.packet_id)).size === ROUTE_IDS.length,
    'route decision identities are not unique');
  const vocabulary = new Set(['PROMOTE', 'REPURPOSE', 'KEEP_CANDIDATE', 'REJECT']);
  for (const group of ['route_decisions', 'capability_decisions', 'domain_decisions']) {
    invariant(bundle[group].length > 0, `${group} must not be empty`);
    for (const row of bundle[group]) {
      invariant(vocabulary.has(row.decision), `${group} has invalid decision ${row.decision}`);
      invariant(row.actual_reverse_engineering_executed === true,
        `${group} lacks actual reverse engineering`);
      invariant(row.evidence_exhausted === true, `${group} has unexhausted evidence`);
      invariant(Array.isArray(row.actionable_hypotheses) && row.actionable_hypotheses.length === 0,
        `${group} retains actionable hypotheses`);
      invariant(row.external_only_gate?.required === true
        && row.external_only_gate?.local_safe_evidence_remaining === false,
      `${group} external-only gate failed`);
    }
  }
  return true;
}

function markdownReport(report) {
  const lines = [
    '# Residual P3 route wave — exact-build deep recovery audit',
    '',
    `- Exact build: \`${EXACT_BUILD}\`; nearest-build fallback forbidden.`,
    `- Full route rows conserved: ${report.conservation.target_row_count.toLocaleString('en-US')}.`,
    `- Distinct payloads executed twice: ${report.conservation.distinct_payload_row_count.toLocaleString('en-US')}.`,
    `- Current safe local evidence saturated: ${report.saturation.current_safe_local_resource_saturated}.`,
    '- Protected Jungle Objective Holdout was not enumerated, read, hashed, decoded, tested, or consumed.',
    '',
    '## Decisions',
    '',
    '| Route | Object | Factory identity | Native result | Decision |',
    '|---|---:|---|---|---|',
  ];
  for (const decision of report.decision_summary.route_decisions) {
    const runtime = report.runtime_static_recovery.routes[decision.packet_discriminator];
    const native = report.native_exact_emulation.routes[decision.packet_discriminator];
    lines.push(`| \`${decision.packet_discriminator}\` | ${runtime.factory_chain.object_size} bytes | ${runtime.factory_chain.case_rva_hex} → ${runtime.factory_chain.deserializer_rva_hex} | ${native.successful_full_consume_distinct_count}/${native.distinct_payload_attempt_count} distinct full-consume; ${native.conserved_failure_occurrence_weight} failure weight conserved | ${decision.decision}: ${decision.hypothesis} |`);
  }
  lines.push(
    '',
    '## Strong negative and repurpose evidence',
    '',
    '`0x018c` shares its exact empty-payload vtable/deserializer with both `PKT_OnLeaveVisibilityClient_s` and `PKT_S2C_DestroyClientMissile_s`. That is a direct counterexample to transferring semantics through a shared codec; only a generic empty-payload protocol signal is retained.',
    '',
    '`0x0178` remains a hero-bound wide snapshot candidate. Its prior 800-row field-behavior profile explicitly had no typed schema, no semantic claim, and zero independent anchors, so no HP/defense/resource field is promoted.',
    '',
    '## Saturation boundary',
    '',
    'Every authorized latest-four occurrence, distinct payload, exact factory/constructor/vtable/deserializer chain, static callback/RTTI surface, full PE function-range packet-ID immediate surface, native branch, stream/entity/time/cross-route relationship, and requested anchor/control was executed. Remaining names and plaintext roles require an exact live callback heap plus controlled business-state evidence.',
    '',
  );
  return lines.join('\n');
}

module.exports = {
  ANCHOR_FAMILIES,
  EXACT_BUILD,
  ROUTE_CONFIG,
  ROUTE_IDS,
  RUNTIME_SHA256,
  SAFE_REPLAYS,
  analyzeNative,
  anchorCorrelation,
  buildDecisions,
  buildProfiles,
  classifyNativeFailure,
  collectEvidence,
  markdownReport,
  nearestEvent,
  packetHex,
  quantile,
  rejectProtectedPath,
  rvaHex,
  sha256,
  sha256File,
  validateDecisionBundle,
};
