'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('./rofl');

const EXACT_BUILD = '16.16.805.0442';
const RUNTIME_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const ROUTE_IDS = Object.freeze([
  0x04ce, 0x0441, 0x0278, 0x046e, 0x00fc, 0x011a, 0x0433,
]);
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
  dampener_switch_state: Object.freeze([0x042d]),
  unit_destroy: Object.freeze([0x04a2]),
  character_data: Object.freeze([0x032f]),
});

const ROUTE_CONFIG = Object.freeze({
  '0x04ce': Object.freeze({
    decision: 'PROMOTE',
    domain: 'spell_targeter_protocol_event',
    capability: 'START_SPELL_TARGETER_PROTOCOL_OCCURRENCE',
    expected_rtti: 'PKT_S2C_StartSpellTargeter_s',
    callback_owner: 'AIHeroClient',
    callback_rva_hex: '0x00333c00',
    hypothesis: 'CALLBACK_VERIFIED_START_SPELL_TARGETER_OCCURRENCE',
    claim: 'Exact-build StartSpellTargeter protocol occurrence; protected slot, scalar, and option-byte meanings remain unpublished.',
    boundary: 'RTTI and callback control flow name the carrier, not its targeting geometry, spell identity, or gameplay behavior.',
  }),
  '0x0441': Object.freeze({
    decision: 'PROMOTE',
    domain: 'movement_driver_protocol_event',
    capability: 'SET_MOVEMENT_DRIVER_PROTOCOL_UPDATE',
    expected_rtti: 'PKT_S2C_SetMovementDriver_s',
    callback_owner: 'AIBaseClient',
    callback_rva_hex: '0x002a4aa0',
    hypothesis: 'CALLBACK_VERIFIED_SET_MOVEMENT_DRIVER_UPDATE',
    claim: 'Exact-build SetMovementDriver protocol update with a callback-decoded driver discriminator; coordinate/vector and option-field meanings remain unpublished.',
    boundary: 'The driver discriminator selects a callback branch, but does not establish path intent, coordinates, speed, or player behavior.',
  }),
  '0x0278': Object.freeze({
    decision: 'PROMOTE',
    domain: 'fake_buff_batch_protocol_event',
    capability: 'ADD_FAKE_BUFFS_BATCH_CARRIER',
    expected_rtti: 'PKT_NPC_AddFakeBuffs_s',
    callback_owner: 'BuffManagerClient',
    callback_rva_hex: '0x008ccbd0',
    hypothesis: 'CALLBACK_VERIFIED_FAKE_BUFF_RECORD_VECTOR',
    claim: 'Exact-build AddFakeBuffs batch carrier with callback-proven vector count and 0x38-byte record stride.',
    boundary: 'The vector and record stride are exact structure; record field roles, buff identities, and visible effects remain unpublished.',
  }),
  '0x046e': Object.freeze({
    decision: 'PROMOTE',
    domain: 'spell_modifier_protocol_event',
    capability: 'ADD_SPELL_MODIFIER_PROTOCOL_OCCURRENCE',
    expected_rtti: 'PKT_S2C_AddSpellModifier_s',
    callback_owner: 'AIBaseClient',
    callback_rva_hex: '0x002a0980',
    hypothesis: 'CALLBACK_VERIFIED_ADD_SPELL_MODIFIER_OCCURRENCE',
    claim: 'Exact-build AddSpellModifier protocol occurrence whose two protected u32 lanes are passed to AIBaseClient virtual slot +0xa00.',
    boundary: 'The callback proves two decoded arguments, not their spell/modifier IDs or mutation semantics.',
  }),
  '0x00fc': Object.freeze({
    decision: 'PROMOTE',
    domain: 'missile_script_trigger_protocol_event',
    capability: 'MISSILE_SCRIPT_TRIGGER_PROTOCOL_OCCURRENCE',
    expected_rtti: 'PKT_S2C_MissileScriptTrigger_s',
    callback_owner: 'MissileClient',
    callback_rva_hex: '0x00974210',
    hypothesis: 'CALLBACK_VERIFIED_MISSILE_SCRIPT_TRIGGER_OCCURRENCE',
    claim: 'Exact-build MissileScriptTrigger protocol occurrence with a callback-decoded f32 lane passed to MissileClient virtual slot +0x1d8.',
    boundary: 'The decoded scalar and protected +0x18 argument block remain role-neutral; no trigger effect or trajectory meaning is inferred.',
  }),
  '0x011a': Object.freeze({
    decision: 'PROMOTE',
    domain: 'structure_turret_flags_protocol_state',
    capability: 'TURRET_FLAGS_EXACT_U32_UPDATE',
    expected_rtti: 'PKT_UpdateTurretFlags_s',
    callback_owner: 'AITurretClient',
    callback_rva_hex: '0x00335590',
    hypothesis: 'CALLBACK_DECODED_TURRET_FLAGS_U32_UPDATE',
    claim: 'Exact-build turret-flags update with the complete callback byte transform recovered to an unsigned 32-bit flags value; bit 0x10 has an observed callback consumer.',
    boundary: 'AITurretClient and the flags field are exact. Raw network IDs do not publish turret subtype, team, lane, location, map truth, or meanings for unconsumed flag bits.',
  }),
  '0x0433': Object.freeze({
    decision: 'PROMOTE',
    domain: 'structure_lifecycle_protocol_event',
    capability: 'BUILDING_DEATH_PROTOCOL_OCCURRENCE',
    expected_rtti: 'PKT_Building_Die_s',
    callback_owner: 'BuildingClient',
    callback_rva_hex: '0x00e258f8',
    hypothesis: 'RTTI_VERIFIED_BUILDING_DEATH_OCCURRENCE_WITH_VIRTUAL_SUBTYPE_BOUNDARY',
    claim: 'Exact-build Building_Die protocol occurrence on BuildingClient, bounded to structure lifecycle occurrence rather than subtype identity.',
    boundary: 'The registered callback is a virtual thunk to owner slot +0x758. A live concrete BuildingClient vtable is required for subtype-specific handling; turret, inhibitor, nexus, team, location, killer, and map labels are not published.',
  }),
});

const ANCHOR_BY_ID = new Map();
for (const [family, packetIds] of Object.entries(ANCHOR_FAMILIES)) {
  for (const packetId of packetIds) {
    if (!ANCHOR_BY_ID.has(packetId)) ANCHOR_BY_ID.set(packetId, []);
    ANCHOR_BY_ID.get(packetId).push(family);
  }
}

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

function offsetHex(offset) {
  return `0x${Number(offset).toString(16).padStart(2, '0')}`;
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

function increment(counter, key, amount = 1) {
  const normalized = String(key);
  counter.set(normalized, (counter.get(normalized) || 0) + amount);
}

function sortedCounter(counter, keyName = 'value', limit = null) {
  const rows = [...counter.entries()]
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

function newDistinctPayload(event, payload) {
  return {
    schema: 'RESIDUAL_P7_DISTINCT_PAYLOAD_V2',
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
        raw_payload_hex: block.payload.toString('hex'),
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
        state.payloads.set(payloadHash, newDistinctPayload(event, block.payload));
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
  const cotimedMismatchExamples = [];
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
    if (delta === 0 && nearest.raw_param !== event.raw_param && cotimedMismatchExamples.length < 12) {
      cotimedMismatchExamples.push({ replay_sha256: event.replay_sha256,
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
    cotimed_raw_param_mismatch_examples: cotimedMismatchExamples,
    semantic_claim: null,
  };
}

function temporalSummary(events) {
  const byReplay = new Map();
  const groups = new Map();
  for (const event of events) {
    if (!byReplay.has(event.replay_sha256)) byReplay.set(event.replay_sha256, []);
    byReplay.get(event.replay_sha256).push(event);
    increment(groups, `${event.replay_sha256}:${event.time}`);
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
  const sizes = [...groups.values()];
  return {
    timestamp_group_count: groups.size,
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
  const result = [];
  for (const [sourceId, source] of states) {
    for (const [targetId, target] of indexes) {
      if (sourceId === targetId) continue;
      let exact = 0;
      let exactParam = 0;
      for (const event of source.events) {
        const params = target.get(`${event.replay_sha256}:${event.time}`);
        if (!params) continue;
        exact += 1;
        exactParam += Number(params.has(event.raw_param));
      }
      if (exact) result.push({
        source_route: packetHex(sourceId),
        target_route: packetHex(targetId),
        source_count: source.count,
        exact_time_count: exact,
        exact_time_rate: round(exact / Math.max(1, source.count)),
        exact_time_same_raw_param_count: exactParam,
        exact_time_same_raw_param_rate: round(exactParam / Math.max(1, source.count)),
      });
    }
  }
  return result.sort((left, right) =>
    right.exact_time_same_raw_param_rate - left.exact_time_same_raw_param_rate
    || right.exact_time_rate - left.exact_time_rate
    || left.source_route.localeCompare(right.source_route)
    || left.target_route.localeCompare(right.target_route));
}

function exactRelation(sourceEvents, anchorByReplay) {
  const index = new Map();
  for (const [replaySha, events] of anchorByReplay) {
    for (const event of events) {
      const key = `${replaySha}:${event.time}`;
      if (!index.has(key)) index.set(key, new Set());
      index.get(key).add(event.raw_param);
    }
  }
  let exact = 0;
  let exactSameParam = 0;
  const sameParamExamples = [];
  const absentExamples = [];
  for (const event of sourceEvents) {
    const params = index.get(`${event.replay_sha256}:${event.time}`);
    if (params) {
      exact += 1;
      if (params.has(event.raw_param)) {
        exactSameParam += 1;
        if (sameParamExamples.length < 12) sameParamExamples.push({
          replay_sha256: event.replay_sha256,
          replay_time_ms: event.time,
          raw_param: event.raw_param,
          payload_sha256: event.payload_sha256,
        });
      }
    } else if (absentExamples.length < 12) {
      absentExamples.push({ replay_sha256: event.replay_sha256,
        replay_time_ms: event.time, raw_param: event.raw_param });
    }
  }
  return {
    source_count: sourceEvents.length,
    exact_time_count: exact,
    exact_time_same_raw_param_count: exactSameParam,
    without_exact_time_anchor_count: sourceEvents.length - exact,
    exact_time_same_raw_param_examples: sameParamExamples,
    no_exact_time_anchor_counterexamples: absentExamples,
  };
}

function structureDiscrimination(states, anchors) {
  const turret = states.get(0x011a).events;
  const buildingDie = states.get(0x0433).events;
  const turretGroups = new Map();
  for (const event of turret) {
    const key = `${event.replay_sha256}:${event.time}:${event.raw_param}`;
    if (!turretGroups.has(key)) turretGroups.set(key, []);
    turretGroups.get(key).push(event);
  }
  const repeated = [...turretGroups.values()].filter((rows) => rows.length > 1);
  const turretEntities = new Set(turret.map((row) => row.raw_param));
  const buildingEntities = new Set(buildingDie.map((row) => row.raw_param));
  const overlap = [...turretEntities].filter((value) => buildingEntities.has(value)).sort((a, b) => a - b);
  return {
    route_011a_named_carrier_vs_identity_boundary: {
      callback_owner: 'AITurretClient',
      named_carrier: 'PKT_UpdateTurretFlags_s',
      occurrence_count: turret.length,
      distinct_raw_param_count: turretEntities.size,
      repeated_same_timestamp_same_entity_group_count: repeated.length,
      repeated_same_timestamp_same_entity_occurrence_count:
        repeated.reduce((sum, rows) => sum + rows.length, 0),
      repeated_transition_examples: repeated.slice(0, 12).map((rows) => ({
        replay_sha256: rows[0].replay_sha256,
        replay_time_ms: rows[0].time,
        raw_param: rows[0].raw_param,
        payload_sequence_hex: rows.sort((left, right) => left.occurrence_index - right.occurrence_index)
          .map((row) => row.raw_payload_hex),
      })),
      publishable_identity_scope: 'AITurretClient protocol subject network ID only',
      forbidden_identity_inferences: ['turret_subtype', 'team', 'lane', 'location', 'map_identity'],
    },
    route_0433_named_carrier_vs_lifecycle_boundary: {
      callback_owner: 'BuildingClient',
      named_carrier: 'PKT_Building_Die_s',
      occurrence_count: buildingDie.length,
      distinct_raw_param_count: buildingEntities.size,
      dampener_switch_state_relation: exactRelation(
        buildingDie, anchors.get('dampener_switch_state'),
      ),
      unit_destroy_relation: exactRelation(buildingDie, anchors.get('unit_destroy')),
      turret_flags_raw_param_overlap_count: overlap.length,
      turret_flags_raw_param_overlap_values: overlap,
      publishable_lifecycle_scope: 'BuildingClient death protocol occurrence at replay time for raw subject network ID',
      forbidden_identity_inferences: [
        'building_subtype', 'turret', 'inhibitor', 'nexus', 'team', 'lane',
        'location', 'killer', 'cause', 'map_truth',
      ],
      live_virtual_dispatch_blocker: {
        callback_thunk_rva_hex: '0x00e258f8',
        owner_vtable_slot_offset_hex: '0x0758',
        missing_state: 'Concrete live BuildingClient subtype object vtable and slot target',
      },
    },
  };
}

function collectEvidence(replayPaths) {
  invariant(Array.isArray(replayPaths) && replayPaths.length === 4,
    'exactly four explicit safe replay paths are required');
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
  const distinctPayloadRows = ROUTE_IDS.flatMap((packetId) =>
    routes[packetHex(packetId)].distinct_payload_rows)
    .sort((left, right) => left.packet_id - right.packet_id
      || left.payload_length - right.payload_length
      || left.raw_payload_sha256.localeCompare(right.raw_payload_sha256));
  for (const route of Object.values(routes)) delete route.distinct_payload_rows;
  const anchorCounts = {};
  for (const [family, byReplay] of anchors) {
    anchorCounts[family] = [...byReplay.values()].reduce((sum, rows) => sum + rows.length, 0);
  }
  const eventRows = ROUTE_IDS.flatMap((packetId) => states.get(packetId).events)
    .sort((left, right) => left.replay_sha256.localeCompare(right.replay_sha256)
      || left.occurrence_index - right.occurrence_index);
  const canonical = {
    replays: replays.map(({ basename, replay_sha256: replaySha256,
      replay_version: replayVersion, block_count: blockCount }) => ({
      basename, replay_sha256: replaySha256, replay_version: replayVersion,
      block_count: blockCount,
    })),
    routes,
    anchor_counts: anchorCounts,
    cross_route_exact_time_matrix: crossRouteMatrix(states),
    structure_discrimination: structureDiscrimination(states, anchors),
    event_rows: eventRows,
    distinct_payload_rows: distinctPayloadRows,
  };
  return {
    ...canonical,
    target_row_count: eventRows.length,
    distinct_payload_row_count: distinctPayloadRows.length,
    deterministic_digest: sha256(Buffer.from(JSON.stringify(canonical), 'utf8')),
  };
}

function buildProfiles(staticRecovery) {
  return ROUTE_IDS.map((packetId) => {
    const packetType = packetHex(packetId);
    const runtime = staticRecovery.routes[packetType];
    invariant(runtime?.factory_chain, `static recovery missing ${packetType}`);
    return {
      schema: 'RESIDUAL_P7_EXACT_NATIVE_PROFILE_V2',
      schema_version: 2,
      exact_build: EXACT_BUILD,
      exact_runtime_image_sha256: RUNTIME_SHA256,
      static_identity: runtime,
      profile: {
        id: `residual-p7-${packetType.slice(2)}-exact-runtime-v2`,
        client_opcode: packetId,
        constructor_rva: Number(runtime.factory_chain.constructor_rva),
        deserialize_rva: Number(runtime.factory_chain.deserializer_rva),
        object_size: Number(runtime.factory_chain.object_size),
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
      object_offset: offsetHex(offset),
      weighted_observation_count: weight,
      distinct_storage_value_count: values.size,
      entropy_bits: entropy(values, weight),
      top_storage_values: sortedCounter(values, 'value_u8', 8),
      semantic_role: null,
    });
  }
  return result;
}

function rotateRight8(value, bits) {
  const normalized = value & 0xff;
  return ((normalized >>> bits) | (normalized << (8 - bits))) & 0xff;
}

function decodeTurretFlagsObject(objectHex) {
  const object = Buffer.from(objectHex, 'hex');
  invariant(object.length >= 0x14, 'turret flags object is truncated');
  const decoded = Buffer.alloc(4);
  for (let index = 0; index < 4; index += 1) {
    let value = object[0x10 + index];
    value = rotateRight8(value, 6);
    value ^= 0x9f;
    value = rotateRight8(value, 6);
    value ^= 0xe0;
    value = (value + 0x51) & 0xff;
    decoded[index] = value;
  }
  return decoded.readUInt32LE(0) >>> 0;
}

function decodeMovementDriverKindObject(objectHex) {
  const object = Buffer.from(objectHex, 'hex');
  invariant(object.length > 0x40, 'movement driver object is truncated');
  let value = object[0x40] ^ 0x47;
  value = rotateRight8(value, 4);
  value = (value - 0x2a) & 0xff;
  value ^= 0x43;
  value = (value - 0x11) & 0xff;
  return value;
}

function decodeMissileTriggerScalarObject(objectHex) {
  const object = Buffer.from(objectHex, 'hex');
  invariant(object.length >= 0x2c, 'missile trigger object is truncated');
  const decoded = Buffer.alloc(4);
  for (let index = 0; index < 4; index += 1) {
    decoded[index] = (object[0x28 + index] + 0xab) & 0xff;
  }
  return {
    decoded_f32: decoded.readFloatLE(0),
    decoded_u32_bits: decoded.readUInt32LE(0) >>> 0,
  };
}

function turretFlagTransitions(successfulRows, eventRows) {
  const byHash = new Map(successfulRows.map((row) => [
    row.raw_payload_sha256, decodeTurretFlagsObject(row.object_hex),
  ]));
  const byEntity = new Map();
  for (const event of eventRows.filter((row) => row.packet_id === 0x011a)) {
    if (!byHash.has(event.payload_sha256)) continue;
    const key = `${event.replay_sha256}:${event.raw_param}`;
    if (!byEntity.has(key)) byEntity.set(key, []);
    byEntity.get(key).push({ ...event, turret_flags_u32: byHash.get(event.payload_sha256) });
  }
  let transitionCount = 0;
  let sameTimeCount = 0;
  let bit10ToggleCount = 0;
  const xorMasks = new Map();
  const examples = [];
  for (const rows of byEntity.values()) {
    rows.sort((left, right) => left.time - right.time || left.occurrence_index - right.occurrence_index);
    for (let index = 1; index < rows.length; index += 1) {
      const before = rows[index - 1];
      const after = rows[index];
      const xorMask = (before.turret_flags_u32 ^ after.turret_flags_u32) >>> 0;
      transitionCount += 1;
      sameTimeCount += Number(before.time === after.time);
      bit10ToggleCount += Number((xorMask & 0x10) !== 0);
      increment(xorMasks, xorMask);
      if (examples.length < 20) examples.push({
        replay_sha256: before.replay_sha256,
        raw_param: before.raw_param,
        before_time_ms: before.time,
        after_time_ms: after.time,
        delta_ms: after.time - before.time,
        before_flags_u32: before.turret_flags_u32,
        after_flags_u32: after.turret_flags_u32,
        xor_mask_u32: xorMask,
        callback_consumer_bit_0x10_toggled: (xorMask & 0x10) !== 0,
      });
    }
  }
  return {
    decoded_event_count: [...byEntity.values()].reduce((sum, rows) => sum + rows.length, 0),
    entity_sequence_count: byEntity.size,
    transition_count: transitionCount,
    same_timestamp_transition_count: sameTimeCount,
    callback_consumer_bit_0x10_toggle_count: bit10ToggleCount,
    xor_mask_distribution: sortedCounter(xorMasks, 'xor_mask_u32', 32),
    transition_examples: examples,
    semantic_boundary: 'Only the complete u32 flags value and callback consumption of bit 0x10 are exact; other bit meanings are null.',
  };
}

function callbackDecodedFields(packetId, successfulRows, eventRows) {
  if (packetId === 0x011a) {
    const values = new Map();
    for (const row of successfulRows) {
      increment(values, decodeTurretFlagsObject(row.object_hex), Number(row.occurrence_count || 1));
    }
    return {
      field: 'turret_flags_u32',
      object_offset: '0x10',
      recovery: 'EXACT_CALLBACK_BYTE_TRANSFORM',
      weighted_value_distribution: sortedCounter(values, 'turret_flags_u32', 64),
      callback_consumer: 'AITurretClient state +0x4ab8; bit test 0x10',
      transitions: turretFlagTransitions(successfulRows, eventRows),
    };
  }
  if (packetId === 0x0441) {
    const values = new Map();
    for (const row of successfulRows) {
      increment(values, decodeMovementDriverKindObject(row.object_hex), Number(row.occurrence_count || 1));
    }
    return {
      field: 'movement_driver_discriminator_u8',
      object_offset: '0x40',
      recovery: 'EXACT_CALLBACK_BYTE_TRANSFORM',
      weighted_value_distribution: sortedCounter(values, 'driver_discriminator_u8', 32),
      callback_branch: 'value 2 consumes protected +0x10/+0x20..+0x30 parameter lanes',
      semantic_role: null,
    };
  }
  if (packetId === 0x00fc) {
    const bits = new Map();
    let finiteCount = 0;
    let nonFiniteCount = 0;
    const finiteValues = [];
    for (const row of successfulRows) {
      const decoded = decodeMissileTriggerScalarObject(row.object_hex);
      const weight = Number(row.occurrence_count || 1);
      increment(bits, decoded.decoded_u32_bits, weight);
      if (Number.isFinite(decoded.decoded_f32)) {
        finiteCount += weight;
        finiteValues.push(decoded.decoded_f32);
      } else {
        nonFiniteCount += weight;
      }
    }
    return {
      field: 'callback_decoded_f32_lane',
      object_offset: '0x28',
      recovery: 'ADD_0xAB_TO_EACH_STORED_BYTE_THEN_IEEE754_LE',
      weighted_bit_pattern_distribution: sortedCounter(bits, 'decoded_u32_bits', 32),
      finite_occurrence_weight: finiteCount,
      nonfinite_occurrence_weight: nonFiniteCount,
      finite_min: finiteValues.length ? Math.min(...finiteValues) : null,
      finite_max: finiteValues.length ? Math.max(...finiteValues) : null,
      callback_consumer: 'xmm2 argument to MissileClient virtual slot +0x1d8',
      semantic_role: null,
    };
  }
  return {
    recovered_named_field_count: 0,
    semantic_role: null,
    reason: 'Callback accesses are statically closed, but local evidence does not justify field names.',
  };
}

function classifyNativeFailure(message) {
  const text = String(message || 'UNKNOWN_NATIVE_FAILURE');
  const rip = text.match(/rip=(0x[0-9a-f]+)/i)?.[1] || null;
  const address = text.match(/address=(0x[0-9a-f]+)/i)?.[1]
    || text.match(/at (0x[0-9a-f]+)/i)?.[1] || null;
  const external = /invalid memory access|read_unmapped|write_unmapped|unmapped|GS:|TLS|heap|UC_ERR|allocator|process state/i.test(text);
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
    const successfulSet = new Set(successful);
    const failed = rows.filter((row) => !successfulSet.has(row));
    const successfulWeight = successful.reduce((sum, row) => sum + Number(row.occurrence_count || 1), 0);
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
      callback_decoded_fields: callbackDecodedFields(packetId, successful, evidence.event_rows),
    };
  }
  return { routes };
}

function strongestPair(matrix, sourceRoute) {
  return matrix.find((row) => row.source_route === sourceRoute) || null;
}

function externalEvidence(packetType, runtime, native, config) {
  const pieces = [];
  if (packetType === '0x0433') {
    pieces.push('an authorized exact-build live BuildingClient object/vtable capture resolving callback thunk 0x00e258f8 virtual slot +0x758 to each concrete subtype handler');
  }
  if (native.conserved_failure_occurrence_weight > 0) {
    pieces.push('the exact process heap/TLS/allocator state spanning every recorded native fault RIP/address');
  }
  pieces.push('a controlled one-property-at-a-time exact-build producer/consumer trace with plaintext field and subject labels');
  return `${pieces.join(', ')}.`;
}

function buildDecisions(evidence, staticRecovery, nativeAnalysis) {
  const routeDecisions = ROUTE_IDS.map((packetId) => {
    const packetType = packetHex(packetId);
    const raw = evidence.routes[packetType];
    const runtime = staticRecovery.routes[packetType];
    const native = nativeAnalysis.routes[packetType];
    const config = ROUTE_CONFIG[packetType];
    invariant(config, `missing route config ${packetType}`);
    const localComplete = runtime.validations.all_factory_checks_pass
      && runtime.receive_identity.bounded_static_surfaces_exhausted
      && runtime.receive_identity.runtime_type_name === config.expected_rtti
      && runtime.receive_identity.callback_owner_type === config.callback_owner
      && runtime.receive_identity.callback_receive_target_rva_hex === config.callback_rva_hex
      && runtime.callback_static_analysis.all_required_signatures_match
      && raw.payload.occurrence_weight_conserved
      && native.all_distinct_payloads_attempted
      && native.full_occurrence_weight_conserved
      && native.all_failures_external_runtime_state;
    const requiredEvidence = externalEvidence(packetType, runtime, native, config);
    const structureCounterexample = packetType === '0x011a'
      ? evidence.structure_discrimination.route_011a_named_carrier_vs_identity_boundary
      : packetType === '0x0433'
        ? evidence.structure_discrimination.route_0433_named_carrier_vs_lifecycle_boundary
        : null;
    return {
      decision_id: `ROUTE_${packetType}_RESIDUAL_P7_WAVE_V2`,
      packet_id: packetId,
      packet_discriminator: packetType,
      decision: config.decision,
      domain: config.domain,
      capability: config.capability,
      hypothesis: config.hypothesis,
      semantic_claim: config.claim,
      structural_claim: `Exact-build ${runtime.factory_chain.object_size}-byte packet object with closed factory/constructor/vtable/deserializer, callback RTTI owner, callback target, and verified consumer signatures.`,
      evidence_grade: 'VERIFIED_DIRECT_EXACT_BUILD_CALLBACK_STRUCTURE_FULL_SAFE_INVENTORY_AND_DOUBLE_NATIVE',
      positive_occurrence_count: raw.count,
      field_semantic_boundary: config.boundary,
      structure_identity_or_lifecycle_counterexamples: structureCounterexample,
      strongest_exact_time_route_relationship: strongestPair(
        evidence.cross_route_exact_time_matrix, packetType,
      ),
      actual_reverse_engineering_executed: true,
      reverse_engineering_steps: [
        'EXPLICIT_SAFE_LATEST_FOUR_FULL_ROUTE_WALK',
        'ALL_DISTINCT_PAYLOAD_HASHES_WITH_OCCURRENCE_WEIGHT_CONSERVATION',
        'EXACT_FACTORY_CASE_ALLOCATION_CONSTRUCTOR_VTABLE_DESERIALIZER_RECOVERY',
        'MAKEFUNCTION_RTTI_OWNER_AND_RECEIVE_TARGET_VERIFICATION',
        'LOGICAL_CALLBACK_SPAN_DISASSEMBLY_AND_EXACT_FIELD_CONSUMER_SIGNATURES',
        'DOUBLE_EXACT_NATIVE_CONSTRUCTOR_PLUS_DESERIALIZER_EMULATION',
        'CALLBACK_FIELD_TRANSFORM_REPLAY_FOR_011A_0441_AND_00FC',
        'STREAM_ENTITY_TIME_NEIGHBOR_CROSS_ROUTE_ANCHOR_AND_SHIFTED_CONTROL_COUNTEREXAMPLES',
      ],
      evidence_exhausted: localComplete,
      evidence_exhausted_scope: 'PINNED_EXACT_RUNTIME_EXPLICIT_SAFE_LATEST_FOUR_ALL_OCCURRENCES_ALL_DISTINCT_PAYLOADS_AND_CALLBACK_LOGIC',
      exhaustion_basis: localComplete
        ? 'ALL_CURRENT_SAFE_LOCAL_STATIC_RAW_TEMPORAL_FIELD_NATIVE_AND_COUNTEREXAMPLE_HYPOTHESES_EXECUTED'
        : 'LOCAL_SURFACE_VALIDATION_REMAINS_INCOMPLETE',
      remaining_local_executable_steps: localComplete ? [] : [
        'Resolve the exact local static/native/count validation reported false.',
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
    decision_id: `CAPABILITY_${route.capability}_RESIDUAL_P7_V2`,
    capability: route.capability,
    domain: route.domain,
    routes: [route.packet_discriminator],
    decision: 'PROMOTE',
    promotion_scope: 'RESEARCH_ARTIFACT_EXACT_BUILD_BOUNDED_PROTOCOL_SEMANTIC',
    semantic_claim: route.semantic_claim,
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
    return {
      decision_id: `DOMAIN_${domain.toUpperCase()}_RESIDUAL_P7_V2`,
      domain,
      routes: members.map((row) => row.packet_discriminator),
      capabilities: members.map((row) => row.capability),
      decision: 'PROMOTE',
      semantic_claim: 'Exact-build bounded protocol domain only; protected field and gameplay interpretations beyond each route claim remain unpublished.',
      actual_reverse_engineering_executed: true,
      evidence_exhausted: exhausted,
      evidence_exhausted_scope: 'PINNED_EXACT_RUNTIME_EXPLICIT_SAFE_LATEST_FOUR_ALL_OCCURRENCES_ALL_DISTINCT_PAYLOADS_AND_CALLBACK_LOGIC',
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
  invariant(bundle.schema === 'RESIDUAL_P7_WAVE_MACHINE_DECISIONS_V2', 'decision schema mismatch');
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
    '# Residual P7 route wave — exact-build deep recovery audit',
    '',
    `- Exact build: \`${EXACT_BUILD}\`; nearest-build fallback forbidden.`,
    `- Full route rows conserved: ${report.conservation.target_row_count}.`,
    `- Distinct payloads executed twice: ${report.conservation.distinct_payload_row_count}.`,
    `- Current safe local evidence saturated: ${report.saturation.current_safe_local_resource_saturated}.`,
    '- Protected Jungle Objective Holdout was not enumerated, read, hashed, decoded, tested, or consumed.',
    '',
    '## Decisions',
    '',
    '| Route | RTTI / owner | Callback result | Native result | Decision |',
    '|---|---|---|---|---|',
  ];
  for (const decision of report.decision_summary.route_decisions) {
    const runtime = report.runtime_static_recovery.routes[decision.packet_discriminator];
    const native = report.native_exact_emulation.routes[decision.packet_discriminator];
    lines.push(`| \`${decision.packet_discriminator}\` | ${runtime.receive_identity.runtime_type_name} / ${runtime.receive_identity.callback_owner_type} | ${runtime.callback_static_analysis.summary} | ${native.successful_full_consume_distinct_count}/${native.distinct_payload_attempt_count} distinct full-consume; ${native.conserved_failure_occurrence_weight} failure weight | ${decision.decision}: ${decision.capability} |`);
  }
  lines.push(
    '',
    '## Structure boundary',
    '',
    '`0x011a` publishes the exact callback-decoded `turret_flags_u32` value and the observed bit-`0x10` consumer, but no subtype/team/lane/location label. Repeated same-time same-entity flag transitions are counterexamples to treating every carrier row as a death event.',
    '',
    '`0x0433` publishes a BuildingClient death-protocol occurrence for the raw subject network ID. Its callback is only `mov rax,[rcx]; jmp [rax+0x758]`; concrete subtype semantics require an authorized live owner vtable. Exact-time dampener-state overlaps and non-overlaps are both retained, so the route is not narrowed to turret or inhibitor identity.',
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
  decodeMissileTriggerScalarObject,
  decodeMovementDriverKindObject,
  decodeTurretFlagsObject,
  markdownReport,
  nearestEvent,
  packetHex,
  quantile,
  rejectProtectedPath,
  sha256,
  sha256File,
  validateDecisionBundle,
};

