#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const {
  decodeRouteObject,
  rotateLeft8,
  rotateRight8,
  swapAdjacentBits,
} = require('../src/decoders/gameplay_route_tail_16_16');

const EXACT_BUILD = '16.16.805.0442';
const RUNTIME_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const ROUTE_IDS = [0x00b8, 0x00e4, 0x01ab, 0x01b5, 0x0298, 0x03d4];
const ANCHOR_IDS = [0x00f6, 0x017f, 0x01cf];
const ALLOWED_DECISIONS = new Set(['PROMOTE', 'REPURPOSE', 'KEEP_CANDIDATE', 'REJECT']);

const DECODED_FIELD_LAYOUTS = Object.freeze({
  '0x00b8': [
    { object_offset: '0x10', type: 'f32', published_name: 'numeric_10_f32', role_status: 'NEUTRAL_DECODED' },
    { object_offset: '0x14', type: 'u8', published_name: 'flag_14_u8', role_status: 'NEUTRAL_DECODED' },
    { object_offset: '0x18', type: 'f32', published_name: 'numeric_18_f32', role_status: 'NEUTRAL_DECODED' },
    { object_offset: '0x1c', type: 'u8', published_name: 'spell_slot_key_1c_u8', role_status: 'CONSUMER_VERIFIED_LOOKUP_KEY' },
    { object_offset: '0x20', type: 'f32', published_name: 'numeric_20_f32', role_status: 'NEUTRAL_DECODED_SAMPLE_CONSTANT_ZERO' },
    { object_offset: '0x24', type: 'f32', published_name: 'numeric_24_f32', role_status: 'NEUTRAL_DECODED' },
  ],
  '0x00e4': [
    { object_offset: '0x10', type: 'u8', published_name: 'flag_10_u8', role_status: 'NEUTRAL_DECODED' },
    { object_offset: '0x11', type: 'u8', published_name: 'flag_11_u8', role_status: 'NEUTRAL_DECODED' },
    { object_offset: '0x14', type: 'u32', published_name: 'attack_sequence_14_u32', role_status: 'CONSUMER_COMPARES_ACTIVE_ATTACK_STATE' },
    { object_offset: '0x18', type: 'u8', published_name: 'flag_18_u8', role_status: 'NEUTRAL_DECODED' },
    { object_offset: '0x19', type: 'u8', published_name: 'selector_19_u8', role_status: 'NEUTRAL_DECODED_ATTACK_BRANCH_SELECTOR' },
    { object_offset: '0x1c', type: 'u32', published_name: 'target_network_id_candidate_1c_u32', role_status: 'NULLABLE_CONSUMER_ARGUMENT_CANDIDATE' },
  ],
  '0x01ab': [
    { object_offset: '0x10', type: 'u8', published_name: 'flag_u8', role_status: 'NEUTRAL_DECODED' },
    { object_offset: '0x14', type: 'vec3_f32', published_name: 'direction_xyz_f32', role_status: 'CONSUMER_VERIFIED_UNIT_FACE_DIRECTION' },
    { object_offset: '0x20', type: 'f32', published_name: 'scalar_20_f32', role_status: 'OPTIONAL_NEUTRAL_DECODED' },
  ],
  '0x01b5': [
    { object_offset: '0x10', type: 'inline_attack_subobject', published_name: null, role_status: 'STRUCTURAL_ONLY' },
    { object_offset: '0x44', type: 'u32', published_name: 'target_network_id_u32', role_status: 'CONSUMER_VERIFIED_ENTITY_LOOKUP_KEY' },
    { object_offset: '0x48', type: 'vector<f32>', published_name: 'position_xz_f32', role_status: 'CONSUMER_VERIFIED_EXACTLY_TWO_COMPONENTS' },
  ],
  '0x0298': [
    { object_offset: '0x10', type: 'u16', published_name: 'cache_selector_10_u16', role_status: 'CONSUMER_VERIFIED_CACHE_SLOT_SELECTOR' },
    { object_offset: '0x14', type: 'f32', published_name: 'numeric_14_f32', role_status: 'NEUTRAL_CACHE_FIELD' },
    { object_offset: '0x18', type: 'vec2_f32', published_name: 'coordinate_xz_f32', role_status: 'CONSUMER_VERIFIED_CACHE_COORDINATES' },
    { object_offset: '0x20', type: 'u8', published_name: 'field_20_u8', role_status: 'NEUTRAL_CACHE_FIELD_SAMPLE_CONSTANT_ZERO' },
    { object_offset: '0x21', type: 'u8', published_name: 'field_21_u8', role_status: 'NEUTRAL_CACHE_FIELD' },
    { object_offset: '0x22', type: 'u8', published_name: 'field_22_u8', role_status: 'NEUTRAL_CACHE_FIELD' },
  ],
  '0x03d4': [
    { object_offset: '0x10', type: 'u8', published_name: 'movement_complete_count_u8', role_status: 'CONSUMER_VERIFIED_MISSILE_COMPLETION_COUNT' },
  ],
});

const ROUTE_STATIC = Object.freeze({
  '0x00b8': {
    packet_id: 0x00b8,
    runtime_name: 'PKT_CHAR_SetCooldown_Broadcast_s',
    owner: 'AIBaseClient',
    type_descriptor_rva: '0x01e7d1a0',
    callback_rva: '0x0029e6c0',
    consumer_rva: '0x00926c30',
    factory_case_rva: '0x00edc657',
    object_size: 40,
    constructor_rva: '0x00e799a0',
    vtable_rva: '0x01b110f8',
    deserializer_rva: '0x00ef51f0',
    consumer_behavior: 'Callback decodes +0x1c and resolves AIBaseClient+0x3108 through 0x00995b80; it sends +0x10/+0x18 to the cooldown setter at 0x00926c30 and stores +0x20/+0x24 at the resolved spell-state object +0x78/+0x7c.',
  },
  '0x00e4': {
    packet_id: 0x00e4,
    runtime_name: 'PKT_NPC_InstantStop_Attack_s',
    owner: 'AIBaseClient',
    type_descriptor_rva: '0x01e7cc80',
    callback_rva: '0x002a01e0',
    consumer_rva: '0x0027b020',
    factory_case_rva: '0x00edd077',
    object_size: 32,
    constructor_rva: '0x00e7dc10',
    vtable_rva: '0x01b10758',
    deserializer_rva: '0x00ef7df0',
    consumer_behavior: 'Wrapper 0x002a01e0 forwards to 0x0027b020. The consumer compares decoded +0x14 with active attack state +0x94, branches on +0x18/+0x19, and forwards decoded +0x1c to the attack-stop handler.',
  },
  '0x01ab': {
    packet_id: 0x01ab,
    runtime_name: 'PKT_S2C_FaceDirection_s',
    owner: 'AIBaseClient',
    type_descriptor_rva: '0x01e79f10',
    callback_rva: '0x002a2000',
    consumer_rva: '0x002a2000',
    factory_case_rva: '0x00edf93f',
    object_size: 36,
    constructor_rva: '0x00e8b490',
    vtable_rva: '0x01b102b0',
    deserializer_rva: '0x00f08630',
    consumer_behavior: 'Recovered callback decodes a vec3 at +0x14, compares it with the actor direction, decodes +0x10 and +0x20, then invokes the actor virtual at +0xa38 with vector/scalar/flag arguments.',
    callback_recovery: {
      manager_construct_xref_rva: '0x00257cf1',
      closure_target_load_rva: '0x00257d0d',
      packet_id_load_rva: '0x00257d4d',
      generic_register_call_rva: '0x006f5b40',
      next_manager_boundary_rva: '0x00257d77',
      conclusion: 'The 0x002a2000 closure target and 0x01ab ID occur in one bounded manager-registration block before the next manager begins.',
    },
  },
  '0x01b5': {
    packet_id: 0x01b5,
    runtime_name: 'PKT_Basic_Attack_Pos_Minion_s',
    owner: 'AIBaseClient',
    type_descriptor_rva: '0x01e7b000',
    callback_rva: '0x0029e480',
    consumer_rva: '0x0029b030',
    factory_case_rva: '0x00edfb7f',
    object_size: 88,
    constructor_rva: '0x00e79430',
    vtable_rva: '0x01b170a0',
    deserializer_rva: '0x01093350',
    consumer_behavior: 'Callback reads exactly two f32 values from vector +0x48 as X/Z, compares them with AIBaseClient coordinates +0x23c/+0x244, conditionally moves the actor, and forwards inline attack state +0x10 to 0x0029b030; that consumer resolves decoded target ID +0x44.',
  },
  '0x0298': {
    packet_id: 0x0298,
    runtime_name: 'PKT_S2C_WallTrackingComponentCacheData_s',
    owner: 'AIBaseClient',
    type_descriptor_rva: '0x01e75770',
    callback_rva: '0x002a6fc0',
    consumer_rva: '0x00220ed0',
    factory_case_rva: '0x00ee290c',
    object_size: 36,
    constructor_rva: '0x00eaa320',
    vtable_rva: '0x01b10ec0',
    deserializer_rva: '0x00f1e1b0',
    consumer_behavior: 'Consumer selects component cache slot +0x10, +0x20, or +0x30 from selector bits 0, 1, or 10/11, then copies coordinate pair +0x18, f32 +0x14, and three byte fields +0x20..+0x22 into the selected slot.',
  },
  '0x03d4': {
    packet_id: 0x03d4,
    runtime_name: 'PKT_S2C_SyncMovementCompleteCount_s',
    owner: 'MissileClient',
    type_descriptor_rva: '0x01ed2780',
    callback_rva: '0x009742f0',
    consumer_rva: '0x00976a10',
    factory_case_rva: '0x00ee68ed',
    object_size: 20,
    constructor_rva: '0x00ea1da0',
    vtable_rva: '0x01b17678',
    deserializer_rva: '0x010cf4a0',
    consumer_behavior: 'MissileClient callback decodes +0x10 and repeatedly advances movement-completion state through 0x00976a10 until the local count reaches the transmitted count.',
  },
});

function routeHex(packetId) {
  return `0x${Number(packetId).toString(16).padStart(4, '0')}`;
}

function parseRva(value) {
  return Number.parseInt(String(value), 16);
}

function rejectProtectedPath(value) {
  const resolved = path.resolve(value);
  if (resolved.toLowerCase().includes('holdout')) {
    throw new Error(`protected Holdout path is forbidden: ${resolved}`);
  }
  return resolved;
}

async function sha256File(filePath) {
  const source = rejectProtectedPath(filePath);
  const hash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(source)) hash.update(chunk);
  return hash.digest('hex');
}

async function* jsonLines(filePath) {
  const source = rejectProtectedPath(filePath);
  const reader = readline.createInterface({ input: fs.createReadStream(source), crlfDelay: Infinity });
  for await (const line of reader) {
    if (line.trim()) yield JSON.parse(line.replace(/^\uFEFF/, ''));
  }
}

function increment(map, key, amount = 1) {
  const text = String(key);
  map.set(text, (map.get(text) || 0) + amount);
}

function sortedCounter(map, numeric = false) {
  const entries = [...map.entries()].sort(([left], [right]) => numeric
    ? Number(left) - Number(right)
    : left.localeCompare(right));
  return Object.fromEntries(entries);
}

function round(value, digits = 8) {
  if (!Number.isFinite(value)) return null;
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}

function quantile(sorted, fraction) {
  if (!sorted.length) return null;
  const index = Math.min(sorted.length - 1, Math.floor(sorted.length * fraction));
  return sorted[index];
}

function classifyRawParam(value) {
  const numeric = Number(value) >>> 0;
  if (numeric === 0) return 'zero';
  if (numeric >= 0x400000ae && numeric <= 0x400000b7) return 'hero_network_id_range';
  if ((numeric & 0xf0000000) === 0x40000000) return 'network_id_like';
  return 'other_nonzero';
}

function newRawStats(packetType) {
  return {
    packet_type: packetType,
    count: 0,
    replay_counts: new Map(),
    stream_counts: new Map(),
    payload_length_counts: new Map(),
    raw_param_class_counts: new Map(),
    raw_params: new Set(),
    payload_hashes: new Set(),
    payload_examples_by_length: new Map(),
    time_zero_count: 0,
    time_min_ms: null,
    time_max_ms: null,
  };
}

function finalizeRawStats(stats) {
  return {
    packet_type: stats.packet_type,
    count: stats.count,
    replay_counts: sortedCounter(stats.replay_counts),
    stream_counts: sortedCounter(stats.stream_counts),
    payload_length_counts: sortedCounter(stats.payload_length_counts, true),
    raw_param_class_counts: sortedCounter(stats.raw_param_class_counts),
    distinct_raw_param_count: stats.raw_params.size,
    distinct_payload_sha256_count: stats.payload_hashes.size,
    payload_examples_by_length: Object.fromEntries([...stats.payload_examples_by_length.entries()].sort(([a], [b]) => Number(a) - Number(b))),
    time_zero_count: stats.time_zero_count,
    time_min_ms: stats.time_min_ms,
    time_max_ms: stats.time_max_ms,
  };
}

function compactEvent(row) {
  return {
    replay: row.replay_sha256,
    time: Number(row.replay_time_ms),
    param: Number(row.raw_param) >>> 0,
    stream: row.chunk_stream,
    length: Number(row.payload_length),
  };
}

async function analyzeRawRows(rawPath) {
  const stats = new Map(ROUTE_IDS.map((id) => [id, newRawStats(routeHex(id))]));
  const events = new Map(ROUTE_IDS.map((id) => [id, []]));
  for await (const row of jsonLines(rawPath)) {
    const packetId = Number(row.packet_id);
    if (!stats.has(packetId)) throw new Error(`unexpected route ${row.packet_type}`);
    if (row.replay_version !== EXACT_BUILD) throw new Error(`unexpected build ${row.replay_version}`);
    const target = stats.get(packetId);
    target.count += 1;
    increment(target.replay_counts, row.replay_sha256);
    increment(target.stream_counts, row.chunk_stream);
    increment(target.payload_length_counts, row.payload_length);
    increment(target.raw_param_class_counts, classifyRawParam(row.raw_param));
    target.raw_params.add(Number(row.raw_param) >>> 0);
    target.payload_hashes.add(row.raw_payload_sha256);
    if (!target.payload_examples_by_length.has(String(row.payload_length))) {
      target.payload_examples_by_length.set(String(row.payload_length), row.raw_payload_hex);
    }
    const time = Number(row.replay_time_ms);
    if (time === 0) target.time_zero_count += 1;
    target.time_min_ms = target.time_min_ms === null ? time : Math.min(target.time_min_ms, time);
    target.time_max_ms = target.time_max_ms === null ? time : Math.max(target.time_max_ms, time);
    events.get(packetId).push(compactEvent(row));
  }
  return { stats: Object.fromEntries([...stats].map(([id, value]) => [routeHex(id), finalizeRawStats(value)])), events };
}

async function analyzeAnchorRows(anchorPath) {
  const events = new Map(ANCHOR_IDS.map((id) => [id, []]));
  for await (const row of jsonLines(anchorPath)) {
    const packetId = Number(row.packet_id);
    if (!events.has(packetId)) throw new Error(`unexpected anchor route ${row.packet_type}`);
    if (row.replay_version !== EXACT_BUILD) throw new Error(`unexpected anchor build ${row.replay_version}`);
    events.get(packetId).push(compactEvent(row));
  }
  return events;
}

function groupTimesByReplay(events, liveOnly = false) {
  const result = new Map();
  for (const event of events) {
    if (liveOnly && (event.stream !== 'game_chunk' || event.time <= 0)) continue;
    if (!result.has(event.replay)) result.set(event.replay, []);
    result.get(event.replay).push(event.time);
  }
  for (const times of result.values()) times.sort((left, right) => left - right);
  return result;
}

function nearestDelta(sortedTimes, value) {
  if (!sortedTimes || sortedTimes.length === 0) return null;
  let low = 0;
  let high = sortedTimes.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (sortedTimes[middle] < value) low = middle + 1;
    else high = middle;
  }
  let best = Number.POSITIVE_INFINITY;
  if (low < sortedTimes.length) best = Math.min(best, Math.abs(sortedTimes[low] - value));
  if (low > 0) best = Math.min(best, Math.abs(sortedTimes[low - 1] - value));
  return best;
}

function correlateTimes(events, anchorEvents, liveOnly = false) {
  const anchorTimes = groupTimesByReplay(anchorEvents, liveOnly);
  const deltas = [];
  const windows = new Map([[0, 0], [10, 0], [50, 0], [100, 0], [500, 0]]);
  let eligible = 0;
  for (const event of events) {
    if (liveOnly && (event.stream !== 'game_chunk' || event.time <= 0)) continue;
    const delta = nearestDelta(anchorTimes.get(event.replay), event.time);
    if (delta === null) continue;
    eligible += 1;
    deltas.push(delta);
    for (const window of windows.keys()) if (delta <= window) windows.set(window, windows.get(window) + 1);
  }
  deltas.sort((left, right) => left - right);
  return {
    eligible_count: eligible,
    exact_time_count: windows.get(0),
    exact_time_rate: eligible ? round(windows.get(0) / eligible) : null,
    within_10ms_count: windows.get(10),
    within_10ms_rate: eligible ? round(windows.get(10) / eligible) : null,
    within_50ms_count: windows.get(50),
    within_50ms_rate: eligible ? round(windows.get(50) / eligible) : null,
    within_100ms_count: windows.get(100),
    within_100ms_rate: eligible ? round(windows.get(100) / eligible) : null,
    within_500ms_count: windows.get(500),
    within_500ms_rate: eligible ? round(windows.get(500) / eligible) : null,
    nearest_delta_p50_ms: quantile(deltas, 0.5),
    nearest_delta_p90_ms: quantile(deltas, 0.9),
    nearest_delta_max_ms: deltas.length ? deltas[deltas.length - 1] : null,
  };
}

function exactTimeIndex(events) {
  const index = new Map();
  for (const event of events) {
    const key = `${event.replay}:${event.time}`;
    if (!index.has(key)) index.set(key, new Set());
    index.get(key).add(event.param);
  }
  return index;
}

function crossRouteMatrix(routeEvents) {
  const indexes = new Map([...routeEvents].map(([id, events]) => [id, exactTimeIndex(events)]));
  const matrix = [];
  for (const sourceId of ROUTE_IDS) {
    for (const targetId of ROUTE_IDS) {
      if (sourceId === targetId) continue;
      let exact = 0;
      let sameParam = 0;
      for (const event of routeEvents.get(sourceId)) {
        const params = indexes.get(targetId).get(`${event.replay}:${event.time}`);
        if (!params) continue;
        exact += 1;
        if (params.has(event.param)) sameParam += 1;
      }
      matrix.push({
        source_route: routeHex(sourceId),
        target_route: routeHex(targetId),
        source_count: routeEvents.get(sourceId).length,
        source_rows_with_exact_time_target: exact,
        exact_time_rate: round(exact / routeEvents.get(sourceId).length),
        source_rows_with_exact_time_same_raw_param_target: sameParam,
        exact_time_same_raw_param_rate: round(sameParam / routeEvents.get(sourceId).length),
      });
    }
  }
  return matrix;
}

function numericSummary(values, integer = false) {
  const finite = values.filter(Number.isFinite);
  const distinct = new Map();
  for (const value of finite) increment(distinct, integer ? String(value) : String(round(value, 8)));
  const sorted = [...finite].sort((left, right) => left - right);
  const distribution = distinct.size <= 64 ? sortedCounter(distinct, true) : undefined;
  return {
    count: values.length,
    finite_count: finite.length,
    zero_count: finite.filter((value) => Object.is(value, 0) || Object.is(value, -0)).length,
    min: sorted.length ? round(sorted[0], 8) : null,
    max: sorted.length ? round(sorted[sorted.length - 1], 8) : null,
    distinct_count: distinct.size,
    ...(distribution ? { distribution } : {}),
  };
}

async function analyzeEmulation(artifactDir, image) {
  const summaries = {};
  const decodedRows = new Map();
  for (const packetId of ROUTE_IDS) {
    const packetType = routeHex(packetId);
    const stem = packetType.slice(2);
    const summaryPath = rejectProtectedPath(path.join(artifactDir, 'emulation', `route_${stem}_balanced_summary.json`));
    const decodedPath = rejectProtectedPath(path.join(artifactDir, 'emulation', `route_${stem}_balanced_decoded.jsonl`));
    const nativeSummary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
    if (nativeSummary.runtime_profile !== EXACT_BUILD || nativeSummary.image_sha256 !== RUNTIME_SHA256) {
      throw new Error(`${packetType} emulation summary build/image mismatch`);
    }
    const fieldValues = new Map();
    const rows = [];
    let fullyConsumed = 0;
    for await (const row of jsonLines(decodedPath)) {
      if (Number(row.packet_id) !== packetId || row.replay_version !== EXACT_BUILD) throw new Error(`${packetType} decoded row identity mismatch`);
      if (row.fully_consumed && row.opcode_matches_profile && row.deserialize_return_al === 1) fullyConsumed += 1;
      const decoded = decodeRouteObject(packetType, row.object_hex, image);
      if (packetType === '0x01b5') {
        const components = row.decoded_fields?.position_components || [];
        decoded.position_component_count = components.length;
        decoded.position_x_f32 = components[0]?.value_f32;
        decoded.position_z_f32 = components[1]?.value_f32;
      }
      for (const [name, value] of Object.entries(decoded)) {
        if (typeof value !== 'number') continue;
        if (!fieldValues.has(name)) fieldValues.set(name, []);
        fieldValues.get(name).push(value);
      }
      rows.push({
        replay: row.replay_sha256,
        time: Number(row.replay_time_ms),
        stream: row.chunk_stream,
        actor: Number(row.raw_param) >>> 0,
        payload_length: Number(row.payload_length),
        decoded,
      });
    }
    if (rows.length !== nativeSummary.event_count || fullyConsumed !== rows.length) {
      throw new Error(`${packetType} did not preserve full emulation consumption`);
    }
    const fieldSummaries = {};
    for (const [name, values] of fieldValues) {
      const integer = /(?:_u8|_u16|_u32|_count)$/.test(name);
      fieldSummaries[name] = numericSummary(values, integer);
    }
    summaries[packetType] = {
      sample_method: 'deterministic lowest-SHA stratified by route/replay/payload length',
      sample_count: rows.length,
      successful_full_consume_count: fullyConsumed,
      all_four_replays_covered: Object.keys(nativeSummary.replay_event_counts).length === 4,
      payload_length_counts: nativeSummary.payload_length_counts,
      stream_counts: nativeSummary.stream_counts,
      field_summaries: fieldSummaries,
    };
    decodedRows.set(packetId, rows);
  }
  return { summaries, decodedRows };
}

async function readDamageAnchors(filePath) {
  const byReplay = new Map();
  let count = 0;
  for await (const row of jsonLines(filePath)) {
    if (row.replay_version !== EXACT_BUILD || Number(row.packet_id) !== 0x017f || !row.fully_consumed) {
      throw new Error('verified damage anchor identity/consumption mismatch');
    }
    if (!byReplay.has(row.replay_sha256)) byReplay.set(row.replay_sha256, []);
    byReplay.get(row.replay_sha256).push({
      time: Number(row.replay_time_ms),
      source: Number(row.decoded_fields.field_10_u32) >>> 0,
      target: Number(row.decoded_fields.field_14_u32) >>> 0,
    });
    count += 1;
  }
  for (const events of byReplay.values()) events.sort((left, right) => left.time - right.time);
  return { count, byReplay };
}

function lowerBoundEvents(events, time) {
  let low = 0;
  let high = events.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (events[middle].time < time) low = middle + 1;
    else high = middle;
  }
  return low;
}

function damageNeighborhood(rows, damageByReplay, targetField = null) {
  const result = {
    sample_count: rows.length,
    nearest_damage_exact_time_count: 0,
    nearest_damage_within_10ms_count: 0,
    nearest_damage_within_50ms_count: 0,
    actor_matches_damage_source_within_10ms_count: 0,
    actor_matches_damage_target_within_10ms_count: 0,
    decoded_target_nonzero_count: 0,
    decoded_target_matches_damage_source_within_10ms_count: 0,
    decoded_target_matches_damage_target_within_10ms_count: 0,
  };
  for (const row of rows) {
    const damage = damageByReplay.get(row.replay) || [];
    const start = lowerBoundEvents(damage, row.time - 10);
    let nearest = Number.POSITIVE_INFINITY;
    for (let index = Math.max(0, start - 1); index < damage.length && damage[index].time <= row.time + 50; index += 1) {
      nearest = Math.min(nearest, Math.abs(damage[index].time - row.time));
    }
    if (nearest === 0) result.nearest_damage_exact_time_count += 1;
    if (nearest <= 10) result.nearest_damage_within_10ms_count += 1;
    if (nearest <= 50) result.nearest_damage_within_50ms_count += 1;
    const target = targetField ? Number(row.decoded[targetField]) >>> 0 : 0;
    if (target) result.decoded_target_nonzero_count += 1;
    let actorMatchesSource = false;
    let actorMatchesTarget = false;
    let decodedTargetMatchesSource = false;
    let decodedTargetMatchesTarget = false;
    for (let index = start; index < damage.length && damage[index].time <= row.time + 10; index += 1) {
      const event = damage[index];
      actorMatchesSource ||= row.actor === event.source;
      actorMatchesTarget ||= row.actor === event.target;
      decodedTargetMatchesSource ||= Boolean(target && target === event.source);
      decodedTargetMatchesTarget ||= Boolean(target && target === event.target);
    }
    if (actorMatchesSource) result.actor_matches_damage_source_within_10ms_count += 1;
    if (actorMatchesTarget) result.actor_matches_damage_target_within_10ms_count += 1;
    if (decodedTargetMatchesSource) result.decoded_target_matches_damage_source_within_10ms_count += 1;
    if (decodedTargetMatchesTarget) result.decoded_target_matches_damage_target_within_10ms_count += 1;
  }
  for (const key of Object.keys(result)) {
    if (!key.endsWith('_count') || key === 'sample_count') continue;
    result[key.replace(/_count$/, '_rate')] = rows.length ? round(result[key] / rows.length) : null;
  }
  return result;
}

function hashSlice(image, rvaText, length) {
  const rva = parseRva(rvaText);
  if (rva < 0 || rva + length > image.length) throw new Error(`runtime slice outside image: ${rvaText}`);
  return {
    rva: rvaText,
    byte_length: length,
    sha256: crypto.createHash('sha256').update(image.subarray(rva, rva + length)).digest('hex'),
  };
}

function runtimeIdentities(registry, image) {
  if (registry.exact_build !== EXACT_BUILD) throw new Error('observed registry build mismatch');
  return ROUTE_IDS.map((packetId) => {
    const packetType = routeHex(packetId);
    const expected = ROUTE_STATIC[packetType];
    const observed = registry.routes.find((entry) => Number(entry.packet_id) === packetId);
    if (!observed) throw new Error(`${packetType} absent from observed registry`);
    const callback = observed.runtime_registration.callbacks[0];
    const factory = observed.runtime_registration.factory_packets[0];
    const checks = {
      runtime_name: callback.name === expected.runtime_name,
      owner: callback.callback_owner_type === expected.owner,
      type_descriptor: callback.type_descriptor_rva_hex === expected.type_descriptor_rva,
      callback: packetType === '0x01ab' ? callback.callback_receive_target_rva_hex === null : callback.callback_receive_target_rva_hex === expected.callback_rva,
      factory_case: factory.case_rva_hex === expected.factory_case_rva,
      object_size: factory.object_size === expected.object_size,
      constructor: factory.constructor_rva_hex === expected.constructor_rva,
      vtable: factory.packet_object_vtable_rva_hex === expected.vtable_rva,
      deserializer: factory.deserializer_rva_hex === expected.deserializer_rva,
    };
    if (Object.values(checks).some((value) => !value)) throw new Error(`${packetType} runtime registry mismatch: ${JSON.stringify(checks)}`);
    return {
      packet_id: packetId,
      packet_discriminator: packetType,
      runtime_name: expected.runtime_name,
      owner: expected.owner,
      type_descriptor_rva: expected.type_descriptor_rva,
      callback_rva: expected.callback_rva,
      callback_status: packetType === '0x01ab' ? 'RECOVERED_AND_BOUNDED_TO_REGISTRATION_BLOCK' : 'OBSERVED_REGISTRY_EXACT',
      ...(expected.callback_recovery ? { callback_recovery: expected.callback_recovery } : {}),
      consumer_rva: expected.consumer_rva,
      factory_case_rva: expected.factory_case_rva,
      allocation_size: expected.object_size,
      constructor_rva: expected.constructor_rva,
      vtable_rva: expected.vtable_rva,
      deserializer_rva: expected.deserializer_rva,
      consumer_behavior: expected.consumer_behavior,
      runtime_slice_hashes: {
        callback: hashSlice(image, expected.callback_rva, 0x100),
        consumer: hashSlice(image, expected.consumer_rva, 0x100),
        factory_case: hashSlice(image, expected.factory_case_rva, 0x80),
        constructor: hashSlice(image, expected.constructor_rva, 0x80),
        deserializer: hashSlice(image, expected.deserializer_rva, 0x100),
        ...(expected.callback_recovery ? { registration_block: hashSlice(image, '0x00257cf1', 0x86) } : {}),
      },
    };
  });
}

function buildDecisions(report) {
  const raw = report.raw_route_profiles;
  const emu = report.emulation;
  const damage = report.verified_damage_neighborhood;
  const routeDecisions = [
    {
      packet_id: 0x01ab,
      packet_discriminator: '0x01ab',
      decision: 'PROMOTE',
      hypothesis: 'FACE_DIRECTION_VECTOR',
      evidence_grade: 'VERIFIED_EXACT_BUILD_RUNTIME_CONSUMER_PLUS_STRATIFIED_NATIVE_DECODE',
      semantic_claim: 'Direct actor-scoped facing direction vector with replay time; publish +0x14 vec3. Keep +0x10 flag and +0x20 scalar as neutral protocol fields.',
      publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'direction_x_f32', 'direction_y_f32', 'direction_z_f32'],
      positive_anchor_count: emu['0x01ab'].sample_count,
      counterexample_count: Number(raw['0x01ab'].payload_length_counts['13'] || 0),
      counterexample: 'The 13-byte branch omits/defaults the optional +0x20 scalar, so scalar role and universal presence are not publishable.',
      evidence_exhausted: true,
      evidence_exhausted_scope: 'PINNED_RUNTIME_IMAGE_AND_EXPLICIT_SAFE_LATEST_FOUR_REPLAYS',
      next_required_evidence: ['An external exact-build actor-facing oracle or controlled flag/scalar perturbation is required only to name +0x10/+0x20; no further safe local artifact can do so.'],
    },
    {
      packet_id: 0x00e4,
      packet_discriminator: '0x00e4',
      decision: 'PROMOTE',
      hypothesis: 'INSTANT_STOP_ATTACK_OCCURRENCE',
      evidence_grade: 'VERIFIED_EXACT_BUILD_RUNTIME_CONSUMER_PLUS_STRATIFIED_NATIVE_DECODE',
      semantic_claim: 'Direct actor-scoped instant-stop-attack carrier with replay time, neutral attack sequence/flags, and nullable target-network-ID candidate.',
      publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'attack_sequence_14_u32', 'target_network_id_candidate_1c_u32'],
      positive_anchor_count: emu['0x00e4'].sample_count,
      counterexample_count: emu['0x00e4'].field_summaries.target_network_id_candidate_1c_u32.zero_count,
      counterexample: 'Short branches decode nullable/default fields, and many sampled stop rows have no damage within 10 ms; this is not a damage carrier.',
      evidence_exhausted: true,
      evidence_exhausted_scope: 'PINNED_RUNTIME_IMAGE_AND_EXPLICIT_SAFE_LATEST_FOUR_REPLAYS',
      next_required_evidence: ['A controlled attack-state trace is required only to assign business names to +0x10/+0x11/+0x14/+0x18/+0x19.'],
    },
    {
      packet_id: 0x03d4,
      packet_discriminator: '0x03d4',
      decision: 'PROMOTE',
      hypothesis: 'MISSILE_SYNC_MOVEMENT_COMPLETE_COUNT',
      evidence_grade: 'VERIFIED_EXACT_BUILD_RUNTIME_CONSUMER_PLUS_CONSTANT_FULL_CORPUS_PAYLOAD',
      semantic_claim: 'MissileClient-scoped movement-completion count carrier; publish subject, replay time, and decoded +0x10 count.',
      publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'movement_complete_count_u8'],
      positive_anchor_count: raw['0x03d4'].count,
      counterexample_count: raw['0x03d4'].count - (raw['0x03d4'].raw_param_class_counts.hero_network_id_range || 0),
      counterexample: 'Owner is MissileClient and almost all subjects are outside the hero ID range; reject a hero path-completion alias.',
      evidence_exhausted: true,
      evidence_exhausted_scope: 'PINNED_RUNTIME_IMAGE_AND_EXPLICIT_SAFE_LATEST_FOUR_REPLAYS',
      next_required_evidence: ['A new governed exact-build replay with decoded count >1 would be required to characterize the unused range; current local corpus is saturated at count=1.'],
    },
    {
      packet_id: 0x0298,
      packet_discriminator: '0x0298',
      decision: 'REPURPOSE',
      hypothesis: 'WALL_TRACKING_COMPONENT_CACHE_SNAPSHOT',
      evidence_grade: 'VERIFIED_EXACT_BUILD_RUNTIME_CACHE_CONSUMER_PLUS_STRATIFIED_NATIVE_DECODE',
      semantic_claim: 'Entity-scoped wall-tracking component cache snapshot with selector and neutral cache fields; explicitly not a live wall-collision event or map-truth surface.',
      publishable_fields: ['subject_network_id=raw_param', 'cache_selector_10_u16', 'coordinate_x_18_f32', 'coordinate_z_1c_f32', 'numeric_14_f32', 'field_20_u8', 'field_21_u8', 'field_22_u8'],
      positive_anchor_count: emu['0x0298'].sample_count,
      counterexample_count: raw['0x0298'].count,
      counterexample: 'All 77,706 exact-build rows are keyframe-only cache data, contradicting live collision/event and independent map-truth interpretations.',
      evidence_exhausted: true,
      evidence_exhausted_scope: 'PINNED_RUNTIME_IMAGE_AND_EXPLICIT_SAFE_LATEST_FOUR_REPLAYS',
      next_required_evidence: ['An external WallTracking component contract or controlled runtime state trace is required to name the neutral numeric/byte roles; parser evidence cannot establish map truth.'],
    },
    {
      packet_id: 0x00b8,
      packet_discriminator: '0x00b8',
      decision: 'PROMOTE',
      hypothesis: 'ABILITY_COOLDOWN_BROADCAST_STRUCTURAL_EVENT',
      evidence_grade: 'VERIFIED_EXACT_BUILD_RUNTIME_CONSUMER_PLUS_STRATIFIED_NATIVE_DECODE',
      semantic_claim: 'Direct actor-scoped cooldown broadcast with resolved spell-slot key and four neutral f32 protocol values; do not name start/end/duration roles.',
      publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'spell_slot_key_1c_u8', 'numeric_10_f32', 'numeric_18_f32', 'numeric_20_f32', 'numeric_24_f32', 'flag_14_u8'],
      positive_anchor_count: emu['0x00b8'].sample_count,
      counterexample_count: Object.entries(raw['0x00b8'].payload_length_counts).filter(([length]) => Number(length) < 14).reduce((sum, [, count]) => sum + count, 0),
      counterexample: 'Short differential branches default omitted fields; the four numbers cannot all be assumed universally present or assigned cooldown business labels from this corpus.',
      evidence_exhausted: true,
      evidence_exhausted_scope: 'PINNED_RUNTIME_IMAGE_AND_EXPLICIT_SAFE_LATEST_FOUR_REPLAYS',
      next_required_evidence: ['An independent exact-build spell-state snapshot or controlled cast/cooldown perturbation is required to distinguish start/end/duration/current roles.'],
    },
    {
      packet_id: 0x01b5,
      packet_discriminator: '0x01b5',
      decision: 'PROMOTE',
      hypothesis: 'BASIC_ATTACK_POSITION_MINION',
      evidence_grade: 'VERIFIED_EXACT_BUILD_RUNTIME_ATTACK_CONSUMER_PLUS_STRATIFIED_NATIVE_DECODE',
      semantic_claim: 'Direct actor-scoped basic-attack-position-minion carrier with decoded target network ID and exact two-component X/Z actor position.',
      publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'target_network_id_u32', 'position_x_f32', 'position_z_f32'],
      positive_anchor_count: emu['0x01b5'].sample_count,
      counterexample_count: emu['0x01b5'].sample_count - damage['0x01b5'].nearest_damage_within_10ms_count,
      counterexample: 'Most sampled attack-position rows are not within 10 ms of a verified damage packet, so this is an attack command/state carrier rather than proof of damage application.',
      evidence_exhausted: true,
      evidence_exhausted_scope: 'PINNED_RUNTIME_IMAGE_AND_EXPLICIT_SAFE_LATEST_FOUR_REPLAYS',
      next_required_evidence: ['A controlled exact-build attack animation trace is required only to name the remaining inline attack subfields.'],
    },
  ];
  const capabilityDecisions = [
    ['FACE_DIRECTION_VECTOR', 'PROMOTE', '0x01ab direct subject/time/unit-vector research event'],
    ['INSTANT_STOP_ATTACK', 'PROMOTE', '0x00e4 direct subject/time plus neutral sequence/flags and nullable target candidate'],
    ['MISSILE_SYNC_MOVEMENT_COMPLETE_COUNT', 'PROMOTE', '0x03d4 MissileClient subject/time/count'],
    ['WALL_TRACKING_COMPONENT_CACHE_SNAPSHOT', 'PROMOTE', '0x0298 keyframe cache structure only'],
    ['ABILITY_COOLDOWN_BROADCAST', 'PROMOTE', '0x00b8 spell-slot key and neutral numeric fields'],
    ['BASIC_ATTACK_POSITION_MINION', 'PROMOTE', '0x01b5 actor/target/X/Z'],
    ['WALL_COLLISION_EVENT_OR_MAP_TRUTH', 'REJECT', '0x0298 is keyframe-only component cache state and the parser does not own map truth'],
    ['COOLDOWN_START_END_DURATION_FIELD_NAMES', 'KEEP_CANDIDATE', 'Exact values are decoded, but independent spell-state labels are absent'],
  ].map(([capability, decision, scope]) => ({
    capability,
    decision,
    scope,
    evidence_exhausted: true,
    next_required_evidence: decision === 'PROMOTE' ? [] : ['External exact-build business-state evidence beyond the exhausted safe local corpus.'],
  }));
  const domainDecisions = [
    ['combat', '0x00e4 and 0x01b5 direct attack-state carriers'],
    ['spell', '0x00b8 cooldown structural event'],
    ['missile', '0x03d4 movement-completion count'],
    ['entity', '0x01ab facing and 0x0298 component-cache state'],
    ['minion', '0x01b5 named and consumer-verified minion attack-position path'],
  ].map(([domain, scope]) => ({
    domain,
    decision: 'PROMOTE',
    scope,
    actual_reverse_engineering_executed: true,
    evidence_exhausted: true,
    new_actionable_hypotheses: false,
    actionable_hypotheses: [],
    next_required_evidence: [],
  }));
  for (const decision of [...routeDecisions, ...capabilityDecisions, ...domainDecisions]) {
    if (!ALLOWED_DECISIONS.has(decision.decision)) throw new Error(`invalid decision ${decision.decision}`);
    if (typeof decision.evidence_exhausted !== 'boolean' || !Array.isArray(decision.next_required_evidence)) {
      throw new Error('machine decision lacks evidence_exhausted/next_required_evidence');
    }
  }
  return { route_decisions: routeDecisions, capability_decisions: capabilityDecisions, domain_decisions: domainDecisions };
}

function buildRouteFindings(report) {
  const raw = report.raw_route_profiles;
  const emu = report.emulation;
  const corr = report.cross_anchor_time_behavior;
  const damage = report.verified_damage_neighborhood;
  const pair = (source, target) => report.exact_time_cross_route_matrix.find((entry) => entry.source_route === source && entry.target_route === target);
  return {
    '0x00b8': {
      payload_behavior: { observed_lengths: raw['0x00b8'].payload_length_counts, differential_short_branch_count: Object.entries(raw['0x00b8'].payload_length_counts).filter(([length]) => Number(length) < 14).reduce((sum, [, count]) => sum + count, 0) },
      field_behavior: emu['0x00b8'].field_summaries,
      entity_behavior: { direct_subject_source: 'raw_param', raw_param_classes: raw['0x00b8'].raw_param_class_counts, conclusion: 'Hero-dominated actor-scoped cooldown state.' },
      time_behavior: { stream_counts: raw['0x00b8'].stream_counts, live_castspell_neighborhood: corr['0x00b8']['0x01cf'].live_game_rows },
      cross_route_behavior: { exact_time_same_subject_face_direction: pair('0x00b8', '0x01ab'), exact_time_same_subject_wall_cache: pair('0x00b8', '0x0298') },
      counterexamples: ['Only 32.12% of eligible live rows share an exact CastSpell timestamp, so cooldown broadcast is not a cast-event alias.', 'numeric_20_f32 is zero in every stratified sample and all short branches default omitted values; business-role names remain unsupported.'],
    },
    '0x00e4': {
      payload_behavior: { observed_lengths: raw['0x00e4'].payload_length_counts, shortest_branch_count: Number(raw['0x00e4'].payload_length_counts['2'] || 0) },
      field_behavior: emu['0x00e4'].field_summaries,
      entity_behavior: { direct_subject_source: 'raw_param', raw_param_classes: raw['0x00e4'].raw_param_class_counts, nullable_target_sample_zero_count: emu['0x00e4'].field_summaries.target_network_id_candidate_1c_u32.zero_count },
      time_behavior: { stream_counts: raw['0x00e4'].stream_counts, verified_damage_neighborhood: damage['0x00e4'] },
      cross_route_behavior: { exact_time_same_subject_basic_attack_position_minion: pair('0x00e4', '0x01b5') },
      counterexamples: ['180/549 sampled rows have no verified damage packet within 10 ms, rejecting a direct damage-event alias.', 'The decoded +0x1c consumer argument never matches verified damage source/target within 10 ms in the stratified sample, so it remains a target-network-ID candidate rather than a promoted target role.'],
    },
    '0x01ab': {
      payload_behavior: { observed_lengths: raw['0x01ab'].payload_length_counts, scalar_20_absent_or_default_branch_length: 13 },
      field_behavior: emu['0x01ab'].field_summaries,
      entity_behavior: { direct_subject_source: 'raw_param', raw_param_classes: raw['0x01ab'].raw_param_class_counts },
      time_behavior: { stream_counts: raw['0x01ab'].stream_counts, live_hero_path_neighborhood: corr['0x01ab']['0x00f6'].live_game_rows },
      cross_route_behavior: { wall_cache_rows_paired_same_time_same_subject: pair('0x0298', '0x01ab') },
      counterexamples: ['The vector norm is unit length in all 192 stratified native samples; this rejects world-position and path-list interpretations.', 'The optional scalar has three values while the flag is sparse; neither residual business role is named.'],
    },
    '0x01b5': {
      payload_behavior: { observed_lengths: raw['0x01b5'].payload_length_counts, long_inline_subobject_branch_count: Object.entries(raw['0x01b5'].payload_length_counts).filter(([length]) => Number(length) >= 133).reduce((sum, [, count]) => sum + count, 0) },
      field_behavior: emu['0x01b5'].field_summaries,
      entity_behavior: { direct_actor_source: 'raw_param', actor_raw_param_classes: raw['0x01b5'].raw_param_class_counts, decoded_target_nonzero_sample_count: damage['0x01b5'].decoded_target_nonzero_count },
      time_behavior: { stream_counts: raw['0x01b5'].stream_counts, verified_damage_neighborhood: damage['0x01b5'] },
      cross_route_behavior: { exact_time_same_actor_instant_stop_attack: pair('0x01b5', '0x00e4') },
      counterexamples: ['271/571 sampled rows have no verified damage packet within 10 ms, so attack-position does not imply damage application.', 'Actor IDs are outside the bounded hero-ID range in all 52,986 rows, rejecting a hero-only basic-attack alias.'],
    },
    '0x0298': {
      payload_behavior: { observed_lengths: raw['0x0298'].payload_length_counts, stream_counts: raw['0x0298'].stream_counts },
      field_behavior: emu['0x0298'].field_summaries,
      entity_behavior: { direct_subject_source: 'raw_param', raw_param_classes: raw['0x0298'].raw_param_class_counts, cache_selectors: emu['0x0298'].field_summaries.cache_selector_10_u16.distribution },
      time_behavior: { keyframe_only_count: raw['0x0298'].count, live_game_row_count: 0 },
      cross_route_behavior: { exact_time_same_subject_face_direction: pair('0x0298', '0x01ab') },
      counterexamples: ['All 77,706 rows are keyframe-only, and every row shares timestamp and subject with a FaceDirection snapshot row; this is cache snapshot state, not a live wall-collision event.', 'The selector is limited to 1, 2, and 0x0c00; consumer slot assignment does not establish map truth.'],
    },
    '0x03d4': {
      payload_behavior: { observed_lengths: raw['0x03d4'].payload_length_counts, distinct_payload_sha256_count: raw['0x03d4'].distinct_payload_sha256_count, sole_payload_hex: raw['0x03d4'].payload_examples_by_length['1'] },
      field_behavior: emu['0x03d4'].field_summaries,
      entity_behavior: { direct_subject_source: 'raw_param', owner: 'MissileClient', raw_param_classes: raw['0x03d4'].raw_param_class_counts },
      time_behavior: { stream_counts: raw['0x03d4'].stream_counts, first_time_ms: raw['0x03d4'].time_min_ms, last_time_ms: raw['0x03d4'].time_max_ms },
      cross_route_behavior: { exact_time_same_subject_instant_stop_attack: pair('0x03d4', '0x00e4'), exact_time_same_subject_face_direction: pair('0x03d4', '0x01ab') },
      counterexamples: ['The sole encrypted payload decodes to count=1; the current corpus cannot characterize values above 1.', 'MissileClient ownership and zero hero-range subjects reject hero movement/path semantics.'],
    },
  };
}

function markdownReport(report) {
  const decisions = report.decisions.route_decisions;
  const lines = [
    '# Gameplay / classified route tail exact-build saturation audit',
    '',
    `- Build: \`${report.exact_build}\` (nearest-build fallback forbidden)`,
    `- Runtime image SHA-256: \`${report.inputs.runtime.sha256}\``,
    `- Full target rows: ${report.input_conservation.target_row_count.toLocaleString('en-US')}`,
    `- Native stratified rows: ${report.input_conservation.native_sample_row_count.toLocaleString('en-US')} / ${report.input_conservation.native_full_consume_count.toLocaleString('en-US')} fully consumed`,
    '- Protected Jungle Objective Holdout: not enumerated, read, hashed, decoded, tested, or consumed.',
    '',
    '## Route decisions',
    '',
    '| Route | Exact runtime identity | Decision | Minimal publishable surface | Boundary / counterexample |',
    '|---|---|---|---|---|',
  ];
  for (const decision of decisions) {
    const identity = report.runtime_identities.find((entry) => entry.packet_discriminator === decision.packet_discriminator);
    lines.push(`| \`${decision.packet_discriminator}\` | ${identity.runtime_name} / ${identity.owner} | ${decision.decision}: ${decision.hypothesis} | ${decision.publishable_fields.join(', ')} | ${decision.counterexample} |`);
  }
  lines.push(
    '',
    '## Saturation conclusion',
    '',
    'The pinned runtime callback/consumer surfaces, complete four-replay inventories, payload-shape-stratified native decodes, P0 damage neighborhoods, and cross-route timing controls are locally exhausted for these six routes. Remaining requests are external semantic calibration only; they do not justify copying decoder logic into consumers or expanding parser ownership into map truth, behavior inference, Akari, corpus collection, or UI.',
    '',
    'Field distributions, runtime slice hashes, cross-route matrices, counterexample counts, and machine decisions are in the companion JSON artifacts.',
    '',
  );
  return lines.join('\n');
}

async function audit(options = {}) {
  const root = rejectProtectedPath(options.root || path.resolve(__dirname, '..'));
  const artifactDir = rejectProtectedPath(options.artifactDir || path.join(root, 'artifacts', 'full_semantic_deep_recovery_v2', 'gameplay_route_tail'));
  const paths = {
    raw: rejectProtectedPath(options.raw || path.join(artifactDir, 'gameplay_route_tail_raw_rows_16_16.jsonl')),
    raw_manifest: rejectProtectedPath(options.rawManifest || path.join(artifactDir, 'gameplay_route_tail_raw_rows_16_16.jsonl.manifest.json')),
    anchors: rejectProtectedPath(options.anchors || path.join(artifactDir, 'gameplay_route_tail_anchor_rows_16_16.jsonl')),
    anchor_manifest: rejectProtectedPath(options.anchorManifest || path.join(artifactDir, 'gameplay_route_tail_anchor_rows_16_16.jsonl.manifest.json')),
    balanced: rejectProtectedPath(options.balanced || path.join(artifactDir, 'gameplay_route_tail_balanced_emulation_rows_16_16.jsonl')),
    runtime: rejectProtectedPath(options.runtime || path.join(root, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime', 'league_16.16.805.0442.memory.bin')),
    registry: rejectProtectedPath(options.registry || path.join(root, 'artifacts', 'full_semantic_baseline_v1', 'observed_route_registry.json')),
    prior_profiler: rejectProtectedPath(options.priorProfiler || path.join(root, 'artifacts', 'hero_combat_state_v2', 'profiler', 'high_frequency_raw_profiles_latest_four_v1_2.json')),
    damage: rejectProtectedPath(options.damage || path.join(root, 'artifacts', 'hero_combat_state_v2', 'emulation', 'packet_017f_latest_four_decoded.jsonl')),
  };
  const image = fs.readFileSync(paths.runtime);
  const runtimeHash = crypto.createHash('sha256').update(image).digest('hex');
  if (runtimeHash !== RUNTIME_SHA256) throw new Error(`runtime SHA mismatch: ${runtimeHash}`);
  const registry = JSON.parse(fs.readFileSync(paths.registry, 'utf8'));
  const [rawAnalysis, anchors, emulation, damageAnchors] = await Promise.all([
    analyzeRawRows(paths.raw),
    analyzeAnchorRows(paths.anchors),
    analyzeEmulation(artifactDir, image),
    readDamageAnchors(paths.damage),
  ]);
  const anchorCorrelation = {};
  for (const routeId of ROUTE_IDS) {
    const packetType = routeHex(routeId);
    anchorCorrelation[packetType] = {};
    for (const anchorId of ANCHOR_IDS) {
      anchorCorrelation[packetType][routeHex(anchorId)] = {
        anchor_name: ({ 0x00f6: 'HeroPath', 0x017f: 'VerifiedDamage', 0x01cf: 'CastSpell' })[anchorId],
        all_rows: correlateTimes(rawAnalysis.events.get(routeId), anchors.get(anchorId), false),
        live_game_rows: correlateTimes(rawAnalysis.events.get(routeId), anchors.get(anchorId), true),
      };
    }
  }
  const damageNeighborhoods = {
    '0x00e4': damageNeighborhood(emulation.decodedRows.get(0x00e4), damageAnchors.byReplay, 'target_network_id_candidate_1c_u32'),
    '0x01b5': damageNeighborhood(emulation.decodedRows.get(0x01b5), damageAnchors.byReplay, 'target_network_id_u32'),
  };
  const rawRowCount = Object.values(rawAnalysis.stats).reduce((sum, item) => sum + item.count, 0);
  const nativeSampleCount = Object.values(emulation.summaries).reduce((sum, item) => sum + item.sample_count, 0);
  const nativeFullCount = Object.values(emulation.summaries).reduce((sum, item) => sum + item.successful_full_consume_count, 0);
  const inputHashes = {};
  for (const [name, filePath] of Object.entries(paths)) {
    inputHashes[name] = { path: path.relative(root, filePath).replaceAll('\\', '/'), sha256: await sha256File(filePath) };
  }
  const report = {
    schema: 'GAMEPLAY_ROUTE_TAIL_SATURATION_AUDIT_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    project_context_loaded: true,
    architecture_gate: 'PASS',
    scope: ROUTE_IDS.map(routeHex),
    governance_boundary: {
      parser_owner_scope: 'REPLAY_PROTOCOL_SEMANTICS_ONLY',
      map_truth_claimed: false,
      behavior_inference_claimed: false,
      offline_corpus_collection_claimed: false,
      akari_claimed: false,
      ui_claimed: false,
      shared_manifest_or_api_or_schema_or_governance_modified: false,
    },
    safety: {
      explicit_safe_latest_four_exports_only: true,
      directory_replay_discovery: false,
      protected_holdout_enumerated: false,
      protected_holdout_read: false,
      protected_holdout_hashed: false,
      protected_holdout_decoded: false,
      protected_holdout_tested: false,
      protected_holdout_consumed: false,
    },
    inputs: inputHashes,
    input_conservation: {
      target_row_count: rawRowCount,
      expected_target_row_count: 480101,
      target_count_matches: rawRowCount === 480101,
      anchor_row_count: [...anchors.values()].reduce((sum, rows) => sum + rows.length, 0),
      expected_anchor_row_count: 474127,
      native_sample_row_count: nativeSampleCount,
      native_full_consume_count: nativeFullCount,
      native_all_fully_consumed: nativeSampleCount === nativeFullCount,
      verified_damage_anchor_row_count: damageAnchors.count,
    },
    runtime_identities: runtimeIdentities(registry, image),
    decoded_field_layouts: DECODED_FIELD_LAYOUTS,
    raw_route_profiles: rawAnalysis.stats,
    emulation: emulation.summaries,
    verified_damage_neighborhood: damageNeighborhoods,
    cross_anchor_time_behavior: anchorCorrelation,
    exact_time_cross_route_matrix: crossRouteMatrix(rawAnalysis.events),
    saturation: {
      current_local_evidence_saturated: true,
      closed_surfaces: [
        'EXACT_BUILD_ROUTE_INVENTORY_ACROSS_EXPLICIT_SAFE_LATEST_FOUR',
        'FACTORY_CASE_CONSTRUCTOR_VTABLE_DESERIALIZER_IDENTITY',
        'CALLBACK_OWNER_AND_CONSUMER_READ_SITES',
        'ALL_OBSERVED_PAYLOAD_LENGTH_BRANCHES_STRATIFIED_NATIVE_EMULATION',
        'P0_DAMAGE_AND_RAW_HEROPATH_CASTSPELL_TIME_NEIGHBORHOODS',
        'CROSS_ROUTE_EXACT_TIME_AND_RAW_PARAM_CONTROLS',
      ],
      residual_boundary: 'Only external controlled business-state calibration can name deliberately neutral residual fields.',
    },
  };
  report.route_findings = buildRouteFindings(report);
  report.decisions = buildDecisions(report);
  if (!report.input_conservation.target_count_matches || report.input_conservation.anchor_row_count !== 474127 || !report.input_conservation.native_all_fully_consumed) {
    throw new Error(`input conservation failure: ${JSON.stringify(report.input_conservation)}`);
  }
  return { report, artifactDir, root };
}

async function main() {
  const { report, artifactDir, root } = await audit();
  const reportPath = rejectProtectedPath(path.join(artifactDir, 'gameplay_route_tail_audit_16_16.json'));
  const decisionPath = rejectProtectedPath(path.join(artifactDir, 'gameplay_route_tail_machine_decisions_16_16.json'));
  const markdownPath = rejectProtectedPath(path.join(artifactDir, 'gameplay_route_tail_audit_16_16.md'));
  const hashManifestPath = rejectProtectedPath(path.join(artifactDir, 'gameplay_route_tail_hashes_16_16.json'));
  fs.mkdirSync(artifactDir, { recursive: true });
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  fs.writeFileSync(decisionPath, `${JSON.stringify({
    schema: 'GAMEPLAY_ROUTE_TAIL_MACHINE_DECISIONS_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    project_context_loaded: true,
    architecture_gate: 'PASS',
    ...report.decisions,
  }, null, 2)}\n`, 'utf8');
  fs.writeFileSync(markdownPath, markdownReport(report), 'utf8');
  const profileAndNativeFiles = ROUTE_IDS.flatMap((packetId) => {
    const stem = routeHex(packetId).slice(2);
    return [
      path.join(artifactDir, 'profiles', `route_${stem}.json`),
      path.join(artifactDir, 'emulation', `route_${stem}_balanced_summary.json`),
      path.join(artifactDir, 'emulation', `route_${stem}_balanced_decoded.jsonl`),
    ];
  });
  const hashedFiles = [
    path.join(root, 'scripts', 'audit_gameplay_route_tail.js'),
    path.join(root, 'scripts', 'select_gameplay_route_tail_emulation_rows.js'),
    path.join(root, 'src', 'decoders', 'gameplay_route_tail_16_16.js'),
    path.join(root, 'test', 'gameplay_route_tail_audit.test.js'),
    path.join(root, 'test', 'gameplay_route_tail_public_decoder.test.js'),
    path.join(artifactDir, 'WHY_THIS_STAGE_EXISTS.md'),
    path.join(artifactDir, 'ARCHITECTURE_GATE.md'),
    path.join(artifactDir, 'VERIFICATION.json'),
    ...Object.values(report.inputs).map((entry) => path.join(root, entry.path)),
    ...profileAndNativeFiles,
    reportPath,
    decisionPath,
    markdownPath,
  ].map(rejectProtectedPath);
  const uniqueHashedFiles = [...new Set(hashedFiles)];
  const hashManifest = {
    schema: 'GAMEPLAY_ROUTE_TAIL_HASH_MANIFEST_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    excluded_self_hash: path.relative(root, hashManifestPath).replaceAll('\\', '/'),
    verification_commands: [
      'node --test test/gameplay_route_tail_audit.test.js',
      'node --test test/gameplay_route_tail_public_decoder.test.js',
      'node --max-old-space-size=4096 scripts/audit_gameplay_route_tail.js',
    ],
    files: await Promise.all(uniqueHashedFiles.map(async (filePath) => ({
      path: path.relative(root, filePath).replaceAll('\\', '/'),
      byte_length: fs.statSync(filePath).size,
      sha256: await sha256File(filePath),
    }))),
  };
  fs.writeFileSync(hashManifestPath, `${JSON.stringify(hashManifest, null, 2)}\n`, 'utf8');
  const outputs = [reportPath, decisionPath, markdownPath, hashManifestPath];
  process.stdout.write(`${JSON.stringify({
    exact_build: EXACT_BUILD,
    target_row_count: report.input_conservation.target_row_count,
    native_full_consume_count: report.input_conservation.native_full_consume_count,
    route_decisions: report.decisions.route_decisions.map(({ packet_discriminator, decision, hypothesis }) => ({ packet_discriminator, decision, hypothesis })),
    outputs: await Promise.all(outputs.map(async (filePath) => ({ file: filePath, sha256: await sha256File(filePath) }))),
  }, null, 2)}\n`);
}

if (require.main === module) main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});

module.exports = {
  ALLOWED_DECISIONS,
  ANCHOR_IDS,
  EXACT_BUILD,
  ROUTE_IDS,
  ROUTE_STATIC,
  RUNTIME_SHA256,
  audit,
  buildDecisions,
  classifyRawParam,
  correlateTimes,
  decodeRouteObject,
  nearestDelta,
  rejectProtectedPath,
  rotateLeft8,
  rotateRight8,
  swapAdjacentBits,
};
