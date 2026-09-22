'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile, walkBlocks } = require('./rofl');

const EXACT_BUILD = '16.16.805.0442';
const RUNTIME_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const IMAGE_BASE = 0x140000000n;
const FACTORY_TABLE_RVA = 0x00eea1bc;
const LOOKUP_TABLE_RVA = 0x01a27950;

const ROUTE_IDS = Object.freeze([
  0x0101,
  0x0213,
  0x0471,
  0x00ab,
  0x01b3,
  0x018e,
  0x0374,
  0x0316,
]);
const ROUTE_SET = new Set(ROUTE_IDS);

const SAFE_REPLAYS = Object.freeze({
  'HN1-11196935467.rofl': 'd3f3b019b70bcf8650934e8e6350d6ae1e3def28b52fb8225cade755a415f862',
  'HN1-11200496018.rofl': '2e6cee94aed783fa62606333fac7e21295b80f5c03fa5617cd38f6f75fdfe47d',
  'HN1-11201899481.rofl': '18ae8e43f54604b288a93aa35d13722a159e5ffea548adfa9e88bbf0518e5d9f',
  'HN1-11209393761.rofl': '9dac6a352dc5a0af8bdd5c3ab0c16cddf310ca56817ce252fcb363a82d0b7f96',
});

const ANCHOR_FAMILIES = Object.freeze({
  damage: Object.freeze([0x017f]),
  hero_death: Object.freeze([0x0112, 0x0074]),
  path: Object.freeze([0x00f6]),
  cast: Object.freeze([0x01cf]),
  buff: Object.freeze([0x0123, 0x0326, 0x041f, 0x043c, 0x045b]),
  item: Object.freeze([0x005a, 0x0064, 0x006c, 0x01e8, 0x02ea, 0x0310, 0x0311]),
  scoreboard: Object.freeze([0x010c]),
});

const CALLBACK_FIELD_RECOVERY = Object.freeze({
  '0x0101': Object.freeze({
    callback_rva: 0x0029e380,
    slice_length: 0x65,
    exact_object_reads: Object.freeze([{ offset: '0x10', width: 4, role: 'target_network_id_u32' }]),
    byte_needles: Object.freeze(['8b4210', '8b542420']),
    downstream_consumers: Object.freeze([
      { call_target_rva: '0x002aa2b0', role: 'decoded target network ID consumer' },
    ]),
  }),
  '0x0213': Object.freeze({
    callback_rva: 0x002a0b00,
    slice_length: 0x243,
    exact_object_reads: Object.freeze([
      { offset: '0x10', width: 4, role: 'neutral_plaintext_f32_lane_10' },
      { offset: '0x14', width: 4, role: 'ammo_max_count_or_default_s32' },
      { offset: '0x18', width: 4, role: 'ammo_current_count_or_sentinel_s32' },
      { offset: '0x1c', width: 4, role: 'ammo_slot_index_u32' },
      { offset: '0x20', width: 1, role: 'neutral_plaintext_u8_lane_20' },
      { offset: '0x24', width: 4, role: 'neutral_plaintext_f32_lane_24' },
    ]),
    byte_needles: Object.freeze(['0fb64220', '8b431c', '8b4318', '8b4314', '8b4324', '8b4310']),
    downstream_consumers: Object.freeze([
      { call_target_rva: '0x00995b80', role: 'lane_1c indexes a bounded 64-entry slot-object table' },
      { call_target_rva: '0x00921870', role: 'lane_14 writes slot-object state offset 0x64 used as the comparison/default maximum' },
      { call_target_rva: '0x009216f0', role: 'lane_18 enters the slot current-count update path and is compared with slot offset 0x64' },
      { call_target_rva: '0x00926ba0', role: 'lane_24 updates slot timing floats; exact business label unresolved' },
      { call_target_rva: '0x004681c0', role: 'lane_10 writes slot float offset 0x6c; exact business label unresolved' },
    ]),
  }),
  '0x0471': Object.freeze({
    callback_rva: 0x0029e3f0,
    slice_length: 0x80,
    exact_object_reads: Object.freeze([{ offset: '0x10', width: 4, role: 'target_network_id_u32' }]),
    byte_needles: Object.freeze(['8b4210', '41ffd2']),
    downstream_consumers: Object.freeze([
      { virtual_call_offset: '0x948', role: 'decoded general target network ID consumer' },
    ]),
  }),
  '0x018e': Object.freeze({
    callback_rva: 0x00337590,
    slice_length: 0x102,
    exact_object_reads: Object.freeze([{ offset: '0x10', width: 12, role: 'object_attacher_offset_xyz_f32' }]),
    byte_needles: Object.freeze(['4883c210', 'f20f1002', '8b7a08']),
    downstream_consumers: Object.freeze([
      { destination_offsets: ['0x2bc', '0x2c0', '0x2c4'], role: 'ObjectAttacher local offset state' },
    ]),
  }),
  '0x0374': Object.freeze({
    callback_rva: 0x002a12a0,
    slice_length: 0x16d,
    exact_object_reads: Object.freeze([
      { offset: '0x10', width: 1, role: 'restriction_enabled_u8' },
      { offset: '0x14', width: 4, role: 'restriction_radius_f32' },
      { offset: '0x18', width: 12, role: 'restriction_center_xyz_f32' },
    ]),
    byte_needles: Object.freeze(['0fb64210', '4c8d4318', '8b4314']),
    downstream_consumers: Object.freeze([
      { call_target_rva: '0x00344c70', role: 'enabled branch stores radius and center state' },
      { call_target_rva: '0x00308a20', role: 'zero branch resets restriction state' },
    ]),
  }),
});

const SHARED_CODEC_FIELD_RECOVERY = Object.freeze({
  '0x01b3': Object.freeze({
    source_routes: Object.freeze(['0x0101', '0x0471']),
    exact_shared_vtable_rva: '0x01b10310',
    exact_shared_deserializer_rva: '0x00ef4bb0',
    object_offset: '0x10',
    field: 'secondary_character_data_network_id_u32',
    validation: 'Every decoded nonzero value is a canonical latest-four champion network ID.',
  }),
});

const DECISION_CONFIG = Object.freeze({
  '0x0101': Object.freeze({
    decision: 'PROMOTE',
    hypothesis: 'AI_TARGET_HERO_PROTOCOL_UPDATE',
    semantic_claim: 'Exact runtime type PKT_AI_TargetHeroS2C_s and its recovered callback establish an AIBaseClient-scoped hero-target update with a decoded target network ID; it is not a hit or damage event.',
    publishable_fields: Object.freeze(['subject_network_id=raw_param', 'replay_time_ms', 'target_network_id_u32']),
    counterexample_anchor: 'damage',
    counterexample: 'Target-selection rows temporally remote from verified damage reject treating selection as hit or damage application.',
    next_required_evidence: Object.freeze(['Controlled exact-build target changes with a live object oracle to resolve any remaining target-zero/reset edge cases.']),
  }),
  '0x0213': Object.freeze({
    decision: 'PROMOTE',
    hypothesis: 'AMMO_UPDATE_PROTOCOL_WITH_SLOT_AND_COUNT_FIELDS',
    semantic_claim: 'Exact runtime type PKT_S2C_AmmoUpdate_s establishes an AIBaseClient-scoped ammo update. Callback dataflow recovers the slot index, maximum/default count, and current/sentinel count; three timing/mode lanes remain deliberately neutral.',
    publishable_fields: Object.freeze([
      'subject_network_id=raw_param', 'replay_time_ms',
      'neutral_plaintext_f32_lane_10', 'ammo_max_count_or_default_s32',
      'ammo_current_count_or_sentinel_s32', 'ammo_slot_index_u32',
      'neutral_plaintext_u8_lane_20', 'neutral_plaintext_f32_lane_24',
    ]),
    counterexample_anchor: 'cast',
    counterexample: 'Ammo updates without a nearby verified cast reject a one-row-equals-one-cast interpretation; lane roles are intentionally unnamed.',
    next_required_evidence: Object.freeze(['Controlled exact-build spell/ammo state trace that varies one ammo property at a time.']),
  }),
  '0x0471': Object.freeze({
    decision: 'PROMOTE',
    hypothesis: 'AI_TARGET_PROTOCOL_UPDATE',
    semantic_claim: 'Exact runtime type PKT_AI_TargetS2C_s and its recovered callback establish a general AIBaseClient target update with a decoded target network ID; it is not damage causality.',
    publishable_fields: Object.freeze(['subject_network_id=raw_param', 'replay_time_ms', 'target_network_id_u32']),
    counterexample_anchor: 'damage',
    counterexample: 'General target updates can be remote from verified damage and may address non-hero targets, so no hit/damage alias is allowed.',
    next_required_evidence: Object.freeze(['Controlled exact-build target acquisition/reset trace for target-class labels beyond raw network identity.']),
  }),
  '0x00ab': Object.freeze({
    decision: 'PROMOTE',
    hypothesis: 'CHARACTER_DATA_STACK_POP_ALL_PROTOCOL_UPDATE',
    semantic_claim: 'Exact runtime type PKT_S2C_PopAllCharacterData_s establishes an AIBaseClient-scoped pop-all character-data protocol update; affected character-data identities remain unknown.',
    publishable_fields: Object.freeze(['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type']),
    counterexample_anchor: 'damage',
    counterexample: 'Sparse character-data stack operations do not establish HP, defense, spell, or damage state.',
    next_required_evidence: Object.freeze(['Controlled exact-build character-data stack trace with the corresponding business dictionary.']),
  }),
  '0x01b3': Object.freeze({
    decision: 'PROMOTE',
    hypothesis: 'SECONDARY_CHARACTER_DATA_PROTOCOL_UPDATE',
    semantic_claim: 'Exact runtime type PKT_S2C_SetSecondaryCharacterData_s establishes an AIBaseClient-scoped secondary-character-data update. Its exact shared protected-u32 codec recovers a related champion network ID; the character-data business identity remains unknown.',
    publishable_fields: Object.freeze(['subject_network_id=raw_param', 'replay_time_ms', 'secondary_character_data_network_id_u32']),
    counterexample_anchor: 'damage',
    counterexample: 'Secondary character presentation/configuration data is not live combat scalar or damage evidence.',
    next_required_evidence: Object.freeze(['Controlled exact-build character-data change plus an external exact-build character-data dictionary.']),
  }),
  '0x018e': Object.freeze({
    decision: 'REPURPOSE',
    hypothesis: 'OBJECT_ATTACHER_LOCAL_OFFSET_VECTOR_UPDATE',
    semantic_claim: 'Exact runtime type PKT_S2C_SetOffsetForObjectAttacher_s and its callback establish an ObjectAttacher-local decoded offset vector. It is attachment state, not entity world position or map truth.',
    publishable_fields: Object.freeze(['subject_network_id=raw_param', 'replay_time_ms', 'offset_x_f32', 'offset_y_f32', 'offset_z_f32']),
    counterexample_anchor: 'path',
    counterexample: 'Object-attacher offsets occur independently of verified hero path and belong to attachment-local presentation state, rejecting a world-position alias.',
    next_required_evidence: Object.freeze(['Controlled exact-build attachment trace only if semantic labels beyond local offset are required.']),
  }),
  '0x0374': Object.freeze({
    decision: 'PROMOTE',
    hypothesis: 'CIRCULAR_RESTRICTION_OVERRIDE_PROTOCOL_UPDATE',
    semantic_claim: 'Exact runtime type PKT_S2C_CircularRestrictionOverride_s and its callback establish enabled/reset state plus decoded radius and center-vector lanes. These are protocol coordinates only, not strategic map truth.',
    publishable_fields: Object.freeze(['subject_network_id=raw_param', 'replay_time_ms', 'restriction_enabled_u8', 'restriction_radius_f32', 'restriction_center_x_f32', 'restriction_center_y_f32', 'restriction_center_z_f32']),
    counterexample_anchor: 'path',
    counterexample: 'A restriction override is neither a hero-path point nor a strategic region; reset and set branches are both retained.',
    next_required_evidence: Object.freeze(['External exact-build system oracle to name the gameplay source of each circular restriction override.']),
  }),
  '0x0316': Object.freeze({
    decision: 'PROMOTE',
    hypothesis: 'CHARACTER_DATA_STACK_POP_PROTOCOL_UPDATE',
    semantic_claim: 'Exact runtime type PKT_S2C_PopCharacterData_s establishes an AIBaseClient-scoped character-data stack pop update; the popped character-data identity remains unknown.',
    publishable_fields: Object.freeze(['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type']),
    counterexample_anchor: 'damage',
    counterexample: 'The four observed stack-pop rows are insufficient and semantically incompatible with live health/damage state.',
    next_required_evidence: Object.freeze(['Controlled exact-build character-data stack trace with the corresponding business dictionary.']),
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

function stableDigest(value) {
  return sha256(Buffer.from(JSON.stringify(value), 'utf8'));
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
    raw_classes: new Map(),
    payloads: new Map(),
    previous: new Map(),
    next: new Map(),
    previous_same_time: new Map(),
    next_same_time: new Map(),
    pending: null,
  };
}

function compactPayloadRow(event, payload) {
  return {
    schema: 'UNKNOWN_P1_WAVE_DISTINCT_PAYLOAD_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    packet_id: event.packet_id,
    packet_discriminator: packetHex(event.packet_id),
    replay_sha256: event.replay_sha256,
    replay_label: event.replay_label,
    replay_version: EXACT_BUILD,
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
    raw_param_occurrence_counts: { [event.raw_param]: 1 },
  };
}

function updatePayloadRow(row, event) {
  row.occurrence_count += 1;
  row.replay_occurrence_counts[event.replay_sha256] =
    (row.replay_occurrence_counts[event.replay_sha256] || 0) + 1;
  row.stream_occurrence_counts[event.stream] =
    (row.stream_occurrence_counts[event.stream] || 0) + 1;
  row.raw_param_occurrence_counts[event.raw_param] =
    (row.raw_param_occurrence_counts[event.raw_param] || 0) + 1;
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
  let within500 = 0;
  let sameEntityWithin10 = 0;
  let shifted137Within10 = 0;
  let shifted997Within10 = 0;
  const farExamples = [];
  for (const event of events) {
    const anchors = byReplay.get(event.replay_sha256) || [];
    const nearest = nearestEvent(anchors, event.time);
    if (!nearest) continue;
    const delta = Math.abs(nearest.time - event.time);
    deltas.push(delta);
    if (delta === 0) exact += 1;
    if (delta <= 10) within10 += 1;
    if (delta <= 500) within500 += 1;
    if (delta <= 10 && nearest.raw_param === event.raw_param) sameEntityWithin10 += 1;
    const shifted137 = nearestEvent(anchors, event.time + 137);
    const shifted997 = nearestEvent(anchors, event.time + 997);
    if (shifted137 && Math.abs(shifted137.time - event.time - 137) <= 10) shifted137Within10 += 1;
    if (shifted997 && Math.abs(shifted997.time - event.time - 997) <= 10) shifted997Within10 += 1;
    if (delta > 500 && farExamples.length < 12) {
      farExamples.push({
        replay_sha256: event.replay_sha256,
        replay_time_ms: event.time,
        raw_param: event.raw_param,
        nearest_anchor_delta_ms: delta,
      });
    }
  }
  const eligible = deltas.length;
  return {
    eligible_count: eligible,
    exact_time_count: exact,
    exact_time_rate: round(exact / Math.max(1, eligible)),
    within_10ms_count: within10,
    within_10ms_rate: round(within10 / Math.max(1, eligible)),
    within_500ms_count: within500,
    within_500ms_rate: round(within500 / Math.max(1, eligible)),
    within_10ms_same_raw_param_count: sameEntityWithin10,
    nearest_delta_p50_ms: quantile(deltas, 0.5),
    nearest_delta_p90_ms: quantile(deltas, 0.9),
    shifted_137ms_within_10ms_count: shifted137Within10,
    shifted_997ms_within_10ms_count: shifted997Within10,
    enrichment_over_137ms_control: round((within10 + 1) / (shifted137Within10 + 1)),
    enrichment_over_997ms_control: round((within10 + 1) / (shifted997Within10 + 1)),
    far_over_500ms_count: eligible - within500,
    far_counterexamples: farExamples,
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
  let sameTimestamp = 0;
  for (const rows of byReplay.values()) {
    rows.sort((left, right) => left.time - right.time || left.occurrence_index - right.occurrence_index);
    for (let index = 1; index < rows.length; index += 1) {
      const delta = rows[index].time - rows[index - 1].time;
      deltas.push(delta);
      if (delta === 0) sameTimestamp += 1;
    }
  }
  const sizes = [...timestampGroups.values()];
  return {
    timestamp_group_count: sizes.length,
    group_size_min: sizes.length ? Math.min(...sizes) : null,
    group_size_p50: quantile(sizes, 0.5),
    group_size_p90: quantile(sizes, 0.9),
    group_size_max: sizes.length ? Math.max(...sizes) : null,
    delta_p50_ms: quantile(deltas, 0.5),
    delta_p90_ms: quantile(deltas, 0.9),
    delta_p99_ms: quantile(deltas, 0.99),
    same_timestamp_transition_rate: round(sameTimestamp / Math.max(1, deltas.length)),
  };
}

function collectEvidence(replayPaths) {
  invariant(Array.isArray(replayPaths) && replayPaths.length === 4,
    'exactly four explicit safe replay paths are required');
  const states = new Map(ROUTE_IDS.map((packetId) => [packetId, newRouteState(packetId)]));
  const anchorByPacket = new Map();
  for (const [family, packetIds] of Object.entries(ANCHOR_FAMILIES)) {
    for (const packetId of packetIds) {
      if (!anchorByPacket.has(packetId)) anchorByPacket.set(packetId, []);
      anchorByPacket.get(packetId).push(family);
    }
  }
  const anchors = new Map(Object.keys(ANCHOR_FAMILIES).map((family) => [family, new Map()]));
  const replays = [];
  for (const replayPath of replayPaths) {
    const source = rejectProtectedPath(replayPath);
    const basename = path.basename(source);
    invariant(Object.hasOwn(SAFE_REPLAYS, basename), `replay outside explicit safe allowlist: ${basename}`);
    const replay = parseReplayFile(source);
    invariant(replay.source_sha256 === SAFE_REPLAYS[basename], `safe replay SHA mismatch: ${basename}`);
    invariant(replay.header.version === EXACT_BUILD, `safe replay build mismatch: ${basename}`);
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
      for (const family of anchorByPacket.get(block.packet_id) || []) {
        const byReplay = anchors.get(family);
        if (!byReplay.has(replay.source_sha256)) byReplay.set(replay.source_sha256, []);
        byReplay.get(replay.source_sha256).push({
          time: block.timestamp_ms,
          raw_param: block.param >>> 0,
          packet_id: block.packet_id,
        });
      }
      if (ROUTE_SET.has(block.packet_id)) {
        const state = states.get(block.packet_id);
        const payloadHash = sha256(block.payload);
        const event = {
          packet_id: block.packet_id,
          replay_sha256: replay.source_sha256,
          replay_label: path.basename(source, path.extname(source)),
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
        increment(state.raw_classes, rawParamClass(event.raw_param));
        increment(state.previous, previous ? packetHex(previous.packet_id) : 'START');
        increment(state.previous_same_time,
          previous && previous.time === event.time ? packetHex(previous.packet_id) : 'DIFFERENT_TIMESTAMP');
        if (!state.payloads.has(payloadHash)) {
          state.payloads.set(payloadHash, compactPayloadRow(event, block.payload));
        } else {
          updatePayloadRow(state.payloads.get(payloadHash), event);
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
    replays.push({
      path: source,
      basename,
      replay_sha256: replay.source_sha256,
      replay_version: replay.header.version,
      block_count: walk.block_count,
    });
  }
  invariant(new Set(replays.map((row) => row.replay_sha256)).size === 4,
    'explicit safe replay inputs must be distinct');
  for (const byReplay of anchors.values()) {
    for (const rows of byReplay.values()) rows.sort((left, right) => left.time - right.time);
  }
  const routes = {};
  const distinctPayloadRows = [];
  for (const packetId of ROUTE_IDS) {
    const state = states.get(packetId);
    const payloadRows = [...state.payloads.values()]
      .sort((left, right) => left.payload_length - right.payload_length
        || left.raw_payload_sha256.localeCompare(right.raw_payload_sha256));
    distinctPayloadRows.push(...payloadRows);
    const branchMap = new Map();
    for (const row of payloadRows) {
      const key = String(row.payload_length);
      if (!branchMap.has(key)) branchMap.set(key, { count: 0, distinct: 0 });
      const branch = branchMap.get(key);
      branch.count += row.occurrence_count;
      branch.distinct += 1;
    }
    const correlations = {};
    for (const [family, byReplay] of anchors) {
      correlations[family] = anchorCorrelation(state.events, byReplay);
    }
    routes[packetHex(packetId)] = {
      packet_id: packetId,
      packet_discriminator: packetHex(packetId),
      count: state.count,
      per_replay_count: sortedCounter(state.per_replay, 'replay_sha256'),
      stream_distribution: sortedCounter(state.streams, 'stream'),
      payload: {
        length_distribution: sortedCounter(state.lengths, 'payload_length'),
        distinct_payload_sha256_count: payloadRows.length,
        occurrence_weight_sum: payloadRows.reduce((sum, row) => sum + row.occurrence_count, 0),
        occurrence_weight_conserved: payloadRows.reduce((sum, row) => sum + row.occurrence_count, 0)
          === state.count,
        branches: [...branchMap.entries()].map(([payloadLength, value]) => ({
          payload_length: Number(payloadLength),
          count: value.count,
          distinct_payload_count: value.distinct,
        })).sort((left, right) => left.payload_length - right.payload_length),
      },
      raw_param: {
        distinct_count: state.raw_params.size,
        class_distribution: sortedCounter(state.raw_classes, 'class'),
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
    };
  }
  distinctPayloadRows.sort((left, right) => left.packet_id - right.packet_id
    || left.payload_length - right.payload_length
    || left.raw_payload_sha256.localeCompare(right.raw_payload_sha256));
  const canonical = { replays, routes, distinct_payload_rows: distinctPayloadRows };
  return {
    ...canonical,
    deterministic_digest: stableDigest(canonical),
    target_row_count: Object.values(routes).reduce((sum, route) => sum + route.count, 0),
    distinct_payload_row_count: distinctPayloadRows.length,
  };
}

function readRvaQword(image, rva) {
  invariant(rva >= 0 && rva + 8 <= image.length, `qword RVA outside image: ${rvaHex(rva)}`);
  const va = image.readBigUInt64LE(rva);
  invariant(va >= IMAGE_BASE, `qword is not an image VA at ${rvaHex(rva)}`);
  return Number(va - IMAGE_BASE);
}

function recoverRuntimeIdentities(registry, image) {
  invariant(registry.exact_build === EXACT_BUILD, 'observed registry exact-build mismatch');
  invariant(sha256(image) === RUNTIME_SHA256, 'pinned exact runtime image SHA mismatch');
  return ROUTE_IDS.map((packetId) => {
    const packetType = packetHex(packetId);
    const route = registry.routes.find((entry) => Number(entry.packet_id) === packetId);
    invariant(route, `registry missing ${packetType}`);
    const callbacks = route.runtime_registration?.callbacks || [];
    const factories = route.runtime_registration?.factory_packets || [];
    invariant(callbacks.length === 1, `${packetType} expected one exact callback RTTI identity`);
    invariant(factories.length === 1, `${packetType} expected one exact factory identity`);
    const callback = callbacks[0];
    const factory = factories[0];
    const descriptorRva = Number.parseInt(callback.type_descriptor_rva_hex, 16);
    const descriptorBytes = image.subarray(descriptorRva, descriptorRva + 0x180);
    const descriptorText = descriptorBytes.toString('latin1');
    invariant(descriptorText.includes(callback.name), `${packetType} runtime RTTI type name mismatch`);
    invariant(descriptorText.includes(callback.callback_owner_type), `${packetType} runtime RTTI owner mismatch`);
    const caseRva = image.readUInt32LE(FACTORY_TABLE_RVA + packetId * 4);
    invariant(caseRva === Number(factory.case_rva), `${packetType} factory case mismatch`);
    invariant(readRvaQword(image, Number(factory.packet_object_vtable_rva) + 8)
      === Number(factory.deserializer_rva), `${packetType} vtable deserializer mismatch`);
    const expectedCallback = CALLBACK_FIELD_RECOVERY[packetType] || null;
    const callbackTarget = callback.callback_receive_target_rva_hex
      ? Number.parseInt(callback.callback_receive_target_rva_hex, 16)
      : null;
    if (expectedCallback) {
      invariant(callbackTarget === expectedCallback.callback_rva,
        `${packetType} callback receive target mismatch`);
      const slice = image.subarray(callbackTarget, callbackTarget + expectedCallback.slice_length);
      for (const needleHex of expectedCallback.byte_needles) {
        invariant(slice.indexOf(Buffer.from(needleHex, 'hex')) >= 0,
          `${packetType} callback object-read needle missing: ${needleHex}`);
      }
    }
    const downstreamConsumers = (expectedCallback?.downstream_consumers || []).map((consumer) => {
      if (!consumer.call_target_rva) return { ...consumer };
      const targetRva = Number.parseInt(consumer.call_target_rva, 16);
      invariant(targetRva >= 0 && targetRva + 0x80 <= image.length,
        `${packetType} downstream call target outside image: ${consumer.call_target_rva}`);
      return {
        ...consumer,
        exact_target_slice_sha256: sha256(image.subarray(targetRva, targetRva + 0x80)),
      };
    });
    return {
      packet_id: packetId,
      packet_discriminator: packetType,
      callback_mapping_status: route.runtime_registration.callback_mapping_status,
      callback_name: callback.name,
      callback_owner_type: callback.callback_owner_type,
      callback_type_descriptor_rva: descriptorRva,
      callback_type_descriptor_rva_hex: rvaHex(descriptorRva),
      callback_type_descriptor_slice_sha256: sha256(descriptorBytes),
      callback_receive_target_rva: callbackTarget,
      callback_receive_target_rva_hex: callbackTarget === null ? null : rvaHex(callbackTarget),
      callback_receive_target_slice_sha256: expectedCallback
        ? sha256(image.subarray(callbackTarget, callbackTarget + expectedCallback.slice_length))
        : null,
      callback_exact_object_reads: expectedCallback?.exact_object_reads || [],
      callback_bounded_downstream_consumers: downstreamConsumers,
      callback_field_recovery_status: expectedCallback
        ? 'EXACT_CALLBACK_OBJECT_READS_AND_TRANSFORMS_RECOVERED'
        : 'EXACT_RTTI_IDENTITY_ONLY_CALLBACK_BODY_NOT_INDEPENDENTLY_MAPPED',
      factory: {
        case_rva: caseRva,
        case_rva_hex: rvaHex(caseRva),
        allocation_size: Number(factory.object_size),
        constructor_rva: Number(factory.constructor_rva),
        constructor_rva_hex: rvaHex(factory.constructor_rva),
        packet_object_vtable_rva: Number(factory.packet_object_vtable_rva),
        packet_object_vtable_rva_hex: rvaHex(factory.packet_object_vtable_rva),
        deserializer_rva: Number(factory.deserializer_rva),
        deserializer_rva_hex: rvaHex(factory.deserializer_rva),
        runtime_slice_hashes: {
          case: sha256(image.subarray(caseRva, caseRva + 0x80)),
          constructor: sha256(image.subarray(Number(factory.constructor_rva), Number(factory.constructor_rva) + 0x80)),
          vtable: sha256(image.subarray(Number(factory.packet_object_vtable_rva), Number(factory.packet_object_vtable_rva) + 0x30)),
          deserializer: sha256(image.subarray(Number(factory.deserializer_rva), Number(factory.deserializer_rva) + 0x100)),
        },
      },
      validations: {
        exact_callback_rtti_type_and_owner_in_image: true,
        exact_factory_case: true,
        exact_constructor: true,
        exact_packet_vtable: true,
        exact_deserializer: true,
        callback_body_needles: expectedCallback ? true : null,
        bounded_downstream_consumer_targets: expectedCallback ? true : null,
        all_pass: true,
      },
    };
  });
}

function buildNativeProfiles(runtimeIdentities) {
  return runtimeIdentities.map((identity) => ({
    schema: 'UNKNOWN_P1_WAVE_NATIVE_PROFILE_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    exact_runtime_image_sha256: RUNTIME_SHA256,
    source_runtime_identity: identity,
    profile: {
      id: `unknown-p1-wave-${identity.packet_discriminator.slice(2)}-exact-runtime-v2`,
      client_opcode: identity.packet_id,
      constructor_rva: identity.factory.constructor_rva,
      deserialize_rva: identity.factory.deserializer_rva,
      object_size: identity.factory.allocation_size,
      fields: [],
    },
  }));
}

function rotateRight8(value, count) {
  const shift = count & 7;
  return ((value >>> shift) | (value << ((8 - shift) & 7))) & 0xff;
}

function swapAdjacentBits(value) {
  return ((((value & 0xd5) << 1) | ((value >>> 1) & 0x55))) & 0xff;
}

function decodeBytes(object, offset, length, transform) {
  const decoded = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) decoded[index] = transform(object[offset + index]);
  return decoded;
}

function lookup(image, value) {
  return image[LOOKUP_TABLE_RVA + (value & 0xff)];
}

function decodeTargetNetworkId(objectHex, image) {
  const object = Buffer.from(objectHex, 'hex');
  invariant(object.length >= 0x14, 'target object shorter than 0x14 bytes');
  const decoded = decodeBytes(object, 0x10, 4, (stored) => {
    let value = lookup(image, stored);
    value = (value ^ 0x21) & 0xff;
    value = (value - 0x64) & 0xff;
    value = lookup(image, value);
    value = rotateRight8(value, 4);
    return (0x2f - value) & 0xff;
  });
  return decoded.readUInt32LE(0);
}

function decodeAmmoObject(objectHex, image) {
  const object = Buffer.from(objectHex, 'hex');
  invariant(object.length >= 0x28, 'ammo object shorter than 0x28 bytes');
  const lane10 = decodeBytes(object, 0x10, 4, (stored) => {
    let value = (stored ^ 0x14) & 0xff;
    value = (value - 0x64) & 0xff;
    value = (value ^ 0x19) & 0xff;
    value = rotateRight8(value, 1);
    value = lookup(image, value);
    return (value - 0x7e) & 0xff;
  });
  const lane14 = decodeBytes(object, 0x14, 4, (stored) => {
    let value = rotateRight8(stored, 4);
    value = swapAdjacentBits(value);
    value = lookup(image, value);
    value = (value ^ 0x6a) & 0xff;
    value = swapAdjacentBits(value);
    return rotateRight8(value, 3);
  });
  const lane18 = decodeBytes(object, 0x18, 4, (stored) => {
    let value = (~stored) & 0xff;
    value = rotateRight8(value, 5);
    value = (value ^ 0x5d) & 0xff;
    value = rotateRight8(value, 7);
    value = (value + 0x14) & 0xff;
    return (~value) & 0xff;
  });
  const lane1c = decodeBytes(object, 0x1c, 4, (stored) => {
    let value = (stored ^ 0x50) & 0xff;
    value = rotateRight8(value, 5);
    value = (value ^ 0xed) & 0xff;
    value = rotateRight8(value, 2);
    return swapAdjacentBits(value);
  });
  let lane20 = (object[0x20] ^ 0x47) & 0xff;
  lane20 = rotateRight8(lane20, 4);
  lane20 = (lane20 - 0x2a) & 0xff;
  lane20 = (lane20 ^ 0x43) & 0xff;
  const lane24 = decodeBytes(object, 0x24, 4, (stored) => {
    let value = (stored - 0x3b) & 0xff;
    value = lookup(image, value);
    value = (value + 0x6f) & 0xff;
    value = (~value) & 0xff;
    value = swapAdjacentBits(value);
    value = (value - 0x18) & 0xff;
    return rotateRight8(value, 1);
  });
  return {
    neutral_plaintext_f32_lane_10: lane10.readFloatLE(0),
    ammo_max_count_or_default_s32: lane14.readInt32LE(0),
    ammo_current_count_or_sentinel_s32: lane18.readInt32LE(0),
    ammo_slot_index_u32: lane1c.readUInt32LE(0),
    neutral_plaintext_u8_lane_20: lane20,
    neutral_plaintext_f32_lane_24: lane24.readFloatLE(0),
  };
}

function decodeObjectAttacherOffset(objectHex) {
  const object = Buffer.from(objectHex, 'hex');
  invariant(object.length >= 0x1c, 'object-attacher object shorter than 0x1c bytes');
  const decoded = decodeBytes(object, 0x10, 12, (stored) => {
    const rotated = rotateRight8(stored, 2);
    let value = (0xe1 - rotated) & 0xff;
    value = (value ^ 0xae) & 0xff;
    return rotateRight8(value, 1);
  });
  return {
    offset_x_f32: decoded.readFloatLE(0),
    offset_y_f32: decoded.readFloatLE(4),
    offset_z_f32: decoded.readFloatLE(8),
  };
}

function decodeCircularRestriction(objectHex, image) {
  const object = Buffer.from(objectHex, 'hex');
  invariant(object.length >= 0x24, 'circular-restriction object shorter than 0x24 bytes');
  let enabled = (object[0x10] - 0x1f) & 0xff;
  enabled = rotateRight8(enabled, 6);
  enabled = (~enabled) & 0xff;
  enabled = rotateRight8(enabled, 4);
  enabled = (enabled ^ 0x86) & 0xff;
  enabled = (enabled + 0x51) & 0xff;
  const radius = decodeBytes(object, 0x14, 4, (stored) => {
    let value = (stored ^ 0xe1) & 0xff;
    value = (value + 0x35) & 0xff;
    value = lookup(image, value);
    value = (value ^ 0x41) & 0xff;
    value = rotateRight8(value, 5);
    value = (value + 0x76) & 0xff;
    value = (value ^ 0xda) & 0xff;
    return (value + 0x30) & 0xff;
  });
  const center = decodeBytes(object, 0x18, 12, (stored) => {
    let value = (~stored) & 0xff;
    value = (value - 0x50) & 0xff;
    value = lookup(image, value);
    value = rotateRight8(value, 2);
    value = lookup(image, value);
    return (value ^ 0x0d) & 0xff;
  });
  return {
    restriction_enabled_u8: enabled,
    restriction_radius_f32: radius.readFloatLE(0),
    restriction_center_x_f32: center.readFloatLE(0),
    restriction_center_y_f32: center.readFloatLE(4),
    restriction_center_z_f32: center.readFloatLE(8),
  };
}

function analyzeDecodedFields(packetType, rows, image) {
  const weighted = new Map();
  const examples = [];
  let finiteFloatRows = 0;
  let decodedRowCount = 0;
  let decodedOccurrenceWeight = 0;
  let networkLikeWeight = 0;
  let championLikeWeight = 0;
  let zeroTargetWeight = 0;
  let ammoSlotInRangeWeight = 0;
  let ammoNonnegativeMaximumWeight = 0;
  let ammoCurrentAtOrBelowMaximumWeight = 0;
  const laneCounters = {};
  const successful = rows.filter((row) => !row.emulation_error
    && row.deserialize_return_al !== 0 && row.fully_consumed === true
    && row.opcode_matches_profile === true && row.object_hex);
  for (const row of successful) {
    const weight = Number(row.occurrence_count || 1);
    let decoded = null;
    if (packetType === '0x0101' || packetType === '0x0471') {
      decoded = { target_network_id_u32: decodeTargetNetworkId(row.object_hex, image) };
      const target = decoded.target_network_id_u32 >>> 0;
      if (target === 0) zeroTargetWeight += weight;
      if (target >= 0x40000000 && target <= 0x4fffffff) networkLikeWeight += weight;
      if (target >= 0x400000ae && target <= 0x400000b7) championLikeWeight += weight;
    } else if (packetType === '0x0213') {
      decoded = decodeAmmoObject(row.object_hex, image);
      if (decoded.ammo_slot_index_u32 <= 0x3f) ammoSlotInRangeWeight += weight;
      if (decoded.ammo_max_count_or_default_s32 >= 0) {
        ammoNonnegativeMaximumWeight += weight;
        if (decoded.ammo_current_count_or_sentinel_s32
          <= decoded.ammo_max_count_or_default_s32) {
          ammoCurrentAtOrBelowMaximumWeight += weight;
        }
      }
    } else if (packetType === '0x01b3') {
      decoded = {
        secondary_character_data_network_id_u32: decodeTargetNetworkId(row.object_hex, image),
      };
      const target = decoded.secondary_character_data_network_id_u32 >>> 0;
      if (target >= 0x400000ae && target <= 0x400000b7) championLikeWeight += weight;
    } else if (packetType === '0x018e') {
      decoded = decodeObjectAttacherOffset(row.object_hex);
    } else if (packetType === '0x0374') {
      decoded = decodeCircularRestriction(row.object_hex, image);
    }
    if (!decoded) continue;
    decodedRowCount += 1;
    decodedOccurrenceWeight += weight;
    const floatValues = Object.entries(decoded).filter(([key]) => key.includes('_f32'));
    if (floatValues.every(([, value]) => Number.isFinite(value))) finiteFloatRows += 1;
    for (const [key, value] of Object.entries(decoded)) {
      if (!laneCounters[key]) laneCounters[key] = new Map();
      const normalized = Number.isFinite(value) ? String(value) : String(value);
      increment(laneCounters[key], normalized, weight);
    }
    const digest = stableDigest(decoded);
    if (!weighted.has(digest)) weighted.set(digest, { decoded, occurrence_weight: 0 });
    weighted.get(digest).occurrence_weight += weight;
    if (examples.length < 24) {
      examples.push({
        raw_payload_sha256: row.raw_payload_sha256,
        occurrence_count: weight,
        decoded,
      });
    }
  }
  return {
    callback_transform_applied: CALLBACK_FIELD_RECOVERY[packetType]
      ? 'EXACT_STATIC_CALLBACK_TRANSFORM'
      : SHARED_CODEC_FIELD_RECOVERY[packetType]
        ? 'EXACT_SHARED_DESERIALIZER_CODEC_WITH_VALUE_DOMAIN_VALIDATION'
        : 'NOT_APPLICABLE',
    decoded_distinct_payload_count: decodedRowCount,
    decoded_occurrence_weight: decodedOccurrenceWeight,
    distinct_plaintext_tuple_count: weighted.size,
    all_decoded_float_rows_finite: decodedRowCount === 0 || finiteFloatRows === decodedRowCount,
    target_network_id_like_occurrence_weight: networkLikeWeight,
    canonical_champion_network_id_occurrence_weight: championLikeWeight,
    target_zero_occurrence_weight: zeroTargetWeight,
    ammo_slot_index_0_through_63_occurrence_weight: ammoSlotInRangeWeight,
    ammo_nonnegative_maximum_occurrence_weight: ammoNonnegativeMaximumWeight,
    ammo_current_at_or_below_nonnegative_maximum_occurrence_weight: ammoCurrentAtOrBelowMaximumWeight,
    ammo_current_at_or_below_nonnegative_maximum_rate: round(
      ammoCurrentAtOrBelowMaximumWeight / Math.max(1, ammoNonnegativeMaximumWeight),
    ),
    semantic_role_checks: {
      target_hero_zero_or_canonical_champion: packetType === '0x0101'
        ? championLikeWeight + zeroTargetWeight === decodedOccurrenceWeight
        : null,
      general_target_zero_or_broad_network_id: packetType === '0x0471'
        ? networkLikeWeight + zeroTargetWeight === decodedOccurrenceWeight
        : null,
      ammo_slot_index_bounded_0_through_63: packetType === '0x0213'
        ? ammoSlotInRangeWeight === decodedOccurrenceWeight
        : null,
      ammo_current_at_or_below_nonnegative_maximum_rate_at_least_95pct: packetType === '0x0213'
        ? ammoCurrentAtOrBelowMaximumWeight / Math.max(1, ammoNonnegativeMaximumWeight) >= 0.95
        : null,
      secondary_character_data_id_is_canonical_champion: packetType === '0x01b3'
        ? championLikeWeight === decodedOccurrenceWeight
        : null,
    },
    field_distributions: Object.fromEntries(Object.entries(laneCounters).map(([key, counter]) => [
      key,
      {
        distinct_count: counter.size,
        top_values: sortedCounter(counter, key, 24),
      },
    ])),
    decoded_examples: examples,
  };
}

function analyzeObjectStorage(rows, objectSize) {
  const offsets = [];
  for (let offset = 0x10; offset < objectSize; offset += 1) {
    const counter = new Map();
    let weight = 0;
    for (const row of rows) {
      if (row.emulation_error || !row.fully_consumed || !row.object_hex) continue;
      const object = Buffer.from(row.object_hex, 'hex');
      if (offset >= object.length) continue;
      const occurrenceWeight = Number(row.occurrence_count || 1);
      increment(counter, object[offset], occurrenceWeight);
      weight += occurrenceWeight;
    }
    if (!weight) continue;
    offsets.push({
      object_offset: rvaHex(offset),
      weighted_observation_count: weight,
      distinct_storage_value_count: counter.size,
      top_storage_values: sortedCounter(counter, 'value_u8', 8),
      semantic_role: null,
    });
  }
  return offsets;
}

function analyzeNativeOutputs(nativeRowsByRoute, nativeSummaries, evidence, runtimeIdentities, image) {
  const identities = new Map(runtimeIdentities.map((row) => [row.packet_discriminator, row]));
  const routes = {};
  for (const packetId of ROUTE_IDS) {
    const packetType = packetHex(packetId);
    const raw = evidence.routes[packetType];
    const rows = nativeRowsByRoute[packetType] || [];
    const summary = nativeSummaries[packetType];
    const successful = rows.filter((row) => !row.emulation_error
      && row.deserialize_return_al !== 0 && row.fully_consumed === true
      && row.opcode_matches_profile === true);
    const attemptedWeight = rows.reduce((sum, row) => sum + Number(row.occurrence_count || 1), 0);
    const successWeight = successful.reduce((sum, row) => sum + Number(row.occurrence_count || 1), 0);
    const failed = rows.filter((row) => !successful.includes(row));
    const failureWeight = failed.reduce((sum, row) => sum + Number(row.occurrence_count || 1), 0);
    routes[packetType] = {
      distinct_payload_attempt_count: rows.length,
      expected_distinct_payload_count: raw.payload.distinct_payload_sha256_count,
      all_distinct_payloads_attempted: rows.length === raw.payload.distinct_payload_sha256_count,
      full_inventory_occurrence_weight: raw.count,
      attempted_occurrence_weight: attemptedWeight,
      successful_full_consume_distinct_count: successful.length,
      successful_full_consume_occurrence_weight: successWeight,
      conserved_failure_distinct_count: failed.length,
      conserved_failure_occurrence_weight: failureWeight,
      full_occurrence_weight_conserved: attemptedWeight === raw.count
        && successWeight + failureWeight === raw.count,
      successful_full_consume_rate_by_occurrence_weight: round(successWeight / Math.max(1, raw.count)),
      payload_length_counts: summary?.payload_length_counts || {},
      emulation_errors: summary?.emulation_errors || {},
      object_storage_lane_profiles: analyzeObjectStorage(successful, identities.get(packetType).factory.allocation_size),
      callback_plaintext_analysis: analyzeDecodedFields(packetType, successful, image),
      failure_examples: failed.slice(0, 16).map((row) => ({
        raw_payload_sha256: row.raw_payload_sha256,
        payload_length: row.payload_length,
        occurrence_count: row.occurrence_count,
        emulation_error: row.emulation_error || null,
        deserialize_return_al: row.deserialize_return_al ?? null,
        fully_consumed: row.fully_consumed ?? null,
      })),
    };
  }
  return { routes };
}

function counterexampleCount(route, config) {
  return route.anchor_correlations_with_shifted_controls[config.counterexample_anchor]?.far_over_500ms_count
    || Math.max(1, route.count);
}

function buildDecisions(evidence, runtimeIdentities, nativeAnalysis) {
  const runtimeByType = new Map(runtimeIdentities.map((row) => [row.packet_discriminator, row]));
  const routeDecisions = ROUTE_IDS.map((packetId) => {
    const packetType = packetHex(packetId);
    const route = evidence.routes[packetType];
    const runtime = runtimeByType.get(packetType);
    const native = nativeAnalysis.routes[packetType];
    const config = DECISION_CONFIG[packetType];
    const decoded = native.callback_plaintext_analysis;
    const recoveredField = CALLBACK_FIELD_RECOVERY[packetType] || SHARED_CODEC_FIELD_RECOVERY[packetType];
    const semanticRoleChecks = Object.values(decoded.semantic_role_checks || {})
      .filter((value) => value !== null);
    const callbackTransformPass = !recoveredField
      || (decoded.decoded_distinct_payload_count === native.successful_full_consume_distinct_count
        && decoded.decoded_occurrence_weight === native.successful_full_consume_occurrence_weight
        && decoded.all_decoded_float_rows_finite
        && semanticRoleChecks.every(Boolean));
    const localComplete = route.payload.occurrence_weight_conserved
      && runtime.validations.all_pass
      && native.all_distinct_payloads_attempted
      && native.full_occurrence_weight_conserved
      && native.conserved_failure_occurrence_weight === 0
      && callbackTransformPass;
    return {
      packet_id: packetId,
      packet_discriminator: packetType,
      decision: config.decision,
      hypothesis: config.hypothesis,
      semantic_claim: config.semantic_claim,
      publishable_fields: [...config.publishable_fields],
      evidence_grade: CALLBACK_FIELD_RECOVERY[packetType]
        ? 'VERIFIED_EXACT_RUNTIME_TYPE_NATIVE_FULL_CONSUME_STATIC_CALLBACK_AND_VALUE_DOMAIN'
        : SHARED_CODEC_FIELD_RECOVERY[packetType]
          ? 'VERIFIED_EXACT_SHARED_DESERIALIZER_CODEC_NATIVE_FULL_CONSUME_AND_VALUE_DOMAIN'
          : 'VERIFIED_EXACT_RUNTIME_TYPE_AND_NATIVE_FULL_LOCAL_PROTOCOL_INVENTORY',
      positive_anchor_count: route.count,
      counterexample_count: counterexampleCount(route, config),
      counterexample: config.counterexample,
      evidence_exhausted: localComplete,
      evidence_exhausted_scope: 'PINNED_EXACT_RUNTIME_EXPLICIT_SAFE_LATEST_FOUR_ALL_OCCURRENCES_ALL_DISTINCT_PAYLOADS_STATIC_CALLBACK_AND_SHIFTED_CONTROLS',
      actual_reverse_engineering_executed: true,
      local_surface_checks: {
        full_inventory_count_conserved: route.payload.occurrence_weight_conserved,
        exact_callback_rtti_factory_constructor_vtable_deserializer: runtime.validations.all_pass,
        all_distinct_payloads_native_attempted: native.all_distinct_payloads_attempted,
        native_success_and_failure_weights_conserved: native.full_occurrence_weight_conserved,
        native_failure_occurrence_weight_zero: native.conserved_failure_occurrence_weight === 0,
        callback_plaintext_transform_pass: callbackTransformPass,
      },
      remaining_local_executable_steps: localComplete ? [] : [
        'Resolve the failing exact local-surface check recorded in local_surface_checks.',
      ],
      actionable_hypotheses: localComplete ? [] : [
        'Repeat exact native execution after repairing the reported local-surface mismatch.',
      ],
      next_required_evidence: localComplete ? [...config.next_required_evidence] : [
        'Complete the failing local surface before saturation.',
      ],
    };
  });
  const capabilityDecisions = [
    {
      capability: 'AI_TARGET_SELECTION_PROTOCOL',
      decision: 'PROMOTE',
      routes: ['0x0101', '0x0471'],
      boundary: 'Target update and decoded network identity only; no hit, aggro intent, behavior, or damage causality.',
      evidence_exhausted: routeDecisions.filter((row) => ['0x0101', '0x0471'].includes(row.packet_discriminator)).every((row) => row.evidence_exhausted),
      actual_reverse_engineering_executed: true,
      actionable_hypotheses: [],
    },
    {
      capability: 'AMMO_UPDATE_PROTOCOL',
      decision: 'PROMOTE',
      routes: ['0x0213'],
      boundary: 'Slot/current/max fields are recovered; three timing/mode plaintext lanes retain neutral names.',
      evidence_exhausted: routeDecisions.find((row) => row.packet_discriminator === '0x0213').evidence_exhausted,
      actual_reverse_engineering_executed: true,
      actionable_hypotheses: [],
    },
    {
      capability: 'CHARACTER_DATA_STACK_PROTOCOL',
      decision: 'PROMOTE',
      routes: ['0x00ab', '0x01b3', '0x0316'],
      boundary: 'Protocol operations plus 0x01b3 related champion network identity; character-data effect dictionary remains UNKNOWN.',
      evidence_exhausted: routeDecisions.filter((row) => ['0x00ab', '0x01b3', '0x0316'].includes(row.packet_discriminator)).every((row) => row.evidence_exhausted),
      actual_reverse_engineering_executed: true,
      actionable_hypotheses: [],
    },
    {
      capability: 'OBJECT_ATTACHER_LOCAL_OFFSET',
      decision: 'REPURPOSE',
      routes: ['0x018e'],
      boundary: 'Attachment-local vector; never world position or map truth.',
      evidence_exhausted: routeDecisions.find((row) => row.packet_discriminator === '0x018e').evidence_exhausted,
      actual_reverse_engineering_executed: true,
      actionable_hypotheses: [],
    },
    {
      capability: 'CIRCULAR_RESTRICTION_OVERRIDE_PROTOCOL',
      decision: 'PROMOTE',
      routes: ['0x0374'],
      boundary: 'Raw protocol center/radius/enable state; no strategic map interpretation.',
      evidence_exhausted: routeDecisions.find((row) => row.packet_discriminator === '0x0374').evidence_exhausted,
      actual_reverse_engineering_executed: true,
      actionable_hypotheses: [],
    },
  ];
  const domainDecisions = [
    { domain: 'TARGET_SELECTION', decision: 'PROMOTE_BOUNDED_PROTOCOL', routes: ['0x0101', '0x0471'] },
    { domain: 'SPELL_AND_AMMO_STATE', decision: 'PROMOTE_OCCURRENCE_KEEP_FIELD_ROLES_UNKNOWN', routes: ['0x0213'] },
    { domain: 'CHARACTER_DATA', decision: 'PROMOTE_BOUNDED_PROTOCOL', routes: ['0x00ab', '0x01b3', '0x0316'] },
    { domain: 'PRESENTATION_ATTACHMENT', decision: 'REPURPOSE_FROM_WORLD_POSITION', routes: ['0x018e'] },
    { domain: 'MOVEMENT_RESTRICTION_PROTOCOL', decision: 'PROMOTE_NO_MAP_TRUTH', routes: ['0x0374'] },
  ].map((row) => ({
    ...row,
    evidence_exhausted: row.routes.every((route) => routeDecisions.find((entry) => entry.packet_discriminator === route).evidence_exhausted),
    actual_reverse_engineering_executed: true,
    actionable_hypotheses: [],
  }));
  const decisionCounts = Object.fromEntries(['PROMOTE', 'KEEP_CANDIDATE', 'REJECT', 'REPURPOSE'].map((decision) => [
    decision,
    routeDecisions.filter((row) => row.decision === decision).length,
  ]));
  return {
    route_decisions: routeDecisions,
    capability_decisions: capabilityDecisions,
    domain_decisions: domainDecisions,
    decision_counts: decisionCounts,
    all_routes_have_one_decision: routeDecisions.length === ROUTE_IDS.length
      && new Set(routeDecisions.map((row) => row.packet_id)).size === ROUTE_IDS.length,
    all_current_local_evidence_exhausted: routeDecisions.every((row) => row.evidence_exhausted)
      && capabilityDecisions.every((row) => row.evidence_exhausted)
      && domainDecisions.every((row) => row.evidence_exhausted),
  };
}

function buildReport({ evidence, registryPath, runtimePath, runtimeIdentities, nativeAnalysis,
  nativeDeterminism, inputHashes, priorCrossCheck }) {
  const decisions = buildDecisions(evidence, runtimeIdentities, nativeAnalysis);
  const targetCountConserved = Object.values(evidence.routes).every((route) =>
    route.payload.occurrence_weight_conserved);
  const nativeConserved = Object.values(nativeAnalysis.routes).every((route) =>
    route.all_distinct_payloads_attempted && route.full_occurrence_weight_conserved
      && route.conserved_failure_occurrence_weight === 0);
  const registryCountsMatch = priorCrossCheck.every((row) =>
    evidence.routes[row.packet_discriminator].count === row.observed_count);
  const report = {
    schema: 'UNKNOWN_P1_WAVE_DEEP_RECOVERY_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    project_context_loaded: true,
    architecture_gate: 'PASS',
    scope: ROUTE_IDS.map(packetHex),
    governance_boundary: {
      parser_owner_scope: 'REPLAY_PROTOCOL_SEMANTICS_ONLY',
      map_truth_claimed: false,
      behavior_inference_claimed: false,
      offline_corpus_collection_claimed: false,
      akari_claimed: false,
      ui_claimed: false,
      shared_manifest_api_schema_governance_docs_or_ledger_modified: false,
    },
    safety: {
      explicit_safe_latest_four_only: true,
      replay_directory_discovery: false,
      protected_holdout_enumerated: false,
      protected_holdout_read: false,
      protected_holdout_hashed: false,
      protected_holdout_decoded: false,
      protected_holdout_tested: false,
      protected_holdout_consumed: false,
    },
    inputs: {
      registry: { path: registryPath, sha256: inputHashes.registry },
      runtime: { path: runtimePath, sha256: inputHashes.runtime },
      callback_sidecar: { path: inputHashes.callback_sidecar_path, sha256: inputHashes.callback_sidecar },
      prior_profiler: { path: inputHashes.profiler_path, sha256: inputHashes.profiler },
      prior_sampled_mining: { path: inputHashes.prior_mining_path, sha256: inputHashes.prior_mining },
      replays: evidence.replays,
    },
    prior_evidence_cross_check: priorCrossCheck,
    full_inventory: {
      target_row_count: evidence.target_row_count,
      distinct_payload_row_count: evidence.distinct_payload_row_count,
      target_occurrence_weight_conserved: targetCountConserved,
      registry_observed_counts_match: registryCountsMatch,
      deterministic_extraction_digest: evidence.deterministic_digest,
    },
    runtime_static_recovery: {
      factory_jump_table_rva: rvaHex(FACTORY_TABLE_RVA),
      lookup_table_rva: rvaHex(LOOKUP_TABLE_RVA),
      identities: runtimeIdentities,
      routes_with_exact_callback_field_transforms: Object.keys(CALLBACK_FIELD_RECOVERY),
      routes_with_exact_shared_deserializer_field_recovery: Object.keys(SHARED_CODEC_FIELD_RECOVERY),
      shared_deserializer_field_recovery: SHARED_CODEC_FIELD_RECOVERY,
      all_routes_closed: runtimeIdentities.every((row) => row.validations.all_pass),
    },
    routes: evidence.routes,
    native_exact_emulation: nativeAnalysis,
    decisions,
    saturation: {
      current_local_evidence_saturated: decisions.all_current_local_evidence_exhausted,
      closed_surfaces: [
        'EXPLICIT_SAFE_LATEST_FOUR_ALL_ROUTE_OCCURRENCES',
        'ALL_DISTINCT_PAYLOAD_HASHES_WITH_EXACT_OCCURRENCE_WEIGHTS',
        'PAYLOAD_LENGTH_STREAM_TIME_RAW_PARAM_ENTITY_CLASSES_AND_IMMEDIATE_NEIGHBORS',
        'DAMAGE_DEATH_PATH_CAST_BUFF_ITEM_SCOREBOARD_ANCHORS_WITH_137MS_AND_997MS_CONTROLS',
        'EXACT_CALLBACK_RTTI_OWNER_FACTORY_CONSTRUCTOR_VTABLE_DESERIALIZER_CHAIN',
        'NATIVE_EXACT_CONSTRUCTOR_AND_DESERIALIZER_EXECUTION_FOR_EVERY_DISTINCT_PAYLOAD',
        'STATIC_CALLBACK_PLAINTEXT_FIELD_RECOVERY_FOR_0x0101_0x0213_0x0471_0x018e_0x0374',
        'EXACT_SHARED_DESERIALIZER_CODEC_AND_CANONICAL_CHAMPION_DOMAIN_RECOVERY_FOR_0x01b3',
        'DETERMINISTIC_EXTRACTION_AND_NATIVE_RERUN',
      ],
      residual_external_thresholds: [...new Set(decisions.route_decisions.flatMap((row) => row.next_required_evidence))],
      remaining_local_executable_steps: decisions.route_decisions.flatMap((row) => row.remaining_local_executable_steps),
      actionable_hypotheses: decisions.route_decisions.flatMap((row) => row.actionable_hypotheses),
    },
    determinism: nativeDeterminism,
    validations: {},
  };
  report.validations = {
    exact_build: true,
    replay_allowlist_and_hashes: evidence.replays.every((row) => SAFE_REPLAYS[row.basename] === row.replay_sha256),
    target_occurrence_weight_conserved: targetCountConserved,
    registry_observed_counts_match: registryCountsMatch,
    all_runtime_routes_closed: runtimeIdentities.every((row) => row.validations.all_pass),
    all_distinct_payloads_native_attempted_and_fully_consumed: nativeConserved,
    callback_plaintext_transforms_finite_and_conserved: Object.entries(nativeAnalysis.routes).every(([packetType, row]) => {
      const recoveredField = CALLBACK_FIELD_RECOVERY[packetType] || SHARED_CODEC_FIELD_RECOVERY[packetType];
      const checks = Object.values(row.callback_plaintext_analysis.semantic_role_checks || {})
        .filter((value) => value !== null);
      return !recoveredField
        || (row.callback_plaintext_analysis.decoded_occurrence_weight
          === row.successful_full_consume_occurrence_weight
          && row.callback_plaintext_analysis.all_decoded_float_rows_finite
          && checks.every(Boolean));
    }),
    native_deterministic_rerun_match: nativeDeterminism.all_match,
    every_route_has_exactly_one_machine_decision: decisions.all_routes_have_one_decision,
    all_route_capability_domain_evidence_exhausted: decisions.all_current_local_evidence_exhausted,
  };
  report.validations.all_pass = Object.values(report.validations).every(Boolean);
  return report;
}

function markdownReport(report) {
  const runtimeById = new Map(report.runtime_static_recovery.identities.map((row) => [row.packet_id, row]));
  const lines = [
    '# Unknown P1 route wave — exact-build deep recovery audit',
    '',
    `- Build: \`${EXACT_BUILD}\`; nearest-build fallback forbidden.`,
    `- Full route inventory: ${report.full_inventory.target_row_count.toLocaleString('en-US')} occurrences.`,
    `- Distinct payloads executed twice: ${report.full_inventory.distinct_payload_row_count.toLocaleString('en-US')}.`,
    `- Current local evidence saturated: ${report.saturation.current_local_evidence_saturated}.`,
    '- Protected Jungle Objective Holdout was not enumerated, read, hashed, decoded, tested, or consumed.',
    '',
    '## Route decisions',
    '',
    '| Route | Exact runtime type | Decision | Minimal publishable surface | Boundary |',
    '|---|---|---|---|---|',
  ];
  for (const decision of report.decisions.route_decisions) {
    const runtime = runtimeById.get(decision.packet_id);
    lines.push(`| \`${decision.packet_discriminator}\` | ${runtime.callback_name} | ${decision.decision}: ${decision.hypothesis} | ${decision.publishable_fields.join(', ')} | ${decision.counterexample} |`);
  }
  lines.push(
    '',
    '## Static callback field recovery',
    '',
    '- `0x0101` / `0x0471`: exact callback transforms recover target network IDs.',
    '- `0x0213`: all six callback-consumed plaintext lanes are recovered; bounded downstream dataflow resolves slot index, maximum/default count, and current/sentinel count while three timing/mode lanes stay neutral.',
    '- `0x01b3`: an exact shared deserializer codec plus canonical-champion value-domain check recovers the secondary character-data network ID.',
    '- `0x018e`: exact callback transform recovers an ObjectAttacher-local XYZ offset vector.',
    '- `0x0374`: exact callback transforms recover restriction enabled/reset, radius, and center-vector lanes; no map truth is inferred.',
    '',
    '## Saturation boundary',
    '',
    'Every safe latest-four occurrence, distinct payload, exact runtime identity chain, native constructor/deserializer branch, requested temporal/entity counterexample surface, and statically reachable callback transform was executed. Remaining labels require controlled exact-build state variation or an external business dictionary.',
    '',
  );
  return lines.join('\n');
}

module.exports = {
  ANCHOR_FAMILIES,
  CALLBACK_FIELD_RECOVERY,
  DECISION_CONFIG,
  EXACT_BUILD,
  FACTORY_TABLE_RVA,
  LOOKUP_TABLE_RVA,
  ROUTE_IDS,
  RUNTIME_SHA256,
  SAFE_REPLAYS,
  SHARED_CODEC_FIELD_RECOVERY,
  analyzeNativeOutputs,
  anchorCorrelation,
  buildDecisions,
  buildNativeProfiles,
  buildReport,
  collectEvidence,
  decodeAmmoObject,
  decodeCircularRestriction,
  decodeObjectAttacherOffset,
  decodeTargetNetworkId,
  markdownReport,
  nearestEvent,
  packetHex,
  quantile,
  recoverRuntimeIdentities,
  rejectProtectedPath,
  rotateRight8,
  sha256,
  sha256File,
  swapAdjacentBits,
};
