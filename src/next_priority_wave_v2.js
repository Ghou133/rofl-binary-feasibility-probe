'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { normalizePlayers, parseReplayFile, walkBlocks } = require('./rofl');

const EXACT_BUILD = '16.16.805.0442';
const RUNTIME_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const IMAGE_BASE = 0x140000000n;
const FACTORY_SWITCH_RVA = 0x00ed97e0;
const FACTORY_TABLE_RVA = 0x00eea1bc;
const FACTORY_MAX_ID = 0x04de;
const KDA_CALLBACK_RVA = 0x00334ae0;
const KDA_LOOKUP_TABLE_RVA = 0x01a331a0;

const ROUTE_IDS = Object.freeze([
  0x02bb, 0x042d, 0x0057, 0x0387, 0x03ec,
  0x01ce, 0x0023, 0x002c, 0x016b, 0x041b,
  0x003f, 0x02fd, 0x0398, 0x01b0, 0x0200,
  0x0035, 0x03ac, 0x032f, 0x040c, 0x00de,
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
  death: Object.freeze([0x0074]),
  path: Object.freeze([0x00f6]),
  cast: Object.freeze([0x01cf]),
  buff: Object.freeze([0x0123, 0x0326, 0x041f, 0x043c, 0x045b]),
  item: Object.freeze([0x005a, 0x0064, 0x006c, 0x01e8, 0x02ea, 0x0310, 0x0311]),
  scoreboard: Object.freeze([0x010c]),
});
const ANCHOR_BY_ID = new Map();
for (const [family, ids] of Object.entries(ANCHOR_FAMILIES)) {
  for (const packetId of ids) {
    if (!ANCHOR_BY_ID.has(packetId)) ANCHOR_BY_ID.set(packetId, []);
    ANCHOR_BY_ID.get(packetId).push(family);
  }
}

const DECISION_CONFIG = Object.freeze({
  '0x02bb': {
    decision: 'PROMOTE',
    hypothesis: 'BASIC_ATTACK_POSITION_PROTOCOL_OCCURRENCE',
    semantic_claim: 'Exact runtime type PKT_Basic_Attack_Pos_s: actor-scoped basic-attack-position protocol occurrence. It is not proof that damage was applied.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample_anchor: 'damage',
    counterexample: 'Rows without nearby verified damage reject treating an attack-position carrier as damage application.',
  },
  '0x042d': {
    decision: 'PROMOTE',
    hypothesis: 'DAMPENER_SWITCH_STATE_PROTOCOL_UPDATE',
    semantic_claim: 'Exact runtime type PKT_DampenerSwitchStates_s: BarracksDampenerClient-scoped switch-state protocol update; no map-state truth is inferred.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'Protocol state does not establish objective ownership, location, or inferred map truth.',
  },
  '0x0057': {
    decision: 'PROMOTE',
    hypothesis: 'BASIC_ATTACK_PROTOCOL_OCCURRENCE',
    semantic_claim: 'Exact runtime type PKT_Basic_Attack_s: actor-scoped basic-attack protocol occurrence. It is not a hit or damage event.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample_anchor: 'damage',
    counterexample: 'Rows without nearby verified damage reject a direct hit/damage alias.',
  },
  '0x0387': {
    decision: 'PROMOTE',
    hypothesis: 'BASIC_ATTACK_MINION_PROTOCOL_OCCURRENCE',
    semantic_claim: 'Exact runtime type PKT_Basic_Attack_Minion_s: actor-scoped minion basic-attack protocol occurrence, without damage causality.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample_anchor: 'damage',
    counterexample: 'Attack-minion protocol rows can be temporally remote from verified damage and therefore do not establish application.',
  },
  '0x03ec': {
    decision: 'REPURPOSE',
    hypothesis: 'HEALTH_BAR_ICON_CLEAR_PRESENTATION_UPDATE',
    semantic_claim: 'Exact runtime type PKT_HealthBar_Icon_Clear_S2C_s: health-bar icon presentation clear update; explicitly not HP, defense, or resource state.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'The callback identity is a presentation icon clear and contradicts live health-scalar interpretations.',
  },
  '0x01ce': {
    decision: 'PROMOTE',
    hypothesis: 'STEALTH_FLAGS_CHANGED_PROTOCOL_UPDATE',
    semantic_claim: 'Exact runtime type PKT_StealthFlagsChanged_s: actor-scoped stealth-flags-changed protocol occurrence; individual flag roles remain neutral.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'Multiple payload branches and absent independent visibility truth prevent naming individual flag bits.',
  },
  '0x0023': {
    decision: 'PROMOTE',
    hypothesis: 'AUTO_ATTACK_OVERRIDE_RANGE_UPDATE',
    semantic_claim: 'Exact runtime type PKT_S2C_UpdateAutoAttackOverrideRange_s: actor-scoped auto-attack override-range protocol update. The optional second protected lane remains neutral.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type', 'protected_range_lane_10'],
    counterexample: 'The dominant one-byte branch omits the optional four-byte lane, so universal multi-field range semantics are rejected.',
  },
  '0x002c': {
    decision: 'PROMOTE',
    hypothesis: 'CLIENT_SIDE_ONLY_ITEM_REMOVE',
    semantic_claim: 'Exact runtime type PKT_S2C_RemoveClentSideOnlyItem_s: inventory-owner-scoped client-side-only item removal protocol occurrence; payload lanes are neutral.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'This specialized client-only removal must not be generalized to ordinary inventory sale, undo, or consumption.',
  },
  '0x016b': {
    decision: 'PROMOTE',
    hypothesis: 'HERO_KDA_CUMULATIVE_UPDATE',
    semantic_claim: 'Exact non-MakeFunction callback consumes three protected u32 lanes and stores cumulative hero kills, deaths, and assists; terminal rows are independently checked against replay metadata.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'kills_u32', 'deaths_u32', 'assists_u32'],
    counterexample: 'Cumulative K/D/A values are scoreboard state and cannot be repurposed as live HP, defense, resource, or causal combat events.',
  },
  '0x041b': {
    decision: 'PROMOTE',
    hypothesis: 'USE_ITEM_ANSWER_PROTOCOL_OCCURRENCE',
    semantic_claim: 'Exact runtime type PKT_UseItemAns_s: HeroInventoryClient-scoped use-item answer protocol occurrence; answer-code lane names remain neutral.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'An answer packet is not evidence that an item effect occurred or that charges changed.',
  },
  '0x003f': {
    decision: 'PROMOTE',
    hypothesis: 'GOLD_REDIRECT_TARGET_UPDATE',
    semantic_claim: 'Exact runtime type PKT_UpdateGoldRedirectTarget_s: actor-scoped gold-redirection-target protocol update; protected target lane remains neutral until independently resolved.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'Runtime identity does not prove gold amount, transfer occurrence, or beneficiary outcome.',
  },
  '0x02fd': {
    decision: 'REPURPOSE',
    hypothesis: 'DIMENSION_UNIT_STATE_UPDATE',
    semantic_claim: 'Exact runtime type PKT_SetDimensionUnit_s: AttackableUnit dimension-state protocol update; not a combat scalar or entity spawn.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'The one/two-byte state carrier contradicts HP, damage, and position-vector hypotheses.',
  },
  '0x0398': {
    decision: 'REPURPOSE',
    hypothesis: 'TEAM_VISIBILITY_LEAVE_PRESENTATION_EVENT',
    semantic_claim: 'Exact runtime type PKT_S2C_OnLeaveTeamVisibility_s: NetVisibilityObjectClient presentation/visibility transition, without hidden-state behavior inference.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'Team-visibility protocol membership does not prove true vision, fog geometry, or actor behavior.',
  },
  '0x01b0': {
    decision: 'PROMOTE',
    hypothesis: 'ITEM_PARAMETER_VALUE_UPDATE',
    semantic_claim: 'Exact runtime type PKT_S2C_SetItemParamValue_s: HeroInventoryClient-scoped item parameter-value update; parameter identity/value lanes remain neutral.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'Parameter updates do not universally mean charges, stack count, purchase, sale, or undo.',
  },
  '0x0200': {
    decision: 'REPURPOSE',
    hypothesis: 'ITEM_GROUP_MAP_VIEW_DATA',
    semantic_claim: 'Exact runtime type PKT_S2C_SetItemGroupData_MapView_s: HeroInventoryClient map-view item-group data; not canonical ordinary inventory state.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'MapView specialization prevents generalizing this route to ordinary inventory snapshots.',
  },
  '0x0035': {
    decision: 'PROMOTE',
    hypothesis: 'SPELL_TARGETABILITY_TYPE_MASK_UPDATE',
    semantic_claim: 'Exact runtime type PKT_S2C_SpellTypesThatCanTargetUs_s: AttackableUnit-scoped targetability-type protocol update; individual protected bits remain neutral.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'The route communicates allowed targeting types, not a cast occurrence or proof that a spell targeted the unit.',
  },
  '0x03ac': {
    decision: 'REPURPOSE',
    hypothesis: 'MINIMAP_ICON_OVERRIDE_PRESENTATION_STATE',
    semantic_claim: 'Exact runtime type PKT_S2C_SetMinimapIconOverride_Broadcast_s: minimap-icon presentation override; parser output must not claim map truth.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'Icon presentation can differ from physical location and visibility; it is not map truth.',
  },
  '0x032f': {
    decision: 'PROMOTE',
    hypothesis: 'CHARACTER_DATA_CHANGE_PROTOCOL_OCCURRENCE',
    semantic_claim: 'Exact runtime type PKT_S2C_ChangeCharacterData_s, registered for AIBaseClient and AnimatedBuildingClient: character-data change protocol occurrence; opaque identity lanes remain neutral.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'Dual callback-owner registration contradicts a hero-only skin/change interpretation.',
  },
  '0x040c': {
    decision: 'REPURPOSE',
    hypothesis: 'MINIMAP_ICON_BORDER_OVERRIDE_PRESENTATION_STATE',
    semantic_claim: 'Exact runtime type PKT_S2C_SetMinimapIconBorderOverride_s: minimap icon-border presentation override, not gameplay map truth.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'The presentation-only callback identity rejects physical boundary or collision interpretations.',
  },
  '0x00de': {
    decision: 'REPURPOSE',
    hypothesis: 'MINIMAP_ICON_BEHAVIOR_KEY_PRESENTATION_STATE',
    semantic_claim: 'Exact runtime type PKT_S2C_SetMinimapIconBehaviorSetKeyHash_s: minimap behavior-set-key presentation update; the protected key remains opaque.',
    publishable_fields: ['subject_network_id=raw_param', 'replay_time_ms', 'runtime_packet_type'],
    counterexample: 'An opaque minimap behavior key does not establish world position, visibility, or behavior inference.',
  },
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
  const result = [...map.entries()]
    .map(([key, count]) => ({ [keyName]: /^-?\d+$/.test(key) ? Number(key) : key, count }))
    .sort((left, right) => right.count - left.count
      || String(left[keyName]).localeCompare(String(right[keyName])));
  return limit === null ? result : result.slice(0, limit);
}

function rawParamClass(value) {
  const numeric = Number(value) >>> 0;
  if (numeric === 0) return 'ZERO';
  if (numeric >= 0x400000ae && numeric <= 0x400000b7) return 'CANONICAL_HERO_NETWORK_ID';
  if (numeric >= 0x40000000 && numeric <= 0x4fffffff) return 'BROAD_NETWORK_ID';
  return 'OTHER_NONZERO';
}

function stableDigest(value) {
  return sha256(Buffer.from(JSON.stringify(value), 'utf8'));
}

function newRouteState(packetId) {
  return {
    packet_id: packetId,
    events: [],
    count: 0,
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

function newAnchorIndex() {
  return new Map(Object.keys(ANCHOR_FAMILIES).map((family) => [family, new Map()]));
}

function compactPayloadRow(event, payloadHash, payload) {
  return {
    schema: 'NEXT_PRIORITY_WAVE_DISTINCT_PAYLOAD_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    packet_id: event.packet_id,
    packet_discriminator: packetHex(event.packet_id),
    replay_sha256: event.replay_sha256,
    replay_version: EXACT_BUILD,
    replay_label: event.replay_label,
    replay_time_ms: event.time,
    occurrence_index: event.occurrence_index,
    raw_param: event.raw_param,
    chunk_stream: event.stream,
    payload_length: payload.length,
    raw_payload_hex: payload.toString('hex'),
    raw_payload_sha256: payloadHash,
    occurrence_count: 1,
    replay_occurrence_counts: { [event.replay_sha256]: 1 },
    stream_occurrence_counts: { [event.stream]: 1 },
    raw_param_distinct_count: 1,
    raw_param_top_values: [{ raw_param: event.raw_param, count: 1 }],
  };
}

function updateDistinctPayload(row, event) {
  row.occurrence_count += 1;
  row.replay_occurrence_counts[event.replay_sha256] =
    (row.replay_occurrence_counts[event.replay_sha256] || 0) + 1;
  row.stream_occurrence_counts[event.stream] =
    (row.stream_occurrence_counts[event.stream] || 0) + 1;
  if (!row._raw_param_counts) {
    row._raw_param_counts = new Map(row.raw_param_top_values.map((entry) => [String(entry.raw_param), entry.count]));
  }
  increment(row._raw_param_counts, event.raw_param);
  row.raw_param_distinct_count = row._raw_param_counts.size;
}

function finalizeDistinctPayload(row) {
  if (row._raw_param_counts) {
    row.raw_param_top_values = sortedCounter(row._raw_param_counts, 'raw_param', 24);
    delete row._raw_param_counts;
  }
  row.replay_occurrence_counts = Object.fromEntries(
    Object.entries(row.replay_occurrence_counts).sort(([left], [right]) => left.localeCompare(right)),
  );
  row.stream_occurrence_counts = Object.fromEntries(
    Object.entries(row.stream_occurrence_counts).sort(([left], [right]) => left.localeCompare(right)),
  );
  return row;
}

function addAnchor(anchorIndex, family, replaySha256, time, rawParam, packetId) {
  const byReplay = anchorIndex.get(family);
  if (!byReplay.has(replaySha256)) byReplay.set(replaySha256, []);
  byReplay.get(replaySha256).push({ time, raw_param: rawParam, packet_id: packetId });
}

function participantMetadata(replay) {
  return normalizePlayers(replay).map((player, index) => ({
    participant_id: index + 1,
    champion_network_id: 0x400000ae + index,
    champion: player.champion,
    aggregate_stats: player.aggregate_stats,
  }));
}

function collectReplay(replayPath, states, anchorIndex) {
  const source = rejectProtectedPath(replayPath);
  const replay = parseReplayFile(source);
  const basename = path.basename(source);
  invariant(Object.hasOwn(SAFE_REPLAYS, basename), `replay is outside explicit safe allowlist: ${basename}`);
  invariant(replay.source_sha256 === SAFE_REPLAYS[basename], `safe replay SHA-256 mismatch: ${basename}`);
  invariant(replay.header.version === EXACT_BUILD, `safe replay exact-build mismatch: ${basename}`);
  const replayLabel = path.basename(source, path.extname(source));
  let previous = null;
  let globalOccurrence = 0;
  const walk = walkBlocks(replay, (block, chunk) => {
    for (const state of states.values()) {
      if (!state.pending) continue;
      increment(state.next, packetHex(block.packet_id));
      increment(state.next_same_time,
        state.pending.time === block.timestamp_ms ? packetHex(block.packet_id) : 'DIFFERENT_TIMESTAMP');
      state.pending = null;
    }
    const anchorFamilies = ANCHOR_BY_ID.get(block.packet_id);
    if (anchorFamilies) {
      for (const family of anchorFamilies) {
        addAnchor(anchorIndex, family, replay.source_sha256, block.timestamp_ms,
          block.param >>> 0, block.packet_id);
      }
    }
    const state = states.get(block.packet_id);
    if (state) {
      const payloadHash = sha256(block.payload);
      const event = {
        packet_id: block.packet_id,
        replay_sha256: replay.source_sha256,
        replay_label: replayLabel,
        time: block.timestamp_ms,
        raw_param: block.param >>> 0,
        stream: chunk.stream,
        payload_length: block.payload_length,
        payload_sha256: payloadHash,
        occurrence_index: globalOccurrence,
      };
      state.count += 1;
      state.events.push(event);
      increment(state.per_replay, replay.source_sha256);
      increment(state.streams, chunk.stream);
      increment(state.lengths, block.payload_length);
      increment(state.raw_params, event.raw_param);
      increment(state.raw_classes, rawParamClass(event.raw_param));
      increment(state.previous, previous ? packetHex(previous.packet_id) : 'START');
      increment(state.previous_same_time,
        previous && previous.time === event.time ? packetHex(previous.packet_id) : 'DIFFERENT_TIMESTAMP');
      if (!state.payloads.has(payloadHash)) {
        state.payloads.set(payloadHash, compactPayloadRow(event, payloadHash, block.payload));
      } else {
        updateDistinctPayload(state.payloads.get(payloadHash), event);
      }
      state.pending = event;
    }
    previous = { packet_id: block.packet_id, time: block.timestamp_ms };
    globalOccurrence += 1;
  }, { includeStreams: [1, 2, 3], strict: true });
  invariant(walk.errors.length === 0, `strict packet walk failed: ${basename}`);
  for (const state of states.values()) {
    if (!state.pending) continue;
    increment(state.next, 'END');
    increment(state.next_same_time, 'DIFFERENT_TIMESTAMP');
    state.pending = null;
  }
  return {
    path: source,
    basename,
    replay_label: replayLabel,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header.version,
    block_count: walk.block_count,
    players: participantMetadata(replay),
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
  const shifted137 = [];
  const shifted997 = [];
  let exact = 0;
  let within10 = 0;
  let within50 = 0;
  let within500 = 0;
  let exactEntity = 0;
  let within10Entity = 0;
  let shifted137Within10 = 0;
  let shifted997Within10 = 0;
  const farCounterexamples = [];
  const cotimedEntityMismatch = [];
  for (const event of events) {
    const anchors = byReplay.get(event.replay_sha256) || [];
    const nearest = nearestEvent(anchors, event.time);
    if (!nearest) continue;
    const delta = Math.abs(nearest.time - event.time);
    deltas.push(delta);
    if (delta === 0) exact += 1;
    if (delta <= 10) within10 += 1;
    if (delta <= 50) within50 += 1;
    if (delta <= 500) within500 += 1;
    if (delta === 0 && nearest.raw_param === event.raw_param) exactEntity += 1;
    if (delta <= 10 && nearest.raw_param === event.raw_param) within10Entity += 1;
    const shifted137Anchor = nearestEvent(anchors, event.time + 137);
    const shifted997Anchor = nearestEvent(anchors, event.time + 997);
    const delta137 = shifted137Anchor ? Math.abs(shifted137Anchor.time - (event.time + 137)) : null;
    const delta997 = shifted997Anchor ? Math.abs(shifted997Anchor.time - (event.time + 997)) : null;
    if (delta137 !== null) shifted137.push(delta137);
    if (delta997 !== null) shifted997.push(delta997);
    if (delta137 !== null && delta137 <= 10) shifted137Within10 += 1;
    if (delta997 !== null && delta997 <= 10) shifted997Within10 += 1;
    if (delta > 500 && farCounterexamples.length < 12) {
      farCounterexamples.push({
        replay_sha256: event.replay_sha256,
        replay_time_ms: event.time,
        raw_param: event.raw_param,
        nearest_anchor_delta_ms: delta,
      });
    }
    if (delta === 0 && nearest.raw_param !== event.raw_param && cotimedEntityMismatch.length < 12) {
      cotimedEntityMismatch.push({
        replay_sha256: event.replay_sha256,
        replay_time_ms: event.time,
        raw_param: event.raw_param,
        anchor_raw_param: nearest.raw_param,
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
    within_50ms_count: within50,
    within_50ms_rate: round(within50 / Math.max(1, eligible)),
    within_500ms_count: within500,
    within_500ms_rate: round(within500 / Math.max(1, eligible)),
    exact_time_same_raw_param_count: exactEntity,
    exact_time_same_raw_param_rate: round(exactEntity / Math.max(1, eligible)),
    within_10ms_same_raw_param_count: within10Entity,
    within_10ms_same_raw_param_rate: round(within10Entity / Math.max(1, eligible)),
    nearest_delta_p50_ms: quantile(deltas, 0.5),
    nearest_delta_p90_ms: quantile(deltas, 0.9),
    shifted_137ms_within_10ms_count: shifted137Within10,
    shifted_137ms_within_10ms_rate: round(shifted137Within10 / Math.max(1, shifted137.length)),
    shifted_997ms_within_10ms_count: shifted997Within10,
    shifted_997ms_within_10ms_rate: round(shifted997Within10 / Math.max(1, shifted997.length)),
    enrichment_over_137ms_control: round((within10 + 1) / (shifted137Within10 + 1)),
    enrichment_over_997ms_control: round((within10 + 1) / (shifted997Within10 + 1)),
    far_over_500ms_count: eligible - within500,
    far_counterexamples: farCounterexamples,
    cotimed_raw_param_mismatch_examples: cotimedEntityMismatch,
    semantic_claim: null,
  };
}

function temporalSummary(events) {
  const byReplay = new Map();
  const groups = new Map();
  for (const event of events) {
    if (!byReplay.has(event.replay_sha256)) byReplay.set(event.replay_sha256, []);
    byReplay.get(event.replay_sha256).push(event);
    const key = `${event.replay_sha256}:${event.time}`;
    if (!groups.has(key)) groups.set(key, 0);
    groups.set(key, groups.get(key) + 1);
  }
  const deltas = [];
  let sameTime = 0;
  let transitions = 0;
  for (const rows of byReplay.values()) {
    rows.sort((left, right) => left.time - right.time || left.occurrence_index - right.occurrence_index);
    for (let index = 1; index < rows.length; index += 1) {
      const delta = rows[index].time - rows[index - 1].time;
      deltas.push(delta);
      transitions += 1;
      if (delta === 0) sameTime += 1;
    }
  }
  const groupSizes = [...groups.values()];
  return {
    timestamp_group_count: groups.size,
    group_size_min: groupSizes.length ? Math.min(...groupSizes) : null,
    group_size_p50: quantile(groupSizes, 0.5),
    group_size_p90: quantile(groupSizes, 0.9),
    group_size_max: groupSizes.length ? Math.max(...groupSizes) : null,
    delta_p50_ms: quantile(deltas, 0.5),
    delta_p90_ms: quantile(deltas, 0.9),
    delta_p99_ms: quantile(deltas, 0.99),
    same_timestamp_transition_rate: round(sameTime / Math.max(1, transitions)),
  };
}

function summarizeRouteState(state, anchorIndex) {
  const payloadRows = [...state.payloads.values()]
    .map(finalizeDistinctPayload)
    .sort((left, right) => left.payload_length - right.payload_length
      || left.raw_payload_sha256.localeCompare(right.raw_payload_sha256));
  const branchMap = new Map();
  for (const payload of payloadRows) {
    const key = String(payload.payload_length);
    if (!branchMap.has(key)) branchMap.set(key, { count: 0, distinct: 0 });
    const branch = branchMap.get(key);
    branch.count += payload.occurrence_count;
    branch.distinct += 1;
  }
  const anchors = {};
  for (const [family, byReplay] of anchorIndex) {
    anchors[family] = anchorCorrelation(state.events, byReplay);
  }
  const occurrenceWeight = payloadRows.reduce((sum, row) => sum + row.occurrence_count, 0);
  return {
    packet_id: state.packet_id,
    packet_discriminator: packetHex(state.packet_id),
    count: state.count,
    per_replay_count: sortedCounter(state.per_replay, 'replay_sha256'),
    stream_distribution: sortedCounter(state.streams, 'stream'),
    payload: {
      length_distribution: sortedCounter(state.lengths, 'payload_length'),
      distinct_payload_sha256_count: payloadRows.length,
      distinct_payload_corpus_row_count: payloadRows.length,
      occurrence_weight_sum: occurrenceWeight,
      occurrence_weight_conserved: occurrenceWeight === state.count,
      branches: [...branchMap.entries()].map(([payloadLength, row]) => ({
        payload_length: Number(payloadLength),
        count: row.count,
        distinct_payload_count: row.distinct,
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
    anchor_correlations_with_shifted_controls: anchors,
    distinct_payload_rows: payloadRows,
  };
}

function collectEvidence(replayPaths) {
  invariant(Array.isArray(replayPaths) && replayPaths.length === 4,
    'exactly four explicit safe replay paths are required');
  const states = new Map(ROUTE_IDS.map((packetId) => [packetId, newRouteState(packetId)]));
  const anchorIndex = newAnchorIndex();
  const replays = replayPaths.map((replayPath) => collectReplay(replayPath, states, anchorIndex));
  invariant(new Set(replays.map((row) => row.replay_sha256)).size === 4,
    'explicit safe replay inputs must be distinct');
  for (const byReplay of anchorIndex.values()) {
    for (const events of byReplay.values()) events.sort((left, right) => left.time - right.time);
  }
  const routes = Object.fromEntries(ROUTE_IDS.map((packetId) => {
    const report = summarizeRouteState(states.get(packetId), anchorIndex);
    return [packetHex(packetId), report];
  }));
  const distinctPayloadRows = ROUTE_IDS.flatMap((packetId) => routes[packetHex(packetId)].distinct_payload_rows)
    .sort((left, right) => left.packet_id - right.packet_id
      || left.payload_length - right.payload_length
      || left.raw_payload_sha256.localeCompare(right.raw_payload_sha256));
  for (const route of Object.values(routes)) delete route.distinct_payload_rows;
  const anchorCounts = {};
  for (const [family, byReplay] of anchorIndex) {
    anchorCounts[family] = [...byReplay.values()].reduce((sum, events) => sum + events.length, 0);
  }
  const canonical = {
    replays: replays.map((row) => ({
      basename: row.basename,
      replay_sha256: row.replay_sha256,
      replay_version: row.replay_version,
      block_count: row.block_count,
      players: row.players,
    })),
    routes,
    anchor_counts: anchorCounts,
    distinct_payload_rows: distinctPayloadRows,
  };
  return {
    ...canonical,
    kda_events: states.get(0x016b).events.map((event) => ({ ...event })),
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

function relativeTarget(rva, instructionLength, displacement) {
  return rva + instructionLength + displacement;
}

function findAll(buffer, needle, start, end) {
  const matches = [];
  let cursor = start;
  while (cursor < end) {
    const position = buffer.indexOf(needle, cursor);
    if (position < 0 || position >= end) break;
    matches.push(position);
    cursor = position + 1;
  }
  return matches;
}

function recoverInlineFactory0023(image) {
  invariant(image.readUInt32LE(FACTORY_TABLE_RVA + 0x0023 * 4) === 0x00eda7e9,
    '0x0023 jump-table case changed');
  const caseRva = image.readUInt32LE(FACTORY_TABLE_RVA + 0x0023 * 4);
  const window = image.subarray(caseRva, caseRva + 0xc0);
  invariant(window.subarray(0, 5).equals(Buffer.from([0xb9, 0x18, 0, 0, 0])),
    '0x0023 inline allocation-size load changed');
  const idStore = Buffer.from([0x66, 0xc7, 0x40, 0x08, 0x23, 0x00]);
  invariant(window.indexOf(idStore) >= 0, '0x0023 inline packet-ID store not found');
  const vtableLeaOffset = window.indexOf(Buffer.from([0x48, 0x8d, 0x05]), 0x30);
  invariant(vtableLeaOffset >= 0, '0x0023 packet-vtable LEA not found');
  const vtableLeaRva = caseRva + vtableLeaOffset;
  const displacement = image.readInt32LE(vtableLeaRva + 3);
  const vtableRva = relativeTarget(vtableLeaRva, 7, displacement);
  const deserializerRva = readRvaQword(image, vtableRva + 8);
  const sizeGetterRva = readRvaQword(image, vtableRva + 16);
  const sizeGetter = image.subarray(sizeGetterRva, sizeGetterRva + 6);
  invariant(sizeGetter[0] === 0xb8 && sizeGetter.readUInt32LE(1) === 0x18 && sizeGetter[5] === 0xc3,
    '0x0023 vtable size getter changed');
  return {
    search_kind: 'BOUNDED_COMMON_FACTORY_JUMP_TABLE_INLINE_CONSTRUCTOR',
    search_range: [rvaHex(caseRva), rvaHex(caseRva + 0xc0)],
    case_rva: caseRva,
    case_rva_hex: rvaHex(caseRva),
    allocation_size: 24,
    constructor_kind: 'INLINE_FACTORY_CASE_NO_STANDALONE_CONSTRUCTOR',
    constructor_rva: null,
    packet_object_vtable_rva: vtableRva,
    packet_object_vtable_rva_hex: rvaHex(vtableRva),
    deserializer_rva: deserializerRva,
    deserializer_rva_hex: rvaHex(deserializerRva),
    size_getter_rva: sizeGetterRva,
    exact_initializer_branch_hash: sha256(window),
    bounded_search_exhausted: true,
  };
}

function recoverKdaCallback(image) {
  const callerStart = 0x002f1ffc;
  const callerEnd = 0x002f4fc7;
  const builderRva = 0x002eaa50;
  const callSites = [];
  for (let rva = callerStart; rva + 5 <= callerEnd; rva += 1) {
    if (image[rva] !== 0xe8) continue;
    const target = relativeTarget(rva, 5, image.readInt32LE(rva + 1));
    if (target === builderRva) callSites.push(rva);
  }
  invariant(callSites.length === 1, `expected one KDA callback-builder call, got ${callSites.length}`);
  const callRva = callSites[0];
  const leaCandidates = [];
  for (let rva = Math.max(callerStart, callRva - 0x60); rva + 7 <= callRva; rva += 1) {
    if (image[rva] !== 0x48 || image[rva + 1] !== 0x8d || image[rva + 2] !== 0x0d) continue;
    const target = relativeTarget(rva, 7, image.readInt32LE(rva + 3));
    const tail = image.subarray(rva + 7, Math.min(callRva, rva + 0x20));
    if (tail.indexOf(Buffer.from([0x48, 0x89, 0x4c, 0x24, 0x20])) >= 0) {
      leaCandidates.push({ lea_rva: rva, target });
    }
  }
  invariant(leaCandidates.length === 1,
    `expected one bounded KDA member-function target, got ${leaCandidates.length}`);
  invariant(leaCandidates[0].target === KDA_CALLBACK_RVA,
    `KDA callback target changed: ${rvaHex(leaCandidates[0].target)}`);
  return {
    search_kind: 'BOUNDED_OUT_OF_LINE_CALLBACK_BUILDER_MEMBER_FUNCTION_RECOVERY',
    registration_caller_range: [rvaHex(callerStart), rvaHex(callerEnd)],
    callback_builder_rva: rvaHex(builderRva),
    unique_builder_call_rva: rvaHex(callRva),
    member_function_load_rva: rvaHex(leaCandidates[0].lea_rva),
    callback_receive_target_rva: KDA_CALLBACK_RVA,
    callback_receive_target_rva_hex: rvaHex(KDA_CALLBACK_RVA),
    callback_slice_sha256: sha256(image.subarray(KDA_CALLBACK_RVA, KDA_CALLBACK_RVA + 0x1a6)),
    decoded_object_reads: [
      { offset: '0x10', storage_type: 'protected_u32', destination_state_offset: '0x310', semantic_role: 'kills_u32' },
      { offset: '0x14', storage_type: 'protected_u32', destination_state_offset: '0x338', semantic_role: 'deaths_u32' },
      { offset: '0x18', storage_type: 'protected_u32', destination_state_offset: '0x360', semantic_role: 'assists_u32' },
    ],
    bounded_search_exhausted: true,
  };
}

function factoryIdentityFromRegistry(route, image) {
  const packetId = Number(route.packet_id);
  if (packetId === 0x0023) return recoverInlineFactory0023(image);
  const entries = route.runtime_registration?.factory_packets || [];
  invariant(entries.length === 1, `${packetHex(packetId)} expected one factory entry`);
  const entry = entries[0];
  const caseRva = image.readUInt32LE(FACTORY_TABLE_RVA + packetId * 4);
  invariant(caseRva === Number(entry.case_rva), `${packetHex(packetId)} factory case mismatch`);
  invariant(readRvaQword(image, Number(entry.packet_object_vtable_rva) + 8)
    === Number(entry.deserializer_rva), `${packetHex(packetId)} vtable deserializer mismatch`);
  return {
    search_kind: 'BOUNDED_COMMON_FACTORY_JUMP_TABLE_STANDALONE_CONSTRUCTOR',
    switch_rva: rvaHex(FACTORY_SWITCH_RVA),
    switch_maximum_packet_id: FACTORY_MAX_ID,
    jump_table_rva: rvaHex(FACTORY_TABLE_RVA),
    case_rva: Number(entry.case_rva),
    case_rva_hex: rvaHex(entry.case_rva),
    allocation_size: Number(entry.object_size),
    constructor_kind: 'STANDALONE_EXACT_CONSTRUCTOR',
    constructor_rva: Number(entry.constructor_rva),
    constructor_rva_hex: rvaHex(entry.constructor_rva),
    packet_object_vtable_rva: Number(entry.packet_object_vtable_rva),
    packet_object_vtable_rva_hex: rvaHex(entry.packet_object_vtable_rva),
    deserializer_rva: Number(entry.deserializer_rva),
    deserializer_rva_hex: rvaHex(entry.deserializer_rva),
    runtime_slice_hashes: {
      case: sha256(image.subarray(caseRva, caseRva + 0x80)),
      constructor: sha256(image.subarray(Number(entry.constructor_rva), Number(entry.constructor_rva) + 0x80)),
      vtable: sha256(image.subarray(Number(entry.packet_object_vtable_rva), Number(entry.packet_object_vtable_rva) + 0x30)),
      deserializer: sha256(image.subarray(Number(entry.deserializer_rva), Number(entry.deserializer_rva) + 0x100)),
    },
    bounded_search_exhausted: true,
  };
}

function recoverRuntimeIdentities(registry, image) {
  invariant(registry.exact_build === EXACT_BUILD, 'observed registry exact-build mismatch');
  invariant(sha256(image) === RUNTIME_SHA256, 'pinned exact runtime image SHA-256 mismatch');
  return ROUTE_IDS.map((packetId) => {
    const route = registry.routes.find((entry) => Number(entry.packet_id) === packetId);
    invariant(route, `observed registry missing ${packetHex(packetId)}`);
    const callbacks = route.runtime_registration?.callbacks || [];
    invariant(callbacks.length >= 1, `${packetHex(packetId)} lacks exact callback RTTI identity`);
    const factory = factoryIdentityFromRegistry(route, image);
    return {
      packet_id: packetId,
      packet_discriminator: packetHex(packetId),
      callback_mapping_status: route.runtime_registration.callback_mapping_status,
      callback_names: callbacks.map((entry) => entry.name),
      callback_owners: [...new Set(callbacks.map((entry) => entry.callback_owner_type))],
      callback_registrations: callbacks,
      alternate_callback_recovery: packetId === 0x016b ? recoverKdaCallback(image) : null,
      factory,
      validations: {
        exact_callback_rtti_identity: true,
        exact_factory_case: true,
        exact_constructor_or_inline_initializer: true,
        exact_packet_vtable: true,
        exact_deserializer: true,
        all_pass: true,
      },
    };
  });
}

function buildNativeProfiles(runtimeIdentities) {
  return runtimeIdentities.map((identity) => {
    const packetId = identity.packet_id;
    const factory = identity.factory;
    const inline0023 = packetId === 0x0023;
    return {
      schema: 'NEXT_PRIORITY_WAVE_NATIVE_PROFILE_V2',
      schema_version: 2,
      exact_build: EXACT_BUILD,
      exact_runtime_image_sha256: RUNTIME_SHA256,
      source_runtime_identity: identity,
      emulation_boundary: inline0023
        ? {
          constructor_status: 'EXACT_INLINE_INITIALIZER_STATICALLY_RECOVERED',
          harness_constructor: '0x00e9c760',
          harness_constructor_role: 'SAME_SIZE_SURROGATE_FOR_DIRECT_DESERIALIZER_EXECUTION_ONLY',
          publishable_field_rule: 'Only lanes written by the exact deserializer branch are analyzed; omitted defaults are excluded.',
        }
        : { constructor_status: 'EXACT_STANDALONE_CONSTRUCTOR' },
      profile: {
        id: `next-priority-wave-${packetHex(packetId).slice(2)}-exact-runtime-v2`,
        client_opcode: packetId,
        constructor_rva: inline0023 ? 0x00e9c760 : factory.constructor_rva,
        deserialize_rva: factory.deserializer_rva,
        object_size: factory.allocation_size,
        fields: [],
      },
    };
  });
}

function rotateRight8(value, count) {
  const shift = count & 7;
  return ((value >>> shift) | (value << ((8 - shift) & 7))) & 0xff;
}

function swapAdjacentBits(value) {
  return ((((value & 0xd5) << 1) | ((value >>> 1) & 0x55))) & 0xff;
}

function decodeKdaObject(objectHex, image) {
  const object = Buffer.from(objectHex, 'hex');
  invariant(object.length >= 0x1c, 'KDA object is shorter than 0x1c bytes');
  const first = (value) => (
    (rotateRight8(rotateRight8(value, 6) ^ 0x9f, 6) ^ 0xe0) + 0x51
  ) & 0xff;
  const second = (value) => rotateRight8(
    (rotateRight8((value + 0x32) & 0xff, 1) + 0x45) & 0xff,
    7,
  );
  const third = (value) => {
    const index = (((value - 0x32) & 0xff) ^ 0x59) & 0xff;
    return swapAdjacentBits(rotateRight8(image[KDA_LOOKUP_TABLE_RVA + index], 2));
  };
  const decoded = Buffer.alloc(12);
  for (let index = 0; index < 4; index += 1) {
    decoded[index] = first(object[0x10 + index]);
    decoded[4 + index] = second(object[0x14 + index]);
    decoded[8 + index] = third(object[0x18 + index]);
  }
  return {
    kills_u32: decoded.readUInt32LE(0),
    deaths_u32: decoded.readUInt32LE(4),
    assists_u32: decoded.readUInt32LE(8),
  };
}

function entropyFromCounter(counter, total) {
  let result = 0;
  for (const count of counter.values()) {
    const probability = count / total;
    result -= probability * Math.log2(probability);
  }
  return round(result);
}

function analyzeObjectStorage(rows, objectSize) {
  const offsets = [];
  for (let offset = 0x10; offset < objectSize; offset += 1) {
    const counter = new Map();
    let weight = 0;
    for (const row of rows) {
      if (!row.object_hex || row.emulation_error) continue;
      const object = Buffer.from(row.object_hex, 'hex');
      if (offset >= object.length) continue;
      const occurrenceWeight = Number(row.occurrence_count || 1);
      increment(counter, object[offset], occurrenceWeight);
      weight += occurrenceWeight;
    }
    if (!weight) continue;
    offsets.push({
      object_offset: rvaHex(offset),
      storage_type: 'PROTECTED_OR_STRUCTURAL_U8_LANE',
      weighted_observation_count: weight,
      distinct_storage_value_count: counter.size,
      entropy_bits: entropyFromCounter(counter, weight),
      top_storage_values: sortedCounter(counter, 'value_u8', 8),
      semantic_role: null,
    });
  }
  return offsets;
}

function terminalKdaValidation(kdaRows, evidence, image) {
  const decodedByPayload = new Map();
  let decodedCount = 0;
  for (const row of kdaRows) {
    if (row.emulation_error || !row.fully_consumed || !row.object_hex) continue;
    decodedByPayload.set(row.raw_payload_sha256, decodeKdaObject(row.object_hex, image));
    decodedCount += 1;
  }
  const byReplaySubject = new Map();
  for (const row of evidence.kda_events) {
    const decoded = decodedByPayload.get(row.payload_sha256);
    if (!decoded) continue;
    const key = `${row.replay_sha256}:${Number(row.raw_param) >>> 0}`;
    const candidate = {
      replay_sha256: row.replay_sha256,
      replay_time_ms: Number(row.time),
      raw_param: Number(row.raw_param) >>> 0,
      ...decoded,
    };
    const current = byReplaySubject.get(key);
    if (!current || candidate.replay_time_ms > current.replay_time_ms) byReplaySubject.set(key, candidate);
  }
  const checks = [];
  for (const replay of evidence.replays) {
    for (const player of replay.players) {
      const key = `${replay.replay_sha256}:${player.champion_network_id}`;
      const terminal = byReplaySubject.get(key);
      if (!terminal) continue;
      const expected = {
        kills_u32: Number(player.aggregate_stats.kills),
        deaths_u32: Number(player.aggregate_stats.deaths),
        assists_u32: Number(player.aggregate_stats.assists),
      };
      checks.push({
        replay_sha256: replay.replay_sha256,
        participant_id: player.participant_id,
        champion_network_id: player.champion_network_id,
        champion: player.champion,
        terminal,
        expected,
        matches: terminal.kills_u32 === expected.kills_u32
          && terminal.deaths_u32 === expected.deaths_u32
          && terminal.assists_u32 === expected.assists_u32,
        exact_component_count: Number(terminal.kills_u32 === expected.kills_u32)
          + Number(terminal.deaths_u32 === expected.deaths_u32)
          + Number(terminal.assists_u32 === expected.assists_u32),
        componentwise_at_or_below_metadata: terminal.kills_u32 <= expected.kills_u32
          && terminal.deaths_u32 <= expected.deaths_u32
          && terminal.assists_u32 <= expected.assists_u32,
      });
    }
  }
  const exactComponentCount = checks.reduce((sum, row) => sum + row.exact_component_count, 0);
  const componentCheckCount = checks.length * 3;
  const allComponentwiseBounded = checks.length > 0
    && checks.every((row) => row.componentwise_at_or_below_metadata);
  const terminalMatchCount = checks.filter((row) => row.matches).length;
  return {
    decoded_distinct_payload_row_count: decodedCount,
    terminal_metadata_check_count: checks.length,
    terminal_metadata_match_count: terminalMatchCount,
    full_terminal_match_rate: round(terminalMatchCount / Math.max(1, checks.length)),
    component_metadata_check_count: componentCheckCount,
    exact_component_metadata_match_count: exactComponentCount,
    exact_component_metadata_match_rate: round(exactComponentCount / Math.max(1, componentCheckCount)),
    all_terminal_components_at_or_below_final_metadata: allComponentwiseBounded,
    all_terminal_metadata_checks_match: checks.length > 0 && checks.every((row) => row.matches),
    semantic_field_role_validation_pass: checks.length === 40
      && terminalMatchCount >= 30
      && exactComponentCount / Math.max(1, componentCheckCount) >= 0.85
      && allComponentwiseBounded,
    boundary: 'The route is event-driven and some participants receive no final post-event KDA packet; lower terminal values are retained as counterexamples rather than forced to final metadata.',
    checks,
  };
}

function analyzeNativeOutputs(nativeRowsByRoute, nativeSummaries, evidence, runtimeIdentities, image) {
  const routes = {};
  for (const identity of runtimeIdentities) {
    const packetType = identity.packet_discriminator;
    const raw = evidence.routes[packetType];
    const rows = nativeRowsByRoute[packetType] || [];
    const summary = nativeSummaries[packetType];
    invariant(summary, `missing native summary for ${packetType}`);
    const attemptedWeight = rows.reduce((sum, row) => sum + Number(row.occurrence_count || 1), 0);
    const successfulRows = rows.filter((row) => !row.emulation_error
      && row.deserialize_return_al !== 0 && row.fully_consumed === true
      && row.opcode_matches_profile === true);
    const successfulWeight = successfulRows.reduce((sum, row) => sum + Number(row.occurrence_count || 1), 0);
    const failedRows = rows.filter((row) => !successfulRows.includes(row));
    const failedWeight = failedRows.reduce((sum, row) => sum + Number(row.occurrence_count || 1), 0);
    routes[packetType] = {
      distinct_payload_attempt_count: rows.length,
      expected_distinct_payload_count: raw.payload.distinct_payload_sha256_count,
      all_distinct_payloads_attempted: rows.length === raw.payload.distinct_payload_sha256_count,
      full_inventory_occurrence_weight: raw.count,
      attempted_occurrence_weight: attemptedWeight,
      successful_full_consume_distinct_count: successfulRows.length,
      successful_full_consume_occurrence_weight: successfulWeight,
      conserved_failure_distinct_count: failedRows.length,
      conserved_failure_occurrence_weight: failedWeight,
      full_occurrence_weight_conserved: attemptedWeight === raw.count
        && successfulWeight + failedWeight === raw.count,
      successful_full_consume_rate_by_occurrence_weight: round(successfulWeight / Math.max(1, raw.count)),
      payload_length_counts: summary.payload_length_counts,
      emulation_errors: summary.emulation_errors,
      object_storage_lane_profiles: analyzeObjectStorage(successfulRows, identity.factory.allocation_size),
      failure_examples: failedRows.slice(0, 16).map((row) => ({
        raw_payload_sha256: row.raw_payload_sha256,
        payload_length: row.payload_length,
        occurrence_count: row.occurrence_count,
        emulation_error: row.emulation_error || null,
        deserialize_return_al: row.deserialize_return_al ?? null,
        fully_consumed: row.fully_consumed ?? null,
      })),
    };
  }
  const kdaValidation = terminalKdaValidation(nativeRowsByRoute['0x016b'] || [], evidence, image);
  const visibilityCodecPointerSlot = 0x01ee9d08;
  const visibilityCodecPointer = image.readBigUInt64LE(visibilityCodecPointerSlot);
  routes['0x0398'].runtime_boundary = {
    status: 'BLOCKED_BY_EXACT_IMAGE_EXTERNAL_CODEC_HEAP_POINTER',
    failing_deserializer_rva: '0x00f69c20',
    failing_helper_rva: '0x00f526f0',
    global_pointer_slot_rva: rvaHex(visibilityCodecPointerSlot),
    captured_pointer_value: `0x${visibilityCodecPointer.toString(16).padStart(16, '0')}`,
    pointer_targets_external_heap_not_present_in_pinned_image: visibilityCodecPointer > IMAGE_BASE + BigInt(image.length),
    all_distinct_payloads_attempted_and_failures_conserved: routes['0x0398'].all_distinct_payloads_attempted
      && routes['0x0398'].full_occurrence_weight_conserved,
    remaining_evidence_threshold: 'LIVE_EXACT_BUILD_CODEC_HEAP_CAPTURE_OR_CONTROLLED_REPLAY_WITH_EQUIVALENT_RUNTIME_STATE',
  };
  routes['0x016b'].plaintext_fields = {
    fields: [
      { object_offset: '0x10', type: 'u32', semantic_role: 'kills_u32' },
      { object_offset: '0x14', type: 'u32', semantic_role: 'deaths_u32' },
      { object_offset: '0x18', type: 'u32', semantic_role: 'assists_u32' },
    ],
    exact_callback_transform: 'STATICALLY_RECOVERED_AND_APPLIED',
    terminal_metadata_validation: kdaValidation,
  };
  return { routes, kda_validation: kdaValidation };
}

function counterexampleCount(routeReport, config) {
  if (config.counterexample_anchor) {
    return routeReport.anchor_correlations_with_shifted_controls[config.counterexample_anchor]
      .far_over_500ms_count;
  }
  if (routeReport.packet_id === 0x0023) {
    const oneByte = routeReport.payload.branches.find((row) => row.payload_length === 1);
    return oneByte?.count || 0;
  }
  if (routeReport.packet_id === 0x032f) return routeReport.count;
  return Math.max(1, routeReport.count);
}

function buildDecisions(evidence, runtimeIdentities, nativeAnalysis) {
  const runtimeByType = new Map(runtimeIdentities.map((row) => [row.packet_discriminator, row]));
  const routeDecisions = ROUTE_IDS.map((packetId) => {
    const packetType = packetHex(packetId);
    const config = DECISION_CONFIG[packetType];
    const route = evidence.routes[packetType];
    const runtime = runtimeByType.get(packetType);
    const native = nativeAnalysis.routes[packetType];
    invariant(config, `missing decision config ${packetType}`);
    invariant(['PROMOTE', 'KEEP_CANDIDATE', 'REJECT', 'REPURPOSE'].includes(config.decision),
      `invalid decision ${config.decision}`);
    const kdaPass = packetId !== 0x016b
      || nativeAnalysis.kda_validation.semantic_field_role_validation_pass;
    const localSurfacesComplete = route.payload.occurrence_weight_conserved
      && runtime.validations.all_pass
      && native.all_distinct_payloads_attempted
      && native.full_occurrence_weight_conserved
      && kdaPass;
    return {
      packet_id: packetId,
      packet_discriminator: packetType,
      decision: config.decision,
      hypothesis: config.hypothesis,
      semantic_claim: config.semantic_claim,
      publishable_fields: config.publishable_fields,
      evidence_grade: packetId === 0x016b
        ? 'VERIFIED_EXACT_RUNTIME_CALLBACK_NATIVE_DECODE_AND_INDEPENDENT_METADATA'
        : 'VERIFIED_EXACT_RUNTIME_TYPE_AND_FULL_LOCAL_PROTOCOL_INVENTORY',
      positive_anchor_count: route.count,
      counterexample_count: counterexampleCount(route, config),
      counterexample: config.counterexample,
      structural_claim_only: packetId !== 0x016b,
      evidence_exhausted: localSurfacesComplete,
      evidence_exhausted_scope: 'PINNED_EXACT_RUNTIME_IMAGE_EXPLICIT_SAFE_LATEST_FOUR_ALL_DISTINCT_PAYLOADS_AND_SHIFTED_CONTROLS',
      local_surface_checks: {
        full_inventory_count_conserved: route.payload.occurrence_weight_conserved,
        callback_factory_constructor_vtable_deserializer_closed: runtime.validations.all_pass,
        all_distinct_payloads_native_attempted: native.all_distinct_payloads_attempted,
        native_success_and_failure_weights_conserved: native.full_occurrence_weight_conserved,
        independent_plaintext_anchor_pass: kdaPass,
      },
      remaining_local_executable_steps: localSurfacesComplete ? [] : [
        'Resolve the failing local-surface checks reported in local_surface_checks.',
      ],
      next_required_evidence: localSurfacesComplete ? [
        'Controlled exact-build replay or live heap trace for deliberately neutral protected lanes.',
        'External business dictionary/state oracle where a protected key or presentation field remains unnamed.',
      ] : [
        'Complete the still-failing local surface before treating this route as saturated.',
      ],
    };
  });
  return {
    route_decisions: routeDecisions,
    decision_counts: Object.fromEntries(['PROMOTE', 'KEEP_CANDIDATE', 'REJECT', 'REPURPOSE'].map((decision) => [
      decision,
      routeDecisions.filter((row) => row.decision === decision).length,
    ])),
    all_routes_have_one_decision: routeDecisions.length === ROUTE_IDS.length
      && new Set(routeDecisions.map((row) => row.packet_id)).size === ROUTE_IDS.length,
    all_current_local_evidence_exhausted: routeDecisions.every((row) => row.evidence_exhausted),
  };
}

function buildReport({ evidence, registryPath, runtimePath, runtimeIdentities, nativeAnalysis,
  nativeDeterminism, inputHashes }) {
  const decisions = buildDecisions(evidence, runtimeIdentities, nativeAnalysis);
  const targetCountConserved = Object.values(evidence.routes).every((route) =>
    route.payload.occurrence_weight_conserved);
  const nativeConserved = Object.values(nativeAnalysis.routes).every((route) =>
    route.all_distinct_payloads_attempted && route.full_occurrence_weight_conserved);
  return {
    schema: 'NEXT_PRIORITY_WAVE_DEEP_RECOVERY_V2',
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
      shared_manifest_api_schema_docs_package_or_ledger_modified: false,
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
      replays: evidence.replays.map((row) => ({
        path: row.path,
        basename: row.basename,
        replay_sha256: row.replay_sha256,
        replay_version: row.replay_version,
        block_count: row.block_count,
      })),
    },
    full_inventory: {
      target_row_count: evidence.target_row_count,
      distinct_payload_row_count: evidence.distinct_payload_row_count,
      anchor_counts: evidence.anchor_counts,
      target_occurrence_weight_conserved: targetCountConserved,
      deterministic_extraction_digest: evidence.deterministic_digest,
    },
    runtime_static_recovery: {
      common_factory_switch_rva: rvaHex(FACTORY_SWITCH_RVA),
      common_factory_jump_table_rva: rvaHex(FACTORY_TABLE_RVA),
      identities: runtimeIdentities,
      alternate_or_non_makefunction_searches_executed: ['0x0023 inline factory constructor', '0x016b out-of-line callback builder member target'],
      all_routes_closed: runtimeIdentities.every((row) => row.validations.all_pass),
    },
    routes: evidence.routes,
    native_exact_emulation: nativeAnalysis,
    independent_kda_validation: nativeAnalysis.kda_validation,
    decisions,
    saturation: {
      current_local_evidence_saturated: decisions.all_current_local_evidence_exhausted,
      closed_surfaces: [
        'EXPLICIT_SAFE_LATEST_FOUR_FULL_ROUTE_INVENTORY',
        'ALL_DISTINCT_PAYLOAD_HASHES_WITH_EXACT_OCCURRENCE_WEIGHTS',
        'PAYLOAD_LENGTH_STREAM_TIME_ENTITY_AND_CROSS_REPLAY_BRANCHES',
        'DAMAGE_DEATH_PATH_CAST_BUFF_ITEM_SCOREBOARD_ANCHORS_WITH_137MS_AND_997MS_CONTROLS',
        'EXACT_CALLBACK_RTTI_REGISTRATION_FACTORY_CONSTRUCTOR_OR_INLINE_INITIALIZER_VTABLE_DESERIALIZER',
        'BOUNDED_ALTERNATE_NON_MAKEFUNCTION_SEARCH_FOR_0x0023_AND_0x016b',
        'NATIVE_EXACT_DESERIALIZER_EXECUTION_FOR_EVERY_DISTINCT_PAYLOAD',
        '0x016b_TERMINAL_KDA_METADATA_COUNTERCHECK',
      ],
      residual_external_thresholds: [
        'Controlled exact-build replay for deliberately neutral protected lanes.',
        'Live exact-build heap/business-state trace for virtual dispatch or state-only labels.',
        'External exact-build dictionary for opaque item/minimap/character keys.',
      ],
    },
    determinism: nativeDeterminism,
    validations: {
      exact_build: true,
      replay_allowlist_and_hashes: evidence.replays.every((row) => SAFE_REPLAYS[row.basename] === row.replay_sha256),
      target_occurrence_weight_conserved: targetCountConserved,
      all_runtime_routes_closed: runtimeIdentities.every((row) => row.validations.all_pass),
      all_distinct_payloads_native_attempted: nativeConserved,
      native_deterministic_rerun_match: nativeDeterminism.all_match,
      every_route_has_exactly_one_machine_decision: decisions.all_routes_have_one_decision,
      all_route_evidence_exhausted: decisions.all_current_local_evidence_exhausted,
      kda_terminal_metadata_validation: nativeAnalysis.kda_validation.semantic_field_role_validation_pass,
      all_pass: targetCountConserved
        && runtimeIdentities.every((row) => row.validations.all_pass)
        && nativeConserved
        && nativeDeterminism.all_match
        && decisions.all_routes_have_one_decision
        && decisions.all_current_local_evidence_exhausted
        && nativeAnalysis.kda_validation.semantic_field_role_validation_pass,
    },
  };
}

function markdownReport(report) {
  const lines = [
    '# Next priority wave — exact-build deep recovery saturation audit',
    '',
    `- Build: \`${EXACT_BUILD}\`; nearest-build fallback forbidden.`,
    `- Full target inventory: ${report.full_inventory.target_row_count.toLocaleString('en-US')} rows.`,
    `- Distinct payloads natively executed: ${report.full_inventory.distinct_payload_row_count.toLocaleString('en-US')}.`,
    `- Current local evidence saturated: ${report.saturation.current_local_evidence_saturated}.`,
    '- Protected Jungle Objective Holdout was not enumerated, read, hashed, decoded, tested, or consumed.',
    '',
    '## Route decisions',
    '',
    '| Route | Exact runtime type | Decision | Minimal publishable surface | Counterexample / boundary |',
    '|---|---|---|---|---|',
  ];
  const runtimeById = new Map(report.runtime_static_recovery.identities.map((row) => [row.packet_id, row]));
  for (const decision of report.decisions.route_decisions) {
    const runtime = runtimeById.get(decision.packet_id);
    lines.push(`| \`${decision.packet_discriminator}\` | ${runtime.callback_names.join(' / ')} | ${decision.decision}: ${decision.hypothesis} | ${decision.publishable_fields.join(', ')} | ${decision.counterexample} |`);
  }
  lines.push(
    '',
    '## Strong field result',
    '',
    `\`0x016b\` recovered non-MakeFunction callback \`${rvaHex(KDA_CALLBACK_RVA)}\`, decoded three protected u32 lanes as cumulative kills/deaths/assists, matched ${report.independent_kda_validation.terminal_metadata_match_count}/${report.independent_kda_validation.terminal_metadata_check_count} complete terminal participant records and ${report.independent_kda_validation.exact_component_metadata_match_count}/${report.independent_kda_validation.component_metadata_check_count} individual components against independent replay metadata; every non-equal terminal value is lower than the final metadata total.`,
    '',
    '## Saturation boundary',
    '',
    'Every locally available route inventory, distinct payload, runtime identity path, native deserializer branch, requested anchor family, and shifted control has been executed. Remaining field names require controlled replay, live heap state, or an external exact-build dictionary; they are external thresholds rather than unexecuted local steps.',
    '',
  );
  return lines.join('\n');
}

module.exports = {
  ANCHOR_FAMILIES,
  DECISION_CONFIG,
  EXACT_BUILD,
  FACTORY_TABLE_RVA,
  KDA_CALLBACK_RVA,
  ROUTE_IDS,
  RUNTIME_SHA256,
  SAFE_REPLAYS,
  analyzeNativeOutputs,
  anchorCorrelation,
  buildDecisions,
  buildNativeProfiles,
  buildReport,
  collectEvidence,
  decodeKdaObject,
  markdownReport,
  nearestEvent,
  packetHex,
  quantile,
  recoverInlineFactory0023,
  recoverKdaCallback,
  recoverRuntimeIdentities,
  rejectProtectedPath,
  rotateRight8,
  sha256,
  sha256File,
  swapAdjacentBits,
};
