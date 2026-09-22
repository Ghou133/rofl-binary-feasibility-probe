#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const { parseReplayFile, walkBlocks } = require('../src/rofl');

const EXACT_BUILD = '16.16.805.0442';
const ROUTES = Object.freeze([0x0105, 0x029d, 0x03aa, 0x0404]);
const ROUTE_SET = new Set(ROUTES);
const SAFE_REPLAYS = Object.freeze({
  'HN1-11196935467.rofl': 'd3f3b019b70bcf8650934e8e6350d6ae1e3def28b52fb8225cade755a415f862',
  'HN1-11200496018.rofl': '2e6cee94aed783fa62606333fac7e21295b80f5c03fa5617cd38f6f75fdfe47d',
  'HN1-11201899481.rofl': '18ae8e43f54604b288a93aa35d13722a159e5ffea548adfa9e88bbf0518e5d9f',
  'HN1-11209393761.rofl': '9dac6a352dc5a0af8bdd5c3ab0c16cddf310ca56817ce252fcb363a82d0b7f96',
});
const CONTEXT_ROUTES = Object.freeze({
  DAMAGE_017F: 0x017f,
  HERO_PATH_00F6: 0x00f6,
  BUFF_UPDATE_COUNT_0123: 0x0123,
  CAST_01CF: 0x01cf,
  PERIODIC_CLUSTER_0199: 0x0199,
  VARIABLE_BATCH_004A: 0x004a,
  AUXILIARY_BATCH_02D4: 0x02d4,
  UNKNOWN_01C2: 0x01c2,
  UNKNOWN_0473: 0x0473,
  ROUTE_0105: 0x0105,
  ROUTE_029D: 0x029d,
  ROUTE_03AA: 0x03aa,
  ROUTE_0404: 0x0404,
});
const CONTEXT_BITS = new Map(Object.values(CONTEXT_ROUTES).map((packetId, index) => [packetId, 1 << index]));

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function packetHex(packetId) {
  return '0x' + packetId.toString(16).padStart(4, '0');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function rejectForbiddenPath(value) {
  const resolved = path.resolve(value);
  if (resolved.toLowerCase().includes('holdout')) {
    throw new Error('protected corpus path is forbidden: ' + resolved);
  }
  return resolved;
}

function requireValue(argv, index, option) {
  if (index >= argv.length || argv[index].startsWith('--')) throw new Error(option + ' requires a value');
  return argv[index];
}

function parseArgs(argv) {
  const options = {
    build: EXACT_BUILD,
    replayFiles: [],
    registryPath: 'artifacts/full_semantic_baseline_v1/observed_route_registry.json',
    miningPath: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/high_frequency_unknown_deep_mining.json',
    profilerPath: 'artifacts/hero_combat_state_v2/profiler/high_frequency_raw_profiles_latest_four_v1_2.json',
    damagePath: 'artifacts/hero_combat_state_v2/emulation/packet_017f_latest_four_decoded.jsonl',
    outputPath: 'artifacts/full_semantic_deep_recovery_v2/remaining_highfreq/remaining_highfreq_raw_audit.json',
    corpusPath: 'artifacts/full_semantic_deep_recovery_v2/remaining_highfreq/remaining_highfreq_runtime_corpus.jsonl',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--build') options.build = requireValue(argv, ++index, option);
    else if (option === '--replay') options.replayFiles.push(rejectForbiddenPath(requireValue(argv, ++index, option)));
    else if (option === '--registry') options.registryPath = rejectForbiddenPath(requireValue(argv, ++index, option));
    else if (option === '--mining') options.miningPath = rejectForbiddenPath(requireValue(argv, ++index, option));
    else if (option === '--profiler') options.profilerPath = rejectForbiddenPath(requireValue(argv, ++index, option));
    else if (option === '--damage') options.damagePath = rejectForbiddenPath(requireValue(argv, ++index, option));
    else if (option === '--output') options.outputPath = rejectForbiddenPath(requireValue(argv, ++index, option));
    else if (option === '--corpus') options.corpusPath = rejectForbiddenPath(requireValue(argv, ++index, option));
    else throw new Error('unknown option: ' + option);
  }
  invariant(options.build === EXACT_BUILD, 'exact build ' + EXACT_BUILD + ' is required');
  invariant(options.replayFiles.length === 4, 'exactly four explicit safe --replay inputs are required');
  return options;
}

function increment(map, key, amount = 1) {
  map.set(key, (map.get(key) || 0) + amount);
}

function rows(map, keyName, limit = null) {
  const result = [...map.entries()]
    .map(([key, count]) => ({ [keyName]: key, count }))
    .sort((left, right) => right.count - left.count || String(left[keyName]).localeCompare(String(right[keyName])));
  return limit === null ? result : result.slice(0, limit);
}

function round(value, digits = 8) {
  if (!Number.isFinite(value)) return null;
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function quantile(values, fraction) {
  if (!values.length) return null;
  const sorted = [...values].sort((left, right) => left - right);
  const position = (sorted.length - 1) * fraction;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (position - lower);
}

function broadNetworkEntity(value) {
  return value >= 0x40000000 && value <= 0x4fffffff;
}

function canonicalHero(value) {
  return value >= 0x400000ae && value <= 0x400000b7;
}

function participantLowByte(value) {
  const participant = (value & 0xff) - 0xad;
  return participant >= 1 && participant <= 10;
}

function newRouteState(packetId) {
  return {
    packetId,
    events: [],
    lengthCounts: new Map(),
    rawCounts: new Map(),
    firstByteCounts: new Map(),
    prefix4Counts: new Map(),
    suffix4Counts: new Map(),
    payloadHashCounts: new Map(),
    payloadRawCounts: new Map(),
    representativeKeys: new Set(),
    corpusRows: new Map(),
    previousCounts: new Map(),
    previousSameCounts: new Map(),
    nextCounts: new Map(),
    nextSameCounts: new Map(),
    witnesses: [],
  };
}

function selectForCorpus(state, replayLabel, payload, payloadHash, event) {
  const allDistinct = state.packetId === 0x03aa || state.packetId === 0x0404;
  const representativeKey = replayLabel + ':' + payload.length;
  if (!allDistinct && state.representativeKeys.has(representativeKey)) return;
  if (!allDistinct) state.representativeKeys.add(representativeKey);
  if (!state.corpusRows.has(payloadHash)) {
    state.corpusRows.set(payloadHash, {
      schema_version: 1,
      exact_build: EXACT_BUILD,
      packet_id: state.packetId,
      packet_discriminator: packetHex(state.packetId),
      payload_sha256: payloadHash,
      payload_length: payload.length,
      selection_policy: allDistinct
        ? 'ALL_DISTINCT_PAYLOADS_WITH_EXACT_OCCURRENCE_WEIGHT'
        : 'FIRST_PAYLOAD_PER_REPLAY_AND_PAYLOAD_LENGTH',
      replay_label: replayLabel,
      replay_time_ms: event.time,
      raw_param: event.raw,
      raw_payload_hex: payload.toString('hex'),
    });
  }
}

function extractReplay(replayPath, states) {
  const replay = parseReplayFile(replayPath);
  const replayLabel = path.basename(replay.source_path, path.extname(replay.source_path));
  const basename = path.basename(replay.source_path);
  invariant(Object.hasOwn(SAFE_REPLAYS, basename), 'replay is outside the explicit latest-four allowlist: ' + basename);
  invariant(replay.source_sha256 === SAFE_REPLAYS[basename], 'safe replay SHA-256 mismatch: ' + basename);
  invariant(replay.header.version === EXACT_BUILD, 'safe replay exact-build mismatch: ' + basename);

  let previous = null;
  let pending = null;
  let occurrenceIndex = 0;
  const firstWalk = walkBlocks(replay, (block) => {
    if (pending) {
      increment(pending.state.nextCounts, packetHex(block.packet_id));
      increment(pending.state.nextSameCounts,
        block.timestamp_ms === pending.time ? packetHex(block.packet_id) : 'DIFFERENT_TIMESTAMP');
      pending = null;
    }
    if (ROUTE_SET.has(block.packet_id)) {
      const state = states.get(block.packet_id);
      const payloadHash = sha256(block.payload);
      const event = {
        replay: replayLabel,
        time: block.timestamp_ms,
        raw: block.param >>> 0,
        length: block.payload_length,
        payloadHash,
        occurrence: occurrenceIndex,
      };
      state.events.push(event);
      increment(state.lengthCounts, block.payload_length);
      increment(state.rawCounts, event.raw);
      increment(state.firstByteCounts, block.payload.length ? block.payload[0] : -1);
      increment(state.prefix4Counts, block.payload.subarray(0, 4).toString('hex'));
      increment(state.suffix4Counts, block.payload.subarray(Math.max(0, block.payload.length - 4)).toString('hex'));
      increment(state.payloadHashCounts, payloadHash);
      if (state.packetId === 0x03aa || state.packetId === 0x0404) {
        if (!state.payloadRawCounts.has(payloadHash)) state.payloadRawCounts.set(payloadHash, new Map());
        increment(state.payloadRawCounts.get(payloadHash), event.raw);
      }
      increment(state.previousCounts, previous ? packetHex(previous.packetId) : 'START');
      increment(state.previousSameCounts,
        previous && previous.time === block.timestamp_ms ? packetHex(previous.packetId) : 'DIFFERENT_TIMESTAMP');
      if (state.witnesses.length < 16) {
        state.witnesses.push({
          replay_label: replayLabel,
          replay_time_ms: block.timestamp_ms,
          occurrence_index: occurrenceIndex,
          raw_param: event.raw,
          payload_length: block.payload_length,
          raw_payload_hex: block.payload.toString('hex'),
        });
      }
      selectForCorpus(state, replayLabel, block.payload, payloadHash, event);
      pending = { state, time: block.timestamp_ms };
    }
    previous = { packetId: block.packet_id, time: block.timestamp_ms };
    occurrenceIndex += 1;
  }, { includeStreams: [1, 2, 3], strict: true });
  invariant(firstWalk.errors.length === 0, 'strict first packet walk failed for ' + basename);
  if (pending) {
    increment(pending.state.nextCounts, 'END');
    increment(pending.state.nextSameCounts, 'DIFFERENT_TIMESTAMP');
  }

  const targetTimes = new Set();
  for (const state of states.values()) {
    for (const event of state.events) {
      if (event.replay === replayLabel) targetTimes.add(event.time);
    }
  }
  const contextByTime = new Map([...targetTimes].map((time) => [time, 0]));
  const secondWalk = walkBlocks(replay, (block) => {
    if (!contextByTime.has(block.timestamp_ms)) return;
    const bit = CONTEXT_BITS.get(block.packet_id);
    if (bit) contextByTime.set(block.timestamp_ms, contextByTime.get(block.timestamp_ms) | bit);
  }, { includeStreams: [1, 2, 3], strict: true });
  invariant(secondWalk.errors.length === 0, 'strict context packet walk failed for ' + basename);
  return {
    replay_path: replay.source_path,
    replay_label: replayLabel,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header.version,
    selected_packet_count: [...states.values()].reduce((sum, state) =>
      sum + state.events.filter((event) => event.replay === replayLabel).length, 0),
    contextByTime,
  };
}

async function loadDamageAnchors(filePath) {
  const source = fs.createReadStream(filePath);
  const digest = crypto.createHash('sha256');
  source.on('data', (chunk) => digest.update(chunk));
  const anchors = new Map();
  let count = 0;
  const lines = readline.createInterface({ input: source, crlfDelay: Infinity });
  for await (const line of lines) {
    if (!line.trim()) continue;
    const row = JSON.parse(line);
    invariant(row.replay_version === EXACT_BUILD, 'damage anchor exact-build mismatch');
    invariant(row.packet_id === 0x017f && row.fully_consumed === true, 'invalid verified damage anchor row');
    const list = anchors.get(row.replay_label) || [];
    list.push({
      time: Number(row.replay_time_ms),
      source: Number(row.decoded_fields.field_10_u32) >>> 0,
      target: Number(row.decoded_fields.field_14_u32) >>> 0,
    });
    anchors.set(row.replay_label, list);
    count += 1;
  }
  for (const list of anchors.values()) list.sort((left, right) => left.time - right.time);
  return { anchors, count, sha256: digest.digest('hex') };
}

function nearestAnchor(anchors, time) {
  if (!anchors || !anchors.length) return null;
  let low = 0;
  let high = anchors.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (anchors[middle].time < time) low = middle + 1;
    else high = middle;
  }
  const candidates = [];
  if (low < anchors.length) candidates.push(anchors[low]);
  if (low > 0) candidates.push(anchors[low - 1]);
  return candidates.sort((left, right) =>
    Math.abs(left.time - time) - Math.abs(right.time - time) || left.time - right.time)[0];
}

function summarizeRoute(state, replayRecords, anchorsByReplay, expectedCount) {
  invariant(state.events.length === expectedCount,
    packetHex(state.packetId) + ' full count does not match the observed registry');
  const rawValues = state.events.map((event) => event.raw);
  const groupMap = new Map();
  const byReplay = new Map();
  for (const event of state.events) {
    const key = event.replay + ':' + event.time;
    if (!groupMap.has(key)) groupMap.set(key, []);
    groupMap.get(key).push(event);
    if (!byReplay.has(event.replay)) byReplay.set(event.replay, []);
    byReplay.get(event.replay).push(event);
  }
  const deltas = [];
  let sameTimestampTransitions = 0;
  let transitionCount = 0;
  for (const events of byReplay.values()) {
    events.sort((left, right) => left.time - right.time || left.occurrence - right.occurrence);
    for (let index = 1; index < events.length; index += 1) {
      const delta = events[index].time - events[index - 1].time;
      deltas.push(delta);
      transitionCount += 1;
      if (delta === 0) sameTimestampTransitions += 1;
    }
  }

  const contexts = [];
  for (const [label, contextPacketId] of Object.entries(CONTEXT_ROUTES)) {
    const bit = CONTEXT_BITS.get(contextPacketId);
    let groupCount = 0;
    let eventCount = 0;
    for (const [key, events] of groupMap.entries()) {
      const split = key.lastIndexOf(':');
      const replay = key.slice(0, split);
      const time = Number(key.slice(split + 1));
      const record = replayRecords.find((row) => row.replay_label === replay);
      if ((record.contextByTime.get(time) & bit) !== 0) {
        groupCount += 1;
        eventCount += events.length;
      }
    }
    contexts.push({
      label,
      packet_id: contextPacketId,
      packet_discriminator: packetHex(contextPacketId),
      same_timestamp_group_count: groupCount,
      same_timestamp_group_rate: round(groupCount / groupMap.size),
      selected_route_event_count_at_shared_timestamps: eventCount,
      selected_route_event_rate_at_shared_timestamps: round(eventCount / state.events.length),
    });
  }

  const damage = {
    available_count: 0,
    exact_time_count: 0,
    within_10ms_count: 0,
    within_500ms_count: 0,
    raw_source_count: 0,
    raw_target_count: 0,
    raw_either_within_10ms_count: 0,
    shifted_137ms_within_10ms_count: 0,
    shifted_997ms_within_10ms_count: 0,
    far_over_500ms_count: 0,
    cotimed_raw_mismatch_count: 0,
    deltas: [],
    far_counterexamples: [],
    cotimed_raw_mismatch_examples: [],
  };
  for (const event of state.events) {
    const anchors = anchorsByReplay.get(event.replay);
    const nearest = nearestAnchor(anchors, event.time);
    if (!nearest) continue;
    const delta = Math.abs(nearest.time - event.time);
    damage.available_count += 1;
    damage.deltas.push(delta);
    if (delta === 0) damage.exact_time_count += 1;
    if (delta <= 10) damage.within_10ms_count += 1;
    if (delta <= 500) damage.within_500ms_count += 1;
    if (event.raw === nearest.source) damage.raw_source_count += 1;
    if (event.raw === nearest.target) damage.raw_target_count += 1;
    if (delta <= 10 && (event.raw === nearest.source || event.raw === nearest.target)) {
      damage.raw_either_within_10ms_count += 1;
    }
    const shifted137 = nearestAnchor(anchors, event.time + 137);
    const shifted997 = nearestAnchor(anchors, event.time + 997);
    if (shifted137 && Math.abs(shifted137.time - (event.time + 137)) <= 10) {
      damage.shifted_137ms_within_10ms_count += 1;
    }
    if (shifted997 && Math.abs(shifted997.time - (event.time + 997)) <= 10) {
      damage.shifted_997ms_within_10ms_count += 1;
    }
    if (delta > 500 && damage.far_counterexamples.length < 16) {
      damage.far_counterexamples.push({
        replay_label: event.replay,
        replay_time_ms: event.time,
        raw_param: event.raw,
        nearest_damage_delta_ms: delta,
      });
    }
    if (delta > 500) damage.far_over_500ms_count += 1;
    if (delta === 0 && event.raw !== nearest.source && event.raw !== nearest.target
        && damage.cotimed_raw_mismatch_examples.length < 16) {
      damage.cotimed_raw_mismatch_examples.push({
        replay_label: event.replay,
        replay_time_ms: event.time,
        raw_param: event.raw,
        damage_source: nearest.source,
        damage_target: nearest.target,
      });
    }
    if (delta === 0 && event.raw !== nearest.source && event.raw !== nearest.target) {
      damage.cotimed_raw_mismatch_count += 1;
    }
  }

  for (const row of state.corpusRows.values()) {
    row.occurrence_count = state.payloadHashCounts.get(row.payload_sha256);
    const payloadRawCounts = state.payloadRawCounts.get(row.payload_sha256);
    if (payloadRawCounts) {
      row.raw_param_distinct_count = payloadRawCounts.size;
      row.raw_param_top_values = rows(payloadRawCounts, 'raw_param', 16);
    }
  }
  const groupSizes = [...groupMap.values()].map((events) => events.length);
  return {
    packet_id: state.packetId,
    packet_discriminator: packetHex(state.packetId),
    count: state.events.length,
    expected_count: expectedCount,
    count_match: state.events.length === expectedCount,
    per_replay_count: [...byReplay.entries()].map(([replay_label, events]) => ({
      replay_label,
      count: events.length,
      first_time_ms: Math.min(...events.map((event) => event.time)),
      last_time_ms: Math.max(...events.map((event) => event.time)),
    })),
    payload: {
      minimum_length: Math.min(...state.events.map((event) => event.length)),
      maximum_length: Math.max(...state.events.map((event) => event.length)),
      distinct_length_count: state.lengthCounts.size,
      length_distribution: rows(state.lengthCounts, 'payload_length'),
      distinct_payload_sha256_count: state.payloadHashCounts.size,
      first_byte_distribution: rows(state.firstByteCounts, 'first_byte', 32),
      prefix_4byte_distribution_top: rows(state.prefix4Counts, 'prefix_hex', 32),
      suffix_4byte_distribution_top: rows(state.suffix4Counts, 'suffix_hex', 32),
      runtime_corpus_row_count: state.corpusRows.size,
    },
    raw_param: {
      zero_count: rawValues.filter((value) => value === 0).length,
      zero_rate: round(rawValues.filter((value) => value === 0).length / rawValues.length),
      distinct_count: state.rawCounts.size,
      canonical_hero_count: rawValues.filter(canonicalHero).length,
      canonical_hero_rate: round(rawValues.filter(canonicalHero).length / rawValues.length),
      participant_low_byte_count: rawValues.filter(participantLowByte).length,
      participant_low_byte_rate: round(rawValues.filter(participantLowByte).length / rawValues.length),
      broad_network_entity_count: rawValues.filter(broadNetworkEntity).length,
      broad_network_entity_rate: round(rawValues.filter(broadNetworkEntity).length / rawValues.length),
      top_values: rows(state.rawCounts, 'raw_param', 24),
    },
    temporal: {
      timestamp_group_count: groupMap.size,
      group_size_min: Math.min(...groupSizes),
      group_size_p50: quantile(groupSizes, 0.5),
      group_size_p90: quantile(groupSizes, 0.9),
      group_size_p99: quantile(groupSizes, 0.99),
      group_size_max: Math.max(...groupSizes),
      delta_p50_ms: quantile(deltas, 0.5),
      delta_p90_ms: quantile(deltas, 0.9),
      delta_p99_ms: quantile(deltas, 0.99),
      same_timestamp_transition_rate: round(sameTimestampTransitions / Math.max(1, transitionCount)),
    },
    immediate_neighbors: {
      previous: rows(state.previousCounts, 'packet_discriminator', 24),
      next: rows(state.nextCounts, 'packet_discriminator', 24),
      previous_same_timestamp: rows(state.previousSameCounts, 'packet_discriminator', 24),
      next_same_timestamp: rows(state.nextSameCounts, 'packet_discriminator', 24),
    },
    timestamp_context: contexts,
    damage_neighborhood: {
      anchor_kind: 'VERIFIED_0x017F_DAMAGE_PACKET_TIME_AND_ENDPOINTS',
      candidate_count_with_anchor_replay: damage.available_count,
      exact_time_count: damage.exact_time_count,
      exact_time_rate: round(damage.exact_time_count / Math.max(1, damage.available_count)),
      within_10ms_count: damage.within_10ms_count,
      within_10ms_rate: round(damage.within_10ms_count / Math.max(1, damage.available_count)),
      within_500ms_count: damage.within_500ms_count,
      within_500ms_rate: round(damage.within_500ms_count / Math.max(1, damage.available_count)),
      far_over_500ms_count: damage.far_over_500ms_count,
      nearest_delta_p50_ms: quantile(damage.deltas, 0.5),
      nearest_delta_p90_ms: quantile(damage.deltas, 0.9),
      raw_param_matches_nearest_damage_source_rate: round(damage.raw_source_count / Math.max(1, damage.available_count)),
      raw_param_matches_nearest_damage_target_rate: round(damage.raw_target_count / Math.max(1, damage.available_count)),
      raw_param_matches_either_within_10ms_rate: round(damage.raw_either_within_10ms_count / Math.max(1, damage.available_count)),
      shifted_137ms_control_within_10ms_rate: round(damage.shifted_137ms_within_10ms_count / Math.max(1, damage.available_count)),
      shifted_997ms_control_within_10ms_rate: round(damage.shifted_997ms_within_10ms_count / Math.max(1, damage.available_count)),
      cotimed_raw_mismatch_count: damage.cotimed_raw_mismatch_count,
      far_counterexamples: damage.far_counterexamples,
      cotimed_raw_mismatch_examples: damage.cotimed_raw_mismatch_examples,
      semantic_claim: null,
    },
    positive_raw_witnesses: state.witnesses,
  };
}

function addCrossRouteRelationships(routeReports, states) {
  const byRouteTime = new Map();
  for (const packetId of ROUTES) {
    const map = new Map();
    for (const event of states.get(packetId).events) {
      const key = event.replay + ':' + event.time;
      if (!map.has(key)) map.set(key, new Set());
      map.get(key).add(event.raw);
    }
    byRouteTime.set(packetId, map);
  }
  for (const report of routeReports) {
    report.cross_route_relationships = ROUTES.filter((other) => other !== report.packet_id).map((other) => {
      const otherGroups = byRouteTime.get(other);
      let cotimed = 0;
      let rawMatch = 0;
      for (const event of states.get(report.packet_id).events) {
        const values = otherGroups.get(event.replay + ':' + event.time);
        if (!values) continue;
        cotimed += 1;
        if (values.has(event.raw)) rawMatch += 1;
      }
      return {
        other_packet_id: other,
        other_packet_discriminator: packetHex(other),
        same_timestamp_event_count: cotimed,
        same_timestamp_event_rate: round(cotimed / report.count),
        same_timestamp_raw_param_match_count: rawMatch,
        same_timestamp_raw_param_match_rate: round(rawMatch / report.count),
        zero_key_confounder: states.get(report.packet_id).rawCounts.has(0) && states.get(other).rawCounts.has(0),
      };
    });
  }
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const registryBytes = fs.readFileSync(options.registryPath);
  const miningBytes = fs.readFileSync(options.miningPath);
  const profilerBytes = fs.readFileSync(options.profilerPath);
  const registry = JSON.parse(registryBytes);
  const mining = JSON.parse(miningBytes);
  const profiler = JSON.parse(profilerBytes);
  invariant(registry.exact_build === EXACT_BUILD, 'observed route registry exact-build mismatch');

  const states = new Map(ROUTES.map((packetId) => [packetId, newRouteState(packetId)]));
  const replayRecords = options.replayFiles.map((replayPath) => extractReplay(replayPath, states));
  invariant(new Set(replayRecords.map((row) => row.replay_sha256)).size === 4,
    'latest-four replay inputs must be distinct');
  const damage = await loadDamageAnchors(options.damagePath);

  const expectedCounts = new Map(ROUTES.map((packetId) => {
    const route = registry.routes.find((row) => row.packet_id === packetId);
    invariant(route, 'registry route missing: ' + packetHex(packetId));
    return [packetId, route.observed.count];
  }));
  const routeReports = ROUTES.map((packetId) =>
    summarizeRoute(states.get(packetId), replayRecords, damage.anchors, expectedCounts.get(packetId)));
  addCrossRouteRelationships(routeReports, states);

  const corpusRows = ROUTES.flatMap((packetId) => [...states.get(packetId).corpusRows.values()])
    .sort((left, right) => left.packet_id - right.packet_id
      || left.payload_length - right.payload_length
      || left.payload_sha256.localeCompare(right.payload_sha256));
  fs.mkdirSync(path.dirname(options.corpusPath), { recursive: true });
  const corpusText = corpusRows.map((row) => JSON.stringify(row)).join('\n') + '\n';
  fs.writeFileSync(options.corpusPath, corpusText, 'utf8');

  const report = {
    schema: 'REMAINING_HIGH_FREQUENCY_RAW_AUDIT_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    scope: ROUTES.map(packetHex),
    promotion_authority: 'NONE',
    input: {
      safe_replays: replayRecords.map((record) => ({
        path: record.replay_path,
        replay_label: record.replay_label,
        replay_sha256: record.replay_sha256,
        replay_version: record.replay_version,
        selected_packet_count: record.selected_packet_count,
      })),
      observed_registry: { path: path.resolve(options.registryPath), sha256: sha256(registryBytes) },
      sampled_mining: { path: path.resolve(options.miningPath), sha256: sha256(miningBytes) },
      prior_field_profiler: { path: path.resolve(options.profilerPath), sha256: sha256(profilerBytes) },
      verified_damage_anchors: {
        path: path.resolve(options.damagePath),
        sha256: damage.sha256,
        row_count: damage.count,
      },
      runtime_corpus: {
        path: path.resolve(options.corpusPath),
        sha256: sha256(corpusText),
        row_count: corpusRows.length,
      },
    },
    prior_evidence_cross_check: {
      mining_routes: ROUTES.map((packetId) => {
        const row = mining.routes.find((candidate) => candidate.packet_id === packetId);
        return row ? {
          packet_id: packetId,
          sample_count: row.sample_count,
          prior_decision: row.research_decision,
          sampled_damage_neighborhood: row.damage_neighborhood,
        } : null;
      }),
      profiler_routes: ROUTES.map((packetId) => {
        const candidates = profiler.profiles || profiler.routes || profiler.results || [];
        const row = candidates.find((candidate) => candidate.packet_id === packetId);
        return row || { packet_id: packetId, note: 'profile retained by input hash; route entry shape not recognized' };
      }),
    },
    routes: routeReports,
    validations: {
      exact_build: replayRecords.every((row) => row.replay_version === EXACT_BUILD),
      replay_allowlist_complete: Object.keys(SAFE_REPLAYS).every((basename) =>
        replayRecords.some((row) => path.basename(row.replay_path) === basename)),
      replay_sha256_match: replayRecords.every((row) =>
        SAFE_REPLAYS[path.basename(row.replay_path)] === row.replay_sha256),
      route_inventory_counts_match: routeReports.every((route) => route.count_match),
      strict_packet_walks: true,
      all_pass: routeReports.every((route) => route.count_match),
    },
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  };
  fs.mkdirSync(path.dirname(options.outputPath), { recursive: true });
  const text = JSON.stringify(report, null, 2) + '\n';
  fs.writeFileSync(options.outputPath, text, 'utf8');
  const summary = {
    output: path.resolve(options.outputPath),
    output_sha256: sha256(text),
    corpus: path.resolve(options.corpusPath),
    corpus_sha256: sha256(corpusText),
    corpus_rows: corpusRows.length,
    route_counts: routeReports.map((route) => ({
      packet_discriminator: route.packet_discriminator,
      count: route.count,
      distinct_payloads: route.payload.distinct_payload_sha256_count,
    })),
    validations: report.validations,
  };
  process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
  return summary;
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write((error.stack || error.message) + '\n');
    process.exitCode = 1;
  });
}

module.exports = {
  EXACT_BUILD,
  ROUTES,
  SAFE_REPLAYS,
  nearestAnchor,
  parseArgs,
  quantile,
  rejectForbiddenPath,
};
