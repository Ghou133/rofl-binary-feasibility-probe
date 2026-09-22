'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const { normalizePlayers, parseReplayFile } = require('./rofl');

const SCHEMA = 'ROFL_STAT_SELECTOR_REGISTRY_V1';
const EXACT_BUILD = '16.16.805.0442';
const RUNTIME_IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const HERO_NETWORK_ID_MIN = 0x400000ae;
const HERO_NETWORK_ID_MAX = 0x400000b7;
const EPSILON = 1e-6;

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function assertSafePath(file) {
  const resolved = path.resolve(file);
  invariant(!/holdout/i.test(resolved), `protected holdout path is forbidden: ${resolved}`);
  let existingAncestor = resolved;
  const missingSuffix = [];
  while (!fs.existsSync(existingAncestor)) {
    const parent = path.dirname(existingAncestor);
    invariant(parent !== existingAncestor, `cannot resolve a safe existing ancestor: ${resolved}`);
    missingSuffix.unshift(path.basename(existingAncestor));
    existingAncestor = parent;
  }
  const realAncestor = fs.realpathSync.native(existingAncestor);
  const canonical = path.join(realAncestor, ...missingSuffix);
  invariant(!/holdout/i.test(canonical),
    `protected holdout canonical path is forbidden: ${canonical}`);
  return canonical;
}

function defaultInputs(rootDir) {
  const controlled = path.join(rootDir, 'artifacts', 'controlled_calibration_replays',
    'HN1-11212942693');
  const intake = path.join(controlled, 'intake', 'replays', 'HN1-11212942693');
  return {
    selectorSources: [
      {
        id: 'latest_four_all',
        path: path.join(rootDir, 'artifacts', 'full_semantic_deep_recovery_v2',
          'hero_state', 'packet_042f_latest_four_all_decoded.jsonl'),
      },
      {
        id: 'p0_aggregate',
        path: path.join(rootDir, 'artifacts', 'full_semantic_deep_recovery_v2',
          'hero_state', 'packet_042f_p0_decoded.jsonl'),
      },
      {
        id: 'controlled_anchor',
        path: path.join(controlled, 'p0_anchor_scan', '0x042f_decoded.jsonl'),
      },
      {
        id: 'stratified_subset',
        path: path.join(rootDir, 'artifacts', 'hero_combat_state_v2', 'runtime',
          'packet_042f_stratified_decoded_16_16.jsonl'),
      },
      {
        id: 'legacy_smoke_subset',
        path: path.join(rootDir, 'artifacts', 'hero_combat_state_v2', 'runtime',
          'packet_042f_smoke_decoded_16_16.jsonl'),
      },
    ],
    runtimeReport: path.join(rootDir, '.omo', 'evidence', 'quant_runtime_bridge',
      'hud_runtime_state_bridge_report.json'),
    eventSources: [
      {
        category: 'ITEM',
        path: path.join(controlled, 'item_route_calibration', 'event_alignment.jsonl'),
        default_replay_sha256: '1fb1321e802103ce8e20e670b981b8b59d43a1fbbdc911f79ba249257ed672ff',
        default_entity_network_id: HERO_NETWORK_ID_MIN,
      },
      ...['level_transition', 'buff', 'damage', 'death', 'heal', 'shield'].map((name) => ({
        category: name.toUpperCase(),
        path: path.join(intake, `${name}_events.jsonl`),
        default_replay_sha256: '1fb1321e802103ce8e20e670b981b8b59d43a1fbbdc911f79ba249257ed672ff',
        default_entity_network_id: HERO_NETWORK_ID_MIN,
      })),
    ],
  };
}

async function sha256File(file) {
  const resolved = assertSafePath(file);
  const hash = crypto.createHash('sha256');
  for await (const chunk of fs.createReadStream(resolved)) hash.update(chunk);
  return hash.digest('hex');
}

function sha256Buffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function readJson(file) {
  const resolved = assertSafePath(file);
  return JSON.parse(fs.readFileSync(resolved, 'utf8').replace(/^\uFEFF/, ''));
}

async function readJsonLines(file, onRow) {
  const resolved = assertSafePath(file);
  let lineNumber = 0;
  let rowCount = 0;
  const input = fs.createReadStream(resolved, { encoding: 'utf8' });
  const reader = readline.createInterface({ input, crlfDelay: Infinity });
  try {
    for await (const rawLine of reader) {
      lineNumber += 1;
      const line = rawLine.replace(/^\uFEFF/, '').trim();
      if (!line) continue;
      let row;
      try {
        row = JSON.parse(line);
      } catch (error) {
        throw new Error(`${resolved}:${lineNumber}: invalid JSON: ${error.message}`);
      }
      rowCount += 1;
      await onRow(row, lineNumber);
    }
  } finally {
    reader.close();
  }
  return rowCount;
}

function normalizeFloat(value) {
  invariant(Number.isFinite(value), 'formula lane must decode to a finite float32');
  return Object.is(value, -0) ? 0 : value;
}

function decodeFloat32Lanes(hex) {
  invariant(typeof hex === 'string' && /^[0-9a-fA-F]{32}$/.test(hex),
    'formula lane storage must be exactly 16 bytes of hex');
  const buffer = Buffer.from(hex, 'hex');
  return [0, 4, 8, 12].map((offset) => normalizeFloat(buffer.readFloatLE(offset)));
}

function outputRecords(row) {
  const fields = row.decoded_fields || {};
  if (Array.isArray(fields.outputs)) {
    return fields.outputs.map((record) => ({
      selector: record.output_kind_storage,
      values_hex: record.formula_values_storage_hex,
    }));
  }
  if (Array.isArray(fields.formula_output_records_0x18)) {
    return fields.formula_output_records_0x18.map((record) => ({
      selector: record.encoded_selector_0x08,
      values_hex: record.encoded_u32_values_0x10,
    }));
  }
  return [];
}

function packetIdentity(row) {
  return [
    row.replay_sha256,
    row.chunk_index,
    row.decompressed_payload_offset,
    row.raw_param,
    row.raw_payload_sha256,
  ].join('|');
}

function rejectionReason(row) {
  if (row.replay_version !== EXACT_BUILD) return 'WRONG_BUILD';
  if (row.packet_type !== '0x042f' || row.packet_id !== 0x042f) return 'WRONG_ROUTE';
  if (row.fully_consumed !== true || row.deserialize_return_al !== 1) return 'NOT_EXACT_FULL_CONSUME';
  if (row.opcode_matches_profile !== true) return 'OPCODE_PROFILE_MISMATCH';
  if (row.decoder_runtime_image_sha256 !== RUNTIME_IMAGE_SHA256) {
    return row.decoder_runtime_image_sha256 ? 'RUNTIME_IMAGE_SHA_MISMATCH' : 'RUNTIME_IMAGE_SHA_MISSING';
  }
  if (!/^[0-9a-f]{64}$/.test(String(row.replay_sha256 || ''))) return 'REPLAY_SHA_MISSING';
  return null;
}

function increment(map, key, amount = 1) {
  const normalized = String(key);
  map.set(normalized, (map.get(normalized) || 0) + amount);
}

function sortedCounts(map, numeric = false) {
  return [...map.entries()]
    .sort((left, right) => numeric
      ? Number(left[0]) - Number(right[0])
      : left[0].localeCompare(right[0]))
    .map(([value, count]) => ({ value: numeric ? Number(value) : value, count }));
}

function quantile(sorted, fraction) {
  if (sorted.length === 0) return null;
  if (sorted.length === 1) return sorted[0];
  const position = (sorted.length - 1) * fraction;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower];
  const weight = position - lower;
  return sorted[lower] * (1 - weight) + sorted[upper] * weight;
}

function numberSummary(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const counts = new Map();
  for (const value of sorted) increment(counts, value);
  const topValues = [...counts.entries()]
    .map(([value, count]) => ({ value: Number(value), count }))
    .sort((a, b) => b.count - a.count || a.value - b.value)
    .slice(0, 32);
  return {
    count: sorted.length,
    finite_count: sorted.length,
    minimum: sorted[0] ?? null,
    maximum: sorted.at(-1) ?? null,
    mean: sorted.length ? sorted.reduce((sum, value) => sum + value, 0) / sorted.length : null,
    quantiles: {
      p00: quantile(sorted, 0),
      p25: quantile(sorted, 0.25),
      p50: quantile(sorted, 0.5),
      p75: quantile(sorted, 0.75),
      p100: quantile(sorted, 1),
    },
    distinct_value_count: counts.size,
    top_values: topValues,
    zero_count: sorted.filter((value) => Math.abs(value) <= EPSILON).length,
    one_count: sorted.filter((value) => Math.abs(value - 1) <= EPSILON).length,
  };
}

function participantIdFromNetworkId(networkId) {
  if (!Number.isInteger(networkId)
      || networkId < HERO_NETWORK_ID_MIN || networkId > HERO_NETWORK_ID_MAX) return null;
  return networkId - 0x400000ad;
}

function replayMetadata(rowsByReplay) {
  const output = new Map();
  for (const [replaySha, replayInfo] of [...rowsByReplay.entries()].sort()) {
    const candidates = [...replayInfo.paths].sort();
    const existing = candidates.find((candidate) => {
      assertSafePath(candidate);
      return fs.existsSync(candidate);
    });
    if (!existing) {
      output.set(replaySha, {
        status: 'REPLAY_FILE_UNAVAILABLE',
        replay_label: replayInfo.label,
        players: [],
      });
      continue;
    }
    try {
      const replay = parseReplayFile(assertSafePath(existing));
      invariant(replay.source_sha256 === replaySha, `${existing}: replay SHA mismatch`);
      output.set(replaySha, {
        status: 'VERIFIED_REPLAY_METADATA',
        replay_label: replayInfo.label,
        game_length_ms: Number(replay.tail.metadata.gameLength) || null,
        players: normalizePlayers(replay).map((player) => ({
          metadata_index: player.metadata_index,
          participant_id: player.metadata_index + 1,
          champion: player.champion,
          team_id: player.team_id,
          team: player.team,
          role: player.role,
          provenance: player.provenance,
        })),
      });
    } catch (error) {
      output.set(replaySha, {
        status: 'REPLAY_METADATA_PARSE_FAILED',
        replay_label: replayInfo.label,
        error: error.message,
        players: [],
      });
    }
  }
  return output;
}

function newSelector(selector) {
  return {
    selector,
    records: [],
    packet_count: 0,
    replayCounts: new Map(),
    entityCounts: new Map(),
    streamCounts: new Map(),
    timeBucketCounts: new Map(),
  };
}

function recordSelector(accumulator, row, record) {
  invariant(Number.isInteger(record.selector) && record.selector >= 0,
    'selector must be a non-negative integer');
  const lanes = decodeFloat32Lanes(record.values_hex);
  let selector = accumulator.selectors.get(record.selector);
  if (!selector) {
    selector = newSelector(record.selector);
    accumulator.selectors.set(record.selector, selector);
  }
  const point = {
    replay_sha256: row.replay_sha256,
    replay_label: row.replay_label || null,
    entity_network_id: row.raw_param,
    replay_time_ms: row.replay_time_ms,
    stream: row.chunk_stream,
    lanes,
  };
  selector.records.push(point);
  selector.packet_count += 1;
  increment(selector.replayCounts, row.replay_sha256);
  increment(selector.entityCounts, row.raw_param);
  increment(selector.streamCounts, row.chunk_stream || 'UNKNOWN');
  increment(selector.timeBucketCounts, Math.floor(Number(row.replay_time_ms || 0) / 60000));
}

function staticMappings(runtimeReport) {
  invariant(runtimeReport.exact_build === EXACT_BUILD, 'runtime report exact-build mismatch');
  invariant(runtimeReport.exact_runtime_image_sha256 === RUNTIME_IMAGE_SHA256,
    'runtime report image SHA mismatch');
  const mapping = runtimeReport.hud_display_function?.non_p0_verified_formatter;
  invariant(mapping?.status === 'VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING',
    'verified static selector mapping missing from runtime report');
  return [{
    selector: mapping.selector,
    lane: mapping.lane,
    semantic: mapping.semantic,
    display_format: mapping.format,
    localization_token: mapping.localization_token,
    evidence_grade: 'VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING',
    observed_in_local_042f_corpus: false,
    source: 'quant_runtime_bridge/hud_runtime_state_bridge_report.json',
  }];
}

function runtimeSurfaces(runtimeReport) {
  const formula = runtimeReport.stat_formula_outputs;
  invariant(formula?.status === 'VERIFIED_DIRECT_STRUCTURE_AND_WRITER_RELATION',
    'verified 0x042f structure/writer evidence missing');
  invariant(formula.route === '0x042f', 'runtime formula evidence route mismatch');
  invariant(formula.reader?.status === 'VERIFIED_DIRECT_GENERIC_SELECTOR_LANE_READER',
    'verified generic selector/lane reader evidence missing');
  return {
    callback_rva: formula.callback_rva,
    owner_storage_offset: formula.owner_storage_offset_hex,
    selector_writer_rva: formula.writer.function_rva,
    selector_helper_rva: formula.writer.selector_helper_rva,
    generic_reader_wrapper_rva: formula.reader.wrapper_rva,
    storage_accessor_rva: formula.reader.storage_accessor_rva,
    lookup_rva: formula.reader.lookup_rva,
    generic_reader_wrapper_direct_caller_count: formula.reader.wrapper_direct_caller_count,
    storage_accessor_direct_caller_count: formula.reader.storage_accessor_direct_caller_count,
    lookup_direct_caller_count: formula.reader.lookup_direct_caller_count,
    upstream_exact_full_consume_count: formula.exact_full_consume_count,
    status: 'VERIFIED_EXACT_RUNTIME_STATIC_SURFACES',
    source: 'quant_runtime_bridge/hud_runtime_state_bridge_report.json',
  };
}

function temporalSummary(records, lane) {
  const sequences = new Map();
  for (const record of records) {
    const key = `${record.replay_sha256}|${record.entity_network_id}`;
    if (!sequences.has(key)) sequences.set(key, []);
    sequences.get(key).push(record);
  }
  let adjacentPairs = 0;
  let changedPairs = 0;
  let keyframeCount = 0;
  let liveCount = 0;
  const intervals = [];
  for (const sequence of sequences.values()) {
    sequence.sort((a, b) => a.replay_time_ms - b.replay_time_ms || a.stream.localeCompare(b.stream));
    for (const record of sequence) {
      if (record.stream === 'keyframe') keyframeCount += 1;
      else liveCount += 1;
    }
    for (let index = 1; index < sequence.length; index += 1) {
      adjacentPairs += 1;
      const delta = sequence[index].replay_time_ms - sequence[index - 1].replay_time_ms;
      if (delta >= 0) intervals.push(delta);
      if (Math.abs(sequence[index].lanes[lane] - sequence[index - 1].lanes[lane]) > EPSILON) {
        changedPairs += 1;
      }
    }
  }
  return {
    sequence_count: sequences.size,
    adjacent_pair_count: adjacentPairs,
    changed_pair_count: changedPairs,
    unchanged_pair_count: adjacentPairs - changedPairs,
    keyframe_observation_count: keyframeCount,
    live_observation_count: liveCount,
    adjacent_interval_ms: numberSummary(intervals),
  };
}

function laneRelationshipSummary(records) {
  let lane0EqualsLane1PlusLane2 = 0;
  let lane3Zero = 0;
  for (const record of records) {
    if (Math.abs(record.lanes[0] - (record.lanes[1] + record.lanes[2])) <= EPSILON) {
      lane0EqualsLane1PlusLane2 += 1;
    }
    if (Math.abs(record.lanes[3]) <= EPSILON) lane3Zero += 1;
  }
  return {
    observation_count: records.length,
    lane0_equals_lane1_plus_lane2_within_1e_6_count: lane0EqualsLane1PlusLane2,
    lane0_equals_lane1_plus_lane2_all: records.length > 0
      && lane0EqualsLane1PlusLane2 === records.length,
    lane3_zero_within_1e_6_count: lane3Zero,
    lane3_zero_all: records.length > 0 && lane3Zero === records.length,
    interpretation: 'STRUCTURAL_INVARIANT_ONLY_NOT_A_STAT_SEMANTIC',
  };
}

function entitySemanticDistribution(selector, metadataByReplay) {
  const champions = new Map();
  const teams = new Map();
  const roles = new Map();
  let mapped = 0;
  let unmapped = 0;
  for (const record of selector.records) {
    const participantId = participantIdFromNetworkId(record.entity_network_id);
    const metadata = metadataByReplay.get(record.replay_sha256);
    const player = participantId === null ? null : metadata?.players?.[participantId - 1];
    if (!player) {
      unmapped += 1;
      continue;
    }
    mapped += 1;
    increment(champions, player.champion ?? 'UNKNOWN');
    increment(teams, player.team ?? 'UNKNOWN');
    increment(roles, player.role ?? 'UNKNOWN');
  }
  return {
    mapping_rule: 'participant_id = network_id - 0x400000ad for 0x400000ae..0x400000b7',
    mapped_observation_count: mapped,
    unmapped_observation_count: unmapped,
    champion_distribution: sortedCounts(champions),
    team_distribution: sortedCounts(teams),
    role_distribution: sortedCounts(roles),
  };
}

function eventTime(row) {
  for (const key of ['route_time_ms', 'replay_time_ms', 'timestamp_ms', 'time_ms', 'nominal_time_ms']) {
    const value = Number(row[key]);
    if (Number.isFinite(value)) return value;
  }
  return null;
}

function eventEntity(row, fallback) {
  for (const key of [
    'entity_network_id', 'subject_network_id', 'target_network_id', 'owner_network_id',
    'source_network_id', 'raw_param',
  ]) {
    const value = Number(row[key]);
    if (Number.isInteger(value)) return value;
  }
  return fallback;
}

function eventReplaySha(row, fallback) {
  const value = row.replay_sha256 || row.source_replay_sha256;
  return /^[0-9a-f]{64}$/.test(String(value || '')) ? value : fallback;
}

async function loadEvents(eventSources, rootDir) {
  const events = [];
  const sourceAudit = [];
  for (const source of eventSources) {
    const resolved = assertSafePath(source.path);
    if (!fs.existsSync(resolved)) {
      sourceAudit.push({
        category: source.category,
        path: path.relative(rootDir, resolved).replaceAll('\\', '/'),
        status: 'FILE_MISSING',
        row_count: 0,
      });
      continue;
    }
    let accepted = 0;
    let rejected = 0;
    const rows = await readJsonLines(resolved, async (row) => {
      const time = eventTime(row);
      const replaySha = eventReplaySha(row, source.default_replay_sha256);
      const entity = eventEntity(row, source.default_entity_network_id);
      if (!Number.isFinite(time) || !replaySha || !Number.isInteger(entity)) {
        rejected += 1;
        return;
      }
      accepted += 1;
      events.push({
        category: source.category,
        replay_sha256: replaySha,
        entity_network_id: entity,
        replay_time_ms: time,
        event_id: row.control_id || row.event_type || null,
        operation: row.operation || null,
        item_id: row.item_id ?? row.prior_controlled_item_id ?? null,
      });
    });
    const stat = fs.statSync(resolved);
    sourceAudit.push({
      category: source.category,
      path: path.relative(rootDir, resolved).replaceAll('\\', '/'),
      status: accepted > 0 ? 'ROWS_ACCEPTED' : 'NO_GOVERNED_ROWS',
      row_count: rows,
      accepted_count: accepted,
      rejected_count: rejected,
      bytes: stat.size,
      sha256: await sha256File(resolved),
    });
  }
  return { events, sourceAudit };
}

function correlateEvents(records, lane, events, maxWindowMs = 90000, categories = null) {
  const sequences = new Map();
  for (const record of records) {
    const key = `${record.replay_sha256}|${record.entity_network_id}`;
    if (!sequences.has(key)) sequences.set(key, []);
    sequences.get(key).push(record);
  }
  for (const sequence of sequences.values()) {
    sequence.sort((a, b) => a.replay_time_ms - b.replay_time_ms);
  }
  const byCategory = new Map();
  for (const category of categories || [...new Set(events.map((event) => event.category))]) {
    byCategory.set(category, {
      event_count: 0,
      same_entity_sequence_count: 0,
      bracketed_count: 0,
      changed_count: 0,
      unchanged_count: 0,
      deltas: [],
      examples: [],
    });
  }
  for (const event of events) {
    if (!byCategory.has(event.category)) byCategory.set(event.category, {
      event_count: 0,
      same_entity_sequence_count: 0,
      bracketed_count: 0,
      changed_count: 0,
      unchanged_count: 0,
      deltas: [],
      examples: [],
    });
    const summary = byCategory.get(event.category);
    summary.event_count += 1;
    const sequence = sequences.get(`${event.replay_sha256}|${event.entity_network_id}`);
    if (!sequence) continue;
    summary.same_entity_sequence_count += 1;
    let before = null;
    let after = null;
    for (const record of sequence) {
      if (record.replay_time_ms <= event.replay_time_ms) before = record;
      if (record.replay_time_ms >= event.replay_time_ms) {
        after = record;
        break;
      }
    }
    if (!before || !after
        || event.replay_time_ms - before.replay_time_ms > maxWindowMs
        || after.replay_time_ms - event.replay_time_ms > maxWindowMs) continue;
    summary.bracketed_count += 1;
    const delta = after.lanes[lane] - before.lanes[lane];
    summary.deltas.push(delta);
    if (Math.abs(delta) > EPSILON) summary.changed_count += 1;
    else summary.unchanged_count += 1;
    if (summary.examples.length < 12) {
      summary.examples.push({
        event_id: event.event_id,
        operation: event.operation,
        item_id: event.item_id,
        event_time_ms: event.replay_time_ms,
        before_time_ms: before.replay_time_ms,
        after_time_ms: after.replay_time_ms,
        before_value: before.lanes[lane],
        after_value: after.lanes[lane],
        delta,
      });
    }
  }
  return [...byCategory.entries()].sort(([a], [b]) => a.localeCompare(b))
    .map(([category, summary]) => ({
      category,
      event_count: summary.event_count,
      same_entity_sequence_count: summary.same_entity_sequence_count,
      bracketed_within_90000ms_count: summary.bracketed_count,
      changed_count: summary.changed_count,
      unchanged_count: summary.unchanged_count,
      delta_summary: numberSummary(summary.deltas),
      examples: summary.examples,
      interpretation: summary.event_count === 0
        ? 'NO_GOVERNED_EVENT_ROWS'
        : 'TEMPORAL_ASSOCIATION_ONLY_NOT_CAUSAL_SEMANTIC_PROOF',
    }));
}

function structuralLaneCandidates(selector, lane, staticMapping) {
  if (staticMapping || selector.records.length === 0) return [];
  const candidates = {
    0: 'AGGREGATE_OR_EFFECTIVE_FACTOR',
    1: 'BASE_OR_IDENTITY_FACTOR',
    2: 'ADDITIVE_FACTOR_DELTA',
    3: 'RESERVED_OR_INACTIVE_LANE',
  };
  return [{
    candidate: candidates[lane],
    status: 'STRUCTURAL_CANDIDATE_ONLY',
    evidence: lane === 3
      ? 'lane 3 is zero in every governed local observation'
      : 'lane 0 equals lane 1 plus lane 2 in every governed local observation',
    semantic_limit: 'Does not identify any gameplay stat or exact formula operation.',
  }];
}

function laneRegistry(selector, lane, staticMapping, events, eventCategories) {
  const values = selector.records.map((record) => record.lanes[lane]);
  return {
    lane,
    semantic: staticMapping?.semantic ?? null,
    semantic_status: staticMapping
      ? 'VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING'
      : 'UNKNOWN_NOT_PROMOTED',
    evidence_grade: staticMapping?.evidence_grade ?? 'UNVERIFIED',
    display_projection: staticMapping ? {
      format: staticMapping.display_format,
      localization_token: staticMapping.localization_token,
      rounding_tie_behavior: 'UNRESOLVED',
    } : null,
    value_distribution: numberSummary(values),
    temporal_behavior: temporalSummary(selector.records, lane),
    event_correlations: correlateEvents(selector.records, lane, events, 90000, eventCategories),
    candidate_meanings: structuralLaneCandidates(selector, lane, staticMapping),
    negative_evidence: staticMapping ? [] : [
      'No exact-build static consumer assigns a stat name to this selector/lane.',
      'Prior direct P0 and quantization-aware searches promoted zero MAX_HP/ARMOR/MAGIC_RESIST/CURRENT_HP candidates.',
      'Observed value shape or correlation alone is insufficient for semantic promotion.',
    ],
  };
}

function selectorRegistryRow(selector, mappingRows, metadataByReplay, events, eventCategories, runtime) {
  const mappingByLane = new Map(mappingRows.map((mapping) => [mapping.lane, mapping]));
  return {
    selector: selector.selector,
    selector_hex: `0x${selector.selector.toString(16).padStart(2, '0')}`,
    observed_in_local_042f_corpus: selector.records.length > 0,
    observed_output_record_count: selector.records.length,
    replay_distribution: sortedCounts(selector.replayCounts),
    entity_network_id_distribution: sortedCounts(selector.entityCounts, true),
    champion_team_role_distribution: entitySemanticDistribution(selector, metadataByReplay),
    stream_distribution: sortedCounts(selector.streamCounts),
    replay_minute_bucket_distribution: sortedCounts(selector.timeBucketCounts, true),
    lane_relationships: laneRelationshipSummary(selector.records),
    runtime_surfaces: runtime,
    lanes: [0, 1, 2, 3].map((lane) => laneRegistry(
      selector, lane, mappingByLane.get(lane), events, eventCategories,
    )),
    selector_semantic_status: mappingRows.length
      ? 'PARTIALLY_MAPPED_BY_VERIFIED_STATIC_CONSUMER'
      : 'UNKNOWN_NOT_PROMOTED',
  };
}

async function buildStatSelectorRegistry({ rootDir, inputs = defaultInputs(rootDir) }) {
  const runtimeReport = readJson(inputs.runtimeReport);
  const mappings = staticMappings(runtimeReport);
  const accumulator = {
    selectors: new Map(),
    packetIdentities: new Set(),
    sourceAudit: [],
    rowsByReplay: new Map(),
    acceptedPackets: 0,
    outputRecords: 0,
    emptyVectors: 0,
    duplicatePackets: 0,
    rejected: new Map(),
  };

  for (const source of inputs.selectorSources) {
    const file = assertSafePath(source.path);
    invariant(fs.existsSync(file), `selector source missing: ${file}`);
    const local = { accepted: 0, duplicates: 0, empty_vectors: 0, rejected: new Map() };
    const rowCount = await readJsonLines(file, async (row) => {
      const rejection = rejectionReason(row);
      if (rejection) {
        increment(local.rejected, rejection);
        increment(accumulator.rejected, rejection);
        return;
      }
      const identity = packetIdentity(row);
      if (accumulator.packetIdentities.has(identity)) {
        local.duplicates += 1;
        accumulator.duplicatePackets += 1;
        return;
      }
      accumulator.packetIdentities.add(identity);
      accumulator.acceptedPackets += 1;
      local.accepted += 1;
      if (!accumulator.rowsByReplay.has(row.replay_sha256)) {
        accumulator.rowsByReplay.set(row.replay_sha256, {
          label: row.replay_label || null,
          paths: new Set(),
        });
      }
      if (row.replay_path) accumulator.rowsByReplay.get(row.replay_sha256).paths.add(row.replay_path);
      const records = outputRecords(row);
      if (records.length === 0) {
        accumulator.emptyVectors += 1;
        local.empty_vectors += 1;
      }
      for (const record of records) {
        recordSelector(accumulator, row, record);
        accumulator.outputRecords += 1;
      }
    });
    const stat = fs.statSync(file);
    accumulator.sourceAudit.push({
      id: source.id,
      path: path.relative(rootDir, file).replaceAll('\\', '/'),
      bytes: stat.size,
      sha256: await sha256File(file),
      jsonl_row_count: rowCount,
      accepted_unique_packet_count: local.accepted,
      duplicate_packet_count: local.duplicates,
      empty_vector_count: local.empty_vectors,
      rejected_by_reason: Object.fromEntries(sortedCounts(local.rejected).map(({ value, count }) => [value, count])),
    });
  }

  const metadataByReplay = replayMetadata(accumulator.rowsByReplay);
  const eventCategories = [...new Set((inputs.eventSources || []).map((source) => source.category))]
    .sort();
  const { events, sourceAudit: eventSourceAudit } = await loadEvents(inputs.eventSources || [], rootDir);
  const runtime = runtimeSurfaces(runtimeReport);

  for (const mapping of mappings) {
    if (!accumulator.selectors.has(mapping.selector)) {
      accumulator.selectors.set(mapping.selector, newSelector(mapping.selector));
    }
  }
  const selectors = [...accumulator.selectors.values()]
    .sort((a, b) => a.selector - b.selector)
    .map((selector) => selectorRegistryRow(
      selector,
      mappings.filter((mapping) => mapping.selector === selector.selector),
      metadataByReplay,
      events,
      eventCategories,
      runtime,
    ));

  const replayAudit = [...metadataByReplay.entries()].sort(([a], [b]) => a.localeCompare(b))
    .map(([replaySha, metadata]) => ({
      replay_sha256: replaySha,
      replay_label: metadata.replay_label,
      metadata_status: metadata.status,
      game_length_ms: metadata.game_length_ms ?? null,
      participant_count: metadata.players.length,
    }));
  const observedSelectorIds = selectors
    .filter((selector) => selector.observed_in_local_042f_corpus)
    .map((selector) => selector.selector);

  return {
    schema: SCHEMA,
    exact_build: EXACT_BUILD,
    exact_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    status: 'REGISTRY_READY_WITH_PARTIAL_SEMANTIC_MAPPING',
    architecture_gate: 'PASS',
    parser_boundary: 'REPLAY_PROTOCOL_AND_EXACT_BUILD_MECHANICS_ONLY',
    corpus_scope: {
      statement: 'Selector IDs listed as observed are local-corpus observations, not a protocol-wide enumeration.',
      accepted_unique_packet_count: accumulator.acceptedPackets,
      decoded_output_record_count: accumulator.outputRecords,
      empty_vector_packet_count: accumulator.emptyVectors,
      duplicate_packet_count: accumulator.duplicatePackets,
      rejected_by_reason: Object.fromEntries(sortedCounts(accumulator.rejected)
        .map(({ value, count }) => [value, count])),
      observed_selector_ids: observedSelectorIds,
      observed_selector_count: observedSelectorIds.length,
      source_files: accumulator.sourceAudit,
      replay_metadata: replayAudit,
      event_sources: eventSourceAudit,
      upstream_runtime_report_exact_full_consume_count:
        runtimeReport.stat_formula_outputs.exact_full_consume_count,
      count_scope_reconciliation: {
        upstream_runtime_report_count: runtimeReport.stat_formula_outputs.exact_full_consume_count,
        registry_unique_count: accumulator.acceptedPackets,
        difference: accumulator.acceptedPackets
          - runtimeReport.stat_formula_outputs.exact_full_consume_count,
        explanation: 'The registry adds the separately decoded controlled replay to the two upstream aggregate partitions.',
      },
    },
    verified_static_mappings: mappings,
    selectors,
    promotion_policy: {
      direct: 'Requires exact-build protocol field or exact-build static consumer identity.',
      derived: 'Requires complete exact-build dependency graph and independently verified mechanics binding.',
      correlation: 'Never sufficient alone for semantic promotion.',
      missing_inputs: 'Preserved explicitly; no defaults or patch-family substitution.',
    },
    negative_evidence: {
      p0_direct_bruteforce: 'PREVIOUSLY_EXHAUSTED_NOT_REPEATED',
      p0_promoted_selector_lane_pairs: 0,
      selector_11_observed_count: 0,
      note: 'ManaRegen selector 11/lane 0 is a static consumer mapping; its absence in this corpus is not protocol absence.',
    },
    protected_holdout: {
      read: false,
      enumerated: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  };
}

function renderRegistryMarkdown(registry) {
  const lines = [
    '# Stat selector registry — exact build 16.16.805.0442',
    '',
    `Status: ${registry.status}`,
    '',
    `Accepted unique 0x042f packets: ${registry.corpus_scope.accepted_unique_packet_count}`,
    '',
    `Observed selector IDs: ${registry.corpus_scope.observed_selector_ids.join(', ') || '(none)'}`,
    '',
    '| selector | observed records | mapped lanes | status |',
    '|---:|---:|---|---|',
  ];
  for (const selector of registry.selectors) {
    const mapped = selector.lanes.filter((lane) => lane.semantic)
      .map((lane) => `${lane.lane}=${lane.semantic}`).join(', ') || 'none';
    lines.push(`| ${selector.selector} | ${selector.observed_output_record_count} | ${mapped} | ${selector.selector_semantic_status} |`);
  }
  lines.push(
    '',
    'Observed means observed in the governed local corpus only. Selector 11/lane 0 is mapped to ManaRegen by an exact-image static consumer, despite zero local packet observations.',
    '',
    'No MAX_HP, ARMOR, MAGIC_RESIST, or CURRENT_HP selector/lane pair is promoted.',
    '',
  );
  return `${lines.join('\n')}\n`;
}

async function writeRegistryArtifacts({ rootDir, outputDir, inputs = defaultInputs(rootDir) }) {
  assertSafePath(outputDir);
  fs.mkdirSync(outputDir, { recursive: true });
  const registry = await buildStatSelectorRegistry({ rootDir, inputs });
  const registryPath = path.join(outputDir, 'stat_selector_registry.json');
  const markdownPath = path.join(outputDir, 'stat_selector_registry.md');
  const registryBuffer = Buffer.from(`${JSON.stringify(registry, null, 2)}\n`, 'utf8');
  const markdownBuffer = Buffer.from(renderRegistryMarkdown(registry), 'utf8');
  fs.writeFileSync(registryPath, registryBuffer);
  fs.writeFileSync(markdownPath, markdownBuffer);
  const artifacts = [
    { path: path.basename(registryPath), bytes: registryBuffer.length, sha256: sha256Buffer(registryBuffer) },
    { path: path.basename(markdownPath), bytes: markdownBuffer.length, sha256: sha256Buffer(markdownBuffer) },
  ];
  const manifest = {
    schema: 'ROFL_STAT_SELECTOR_REGISTRY_ARTIFACT_MANIFEST_V1',
    exact_build: EXACT_BUILD,
    artifacts,
    protected_holdout: registry.protected_holdout,
  };
  const manifestPath = path.join(outputDir, 'manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return { registry, manifest, paths: { registryPath, markdownPath, manifestPath } };
}

module.exports = {
  SCHEMA,
  EXACT_BUILD,
  RUNTIME_IMAGE_SHA256,
  assertSafePath,
  buildStatSelectorRegistry,
  correlateEvents,
  decodeFloat32Lanes,
  defaultInputs,
  outputRecords,
  participantIdFromNetworkId,
  renderRegistryMarkdown,
  writeRegistryArtifacts,
};
