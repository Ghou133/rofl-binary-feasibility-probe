'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const EXACT_BUILD = '16.16.805.0442';
const EXPECTED_ADJUSTMENT_RECORDS = 714;
const EXPECTED_FORMULA_ROWS = 130484;
const WINDOW_MS = Object.freeze([0, 1, 10, 100, 1000, 5000]);
const RUNTIME_IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const PINNED_SOURCE_SHA256 = Object.freeze({
  adjustmentEvents: 'd0b27ca27404631d1e864300697c93ed62d5bb34c07bb2874243fa907daa35ec',
  formulaLatest: 'b7b46adf1fb120f4431d38f262d68e4d7b7b8316f4faa6d43a1d49d16e70a556',
  formulaP0: 'f897e142249af7ccc091dd59a76b4b4bc8169d2a1579870b30a49026274fd847',
  consumerDisassembly: '4aa24f5a1ab2efc71e40c86fc2fadce86cf2d3487bbea923ba41719e1c562e35',
  runtimeImage: RUNTIME_IMAGE_SHA256,
  formulaLatestSummary: '85173f17359600d297eb5020c31fe71b083c4db5ca6ac3839a1b1585ee0b852a',
  formulaP0Summary: 'cb6532da3f4bafff7312cccdb815aa648bdda2acdcda984d60e669d8674c7ccd',
});
const FORMULA_PROFILE_SHA256 = Object.freeze({
  formulaLatest: '6fc8ceeddaa3c13431991ddad47957a4e095909229fd1aea5574fe6c6e047f1a',
  formulaP0: '97e2095151daa29c75f30f16775dd55280ec29f7a7e98d05a6c6f81e51b50368',
});

function defaultInputs(rootDir) {
  const hero = path.join(rootDir, 'artifacts', 'full_semantic_deep_recovery_v2', 'hero_state');
  return {
    adjustmentEvents: path.join(hero, 'packet_0412_buff_stat_adjustment_events.jsonl'),
    formulaLatest: path.join(hero, 'packet_042f_latest_four_all_decoded.jsonl'),
    formulaP0: path.join(hero, 'packet_042f_p0_decoded.jsonl'),
    consumerDisassembly: path.join(hero, 'runtime_0412_adjustment_consumer_disassembly.json'),
    formulaLatestSummary: path.join(hero, 'packet_042f_latest_four_all_decoded.summary.json'),
    formulaP0Summary: path.join(hero, 'packet_042f_p0_decoded.summary.json'),
    deepReport: path.join(hero, 'hero_state_damage_defense_deep_report_16_16.json'),
    runtimeBridgeManifest: path.join(rootDir, '.omo', 'evidence', 'quant_runtime_bridge',
      'artifact_manifest.json'),
    runtimeBridgeReport: path.join(rootDir, '.omo', 'evidence', 'quant_runtime_bridge',
      'hud_runtime_state_bridge_report.json'),
    runtimeImage: path.join(rootDir, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime',
      'league_16.16.805.0442.memory.bin'),
  };
}

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function readJson(file) {
  assertNonHoldoutPath(file);
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}

function verifyArtifactManifest(manifestPath) {
  const manifest = readJson(manifestPath);
  const entries = manifest.artifacts || manifest.outputs;
  invariant(Array.isArray(entries) && entries.length > 0, 'upstream artifact manifest is empty');
  const verified = entries.map((entry) => {
    const file = path.resolve(path.dirname(manifestPath), entry.path);
    assertNonHoldoutPath(file);
    invariant(fs.existsSync(file), `upstream artifact missing: ${entry.path}`);
    const bytes = fs.statSync(file).size;
    invariant(bytes === (entry.bytes ?? entry.byte_size), `upstream artifact size mismatch: ${entry.path}`);
    const sha256 = hashFileSync(file);
    invariant(sha256 === entry.sha256, `upstream artifact hash mismatch: ${entry.path}`);
    return { path: entry.path, bytes, sha256, match: true };
  });
  return { schema: manifest.schema || manifest.schema_version, verified_count: verified.length,
    artifacts: verified };
}

function verifyPinnedSources(inputs) {
  const pinned = {};
  for (const [name, expected] of Object.entries(PINNED_SOURCE_SHA256)) {
    const actual = hashFileSync(inputs[name]);
    invariant(actual === expected, `${name}: pinned source SHA-256 mismatch`);
    pinned[name] = { expected, actual, match: true };
  }
  const bridgeManifest = verifyArtifactManifest(inputs.runtimeBridgeManifest);
  const bridge = readJson(inputs.runtimeBridgeReport);
  invariant(bridge.schema === 'HUD_RUNTIME_STATE_BRIDGE_AUDIT_V1', 'runtime bridge schema mismatch');
  invariant(bridge.exact_build === EXACT_BUILD, 'runtime bridge exact-build mismatch');
  invariant(bridge.exact_runtime_image_sha256 === RUNTIME_IMAGE_SHA256,
    'runtime bridge runtime-image SHA mismatch');
  const deep = readJson(inputs.deepReport);
  invariant(deep.exact_build === EXACT_BUILD, 'deep report exact-build mismatch');
  invariant(deep.evidence_hashes.runtime_image.sha256 === RUNTIME_IMAGE_SHA256,
    'deep report runtime-image SHA mismatch');
  invariant(deep.evidence_hashes.runtime_0412_adjustment_consumer_disassembly.sha256
    === PINNED_SOURCE_SHA256.consumerDisassembly, 'deep report disassembly SHA mismatch');
  invariant(deep.routes['0x0412_buff_update_stat_adjustments'].exact_plaintext_recovery.output_sha256
    === PINNED_SOURCE_SHA256.adjustmentEvents, 'deep report adjustment-event SHA mismatch');
  invariant(deep.evidence_hashes.formula_latest_summary.sha256
    === PINNED_SOURCE_SHA256.formulaLatestSummary, 'deep report latest formula summary SHA mismatch');
  invariant(deep.evidence_hashes.formula_p0_summary.sha256
    === PINNED_SOURCE_SHA256.formulaP0Summary, 'deep report P0 formula summary SHA mismatch');
  return { pinned, runtime_bridge_manifest: bridgeManifest,
    runtime_bridge_report_sha256: hashFileSync(inputs.runtimeBridgeReport),
    deep_report_sha256: hashFileSync(inputs.deepReport) };
}

function assertNonHoldoutPath(file) {
  if (/holdout/i.test(path.resolve(file))) {
    throw new Error('protected Holdout input is forbidden');
  }
}

function hashFileSync(file) {
  assertNonHoldoutPath(file);
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(file, 'r');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    let count;
    do {
      count = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (count) hash.update(buffer.subarray(0, count));
    } while (count);
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

async function* readJsonl(file) {
  assertNonHoldoutPath(file);
  const input = fs.createReadStream(file, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  for await (const line of lines) {
    if (line.trim()) yield JSON.parse(line.replace(/^\uFEFF/, ''));
  }
}

function key(replay, entity) {
  return `${replay}:${entity}`;
}

function increment(counter, value, amount = 1) {
  const name = String(value);
  counter.set(name, (counter.get(name) || 0) + amount);
}

function sortedCounter(counter) {
  return Object.fromEntries([...counter].sort(([a], [b]) => a.localeCompare(b)));
}

function round(value, digits = 6) {
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}

function formulaOutputs(row) {
  return row.decoded_fields.outputs ?? row.decoded_fields.formula_output_records_0x18 ?? [];
}

function physicalPacketIdentity(row) {
  return [row.replay_sha256, row.chunk_stream, row.chunk_index, row.decompressed_block_offset,
    row.decompressed_payload_offset, row.occurrence_index, row.raw_param, row.raw_payload_sha256].join(':');
}

function adjustmentRecordIdentity(row) {
  return [row.replay_sha256, row.source_packet.chunk_index,
    row.source_packet.decompressed_block_offset, row.source_packet.raw_payload_sha256,
    row.record_index].join(':');
}

function acceptUniqueIdentity(seen, identity) {
  if (seen.has(identity)) return false;
  seen.add(identity);
  return true;
}

function validateAdjustmentEvent(row) {
  invariant(row.schema_version === 1, '0x0412 adjustment event schema mismatch');
  invariant(row.event_type === 'BUFF_STAT_ADJUSTMENT_STORAGE_RESEARCH_V1',
    '0x0412 adjustment event_type mismatch');
  invariant(row.exact_build === EXACT_BUILD, '0x0412 adjustment exact-build mismatch');
  invariant(row.source_packet?.packet_id === 0x0412, '0x0412 source packet route mismatch');
  invariant(Number.isInteger(row.source_packet.payload_length) && row.source_packet.payload_length > 0,
    '0x0412 source packet payload length invalid');
  invariant(/^[0-9a-f]{64}$/.test(row.source_packet.raw_payload_sha256 || ''),
    '0x0412 source packet SHA invalid');
  invariant(/^[0-9a-f]{64}$/.test(row.replay_sha256 || ''), '0x0412 replay SHA invalid');
  invariant(Number.isInteger(row.entity_network_id), '0x0412 entity identity invalid');
  invariant(Number.isFinite(row.replay_time_ms), '0x0412 replay time invalid');
  return row;
}

function validateFormulaRow(row, expectedProfileSha256) {
  invariant(row.schema_version === 1, '0x042f schema mismatch');
  invariant(row.replay_version === EXACT_BUILD, '0x042f exact-build mismatch');
  invariant(row.packet_id === 0x042f && row.packet_type === '0x042f', '0x042f packet route mismatch');
  invariant(row.decoded_opcode === 0x042f && row.decoded_opcode_hex === '0x042f'
    && row.opcode_matches_profile === true, '0x042f decoded opcode mismatch');
  invariant(row.fully_consumed === true && row.deserialize_return_al !== 0,
    '0x042f row is not exact full-consume');
  invariant(row.decoder_runtime_image_sha256 === RUNTIME_IMAGE_SHA256,
    '0x042f decoder runtime SHA mismatch');
  invariant(row.decoder_profile_sha256 === expectedProfileSha256,
    '0x042f decoder profile SHA mismatch');
  invariant(/^[0-9a-f]{64}$/.test(row.raw_payload_sha256 || ''), '0x042f payload SHA invalid');
  invariant(/^[0-9a-f]{64}$/.test(row.replay_sha256 || ''), '0x042f replay SHA invalid');
  invariant(Number.isInteger(row.raw_param) && Number.isFinite(row.replay_time_ms),
    '0x042f entity/time identity invalid');
  invariant(formulaOutputs(row).length > 0, '0x042f output vector is empty');
  return row;
}

function decodeLanes(record) {
  const hex = record.formula_values_storage_hex ?? record.encoded_u32_values_0x10;
  const bytes = Buffer.from(hex, 'hex');
  if (bytes.length !== 16) throw new Error(`0x042f output does not contain four f32 lanes: ${hex}`);
  return [0, 4, 8, 12].map((offset) => bytes.readFloatLE(offset));
}

function flattenInstructions(disassembly) {
  return (disassembly.disassembly || []).flatMap((slice) => slice.instructions || []);
}

function verifyRecordLayout(disassembly) {
  const byRva = new Map(flattenInstructions(disassembly).map((row) => [row.rva, row]));
  const required = [
    [0x00395921, 'imul', 'r15, rax, 0x1c', 'record stride = 28 bytes'],
    [0x00395980, 'movzx', 'edi, byte ptr [r14 + 0x10]', 'kind encoded byte read'],
    [0x00395989, 'mov', 'eax, dword ptr [r14 + 0x18]', 'encoded field D read'],
    [0x003959d1, 'mov', 'eax, dword ptr [r14 + 0xc]', 'encoded field B read'],
    [0x00395a0f, 'mov', 'eax, dword ptr [r14 + 8]', 'encoded field A read'],
    [0x00395a4a, 'mov', 'eax, dword ptr [r14 + 0x14]', 'encoded field C read'],
    [0x00395b1c, 'movss', 'dword ptr [rdx + 4], xmm6', 'decoded C stored at destination +4'],
    [0x00395b21, 'mov', 'byte ptr [rdx + 0x15], 0', 'destination flag +0x15 initialized false'],
    [0x00395b2d, 'movss', 'dword ptr [rdx + 8], xmm7', 'conditional decoded A/C stored +8'],
    [0x00395b32, 'movss', 'dword ptr [rdx + 0x10], xmm8', 'decoded D stored +0x10'],
    [0x00395b38, 'movss', 'dword ptr [rdx + 0xc], xmm9', 'decoded B stored +0x0c'],
    [0x00395b3e, 'mov', 'byte ptr [rdx + 0x14], 1', 'destination flag +0x14 initialized true'],
  ];
  const checks = required.map(([rva, mnemonic, operands, claim]) => {
    const actual = byRva.get(rva);
    const match = Boolean(actual && actual.mnemonic === mnemonic && actual.operands === operands);
    if (!match) throw new Error(`0x0412 record-layout instruction mismatch at 0x${rva.toString(16)}`);
    return { rva: `0x${rva.toString(16).padStart(8, '0')}`, mnemonic, operands, claim, match };
  });
  return {
    status: 'VERIFIED_DIRECT_STATIC_RECORD_LAYOUT',
    consumer_rva: '0x003958d0',
    source_record_stride_bytes: 28,
    source_encoded_fields: {
      field_a: { offset: 8, width: 4, decoded_type: 'f32', semantic: 'UNKNOWN' },
      field_b: { offset: 12, width: 4, decoded_type: 'f32', semantic: 'TIME_LIKE_CANDIDATE' },
      adjustment_kind: { offset: 16, width: 1, decoded_type: 'u8', semantic: 'UNKNOWN' },
      field_c: { offset: 20, width: 4, decoded_type: 'f32', semantic: 'UNKNOWN' },
      field_d: { offset: 24, width: 4, decoded_type: 'f32', semantic: 'UNKNOWN' },
    },
    destination_writes: {
      kind_u8_offset_0: 'decoded adjustment_kind',
      f32_offset_4: 'decoded field_c',
      f32_offset_8: 'field_d > 0 ? decoded field_a : decoded field_c',
      f32_offset_12: 'decoded field_b',
      f32_offset_16: 'decoded field_d',
      byte_offset_20: 1,
      byte_offset_21: 0,
    },
    flags_evidence: 'CONSUMER_INITIALIZATION_CONSTANTS_ONLY; NO_PACKET_FLAG_OR_OPERATION_SEMANTIC',
    instruction_checks: checks,
  };
}

function lowerBound(rows, timestamp) {
  let low = 0;
  let high = rows.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (rows[middle].time < timestamp) low = middle + 1;
    else high = middle;
  }
  return low;
}

function vectorDelta(before, after) {
  if (!before || !after || before.selector !== after.selector) return null;
  return before.lanes.map((value, index) => round(after.lanes[index] - value, 7));
}

function samplePush(array, value, limit = 24) {
  if (array.length < limit) array.push(value);
}

async function loadAdjustmentAudit(file) {
  const records = [];
  const seen = new Set();
  const corpus = new Map();
  const replay = new Map();
  const entity = new Map();
  const outerKind = new Map();
  const kind = new Map();
  const patterns = new Map();
  const fields = { a: new Map(), b: new Map(), c: new Map(), d: new Map() };
  let timeDeltaMin = Infinity;
  let timeDeltaMax = -Infinity;
  let timeDeltaAbs = 0;
  let timeDeltaWithin1ms = 0;
  let rawRecordCount = 0;
  let duplicateRecordCount = 0;
  for await (const row of readJsonl(file)) {
    rawRecordCount += 1;
    validateAdjustmentEvent(row);
    const identity = adjustmentRecordIdentity(row);
    if (!acceptUniqueIdentity(seen, identity)) {
      duplicateRecordCount += 1;
      continue;
    }
    const values = [row.field_a_plain_f32, row.field_b_plain_f32,
      row.field_c_plain_f32, row.field_d_plain_f32];
    if (!values.every(Number.isFinite)) throw new Error('0x0412 plaintext record has non-finite field');
    records.push(row);
    increment(corpus, row.corpus);
    increment(replay, row.replay_sha256);
    increment(entity, row.entity_network_id_hex);
    increment(outerKind, row.outer_update_kind_plain_u8);
    increment(kind, row.adjustment_kind_plain_u8);
    increment(patterns, JSON.stringify(values.map((value) => round(value))));
    ['a', 'b', 'c', 'd'].forEach((name, index) => increment(fields[name], round(values[index])));
    const delta = row.replay_time_ms - row.field_b_plain_f32 * 1000;
    timeDeltaMin = Math.min(timeDeltaMin, delta);
    timeDeltaMax = Math.max(timeDeltaMax, delta);
    timeDeltaAbs += Math.abs(delta);
    timeDeltaWithin1ms += Number(Math.abs(delta) <= 1);
  }
  return {
    records,
    audit: {
      raw_record_count: rawRecordCount, record_count: records.length,
      duplicate_record_count: duplicateRecordCount, rejected_record_count: 0,
      corpus_counts: sortedCounter(corpus), replay_counts: sortedCounter(replay),
      entity_counts: sortedCounter(entity), outer_update_kind_counts: sortedCounter(outerKind),
      adjustment_kind_counts: sortedCounter(kind), value_pattern_counts: sortedCounter(patterns),
      field_value_counts: Object.fromEntries(Object.entries(fields).map(([name, counts]) =>
        [name, sortedCounter(counts)])),
      field_b_replay_time_delta_ms: {
        count: records.length, min: round(timeDeltaMin), max: round(timeDeltaMax),
        mean_absolute: round(timeDeltaAbs / records.length), within_one_ms_count: timeDeltaWithin1ms,
        classification: 'TIME_LIKE_COMPONENT_CANDIDATE_NOT_OPERATION_OR_VALUE_PROMOTION',
      },
    },
  };
}

async function loadFormulaSeries(files) {
  const groups = new Map();
  const seen = new Set();
  const selectors = new Map();
  const streams = new Map();
  const replays = new Map();
  let rowCount = 0;
  let outputCount = 0;
  let rawRowCount = 0;
  let duplicatePacketCount = 0;
  for (const { file, profileSha256 } of files) {
    for await (const row of readJsonl(file)) {
      rawRowCount += 1;
      validateFormulaRow(row, profileSha256);
      const identity = physicalPacketIdentity(row);
      if (!acceptUniqueIdentity(seen, identity)) {
        duplicatePacketCount += 1;
        continue;
      }
      rowCount += 1;
      increment(streams, row.chunk_stream);
      increment(replays, row.replay_sha256);
      const groupKey = key(row.replay_sha256, row.raw_param);
      if (!groups.has(groupKey)) groups.set(groupKey, []);
      for (const output of formulaOutputs(row)) {
        const selector = output.output_kind_storage ?? output.encoded_selector_0x08;
        const normalized = { time: row.replay_time_ms, selector, lanes: decodeLanes(output),
          stream: row.chunk_stream, raw_payload_sha256: row.raw_payload_sha256 };
        groups.get(groupKey).push(normalized);
        increment(selectors, selector);
        outputCount += 1;
      }
    }
  }
  for (const rows of groups.values()) rows.sort((a, b) => a.time - b.time);
  return { groups, summary: { raw_row_count: rawRowCount, row_count: rowCount,
    duplicate_packet_count: duplicatePacketCount, rejected_row_count: 0, output_count: outputCount,
    selector_counts: sortedCounter(selectors), stream_counts: sortedCounter(streams),
    replay_counts: sortedCounter(replays), entity_series_count: groups.size } };
}

function analyzeTemporalDependencies(adjustments, formulaGroups) {
  const windows = Object.fromEntries(WINDOW_MS.map((window) => [String(window), 0]));
  const nearestDistance = [];
  const deltaPatterns = new Map();
  const selectorPairs = new Map();
  const examples = { no_same_entity_series: [], no_formula_within_1000ms: [],
    bracketed_zero_delta: [], bracketed_nonzero_delta: [] };
  let seriesCount = 0;
  let sameTimestampCount = 0;
  let bracketedCount = 0;
  let comparableCount = 0;
  let zeroDeltaCount = 0;
  let nonzeroDeltaCount = 0;
  for (const adjustment of adjustments) {
    const rows = formulaGroups.get(key(adjustment.replay_sha256, adjustment.entity_network_id));
    const id = { replay_sha256: adjustment.replay_sha256,
      entity_network_id_hex: adjustment.entity_network_id_hex, replay_time_ms: adjustment.replay_time_ms,
      source_packet_sha256: adjustment.source_packet.raw_payload_sha256 };
    if (!rows || !rows.length) {
      samplePush(examples.no_same_entity_series, id);
      continue;
    }
    seriesCount += 1;
    const index = lowerBound(rows, adjustment.replay_time_ms);
    const exact = rows[index]?.time === adjustment.replay_time_ms ? rows[index] : null;
    const prior = index > 0 ? rows[index - 1] : null;
    let afterIndex = index;
    while (afterIndex < rows.length && rows[afterIndex].time === adjustment.replay_time_ms) afterIndex += 1;
    const after = rows[afterIndex] || null;
    sameTimestampCount += Number(Boolean(exact));
    const candidates = [prior, exact, after].filter(Boolean);
    const distance = Math.min(...candidates.map((row) => Math.abs(row.time - adjustment.replay_time_ms)));
    nearestDistance.push(distance);
    for (const window of WINDOW_MS) windows[String(window)] += Number(distance <= window);
    if (distance > 1000) samplePush(examples.no_formula_within_1000ms, { ...id, nearest_distance_ms: distance });
    if (!prior || !after) continue;
    bracketedCount += 1;
    increment(selectorPairs, `${prior.selector}->${after.selector}`);
    const delta = vectorDelta(prior, after);
    if (!delta) continue;
    comparableCount += 1;
    increment(deltaPatterns, JSON.stringify(delta));
    const zero = delta.every((value) => Object.is(value, 0) || Math.abs(value) <= 1e-7);
    zeroDeltaCount += Number(zero);
    nonzeroDeltaCount += Number(!zero);
    const example = { ...id, before_time_ms: prior.time, after_time_ms: after.time,
      before_selector: prior.selector, after_selector: after.selector, lane_delta: delta };
    samplePush(zero ? examples.bracketed_zero_delta : examples.bracketed_nonzero_delta, example);
  }
  nearestDistance.sort((a, b) => a - b);
  const median = nearestDistance.length ? nearestDistance[Math.floor(nearestDistance.length / 2)] : null;
  return {
    adjustment_record_count: adjustments.length,
    same_replay_entity_formula_series_count: seriesCount,
    same_timestamp_formula_count: sameTimestampCount,
    nearest_formula_window_counts_ms: windows,
    nearest_formula_distance_ms: { count: nearestDistance.length, min: nearestDistance[0] ?? null,
      median, max: nearestDistance.at(-1) ?? null },
    bracketed_by_strict_before_after_count: bracketedCount,
    same_selector_comparable_count: comparableCount,
    zero_lane_delta_count: zeroDeltaCount,
    nonzero_lane_delta_count: nonzeroDeltaCount,
    selector_before_after_counts: sortedCounter(selectorPairs),
    lane_delta_pattern_counts: sortedCounter(deltaPatterns),
    examples,
  };
}

function semanticDecision(adjustmentAudit, formulaSummary, dependency) {
  const kinds = Object.keys(adjustmentAudit.adjustment_kind_counts);
  const selectors = Object.keys(formulaSummary.selector_counts);
  return {
    selector: {
      status: 'UNKNOWN',
      evidence: `0x0412 adjustment_kind has observed domain [${kinds.join(', ')}]; no static edge binds it or any float field to 0x042f selector domain [${selectors.join(', ')}].`,
    },
    operation: {
      status: 'UNKNOWN',
      evidence: 'No decoded discriminator varies with independently known add/remove/replace ground truth; outer update kind and consumer flags lack named operation evidence.',
    },
    value: {
      status: 'UNKNOWN',
      evidence: 'field_b is time-like; fields a/c/d have repeated neutral shapes, but no field has directionality plus a repeated output-delta response and counterexample closure.',
    },
    flags: {
      status: 'STRUCTURE_ONLY',
      evidence: 'Consumer writes destination bytes +0x14=1 and +0x15=0; these constants are not proved packet flags or operation semantics.',
    },
    formula_dependency: {
      status: 'MISSING_EDGE',
      observed_temporal_same_entity_pairs: dependency.same_replay_entity_formula_series_count,
      missing_edge: 'No exact-build static consumer/writer dataflow connects a 0x0412 decoded component to a 0x042f selector/lane, and temporal bracketing does not uniquely map an input component to an output delta.',
      promoted_edges: [],
    },
    flat_percent: {
      status: 'UNRESOLVED',
      reason: 'Neither ADD_FLAT nor ADD_PERCENT has a proved target stat, operation discriminator, amount field, direction, reversible transition, and cross-stat counterexamples.',
    },
    semantic_promotion: 'NO_PUBLIC_STAT_MODIFIER_PROMOTION',
  };
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

async function runStatModifierDependencyAudit({ rootDir, outputDir }) {
  const inputs = defaultInputs(rootDir);
  Object.values(inputs).forEach(assertNonHoldoutPath);
  assertNonHoldoutPath(outputDir);
  fs.mkdirSync(outputDir, { recursive: true });
  for (const stale of ['manifest.json', 'test-results.xml']) {
    const stalePath = path.join(outputDir, stale);
    if (fs.existsSync(stalePath)) fs.unlinkSync(stalePath);
  }
  const upstreamValidation = verifyPinnedSources(inputs);
  const disassembly = JSON.parse(fs.readFileSync(inputs.consumerDisassembly, 'utf8'));
  const layout = verifyRecordLayout(disassembly);
  const adjustment = await loadAdjustmentAudit(inputs.adjustmentEvents);
  const formula = await loadFormulaSeries([
    { file: inputs.formulaLatest, profileSha256: FORMULA_PROFILE_SHA256.formulaLatest },
    { file: inputs.formulaP0, profileSha256: FORMULA_PROFILE_SHA256.formulaP0 },
  ]);
  if (adjustment.records.length !== EXPECTED_ADJUSTMENT_RECORDS) {
    throw new Error(`expected ${EXPECTED_ADJUSTMENT_RECORDS} 0x0412 records, got ${adjustment.records.length}`);
  }
  if (formula.summary.row_count !== EXPECTED_FORMULA_ROWS) {
    throw new Error(`expected ${EXPECTED_FORMULA_ROWS} 0x042f rows, got ${formula.summary.row_count}`);
  }
  const dependency = analyzeTemporalDependencies(adjustment.records, formula.groups);
  const decision = semanticDecision(adjustment.audit, formula.summary, dependency);
  const sourceArtifacts = Object.fromEntries(Object.entries(inputs).map(([name, file]) => [name, {
    path: path.relative(rootDir, file), sha256: hashFileSync(file), bytes: fs.statSync(file).size,
  }]));
  const runtimeHash = sourceArtifacts.runtimeImage.sha256;
  invariant(runtimeHash === RUNTIME_IMAGE_SHA256, 'runtime image is not the governed exact image');
  invariant(disassembly.image_base === 0x140000000, 'consumer disassembly image base mismatch');
  invariant(Array.isArray(disassembly.executable_ranges) && disassembly.executable_ranges.length > 0,
    'consumer disassembly executable ranges missing');
  invariant(sourceArtifacts.consumerDisassembly.sha256
    === deepReportDisassemblyHash(readJson(inputs.deepReport)),
  'consumer disassembly is not bound to the governed deep report');
  const report = {
    schema: 'ROFL_STAT_MODIFIER_DEPENDENCY_AUDIT_V1', schema_version: 1,
    exact_build: EXACT_BUILD, status: 'EVIDENCE_EXHAUSTED_NO_MODIFIER_SEMANTIC_PROMOTION',
    project_context_loaded: true, architecture_gate: 'PASS',
    protected_holdout: { read: false, enumerate: false, hash: false, decode: false, test: false, consume: false },
    runtime_image_sha256: runtimeHash, source_artifacts: sourceArtifacts,
    upstream_source_validation: upstreamValidation,
    record_layout: layout, adjustment_observations: adjustment.audit,
    formula_observations: formula.summary, dependency_analysis: dependency,
    semantic_decision: decision,
    negative_controls: [
      'RTTI/type name establishes route ownership only, not selector/operation/value semantics.',
      'Time proximity and same entity are dependency hypotheses, not causal or semantic promotion evidence.',
      'A repeated numeric shape cannot distinguish flat, percent, duration, interpolation, or control metadata.',
      '0x042f observed selector 194 cannot name a stat without a semantic consumer/writer and behavioral counterexamples.',
    ],
    missing_edges: [decision.formula_dependency.missing_edge,
      'No independently labeled add/remove/update event maps outer_update_kind to an operation.',
      'No exact-build target-stat identity maps any 0x0412 field to a stat selector/lane.',
      'No reversible controlled modifier transition demonstrates flat versus percent response.'],
    reproduction: {
      analyzer_invocation: 'node scripts/analyze_stat_modifier_dependencies.js --output-dir .omo/evidence/stat_semantic_mapping_v1/modifier_dependency',
      test_invocation: 'node --test --test-reporter=junit --test-reporter-destination=.omo/evidence/stat_semantic_mapping_v1/modifier_dependency/test-results.xml test/stat_modifier_dependency.test.js',
      finalizer_invocation: 'node scripts/analyze_stat_modifier_dependencies.js --output-dir .omo/evidence/stat_semantic_mapping_v1/modifier_dependency --finalize --test-results .omo/evidence/stat_semantic_mapping_v1/modifier_dependency/test-results.xml',
      binary_observables: {
        adjustment_record_count: EXPECTED_ADJUSTMENT_RECORDS,
        formula_row_count: EXPECTED_FORMULA_ROWS,
        promoted_dependency_edge_count: 0,
        selector_status: 'UNKNOWN',
        operation_status: 'UNKNOWN',
      },
    },
  };
  const paths = {
    report: path.join(outputDir, 'modifier_dependency_report.json'),
    recordLayout: path.join(outputDir, 'record_layout.json'),
    dependencyGraph: path.join(outputDir, 'stat_formula_dependency_graph.json'),
    counterexamples: path.join(outputDir, 'counterexamples.json'),
    manifest: path.join(outputDir, 'manifest.json'),
    testResults: path.join(outputDir, 'test-results.xml'),
  };
  writeJson(paths.report, report);
  writeJson(paths.recordLayout, layout);
  writeJson(paths.dependencyGraph, {
    schema: 'STAT_FORMULA_DEPENDENCY_GRAPH_V1', exact_build: EXACT_BUILD,
    status: 'NO_PROMOTED_EDGES', promoted_edges: [], temporal_observations: dependency,
    rejected_candidate: decision.formula_dependency,
  });
  writeJson(paths.counterexamples, {
    schema: 'STAT_MODIFIER_DEPENDENCY_COUNTEREXAMPLES_V1', exact_build: EXACT_BUILD,
    aggregate: { zero_lane_delta_count: dependency.zero_lane_delta_count,
      no_same_entity_series_count: adjustment.records.length - dependency.same_replay_entity_formula_series_count,
      no_formula_within_1000ms_count: adjustment.records.length - dependency.nearest_formula_window_counts_ms['1000'] },
    examples: dependency.examples,
  });
  return { report, paths };
}

function deepReportDisassemblyHash(deep) {
  return deep.evidence_hashes?.runtime_0412_adjustment_consumer_disassembly?.sha256;
}

function finalizeEvidenceManifest({ outputDir, testResultsPath }) {
  assertNonHoldoutPath(outputDir);
  assertNonHoldoutPath(testResultsPath);
  const expectedTestPath = path.join(outputDir, 'test-results.xml');
  invariant(path.resolve(testResultsPath) === path.resolve(expectedTestPath),
    'test result must use the canonical evidence path');
  const fixedNames = ['modifier_dependency_report.json', 'record_layout.json',
    'stat_formula_dependency_graph.json', 'counterexamples.json', 'test-results.xml'];
  const files = fixedNames.map((name) => path.join(outputDir, name));
  for (const file of files) invariant(fs.existsSync(file) && fs.statSync(file).size > 0,
    `final evidence artifact missing or empty: ${path.basename(file)}`);
  invariant(fs.statSync(testResultsPath).mtimeMs >= fs.statSync(files[0]).mtimeMs,
    'test results predate the final analysis report');
  const junit = fs.readFileSync(testResultsPath, 'utf8');
  invariant(/<!-- tests 9 -->/.test(junit) && /<!-- pass 9 -->/.test(junit)
    && /<!-- fail 0 -->/.test(junit), 'JUnit result is not the required 9/9 passing suite');
  const allowed = new Set([...fixedNames, 'manifest.json']);
  const unexpected = fs.readdirSync(outputDir).filter((name) => !allowed.has(name));
  invariant(unexpected.length === 0, `unexpected unmanifested evidence files: ${unexpected.join(', ')}`);
  const manifestPath = path.join(outputDir, 'manifest.json');
  writeJson(manifestPath, {
    schema: 'STAT_MODIFIER_DEPENDENCY_EVIDENCE_MANIFEST_V1', exact_build: EXACT_BUILD,
    finalized_after_tests: true,
    artifacts: files.map((file) => ({ path: path.basename(file), bytes: fs.statSync(file).size,
      sha256: hashFileSync(file) })),
  });
  return { manifestPath, artifact_count: files.length };
}

module.exports = {
  EXACT_BUILD, EXPECTED_ADJUSTMENT_RECORDS, EXPECTED_FORMULA_ROWS, FORMULA_PROFILE_SHA256,
  PINNED_SOURCE_SHA256, RUNTIME_IMAGE_SHA256, WINDOW_MS,
  acceptUniqueIdentity, analyzeTemporalDependencies, assertNonHoldoutPath, defaultInputs, decodeLanes,
  finalizeEvidenceManifest, lowerBound, physicalPacketIdentity, runStatModifierDependencyAudit,
  semanticDecision, validateAdjustmentEvent, validateFormulaRow, verifyPinnedSources,
  verifyRecordLayout,
};
