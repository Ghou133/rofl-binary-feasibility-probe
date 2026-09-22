#!/usr/bin/env node

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT_DIR = path.join(
  ROOT,
  'artifacts',
  'full_semantic_deep_recovery_v2',
  'hero_state',
);

const ATTACK_SPEED_PRESENCE_TABLE_RVA = 0x01a27950;
const BUFF_ADJUSTMENT_TABLE_RVA = 0x01a41d00;

const PATHS = {
  runtimeImage: path.join(
    ROOT,
    'artifacts',
    'new_build_rofl_compatibility_gate_v1',
    'runtime',
    'league_16.16.805.0442.memory.bin',
  ),
  detailsManifest: path.join(
    ROOT,
    'artifacts',
    'hero_combat_state_v2',
    'anchors',
    'details_p0_manifest.json',
  ),
  detailsAnchors: path.join(
    ROOT,
    'artifacts',
    'hero_combat_state_v2',
    'anchors',
    'details_p0_ground_truth.jsonl',
  ),
  inventoryCrosscheck: path.join(
    ROOT,
    'artifacts',
    'hero_combat_state_v2',
    'runtime',
    'target_route_inventory_crosscheck_16_16.json',
  ),
  damageValidation: path.join(
    ROOT,
    'artifacts',
    'hero_combat_state_v2',
    'damage',
    'damage_16_16_anchor_validation.json',
  ),
  formulaLatest: path.join(ARTIFACT_DIR, 'packet_042f_latest_four_all_decoded.jsonl'),
  formulaP0: path.join(ARTIFACT_DIR, 'packet_042f_p0_decoded.jsonl'),
  adjustmentsLatest: path.join(
    ROOT,
    'artifacts',
    'hero_combat_state_v2',
    'emulation',
    'packet_0412_all_decoded.jsonl',
  ),
  adjustmentsP0: path.join(ARTIFACT_DIR, 'packet_0412_p0_decoded.jsonl'),
  replicateP0: path.join(ARTIFACT_DIR, 'packet_01dc_p0_decoded.jsonl'),
  statStoneLatestSummary: path.join(
    ARTIFACT_DIR,
    'packet_03dc_latest_four_tags.summary.json',
  ),
  statStoneP0Summary: path.join(ARTIFACT_DIR, 'packet_03dc_p0_tags.summary.json'),
  statStoneP0: path.join(ARTIFACT_DIR, 'packet_03dc_p0_tags.jsonl'),
  deathTimerLatest: path.join(ARTIFACT_DIR, 'packet_0074_latest_four_decoded.jsonl'),
  deathTimerP0: path.join(ARTIFACT_DIR, 'packet_0074_p0_decoded.jsonl'),
  showHealthLatest: path.join(ARTIFACT_DIR, 'packet_00d2_latest_four_decoded.jsonl'),
  showHealthP0: path.join(ARTIFACT_DIR, 'packet_00d2_p0_decoded.jsonl'),
  attackSpeedLatest: path.join(ARTIFACT_DIR, 'packet_00dd_latest_four_decoded.jsonl'),
  attackSpeedP0: path.join(ARTIFACT_DIR, 'packet_00dd_p0_decoded.jsonl'),
  healthTicksLatest: path.join(ARTIFACT_DIR, 'packet_02cf_latest_four_decoded.jsonl'),
  healthTicksP0: path.join(ARTIFACT_DIR, 'packet_02cf_p0_decoded.jsonl'),
  npcLevelLatest: path.join(ARTIFACT_DIR, 'packet_0345_latest_four_decoded.jsonl'),
  npcLevelP0: path.join(ARTIFACT_DIR, 'packet_0345_p0_decoded.jsonl'),
  latestManifest: path.join(ARTIFACT_DIR, 'packet_priority_state_latest_four_all.jsonl.manifest.json'),
  p0Manifest: path.join(ARTIFACT_DIR, 'packet_state_candidates_p0_all.jsonl.manifest.json'),
  route0474Audit: path.join(
    ROOT,
    'artifacts',
    'full_semantic_deep_recovery_v2',
    'unknown_mining',
    'route_0474_champion_specific_audit.json',
  ),
  route02d4Audit: path.join(
    ROOT,
    'artifacts',
    'full_semantic_deep_recovery_v2',
    'unknown_mining',
    'route_02d4_auxiliary_batch_audit.json',
  ),
  heroStatsCrossCheck: path.join(
    ROOT,
    'artifacts',
    'hero_combat_state_v2',
    'profiler',
    'packet_010c_hero_stats_cross_check.json',
  ),
  heroStatsLatestSummary: path.join(
    ROOT,
    'artifacts',
    'hero_combat_state_v2',
    'emulation',
    'packet_010c_all_latest_four_decoded.jsonl.summary.json',
  ),
};

function parseArgs(argv) {
  const options = {
    output: path.join(ARTIFACT_DIR, 'hero_state_damage_defense_deep_report_16_16.json'),
    markdown: path.join(ARTIFACT_DIR, 'HERO_STATE_DAMAGE_DEFENSE_DEEP_REPORT_16_16.md'),
    deathEvents: path.join(ARTIFACT_DIR, 'packet_0074_death_timer_events.jsonl'),
    attackSpeedEvents: path.join(
      ARTIFACT_DIR,
      'packet_00dd_attack_speed_cap_override_events.jsonl',
    ),
    buffAdjustmentEvents: path.join(
      ARTIFACT_DIR,
      'packet_0412_buff_stat_adjustment_events.jsonl',
    ),
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--output') options.output = path.resolve(argv[++index]);
    else if (value === '--markdown') options.markdown = path.resolve(argv[++index]);
    else if (value === '--death-events') options.deathEvents = path.resolve(argv[++index]);
    else if (value === '--attack-speed-events') {
      options.attackSpeedEvents = path.resolve(argv[++index]);
    }
    else if (value === '--buff-adjustment-events') {
      options.buffAdjustmentEvents = path.resolve(argv[++index]);
    }
    else throw new Error(`unknown argument: ${value}`);
  }
  return options;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}

async function* readJsonl(file) {
  const input = fs.createReadStream(file, { encoding: 'utf8' });
  const lines = readline.createInterface({ input, crlfDelay: Infinity });
  for await (const line of lines) {
    if (line.trim()) yield JSON.parse(line.replace(/^\uFEFF/, ''));
  }
}

function increment(counter, key, amount = 1) {
  counter.set(String(key), (counter.get(String(key)) || 0) + amount);
}

function sortedCounter(counter) {
  return Object.fromEntries([...counter.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

function round(value, digits = 6) {
  if (!Number.isFinite(value)) return null;
  const scale = 10 ** digits;
  return Math.round(value * scale) / scale;
}

function participantNetworkId(participantId) {
  return 0x400000ad + participantId;
}

function isHeroNetworkId(value) {
  return value >= participantNetworkId(1) && value <= participantNetworkId(10);
}

function rotateRight8(value, count) {
  const shift = count & 7;
  return ((value >>> shift) | (value << (8 - shift))) & 0xff;
}

function swapAdjacentBits(value) {
  return ((((value & 0xd5) * 2) | ((value >>> 1) & 0x55))) & 0xff;
}

// Exact inverse used by AIBaseClient::Receive(PKT_S2C_UpdateDeathTimer_s)
// at 16.16.805.0442 RVA 0x002a6480..0x002a64aa.
function decodeDeathTimerByte(encoded) {
  let value = rotateRight8(encoded, 6);
  value = (value - 0x67) & 0xff;
  let even = value;
  value = (value >>> 1) & 0x55;
  even = (even & 0xd5) * 2;
  value = (even | value) & 0xff;
  value = rotateRight8(value, 5);
  return (~value) & 0xff;
}

function decodeDeathTimerStorage(storage) {
  if (!Buffer.isBuffer(storage) || storage.length !== 4) {
    throw new Error('death timer storage must be exactly four bytes');
  }
  const decoded = Buffer.from(storage.map(decodeDeathTimerByte));
  return decoded.readFloatLE(0);
}

function decodeDeathTimerObjectHex(objectHex) {
  const object = Buffer.from(objectHex, 'hex');
  if (object.length < 0x14) throw new Error('death timer object is shorter than 0x14 bytes');
  return decodeDeathTimerStorage(object.subarray(0x10, 0x14));
}

// Exact plaintext recovery used by
// AIHeroClient::Receive(PKT_S2C_UpdateAttackSpeedCapOverrides_s), callback RVA
// 0x002a6180.  The callback decrypts packet storage to a stack f32 before it
// writes into the entity's independently protected rolling-value storage.
function decodeAttackSpeedPresenceField1c(encoded) {
  let value = swapAdjacentBits(encoded);
  value = rotateRight8(value, 3);
  value = (value + 0x76) & 0xff;
  value = swapAdjacentBits(value);
  value = rotateRight8(value, 3);
  return value !== 0;
}

function decodeAttackSpeedPresenceField10(encoded, table) {
  if (!Buffer.isBuffer(table) || table.length !== 0x100) {
    throw new Error('attack-speed presence table must be exactly 256 bytes');
  }
  let value = table[(~encoded) & 0xff];
  value = rotateRight8(value, 1) ^ 0x94;
  value = (value - 0x47) & 0xff;
  return table[value] !== 0;
}

function decodeAttackSpeedField18Byte(encoded) {
  let value = rotateRight8(encoded, 3);
  value = (value - 0x64) & 0xff;
  value = swapAdjacentBits(value);
  value = (value - 0x33) & 0xff;
  value = rotateRight8(value, 5);
  return (value - 0x7f) & 0xff;
}

function decodeAttackSpeedField14Byte(encoded, table) {
  let value = (encoded - 0x1e) & 0xff;
  value = rotateRight8(value, 5);
  value = swapAdjacentBits(value);
  value = (value + 0x3a) & 0xff;
  value = table[value];
  return rotateRight8(value, 4);
}

function decodeAttackSpeedFloatStorage(storage, byteDecoder) {
  if (!Buffer.isBuffer(storage) || storage.length !== 4) {
    throw new Error('attack-speed float storage must be exactly four bytes');
  }
  return Buffer.from(storage.map(byteDecoder)).readFloatLE(0);
}

function decodeAttackSpeedObjectHex(objectHex, table) {
  const object = Buffer.from(objectHex, 'hex');
  if (object.length < 0x20) throw new Error('attack-speed override object is shorter than 0x20 bytes');
  const field14Present = decodeAttackSpeedPresenceField10(object[0x10], table);
  const field18Present = decodeAttackSpeedPresenceField1c(object[0x1c]);
  return {
    field_14_present: field14Present,
    field_18_present: field18Present,
    field_14_plain_f32: field14Present
      ? decodeAttackSpeedFloatStorage(
        object.subarray(0x14, 0x18),
        (value) => decodeAttackSpeedField14Byte(value, table),
      )
      : null,
    field_18_plain_f32: field18Present
      ? decodeAttackSpeedFloatStorage(object.subarray(0x18, 0x1c), decodeAttackSpeedField18Byte)
      : null,
  };
}

// Exact plaintext recovery performed by the 0x0412 consumer at RVA 0x003958d0
// after BuffManagerClient's callback (RVA 0x008cd3a0) forwards the packet's
// 0x1c-byte adjustment records.
function decodeBuffAdjustmentKindByte(encoded) {
  let value = (encoded + 0x12) & 0xff;
  value = rotateRight8(value, 4);
  value = (value + 0x43) & 0xff;
  value = rotateRight8(value, 4);
  value ^= 0x30;
  return rotateRight8(value, 5);
}

function decodeBuffAdjustmentFieldAByte(encoded) {
  let value = (~encoded) & 0xff;
  value = rotateRight8(value, 6);
  value = (value - 0x71) & 0xff;
  value = rotateRight8(value, 3);
  return swapAdjacentBits(value);
}

function decodeBuffAdjustmentFieldBByte(encoded, table) {
  let value = table[encoded];
  value ^= 0x6d;
  value = rotateRight8(value, 2);
  value = (value + 0x29) & 0xff;
  value = swapAdjacentBits(value);
  return (value + 0x0e) & 0xff;
}

function decodeBuffAdjustmentFieldCByte(encoded, table) {
  let value = (encoded + 0x50) & 0xff;
  value = rotateRight8(value, 2);
  value = (~value) & 0xff;
  value = table[value];
  value = (value - 0x12) & 0xff;
  value = table[value];
  value = (value - 0x18) & 0xff;
  return table[value];
}

function decodeBuffAdjustmentFieldDByte(encoded) {
  let value = (~encoded) & 0xff;
  value = rotateRight8(value, 5);
  value ^= 0x52;
  value = (value - 0x63) & 0xff;
  value = rotateRight8(value, 2);
  value = (~value) & 0xff;
  return (value - 0x0e) & 0xff;
}

function decodeBuffAdjustmentRecordObjectHex(objectHex, table) {
  if (!Buffer.isBuffer(table) || table.length !== 0x100) {
    throw new Error('buff-adjustment lookup table must be exactly 256 bytes');
  }
  const object = Buffer.from(objectHex, 'hex');
  if (object.length < 0x1c) throw new Error('buff-adjustment record is shorter than 0x1c bytes');
  return {
    adjustment_kind_plain_u8: decodeBuffAdjustmentKindByte(object[0x10]),
    field_a_plain_f32: decodeAttackSpeedFloatStorage(
      object.subarray(0x08, 0x0c),
      decodeBuffAdjustmentFieldAByte,
    ),
    field_b_plain_f32: decodeAttackSpeedFloatStorage(
      object.subarray(0x0c, 0x10),
      (value) => decodeBuffAdjustmentFieldBByte(value, table),
    ),
    field_c_plain_f32: decodeAttackSpeedFloatStorage(
      object.subarray(0x14, 0x18),
      (value) => decodeBuffAdjustmentFieldCByte(value, table),
    ),
    field_d_plain_f32: decodeAttackSpeedFloatStorage(
      object.subarray(0x18, 0x1c),
      decodeBuffAdjustmentFieldDByte,
    ),
  };
}

function decodeFormulaValues(hex) {
  const bytes = Buffer.from(hex, 'hex');
  if (bytes.length % 4 !== 0) throw new Error(`formula vector is not f32-aligned: ${hex}`);
  const values = [];
  for (let offset = 0; offset < bytes.length; offset += 4) values.push(bytes.readFloatLE(offset));
  return values;
}

function itemAnchors(detailsManifest) {
  const fieldByRole = {
    PERSISTENT_MAX_HP_PURCHASE: 'max_hp',
    PERSISTENT_MAGIC_RESIST_PURCHASE: 'magic_resist',
    PERSISTENT_ARMOR_PURCHASE: 'armor',
  };
  return detailsManifest.replays
    .map((replay) => ({ replay, sample: replay.key_sample_validation }))
    .filter(({ sample }) => fieldByRole[sample.role])
    .map(({ replay, sample }) => {
      const field = fieldByRole[sample.role];
      const frames = sample.frame_p0;
      return {
        role: sample.role,
        game_id: replay.game_id,
        replay_sha256: replay.replay.sha256,
        participant_id: sample.participant_id,
        champion: sample.champion,
        network_id: participantNetworkId(sample.participant_id),
        event_timestamp_ms: sample.event.timestamp_ms,
        frame_start_ms: frames[0].timestamp_ms,
        frame_end_ms: frames.at(-1).timestamp_ms,
        field,
        before: frames[0][field],
        after: frames.at(-1)[field],
      };
    });
}

function deathAnchor(detailsManifest) {
  const entry = detailsManifest.replays.find(
    (replay) => replay.key_sample_validation.role === 'DAMAGE_DEATH_RESPAWN_FRAME_BOUND',
  );
  const sample = entry.key_sample_validation;
  return {
    game_id: entry.game_id,
    replay_sha256: entry.replay.sha256,
    participant_id: sample.participant_id,
    champion: sample.champion,
    network_id: participantNetworkId(sample.participant_id),
    death_event_timestamp_ms: sample.event.timestamp_ms,
    zero_health_frame_timestamp_ms: sample.death_respawn_frame_bound.zero_health_frame_timestamp_ms,
    respawn_lower_bound_timestamp_ms: sample.death_respawn_frame_bound.respawn_lower_bound_timestamp_ms,
    respawn_upper_bound_timestamp_ms: sample.death_respawn_frame_bound.respawn_upper_bound_timestamp_ms,
  };
}

function emptyWindowMetrics(anchors) {
  return Object.fromEntries(anchors.map((anchor) => [anchor.role, {
    ...anchor,
    row_count: 0,
    before_value_match_count: 0,
    after_value_match_count: 0,
  }]));
}

async function analyzeFormulaCorpus(file, corpus, anchors, anchoredValues) {
  const patterns = new Map();
  const selectors = new Map();
  const vectorLengths = new Map();
  const streams = new Map();
  const replayCounts = new Map();
  const windows = emptyWindowMetrics(anchors);
  let rowCount = 0;
  let fullConsumeCount = 0;
  let valueCount = 0;
  let finiteValueCount = 0;
  let min = Infinity;
  let max = -Infinity;
  let anchoredNontrivialMatchCount = 0;
  for await (const row of readJsonl(file)) {
    rowCount += 1;
    fullConsumeCount += Number(row.fully_consumed && row.deserialize_return_al !== 0);
    increment(streams, row.chunk_stream);
    increment(replayCounts, row.replay_sha256);
    // The original latest-four export predates the neutral field-name cleanup
    // used by the P0 re-export.  Both shapes were produced by the same exact
    // 16.16 runtime profile and carry the same object bytes.
    const outputs = row.decoded_fields.outputs
      ?? row.decoded_fields.formula_output_records_0x18
      ?? [];
    for (const output of outputs) {
      const selector = output.output_kind_storage ?? output.encoded_selector_0x08;
      const valuesHex = output.formula_values_storage_hex ?? output.encoded_u32_values_0x10;
      increment(selectors, selector);
      const values = decodeFormulaValues(valuesHex);
      increment(vectorLengths, values.length);
      increment(patterns, JSON.stringify(values.map((value) => round(value, 6))));
      for (const value of values) {
        valueCount += 1;
        if (Number.isFinite(value)) {
          finiteValueCount += 1;
          min = Math.min(min, value);
          max = Math.max(max, value);
          if (anchoredValues.has(String(round(value, 6)))) anchoredNontrivialMatchCount += 1;
        }
      }
      for (const anchor of anchors) {
        if (row.replay_sha256 !== anchor.replay_sha256
            || row.raw_param !== anchor.network_id
            || row.replay_time_ms < anchor.frame_start_ms
            || row.replay_time_ms > anchor.frame_end_ms) continue;
        const metric = windows[anchor.role];
        metric.row_count += 1;
        metric.before_value_match_count += values.filter((value) => Math.abs(value - anchor.before) < 1e-6).length;
        metric.after_value_match_count += values.filter((value) => Math.abs(value - anchor.after) < 1e-6).length;
      }
    }
  }
  return {
    corpus,
    source: path.relative(ROOT, file),
    row_count: rowCount,
    exact_success_full_consume_count: fullConsumeCount,
    stream_counts: sortedCounter(streams),
    replay_counts: sortedCounter(replayCounts),
    output_selector_counts: sortedCounter(selectors),
    vector_length_counts: sortedCounter(vectorLengths),
    value_pattern_counts: sortedCounter(patterns),
    value_count: valueCount,
    finite_value_count: finiteValueCount,
    value_min: min,
    value_max: max,
    anchored_nontrivial_scalar_match_count: anchoredNontrivialMatchCount,
    item_anchor_windows: windows,
  };
}

async function analyzeReplicateFields(file) {
  const payloadLengths = new Map();
  const shapes = new Map();
  let rowCount = 0;
  let fullConsumeCount = 0;
  let nonemptyFieldIdCount = 0;
  let nonemptyValueCount = 0;
  for await (const row of readJsonl(file)) {
    rowCount += 1;
    fullConsumeCount += Number(row.fully_consumed && row.deserialize_return_al !== 0);
    increment(payloadLengths, row.payload_length);
    const ids = row.decoded_fields.field_ids_hex;
    const values = row.decoded_fields.field_values_hex;
    nonemptyFieldIdCount += Number(ids.replace(/00/g, '').length > 0);
    nonemptyValueCount += Number(values.length > 0);
    increment(shapes, `${row.payload_length}:${ids}:${values}`);
  }
  return {
    source: path.relative(ROOT, file),
    row_count: rowCount,
    exact_success_full_consume_count: fullConsumeCount,
    payload_length_counts: sortedCounter(payloadLengths),
    decoded_shape_counts: sortedCounter(shapes),
    nonzero_field_id_vector_count: nonemptyFieldIdCount,
    nonempty_field_value_vector_count: nonemptyValueCount,
    direct_state_carrier: false,
  };
}

async function analyzeAdjustments(file, corpus, anchors) {
  const rawParams = new Map();
  const replays = new Map();
  const payloadLengths = new Map();
  const adjustmentLengths = new Map();
  const windows = emptyWindowMetrics(anchors);
  let rowCount = 0;
  let fullConsumeCount = 0;
  let heroRowCount = 0;
  for await (const row of readJsonl(file)) {
    rowCount += 1;
    fullConsumeCount += Number(row.fully_consumed && row.deserialize_return_al !== 0);
    heroRowCount += Number(isHeroNetworkId(row.raw_param));
    increment(rawParams, row.raw_param_hex);
    increment(replays, row.replay_sha256);
    increment(payloadLengths, row.payload_length);
    increment(adjustmentLengths, row.decoded_fields.adjustments.length);
    for (const anchor of anchors) {
      if (row.replay_sha256 !== anchor.replay_sha256
          || row.raw_param !== anchor.network_id
          || row.replay_time_ms < anchor.frame_start_ms
          || row.replay_time_ms > anchor.frame_end_ms) continue;
      windows[anchor.role].row_count += 1;
    }
  }
  return {
    corpus,
    source: path.relative(ROOT, file),
    row_count: rowCount,
    exact_success_full_consume_count: fullConsumeCount,
    hero_network_id_row_count: heroRowCount,
    replay_counts: sortedCounter(replays),
    raw_param_counts: sortedCounter(rawParams),
    payload_length_counts: sortedCounter(payloadLengths),
    adjustment_vector_length_counts: sortedCounter(adjustmentLengths),
    item_anchor_windows: windows,
  };
}

async function analyzeBuffAdjustmentsExact(files, table, anchors, outputPath) {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  const output = fs.createWriteStream(outputPath, { encoding: 'utf8' });
  const corpusRows = new Map();
  const replayRows = new Map();
  const entityRows = new Map();
  const outerKinds = new Map();
  const adjustmentKinds = new Map();
  const recordLengths = new Map();
  const fieldValues = {
    a: new Map(),
    b: new Map(),
    c: new Map(),
    d: new Map(),
  };
  const valuePatterns = new Map();
  const windows = emptyWindowMetrics(anchors);
  let rowCount = 0;
  let fullConsumeCount = 0;
  let recordCount = 0;
  let finiteRecordCount = 0;
  let standardAdjustmentCount = 0;
  let clearSentinelCount = 0;
  let unexplainedShapeCount = 0;
  let anchorScalarMatchCount = 0;
  let timeDeltaCount = 0;
  let timeDeltaMin = Infinity;
  let timeDeltaMax = -Infinity;
  let timeDeltaAbsSum = 0;
  let timeDeltaWithinOneMsCount = 0;
  try {
    for (const { corpus, file } of files) {
      for await (const row of readJsonl(file)) {
        const outerKind = decodeBuffAdjustmentKindByte(row.decoded_fields.update_kind_storage);
        const records = row.decoded_fields.adjustments.map(
          (record) => decodeBuffAdjustmentRecordObjectHex(record.object_hex, table),
        );
        rowCount += 1;
        fullConsumeCount += Number(row.fully_consumed && row.deserialize_return_al !== 0);
        increment(corpusRows, corpus);
        increment(replayRows, row.replay_sha256);
        increment(entityRows, row.raw_param_hex);
        increment(outerKinds, outerKind);
        increment(recordLengths, records.length);
        for (let recordIndex = 0; recordIndex < records.length; recordIndex += 1) {
          const record = records[recordIndex];
          const values = [
            record.field_a_plain_f32,
            record.field_b_plain_f32,
            record.field_c_plain_f32,
            record.field_d_plain_f32,
          ];
          recordCount += 1;
          increment(adjustmentKinds, record.adjustment_kind_plain_u8);
          increment(fieldValues.a, round(record.field_a_plain_f32, 6));
          increment(fieldValues.b, round(record.field_b_plain_f32, 6));
          increment(fieldValues.c, round(record.field_c_plain_f32, 6));
          increment(fieldValues.d, round(record.field_d_plain_f32, 6));
          increment(valuePatterns, JSON.stringify(values.map((value) => round(value, 6))));
          finiteRecordCount += Number(values.every(Number.isFinite));
          const standard = record.adjustment_kind_plain_u8 === 0
            && Object.is(record.field_a_plain_f32, 0)
            && Math.abs(record.field_c_plain_f32 - 0.05) < 1e-6
            && Object.is(record.field_d_plain_f32, 5);
          const clear = record.adjustment_kind_plain_u8 === 0
            && Object.is(record.field_a_plain_f32, -1)
            && Object.is(record.field_c_plain_f32, -1)
            && Object.is(record.field_d_plain_f32, 0);
          standardAdjustmentCount += Number(standard);
          clearSentinelCount += Number(clear);
          unexplainedShapeCount += Number(!standard && !clear);
          if (Number.isFinite(record.field_b_plain_f32)) {
            const delta = row.replay_time_ms / 1000 - record.field_b_plain_f32;
            timeDeltaCount += 1;
            timeDeltaMin = Math.min(timeDeltaMin, delta);
            timeDeltaMax = Math.max(timeDeltaMax, delta);
            timeDeltaAbsSum += Math.abs(delta);
            timeDeltaWithinOneMsCount += Number(Math.abs(delta) <= 0.001);
          }
          for (const anchor of anchors) {
            if (row.replay_sha256 !== anchor.replay_sha256
                || row.raw_param !== anchor.network_id
                || row.replay_time_ms < anchor.frame_start_ms
                || row.replay_time_ms > anchor.frame_end_ms) continue;
            windows[anchor.role].row_count += 1;
            windows[anchor.role].record_count = (windows[anchor.role].record_count || 0) + 1;
            const matches = values.filter(
              (value) => Math.abs(value - anchor.before) < 1e-6
                || Math.abs(value - anchor.after) < 1e-6,
            ).length;
            windows[anchor.role].before_value_match_count += values.filter(
              (value) => Math.abs(value - anchor.before) < 1e-6,
            ).length;
            windows[anchor.role].after_value_match_count += values.filter(
              (value) => Math.abs(value - anchor.after) < 1e-6,
            ).length;
            anchorScalarMatchCount += matches;
          }
          output.write(`${JSON.stringify({
            schema_version: 1,
            event_type: 'BUFF_STAT_ADJUSTMENT_STORAGE_RESEARCH_V1',
            exact_build: '16.16.805.0442',
            corpus,
            replay_sha256: row.replay_sha256,
            replay_label: row.replay_label,
            replay_time_ms: row.replay_time_ms,
            entity_network_id: row.raw_param,
            entity_network_id_hex: row.raw_param_hex,
            outer_update_kind_plain_u8: outerKind,
            record_index: recordIndex,
            ...record,
            source_packet: {
              packet_id: row.packet_id,
              payload_length: row.payload_length,
              raw_payload_sha256: row.raw_payload_sha256,
              chunk_index: row.chunk_index,
              decompressed_block_offset: row.decompressed_block_offset,
            },
            decoder_evidence: {
              callback_receive_rva: '0x008cd3a0',
              plaintext_consumer_rva: '0x003958d0',
              record_decode_loop_rva: '0x00395980',
              plaintext_use_rva: '0x00395a96',
              lookup_table_rva: '0x01a41d00',
            },
          })}\n`);
        }
      }
    }
  } finally {
    await new Promise((resolve, reject) => {
      output.on('error', reject);
      output.end(resolve);
    });
  }
  return {
    output_path: path.relative(ROOT, outputPath),
    output_sha256: await sha256(outputPath),
    row_count: rowCount,
    exact_success_full_consume_count: fullConsumeCount,
    record_count: recordCount,
    finite_record_count: finiteRecordCount,
    corpus_row_counts: sortedCounter(corpusRows),
    replay_row_counts: sortedCounter(replayRows),
    entity_row_counts: sortedCounter(entityRows),
    record_length_counts: sortedCounter(recordLengths),
    outer_update_kind_counts: sortedCounter(outerKinds),
    adjustment_kind_counts: sortedCounter(adjustmentKinds),
    field_a_value_counts: sortedCounter(fieldValues.a),
    field_b_value_counts: sortedCounter(fieldValues.b),
    field_c_value_counts: sortedCounter(fieldValues.c),
    field_d_value_counts: sortedCounter(fieldValues.d),
    value_pattern_counts: sortedCounter(valuePatterns),
    standard_adjustment_count: standardAdjustmentCount,
    clear_sentinel_count: clearSentinelCount,
    unexplained_decoded_shape_count: unexplainedShapeCount,
    item_anchor_windows: windows,
    anchored_persistent_scalar_match_count: anchorScalarMatchCount,
    field_b_replay_time_delta_seconds: {
      count: timeDeltaCount,
      min: timeDeltaMin === Infinity ? null : timeDeltaMin,
      max: timeDeltaMax === -Infinity ? null : timeDeltaMax,
      mean_absolute: timeDeltaCount ? timeDeltaAbsSum / timeDeltaCount : null,
      within_one_ms_count: timeDeltaWithinOneMsCount,
      semantic_status: 'TIME_LIKE_COMPONENT_CANDIDATE_NOT_PROMOTED',
    },
    callback_receive_rva: '0x008cd3a0',
    plaintext_consumer_rva: '0x003958d0',
    field_roles: 'UNMAPPED_WITHIN_BUFF_STAT_ADJUSTMENT_ROUTE',
  };
}

async function analyzeHealthTicks(file, corpus, anchors) {
  const lengths = new Map();
  const payloadLengths = new Map();
  const windows = emptyWindowMetrics(anchors);
  let rowCount = 0;
  let fullConsumeCount = 0;
  let heroRowCount = 0;
  let heroNonemptyCount = 0;
  let nonheroNonemptyCount = 0;
  let min = Infinity;
  let max = -Infinity;
  for await (const row of readJsonl(file)) {
    rowCount += 1;
    fullConsumeCount += Number(row.fully_consumed && row.deserialize_return_al !== 0);
    increment(payloadLengths, row.payload_length);
    const records = row.decoded_fields.field_10_records;
    increment(lengths, records.length);
    const hero = isHeroNetworkId(row.raw_param);
    heroRowCount += Number(hero);
    heroNonemptyCount += Number(hero && records.length > 0);
    nonheroNonemptyCount += Number(!hero && records.length > 0);
    for (const record of records) {
      if (Number.isFinite(record.f32)) {
        min = Math.min(min, record.f32);
        max = Math.max(max, record.f32);
      }
    }
    for (const anchor of anchors) {
      if (row.replay_sha256 !== anchor.replay_sha256
          || row.raw_param !== anchor.network_id
          || row.replay_time_ms < anchor.frame_start_ms
          || row.replay_time_ms > anchor.frame_end_ms) continue;
      windows[anchor.role].row_count += 1;
      windows[anchor.role].nonempty_vector_row_count =
        (windows[anchor.role].nonempty_vector_row_count || 0) + Number(records.length > 0);
    }
  }
  return {
    corpus,
    source: path.relative(ROOT, file),
    row_count: rowCount,
    exact_success_full_consume_count: fullConsumeCount,
    payload_length_counts: sortedCounter(payloadLengths),
    vector_length_counts: sortedCounter(lengths),
    hero_network_id_row_count: heroRowCount,
    hero_nonempty_vector_row_count: heroNonemptyCount,
    nonhero_nonempty_vector_row_count: nonheroNonemptyCount,
    nonhero_tick_value_min: min === Infinity ? null : min,
    nonhero_tick_value_max: max === -Infinity ? null : max,
    item_anchor_windows: windows,
    direct_hero_state_carrier: heroNonemptyCount > 0,
  };
}

async function analyzeGenericRoute(file, corpus) {
  const payloadLengths = new Map();
  const streams = new Map();
  const replayCounts = new Map();
  let rowCount = 0;
  let fullConsumeCount = 0;
  let heroRowCount = 0;
  let heroGameChunkRowCount = 0;
  let heroPayloadAboveOneCount = 0;
  for await (const row of readJsonl(file)) {
    rowCount += 1;
    fullConsumeCount += Number(row.fully_consumed && row.deserialize_return_al !== 0);
    increment(payloadLengths, row.payload_length);
    increment(streams, row.chunk_stream);
    increment(replayCounts, row.replay_sha256);
    const hero = isHeroNetworkId(row.raw_param);
    heroRowCount += Number(hero);
    heroGameChunkRowCount += Number(hero && row.chunk_stream === 'game_chunk');
    heroPayloadAboveOneCount += Number(hero && row.payload_length > 1);
  }
  return {
    corpus,
    source: path.relative(ROOT, file),
    row_count: rowCount,
    exact_success_full_consume_count: fullConsumeCount,
    payload_length_counts: sortedCounter(payloadLengths),
    stream_counts: sortedCounter(streams),
    replay_counts: sortedCounter(replayCounts),
    hero_network_id_row_count: heroRowCount,
    hero_game_chunk_row_count: heroGameChunkRowCount,
    hero_payload_above_one_count: heroPayloadAboveOneCount,
  };
}

async function analyzeAttackSpeedOverrides(files, table, outputPath) {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  const output = fs.createWriteStream(outputPath, { encoding: 'utf8' });
  const corpusRows = new Map();
  const corpusPresentRows = new Map();
  const replayPresentRows = new Map();
  const entityPresentRows = new Map();
  const payloadLengths = new Map();
  const presenceCombinations = new Map();
  const payloadPresenceShapes = new Map();
  const field14Values = new Map();
  const field18Values = new Map();
  let rowCount = 0;
  let fullConsumeCount = 0;
  let presentRowCount = 0;
  let heroPresentRowCount = 0;
  let field18ClearSentinelCount = 0;
  let field18NinetyCount = 0;
  let bothEqualRampCount = 0;
  let unexplainedDecodedShapeCount = 0;
  let finiteField14Count = 0;
  let finiteField18Count = 0;
  let equalPresentValuesCount = 0;
  let field14Min = Infinity;
  let field14Max = -Infinity;
  let field18Min = Infinity;
  let field18Max = -Infinity;
  try {
    for (const { corpus, file } of files) {
      for await (const row of readJsonl(file)) {
        const decoded = decodeAttackSpeedObjectHex(row.object_hex, table);
        const presentCount = Number(decoded.field_14_present) + Number(decoded.field_18_present);
        const combination = `${Number(decoded.field_14_present)}${Number(decoded.field_18_present)}`;
        rowCount += 1;
        fullConsumeCount += Number(row.fully_consumed && row.deserialize_return_al !== 0);
        increment(corpusRows, corpus);
        increment(payloadLengths, row.payload_length);
        increment(presenceCombinations, combination);
        increment(payloadPresenceShapes, `${row.payload_length}:${combination}`);
        if (decoded.field_14_present) {
          increment(field14Values, round(decoded.field_14_plain_f32, 6));
          if (Number.isFinite(decoded.field_14_plain_f32)) {
            finiteField14Count += 1;
            field14Min = Math.min(field14Min, decoded.field_14_plain_f32);
            field14Max = Math.max(field14Max, decoded.field_14_plain_f32);
          }
        }
        if (decoded.field_18_present) {
          increment(field18Values, round(decoded.field_18_plain_f32, 6));
          if (Number.isFinite(decoded.field_18_plain_f32)) {
            finiteField18Count += 1;
            field18Min = Math.min(field18Min, decoded.field_18_plain_f32);
            field18Max = Math.max(field18Max, decoded.field_18_plain_f32);
          }
        }
        if (decoded.field_14_present && decoded.field_18_present) {
          equalPresentValuesCount += Number(
            Object.is(decoded.field_14_plain_f32, decoded.field_18_plain_f32),
          );
        }
        const field18Clear = row.payload_length === 1
          && combination === '01'
          && Object.is(decoded.field_18_plain_f32, -1);
        const field18Ninety = row.payload_length === 5
          && combination === '01'
          && Object.is(decoded.field_18_plain_f32, 90);
        const bothEqualRamp = row.payload_length === 9
          && combination === '11'
          && Object.is(decoded.field_14_plain_f32, decoded.field_18_plain_f32)
          && decoded.field_14_plain_f32 >= 0.625
          && decoded.field_14_plain_f32 <= 0.92;
        const empty = row.payload_length === 1 && combination === '00';
        field18ClearSentinelCount += Number(field18Clear);
        field18NinetyCount += Number(field18Ninety);
        bothEqualRampCount += Number(bothEqualRamp);
        unexplainedDecodedShapeCount += Number(
          !empty && !field18Clear && !field18Ninety && !bothEqualRamp,
        );
        if (presentCount === 0) continue;
        presentRowCount += 1;
        heroPresentRowCount += Number(isHeroNetworkId(row.raw_param));
        increment(corpusPresentRows, corpus);
        increment(replayPresentRows, row.replay_sha256);
        increment(entityPresentRows, row.raw_param_hex);
        output.write(`${JSON.stringify({
          schema_version: 1,
          event_type: 'ATTACK_SPEED_CAP_OVERRIDE_STORAGE_RESEARCH_V1',
          exact_build: '16.16.805.0442',
          corpus,
          replay_sha256: row.replay_sha256,
          replay_label: row.replay_label,
          replay_time_ms: row.replay_time_ms,
          entity_network_id: row.raw_param,
          entity_network_id_hex: row.raw_param_hex,
          ...decoded,
          source_packet: {
            packet_id: row.packet_id,
            payload_length: row.payload_length,
            raw_payload_sha256: row.raw_payload_sha256,
            chunk_index: row.chunk_index,
            decompressed_block_offset: row.decompressed_block_offset,
          },
          decoder_evidence: {
            runtime_type_name: 'PKT_S2C_UpdateAttackSpeedCapOverrides_s',
            callback_receive_rva: '0x002a6180',
            field_18_plaintext_loop_rva: '0x002a61e0',
            field_18_plaintext_use_rva: '0x002a6274',
            field_10_presence_table_rva: '0x01a27950',
            field_14_plaintext_loop_rva: '0x002a6331',
            field_14_plaintext_use_rva: '0x002a63c7',
          },
        })}\n`);
      }
    }
  } finally {
    await new Promise((resolve, reject) => {
      output.on('error', reject);
      output.end(resolve);
    });
  }
  return {
    output_path: path.relative(ROOT, outputPath),
    output_sha256: await sha256(outputPath),
    row_count: rowCount,
    exact_success_full_consume_count: fullConsumeCount,
    present_row_count: presentRowCount,
    hero_present_row_count: heroPresentRowCount,
    corpus_row_counts: sortedCounter(corpusRows),
    corpus_present_row_counts: sortedCounter(corpusPresentRows),
    replay_present_row_counts: sortedCounter(replayPresentRows),
    entity_present_row_counts: sortedCounter(entityPresentRows),
    payload_length_counts: sortedCounter(payloadLengths),
    presence_combination_counts: sortedCounter(presenceCombinations),
    payload_presence_shape_counts: sortedCounter(payloadPresenceShapes),
    field_18_clear_sentinel_count: field18ClearSentinelCount,
    field_18_90_value_count: field18NinetyCount,
    both_fields_equal_ramp_count: bothEqualRampCount,
    unexplained_decoded_shape_count: unexplainedDecodedShapeCount,
    field_14_value_counts: sortedCounter(field14Values),
    field_18_value_counts: sortedCounter(field18Values),
    field_14_finite_count: finiteField14Count,
    field_18_finite_count: finiteField18Count,
    field_14_min: field14Min === Infinity ? null : field14Min,
    field_14_max: field14Max === -Infinity ? null : field14Max,
    field_18_min: field18Min === Infinity ? null : field18Min,
    field_18_max: field18Max === -Infinity ? null : field18Max,
    both_present_equal_value_count: equalPresentValuesCount,
    callback_receive_rva: '0x002a6180',
    field_roles: 'UNMAPPED_WITHIN_ATTACK_SPEED_CAP_OVERRIDE_ROUTE',
  };
}

async function analyzeStatStoneWindows(file, anchors) {
  const windows = emptyWindowMetrics(anchors);
  let rowCount = 0;
  let fullConsumeCount = 0;
  for await (const row of readJsonl(file)) {
    rowCount += 1;
    fullConsumeCount += Number(row.fully_consumed && row.deserialize_return_al !== 0);
    for (const anchor of anchors) {
      if (row.replay_sha256 !== anchor.replay_sha256
          || row.raw_param !== anchor.network_id
          || row.replay_time_ms < anchor.frame_start_ms
          || row.replay_time_ms > anchor.frame_end_ms) continue;
      windows[anchor.role].row_count += 1;
    }
  }
  return {
    row_count: rowCount,
    exact_success_full_consume_count: fullConsumeCount,
    item_anchor_windows: windows,
  };
}

async function analyzeDeathTimers(files, anchor, outputPath) {
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  const output = fs.createWriteStream(outputPath, { encoding: 'utf8' });
  const timerCounts = new Map();
  const corpusCounts = new Map();
  const replayCounts = new Map();
  let rowCount = 0;
  let fullConsumeCount = 0;
  let finiteCount = 0;
  let heroCount = 0;
  let min = Infinity;
  let max = -Infinity;
  let closest = null;
  try {
    for (const { corpus, file } of files) {
      for await (const row of readJsonl(file)) {
        const seconds = decodeDeathTimerObjectHex(row.object_hex);
        const event = {
          schema_version: 1,
          event_type: 'HERO_DEATH_TIMER_UPDATE_RESEARCH_V1',
          exact_build: '16.16.805.0442',
          corpus,
          replay_sha256: row.replay_sha256,
          replay_label: row.replay_label,
          replay_time_ms: row.replay_time_ms,
          entity_network_id: row.raw_param,
          entity_network_id_hex: row.raw_param_hex,
          death_timer_seconds: seconds,
          source_packet: {
            packet_id: row.packet_id,
            payload_length: row.payload_length,
            raw_payload_sha256: row.raw_payload_sha256,
            chunk_index: row.chunk_index,
            decompressed_block_offset: row.decompressed_block_offset,
          },
          decoder_evidence: {
            runtime_type_name: 'PKT_S2C_UpdateDeathTimer_s',
            callback_receive_rva: '0x002a6460',
            callback_decode_loop_rva: '0x002a6480',
            callback_float_use_rva: '0x002a64aa',
          },
        };
        output.write(`${JSON.stringify(event)}\n`);
        rowCount += 1;
        fullConsumeCount += Number(row.fully_consumed && row.deserialize_return_al !== 0);
        increment(corpusCounts, corpus);
        increment(replayCounts, row.replay_sha256);
        increment(timerCounts, round(seconds, 6));
        if (Number.isFinite(seconds)) {
          finiteCount += 1;
          min = Math.min(min, seconds);
          max = Math.max(max, seconds);
        }
        heroCount += Number(isHeroNetworkId(row.raw_param));
        if (corpus === 'paired_p0'
            && row.replay_sha256 === anchor.replay_sha256
            && row.raw_param === anchor.network_id) {
          const delta = row.replay_time_ms - anchor.death_event_timestamp_ms;
          if (!closest || Math.abs(delta) < Math.abs(closest.timestamp_delta_ms)) {
            closest = { ...event, timestamp_delta_ms: delta };
          }
        }
      }
    }
  } finally {
    await new Promise((resolve, reject) => {
      output.on('error', reject);
      output.end(resolve);
    });
  }
  const anchorMatch = closest && Math.abs(closest.timestamp_delta_ms) <= 100
    ? {
      status: 'MATCH',
      death_anchor: anchor,
      packet_time_ms: closest.replay_time_ms,
      timestamp_delta_ms: closest.timestamp_delta_ms,
      death_timer_seconds: closest.death_timer_seconds,
      projected_timer_end_ms: closest.replay_time_ms + closest.death_timer_seconds * 1000,
      projected_end_inside_details_respawn_frame_bound:
        closest.replay_time_ms + closest.death_timer_seconds * 1000
          >= anchor.respawn_lower_bound_timestamp_ms
        && closest.replay_time_ms + closest.death_timer_seconds * 1000
          <= anchor.respawn_upper_bound_timestamp_ms,
      source_packet: closest.source_packet,
    }
    : { status: 'NO_MATCH_WITHIN_100_MS', closest };
  return {
    output_path: path.relative(ROOT, outputPath),
    output_sha256: await sha256(outputPath),
    row_count: rowCount,
    exact_success_full_consume_count: fullConsumeCount,
    finite_timer_count: finiteCount,
    hero_network_id_row_count: heroCount,
    corpus_counts: sortedCounter(corpusCounts),
    replay_counts: sortedCounter(replayCounts),
    timer_seconds_counts: sortedCounter(timerCounts),
    timer_seconds_min: min,
    timer_seconds_max: max,
    p0_death_anchor_match: anchorMatch,
    semantic_status: 'RESEARCH_PROMOTION_RECOMMENDED',
  };
}

function damageStageAnalysis(validation, anchorMatch) {
  const residuals = validation.matches.map((match) => match.amount_delta_from_details);
  const absolute = residuals.map(Math.abs);
  const mean = absolute.reduce((sum, value) => sum + value, 0) / absolute.length;
  const deathDamage = validation.matches.find(
    (match) => match.timestamp_ms === anchorMatch.death_anchor.death_event_timestamp_ms
      && match.target_participant_id === anchorMatch.death_anchor.participant_id,
  );
  return {
    exact_build: validation.exact_build,
    decoded_row_count: validation.decoded_row_count,
    details_anchor_count: validation.details_anchor_count,
    matched_anchor_count: validation.matched_anchor_count,
    damage_type_match_counts: validation.damage_type_match_counts,
    damage_type_mismatch_count: validation.damage_type_mismatch_count,
    recorded_component_residual: {
      status: 'COMPUTABLE',
      sample_count: residuals.length,
      mean_absolute_residual: mean,
      max_absolute_residual: Math.max(...absolute),
      residuals,
      interpretation: 'The decoded float tracks the integer DETAILS damage component to rounding precision.',
    },
    effective_hp_loss_residual: {
      status: 'NOT_COMPUTABLE',
      reason: 'DETAILS HP is a minute-frame snapshot and provides no same-timestamp pre/post HP pair; shields, regeneration, healing, and death reset are unobserved between frames.',
    },
    pre_mitigation_residual: {
      status: 'NOT_COMPUTABLE',
      reason: 'No exact-timestamp unmitigated attack/spell magnitude is present in the bounded Replay evidence.',
    },
    post_mitigation_stage_test: {
      status: 'UNDERDETERMINED',
      reason: 'Matching a reported damage component does not distinguish post-mitigation, displayed, or effective HP-loss semantics without a same-timestamp HP delta or raw pre-mitigation amount.',
    },
    static_handler_trace: {
      callback_receive_rva: '0x002a7fa0',
      recorded_amount_field_offset: '0x24',
      optional_secondary_amount_field_offset: '0x2c',
      combined_amount_rva: '0x002a812f',
      downstream_call_rva: '0x0026d260',
      target_virtual_slot: '0x720',
      conclusion: 'The client consumes the decoded amount, but this control flow does not label the mitigation/effective-HP stage.',
    },
    death_anchor_coincidence: deathDamage ? {
      damage_packet_time_ms: deathDamage.replay_packet_time_ms,
      death_timer_packet_time_ms: anchorMatch.packet_time_ms,
      same_packet_time: deathDamage.replay_packet_time_ms === anchorMatch.packet_time_ms,
      recorded_amount: deathDamage.recorded_amount,
      details_amount: deathDamage.details_amount,
      damage_type: deathDamage.damage_type,
    } : null,
    amount_semantic_stage: 'RECORDED_COMPONENT_STAGE_UNKNOWN',
    promotion_recommended: false,
  };
}

async function sha256(file) {
  const hash = crypto.createHash('sha256');
  await new Promise((resolve, reject) => {
    const input = fs.createReadStream(file);
    input.on('data', (chunk) => hash.update(chunk));
    input.on('end', resolve);
    input.on('error', reject);
  });
  return hash.digest('hex');
}

function renderMarkdown(report) {
  const formula = report.routes['0x042f_stat_formula_outputs'];
  const death = report.routes['0x0074_update_death_timer'];
  const buffAdjustments = report.routes['0x0412_buff_update_stat_adjustments'];
  const attackSpeed = report.routes['0x00dd_attack_speed_cap_overrides'];
  const route0474 = report.routes['0x0474_champion_specific_negative_control'];
  const route02d4 = report.routes['0x02d4_auxiliary_batch_negative_control'];
  const heroStats = report.routes['0x010c_hero_stats_negative_control'];
  const damage = report.damage_stage;
  return `# Hero state + damage/defense deep recovery — 16.16.805.0442

Status: **${report.status}**

## Outcome

- CURRENT_HP / MAX_HP / ARMOR / MAGIC_RESIST / current resource remain unavailable from the bounded Replay packet evidence.
- Opcode 0x0074 is a positive exact-build recovery: ${death.combined.row_count} death-timer updates decode to finite seconds. The Talon death anchor matches at +${death.combined.p0_death_anchor_match.timestamp_delta_ms} ms with ${death.combined.p0_death_anchor_match.death_timer_seconds} seconds.
- The 0x017f amount remains a recorded damage component with unknown pre/post-mitigation or effective-HP stage.

## Exhausted candidate evidence

- 0x042f: ${formula.combined_row_count} exact full-consume rows across eight safe replays; every vector is four coefficients in [${formula.value_min}, ${formula.value_max}], with zero nontrivial P0 scalar matches.
- 0x010c: ${heroStats.latest_four_full_corpus.event_count} exact full-consume, keyframe-only rows across the latest four safe replays; the independent cross-check classifies this route as cumulative scoreboard statistics, not live HP/defense/resource state.
- 0x01dc: ${report.routes['0x01dc_replicate_fields'].combined_row_count} exact rows; all decoded value vectors are empty.
- 0x0259 / 0x03f8 / 0x04df: zero rows in both the latest-four and four paired P0 corpora.
- 0x02cf: hero rows are present but ${report.routes['0x02cf_health_bar_variable_ticks'].combined_hero_nonempty_vector_row_count} carry a nonempty tick vector; nonempty vectors belong to non-hero health-bar presentation objects.
- 0x03dc: exact RTTI and three captured union tags classify it as historical StatStone deltas, not live combat state.
- 0x0412 exact consumer inversion recovers ${buffAdjustments.exact_plaintext_recovery.record_count} transient buff-stat adjustment records with ${buffAdjustments.exact_plaintext_recovery.unexplained_decoded_shape_count} unexplained decoded shapes and zero persistent-item-anchor scalar matches; its neutral field roles remain unmapped.
- 0x00dd exact callback inversion recovers ${attackSpeed.exact_plaintext_recovery.present_row_count} temporary attack-speed-cap override updates with ${attackSpeed.exact_plaintext_recovery.unexplained_decoded_shape_count} unexplained decoded shapes; both float roles remain unmapped, so this is research evidence rather than a canonical stat field.
- 0x0345 has zero canonical hero network-id rows in both corpora.
- 0x02d4 is a full latest-four negative control: ${route02d4.event_count} rows form ${route02d4.timestamp_group_count} variable-cardinality timestamp groups, including ${route02d4.groups_without_damage} groups without Damage and groups as large as ${route02d4.maximum_group_size}; this rejects a direct Damage/HP/defense/resource/entity-scalar interpretation.
- 0x0474 is a strong cross-replay negative control: ${route0474.event_count} exact latest-four rows are ${round(route0474.dominant_champion_event_rate * 100, 4)}% concentrated on Zilean, and every dominant row has the same payload. This rejects a general volatile hero-state scalar without assigning a positive semantic.

## Damage-stage residual

- Recorded-component residual: n=${damage.recorded_component_residual.sample_count}, max absolute ${round(damage.recorded_component_residual.max_absolute_residual, 6)}.
- Effective HP-loss residual: ${damage.effective_hp_loss_residual.status}.
- Pre-mitigation residual: ${damage.pre_mitigation_residual.status}.
- Promotion: ${damage.promotion_recommended ? 'yes' : 'no'}; stage remains ${damage.amount_semantic_stage}.

## Promotion decision

- Persistent HP/defense/resource fields: **NO PROMOTION**.
- 0x017f amount-stage label: **NO PROMOTION**.
- Research-only 0x0074 death timer event: **PROMOTION RECOMMENDED**, without changing the canonical schema or public capability manifest in this branch.
- Research-only 0x0412 neutral-field decoder: **PROMOTION RECOMMENDED**; the four field-role names remain **NO PROMOTION**.
- Research-only 0x00dd neutral-field decoder: **PROMOTION RECOMMENDED**; the two field-role names remain **NO PROMOTION**.
`;
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const detailsManifest = readJson(PATHS.detailsManifest);
  const inventory = readJson(PATHS.inventoryCrosscheck);
  const damageValidation = readJson(PATHS.damageValidation);
  const latestManifest = readJson(PATHS.latestManifest);
  const p0Manifest = readJson(PATHS.p0Manifest);
  const statStoneLatest = readJson(PATHS.statStoneLatestSummary);
  const statStoneP0 = readJson(PATHS.statStoneP0Summary);
  const route0474Audit = readJson(PATHS.route0474Audit);
  const route02d4Audit = readJson(PATHS.route02d4Audit);
  const heroStatsCrossCheck = readJson(PATHS.heroStatsCrossCheck);
  const heroStatsLatestSummary = readJson(PATHS.heroStatsLatestSummary);
  const runtimeImage = fs.readFileSync(PATHS.runtimeImage);
  const attackSpeedPresenceTable = Buffer.from(runtimeImage.subarray(
    ATTACK_SPEED_PRESENCE_TABLE_RVA,
    ATTACK_SPEED_PRESENCE_TABLE_RVA + 0x100,
  ));
  if (attackSpeedPresenceTable.length !== 0x100) {
    throw new Error('runtime image does not contain the 0x00dd presence lookup table');
  }
  const buffAdjustmentTable = Buffer.from(runtimeImage.subarray(
    BUFF_ADJUSTMENT_TABLE_RVA,
    BUFF_ADJUSTMENT_TABLE_RVA + 0x100,
  ));
  if (buffAdjustmentTable.length !== 0x100) {
    throw new Error('runtime image does not contain the 0x0412 adjustment lookup table');
  }
  const anchors = itemAnchors(detailsManifest);
  const death = deathAnchor(detailsManifest);

  let anchorRecordCount = 0;
  const anchoredValues = new Set();
  for await (const row of readJsonl(PATHS.detailsAnchors)) {
    anchorRecordCount += 1;
    for (const field of ['current_hp', 'max_hp', 'armor', 'magic_resist']) {
      if (Number.isFinite(row[field]) && row[field] > 1.06) anchoredValues.add(String(round(row[field], 6)));
    }
  }

  const [
    formulaLatest,
    formulaP0,
    replicateP0,
    adjustmentsLatest,
    adjustmentsP0,
    healthTicksLatest,
    healthTicksP0,
    showHealthLatest,
    showHealthP0,
    attackSpeedLatest,
    attackSpeedP0,
    npcLevelLatest,
    npcLevelP0,
    statStoneWindows,
  ] = await Promise.all([
    analyzeFormulaCorpus(PATHS.formulaLatest, 'latest_four', anchors, anchoredValues),
    analyzeFormulaCorpus(PATHS.formulaP0, 'paired_p0', anchors, anchoredValues),
    analyzeReplicateFields(PATHS.replicateP0),
    analyzeAdjustments(PATHS.adjustmentsLatest, 'latest_four', anchors),
    analyzeAdjustments(PATHS.adjustmentsP0, 'paired_p0', anchors),
    analyzeHealthTicks(PATHS.healthTicksLatest, 'latest_four', anchors),
    analyzeHealthTicks(PATHS.healthTicksP0, 'paired_p0', anchors),
    analyzeGenericRoute(PATHS.showHealthLatest, 'latest_four'),
    analyzeGenericRoute(PATHS.showHealthP0, 'paired_p0'),
    analyzeGenericRoute(PATHS.attackSpeedLatest, 'latest_four'),
    analyzeGenericRoute(PATHS.attackSpeedP0, 'paired_p0'),
    analyzeGenericRoute(PATHS.npcLevelLatest, 'latest_four'),
    analyzeGenericRoute(PATHS.npcLevelP0, 'paired_p0'),
    analyzeStatStoneWindows(PATHS.statStoneP0, anchors),
  ]);

  const [deathTimers, attackSpeedOverrides, buffAdjustmentsExact] = await Promise.all([
    analyzeDeathTimers([
      { corpus: 'latest_four', file: PATHS.deathTimerLatest },
      { corpus: 'paired_p0', file: PATHS.deathTimerP0 },
    ], death, options.deathEvents),
    analyzeAttackSpeedOverrides([
      { corpus: 'latest_four', file: PATHS.attackSpeedLatest },
      { corpus: 'paired_p0', file: PATHS.attackSpeedP0 },
    ], attackSpeedPresenceTable, options.attackSpeedEvents),
    analyzeBuffAdjustmentsExact([
      { corpus: 'latest_four', file: PATHS.adjustmentsLatest },
      { corpus: 'paired_p0', file: PATHS.adjustmentsP0 },
    ], buffAdjustmentTable, anchors, options.buffAdjustmentEvents),
  ]);
  const damageStage = damageStageAnalysis(
    damageValidation,
    deathTimers.p0_death_anchor_match,
  );

  const formulaCombinedPatterns = new Map();
  for (const result of [formulaLatest, formulaP0]) {
    for (const [key, count] of Object.entries(result.value_pattern_counts)) {
      increment(formulaCombinedPatterns, key, count);
    }
  }
  const formulaCombinedRows = formulaLatest.row_count + formulaP0.row_count;
  const formula = {
    runtime_type_name: 'PKT_S2C_StatFormulaOutputs_s',
    latest_four: formulaLatest,
    paired_p0: formulaP0,
    combined_row_count: formulaCombinedRows,
    combined_exact_success_full_consume_count:
      formulaLatest.exact_success_full_consume_count + formulaP0.exact_success_full_consume_count,
    combined_value_pattern_counts: sortedCounter(formulaCombinedPatterns),
    value_min: Math.min(formulaLatest.value_min, formulaP0.value_min),
    value_max: Math.max(formulaLatest.value_max, formulaP0.value_max),
    combined_anchored_nontrivial_scalar_match_count:
      formulaLatest.anchored_nontrivial_scalar_match_count
      + formulaP0.anchored_nontrivial_scalar_match_count,
    direct_hp_defense_resource_carrier: false,
    classification: 'BOUNDED_FORMULA_COEFFICIENT_OUTPUT',
  };

  const zeroRoutes = Object.fromEntries(['0x0259', '0x03f8', '0x04df'].map((route) => [route, {
    latest_four_count: inventory.routes[route].count,
    paired_p0_count: p0Manifest.packet_counts[String(Number.parseInt(route, 16))] || 0,
  }]));

  const hashes = {};
  for (const [name, file] of Object.entries({
    runtime_image: PATHS.runtimeImage,
    details_manifest: PATHS.detailsManifest,
    details_anchors: PATHS.detailsAnchors,
    inventory_crosscheck: PATHS.inventoryCrosscheck,
    damage_validation: PATHS.damageValidation,
    latest_export_manifest: PATHS.latestManifest,
    p0_export_manifest: PATHS.p0Manifest,
    formula_latest_summary: `${PATHS.formulaLatest.replace(/\.jsonl$/, '')}.summary.json`,
    formula_p0_summary: `${PATHS.formulaP0.replace(/\.jsonl$/, '')}.summary.json`,
    stat_stone_latest_summary: PATHS.statStoneLatestSummary,
    stat_stone_p0_summary: PATHS.statStoneP0Summary,
    route_0474_champion_specific_audit: PATHS.route0474Audit,
    route_02d4_auxiliary_batch_audit: PATHS.route02d4Audit,
    route_010c_hero_stats_cross_check: PATHS.heroStatsCrossCheck,
    route_010c_latest_four_summary: PATHS.heroStatsLatestSummary,
    profile_0074: path.join(ARTIFACT_DIR, 'profiles', 'packet_0074.json'),
    profile_00d2: path.join(ARTIFACT_DIR, 'profiles', 'packet_00d2.json'),
    profile_00dd: path.join(ARTIFACT_DIR, 'profiles', 'packet_00dd.json'),
    profile_02cf: path.join(ARTIFACT_DIR, 'profiles', 'packet_02cf.json'),
    profile_0345: path.join(ARTIFACT_DIR, 'profiles', 'packet_0345.json'),
    profile_03dc: path.join(ARTIFACT_DIR, 'profiles', 'packet_03dc.json'),
    summary_0074_latest: `${PATHS.deathTimerLatest.replace(/\.jsonl$/, '')}.summary.json`,
    summary_0074_p0: `${PATHS.deathTimerP0.replace(/\.jsonl$/, '')}.summary.json`,
    summary_00d2_latest: `${PATHS.showHealthLatest.replace(/\.jsonl$/, '')}.summary.json`,
    summary_00d2_p0: `${PATHS.showHealthP0.replace(/\.jsonl$/, '')}.summary.json`,
    summary_00dd_latest: `${PATHS.attackSpeedLatest.replace(/\.jsonl$/, '')}.summary.json`,
    summary_00dd_p0: `${PATHS.attackSpeedP0.replace(/\.jsonl$/, '')}.summary.json`,
    summary_01dc_p0: `${PATHS.replicateP0.replace(/\.jsonl$/, '')}.summary.json`,
    summary_02cf_latest: `${PATHS.healthTicksLatest.replace(/\.jsonl$/, '')}.summary.json`,
    summary_02cf_p0: `${PATHS.healthTicksP0.replace(/\.jsonl$/, '')}.summary.json`,
    summary_0345_latest: `${PATHS.npcLevelLatest.replace(/\.jsonl$/, '')}.summary.json`,
    summary_0345_p0: `${PATHS.npcLevelP0.replace(/\.jsonl$/, '')}.summary.json`,
    summary_0412_p0: `${PATHS.adjustmentsP0.replace(/\.jsonl$/, '')}.summary.json`,
    runtime_0412_callback_disassembly: path.join(
      ARTIFACT_DIR,
      'runtime_0412_callback_disassembly.json',
    ),
    runtime_0412_adjustment_consumer_disassembly: path.join(
      ARTIFACT_DIR,
      'runtime_0412_adjustment_consumer_disassembly.json',
    ),
    runtime_priority_callbacks_disassembly: path.join(
      ARTIFACT_DIR,
      'runtime_priority_callbacks_disassembly.json',
    ),
    runtime_damage_callback_disassembly: path.join(
      ARTIFACT_DIR,
      'runtime_damage_callback_disassembly.json',
    ),
    analysis_script: __filename,
  })) hashes[name] = { path: path.relative(ROOT, file), sha256: await sha256(file) };

  const report = {
    schema: 'ROFL_FULL_SEMANTIC_DEEP_RECOVERY_HERO_STATE_DAMAGE_DEFENSE_V2',
    schema_version: 2,
    status: 'SATURATED_NO_PERSISTENT_STATE_PROMOTION',
    exact_build: '16.16.805.0442',
    project_context_loaded: true,
    architecture_gate: 'PASS',
    scope: {
      owner: 'ROFL binary feasibility probe',
      parser_boundary_respected: true,
      network_acquisition_performed: false,
      protected_corpus_accessed: false,
      public_manifest_or_schema_modified: false,
    },
    corpus: {
      latest_four_replay_count: latestManifest.replay_count,
      latest_four_replay_sha256: latestManifest.replays.map((replay) => replay.sha256),
      paired_p0_replay_count: p0Manifest.replay_count,
      paired_p0_replay_sha256: p0Manifest.replays.map((replay) => replay.sha256),
      p0_anchor_record_count: anchorRecordCount,
      safe_replay_total: latestManifest.replay_count + p0Manifest.replay_count,
      parser_error_count:
        latestManifest.replays.reduce((sum, replay) => sum + replay.parser_error_count, 0)
        + p0Manifest.replays.reduce((sum, replay) => sum + replay.parser_error_count, 0),
    },
    p0_item_anchors: anchors,
    routes: {
      '0x010c_hero_stats_negative_control': {
        runtime_type_name: 'PKT_S2C_HeroStats_s',
        source: path.relative(ROOT, PATHS.heroStatsCrossCheck),
        exact_build: heroStatsCrossCheck.exact_build,
        route_role: heroStatsCrossCheck.route_role,
        known_route_semantics: heroStatsCrossCheck.known_route_semantics,
        excluded_from_combat_state_ranking:
          heroStatsCrossCheck.excluded_from_combat_state_ranking,
        independent_cross_check: {
          decoded_source_row_count: heroStatsCrossCheck.decoded_source_row_count,
          decoded_source_full_consume_count:
            heroStatsCrossCheck.decoded_source_full_consume_count,
          replay_count: heroStatsCrossCheck.input_coverage.length,
          snapshot_cadence_ms: 'APPROXIMATELY_60000',
          field_semantic_status: heroStatsCrossCheck.field_semantic_status,
          semantic_claim: heroStatsCrossCheck.semantic_claim,
        },
        latest_four_full_corpus: {
          event_count: heroStatsLatestSummary.event_count,
          exact_success_full_consume_count:
            heroStatsLatestSummary.successful_full_consume_count,
          payload_length_counts: heroStatsLatestSummary.payload_length_counts,
          stream_counts: heroStatsLatestSummary.stream_counts,
          replay_event_counts: heroStatsLatestSummary.replay_event_counts,
        },
        classification: 'CUMULATIVE_SCOREBOARD_SNAPSHOT_NEGATIVE_CONTROL',
        direct_live_hp_defense_resource_carrier: false,
      },
      '0x042f_stat_formula_outputs': formula,
      '0x01dc_replicate_fields': {
        runtime_type_name: 'PKT_S2C_ReplicateFields_s',
        latest_four: inventory.routes['0x01dc'],
        paired_p0: replicateP0,
        combined_row_count: inventory.routes['0x01dc'].count + replicateP0.row_count,
        direct_hp_defense_resource_carrier: false,
      },
      '0x0412_buff_update_stat_adjustments': {
        runtime_type_name: 'PKT_NPC_BuffUpdateStatAdjustments_s',
        latest_four: adjustmentsLatest,
        paired_p0: adjustmentsP0,
        combined_row_count: adjustmentsLatest.row_count + adjustmentsP0.row_count,
        exact_plaintext_recovery: buffAdjustmentsExact,
        classification: 'TRANSIENT_BUFF_STAT_ADJUSTMENT_NEUTRAL_FIELDS_RECOVERED',
        persistent_hp_defense_carrier: false,
        research_decoder_promotion_recommended: true,
        field_role_promotion_recommended: false,
      },
      '0x03dc_stat_stone_game_delta': {
        runtime_type_name: 'PKT_S2C_UpdateStatStoneGameDelta_s',
        latest_four: statStoneLatest,
        paired_p0: statStoneP0,
        paired_p0_item_anchor_windows: statStoneWindows.item_anchor_windows,
        combined_row_count: statStoneLatest.event_count + statStoneP0.event_count,
        classification: 'HISTORICAL_STAT_STONE_DELTA_NOT_LIVE_COMBAT_STATE',
        direct_hp_defense_resource_carrier: false,
      },
      '0x0259_03f8_04df_absence': zeroRoutes,
      '0x0074_update_death_timer': {
        runtime_type_name: 'PKT_S2C_UpdateDeathTimer_s',
        object_size: 20,
        field: {
          offset: 16,
          storage_type: 'protected_f32',
          semantic_name: 'death_timer_seconds',
          callback_receive_rva: '0x002a6460',
        },
        combined: deathTimers,
        persistent_hp_defense_carrier: false,
      },
      '0x00d2_show_health_bar': {
        runtime_type_name: 'PKT_S2C_ShowHealthBar_s',
        latest_four: showHealthLatest,
        paired_p0: showHealthP0,
        combined_row_count: showHealthLatest.row_count + showHealthP0.row_count,
        payload_semantics: 'ONE_BYTE_VISIBILITY_TOGGLE',
        hp_scalar_present: false,
      },
      '0x02cf_health_bar_variable_ticks': {
        runtime_type_name: 'PKT_S2C_OnSetHealthBarVariableTicks_s',
        latest_four: healthTicksLatest,
        paired_p0: healthTicksP0,
        combined_row_count: healthTicksLatest.row_count + healthTicksP0.row_count,
        combined_hero_nonempty_vector_row_count:
          healthTicksLatest.hero_nonempty_vector_row_count
          + healthTicksP0.hero_nonempty_vector_row_count,
        classification: 'NONHERO_HEALTH_BAR_PRESENTATION_TICKS',
        direct_hp_scalar_present: false,
      },
      '0x00dd_attack_speed_cap_overrides': {
        runtime_type_name: 'PKT_S2C_UpdateAttackSpeedCapOverrides_s',
        latest_four: attackSpeedLatest,
        paired_p0: attackSpeedP0,
        combined_row_count: attackSpeedLatest.row_count + attackSpeedP0.row_count,
        exact_plaintext_recovery: attackSpeedOverrides,
        object_layout: {
          field_10: 'protected optional-presence byte',
          field_14: 'protected f32 override',
          field_18: 'protected f32 override',
          field_1c: 'protected optional-presence byte',
        },
        classification: 'TRANSIENT_ATTACK_SPEED_CAP_OVERRIDE',
        persistent_hp_defense_carrier: false,
        research_decoder_promotion_recommended: true,
        field_role_promotion_recommended: false,
      },
      '0x0345_npc_level_up_global': {
        runtime_type_name: 'PKT_NPC_LevelUp_Global_s',
        latest_four: npcLevelLatest,
        paired_p0: npcLevelP0,
        combined_row_count: npcLevelLatest.row_count + npcLevelP0.row_count,
        combined_hero_network_id_row_count:
          npcLevelLatest.hero_network_id_row_count + npcLevelP0.hero_network_id_row_count,
        classification: 'NPC_ONLY_IN_BOUNDED_CORPORA',
        hero_level_carrier: false,
      },
      '0x02d4_auxiliary_batch_negative_control': {
        source: path.relative(ROOT, PATHS.route02d4Audit),
        exact_build: route02d4Audit.exact_build,
        event_count: route02d4Audit.counts.event_count,
        replay_count: route02d4Audit.counts.replay_count,
        timestamp_group_count: route02d4Audit.counts.timestamp_group_count,
        groups_without_damage: route02d4Audit.counts.groups_without_damage,
        groups_without_damage_rate: route02d4Audit.counts.groups_without_damage_rate,
        maximum_group_size: route02d4Audit.counts.maximum_group_size,
        giant_group_at_least_100_rows_count:
          route02d4Audit.counts.giant_group_at_least_100_rows_count,
        recovered_bounded_structure: route02d4Audit.recovered_bounded_structure,
        rejected_hypotheses: route02d4Audit.negative_evidence.rejected_hypotheses,
        sampled_raw_param_matches_damage_source_or_target_within_10ms_rate:
          route02d4Audit.negative_evidence.evidence
            .sampled_raw_param_matches_damage_source_or_target_within_10ms_rate,
        direct_damage_semantic_rejected:
          route02d4Audit.validations.direct_damage_semantic_rejected,
        direct_entity_scalar_semantic_rejected:
          route02d4Audit.validations.direct_entity_scalar_semantic_rejected,
        classification: route02d4Audit.route_decisions[0].hypothesis,
        evidence_grade: route02d4Audit.route_decisions[0].evidence_grade,
        positive_semantic_claim: null,
      },
      '0x0474_champion_specific_negative_control': {
        source: path.relative(ROOT, PATHS.route0474Audit),
        exact_build: route0474Audit.exact_build,
        event_count: route0474Audit.counts.event_count,
        replay_count: route0474Audit.counts.replay_count,
        covered_replay_participant_slots: route0474Audit.counts.covered_replay_participant_slots,
        total_roster_participant_slots: route0474Audit.counts.total_roster_participant_slots,
        dominant_champion: route0474Audit.dominant_behavior.champion,
        dominant_champion_event_count: route0474Audit.dominant_behavior.event_count,
        dominant_champion_event_rate: route0474Audit.dominant_behavior.event_rate,
        dominant_payload_hex: route0474Audit.dominant_behavior.top_payload_hex,
        dominant_payload_rate: route0474Audit.dominant_behavior.top_payload_rate_within_dominant_champion,
        counterexample_count: route0474Audit.route_decisions[0].counterexample_count,
        rejected_hypotheses: route0474Audit.negative_evidence.rejected_hypotheses,
        general_hero_persistent_state_hypothesis_rejected:
          route0474Audit.validations.general_hero_persistent_state_hypothesis_rejected,
        classification: route0474Audit.route_decisions[0].hypothesis,
        evidence_grade: route0474Audit.route_decisions[0].evidence_grade,
        positive_semantic_claim: null,
      },
    },
    damage_stage: damageStage,
    semantic_availability: {
      current_hp: 'UNAVAILABLE',
      max_hp: 'UNAVAILABLE',
      armor: 'UNAVAILABLE',
      magic_resist: 'UNAVAILABLE',
      current_resource: 'UNAVAILABLE',
      temporary_stat_adjustments: 'RESEARCH_VALUES_RECOVERED_FIELD_ROLES_UNMAPPED',
      temporary_attack_speed_cap_overrides: 'RESEARCH_VALUES_RECOVERED_FIELD_ROLES_UNMAPPED',
      death_timer_seconds: 'RESEARCH_PROMOTION_RECOMMENDED',
      damage_recorded_amount: 'AVAILABLE_STAGE_UNKNOWN',
    },
    promotion_decision: {
      persistent_hero_state: 'NO_PROMOTION',
      damage_amount_stage: 'NO_PROMOTION',
      death_timer_research_event: 'PROMOTION_RECOMMENDED',
      buff_stat_adjustment_research_decoder: 'PROMOTION_RECOMMENDED',
      buff_stat_adjustment_field_roles: 'NO_PROMOTION',
      attack_speed_cap_override_research_decoder: 'PROMOTION_RECOMMENDED',
      attack_speed_cap_override_field_roles: 'NO_PROMOTION',
      reason: 'Death-timer seconds has an exact callback decode plus a direct P0 event anchor. Routes 0x0412 and 0x00dd have exact neutral-field plaintext recovery, but need controlled evidence to name their component roles. No bounded route yields current HP/max HP/armor/MR/resource state.',
    },
    route_decisions: [
      {
        packet_discriminator: '0x010c',
        candidate: 'LIVE_HERO_HP_DEFENSE_RESOURCE_STATE',
        decision: 'REPURPOSE',
        resulting_classification: 'CUMULATIVE_SCOREBOARD_SNAPSHOT_NEGATIVE_CONTROL',
        evidence_exhausted: true,
        next_required_evidence: [],
      },
      {
        packet_discriminator: '0x01dc',
        candidate: 'REPLICATED_HERO_STATE_FIELDS',
        decision: 'REJECT',
        reason: 'All 26,507 bounded exact rows decode to empty/zero field vectors.',
        evidence_exhausted: true,
        next_required_evidence: [
          'A safe exact-build occurrence with a nonempty field-value vector.',
        ],
      },
      {
        packet_discriminator: '0x042f',
        candidate: 'DIRECT_HP_DEFENSE_RESOURCE_SCALARS',
        decision: 'REPURPOSE',
        resulting_classification: 'BOUNDED_FORMULA_COEFFICIENT_OUTPUT',
        evidence_exhausted: true,
        next_required_evidence: [
          'A controlled formula-input/output calibration is required only to name coefficient roles, not to revive the rejected direct-state hypothesis.',
        ],
      },
      {
        packet_discriminator: '0x0412',
        candidate: 'NEUTRAL_STRUCTURAL_PLAINTEXT_DECODER',
        decision: 'PROMOTE',
        promotion_scope: 'RESEARCH_EXACT_BUILD_ONLY',
        promoted_fields: [
          'adjustment_kind_plain_u8',
          'field_a_plain_f32',
          'field_b_plain_f32',
          'field_c_plain_f32',
          'field_d_plain_f32',
        ],
        evidence_exhausted: true,
        next_required_evidence: [],
      },
      {
        packet_discriminator: '0x0412',
        candidate: 'NAMED_BUFF_STAT_ADJUSTMENT_FIELD_ROLES',
        decision: 'KEEP_CANDIDATE',
        evidence_exhausted: false,
        next_required_evidence: [
          'A controlled safe replay with a known timed buff/stat override and exact before/after stat samples.',
        ],
      },
      {
        packet_discriminator: '0x0259',
        candidate: 'COMBAT_STATE_CHANGED_HERO_STATE_CARRIER',
        decision: 'REJECT',
        reason: 'Zero occurrences in all eight bounded safe replays.',
        evidence_exhausted: true,
        next_required_evidence: ['A safe exact-build replay containing this route.'],
      },
      {
        packet_discriminator: '0x03f8',
        candidate: 'ABILITY_RESOURCE_STATE_CARRIER',
        decision: 'REJECT',
        reason: 'Zero occurrences in all eight bounded safe replays.',
        evidence_exhausted: true,
        next_required_evidence: ['A safe exact-build replay containing this route.'],
      },
      {
        packet_discriminator: '0x04df',
        candidate: 'SINGLE_REPLICATE_FIELD_STATE_CARRIER',
        decision: 'REJECT',
        reason: 'Zero occurrences in all eight bounded safe replays.',
        evidence_exhausted: true,
        next_required_evidence: ['A safe exact-build replay containing this route.'],
      },
      {
        packet_discriminator: '0x03dc',
        candidate: 'LIVE_HP_DEFENSE_RESOURCE_STATE',
        decision: 'REPURPOSE',
        resulting_classification: 'HISTORICAL_STAT_STONE_DELTA',
        evidence_exhausted: true,
        next_required_evidence: [],
      },
      {
        packet_discriminator: '0x0074',
        candidate: 'DEATH_TIMER_SECONDS',
        decision: 'PROMOTE',
        promotion_scope: 'RESEARCH_EXACT_BUILD_ONLY',
        evidence_exhausted: true,
        next_required_evidence: [],
      },
      {
        packet_discriminator: '0x00d2',
        candidate: 'CURRENT_OR_MAX_HP_SCALAR',
        decision: 'REPURPOSE',
        resulting_classification: 'ONE_BYTE_HEALTH_BAR_VISIBILITY_TOGGLE',
        evidence_exhausted: true,
        next_required_evidence: [],
      },
      {
        packet_discriminator: '0x02cf',
        candidate: 'HERO_HP_SCALAR',
        decision: 'REPURPOSE',
        resulting_classification: 'NONHERO_HEALTH_BAR_PRESENTATION_TICKS',
        evidence_exhausted: true,
        next_required_evidence: [],
      },
      {
        packet_discriminator: '0x00dd',
        candidate: 'NEUTRAL_STRUCTURAL_PLAINTEXT_DECODER',
        decision: 'PROMOTE',
        promotion_scope: 'RESEARCH_EXACT_BUILD_ONLY',
        promoted_fields: [
          'field_14_present',
          'field_18_present',
          'field_14_plain_f32',
          'field_18_plain_f32',
        ],
        evidence_exhausted: true,
        next_required_evidence: [],
      },
      {
        packet_discriminator: '0x00dd',
        candidate: 'NAMED_ATTACK_SPEED_CAP_OVERRIDE_FIELD_ROLES',
        decision: 'KEEP_CANDIDATE',
        evidence_exhausted: false,
        next_required_evidence: [
          'A controlled exact-build replay that independently toggles each override component and records the resulting client-visible cap behavior.',
        ],
      },
      {
        packet_discriminator: '0x0345',
        candidate: 'HERO_LEVEL_STATE',
        decision: 'REPURPOSE',
        resulting_classification: 'NPC_ONLY_LEVEL_UP_ROUTE_IN_BOUNDED_CORPORA',
        evidence_exhausted: true,
        next_required_evidence: [],
      },
      {
        packet_discriminator: '0x02d4',
        candidate: 'DIRECT_DAMAGE_HP_DEFENSE_RESOURCE_OR_ENTITY_SCALAR',
        decision: route02d4Audit.route_decisions[0].decision,
        resulting_classification: route02d4Audit.route_decisions[0].hypothesis,
        evidence_exhausted: route02d4Audit.route_decisions[0].evidence_exhausted,
        next_required_evidence: route02d4Audit.route_decisions[0].next_required_evidence,
      },
      {
        packet_discriminator: '0x0474',
        candidate: 'GENERAL_HERO_PERSISTENT_OR_VOLATILE_STATE',
        decision: route0474Audit.route_decisions[0].decision,
        resulting_classification: route0474Audit.route_decisions[0].hypothesis,
        evidence_exhausted: route0474Audit.route_decisions[0].evidence_exhausted,
        next_required_evidence: route0474Audit.route_decisions[0].next_required_evidence,
      },
      {
        packet_discriminator: '0x017f',
        candidate: 'DAMAGE_AMOUNT_MITIGATION_OR_EFFECTIVE_HP_STAGE',
        decision: 'KEEP_CANDIDATE',
        evidence_exhausted: false,
        next_required_evidence: [
          'A same-timestamp pre/post HP pair with shield/heal/regen controls.',
          'An exact unmitigated input paired with armor/MR and the recorded amount.',
        ],
      },
    ],
    capability_decisions: [
      ...['CURRENT_HP', 'MAX_HP', 'ARMOR', 'MAGIC_RESIST', 'CURRENT_RESOURCE'].map(
        (capability) => ({
          capability,
          decision: 'REJECT',
          decision_scope: 'PROMOTION_FROM_BOUNDED_EXACT_BUILD_ROUTE_EVIDENCE',
          evidence_exhausted: true,
          next_required_evidence: [
            'An exact-build route carrying same-timestamp hero scalar updates, or a safe paired oracle with sub-second state samples.',
          ],
        }),
      ),
      {
        capability: 'TEMPORARY_BUFF_STAT_ADJUSTMENT_NEUTRAL_FIELDS',
        decision: 'PROMOTE',
        promotion_scope: 'RESEARCH_EXACT_BUILD_ONLY',
        semantic_role_decision: 'KEEP_CANDIDATE',
        evidence_exhausted: true,
        next_required_evidence: [
          'Controlled buff/stat calibration is required to name the four neutral float roles.',
        ],
      },
      {
        capability: 'TEMPORARY_ATTACK_SPEED_CAP_OVERRIDE_NEUTRAL_FIELDS',
        decision: 'PROMOTE',
        promotion_scope: 'RESEARCH_EXACT_BUILD_ONLY',
        semantic_role_decision: 'KEEP_CANDIDATE',
        evidence_exhausted: true,
        next_required_evidence: [
          'Controlled independent component toggles are required to name the two neutral float roles.',
        ],
      },
      {
        capability: 'DEATH_TIMER_SECONDS',
        decision: 'PROMOTE',
        promotion_scope: 'RESEARCH_EXACT_BUILD_ONLY',
        evidence_exhausted: true,
        next_required_evidence: [],
      },
      {
        capability: 'DAMAGE_AMOUNT_MITIGATION_OR_EFFECTIVE_HP_STAGE',
        decision: 'KEEP_CANDIDATE',
        evidence_exhausted: false,
        next_required_evidence: [
          'Same-timestamp controlled HP delta or exact pre-mitigation magnitude evidence.',
        ],
      },
    ],
    domain_decisions: [
      {
        domain: 'HERO_PERSISTENT_HP_DEFENSE_RESOURCE_STATE',
        decision: 'REJECT',
        decision_scope: 'PROMOTION_FROM_CURRENT_BOUNDED_EXACT_BUILD_SEARCH',
        evidence_exhausted: true,
        next_required_evidence: [
          'A new exact-build carrier or sub-second paired state oracle.',
        ],
      },
      {
        domain: 'TRANSIENT_HERO_STAT_ADJUSTMENT_STRUCTURE',
        decision: 'PROMOTE',
        promotion_scope: 'RESEARCH_NEUTRAL_FIELDS_ONLY',
        semantic_role_decision: 'KEEP_CANDIDATE',
        evidence_exhausted: true,
        next_required_evidence: [
          'Controlled calibration to name component roles.',
        ],
      },
      {
        domain: 'COMBAT_LIFECYCLE_DEATH_TIMER',
        decision: 'PROMOTE',
        promotion_scope: 'RESEARCH_EXACT_BUILD_ONLY',
        evidence_exhausted: true,
        next_required_evidence: [],
      },
      {
        domain: 'DAMAGE_DEFENSE_SEMANTIC_STAGE',
        decision: 'KEEP_CANDIDATE',
        evidence_exhausted: false,
        next_required_evidence: [
          'Same-timestamp controlled pre/post state and raw-input evidence.',
        ],
      },
    ],
    exhausted_search_space: [
      '0x010c HeroStats scoreboard snapshot (XP/lane CS only)',
      '0x01dc ReplicateFields exact empty/zero vectors',
      '0x042f StatFormulaOutputs exact coefficient vectors',
      '0x0412 BuffUpdateStatAdjustments exact neutral-field plaintext values',
      '0x0259 CombatStateChanged absent',
      '0x03f8 SetAbilityResourceState absent',
      '0x04df ReplicateField absent',
      '0x03dc UpdateStatStoneGameDelta historical stream',
      '0x00d2 ShowHealthBar visibility toggle',
      '0x02cf HealthBarVariableTicks nonhero presentation vectors',
      '0x00dd AttackSpeedCapOverrides exact neutral-field plaintext floats',
      '0x0345 NPC_LevelUp_Global no canonical hero rows',
      '0x02d4 cross-domain bit-packed auxiliary update batch negative control',
      '0x0474 champion-specific periodic family negative control',
      '0x017f UnitApplyDamage callback and P0 component residual',
    ],
    next_evidence_required: {
      persistent_hp_defense_resource: 'An exact-build route carrying same-timestamp hero scalar updates, or a safe paired oracle with sub-second HP/defense/resource samples that can identify a candidate field.',
      damage_stage: 'A same-timestamp pre/post HP pair with shield/heal/regen controls, or an exact unmitigated input paired with armor/MR and the recorded amount.',
      temporary_adjustments: 'A controlled safe replay with a known timed buff/stat override and exact before/after stat samples.',
      attack_speed_cap_override_field_roles: 'A controlled exact-build replay that independently toggles each cap-override component and records the resulting client-visible attack-speed-cap behavior.',
    },
    evidence_hashes: hashes,
  };

  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  fs.writeFileSync(options.output, `${JSON.stringify(report, null, 2)}\n`);
  fs.mkdirSync(path.dirname(options.markdown), { recursive: true });
  fs.writeFileSync(options.markdown, renderMarkdown(report));
  process.stdout.write(`${JSON.stringify({
    status: report.status,
    output: options.output,
    markdown: options.markdown,
    death_events: options.deathEvents,
    attack_speed_events: options.attackSpeedEvents,
    buff_adjustment_events: options.buffAdjustmentEvents,
    formula_rows: formulaCombinedRows,
    death_timer_rows: deathTimers.row_count,
    death_anchor: deathTimers.p0_death_anchor_match,
    promotion: report.promotion_decision,
  }, null, 2)}\n`);
  return report;
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  ATTACK_SPEED_PRESENCE_TABLE_RVA,
  BUFF_ADJUSTMENT_TABLE_RVA,
  decodeAttackSpeedField14Byte,
  decodeAttackSpeedField18Byte,
  decodeAttackSpeedFloatStorage,
  decodeAttackSpeedObjectHex,
  decodeAttackSpeedPresenceField10,
  decodeAttackSpeedPresenceField1c,
  decodeBuffAdjustmentFieldAByte,
  decodeBuffAdjustmentFieldBByte,
  decodeBuffAdjustmentFieldCByte,
  decodeBuffAdjustmentFieldDByte,
  decodeBuffAdjustmentKindByte,
  decodeBuffAdjustmentRecordObjectHex,
  decodeDeathTimerByte,
  decodeDeathTimerObjectHex,
  decodeDeathTimerStorage,
  decodeFormulaValues,
  main,
  participantNetworkId,
};
