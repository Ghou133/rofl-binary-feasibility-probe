'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: profile,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V6_821: v6Profile,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V1_ID_821: v1ProfileId,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V2_ID_821: v2ProfileId,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821: v3ProfileId,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821: v4ProfileId,
  decodeUnitApplyDamageCallbackF32FromRaw821,
  decodeUnitApplyDamageCallbackU32FromRaw821,
  decodeUnitApplyDamageCallbackF32At18FromEncoded821,
  decodeUnitApplyDamageCallbackU32At1cFromEncoded821,
  decodeUnitApplyDamageU32At1cFromRawSpan821,
  UNIT_APPLY_DAMAGE_U32_0X1C_RAW_CALL_RVA_BY_SELECTOR_821,
  decodeUnitApplyDamageLookupKeyFromRaw821,
  isObservedShape,
} = require('../src/decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');
const { prepareEventQuery, streamEventQuery } = require('../src/event_query');
const { bindSavedPacketArtifactToPhysicalReplay } =
  require('./helpers/physical_saved_packet_replay');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'unit_apply_damage_packet_candidates';
const CAPABILITY = 'unit_apply_damage_packet';
const SHA = 'a'.repeat(64);
const SOURCE_PATH = 'synthetic.rofl';
const FLOAT_PACKET = '71875e460b083dbaef3ba6ec39b975';
const OTHER_PACKET = '54814747c6c4d9a90b6ef07c44e2ecaf5b75';
const RAW_F32_18_PACKET = '3706a54411d863b80b68bb01d1ca1e9bde73ec6b75';
const RAW_U32_1C_PACKET = '72959d41c6d904810b00f17252b4ded07ecd6b75';
const CONSTANT_PACKETS = [
  ['5b814d4650a07e33c07422', 'CONSTANT_0', 0],
  ['6a87dd49ea0d8c9d0b3891ecac75', 'CONSTANT_1', 1],
  ['7901ad410aca18ce0b5eec3f5275', 'CONSTANT_2', 2],
];

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function nativeInputSha256(rows) {
  const hash = crypto.createHash('sha256');
  for (const entry of rows) {
    const payload = Buffer.from(entry.raw_packet_ref.raw_payload_hex, 'hex');
    const header = Buffer.alloc(8);
    header.writeUInt32LE(entry.raw_param, 0);
    header.writeUInt32LE(payload.length, 4);
    hash.update(header).update(payload);
  }
  return hash.digest('hex');
}

function command(target, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', target, '--event', EVENT, ...args],
    { encoding: 'utf8' });
}

function row(index, payloadHex = FLOAT_PACKET) {
  const payload = Buffer.from(payloadHex, 'hex');
  const selector24 = payload[3] & 7;
  const selector0 = payload[0] & 7;
  const selector3 = (payload[0] >>> 3) & 7;
  assert.equal(isObservedShape(payload.length, selector24, selector0, selector3), true);
  const hasFloat = payload.length === 15 && selector24 === 6
    && selector0 === 1 && selector3 === 6;
  const time = 1000 + index;
  const rawParam = 0x40004007 + index;
  const rawBytes = hasFloat ? payload.subarray(5, 9).toString('hex') : null;
  return {
    event_type: 'UNIT_APPLY_DAMAGE_PACKET_CANDIDATE',
    game_version: profile.replay_version, patch: '16.19',
    build_profile: v1ProfileId, replay_sha256: SHA,
    replay_time_ms: time, raw_param: rawParam,
    packet_name_candidate: profile.packet_name,
    header_selector_bits_24_26: selector24,
    header_selector_bits_0_2: selector0,
    header_selector_bits_3_5: selector3,
    callback_f32_0x20_candidate: hasFloat
      ? decodeUnitApplyDamageCallbackF32FromRaw821(rawBytes) : null,
    callback_f32_0x20_status: hasFloat
      ? 'NATIVE_MATCHED_SHAPE' : 'UNAVAILABLE_SHAPE',
    callback_f32_0x20_raw_bytes_hex: rawBytes,
    semantic_effect_status: 'UNKNOWN', confidence: 'CANDIDATE',
    semantic_status: profile.evidence_status,
    raw_packet_ref: {
      source_path: SOURCE_PATH, replay_sha256: SHA,
      chunk_index: index + 1, chunk_id: index + 1,
      chunk_stream: 'game_chunk', chunk_file_offset: 100 + index,
      decompressed_block_offset: 20 + index,
      decompressed_payload_offset: 29 + index,
      packet_id: profile.replay_block_packet_id,
      replay_time_ms: time, payload_length: payload.length,
      raw_param: rawParam, raw_payload_hex: payloadHex,
      raw_payload_sha256: sha256(payload),
    },
  };
}

function v2Row(index, payloadHex = FLOAT_PACKET) {
  const entry = row(index, payloadHex);
  const constant = CONSTANT_PACKETS.find(([hex]) => hex === payloadHex);
  const offset = constant ? null : payloadHex === OTHER_PACKET ? 9 : 5;
  const rawBytes = offset === null ? null
    : Buffer.from(payloadHex, 'hex').subarray(offset, offset + 4).toString('hex');
  entry.build_profile = v2ProfileId;
  entry.native_callback_f32_0x20_candidate = constant
    ? constant[2] : decodeUnitApplyDamageCallbackF32FromRaw821(rawBytes);
  entry.native_callback_f32_0x20_source = constant ? constant[1] : 'RAW_READER';
  entry.native_callback_f32_0x20_raw_offset = offset;
  entry.native_callback_f32_0x20_raw_bytes_hex = rawBytes;
  return entry;
}

function v3Row(index, payloadHex = FLOAT_PACKET, relation = 'EQUAL',
  encoded24 = '01020304', encoded2c = '05060708') {
  const entry = v2Row(index, payloadHex);
  const key24 = decodeUnitApplyDamageLookupKeyFromRaw821(encoded24, 0x24);
  const key2c = decodeUnitApplyDamageLookupKeyFromRaw821(encoded2c, 0x2c);
  entry.build_profile = v3ProfileId;
  entry.raw_param = relation === 'EQUAL' ? key24
    : relation === 'RAW_PARAM_IS_LOOKUP_PLUS_0X100' ? key24 + 0x100
      : key24 + 0x200;
  entry.raw_packet_ref.raw_param = entry.raw_param;
  entry.native_callback_lookup_key_u32_0x24_candidate = key24;
  entry.native_callback_lookup_key_0x24_encoded_bytes_hex = encoded24;
  entry.native_callback_lookup_key_u32_0x2c_candidate = key2c;
  entry.native_callback_lookup_key_0x2c_encoded_bytes_hex = encoded2c;
  entry.native_callback_lookup_key_0x24_raw_param_relation = relation;
  return entry;
}

function v4Row(index, payloadHex = FLOAT_PACKET, relation = 'EQUAL') {
  const entry = v3Row(index, payloadHex, relation);
  const isConstant = entry.header_selector_bits_24_26 === 6;
  const encoded = isConstant ? '85858585' : '01020304';
  entry.build_profile = v4ProfileId;
  entry.native_callback_u32_0x10_candidate =
    decodeUnitApplyDamageCallbackU32FromRaw821(encoded);
  entry.native_callback_u32_0x10_encoded_bytes_hex = encoded;
  entry.native_callback_u32_0x10_source = isConstant
    ? 'CONSTANT_0' : 'RAW_READER';
  return entry;
}

function v5Row(index, payloadHex = OTHER_PACKET) {
  const entry = v4Row(index, payloadHex);
  const payload = Buffer.from(payloadHex, 'hex');
  const selector = ((payload[0] >>> 6) | (payload[1] << 2)) & 7;
  assert.ok([0, 5].includes(selector));
  entry.build_profile = profile.id;
  entry.header_selector_bits_6_8 = selector;
  if (selector === 5) {
    entry.native_callback_f32_0x18_candidate = 0;
    entry.native_callback_f32_0x18_encoded_bytes_hex = '3e3e3e3e';
    entry.native_callback_f32_0x18_source = 'CONSTANT_0';
    entry.native_callback_f32_0x18_raw_offset = null;
    entry.native_callback_f32_0x18_raw_bytes_hex = null;
  } else {
    assert.equal(payloadHex, RAW_F32_18_PACKET);
    const at18 = payload.subarray(9, 13);
    entry.native_callback_f32_0x18_encoded_bytes_hex =
      Buffer.from(at18).reverse().toString('hex');
    entry.native_callback_f32_0x18_candidate =
      decodeUnitApplyDamageCallbackF32At18FromEncoded821(
        entry.native_callback_f32_0x18_encoded_bytes_hex);
    entry.native_callback_f32_0x18_source = 'RAW_READER';
    entry.native_callback_f32_0x18_raw_offset = 9;
    entry.native_callback_f32_0x18_raw_bytes_hex = at18.toString('hex');
    entry.native_callback_f32_0x20_raw_offset = 13;
    entry.native_callback_f32_0x20_raw_bytes_hex = payload.subarray(13, 17).toString('hex');
    entry.native_callback_f32_0x20_candidate =
      decodeUnitApplyDamageCallbackF32FromRaw821(
        entry.native_callback_f32_0x20_raw_bytes_hex);
  }
  return entry;
}

function v6Row(index, payloadHex = OTHER_PACKET) {
  const entry = v5Row(index, payloadHex);
  const payload = Buffer.from(payloadHex, 'hex');
  const selector = (payload[1] >>> 4) & 7;
  assert.ok([0, 1].includes(selector));
  entry.build_profile = v6Profile.id;
  entry.header_selector_bits_12_14 = selector;
  if (selector === 0) {
    entry.native_callback_u32_0x1c_candidate = 0;
    entry.native_callback_u32_0x1c_encoded_bytes_hex = '05050505';
    entry.native_callback_u32_0x1c_source = 'CONSTANT_0';
    entry.native_callback_u32_0x1c_raw_call_rva = null;
    entry.native_callback_u32_0x1c_raw_offset = null;
    entry.native_callback_u32_0x1c_raw_bytes_hex = null;
  } else {
    assert.equal(payloadHex, RAW_U32_1C_PACKET);
    const rawBytes = payload.subarray(9, 11).toString('hex');
    entry.native_callback_u32_0x1c_candidate =
      decodeUnitApplyDamageU32At1cFromRawSpan821(rawBytes);
    entry.native_callback_u32_0x1c_encoded_bytes_hex = 'c0f305e5';
    assert.equal(decodeUnitApplyDamageCallbackU32At1cFromEncoded821(
      entry.native_callback_u32_0x1c_encoded_bytes_hex),
    entry.native_callback_u32_0x1c_candidate);
    entry.native_callback_u32_0x1c_source = 'RAW_READER';
    entry.native_callback_u32_0x1c_raw_call_rva =
      UNIT_APPLY_DAMAGE_U32_0X1C_RAW_CALL_RVA_BY_SELECTOR_821[selector];
    entry.native_callback_u32_0x1c_raw_offset = 9;
    entry.native_callback_u32_0x1c_raw_bytes_hex = rawBytes;
  }
  return entry;
}

async function queryLibrary(directory, options) {
  const lines = [];
  const summary = await streamEventQuery(prepareEventQuery(directory, EVENT), options,
    async (line) => lines.push(line));
  return { lines, summary };
}

function writeReplay(root, name, rows, {
  replayVersion = profile.replay_version, capabilityStatus = 'CANDIDATE',
} = {}) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const available = rows.filter((entry) =>
    entry.callback_f32_0x20_status === 'NATIVE_MATCHED_SHAPE').length;
  const shapes = new Set(rows.map((entry) => [
    entry.raw_packet_ref.payload_length,
    entry.header_selector_bits_24_26,
    entry.header_selector_bits_0_2,
    entry.header_selector_bits_3_5,
  ].join(':')));
  const result = {
    profile_id: rows[0]?.build_profile ?? v1ProfileId,
    input_packet_id: profile.replay_block_packet_id,
    evidence_status: profile.evidence_status,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    evidence_scalar_table_sha256: profile.evidence_scalar_table_sha256,
    evidence_shape_catalog_sha256: profile.evidence_shape_catalog_sha256,
    status: capabilityStatus, input_count: rows.length, event_count: rows.length,
    native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: rows.length,
    native_input_sha256: nativeInputSha256(rows),
    observed_shape_family_count: shapes.size,
    callback_f32_available_count: available,
    callback_f32_unavailable_count: rows.length - available,
    ...(rows[0]?.build_profile !== v1ProfileId ? {
      native_callback_f32_available_count: rows.length,
      native_callback_f32_source_counts: {
        RAW_READER: rows.filter((entry) =>
          entry.native_callback_f32_0x20_source === 'RAW_READER').length,
        CONSTANT_0: rows.filter((entry) =>
          entry.native_callback_f32_0x20_source === 'CONSTANT_0').length,
        CONSTANT_1: rows.filter((entry) =>
          entry.native_callback_f32_0x20_source === 'CONSTANT_1').length,
        CONSTANT_2: rows.filter((entry) =>
          entry.native_callback_f32_0x20_source === 'CONSTANT_2').length,
      },
    } : {}),
    ...([v3ProfileId, v4ProfileId, profile.id, v6Profile.id]
      .includes(rows[0]?.build_profile) ? {
      native_callback_lookup_full_write_count: rows.length,
      evidence_lookup_key_0x24_table_sha256:
        profile.evidence_lookup_key_0x24_table_sha256,
      evidence_lookup_key_0x2c_table_sha256:
        profile.evidence_lookup_key_0x2c_table_sha256,
      native_callback_lookup_key_0x24_raw_param_relation_counts: {
        EQUAL: rows.filter((entry) =>
          entry.native_callback_lookup_key_0x24_raw_param_relation === 'EQUAL').length,
        RAW_PARAM_IS_LOOKUP_PLUS_0X100: rows.filter((entry) =>
          entry.native_callback_lookup_key_0x24_raw_param_relation
            === 'RAW_PARAM_IS_LOOKUP_PLUS_0X100').length,
        OTHER: rows.filter((entry) =>
          entry.native_callback_lookup_key_0x24_raw_param_relation === 'OTHER').length,
      },
    } : {}),
    ...([v4ProfileId, profile.id, v6Profile.id].includes(rows[0]?.build_profile) ? {
      evidence_callback_u32_0x10_table_sha256:
        profile.evidence_callback_u32_0x10_table_sha256,
      native_callback_u32_0x10_full_write_count: rows.length,
      native_callback_u32_0x10_source_counts: {
        RAW_READER: rows.filter((entry) =>
          entry.native_callback_u32_0x10_source === 'RAW_READER').length,
        CONSTANT_0: rows.filter((entry) =>
          entry.native_callback_u32_0x10_source === 'CONSTANT_0').length,
      },
    } : {}),
    ...([profile.id, v6Profile.id].includes(rows[0]?.build_profile) ? {
      evidence_callback_f32_0x18_table_sha256:
        profile.evidence_callback_f32_0x18_table_sha256,
      native_callback_f32_0x18_full_write_count: rows.length,
      native_callback_f32_0x18_source_counts: {
        RAW_READER: rows.filter((entry) =>
          entry.native_callback_f32_0x18_source === 'RAW_READER').length,
        CONSTANT_0: rows.filter((entry) =>
          entry.native_callback_f32_0x18_source === 'CONSTANT_0').length,
      },
    } : {}),
    ...(rows[0]?.build_profile === v6Profile.id ? {
      evidence_callback_u32_0x1c_table_sha256:
        v6Profile.evidence_callback_u32_0x1c_table_sha256,
      native_callback_u32_0x1c_full_write_count: rows.length,
      native_callback_u32_0x1c_source_counts: {
        RAW_READER: rows.filter((entry) =>
          entry.native_callback_u32_0x1c_source === 'RAW_READER').length,
        CONSTANT_0: rows.filter((entry) =>
          entry.native_callback_u32_0x1c_source === 'CONSTANT_0').length,
      },
    } : {}),
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
  };
  const semantic = {
    replay_version: replayVersion, replay_sha256: SHA,
    container_status: 'PASS', status: 'CANDIDATE', api_status: 'CANDIDATE',
    requested_capabilities: [CAPABILITY], capability_results: { [CAPABILITY]: result },
  };
  const analysis = {
    patch: '16.19', replay_version: replayVersion, replay_sha256: SHA,
    source_path: SOURCE_PATH, event_storage: 'JSONL_ONLY',
    event_counts: { [EVENT]: rows.length },
    event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` }, events: null,
  };
  fs.writeFileSync(path.join(directory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(directory, 'replay_analysis.json'), JSON.stringify(analysis));
  const lines = rows.map((entry) => JSON.stringify(entry));
  fs.writeFileSync(path.join(directory, `${EVENT}.jsonl`),
    lines.length ? `${lines.join('\n')}\n` : '');
  return { directory, lines };
}

function fixture(t, rows, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-damage-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, ...writeReplay(root, 'synthetic', rows, options) };
}

test('source verification checks every physical v6 damage row without a damage filter', (t) => {
  const f = fixture(t, [v6Row(0), v6Row(1, RAW_U32_1C_PACKET)]);
  const physical = bindSavedPacketArtifactToPhysicalReplay(f.directory);
  const verified = command(f.directory, '--verify-source', '--limit', '1');
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(verified.stdout, `${JSON.stringify(physical.rows[0])}\n`);
  const summary = JSON.parse(verified.stderr);
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');

  const changedPosition = structuredClone(physical.rows);
  changedPosition[1].replay_time_ms += 1;
  changedPosition[1].raw_packet_ref.replay_time_ms += 1;
  changedPosition[1].raw_packet_ref.chunk_file_offset += 1;
  changedPosition[1].raw_packet_ref.decompressed_block_offset += 1;
  changedPosition[1].raw_packet_ref.decompressed_payload_offset += 1;
  fs.writeFileSync(physical.eventPath,
    `${changedPosition.map(JSON.stringify).join('\n')}\n`);
  const rejectedPosition = command(f.directory, '--verify-source', '--limit', '1');
  assert.equal(rejectedPosition.status, 2, rejectedPosition.stderr);
  assert.equal(JSON.parse(rejectedPosition.stderr).code,
    'SOURCE_PROVENANCE_MISMATCH');
  assert.equal(rejectedPosition.stdout, '');

  const changedCallback = structuredClone(physical.rows);
  changedCallback[1].native_callback_u32_0x1c_source = 'CONSTANT_0';
  fs.writeFileSync(physical.eventPath,
    `${changedCallback.map(JSON.stringify).join('\n')}\n`);
  const rejectedCallback = command(f.directory, '--verify-source', '--limit', '1');
  assert.equal(rejectedCallback.status, 2, rejectedCallback.stderr);
  assert.equal(JSON.parse(rejectedCallback.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(rejectedCallback.stdout, '');
});

test('source verification accepts the earlier exact-821 damage row profile', (t) => {
  const f = fixture(t, [row(0), row(1, OTHER_PACKET)]);
  const physical = bindSavedPacketArtifactToPhysicalReplay(f.directory);
  const verified = command(f.directory, '--verify-source', '--limit', '1');
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(verified.stdout, `${JSON.stringify(physical.rows[0])}\n`);
  assert.equal(JSON.parse(verified.stderr).source_provenance_status,
    'SOURCE_REPLAY_VERIFIED');
});

test('query-events selects only native-matched anonymous float rows and preserves JSONL', (t) => {
  const { directory, lines } = fixture(t,
    [row(0), row(1, OTHER_PACKET), row(2)]);
  const selected = command(directory, '--damage-callback-f32-available', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[0]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.damage_callback_f32_checked_count, 3);
  assert.equal(summary.damage_callback_f32_available_count, 2);
  assert.equal(summary.damage_callback_f32_unavailable_count, 1);
  assert.equal(summary.native_witness_check, 'PERSISTED_METADATA_AND_RAW_BYTES');
  assert.equal(summary.filters.damage_callback_f32_available, true);
  assert.equal(summary.rows_unmodified, true);
  const narrowed = command(directory, '--damage-callback-f32-available',
    '--raw-param', '0x40004009');
  assert.equal(narrowed.status, 0, narrowed.stderr);
  assert.equal(narrowed.stdout, `${lines[2]}\n`);
});

test('query-events checks v2 native float provenance while preserving the legacy filter', (t) => {
  const rows = [v2Row(0), v2Row(1, OTHER_PACKET),
    ...CONSTANT_PACKETS.map(([payload], index) => v2Row(index + 2, payload))];
  const { directory, lines } = fixture(t, rows);
  const selected = command(directory, '--damage-callback-f32-available', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[0]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 5);
  assert.equal(summary.damage_callback_f32_available_count, 1);
  assert.equal(summary.damage_callback_f32_unavailable_count, 4);
  const changed = rows.map((entry) => structuredClone(entry));
  changed[1].native_callback_f32_0x20_raw_offset = 8;
  const damaged = fixture(t, changed);
  const rejected = command(damaged.directory,
    '--damage-callback-f32-available', '--limit', '1');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
});

test('query-events checks v3 native lookup keys and relation counts after output limit', (t) => {
  const rows = [v3Row(0),
    v3Row(1, OTHER_PACKET, 'RAW_PARAM_IS_LOOKUP_PLUS_0X100'),
    v3Row(2, CONSTANT_PACKETS[0][0], 'OTHER')];
  const { directory, lines } = fixture(t, rows);
  const selected = command(directory, '--damage-callback-f32-available', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[0]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 1);
  const damagedRows = rows.map((entry) => structuredClone(entry));
  damagedRows[1].native_callback_lookup_key_0x24_encoded_bytes_hex = '00000000';
  const damaged = fixture(t, damagedRows);
  const rejected = command(damaged.directory,
    '--damage-callback-f32-available', '--limit', '1');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
  const { directory: badMetadata } = fixture(t, rows);
  const metadataFile = path.join(badMetadata, 'semantic_run.json');
  const semantic = JSON.parse(fs.readFileSync(metadataFile, 'utf8'));
  semantic.capability_results[CAPABILITY]
    .native_callback_lookup_key_0x24_raw_param_relation_counts.OTHER += 1;
  fs.writeFileSync(metadataFile, JSON.stringify(semantic));
  const badCounts = command(badMetadata, '--damage-callback-f32-available');
  assert.equal(badCounts.status, 2, badCounts.stderr);
  assert.equal(JSON.parse(badCounts.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
});

test('saved v3 query filters exact +0x24 and +0x2c keys independently and together', async (t) => {
  const rows = [v3Row(0),
    v3Row(1, OTHER_PACKET, 'RAW_PARAM_IS_LOOKUP_PLUS_0X100',
      '090a0b0c', '05060708'),
    v3Row(2, CONSTANT_PACKETS[0][0], 'OTHER',
      '01020304', '0d0e0f10')];
  const { directory, lines } = fixture(t, rows);
  const key24 = rows[0].native_callback_lookup_key_u32_0x24_candidate;
  const key2c = rows[0].native_callback_lookup_key_u32_0x2c_candidate;
  const by24 = await queryLibrary(directory, { damageLookupKey24: key24 });
  assert.deepEqual(by24.lines, [`${lines[0]}\n`, `${lines[2]}\n`]);
  assert.equal(by24.summary.scanned_count, 3);
  assert.equal(by24.summary.matched_count, 2);
  assert.equal(by24.summary.damage_lookup_keys_checked_count, 3);
  assert.equal(by24.summary.native_witness_check,
    'PERSISTED_METADATA_AND_RAW_BYTES');
  assert.deepEqual(by24.summary.filters.damage_lookup_key24, key24);
  assert.equal(by24.summary.rows_unmodified, true);
  const by2c = await queryLibrary(directory, { damageLookupKey2c: key2c });
  assert.deepEqual(by2c.lines, [`${lines[0]}\n`, `${lines[1]}\n`]);
  const both = await queryLibrary(directory, {
    damageLookupKey24: key24, damageLookupKey2c: key2c, limit: 1,
  });
  assert.deepEqual(both.lines, [`${lines[0]}\n`]);
  assert.equal(both.summary.scanned_count, 3);
  assert.equal(both.summary.matched_count, 1);
  assert.equal(both.summary.emitted_count, 1);
  assert.equal(both.summary.filters.damage_lookup_key2c, key2c);
  const none = await queryLibrary(directory, { damageLookupKey24: 0 });
  assert.equal(none.summary.matched_count, 0);
  assert.equal(none.summary.damage_lookup_keys_checked_count, 3);
});

test('CLI exposes v3 lookup key filters without changing saved candidate rows', (t) => {
  const rows = [v3Row(0),
    v3Row(1, OTHER_PACKET, 'RAW_PARAM_IS_LOOKUP_PLUS_0X100',
      '090a0b0c', '05060708'),
    v3Row(2, CONSTANT_PACKETS[0][0], 'OTHER',
      '01020304', '0d0e0f10')];
  const { directory, lines } = fixture(t, rows);
  const key24 = rows[0].native_callback_lookup_key_u32_0x24_candidate;
  const key2c = rows[0].native_callback_lookup_key_u32_0x2c_candidate;
  const selected = command(directory,
    '--damage-lookup-key24', `0x${key24.toString(16)}`,
    '--damage-lookup-key2c', String(key2c), '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[0]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.damage_lookup_keys_checked_count, 3);
  assert.equal(summary.filters.damage_lookup_key24, key24);
  assert.equal(summary.filters.damage_lookup_key2c, key2c);
  assert.equal(summary.native_witness_check,
    'PERSISTED_METADATA_AND_RAW_BYTES');
  assert.equal(summary.rows_unmodified, true);
});

test('saved v3 lookup filter validates every row after limit and rejects damaged metadata', async (t) => {
  const rows = [v3Row(0), v3Row(1, OTHER_PACKET), v3Row(2)];
  const key24 = rows[0].native_callback_lookup_key_u32_0x24_candidate;
  const damagedRows = rows.map((entry) => structuredClone(entry));
  damagedRows[2].native_callback_lookup_key_0x2c_encoded_bytes_hex = '00000000';
  const damaged = fixture(t, damagedRows);
  await assert.rejects(queryLibrary(damaged.directory,
    { damageLookupKey24: key24, limit: 1 }),
  (error) => error.code === 'INVALID_EVENT_ROW');
  const badMetadata = fixture(t, rows);
  const semanticFile = path.join(badMetadata.directory, 'semantic_run.json');
  const semantic = JSON.parse(fs.readFileSync(semanticFile, 'utf8'));
  semantic.capability_results[CAPABILITY].evidence_lookup_key_0x2c_table_sha256 =
    '0'.repeat(64);
  fs.writeFileSync(semanticFile, JSON.stringify(semantic));
  await assert.rejects(queryLibrary(badMetadata.directory,
    { damageLookupKey2c: rows[0].native_callback_lookup_key_u32_0x2c_candidate }),
  (error) => error.code === 'CAPABILITY_METADATA_MISMATCH');
});

test('saved v4 query filters anonymous +0x10 u32 including zero after full validation',
  async (t) => {
    const rows = [v4Row(0), v4Row(1, OTHER_PACKET),
      v4Row(2, CONSTANT_PACKETS[0][0])];
    const { directory, lines } = fixture(t, rows);
    const zero = await queryLibrary(directory,
      { damageCallbackU32At10: 0, limit: 1 });
    assert.deepEqual(zero.lines, [`${lines[0]}\n`]);
    assert.equal(zero.summary.scanned_count, 3);
    assert.equal(zero.summary.matched_count, 2);
    assert.equal(zero.summary.emitted_count, 1);
    assert.equal(zero.summary.damage_callback_u32_0x10_checked_count, 3);
    assert.equal(zero.summary.filters.damage_callback_u32_0x10, 0);
    assert.equal(zero.summary.native_witness_check,
      'PERSISTED_METADATA_AND_RAW_BYTES');
    assert.equal(zero.summary.rows_unmodified, true);
    const rawValue = rows[1].native_callback_u32_0x10_candidate;
    const nonzero = await queryLibrary(directory,
      { damageCallbackU32At10: rawValue,
        damageLookupKey24: rows[1].native_callback_lookup_key_u32_0x24_candidate });
    assert.deepEqual(nonzero.lines, [`${lines[1]}\n`]);
    assert.equal(nonzero.summary.scanned_count, 3);
    assert.equal(nonzero.summary.matched_count, 1);
  });

test('CLI v4 +0x10 filter accepts zero and scans rows after limit', (t) => {
  const rows = [v4Row(0), v4Row(1, OTHER_PACKET),
    v4Row(2, CONSTANT_PACKETS[0][0])];
  const { directory, lines } = fixture(t, rows);
  const selected = command(directory, '--damage-callback-u32-0x10', '0',
    '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[0]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.filters.damage_callback_u32_0x10, 0);
});

test('saved v4 +0x10 query rejects altered row and metadata after output limit',
  async (t) => {
    const rows = [v4Row(0), v4Row(1, OTHER_PACKET), v4Row(2)];
    for (const mutate of [
      (entry) => { entry.native_callback_u32_0x10_encoded_bytes_hex = '00000000'; },
      (entry) => { entry.native_callback_u32_0x10_source = 'RAW_READER'; },
      (entry) => { entry.native_callback_u32_0x10_candidate = -1; },
      (entry) => { delete entry.native_callback_u32_0x10_source; },
    ]) {
      const changed = rows.map((entry) => structuredClone(entry));
      mutate(changed[2]);
      const damaged = fixture(t, rows);
      fs.writeFileSync(path.join(damaged.directory, `${EVENT}.jsonl`),
        `${changed.map((entry) => JSON.stringify(entry)).join('\n')}\n`);
      await assert.rejects(queryLibrary(damaged.directory,
        { damageCallbackU32At10: 0, limit: 1 }),
      (error) => error.code === 'INVALID_EVENT_ROW');
    }
    const bad = fixture(t, rows);
    const semanticFile = path.join(bad.directory, 'semantic_run.json');
    const semantic = JSON.parse(fs.readFileSync(semanticFile, 'utf8'));
    semantic.capability_results[CAPABILITY]
      .native_callback_u32_0x10_source_counts.RAW_READER += 1;
    fs.writeFileSync(semanticFile, JSON.stringify(semantic));
    await assert.rejects(queryLibrary(bad.directory,
      { damageCallbackU32At10: 0 }),
    (error) => error.code === 'CAPABILITY_METADATA_MISMATCH');
  });

test('anonymous +0x10 filter requires v4 and validates uint32 input', async (t) => {
  for (const older of [row(0), v2Row(0), v3Row(0)]) {
    const saved = fixture(t, [older]);
    await assert.rejects(queryLibrary(saved.directory,
      { damageCallbackU32At10: 0 }),
    (error) => error.code === 'UNSUPPORTED_FILTER');
  }
  const saved = fixture(t, [v4Row(0)]);
  for (const invalid of [-1, 0x100000000, 1.5, '0']) {
    await assert.rejects(queryLibrary(saved.directory,
      { damageCallbackU32At10: invalid }),
    (error) => error.code === 'INVALID_FILTER');
  }
});

test('saved v5 +0x18 raw selector filters native values and preserves rows',
  async (t) => {
    const rows = [v5Row(0, OTHER_PACKET), v5Row(1, RAW_F32_18_PACKET),
      v5Row(2, OTHER_PACKET)];
    const { directory, lines } = fixture(t, rows);
    const selected = await queryLibrary(directory,
      { damageCallbackF32At18Raw: true, limit: 1 });
    assert.deepEqual(selected.lines, [`${lines[1]}\n`]);
    assert.equal(selected.summary.scanned_count, 3);
    assert.equal(selected.summary.matched_count, 1);
    assert.equal(selected.summary.emitted_count, 1);
    assert.equal(selected.summary.damage_callback_f32_0x18_checked_count, 3);
    assert.equal(selected.summary.filters.damage_callback_f32_0x18_raw, true);
    assert.equal(selected.summary.native_witness_check,
      'PERSISTED_METADATA_AND_RAW_BYTES');
    assert.equal(selected.summary.rows_unmodified, true);
    const cli = command(directory, '--damage-callback-f32-0x18-raw', '--limit', '1');
    assert.equal(cli.status, 0, cli.stderr);
    assert.equal(cli.stdout, `${lines[1]}\n`);
    assert.equal(JSON.parse(cli.stderr).matched_count, 1);
  });

test('saved v5 +0x18 query checks later rows and rejects altered metadata',
  async (t) => {
    const rows = [v5Row(0, RAW_F32_18_PACKET), v5Row(1, OTHER_PACKET)];
    for (const mutate of [
      (entry) => { entry.header_selector_bits_6_8 = 0; },
      (entry) => { entry.native_callback_f32_0x18_encoded_bytes_hex = '00000000'; },
      (entry) => { entry.native_callback_f32_0x18_candidate = 1; },
      (entry) => { entry.native_callback_f32_0x18_source = 'RAW_READER'; },
      (entry) => { delete entry.native_callback_f32_0x18_raw_offset; },
    ]) {
      const changed = rows.map((entry) => structuredClone(entry));
      mutate(changed[1]);
      const saved = fixture(t, changed);
      await assert.rejects(queryLibrary(saved.directory,
        { damageCallbackF32At18Raw: true, limit: 1 }),
      (error) => error.code === 'INVALID_EVENT_ROW');
    }
    const bad = fixture(t, rows);
    const semanticFile = path.join(bad.directory, 'semantic_run.json');
    const semantic = JSON.parse(fs.readFileSync(semanticFile, 'utf8'));
    semantic.capability_results[CAPABILITY]
      .native_callback_f32_0x18_source_counts.RAW_READER += 1;
    fs.writeFileSync(semanticFile, JSON.stringify(semantic));
    await assert.rejects(queryLibrary(bad.directory,
      { damageCallbackF32At18Raw: true, limit: 1 }),
    (error) => error.code === 'CAPABILITY_METADATA_MISMATCH');
  });

test('anonymous +0x18 raw filter is exact v5 only', async (t) => {
  for (const older of [row(0), v2Row(0), v3Row(0), v4Row(0)]) {
    const saved = fixture(t, [older]);
    await assert.rejects(queryLibrary(saved.directory,
      { damageCallbackF32At18Raw: true }),
    (error) => error.code === 'UNSUPPORTED_FILTER');
  }
  const saved = fixture(t, [v5Row(0, RAW_F32_18_PACKET)]);
  await assert.rejects(queryLibrary(saved.directory,
    { damageCallbackF32At18Raw: 1 }),
  (error) => error.code === 'INVALID_FILTER');
  const unrelated = command(saved.directory, '--event', 'show_health_bar_packet_candidates',
    '--damage-callback-f32-0x18-raw');
  assert.equal(unrelated.status, 1);
});

test('saved v6 +0x1c query selects zero and raw u32 without changing rows',
  async (t) => {
    const rows = [v6Row(0), v6Row(1, RAW_U32_1C_PACKET), v6Row(2)];
    const { directory, lines } = fixture(t, rows);
    const zero = await queryLibrary(directory,
      { damageCallbackU32At1c: 0, limit: 1 });
    assert.deepEqual(zero.lines, [`${lines[0]}\n`]);
    assert.equal(zero.summary.scanned_count, 3);
    assert.equal(zero.summary.matched_count, 2);
    assert.equal(zero.summary.emitted_count, 1);
    assert.equal(zero.summary.damage_callback_u32_0x1c_checked_count, 3);
    assert.equal(zero.summary.filters.damage_callback_u32_0x1c, 0);
    assert.equal(zero.summary.native_witness_check,
      'PERSISTED_METADATA_AND_RAW_BYTES');
    assert.equal(zero.summary.rows_unmodified, true);
    const rawValue = rows[1].native_callback_u32_0x1c_candidate;
    const raw = await queryLibrary(directory,
      { damageCallbackU32At1c: rawValue });
    assert.deepEqual(raw.lines, [`${lines[1]}\n`]);
    const cli = command(directory, '--damage-callback-u32-0x1c',
      `0x${rawValue.toString(16)}`);
    assert.equal(cli.status, 0, cli.stderr);
    assert.equal(cli.stdout, `${lines[1]}\n`);
  });

test('saved v6 +0x1c validates every row after limit and rejects forged metadata',
  async (t) => {
    const rows = [v6Row(0), v6Row(1, RAW_U32_1C_PACKET)];
    for (const mutate of [
      (entry) => { entry.header_selector_bits_12_14 = 6; },
      (entry) => { entry.native_callback_u32_0x1c_candidate += 1; },
      (entry) => { entry.native_callback_u32_0x1c_encoded_bytes_hex = '00000000'; },
      (entry) => { entry.native_callback_u32_0x1c_source = 'CONSTANT_0'; },
      (entry) => { entry.native_callback_u32_0x1c_raw_call_rva = '0xf4a742'; },
      (entry) => { entry.native_callback_u32_0x1c_raw_offset = 8; },
      (entry) => { entry.native_callback_u32_0x1c_raw_bytes_hex = '00f100'; },
      (entry) => { delete entry.native_callback_u32_0x1c_raw_bytes_hex; },
    ]) {
      const changed = rows.map((entry) => structuredClone(entry));
      mutate(changed[1]);
      const saved = fixture(t, changed);
      await assert.rejects(queryLibrary(saved.directory,
        { damageCallbackU32At1c: 0, limit: 1 }),
      (error) => error.code === 'INVALID_EVENT_ROW');
    }
    const unseen = rows.map((entry) => structuredClone(entry));
    const unseenPayload = Buffer.from(unseen[1].raw_packet_ref.raw_payload_hex, 'hex');
    unseenPayload[1] = (unseenPayload[1] & 0x8f) | 0x60;
    unseen[1].raw_packet_ref.raw_payload_hex = unseenPayload.toString('hex');
    unseen[1].raw_packet_ref.raw_payload_sha256 = sha256(unseenPayload);
    unseen[1].header_selector_bits_12_14 = 6;
    const unseenSaved = fixture(t, unseen);
    await assert.rejects(queryLibrary(unseenSaved.directory,
      { damageCallbackU32At1c: 0, limit: 1 }),
    (error) => error.code === 'INVALID_EVENT_ROW');
    for (const mutate of [
      (result) => { result.evidence_callback_u32_0x1c_table_sha256 = '0'.repeat(64); },
      (result) => { result.native_callback_u32_0x1c_full_write_count -= 1; },
      (result) => { result.native_callback_u32_0x1c_source_counts.RAW_READER += 1; },
    ]) {
      const saved = fixture(t, rows);
      const file = path.join(saved.directory, 'semantic_run.json');
      const semantic = JSON.parse(fs.readFileSync(file, 'utf8'));
      mutate(semantic.capability_results[CAPABILITY]);
      fs.writeFileSync(file, JSON.stringify(semantic));
      await assert.rejects(queryLibrary(saved.directory,
        { damageCallbackU32At1c: 0, limit: 1 }),
      (error) => error.code === 'CAPABILITY_METADATA_MISMATCH');
    }
  });

test('anonymous +0x1c filter is exact v6 only', async (t) => {
  for (const older of [row(0), v2Row(0), v3Row(0), v4Row(0), v5Row(0)]) {
    const saved = fixture(t, [older]);
    await assert.rejects(queryLibrary(saved.directory,
      { damageCallbackU32At1c: 0 }),
    (error) => error.code === 'UNSUPPORTED_FILTER');
  }
  const forgedV5 = fixture(t, [v5Row(0)]);
  const forgedFile = path.join(forgedV5.directory, 'semantic_run.json');
  const forgedSemantic = JSON.parse(fs.readFileSync(forgedFile, 'utf8'));
  forgedSemantic.capability_results[CAPABILITY]
    .evidence_callback_u32_0x1c_table_sha256 =
      v6Profile.evidence_callback_u32_0x1c_table_sha256;
  fs.writeFileSync(forgedFile, JSON.stringify(forgedSemantic));
  await assert.rejects(queryLibrary(forgedV5.directory,
    { damageCallbackF32At18Raw: true }),
  (error) => error.code === 'CAPABILITY_METADATA_MISMATCH');
  const v6 = fixture(t, [v6Row(0)]);
  for (const invalid of [-1, 0x100000000, 1.5, '0']) {
    await assert.rejects(queryLibrary(v6.directory,
      { damageCallbackU32At1c: invalid }),
    (error) => error.code === 'INVALID_FILTER');
  }
  const wrongBuild = fixture(t, [v6Row(0)], {
    replayVersion: '16.19.820.7193',
  });
  await assert.rejects(queryLibrary(wrongBuild.directory,
    { damageCallbackU32At1c: 0 }),
  (error) => error.code === 'UNSUPPORTED_FILTER');
  const unrelated = command(v6.directory, '--event', 'show_health_bar_packet_candidates',
    '--damage-callback-u32-0x1c', '0');
  assert.equal(unrelated.status, 1);
});

test('original saved KR v3 packet artifact remains queryable', async (t) => {
  const directory = path.resolve(__dirname, '..', 'artifacts',
    '16_19_development', 'combat_lookup_roster_batch_v3_11_821',
    'replays', 'KR_8392938200');
  if (!fs.existsSync(path.join(directory, 'semantic_run.json'))
      || !fs.existsSync(path.join(directory, `${EVENT}.jsonl`))) {
    t.skip('original local saved v3 artifact absent');
    return;
  }
  const semantic = JSON.parse(fs.readFileSync(path.join(directory,
    'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[CAPABILITY].profile_id, v3ProfileId);
  const queried = await queryLibrary(directory, { damageLookupKey24: 0, limit: 1 });
  assert.equal(queried.summary.scanned_count,
    semantic.capability_results[CAPABILITY].event_count);
  assert.equal(queried.summary.matched_count, 0);
  assert.equal(queried.summary.damage_lookup_keys_checked_count,
    queried.summary.scanned_count);
  assert.deepEqual(queried.lines, []);
});

test('saved lookup filter accepts only exact 821 v3 packet artifacts and uint32 keys', async (t) => {
  const v1 = fixture(t, [row(0)]);
  const v2 = fixture(t, [v2Row(0)]);
  const foreign = fixture(t, [v3Row(0)], {
    replayVersion: '16.19.820.7193',
  });
  for (const directory of [v1.directory, v2.directory, foreign.directory]) {
    await assert.rejects(queryLibrary(directory, { damageLookupKey24: 1 }),
      (error) => error.code === 'UNSUPPORTED_FILTER');
  }
  const v3 = fixture(t, [v3Row(0)]);
  for (const invalid of [-1, 0x100000000, 1.5, '1']) {
    await assert.rejects(queryLibrary(v3.directory,
      { damageLookupKey2c: invalid }),
    (error) => error.code === 'INVALID_FILTER');
  }
});

test('query-events distinguishes zero available floats from unavailable shapes and capability', (t) => {
  const { directory } = fixture(t, [row(0, OTHER_PACKET), row(1, OTHER_PACKET)]);
  const selected = command(directory, '--damage-callback-f32-available');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, '');
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.matched_count, 0);
  assert.equal(summary.damage_callback_f32_available_count, 0);
  assert.equal(summary.damage_callback_f32_unavailable_count, 2);
  const missing = fixture(t, [row(0)], { capabilityStatus: 'MISSING_INPUT' });
  const rejected = command(missing.directory, '--damage-callback-f32-available');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_UNAVAILABLE');
});

test('query-events validates all UnitApplyDamage rows after output limit', (t) => {
  const corruptions = [
    (entry) => { entry.raw_packet_ref.raw_payload_sha256 = '0'.repeat(64); },
    (entry) => { entry.raw_packet_ref.raw_payload_hex = '00'; },
    (entry) => { entry.raw_packet_ref.raw_param += 1; },
    (entry) => { entry.raw_packet_ref.chunk_stream = 'keyframe'; },
    (entry) => { entry.header_selector_bits_3_5 = 0; },
    (entry) => { entry.callback_f32_0x20_candidate = 1; },
    (entry) => { entry.callback_f32_0x20_raw_bytes_hex = '00000000'; },
    (entry) => { entry.callback_f32_0x20_status = 'UNAVAILABLE_SHAPE'; },
    (entry) => { entry.semantic_effect_status = 'CONFIRMED'; },
    (entry) => { entry.damage_amount = 1; },
  ];
  for (const corrupt of corruptions) {
    const damaged = row(1);
    corrupt(damaged);
    const { root, directory } = fixture(t, [row(0), damaged]);
    const output = path.join(root, 'selected.jsonl');
    const result = command(directory, '--damage-callback-f32-available',
      '--limit', '1', '--output', output);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('query-events checks exact build, profile, image, transform and counts', (t) => {
  const changes = [
    (result) => { result.profile_id = 'foreign'; },
    (result) => { result.input_packet_id = 0x0060; },
    (result) => { result.runtime_image_sha256 = '0'.repeat(64); },
    (result) => { result.evidence_scalar_table_sha256 = '0'.repeat(64); },
    (result) => { result.evidence_shape_catalog_sha256 = '0'.repeat(64); },
    (result) => { result.native_witness_status = 'PARTIAL'; },
    (result) => { result.native_full_success_count = 0; },
    (result) => { result.native_input_sha256 = 'not-a-sha'; },
    (result) => { result.callback_f32_available_count = 0; },
    (result) => { result.observed_shape_family_count = 0; },
  ];
  for (const change of changes) {
    const { directory } = fixture(t, [row(0)]);
    const filename = path.join(directory, 'semantic_run.json');
    const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
    change(semantic.capability_results[CAPABILITY]);
    fs.writeFileSync(filename, JSON.stringify(semantic));
    const rejected = command(directory, '--damage-callback-f32-available');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  }
  const foreign = fixture(t, [row(0)], { replayVersion: '16.19.820.7193' });
  const wrongBuild = command(foreign.directory, '--damage-callback-f32-available');
  assert.equal(wrongBuild.status, 2, wrongBuild.stderr);
  assert.equal(JSON.parse(wrongBuild.stderr).code, 'UNSUPPORTED_FILTER');
});

test('query-events rejects a changed ordered native input digest after scanning rows', (t) => {
  const { root, directory } = fixture(t, [row(0), row(1, OTHER_PACKET)]);
  const filename = path.join(directory, 'semantic_run.json');
  const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
  semantic.capability_results[CAPABILITY].native_input_sha256 = '0'.repeat(64);
  fs.writeFileSync(filename, JSON.stringify(semantic));
  const output = path.join(root, 'selected.jsonl');
  const rejected = command(directory, '--damage-callback-f32-available',
    '--limit', '1', '--output', output);
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'EVENT_COUNT_MISMATCH');
  assert.equal(fs.existsSync(output), false);
});

test('CLI rejects the UnitApplyDamage filter for unrelated event keys', (t) => {
  const { directory } = fixture(t, [row(0)]);
  const unrelated = spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', 'hero_level_state_candidates',
      '--damage-callback-f32-available'], { encoding: 'utf8' });
  assert.equal(unrelated.status, 1);
  assert.match(unrelated.stderr, /--damage-callback-f32-available requires/);
});
