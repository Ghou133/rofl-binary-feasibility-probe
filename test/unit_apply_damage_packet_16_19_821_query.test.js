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
  decodeUnitApplyDamageCallbackF32FromRaw821,
  isObservedShape,
} = require('../src/decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'unit_apply_damage_packet_candidates';
const CAPABILITY = 'unit_apply_damage_packet';
const SHA = 'a'.repeat(64);
const SOURCE_PATH = 'synthetic.rofl';
const FLOAT_PACKET = '71875e460b083dbaef3ba6ec39b975';
const OTHER_PACKET = '54814747c6c4d9a90b6ef07c44e2ecaf5b75';

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
    build_profile: profile.id, replay_sha256: SHA,
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
    profile_id: profile.id,
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
