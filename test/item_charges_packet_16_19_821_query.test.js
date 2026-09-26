'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { ITEM_CHARGES_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeProtectedItemChargesCallbackBytes } =
  require('../src/decoders/rofl_16_19_821_item_charges_packet_candidate');
const { streamEventQuery } = require('../src/event_query');
const { bindSavedPacketArtifactToPhysicalReplay } =
  require('./helpers/physical_saved_packet_replay');

const CLI = path.resolve(__dirname, '../src/cli.js');
const CAPABILITY = 'item_charges_packet';
const EVENT = 'item_charges_packet_candidates';
const SOURCE_PATH = 'synthetic.rofl';
const REPLAY_SHA = 'a'.repeat(64);
// These bytes and callback arguments were witnessed on the pinned 821 runtime.
// The surrounding saved artifact is synthetic and is only a query fixture.
const PACKETS = [
  { payload: '36b1', protected: 'b1c1eae6', selector: 0, value: 35,
    rawParam: 0x400000b4 },
  { payload: '13', protected: '9fc136e6', selector: 2, value: 2,
    rawParam: 0x400000ae },
];

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function row(index) {
  const packet = PACKETS[index];
  const time = 1000 + index;
  return {
    event_type: 'ITEM_CHARGES_PACKET_CANDIDATE',
    game_version: profile.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: REPLAY_SHA,
    replay_time_ms: time, raw_param: packet.rawParam,
    packet_name_candidate: profile.packet_name,
    native_protected_callback_bytes_hex: packet.protected,
    native_callback_selector_u8: packet.selector,
    native_callback_value_u16: packet.value,
    native_pre_receiver_witness: 'NATIVE_RANGE_CHECK_PASSED',
    native_receiver_status: 'NOT_EXECUTED',
    item_identity_status: 'UNKNOWN', charge_state_status: 'UNKNOWN',
    slot_identity_status: 'UNKNOWN', owner_status: 'UNKNOWN',
    semantic_effect_status: 'UNKNOWN', confidence: 'CANDIDATE',
    semantic_status: profile.evidence_status,
    raw_packet_ref: {
      source_path: SOURCE_PATH, replay_sha256: REPLAY_SHA,
      chunk_index: index, chunk_id: index + 1, chunk_stream: 'game_chunk',
      chunk_file_offset: 100 + index, decompressed_block_offset: 20 + index * 30,
      decompressed_payload_offset: 26 + index * 30,
      packet_id: profile.replay_block_packet_id, replay_time_ms: time,
      payload_length: packet.payload.length / 2, raw_param: packet.rawParam,
      raw_payload_hex: packet.payload,
      raw_payload_sha256: sha256(Buffer.from(packet.payload, 'hex')),
    },
  };
}

function hashes(rows) {
  const input = crypto.createHash('sha256');
  const output = crypto.createHash('sha256');
  for (const item of rows) {
    const payload = Buffer.from(item.raw_packet_ref.raw_payload_hex, 'hex');
    const header = Buffer.alloc(8);
    header.writeUInt32LE(item.raw_param, 0);
    header.writeUInt32LE(payload.length, 4);
    input.update(header).update(payload);
    const callback = Buffer.alloc(6);
    callback.writeUInt32LE(item.native_callback_selector_u8, 0);
    callback.writeUInt16LE(item.native_callback_value_u16, 4);
    output.update(Buffer.from(item.native_protected_callback_bytes_hex, 'hex'))
      .update(callback);
  }
  return [input.digest('hex'), output.digest('hex')];
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-item-charges-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = path.join(root, 'replays', 'sample');
  fs.mkdirSync(dir, { recursive: true });
  const rows = [row(0), row(1)];
  const [nativeInput, nativeOutput] = hashes(rows);
  const result = {
    profile_id: profile.id, input_packet_id: profile.replay_block_packet_id,
    evidence_status: profile.evidence_status,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    status: 'CANDIDATE', input_count: 2, event_count: 2, scanned_block_count: 2,
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      native_callback_selector_u8: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
      native_callback_value_u16: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
    },
    native_witness_status: 'FULLY_CONSUMED_ALL_PRE_RECEIVER',
    native_pre_receiver_witness: 'NATIVE_RANGE_CHECK_PASSED',
    native_full_success_count: 2, native_batch_count: 1,
    native_input_sha256: nativeInput, native_output_sha256: nativeOutput,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
  };
  const semantic = {
    replay_version: profile.replay_version, replay_sha256: REPLAY_SHA,
    container_status: 'PASS', status: 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE', requested_capabilities: [CAPABILITY],
    capability_results: { [CAPABILITY]: result },
  };
  const analysis = {
    patch: '16.19', replay_version: profile.replay_version,
    replay_sha256: REPLAY_SHA, source_path: SOURCE_PATH,
    event_storage: 'JSONL_ONLY', event_counts: { [EVENT]: 2 },
    event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` }, events: null,
    semantic: { status: 'CANDIDATE', requested_capabilities: [CAPABILITY],
      capability_results: { [CAPABILITY]: result } },
  };
  const semanticPath = path.join(dir, 'semantic_run.json');
  const analysisPath = path.join(dir, 'replay_analysis.json');
  const eventPath = path.join(dir, `${EVENT}.jsonl`);
  fs.writeFileSync(semanticPath, JSON.stringify(semantic));
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  fs.writeFileSync(eventPath, `${rows.map(JSON.stringify).join('\n')}\n`);
  return { root, dir, rows, semantic, analysis, semanticPath, analysisPath,
    eventPath };
}

function query(dir, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', dir, '--event', EVENT, ...args], { encoding: 'utf8' });
}

function errorCode(run) {
  assert.equal(run.status, 2, run.stderr);
  return JSON.parse(run.stderr).code;
}

test('saved item charges query selects callback witness and keeps rows unchanged', (t) => {
  const f = fixture(t);
  assert.deepEqual(PACKETS.map((packet) =>
    decodeProtectedItemChargesCallbackBytes(packet.protected)), [
    { selector_u8: 0, value_u16: 35 },
    { selector_u8: 2, value_u16: 2 },
  ]);
  const selected = query(f.dir, '--item-charges-selector-u8', '0',
    '--item-charges-value-u16', '35', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(f.rows[0])}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.rows_unmodified, true);
  assert.equal(summary.source_provenance_status, 'SAVED_ONLY_UNVERIFIED');
  assert.equal(summary.filters.item_charges_selector_u8, 0);
  assert.equal(summary.filters.item_charges_value_u16, 35);
});

test('source verification checks every saved packet after the output limit', (t) => {
  const f = fixture(t);
  const physical = bindSavedPacketArtifactToPhysicalReplay(f.dir);
  const verified = query(f.dir, '--verify-source', '--limit', '1');
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(JSON.parse(verified.stderr).source_provenance_status,
    'SOURCE_REPLAY_VERIFIED');
  assert.equal(verified.stdout, `${JSON.stringify(physical.rows[0])}\n`);

  const forged = structuredClone(physical.rows);
  forged[1].replay_time_ms += 1;
  forged[1].raw_packet_ref.replay_time_ms = forged[1].replay_time_ms;
  forged[1].raw_packet_ref.chunk_file_offset += 1;
  forged[1].raw_packet_ref.decompressed_block_offset += 1;
  forged[1].raw_packet_ref.decompressed_payload_offset += 1;
  fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  const rejected = query(f.dir, '--verify-source', '--limit', '1');
  assert.equal(errorCode(rejected), 'SOURCE_PROVENANCE_MISMATCH');
  assert.equal(rejected.stdout, '');
  const offline = query(f.dir, '--limit', '1');
  assert.equal(offline.status, 0, offline.stderr);
  assert.equal(JSON.parse(offline.stderr).source_provenance_status,
    'SAVED_ONLY_UNVERIFIED');
});

test('source verification rejects missing and mismatched ROFL; override accepts a copy', (t) => {
  const f = fixture(t);
  const { sourcePath } = bindSavedPacketArtifactToPhysicalReplay(f.dir);
  const relocated = path.join(f.root, 'relocated.rofl');
  fs.copyFileSync(sourcePath, relocated);
  const accepted = query(f.dir, '--verify-source', '--source-replay', relocated,
    '--limit', '1');
  assert.equal(accepted.status, 0, accepted.stderr);
  assert.equal(JSON.parse(accepted.stderr).source_provenance_status,
    'SOURCE_REPLAY_VERIFIED');

  const missing = query(f.dir, '--verify-source', '--source-replay',
    path.join(f.root, 'missing.rofl'), '--limit', '1');
  assert.equal(errorCode(missing), 'SOURCE_REPLAY_READ_FAILED');
  assert.equal(missing.stdout, '');

  const wrong = path.join(f.root, 'wrong.rofl');
  const bytes = fs.readFileSync(sourcePath);
  bytes[15 + profile.replay_version.length + 17 + 12] ^= 1;
  fs.writeFileSync(wrong, bytes);
  const mismatched = query(f.dir, '--verify-source', '--source-replay', wrong,
    '--limit', '1');
  assert.equal(errorCode(mismatched), 'SOURCE_REPLAY_IDENTITY_MISMATCH');
  assert.equal(mismatched.stdout, '');

  const wrongBuild = path.join(f.root, 'wrong-build.rofl');
  const otherBuild = fs.readFileSync(sourcePath);
  otherBuild.write('16.19.820.7193', 15, 'ascii');
  fs.writeFileSync(wrongBuild, otherBuild);
  const buildMismatch = query(f.dir, '--verify-source', '--source-replay',
    wrongBuild, '--limit', '1');
  assert.equal(errorCode(buildMismatch), 'SOURCE_REPLAY_IDENTITY_MISMATCH');
  assert.equal(JSON.parse(buildMismatch.stderr).observed_replay_version,
    '16.19.820.7193');
  assert.equal(buildMismatch.stdout, '');
});

test('batch source verification uses each Replay source and preserves manifest checks', (t) => {
  const f = fixture(t);
  const physical = bindSavedPacketArtifactToPhysicalReplay(f.dir);
  const relative = 'replays/sample';
  const hashes = Object.fromEntries(['semantic_run.json', 'replay_analysis.json',
    `${EVENT}.jsonl`].map((name) => [`${relative}/${name}`,
    sha256(fs.readFileSync(path.join(f.dir, name)))]));
  const manifest = {
    command_args: ['batch'], replay_inputs: [{ artifact_directory: relative,
      sha256: physical.semantic.replay_sha256, version: profile.replay_version }],
    output_hashes_excluding_manifest: hashes,
  };
  const manifestPath = path.join(f.root, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  const selected = query(f.root, '--verify-source', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
  assert.deepEqual(summary.replay_results.map((replay) =>
    replay.source_provenance_status), ['SOURCE_REPLAY_VERIFIED']);
  assert.equal(selected.stdout, `${JSON.stringify(physical.rows[0])}\n`);

  const override = query(f.root, '--verify-source', '--source-replay',
    physical.sourcePath, '--limit', '1');
  assert.equal(errorCode(override), 'UNSUPPORTED_SOURCE_REPLAY_OVERRIDE');
  assert.equal(override.stdout, '');

  const unavailableRelative = 'replays/unavailable';
  const unavailableDir = path.join(f.root, 'replays', 'unavailable');
  fs.mkdirSync(unavailableDir);
  const unavailableSha = 'b'.repeat(64);
  const unavailableSemantic = structuredClone(physical.semantic);
  const unavailableAnalysis = structuredClone(physical.analysis);
  unavailableSemantic.replay_sha256 = unavailableSha;
  unavailableAnalysis.replay_sha256 = unavailableSha;
  for (const result of [unavailableSemantic.capability_results[CAPABILITY],
    unavailableAnalysis.semantic.capability_results[CAPABILITY]]) {
    result.status = 'MISSING_INPUT';
    result.missing_input = 'runtime_image';
  }
  fs.writeFileSync(path.join(unavailableDir, 'semantic_run.json'),
    JSON.stringify(unavailableSemantic));
  fs.writeFileSync(path.join(unavailableDir, 'replay_analysis.json'),
    JSON.stringify(unavailableAnalysis));
  manifest.replay_inputs.push({ artifact_directory: unavailableRelative,
    sha256: unavailableSha, version: profile.replay_version });
  for (const name of ['semantic_run.json', 'replay_analysis.json']) {
    manifest.output_hashes_excluding_manifest[`${unavailableRelative}/${name}`] =
      sha256(fs.readFileSync(path.join(unavailableDir, name)));
  }
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  const partial = query(f.root, '--verify-source', '--limit', '1');
  assert.equal(partial.status, 0, partial.stderr);
  const partialSummary = JSON.parse(partial.stderr);
  assert.equal(partialSummary.query_status, 'PARTIAL');
  assert.equal(partialSummary.source_provenance_status,
    'PARTIAL_SOURCE_REPLAY_VERIFIED');
  assert.deepEqual(partialSummary.replay_results.map((replay) =>
    replay.source_provenance_status), ['SOURCE_REPLAY_VERIFIED', 'NOT_VERIFIED']);
});

test('source verification rejects unrelated saved event shapes explicitly', async () => {
  await assert.rejects(streamEventQuery({
    eventKey: 'hero_death_candidates', replayVersion: profile.replay_version,
    capabilityStatus: 'CANDIDATE',
  }, { verifySource: true }, async () => {}),
  { code: 'UNSUPPORTED_SOURCE_VERIFICATION' });
});

test('saved query accepts a native range-checked selector outside observed Replay values', (t) => {
  const f = fixture(t);
  const rows = structuredClone(f.rows);
  // The pinned 821 image fully consumes this synthetic packet and returns 7/62.
  rows[1].native_protected_callback_bytes_hex = '8dc1d8e6';
  rows[1].native_callback_selector_u8 = 7;
  rows[1].native_callback_value_u16 = 62;
  rows[1].raw_packet_ref.raw_payload_hex = '9e8dd8';
  rows[1].raw_packet_ref.payload_length = 3;
  rows[1].raw_packet_ref.raw_payload_sha256 =
    sha256(Buffer.from('9e8dd8', 'hex'));
  assert.deepEqual(decodeProtectedItemChargesCallbackBytes(
    rows[1].native_protected_callback_bytes_hex),
  { selector_u8: 7, value_u16: 62 });
  const [nativeInput, nativeOutput] = hashes(rows);
  for (const result of [f.semantic.capability_results[CAPABILITY],
    f.analysis.semantic.capability_results[CAPABILITY]]) {
    result.native_input_sha256 = nativeInput;
    result.native_output_sha256 = nativeOutput;
  }
  fs.writeFileSync(f.eventPath, `${rows.map(JSON.stringify).join('\n')}\n`);
  fs.writeFileSync(f.semanticPath, JSON.stringify(f.semantic));
  fs.writeFileSync(f.analysisPath, JSON.stringify(f.analysis));
  const selected = query(f.dir, '--item-charges-selector-u8', '7', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(rows[1])}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
});

test('valid unobserved callback filters scan all saved rows and return zero', (t) => {
  const f = fixture(t);
  for (const args of [
    ['--item-charges-selector-u8', '6'],
    ['--item-charges-value-u16', '1112'],
  ]) {
    const selected = query(f.dir, ...args);
    assert.equal(selected.status, 0, selected.stderr);
    assert.equal(selected.stdout, '');
    const summary = JSON.parse(selected.stderr);
    assert.equal(summary.scanned_count, 2);
    assert.equal(summary.matched_count, 0);
  }
  const badSelector = query(f.dir, '--item-charges-selector-u8', '256');
  assert.equal(badSelector.status, 1);
  assert.match(badSelector.stderr, /--item-charges-selector-u8 must be in 0\.\.255/);
  const badValue = query(f.dir, '--item-charges-value-u16', '65536');
  assert.equal(badValue.status, 1);
  assert.match(badValue.stderr, /--item-charges-value-u16 must be in 0\.\.65535/);
});

test('a later transform-consistent native output forgery fails after limit', (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.rows);
  forged[1].native_protected_callback_bytes_hex = PACKETS[0].protected;
  forged[1].native_callback_selector_u8 = PACKETS[0].selector;
  forged[1].native_callback_value_u16 = PACKETS[0].value;
  fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  const selected = query(f.dir, '--limit', '1');
  assert.equal(errorCode(selected), 'EVENT_COUNT_MISMATCH');
  assert.equal(selected.stdout, '');
  const output = path.join(f.root, 'selected.jsonl');
  assert.equal(errorCode(query(f.dir, '--limit', '1', '--output', output)),
    'EVENT_COUNT_MISMATCH');
  assert.equal(fs.existsSync(output), false);
});

test('a later callback, raw input, or promoted metadata forgery fails closed', (t) => {
  const f = fixture(t);
  const original = `${f.rows.map(JSON.stringify).join('\n')}\n`;
  const forged = structuredClone(f.rows);
  forged[1].native_callback_value_u16 = 3;
  fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  const invalidCallback = query(f.dir, '--limit', '1');
  assert.equal(errorCode(invalidCallback), 'INVALID_EVENT_ROW');
  assert.equal(invalidCallback.stdout, '');
  forged[1] = structuredClone(f.rows[1]);
  forged[1].raw_packet_ref.raw_payload_hex = '14';
  forged[1].raw_packet_ref.raw_payload_sha256 = sha256(Buffer.from('14', 'hex'));
  fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  const invalidInput = query(f.dir, '--limit', '1');
  assert.equal(errorCode(invalidInput), 'EVENT_COUNT_MISMATCH');
  assert.equal(invalidInput.stdout, '');
  fs.writeFileSync(f.eventPath, original);
  for (const status of ['PASS', 'PROMOTED']) {
    const semantic = structuredClone(f.semantic);
    const analysis = structuredClone(f.analysis);
    semantic.capability_results[CAPABILITY].status = status;
    analysis.semantic.capability_results[CAPABILITY].status = status;
    fs.writeFileSync(f.semanticPath, JSON.stringify(semantic));
    fs.writeFileSync(f.analysisPath, JSON.stringify(analysis));
    assert.equal(errorCode(query(f.dir)), 'CAPABILITY_METADATA_MISMATCH');
  }
});
