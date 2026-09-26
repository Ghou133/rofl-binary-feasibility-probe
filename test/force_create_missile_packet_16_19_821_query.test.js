'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { FORCE_CREATE_MISSILE_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeProtectedForceCreateMissileComparisonKeyU32 } =
  require('../src/decoders/rofl_16_19_821_force_create_missile_packet_candidate');
const { bindSavedPacketArtifactToPhysicalReplay } =
  require('./helpers/physical_saved_packet_replay');

const CLI = path.resolve(__dirname, '../src/cli.js');
const CAPABILITY = 'force_create_missile_packet';
const EVENT = 'force_create_missile_packet_candidates';
const SOURCE_PATH = 'synthetic.rofl';
const REPLAY_SHA = 'a'.repeat(64);
const PACKETS = [
  ['f0abcd', '90cdc94a', 0x40000263],
  ['f1123456', 'cf4ac94a', 0x40004003],
];

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function row(index) {
  const [hex, protectedHex, comparisonKey] = PACKETS[index];
  const time = 1000 + index;
  const rawParam = 0x400000b5;
  return {
    event_type: 'FORCE_CREATE_MISSILE_PACKET_CANDIDATE',
    game_version: profile.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: REPLAY_SHA,
    replay_time_ms: time, raw_param: rawParam,
    packet_name_candidate: profile.packet_name,
    native_protected_comparison_bytes_hex: protectedHex,
    native_callback_comparison_key_u32: comparisonKey,
    native_callback_witness_status: 'SYNTHETIC_RECEIVER_PRE_COMPARE',
    live_receiver_lookup_status: 'UNKNOWN',
    source_actor_status: 'UNKNOWN', owner_status: 'UNKNOWN',
    missile_identity_status: 'UNKNOWN', target_status: 'UNKNOWN',
    creation_effect_status: 'UNKNOWN', causality_status: 'UNKNOWN',
    confidence: 'CANDIDATE', semantic_status: profile.evidence_status,
    raw_packet_ref: {
      source_path: SOURCE_PATH, replay_sha256: REPLAY_SHA,
      chunk_index: index, chunk_id: index + 1, chunk_stream: 'game_chunk',
      chunk_file_offset: 100 + index, decompressed_block_offset: 20 + index * 30,
      decompressed_payload_offset: 29 + index * 30,
      packet_id: profile.replay_block_packet_id, replay_time_ms: time,
      payload_length: hex.length / 2, raw_param: rawParam,
      raw_payload_hex: hex, raw_payload_sha256: sha256(Buffer.from(hex, 'hex')),
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
    const key = Buffer.alloc(4);
    key.writeUInt32LE(item.native_callback_comparison_key_u32);
    output.update(Buffer.from(item.native_protected_comparison_bytes_hex, 'hex'))
      .update(key);
  }
  return [input.digest('hex'), output.digest('hex')];
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-missile-query-'));
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
      native_callback_comparison_key_u32: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
    },
    native_witness_status: 'FULLY_CONSUMED_ALL', native_full_success_count: 2,
    native_batch_count: 1, native_input_sha256: nativeInput,
    native_output_sha256: nativeOutput, runtime_image_status: 'MATCHED_USED',
    runtime_image_used: true,
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

test('saved missile comparison key query emits original rows and filters only observed key', (t) => {
  const f = fixture(t);
  for (const [, protectedHex, key] of PACKETS) {
    assert.equal(decodeProtectedForceCreateMissileComparisonKeyU32(protectedHex), key);
  }
  const selected = query(f.dir, '--opaque-u32', '0x40000263', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(f.rows[0])}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.rows_unmodified, true);
  const noMatch = query(f.dir, '--opaque-u32', '0');
  assert.equal(noMatch.status, 0, noMatch.stderr);
  assert.equal(noMatch.stdout, '');
  assert.equal(JSON.parse(noMatch.stderr).scanned_count, 2);
  assert.equal(errorCode(query(f.dir, '--participant', '1')),
    'PARTICIPANT_UNAVAILABLE');
});

test('missile source verification checks every physical packet after the output limit', (t) => {
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
});

test('later forged comparison output fails after limit without partial stdout or file', (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.rows);
  forged[1].native_protected_comparison_bytes_hex = PACKETS[0][1];
  forged[1].native_callback_comparison_key_u32 = PACKETS[0][2];
  fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  const selected = query(f.dir, '--limit', '1');
  assert.equal(errorCode(selected), 'EVENT_COUNT_MISMATCH');
  assert.equal(selected.stdout, '');
  const output = path.join(f.root, 'selected.jsonl');
  assert.equal(errorCode(query(f.dir, '--limit', '1', '--output', output)),
    'EVENT_COUNT_MISMATCH');
  assert.equal(fs.existsSync(output), false);
});

test('later altered raw payload with matching row SHA fails ordered native input digest', (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.rows);
  forged[1].raw_packet_ref.raw_payload_hex = 'f2123456';
  forged[1].raw_packet_ref.raw_payload_sha256 = sha256(Buffer.from('f2123456', 'hex'));
  fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  const selected = query(f.dir, '--limit', '1');
  assert.equal(errorCode(selected), 'EVENT_COUNT_MISMATCH');
  assert.equal(selected.stdout, '');
});

test('later promoted receiver or malformed comparison key is rejected without output', (t) => {
  const f = fixture(t);
  for (const mutate of [
    (item) => { item.live_receiver_lookup_status = 'MATCHED'; },
    (item) => { item.native_callback_comparison_key_u32 += 1; },
    (item) => { item.missile_identity_status = 'KNOWN'; },
  ]) {
    const forged = structuredClone(f.rows);
    mutate(forged[1]);
    fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
    const selected = query(f.dir, '--limit', '1');
    assert.equal(errorCode(selected), 'INVALID_EVENT_ROW');
    assert.equal(selected.stdout, '');
  }
});

test('candidate metadata and exact image remain fail closed', (t) => {
  const f = fixture(t);
  for (const change of [
    (result) => { result.status = 'PASS'; },
    (result) => { result.runtime_image_sha256 = '0'.repeat(64); },
    (result) => { result.native_full_success_count = 1; },
  ]) {
    const semantic = structuredClone(f.semantic);
    const analysis = structuredClone(f.analysis);
    change(semantic.capability_results[CAPABILITY]);
    change(analysis.semantic.capability_results[CAPABILITY]);
    fs.writeFileSync(f.semanticPath, JSON.stringify(semantic));
    fs.writeFileSync(f.analysisPath, JSON.stringify(analysis));
    assert.equal(errorCode(query(f.dir)), 'CAPABILITY_METADATA_MISMATCH');
  }
});
