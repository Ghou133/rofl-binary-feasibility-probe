'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { SET_DIMENSION_MISSILE_PACKET_CANDIDATE_PROFILE_821: profile } =
  require('../src/decoders/rofl_16_19_821_set_dimension_missile_packet_candidate');
const { bindSavedPacketArtifactToPhysicalReplay } =
  require('./helpers/physical_saved_packet_replay');

const CLI = path.resolve(__dirname, '../src/cli.js');
const CAPABILITY = 'set_dimension_missile_packet';
const EVENT = 'set_dimension_missile_packet_candidates';
const REPLAY_SHA = 'a'.repeat(64);
const PACKETS = [
  { payload: '758fd1', protectedByte: 'd5', argument: 0 },
  { payload: '786b3aa7', protectedByte: 'a7', argument: 6 },
];

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function row(index) {
  const packet = PACKETS[index];
  const time = 1000 + index;
  const rawParam = 0x400000b5;
  return {
    event_type: 'SET_DIMENSION_MISSILE_PACKET_CANDIDATE',
    game_version: profile.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: REPLAY_SHA,
    replay_time_ms: time, raw_param: rawParam,
    packet_name_candidate: profile.packet_name,
    native_protected_dimension_byte_hex: packet.protectedByte,
    native_callback_argument_u8: packet.argument,
    native_callback_witness_status: 'STOPPED_BEFORE_RECEIVER_METHOD',
    live_receiver_status: 'UNKNOWN', source_actor_status: 'UNKNOWN',
    owner_status: 'UNKNOWN', missile_identity_status: 'UNKNOWN',
    target_status: 'UNKNOWN', dimension_change_status: 'UNKNOWN',
    gameplay_effect_status: 'UNKNOWN', causality_status: 'UNKNOWN',
    confidence: 'CANDIDATE', semantic_status: profile.evidence_status,
    raw_packet_ref: {
      source_path: 'synthetic.rofl', replay_sha256: REPLAY_SHA,
      chunk_index: index, chunk_id: index + 1, chunk_stream: 'game_chunk',
      chunk_file_offset: 100 + index, decompressed_block_offset: 20 + index * 30,
      decompressed_payload_offset: 29 + index * 30,
      packet_id: profile.replay_block_packet_id, replay_time_ms: time,
      payload_length: packet.payload.length / 2, raw_param: rawParam,
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
    output.update(Buffer.from(item.native_protected_dimension_byte_hex, 'hex'))
      .update(Buffer.from([item.native_callback_argument_u8]));
  }
  return [input.digest('hex'), output.digest('hex')];
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-set-dimension-query-'));
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
      native_callback_argument_u8: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
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
    replay_sha256: REPLAY_SHA, source_path: 'synthetic.rofl',
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

test('saved callback candidate query emits original rows and validates full digests after limit', (t) => {
  const f = fixture(t);
  const selected = query(f.dir, '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(f.rows[0])}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.rows_unmodified, true);
});

test('source verification rejects forged later time and offsets with zero output', (t) => {
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

test('source verification checks later top-level time and parameter without a value filter', (t) => {
  const f = fixture(t);
  bindSavedPacketArtifactToPhysicalReplay(f.dir);
  const original = fs.readFileSync(f.eventPath, 'utf8').trimEnd()
    .split('\n').map(JSON.parse);
  for (const mutate of [
    (item) => { item.replay_time_ms += 1; },
    (item) => { item.raw_param += 1; },
  ]) {
    const forged = structuredClone(original);
    mutate(forged[1]);
    fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
    const rejected = query(f.dir, '--verify-source', '--limit', '1');
    assert.equal(errorCode(rejected), 'INVALID_EVENT_ROW');
    assert.equal(rejected.stdout, '');
  }
});

test('later forged native output or raw payload fails ordered digest after limit', (t) => {
  const f = fixture(t);
  const outputPath = path.join(f.root, 'selected.jsonl');
  const nativeForgery = structuredClone(f.rows);
  nativeForgery[1].native_protected_dimension_byte_hex = 'd5';
  nativeForgery[1].native_callback_argument_u8 = 0;
  fs.writeFileSync(f.eventPath, `${nativeForgery.map(JSON.stringify).join('\n')}\n`);
  const rejected = query(f.dir, '--limit', '1', '--output', outputPath);
  assert.equal(errorCode(rejected), 'EVENT_COUNT_MISMATCH');
  assert.equal(rejected.stdout, '');
  assert.equal(fs.existsSync(outputPath), false);

  const rawForgery = structuredClone(f.rows);
  rawForgery[1].raw_packet_ref.raw_payload_hex = '786b3aa6';
  rawForgery[1].raw_packet_ref.raw_payload_sha256 =
    sha256(Buffer.from('786b3aa6', 'hex'));
  fs.writeFileSync(f.eventPath, `${rawForgery.map(JSON.stringify).join('\n')}\n`);
  const rawRejected = query(f.dir, '--limit', '1');
  assert.equal(errorCode(rawRejected), 'EVENT_COUNT_MISMATCH');
  assert.equal(rawRejected.stdout, '');
});

test('saved rows cannot promote live effects or alter callback argument', (t) => {
  const f = fixture(t);
  for (const mutate of [
    (item) => { item.live_receiver_status = 'MATCHED'; },
    (item) => { item.native_callback_argument_u8 += 1; },
    (item) => { item.dimension_change_status = 'OBSERVED'; },
  ]) {
    const forged = structuredClone(f.rows);
    mutate(forged[1]);
    fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
    const rejected = query(f.dir, '--limit', '1');
    assert.equal(errorCode(rejected), 'INVALID_EVENT_ROW');
    assert.equal(rejected.stdout, '');
  }
});

test('saved capability metadata requires the exact framing packet ID', (t) => {
  const f = fixture(t);
  const semantic = structuredClone(f.semantic);
  const analysis = structuredClone(f.analysis);
  semantic.capability_results[CAPABILITY].input_packet_id = 0x0087;
  analysis.semantic.capability_results[CAPABILITY].input_packet_id = 0x0087;
  fs.writeFileSync(f.semanticPath, JSON.stringify(semantic));
  fs.writeFileSync(f.analysisPath, JSON.stringify(analysis));
  const rejected = query(f.dir, '--limit', '1');
  assert.equal(errorCode(rejected), 'CAPABILITY_METADATA_MISMATCH');
  assert.equal(rejected.stdout, '');
});
