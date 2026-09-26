'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { ANONYMOUS_029C_PACKET_CANDIDATE_PROFILE_821: profile } =
  require('../src/decoders/rofl_16_19_821_anonymous_029c_packet_candidate');
const { bindSavedPacketArtifactToPhysicalReplay } =
  require('./helpers/physical_saved_packet_replay');

const CLI = path.resolve(__dirname, '../src/cli.js');
const CAPABILITY = 'anonymous_029c_packet';
const EVENT = 'anonymous_029c_packet_candidates';
const REPLAY_SHA = 'a'.repeat(64);
const PACKETS = [
  { payload: '72', protectedU32: '18181818', value: 0xffffffff },
  { payload: '761fff', protectedU32: '1f2ae31e', value: 0x400001f7 },
];

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function row(index) {
  const packet = PACKETS[index];
  const time = 1000 + index;
  const rawParam = index === 0 ? 0 : 0x400000b5;
  return {
    event_type: 'ANONYMOUS_029C_PACKET_CANDIDATE',
    game_version: profile.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: REPLAY_SHA,
    replay_time_ms: time, raw_param: rawParam,
    native_protected_selector_byte_hex: '3e', native_selector_u8: 0,
    native_protected_u32_hex: packet.protectedU32,
    anonymous_u32_candidate: packet.value,
    anonymous_u32_is_sentinel: packet.value === 0xffffffff,
    actor_status: 'UNKNOWN', target_status: 'UNKNOWN',
    object_role_status: 'UNKNOWN', receiver_state_status: 'UNKNOWN',
    behavior_status: 'UNKNOWN', effect_status: 'UNKNOWN',
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
    const value = Buffer.alloc(4);
    value.writeUInt32LE(item.anonymous_u32_candidate);
    output.update(Buffer.from(item.native_protected_selector_byte_hex, 'hex'))
      .update(Buffer.from(item.native_protected_u32_hex, 'hex')).update(value);
  }
  return [input.digest('hex'), output.digest('hex')];
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-anonymous-029c-query-'));
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
      native_selector_u8: 'CANDIDATE_EXACT_RUNTIME_NATIVE_OBJECT',
      anonymous_u32_candidate: 'CANDIDATE_EXACT_RUNTIME_NATIVE_OBJECT',
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

test('saved anonymous rows filter u32 and validate complete hashes after limit', (t) => {
  const f = fixture(t);
  const selected = query(f.dir, '--opaque-u32', '0x400001f7', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(f.rows[1])}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.rows_unmodified, true);
});

test('physical source verification covers later row even with result limit', (t) => {
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

test('later forged native value or raw payload fails after limit', (t) => {
  const f = fixture(t);
  const nativeForgery = structuredClone(f.rows);
  nativeForgery[1].native_protected_u32_hex = '142ae31e';
  nativeForgery[1].anonymous_u32_candidate = 0x400001f8;
  fs.writeFileSync(f.eventPath, `${nativeForgery.map(JSON.stringify).join('\n')}\n`);
  const rejected = query(f.dir, '--limit', '1');
  assert.equal(errorCode(rejected), 'EVENT_COUNT_MISMATCH');
  assert.equal(rejected.stdout, '');

  const rawForgery = structuredClone(f.rows);
  rawForgery[1].raw_packet_ref.raw_payload_hex = '761ffe';
  rawForgery[1].raw_packet_ref.raw_payload_sha256 =
    sha256(Buffer.from('761ffe', 'hex'));
  fs.writeFileSync(f.eventPath, `${rawForgery.map(JSON.stringify).join('\n')}\n`);
  const rawRejected = query(f.dir, '--limit', '1');
  assert.equal(errorCode(rawRejected), 'EVENT_COUNT_MISMATCH');
  assert.equal(rawRejected.stdout, '');
});

test('rows cannot promote roles, packet name or selector', (t) => {
  const f = fixture(t);
  for (const mutate of [
    (item) => { item.actor_status = 'MATCHED'; },
    (item) => { item.packet_name_candidate = 'PKT_AI_TargetS2C_s'; },
    (item) => { item.native_selector_u8 = 1; },
    (item) => { item.anonymous_u32_is_sentinel = true; },
  ]) {
    const forged = structuredClone(f.rows);
    mutate(forged[1]);
    fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
    const rejected = query(f.dir, '--limit', '1');
    assert.equal(errorCode(rejected), 'INVALID_EVENT_ROW');
    assert.equal(rejected.stdout, '');
  }
});

test('saved metadata must retain exact route and full native identity', (t) => {
  const f = fixture(t);
  const semantic = structuredClone(f.semantic);
  const analysis = structuredClone(f.analysis);
  semantic.capability_results[CAPABILITY].input_packet_id = 0x0282;
  analysis.semantic.capability_results[CAPABILITY].input_packet_id = 0x0282;
  fs.writeFileSync(f.semanticPath, JSON.stringify(semantic));
  fs.writeFileSync(f.analysisPath, JSON.stringify(analysis));
  const rejected = query(f.dir, '--limit', '1');
  assert.equal(errorCode(rejected), 'CAPABILITY_METADATA_MISMATCH');
  assert.equal(rejected.stdout, '');
});
