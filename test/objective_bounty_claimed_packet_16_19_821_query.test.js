'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE: PROFILE } =
  require('../src/decoders/rofl_16_19_821_objective_bounty_claimed_packet_candidate');
const { prepareEventQuery, streamEventQuery } = require('../src/event_query');

const EVENT = 'objective_bounty_claimed_packet_candidates';
const BUILD = '16.19.821.7343';
const SHA = 'a'.repeat(64);
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const REAL_BATCH = path.resolve(__dirname, '..', 'artifacts',
  '16_19_development', 'objective_bounty_claimed_cli_batch_11_821');

function hash(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function command(...args) {
  return spawnSync(process.execPath, [CLI, 'query-events', ...args], {
    encoding: 'utf8', timeout: 120000,
  });
}

function packetRef(time, param, offset) {
  return {
    source_path: 'synthetic.rofl', replay_sha256: SHA,
    chunk_index: 1, chunk_id: 2, chunk_stream: 'game_chunk',
    chunk_file_offset: 8, decompressed_block_offset: offset,
    decompressed_payload_offset: offset + 6, packet_id: 0x040a,
    replay_time_ms: time, payload_length: 17, raw_param: param,
    raw_payload_sha256: 'b'.repeat(64),
  };
}

function candidate(time = 100, word = 0x40000088, offset = 32) {
  const blob = Buffer.alloc(8);
  blob.writeUInt32LE(469, 0);
  blob.writeUInt32LE(word, 4);
  return {
    event_type: 'OBJECTIVE_BOUNTY_CLAIMED_PACKET_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: PROFILE.id,
    replay_sha256: SHA, replay_time_ms: time, raw_param: 0x400000ae,
    event_id: 0x0113, event_name: 'OnObjectiveBountyClaimed',
    event_schema_u32_0x00: 469, blob_u32_0x04: word,
    raw_event_id_hex: '0x09e5', event_blob_hex: blob.toString('hex'),
    event_blob_sha256: hash(blob), confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
    raw_packet_ref: packetRef(time, 0x400000ae, offset),
  };
}

function writeJson(filename, value) {
  fs.writeFileSync(filename, JSON.stringify(value));
}

function fixture(t, rows = [candidate()]) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-objective-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const artifact = path.join(root, 'replay');
  fs.mkdirSync(artifact);
  const control = packetRef(90, 0x400000af, 8);
  const result = {
    status: 'CANDIDATE', profile_id: PROFILE.id,
    evidence_runtime_image_sha256: PROFILE.evidence_runtime_image_sha256,
    runtime_image_sha256: PROFILE.evidence_runtime_image_sha256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
    input_packet_id: 0x040a, input_packet_scope: 'child_0113_length_17',
    child_event_id: 0x0113, input_count: rows.length + 1,
    target_packet_count: rows.length, event_count: rows.length,
    same_length_control_count: 1, same_length_control_ids: { '0x0114': 1 },
    same_length_control_refs: [{
      child_event_id: 0x0114, raw_event_id_hex: '0x09e6', raw_packet_ref: control,
    }],
    known_limits: [...PROFILE.known_limits],
  };
  const semantic = {
    replay_version: BUILD, replay_sha256: SHA, container_status: 'PASS',
    status: 'CANDIDATE', requested_capabilities: [PROFILE.capability],
    capability_results: { [PROFILE.capability]: result },
  };
  const analysis = {
    patch: '16.19', replay_version: BUILD, replay_sha256: SHA,
    source_path: 'synthetic.rofl',
    event_counts: { [EVENT]: rows.length },
    event_storage: 'JSONL_ONLY', events: null,
    event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` },
  };
  writeJson(path.join(artifact, 'semantic_run.json'), semantic);
  writeJson(path.join(artifact, 'replay_analysis.json'), analysis);
  const lines = rows.map(JSON.stringify);
  fs.writeFileSync(path.join(artifact, `${EVENT}.jsonl`), `${lines.join('\n')}\n`);
  return { root, artifact, semantic, analysis, rows, lines };
}

test('saved exact-821 claim packets support time, child, and anonymous-word queries', async (t) => {
  const sample = fixture(t);
  const selected = command(sample.artifact, '--event', EVENT,
    '--from-ms', '100', '--to-ms', '100', '--child-event-id', '0x0113',
    '--opaque-u32', '0x40000088');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${sample.lines[0]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, 1);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.rows_unmodified, true);

  const prepared = prepareEventQuery(sample.artifact, EVENT);
  const output = [];
  const api = await streamEventQuery(prepared, { opaqueU32: 0x40000088 },
    async (line) => output.push(line));
  assert.deepEqual(output, [`${sample.lines[0]}\n`]);
  assert.equal(api.emitted_count, 1);
});

test('claim query rejects changed exact-image metadata and later corrupt rows', (t) => {
  for (const mutate of [
    (result) => { result.runtime_image_sha256 = 'f'.repeat(64); },
    (result) => { result.input_count += 1; },
    (result) => { result.same_length_control_ids = { '0x0115': 1 }; },
    (result) => { result.same_length_control_refs[0].raw_packet_ref.payload_length = 18; },
  ]) {
    const sample = fixture(t);
    mutate(sample.semantic.capability_results[PROFILE.capability]);
    writeJson(path.join(sample.artifact, 'semantic_run.json'), sample.semantic);
    const rejected = command(sample.artifact, '--event', EVENT);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  }
  for (const mutate of [
    (row) => { row.event_id = 0x0114; },
    (row) => { row.blob_u32_0x04 += 1; },
    (row) => { row.event_blob_sha256 = 'f'.repeat(64); },
    (row) => { row.raw_packet_ref.source_path = 'foreign.rofl'; },
  ]) {
    const rows = [candidate(), candidate(200, 0x40000089, 64)];
    mutate(rows[1]);
    const sample = fixture(t, rows);
    const output = path.join(sample.root, 'must-not-exist.jsonl');
    const rejected = command(sample.artifact, '--event', EVENT,
      '--limit', '1', '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('real 11-Replay claim query preserves seven available and four absent sources', (t) => {
  if (!fs.existsSync(path.join(REAL_BATCH, 'manifest.json'))) {
    t.skip('saved exact-821 claim batch absent');
    return;
  }
  const queried = command(REAL_BATCH, '--event', EVENT, '--child-event-id', '0x0113');
  assert.equal(queried.status, 0, queried.stderr);
  const summary = JSON.parse(queried.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.completed_replay_count, 7);
  assert.equal(summary.unavailable_replay_count, 4);
  assert.equal(summary.scanned_count, 11);
  assert.equal(summary.emitted_count, 11);
  assert.equal(queried.stdout.trim().split('\n').length, 11);
});
