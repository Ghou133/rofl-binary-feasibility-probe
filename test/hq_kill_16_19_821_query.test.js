'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { HQ_KILL_EVENT_PACKET_821_PROFILE: PROFILE } =
  require('../src/decoders/rofl_16_19_821_hq_kill_event_packet_candidate');
const { prepareEventQuery, streamEventQuery } = require('../src/event_query');

const EVENT = 'hq_kill_event_packet_candidates';
const BUILD = '16.19.821.7343';
const SHA = 'a'.repeat(64);
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const REAL_BATCH = path.resolve(__dirname, '..', 'artifacts',
  '16_19_development', 'hq_kill_query_batch_11_821');

function command(...args) {
  return spawnSync(process.execPath, [CLI, 'query-events', ...args], {
    encoding: 'utf8', timeout: 120000,
  });
}

function row(time, rawParam, blockOffset) {
  const blob = Buffer.alloc(108, time & 0xff);
  return {
    event_type: 'HQ_KILL_EVENT_PACKET_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: PROFILE.id,
    replay_sha256: SHA, replay_time_ms: time, raw_param: rawParam,
    event_id: 0x0046, event_name: 'OnHQKill', raw_event_id_hex: '0x4918',
    event_blob_hex: blob.toString('hex'),
    event_blob_sha256: crypto.createHash('sha256').update(blob).digest('hex'),
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_ON_HQ_KILL_PACKET',
    raw_packet_ref: {
      source_path: 'synthetic.rofl', replay_sha256: SHA,
      chunk_index: 1, chunk_id: 2, chunk_stream: 'game_chunk',
      chunk_file_offset: 8, decompressed_block_offset: blockOffset,
      decompressed_payload_offset: blockOffset + 6, packet_id: 0x040a,
      replay_time_ms: time, payload_length: 116, raw_param: rawParam,
      raw_payload_sha256: 'b'.repeat(64),
    },
  };
}

function writeJson(filename, value) {
  fs.writeFileSync(filename, JSON.stringify(value));
}

function fixture(t, rows = [row(100, 0x400000af, 32), row(200, 0x400000b0, 64)]) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-hq-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const artifact = path.join(root, 'replays', 'synthetic');
  fs.mkdirSync(artifact, { recursive: true });
  const capability = {
    status: 'CANDIDATE', profile_id: PROFILE.id,
    evidence_runtime_image_sha256: PROFILE.evidence_runtime_image_sha256,
    runtime_image_sha256: PROFILE.evidence_runtime_image_sha256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_ON_HQ_KILL_PACKET',
    input_packet_id: 0x040a, input_packet_scope: 'child_0046_length_116',
    child_event_id: 0x0046, input_count: rows.length, event_count: rows.length,
    observed_same_length_packet_count: rows.length,
    excluded_same_length_foreign_count: 0,
    excluded_same_length_foreign_packet_refs: [],
    known_limits: [...PROFILE.known_limits],
  };
  const semantic = {
    replay_version: BUILD, replay_sha256: SHA, container_status: 'PASS',
    status: 'CANDIDATE', requested_capabilities: ['hq_kill_event_packet'],
    capability_results: { hq_kill_event_packet: capability },
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

test('CLI and API query exact HQ child, time and raw parameter without changing rows', async (t) => {
  const sample = fixture(t);
  const selected = command(sample.artifact, '--event', EVENT,
    '--from-ms', '200', '--to-ms', '200', '--raw-param', '0x400000b0',
    '--child-event-id', '0x0046');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${sample.lines[1]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.filters.child_event_id, 0x0046);
  assert.equal(summary.rows_unmodified, true);

  const prepared = prepareEventQuery(sample.artifact, EVENT);
  const output = [];
  const apiSummary = await streamEventQuery(prepared,
    { childEventId: 0x0046, limit: 1 }, async (line) => output.push(line));
  assert.deepEqual(output, [`${sample.lines[0]}\n`]);
  assert.equal(apiSummary.scanned_count, 2);
  assert.equal(apiSummary.matched_count, 2);
  assert.equal(apiSummary.emitted_count, 1);

  const otherChild = command(sample.artifact, '--event', EVENT,
    '--child-event-id', '0x0035');
  assert.equal(otherChild.status, 1);
  assert.match(otherChild.stderr, /must be 0x0046/);
  const foreignStream = command(sample.artifact, '--event',
    'hero_inventory_broadcast_packet_candidates', '--child-event-id', '0x0046');
  assert.equal(foreignStream.status, 1);
  assert.match(foreignStream.stderr, /--child-event-id requires/);
});

test('HQ query rejects foreign build, unavailable image and changed profile metadata', (t) => {
  const foreign = fixture(t);
  foreign.semantic.replay_version = '16.19.820.7193';
  foreign.analysis.replay_version = '16.19.820.7193';
  writeJson(path.join(foreign.artifact, 'semantic_run.json'), foreign.semantic);
  writeJson(path.join(foreign.artifact, 'replay_analysis.json'), foreign.analysis);
  const wrongBuild = command(foreign.artifact, '--event', EVENT);
  assert.equal(wrongBuild.status, 2);
  assert.equal(JSON.parse(wrongBuild.stderr).code, 'UNSUPPORTED_EVENT_BUILD');

  for (const status of ['MISSING_INPUT', 'PROFILE_UNAVAILABLE']) {
    const unavailable = fixture(t);
    const result = unavailable.semantic.capability_results.hq_kill_event_packet;
    result.status = status;
    result.event_count = null;
    writeJson(path.join(unavailable.artifact, 'semantic_run.json'), unavailable.semantic);
    const rejected = command(unavailable.artifact, '--event', EVENT);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_UNAVAILABLE');
  }
  for (const mutate of [
    (result) => { result.profile_id = 'foreign'; },
    (result) => { result.runtime_image_sha256 = 'f'.repeat(64); },
    (result) => { result.runtime_image_used = false; },
    (result) => { result.input_packet_scope = 'child_0035_length_116'; },
    (result) => { result.child_event_id = 0x0035; },
    (result) => { result.input_count += 1; },
    (result) => { result.excluded_same_length_foreign_count = 1; },
  ]) {
    const changed = fixture(t);
    mutate(changed.semantic.capability_results.hq_kill_event_packet);
    writeJson(path.join(changed.artifact, 'semantic_run.json'), changed.semantic);
    const rejected = command(changed.artifact, '--event', EVENT);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  }
});

test('HQ query validates later rows and saved packet references after output limit', (t) => {
  for (const mutate of [
    (event) => { event.event_id = 0x0035; },
    (event) => { event.raw_event_id_hex = '0x4906'; },
    (event) => { event.event_blob_hex = '00'; },
    (event) => { event.event_blob_sha256 = 'f'.repeat(64); },
    (event) => { event.raw_packet_ref.source_path = 'foreign.rofl'; },
    (event) => { event.raw_packet_ref.payload_length = 104; },
    (event) => { event.raw_packet_ref.raw_param += 1; },
    (event) => { event.raw_packet_ref.raw_payload_sha256 = 'invalid'; },
  ]) {
    const rows = [row(100, 0x400000af, 32), row(200, 0x400000b0, 64)];
    mutate(rows[1]);
    const sample = fixture(t, rows);
    const output = path.join(sample.root, 'must-not-exist.jsonl');
    const rejected = command(sample.artifact, '--event', EVENT,
      '--child-event-id', '0x0046', '--limit', '1', '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
  const duplicate = fixture(t, [row(100, 0x400000af, 32), row(200, 0x400000b0, 32)]);
  const rejected = command(duplicate.artifact, '--event', EVENT);
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
});

test('saved 11-Replay HQ batch query verifies manifest and emits original lines', (t) => {
  const manifestPath = path.join(REAL_BATCH, 'manifest.json');
  if (!fs.existsSync(manifestPath)) {
    t.skip('saved 11-Replay exact-821 HQ batch absent');
    return;
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const expected = manifest.replay_inputs.map((entry) =>
    fs.readFileSync(path.join(REAL_BATCH, entry.artifact_directory, `${EVENT}.jsonl`),
      'utf8')).join('');
  assert.equal(expected.trim().split('\n').length, 11);
  const selected = command(REAL_BATCH, '--event', EVENT,
    '--child-event-id', '0x0046');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, expected);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.completed_replay_count, 11);
  assert.equal(summary.scanned_count, 11);
  assert.equal(summary.matched_count, 11);
  assert.equal(summary.emitted_count, 11);
  assert.equal(summary.rows_unmodified, true);
  const sourceLines = expected.trim().split('\n');
  const first = JSON.parse(sourceLines[0]);
  const selective = command(REAL_BATCH, '--event', EVENT,
    '--from-ms', String(first.replay_time_ms),
    '--to-ms', String(first.replay_time_ms),
    '--raw-param', String(first.raw_param));
  assert.equal(selective.status, 0, selective.stderr);
  const selectedLines = sourceLines.filter((line) => {
    const event = JSON.parse(line);
    return event.replay_time_ms === first.replay_time_ms
      && event.raw_param === first.raw_param;
  });
  assert.equal(selective.stdout, selectedLines.map((line) => `${line}\n`).join(''));
  assert.equal(JSON.parse(selective.stderr).matched_count, selectedLines.length);
  const limited = command(REAL_BATCH, '--event', EVENT,
    '--child-event-id', '0x0046', '--limit', '1');
  assert.equal(limited.status, 0, limited.stderr);
  assert.equal(limited.stdout, expected.split('\n')[0] + '\n');
  const limitedSummary = JSON.parse(limited.stderr);
  assert.equal(limitedSummary.scanned_count, 11);
  assert.equal(limitedSummary.matched_count, 11);
  assert.equal(limitedSummary.emitted_count, 1);
});
