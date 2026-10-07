'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { OBJECTIVE_STEAL_EVENT_PACKET_821_PROFILE: PROFILE } =
  require('../src/decoders/rofl_16_19_821_objective_steal_event_packet_candidate');
const { prepareEventQuery, streamEventQuery } = require('../src/event_query');

const EVENT = 'objective_steal_event_packet_candidates';
const SHA = 'a'.repeat(64);
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const SAVED = path.resolve(__dirname, '..', 'artifacts', '16_19_development');

function command(...args) {
  return spawnSync(process.execPath, [CLI, 'query-events', ...args], {
    encoding: 'utf8', timeout: 120000,
  });
}

function hash(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packetRef(time, rawParam, offset) {
  return {
    source_path: 'synthetic.rofl', replay_sha256: SHA,
    chunk_index: 1, chunk_id: 2, chunk_stream: 'game_chunk',
    chunk_file_offset: 8, decompressed_block_offset: offset,
    decompressed_payload_offset: offset + 6,
    packet_id: 0x040a, replay_time_ms: time, payload_length: 133,
    raw_param: rawParam, raw_payload_sha256: 'b'.repeat(64),
  };
}

function row(childId, time, rawParam, offset) {
  const dragon = childId === 0x00be;
  const blob = Buffer.alloc(124, dragon ? 0x31 : 0x32);
  return {
    event_type: 'OBJECTIVE_STEAL_EVENT_PACKET_CANDIDATE',
    game_version: PROFILE.replay_version, patch: '16.19',
    build_profile: PROFILE.id, replay_sha256: SHA,
    replay_time_ms: time, raw_param: rawParam,
    child_event_id: childId,
    registered_event_name: dragon ? 'OnKillDragonSteal' : 'OnKillWormSteal',
    raw_event_id_hex: dragon ? '0x499e' : '0x490c',
    event_blob_hex: blob.toString('hex'), event_blob_sha256: hash(blob),
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
    semantic_effect_status: 'UNKNOWN',
    raw_packet_ref: packetRef(time, rawParam, offset),
  };
}

function writeJson(filename, value) {
  fs.writeFileSync(filename, JSON.stringify(value));
}

function fixture(t, rows = [
  row(0x00be, 100, 0x400000af, 32),
  row(0x00d6, 200, 0x400000b0, 64),
]) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-objective-steal-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const artifact = path.join(root, 'replay');
  fs.mkdirSync(artifact);
  const capability = {
    status: 'CANDIDATE', profile_id: PROFILE.id,
    evidence_runtime_image_sha256: PROFILE.evidence_runtime_image_sha256,
    runtime_image_sha256: PROFILE.evidence_runtime_image_sha256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
    input_packet_id: 0x040a,
    input_packet_scope: 'children_00be_00d6_length_133',
    child_event_ids: [0x00be, 0x00d6],
    input_count: rows.length, observed_same_length_packet_count: rows.length,
    target_packet_count: rows.length, event_count: rows.length,
    child_event_id_counts: { '0x00be': 1, '0x00d6': 1 },
    scanned_block_count: 10,
    known_limits: [...PROFILE.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      child_event_id: 'VERIFIED_EXACT_NATIVE_CHILD',
      registered_event_name: 'VERIFIED_EXACT_IMAGE_LABEL',
      event_blob_hex: 'VERIFIED_EXACT_NATIVE_BLOB',
    },
  };
  const semantic = {
    replay_version: PROFILE.replay_version, replay_sha256: SHA,
    container_status: 'PASS', status: 'CANDIDATE',
    requested_capabilities: [PROFILE.capability],
    capability_results: { [PROFILE.capability]: capability },
  };
  const analysis = {
    patch: '16.19', replay_version: PROFILE.replay_version,
    replay_sha256: SHA, source_path: 'synthetic.rofl',
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

test('objective steal query filters both exact 821 child IDs without changing rows', async (t) => {
  const sample = fixture(t);
  const dragon = command(sample.artifact, '--event', EVENT,
    '--child-event-id', '0x00be', '--raw-param', '0x400000af');
  assert.equal(dragon.status, 0, dragon.stderr);
  assert.equal(dragon.stdout, `${sample.lines[0]}\n`);
  const dragonSummary = JSON.parse(dragon.stderr);
  assert.equal(dragonSummary.query_status, 'COMPLETE');
  assert.equal(dragonSummary.scanned_count, 2);
  assert.equal(dragonSummary.matched_count, 1);
  assert.equal(dragonSummary.filters.child_event_id, 0x00be);
  assert.equal(dragonSummary.rows_unmodified, true);

  const output = [];
  const wormSummary = await streamEventQuery(prepareEventQuery(sample.artifact, EVENT),
    { childEventId: 0x00d6, limit: 1 }, async (line) => output.push(line));
  assert.deepEqual(output, [`${sample.lines[1]}\n`]);
  assert.equal(wormSummary.scanned_count, 2);
  assert.equal(wormSummary.matched_count, 1);
  assert.equal(wormSummary.emitted_count, 1);

  const noMatch = command(sample.artifact, '--event', EVENT,
    '--child-event-id', '0x00be', '--from-ms', '201');
  assert.equal(noMatch.status, 0, noMatch.stderr);
  assert.equal(noMatch.stdout, '');
  assert.equal(JSON.parse(noMatch.stderr).matched_count, 0);
  const foreignChild = command(sample.artifact, '--event', EVENT,
    '--child-event-id', '0x0046');
  assert.equal(foreignChild.status, 1);
  assert.match(foreignChild.stderr, /must be 0x00be.*0x00d6/);
});

test('objective steal query rejects wrong build and altered candidate metadata', (t) => {
  for (const mutate of [
    (sample) => {
      sample.semantic.replay_version = '16.19.820.7193';
      sample.analysis.replay_version = '16.19.820.7193';
    },
    (sample) => { sample.semantic.capability_results[PROFILE.capability].status = 'PASS'; },
    (sample) => { sample.semantic.capability_results[PROFILE.capability].profile_id = 'foreign'; },
    (sample) => { sample.semantic.capability_results[PROFILE.capability].runtime_image_sha256 = 'f'.repeat(64); },
    (sample) => { sample.semantic.capability_results[PROFILE.capability].child_event_ids = [0x00be]; },
    (sample) => { sample.semantic.capability_results[PROFILE.capability].child_event_id_counts['0x00d6'] = 0; },
    (sample) => { sample.semantic.capability_results[PROFILE.capability].input_count += 1; },
  ]) {
    const sample = fixture(t);
    mutate(sample);
    writeJson(path.join(sample.artifact, 'semantic_run.json'), sample.semantic);
    writeJson(path.join(sample.artifact, 'replay_analysis.json'), sample.analysis);
    const rejected = command(sample.artifact, '--event', EVENT);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code,
      sample.semantic.replay_version === PROFILE.replay_version
        ? 'CAPABILITY_METADATA_MISMATCH' : 'UNSUPPORTED_EVENT_BUILD');
  }
});

test('objective steal query validates later rows and totals after output limit', (t) => {
  for (const mutate of [
    (event) => { event.child_event_id = 0x0046; },
    (event) => { event.registered_event_name = 'OnKillDragonSteal'; },
    (event) => { event.raw_event_id_hex = '0x499e'; },
    (event) => { event.event_blob_hex = '00'; },
    (event) => { event.event_blob_sha256 = 'f'.repeat(64); },
    (event) => { event.raw_packet_ref.payload_length = 132; },
    (event) => { event.raw_packet_ref.raw_param += 1; },
    (event) => { event.raw_packet_ref.decompressed_block_offset = 32; },
    (event) => { event.semantic_effect_status = 'PASS'; },
    (event) => { event.actor = 1; },
  ]) {
    const rows = [row(0x00be, 100, 0x400000af, 32),
      row(0x00d6, 200, 0x400000b0, 64)];
    mutate(rows[1]);
    const sample = fixture(t, rows);
    const output = path.join(sample.root, 'must-not-exist.jsonl');
    const rejected = command(sample.artifact, '--event', EVENT,
      '--child-event-id', '0x00be', '--limit', '1', '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
  const wrongTotals = fixture(t, [row(0x00be, 100, 0x400000af, 32),
    row(0x00be, 200, 0x400000b0, 64)]);
  const output = path.join(wrongTotals.root, 'must-not-exist.jsonl');
  const rejected = command(wrongTotals.artifact, '--event', EVENT,
    '--limit', '1', '--output', output);
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'EVENT_COUNT_MISMATCH');
  assert.equal(fs.existsSync(output), false);
});

test('saved dragon, worm, and absent 821 artifacts preserve query statuses', (t) => {
  const dragon = path.join(SAVED, 'objective_steal_merged_dragon');
  const worm = path.join(SAVED, 'objective_steal_merged_worm');
  const absent = path.join(SAVED, 'objective_steal_merged_absent');
  if ([dragon, worm, absent].some((directory) =>
    !fs.existsSync(path.join(directory, 'manifest.json')))) {
    t.skip('saved exact-821 objective-steal artifacts are unavailable');
    return;
  }
  for (const [directory, childId] of [[dragon, 0x00be], [worm, 0x00d6]]) {
    const selected = command(directory, '--event', EVENT,
      '--child-event-id', `0x${childId.toString(16)}`, '--limit', '1');
    assert.equal(selected.status, 0, selected.stderr);
    const summary = JSON.parse(selected.stderr);
    assert.equal(summary.query_status, 'COMPLETE');
    assert.equal(summary.scanned_count, 1);
    assert.equal(summary.emitted_count, 1);
    assert.equal(JSON.parse(selected.stdout).child_event_id, childId);
  }
  const unavailable = command(absent, '--event', EVENT,
    '--child-event-id', '0x00be');
  assert.equal(unavailable.status, 2, unavailable.stderr);
  const summary = JSON.parse(unavailable.stderr);
  assert.equal(summary.code, 'BATCH_EVENT_UNAVAILABLE');
  assert.equal(summary.replay_results[0].code, 'CAPABILITY_UNAVAILABLE');
  assert.equal(summary.replay_results[0].capability_status, 'PROFILE_UNAVAILABLE');
});
