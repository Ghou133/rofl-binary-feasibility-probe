'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { FIRST_BLOOD_ASSIST_EVENT_PACKET_821_PROFILE: PROFILE } =
  require('../src/decoders/rofl_16_19_821_first_blood_assist_event_packet_candidate');
const { prepareEventQuery, streamEventQuery } = require('../src/event_query');

const EVENT = 'first_blood_assist_event_packet_candidates';
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
    packet_id: 0x040a, replay_time_ms: time, payload_length: 16,
    raw_param: rawParam, raw_payload_sha256: 'b'.repeat(64),
  };
}

function row(time, rawParam, offset) {
  const blob = Buffer.from('d501000000000000', 'hex');
  return {
    event_type: 'FIRST_BLOOD_ASSIST_EVENT_PACKET_CANDIDATE',
    game_version: PROFILE.replay_version, patch: '16.19',
    build_profile: PROFILE.id, replay_sha256: SHA,
    replay_time_ms: time, raw_param: rawParam,
    child_event_id: 0x0017, registered_event_name: 'OnFirstBloodAssist',
    raw_event_id_hex: '0x49e4', event_blob_hex: blob.toString('hex'),
    event_blob_sha256: hash(blob), confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
    raw_packet_ref: packetRef(time, rawParam, offset),
  };
}

function writeJson(filename, value) {
  fs.writeFileSync(filename, JSON.stringify(value));
}

function fixture(t, rows = [row(100, 0x400000af, 32), row(200, 0x400000b0, 64)]) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-first-blood-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const artifact = path.join(root, 'replay');
  fs.mkdirSync(artifact);
  const excluded = packetRef(150, 0x400000b1, 96);
  const capability = {
    status: 'CANDIDATE', profile_id: PROFILE.id,
    evidence_runtime_image_sha256: PROFILE.evidence_runtime_image_sha256,
    runtime_image_sha256: PROFILE.evidence_runtime_image_sha256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
    input_packet_id: 0x040a, input_packet_scope: 'child_0017_length_16',
    child_event_id: 0x0017, input_count: rows.length + 1,
    observed_same_length_packet_count: rows.length + 1,
    target_packet_count: rows.length, event_count: rows.length,
    excluded_same_length_foreign_count: 1,
    excluded_same_length_foreign_packet_refs: [excluded],
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

test('saved first-blood-assist query retains exact 821 candidate rows and child filter', async (t) => {
  const sample = fixture(t);
  const selected = command(sample.artifact, '--event', EVENT,
    '--child-event-id', '0x0017', '--from-ms', '200', '--raw-param', '0x400000b0');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${sample.lines[1]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.filters.child_event_id, 0x0017);
  assert.equal(summary.rows_unmodified, true);

  const output = [];
  const apiSummary = await streamEventQuery(prepareEventQuery(sample.artifact, EVENT),
    { childEventId: 0x0017, limit: 1 }, async (line) => output.push(line));
  assert.deepEqual(output, [`${sample.lines[0]}\n`]);
  assert.equal(apiSummary.scanned_count, 2);
  assert.equal(apiSummary.matched_count, 2);
  assert.equal(apiSummary.emitted_count, 1);

  const foreignChild = command(sample.artifact, '--event', EVENT,
    '--child-event-id', '0x002c');
  assert.equal(foreignChild.status, 1);
  assert.match(foreignChild.stderr, /must be 0x0017/);
});

test('saved first-blood-assist query rejects foreign build and changed witness metadata', (t) => {
  for (const mutate of [
    (sample) => {
      sample.semantic.replay_version = '16.19.820.7193';
      sample.analysis.replay_version = '16.19.820.7193';
    },
    (sample) => { sample.semantic.capability_results[PROFILE.capability].profile_id = 'foreign'; },
    (sample) => { sample.semantic.capability_results[PROFILE.capability].status = 'PASS'; },
    (sample) => { sample.semantic.capability_results[PROFILE.capability].runtime_image_used = false; },
    (sample) => { sample.semantic.capability_results[PROFILE.capability].input_count += 1; },
    (sample) => { sample.semantic.capability_results[PROFILE.capability]
      .excluded_same_length_foreign_packet_refs[0].packet_id = 0x040b; },
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

test('saved first-blood-assist query checks every row after output limit', (t) => {
  for (const mutate of [
    (event) => { event.child_event_id = 0x002c; },
    (event) => { event.registered_event_name = 'OnReviveAlly'; },
    (event) => { event.event_blob_hex = '00'; },
    (event) => { event.event_blob_sha256 = 'f'.repeat(64); },
    (event) => { event.raw_packet_ref.payload_length = 17; },
    (event) => { event.raw_packet_ref.raw_param += 1; },
    (event) => { event.raw_packet_ref.decompressed_block_offset = 96; },
    (event) => { event.assisting_participant_id = 1; },
  ]) {
    const rows = [row(100, 0x400000af, 32), row(200, 0x400000b0, 64)];
    mutate(rows[1]);
    const sample = fixture(t, rows);
    const output = path.join(sample.root, 'must-not-exist.jsonl');
    const rejected = command(sample.artifact, '--event', EVENT,
      '--child-event-id', '0x0017', '--limit', '1', '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
  const duplicate = fixture(t,
    [row(100, 0x400000af, 32), row(200, 0x400000b0, 32)]);
  const rejected = command(duplicate.artifact, '--event', EVENT);
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
});

test('saved target and absent 821 artifacts retain complete and unavailable statuses', (t) => {
  const target = path.join(SAVED, 'merged_first_blood_assist_target');
  const absent = path.join(SAVED, 'merged_first_blood_assist_absent');
  if (!fs.existsSync(path.join(target, 'manifest.json'))
      || !fs.existsSync(path.join(absent, 'manifest.json'))) {
    t.skip('saved exact-821 target or absent artifact is unavailable');
    return;
  }
  const targetRun = command(target, '--event', EVENT,
    '--child-event-id', '0x0017', '--limit', '1');
  assert.equal(targetRun.status, 0, targetRun.stderr);
  const targetSummary = JSON.parse(targetRun.stderr);
  assert.equal(targetSummary.query_status, 'COMPLETE');
  assert.equal(targetSummary.scanned_count, 2);
  assert.equal(targetSummary.emitted_count, 1);
  assert.equal(JSON.parse(targetRun.stdout).child_event_id, 0x0017);

  const absentRun = command(absent, '--event', EVENT,
    '--child-event-id', '0x0017');
  assert.equal(absentRun.status, 2, absentRun.stderr);
  const absentSummary = JSON.parse(absentRun.stderr);
  assert.equal(absentSummary.code, 'BATCH_EVENT_UNAVAILABLE');
  assert.equal(absentSummary.replay_results[0].code, 'CAPABILITY_UNAVAILABLE');
  assert.equal(absentSummary.replay_results[0].capability_status,
    'PROFILE_UNAVAILABLE');
});
