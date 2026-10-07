'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { NOTIFY_CONTEXTUAL_SITUATION_PACKET_CANDIDATE_PROFILE_821: profile } =
  require('../src/decoders/rofl_16_19_821_notify_contextual_situation_packet_candidate');
const { bindSavedPacketArtifactToPhysicalReplay } =
  require('./helpers/physical_saved_packet_replay');

const CLI = path.resolve(__dirname, '../src/cli.js');
const CAPABILITY = 'notify_contextual_situation_packet';
const EVENT = 'notify_contextual_situation_packet_candidates';
const PAYLOAD_HEX = '0cc3aafbf72fbf89888831f7311f';
const BLASTCONE_PAYLOAD_HEX = '0e670619e699e6dcf3d7d7e6f0cd09f3ea';
const SOURCE_PATH = 'synthetic.rofl';
const STRING = 'RecallLeadIn';

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function row(index, replaySha, situation = STRING) {
  const time = 1000 + index;
  const rawParam = 0x400000b4 + index;
  const bytes = Buffer.from(situation, 'utf8');
  const payloadHex = situation === 'AttackBlastcone'
    ? BLASTCONE_PAYLOAD_HEX : PAYLOAD_HEX;
  return {
    event_type: 'NOTIFY_CONTEXTUAL_SITUATION_PACKET_CANDIDATE',
    game_version: profile.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: replaySha,
    replay_time_ms: time, raw_param: rawParam,
    packet_name_candidate: profile.packet_name,
    contextual_situation: situation,
    contextual_situation_utf8_hex: bytes.toString('hex'),
    native_string_length: bytes.length,
    native_string_capacity: bytes.length + (situation === 'AttackBlastcone' ? 2 : 1),
    semantic_effect_status: 'UNKNOWN', confidence: 'CANDIDATE',
    semantic_status: profile.evidence_status,
    raw_packet_ref: {
      source_path: SOURCE_PATH, replay_sha256: replaySha,
      chunk_index: index, chunk_id: index + 1, chunk_stream: 'game_chunk',
      chunk_file_offset: 100 + index,
      decompressed_block_offset: 20 + index * 30,
      decompressed_payload_offset: 29 + index * 30,
      packet_id: profile.replay_block_packet_id, replay_time_ms: time,
      payload_length: payloadHex.length / 2, raw_param: rawParam,
      raw_payload_hex: payloadHex,
      raw_payload_sha256: sha256(Buffer.from(payloadHex, 'hex')),
    },
  };
}

function nativeInputSha256(rows) {
  const digest = crypto.createHash('sha256');
  const header = Buffer.alloc(8);
  for (const entry of rows) {
    const payload = Buffer.from(entry.raw_packet_ref.raw_payload_hex, 'hex');
    header.writeUInt32LE(entry.raw_param, 0);
    header.writeUInt32LE(payload.length, 4);
    digest.update(header);
    digest.update(payload);
  }
  return digest.digest('hex');
}

function nativeOutputSha256(rows) {
  const digest = crypto.createHash('sha256');
  const header = Buffer.alloc(8);
  for (const entry of rows) {
    const bytes = Buffer.from(entry.contextual_situation_utf8_hex, 'hex');
    header.writeUInt32LE(entry.native_string_length, 0);
    header.writeUInt32LE(entry.native_string_capacity, 4);
    digest.update(header);
    digest.update(bytes);
  }
  return digest.digest('hex');
}

function writeReplay(root, name, rows, replaySha, replayVersion = profile.replay_version) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const result = {
    profile_id: profile.id, input_packet_id: profile.replay_block_packet_id,
    evidence_status: profile.evidence_status,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    status: 'CANDIDATE', input_count: rows.length, event_count: rows.length,
    scanned_block_count: rows.length + 2,
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      contextual_situation: 'CANDIDATE_EXACT_RUNTIME_NATIVE_STRING',
    },
    native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: rows.length,
    native_input_sha256: nativeInputSha256(rows),
    native_output_sha256: nativeOutputSha256(rows),
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
  };
  const semantic = {
    replay_version: replayVersion, replay_sha256: replaySha,
    container_status: 'PASS', status: 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE',
    requested_capabilities: [CAPABILITY],
    capability_results: { [CAPABILITY]: result },
  };
  const analysis = {
    patch: '16.19', replay_version: replayVersion, replay_sha256: replaySha,
    source_path: SOURCE_PATH, event_storage: 'JSONL_ONLY',
    event_counts: { [EVENT]: rows.length },
    event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` }, events: null,
    semantic: { status: semantic.status,
      requested_capabilities: [CAPABILITY],
      capability_results: { [CAPABILITY]: result } },
  };
  const semanticPath = path.join(directory, 'semantic_run.json');
  const analysisPath = path.join(directory, 'replay_analysis.json');
  const eventPath = path.join(directory, `${EVENT}.jsonl`);
  const lines = rows.map(JSON.stringify);
  fs.writeFileSync(semanticPath, JSON.stringify(semantic));
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  fs.writeFileSync(eventPath, `${lines.join('\n')}\n`);
  return { directory, semanticPath, analysisPath, eventPath, lines,
    sha: replaySha, name };
}

function fixture(t, count = 2) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-contextual-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const replaySha = 'a'.repeat(64);
  const first = writeReplay(root, 'first',
    Array.from({ length: count }, (_, index) => row(index, replaySha)), replaySha);
  return { root, first };
}

function query(target, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', target, '--event', EVENT, ...args],
    { encoding: 'utf8' });
}

function errorCode(result) {
  assert.equal(result.status, 2, result.stderr);
  return JSON.parse(result.stderr).code;
}

test('source verification accepts exact-821 contextual packet references', (t) => {
  const { first } = fixture(t);
  const physical = bindSavedPacketArtifactToPhysicalReplay(first.directory);
  const selected = query(first.directory, '--verify-source', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(physical.rows[0])}\n`);
  assert.equal(JSON.parse(selected.stderr).source_provenance_status,
    'SOURCE_REPLAY_VERIFIED');
});

test('saved 821 contextual string query filters exact text, time and raw parameter', (t) => {
  const { first } = fixture(t);
  const selected = query(first.directory, '--contextual-situation', STRING,
    '--from-ms', '1001', '--to-ms', '1001', '--raw-param', '0x400000b5');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${first.lines[1]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.rows_unmodified, true);
  assert.equal(summary.filters.contextual_situation, STRING);
  assert.equal(fs.readFileSync(first.eventPath, 'utf8'),
    `${first.lines.join('\n')}\n`);

  const prefix = query(first.directory, '--contextual-situation', 'Recall');
  assert.equal(prefix.status, 0, prefix.stderr);
  assert.equal(prefix.stdout, '');
  assert.equal(JSON.parse(prefix.stderr).matched_count, 0);
  assert.equal(errorCode(query(first.directory, '--participant', '1')),
    'PARTICIPANT_UNAVAILABLE');
});

test('saved 821 contextual rows are validated after limit and partial output is removed', (t) => {
  const { root, first } = fixture(t);
  const original = fs.readFileSync(first.eventPath, 'utf8');
  const corruptions = [
    (entry) => { entry.contextual_situation = 'UnknownAction'; },
    (entry) => { entry.contextual_situation_utf8_hex = 'ff'; },
    (entry) => { entry.native_string_length = 11; },
    (entry) => { entry.native_string_capacity = 12; },
    (entry) => { entry.packet_name_candidate = 'Recall'; },
    (entry) => { entry.raw_packet_ref.packet_id = 0x040a; },
    (entry) => { entry.raw_packet_ref.raw_payload_hex = '00'.repeat(14); },
    (entry) => { entry.raw_packet_ref.raw_payload_sha256 = '0'.repeat(64); },
    (entry) => { entry.raw_packet_ref.chunk_stream = 'keyframe'; },
    (entry) => { entry.semantic_effect_status = 'CONFIRMED'; },
    (entry) => { entry.participant_id_candidate = 7; },
  ];
  for (const corrupt of corruptions) {
    const rows = first.lines.map((line) => JSON.parse(line));
    corrupt(rows[1]);
    fs.writeFileSync(first.eventPath, `${rows.map(JSON.stringify).join('\n')}\n`);
    const output = path.join(root, 'selected.jsonl');
    const selected = query(first.directory, '--limit', '1', '--output', output);
    assert.equal(errorCode(selected), 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
    fs.writeFileSync(first.eventPath, original);
  }
});

test('valid-to-valid native string forgery fails the ordered output digest, including after limit', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-contextual-output-hash-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const replaySha = 'a'.repeat(64);
  const first = writeReplay(root, 'first', [
    row(0, replaySha, 'AttackBlastcone'),
    row(1, replaySha, 'AttackBlastcone'),
  ], replaySha);
  const original = first.lines.map((line) => JSON.parse(line));
  for (const alteredIndex of [0, 1]) {
    const forged = structuredClone(original);
    forged[alteredIndex].contextual_situation = 'RecallLeadIn';
    forged[alteredIndex].contextual_situation_utf8_hex =
      Buffer.from('RecallLeadIn', 'utf8').toString('hex');
    forged[alteredIndex].native_string_length = Buffer.byteLength('RecallLeadIn');
    forged[alteredIndex].native_string_capacity = Buffer.byteLength('RecallLeadIn') + 1;
    fs.writeFileSync(first.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
    const output = path.join(root, `forged-${alteredIndex}.jsonl`);
    const selected = query(first.directory, '--contextual-situation',
      alteredIndex === 0 ? 'RecallLeadIn' : 'AttackBlastcone',
      '--limit', '1', '--output', output);
    assert.equal(errorCode(selected), 'EVENT_COUNT_MISMATCH');
    assert.equal(fs.existsSync(output), false);
  }
});

test('saved 821 contextual metadata is exact-build and native-input/output bound', (t) => {
  const { first } = fixture(t);
  const originalSemantic = fs.readFileSync(first.semanticPath, 'utf8');
  const originalAnalysis = fs.readFileSync(first.analysisPath, 'utf8');
  for (const [field, value] of [
    ['profile_id', 'foreign'],
    ['runtime_image_sha256', '0'.repeat(64)],
    ['native_full_success_count', 1],
    ['native_output_sha256', 'not-a-sha'],
  ]) {
    const semantic = JSON.parse(originalSemantic);
    const analysis = JSON.parse(originalAnalysis);
    semantic.capability_results[CAPABILITY][field] = value;
    analysis.semantic.capability_results[CAPABILITY][field] = value;
    fs.writeFileSync(first.semanticPath, JSON.stringify(semantic));
    fs.writeFileSync(first.analysisPath, JSON.stringify(analysis));
    assert.equal(errorCode(query(first.directory)), 'CAPABILITY_METADATA_MISMATCH');
  }
  fs.writeFileSync(first.semanticPath, originalSemantic);
  fs.writeFileSync(first.analysisPath, originalAnalysis);
  const semantic = JSON.parse(originalSemantic);
  const analysis = JSON.parse(originalAnalysis);
  semantic.capability_results[CAPABILITY].native_input_sha256 = '0'.repeat(64);
  analysis.semantic.capability_results[CAPABILITY].native_input_sha256 = '0'.repeat(64);
  fs.writeFileSync(first.semanticPath, JSON.stringify(semantic));
  fs.writeFileSync(first.analysisPath, JSON.stringify(analysis));
  assert.equal(errorCode(query(first.directory)), 'EVENT_COUNT_MISMATCH');

  semantic.capability_results[CAPABILITY].native_input_sha256 =
    JSON.parse(originalSemantic).capability_results[CAPABILITY].native_input_sha256;
  analysis.semantic.capability_results[CAPABILITY].native_input_sha256 =
    JSON.parse(originalAnalysis).semantic.capability_results[CAPABILITY].native_input_sha256;
  semantic.capability_results[CAPABILITY].native_output_sha256 = '0'.repeat(64);
  analysis.semantic.capability_results[CAPABILITY].native_output_sha256 = '0'.repeat(64);
  fs.writeFileSync(first.semanticPath, JSON.stringify(semantic));
  fs.writeFileSync(first.analysisPath, JSON.stringify(analysis));
  assert.equal(errorCode(query(first.directory)), 'EVENT_COUNT_MISMATCH');

  fs.writeFileSync(first.semanticPath, originalSemantic);
  fs.writeFileSync(first.analysisPath, originalAnalysis);
  const foreignSemantic = JSON.parse(originalSemantic);
  const foreignAnalysis = JSON.parse(originalAnalysis);
  foreignSemantic.replay_version = '16.19.820.7193';
  foreignAnalysis.replay_version = '16.19.820.7193';
  fs.writeFileSync(first.semanticPath, JSON.stringify(foreignSemantic));
  fs.writeFileSync(first.analysisPath, JSON.stringify(foreignAnalysis));
  assert.equal(errorCode(query(first.directory)), 'UNSUPPORTED_EVENT_BUILD');

  const unavailableSemantic = JSON.parse(originalSemantic);
  const unavailableAnalysis = JSON.parse(originalAnalysis);
  unavailableSemantic.capability_results[CAPABILITY].status = 'MISSING_INPUT';
  unavailableAnalysis.semantic.capability_results[CAPABILITY].status = 'MISSING_INPUT';
  fs.writeFileSync(first.semanticPath, JSON.stringify(unavailableSemantic));
  fs.writeFileSync(first.analysisPath, JSON.stringify(unavailableAnalysis));
  assert.equal(errorCode(query(first.directory)), 'CAPABILITY_UNAVAILABLE');

  for (const promotedStatus of ['PASS', 'PROMOTED']) {
    const promotedSemantic = JSON.parse(originalSemantic);
    const promotedAnalysis = JSON.parse(originalAnalysis);
    promotedSemantic.capability_results[CAPABILITY].status = promotedStatus;
    promotedAnalysis.semantic.capability_results[CAPABILITY].status = promotedStatus;
    fs.writeFileSync(first.semanticPath, JSON.stringify(promotedSemantic));
    fs.writeFileSync(first.analysisPath, JSON.stringify(promotedAnalysis));
    assert.equal(errorCode(query(first.directory)), 'CAPABILITY_METADATA_MISMATCH');
  }
});

test('contextual string filter is scoped to its candidate event', (t) => {
  const { first } = fixture(t);
  const wrongEvent = spawnSync(process.execPath,
    [CLI, 'query-events', first.directory, '--event', 'hero_death_candidates',
      '--contextual-situation', STRING], { encoding: 'utf8' });
  assert.equal(wrongEvent.status, 1);
  assert.match(wrongEvent.stderr, /--contextual-situation requires/);
  const listWithFilter = spawnSync(process.execPath,
    [CLI, 'query-events', first.directory, '--list-events',
      '--contextual-situation', STRING], { encoding: 'utf8' });
  assert.equal(listWithFilter.status, 1);
});

test('batch contextual queries retain manifest hashes and original JSONL rows', (t) => {
  const { root, first } = fixture(t, 1);
  const secondSha = 'b'.repeat(64);
  const second = writeReplay(root, 'second', [row(0, secondSha)], secondSha);
  const hashes = {};
  for (const entry of [first, second]) {
    for (const name of fs.readdirSync(entry.directory)) {
      const relative = `replays/${entry.name}/${name}`;
      hashes[relative] = sha256(fs.readFileSync(path.join(root, relative)));
    }
  }
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
    command_args: ['batch', 'synthetic-input'],
    replay_inputs: [first, second].map((entry) => ({
      sha256: entry.sha, version: profile.replay_version,
      artifact_directory: `replays/${entry.name}`,
    })),
    output_hashes_excluding_manifest: hashes,
  }));
  const selected = query(root, '--contextual-situation', STRING);
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${first.lines[0]}\n${second.lines[0]}\n`);
  assert.equal(JSON.parse(selected.stderr).query_status, 'COMPLETE');

  fs.appendFileSync(second.eventPath, ' ');
  const tampered = query(root, '--contextual-situation', STRING);
  assert.equal(errorCode(tampered), 'ARTIFACT_HASH_MISMATCH');
});
