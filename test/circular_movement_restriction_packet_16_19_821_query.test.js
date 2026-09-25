'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { CIRCULAR_MOVEMENT_RESTRICTION_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeCircularMovementRestrictionPayload821 } = require(
  '../src/decoders/rofl_16_19_821_circular_movement_restriction_packet_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'circular_movement_restriction_packet_candidates';
const CAPABILITY = 'circular_movement_restriction_packet';
const SHA = 'a'.repeat(64);
const SOURCE_PATH = 'synthetic.rofl';
const RECORD_PAYLOAD = '37acbb2393d15e28d1dc507a4e65ef024e04681c4edc8989';

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function command(target, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', target, '--event', EVENT, ...args],
    { encoding: 'utf8' });
}

function row(index, payloadHex = '36', replaySha = SHA) {
  const time = 1000 + index;
  const rawParam = 0x400000ae + index;
  return {
    event_type: 'CIRCULAR_MOVEMENT_RESTRICTION_PACKET_CANDIDATE',
    game_version: profile.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: replaySha,
    replay_time_ms: time, raw_param: rawParam,
    raw_payload_hex: payloadHex, raw_selector_byte: Number.parseInt(payloadHex.slice(0, 2), 16),
    ...decodeCircularMovementRestrictionPayload821(payloadHex),
    semantic_effect_status: 'UNKNOWN', confidence: 'CANDIDATE',
    semantic_status: profile.evidence_status,
    raw_packet_ref: {
      source_path: SOURCE_PATH, replay_sha256: replaySha,
      chunk_index: index + 1, chunk_id: index + 1,
      chunk_stream: index % 2 ? 'game_chunk' : 'keyframe',
      chunk_file_offset: 100 + index,
      decompressed_block_offset: 20 + index,
      decompressed_payload_offset: 29 + index,
      packet_id: profile.replay_block_packet_id,
      replay_time_ms: time, payload_length: payloadHex.length / 2,
      raw_param: rawParam,
      raw_payload_sha256: sha256(Buffer.from(payloadHex, 'hex')),
    },
  };
}

function writeReplay(root, name, rows, {
  replaySha = SHA, replayVersion = profile.replay_version,
  capabilityStatus = 'CANDIDATE',
} = {}) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const empty1 = rows.filter((entry) => entry.packet_shape_candidate === 'empty1').length;
  const result = {
    profile_id: profile.id,
    input_packet_id: profile.replay_block_packet_id,
    evidence_status: profile.evidence_status,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    evidence_byte_table_sha256: profile.evidence_byte_table_sha256,
    evidence_scalar_transform_sha256: profile.evidence_scalar_transform_sha256,
    evidence_vector_transform_sha256: profile.evidence_vector_transform_sha256,
    status: capabilityStatus, input_count: rows.length, event_count: rows.length,
    observed_shape_counts: { empty1, record24: rows.length - empty1 },
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
  };
  const semantic = {
    replay_version: replayVersion, replay_sha256: replaySha,
    container_status: 'PASS', status: 'CANDIDATE', api_status: 'CANDIDATE',
    requested_capabilities: [CAPABILITY], capability_results: { [CAPABILITY]: result },
  };
  const analysis = {
    patch: '16.19', replay_version: replayVersion, replay_sha256: replaySha,
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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-circular-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, ...writeReplay(root, 'synthetic', rows, options) };
}

test('query-events filters checked 821 packet records and preserves source JSONL', (t) => {
  const { directory, lines } = fixture(t,
    [row(0), row(1, RECORD_PAYLOAD), row(2)]);
  const one = command(directory, '--packet-record-count', '1', '--limit', '1');
  assert.equal(one.status, 0, one.stderr);
  assert.equal(one.stdout, `${lines[1]}\n`);
  const summary = JSON.parse(one.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.packet_record_count_checked_count, 3);
  assert.equal(summary.packet_record_count_unavailable_count, 0);
  assert.equal(summary.filters.packet_record_count, 1);
  assert.equal(summary.rows_unmodified, true);

  const zero = command(directory, '--packet-record-count', '0',
    '--raw-param', '0x400000ae');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${lines[0]}\n`);
  assert.equal(JSON.parse(zero.stderr).matched_count, 1);
});

test('query-events distinguishes checked zero matches from unavailable packet fields', (t) => {
  const { directory } = fixture(t, [row(0), row(1)]);
  const checked = command(directory, '--packet-record-count', '1');
  assert.equal(checked.status, 0, checked.stderr);
  assert.equal(checked.stdout, '');
  const summary = JSON.parse(checked.stderr);
  assert.equal(summary.matched_count, 0);
  assert.equal(summary.packet_record_count_checked_count, 2);
  assert.equal(summary.packet_record_count_unavailable_count, 0);

  const unavailable = fixture(t, [row(0)], { capabilityStatus: 'MISSING_INPUT' });
  const missing = command(unavailable.directory, '--packet-record-count', '0');
  assert.equal(missing.status, 2, missing.stderr);
  assert.equal(JSON.parse(missing.stderr).code, 'CAPABILITY_UNAVAILABLE');
});

test('query-events validates every 821 raw payload and reference after output limit', (t) => {
  const corruptions = [
    (entry) => { entry.packet_record_count_candidate = 0; },
    (entry) => { entry.raw_payload_hex = '37'; },
    (entry) => { entry.raw_packet_ref.raw_payload_sha256 = '0'.repeat(64); },
    (entry) => { entry.raw_packet_ref.raw_param += 1; },
    (entry) => { entry.raw_packet_ref.chunk_stream = 'loading'; },
    (entry) => { entry.callback_scalar_bytes_hex = '00000000'; },
    (entry) => { entry.anonymous_vector_xyz_f32_candidate.x += 1; },
    (entry) => { entry.raw_protected_vector_bytes_hex = '0'.repeat(24); },
    (entry) => { entry.semantic_effect_status = 'CONFIRMED'; },
  ];
  for (const corrupt of corruptions) {
    const damaged = row(1, RECORD_PAYLOAD);
    corrupt(damaged);
    const { root, directory } = fixture(t, [row(0), damaged]);
    const output = path.join(root, 'selected.jsonl');
    const result = command(directory, '--packet-record-count', '0',
      '--limit', '1', '--to-ms', '1000', '--output', output);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('query-events checks exact profile, image, transform and shape metadata', (t) => {
  const changes = [
    (result) => { result.profile_id = 'foreign'; },
    (result) => { result.input_packet_id = 0x0465; },
    (result) => { result.runtime_image_sha256 = '0'.repeat(64); },
    (result) => { result.evidence_byte_table_sha256 = '0'.repeat(64); },
    (result) => { result.evidence_scalar_transform_sha256 = '0'.repeat(64); },
    (result) => { result.evidence_vector_transform_sha256 = '0'.repeat(64); },
    (result) => { result.observed_shape_counts.empty1 = 0; },
  ];
  for (const change of changes) {
    const { directory } = fixture(t, [row(0)]);
    const filename = path.join(directory, 'semantic_run.json');
    const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
    change(semantic.capability_results[CAPABILITY]);
    fs.writeFileSync(filename, JSON.stringify(semantic));
    const rejected = command(directory, '--packet-record-count', '0');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  }
});

test('query-events rejects unsupported event, foreign build and filter bounds', (t) => {
  const { directory } = fixture(t, [row(0)]);
  for (const value of ['-1', '2', '0x1', '1.5', '01']) {
    const result = command(directory, '--packet-record-count', value);
    assert.equal(result.status, 1, `${value}: ${result.stderr}`);
  }
  const unsupported = spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', 'hero_level_state_candidates',
      '--packet-record-count', '0'], { encoding: 'utf8' });
  assert.equal(unsupported.status, 1);
  assert.match(unsupported.stderr, /--packet-record-count requires/);
  const foreign = fixture(t, [row(0)], { replayVersion: '16.19.820.7193' });
  const wrongBuild = command(foreign.directory, '--packet-record-count', '0');
  assert.equal(wrongBuild.status, 2, wrongBuild.stderr);
  assert.equal(JSON.parse(wrongBuild.stderr).code, 'UNSUPPORTED_FILTER');
});
