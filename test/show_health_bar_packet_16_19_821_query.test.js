'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { SHOW_HEALTH_BAR_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeShowHealthBarPayload821 } = require(
  '../src/decoders/rofl_16_19_821_show_health_bar_packet_candidate');
const { bindSavedPacketArtifactToPhysicalReplay } =
  require('./helpers/physical_saved_packet_replay');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'show_health_bar_packet_candidates';
const CAPABILITY = 'show_health_bar_packet';
const SOURCE_PATH = 'synthetic.rofl';

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function nativeInputSha256(rows) {
  const hash = crypto.createHash('sha256');
  for (const entry of rows) {
    const payload = Buffer.from(entry.raw_packet_ref.raw_payload_hex, 'hex');
    const header = Buffer.alloc(8);
    header.writeUInt32LE(entry.raw_param, 0);
    header.writeUInt32LE(payload.length, 4);
    hash.update(header).update(payload);
  }
  return hash.digest('hex');
}

function command(target, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', target, '--event', EVENT, ...args],
    { encoding: 'utf8' });
}

function row(index, payloadHex = '4a', replaySha = 'a'.repeat(64)) {
  const time = 1000 + index;
  const rawParam = 0x40004007 + index;
  return {
    event_type: 'SHOW_HEALTH_BAR_PACKET_CANDIDATE',
    game_version: profile.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: replaySha,
    replay_time_ms: time, raw_param: rawParam,
    packet_name_candidate: profile.packet_name,
    ...decodeShowHealthBarPayload821(payloadHex),
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
      replay_time_ms: time, payload_length: 1, raw_param: rawParam,
      raw_payload_hex: payloadHex,
      raw_payload_sha256: sha256(Buffer.from(payloadHex, 'hex')),
    },
  };
}

function writeReplay(root, name, rows, {
  replaySha = 'a'.repeat(64), replayVersion = profile.replay_version,
  capabilityStatus = 'CANDIDATE',
} = {}) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const result = {
    profile_id: profile.id,
    input_packet_id: profile.replay_block_packet_id,
    evidence_status: profile.evidence_status,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    evidence_callback_table_sha256: profile.evidence_callback_table_sha256,
    status: capabilityStatus, input_count: rows.length, event_count: rows.length,
    scanned_block_count: rows.length + 100,
    known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      callback_byte_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
      callback_zero_flag_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
    },
    observed_payload_counts: {
      '4a': rows.filter((entry) => entry.raw_payload_byte_hex === '4a').length,
      '4b': rows.filter((entry) => entry.raw_payload_byte_hex === '4b').length,
    },
    native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: rows.length,
    native_input_sha256: nativeInputSha256(rows),
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
  };
  const semantic = {
    replay_version: replayVersion, replay_sha256: replaySha,
    container_status: 'PASS', status: 'EXPERIMENTAL_CANDIDATE',
    api_status: 'CANDIDATE', requested_capabilities: [CAPABILITY],
    capability_results: { [CAPABILITY]: result },
  };
  const analysis = {
    patch: '16.19', replay_version: replayVersion, replay_sha256: replaySha,
    source_path: SOURCE_PATH, event_storage: 'JSONL_ONLY',
    event_counts: { [EVENT]: rows.length },
    event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` }, events: null,
    semantic: { capability_results: { [CAPABILITY]: structuredClone(result) } },
  };
  fs.writeFileSync(path.join(directory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(directory, 'replay_analysis.json'), JSON.stringify(analysis));
  const lines = rows.map((entry) => JSON.stringify(entry));
  fs.writeFileSync(path.join(directory, `${EVENT}.jsonl`),
    lines.length ? `${lines.join('\n')}\n` : '');
  return { directory, lines, replaySha, replayVersion };
}

function fixture(t, rows, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-show-bar-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, ...writeReplay(root, 'synthetic', rows, options) };
}

function changeResult(directory, mutate) {
  for (const basename of ['semantic_run.json', 'replay_analysis.json']) {
    const filename = path.join(directory, basename);
    const document = JSON.parse(fs.readFileSync(filename, 'utf8'));
    const result = basename === 'semantic_run.json'
      ? document.capability_results[CAPABILITY]
      : document.semantic.capability_results[CAPABILITY];
    mutate(result);
    fs.writeFileSync(filename, JSON.stringify(document));
  }
}

function writeManifest(root, entries) {
  const hashes = {};
  for (const entry of entries) {
    for (const basename of ['semantic_run.json', 'replay_analysis.json',
      `${EVENT}.jsonl`]) {
      const filename = path.join(entry.directory, basename);
      hashes[`replays/${path.basename(entry.directory)}/${basename}`] =
        sha256(fs.readFileSync(filename));
    }
  }
  const manifest = {
    command_args: ['batch'],
    replay_inputs: entries.map((entry) => ({
      artifact_directory: `replays/${path.basename(entry.directory)}`,
      sha256: entry.replaySha, version: entry.replayVersion,
    })),
    output_hashes_excluding_manifest: hashes,
  };
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify(manifest));
}

test('query-events filters exact 821 callback zero flags and preserves JSONL', (t) => {
  const { directory, lines } = fixture(t, [row(0), row(1, '4b'), row(2)]);
  const one = command(directory, '--show-health-zero-flag', '1', '--limit', '1');
  assert.equal(one.status, 0, one.stderr);
  assert.equal(one.stdout, `${lines[1]}\n`);
  const summary = JSON.parse(one.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.show_health_zero_flag_checked_count, 3);
  assert.equal(summary.show_health_zero_flag_unavailable_count, 0);
  assert.equal(summary.native_witness_check, 'PERSISTED_METADATA_AND_RAW_BYTES');
  assert.equal(summary.filters.show_health_zero_flag, 1);
  assert.equal(summary.rows_unmodified, true);

  const zero = command(directory, '--show-health-zero-flag', '0',
    '--raw-param', '0x40004009');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${lines[2]}\n`);
});

test('ShowHealthBar source verification checks every physical packet after limit', (t) => {
  const { directory } = fixture(t, [row(0), row(1, '4b')]);
  const physical = bindSavedPacketArtifactToPhysicalReplay(directory);
  const verified = command(directory, '--verify-source', '--limit', '1');
  assert.equal(verified.status, 0, verified.stderr);
  const summary = JSON.parse(verified.stderr);
  assert.equal(summary.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(verified.stdout, `${JSON.stringify(physical.rows[0])}\n`);

  const forged = structuredClone(physical.rows);
  forged[1].replay_time_ms += 1;
  forged[1].raw_packet_ref.replay_time_ms = forged[1].replay_time_ms;
  forged[1].raw_packet_ref.chunk_file_offset += 1;
  forged[1].raw_packet_ref.decompressed_block_offset += 1;
  forged[1].raw_packet_ref.decompressed_payload_offset += 1;
  fs.writeFileSync(physical.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  const rejected = command(directory, '--verify-source', '--limit', '1');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'SOURCE_PROVENANCE_MISMATCH');
  assert.equal(rejected.stdout, '');
});

test('ShowHealthBar source check pins top-level fields and packet ID without value filter', (t) => {
  const { directory } = fixture(t, [row(0), row(1, '4b')]);
  const physical = bindSavedPacketArtifactToPhysicalReplay(directory);
  for (const field of ['replay_time_ms', 'raw_param']) {
    const forged = structuredClone(physical.rows);
    forged[1][field] = field === 'replay_time_ms'
      ? physical.rows[0].replay_time_ms : forged[1][field] + 1;
    fs.writeFileSync(physical.eventPath,
      `${forged.map(JSON.stringify).join('\n')}\n`);
    const rejected = command(directory, '--verify-source',
      '--from-ms', '1000', '--to-ms', '1000', '--limit', '1');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(rejected.stdout, '');
  }
  fs.writeFileSync(physical.eventPath,
    `${physical.rows.map(JSON.stringify).join('\n')}\n`);
  changeResult(directory, (result) => { result.input_packet_id = 0x0166; });
  const rejected = command(directory, '--verify-source', '--limit', '1');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  assert.equal(rejected.stdout, '');
});

test('query-events distinguishes checked zero matches from unavailable capability', (t) => {
  const { directory } = fixture(t, [row(0, '4b'), row(1, '4b')]);
  const checked = command(directory, '--show-health-zero-flag', '0');
  assert.equal(checked.status, 0, checked.stderr);
  assert.equal(checked.stdout, '');
  assert.equal(JSON.parse(checked.stderr).show_health_zero_flag_checked_count, 2);
  const missing = fixture(t, [row(0)], { capabilityStatus: 'MISSING_INPUT' });
  const rejected = command(missing.directory, '--show-health-zero-flag', '0');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_UNAVAILABLE');
});

test('query-events checks every raw packet and candidate value after output limit', (t) => {
  const corruptions = [
    (entry) => { entry.callback_zero_flag_candidate = 0; },
    (entry) => { entry.callback_byte_candidate = 1; },
    (entry) => { entry.native_object_byte_0x10_hex = '00'; },
    (entry) => { entry.raw_packet_ref.raw_payload_hex = '4a'; },
    (entry) => { entry.raw_packet_ref.raw_payload_sha256 = '0'.repeat(64); },
    (entry) => { entry.raw_packet_ref.raw_param += 1; },
    (entry) => { entry.raw_packet_ref.chunk_stream = 'loading'; },
    (entry) => { entry.packet_name_candidate = 'other'; },
    (entry) => { entry.semantic_effect_status = 'CONFIRMED'; },
    (entry) => { entry.health_amount = 1; },
    (entry) => { entry.raw_packet_ref.extra = true; },
  ];
  for (const corrupt of corruptions) {
    const damaged = row(1, '4b');
    corrupt(damaged);
    const { root, directory } = fixture(t, [row(0), damaged]);
    const output = path.join(root, 'selected.jsonl');
    const rejected = command(directory, '--show-health-zero-flag', '0',
      '--limit', '1', '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('query-events checks profile, runtime, native witness and count metadata', (t) => {
  const changes = [
    (result) => { result.profile_id = 'foreign'; },
    (result) => { result.input_packet_id = 0x0465; },
    (result) => { result.runtime_image_sha256 = '0'.repeat(64); },
    (result) => { result.evidence_callback_table_sha256 = '0'.repeat(64); },
    (result) => { result.native_witness_status = 'PARTIAL'; },
    (result) => { result.native_full_success_count = 0; },
    (result) => { result.observed_payload_counts['4a'] = 0; },
    (result) => { result.event_field_confidence.callback_zero_flag_candidate = 'CONFIRMED'; },
    (result) => { result.known_limits = []; },
    (result) => { result.extra = true; },
  ];
  for (const change of changes) {
    const { directory } = fixture(t, [row(0)]);
    changeResult(directory, change);
    const rejected = command(directory, '--show-health-zero-flag', '0');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  }
});

test('query-events checks ordered native input digest and replay source order', (t) => {
  const { root, directory } = fixture(t, [row(0), row(1, '4b')]);
  changeResult(directory, (result) => {
    result.native_input_sha256 = '0'.repeat(64);
  });
  const output = path.join(root, 'selected.jsonl');
  const rejected = command(directory, '--show-health-zero-flag', '0',
    '--limit', '1', '--output', output);
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'EVENT_COUNT_MISMATCH');
  assert.equal(fs.existsSync(output), false);

  const reordered = fixture(t, [row(1, '4b'), row(0)]);
  const wrongOrder = command(reordered.directory, '--show-health-zero-flag', '0');
  assert.equal(wrongOrder.status, 2, wrongOrder.stderr);
  assert.equal(JSON.parse(wrongOrder.stderr).code, 'INVALID_EVENT_ROW');
});

test('query-events checks both Replays in a batch after the global output limit', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-show-bar-batch-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const a = writeReplay(root, 'first', [row(0, '4b', 'a'.repeat(64))],
    { replaySha: 'a'.repeat(64) });
  const b = writeReplay(root, 'second', [row(0, '4b', 'b'.repeat(64)),
    row(1, '4a', 'b'.repeat(64))], { replaySha: 'b'.repeat(64) });
  writeManifest(root, [a, b]);
  const selected = command(root, '--show-health-zero-flag', '1', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${a.lines[0]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.show_health_zero_flag_checked_count, 3);
  assert.equal(summary.show_health_zero_flag_unavailable_replay_count, 0);
  assert.equal(summary.replay_results[1].show_health_zero_flag_checked_count, 2);

  const filename = path.join(b.directory, `${EVENT}.jsonl`);
  const damaged = JSON.parse(b.lines[1]);
  damaged.callback_zero_flag_candidate = 1;
  fs.writeFileSync(filename, `${b.lines[0]}\n${JSON.stringify(damaged)}\n`);
  writeManifest(root, [a, b]);
  const output = path.join(root, 'selected.jsonl');
  const rejected = command(root, '--show-health-zero-flag', '1',
    '--limit', '1', '--output', output);
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(fs.existsSync(output), false);
});

test('CLI rejects foreign builds, unrelated events and filter values', (t) => {
  const { directory } = fixture(t, [row(0)]);
  for (const value of ['-1', '2', '0x1', '1.5', '01']) {
    const rejected = command(directory, '--show-health-zero-flag', value);
    assert.equal(rejected.status, 1, `${value}: ${rejected.stderr}`);
  }
  const unrelated = spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', 'hero_level_state_candidates',
      '--show-health-zero-flag', '0'], { encoding: 'utf8' });
  assert.equal(unrelated.status, 1);
  assert.match(unrelated.stderr, /--show-health-zero-flag requires/);
  const foreign = fixture(t, [row(0)], { replayVersion: '16.19.820.7193' });
  const wrongBuild = command(foreign.directory, '--show-health-zero-flag', '0');
  assert.equal(wrongBuild.status, 2, wrongBuild.stderr);
  assert.equal(JSON.parse(wrongBuild.stderr).code, 'UNSUPPORTED_FILTER');
});
