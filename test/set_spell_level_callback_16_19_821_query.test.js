'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_821: v1,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_821: v2,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_FIELD_CONFIDENCE_V2_821: v2FieldConfidence,
  decodeSetSpellLevelU32At10FromRaw821,
  decodeSetSpellLevelU32At14FromRaw821,
} = require('../src/decoders/rofl_16_19_821_set_spell_level_packet_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'set_spell_level_packet_candidates';
const CAPABILITY = 'set_spell_level_packet';
const SHA = 'a'.repeat(64);
const SOURCE = 'synthetic.rofl';

function command(directory, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', EVENT, ...args],
    { encoding: 'utf8' });
}

function row(index, rawIndex, rawScalar, replaySha = SHA, profile = v2) {
  const decodedIndex = decodeSetSpellLevelU32At10FromRaw821(rawIndex);
  const decodedScalar = decodeSetSpellLevelU32At14FromRaw821(rawScalar);
  const time = 1000 + index;
  const rawParam = 0x400000b4;
  return {
    event_type: 'SET_SPELL_LEVEL_PACKET_CANDIDATE',
    game_version: v2.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: replaySha,
    replay_time_ms: time, raw_param: rawParam,
    opaque_u32_0x10: decodedIndex, opaque_u32_0x14: decodedScalar,
    raw_object_u32_0x10_hex: rawIndex,
    raw_object_u32_0x14_hex: rawScalar,
    ...(profile === v2 ? {
      native_receiver_slot_candidate: decodedIndex <= 63 ? decodedIndex : 0,
      native_receiver_selection_source: decodedIndex <= 63 ? 'INDEXED' : 'FALLBACK_0',
      native_clamped_scalar_candidate: Math.min(decodedScalar, 6),
      native_positive_flag_written: decodedScalar > 0,
    } : {}),
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
    raw_packet_ref: {
      source_path: SOURCE, replay_sha256: replaySha,
      chunk_index: index, chunk_id: index, chunk_stream: 'game_chunk',
      chunk_file_offset: 100 + index,
      decompressed_block_offset: 20 + index,
      decompressed_payload_offset: 35 + index,
      packet_id: v2.replay_block_packet_id, replay_time_ms: time,
      payload_length: 1, raw_param: rawParam,
      raw_payload_sha256: 'b'.repeat(64),
    },
  };
}

function writeReplay(root, name, rows, { profile = v2,
  replaySha = SHA } = {}) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const capabilityResult = {
    profile_id: profile.id,
    input_packet_id: profile.replay_block_packet_id,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    evidence_callback_table_sha256: profile.evidence_callback_table_sha256,
    ...(profile === v2 ? {
      evidence_callback_rva: profile.evidence_callback_rva,
      evidence_receiver_write_rva: profile.evidence_receiver_write_rva,
      evidence_callback_region_sha256: profile.evidence_callback_region_sha256,
      evidence_receiver_write_region_sha256:
        profile.evidence_receiver_write_region_sha256,
      evidence_callback_witness_mode: profile.evidence_callback_witness_mode,
    } : {}),
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
    input_count: rows.length, event_count: rows.length,
    scanned_block_count: Math.max(rows.length, 1),
    known_limits: [...profile.known_limits],
    event_field_confidence: profile === v2
      ? { ...v2FieldConfidence }
      : Object.fromEntries(Object.entries(v2FieldConfidence)
        .filter(([field]) => !field.startsWith('native_'))),
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
  };
  const semantic = {
    replay_version: profile.replay_version, replay_sha256: replaySha,
    container_status: 'PASS', status: 'CANDIDATE', api_status: 'CANDIDATE',
    requested_capabilities: [CAPABILITY],
    capability_results: { [CAPABILITY]: capabilityResult },
  };
  const analysis = {
    patch: '16.19', replay_version: profile.replay_version,
    replay_sha256: replaySha, source_path: SOURCE,
    event_storage: 'JSONL_ONLY', event_counts: { [EVENT]: rows.length },
    event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` }, events: null,
    semantic: { capability_results: { [CAPABILITY]: capabilityResult } },
  };
  fs.writeFileSync(path.join(directory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(directory, 'replay_analysis.json'), JSON.stringify(analysis));
  const lines = rows.map((entry) => JSON.stringify(entry));
  fs.writeFileSync(path.join(directory, `${EVENT}.jsonl`),
    lines.length ? `${lines.join('\n')}\n` : '');
  return { directory, lines, replaySha };
}

function fixture(t, rows, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-spell-level-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, ...writeReplay(root, 'synthetic', rows, options) };
}

function fileSha(filename) {
  return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
}

test('saved V2 query filters native receiver and clamped scalar without changing rows', (t) => {
  const rows = [row(0, 'bbbbbbbb', 'f1f1f1f1'),
    row(1, '7bbbbbbb', '30f1f1f1'),
    row(2, 'b3bbbbbb', '30f1f1f1')];
  assert.deepEqual(rows.map((value) => [value.opaque_u32_0x10,
    value.opaque_u32_0x14]), [[0, 0], [12, 9], [64, 9]]);
  const { directory, lines } = fixture(t, rows);
  const selected = command(directory, '--spell-level-receiver-index', '0x0',
    '--spell-level-clamped-scalar', '6', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[2]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.spell_level_callback_checked_count, 3);
  assert.equal(summary.spell_level_callback_unavailable_count, 0);
  assert.equal(summary.filters.spell_level_receiver_index, 0);
  assert.equal(summary.filters.spell_level_clamped_scalar, 6);
  assert.equal(summary.rows_unmodified, true);

  const twelve = command(directory, '--spell-level-receiver-index', '12');
  assert.equal(twelve.status, 0, twelve.stderr);
  assert.equal(twelve.stdout, `${lines[1]}\n`);
  const zero = command(directory, '--spell-level-clamped-scalar', '0');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${lines[0]}\n`);
});

test('saved V2 query checks later rows after limit and rejects forged witness fields', (t) => {
  const corruptions = [
    (value) => { value.raw_object_u32_0x14_hex = 'f1f1f1f1'; },
    (value) => { value.native_receiver_slot_candidate = 5; },
    (value) => { value.native_clamped_scalar_candidate = 5; },
    (value) => { value.native_positive_flag_written = false; },
    (value) => { value.raw_packet_ref.packet_id = 0x025e; },
    (value) => { value.replay_sha256 = 'c'.repeat(64); },
    (value) => { value.spell_level = 5; },
    (value) => { value.raw_packet_ref.spell_identity = 3; },
  ];
  for (const corrupt of corruptions) {
    const first = row(0, 'bbbbbbbb', 'f1f1f1f1');
    const later = row(1, '7bbbbbbb', '30f1f1f1');
    corrupt(later);
    const { root, directory } = fixture(t, [first, later]);
    const output = path.join(root, 'selected.jsonl');
    const result = command(directory, '--spell-level-receiver-index', '0',
      '--limit', '1', '--to-ms', '1000', '--output', output);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code,
      later.replay_sha256 === SHA ? 'INVALID_EVENT_ROW' : 'ARTIFACT_IDENTITY_MISMATCH');
    assert.equal(fs.existsSync(output), false);
  }
});

test('saved V2 query rejects changed callback metadata and V1 has unavailable fields', (t) => {
  const current = row(0, 'bbbbbbbb', 'f1f1f1f1');
  for (const field of ['evidence_callback_region_sha256',
    'evidence_receiver_write_region_sha256', 'evidence_callback_witness_mode',
    'known_limits', 'event_field_confidence']) {
    const { directory } = fixture(t, [current]);
    const filename = path.join(directory, 'semantic_run.json');
    const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
    semantic.capability_results[CAPABILITY][field] = 'changed';
    fs.writeFileSync(filename, JSON.stringify(semantic));
    const result = command(directory, '--spell-level-receiver-index', '0');
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  }
  const divergent = fixture(t, [current]);
  const analysisPath = path.join(divergent.directory, 'replay_analysis.json');
  const analysis = JSON.parse(fs.readFileSync(analysisPath, 'utf8'));
  analysis.semantic.capability_results[CAPABILITY].evidence_callback_rva = 'changed';
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  const mismatched = command(divergent.directory, '--spell-level-receiver-index', '0');
  assert.equal(mismatched.status, 2, mismatched.stderr);
  assert.equal(JSON.parse(mismatched.stderr).code, 'CAPABILITY_METADATA_MISMATCH');

  const empty = fixture(t, []);
  const zero = command(empty.directory, '--spell-level-receiver-index', '0');
  assert.equal(zero.status, 2, zero.stderr);
  assert.equal(JSON.parse(zero.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  const older = row(0, 'bbbbbbbb', 'f1f1f1f1', SHA, v1);
  const { directory } = fixture(t, [older], { profile: v1 });
  const result = command(directory, '--spell-level-clamped-scalar', '0');
  assert.equal(result.status, 2, result.stderr);
  const failure = JSON.parse(result.stderr);
  assert.equal(failure.code, 'SPELL_LEVEL_CALLBACK_UNAVAILABLE');
  assert.equal(failure.spell_level_callback_checked_count, 0);
  assert.equal(failure.spell_level_callback_unavailable_count, 1);
});

test('batch query reports V2 checked rows and V1 unavailable replay separately', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-spell-level-batch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const current = writeReplay(root, 'current',
    [row(0, 'bbbbbbbb', 'f1f1f1f1')]);
  const oldSha = 'c'.repeat(64);
  const older = writeReplay(root, 'older',
    [row(0, 'bbbbbbbb', 'f1f1f1f1', oldSha, v1)],
    { profile: v1, replaySha: oldSha });
  const hashes = {};
  for (const [name, replay] of [['current', current], ['older', older]]) {
    for (const file of ['semantic_run.json', 'replay_analysis.json', `${EVENT}.jsonl`]) {
      hashes[`replays/${name}/${file}`] = fileSha(path.join(replay.directory, file));
    }
  }
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
    command_args: ['batch'],
    replay_inputs: [
      { artifact_directory: 'replays/current', sha256: SHA,
        version: v2.replay_version },
      { artifact_directory: 'replays/older', sha256: oldSha,
        version: v2.replay_version },
    ],
    output_hashes_excluding_manifest: hashes,
  }));
  const result = command(root, '--spell-level-receiver-index', '0');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${current.lines[0]}\n`);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.completed_replay_count, 1);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.spell_level_callback_checked_count, 1);
  assert.equal(summary.spell_level_callback_unavailable_count, 1);
  assert.equal(summary.spell_level_callback_unavailable_replay_count, 1);
  assert.equal(summary.replay_results[1].code, 'SPELL_LEVEL_CALLBACK_UNAVAILABLE');
});
