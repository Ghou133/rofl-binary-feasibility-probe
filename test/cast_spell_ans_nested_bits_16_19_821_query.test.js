'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821: profile,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V5_821: v5Profile,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V6_821: v6Profile,
  decodeCastSpellAnsNestedU32FromRaw821,
  decodeCastSpellAnsNestedU32At4cFromRaw821 } =
  require('../src/decoders/rofl_16_19_821_cast_spell_ans_packet_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'cast_spell_ans_packet_candidates';
const CAPABILITY = 'cast_spell_ans_packet';
const SHA = 'a'.repeat(64);
const SOURCE_PATH = 'synthetic.rofl';

function command(target, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', target, '--event', EVENT, ...args],
    { encoding: 'utf8' });
}

function row(index, raw = 'c8', value = 4, replaySha = SHA) {
  const time = 1000 + index;
  const rawParam = 0x400000ae;
  return {
    event_type: 'NPC_CAST_SPELL_ANS_PACKET_CANDIDATE',
    game_version: profile.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: replaySha,
    replay_time_ms: time, raw_param: rawParam,
    opaque_i32_0x14c: 0, raw_nested_bits_0x24_hex: raw,
    opaque_nested_bits_0x24: value,
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
    raw_packet_ref: {
      source_path: SOURCE_PATH, replay_sha256: replaySha,
      chunk_index: index, chunk_id: index, chunk_stream: 'game_chunk',
      chunk_file_offset: 100 + index,
      decompressed_block_offset: 20 + index,
      decompressed_payload_offset: 26 + index,
      packet_id: profile.replay_block_packet_id, replay_time_ms: time,
      payload_length: 129, raw_param: rawParam,
      raw_payload_sha256: 'b'.repeat(64),
    },
  };
}

function rowV5(index, rawU32, replaySha = SHA) {
  return { ...row(index, 'c8', 4, replaySha), build_profile: v5Profile.id,
    raw_u32_0x1c_hex: rawU32,
    opaque_u32_0x1c: decodeCastSpellAnsNestedU32FromRaw821(rawU32) };
}

function rowV6(index, rawAt4c, replaySha = SHA) {
  return { ...rowV5(index, 'cee352e7', replaySha), build_profile: v6Profile.id,
    raw_u32_0x4c_hex: rawAt4c,
    opaque_u32_0x4c: decodeCastSpellAnsNestedU32At4cFromRaw821(rawAt4c) };
}

function writeReplay(root, name, rows, { replaySha = SHA,
  fieldProfile = profile, profileId = fieldProfile.id,
  replayVersion = profile.replay_version } = {}) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const result = {
    profile_id: profileId,
    input_packet_id: profile.replay_block_packet_id,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    evidence_callback_table_sha256: profile.evidence_callback_table_sha256,
    evidence_nested_float_inverse_sha256:
      profile.evidence_nested_float_inverse_sha256,
    evidence_nested_byte_inverse_sha256:
      profile.evidence_nested_byte_inverse_sha256,
    ...([v5Profile, v6Profile].includes(fieldProfile) ? {
      evidence_nested_u32_transform_sha256:
        v5Profile.evidence_nested_u32_transform_sha256 } : {}),
    ...(fieldProfile === v6Profile ? {
      evidence_nested_u32_0x4c_transform_sha256:
        v6Profile.evidence_nested_u32_0x4c_transform_sha256 } : {}),
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
    input_count: rows.length, event_count: rows.length,
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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-cast-bits-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, ...writeReplay(root, 'synthetic', rows, options) };
}

function hashFile(filename) {
  return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
}

test('query-events selects exact 821 nested bits from original JSONL and distinguishes zero', (t) => {
  const rows = [row(0, 'c4', 0), row(1, 'c6', 1), row(2, 'c8', 4),
    row(3, 'c8', 4)];
  const { directory, lines } = fixture(t, rows);
  const selected = command(directory, '--cast-nested-bits', '0x4', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[2]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 4);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.cast_nested_bits_checked_count, 4);
  assert.equal(summary.cast_nested_bits_unavailable_count, 0);
  assert.equal(summary.filters.cast_nested_bits, 4);
  assert.equal(summary.rows_unmodified, true);

  const zero = command(directory, '--cast-nested-bits', '0');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${lines[0]}\n`);
  const absent = command(directory, '--cast-nested-bits', '2');
  assert.equal(absent.status, 0, absent.stderr);
  assert.equal(absent.stdout, '');
  assert.equal(JSON.parse(absent.stderr).matched_count, 0);
  assert.equal(JSON.parse(absent.stderr).cast_nested_bits_checked_count, 4);
});

test('query-events validates later rows after limit and removes partial output', (t) => {
  const corruptions = [
    (value) => { value.raw_nested_bits_0x24_hex = 'xx'; },
    (value) => { value.opaque_nested_bits_0x24 = 5; },
    (value) => { delete value.raw_nested_bits_0x24_hex; },
    (value) => { value.build_profile = 'foreign'; },
    (value) => { value.raw_packet_ref.packet_id = 0x01db; },
    (value) => { value.raw_packet_ref.raw_param += 1; },
    (value) => { value.raw_packet_ref.raw_payload_sha256 = 'invalid'; },
  ];
  for (const corrupt of corruptions) {
    const bad = row(1, 'c6', 1);
    corrupt(bad);
    const { root, directory } = fixture(t, [row(0), bad]);
    const output = path.join(root, 'selected.jsonl');
    const result = command(directory, '--cast-nested-bits', '4',
      '--limit', '1', '--to-ms', '1000', '--output', output);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('query-events rejects foreign build, event and malformed filter bounds', (t) => {
  const { directory } = fixture(t, [row(0)]);
  for (const value of ['-1', '256', '0x100', '1.5', '1e2', '+1']) {
    const result = command(directory, '--cast-nested-bits', value);
    assert.equal(result.status, 1, `${value}: ${result.stderr}`);
  }
  const unsupportedEvent = spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event',
      'hero_level_state_candidates', '--cast-nested-bits', '0'],
    { encoding: 'utf8' });
  assert.equal(unsupportedEvent.status, 1);
  assert.match(unsupportedEvent.stderr, /--cast-nested-bits requires/);

  const foreign = fixture(t, [row(0)], { replayVersion: '16.19.820.7193' });
  const wrongBuild = command(foreign.directory, '--cast-nested-bits', '4');
  assert.equal(wrongBuild.status, 2, wrongBuild.stderr);
  assert.equal(JSON.parse(wrongBuild.stderr).code, 'UNSUPPORTED_FILTER');
});

test('query-events rejects changed v4 profile metadata before selecting rows', (t) => {
  for (const change of [
    (result) => { result.profile_id = 'foreign'; },
    (result) => { result.runtime_image_sha256 = '0'.repeat(64); },
    (result) => { result.evidence_callback_table_sha256 = '0'.repeat(64); },
    (result) => { result.evidence_nested_byte_inverse_sha256 = '0'.repeat(64); },
    (result) => { result.input_packet_id = 0x01db; },
  ]) {
    const { directory } = fixture(t, [row(0)]);
    const filename = path.join(directory, 'semantic_run.json');
    const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
    change(semantic.capability_results[CAPABILITY]);
    fs.writeFileSync(filename, JSON.stringify(semantic));
    const rejected = command(directory, '--cast-nested-bits', '4');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  }
});

test('v3 CastSpellAns remains queryable through old filter and nested bits are unavailable', (t) => {
  const older = row(0);
  delete older.raw_nested_bits_0x24_hex;
  delete older.opaque_nested_bits_0x24;
  older.build_profile = profile.id.replace(/-v4$/, '-v3');
  const { directory } = fixture(t, [older], { profileId: older.build_profile });
  const oldFilter = command(directory, '--opaque-i32', '0');
  assert.equal(oldFilter.status, 0, oldFilter.stderr);
  assert.equal(JSON.parse(oldFilter.stdout).build_profile, older.build_profile);
  const unavailable = command(directory, '--cast-nested-bits', '0');
  assert.equal(unavailable.status, 2, unavailable.stderr);
  const failure = JSON.parse(unavailable.stderr);
  assert.equal(failure.code, 'CAST_NESTED_BITS_UNAVAILABLE');
  assert.equal(failure.cast_nested_bits_checked_count, 0);
  assert.equal(failure.cast_nested_bits_unavailable_count, 1);
});

test('batch counts checked v4 rows and unavailable v3 replay separately', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-cast-bits-batch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const current = writeReplay(root, 'current', [row(0)]);
  const oldSha = 'c'.repeat(64);
  const olderRow = row(0, 'c8', 4, oldSha);
  delete olderRow.raw_nested_bits_0x24_hex;
  delete olderRow.opaque_nested_bits_0x24;
  olderRow.build_profile = profile.id.replace(/-v4$/, '-v3');
  const older = writeReplay(root, 'older', [olderRow], {
    replaySha: oldSha, profileId: olderRow.build_profile,
  });
  const hashes = {};
  for (const [name, replay] of [['current', current], ['older', older]]) {
    for (const file of ['semantic_run.json', 'replay_analysis.json', `${EVENT}.jsonl`]) {
      hashes[`replays/${name}/${file}`] = hashFile(path.join(replay.directory, file));
    }
  }
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
    command_args: ['batch'],
    replay_inputs: [
      { artifact_directory: 'replays/current', sha256: SHA,
        version: profile.replay_version },
      { artifact_directory: 'replays/older', sha256: oldSha,
        version: profile.replay_version },
    ],
    output_hashes_excluding_manifest: hashes,
  }));
  const queried = command(root, '--cast-nested-bits', '4');
  assert.equal(queried.status, 0, queried.stderr);
  assert.equal(queried.stdout, `${current.lines[0]}\n`);
  const summary = JSON.parse(queried.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.completed_replay_count, 1);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.cast_nested_bits_checked_count, 1);
  assert.equal(summary.cast_nested_bits_unavailable_count, 1);
  assert.equal(summary.cast_nested_bits_unavailable_replay_count, 1);
  assert.equal(summary.replay_results[1].code, 'CAST_NESTED_BITS_UNAVAILABLE');
});

test('V5 nested u32 query distinguishes zero and scans every saved row', (t) => {
  assert.equal(decodeCastSpellAnsNestedU32FromRaw821('eeeeeeee'), 0);
  assert.equal(decodeCastSpellAnsNestedU32FromRaw821('cee352e7'), 1531465011);
  const rows = [rowV5(0, 'eeeeeeee'), rowV5(1, 'cee352e7'),
    rowV5(2, 'cee352e7')];
  const { directory, lines } = fixture(t, rows, { fieldProfile: v5Profile });
  const selected = command(directory, '--cast-nested-u32', '1531465011', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[1]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.cast_nested_u32_checked_count, 3);
  assert.equal(summary.cast_nested_u32_unavailable_count, 0);
  assert.equal(summary.filters.cast_nested_u32, 1531465011);
  assert.equal(summary.rows_unmodified, true);

  const zero = command(directory, '--cast-nested-u32', '0x0');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${lines[0]}\n`);
  const bits = command(directory, '--cast-nested-bits', '4',
    '--cast-nested-u32', '0');
  assert.equal(bits.status, 0, bits.stderr);
  assert.equal(bits.stdout, `${lines[0]}\n`);
  assert.equal(JSON.parse(bits.stderr).cast_nested_bits_checked_count, 3);
});

test('V5 nested u32 query rejects historical artifact and invalid bounds', (t) => {
  const old = fixture(t, [row(0)]);
  const unavailable = command(old.directory, '--cast-nested-u32', '0');
  assert.equal(unavailable.status, 2, unavailable.stderr);
  const failure = JSON.parse(unavailable.stderr);
  assert.equal(failure.code, 'CAST_NESTED_U32_UNAVAILABLE');
  assert.equal(failure.cast_nested_u32_checked_count, 0);
  assert.equal(failure.cast_nested_u32_unavailable_count, 1);

  const current = fixture(t, [rowV5(0, 'eeeeeeee')],
    { fieldProfile: v5Profile });
  for (const value of ['-1', '4294967296', '0x100000000', '1.5', '+1']) {
    const rejected = command(current.directory, '--cast-nested-u32', value);
    assert.equal(rejected.status, 1, `${value}: ${rejected.stderr}`);
  }
});

test('V5 nested u32 query rejects changed metadata and later forged row', (t) => {
  for (const change of [
    (result) => { result.evidence_nested_u32_transform_sha256 = '0'.repeat(64); },
    (result) => { result.evidence_callback_table_sha256 = '0'.repeat(64); },
    (result) => { result.runtime_image_sha256 = '0'.repeat(64); },
  ]) {
    const { directory } = fixture(t, [rowV5(0, 'cee352e7')],
      { fieldProfile: v5Profile });
    const filename = path.join(directory, 'semantic_run.json');
    const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
    change(semantic.capability_results[CAPABILITY]);
    fs.writeFileSync(filename, JSON.stringify(semantic));
    const rejected = command(directory, '--cast-nested-u32', '1531465011');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  }
  for (const change of [
    (entry) => { entry.raw_u32_0x1c_hex = 'invalid'; },
    (entry) => { entry.opaque_u32_0x1c += 1; },
    (entry) => { delete entry.opaque_u32_0x1c; },
    (entry) => { entry.build_profile = profile.id; },
    (entry) => { entry.raw_packet_ref.raw_param += 1; },
  ]) {
    const later = rowV5(1, 'cee352e7');
    change(later);
    const { root, directory } = fixture(t, [rowV5(0, 'cee352e7'), later],
      { fieldProfile: v5Profile });
    const output = path.join(root, 'selected.jsonl');
    const rejected = command(directory, '--cast-nested-u32', '1531465011',
      '--limit', '1', '--to-ms', '1000', '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('batch nested u32 query counts V5 checks and V4 unavailable separately', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-cast-u32-batch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const current = writeReplay(root, 'current', [rowV5(0, 'cee352e7')],
    { fieldProfile: v5Profile });
  const oldSha = 'c'.repeat(64);
  const old = writeReplay(root, 'older', [row(0, 'c8', 4, oldSha)],
    { replaySha: oldSha });
  const hashes = {};
  for (const [name, replay] of [['current', current], ['older', old]]) {
    for (const file of ['semantic_run.json', 'replay_analysis.json', `${EVENT}.jsonl`]) {
      hashes[`replays/${name}/${file}`] = hashFile(path.join(replay.directory, file));
    }
  }
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
    command_args: ['batch'],
    replay_inputs: [
      { artifact_directory: 'replays/current', sha256: SHA,
        version: profile.replay_version },
      { artifact_directory: 'replays/older', sha256: oldSha,
        version: profile.replay_version },
    ],
    output_hashes_excluding_manifest: hashes,
  }));
  const queried = command(root, '--cast-nested-u32', '1531465011');
  assert.equal(queried.status, 0, queried.stderr);
  assert.equal(queried.stdout, `${current.lines[0]}\n`);
  const summary = JSON.parse(queried.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.completed_replay_count, 1);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.cast_nested_u32_checked_count, 1);
  assert.equal(summary.cast_nested_u32_unavailable_count, 1);
  assert.equal(summary.cast_nested_u32_unavailable_replay_count, 1);
  assert.equal(summary.replay_results[1].code, 'CAST_NESTED_U32_UNAVAILABLE');
});

test('V6 second nested u32 query checks all rows and preserves V5 filters', (t) => {
  assert.equal(decodeCastSpellAnsNestedU32At4cFromRaw821('7525f20b'), 1073742460);
  assert.equal(decodeCastSpellAnsNestedU32At4cFromRaw821('c925f20b'), 1073742385);
  const rows = [rowV6(0, 'c925f20b'), rowV6(1, '7525f20b'),
    rowV6(2, '7525f20b')];
  const { directory, lines } = fixture(t, rows, { fieldProfile: v6Profile });
  const selected = command(directory, '--cast-nested-u32-0x4c',
    '1073742460', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[1]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.cast_nested_u32_0x4c_checked_count, 3);
  assert.equal(summary.cast_nested_u32_0x4c_unavailable_count, 0);
  assert.equal(summary.filters.cast_nested_u32_0x4c, 1073742460);
  assert.equal(summary.rows_unmodified, true);

  const combined = command(directory, '--cast-nested-u32-0x4c',
    '0x4000027c', '--cast-nested-u32', '1531465011',
    '--cast-nested-bits', '4');
  assert.equal(combined.status, 0, combined.stderr);
  assert.equal(combined.stdout, `${lines[1]}\n${lines[2]}\n`);
  assert.equal(JSON.parse(combined.stderr).cast_nested_u32_checked_count, 3);
});

test('V6 second nested u32 query distinguishes historical unavailability', (t) => {
  for (const [entry, fieldProfile] of [
    [row(0), profile], [rowV5(0, 'cee352e7'), v5Profile],
  ]) {
    const { directory } = fixture(t, [entry], { fieldProfile });
    const unavailable = command(directory, '--cast-nested-u32-0x4c', '0');
    assert.equal(unavailable.status, 2, unavailable.stderr);
    const failure = JSON.parse(unavailable.stderr);
    assert.equal(failure.code, 'CAST_NESTED_U32_0X4C_UNAVAILABLE');
    assert.equal(failure.cast_nested_u32_0x4c_checked_count, 0);
    assert.equal(failure.cast_nested_u32_0x4c_unavailable_count, 1);
  }
  const current = fixture(t, [rowV6(0, '7525f20b')],
    { fieldProfile: v6Profile });
  for (const value of ['-1', '4294967296', '0x100000000', '1.5', '+1']) {
    const rejected = command(current.directory, '--cast-nested-u32-0x4c', value);
    assert.equal(rejected.status, 1, `${value}: ${rejected.stderr}`);
  }
});

test('V6 second nested u32 query rejects changed metadata and later rows', (t) => {
  for (const change of [
    (result) => { result.evidence_nested_u32_0x4c_transform_sha256 = '0'.repeat(64); },
    (result) => { result.evidence_nested_u32_transform_sha256 = '0'.repeat(64); },
  ]) {
    const { directory } = fixture(t, [rowV6(0, '7525f20b')],
      { fieldProfile: v6Profile });
    const filename = path.join(directory, 'semantic_run.json');
    const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
    change(semantic.capability_results[CAPABILITY]);
    fs.writeFileSync(filename, JSON.stringify(semantic));
    const rejected = command(directory, '--cast-nested-u32-0x4c', '1073742460');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  }
  for (const change of [
    (entry) => { entry.raw_u32_0x4c_hex = 'invalid'; },
    (entry) => { entry.opaque_u32_0x4c += 1; },
    (entry) => { delete entry.opaque_u32_0x4c; },
    (entry) => { entry.raw_u32_0x1c_hex = 'invalid'; },
  ]) {
    const later = rowV6(1, '7525f20b');
    change(later);
    const { root, directory } = fixture(t, [rowV6(0, '7525f20b'), later],
      { fieldProfile: v6Profile });
    const output = path.join(root, 'selected.jsonl');
    const rejected = command(directory, '--cast-nested-u32-0x4c', '1073742460',
      '--limit', '1', '--to-ms', '1000', '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('batch second nested u32 query counts V6 checks and V5 unavailable', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-cast-u32-4c-batch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const current = writeReplay(root, 'current', [rowV6(0, '7525f20b')],
    { fieldProfile: v6Profile });
  const oldSha = 'c'.repeat(64);
  const old = writeReplay(root, 'older', [rowV5(0, 'cee352e7', oldSha)],
    { replaySha: oldSha, fieldProfile: v5Profile });
  const hashes = {};
  for (const [name, replay] of [['current', current], ['older', old]]) {
    for (const file of ['semantic_run.json', 'replay_analysis.json', `${EVENT}.jsonl`]) {
      hashes[`replays/${name}/${file}`] = hashFile(path.join(replay.directory, file));
    }
  }
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
    command_args: ['batch'],
    replay_inputs: [
      { artifact_directory: 'replays/current', sha256: SHA,
        version: profile.replay_version },
      { artifact_directory: 'replays/older', sha256: oldSha,
        version: profile.replay_version },
    ],
    output_hashes_excluding_manifest: hashes,
  }));
  const queried = command(root, '--cast-nested-u32-0x4c', '1073742460');
  assert.equal(queried.status, 0, queried.stderr);
  assert.equal(queried.stdout, `${current.lines[0]}\n`);
  const summary = JSON.parse(queried.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.completed_replay_count, 1);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.cast_nested_u32_0x4c_checked_count, 1);
  assert.equal(summary.cast_nested_u32_0x4c_unavailable_count, 1);
  assert.equal(summary.cast_nested_u32_0x4c_unavailable_replay_count, 1);
  assert.equal(summary.replay_results[1].code, 'CAST_NESTED_U32_0X4C_UNAVAILABLE');
});
