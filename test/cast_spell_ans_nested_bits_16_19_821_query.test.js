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
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V7_821: v7Profile,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V8_821: v8Profile,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V9_821: v9Profile,
  decodeCastSpellAnsNestedU32FromRaw821,
  decodeCastSpellAnsNestedU32At4cFromRaw821,
  decodeCastSpellAnsNestedF32AtA0FromRaw821,
  decodeCastSpellAnsNestedU32At28FromRaw821 } =
  require('../src/decoders/rofl_16_19_821_cast_spell_ans_packet_candidate');
const { DIGEST_SCHEMA, batchDigest, replayDigestStart, replayDigestBatch } =
  require('../src/decoders/rofl_16_19_821_cast_spell_ans_native_digest');
const { bindSavedPacketArtifactToPhysicalReplay } =
  require('./helpers/physical_saved_packet_replay');

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

function rowV7(index, rawAtA0, replaySha = SHA) {
  return { ...rowV6(index, '7525f20b', replaySha), build_profile: v7Profile.id,
    raw_f32_0xa0_bytes_hex: rawAtA0,
    opaque_f32_0xa0: decodeCastSpellAnsNestedF32AtA0FromRaw821(rawAtA0) };
}

function rowV8(index, rawAt28, replaySha = SHA) {
  return { ...rowV7(index, '5858c8d6', replaySha), build_profile: v8Profile.id,
    raw_u32_0x28_hex: rawAt28,
    opaque_u32_0x28: decodeCastSpellAnsNestedU32At28FromRaw821(rawAt28),
    callback_tree_lookup_status: 'UNKNOWN' };
}

function rowV9(index, rawAt28, replaySha = SHA) {
  return { ...rowV8(index, rawAt28, replaySha), build_profile: v9Profile.id,
    opaque_flag_0x148: 0, opaque_i32_0x14c: 0,
    raw_f32_0xe0_bytes_hex: 'ffffffff', opaque_f32_0xe0: 0,
    raw_u8_0x140_hex: '2c', opaque_u8_0x140: 0 };
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
    ...([v5Profile, v6Profile, v7Profile, v8Profile, v9Profile].includes(fieldProfile) ? {
      evidence_nested_u32_transform_sha256:
        v5Profile.evidence_nested_u32_transform_sha256 } : {}),
    ...([v6Profile, v7Profile, v8Profile, v9Profile].includes(fieldProfile) ? {
      evidence_nested_u32_0x4c_transform_sha256:
        v6Profile.evidence_nested_u32_0x4c_transform_sha256 } : {}),
    ...([v7Profile, v8Profile, v9Profile].includes(fieldProfile) ? {
      evidence_nested_f32_0xa0_transform_sha256:
        v7Profile.evidence_nested_f32_0xa0_transform_sha256,
      evidence_nested_f32_0xa0_inverse_sha256:
        v7Profile.evidence_nested_f32_0xa0_inverse_sha256 } : {}),
    ...([v8Profile, v9Profile].includes(fieldProfile) ? {
      evidence_nested_u32_0x28_transform_sha256:
        v8Profile.evidence_nested_u32_0x28_transform_sha256,
      evidence_nested_u32_0x28_inverse_sha256:
        v8Profile.evidence_nested_u32_0x28_inverse_sha256 } : {}),
    ...(fieldProfile === v9Profile ? (() => {
      const hash = replayDigestStart(replaySha);
      for (let start = 0; start < rows.length; start += 8192) {
        const batch = rows.slice(start, start + 8192);
        replayDigestBatch(hash, start, batch.length, batchDigest(batch, true));
      }
      return { evidence_native_output_digest_schema: DIGEST_SCHEMA,
        native_output_batch_size: 8192,
        native_output_sha256: hash.digest('hex') };
    })() : {}),
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

test('V7 nested f32 query validates exact raw transforms and preserves rows', (t) => {
  const rows = [rowV7(0, '5858c8d6'), rowV7(1, '47aed8d6'),
    rowV7(2, 'c41d0b32')];
  assert.deepEqual(rows.map((entry) => entry.opaque_f32_0xa0),
    [1, 1.1395000219345093, 2.1871252059936523]);
  const { directory, lines } = fixture(t, rows, { fieldProfile: v7Profile });
  const selected = command(directory, '--cast-nested-f32-0xa0',
    '1.1395000219345093', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[1]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.cast_nested_f32_0xa0_checked_count, 3);
  assert.equal(summary.cast_nested_f32_0xa0_unavailable_count, 0);
  assert.equal(summary.filters.cast_nested_f32_0xa0, 1.1395000219345093);
  assert.equal(summary.rows_unmodified, true);
  const rounded = command(directory, '--cast-nested-f32-0xa0', '1.1395');
  assert.equal(rounded.status, 0, rounded.stderr);
  assert.equal(rounded.stdout, `${lines[1]}\n`);
  const previous = command(directory, '--cast-nested-u32-0x4c', '1073742460');
  assert.equal(previous.status, 0, previous.stderr);
  assert.equal(previous.stdout, `${lines.join('\n')}\n`);
});

test('V7 nested f32 query rejects metadata drift and later forged rows', (t) => {
  for (const field of ['evidence_nested_f32_0xa0_transform_sha256',
    'evidence_nested_f32_0xa0_inverse_sha256']) {
    const { directory } = fixture(t, [rowV7(0, '5858c8d6')],
      { fieldProfile: v7Profile });
    const filename = path.join(directory, 'semantic_run.json');
    const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
    semantic.capability_results[CAPABILITY][field] = '0'.repeat(64);
    fs.writeFileSync(filename, JSON.stringify(semantic));
    const rejected = command(directory, '--cast-nested-f32-0xa0', '1');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  }
  for (const change of [
    (entry) => { entry.raw_f32_0xa0_bytes_hex = '00000000'; },
    (entry) => { entry.opaque_f32_0xa0 = 1; },
    (entry) => { entry.raw_u32_0x4c_hex = 'invalid'; },
    (entry) => { entry.raw_packet_ref.packet_id = 0x01db; },
  ]) {
    const later = rowV7(1, '47aed8d6');
    change(later);
    const { root, directory } = fixture(t,
      [rowV7(0, '5858c8d6'), later], { fieldProfile: v7Profile });
    const output = path.join(root, 'selected.jsonl');
    const rejected = command(directory, '--cast-nested-f32-0xa0', '1',
      '--limit', '1', '--to-ms', '1000', '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('batch V7 nested f32 query counts V6 unavailable separately', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-cast-f32-a0-batch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const current = writeReplay(root, 'current', [rowV7(0, '5858c8d6')],
    { fieldProfile: v7Profile });
  const oldSha = 'c'.repeat(64);
  const old = writeReplay(root, 'older', [rowV6(0, '7525f20b', oldSha)],
    { replaySha: oldSha, fieldProfile: v6Profile });
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
  const queried = command(root, '--cast-nested-f32-0xa0', '1');
  assert.equal(queried.status, 0, queried.stderr);
  assert.equal(queried.stdout, `${current.lines[0]}\n`);
  const summary = JSON.parse(queried.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.completed_replay_count, 1);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.cast_nested_f32_0xa0_checked_count, 1);
  assert.equal(summary.cast_nested_f32_0xa0_unavailable_count, 1);
  assert.equal(summary.cast_nested_f32_0xa0_unavailable_replay_count, 1);
  assert.equal(summary.replay_results[1].code, 'CAST_NESTED_F32_0XA0_UNAVAILABLE');
});

test('V8 packet-local lookup-key query validates all rows and preserves original JSONL', (t) => {
  const rows = [rowV8(0, '9194b8fb'), rowV8(1, '7cef92cb'),
    rowV8(2, '09a09cbb')];
  assert.deepEqual(rows.map((entry) => entry.opaque_u32_0x28),
    [137424977, 190941627, 11563543]);
  const { directory, lines } = fixture(t, rows, { fieldProfile: v8Profile });
  const selected = command(directory, '--cast-nested-u32-0x28',
    '190941627', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[1]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.cast_nested_u32_0x28_checked_count, 3);
  assert.equal(summary.cast_nested_u32_0x28_unavailable_count, 0);
  assert.equal(summary.filters.cast_nested_u32_0x28, 190941627);
  assert.equal(summary.rows_unmodified, true);
  assert.equal(summary.native_witness_check, 'PERSISTED_METADATA_AND_RAW_BYTES');
  const hex = command(directory, '--cast-nested-u32-0x28', '0x0b6189bb');
  assert.equal(hex.status, 0, hex.stderr);
  assert.equal(hex.stdout, `${lines[1]}\n`);
  const prior = command(directory, '--cast-nested-f32-0xa0', '1');
  assert.equal(prior.status, 0, prior.stderr);
  assert.equal(prior.stdout, `${lines.join('\n')}\n`);
});

test('V9 query checks its ordered native-output digest after limit and without filters', (t) => {
  const rows = [rowV9(0, '9194b8fb'), rowV9(1, '7cef92cb')];
  const { root, directory, lines } = fixture(t, rows, { fieldProfile: v9Profile });
  const selected = command(directory, '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[0]}\n`);
  assert.equal(JSON.parse(selected.stderr).native_witness_check,
    'ORDERED_NATIVE_OUTPUT_DIGEST');
  const filtered = command(directory, '--cast-nested-u32-0x28', '137424977',
    '--limit', '1');
  assert.equal(filtered.status, 0, filtered.stderr);
  assert.equal(filtered.stdout, `${lines[0]}\n`);
  assert.equal(JSON.parse(filtered.stderr).scanned_count, 2);

  const forged = structuredClone(rows);
  forged[1].raw_u32_0x28_hex = '09a09cbb';
  forged[1].opaque_u32_0x28 = 11563543;
  fs.writeFileSync(path.join(directory, `${EVENT}.jsonl`),
    `${forged.map(JSON.stringify).join('\n')}\n`);
  const output = path.join(root, 'forged-selection.jsonl');
  const rejected = command(directory, '--limit', '1', '--to-ms', '1000',
    '--output', output);
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'NATIVE_OUTPUT_DIGEST_MISMATCH');
  assert.equal(rejected.stdout, '');
  assert.equal(fs.existsSync(output), false);
});

test('V9 rejects literal negative-zero float forgeries after limit', (t) => {
  for (const field of ['opaque_f32_0xe0', 'opaque_f32_0xa0']) {
    const rows = [rowV9(0, '9194b8fb'), rowV9(1, '7cef92cb'),
      rowV9(2, '09a09cbb')];
    for (const entry of rows) {
      entry.raw_f32_0xa0_bytes_hex = '58585858';
      entry.opaque_f32_0xa0 = 0;
    }
    // The third row represents a native -0 serialized as JSON number 0.
    rows[2].raw_f32_0xe0_bytes_hex = 'ffffffef';
    rows[2].raw_f32_0xa0_bytes_hex = '585858c8';
    const { directory, lines } = fixture(t, rows, { fieldProfile: v9Profile });
    const valid = command(directory, '--limit', '1');
    assert.equal(valid.status, 0, valid.stderr);
    assert.equal(valid.stdout, `${lines[0]}\n`);
    assert.equal(JSON.parse(valid.stderr).scanned_count, 3);
    assert.equal(JSON.parse(valid.stderr).native_witness_check,
      'ORDERED_NATIVE_OUTPUT_DIGEST');

    const forged = lines.slice();
    forged[1] = forged[1].replace(`"${field}":0`, `"${field}":-0.0`);
    assert.notEqual(forged[1], lines[1]);
    fs.writeFileSync(path.join(directory, `${EVENT}.jsonl`),
      `${forged.join('\n')}\n`);
    const rejected = command(directory, '--limit', '1');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(rejected.stdout, '');
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
  }
});

test('V9 saved query rejects missing digest metadata and V8 downgrade', (t) => {
  for (const change of [
    (result) => { delete result.native_output_sha256; },
    (result) => { result.native_output_sha256 = '0'.repeat(64); },
    (result) => { result.profile_id = v8Profile.id; },
  ]) {
    const { directory } = fixture(t, [rowV9(0, '9194b8fb')],
      { fieldProfile: v9Profile });
    const file = path.join(directory, 'semantic_run.json');
    const semantic = JSON.parse(fs.readFileSync(file, 'utf8'));
    change(semantic.capability_results[CAPABILITY]);
    fs.writeFileSync(file, JSON.stringify(semantic));
    const rejected = command(directory, '--limit', '1');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(rejected.stdout, '');
    assert.ok(['CAPABILITY_METADATA_MISMATCH', 'NATIVE_OUTPUT_DIGEST_MISMATCH']
      .includes(JSON.parse(rejected.stderr).code));
  }
});

test('V8 lookup-key query rejects metadata drift and a forged later row without stdout', (t) => {
  for (const field of ['evidence_nested_u32_0x28_transform_sha256',
    'evidence_nested_u32_0x28_inverse_sha256']) {
    const { directory } = fixture(t, [rowV8(0, '9194b8fb')],
      { fieldProfile: v8Profile });
    const filename = path.join(directory, 'semantic_run.json');
    const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
    semantic.capability_results[CAPABILITY][field] = '0'.repeat(64);
    fs.writeFileSync(filename, JSON.stringify(semantic));
    const rejected = command(directory, '--cast-nested-u32-0x28', '137424977');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
    assert.equal(rejected.stdout, '');
  }
  for (const change of [
    (entry) => { entry.raw_u32_0x28_hex = 'invalid'; },
    (entry) => { entry.opaque_u32_0x28 += 1; },
    (entry) => { entry.callback_tree_lookup_status = 'HIT'; },
    (entry) => { entry.raw_packet_ref.packet_id = 0x01db; },
  ]) {
    const later = rowV8(1, '7cef92cb');
    change(later);
    const { root, directory } = fixture(t, [rowV8(0, '9194b8fb'), later],
      { fieldProfile: v8Profile });
    const output = path.join(root, 'selected.jsonl');
    const rejected = command(directory, '--cast-nested-u32-0x28', '137424977',
      '--limit', '1', '--to-ms', '1000', '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(rejected.stdout, '');
    assert.equal(fs.existsSync(output), false);
  }
});

test('V8 source check binds every saved packet ref to physical ROFL after limit', (t) => {
  // Physical-source validation is independent of the synthetic native fields.
  const payloads = [Buffer.alloc(129, 0x11), Buffer.alloc(129, 0x22),
    Buffer.alloc(129, 0x33)];
  const rows = [rowV8(0, '9194b8fb'), rowV8(1, '7cef92cb'),
    rowV8(2, '09a09cbb')];
  rows.forEach((entry, index) => {
    entry.raw_packet_ref.raw_payload_sha256 = crypto.createHash('sha256')
      .update(payloads[index]).digest('hex');
  });
  const { directory } = fixture(t, rows, { fieldProfile: v8Profile });
  const physical = bindSavedPacketArtifactToPhysicalReplay(directory, { payloads });
  const verified = command(directory, '--cast-nested-u32-0x28', '137424977',
    '--verify-source', '--limit', '1');
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(JSON.parse(verified.stderr).source_provenance_status,
    'SOURCE_REPLAY_VERIFIED');
  assert.equal(verified.stdout, `${JSON.stringify(physical.rows[0])}\n`);

  const forged = structuredClone(physical.rows);
  forged[2].replay_time_ms += 1;
  forged[2].raw_packet_ref.replay_time_ms = forged[2].replay_time_ms;
  forged[2].raw_packet_ref.chunk_file_offset += 1;
  forged[2].raw_packet_ref.decompressed_block_offset += 1;
  forged[2].raw_packet_ref.decompressed_payload_offset += 1;
  fs.writeFileSync(physical.eventPath,
    `${forged.map(JSON.stringify).join('\n')}\n`);
  const rejected = command(directory, '--cast-nested-u32-0x28', '137424977',
    '--verify-source', '--limit', '1');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'SOURCE_PROVENANCE_MISMATCH');
  assert.equal(rejected.stdout, '');
});

test('V8 source check rejects later top-level time or parameter drift without a nested filter', (t) => {
  const payloads = [Buffer.alloc(129, 0x44), Buffer.alloc(129, 0x55)];
  const rows = [rowV8(0, '9194b8fb'), rowV8(1, '7cef92cb')];
  rows.forEach((entry, index) => {
    entry.raw_packet_ref.raw_payload_sha256 = crypto.createHash('sha256')
      .update(payloads[index]).digest('hex');
  });
  const { directory } = fixture(t, rows, { fieldProfile: v8Profile });
  const physical = bindSavedPacketArtifactToPhysicalReplay(directory, { payloads });
  const args = ['--verify-source', '--from-ms', '1000',
    '--to-ms', '1000', '--limit', '1'];
  const valid = command(directory, ...args);
  assert.equal(valid.status, 0, valid.stderr);
  assert.equal(JSON.parse(valid.stderr).source_provenance_status,
    'SOURCE_REPLAY_VERIFIED');
  assert.equal(JSON.parse(valid.stderr).matched_count, 1);
  assert.equal(valid.stdout, `${JSON.stringify(physical.rows[0])}\n`);

  for (const field of ['replay_time_ms', 'raw_param']) {
    const forged = structuredClone(physical.rows);
    forged[1][field] = field === 'replay_time_ms'
      ? physical.rows[0].replay_time_ms : forged[1][field] + 1;
    fs.writeFileSync(physical.eventPath,
      `${forged.map(JSON.stringify).join('\n')}\n`);
    const rejected = command(directory, ...args);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(rejected.stdout, '');
  }

  fs.writeFileSync(physical.eventPath,
    `${physical.rows.map(JSON.stringify).join('\n')}\n`);
  const semanticPath = path.join(directory, 'semantic_run.json');
  const semantic = JSON.parse(fs.readFileSync(semanticPath, 'utf8'));
  semantic.capability_results[CAPABILITY].input_packet_id = 0x01db;
  fs.writeFileSync(semanticPath, JSON.stringify(semantic));
  const rejectedProfile = command(directory, ...args);
  assert.equal(rejectedProfile.status, 2, rejectedProfile.stderr);
  assert.equal(JSON.parse(rejectedProfile.stderr).code,
    'CAPABILITY_METADATA_MISMATCH');
  assert.equal(rejectedProfile.stdout, '');
});

test('historical V3 CastSpellAns remains physically source-verifiable', (t) => {
  const payload = Buffer.alloc(129, 0x66);
  const old = row(0);
  delete old.raw_nested_bits_0x24_hex;
  delete old.opaque_nested_bits_0x24;
  old.build_profile = profile.id.replace(/-v4$/, '-v3');
  old.raw_packet_ref.raw_payload_sha256 = crypto.createHash('sha256')
    .update(payload).digest('hex');
  const { directory } = fixture(t, [old], { profileId: old.build_profile });
  const physical = bindSavedPacketArtifactToPhysicalReplay(directory,
    { payloads: [payload] });
  const verified = command(directory, '--verify-source', '--opaque-i32', '0');
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(JSON.parse(verified.stderr).source_provenance_status,
    'SOURCE_REPLAY_VERIFIED');
  assert.equal(verified.stdout, `${JSON.stringify(physical.rows[0])}\n`);
  const unavailable = command(directory, '--cast-nested-bits', '0');
  assert.equal(unavailable.status, 2, unavailable.stderr);
  assert.equal(JSON.parse(unavailable.stderr).code, 'CAST_NESTED_BITS_UNAVAILABLE');
});

test('V4 through V8 CastSpellAns remain source-verifiable without field filters', (t) => {
  for (const [fieldProfile, entry] of [
    [profile, row(0)],
    [v5Profile, rowV5(0, 'cee352e7')],
    [v6Profile, rowV6(0, '7525f20b')],
    [v7Profile, rowV7(0, '5858c8d6')],
    [v8Profile, rowV8(0, '9194b8fb')],
  ]) {
    const payload = Buffer.alloc(129, fieldProfile.id.charCodeAt(
      fieldProfile.id.length - 1));
    entry.raw_packet_ref.raw_payload_sha256 = crypto.createHash('sha256')
      .update(payload).digest('hex');
    const { directory } = fixture(t, [entry], { fieldProfile });
    bindSavedPacketArtifactToPhysicalReplay(directory, { payloads: [payload] });
    const verified = command(directory, '--verify-source', '--limit', '1');
    assert.equal(verified.status, 0, `${fieldProfile.id}: ${verified.stderr}`);
    assert.equal(JSON.parse(verified.stderr).source_provenance_status,
      'SOURCE_REPLAY_VERIFIED');
  }
});

test('batch V8 lookup-key query counts V7 unavailable separately', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-cast-u32-28-batch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const current = writeReplay(root, 'current', [rowV8(0, '9194b8fb')],
    { fieldProfile: v8Profile });
  const oldSha = 'c'.repeat(64);
  const old = writeReplay(root, 'older', [rowV7(0, '5858c8d6', oldSha)],
    { replaySha: oldSha, fieldProfile: v7Profile });
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
  const queried = command(root, '--cast-nested-u32-0x28', '137424977');
  assert.equal(queried.status, 0, queried.stderr);
  assert.equal(queried.stdout, `${current.lines[0]}\n`);
  const summary = JSON.parse(queried.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.completed_replay_count, 1);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.cast_nested_u32_0x28_checked_count, 1);
  assert.equal(summary.cast_nested_u32_0x28_unavailable_count, 1);
  assert.equal(summary.cast_nested_u32_0x28_unavailable_replay_count, 1);
  assert.equal(summary.replay_results[1].code, 'CAST_NESTED_U32_0X28_UNAVAILABLE');
});
