'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_821: v1,
  SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V2_821: v2,
  SET_SPELL_TIMER_FROM_BUFF_V2_EVENT_FIELD_CONFIDENCE_821: v2FieldConfidence,
  decodeSetSpellTimerRawFields821,
} = require('../src/decoders/rofl_16_19_821_set_spell_timer_from_buff_packet_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'set_spell_timer_from_buff_packet_candidates';
const CAPABILITY = 'set_spell_timer_from_buff_packet';
const SHA = 'a'.repeat(64);
const SOURCE = 'synthetic.rofl';
const RAW_CASES = [
  { raw_object_u8_0x10_hex: 'c0', raw_object_u8_0x11_hex: 'c6',
    raw_object_f32_0x14_hex: '6a6a6a6a', raw_object_u32_0x18_hex: 'ee80ae84',
    raw_object_u32_0x1c_hex: '00000000', raw_object_u8_0x20_hex: 'bb' },
  { raw_object_u8_0x10_hex: 'c0', raw_object_u8_0x11_hex: 'c4',
    raw_object_f32_0x14_hex: '6a6a6a6a', raw_object_u32_0x18_hex: '381ae999',
    raw_object_u32_0x1c_hex: '00000000', raw_object_u8_0x20_hex: 'ab' },
  { raw_object_u8_0x10_hex: 'c0', raw_object_u8_0x11_hex: 'c4',
    raw_object_f32_0x14_hex: '6a6a6a6a', raw_object_u32_0x18_hex: '9d1cc7bc',
    raw_object_u32_0x1c_hex: '00000000', raw_object_u8_0x20_hex: '43' },
];

function command(directory, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', EVENT, ...args],
    { encoding: 'utf8' });
}

function row(index, replaySha = SHA, profile = v2) {
  const raw = RAW_CASES[index];
  const decoded = decodeSetSpellTimerRawFields821(raw);
  assert.ok(decoded);
  const slot = decoded.opaque_u8_0x20;
  const time = 1000 + index;
  const rawParam = 0x400000b4;
  return {
    event_type: 'SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE',
    game_version: v2.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: replaySha,
    replay_time_ms: time, raw_param: rawParam,
    ...decoded, ...raw,
    ...(profile === v2 ? {
      native_receiver_slot_candidate: slot,
      native_receiver_selection_path: slot === 63 ? 'INDEX_63' : 'INDEX_0_TO_5',
      native_receiver_forwarded_fields_witnessed: true,
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
      payload_length: 11, raw_param: rawParam,
      raw_payload_sha256: 'b'.repeat(64),
    },
  };
}

function writeReplay(root, name, rows, { profile = v2,
  replaySha = SHA } = {}) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const result = {
    profile_id: profile.id,
    input_packet_id: profile.replay_block_packet_id,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    evidence_callback_table_sha256: profile.evidence_callback_table_sha256,
    ...(profile === v2 ? {
      evidence_callback_rva: profile.evidence_callback_rva,
      evidence_receiver_lookup_rva: profile.evidence_receiver_lookup_rva,
      evidence_receiver_call_rva: profile.evidence_receiver_call_rva,
      evidence_callback_region_sha256: profile.evidence_callback_region_sha256,
      evidence_receiver_lookup_region_sha256:
        profile.evidence_receiver_lookup_region_sha256,
      evidence_callback_witness_mode: profile.evidence_callback_witness_mode,
    } : {}),
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
    input_count: rows.length, event_count: rows.length,
    scanned_block_count: Math.max(rows.length, 1),
    known_limits: [...profile.known_limits],
    event_field_confidence: profile === v2
      ? { ...v2FieldConfidence } : Object.fromEntries(
        Object.entries(v2FieldConfidence)
          .filter(([field]) => !field.startsWith('native_'))),
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
  };
  const semantic = {
    replay_version: profile.replay_version, replay_sha256: replaySha,
    container_status: 'PASS', status: 'CANDIDATE', api_status: 'CANDIDATE',
    requested_capabilities: [CAPABILITY], capability_results: { [CAPABILITY]: result },
  };
  const analysis = {
    patch: '16.19', replay_version: profile.replay_version,
    replay_sha256: replaySha, source_path: SOURCE,
    event_storage: 'JSONL_ONLY', event_counts: { [EVENT]: rows.length },
    event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` }, events: null,
    semantic: { capability_results: { [CAPABILITY]: result } },
  };
  fs.writeFileSync(path.join(directory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(directory, 'replay_analysis.json'), JSON.stringify(analysis));
  const lines = rows.map((entry) => JSON.stringify(entry));
  fs.writeFileSync(path.join(directory, `${EVENT}.jsonl`),
    lines.length ? `${lines.join('\n')}\n` : '');
  return { directory, lines };
}

function fixture(t, rows, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-spell-timer-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, ...writeReplay(root, 'synthetic', rows, options) };
}

function fileSha(filename) {
  return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
}

test('saved V2 query filters observed native receiver slots and preserves rows', (t) => {
  const rows = [row(0), row(1), row(2)];
  assert.deepEqual(rows.map((entry) => entry.native_receiver_slot_candidate),
    [0, 2, 63]);
  const { directory, lines } = fixture(t, rows);
  const selected = command(directory, '--spell-timer-receiver-slot', '0x3f',
    '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[2]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.spell_timer_receiver_checked_count, 3);
  assert.equal(summary.spell_timer_receiver_unavailable_count, 0);
  assert.equal(summary.filters.spell_timer_receiver_slot, 63);
  assert.equal(summary.rows_unmodified, true);
  const zero = command(directory, '--spell-timer-receiver-slot', '0');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${lines[0]}\n`);
});

test('saved V2 query checks later rows after limit and rejects forged native fields', (t) => {
  const corruptions = [
    (value) => { value.raw_object_u8_0x20_hex = 'bb'; },
    (value) => { value.raw_object_u32_0x18_hex = '00000000'; },
    (value) => { value.native_receiver_selection_path = 'INDEX_63'; },
    (value) => { value.native_receiver_forwarded_fields_witnessed = false; },
    (value) => { value.raw_packet_ref.packet_id = 0x00fe; },
    (value) => { value.timer_effect = 'confirmed'; },
  ];
  for (const corrupt of corruptions) {
    const first = row(0);
    const later = row(1);
    corrupt(later);
    const { root, directory } = fixture(t, [first, later]);
    const output = path.join(root, 'selected.jsonl');
    const result = command(directory, '--spell-timer-receiver-slot', '0',
      '--limit', '1', '--to-ms', '1000', '--output', output);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('saved V2 query rejects metadata drift and V1 reports receiver unavailable', (t) => {
  for (const field of ['evidence_callback_region_sha256',
    'evidence_receiver_lookup_region_sha256', 'evidence_callback_witness_mode',
    'known_limits', 'event_field_confidence']) {
    const { directory } = fixture(t, [row(0)]);
    const filename = path.join(directory, 'semantic_run.json');
    const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
    semantic.capability_results[CAPABILITY][field] = 'changed';
    fs.writeFileSync(filename, JSON.stringify(semantic));
    const result = command(directory, '--spell-timer-receiver-slot', '0');
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
  }
  const older = row(0, SHA, v1);
  const { directory } = fixture(t, [older], { profile: v1 });
  const unavailable = command(directory, '--spell-timer-receiver-slot', '0');
  assert.equal(unavailable.status, 2, unavailable.stderr);
  const failure = JSON.parse(unavailable.stderr);
  assert.equal(failure.code, 'SPELL_TIMER_RECEIVER_UNAVAILABLE');
  assert.equal(failure.spell_timer_receiver_checked_count, 0);
  assert.equal(failure.spell_timer_receiver_unavailable_count, 1);
  for (const invalid of ['6', '62', '64', '-1', '256']) {
    const rejected = command(directory, '--spell-timer-receiver-slot', invalid);
    assert.notEqual(rejected.status, 0);
  }
});

test('batch query counts V2 checked rows and V1 unavailable replay separately', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-spell-timer-batch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const current = writeReplay(root, 'current', [row(0)]);
  const oldSha = 'c'.repeat(64);
  const older = writeReplay(root, 'older', [row(0, oldSha, v1)],
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
  const result = command(root, '--spell-timer-receiver-slot', '0');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${current.lines[0]}\n`);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.completed_replay_count, 1);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.spell_timer_receiver_checked_count, 1);
  assert.equal(summary.spell_timer_receiver_unavailable_count, 1);
  assert.equal(summary.spell_timer_receiver_unavailable_replay_count, 1);
  assert.equal(summary.replay_results[1].code, 'SPELL_TIMER_RECEIVER_UNAVAILABLE');
});
