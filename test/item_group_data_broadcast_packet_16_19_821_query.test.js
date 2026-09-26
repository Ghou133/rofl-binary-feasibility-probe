'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { ITEM_GROUP_DATA_BROADCAST_PACKET_CANDIDATE_PROFILE_821: profile,
  ITEM_GROUP_DATA_BROADCAST_PACKET_CANDIDATE_PROFILE_V2_821: profileV2 } =
  require('../src/decoders/rofl_16_19_821_item_group_data_broadcast_packet_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const CAPABILITY = 'item_group_data_broadcast_packet';
const EVENT = 'item_group_data_broadcast_packet_candidates';
const SOURCE_PATH = 'synthetic.rofl';
const REPLAY_SHA = 'a'.repeat(64);
const PACKETS = [
  ['1e567825e7f836', '251064ea', 5247418],
  ['1e5670099d3d48', '40e33eea', 6444154],
];
const V2_PACKETS = [
  ['1e5672c257c166', '522d2722', 90922051, '44', 1],
  ['1e5076c257c166', '522d2722', 90922051, 'c4', 0],
];

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function row(index, v2 = false) {
  const selected = v2 ? profileV2 : profile;
  const [hex, protectedHex, lookupKey, protectedByte, callbackValue] =
    (v2 ? V2_PACKETS : PACKETS)[index];
  const time = 1000 + index;
  const rawParam = 0x400000ae;
  return {
    event_type: 'ITEM_GROUP_DATA_BROADCAST_PACKET_CANDIDATE',
    game_version: selected.replay_version, patch: '16.19',
    build_profile: selected.id, replay_sha256: REPLAY_SHA,
    replay_time_ms: time, raw_param: rawParam,
    packet_name_candidate: selected.packet_name,
    native_protected_lookup_bytes_hex: protectedHex,
    native_callback_lookup_key_u32: lookupKey,
    ...(v2 ? { native_protected_callback_u8_hex: protectedByte,
      native_callback_u8_if_lookup_hit_candidate: callbackValue,
      native_conditional_callback_witness: 'SYNTHETIC_LOOKUP_HIT' } : {}),
    native_receiver_lookup_status: 'NOT_OBSERVED',
    group_identity_status: 'UNKNOWN', item_identity_status: 'UNKNOWN',
    owner_status: 'UNKNOWN', participant_status: 'UNKNOWN',
    inventory_state_change_status: 'UNKNOWN', semantic_effect_status: 'UNKNOWN',
    confidence: 'CANDIDATE', semantic_status: selected.evidence_status,
    raw_packet_ref: {
      source_path: SOURCE_PATH, replay_sha256: REPLAY_SHA,
      chunk_index: index, chunk_id: index + 1, chunk_stream: 'keyframe',
      chunk_file_offset: 100 + index, decompressed_block_offset: 20 + index * 30,
      decompressed_payload_offset: 29 + index * 30,
      packet_id: selected.replay_block_packet_id, replay_time_ms: time,
      payload_length: hex.length / 2, raw_param: rawParam,
      raw_payload_hex: hex, raw_payload_sha256: sha256(Buffer.from(hex, 'hex')),
    },
  };
}

function hashes(rows, v2 = false) {
  const input = crypto.createHash('sha256');
  const output = crypto.createHash('sha256');
  for (const item of rows) {
    const payload = Buffer.from(item.raw_packet_ref.raw_payload_hex, 'hex');
    const header = Buffer.alloc(8);
    header.writeUInt32LE(item.raw_param, 0);
    header.writeUInt32LE(payload.length, 4);
    input.update(header).update(payload);
    const key = Buffer.alloc(4);
    key.writeUInt32LE(item.native_callback_lookup_key_u32);
    output.update(Buffer.from(item.native_protected_lookup_bytes_hex, 'hex'))
      .update(key);
    if (v2) output.update(Buffer.from(item.native_protected_callback_u8_hex, 'hex'))
      .update(Buffer.from([item.native_callback_u8_if_lookup_hit_candidate]));
  }
  return [input.digest('hex'), output.digest('hex')];
}

function fixture(t, v2 = false) {
  const selected = v2 ? profileV2 : profile;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-item-group-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dir = path.join(root, 'replays', 'sample');
  fs.mkdirSync(dir, { recursive: true });
  const rows = [row(0, v2), row(1, v2)];
  const [nativeInput, nativeOutput] = hashes(rows, v2);
  const result = {
    profile_id: selected.id, input_packet_id: selected.replay_block_packet_id,
    evidence_status: selected.evidence_status,
    evidence_runtime_image_sha256: selected.evidence_runtime_image_sha256,
    status: 'CANDIDATE', input_count: 2, event_count: 2, scanned_block_count: 2,
    known_limits: [...selected.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      native_callback_lookup_key_u32: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
      ...(v2 ? { native_protected_callback_u8_hex: 'CANDIDATE_EXACT_RUNTIME_FIELD',
        native_callback_u8_if_lookup_hit_candidate:
          'CANDIDATE_EXACT_RUNTIME_SYNTHETIC_LOOKUP_HIT' } : {}),
    },
    ...(v2 ? { native_conditional_callback_witness: 'SYNTHETIC_LOOKUP_HIT' } : {}),
    native_witness_status: 'FULLY_CONSUMED_ALL', native_full_success_count: 2,
    native_batch_count: 1, native_input_sha256: nativeInput,
    native_output_sha256: nativeOutput, runtime_image_status: 'MATCHED_USED',
    runtime_image_used: true,
    runtime_image_sha256: selected.evidence_runtime_image_sha256,
  };
  const semantic = {
    replay_version: selected.replay_version, replay_sha256: REPLAY_SHA,
    container_status: 'PASS', status: 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE', requested_capabilities: [CAPABILITY],
    capability_results: { [CAPABILITY]: result },
  };
  const analysis = {
    patch: '16.19', replay_version: selected.replay_version,
    replay_sha256: REPLAY_SHA, source_path: SOURCE_PATH,
    event_storage: 'JSONL_ONLY', event_counts: { [EVENT]: 2 },
    event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` }, events: null,
    semantic: { status: 'CANDIDATE', requested_capabilities: [CAPABILITY],
      capability_results: { [CAPABILITY]: result } },
  };
  const semanticPath = path.join(dir, 'semantic_run.json');
  const analysisPath = path.join(dir, 'replay_analysis.json');
  const eventPath = path.join(dir, `${EVENT}.jsonl`);
  fs.writeFileSync(semanticPath, JSON.stringify(semantic));
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  fs.writeFileSync(eventPath, `${rows.map(JSON.stringify).join('\n')}\n`);
  return { root, dir, rows, semantic, analysis, semanticPath, analysisPath,
    eventPath };
}

function query(dir, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', dir, '--event', EVENT, ...args], { encoding: 'utf8' });
}

function errorCode(run) {
  assert.equal(run.status, 2, run.stderr);
  return JSON.parse(run.stderr).code;
}

test('saved item-group lookup query validates all rows and emits original JSONL', (t) => {
  const f = fixture(t);
  const selected = query(f.dir, '--opaque-u32', '5247418', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(f.rows[0])}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.rows_unmodified, true);
  assert.equal(errorCode(query(f.dir, '--participant', '1')),
    'PARTICIPANT_UNAVAILABLE');
});

test('later forged native output is detected after limit with no partial output', (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.rows);
  forged[1].native_protected_lookup_bytes_hex = PACKETS[0][1];
  forged[1].native_callback_lookup_key_u32 = PACKETS[0][2];
  fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  const output = path.join(f.root, 'selected.jsonl');
  assert.equal(errorCode(query(f.dir, '--limit', '1', '--output', output)),
    'EVENT_COUNT_MISMATCH');
  assert.equal(fs.existsSync(output), false);
});

test('stdout stays empty when a later native output fails integrity', (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.rows);
  forged[1].native_protected_lookup_bytes_hex = PACKETS[0][1];
  forged[1].native_callback_lookup_key_u32 = PACKETS[0][2];
  fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  const selected = query(f.dir, '--limit', '1');
  assert.equal(errorCode(selected), 'EVENT_COUNT_MISMATCH');
  assert.equal(selected.stdout, '');
});

test('raw payload and capability promotion forgeries fail closed', (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.rows);
  forged[1].raw_packet_ref.raw_payload_hex = PACKETS[0][0];
  forged[1].raw_packet_ref.raw_payload_sha256 = sha256(Buffer.from(PACKETS[0][0], 'hex'));
  fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  assert.equal(errorCode(query(f.dir, '--limit', '1')), 'EVENT_COUNT_MISMATCH');
  fs.writeFileSync(f.eventPath, `${f.rows.map(JSON.stringify).join('\n')}\n`);
  for (const status of ['PASS', 'PROMOTED']) {
    const semantic = structuredClone(f.semantic);
    const analysis = structuredClone(f.analysis);
    semantic.capability_results[CAPABILITY].status = status;
    analysis.semantic.capability_results[CAPABILITY].status = status;
    fs.writeFileSync(f.semanticPath, JSON.stringify(semantic));
    fs.writeFileSync(f.analysisPath, JSON.stringify(analysis));
    assert.equal(errorCode(query(f.dir)), 'CAPABILITY_METADATA_MISMATCH');
  }
});

test('V2 saved query preserves both conditional callback values under one lookup key', (t) => {
  const f = fixture(t, true);
  const selected = query(f.dir, '--opaque-u32', '90922051',
    '--item-group-callback-u8', '0', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(f.rows[1])}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.rows_unmodified, true);
  assert.equal(summary.filters.item_group_callback_u8, 0);
  assert.deepEqual(f.rows.map((entry) =>
    entry.native_callback_u8_if_lookup_hit_candidate), [1, 0]);
  const unseen = query(f.dir, '--item-group-callback-u8', '4');
  assert.equal(unseen.status, 0, unseen.stderr);
  assert.equal(unseen.stdout, '');
  assert.equal(JSON.parse(unseen.stderr).scanned_count, 2);
  assert.equal(JSON.parse(unseen.stderr).matched_count, 0);
  const v1 = fixture(t);
  assert.equal(errorCode(query(v1.dir, '--item-group-callback-u8', '1')),
    'UNSUPPORTED_FILTER');
});

test('V2 altered valid callback byte after limit fails ordered native-output digest', (t) => {
  const f = fixture(t, true);
  const forged = structuredClone(f.rows);
  forged[1].native_protected_callback_u8_hex = '44';
  forged[1].native_callback_u8_if_lookup_hit_candidate = 1;
  fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  const output = path.join(f.root, 'selected-v2.jsonl');
  assert.equal(errorCode(query(f.dir, '--item-group-callback-u8', '1',
    '--limit', '1', '--output', output)),
    'EVENT_COUNT_MISMATCH');
  assert.equal(fs.existsSync(output), false);
});

test('V2 callback transform, raw-input digest, and candidate status fail closed', (t) => {
  const f = fixture(t, true);
  const original = `${f.rows.map(JSON.stringify).join('\n')}\n`;
  const forged = structuredClone(f.rows);
  forged[1].native_callback_u8_if_lookup_hit_candidate = 1;
  fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  assert.equal(errorCode(query(f.dir, '--limit', '1')), 'INVALID_EVENT_ROW');
  forged[1] = structuredClone(f.rows[1]);
  forged[1].raw_param = 0x400000b7;
  forged[1].raw_packet_ref.raw_param = 0x400000b7;
  fs.writeFileSync(f.eventPath, `${forged.map(JSON.stringify).join('\n')}\n`);
  assert.equal(errorCode(query(f.dir, '--limit', '1')), 'EVENT_COUNT_MISMATCH');
  fs.writeFileSync(f.eventPath, original);
  for (const status of ['PASS', 'PROMOTED']) {
    const semantic = structuredClone(f.semantic);
    const analysis = structuredClone(f.analysis);
    semantic.capability_results[CAPABILITY].status = status;
    analysis.semantic.capability_results[CAPABILITY].status = status;
    fs.writeFileSync(f.semanticPath, JSON.stringify(semantic));
    fs.writeFileSync(f.analysisPath, JSON.stringify(analysis));
    assert.equal(errorCode(query(f.dir)), 'CAPABILITY_METADATA_MISMATCH');
  }
});
