'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  NPC_BUFF_REMOVE_PACKET_CANDIDATE_PROFILE,
  decodeNpcBuffRemovePacketCandidates,
} = require('../src/decoders/rofl_16_19_buff_remove_candidate');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const IMAGE_SHA256 = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';
const IMAGE = path.resolve(__dirname,
  '../artifacts/16_19_development/runtime_capture_820_7193/League_of_Legends_pid29960.bin');

function packet(packetId, rawParam, payload) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replayWithPackets(rows, build = BUILD) {
  return replayFromChunks([{ body: Buffer.concat(rows.map((row) =>
    packet(row.packetId, row.param, row.payload))) }], build);
}

function fixtureReplay() {
  // These bytes exercise framing and result binding only; the mocked helper
  // below does not treat them as observed exact-runtime packets.
  return replayWithPackets([
    { packetId: 0x043c, param: 0x400002b7, payload: Buffer.from('01020304050607', 'hex') },
    { packetId: 0x043c, param: 0x400000b5, payload: Buffer.from('aabbccddeeff', 'hex') },
  ]);
}

function temporaryImage(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-buff-remove-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const image = path.join(root, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function mockedRows(request) {
  return request.packets.map((row, inputIndex) => ({
    status: 'DECODED', input_index: inputIndex, raw_param: row.raw_param,
    raw_payload_sha256: crypto.createHash('sha256')
      .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
    deserialize_return_al: 1, bytes_consumed: row.payload_hex.length / 2,
    decoded_time_f32_seconds: inputIndex === 0 ? 0 : 24.5,
    slot_index_u8: inputIndex === 0 ? 35 : 0,
    lookup_token_u32: inputIndex === 0 ? 54814997 : 217270246,
    raw_object_time_bytes_hex: 'b4b4b4b4',
    raw_object_slot_byte_hex: '32',
    raw_object_lookup_bytes_hex: 'ec3f9314',
  }));
}

test('BuffRemove2 emits only exact-image candidate packet fields and raw provenance', (t) => {
  const image = temporaryImage(t);
  const calls = [];
  t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    const request = JSON.parse(options.input);
    calls.push({ args, request });
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
      results: mockedRows(request),
    }) };
  });
  const replay = fixtureReplay();
  const result = decodeNpcBuffRemovePacketCandidates(replay, null,
    { runtimeImagePath: image });
  assert.equal(NPC_BUFF_REMOVE_PACKET_CANDIDATE_PROFILE.capability,
    'npc_buff_remove_packet');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].buff_slot_index_candidate, 35);
  assert.equal(result.events[0].buff_lookup_token_u32_candidate, 54814997);
  assert.equal(result.events[1].decoded_time_f32_seconds_candidate, 24.5);
  assert.equal(result.events[0].raw_payload_hex, '01020304050607');
  assert.equal(result.events[0].raw_packet_ref.packet_id, 0x043c);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[0].raw_packet_ref.raw_param, 0x400002b7);
  assert.equal(result.event_field_confidence.buff_slot_index_candidate,
    'CANDIDATE_EXACT_RUNTIME_VECTOR_INDEX');
  assert.ok(result.known_limits.some((limit) => limit.includes('successful buff removal')));
  assert.equal(Object.hasOwn(result.events[0], 'field_confidence'), false);
  assert.equal(Object.hasOwn(result.events[0], 'known_limits'), false);
  assert.equal(Object.hasOwn(result.events[0], 'participant_id_candidate'), false);
  assert.equal(Object.hasOwn(result.events[0], 'buff_name'), false);
  assert.equal(calls.length, 1);
  assert.match(calls[0].args[1], /decode_buff_remove_16_19\.py$/);
});

test('wrong route, wrong version, and changed replay source never call runtime', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime should not run');
  });
  const wrongRoute = replayWithPackets([{
    packetId: 0x03ed, param: 0x400000ae,
    payload: Buffer.from('01020304050607', 'hex'),
  }]);
  assert.equal(decodeNpcBuffRemovePacketCandidates(wrongRoute).status,
    'PROFILE_UNAVAILABLE');
  const wrongVersion = replayWithPackets([{
    packetId: 0x043c, param: 0x400000ae,
    payload: Buffer.from('01020304050607', 'hex'),
  }], '16.19.821.7343');
  assert.equal(decodeNpcBuffRemovePacketCandidates(wrongVersion).status,
    'UNSUPPORTED');
  const changedSource = fixtureReplay();
  changedSource.buffer[changedSource.buffer.length - 8] ^= 1;
  assert.equal(decodeNpcBuffRemovePacketCandidates(changedSource).status,
    'DECODE_FAILED');
  assert.equal(invoke.mock.callCount(), 0);
});

test('BuffRemove2 stops at 50,001 route packets before a later framing error', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime must not run');
  });
  const one = packet(0x043c, 0x400002b7, Buffer.from('01020304050607', 'hex'));
  const replay = replayFromChunks([{
    body: Buffer.concat([...Array(50_001).fill(one), Buffer.from([0x10])]),
  }], BUILD);
  const result = decodeNpcBuffRemovePacketCandidates(replay);
  assert.equal(result.status, 'UNSUPPORTED');
  assert.equal(result.input_count, null);
  assert.equal(result.observed_packet_count_minimum, 50_001);
  assert.equal(result.event_count, null);
  assert.equal(result.events, null);
  assert.equal(result.runtime_image_status, 'NOT_CHECKED');
  assert.equal(invoke.mock.callCount(), 0);
});

test('BuffRemove2 rejects Replay source mutation during the walk', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime must not run');
  });
  const replay = fixtureReplay();
  const chunks = replay.chunks;
  let changed = false;
  Object.defineProperty(replay, 'chunks', { configurable: true, get() {
    if (!changed) {
      replay.buffer[chunks[0].body_offset + 15] ^= 1;
      changed = true;
    }
    return chunks;
  } });
  const result = decodeNpcBuffRemovePacketCandidates(replay, null,
    { runtimeImagePath: temporaryImage(t) });
  assert.equal(changed, true);
  assert.equal(result.status, 'DECODE_FAILED');
  assert.match(result.error, /Replay source integrity failed after walk/);
  assert.equal(result.events, null);
  assert.equal(invoke.mock.callCount(), 0);
});

test('missing and wrong image fail closed', (t) => {
  const missing = decodeNpcBuffRemovePacketCandidates(fixtureReplay());
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.event_count, null);
  const wrong = decodeNpcBuffRemovePacketCandidates(fixtureReplay(), null,
    { runtimeImagePath: temporaryImage(t) });
  assert.equal(wrong.status, 'DECODE_FAILED');
  assert.equal(wrong.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(wrong.events, null);
});

test('truncated and appended runtime payload results suppress every candidate', (t) => {
  const image = temporaryImage(t);
  for (const fault of ['truncated', 'appended']) {
    const mock = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
      const request = JSON.parse(options.input);
      const results = mockedRows(request);
      if (fault === 'truncated') {
        results[1].status = 'FAILED';
        results[1].deserialize_return_al = 0;
      } else {
        results[1].bytes_consumed -= 1;
      }
      return { status: 0, stderr: '', stdout: JSON.stringify({
        status: 'PASS', runtime_image_sha256: IMAGE_SHA256, results,
      }) };
    });
    const result = decodeNpcBuffRemovePacketCandidates(fixtureReplay(), null,
      { runtimeImagePath: image });
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.event_count, null);
    assert.equal(result.events, null);
    assert.equal(result.failed_packet_count, 1);
    assert.equal(result.first_failed_packet_ref.packet_id, 0x043c);
    mock.mock.restore();
  }
});

test('exact helper accepts observed bytes and rejects truncation, suffix, and wrong-route payload', (t) => {
  if (!fs.existsSync(IMAGE)) {
    t.skip('pinned 16.19 HN runtime image is not available');
    return;
  }
  const script = path.resolve(__dirname, '../src/decoders/decode_buff_remove_16_19.py');
  const request = { replay_version: BUILD, packets: [
    { raw_param: 0x400002b7, payload_hex: '59993264e92504' },
    { raw_param: 0x400002b7, payload_hex: '59993264e925' },
    { raw_param: 0x400002b7, payload_hex: '59993264e92504ff' },
    { raw_param: 0x400000ae, payload_hex: '3c75e675f6d9065b2ebe9141ec01c86bb5a6958a5287' },
  ] };
  const run = childProcess.spawnSync(process.env.PYTHON || 'python',
    ['-B', script, '--image', IMAGE], {
      input: JSON.stringify(request), encoding: 'utf8', timeout: 30_000,
    });
  assert.equal(run.status, 0, run.stderr);
  const result = JSON.parse(run.stdout);
  assert.equal(result.runtime_image_sha256, IMAGE_SHA256);
  assert.deepEqual(result.results.map((row) => row.status),
    ['DECODED', 'FAILED', 'FAILED', 'FAILED']);
  assert.equal(result.results[0].slot_index_u8, 35);
  assert.equal(result.results[0].lookup_token_u32, 54814997);
  assert.equal(result.results[0].decoded_time_f32_seconds, 0);
  assert.equal(result.results[1].deserialize_return_al, 0);
  assert.equal(result.results[2].deserialize_return_al, 1);
  assert.equal(result.results[2].bytes_consumed, 7);
  assert.equal(result.results[3].deserialize_return_al, 1);
  assert.equal(result.results[3].bytes_consumed, 6);
});

test('selected API and capability query keep BuffRemove2 experimental and image-bound', (t) => {
  const { decodeSemanticReplay, getNpcBuffRemovePacketCandidates } = require('../src/semantic_api');
  const { capabilityQuery } = require('../src/cli');
  const image = temporaryImage(t);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
      results: mockedRows(request),
    }) };
  });
  const replay = fixtureReplay();
  const decoded = decodeSemanticReplay(replay, {
    capabilities: ['npc_buff_remove_packet'], runtimeImagePath: image,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.npc_buff_remove_packet.event_count, 2);
  assert.deepEqual(Object.keys(decoded.events), ['npc_buff_remove_packet_candidates']);
  assert.equal(getNpcBuffRemovePacketCandidates(decoded).length, 2);
  assert.equal(decoded.events.buff_remove_events, undefined);
  const row = capabilityQuery(replay).capabilities
    .find((entry) => entry.capability === 'npc_buff_remove_packet');
  assert.equal(row.status, 'CANDIDATE');
  assert.equal(row.output, 'npc_buff_remove_packet_candidates');
  assert.equal(row.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.deepEqual(row.missing_inputs, ['exact_runtime_image']);
});

test('selected CLI writes BuffRemove2 candidates with raw packet provenance', async (t) => {
  const { main } = require('../src/cli');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-buff-remove-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const image = path.join(root, 'runtime.bin');
  const output = path.join(root, 'output');
  fs.writeFileSync(input, fixtureReplay().buffer);
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
      results: mockedRows(request),
    }) };
  });
  assert.equal(await main(['decode', input, '--events', 'npc_buff_remove_packet',
    '--runtime-image', image, '--out-dir', output]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDir = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDir, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results.npc_buff_remove_packet.event_count, 2);
  assert.equal(semantic.capability_results.npc_buff_remove_packet.event_field_confidence
    .buff_slot_index_candidate, 'CANDIDATE_EXACT_RUNTIME_VECTOR_INDEX');
  const rows = fs.readFileSync(path.join(replayDir, 'npc_buff_remove_packet_candidates.jsonl'), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(rows.length, 2);
  assert.equal(rows[1].decoded_time_f32_seconds_candidate, 24.5);
  assert.equal(rows[0].raw_packet_ref.replay_sha256,
    crypto.createHash('sha256').update(fs.readFileSync(input)).digest('hex'));
  assert.equal(rows[0].raw_packet_ref.raw_param, 0x400002b7);
  assert.equal(Object.hasOwn(rows[0], 'known_limits'), false);
  assert.equal(Object.hasOwn(rows[0], 'field_confidence'), false);
});
