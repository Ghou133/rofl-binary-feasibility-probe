'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  NPC_BUFF_ADD_PACKET_CANDIDATE_PROFILE,
  decodeNpcBuffAddPacketCandidates,
} = require('../src/decoders/rofl_16_19_buff_add_candidate');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const IMAGE_SHA256 = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';
const IMAGE = path.resolve(__dirname,
  '../artifacts/16_19_development/runtime_capture_820_7193/League_of_Legends_pid29960.bin');
const KEYFRAME_PAYLOAD = '3c75e675f6d9065b2ebe9141ec01c86bb5a6958a5287';
const GAME_PAYLOAD = '62756775f6d8065b2ebe91415b1bdc7726adeab6a738';

function packet(packetId, rawParam, payload) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replayWithPackets(rows, build = BUILD) {
  return replayFromChunks(rows.map((row) => ({
    stream: row.stream,
    body: packet(row.packetId, row.param, row.payload),
  })), build);
}

function fixtureReplay() {
  return replayWithPackets([
    { stream: 1, packetId: 0x03ed, param: 0x400000ae,
      payload: Buffer.from(GAME_PAYLOAD, 'hex') },
    { stream: 2, packetId: 0x03ed, param: 0x400000af,
      payload: Buffer.from(KEYFRAME_PAYLOAD, 'hex') },
  ]);
}

function temporaryImage(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-buff-add-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const image = path.join(root, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function mockedRows(request) {
  const obj = Buffer.alloc(0x60).toString('hex');
  const values = {
    offset_0x10_u32: 0x400000ae,
    offset_0x14_f32: 5.5,
    offset_0x1c_f32: 1.25,
    offset_0x24_u32: 123456,
    offset_0x28_u8: 7,
    offset_0x30_u32: 654321,
  };
  const raw = Object.fromEntries(Object.keys(values).map((name) => {
    const offset = Number.parseInt(name.slice(9, 11), 16);
    const size = name.endsWith('_u8') ? 1 : 4;
    return [name, obj.slice(offset * 2, (offset + size) * 2)];
  }));
  return request.packets.map((row, index) => ({
    status: 'DECODED', input_index: index,
    stream_tag: row.stream_tag, raw_param: row.raw_param,
    raw_payload_sha256: crypto.createHash('sha256')
      .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
    deserialize_return_al: 1, bytes_consumed: row.payload_hex.length / 2,
    decoded_scalar_fields: values,
    raw_object_scalar_bytes_hex: raw,
    raw_object_hex: obj,
  }));
}

test('BuffAdd2 exposes bounded exact-runtime scalars from both streams with raw refs', (t) => {
  const image = temporaryImage(t);
  let request;
  t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    request = JSON.parse(options.input);
    assert.match(args[1], /decode_buff_add_16_19\.py$/);
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
      results: mockedRows(request),
    }) };
  });
  const replay = fixtureReplay();
  const result = decodeNpcBuffAddPacketCandidates(replay, null, { runtimeImagePath: image });
  assert.equal(NPC_BUFF_ADD_PACKET_CANDIDATE_PROFILE.capability, 'npc_buff_add_packet');
  assert.deepEqual(NPC_BUFF_ADD_PACKET_CANDIDATE_PROFILE.stream_tags, [1, 2]);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 2);
  assert.deepEqual(result.events.map((row) => row.stream_tag), [1, 2]);
  assert.equal(result.events[0].decoded_scalar_fields_candidate.offset_0x14_f32, 5.5);
  assert.equal(result.events[0].decoded_scalar_fields_candidate.offset_0x1c_f32, 1.25);
  assert.equal(result.events[0].raw_object_hex.length, 192);
  assert.equal(result.events[0].raw_payload_hex, GAME_PAYLOAD);
  assert.equal(result.events[1].raw_payload_hex, KEYFRAME_PAYLOAD);
  assert.equal(result.events[0].raw_packet_ref.chunk_stream_tag, 1);
  assert.equal(result.events[1].raw_packet_ref.chunk_stream_tag, 2);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[0].raw_packet_ref.raw_param, 0x400000ae);
  assert.equal(result.event_field_confidence.decoded_scalar_fields_candidate
    .offset_0x14_f32, 'CANDIDATE_EXACT_RUNTIME_CALLBACK_SCALAR');
  assert.ok(result.known_limits.some((limit) => limit.includes('cross-stream')));
  assert.equal(Object.hasOwn(result.events[0], 'field_confidence'), false);
  assert.equal(Object.hasOwn(result.events[0], 'known_limits'), false);
  assert.equal(Object.hasOwn(result.events[0], 'participant_id_candidate'), false);
  assert.equal(Object.hasOwn(result.events[0], 'buff_name'), false);
  assert.deepEqual(request.packets.map((row) => row.stream_tag), [1, 2]);
});

test('wrong route, version, malformed source and unobserved shape refuse decoding', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime must not run');
  });
  const wrongRoute = replayWithPackets([{
    stream: 1, packetId: 0x043c, param: 0x400000ae,
    payload: Buffer.from(GAME_PAYLOAD, 'hex'),
  }]);
  assert.equal(decodeNpcBuffAddPacketCandidates(wrongRoute).status, 'PROFILE_UNAVAILABLE');
  const wrongVersion = replayWithPackets([{
    stream: 1, packetId: 0x03ed, param: 0x400000ae,
    payload: Buffer.from(GAME_PAYLOAD, 'hex'),
  }], '16.19.821.7343');
  assert.equal(decodeNpcBuffAddPacketCandidates(wrongVersion).status, 'UNSUPPORTED');
  const malformed = fixtureReplay();
  malformed.buffer[malformed.buffer.length - 8] ^= 1;
  assert.equal(decodeNpcBuffAddPacketCandidates(malformed).status, 'DECODE_FAILED');
  const unknownShape = replayWithPackets([{
    stream: 1, packetId: 0x03ed, param: 0x400000ae,
    payload: Buffer.alloc(16),
  }]);
  assert.equal(decodeNpcBuffAddPacketCandidates(unknownShape).status, 'UNSUPPORTED');
  assert.equal(invoke.mock.callCount(), 0);
});

test('BuffAdd2 stops at 50,001 route packets before a later framing error', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime must not run');
  });
  const one = packet(0x03ed, 0x400000ae, Buffer.from(GAME_PAYLOAD, 'hex'));
  const replay = replayFromChunks([{
    stream: 1, body: Buffer.concat([...Array(50_001).fill(one), Buffer.from([0x10])]),
  }], BUILD);
  const result = decodeNpcBuffAddPacketCandidates(replay);
  assert.equal(result.status, 'UNSUPPORTED');
  assert.equal(result.input_count, null);
  assert.equal(result.observed_packet_count_minimum, 50_001);
  assert.equal(result.event_count, null);
  assert.equal(result.events, null);
  assert.equal(result.runtime_image_status, 'NOT_CHECKED');
  assert.equal(invoke.mock.callCount(), 0);
});

test('BuffAdd2 rejects Replay source mutation during the walk', (t) => {
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
  const result = decodeNpcBuffAddPacketCandidates(replay, null,
    { runtimeImagePath: temporaryImage(t) });
  assert.equal(changed, true);
  assert.equal(result.status, 'DECODE_FAILED');
  assert.match(result.error, /Replay source integrity failed after walk/);
  assert.equal(result.events, null);
  assert.equal(invoke.mock.callCount(), 0);
});

test('missing and wrong runtime image fail closed', (t) => {
  const missing = decodeNpcBuffAddPacketCandidates(fixtureReplay());
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.events, null);
  const wrong = decodeNpcBuffAddPacketCandidates(fixtureReplay(), null,
    { runtimeImagePath: temporaryImage(t) });
  assert.equal(wrong.status, 'DECODE_FAILED');
  assert.equal(wrong.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(wrong.events, null);
});

test('packet result binding and full consumption suppress all candidates on mismatch', (t) => {
  const image = temporaryImage(t);
  for (const fault of ['hash', 'stream', 'truncated', 'appended', 'object']) {
    const mock = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
      const request = JSON.parse(options.input);
      const results = mockedRows(request);
      if (fault === 'hash') results[1].raw_payload_sha256 = '0'.repeat(64);
      if (fault === 'stream') results[1].stream_tag = 1;
      if (fault === 'truncated') results[1].deserialize_return_al = 0;
      if (fault === 'appended') results[1].bytes_consumed -= 1;
      if (fault === 'object') {
        const at = 0x14 * 2;
        results[1].raw_object_hex = results[1].raw_object_hex.slice(0, at)
          + 'ff' + results[1].raw_object_hex.slice(at + 2);
      }
      return { status: 0, stderr: '', stdout: JSON.stringify({
        status: 'PASS', runtime_image_sha256: IMAGE_SHA256, results,
      }) };
    });
    const result = decodeNpcBuffAddPacketCandidates(fixtureReplay(), null,
      { runtimeImagePath: image });
    assert.equal(result.status, 'DECODE_FAILED', fault);
    assert.equal(result.events, null, fault);
    assert.equal(result.event_count, null, fault);
    assert.equal(result.first_failed_packet_ref.chunk_stream_tag, 2, fault);
    mock.mock.restore();
  }
});

test('exact helper accepts observed packet and rejects truncation and suffix', (t) => {
  if (!fs.existsSync(IMAGE)) {
    t.skip('pinned HN 16.19 runtime image is unavailable');
    return;
  }
  const script = path.resolve(__dirname, '../src/decoders/decode_buff_add_16_19.py');
  const request = { replay_version: BUILD, packets: [
    { stream_tag: 2, raw_param: 0x400000ae, payload_hex: KEYFRAME_PAYLOAD },
    { stream_tag: 2, raw_param: 0x400000ae, payload_hex: KEYFRAME_PAYLOAD.slice(0, -2) },
    { stream_tag: 2, raw_param: 0x400000ae, payload_hex: KEYFRAME_PAYLOAD + 'ff' },
    { stream_tag: 1, raw_param: 0x400000ae, payload_hex: GAME_PAYLOAD },
  ] };
  const run = childProcess.spawnSync(process.env.PYTHON || 'python',
    ['-B', script, '--image', IMAGE], {
      input: JSON.stringify(request), encoding: 'utf8', timeout: 30000,
    });
  assert.equal(run.status, 0, run.stderr);
  const result = JSON.parse(run.stdout);
  assert.equal(result.runtime_image_sha256, IMAGE_SHA256);
  assert.deepEqual(result.results.map((row) => row.status),
    ['DECODED', 'FAILED', 'FAILED', 'DECODED']);
  assert.equal(result.results[0].decoded_scalar_fields.offset_0x14_f32, 25000);
  assert.equal(result.results[0].decoded_scalar_fields.offset_0x1c_f32, 0);
  assert.equal(result.results[0].decoded_scalar_fields.offset_0x10_u32, 0x400000ae);
  assert.equal(result.results[1].deserialize_return_al, 0);
  assert.equal(result.results[2].deserialize_return_al, 1);
  assert.equal(result.results[2].bytes_consumed, 22);
  assert.equal(result.results[3].stream_tag, 1);
});

test('selected API and capability query expose image-bound BuffAdd2 candidates only', (t) => {
  const { decodeSemanticReplay, getNpcBuffAddPacketCandidates } = require('../src/semantic_api');
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
    capabilities: ['npc_buff_add_packet'], runtimeImagePath: image,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.npc_buff_add_packet.event_count, 2);
  assert.deepEqual(Object.keys(decoded.events), ['npc_buff_add_packet_candidates']);
  assert.equal(getNpcBuffAddPacketCandidates(decoded).length, 2);
  assert.equal(decoded.events.buff_add_events, undefined);
  const row = capabilityQuery(replay).capabilities
    .find((entry) => entry.capability === 'npc_buff_add_packet');
  assert.equal(row.status, 'CANDIDATE');
  assert.equal(row.output, 'npc_buff_add_packet_candidates');
  assert.equal(row.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.deepEqual(row.missing_inputs, ['exact_runtime_image']);
});

test('selected CLI writes game and keyframe BuffAdd2 candidate JSONL with provenance', async (t) => {
  const { main } = require('../src/cli');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-buff-add-cli-'));
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
  assert.equal(await main(['decode', input, '--events', 'npc_buff_add_packet',
    '--runtime-image', image, '--out-dir', output]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDir = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDir, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results.npc_buff_add_packet.event_count, 2);
  assert.equal(semantic.capability_results.npc_buff_add_packet.event_field_confidence
    .decoded_scalar_fields_candidate.offset_0x14_f32,
  'CANDIDATE_EXACT_RUNTIME_CALLBACK_SCALAR');
  const rows = fs.readFileSync(path.join(replayDir, 'npc_buff_add_packet_candidates.jsonl'), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(rows.length, 2);
  assert.deepEqual(rows.map((row) => row.stream_tag), [1, 2]);
  assert.equal(rows[0].decoded_scalar_fields_candidate.offset_0x14_f32, 5.5);
  assert.equal(Object.hasOwn(rows[0], 'known_limits'), false);
  assert.equal(Object.hasOwn(rows[0], 'field_confidence'), false);
  assert.equal(rows[1].raw_packet_ref.replay_sha256,
    crypto.createHash('sha256').update(fs.readFileSync(input)).digest('hex'));
  assert.equal(rows[1].raw_packet_ref.raw_param, 0x400000af);
});
