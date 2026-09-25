'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { collect821Routes } = require('../src/decoders/rofl_16_19_821_scan');
const {
  NPC_BUFF_UPDATE_NUM_COUNTER_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeNpcBuffUpdateNumCounterPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_buff_update_num_counter_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const PAYLOAD = Buffer.from('1d438b48370f35', 'hex');

function packet(packetId = 0x0194, rawParam = 0x400000ae, payload = PAYLOAD) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replayWithChunks(chunks, build = BUILD) {
  return replayFromChunks(chunks.map(({ stream = 1, packets }) => ({
    stream, body: Buffer.concat(packets),
  })), build);
}

function fakeImage(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-buff-update-num-'));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  t.after(() => { fs.unlinkSync(image); fs.rmdirSync(directory); });
  return image;
}

function nativeResult(request) {
  return {
    status: 'PASS',
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
    callback_table_sha256: profile.evidence_callback_table_sha256,
    results: request.packets.map((input, inputIndex) => ({
      status: 'DECODED', input_index: inputIndex,
      raw_param: input.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: input.payload_hex.length / 2,
      native_packet_id: 0x0194, native_raw_param: input.raw_param,
      opaque_u8_0x10: 1, opaque_u32_0x14: 95298804,
      opaque_u8_0x18: 13, opaque_u32_0x1c: inputIndex === 0 ? 0 : 3,
      raw_u8_0x10_hex: '72', raw_u32_0x14_hex: '8b5d4e6b',
      raw_u8_0x18_hex: '35',
      raw_u32_0x1c_hex: inputIndex === 0 ? '64646464' : '58646464',
    })),
  };
}

test('821 BuffUpdateNumCounter exposes anonymous packet fields with source-bound shared scan', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([
    { packets: [packet()] },
    { packets: [packet(0x0194, 0x400000b4, Buffer.alloc(9))] },
  ]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_buff_update_num_counter_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag]),
      [[0x0194, 1], [0x0194, 1]]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const token = collect821Routes(replay, ['npc_buff_update_num_counter_packet']);
  const result = decode(replay, { runtimeImagePath: image, precollected: token });
  assert.equal(profile.packet_name, 'PKT_NPC_BuffUpdateNumCounter_s');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].event_type, 'NPC_BUFF_UPDATE_NUM_COUNTER_PACKET_CANDIDATE');
  assert.equal(result.events[0].opaque_u32_0x14, 95298804);
  assert.equal(result.events[1].opaque_u32_0x1c, 3);
  assert.equal(result.events[0].raw_object_u8_0x10_hex, '72');
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[1].raw_packet_ref.raw_param, 0x400000b4);
  for (const field of ['owner', 'buff_identity', 'target', 'counter', 'duration']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 BuffUpdateNumCounter separates absent, missing-input and unsupported build', () => {
  assert.equal(decode(replayWithChunks([{ packets: [packet()] }], '16.19.820.7193')).status,
    'UNSUPPORTED');
  assert.equal(decode(replayWithChunks([{ packets: [packet(0x01da)] }])).status,
    'PROFILE_UNAVAILABLE');
  const missing = decode(replayWithChunks([{ packets: [packet()] }]));
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.input_count, 1);
});

test('821 BuffUpdateNumCounter rejects altered source and foreign stream or length', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('native decoder should not be invoked');
  });
  const mutated = replayWithChunks([{ packets: [packet()] }]);
  mutated.buffer[0] ^= 1;
  assert.match(decode(mutated).error, /source integrity/);
  assert.equal(decode(replayWithChunks([{ packets: [packet(0x0194, 0x400000ae,
    Buffer.alloc(5))] }])).status, 'DECODE_FAILED');
  assert.equal(decode(replayWithChunks([{ stream: 2, packets: [packet()] }])).status,
    'DECODE_FAILED');
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 BuffUpdateNumCounter rejects wrong image, incomplete native output and digest drift', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'runtime image SHA-256 mismatch: wrong image', stdout: '',
  }));
  const wrong = decode(replay, { runtimeImagePath: image });
  assert.equal(wrong.status, 'DECODE_FAILED');
  assert.equal(wrong.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(wrong.events, null);
  invoke.mock.restore();
  const partial = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    result.results[0].bytes_consumed -= 1;
    return { status: 0, stdout: JSON.stringify(result) };
  });
  const incomplete = decode(replay, { runtimeImagePath: image });
  assert.equal(incomplete.status, 'DECODE_FAILED');
  assert.equal(incomplete.first_failed_packet_ref.packet_id, 0x0194);
  assert.equal(incomplete.events, null);
  partial.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    result.callback_table_sha256 = {
      ...result.callback_table_sha256, opaque_u32_0x14: '0'.repeat(64),
    };
    return { status: 0, stdout: JSON.stringify(result) };
  });
  const drift = decode(replay, { runtimeImagePath: image });
  assert.equal(drift.status, 'DECODE_FAILED');
  assert.equal(drift.events, null);
});

test('821 BuffUpdateNumCounter bounds direct and shared retention at 25,000 packets', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('native decoder should not be invoked');
  });
  const replay = replayWithChunks([{ packets: Array.from({ length: 25_001 }, () => packet()) }]);
  const direct = decode(replay);
  assert.equal(direct.status, 'UNSUPPORTED');
  assert.equal(direct.observed_packet_count_minimum, 25_001);
  const token = collect821Routes(replay, ['npc_buff_update_num_counter_packet']);
  const shared = decode(replay, { precollected: token });
  assert.equal(shared.status, 'UNSUPPORTED');
  assert.equal(shared.observed_packet_count_minimum, 25_001);
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 BuffUpdateNumCounter exact image decodes a pinned real packet', {
  skip: !fs.existsSync(IMAGE),
}, () => {
  const request = JSON.stringify({
    replay_version: BUILD,
    packets: [PAYLOAD, PAYLOAD.subarray(0, -1), Buffer.concat([PAYLOAD, Buffer.from([0xa5])])]
      .map((payload) => ({ packet_id: 0x0194, stream_tag: 1, raw_param: 0x400000ae,
        payload_hex: payload.toString('hex') })),
  });
  const run = childProcess.spawnSync(process.env.PYTHON || 'python', [
    '-B', path.resolve(__dirname, '..', 'scripts',
      'decode_buff_update_num_counter_packet_16_19_821.py'), '--image', IMAGE,
  ], { input: request, encoding: 'utf8', timeout: 60000 });
  assert.equal(run.status, 0, run.stderr);
  const [row, truncated, appended] = JSON.parse(run.stdout).results;
  assert.equal(row.status, 'DECODED');
  assert.equal(row.bytes_consumed, PAYLOAD.length);
  assert.equal(row.opaque_u8_0x10, 1);
  assert.equal(row.opaque_u32_0x14, 95298804);
  assert.equal(row.opaque_u8_0x18, 13);
  assert.equal(row.opaque_u32_0x1c, 0);
  assert.equal(truncated.status, 'FAILED');
  assert.equal(truncated.deserialize_return_al, 0);
  assert.equal(appended.status, 'FAILED');
  assert.equal(appended.bytes_consumed, PAYLOAD.length);
});
