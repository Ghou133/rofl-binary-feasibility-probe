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
  NPC_BUFF_REPLACE_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeNpcBuffReplacePacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_buff_replace_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
// KR_8392938200.rofl SHA-256 d3a93326b3420ac0e2d0f077eef70b9b6413a9eb4b3e09f69056902ec2d11a8e:
// game stream, chunk 9, Replay time 131763 ms, raw param 0x400000ae.
const PAYLOAD = Buffer.from('a3647f7575b3f0a6f9', 'hex');

function packet(packetId = 0x01ad, rawParam = 0x400000ae, payload = PAYLOAD) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-buff-replace-'));
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
    results: request.packets.map((input, index) => ({
      status: 'DECODED', input_index: index,
      raw_param: input.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: input.payload_hex.length / 2,
      native_packet_id: 0x01ad, native_raw_param: input.raw_param,
      opaque_u8_0x10: 21, opaque_f32_0x14: 0.25,
      opaque_u32_0x18: 0x400000ae, opaque_f32_0x1c: 0,
      raw_u8_0x10_hex: '7f', raw_f32_0x14_hex: '7575b3f0',
      raw_u32_0x18_hex: 'a6fbfb7b', raw_f32_0x1c_hex: '64646464',
    })),
  };
}

test('821 BuffReplace exposes anonymous packet fields through source-bound shared scan', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([
    { packets: [packet()] },
    { packets: [packet(0x02d9), packet(0x01ad, 0x40000284,
      Buffer.from('666f75052dec87f9', 'hex'))] },
  ]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_buff_replace_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag]),
      [[0x01ad, 1], [0x01ad, 1]]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const token = collect821Routes(replay, ['npc_buff_replace_packet']);
  const result = decode(replay, { runtimeImagePath: image, precollected: token });
  assert.equal(profile.packet_name, 'PKT_NPC_BuffReplace_s');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].event_type, 'NPC_BUFF_REPLACE_PACKET_CANDIDATE');
  assert.equal(result.events[0].opaque_u8_0x10, 21);
  assert.equal(result.events[0].opaque_f32_0x14, 0.25);
  assert.equal(result.events[0].opaque_u32_0x18, 0x400000ae);
  assert.equal(result.events[0].opaque_f32_0x1c, 0);
  assert.equal(result.events[0].raw_object_u32_0x18_hex, 'a6fbfb7b');
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[1].raw_packet_ref.raw_param, 0x40000284);
  for (const field of ['owner', 'buff_identity', 'target', 'effect', 'replacement']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 BuffReplace separates absent, missing input, and unsupported build', () => {
  assert.equal(decode(replayWithChunks([{ packets: [packet()] }], '16.19.820.7193')).status,
    'UNSUPPORTED');
  assert.equal(decode(replayWithChunks([{ packets: [packet(0x02d9)] }])).status,
    'PROFILE_UNAVAILABLE');
  const missing = decode(replayWithChunks([{ packets: [packet()] }]));
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.input_count, 1);
});

test('821 BuffReplace rejects altered source and foreign stream or packet shape', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('native decoder should not be invoked');
  });
  const mutated = replayWithChunks([{ packets: [packet()] }]);
  mutated.buffer[0] ^= 1;
  assert.match(decode(mutated).error, /source integrity/);
  assert.equal(decode(replayWithChunks([{ packets: [packet(0x01ad, 0x400000ae,
    Buffer.alloc(7))] }])).status, 'DECODE_FAILED');
  assert.equal(decode(replayWithChunks([{ stream: 2, packets: [packet()] }])).status,
    'DECODE_FAILED');
  const source = replayWithChunks([{ packets: [packet()] }]);
  const token = collect821Routes(source, ['npc_buff_replace_packet']);
  const unrelated = replayWithChunks([{ packets: [packet()] }]);
  assert.equal(decode(unrelated, { precollected: token }).status, 'DECODE_FAILED');
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 BuffReplace rejects wrong image, incomplete native output, and transform drift', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const wrongInvoke = t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'runtime image SHA-256 mismatch: wrong image', stdout: '',
  }));
  const wrong = decode(replay, { runtimeImagePath: image });
  assert.equal(wrong.status, 'DECODE_FAILED');
  assert.equal(wrong.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(wrong.events, null);
  wrongInvoke.mock.restore();
  const partialInvoke = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    result.results[0].bytes_consumed -= 1;
    return { status: 0, stdout: JSON.stringify(result) };
  });
  const partial = decode(replay, { runtimeImagePath: image });
  assert.equal(partial.status, 'DECODE_FAILED');
  assert.equal(partial.first_failed_packet_ref.packet_id, 0x01ad);
  assert.equal(partial.events, null);
  partialInvoke.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    result.callback_table_sha256 = {
      ...result.callback_table_sha256, opaque_u32_0x18: '0'.repeat(64),
    };
    return { status: 0, stdout: JSON.stringify(result) };
  });
  const drift = decode(replay, { runtimeImagePath: image });
  assert.equal(drift.status, 'DECODE_FAILED');
  assert.equal(drift.events, null);
});

test('821 BuffReplace bounds direct and shared retention at 10,000 packets', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('native decoder should not be invoked');
  });
  const replay = replayWithChunks([{ packets: Array.from({ length: 10_001 }, () => packet()) }]);
  const direct = decode(replay);
  assert.equal(direct.status, 'UNSUPPORTED');
  assert.equal(direct.observed_packet_count_minimum, 10_001);
  const token = collect821Routes(replay, ['npc_buff_replace_packet']);
  const shared = decode(replay, { precollected: token });
  assert.equal(shared.status, 'UNSUPPORTED');
  assert.equal(shared.observed_packet_count_minimum, 10_001);
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 BuffReplace exact image decodes a pinned real packet and rejects controls', {
  skip: !fs.existsSync(IMAGE),
}, () => {
  const request = JSON.stringify({
    replay_version: BUILD,
    packets: [PAYLOAD, PAYLOAD.subarray(0, -1), Buffer.concat([PAYLOAD, Buffer.from([0xa5])])]
      .map((payload) => ({ packet_id: 0x01ad, stream_tag: 1, raw_param: 0x400000ae,
        payload_hex: payload.toString('hex') }))
      .concat([0x00ae, 0x0194, 0x02d9, 0x047c].map((packetId) => ({
        packet_id: packetId, stream_tag: 1, raw_param: 0x400000ae,
        payload_hex: PAYLOAD.toString('hex'),
      }))),
  });
  const run = childProcess.spawnSync(process.env.PYTHON || 'python', [
    '-B', path.resolve(__dirname, '..', 'scripts',
      'decode_buff_replace_packet_16_19_821.py'), '--image', IMAGE,
  ], { input: request, encoding: 'utf8', timeout: 60000 });
  assert.equal(run.status, 0, run.stderr);
  const [row, truncated, appended, ...foreign] = JSON.parse(run.stdout).results;
  assert.equal(row.status, 'DECODED');
  assert.equal(row.bytes_consumed, PAYLOAD.length);
  assert.equal(row.opaque_u8_0x10, 21);
  assert.equal(row.opaque_f32_0x14, 0.25);
  assert.equal(row.opaque_u32_0x18, 0x400000ae);
  assert.equal(row.opaque_f32_0x1c, 0);
  assert.equal(truncated.status, 'FAILED');
  assert.equal(truncated.deserialize_return_al, 0);
  assert.equal(appended.status, 'FAILED');
  assert.equal(appended.deserialize_return_al, 1);
  assert.equal(appended.bytes_consumed, PAYLOAD.length);
  assert.equal(foreign.length, 4);
  foreign.forEach((control) => {
    assert.equal(control.status, 'FAILED');
    assert.match(control.error, /packet ID/);
  });
});
