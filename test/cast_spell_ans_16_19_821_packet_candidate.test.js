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
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeCastSpellAnsPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_cast_spell_ans_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';
const PAYLOAD = Buffer.concat([Buffer.from([0x15]), Buffer.alloc(128)]);

function packet(packetId = 0x01da, rawParam = 0x400000ae, payload = PAYLOAD) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-cast-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request, values = []) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    callback_table_sha256: TABLE_SHA256,
    results: request.packets.map((input, inputIndex) => ({
      status: 'DECODED', input_index: inputIndex,
      raw_param: input.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: input.payload_hex.length / 2,
      native_packet_id: 0x01da, native_raw_param: input.raw_param,
      raw_flag_byte_hex: values[inputIndex]?.flag === 1 ? '4d' : 'fc',
      opaque_flag_0x148: values[inputIndex]?.flag ?? 0,
      raw_i32_bytes_hex: values[inputIndex]?.i32 ? '78e89bbb' : 'bbbbbbbb',
      opaque_i32_0x14c: values[inputIndex]?.i32 ?? 0,
    })),
  };
}

test('821 CastSpellAns candidate exposes only provenance and opaque packet fields', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([
    { stream: 1, packets: [packet()] },
    { stream: 2, packets: [packet(0x01da, 0x4000023c)] },
  ]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_cast_spell_ans_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => row.raw_param),
      [0x400000ae, 0x4000023c]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request, [
      { flag: 1 }, { i32: 80444 },
    ])) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(profile.packet_name, 'PKT_NPC_CastSpellAns_s');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].opaque_flag_0x148, 1);
  assert.equal(result.events[1].opaque_i32_0x14c, 80444);
  assert.equal(result.events[1].raw_packet_ref.chunk_stream, 'keyframe');
  assert.equal(result.events[1].raw_packet_ref.raw_param, 0x4000023c);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal('spell_slot' in result.events[0], false);
  assert.equal('owner' in result.events[0], false);
  assert.equal('target' in result.events[0], false);
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 CastSpellAns requires exact Replay build and leaves absent route unavailable', () => {
  const older = replayWithChunks([{ packets: [packet()] }], '16.19.820.7193');
  assert.equal(decode(older).status, 'UNSUPPORTED');
  const absent = replayWithChunks([{ packets: [packet(0x018d)] }]);
  assert.equal(decode(absent).status, 'PROFILE_UNAVAILABLE');
  const present = replayWithChunks([{ packets: [packet()] }]);
  const missing = decode(present);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
});

test('821 CastSpellAns rejects changed Replay source and observed-scope shape errors before runtime', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime should not be invoked');
  });
  const mutated = replayWithChunks([{ packets: [packet()] }]);
  mutated.buffer[0] ^= 1;
  assert.match(decode(mutated).error, /source integrity/);
  const short = replayWithChunks([{ packets: [packet(0x01da, 0x400000ae,
    Buffer.concat([Buffer.from([0x15]), Buffer.alloc(95)]))] }]);
  assert.equal(decode(short).status, 'DECODE_FAILED');
  const wrongSelector = replayWithChunks([{ packets: [packet(0x01da, 0x400000ae,
    Buffer.concat([Buffer.from([0xff]), Buffer.alloc(128)]))] }]);
  assert.equal(decode(wrongSelector).status, 'DECODE_FAILED');
  const wrongStream = replayWithChunks([{ stream: 3, packets: [packet()] }]);
  assert.equal(decode(wrongStream).status, 'DECODE_FAILED');
  const mixedStream = replayWithChunks([
    { stream: 1, packets: [packet()] },
    { stream: 3, packets: [packet()] },
  ]);
  const mixed = decode(mixedStream);
  assert.equal(mixed.status, 'DECODE_FAILED');
  assert.equal(mixed.events, null);
  const collected = collect821Routes(mixedStream, ['cast_spell_ans_packet']);
  const shared = decode(mixedStream, { precollected: collected });
  assert.equal(shared.status, 'DECODE_FAILED');
  assert.equal(shared.events, null);
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 CastSpellAns reports wrong image identity without candidate events', (t) => {
  const image = fakeImage(t);
  t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'runtime image SHA-256 mismatch: old image', stdout: '',
  }));
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(result.runtime_image_used, false);
  assert.equal(result.event_count, null);
  assert.equal(result.events, null);
});

test('821 CastSpellAns rejects incomplete native consumption and invalid field shape', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const first = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].bytes_consumed -= 1;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const truncated = decode(replay, { runtimeImagePath: image });
  assert.equal(truncated.status, 'DECODE_FAILED');
  assert.equal(truncated.runtime_image_status, 'MATCHED_USED');
  assert.equal(truncated.first_failed_packet_ref.packet_id, 0x01da);
  assert.equal(truncated.events, null);
  first.mock.restore();
  const second = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].opaque_flag_0x148 = 2;
    output.results[0].opaque_i32_0x14c = 0x80000000;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const invalid = decode(replay, { runtimeImagePath: image });
  assert.equal(invalid.status, 'DECODE_FAILED');
  assert.equal(invalid.events, null);
  assert.equal(second.mock.callCount(), 1);
});

test('821 CastSpellAns discards earlier batch events when a later native batch fails', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: Array.from({ length: 8193 }, () => packet()) }]);
  let calls = 0;
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    calls += 1;
    if (calls === 1) {
      const request = JSON.parse(options.input);
      assert.equal(request.packets.length, 8192);
      return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
    }
    assert.equal(JSON.parse(options.input).packets.length, 1);
    return { status: 1, stderr: 'native failure in second batch', stdout: '' };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(calls, 2);
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.input_count, 8193);
  assert.equal(result.runtime_image_used, true);
  assert.equal(result.event_count, null);
  assert.equal(result.events, null);
});
