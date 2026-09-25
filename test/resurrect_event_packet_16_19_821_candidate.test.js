'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  RESURRECT_EVENT_PACKET_821_PROFILE: profile,
  decodeResurrectEventPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_resurrect_event_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(packetId = 0x040a, rawParam = 0x400000ae,
  payload = Buffer.alloc(20, 0x4a)) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-resurrect-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => {
      const blob = Buffer.alloc(12);
      blob.writeUInt32LE(45, 0);
      blob.writeUInt32LE(0x400000b4 + index, 4);
      blob.writeUInt32LE(0x400000af + index, 8);
      return {
        status: 'DECODED', input_index: index,
        raw_param: row.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 1, bytes_consumed: 20,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: 0x002d, raw_event_id_hex: '0x498a',
        event_blob_length: 12, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: crypto.createHash('sha256').update(blob).digest('hex'),
        event_schema_u32_0x00: 45,
        event_u32_0x04: 0x400000b4 + index,
        event_u32_0x08: 0x400000af + index,
      };
    }),
  };
}

test('821 OnResurrect emits only length-20 game packet candidates with raw refs', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [
    packet(), packet(0x040a, 0x400000af, Buffer.alloc(16)),
    packet(0x040a, 0x400000b0),
  ] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_resurrect_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag,
      row.payload_hex.length / 2]), [
      [0x040a, 1, 20], [0x040a, 1, 20],
    ]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(profile.child_event_name, 'OnResurrect');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.deepEqual(result.events.map((row) => row.event_u32_0x04),
    [0x400000b4, 0x400000b5]);
  assert.deepEqual(result.events.map((row) => row.event_u32_0x08),
    [0x400000af, 0x400000b0]);
  assert.equal(result.events[0].event_type, 'RESURRECT_EVENT_PACKET_CANDIDATE');
  assert.equal(result.events[0].event_id, 0x002d);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[0].raw_packet_ref.payload_length, 20);
  for (const field of ['resurrected', 'caster', 'target', 'effective_resurrection']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 OnResurrect distinguishes absent shape, missing image, wrong build, and corrupt Replay', () => {
  const absent = replayWithChunks([{ packets: [packet(0x040a, 0x400000ae,
    Buffer.alloc(16))] }]);
  assert.equal(decode(absent).status, 'PROFILE_UNAVAILABLE');
  const present = replayWithChunks([{ packets: [packet()] }]);
  const missing = decode(present);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.input_count, 1);
  const wrongBuild = replayWithChunks([{ packets: [packet()] }], '16.19.820.7193');
  assert.equal(decode(wrongBuild).status, 'UNSUPPORTED');
  const mutated = replayWithChunks([{ packets: [packet()] }]);
  mutated.buffer[0] ^= 1;
  const failed = decode(mutated);
  assert.equal(failed.status, 'DECODE_FAILED');
  assert.match(failed.error, /source integrity/);
});

test('821 OnResurrect rejects foreign stream and wrong image digest', (t) => {
  const image = fakeImage(t);
  const foreign = replayWithChunks([{ stream: 2, packets: [packet()] }]);
  assert.equal(decode(foreign, { runtimeImagePath: image }).status, 'DECODE_FAILED');
  const replay = replayWithChunks([{ packets: [packet()] }]);
  t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'OnResurrect runtime image SHA-256 mismatch: bad', stdout: '',
  }));
  const failed = decode(replay, { runtimeImagePath: image });
  assert.equal(failed.status, 'DECODE_FAILED');
  assert.equal(failed.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(failed.events, null);
});

test('821 OnResurrect binds native ID and both u32 fields to returned bytes atomically', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet(), packet()] }]);
  let failure = 'foreign_id';
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    if (failure === 'foreign_id') result.results[1].event_id = 0x002c;
    if (failure === 'field') result.results[1].event_u32_0x08 += 1;
    if (failure === 'hash') result.results[1].event_blob_sha256 = '0'.repeat(64);
    return { status: 0, stderr: '', stdout: JSON.stringify(result) };
  });
  for (const mode of ['foreign_id', 'field', 'hash']) {
    failure = mode;
    const failed = decode(replay, { runtimeImagePath: image });
    assert.equal(failed.status, 'DECODE_FAILED', mode);
    assert.equal(failed.event_count, null, mode);
    assert.equal(failed.events, null, mode);
    assert.equal(failed.first_failed_packet_ref.packet_id, 0x040a);
  }
});
