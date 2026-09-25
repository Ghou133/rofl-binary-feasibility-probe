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
  TURRET_DIE_EVENT_PACKET_821_PROFILE: profile,
  decodeTurretDieEventPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_turret_die_event_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const FOREIGN_SUFFIXES = ['247152269548', '247152269506',
  '247152269586', '247152269518'];

function shapedPayload(suffix = '247152269566') {
  const payload = Buffer.alloc(116, 0xb3);
  Buffer.from('f01eb9b33d', 'hex').copy(payload, 0);
  Buffer.from(suffix, 'hex').copy(payload, 110);
  return payload;
}

function packet(packetId = 0x040a, rawParam = 0x4000008c, payload = shapedPayload()) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-turret-die-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => {
      const blob = Buffer.alloc(108);
      blob.writeUInt32LE(0x1d5, 0);
      blob.writeUInt32LE(0x400000b3 + index, 4);
      blob[100] = 0xff;
      return {
        status: 'DECODED', input_index: index,
        raw_param: row.raw_param,
        raw_payload_sha256: sha256(Buffer.from(row.payload_hex, 'hex')),
        deserialize_return_al: 1, bytes_consumed: 116,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: 0x003b, raw_event_id_hex: '0x4966',
        event_blob_length: 108, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: sha256(blob),
      };
    }),
  };
}

test('821 OnTurretDie selects native checked target and preserves four foreign refs', (t) => {
  const image = fakeImage(t);
  const target = shapedPayload();
  const foreign = FOREIGN_SUFFIXES.map(shapedPayload);
  const replay = replayWithChunks([{ packets: [packet(),
    ...foreign.map((payload) => packet(0x040a, 0x4000008d, payload)),
    packet(0x040a, 0x4000008c, Buffer.alloc(20)),
  ] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_turret_die_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag,
      row.payload_hex.length / 2]), [[0x040a, 1, 116]]);
    assert.deepEqual(request.packets.map((row) => row.payload_hex),
      [target.toString('hex')]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(profile.child_event_name, 'OnTurretDie');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 1);
  assert.equal(result.event_count, 1);
  assert.equal(result.observed_same_length_packet_count, 5);
  assert.equal(result.excluded_same_length_foreign_count, 4);
  assert.deepEqual(result.excluded_same_length_foreign_packet_refs.map((ref) =>
    ref.raw_payload_sha256), foreign.map(sha256));
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].event_type, 'TURRET_DIE_EVENT_PACKET_CANDIDATE');
  assert.equal(result.events[0].event_id, 0x003b);
  assert.equal(result.events[0].event_name, 'OnTurretDie');
  assert.equal(result.events[0].event_blob_hex.length, 216);
  assert.equal(result.events[0].event_blob_sha256,
    sha256(Buffer.from(result.events[0].event_blob_hex, 'hex')));
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[0].raw_packet_ref.raw_payload_sha256, sha256(target));
  for (const field of ['turret_destroyed', 'actor', 'target', 'effective_death']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 OnTurretDie reports absent shape, missing image, wrong build, and corrupt Replay', () => {
  const absent = replayWithChunks([{ packets: [packet(0x040a, 0x4000008d,
    shapedPayload(FOREIGN_SUFFIXES[0]))] }]);
  const unavailable = decode(absent);
  assert.equal(unavailable.status, 'PROFILE_UNAVAILABLE');
  assert.equal(unavailable.event_count, null);
  assert.equal(unavailable.observed_same_length_packet_count, 1);
  assert.equal(unavailable.excluded_same_length_foreign_count, 1);
  const present = replayWithChunks([{ packets: [packet()] }]);
  const missing = decode(present);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.input_count, 1);
  assert.equal(decode(replayWithChunks([{ packets: [packet()] }],
    '16.19.820.7193')).status, 'UNSUPPORTED');
  present.buffer[0] ^= 1;
  const corrupt = decode(present);
  assert.equal(corrupt.status, 'DECODE_FAILED');
  assert.match(corrupt.error, /source integrity/);
});

test('821 OnTurretDie rejects foreign stream, unknown length-116 shape, and wrong image', (t) => {
  const image = fakeImage(t);
  const foreignStream = replayWithChunks([{ stream: 2, packets: [packet()] }]);
  assert.equal(decode(foreignStream, { runtimeImagePath: image }).status, 'DECODE_FAILED');
  const unknown = replayWithChunks([{ packets: [packet(),
    packet(0x040a, 0x4000008d, Buffer.alloc(116, 0x99))] }]);
  const unknownResult = decode(unknown, { runtimeImagePath: image });
  assert.equal(unknownResult.status, 'DECODE_FAILED');
  assert.match(unknownResult.error, /unrecognized.*fingerprint/i);
  assert.equal(unknownResult.events, null);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'OnTurretDie runtime image SHA-256 mismatch: bad', stdout: '',
  }));
  const failed = decode(replay, { runtimeImagePath: image });
  assert.equal(failed.status, 'DECODE_FAILED');
  assert.equal(failed.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(failed.events, null);
});

test('821 OnTurretDie rejects native child, partial decode, and altered blob atomically', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet(), packet()] }]);
  let failure = 'foreign_id';
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    if (failure === 'foreign_id') result.results[1].event_id = 0x0035;
    if (failure === 'raw_id') result.results[1].raw_event_id_hex = '0x4958';
    if (failure === 'partial') result.results[1].bytes_consumed = 115;
    if (failure === 'length') result.results[1].event_blob_length = 107;
    if (failure === 'hash') result.results[1].event_blob_sha256 = '0'.repeat(64);
    return { status: 0, stderr: '', stdout: JSON.stringify(result) };
  });
  for (const mode of ['foreign_id', 'raw_id', 'partial', 'length', 'hash']) {
    failure = mode;
    const failed = decode(replay, { runtimeImagePath: image });
    assert.equal(failed.status, 'DECODE_FAILED', mode);
    assert.equal(failed.event_count, null, mode);
    assert.equal(failed.events, null, mode);
    assert.equal(failed.first_failed_packet_ref.packet_id, 0x040a);
  }
});
