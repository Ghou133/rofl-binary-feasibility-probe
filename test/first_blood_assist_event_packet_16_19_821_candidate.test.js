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
  FIRST_BLOOD_ASSIST_EVENT_PACKET_821_PROFILE: profile,
  decodeFirstBloodAssistEventPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_first_blood_assist_event_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const TARGET = Buffer.from('d4bdb9b33db3b3b3b37f32eb01e94de4', 'hex');
const FOREIGN = Buffer.from('c0bdb94b3db3b3b3b37f32eb01e94dca', 'hex');

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packet(payload, rawParam = 0x400000b5, packetId = 0x040a) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replay(chunks, build = BUILD) {
  return replayFromChunks(chunks.map(({ stream = 1, packets }) => ({
    stream, body: Buffer.concat(packets),
  })), build);
}

function image(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-first-blood-assist-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'image.bin');
  fs.writeFileSync(file, Buffer.from([1, 2, 3]));
  return file;
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => {
      const target = row.payload_hex === TARGET.toString('hex');
      const blob = Buffer.from(target ? 'd501000000000000' : 'd5010000b6000040', 'hex');
      return {
        status: target ? 'DECODED' : 'EXCLUDED_CHILD',
        input_index: index, raw_param: row.raw_param,
        raw_payload_sha256: sha256(Buffer.from(row.payload_hex, 'hex')),
        deserialize_return_al: 1, bytes_consumed: 16,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: target ? 0x0017 : 0x002c,
        raw_event_id_hex: target ? '0x49e4' : '0x49ca',
        event_blob_length: 8, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: sha256(blob),
      };
    }),
  };
}

test('821 first-blood-assist marker retains only native child 0x0017 and source refs', (t) => {
  const imagePath = image(t);
  const input = replay([{ packets: [
    packet(TARGET), packet(FOREIGN, 0x400000b6), packet(Buffer.alloc(20)),
  ] }]);
  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_first_blood_assist_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => row.payload_hex),
      [TARGET.toString('hex'), FOREIGN.toString('hex')]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const result = decode(input, { runtimeImagePath: imagePath });
  assert.equal(profile.child_event_name, 'OnFirstBloodAssist');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.target_packet_count, 1);
  assert.equal(result.excluded_same_length_foreign_count, 1);
  assert.equal(result.excluded_same_length_foreign_packet_refs[0].raw_payload_sha256,
    sha256(FOREIGN));
  assert.equal(result.event_count, 1);
  assert.equal(result.events[0].registered_event_name, 'OnFirstBloodAssist');
  assert.equal(result.events[0].raw_event_id_hex, '0x49e4');
  assert.equal(result.events[0].event_blob_hex, 'd501000000000000');
  assert.equal(result.events[0].raw_packet_ref.raw_payload_sha256, sha256(TARGET));
  for (const field of ['assistant_participant_id', 'first_blood', 'actor', 'effect']) {
    assert.equal(Object.hasOwn(result.events[0], field), false);
  }
  assert.equal(native.mock.callCount(), 1);
});

test('821 first-blood-assist marker preserves unavailable and missing-input states', (t) => {
  const imagePath = image(t);
  const foreign = replay([{ packets: [packet(FOREIGN)] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => ({
    status: 0, stderr: '', stdout: JSON.stringify(nativeResult(JSON.parse(options.input))),
  }));
  const absent = decode(foreign, { runtimeImagePath: imagePath });
  assert.equal(absent.status, 'PROFILE_UNAVAILABLE');
  assert.equal(absent.target_packet_count, 0);
  assert.equal(absent.excluded_same_length_foreign_count, 1);
  assert.equal(absent.events, null);
  const present = replay([{ packets: [packet(TARGET)] }]);
  assert.equal(decode(present).status, 'MISSING_INPUT');
  assert.equal(decode(replay([{ packets: [packet(TARGET)] }], '16.19.820.7193')).status,
    'UNSUPPORTED');
  present.buffer[0] ^= 1;
  assert.match(decode(present).error, /source integrity/);
  const keyframeOnly = replay([{ stream: 2, packets: [packet(TARGET)] }]);
  assert.equal(decode(keyframeOnly, { runtimeImagePath: imagePath }).status,
    'PROFILE_UNAVAILABLE');
});

test('821 first-blood-assist marker rejects partial, foreign, and forged native output', (t) => {
  const imagePath = image(t);
  const input = replay([{ packets: [packet(TARGET), packet(FOREIGN)] }]);
  let mode = 'partial';
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    if (mode === 'partial') output.results[0].bytes_consumed = 15;
    if (mode === 'foreign') output.results[0].event_id = 0x002c;
    if (mode === 'hash') output.results[1].event_blob_sha256 = '0'.repeat(64);
    if (mode === 'unknown') output.results[1].event_id = 0x0117;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  for (mode of ['partial', 'foreign', 'hash', 'unknown']) {
    const failed = decode(input, { runtimeImagePath: imagePath });
    assert.equal(failed.status, 'DECODE_FAILED', mode);
    assert.equal(failed.events, null, mode);
    assert.equal(failed.event_count, null, mode);
    assert.equal(failed.first_failed_packet_ref.packet_id, 0x040a);
  }
});

test('821 first-blood-assist marker reports wrong pinned image separately', (t) => {
  const imagePath = image(t);
  const input = replay([{ packets: [packet(TARGET)] }]);
  t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'runtime image SHA-256 mismatch', stdout: '',
  }));
  const result = decode(input, { runtimeImagePath: imagePath });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.runtime_image_status, 'HASH_MISMATCH');
});
