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
  ON_SHUTDOWN_EVENT_PACKET_821_PROFILE: profile,
  decodeOnShutdownEventPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_on_shutdown_event_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(packetId = 0x040a, rawParam = 0x400000ae, payload = Buffer.alloc(105, 0x4a)) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-on-shutdown-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => {
      const blob = Buffer.alloc(96);
      blob.writeUInt32LE(0x400000b4, 0x04);
      blob.writeUInt32LE(63, 0x58);
      blob.writeUInt32LE(0xe3f7fb9c, 0x5c);
      return {
        status: 'DECODED',
        input_index: index, raw_param: row.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 1, bytes_consumed: 105,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: 0x00e8, raw_event_id_hex: '0x49af',
        event_blob_length: 96, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: crypto.createHash('sha256').update(blob).digest('hex'),
        event_u32_0x04: 0x400000b4,
        event_u32_0x58: 63,
        event_u32_0x5c: 0xe3f7fb9c,
      };
    }),
  };
}

test('821 OnShutdown selects only the observed length-105 game-stream child', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [
    packet(), packet(0x040a, 0x400000b2, Buffer.alloc(104)),
  ] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_on_shutdown_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag,
      row.payload_hex.length / 2]), [[0x040a, 1, 105]]);
    return { status: 0, stderr: '',
      stdout: JSON.stringify(nativeResult(request)) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(profile.registered_event_name, 'OnShutdown');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 1);
  assert.equal(result.target_packet_count, 1);
  assert.equal(result.excluded_child_count, 0);
  assert.deepEqual(result.excluded_child_ids, {});
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].event_type, 'ON_SHUTDOWN_EVENT_PACKET_CANDIDATE');
  assert.equal(result.events[0].registered_event_name, 'OnShutdown');
  assert.equal(result.events[0].child_event_id, 0x00e8);
  assert.equal(result.events[0].raw_event_id_hex, '0x49af');
  assert.equal(result.events[0].event_u32_0x04, 0x400000b4);
  assert.equal(result.events[0].event_u32_0x58, 63);
  assert.equal(result.events[0].event_u32_0x5c, 0xe3f7fb9c);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  for (const field of ['killer', 'victim', 'source', 'target', 'shutdown_effect']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 OnShutdown distinguishes absent shape, missing image, wrong build, and source corruption', () => {
  const absent = replayWithChunks([{ packets: [packet(0x040a, 0x400000ae,
    Buffer.alloc(60))] }]);
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
  assert.equal(decode(mutated).status, 'DECODE_FAILED');
  assert.match(decode(mutated).error, /source integrity/);
});

test('821 OnShutdown rejects foreign stream and unknown native child', (t) => {
  const image = fakeImage(t);
  const foreign = replayWithChunks([{ stream: 2, packets: [packet()] }]);
  assert.equal(decode(foreign, { runtimeImagePath: image }).status, 'DECODE_FAILED');
  const replay = replayWithChunks([{ packets: [packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    const output = nativeResult(request);
    output.results[0].event_id = 0x0007;
    return { status: 0, stderr: '',
      stdout: JSON.stringify(output) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.events, null);
  assert.equal(result.first_failed_packet_ref.packet_id, 0x040a);
});

test('821 OnShutdown rejects a mismatched raw child ID and incomplete native consumption', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  let tamper = 'raw_event_id_hex';
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    const output = nativeResult(request);
    if (tamper === 'raw_event_id_hex') output.results[0].raw_event_id_hex = '0x49e8';
    if (tamper === 'bytes_consumed') output.results[0].bytes_consumed = 104;
    return { status: 0, stderr: '',
      stdout: JSON.stringify(output) };
  });
  for (const field of ['raw_event_id_hex', 'bytes_consumed']) {
    tamper = field;
    const result = decode(replay, { runtimeImagePath: image });
    assert.equal(result.status, 'DECODE_FAILED', field);
    assert.equal(result.events, null, field);
  }
});

test('821 OnShutdown reports wrong image and missing Unicorn distinctly', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  let detail = 'OnShutdown runtime image SHA-256 mismatch: bad';
  t.mock.method(childProcess, 'spawnSync', () => ({ status: 1, stderr: detail, stdout: '' }));
  const mismatch = decode(replay, { runtimeImagePath: image });
  assert.equal(mismatch.status, 'DECODE_FAILED');
  assert.equal(mismatch.runtime_image_status, 'HASH_MISMATCH');
  detail = "ModuleNotFoundError: No module named 'unicorn'";
  const missing = decode(replay, { runtimeImagePath: image });
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'python_unicorn');
});

test('821 OnShutdown rejects tampered native blob hash and anonymous fields', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  let tamper = 'event_u32_0x04';
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    const output = nativeResult(request);
    if (tamper === 'event_blob_sha256') {
      output.results[0].event_blob_sha256 = 'a'.repeat(64);
    } else {
      output.results[0][tamper] ^= 1;
    }
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  for (const field of ['event_u32_0x04', 'event_u32_0x58',
    'event_u32_0x5c', 'event_blob_sha256']) {
    tamper = field;
    const outcome = decode(replay, { runtimeImagePath: image });
    assert.equal(outcome.status, 'DECODE_FAILED', field);
    assert.equal(outcome.events, null, field);
    assert.equal(outcome.first_failed_packet_ref.packet_id, 0x040a, field);
  }
});
