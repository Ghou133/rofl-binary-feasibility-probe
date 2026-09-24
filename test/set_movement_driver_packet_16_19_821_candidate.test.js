'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { capabilityQuery } = require('../src/cli');
const {
  SET_MOVEMENT_DRIVER_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeSetMovementDriverPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_set_movement_driver_packet_candidate');

const BUILD = '16.19.821.7343';
const SHORT = Buffer.from([0x54, 0x37]);
const LONG = Buffer.concat([Buffer.from([0x26]), Buffer.alloc(27, 0x01)]);

function packet(packetId = 0x0335, rawParam = 0x400000ae, payload = SHORT) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-set-driver-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request) {
  return {
    status: 'PASS',
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
    callback_transform_sha256: profile.evidence_callback_transform_sha256,
    results: request.packets.map((input, inputIndex) => {
      const length = input.payload_hex.length / 2;
      return {
        status: 'DECODED', input_index: inputIndex,
        raw_param: input.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 1, bytes_consumed: length,
        native_packet_id: 0x0335, native_raw_param: input.raw_param,
        raw_u8_byte_0x2a_hex: length === 2 ? '09' : '29',
        opaque_u8_0x2a: length === 2 ? 1 : 2,
      };
    }),
  };
}

test('821 SetMovementDriver exposes only exact callback selector and packet provenance', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([
    { packets: [packet(0x0335, 0x400000ae, LONG)] },
    { packets: [packet(0x0335, 0x400001ae, SHORT)] },
  ]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_set_movement_driver_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag,
      row.payload_hex.length / 2]), [[0x0335, 1, 28], [0x0335, 1, 2]]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(profile.packet_name, 'PKT_S2C_SetMovementDriver_s');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.deepEqual(result.events.map((row) => [row.opaque_u8_0x2a,
    row.raw_payload_byte_0, row.raw_object_u8_byte_0x2a_hex]),
  [[2, 0x26, '29'], [1, 0x54, '09']]);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[1].raw_packet_ref.raw_param, 0x400001ae);
  for (const field of ['position', 'path', 'hero_id', 'participant_id',
    'owner', 'target', 'driver_changed']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 SetMovementDriver distinguishes exact build, absent route and missing image', () => {
  const older = replayWithChunks([{ packets: [packet()] }], '16.19.820.7193');
  assert.equal(decode(older).status, 'UNSUPPORTED');
  const absent = replayWithChunks([{ packets: [packet(0x00ba)] }]);
  assert.equal(decode(absent).status, 'PROFILE_UNAVAILABLE');
  const present = replayWithChunks([{ packets: [packet()] }]);
  const missing = decode(present);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
});

test('821 SetMovementDriver rejects changed source and unobserved shape before native decode', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('native decoder should not be invoked');
  });
  const mutated = replayWithChunks([{ packets: [packet()] }]);
  mutated.buffer[0] ^= 1;
  assert.match(decode(mutated).error, /source integrity/);
  const wrongLength = replayWithChunks([{ packets: [packet(0x0335, 0x400000ae,
    LONG.subarray(0, 27))] }]);
  assert.equal(decode(wrongLength).status, 'DECODE_FAILED');
  // The exact native deserializer fully consumes this mutation, so the
  // observed selector gate must act before calling it.
  const zeroSelector = replayWithChunks([{ packets: [packet(0x0335, 0x400000ae,
    Buffer.from([0, 0x37]))] }]);
  assert.equal(decode(zeroSelector).status, 'DECODE_FAILED');
  const wrongStream = replayWithChunks([{ stream: 2, packets: [packet()] }]);
  assert.equal(decode(wrongStream).status, 'DECODE_FAILED');
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 SetMovementDriver fails closed on image mismatch and incomplete native selector', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const mismatch = t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'runtime image SHA-256 mismatch: foreign image', stdout: '',
  }));
  const wrongImage = decode(replay, { runtimeImagePath: image });
  assert.equal(wrongImage.status, 'DECODE_FAILED');
  assert.equal(wrongImage.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(wrongImage.events, null);
  mismatch.mock.restore();
  const partial = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].bytes_consumed -= 1;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const incomplete = decode(replay, { runtimeImagePath: image });
  assert.equal(incomplete.status, 'DECODE_FAILED');
  assert.equal(incomplete.first_failed_packet_ref.packet_id, 0x0335);
  assert.equal(incomplete.events, null);
  partial.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].opaque_u8_0x2a = 2;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const wrongSelector = decode(replay, { runtimeImagePath: image });
  assert.equal(wrongSelector.status, 'DECODE_FAILED');
  assert.equal(wrongSelector.events, null);
});

test('821 SetMovementDriver selected API shares scan and retains independent missing route', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => ({
    status: 0, stderr: '', stdout: JSON.stringify(nativeResult(JSON.parse(options.input))),
  }));
  const decoded = decodeSemanticReplay(replay, {
    capabilities: ['set_movement_driver_packet', 'direct_input_movement_turn_packet'],
    runtimeImagePath: image,
  });
  assert.equal(decoded.capability_results.set_movement_driver_packet.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.direct_input_movement_turn_packet.status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decoded.events.set_movement_driver_packet_candidates.length, 1);
  assert.equal(decoded.decoded_packet_count, 1);
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 SetMovementDriver capability query requires exact image', () => {
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const row = capabilityQuery(replay).capabilities.find((item) =>
    item.capability === 'set_movement_driver_packet');
  assert.equal(row.status, 'CANDIDATE');
  assert.equal(row.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.deepEqual(row.missing_inputs, ['exact_runtime_image']);
  assert.equal(row.output, 'set_movement_driver_packet_candidates');
});
