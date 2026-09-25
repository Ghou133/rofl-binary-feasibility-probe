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
  DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeDirectInputMovementTurnPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_direct_input_turn_packet_candidate');

const BUILD = '16.19.821.7343';
const PAYLOAD = Buffer.from('857d09f6f37268f3f36d17f3f3', 'hex');

function packet(packetId = 0x00ba, rawParam = 0x400000ae, payload = PAYLOAD) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-turn-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request) {
  const transformed = Buffer.alloc(12);
  transformed.writeFloatLE(12.5, 0);
  transformed.writeFloatLE(-1.25, 4);
  transformed.writeFloatLE(400.75, 8);
  return {
    status: 'PASS',
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
    callback_transform_sha256: profile.evidence_callback_transform_sha256,
    results: request.packets.map((input, inputIndex) => ({
      status: 'DECODED', input_index: inputIndex,
      raw_param: input.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: 13,
      native_packet_id: 0x00ba, native_raw_param: input.raw_param,
      raw_object_vector_bytes_hex: 'f3f3176df3f36872f3f6097d',
      callback_vector_bytes_hex: transformed.toString('hex'),
      opaque_f32_0x10: 12.5,
      opaque_f32_0x14: -1.25,
      opaque_f32_0x18: 400.75,
    })),
  };
}

test('821 direct-input turn candidate retains anonymous f32 packet fields and raw refs', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([
    { stream: 1, packets: [packet()] },
    { stream: 2, packets: [packet(0x00ba, 0x400001ae)] },
  ]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_direct_input_turn_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag]),
      [[0x00ba, 1], [0x00ba, 2]]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(profile.packet_name, 'PKT_DirectInputMovementDriverServerTurnData_s');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].opaque_f32_0x10, 12.5);
  assert.equal(result.events[0].opaque_f32_0x14, -1.25);
  assert.equal(result.events[0].opaque_f32_0x18, 400.75);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[1].raw_packet_ref.chunk_stream, 'keyframe');
  assert.equal(result.events[1].raw_param, 0x400001ae);
  for (const field of ['position', 'path', 'hero_id', 'participant_id', 'owner', 'target']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 direct-input turn distinguishes foreign build, absent route and missing image', () => {
  const older = replayWithChunks([{ packets: [packet()] }], '16.19.820.7193');
  assert.equal(decode(older).status, 'UNSUPPORTED');
  const absent = replayWithChunks([{ packets: [packet(0x0335)] }]);
  assert.equal(decode(absent).status, 'PROFILE_UNAVAILABLE');
  const present = replayWithChunks([{ packets: [packet()] }]);
  const missing = decode(present);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.input_count, 1);
});

test('821 direct-input turn rejects changed source and unobserved packet shapes before native decode', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('native decoder should not be invoked');
  });
  const mutated = replayWithChunks([{ packets: [packet()] }]);
  mutated.buffer[0] ^= 1;
  assert.match(decode(mutated).error, /source integrity/);
  const wrongLength = replayWithChunks([{ packets: [packet(0x00ba, 0x400000ae,
    PAYLOAD.subarray(0, 12))] }]);
  assert.equal(decode(wrongLength).status, 'DECODE_FAILED');
  const wrongSelector = replayWithChunks([{ packets: [packet(0x00ba, 0x400000ae,
    Buffer.concat([Buffer.from([0]), PAYLOAD.subarray(1)]))] }]);
  assert.equal(decode(wrongSelector).status, 'DECODE_FAILED');
  const wrongStream = replayWithChunks([{ stream: 3, packets: [packet()] }]);
  assert.equal(decode(wrongStream).status, 'DECODE_FAILED');
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 direct-input turn fails closed for image mismatch or incomplete native field output', (t) => {
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
    output.results[0].bytes_consumed = 12;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const incomplete = decode(replay, { runtimeImagePath: image });
  assert.equal(incomplete.status, 'DECODE_FAILED');
  assert.equal(incomplete.first_failed_packet_ref.packet_id, 0x00ba);
  assert.equal(incomplete.events, null);
  partial.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].opaque_f32_0x10 = 99;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const inconsistent = decode(replay, { runtimeImagePath: image });
  assert.equal(inconsistent.status, 'DECODE_FAILED');
  assert.equal(inconsistent.events, null);
});

test('821 direct-input turn rejects helper vectors unrelated to source payload or callback transform', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const rawMismatch = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].raw_object_vector_bytes_hex = '00'.repeat(12);
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  assert.equal(decode(replay, { runtimeImagePath: image }).status, 'DECODE_FAILED');
  rawMismatch.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].callback_vector_bytes_hex = '00'.repeat(12);
    output.results[0].opaque_f32_0x10 = 0;
    output.results[0].opaque_f32_0x14 = 0;
    output.results[0].opaque_f32_0x18 = 0;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const callbackMismatch = decode(replay, { runtimeImagePath: image });
  assert.equal(callbackMismatch.status, 'DECODE_FAILED');
  assert.equal(callbackMismatch.events, null);
});

test('821 direct-input turn is selected through shared semantic API scan', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => ({
    status: 0, stderr: '', stdout: JSON.stringify(nativeResult(JSON.parse(options.input))),
  }));
  const result = decodeSemanticReplay(replay, {
    capabilities: ['direct_input_movement_turn_packet', 'hero_inventory_packet'],
    runtimeImagePath: image,
  });
  assert.equal(result.capability_results.direct_input_movement_turn_packet.status, 'CANDIDATE');
  assert.equal(result.capability_results.hero_inventory_packet.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.events.direct_input_movement_turn_packet_candidates.length, 1);
  assert.equal(result.decoded_packet_count, 1);
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 direct-input turn capability query exposes its exact-image candidate boundary', () => {
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const row = capabilityQuery(replay).capabilities.find((item) =>
    item.capability === 'direct_input_movement_turn_packet');
  assert.equal(row.status, 'CANDIDATE');
  assert.equal(row.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.equal(row.output, 'direct_input_movement_turn_packet_candidates');
  assert.deepEqual(row.missing_inputs, ['exact_runtime_image']);
});
