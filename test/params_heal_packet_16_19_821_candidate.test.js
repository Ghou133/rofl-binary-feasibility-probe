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
  PARAMS_HEAL_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeParamsHealPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_params_heal_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(packetId = 0x040a, rawParam = 0x400000ae, payload = Buffer.alloc(60, 0x4a)) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-params-heal-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => ({
      status: 'DECODED', input_index: index,
      raw_param: row.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: 60,
      native_packet_id: 0x040a, native_raw_param: row.raw_param,
      event_id: 0x004b, raw_event_id_hex: '0x4958',
      event_blob_length: 52, event_blob_sha256: 'a'.repeat(64),
      event_entity_u32_0x04: 0x400000b3,
      event_entity_u32_0x14: 0x400000b4,
      reported_amount_candidate: 50.0 + index,
    })),
  };
}

test('821 ParamsHeal selects only length-60 OnEvent and emits bounded candidate fields', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [
    packet(), packet(0x040a, 0x400000ae, Buffer.alloc(44, 0x4a)),
    packet(0x040a, 0x400000b3),
  ] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_params_heal_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag,
      row.payload_hex.length / 2]), [[0x040a, 1, 60], [0x040a, 1, 60]]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const shared = collect821Routes(replay, ['params_heal_packet']);
  const result = decode(replay, { runtimeImagePath: image, precollected: shared });
  assert.equal(profile.child_event_name, 'ParamsHeal');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].event_type, 'PARAMS_HEAL_PACKET_CANDIDATE');
  assert.equal(result.events[0].event_id, 0x004b);
  assert.equal(result.events[0].reported_amount_candidate, 50);
  assert.equal(result.events[1].reported_amount_candidate, 51);
  assert.equal(result.events[0].event_entity_u32_0x04, 0x400000b3);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  for (const field of ['effective_heal', 'source', 'target', 'caster', 'recipient']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 ParamsHeal separates absent shape, missing image, wrong build and source corruption', () => {
  const absent = replayWithChunks([{ packets: [packet(0x040a, 0x400000ae,
    Buffer.alloc(44))] }]);
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

test('821 ParamsHeal rejects foreign stream and mixed native result before emitting events', (t) => {
  const image = fakeImage(t);
  const foreign = replayWithChunks([{ stream: 2, packets: [packet()] }]);
  assert.equal(decode(foreign, { runtimeImagePath: image }).status, 'DECODE_FAILED');
  const replay = replayWithChunks([{ packets: [packet(), packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    result.results[1].event_id = 0x0056;
    return { status: 0, stderr: '', stdout: JSON.stringify(result) };
  });
  const failed = decode(replay, { runtimeImagePath: image });
  assert.equal(failed.status, 'DECODE_FAILED');
  assert.equal(failed.event_count, null);
  assert.equal(failed.events, null);
  assert.equal(failed.first_failed_packet_ref.packet_id, 0x040a);
});
