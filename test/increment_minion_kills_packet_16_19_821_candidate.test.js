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
  INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeIncrementMinionKillsPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_increment_minion_kills_packet_candidate');

const BUILD = '16.19.821.7343';
const LOOKUP_BYTES = new Map([
  [0x400000b1, '26d7d7e7'],
  [0x400000b6, '07d7d7e7'],
]);

function packet(packetId = 0x03a7, rawParam = 0x400000b1,
  payload = Buffer.from('3a2618', 'hex')) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-cs-route-test-'));
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
    results: request.packets.map((input, inputIndex) => ({
      status: 'DECODED', input_index: inputIndex,
      raw_param: input.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: input.payload_hex.length / 2,
      native_packet_id: 0x03a7, native_raw_param: input.raw_param,
      native_object_lookup_key_bytes_hex: LOOKUP_BYTES.get(input.raw_param),
      callback_lookup_key_candidate: input.raw_param,
    })),
  };
}

test('821 IncrementMinionKills exposes a native callback lookup key and raw provenance only', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([
    { packets: [packet(0x03a7, 0x400000b1, Buffer.from('3a2618', 'hex'))] },
    { packets: [packet(0x03a7, 0x400000b6, Buffer.from('380718', 'hex'))] },
  ]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_increment_minion_kills_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag,
      row.raw_param, row.payload_hex]), [
      [0x03a7, 1, 0x400000b1, '3a2618'],
      [0x03a7, 1, 0x400000b6, '380718'],
    ]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(profile.packet_name, 'PKT_S2C_IncrementMinionKills_s');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 2);
  assert.equal(result.input_count, 2);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.deepEqual(result.events.map((row) => [row.raw_selector_byte,
    row.native_object_lookup_key_bytes_hex, row.callback_lookup_key_candidate]), [
    [0x3a, '26d7d7e7', 0x400000b1],
    [0x38, '07d7d7e7', 0x400000b6],
  ]);
  for (const event of result.events) {
    assert.equal(event.callback_lookup_key_matches_raw_param, true);
    assert.equal(event.conditional_counter_write_status, 'UNKNOWN');
    assert.equal(event.semantic_cs_effect_status, 'UNKNOWN');
    assert.equal(event.raw_packet_ref.replay_sha256, replay.source_sha256);
    assert.equal(event.raw_packet_ref.packet_id, 0x03a7);
    assert.equal(event.raw_packet_ref.payload_length, 3);
    assert.equal(event.raw_packet_ref.raw_param, event.raw_param);
    assert.equal(event.raw_packet_ref.raw_payload_sha256,
      crypto.createHash('sha256').update(Buffer.from(event.raw_payload_hex, 'hex')).digest('hex'));
    for (const field of ['participant_id', 'hero_id', 'minion_id', 'minion_kill',
      'cs_delta', 'cs_total', 'counter_write', 'experience_gain']) {
      assert.equal(field in event, false);
    }
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 IncrementMinionKills distinguishes build, absent route, and missing image', () => {
  assert.equal(decode(replayWithChunks([{ packets: [packet()] }],
    '16.19.820.7193')).status, 'UNSUPPORTED');
  assert.equal(decode(replayWithChunks([{ packets: [packet(0x03a6)] }])).status,
    'PROFILE_UNAVAILABLE');
  const missing = decode(replayWithChunks([{ packets: [packet()] }]));
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
});

test('821 IncrementMinionKills rejects source changes and unobserved packet shapes before native decode', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('native decoder should not be invoked');
  });
  const changed = replayWithChunks([{ packets: [packet()] }]);
  changed.buffer[0] ^= 1;
  assert.match(decode(changed).error, /source integrity/);
  for (const replay of [
    replayWithChunks([{ stream: 2, packets: [packet()] }]),
    replayWithChunks([{ packets: [packet(0x03a7, 0x400001b1)] }]),
    replayWithChunks([{ packets: [packet(0x03a7, 0x400000b1,
      Buffer.from('3a2719', 'hex'))] }]),
    replayWithChunks([{ packets: [packet(0x03a7, 0x400000b1,
      Buffer.from('3a2718ff', 'hex'))] }]),
  ]) {
    const result = decode(replay);
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
  }
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 IncrementMinionKills fails closed on foreign image and incomplete or mismatched native key', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const foreignImage = t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'runtime image SHA-256 mismatch', stdout: '',
  }));
  const mismatch = decode(replay, { runtimeImagePath: image });
  assert.equal(mismatch.status, 'DECODE_FAILED');
  assert.equal(mismatch.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(mismatch.events, null);
  foreignImage.mock.restore();

  for (const mutate of [
    (row) => { row.bytes_consumed = 2; },
    (row) => { row.native_object_lookup_key_bytes_hex = '07d7d7e7'; },
    (row) => { row.callback_lookup_key_candidate = 0x400000b6; },
    (row) => { row.native_raw_param = 0x400000b6; },
  ]) {
    const invoke = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
      const output = nativeResult(JSON.parse(options.input));
      mutate(output.results[0]);
      return { status: 0, stderr: '', stdout: JSON.stringify(output) };
    });
    const result = decode(replay, { runtimeImagePath: image });
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
    assert.equal(result.first_failed_packet_ref.packet_id, 0x03a7);
    invoke.mock.restore();
  }
});
