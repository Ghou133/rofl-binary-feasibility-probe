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
  CHAMPION_DIE_EVENT_PACKET_821_PROFILE: profile,
  decodeChampionDieEventPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_champion_die_event_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(packetId = 0x040a, rawParam = 0x400000ae,
  payload = Buffer.alloc(116, 0x4a)) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-champion-die-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request, eventIds) {
  assert.equal(request.packets.length, eventIds.length);
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => {
      const blob = Buffer.alloc(108);
      if (eventIds[index] === 0x0004) blob.writeUInt32LE(0x400000b3 + index, 4);
      return {
      status: eventIds[index] === 0x0004 ? 'DECODED' : 'CONTROL',
      input_index: index, raw_param: row.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: 116,
      native_packet_id: 0x040a, native_raw_param: row.raw_param,
      event_id: eventIds[index],
      raw_event_id_hex: eventIds[index] === 0x0004 ? '0x4948' : '0x4900',
      event_blob_length: 108, event_blob_hex: blob.toString('hex'),
      event_blob_sha256: crypto.createHash('sha256').update(blob).digest('hex'),
      ...(eventIds[index] === 0x0004 ? { event_u32_0x04: 0x400000b3 + index } : {}),
      };
    }),
  };
}

test('821 OnChampionDie checks all same-length children and emits only ID 4 candidates', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [
    packet(), packet(0x040a, 0x400000af),
    packet(0x040a, 0x400000b0, Buffer.alloc(104)),
    packet(0x040a, 0x400000b1),
  ] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_champion_die_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag,
      row.payload_hex.length / 2]), [
      [0x040a, 1, 116], [0x040a, 1, 116], [0x040a, 1, 116],
    ]);
    return { status: 0, stderr: '',
      stdout: JSON.stringify(nativeResult(request, [0x0004, 0x003b, 0x0004])) };
  });
  const shared = collect821Routes(replay, ['champion_die_event_packet']);
  const result = decode(replay, { runtimeImagePath: image, precollected: shared });
  assert.equal(profile.child_event_name, 'OnChampionDie');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 3);
  assert.equal(result.event_count, 2);
  assert.equal(result.observed_same_length_control_count, 1);
  assert.deepEqual(result.observed_same_length_control_ids, { '0x003b': 1 });
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].event_type, 'CHAMPION_DIE_EVENT_PACKET_CANDIDATE');
  assert.equal(result.events[0].event_id, 0x0004);
  assert.equal(result.events[0].event_name, 'OnChampionDie');
  assert.equal(result.events[0].event_u32_0x04, 0x400000b3);
  assert.equal(result.events[1].event_u32_0x04, 0x400000b5);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  for (const field of ['victim', 'killer', 'effective_death', 'death_time_ms']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 OnChampionDie reports no target when native decode finds only controls', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet(), packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    return { status: 0, stderr: '',
      stdout: JSON.stringify(nativeResult(request, [0x0035, 0x0046])) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(result.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.event_count, 0);
  assert.deepEqual(result.events, []);
  assert.deepEqual(result.observed_same_length_control_ids,
    { '0x0035': 1, '0x0046': 1 });
});

test('821 OnChampionDie separates absent shape, missing image, wrong build and source corruption', () => {
  const absent = replayWithChunks([{ packets: [packet(0x040a, 0x400000ae,
    Buffer.alloc(104))] }]);
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

test('821 OnChampionDie rejects foreign stream and mixed native result atomically', (t) => {
  const image = fakeImage(t);
  const foreign = replayWithChunks([{ stream: 2, packets: [packet()] }]);
  assert.equal(decode(foreign, { runtimeImagePath: image }).status, 'DECODE_FAILED');
  const replay = replayWithChunks([{ packets: [packet(), packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input), [0x0004, 0x003b]);
    result.results[1].event_id = 0x0009;
    return { status: 0, stderr: '', stdout: JSON.stringify(result) };
  });
  const failed = decode(replay, { runtimeImagePath: image });
  assert.equal(failed.status, 'DECODE_FAILED');
  assert.equal(failed.event_count, null);
  assert.equal(failed.events, null);
  assert.equal(failed.first_failed_packet_ref.packet_id, 0x040a);
});

test('821 OnChampionDie binds the child field and blob hash to returned bytes', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input), [0x0004]);
    result.results[0].event_u32_0x04 += 1;
    return { status: 0, stderr: '', stdout: JSON.stringify(result) };
  });
  assert.equal(decode(replay, { runtimeImagePath: image }).status, 'DECODE_FAILED');
});
