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
  STEALTH_EVENT_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeStealthEventPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_stealth_event_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(packetId = 0x040a, rawParam = 0x400000ae, payload = Buffer.alloc(17, 0x4a)) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-stealth-event-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request, eventIds) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => {
      const eventId = eventIds[index];
      const target = eventId === 0x0101 || eventId === 0x0102;
      const blob = Buffer.alloc(8);
      blob.writeUInt32LE(469, 0);
      blob.writeUInt32LE(index === 1 ? row.raw_param - 256 : row.raw_param, 4);
      return {
        status: target ? 'DECODED' : 'EXCLUDED_CHILD', input_index: index,
        raw_param: row.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 1, bytes_consumed: 17,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: eventId,
        raw_event_id_hex: eventId === 0x0101 ? '0x0909'
          : eventId === 0x0102 ? '0x0929' : '0x0100',
        event_blob_length: 8, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: crypto.createHash('sha256').update(blob).digest('hex'),
        event_schema_u32_0x00: 469,
        event_u32_0x04: blob.readUInt32LE(4),
      };
    }),
  };
}

test('821 stealth-event selects target children and counts same-length controls separately', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [
    packet(), packet(0x040a, 0x400001ae), packet(0x040a, 0x400002ae),
    packet(0x040a, 0x400003ae, Buffer.alloc(29)),
  ] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_stealth_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag,
      row.payload_hex.length / 2]), [[0x040a, 1, 17], [0x040a, 1, 17], [0x040a, 1, 17]]);
    return { status: 0, stderr: '', stdout: JSON.stringify(
      nativeResult(request, [0x0101, 0x0107, 0x0102])) };
  });
  const shared = collect821Routes(replay, ['stealth_event_packet']);
  const result = decode(replay, { runtimeImagePath: image, precollected: shared });
  assert.deepEqual(profile.registered_event_names, ['OnEnterStealth', 'OnExitStealth']);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_packet_scope, 'child_0101_0102_length_17');
  assert.equal(result.input_count, 3);
  assert.equal(result.target_packet_count, 2);
  assert.equal(result.excluded_child_count, 1);
  assert.deepEqual(result.excluded_child_ids, { '0x0107': 1 });
  assert.equal(result.event_count, 2);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.deepEqual(result.events.map((event) => event.registered_event_name),
    ['OnEnterStealth', 'OnExitStealth']);
  assert.equal(result.events[0].event_type, 'STEALTH_EVENT_PACKET_CANDIDATE');
  assert.equal(result.events[0].event_u32_0x04, 0x400000ae);
  assert.equal(result.events[1].event_u32_0x04, 0x400002ae);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  for (const field of ['actor', 'target', 'visibility', 'stealth_state', 'duration_ms']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 stealth-event separates absent shape, missing image, wrong build and source corruption', () => {
  const absent = replayWithChunks([{ packets: [packet(0x040a, 0x400000ae,
    Buffer.alloc(29))] }]);
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

test('821 stealth-event fails closed on foreign stream and unknown same-length child', (t) => {
  const image = fakeImage(t);
  const foreign = replayWithChunks([{ stream: 2, packets: [packet()] }]);
  assert.equal(decode(foreign, { runtimeImagePath: image }).status, 'DECODE_FAILED');
  const replay = replayWithChunks([{ packets: [packet(), packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input), [0x0101, 0x0199]);
    return { status: 0, stderr: '', stdout: JSON.stringify(result) };
  });
  const unknown = decode(replay, { runtimeImagePath: image });
  assert.equal(unknown.status, 'DECODE_FAILED');
  assert.equal(unknown.event_count, null);
  assert.equal(unknown.events, null);
  assert.equal(unknown.first_failed_packet_ref.packet_id, 0x040a);
});

test('821 stealth-event fails closed when native packet consumption is partial', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input), [0x0101]);
    result.results[0].bytes_consumed = 16;
    return { status: 0, stderr: '', stdout: JSON.stringify(result) };
  });
  const failed = decode(replay, { runtimeImagePath: image });
  assert.equal(failed.status, 'DECODE_FAILED');
  assert.equal(failed.target_packet_count, null);
  assert.equal(failed.events, null);
});
