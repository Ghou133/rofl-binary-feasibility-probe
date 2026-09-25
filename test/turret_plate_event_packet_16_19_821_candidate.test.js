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
  TURRET_PLATE_EVENT_PACKET_821_PROFILE: profile,
  decodeTurretPlateEventPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_turret_plate_event_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(packetId = 0x040a, rawParam = 0x400000ae,
  payload = Buffer.alloc(17, 0x4a)) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-turret_plate-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request, childIds = [0x0107, 0x0101, 0x0107]) {
  const rawIds = new Map([[0x0107, '0x09e8'], [0x0101, '0x0909'],
    [0x0102, '0x0929']]);
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => {
      const childId = childIds[index] ?? 0x0107;
      const blob = Buffer.alloc(8);
      blob.writeUInt32LE(469, 0);
      blob.writeUInt32LE(0x40000088 + index, 4);
      return {
        status: childId === 0x0107 ? 'DECODED' : 'EXCLUDED_CHILD',
        input_index: index,
        raw_param: row.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 1, bytes_consumed: 17,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: childId, raw_event_id_hex: rawIds.get(childId) ?? '0x0000',
        event_blob_length: 8, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: crypto.createHash('sha256').update(blob).digest('hex'),
        event_schema_u32_0x00: 469,
        event_u32_0x04: 0x40000088 + index,
      };
    }),
  };
}

test('821 OnTurretPlateDestroyed excludes same-length foreign children and keeps raw refs', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [
    packet(), packet(0x040a, 0x400000af),
    packet(0x040a, 0x400000b0),
    packet(0x040a, 0x400000b1, Buffer.alloc(16)),
  ] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_turret_plate_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag,
      row.payload_hex.length / 2]), [
      [0x040a, 1, 17], [0x040a, 1, 17], [0x040a, 1, 17],
    ]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(profile.child_event_name, 'OnTurretPlateDestroyed');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 3);
  assert.equal(result.event_count, 2);
  assert.equal(result.target_packet_count, 2);
  assert.equal(result.same_length_control_count, 1);
  assert.deepEqual(result.same_length_control_ids, { '0x0101': 1 });
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.deepEqual(result.events.map((row) => row.event_u32_0x04),
    [0x40000088, 0x4000008a]);
  assert.equal(result.events[0].event_type, 'TURRET_PLATE_EVENT_PACKET_CANDIDATE');
  assert.equal(result.events[0].event_id, 0x0107);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[0].raw_packet_ref.payload_length, 17);
  assert.equal(result.events[0].semantic_status, 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD');
  for (const field of ['plate_destroyed', 'caster', 'target', 'event_u32_0x08']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 OnTurretPlateDestroyed distinguishes absent shape, missing image, wrong build, and corrupt Replay', () => {
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

test('821 OnTurretPlateDestroyed reports foreign-only native packets as unavailable', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet(), packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => ({
    status: 0, stderr: '',
    stdout: JSON.stringify(nativeResult(JSON.parse(options.input), [0x0101, 0x0102])),
  }));
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(result.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.input_count, 2);
  assert.equal(result.target_packet_count, null);
  assert.equal(result.event_count, null);
  assert.equal(result.events, null);
  assert.equal(result.same_length_control_count, 2);
  assert.deepEqual(result.same_length_control_ids, { '0x0101': 1, '0x0102': 1 });
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
});

test('821 OnTurretPlateDestroyed rejects foreign stream and wrong image digest', (t) => {
  const image = fakeImage(t);
  const foreign = replayWithChunks([{ stream: 2, packets: [packet()] }]);
  assert.equal(decode(foreign, { runtimeImagePath: image }).status, 'DECODE_FAILED');
  const replay = replayWithChunks([{ packets: [packet()] }]);
  t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'OnTurretPlateDestroyed runtime image SHA-256 mismatch: bad', stdout: '',
  }));
  const failed = decode(replay, { runtimeImagePath: image });
  assert.equal(failed.status, 'DECODE_FAILED');
  assert.equal(failed.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(failed.events, null);
});

test('821 OnTurretPlateDestroyed binds native ID and anonymous u32 to returned bytes atomically', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet(), packet(), packet()] }]);
  let failure = 'unknown_id';
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    if (failure === 'unknown_id') result.results[1].event_id = 0x002c;
    if (failure === 'field') result.results[2].event_u32_0x04 += 1;
    if (failure === 'hash') result.results[2].event_blob_sha256 = '0'.repeat(64);
    if (failure === 'target_marked_excluded') result.results[0].status = 'EXCLUDED_CHILD';
    return { status: 0, stderr: '', stdout: JSON.stringify(result) };
  });
  for (const mode of ['unknown_id', 'field', 'hash', 'target_marked_excluded']) {
    failure = mode;
    const failed = decode(replay, { runtimeImagePath: image });
    assert.equal(failed.status, 'DECODE_FAILED', mode);
    assert.equal(failed.event_count, null, mode);
    assert.equal(failed.events, null, mode);
    assert.equal(failed.first_failed_packet_ref.packet_id, 0x040a);
  }
});
