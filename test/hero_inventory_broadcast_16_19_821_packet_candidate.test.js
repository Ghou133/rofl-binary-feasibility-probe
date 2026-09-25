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
  HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeHeroInventoryBroadcastPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_inventory_broadcast_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const SLOT_BYTES = ['c1', '15', '9f', '2e', 'f6', '6b', 'db', '68', '46', 'd4'];

function payload(length = 80) {
  return Buffer.concat([Buffer.from([0x1e]), Buffer.alloc(length - 1)]);
}

function packet(packetId, rawParam, body = payload()) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(body.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, body]);
}

function replayWithChunks(chunks, build = BUILD) {
  return replayFromChunks(chunks.map(({ stream, packets }) => ({
    stream, body: Buffer.concat(packets.map(([id, param, body]) => packet(id, param, body))),
  })), build);
}

function fakeImage(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-broadcast-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const image = path.join(dir, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function record(index, slot, itemId) {
  return {
    record_index: index, slot, item_id: itemId,
    raw_slot_byte_hex: SLOT_BYTES[slot] ?? '00',
    raw_item_id_bytes_hex: itemId === 0 ? 'eaeaeaea' : 'f248eaea',
  };
}

function nativeResult(request, recordsByPacket) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => ({
      status: 'DECODED', input_index: index, raw_param: row.raw_param,
      chunk_stream: row.chunk_stream,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: row.payload_hex.length / 2,
      record_count: recordsByPacket[index].length,
      records: recordsByPacket[index],
    })),
  };
}

const keyframeRows = Array.from({ length: 10 }, (_, slot) =>
  record(slot, slot, slot === 0 ? 1001 : 0));
const gameRows = [0, 1, 2, 6, 7, 8].map((slot, index) =>
  record(index, slot, slot === 0 ? 2003 : 0));

test('821 Broadcast yields packet-local full and partial slot candidates with zero and absent distinct', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([
    { stream: 2, packets: [[0x0357, 0x400000ae, payload(79)]] },
    { stream: 1, packets: [[0x0357, 0x400001af, payload(76)]] },
  ]);
  let calls = 0;
  t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    calls += 1;
    assert.match(args[1], /decode_broadcast_inventory_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => row.chunk_stream),
      ['keyframe', 'game_chunk']);
    return { status: 0, stderr: '',
      stdout: JSON.stringify(nativeResult(request, [keyframeRows, gameRows])) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(profile.packet_name, 'PKT_S2C_SetInventory_Broadcast_s');
  assert.equal(profile.evidence_registration_type_descriptor_rva, '0x1f301c0');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.decoded_record_count, 16);
  assert.equal(result.events[0].participant_id_candidate, 1);
  assert.equal(result.events[1].participant_id_candidate, null);
  assert.equal(result.unmapped_raw_param_count, 1);
  assert.equal(result.events[0].packet_slot_snapshot_candidate[1].item_id_candidate, 0);
  assert.equal(result.events[0].packet_slot_snapshot_candidate[1].value_basis,
    'DECODED_PACKET_RECORD');
  assert.deepEqual(result.events[1].packet_slot_snapshot_candidate[3], {
    slot_candidate: 3, item_id_candidate: null,
    value_basis: 'CALLBACK_RESET_WITH_NO_PACKET_RECORD',
  });
  assert.equal(result.events[1].packet_slot_snapshot_candidate[0].item_id_candidate, 2003);
  assert.equal(result.events[1].packet_slot_snapshot_candidate[9].item_id_candidate, null);
  assert.equal(result.events[1].field_confidence.participant_id_candidate, 'UNAVAILABLE');
  assert.equal(result.events[1].raw_packet_ref.raw_param, 0x400001af);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(calls, 1);
});

test('821 Broadcast uses one source-bound precollected scan for game and keyframe rows', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([
    { stream: 1, packets: [[0x0357, 0x400000ae, payload(76)]] },
    { stream: 2, packets: [[0x0357, 0x400000af, payload(79)]] },
  ]);
  const token = collect821Routes(replay, ['hero_inventory_broadcast_packet']);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    assert.deepEqual(request.packets.map((row) => row.chunk_stream),
      ['game_chunk', 'keyframe']);
    return { status: 0, stderr: '',
      stdout: JSON.stringify(nativeResult(request, [gameRows, keyframeRows])) };
  });
  const result = decode(replay, { runtimeImagePath: image, precollected: token });
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 2);
  assert.equal(result.decoded_record_count, 16);
  const otherReplay = replayWithChunks([
    { stream: 1, packets: [[0x0357, 0x400000ae, payload(76)]] },
  ]);
  const mismatch = decode(otherReplay, { runtimeImagePath: image, precollected: token });
  assert.equal(mismatch.status, 'DECODE_FAILED');
  assert.match(mismatch.error, /different Replay|source-bound/);
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 Broadcast distinguishes absent route, missing image, and wrong build', (t) => {
  const invoked = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime should not be invoked');
  });
  const absent = decode(replayWithChunks([
    { stream: 1, packets: [[0x018d, 0x400000ae]] },
  ]));
  assert.equal(absent.status, 'PROFILE_UNAVAILABLE');
  assert.equal(absent.observed_raw_route_count, 0);
  const replay = replayWithChunks([
    { stream: 2, packets: [[0x0357, 0x400000ae]] },
  ]);
  const missing = decode(replay);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(decode(replayWithChunks([
    { stream: 2, packets: [[0x0357, 0x400000ae]] },
  ], '16.19.820.7193')).status, 'UNSUPPORTED');
  assert.equal(invoked.mock.callCount(), 0);
});

test('821 Broadcast rejects unobserved param, stream shape, and payload before runtime', (t) => {
  const invoked = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime should not be invoked');
  });
  const cases = [
    replayWithChunks([{ stream: 1, packets: [[0x0357, 0x400001b2]] }]),
    replayWithChunks([{ stream: 2, packets: [[0x0357, 0x400001af]] }]),
    replayWithChunks([{ stream: 1, packets: [[0x0357, 0x400000ae, payload(75)]] }]),
    replayWithChunks([{ stream: 1, packets: [[0x0357, 0x400000ae, payload(167)]] }]),
  ];
  for (const replay of cases) {
    const result = decode(replay);
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.first_failed_packet_ref.packet_id, 0x0357);
    assert.equal(result.events, null);
  }
  assert.equal(invoked.mock.callCount(), 0);
});

test('821 Broadcast preserves source binding and rejects wrong image identity', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ stream: 2,
    packets: [[0x0357, 0x400000ae, payload(79)]] }]);
  const invoked = t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1,
    stderr: '821 Broadcast exact-runtime decoder error: runtime image SHA-256 mismatch: bad',
    stdout: '',
  }));
  const mismatch = decode(replay, { runtimeImagePath: image });
  assert.equal(mismatch.status, 'DECODE_FAILED');
  assert.equal(mismatch.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(invoked.mock.callCount(), 1);
  replay.buffer[0] ^= 1;
  assert.match(decode(replay, { runtimeImagePath: image }).error, /source integrity/);
  assert.equal(invoked.mock.callCount(), 1);
});

test('821 Broadcast rejects trailing bytes and forged packet binding without partial events', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ stream: 2,
    packets: [[0x0357, 0x400000ae, payload(79)]] }]);
  const mocked = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input), [keyframeRows]);
    output.results[0].bytes_consumed -= 1;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const trailing = decode(replay, { runtimeImagePath: image });
  assert.equal(trailing.status, 'DECODE_FAILED');
  assert.equal(trailing.events, null);
  assert.equal(trailing.first_failed_packet_ref.packet_id, 0x0357);
  mocked.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input), [keyframeRows]);
    output.results[0].raw_payload_sha256 = '0'.repeat(64);
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const forged = decode(replay, { runtimeImagePath: image });
  assert.equal(forged.status, 'DECODE_FAILED');
  assert.equal(forged.events, null);
});

test('821 Broadcast rejects incomplete keyframes and game records outside observed slots', (t) => {
  const image = fakeImage(t);
  const keyframe = replayWithChunks([{ stream: 2,
    packets: [[0x0357, 0x400000ae, payload(79)]] }]);
  const mocked = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => ({
    status: 0, stderr: '',
    stdout: JSON.stringify(nativeResult(JSON.parse(options.input), [keyframeRows.slice(0, 9)])),
  }));
  assert.equal(decode(keyframe, { runtimeImagePath: image }).status, 'DECODE_FAILED');
  mocked.mock.restore();
  const game = replayWithChunks([{ stream: 1,
    packets: [[0x0357, 0x400000ae, payload(76)]] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => ({
    status: 0, stderr: '',
    stdout: JSON.stringify(nativeResult(JSON.parse(options.input), [
      [...gameRows.slice(0, 5), record(5, 9, 1001)],
    ])),
  }));
  const invalid = decode(game, { runtimeImagePath: image });
  assert.equal(invalid.status, 'DECODE_FAILED');
  assert.equal(invalid.events, null);
});
