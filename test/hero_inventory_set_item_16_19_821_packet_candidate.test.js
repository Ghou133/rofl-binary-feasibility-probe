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
  HERO_INVENTORY_SET_ITEM_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeHeroInventorySetItemPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_inventory_set_item_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(id, rawParam, body = Buffer.from('1e26efba46c52c', 'hex')) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(body.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, body]);
}

function replayWithChunks(chunks, build = BUILD) {
  return replayFromChunks(chunks.map(({ stream, packets }) => ({
    stream, body: Buffer.concat(packets.map(([id, param, body]) => packet(id, param, body))),
  })), build);
}

function fakeImage(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-set-item-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const image = path.join(dir, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => ({
      status: 'DECODED', input_index: index, raw_param: row.raw_param,
      chunk_stream: row.chunk_stream,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: row.payload_hex.length / 2,
      slot: 8, item_id: index === 0 ? 1222 : 1203,
      raw_slot_byte_hex: '46',
      raw_item_id_bytes_hex: index === 0 ? 'c5f6eaea' : 'e1f6eaea',
    })),
  };
}

test('821 SetItem exposes packet fields and keeps variant identity unavailable', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ stream: 1, packets: [
    [0x002d, 0x400000ae], [0x002d, 0x400001b2],
  ] }]);
  const token = collect821Routes(replay, ['hero_inventory_set_item_packet']);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_set_item_inventory_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => row.chunk_stream),
      ['game_chunk', 'game_chunk']);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const result = decode(replay, { runtimeImagePath: image, precollected: token });
  assert.equal(profile.packet_name, 'PKT_SetItem_s');
  assert.equal(profile.evidence_registration_type_descriptor_rva, '0x1f2feb0');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 2);
  assert.equal(result.events[0].event_type, 'HERO_INVENTORY_SET_ITEM_PACKET_CANDIDATE');
  assert.equal(result.events[0].slot_candidate, 8);
  assert.equal(result.events[0].item_id_candidate, 1222);
  assert.equal(result.events[0].participant_id_candidate, 1);
  assert.equal(result.events[1].item_id_candidate, 1203);
  assert.equal(result.events[1].participant_id_candidate, null);
  assert.equal(result.events[1].field_confidence.participant_id_candidate, 'UNAVAILABLE');
  assert.equal(result.unmapped_raw_param_count, 1);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(invoke.mock.callCount(), 1);

  const otherReplay = replayWithChunks([{ stream: 1, packets: [[0x002d, 0x400000ae]] }]);
  const mismatch = decode(otherReplay, { runtimeImagePath: image, precollected: token });
  assert.equal(mismatch.status, 'DECODE_FAILED');
  assert.match(mismatch.error, /different Replay|source-bound/);
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 SetItem distinguishes absent route, missing image, wrong build, and shape', (t) => {
  const invoked = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime should not be invoked');
  });
  assert.equal(decode(replayWithChunks([{ stream: 1,
    packets: [[0x0357, 0x400000ae]] }])).status, 'PROFILE_UNAVAILABLE');
  const valid = replayWithChunks([{ stream: 1,
    packets: [[0x002d, 0x400000ae]] }]);
  assert.equal(decode(valid).status, 'MISSING_INPUT');
  assert.equal(decode(replayWithChunks([{ stream: 1,
    packets: [[0x002d, 0x400000ae]] }], '16.19.820.7193')).status, 'UNSUPPORTED');
  for (const bad of [
    replayWithChunks([{ stream: 2, packets: [[0x002d, 0x400000ae]] }]),
    replayWithChunks([{ stream: 1, packets: [[0x002d, 0x400001af]] }]),
    replayWithChunks([{ stream: 1, packets: [[0x002d, 0x400000ae,
      Buffer.from('1e26efba46c5', 'hex')]] }]),
    replayWithChunks([{ stream: 1, packets: [[0x002d, 0x400000ae,
      Buffer.from('0026efba46c52c', 'hex')]] }]),
  ]) {
    const result = decode(bad);
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.first_failed_packet_ref.packet_id, 0x002d);
    assert.equal(result.events, null);
  }
  assert.equal(invoked.mock.callCount(), 0);
});

test('821 SetItem rejects forged native binding and incomplete or foreign slot output', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ stream: 1,
    packets: [[0x002d, 0x400000ae]] }]);
  const changes = [
    (output) => { output.results[0].raw_payload_sha256 = '0'.repeat(64); },
    (output) => { output.results[0].bytes_consumed -= 1; },
    (output) => { output.results[0].slot = 7; },
  ];
  for (const change of changes) {
    const mocked = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
      const output = nativeResult(JSON.parse(options.input));
      change(output);
      return { status: 0, stderr: '', stdout: JSON.stringify(output) };
    });
    const result = decode(replay, { runtimeImagePath: image });
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
    assert.equal(result.first_failed_packet_ref.packet_id, 0x002d);
    mocked.mock.restore();
  }
});

test('821 SetItem rejects source mutation and wrong image identity', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ stream: 1,
    packets: [[0x002d, 0x400000ae]] }]);
  const invoked = t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'runtime image SHA-256 mismatch: bad', stdout: '',
  }));
  const mismatch = decode(replay, { runtimeImagePath: image });
  assert.equal(mismatch.status, 'DECODE_FAILED');
  assert.equal(mismatch.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(invoked.mock.callCount(), 1);
  replay.buffer[0] ^= 1;
  assert.match(decode(replay, { runtimeImagePath: image }).error, /source integrity/);
  assert.equal(invoked.mock.callCount(), 1);
});

test('821 SetItem scan caps a source-bound batch before invoking runtime', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ stream: 1,
    packets: Array.from({ length: 257 }, () => [0x002d, 0x400000ae]) }]);
  const token = collect821Routes(replay, ['hero_inventory_set_item_packet']);
  const invoked = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime should not be invoked');
  });
  const result = decode(replay, { runtimeImagePath: image, precollected: token });
  assert.equal(result.status, 'UNSUPPORTED');
  assert.equal(result.input_count, 257);
  assert.equal(result.events, null);
  assert.equal(invoked.mock.callCount(), 0);
});
