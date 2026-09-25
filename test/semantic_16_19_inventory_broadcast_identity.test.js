'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { decodeHeroInventoryBroadcastCandidates } = require('../src/decoders/rofl_16_19_820_7193');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const IMAGE_SHA256 = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';

function broadcastPacket(rawParam) {
  const payload = Buffer.alloc(79);
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x03ef, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

test('Broadcast participant candidates are limited to exact observed raw params', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-broadcast-identity-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const image = path.join(root, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  const params = [
    ...Array.from({ length: 10 }, (_, index) => 0x400000ae + index),
    0x400001b1, 0x400001af, 0x400001b7, 0x400001b0,
    0x400002af, 0x400002b1,
  ];
  const replay = replayFromChunks(params.map((param, index) => ({
    stream: index === 0 ? 2 : 1,
    body: broadcastPacket(param),
  })), BUILD);
  const mock = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    assert.deepEqual(request.packets.map((row) => row.raw_param), params);
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
      results: request.packets.map((row, index) => ({
        status: 'DECODED', input_index: index,
        raw_param: row.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 1,
        bytes_consumed: row.payload_hex.length / 2,
        record_count: 1,
        records: [{ record_index: 0, slot: 7, item_key_u32: 2001, flag: 1,
          raw_slot_byte_hex: '02', raw_flag_byte_hex: 'bd',
          raw_item_key_bytes_hex: '7fd5fcfc' }],
      })),
    }) };
  });

  const result = decodeHeroInventoryBroadcastCandidates(replay, null,
    { runtimeImagePath: image });
  assert.equal(result.status, 'CANDIDATE');
  assert.match(result.profile_id, /inventory-broadcast-runtime-candidate-v4$/);
  assert.equal(result.input_count, 16);
  assert.equal(result.event_count, 16);
  assert.equal(result.unmapped_raw_param_count, 4);
  assert.deepEqual(result.events.map((row) => row.participant_id_candidate),
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 4, 2, null, null, null, null]);
  assert.deepEqual(result.events.map((row) => row.field_confidence.participant_id_candidate),
    [...Array(12).fill('CANDIDATE'), ...Array(4).fill('UNAVAILABLE')]);
  assert.deepEqual(result.events.map((row) => row.raw_param), params);
  assert.deepEqual(result.events.map((row) => row.raw_packet_ref.raw_param), params);
  assert.equal(result.events[11].raw_packet_ref.packet_id, 0x03ef);
  assert.equal(result.events[11].raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(Buffer.alloc(79)).digest('hex'));
  assert.equal(result.events[11].semantic_status,
    'CANDIDATE_EXACT_RUNTIME_BROADCAST_THREE_REPLAYS');
  assert.ok(result.events.every((row) =>
    row.raw_packet_ref.replay_sha256 === replay.source_sha256
    && row.raw_packet_ref.packet_id === 0x03ef
    && row.confidence === 'CANDIDATE'
    && row.known_limits.some((limit) => limit.includes('no generic masking rule'))));
  assert.equal(mock.mock.callCount(), 1);
});
