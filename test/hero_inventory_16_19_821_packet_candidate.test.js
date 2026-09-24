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
  HERO_INVENTORY_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeHeroInventoryPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_inventory_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const PAYLOAD = Buffer.concat([Buffer.from([0x1e]), Buffer.alloc(22)]);

function packet(packetId, rawParam, payload = PAYLOAD) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replayWithPackets(rows, build = BUILD) {
  return replayFromChunks([{
    body: Buffer.concat(rows.map(([id, param, payload]) => packet(id, param, payload))),
  }], build);
}

function fakeImage(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-mapview-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const image = path.join(dir, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request, recordsByPacket) {
  return {
    status: 'PASS',
    runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => ({
      status: 'DECODED',
      input_index: index,
      raw_param: row.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1,
      bytes_consumed: row.payload_hex.length / 2,
      record_count: recordsByPacket[index].length,
      records: recordsByPacket[index],
    })),
  };
}

function record(index, slot, itemId) {
  return {
    record_index: index, slot, item_id: itemId,
    raw_slot_byte_hex: slot === 0 ? 'c1' : '15',
    raw_item_id_bytes_hex: 'f248eaea',
  };
}

test('821 MapView emits packet-bound candidates and leaves observed raw-param variants unmapped', (t) => {
  const image = fakeImage(t);
  const replay = replayWithPackets([
    [0x018d, 0x400000ae],
    [0x018d, 0x400001b2],
  ]);
  const token = collect821Routes(replay, ['hero_inventory_packet']);
  let invocations = 0;
  t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    invocations += 1;
    assert.match(args[1], /decode_mapview_inventory_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => row.raw_param),
      [0x400000ae, 0x400001b2]);
    return {
      status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request, [
        [record(0, 0, 1001), record(1, 1, 2031)],
        [record(0, 0, 1001), record(1, 1, 2031)],
      ])),
    };
  });
  const result = decode(replay, { runtimeImagePath: image, precollected: token });
  assert.equal(profile.packet_name, 'PKT_S2C_SetInventory_MapView_s');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.runtime_image_used, true);
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.decoded_record_count, 4);
  assert.equal(result.events[0].participant_id_candidate, 1);
  assert.equal(result.events[1].participant_id_candidate, null);
  assert.equal(result.events[1].field_confidence.participant_id_candidate, 'UNAVAILABLE');
  assert.equal(result.events[0].records_candidate[1].item_id_candidate, 2031);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[1].raw_packet_ref.raw_param, 0x400001b2);
  assert.equal(result.unmapped_raw_param_count, 1);
  assert.equal(result.unmapped_raw_packet_refs[0].raw_param, 0x400001b2);
  assert.equal(invocations, 1);
});

test('821 MapView falls back to one bound scan and reports absent route before image access', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime should not be invoked');
  });
  const replay = replayWithPackets([[0x0048, 0x400000ae]]);
  const result = decode(replay);
  assert.equal(result.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.input_count, null);
  assert.equal(result.observed_raw_route_count, 0);
  assert.equal(result.runtime_image_used, false);
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 MapView fails closed on an unobserved raw param with a source reference', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime should not be invoked');
  });
  const replay = replayWithPackets([[0x018d, 0x400001b3]]);
  const result = decode(replay);
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.input_count, 1);
  assert.equal(result.first_failed_packet_ref.raw_param, 0x400001b3);
  assert.equal(result.runtime_image_used, false);
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 MapView requires the exact Replay build and an image for present packets', () => {
  const older = replayWithPackets([[0x018d, 0x400000ae]], '16.19.820.7193');
  assert.equal(decode(older).status, 'UNSUPPORTED');
  const replay = replayWithPackets([[0x018d, 0x400000ae]]);
  const missing = decode(replay);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.runtime_image_status, 'MISSING');
  assert.equal(missing.runtime_image_used, false);
});

test('821 MapView rejects a changed Replay source before invoking runtime', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime should not be invoked');
  });
  const replay = replayWithPackets([[0x018d, 0x400000ae]]);
  const token = collect821Routes(replay, ['hero_inventory_packet']);
  replay.buffer[0] ^= 1;
  const result = decode(replay, { precollected: token });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.match(result.error, /source integrity/);
  assert.equal(result.runtime_image_used, false);
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 MapView reports wrong image identity as a local failure', (t) => {
  const image = fakeImage(t);
  t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1,
    stderr: '821 MapView exact-runtime decoder error: runtime image SHA-256 mismatch: bad',
    stdout: '',
  }));
  const replay = replayWithPackets([[0x018d, 0x400000ae]]);
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(result.runtime_image_used, false);
  assert.equal(result.event_count, null);
});

test('821 MapView rejects native output with mismatched source binding or trailing bytes', (t) => {
  const image = fakeImage(t);
  const replay = replayWithPackets([[0x018d, 0x400000ae]]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input), [
      [record(0, 0, 1001), record(1, 1, 2031)],
    ]);
    output.results[0].bytes_consumed -= 1;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.first_failed_packet_ref.packet_id, 0x018d);
  assert.equal(result.event_count, null);
  assert.equal(invoke.mock.callCount(), 1);
  invoke.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input), [
      [record(0, 0, 1001), record(1, 1, 2031)],
    ]);
    output.results[0].raw_payload_sha256 = '0'.repeat(64);
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const changed = decode(replay, { runtimeImagePath: image });
  assert.equal(changed.status, 'DECODE_FAILED');
  assert.equal(changed.event_count, null);
});

test('821 MapView rejects repeated native slots without partial events', (t) => {
  const image = fakeImage(t);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => ({
    status: 0,
    stderr: '',
    stdout: JSON.stringify(nativeResult(JSON.parse(options.input), [
      [record(0, 0, 1001), record(1, 0, 2031)],
    ])),
  }));
  const result = decode(replayWithPackets([[0x018d, 0x400000ae]]),
    { runtimeImagePath: image });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.event_count, null);
  assert.equal(result.events, null);
});
