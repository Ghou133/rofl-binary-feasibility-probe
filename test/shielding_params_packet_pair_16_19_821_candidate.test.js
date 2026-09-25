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
  SHIELDING_PARAMS_PACKET_PAIR_821_PROFILE: profile,
  decodeShieldingParamsPacketPairCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_shielding_params_packet_pair_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const BLOB = Buffer.from('d501000000000000b7000040b700004033331a42', 'hex');

function packet(packetId = 0x040a, rawParam = 0x400000b7, payload = Buffer.alloc(29, 0x4a)) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-shielding-pair-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request, options = {}) {
  const ids = options.ids || [0x00f0, 0x00ef];
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => ({
      status: 'DECODED', input_index: index,
      raw_param: row.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: 29,
      native_packet_id: 0x040a, native_raw_param: row.raw_param,
      event_id: ids[index], raw_event_id_hex: ids[index] === 0x00f0 ? '0x492b' : '0x4951',
      event_blob_length: 20, event_blob_hex: BLOB.toString('hex'),
      event_blob_sha256: crypto.createHash('sha256').update(BLOB).digest('hex'),
      event_schema_u32_0x00: 469, event_reserved_u32_0x04: 0,
      event_u32_0x08: 0x400000b7, event_u32_0x0c: 0x400000b7,
      event_raw_f32_0x10: options.rawFloat ?? 38.54999923706055,
    })),
  };
}

test('821 ShieldingParams pairs distinct raw-param packets and retains both source refs', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [
    packet(0x040a, 0x400000b7),
    packet(0x040a, 0x400001b6, Buffer.alloc(29, 0x4b)),
    packet(0x040a, 0x400000b7, Buffer.alloc(60, 0x4a)),
  ] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_shielding_params_packet_pair_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag,
      row.payload_hex.length / 2]), [[0x040a, 1, 29], [0x040a, 1, 29]]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const shared = collect821Routes(replay, ['shielding_params_packet_pair']);
  const result = decode(replay, { runtimeImagePath: image, precollected: shared });
  assert.equal(profile.capability, 'shielding_params_packet_pair');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 1);
  assert.equal(result.input_packet_scope, 'child_00ef_00f0_length_29');
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].event_type, 'SHIELDING_PARAMS_PACKET_PAIR_CANDIDATE');
  assert.deepEqual(result.events[0].child_event_ids, [0x00f0, 0x00ef]);
  assert.equal(result.events[0].event_u32_0x08, 0x400000b7);
  assert.equal(result.events[0].event_raw_f32_0x10, 38.54999923706055);
  assert.equal(result.events[0].raw_packet_refs.length, 2);
  assert.deepEqual(result.events[0].raw_packet_refs.map((ref) => ref.raw_param),
    [0x400000b7, 0x400001b6]);
  assert.equal(result.events[0].raw_packet_refs[0].replay_sha256, replay.source_sha256);
  assert.equal(result.events[0].raw_packet_refs[1].replay_sha256, replay.source_sha256);
  assert.equal(result.events[0].raw_packet_refs[0].decompressed_block_offset
    < result.events[0].raw_packet_refs[1].decompressed_block_offset, true);
  for (const field of ['shield_generated', 'shield_absorbed', 'effective_shield',
    'source', 'target', 'caster', 'recipient', 'amount']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 ShieldingParams distinguishes absent shape, missing image, wrong build and source corruption', () => {
  const absent = replayWithChunks([{ packets: [packet(0x040a, 0x400000b7,
    Buffer.alloc(60))] }]);
  assert.equal(decode(absent).status, 'PROFILE_UNAVAILABLE');
  const present = replayWithChunks([{ packets: [packet(), packet()] }]);
  const missing = decode(present);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.input_count, 2);
  const wrongBuild = replayWithChunks([{ packets: [packet()] }], '16.19.820.7193');
  assert.equal(decode(wrongBuild).status, 'UNSUPPORTED');
  const mutated = replayWithChunks([{ packets: [packet()] }]);
  mutated.buffer[0] ^= 1;
  assert.equal(decode(mutated).status, 'DECODE_FAILED');
  assert.match(decode(mutated).error, /source integrity/);
});

test('821 ShieldingParams rejects foreign stream and orphan or duplicated child before events', (t) => {
  const image = fakeImage(t);
  const foreign = replayWithChunks([{ stream: 2, packets: [packet()] }]);
  assert.equal(decode(foreign, { runtimeImagePath: image }).status, 'DECODE_FAILED');
  const orphan = replayWithChunks([{ packets: [packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request,
      request.packets.length === 2 ? { ids: [0x00f0, 0x00f0] } : {})) };
  });
  const orphanResult = decode(orphan, { runtimeImagePath: image });
  assert.equal(orphanResult.status, 'DECODE_FAILED');
  assert.equal(orphanResult.events, null);
  assert.match(orphanResult.error, /pair is missing/);
  const duplicate = replayWithChunks([{ packets: [packet(), packet()] }]);
  const duplicateResult = decode(duplicate, { runtimeImagePath: image });
  assert.equal(duplicateResult.status, 'DECODE_FAILED');
  assert.equal(duplicateResult.events, null);
  assert.match(duplicateResult.error, /duplicate ShieldingParams child/);
});

test('821 ShieldingParams rejects a foreign child ID', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet(), packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const response = nativeResult(JSON.parse(options.input), { ids: [0x00f0, 0x00f1] });
    return { status: 0, stderr: '', stdout: JSON.stringify(response) };
  });
  const mixed = decode(replay, { runtimeImagePath: image });
  assert.equal(mixed.status, 'DECODE_FAILED');
  assert.equal(mixed.event_count, null);
  assert.equal(mixed.events, null);
});
