'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { resolveBuildProfile, resolveCapability } = require('../src/build_registry');
const { capabilityQuery, parseOne } = require('../src/cli');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { collect821Routes, rowsFor821Capability } =
  require('../src/decoders/rofl_16_19_821_scan');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(length, rawParam = 0x400000ae) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(length, 5);
  header.writeUInt16LE(0x040a, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, Buffer.alloc(length, 0x4a)]);
}

function replay(lengths = [17, 17, 16]) {
  return replayFromChunks([{
    stream: 1,
    body: Buffer.concat(lengths.map((length, index) =>
      packet(length, 0x400000ae + index))),
  }], BUILD);
}

function nativeResult(request, childIds = [0x0107, 0x0101]) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, inputIndex) => {
      const childId = childIds[inputIndex];
      const blob = Buffer.alloc(8);
      blob.writeUInt32LE(469, 0);
      blob.writeUInt32LE(0x40000088 + inputIndex, 4);
      return {
        status: childId === 0x0107 ? 'DECODED' : 'EXCLUDED_CHILD',
        input_index: inputIndex,
        raw_param: row.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 1, bytes_consumed: 17,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: childId,
        raw_event_id_hex: childId === 0x0107 ? '0x09e8' : '0x0909',
        event_blob_length: 8,
        event_blob_hex: blob.toString('hex'),
        event_blob_sha256: crypto.createHash('sha256').update(blob).digest('hex'),
        event_schema_u32_0x00: 469,
        event_u32_0x04: 0x40000088 + inputIndex,
      };
    }),
  };
}

test('821 turret plate event registry and shared scan keep the exact parent shape', () => {
  const input = replay();
  assert.equal(resolveBuildProfile(input).status, 'SUPPORTED');
  assert.equal(resolveCapability(BUILD, 'turret_plate_event_packet').status, 'CANDIDATE');
  const queried = capabilityQuery(input).capabilities.find((row) =>
    row.capability === 'turret_plate_event_packet');
  assert.equal(queried.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.equal(queried.output, 'turret_plate_event_packet_candidates');
  const scan = collect821Routes(input, ['turret_plate_event_packet']);
  assert.deepEqual(rowsFor821Capability(input, scan, 'turret_plate_event_packet')
    .rows.map((row) => row.block.payload_length), [17, 17]);
});

test('821 turret plate event API and CLI report target count separately from controls', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-turret-entry-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'sample.rofl');
  const imagePath = path.join(directory, 'image.bin');
  const input = replay();
  fs.writeFileSync(filePath, input.buffer);
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  const missing = decodeSemanticReplay(input, {
    capabilities: ['turret_plate_event_packet'],
  });
  assert.equal(missing.capability_results.turret_plate_event_packet.status, 'MISSING_INPUT');
  assert.equal(missing.events, null);

  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_turret_plate_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.deepEqual(request.packets.map((row) => row.payload_hex.length / 2), [17, 17]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const decoded = decodeSemanticReplay(input, {
    capabilities: ['turret_plate_event_packet'], runtimeImagePath: imagePath,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.decoded_packet_count, 1);
  const result = decoded.capability_results.turret_plate_event_packet;
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.target_packet_count, 1);
  assert.equal(result.same_length_control_count, 1);
  assert.deepEqual(result.same_length_control_ids, { '0x0101': 1 });
  assert.deepEqual(Object.keys(decoded.events), ['turret_plate_event_packet_candidates']);
  assert.equal(decoded.events.turret_plate_event_packet_candidates.length, 1);
  assert.equal(decoded.events.turret_plate_event_packet_candidates[0].event_u32_0x04,
    0x40000088);

  const parsed = parseOne(filePath, {
    semantic: true, events: ['turret_plate_event_packet'],
    runtimeImage: imagePath, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.decoded_packet_count, 1);
  assert.equal(parsed.analysis.semantic.capability_results.turret_plate_event_packet.status,
    'CANDIDATE');
  assert.deepEqual(Object.keys(parsed.analysis.events),
    ['turret_plate_event_packet_candidates']);
  assert.equal(parsed.analysis.events.turret_plate_event_packet_candidates[0].event_name,
    'OnTurretPlateDestroyed');
  assert.equal(native.mock.callCount(), 2);
});

test('821 turret plate event foreign child alone stays unavailable in selected API', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-turret-control-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const imagePath = path.join(directory, 'image.bin');
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => ({
    status: 0, stderr: '',
    stdout: JSON.stringify(nativeResult(JSON.parse(options.input), [0x0101])),
  }));
  const decoded = decodeSemanticReplay(replay([17]), {
    capabilities: ['turret_plate_event_packet'], runtimeImagePath: imagePath,
  });
  assert.equal(decoded.capability_results.turret_plate_event_packet.status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decoded.capability_results.turret_plate_event_packet.same_length_control_count,
    1);
  assert.equal(decoded.decoded_packet_count, 0);
  assert.equal(decoded.events, null);
});
