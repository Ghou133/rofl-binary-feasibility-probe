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

function packet(length, streamTime = 1000) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(streamTime / 1000, 1);
  header.writeUInt32LE(length, 5);
  header.writeUInt16LE(0x040a, 9);
  header.writeUInt32LE(0x400000ae, 11);
  return Buffer.concat([header, Buffer.alloc(length, 0x4a)]);
}

function replay(lengths) {
  return replayFromChunks([{
    stream: 1, body: Buffer.concat(lengths.map((length) => packet(length))),
  }], BUILD);
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, inputIndex) => {
      const blob = Buffer.alloc(12);
      blob.writeUInt32LE(45, 0);
      blob.writeUInt32LE(0x400000b4, 4);
      blob.writeUInt32LE(0x400000af, 8);
      return {
        status: 'DECODED', input_index: inputIndex,
        raw_param: row.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 1, bytes_consumed: 20,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: 0x002d, raw_event_id_hex: '0x498a',
        event_blob_length: 12, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: crypto.createHash('sha256').update(blob).digest('hex'),
        event_schema_u32_0x00: 45,
        event_u32_0x04: 0x400000b4,
        event_u32_0x08: 0x400000af,
      };
    }),
  };
}

test('821 OnResurrect registry, preflight, and shared scan select only length-20 route', () => {
  const input = replay([20, 105, 17]);
  assert.equal(resolveBuildProfile(input).status, 'SUPPORTED');
  assert.equal(resolveCapability(BUILD, 'resurrect_event_packet').status, 'CANDIDATE');
  const queried = capabilityQuery(input).capabilities.find((row) =>
    row.capability === 'resurrect_event_packet');
  assert.equal(queried.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.equal(queried.output, 'resurrect_event_packet_candidates');
  const scan = collect821Routes(input,
    ['resurrect_event_packet', 'on_shutdown_event_packet']);
  assert.deepEqual(rowsFor821Capability(input, scan, 'resurrect_event_packet')
    .rows.map((row) => row.block.payload_length), [20]);
  assert.deepEqual(rowsFor821Capability(input, scan, 'on_shutdown_event_packet')
    .rows.map((row) => row.block.payload_length), [105]);
});

test('821 OnResurrect API and CLI emit candidate rows and keep absent route unavailable', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-resurrect-entry-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'sample.rofl');
  const absentPath = path.join(directory, 'absent.rofl');
  const imagePath = path.join(directory, 'image.bin');
  const input = replay([20, 17]);
  fs.writeFileSync(filePath, input.buffer);
  fs.writeFileSync(absentPath, replay([17]).buffer);
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  const missing = decodeSemanticReplay(input, {
    capabilities: ['resurrect_event_packet'],
  });
  assert.equal(missing.capability_results.resurrect_event_packet.status, 'MISSING_INPUT');
  assert.equal(missing.events, null);
  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_resurrect_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.deepEqual(request.packets.map((row) => row.payload_hex.length / 2), [20]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const decoded = decodeSemanticReplay(input, {
    capabilities: ['resurrect_event_packet'], runtimeImagePath: imagePath,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.resurrect_event_packet.runtime_image_status,
    'MATCHED_USED');
  assert.equal(decoded.events.resurrect_event_packet_candidates.length, 1);
  const parsed = parseOne(filePath, {
    semantic: true, events: ['resurrect_event_packet'],
    runtimeImage: imagePath, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.capability_results.resurrect_event_packet.status,
    'CANDIDATE');
  assert.deepEqual(Object.keys(parsed.analysis.events),
    ['resurrect_event_packet_candidates']);
  assert.equal(parsed.analysis.events.resurrect_event_packet_candidates[0]
    .event_name, 'OnResurrect');
  assert.equal(native.mock.callCount(), 2);

  const absent = parseOne(absentPath, {
    semantic: true, events: ['resurrect_event_packet'],
    runtimeImage: imagePath, strict: true, timelineLimit: 0,
  });
  assert.equal(absent.ok, true);
  assert.equal(absent.analysis.semantic.capability_results.resurrect_event_packet.status,
    'PROFILE_UNAVAILABLE');
  assert.equal(absent.analysis.semantic.capability_results.resurrect_event_packet.event_count,
    null);
  assert.deepEqual(Object.keys(absent.analysis.events), []);
  assert.equal(native.mock.callCount(), 2);
});
