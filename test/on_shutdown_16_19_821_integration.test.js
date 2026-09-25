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

function replay() {
  return replayFromChunks([
    { stream: 1, body: Buffer.concat([packet(105), packet(104)]) },
  ], BUILD);
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, inputIndex) => {
      const blob = Buffer.alloc(96);
      blob.writeUInt32LE(0x400000b4, 0x04);
      blob.writeUInt32LE(63, 0x58);
      blob.writeUInt32LE(0xe3f7fb9c, 0x5c);
      return {
        status: 'DECODED', input_index: inputIndex,
        raw_param: row.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 1, bytes_consumed: 105,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: 0x00e8, raw_event_id_hex: '0x49af',
        event_blob_length: 96, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: crypto.createHash('sha256').update(blob).digest('hex'),
        event_u32_0x04: 0x400000b4,
        event_u32_0x58: 63,
        event_u32_0x5c: 0xe3f7fb9c,
      };
    }),
  };
}

test('821 OnShutdown registry, preflight, and shared scan select the exact packet route', () => {
  const input = replay();
  assert.equal(resolveBuildProfile(input).status, 'SUPPORTED');
  assert.equal(resolveCapability(BUILD, 'on_shutdown_event_packet').status, 'CANDIDATE');
  const queried = capabilityQuery(input).capabilities.find((row) =>
    row.capability === 'on_shutdown_event_packet');
  assert.equal(queried.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.equal(queried.output, 'on_shutdown_event_packet_candidates');
  const scan = collect821Routes(input,
    ['on_shutdown_event_packet', 'champion_kill_event_packet']);
  assert.deepEqual(rowsFor821Capability(input, scan, 'on_shutdown_event_packet')
    .rows.map((row) => row.block.payload_length), [105]);
  assert.deepEqual(rowsFor821Capability(input, scan, 'champion_kill_event_packet')
    .rows.map((row) => row.block.payload_length), [104]);
});

test('821 OnShutdown API and CLI emit only selected native candidate rows', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-shutdown-entry-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'sample.rofl');
  const imagePath = path.join(directory, 'image.bin');
  const input = replay();
  fs.writeFileSync(filePath, input.buffer);
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  const missing = decodeSemanticReplay(input, {
    capabilities: ['on_shutdown_event_packet'],
  });
  assert.equal(missing.capability_results.on_shutdown_event_packet.status, 'MISSING_INPUT');
  assert.equal(missing.events, null);
  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_on_shutdown_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.deepEqual(request.packets.map((row) => row.payload_hex.length / 2), [105]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const decoded = decodeSemanticReplay(input, {
    capabilities: ['on_shutdown_event_packet'], runtimeImagePath: imagePath,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.on_shutdown_event_packet.runtime_image_status,
    'MATCHED_USED');
  assert.equal(decoded.events.on_shutdown_event_packet_candidates.length, 1);
  const parsed = parseOne(filePath, {
    semantic: true, events: ['on_shutdown_event_packet'],
    runtimeImage: imagePath, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.capability_results.on_shutdown_event_packet.status,
    'CANDIDATE');
  assert.deepEqual(Object.keys(parsed.analysis.events),
    ['on_shutdown_event_packet_candidates']);
  assert.equal(parsed.analysis.events.on_shutdown_event_packet_candidates.length, 1);
  assert.equal(parsed.analysis.events.on_shutdown_event_packet_candidates[0]
    .registered_event_name, 'OnShutdown');
  assert.equal(native.mock.callCount(), 2);
});
