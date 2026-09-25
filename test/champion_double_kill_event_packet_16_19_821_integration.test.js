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
const CAPABILITY = 'champion_double_kill_event_packet';
const EVENT_KEY = `${CAPABILITY}_candidates`;
const RAW_IDS = { 0x0007: '0x49e8', 0x000b: '0x4968',
  0x000c: '0x49c8', 0x000d: '0x4988' };

function packet(length, rawParam) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(length, 5);
  header.writeUInt16LE(0x040a, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, Buffer.alloc(length, 0x4a)]);
}

function replay(lengths = [104, 104, 104, 104, 88]) {
  return replayFromChunks([{ stream: 1,
    body: Buffer.concat(lengths.map((length, index) =>
      packet(length, 0x400000ae + index))) }], BUILD);
}

function hash(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function nativeResult(request, childIds = [0x000b, 0x0007, 0x000c, 0x000d]) {
  return { status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => {
      const child = childIds[index];
      const blob = Buffer.alloc(96, child & 0xff);
      return {
        status: child === 0x000b ? 'DECODED' : 'EXCLUDED_CHILD',
        input_index: index, raw_param: row.raw_param,
        raw_payload_sha256: hash(Buffer.from(row.payload_hex, 'hex')),
        deserialize_return_al: 1, bytes_consumed: 104,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: child, raw_event_id_hex: RAW_IDS[child],
        event_blob_length: 96, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: hash(blob),
      };
    }) };
}

test('821 double-kill marker registry and shared scan select only its parent shape', () => {
  const input = replay();
  assert.equal(resolveBuildProfile(input).status, 'SUPPORTED');
  assert.equal(resolveCapability(BUILD, CAPABILITY).status, 'CANDIDATE');
  const queried = capabilityQuery(input).capabilities.find((row) =>
    row.capability === CAPABILITY);
  assert.equal(queried.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.equal(queried.output, EVENT_KEY);
  const scan = collect821Routes(input, [CAPABILITY]);
  assert.deepEqual(rowsFor821Capability(input, scan, CAPABILITY)
    .rows.map((row) => row.block.payload_length), [104, 104, 104, 104]);
});

test('821 double-kill marker selected API and CLI preserve child controls and raw provenance', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-double-entry-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'sample.rofl');
  const imagePath = path.join(directory, 'image.bin');
  const input = replay();
  fs.writeFileSync(filePath, input.buffer);
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));

  const missing = decodeSemanticReplay(input, { capabilities: [CAPABILITY] });
  assert.equal(missing.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(missing.events, null);

  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_champion_double_kill_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.deepEqual(request.packets.map((row) => row.payload_hex.length / 2),
      [104, 104, 104, 104]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const decoded = decodeSemanticReplay(input, {
    capabilities: [CAPABILITY], runtimeImagePath: imagePath,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.decoded_packet_count, 1);
  const capability = decoded.capability_results[CAPABILITY];
  assert.equal(capability.status, 'CANDIDATE');
  assert.equal(capability.input_count, 4);
  assert.equal(capability.target_packet_count, 1);
  assert.equal(capability.excluded_child_count, 3);
  assert.deepEqual(capability.excluded_child_ids,
    { '0x0007': 1, '0x000c': 1, '0x000d': 1 });
  assert.deepEqual(Object.keys(decoded.events), [EVENT_KEY]);
  const event = decoded.events[EVENT_KEY][0];
  assert.equal(event.registered_event_name, 'OnChampionDoubleKill');
  assert.equal(event.raw_packet_ref.replay_sha256, input.source_sha256);
  assert.equal(Object.hasOwn(event, 'participant_id_candidate'), false);

  const parsed = parseOne(filePath, {
    semantic: true, events: [CAPABILITY], runtimeImage: imagePath,
    strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.decoded_packet_count, 1);
  assert.equal(parsed.analysis.semantic.capability_results[CAPABILITY].status,
    'CANDIDATE');
  assert.deepEqual(Object.keys(parsed.analysis.events), [EVENT_KEY]);
  assert.equal(parsed.analysis.events[EVENT_KEY][0].registered_event_name,
    'OnChampionDoubleKill');
  assert.equal(native.mock.callCount(), 2);
});

test('821 double-kill foreign child alone stays unavailable in selected API', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-double-control-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const imagePath = path.join(directory, 'image.bin');
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => ({
    status: 0, stderr: '',
    stdout: JSON.stringify(nativeResult(JSON.parse(options.input), [0x0007])),
  }));
  const decoded = decodeSemanticReplay(replay([104]), {
    capabilities: [CAPABILITY], runtimeImagePath: imagePath,
  });
  assert.equal(decoded.capability_results[CAPABILITY].status, 'PROFILE_UNAVAILABLE');
  assert.equal(decoded.capability_results[CAPABILITY].excluded_child_count, 1);
  assert.equal(decoded.decoded_packet_count, 0);
  assert.equal(decoded.events, null);
});
