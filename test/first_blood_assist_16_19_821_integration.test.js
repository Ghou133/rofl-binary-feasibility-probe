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
const TARGET = Buffer.from('d4bdb9b33db3b3b3b37f32eb01e94de4', 'hex');
const FOREIGN = Buffer.from('c0bdb94b3db3b3b3b37f32eb01e94dca', 'hex');

function packet(payload, rawParam = 0x400000b5) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x040a, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replay(payloads) {
  return replayFromChunks([{ stream: 1,
    body: Buffer.concat(payloads.map((payload) => packet(payload))) }], BUILD);
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => {
      const target = row.payload_hex === TARGET.toString('hex');
      const blob = Buffer.from(target ? 'd501000000000000' : 'd5010000b6000040', 'hex');
      return {
        status: target ? 'DECODED' : 'EXCLUDED_CHILD',
        input_index: index, raw_param: row.raw_param,
        raw_payload_sha256: sha256(Buffer.from(row.payload_hex, 'hex')),
        deserialize_return_al: 1, bytes_consumed: 16,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: target ? 0x0017 : 0x002c,
        raw_event_id_hex: target ? '0x49e4' : '0x49ca',
        event_blob_length: 8, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: sha256(blob),
      };
    }),
  };
}

test('821 first-blood-assist capability preflight and shared scan are exact-build', () => {
  const input = replay([TARGET, FOREIGN, Buffer.alloc(20)]);
  assert.equal(resolveBuildProfile(input).status, 'SUPPORTED');
  assert.equal(resolveCapability(BUILD, 'first_blood_assist_event_packet').status,
    'CANDIDATE');
  const queried = capabilityQuery(input).capabilities.find((row) =>
    row.capability === 'first_blood_assist_event_packet');
  assert.equal(queried.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.equal(queried.output, 'first_blood_assist_event_packet_candidates');
  const scan = collect821Routes(input, [
    'first_blood_assist_event_packet', 'revive_ally_event_packet',
  ]);
  assert.deepEqual(rowsFor821Capability(input, scan,
    'first_blood_assist_event_packet').rows.map((row) => row.block.payload_length),
  [16, 16]);
  assert.deepEqual(rowsFor821Capability(input, scan,
    'revive_ally_event_packet').rows.map((row) => row.block.payload_length),
  [16, 16]);
});

test('821 first-blood-assist API and selected CLI output only emit native target', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-first-blood-entry-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const replayPath = path.join(directory, 'sample.rofl');
  const imagePath = path.join(directory, 'image.bin');
  const input = replay([TARGET, FOREIGN]);
  fs.writeFileSync(replayPath, input.buffer);
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));

  const missing = decodeSemanticReplay(input, {
    capabilities: ['first_blood_assist_event_packet'],
  });
  assert.equal(missing.capability_results.first_blood_assist_event_packet.status,
    'MISSING_INPUT');
  assert.equal(missing.events, null);

  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_first_blood_assist_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.deepEqual(request.packets.map((row) => row.payload_hex),
      [TARGET.toString('hex'), FOREIGN.toString('hex')]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const decoded = decodeSemanticReplay(input, {
    capabilities: ['first_blood_assist_event_packet'], runtimeImagePath: imagePath,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.first_blood_assist_event_packet.status,
    'CANDIDATE');
  assert.equal(decoded.events.first_blood_assist_event_packet_candidates.length, 1);
  const parsed = parseOne(replayPath, {
    semantic: true, events: ['first_blood_assist_event_packet'],
    runtimeImage: imagePath, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.capability_results
    .first_blood_assist_event_packet.status, 'CANDIDATE');
  assert.deepEqual(Object.keys(parsed.analysis.events),
    ['first_blood_assist_event_packet_candidates']);
  const event = parsed.analysis.events.first_blood_assist_event_packet_candidates[0];
  assert.equal(event.registered_event_name, 'OnFirstBloodAssist');
  assert.equal(event.child_event_id, 0x0017);
  assert.equal(event.raw_packet_ref.packet_id, 0x040a);
  assert.equal(native.mock.callCount(), 2);
});
