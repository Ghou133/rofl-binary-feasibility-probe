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

function payloadWithRawChildSuffix(suffix) {
  const payload = Buffer.alloc(116, 0xb3);
  payload[0] = 0xf0;
  Buffer.from('1eb9b33d', 'hex').copy(payload, 1);
  Buffer.from(suffix, 'hex').copy(payload, 110);
  return payload;
}

const TARGET = payloadWithRawChildSuffix('247152269586');
const FOREIGN = payloadWithRawChildSuffix('247152269566');

function packet(payload, timeMs = 1000) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x040a, 9);
  header.writeUInt32LE(0x4000008c, 11);
  return Buffer.concat([header, payload]);
}

function replay(payloads) {
  return replayFromChunks([{
    stream: 1, body: Buffer.concat(payloads.map((payload) => packet(payload))),
  }], BUILD);
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, inputIndex) => {
      const blob = Buffer.alloc(108);
      return {
        status: 'DECODED', input_index: inputIndex,
        raw_param: row.raw_param,
        raw_payload_sha256: sha256(Buffer.from(row.payload_hex, 'hex')),
        deserialize_return_al: 1, bytes_consumed: 116,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: 0x003d, raw_event_id_hex: '0x4986',
        event_blob_length: 108, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: sha256(blob),
      };
    }),
  };
}

test('821 OnTurretFirstBlood registry and shared scan expose the exact candidate route', () => {
  const input = replay([TARGET, FOREIGN, Buffer.alloc(20)]);
  assert.equal(resolveBuildProfile(input).status, 'SUPPORTED');
  assert.equal(resolveCapability(BUILD, 'turret_first_blood_event_packet').status,
    'CANDIDATE');
  const queried = capabilityQuery(input).capabilities.find((row) =>
    row.capability === 'turret_first_blood_event_packet');
  assert.equal(queried.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.equal(queried.output, 'turret_first_blood_event_packet_candidates');
  const scan = collect821Routes(input,
    ['turret_first_blood_event_packet', 'turret_die_event_packet']);
  assert.deepEqual(rowsFor821Capability(input, scan, 'turret_first_blood_event_packet')
    .rows.map((row) => row.block.payload_length), [116, 116]);
  assert.deepEqual(rowsFor821Capability(input, scan, 'turret_die_event_packet')
    .rows.map((row) => row.block.payload_length), [116, 116]);
});

test('821 OnTurretFirstBlood API and CLI emit only native target and preserve controls', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-turret-first-entry-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'sample.rofl');
  const absentPath = path.join(directory, 'absent.rofl');
  const imagePath = path.join(directory, 'image.bin');
  const input = replay([TARGET, FOREIGN]);
  fs.writeFileSync(filePath, input.buffer);
  fs.writeFileSync(absentPath, replay([FOREIGN]).buffer);
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));

  const missing = decodeSemanticReplay(input, {
    capabilities: ['turret_first_blood_event_packet'],
  });
  assert.equal(missing.capability_results.turret_first_blood_event_packet.status,
    'MISSING_INPUT');
  assert.equal(missing.events, null);

  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_turret_first_blood_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.deepEqual(request.packets.map((row) => row.payload_hex),
      [TARGET.toString('hex')]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const decoded = decodeSemanticReplay(input, {
    capabilities: ['turret_first_blood_event_packet'], runtimeImagePath: imagePath,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.turret_first_blood_event_packet.runtime_image_status,
    'MATCHED_USED');
  assert.equal(decoded.capability_results.turret_first_blood_event_packet
    .excluded_same_length_foreign_count, 1);
  assert.equal(decoded.events.turret_first_blood_event_packet_candidates.length, 1);

  const parsed = parseOne(filePath, {
    semantic: true, events: ['turret_first_blood_event_packet'],
    runtimeImage: imagePath, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.capability_results.turret_first_blood_event_packet.status,
    'CANDIDATE');
  assert.deepEqual(Object.keys(parsed.analysis.events),
    ['turret_first_blood_event_packet_candidates']);
  assert.equal(parsed.analysis.events.turret_first_blood_event_packet_candidates[0].event_name,
    'OnTurretFirstBlood');
  assert.equal(native.mock.callCount(), 2);

  const absent = parseOne(absentPath, {
    semantic: true, events: ['turret_first_blood_event_packet'],
    runtimeImage: imagePath, strict: true, timelineLimit: 0,
  });
  assert.equal(absent.ok, true);
  assert.equal(absent.analysis.semantic.capability_results.turret_first_blood_event_packet.status,
    'PROFILE_UNAVAILABLE');
  assert.equal(absent.analysis.semantic.capability_results.turret_first_blood_event_packet.event_count,
    null);
  assert.deepEqual(Object.keys(absent.analysis.events), []);
  assert.equal(native.mock.callCount(), 2);
});
