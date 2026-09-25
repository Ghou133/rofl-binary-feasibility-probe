'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { parseOne } = require('../src/cli');
const { decodeSemanticReplay } = require('../src/semantic_api');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const SELECTED = ['turret_die_event_packet', 'turret_first_blood_event_packet'];

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function targetPayload(suffix) {
  const payload = Buffer.alloc(116, 0xb3);
  payload[0] = 0xf0;
  Buffer.from('1eb9b33d', 'hex').copy(payload, 1);
  Buffer.from(suffix, 'hex').copy(payload, 110);
  return payload;
}

const DIE = targetPayload('247152269566');
const FIRST = targetPayload('247152269586');

function packet(packetId, rawParam, payload, timeMs = 1000) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replay({ interveningOnEvent = false } = {}) {
  const body = Buffer.concat([
    packet(0x040a, 0x400000b3, DIE),
    interveningOnEvent
      ? packet(0x040a, 0x400000b4, Buffer.alloc(20, 0x04))
      : packet(0x0259, 0x400000b2, Buffer.alloc(7, 0x59)),
    packet(0x040a, 0x400001bc, FIRST),
  ]);
  return replayFromChunks([{ stream: 1, body }], BUILD);
}

function nativeResult(request, childId) {
  const blob = Buffer.alloc(108, childId);
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, inputIndex) => ({
      status: 'DECODED', input_index: inputIndex,
      raw_param: row.raw_param,
      raw_payload_sha256: sha256(Buffer.from(row.payload_hex, 'hex')),
      deserialize_return_al: 1, bytes_consumed: 116,
      native_packet_id: 0x040a, native_raw_param: row.raw_param,
      event_id: childId, raw_event_id_hex: childId === 0x003b ? '0x4966' : '0x4986',
      event_blob_length: 108, event_blob_hex: blob.toString('hex'),
      event_blob_sha256: sha256(blob),
    })),
  };
}

test('821 selected turret packet routes derive a candidate pair in API and CLI', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-turret-pair-entry-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const imagePath = path.join(directory, 'image.bin');
  const replayPath = path.join(directory, 'sample.rofl');
  const input = replay();
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  fs.writeFileSync(replayPath, input.buffer);

  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    const childId = /decode_turret_die_event_packet_16_19_821\.py$/.test(args[1])
      ? 0x003b : /decode_turret_first_blood_event_packet_16_19_821\.py$/.test(args[1])
        ? 0x003d : null;
    assert.ok(childId, `unexpected native helper: ${args[1]}`);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.deepEqual(request.packets.map((row) => row.payload_hex),
      [(childId === 0x003b ? DIE : FIRST).toString('hex')]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request, childId)) };
  });

  const decoded = decodeSemanticReplay(input, {
    capabilities: SELECTED, runtimeImagePath: imagePath,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.turret_die_event_packet.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.turret_first_blood_event_packet.status, 'CANDIDATE');
  assert.equal(decoded.candidate_associations.turret_first_blood_die_pair.status, 'CANDIDATE');
  assert.equal(decoded.candidate_associations.turret_first_blood_die_pair.pair_count, 1);
  assert.equal(decoded.candidate_associations.turret_first_blood_die_pair.turret_die_count, 1);
  assert.equal(decoded.events.turret_die_event_packet_candidates.length, 1);
  assert.equal(decoded.events.turret_first_blood_event_packet_candidates.length, 1);
  assert.equal(decoded.events.turret_first_blood_die_pair_candidates.length, 1);
  const pair = decoded.events.turret_first_blood_die_pair_candidates[0];
  assert.equal(pair.confidence, 'CANDIDATE');
  assert.equal(pair.intervening_on_event_count, 0);
  assert.equal(pair.turret_die_raw_param, 0x400000b3);
  assert.equal(pair.turret_first_blood_raw_param, 0x400001bc);
  assert.deepEqual(pair.raw_packet_refs, [
    decoded.events.turret_die_event_packet_candidates[0].raw_packet_ref,
    decoded.events.turret_first_blood_event_packet_candidates[0].raw_packet_ref,
  ]);

  const parsed = parseOne(replayPath, {
    semantic: true, events: SELECTED, runtimeImage: imagePath,
    strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.candidate_associations
    .turret_first_blood_die_pair.status, 'CANDIDATE');
  assert.equal(parsed.analysis.events.turret_first_blood_die_pair_candidates.length, 1);
  assert.equal(parsed.analysis.event_counts.turret_first_blood_die_pair_candidates, 1);

  const onlyDie = decodeSemanticReplay(input, {
    capabilities: ['turret_die_event_packet'], runtimeImagePath: imagePath,
  });
  assert.equal(onlyDie.candidate_associations.turret_first_blood_die_pair, undefined);
  assert.equal(onlyDie.events.turret_first_blood_die_pair_candidates, undefined);
  assert.equal(onlyDie.events.turret_die_event_packet_candidates.length, 1);

  const intervened = decodeSemanticReplay(replay({ interveningOnEvent: true }), {
    capabilities: SELECTED, runtimeImagePath: imagePath,
  });
  assert.equal(intervened.candidate_associations.turret_first_blood_die_pair.status,
    'INCONSISTENT');
  assert.equal(intervened.events.turret_first_blood_die_pair_candidates, undefined);
  assert.equal(intervened.events.turret_die_event_packet_candidates.length, 1);
  assert.equal(intervened.events.turret_first_blood_event_packet_candidates.length, 1);
  assert.equal(native.mock.callCount(), 7);
});
