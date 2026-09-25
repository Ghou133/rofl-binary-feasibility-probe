'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayBuffer } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { parseOne } = require('../src/cli');
const { decodeSemanticReplay } = require('../src/semantic_api');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const CAPABILITIES = ['hero_death', 'champion_die_event_packet',
  'champion_multiple_kill_event_packet', 'champion_double_kill_event_packet'];
const ASSOCIATION = 'champion_double_kill_multi_group';
const EVENT_KEY = 'champion_double_kill_multi_group_candidates';
const SOURCE_RAW = 0x400000b3;
const VICTIM_RAW = 0x400000ae;

function hash(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packet(packetId, rawParam, payload, timeMs = 1000) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replay() {
  const paired = Buffer.alloc(13);
  paired.set(Buffer.from('3678', 'hex'), paired.length - 2);
  const body = Buffer.concat([
    packet(0x040a, VICTIM_RAW, Buffer.alloc(116, 0x11)),
    packet(0x040a, SOURCE_RAW, Buffer.alloc(104, 0x22)),
    packet(0x040a, SOURCE_RAW, Buffer.alloc(88, 0x33)),
    packet(0x031b, 0, Buffer.alloc(12, 0x44)),
    packet(0x0259, VICTIM_RAW, Buffer.alloc(5, 0x55)),
    packet(0x0438, VICTIM_RAW, paired),
  ]);
  const original = replayFromChunks([{ stream: 1, body }], BUILD);
  const stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index === 0 ? '1' : '0',
    CHAMPIONS_KILLED: index === 5 ? '1' : '0',
  }));
  const trailerOffset = original.buffer.length - 4;
  const metadataOffset = trailerOffset - original.buffer.readUInt32LE(trailerOffset);
  const metadata = Buffer.from(JSON.stringify({ gameLength: 600000,
    statsJson: JSON.stringify(stats) }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  const bytes = Buffer.concat([original.buffer.subarray(0, metadataOffset),
    metadata, trailer]);
  return parseReplayBuffer(bytes, 'synthetic-double-group.rofl');
}

function nativeOutput(script, request) {
  const isDie = /decode_champion_die_event_packet_16_19_821\.py$/.test(script);
  const isMulti = /decode_champion_multiple_kill_event_packet_16_19_821\.py$/.test(script);
  const isDouble = /decode_champion_double_kill_event_packet_16_19_821\.py$/.test(script);
  assert.equal([isDie, isMulti, isDouble].filter(Boolean).length, 1);
  const length = isDie ? 116 : isMulti ? 88 : 104;
  const blob = Buffer.alloc(isDie ? 108 : isMulti ? 80 : 96);
  if (isDie) blob.writeUInt32LE(SOURCE_RAW, 0x04);
  if (isMulti) {
    blob.writeUInt32LE(469, 0);
    blob.writeUInt32LE(VICTIM_RAW, 0x04);
    blob.writeUInt32LE(2, 0x08);
    blob.writeUInt32LE(1, 0x0c);
    blob.writeUInt32LE(0x400000b7, 0x10);
  }
  return { status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, inputIndex) => {
      assert.equal(row.payload_hex.length / 2, length);
      const common = {
        status: 'DECODED', input_index: inputIndex, raw_param: row.raw_param,
        raw_payload_sha256: hash(Buffer.from(row.payload_hex, 'hex')),
        deserialize_return_al: 1, bytes_consumed: length,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: isDie ? 0x0004 : isMulti ? 0x0009 : 0x000b,
        raw_event_id_hex: isDie ? '0x4948' : isMulti ? '0x4989' : '0x4968',
        event_blob_length: blob.length, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: hash(blob),
      };
      if (isDie) return { ...common, event_u32_0x04: SOURCE_RAW };
      if (isMulti) return { ...common, event_u32_0x04: VICTIM_RAW,
        event_u32_0x08: 2, event_u32_0x0c: 1,
        event_u32_list_0x10: [0x400000b7] };
      return common;
    }) };
}

test('821 selected API and CLI expose only an exact-image double-kill packet group candidate', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-double-group-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const replayPath = path.join(directory, 'sample.rofl');
  const imagePath = path.join(directory, 'image.bin');
  const input = replay();
  fs.writeFileSync(replayPath, input.buffer);
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.equal(args[3], path.resolve(imagePath));
    return { status: 0, stderr: '',
      stdout: JSON.stringify(nativeOutput(args[1], JSON.parse(options.input))) };
  });

  const decoded = decodeSemanticReplay(input, {
    capabilities: CAPABILITIES, runtimeImagePath: imagePath,
  });
  assert.equal(decoded.candidate_associations[ASSOCIATION].status, 'CANDIDATE');
  assert.equal(decoded.candidate_associations[ASSOCIATION].pair_count, 1);
  assert.equal(decoded.candidate_associations[ASSOCIATION]
    .matched_multi_u32_0x08_2_count, 1);
  assert.equal(decoded.events[EVENT_KEY].length, 1);
  const group = decoded.events[EVENT_KEY][0];
  assert.equal(group.on_champion_double_kill_registered_event_name,
    'OnChampionDoubleKill');
  assert.equal(group.on_champion_multiple_kill_opaque_u32_0x08, 2);
  assert.equal(group.replay_sha256, input.source_sha256);
  assert.deepEqual(group.raw_packet_refs.map((ref) => ref.packet_id),
    [0x040a, 0x040a, 0x040a, 0x031b, 0x0259, 0x0438]);
  for (const unverified of ['effective_double_kill', 'killer_participant_id',
    'victim_participant_id']) assert.equal(Object.hasOwn(group, unverified), false);

  const parsed = parseOne(replayPath, {
    semantic: true, events: CAPABILITIES, runtimeImage: imagePath,
    strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.candidate_associations[ASSOCIATION].status,
    'CANDIDATE');
  assert.equal(parsed.analysis.events[EVENT_KEY].length, 1);
  assert.equal(parsed.analysis.events[EVENT_KEY][0].raw_packet_ref.replay_sha256,
    input.source_sha256);
  assert.equal(native.mock.callCount(), 6);
});

test('821 double-kill group requires all four selected routes', () => {
  const decoded = decodeSemanticReplay(replay(), {
    capabilities: CAPABILITIES.filter((name) =>
      name !== 'champion_double_kill_event_packet'),
  });
  assert.equal(Object.hasOwn(decoded.candidate_associations ?? {}, ASSOCIATION), false);
  assert.equal(Object.hasOwn(decoded.events ?? {}, EVENT_KEY), false);
});

test('821 double-kill group has no derived rows without the pinned runtime image', (t) => {
  const input = replay();
  const missing = decodeSemanticReplay(input, { capabilities: CAPABILITIES });
  assert.equal(missing.candidate_associations[ASSOCIATION].status, 'MISSING_INPUT');
  assert.equal(Object.hasOwn(missing.events ?? {}, EVENT_KEY), false);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-double-bad-image-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const wrongImagePath = path.join(directory, 'wrong-image.bin');
  fs.writeFileSync(wrongImagePath, Buffer.from([9, 9, 9]));
  const native = t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stdout: '', stderr: 'runtime image SHA-256 mismatch',
  }));
  const mismatched = decodeSemanticReplay(input, {
    capabilities: CAPABILITIES, runtimeImagePath: wrongImagePath,
  });
  assert.equal(mismatched.candidate_associations[ASSOCIATION].status,
    'MISSING_INPUT');
  assert.equal(Object.hasOwn(mismatched.events ?? {}, EVENT_KEY), false);
  for (const name of CAPABILITIES.slice(1)) {
    assert.equal(mismatched.capability_results[name].runtime_image_status,
      'HASH_MISMATCH');
  }
  assert.equal(native.mock.callCount(), 3);
});
