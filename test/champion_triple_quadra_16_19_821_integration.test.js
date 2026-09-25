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
  'champion_multiple_kill_event_packet', 'champion_triple_quadra_event_packet'];
const PACKET_CAPABILITY = 'champion_triple_quadra_event_packet';
const PACKET_KEY = 'champion_triple_quadra_event_packet_candidates';
const ASSOCIATION = 'champion_triple_quadra_multi_group';
const GROUP_KEY = 'champion_triple_quadra_multi_group_candidates';
const SOURCE_RAW = 0x400000b3;
const VICTIM_RAWS = [0x400000ae, 0x400000af];
const CHILD_BY_PAYLOAD = new Map([
  [0xcc, [0x000c, '0x49c8']], [0xdd, [0x000d, '0x4988']],
  [0x07, [0x0007, '0x49e8']], [0x0b, [0x000b, '0x4968']],
]);

function hash(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packet(packetId, rawParam, payload, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replay() {
  const body = Buffer.concat(VICTIM_RAWS.flatMap((victimRaw, index) => {
    const timeMs = 1000 * (index + 1);
    const paired = Buffer.alloc(13);
    paired.set(Buffer.from('3678', 'hex'), paired.length - 2);
    return [
      packet(0x040a, victimRaw, Buffer.alloc(116, 0x11), timeMs),
      packet(0x040a, SOURCE_RAW, Buffer.alloc(104, index ? 0xdd : 0xcc), timeMs),
      packet(0x040a, SOURCE_RAW, Buffer.alloc(104, index ? 0x0b : 0x07), timeMs),
      packet(0x040a, SOURCE_RAW, Buffer.alloc(88, index ? 0x44 : 0x33), timeMs),
      packet(0x031b, 0, Buffer.alloc(12, 0x55), timeMs),
      packet(0x0259, victimRaw, Buffer.alloc(5, 0x66), timeMs),
      packet(0x0438, victimRaw, paired, timeMs),
    ];
  }));
  const original = replayFromChunks([{ stream: 1, body }], BUILD);
  const stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index < 2 ? '1' : '0',
    CHAMPIONS_KILLED: index === 5 ? '2' : '0',
  }));
  const trailerOffset = original.buffer.length - 4;
  const metadataOffset = trailerOffset - original.buffer.readUInt32LE(trailerOffset);
  const metadata = Buffer.from(JSON.stringify({ gameLength: 600000,
    statsJson: JSON.stringify(stats) }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  return parseReplayBuffer(Buffer.concat([
    original.buffer.subarray(0, metadataOffset), metadata, trailer,
  ]), 'synthetic-triple-quadra-group.rofl');
}

function nativeOutput(script, request) {
  const isDie = /decode_champion_die_event_packet_16_19_821\.py$/.test(script);
  const isMulti = /decode_champion_multiple_kill_event_packet_16_19_821\.py$/.test(script);
  const isNamed = /decode_champion_triple_quadra_event_packet_16_19_821\.py$/.test(script);
  assert.equal([isDie, isMulti, isNamed].filter(Boolean).length, 1);
  const length = isDie ? 116 : isMulti ? 88 : 104;
  return { status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, inputIndex) => {
      const payload = Buffer.from(row.payload_hex, 'hex');
      assert.equal(payload.length, length);
      const isControl = isNamed && [0x07, 0x0b].includes(payload[0]);
      const child = isDie ? [0x0004, '0x4948']
        : isMulti ? [0x0009, '0x4989'] : CHILD_BY_PAYLOAD.get(payload[0]);
      assert.ok(child);
      const blob = Buffer.alloc(isDie ? 108 : isMulti ? 80 : 96);
      if (isDie) blob.writeUInt32LE(SOURCE_RAW, 0x04);
      if (isMulti) {
        const second = payload[0] === 0x44;
        blob.writeUInt32LE(469, 0);
        blob.writeUInt32LE(VICTIM_RAWS[Number(second)], 0x04);
        blob.writeUInt32LE(second ? 4 : 3, 0x08);
        blob.writeUInt32LE(1, 0x0c);
        blob.writeUInt32LE(0x400000b7, 0x10);
      }
      const common = {
        status: isControl ? 'EXCLUDED_CHILD' : 'DECODED',
        input_index: inputIndex, raw_param: row.raw_param,
        raw_payload_sha256: hash(payload), deserialize_return_al: 1,
        bytes_consumed: length, native_packet_id: 0x040a,
        native_raw_param: row.raw_param, event_id: child[0],
        raw_event_id_hex: child[1], event_blob_length: blob.length,
        event_blob_hex: blob.toString('hex'), event_blob_sha256: hash(blob),
      };
      if (isDie) return { ...common, event_u32_0x04: SOURCE_RAW };
      if (isMulti) return { ...common,
        event_u32_0x04: blob.readUInt32LE(0x04),
        event_u32_0x08: blob.readUInt32LE(0x08),
        event_u32_0x0c: 1, event_u32_list_0x10: [0x400000b7] };
      return common;
    }) };
}

test('821 selected API and CLI expose two exact-image triple/quadra packet groups', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-triple-quadra-'));
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
  const packets = decoded.capability_results[PACKET_CAPABILITY];
  assert.equal(packets.status, 'CANDIDATE');
  assert.equal(packets.input_count, 4);
  assert.equal(packets.target_packet_count, 2);
  assert.equal(packets.excluded_child_count, 2);
  assert.deepEqual(packets.excluded_child_ids,
    { '0x0007': 1, '0x000b': 1 });
  assert.deepEqual(decoded.events[PACKET_KEY].map((row) => row.child_event_id),
    [0x000c, 0x000d]);
  const association = decoded.candidate_associations[ASSOCIATION];
  assert.equal(association.status, 'CANDIDATE');
  assert.equal(association.pair_count, 2);
  assert.equal(association.matched_multi_u32_0x08_3_count, 1);
  assert.equal(association.matched_multi_u32_0x08_4_count, 1);
  assert.equal(association.unmatched_on_champion_triple_quadra_count, 0);
  assert.equal(decoded.events[GROUP_KEY].length, 2);
  assert.deepEqual(decoded.events[GROUP_KEY].map((row) => [
    row.on_champion_triple_quadra_child_event_id,
    row.on_champion_multiple_kill_opaque_u32_0x08,
  ]), [[0x000c, 3], [0x000d, 4]]);
  for (const group of decoded.events[GROUP_KEY]) {
    assert.equal(group.replay_sha256, input.source_sha256);
    assert.deepEqual(group.raw_packet_refs.map((ref) => ref.packet_id),
      [0x040a, 0x040a, 0x040a, 0x031b, 0x0259, 0x0438]);
    for (const unverified of ['effective_triple_kill', 'effective_quadra_kill',
      'killer_participant_id', 'victim_participant_id']) {
      assert.equal(Object.hasOwn(group, unverified), false);
    }
  }

  const parsed = parseOne(replayPath, {
    semantic: true, events: CAPABILITIES, runtimeImage: imagePath,
    strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.candidate_associations[ASSOCIATION].status,
    'CANDIDATE');
  assert.equal(parsed.analysis.events[GROUP_KEY].length, 2);
  assert.deepEqual(parsed.analysis.events[PACKET_KEY].map((row) => row.child_event_id),
    [0x000c, 0x000d]);
  assert.equal(native.mock.callCount(), 6);
});

test('821 triple/quadra packet group requires all four selected routes', () => {
  const decoded = decodeSemanticReplay(replay(), {
    capabilities: CAPABILITIES.filter((name) => name !== PACKET_CAPABILITY),
  });
  assert.equal(Object.hasOwn(decoded.candidate_associations ?? {}, ASSOCIATION), false);
  assert.equal(Object.hasOwn(decoded.events ?? {}, GROUP_KEY), false);
});

test('821 triple/quadra packet group has no derived rows without runtime image', () => {
  const decoded = decodeSemanticReplay(replay(), { capabilities: CAPABILITIES });
  assert.equal(decoded.capability_results[PACKET_CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(decoded.candidate_associations[ASSOCIATION].status, 'MISSING_INPUT');
  assert.equal(Object.hasOwn(decoded.events ?? {}, GROUP_KEY), false);
});
