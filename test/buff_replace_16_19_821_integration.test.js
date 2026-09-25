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
const { NPC_BUFF_REPLACE_PACKET_CANDIDATE_PROFILE_821: profile } =
  require('../src/decoders/rofl_16_19_821_buff_replace_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(packetId, length, rawParam = 0x400000ae) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, Buffer.alloc(length, 0x4a)]);
}

function replay(packets) {
  return replayFromChunks([{
    stream: 1, body: Buffer.concat(packets),
  }], BUILD);
}

function nativeResult(request) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    callback_table_sha256: profile.evidence_callback_table_sha256,
    results: request.packets.map((row, inputIndex) => ({
      status: 'DECODED', input_index: inputIndex,
      raw_param: row.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: row.payload_hex.length / 2,
      native_packet_id: 0x01ad, native_raw_param: row.raw_param,
      opaque_u8_0x10: inputIndex,
      opaque_f32_0x14: 0.5 + inputIndex,
      opaque_u32_0x18: 0x400000af + inputIndex,
      opaque_f32_0x1c: 1.5 + inputIndex,
      raw_u8_0x10_hex: '00',
      raw_f32_0x14_hex: '00000000',
      raw_u32_0x18_hex: '00000000',
      raw_f32_0x1c_hex: '00000000',
    })),
  };
}

test('821 BuffReplace registry and shared scan keep only packet 0x01ad', () => {
  const input = replay([
    packet(0x01ad, 4), packet(0x02d9, 6), packet(0x01ad, 10, 0x400000af),
  ]);
  assert.equal(resolveBuildProfile(input).status, 'SUPPORTED');
  assert.equal(resolveCapability(BUILD, 'npc_buff_replace_packet').status, 'CANDIDATE');
  const queried = capabilityQuery(input).capabilities.find((row) =>
    row.capability === 'npc_buff_replace_packet');
  assert.equal(queried.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.equal(queried.output, 'npc_buff_replace_packet_candidates');
  const scan = collect821Routes(input, ['npc_buff_replace_packet']);
  assert.deepEqual(rowsFor821Capability(input, scan, 'npc_buff_replace_packet')
    .rows.map((row) => row.block.payload_length), [4, 10]);
});

test('821 BuffReplace API and CLI emit anonymous packet candidates', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-buff-replace-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'sample.rofl');
  const imagePath = path.join(directory, 'image.bin');
  const input = replay([
    packet(0x01ad, 4), packet(0x02d9, 6), packet(0x01ad, 10, 0x400000af),
  ]);
  fs.writeFileSync(filePath, input.buffer);
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  const missing = decodeSemanticReplay(input, {
    capabilities: ['npc_buff_replace_packet'],
  });
  assert.equal(missing.capability_results.npc_buff_replace_packet.status,
    'MISSING_INPUT');
  assert.equal(missing.events, null);

  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_buff_replace_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.deepEqual(request.packets.map((row) =>
      [row.packet_id, row.payload_hex.length / 2]), [[0x01ad, 4], [0x01ad, 10]]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const decoded = decodeSemanticReplay(input, {
    capabilities: ['npc_buff_replace_packet'], runtimeImagePath: imagePath,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.decoded_packet_count, 2);
  assert.equal(decoded.capability_results.npc_buff_replace_packet.input_count, 2);
  assert.equal(decoded.capability_results.npc_buff_replace_packet.event_count, 2);
  assert.deepEqual(Object.keys(decoded.events), ['npc_buff_replace_packet_candidates']);
  assert.deepEqual(decoded.events.npc_buff_replace_packet_candidates
    .map((row) => row.opaque_u32_0x18), [0x400000af, 0x400000b0]);
  assert.equal(decoded.events.npc_buff_replace_packet_candidates[0]
    .raw_packet_ref.packet_id, 0x01ad);
  for (const key of ['buff_id', 'owner', 'replacement_effect', 'target']) {
    assert.equal(key in decoded.events.npc_buff_replace_packet_candidates[0], false);
  }

  const parsed = parseOne(filePath, {
    semantic: true, events: ['npc_buff_replace_packet'],
    runtimeImage: imagePath, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.capability_results.npc_buff_replace_packet.status,
    'CANDIDATE');
  assert.deepEqual(Object.keys(parsed.analysis.events),
    ['npc_buff_replace_packet_candidates']);
  assert.equal(native.mock.callCount(), 2);
});
