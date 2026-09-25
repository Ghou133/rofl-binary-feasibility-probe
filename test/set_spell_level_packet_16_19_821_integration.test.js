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
const { SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_821: profile } =
  require('../src/decoders/rofl_16_19_821_set_spell_level_packet_candidate');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'set_spell_level_packet';
const EVENT_KEY = 'set_spell_level_packet_candidates';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(packetId, length, rawParam = 0x400000b4) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, Buffer.alloc(length, 0x4a)]);
}

function replay(packets) {
  return replayFromChunks([{ stream: 1, body: Buffer.concat(packets) }], BUILD);
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
      native_packet_id: 0x025d, native_raw_param: row.raw_param,
      opaque_u32_0x10: 2 + inputIndex,
      opaque_u32_0x14: 11 + inputIndex,
      raw_u32_0x10_hex: '00000000',
      raw_u32_0x14_hex: '00000000',
    })),
  };
}

test('821 SetSpellLevel registry and shared scan select only route 0x025d', () => {
  const input = replay([
    packet(0x025d, 1), packet(0x00fd, 7), packet(0x025d, 3, 0x400000b5),
  ]);
  assert.equal(resolveBuildProfile(input).status, 'SUPPORTED');
  assert.equal(resolveCapability(BUILD, CAPABILITY).status, 'CANDIDATE');
  const queried = capabilityQuery(input).capabilities.find((row) =>
    row.capability === CAPABILITY);
  assert.equal(queried.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.equal(queried.output, EVENT_KEY);
  const scan = collect821Routes(input, [CAPABILITY]);
  assert.deepEqual(rowsFor821Capability(input, scan, CAPABILITY)
    .rows.map((row) => row.block.payload_length), [1, 3]);
});

test('821 SetSpellLevel API and CLI emit anonymous packet candidates', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-set-spell-level-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'sample.rofl');
  const imagePath = path.join(directory, 'image.bin');
  const input = replay([
    packet(0x025d, 1), packet(0x00fd, 7), packet(0x025d, 3, 0x400000b5),
  ]);
  fs.writeFileSync(filePath, input.buffer);
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  const missing = decodeSemanticReplay(input, { capabilities: [CAPABILITY] });
  assert.equal(missing.capability_results[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(missing.events, null);

  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_set_spell_level_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(imagePath));
    const request = JSON.parse(options.input);
    assert.deepEqual(request.packets.map((row) =>
      [row.packet_id, row.payload_hex.length / 2]), [[0x025d, 1], [0x025d, 3]]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const decoded = decodeSemanticReplay(input, {
    capabilities: [CAPABILITY], runtimeImagePath: imagePath,
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.decoded_packet_count, 2);
  assert.equal(decoded.capability_results[CAPABILITY].input_count, 2);
  assert.equal(decoded.capability_results[CAPABILITY].event_count, 2);
  assert.deepEqual(Object.keys(decoded.events), [EVENT_KEY]);
  assert.deepEqual(decoded.events[EVENT_KEY].map((row) => row.opaque_u32_0x10), [2, 3]);
  assert.equal(decoded.events[EVENT_KEY][0].raw_packet_ref.packet_id, 0x025d);
  for (const key of ['spell_slot', 'owner', 'spell_level', 'level_change']) {
    assert.equal(key in decoded.events[EVENT_KEY][0], false);
  }

  const parsed = parseOne(filePath, {
    semantic: true, events: [CAPABILITY],
    runtimeImage: imagePath, strict: true, timelineLimit: 0,
  });
  assert.equal(parsed.ok, true);
  assert.equal(parsed.analysis.semantic.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.deepEqual(Object.keys(parsed.analysis.events), [EVENT_KEY]);
  assert.equal(native.mock.callCount(), 2);
});
