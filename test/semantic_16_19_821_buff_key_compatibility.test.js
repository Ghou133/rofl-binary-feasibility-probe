'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { analyzeBuffPacketKeyCompatibility821 } =
  require('../src/decoders/rofl_16_19_821_buff_key_compatibility');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { NPC_BUFF_ADD_PACKET_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_buff_add_packet_candidate');
const { NPC_BUFF_REMOVE_PACKET_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_buff_remove_packet_candidate');

const REPLAY_SHA = 'a'.repeat(64);

function packet(kind, token, slot, stream, chunkIndex, blockOffset, time) {
  const isAdd = kind === 'add';
  const packetId = isAdd ? 0x00ae : 0x047c;
  const rawParam = 0x400000ae;
  return {
    event_type: isAdd ? 'NPC_BUFF_ADD_PACKET_CANDIDATE'
      : 'NPC_BUFF_REMOVE_PACKET_CANDIDATE',
    game_version: '16.19.821.7343',
    build_profile: isAdd
      ? 'rofl-16.19.821.7343-kr-buff-add2-packet-runtime-candidate-v1'
      : 'rofl-16.19.821.7343-kr-buff-remove2-packet-runtime-candidate-v1',
    replay_sha256: REPLAY_SHA,
    replay_time_ms: time,
    raw_param: rawParam,
    opaque_u32_0x10: token,
    opaque_u8_0x14: slot,
    ...(!isAdd ? { opaque_f32_0x18: 0 } : {}),
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
    raw_packet_ref: {
      replay_sha256: REPLAY_SHA,
      chunk_index: chunkIndex,
      chunk_stream: stream,
      decompressed_block_offset: blockOffset,
      packet_id: packetId,
      replay_time_ms: time,
      raw_param: rawParam,
      raw_payload_sha256: 'b'.repeat(64),
    },
  };
}

const add = (token, slot, stream, chunkIndex, blockOffset, time) =>
  packet('add', token, slot, stream, chunkIndex, blockOffset, time);
const remove = (token, slot, chunkIndex, blockOffset, time) =>
  packet('remove', token, slot, 'game_chunk', chunkIndex, blockOffset, time);

test('821 opaque Buff key overlap separates game Add and keyframe snapshots without row joins', () => {
  const addRows = [
    add(10, 1, 'game_chunk', 1, 30, 30),
    add(10, 1, 'keyframe', 0, 0, 0),
    add(20, 2, 'keyframe', 0, 5, 0),
    add(10, 1, 'game_chunk', 1, 10, 10),
    add(30, 3, 'game_chunk', 1, 40, 40),
    add(40, 4, 'game_chunk', 1, 70, 70),
  ];
  const removeRows = [
    remove(10, 1, 1, 35, 35),
    remove(10, 1, 1, 25, 25),
    remove(10, 1, 1, 20, 20),
    remove(20, 2, 1, 50, 50),
    remove(40, 4, 1, 60, 60),
    remove(50, 5, 1, 80, 80),
  ];
  const result = analyzeBuffPacketKeyCompatibility821(addRows, removeRows, REPLAY_SHA);
  assert.equal(result.status, 'CANDIDATE');
  assert.deepEqual({
    add: result.add_packet_count,
    game: result.game_add_packet_count,
    keyframe: result.keyframe_add_packet_count,
    remove: result.remove_packet_count,
  }, { add: 6, game: 4, keyframe: 2, remove: 6 });
  assert.deepEqual({
    add: result.distinct_add_key_count,
    game: result.distinct_game_add_key_count,
    keyframe: result.distinct_keyframe_add_key_count,
    remove: result.distinct_remove_key_count,
  }, { add: 4, game: 3, keyframe: 2, remove: 4 });
  assert.deepEqual({
    all: result.remove_keys_present_in_add,
    game: result.remove_keys_present_in_game_add,
    keyframe: result.remove_keys_present_in_keyframe_add,
    onlyKeyframe: result.remove_keys_only_in_keyframe_add,
  }, { all: 3, game: 2, keyframe: 2, onlyKeyframe: 1 });
  assert.deepEqual({
    all: result.remove_packets_with_key_present_in_add,
    game: result.remove_packets_with_key_present_in_game_add,
    keyframe: result.remove_packets_with_key_present_in_keyframe_add,
    noPrecedingGame: result.remove_packets_without_preceding_game_add,
    multiplePrecedingGame: result.remove_packets_with_multiple_preceding_game_adds,
    secondRemove: result.remove_packets_after_previous_remove_without_intervening_game_add,
  }, { all: 5, game: 4, keyframe: 4, noPrecedingGame: 3,
    multiplePrecedingGame: 1, secondRemove: 1 });
  assert.equal(result.distinct_remove_keys_with_multiple_packets, 1);
  assert.equal(result.distinct_remove_keys_with_multiple_game_adds, 1);
  assert.deepEqual(result.unmatched_remove_key_samples, [{
    opaque_u32_0x10: 50, opaque_u8_0x14: 5, remove_packet_count: 1,
  }]);
  assert.equal(Object.hasOwn(result, 'matched_packets'), false);
  assert.ok(result.known_limits.some((limit) => /row join/.test(limit)));
});

test('821 opaque Buff key comparison rejects foreign Replay, route, and malformed fields', () => {
  const oneAdd = add(1, 2, 'game_chunk', 1, 10, 10);
  const oneRemove = remove(1, 2, 1, 20, 20);
  assert.throws(() => analyzeBuffPacketKeyCompatibility821([oneAdd], [oneRemove],
    'not-a-sha'), /Replay SHA-256/);
  const cases = [
    ['foreign build', (a) => { a.game_version = '16.19.820.7193'; }],
    ['foreign profile', (a) => { a.build_profile = 'foreign'; }],
    ['foreign Replay', (a) => { a.replay_sha256 = 'c'.repeat(64); }],
    ['foreign route', (a, r) => { r.raw_packet_ref.packet_id = 0x03ed; }],
    ['wrong stream', (a, r) => { r.raw_packet_ref.chunk_stream = 'keyframe'; }],
    ['wrong time', (a, r) => { r.raw_packet_ref.replay_time_ms = 21; }],
    ['wrong raw param', (a, r) => { r.raw_packet_ref.raw_param = 1; }],
    ['missing payload hash', (a) => { a.raw_packet_ref.raw_payload_sha256 = null; }],
  ];
  for (const [label, change] of cases) {
    const testAdd = structuredClone(oneAdd);
    const testRemove = structuredClone(oneRemove);
    change(testAdd, testRemove);
    assert.throws(() => analyzeBuffPacketKeyCompatibility821([testAdd], [testRemove],
      REPLAY_SHA), /not bound/, label);
  }
  assert.throws(() => analyzeBuffPacketKeyCompatibility821(
    [add(1, 256, 'game_chunk', 1, 10, 10)], [oneRemove], REPLAY_SHA),
  /invalid anonymous key field/);
  assert.throws(() => analyzeBuffPacketKeyCompatibility821(
    [add(-1, 2, 'game_chunk', 1, 10, 10)], [oneRemove], REPLAY_SHA),
  /invalid anonymous key field/);
  const invalidF32 = remove(1, 2, 1, 20, 20);
  invalidF32.opaque_f32_0x18 = Infinity;
  assert.throws(() => analyzeBuffPacketKeyCompatibility821([oneAdd],
    [invalidF32], REPLAY_SHA), /invalid anonymous f32/);
  assert.throws(() => analyzeBuffPacketKeyCompatibility821([oneAdd, oneAdd],
    [oneRemove], REPLAY_SHA), /position is duplicated/);
});

function framedPacket(packetId, payload) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(0x400000ae, 11);
  return Buffer.concat([header, payload]);
}

function buffReplay() {
  return replayFromChunks([{ stream: 1, body: Buffer.concat([
    framedPacket(0x00ae, Buffer.alloc(22, 0x4a)),
    framedPacket(0x047c, Buffer.from('20411172836b', 'hex')),
  ]) }], '16.19.821.7343');
}

test('821 API exposes aggregate Buff key overlap only when both exact-image decoders succeed', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-buff-pair-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  const replay = buffReplay();
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    const isAdd = /decode_buff_add_packet_16_19_821\.py$/.test(args[1]);
    assert.ok(isAdd || /decode_buff_remove_packet_16_19_821\.py$/.test(args[1]));
    const request = JSON.parse(options.input);
    const profile = isAdd ? NPC_BUFF_ADD_PACKET_CANDIDATE_PROFILE_821
      : NPC_BUFF_REMOVE_PACKET_CANDIDATE_PROFILE_821;
    const packetId = isAdd ? 0x00ae : 0x047c;
    const results = request.packets.map((input, inputIndex) => ({
      status: 'DECODED', input_index: inputIndex,
      raw_param: input.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: input.payload_hex.length / 2,
      native_packet_id: packetId, native_raw_param: input.raw_param,
      opaque_u32_0x10: 87336022, opaque_u8_0x14: 1,
      ...(!isAdd ? { opaque_f32_0x18: 0, raw_f32_bytes_hex: '75757575' } : {}),
      raw_u32_bytes_hex: '2ff5b770', raw_u8_byte_hex: '59',
    }));
    return { status: 0, stderr: '', stdout: JSON.stringify({
      status: 'PASS',
      runtime_image_sha256:
        '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325',
      callback_table_sha256: profile.evidence_callback_table_sha256,
      results,
    }) };
  });
  const decoded = decodeSemanticReplay(replay, {
    capabilities: ['npc_buff_add_packet', 'npc_buff_remove_packet'],
    runtimeImagePath: image,
  });
  assert.equal(invoke.mock.callCount(), 2);
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  const association = decoded.candidate_associations.npc_buff_add_remove_opaque_key;
  assert.equal(association.status, 'CANDIDATE');
  assert.equal(association.remove_keys_present_in_add, 1);
  assert.equal(association.remove_packets_without_preceding_game_add, 0);
  assert.equal(Object.hasOwn(association, 'matched_packets'), false);
});

test('821 API leaves Buff association unavailable when the runtime image is missing', () => {
  const decoded = decodeSemanticReplay(buffReplay(), {
    capabilities: ['npc_buff_add_packet', 'npc_buff_remove_packet'],
  });
  assert.equal(decoded.status, 'MISSING_INPUT');
  assert.deepEqual(decoded.candidate_associations.npc_buff_add_remove_opaque_key, {
    status: 'UNAVAILABLE',
    required_capabilities: ['npc_buff_add_packet', 'npc_buff_remove_packet'],
    dependency_statuses: {
      npc_buff_add_packet: 'MISSING_INPUT',
      npc_buff_remove_packet: 'MISSING_INPUT',
    },
  });
});
