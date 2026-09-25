'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { analyzeBuffAddUpdateNumCounterCompatibility821 } =
  require('../src/decoders/rofl_16_19_821_buff_add_update_compatibility');
const { NPC_BUFF_ADD_PACKET_CANDIDATE_PROFILE_821: ADD_PROFILE } =
  require('../src/decoders/rofl_16_19_821_buff_add_packet_candidate');
const { NPC_BUFF_UPDATE_NUM_COUNTER_PACKET_CANDIDATE_PROFILE_821: UPDATE_PROFILE } =
  require('../src/decoders/rofl_16_19_821_buff_update_num_counter_packet_candidate');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.821.7343';
const REPLAY_SHA = 'a'.repeat(64);
const RAW_PARAM_A = 0x400000ae;
const RAW_PARAM_B = 0x400000af;
const RAW_PARAM_C = 0x400000b0;
const RAW_PARAM_D = 0x400000b1;
const RAW_PARAM_E = 0x400000b2;

function packet(kind, token, slot, rawParam, stream, chunkIndex, blockOffset) {
  const isAdd = kind === 'add';
  const packetId = isAdd ? 0x00ae : 0x0194;
  const time = chunkIndex * 1000 + blockOffset;
  return {
    event_type: isAdd ? 'NPC_BUFF_ADD_PACKET_CANDIDATE'
      : 'NPC_BUFF_UPDATE_NUM_COUNTER_PACKET_CANDIDATE',
    game_version: BUILD,
    patch: '16.19',
    build_profile: isAdd ? ADD_PROFILE.id : UPDATE_PROFILE.id,
    replay_sha256: REPLAY_SHA,
    replay_time_ms: time,
    raw_param: rawParam,
    ...(isAdd ? {
      opaque_u32_0x10: token, opaque_u8_0x14: slot,
      raw_object_u32_bytes_hex: '01020304', raw_object_u8_byte_hex: '05',
    } : {
      opaque_u8_0x10: 1, opaque_u32_0x14: token,
      opaque_u8_0x18: slot, opaque_u32_0x1c: 0,
      raw_object_u8_0x10_hex: '01', raw_object_u32_0x14_hex: '02030405',
      raw_object_u8_0x18_hex: '06', raw_object_u32_0x1c_hex: '0708090a',
    }),
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
    raw_packet_ref: {
      replay_sha256: REPLAY_SHA, chunk_index: chunkIndex, chunk_id: chunkIndex,
      chunk_stream: stream, chunk_file_offset: chunkIndex * 100,
      decompressed_block_offset: blockOffset,
      decompressed_payload_offset: blockOffset + 6,
      packet_id: packetId, replay_time_ms: time,
      payload_length: isAdd ? 22 : 7, raw_param: rawParam,
      raw_payload_sha256: 'b'.repeat(64),
    },
  };
}

const add = (token, slot, rawParam, stream, chunkIndex, blockOffset) =>
  packet('add', token, slot, rawParam, stream, chunkIndex, blockOffset);
const update = (token, slot, rawParam, chunkIndex, blockOffset) =>
  packet('update', token, slot, rawParam, 'game_chunk', chunkIndex, blockOffset);

test('821 Buff Add/Update compatibility counts pair overlap and preceding game packets only', () => {
  const addRows = [
    add(10, 1, RAW_PARAM_A, 'game_chunk', 1, 30),
    add(10, 1, RAW_PARAM_A, 'keyframe', 0, 5),
    add(20, 2, RAW_PARAM_B, 'keyframe', 0, 8),
    add(10, 1, RAW_PARAM_A, 'game_chunk', 1, 10),
    add(20, 2, RAW_PARAM_C, 'game_chunk', 1, 50),
    add(30, 3, RAW_PARAM_B, 'game_chunk', 1, 70),
    add(50, 5, RAW_PARAM_E, 'keyframe', 0, 12),
  ];
  const updateRows = [
    update(10, 1, RAW_PARAM_A, 1, 20),
    update(10, 1, RAW_PARAM_A, 1, 40),
    update(20, 2, RAW_PARAM_B, 1, 60),
    update(20, 2, RAW_PARAM_C, 1, 45),
    update(40, 4, RAW_PARAM_D, 1, 80),
    update(30, 3, RAW_PARAM_B, 1, 75),
    update(50, 5, RAW_PARAM_E, 1, 90),
  ];
  const result = analyzeBuffAddUpdateNumCounterCompatibility821(
    addRows, updateRows, REPLAY_SHA);
  assert.equal(result.status, 'CANDIDATE');
  assert.deepEqual([
    result.add_packet_count, result.game_add_packet_count,
    result.keyframe_add_packet_count, result.update_packet_count,
  ], [7, 4, 3, 7]);
  assert.deepEqual([
    result.update_packets_with_pair_in_add,
    result.update_packets_with_pair_in_game_add,
    result.update_packets_with_pair_in_keyframe_add,
    result.update_packets_with_raw_param_pair_in_add,
    result.update_packets_with_raw_param_pair_in_game_add,
    result.update_packets_with_raw_param_pair_in_keyframe_add,
  ], [6, 5, 5, 6, 4, 4]);
  assert.equal(result.update_packets_with_preceding_game_add_same_raw_param_pair, 3);
  assert.equal(result.update_packets_with_multiple_preceding_game_adds_same_raw_param_pair, 1);
  assert.equal(result.distinct_update_raw_param_pairs_with_multiple_packets, 1);
  assert.equal(result.update_packets_on_repeated_raw_param_pairs, 2);
  assert.equal(Object.hasOwn(result, 'matched_packets'), false);
  assert.ok(result.known_limits.some((limit) => /row pairing/.test(limit)));
});

test('821 Buff Add/Update compatibility rejects foreign route, Replay and malformed fields', () => {
  const oneAdd = add(1, 2, RAW_PARAM_A, 'game_chunk', 1, 10);
  const oneUpdate = update(1, 2, RAW_PARAM_A, 1, 20);
  assert.throws(() => analyzeBuffAddUpdateNumCounterCompatibility821(
    [oneAdd], [oneUpdate], 'not-a-sha'), /Replay SHA-256/);
  const cases = [
    ['foreign build', (a) => { a.game_version = '16.19.820.7193'; }],
    ['foreign profile', (a) => { a.build_profile = 'foreign'; }],
    ['foreign Replay', (a) => { a.replay_sha256 = 'c'.repeat(64); }],
    ['wrong update route', (a, u) => { u.raw_packet_ref.packet_id = 0x00ae; }],
    ['wrong update stream', (a, u) => { u.raw_packet_ref.chunk_stream = 'keyframe'; }],
    ['wrong raw param', (a, u) => { u.raw_packet_ref.raw_param = 1; }],
    ['missing payload hash', (a) => { a.raw_packet_ref.raw_payload_sha256 = null; }],
    ['invalid update length', (a, u) => { u.raw_packet_ref.payload_length = 22; }],
    ['wrong patch', (a) => { a.patch = '16.18'; }],
  ];
  for (const [label, change] of cases) {
    const testAdd = structuredClone(oneAdd);
    const testUpdate = structuredClone(oneUpdate);
    change(testAdd, testUpdate);
    assert.throws(() => analyzeBuffAddUpdateNumCounterCompatibility821(
      [testAdd], [testUpdate], REPLAY_SHA), /not bound/, label);
  }
  assert.throws(() => analyzeBuffAddUpdateNumCounterCompatibility821(
    [add(1, 256, RAW_PARAM_A, 'game_chunk', 1, 10)], [oneUpdate], REPLAY_SHA),
  /invalid anonymous fields/);
  assert.throws(() => analyzeBuffAddUpdateNumCounterCompatibility821(
    [oneAdd], [update(-1, 2, RAW_PARAM_A, 1, 20)], REPLAY_SHA),
  /invalid anonymous fields/);
  assert.throws(() => analyzeBuffAddUpdateNumCounterCompatibility821(
    [oneAdd, oneAdd], [oneUpdate], REPLAY_SHA), /position is duplicated/);
  assert.throws(() => analyzeBuffAddUpdateNumCounterCompatibility821(
    [oneAdd], [update(1, 2, RAW_PARAM_A, 1, 10)], REPLAY_SHA),
  /position is duplicated/);
});

function framedPacket(packetId, payload) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(RAW_PARAM_A, 11);
  return Buffer.concat([header, payload]);
}

function buffReplay() {
  return replayFromChunks([{ stream: 1, body: Buffer.concat([
    framedPacket(0x00ae, Buffer.alloc(22, 0x4a)),
    framedPacket(0x0194, Buffer.from('20411172836b55', 'hex')),
  ]) }], BUILD);
}

test('821 API exposes aggregate Add/Update compatibility only after both native candidates succeed', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-buff-update-pair-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const imagePath = path.join(directory, 'runtime.bin');
  fs.writeFileSync(imagePath, Buffer.from([1, 2, 3]));
  const replay = buffReplay();
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    const isAdd = /decode_buff_add_packet_16_19_821\.py$/.test(args[1]);
    assert.ok(isAdd || /decode_buff_update_num_counter_packet_16_19_821\.py$/.test(args[1]));
    const request = JSON.parse(options.input);
    const profile = isAdd ? ADD_PROFILE : UPDATE_PROFILE;
    const packetId = isAdd ? 0x00ae : 0x0194;
    const results = request.packets.map((input, inputIndex) => ({
      status: 'DECODED', input_index: inputIndex,
      raw_param: input.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: input.payload_hex.length / 2,
      native_packet_id: packetId, native_raw_param: input.raw_param,
      ...(isAdd ? {
        opaque_u32_0x10: 42, opaque_u8_0x14: 3,
        raw_u32_bytes_hex: '01020304', raw_u8_byte_hex: '05',
      } : {
        opaque_u8_0x10: 1, opaque_u32_0x14: 42, opaque_u8_0x18: 3,
        opaque_u32_0x1c: 0, raw_u8_0x10_hex: '01',
        raw_u32_0x14_hex: '02030405', raw_u8_0x18_hex: '06',
        raw_u32_0x1c_hex: '0708090a',
      }),
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
    capabilities: ['npc_buff_add_packet', 'npc_buff_update_num_counter_packet'],
    runtimeImagePath: imagePath,
  });
  assert.equal(invoke.mock.callCount(), 2);
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  const association = decoded.candidate_associations.npc_buff_add_update_num_counter_opaque_pair;
  assert.equal(association.status, 'CANDIDATE');
  assert.equal(association.update_packets_with_pair_in_game_add, 1);
  assert.equal(association.update_packets_with_preceding_game_add_same_raw_param_pair, 1);
  assert.equal(Object.hasOwn(association, 'matched_packets'), false);
});

test('821 API leaves Add/Update compatibility unavailable when the runtime image is missing', () => {
  const decoded = decodeSemanticReplay(buffReplay(), {
    capabilities: ['npc_buff_add_packet', 'npc_buff_update_num_counter_packet'],
  });
  assert.equal(decoded.status, 'MISSING_INPUT');
  assert.deepEqual(decoded.candidate_associations.npc_buff_add_update_num_counter_opaque_pair, {
    status: 'UNAVAILABLE',
    required_capabilities: ['npc_buff_add_packet', 'npc_buff_update_num_counter_packet'],
    dependency_statuses: {
      npc_buff_add_packet: 'MISSING_INPUT',
      npc_buff_update_num_counter_packet: 'MISSING_INPUT',
    },
  });
});
