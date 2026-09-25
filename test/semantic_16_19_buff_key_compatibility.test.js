'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { analyzeBuffPacketKeyCompatibility } =
  require('../src/decoders/rofl_16_19_buff_key_compatibility');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const REPLAY_SHA = 'a'.repeat(64);

function add(token, slot, streamTag = 1) {
  return {
    game_version: '16.19.820.7193', replay_sha256: REPLAY_SHA,
    stream_tag: streamTag,
    decoded_scalar_fields_candidate: {
      offset_0x30_u32: token, offset_0x28_u8: slot,
    },
    raw_packet_ref: { replay_sha256: REPLAY_SHA, packet_id: 0x03ed },
  };
}

function remove(token, slot) {
  return {
    game_version: '16.19.820.7193', replay_sha256: REPLAY_SHA,
    buff_lookup_token_u32_candidate: token,
    buff_slot_index_candidate: slot,
    raw_packet_ref: { replay_sha256: REPLAY_SHA, packet_id: 0x043c },
  };
}

test('opaque Buff packet-key overlap reports counts without a row join', () => {
  const result = analyzeBuffPacketKeyCompatibility([
    add(10, 1), add(10, 1), add(20, 2, 2),
  ], [
    remove(10, 1), remove(10, 1), remove(10, 1),
    remove(20, 2), remove(30, 3),
  ], REPLAY_SHA);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.add_packet_count, 3);
  assert.equal(result.game_add_packet_count, 2);
  assert.equal(result.remove_packet_count, 5);
  assert.equal(result.distinct_add_key_count, 2);
  assert.equal(result.distinct_game_add_key_count, 1);
  assert.equal(result.distinct_remove_key_count, 3);
  assert.equal(result.remove_keys_present_in_add, 2);
  assert.equal(result.remove_keys_present_in_game_add, 1);
  assert.equal(result.remove_packets_with_key_present_in_add, 4);
  assert.equal(result.remove_packets_with_key_present_in_game_add, 3);
  assert.deepEqual(result.unmatched_remove_key_samples, [{
    token_u32_candidate: 30, slot_u8_candidate: 3, remove_packet_count: 1,
  }]);
  assert.ok(result.known_limits.some((limit) => /no.*row join|prevent.*row join/i.test(limit)));
  assert.equal(Object.hasOwn(result, 'matched_packets'), false);
});

test('opaque Buff packet-key comparison rejects foreign Replay, route and invalid scalars', () => {
  assert.throws(() => analyzeBuffPacketKeyCompatibility([add(1, 2)],
    [remove(1, 2)], 'bad-hash'), /Replay SHA-256/);
  const foreign = add(1, 2);
  foreign.replay_sha256 = 'b'.repeat(64);
  assert.throws(() => analyzeBuffPacketKeyCompatibility([foreign],
    [remove(1, 2)], REPLAY_SHA), /not bound/);
  const foreignRoute = remove(1, 2);
  foreignRoute.raw_packet_ref.packet_id = 0x03ed;
  assert.throws(() => analyzeBuffPacketKeyCompatibility([add(1, 2)],
    [foreignRoute], REPLAY_SHA), /not bound/);
  assert.throws(() => analyzeBuffPacketKeyCompatibility([add(1, 256)],
    [remove(1, 2)], REPLAY_SHA), /invalid token or slot/);
});

test('16.19 API reports unavailable correlation when the exact runtime image is missing', () => {
  const packet = (packetId, payload) => {
    const header = Buffer.alloc(15);
    header.writeFloatLE(1, 1);
    header.writeUInt32LE(payload.length, 5);
    header.writeUInt16LE(packetId, 9);
    header.writeUInt32LE(0x400000ae, 11);
    return Buffer.concat([header, payload]);
  };
  const replay = replayFromChunks([{ stream: 1, body: Buffer.concat([
    packet(0x03ed, Buffer.from('62756775f6d8065b2ebe91415b1bdc7726adeab6a738', 'hex')),
    packet(0x043c, Buffer.from('5e99f05d5b6dc4', 'hex')),
  ]) }], '16.19.820.7193');
  const result = decodeSemanticReplay(replay, {
    capabilities: ['npc_buff_add_packet', 'npc_buff_remove_packet'],
  });
  assert.equal(result.status, 'MISSING_INPUT');
  assert.equal(result.capability_results.npc_buff_add_packet.status, 'MISSING_INPUT');
  assert.equal(result.capability_results.npc_buff_remove_packet.status, 'MISSING_INPUT');
  assert.deepEqual(result.candidate_associations.npc_buff_add_remove_opaque_key, {
    status: 'UNAVAILABLE',
    required_capabilities: ['npc_buff_add_packet', 'npc_buff_remove_packet'],
    dependency_statuses: {
      npc_buff_add_packet: 'MISSING_INPUT',
      npc_buff_remove_packet: 'MISSING_INPUT',
    },
  });
});
