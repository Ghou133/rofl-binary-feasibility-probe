'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeSemanticReplay } = require('../src/semantic_api');
const {
  ANONYMOUS_029C_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeAnonymous029cPacketCandidates821: decode,
  decodeProtectedAnonymous029cU32,
  isObservedAnonymous029cPayload,
} = require('../src/decoders/rofl_16_19_821_anonymous_029c_packet_candidate');

const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;

function packet(hex, timeMs = 1000, id = 0x029c, param = 0) {
  const payload = Buffer.from(hex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = profile.replay_version, stream = 1,
  packets = [packet('72')] } = {}) {
  return replayFromChunks([{ stream, body: Buffer.concat(packets) }], version);
}

function outputHash(rows) {
  const hash = crypto.createHash('sha256');
  for (const row of rows) {
    const value = Buffer.alloc(4);
    value.writeUInt32LE(row.anonymous_u32_candidate);
    hash.update(Buffer.from(row.native_protected_selector_byte_hex, 'hex'))
      .update(Buffer.from(row.native_protected_u32_hex, 'hex')).update(value);
  }
  return hash.digest('hex');
}

test('0x029c is anonymous, opt-in and bounded to the 13 observed shapes', () => {
  assert.equal(profile.replay_block_packet_id, 0x029c);
  assert.equal(profile.packet_name, undefined);
  assert.equal(decodeProtectedAnonymous029cU32('18181818'), 0xffffffff);
  assert.equal(decodeProtectedAnonymous029cU32('1f2ae31e'), 0x400001f7);
  assert.equal(decodeProtectedAnonymous029cU32('zz'), null);
  assert.equal(decode(fixture({ version: '16.19.820.7193' })).status,
    'UNSUPPORTED');
  assert.equal(decode(fixture({ packets: [packet('72', 1000, 0x0282)] })).status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decode(fixture()).missing_input, 'runtime_image');
  assert.equal(decode(fixture({ stream: 2 })).status, 'DECODE_FAILED');
  for (const prefix of [0x70, 0x76, 0x78, 0x7a, 0x7c, 0x7e]) {
    for (const length of [3, 4]) {
      assert.equal(isObservedAnonymous029cPayload(Buffer.from([prefix,
        ...Array(length - 1).fill(0)])), true);
    }
  }
  for (const hex of ['71', '7200', '7600', '7600000000', '740000']) {
    assert.equal(decode(fixture({ packets: [packet(hex)] })).status,
      'DECODE_FAILED', hex);
  }
});

test('exact image yields native anonymous packet-local u32 with unknown roles',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const replay = fixture({ packets: [packet('72'),
      packet('761fff', 1100, 0x029c, 0x400000b5),
      packet('7e14ff', 1200, 0x029c, 0x400000b6)] });
    const result = decode(replay, { runtimeImagePath: IMAGE });
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.native_full_success_count, 3);
    assert.equal(result.native_batch_count, 1);
    assert.equal(result.native_output_sha256, outputHash(result.events));
    assert.deepEqual(result.events.map((row) => row.anonymous_u32_candidate),
      [0xffffffff, 0x400001f7, 0x400001f8]);
    assert.deepEqual(result.events.map((row) => row.raw_param),
      [0, 0x400000b5, 0x400000b6]);
    assert.deepEqual(result.events.map((row) => row.anonymous_u32_is_sentinel),
      [true, false, false]);
    for (const row of result.events) {
      assert.equal(row.native_selector_u8, 0);
      assert.equal(row.native_protected_selector_byte_hex, '3e');
      assert.equal(row.raw_packet_ref.packet_id, 0x029c);
      assert.equal(row.raw_packet_ref.raw_param, row.raw_param);
      assert.equal(row.raw_packet_ref.chunk_stream, 'game_chunk');
      for (const field of ['actor_status', 'target_status', 'object_role_status',
        'receiver_state_status', 'behavior_status', 'effect_status']) {
        assert.equal(row[field], 'UNKNOWN');
      }
      assert.equal('packet_name_candidate' in row, false);
    }
    const api = decodeSemanticReplay(replay, {
      capabilities: ['anonymous_029c_packet'], runtimeImagePath: IMAGE,
    });
    assert.equal(api.capability_results.anonymous_029c_packet.status, 'CANDIDATE');
    assert.equal(api.events.anonymous_029c_packet_candidates.length, 3);
    const appended = decode(fixture({ packets: [packet('761fff00', 1000)] }),
      { runtimeImagePath: IMAGE });
    assert.equal(appended.status, 'DECODE_FAILED');
    assert.equal(appended.events, null);
  });

test('missing native runtime and wrong image emit no candidate rows',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const missing = decode(fixture(), { runtimeImagePath: IMAGE,
      pythonExecutable: path.join(__dirname, 'no-such-python-821') });
    assert.equal(missing.status, 'MISSING_INPUT');
    assert.equal(missing.missing_input, 'python_unicorn');
    assert.equal(missing.events, null);
    const wrong = decode(fixture(), { runtimeImagePath: __filename });
    assert.equal(wrong.status, 'MISSING_INPUT');
    assert.equal(wrong.events, null);
  });

test('packet count above 50000 fails closed before native output', () => {
  const packets = Array.from({ length: 50_001 }, () => packet('72'));
  const result = decode(fixture({ packets }));
  assert.equal(result.status, 'UNSUPPORTED');
  assert.equal(result.input_count, 50_001);
  assert.equal(result.events, null);
});
