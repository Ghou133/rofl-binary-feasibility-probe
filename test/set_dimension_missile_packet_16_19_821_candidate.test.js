'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { SET_DIMENSION_MISSILE_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeSetDimensionMissilePacketCandidates821: decode,
  decodeProtectedSetDimensionMissileArgumentU8,
} = require('../src/decoders/rofl_16_19_821_set_dimension_missile_packet_candidate');

const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;

function packet(hex, timeMs = 1000, id = 0x008a, param = 0x40000263) {
  const payload = Buffer.from(hex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = profile.replay_version, stream = 1,
  packets = [packet('758fd1')] } = {}) {
  return replayFromChunks([{ stream, body: Buffer.concat(packets) }], version);
}

function outputHash(rows) {
  const hash = crypto.createHash('sha256');
  for (const row of rows) {
    hash.update(Buffer.from(row.native_protected_dimension_byte_hex, 'hex'))
      .update(Buffer.from([row.native_callback_argument_u8]));
  }
  return hash.digest('hex');
}

test('0x008a requires exact build, framing ID, observed shape and pinned image', () => {
  assert.equal(profile.replay_block_packet_id, 0x008a);
  assert.equal(profile.packet_name, 'PKT_SetDimensionMissile_s');
  assert.equal(decodeProtectedSetDimensionMissileArgumentU8('d5'), 0);
  assert.equal(decodeProtectedSetDimensionMissileArgumentU8('a7'), 6);
  assert.equal(decodeProtectedSetDimensionMissileArgumentU8('ff'), null);
  assert.equal(decode(fixture({ version: '16.19.820.7193' })).status,
    'UNSUPPORTED');
  assert.equal(decode(fixture({ packets: [packet('758fd1', 1000, 0x0087)] })).status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decode(fixture()).missing_input, 'runtime_image');
  assert.equal(decode(fixture({ stream: 2 })).status, 'DECODE_FAILED');
  for (const hex of ['f08fd1', '758f', '786b3aa7ff00']) {
    assert.equal(decode(fixture({ packets: [packet(hex)] })).status,
      'DECODE_FAILED', hex);
  }
});

test('exact image yields packet-local callback u8 without live effect claims',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const replay = fixture({ packets: [
      packet('758fd1', 1000, 0x008a, 0x40000263),
      packet('786b3aa7', 1100, 0x008a, 0x40000b20),
    ] });
    const result = decode(replay, { runtimeImagePath: IMAGE });
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.native_full_success_count, 2);
    assert.equal(result.native_batch_count, 1);
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.native_output_sha256, outputHash(result.events));
    assert.deepEqual(result.events.map((row) => row.native_callback_argument_u8),
      [0, 6]);
    assert.deepEqual(result.events.map((row) => row.native_protected_dimension_byte_hex),
      ['d5', 'a7']);
    for (const row of result.events) {
      assert.equal(row.raw_packet_ref.packet_id, 0x008a);
      assert.equal(row.raw_packet_ref.chunk_stream, 'game_chunk');
      assert.equal(row.native_callback_witness_status,
        'STOPPED_BEFORE_RECEIVER_METHOD');
      for (const field of ['live_receiver_status', 'source_actor_status',
        'owner_status', 'missile_identity_status', 'target_status',
        'dimension_change_status', 'gameplay_effect_status',
        'causality_status']) assert.equal(row[field], 'UNKNOWN');
      assert.equal('missile_entity_id' in row, false);
      assert.equal('dimension_changed' in row, false);
    }
    const appended = decode(fixture({ packets: [packet('758fd100')] }),
      { runtimeImagePath: IMAGE });
    assert.equal(appended.status, 'DECODE_FAILED');
    assert.equal(appended.events, null);
    const api = decodeSemanticReplay(replay, {
      capabilities: ['set_dimension_missile_packet'], runtimeImagePath: IMAGE,
    });
    assert.equal(api.capability_results.set_dimension_missile_packet.status,
      'CANDIDATE');
    assert.equal(api.events.set_dimension_missile_packet_candidates.length, 2);
  });

test('missing runner and wrong image never publish candidate rows',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const missing = decode(fixture(), { runtimeImagePath: IMAGE,
      pythonExecutable: path.join(__dirname, 'no-such-python-821') });
    assert.equal(missing.status, 'MISSING_INPUT');
    assert.equal(missing.missing_input, 'python_unicorn');
    assert.equal(missing.runtime_image_status, 'MATCHED_PRECHECKED');
    assert.equal(missing.events, null);
    const wrong = decode(fixture(), { runtimeImagePath: __filename });
    assert.equal(wrong.status, 'MISSING_INPUT');
    assert.equal(wrong.events, null);
  });
