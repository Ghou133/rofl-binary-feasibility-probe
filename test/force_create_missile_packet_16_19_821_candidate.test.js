'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeSemanticReplay } = require('../src/semantic_api');
const {
  FORCE_CREATE_MISSILE_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeForceCreateMissilePacketCandidates821: decode,
  decodeProtectedForceCreateMissileComparisonKeyU32,
} = require('../src/decoders/rofl_16_19_821_force_create_missile_packet_candidate');

const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;
const SHORT = 'f08fd1';
const LONG = 'f6d0cacb';

function packet(hex, timeMs = 1000, id = 0x0087, param = 0x400000ae) {
  const payload = Buffer.from(hex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = profile.replay_version, stream = 1,
  packets = [packet(SHORT)] } = {}) {
  return replayFromChunks([{ stream, body: Buffer.concat(packets) }], version);
}

function outputHash(rows) {
  const hash = crypto.createHash('sha256');
  for (const row of rows) {
    const key = Buffer.alloc(4);
    key.writeUInt32LE(row.native_callback_comparison_key_u32);
    hash.update(Buffer.from(row.native_protected_comparison_bytes_hex, 'hex'))
      .update(key);
  }
  return hash.digest('hex');
}

test('0x0087 is opt-in, exact-build and restricted to 12 observed game shapes', () => {
  assert.equal(profile.replay_block_packet_id, 0x0087);
  assert.equal(profile.packet_name, 'PKT_S2C_ForceCreateMissile_s');
  assert.equal(decode(fixture({ version: '16.19.820.7193' })).status, 'UNSUPPORTED');
  assert.equal(decode(fixture({ packets: [packet(SHORT, 1000, 0x008a)] })).status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decode(fixture()).missing_input, 'runtime_image');
  assert.equal(decode(fixture({ stream: 2 })).status, 'DECODE_FAILED');
  for (const hex of ['f3', 'f5', 'f08f', '758fd1']) {
    assert.equal(decode(fixture({ packets: [packet(hex)] })).status, 'DECODE_FAILED',
      hex);
  }
  assert.equal(decodeProtectedForceCreateMissileComparisonKeyU32('90cdc94a'),
    0x40000263);
  assert.equal(decodeProtectedForceCreateMissileComparisonKeyU32('cf4ac94a'),
    0x40004003);
  assert.equal(decodeProtectedForceCreateMissileComparisonKeyU32('zz'), null);
});

test('real exact image decodes packet-local comparison key; live semantics stay unknown',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const replay = fixture({ packets: [packet(SHORT), packet(LONG, 1100,
      0x0087, 0x400000b1)] });
    const result = decode(replay, { runtimeImagePath: IMAGE });
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.native_full_success_count, 2);
    assert.equal(result.native_batch_count, 1);
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.native_output_sha256, outputHash(result.events));
    assert.deepEqual(result.events.map((row) => row.native_callback_comparison_key_u32),
      [0x40000263, 0x40004003]);
    assert.deepEqual(result.events.map((row) => row.raw_packet_ref.raw_payload_hex),
      [SHORT, LONG]);
    for (const row of result.events) {
      assert.equal(row.raw_packet_ref.chunk_stream, 'game_chunk');
      assert.equal(row.native_callback_witness_status,
        'SYNTHETIC_RECEIVER_PRE_COMPARE');
      assert.equal(row.live_receiver_lookup_status, 'UNKNOWN');
      for (const field of ['source_actor_status', 'owner_status',
        'missile_identity_status', 'target_status', 'creation_effect_status',
        'causality_status']) {
        assert.equal(row[field], 'UNKNOWN');
      }
      assert.equal('missile_entity_id' in row, false);
      assert.equal('created' in row, false);
    }
    const appended = decode(fixture({ packets: [packet('f08fd100')] }),
      { runtimeImagePath: IMAGE });
    assert.equal(appended.status, 'DECODE_FAILED');
    assert.equal(appended.events, null);
    const api = decodeSemanticReplay(replay, {
      capabilities: ['force_create_missile_packet'], runtimeImagePath: IMAGE,
    });
    assert.equal(api.capability_results.force_create_missile_packet.status,
      'CANDIDATE');
    assert.equal(api.events.force_create_missile_packet_candidates.length, 2);
  });

test('matched image before missing native runner is prechecked but unused',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const result = decode(fixture(), { runtimeImagePath: IMAGE,
      pythonExecutable: path.join(__dirname, 'no-such-python-821') });
    assert.equal(result.status, 'MISSING_INPUT');
    assert.equal(result.missing_input, 'python_unicorn');
    assert.equal(result.runtime_image_status, 'MATCHED_PRECHECKED');
    assert.equal(result.runtime_image_used, false);
    assert.equal(result.events, null);
  });

test('wrong image never emits candidate rows', () => {
  const result = decode(fixture(), { runtimeImagePath: __filename });
  assert.equal(result.status, 'MISSING_INPUT');
  assert.equal(result.events, null);
});
