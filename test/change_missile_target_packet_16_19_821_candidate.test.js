'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeSemanticReplay } = require('../src/semantic_api');
const {
  CHANGE_MISSILE_TARGET_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeChangeMissileTargetPacketCandidates821: decode,
  decodeProtectedChangeMissileTargetComparisonKeyU32,
} = require('../src/decoders/rofl_16_19_821_change_missile_target_packet_candidate');

const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;
const SHORT = '916fcb';
const LONG = '9656981069287b66ec2cad7569';

function packet(hex, timeMs = 1000, id = 0x040c, param = 0x400000ae) {
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

test('0x040c is opt-in, exact-build and restricted to 13 observed game shapes', () => {
  assert.equal(profile.replay_block_packet_id, 0x040c);
  assert.equal(profile.packet_name, 'PKT_S2C_ChangeMissileTarget_s');
  const defaultApi = decodeSemanticReplay(fixture());
  assert.equal(defaultApi.capability_results.change_missile_target_packet, undefined);
  assert.equal(decode(fixture({ version: '16.19.820.7193' })).status, 'UNSUPPORTED');
  assert.equal(decode(fixture({ packets: [packet(SHORT, 1000, 0x0087)] })).status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decode(fixture()).missing_input, 'runtime_image');
  assert.equal(decode(fixture({ stream: 2 })).status, 'DECODE_FAILED');
  for (const hex of ['90', '966fcb', '966fcb00', '916f',
    '916fcb0000', '9156981069287b66ec2cad7569']) {
    assert.equal(decode(fixture({ packets: [packet(hex)] })).status, 'DECODE_FAILED',
      hex);
  }
  assert.equal(decode(fixture({ packets: [packet('916fcb00')] })).status,
    'MISSING_INPUT');
  assert.equal(decodeProtectedChangeMissileTargetComparisonKeyU32('c9c9c9c9'), 0);
  assert.equal(decodeProtectedChangeMissileTargetComparisonKeyU32('6fc9c94a'),
    0x400000b2);
  assert.equal(decodeProtectedChangeMissileTargetComparisonKeyU32('zz'), null);
});

test('real exact image decodes packet-local comparison key; live semantics stay unknown',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const replay = fixture({ packets: [packet(SHORT), packet(LONG, 1100,
      0x040c, 0x400000b1)] });
    const result = decode(replay, { runtimeImagePath: IMAGE });
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.native_full_success_count, 2);
    assert.equal(result.native_batch_count, 1);
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.native_output_sha256, outputHash(result.events));
    assert.deepEqual(result.events.map((row) => row.native_callback_comparison_key_u32),
      [0x400000b2, 0]);
    assert.deepEqual(result.events.map((row) => row.raw_packet_ref.raw_payload_hex),
      [SHORT, LONG]);
    for (const row of result.events) {
      assert.equal(row.raw_packet_ref.chunk_stream, 'game_chunk');
      assert.equal(row.native_callback_witness_status,
        'SYNTHETIC_RECEIVER_PRE_COMPARE');
      assert.equal(row.live_receiver_comparison_status, 'UNKNOWN');
      for (const field of ['source_actor_status', 'owner_status',
        'missile_identity_status', 'target_status', 'target_change_effect_status',
        'causality_status']) {
        assert.equal(row[field], 'UNKNOWN');
      }
      assert.equal('missile_entity_id' in row, false);
      assert.equal('target_changed' in row, false);
    }
    const appended = decode(fixture({ packets: [packet('9656981069287b66ec2cad756900')] }),
      { runtimeImagePath: IMAGE });
    assert.equal(appended.status, 'DECODE_FAILED');
    assert.equal(appended.events, null);
    const api = decodeSemanticReplay(replay, {
      capabilities: ['change_missile_target_packet'], runtimeImagePath: IMAGE,
    });
    assert.equal(api.capability_results.change_missile_target_packet.status,
      'CANDIDATE');
    assert.equal(api.events.change_missile_target_packet_candidates.length, 2);
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
