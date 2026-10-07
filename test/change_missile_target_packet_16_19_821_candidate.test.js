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
  CHANGE_MISSILE_TARGET_PACKET_CANDIDATE_PROFILE_V2_821: profileV2,
  decodeChangeMissileTargetPacketCandidates821: decode,
  decodeProtectedChangeMissileTargetComparisonKeyU32,
  decodeProtectedChangeMissileTargetVectorF32,
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

function outputHash(rows, version = 'v1') {
  const hash = crypto.createHash('sha256');
  for (const row of rows) {
    const key = Buffer.alloc(4);
    key.writeUInt32LE(row.native_callback_comparison_key_u32);
    hash.update(Buffer.from(row.native_protected_comparison_bytes_hex, 'hex'))
      .update(key);
    if (version === 'v2') {
      hash.update(Buffer.from(row.native_vector_protected_bytes_hex, 'hex'))
        .update(Buffer.from(row.native_vector_raw_f32_bytes_hex, 'hex'))
        .update(Buffer.from([row.native_vector_source === 'PACKET_RAW_12' ? 1 : 0]));
    }
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

test('V2 is explicit and reports native object +0x10 f32 data without target meaning',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const replay = fixture({ packets: [packet(SHORT), packet(LONG, 1100)] });
    const old = decode(replay, { runtimeImagePath: IMAGE });
    const v2 = decode(replay, { runtimeImagePath: IMAGE, profileVersion: 'v2' });
    assert.equal(old.profile_id, profile.id);
    assert.equal('native_vector_f32' in old.events[0], false);
    assert.equal(v2.status, 'CANDIDATE', v2.error);
    assert.equal(v2.profile_id, profileV2.id);
    assert.equal(v2.native_output_sha256, outputHash(v2.events, 'v2'));
    assert.deepEqual(v2.events.map((row) => row.native_vector_source),
      ['NATIVE_DEFAULT_ZERO', 'PACKET_RAW_12']);
    assert.deepEqual(v2.events[0].native_vector_f32, [0, 0, 0]);
    assert.equal(v2.events[0].native_vector_protected_bytes_hex, '0b'.repeat(12));
    assert.equal(v2.events[0].native_vector_raw_f32_bytes_hex, '00'.repeat(12));
    assert.equal(v2.events[1].native_vector_protected_bytes_hex,
      '2cad7569287b66ec56981069');
    const decoded = decodeProtectedChangeMissileTargetVectorF32(
      v2.events[1].native_vector_protected_bytes_hex);
    assert.equal(v2.events[1].native_vector_raw_f32_bytes_hex,
      decoded.raw_bytes_hex);
    assert.deepEqual(v2.events[1].native_vector_f32, decoded.values);
    assert.equal(v2.events[1].target_status, 'UNKNOWN');
    assert.equal(v2.events[1].target_change_effect_status, 'UNKNOWN');
    const api = decodeSemanticReplay(replay, {
      capabilities: ['change_missile_target_packet'], runtimeImagePath: IMAGE,
      changeMissileTargetProfile: 'v2',
    });
    assert.equal(api.capability_results.change_missile_target_packet.profile_id,
      profileV2.id);
  });

test('V2 native vector is packet-byte local under 12 mutations and rejects wrong shapes',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const altered = [];
    for (let index = 1; index <= 12; index += 1) {
      const bytes = Buffer.from(LONG, 'hex');
      bytes[index] ^= 1;
      altered.push(packet(bytes.toString('hex'), 1100 + index));
    }
    const result = decode(fixture({ packets: [packet(LONG), ...altered] }), {
      runtimeImagePath: IMAGE, profileVersion: 'v2',
    });
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.native_full_success_count, 13);
    for (let index = 1; index <= 12; index += 1) {
      const before = Buffer.from(result.events[0].native_vector_protected_bytes_hex, 'hex');
      const after = Buffer.from(result.events[index].native_vector_protected_bytes_hex, 'hex');
      assert.equal(before.reduce((count, byte, offset) =>
        count + Number(byte !== after[offset]), 0), 1);
      assert.equal(result.events[index].native_callback_comparison_key_u32, 0);
    }
    for (const hex of [LONG.slice(0, -2), `${LONG}00`]) {
      const rejected = decode(fixture({ packets: [packet(hex)] }), {
        runtimeImagePath: IMAGE, profileVersion: 'v2',
      });
      assert.equal(rejected.status, 'DECODE_FAILED', hex);
      assert.equal(rejected.events, null);
    }
    const wrongImage = decode(fixture({ packets: [packet(LONG)] }), {
      runtimeImagePath: __filename, profileVersion: 'v2',
    });
    assert.equal(wrongImage.status, 'MISSING_INPUT');
    assert.equal(wrongImage.events, null);
  });
