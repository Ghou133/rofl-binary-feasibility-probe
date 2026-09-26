'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeSemanticReplay } = require('../src/semantic_api');
const {
  TARGET_HERO_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeTargetHeroPacketCandidates821: decode,
  decodeProtectedTargetHeroLookupKeyU32,
} = require('../src/decoders/rofl_16_19_821_target_hero_packet_candidate');

const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;
const SHORT = '33';
const LONG = '37c68e';
const RAW_PARAM = 0x400000b5;

function packet(hex, timeMs = 1000, id = 0x0265, param = RAW_PARAM) {
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
    key.writeUInt32LE(row.native_callback_lookup_key_u32);
    hash.update(Buffer.from(row.native_protected_lookup_bytes_hex, 'hex')).update(key);
  }
  return hash.digest('hex');
}

test('0x0265 is opt-in, exact-build and two-shape bounded', () => {
  assert.equal(profile.replay_block_packet_id, 0x0265);
  assert.equal(profile.packet_name, 'PKT_AI_TargetHeroS2C_s');
  assert.equal(decode(fixture({ version: '16.19.820.7193' })).status, 'UNSUPPORTED');
  assert.equal(decode(fixture({ packets: [packet(SHORT, 1000, 0x040a)] })).status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decode(fixture()).missing_input, 'runtime_image');
  assert.equal(decode(fixture({ stream: 2 })).status, 'DECODE_FAILED');
  assert.equal(decode(fixture({ packets: [packet('330000')] })).status,
    'DECODE_FAILED');
  assert.equal(decodeProtectedTargetHeroLookupKeyU32('35353535'), 0);
  assert.equal(decodeProtectedTargetHeroLookupKeyU32('c63535f3'), 0x400000b0);
  assert.equal(decodeProtectedTargetHeroLookupKeyU32('zz'), null);
});

test('original 0x0265 samples yield native callback key while state stays unknown',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const result = decode(fixture({ stream: 1,
      packets: [packet(SHORT), packet(LONG, 1100)] }), { runtimeImagePath: IMAGE });
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.native_full_success_count, 2);
    assert.equal(result.native_batch_count, 1);
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.native_output_sha256, outputHash(result.events));
    assert.deepEqual(result.events.map((row) => row.native_callback_lookup_key_u32),
      [0, 0x400000b0]);
    assert.deepEqual(result.events.map((row) => row.raw_packet_ref.raw_payload_hex),
      [SHORT, LONG]);
    for (const row of result.events) {
      assert.equal(row.raw_packet_ref.chunk_stream, 'game_chunk');
      assert.equal(row.native_receiver_call_status, 'NOT_EXECUTED');
      for (const field of ['source_actor_status', 'target_object_status',
        'target_state_status', 'semantic_effect_status']) {
        assert.equal(row[field], 'UNKNOWN');
      }
      assert.equal('target_object' in row, false);
    }
    const api = decodeSemanticReplay(fixture(), {
      capabilities: ['target_hero_packet'], runtimeImagePath: IMAGE,
    });
    assert.equal(api.capability_results.target_hero_packet.status,
      'CANDIDATE');
  });

test('observed shape gate rejects appended and truncated packet bodies',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const appended = decode(fixture({ packets: [packet('3300')] }),
      { runtimeImagePath: IMAGE });
    assert.equal(appended.status, 'DECODE_FAILED');
    assert.equal(appended.events, null);
    const truncated = decode(fixture({ packets: [packet(LONG.slice(0, -2))] }),
      { runtimeImagePath: IMAGE });
    assert.equal(truncated.status, 'DECODE_FAILED');
    assert.equal(truncated.events, null);
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
