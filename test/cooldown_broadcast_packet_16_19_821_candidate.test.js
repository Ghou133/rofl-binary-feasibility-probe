'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeSemanticReplay } = require('../src/semantic_api');
const {
  COOLDOWN_BROADCAST_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeCooldownBroadcastPacketCandidates821: decode,
  decodeProtectedCooldownLookupKeyU32,
  COOLDOWN_BROADCAST_PACKET_CANDIDATE_PROFILE_V2_821: profileV2,
  cooldownRequestFieldsError821,
} = require('../src/decoders/rofl_16_19_821_cooldown_broadcast_packet_candidate');

const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;
const SHORT = '733e';
const LONG = '70661cc0ec7878';
const RAW_PARAM = 0x400000ae;

function packet(hex, timeMs = 1000, id = 0x039d, param = RAW_PARAM) {
  const payload = Buffer.from(hex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = profile.replay_version, stream = 2,
  packets = [packet(SHORT)] } = {}) {
  return replayFromChunks([{ stream, body: Buffer.concat(packets) }], version);
}

function outputHash(rows) {
  const hash = crypto.createHash('sha256');
  for (const row of rows) {
    const key = Buffer.alloc(4);
    key.writeUInt32LE(row.native_callback_lookup_key_u32);
    hash.update(Buffer.from(row.native_protected_lookup_byte_hex, 'hex')).update(key);
  }
  return hash.digest('hex');
}

test('0x039d is opt-in, exact-build and eight-length bounded', () => {
  assert.equal(profile.replay_block_packet_id, 0x039d);
  assert.equal(profile.packet_name, 'PKT_CHAR_SetCooldown_Broadcast_s');
  assert.equal(decode(fixture({ version: '16.19.820.7193' })).status, 'UNSUPPORTED');
  assert.equal(decode(fixture({ packets: [packet(SHORT, 1000, 0x040a)] })).status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decode(fixture()).missing_input, 'runtime_image');
  assert.equal(decode(fixture({ stream: 1 })).missing_input, 'runtime_image');
  assert.equal(decode(fixture({ packets: [packet('733e0000')] })).status,
    'DECODE_FAILED');
  assert.equal(decodeProtectedCooldownLookupKeyU32('24'), 0);
  assert.equal(decodeProtectedCooldownLookupKeyU32('26'), 1);
  assert.equal(decodeProtectedCooldownLookupKeyU32('zz'), null);
});

test('original 0x039d samples yield native callback key while state stays unknown',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const result = decode(fixture({ stream: 1,
      packets: [packet(SHORT), packet(LONG, 1100)] }), { runtimeImagePath: IMAGE });
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.native_full_success_count, 2);
    assert.equal(result.native_batch_count, 1);
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.native_output_sha256, outputHash(result.events));
    assert.deepEqual(result.events.map((row) => row.native_callback_lookup_key_u32),
      [0, 4]);
    assert.deepEqual(result.events.map((row) => row.raw_packet_ref.raw_payload_hex),
      [SHORT, LONG]);
    for (const row of result.events) {
      assert.equal(row.raw_packet_ref.chunk_stream, 'game_chunk');
      assert.equal(row.native_receiver_lookup_status, 'NOT_OBSERVED');
      for (const field of ['cooldown_state_status', 'slot_identity_status',
        'actor_status', 'target_status', 'semantic_effect_status']) {
        assert.equal(row[field], 'UNKNOWN');
      }
      assert.equal('cooldown' in row, false);
      assert.equal('slot' in row, false);
    }
    const api = decodeSemanticReplay(fixture(), {
      capabilities: ['cooldown_broadcast_packet'], runtimeImagePath: IMAGE,
    });
    assert.equal(api.capability_results.cooldown_broadcast_packet.status,
      'CANDIDATE');
  });

test('native full consumption rejects an appended or truncated packet',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const appended = decode(fixture({ packets: [packet('733e00')] }),
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

test('cooldown V2 selection is explicit and invalid profile fails closed', () => {
  const {parseArgs}=require('../src/cli');
  assert.equal(decode(fixture(),{cooldownPacketProfile:'v2'}).profile_id,profileV2.id);
  assert.equal(decode(fixture(),{cooldownPacketProfile:'v3'}).status,'UNSUPPORTED');
  for(const args of [ ['query-events','unused','--list-events'], ['decode','unused','--events','hero_death'] ]) {
    assert.throws(()=>parseArgs([...args,'--cooldown-packet-v2']),/requires decode or batch/);
  }
});

test('V2 original packet slices expose f32 intent without executing receiver or changing V1',
  {skip:!IMAGE||!fs.existsSync(IMAGE)?'exact 821 image unavailable':false},()=>{
    const replay=fixture({stream:1,packets:[packet(SHORT),packet(LONG,1100)]});
    const v2=decode(replay,{runtimeImagePath:IMAGE,cooldownPacketProfile:'v2'});
    assert.equal(v2.status,'CANDIDATE',v2.error);
    assert.equal(v2.evidence_request_mode,'NATIVE_PACKET_ONLY_CALLBACK_SLICES');
    assert.deepEqual(v2.events.map(row=>row.native_callback_request.argument_f32),[[0,-1,0,0],[15,0,0,0]]);
    for(const row of v2.events){
      assert.equal(cooldownRequestFieldsError821(row.native_callback_request),null);
      assert.equal(row.native_callback_request.application_status,'NOT_OBSERVED');
      assert.equal(row.native_receiver_lookup_status,'NOT_OBSERVED');
      assert.equal(row.cooldown_state_status,'UNKNOWN');
    }
    const forged=structuredClone(v2.events[1].native_callback_request);
    forged.argument_f32[0]=16;
    assert.ok(cooldownRequestFieldsError821(forged));
    forged.argument_f32[0]=15;forged.application_status='APPLIED';
    assert.ok(cooldownRequestFieldsError821(forged));
    const v1=decode(replay,{runtimeImagePath:IMAGE});
    assert.equal(v1.profile_id,profile.id);
    assert.equal('native_callback_request' in v1.events[0],false);
    assert.equal(v1.native_output_sha256,outputHash(v1.events));
    const api=decodeSemanticReplay(replay,{capabilities:['cooldown_broadcast_packet'],runtimeImagePath:IMAGE,cooldownPacketProfile:'v2'});
    assert.equal(api.capability_results.cooldown_broadcast_packet.profile_id,profileV2.id);
  });
