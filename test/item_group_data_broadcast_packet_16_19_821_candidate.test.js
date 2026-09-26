'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeSemanticReplay } = require('../src/semantic_api');
const {
  ITEM_GROUP_DATA_BROADCAST_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeItemGroupDataBroadcastPacketCandidates821: decode,
  decodeProtectedLookupU32,
} = require('../src/decoders/rofl_16_19_821_item_group_data_broadcast_packet_candidate');

const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;
const FIRST = '1e567825e7f836';
const SECOND = '1e5670099d3d48';

function packet(hex, timeMs = 1000, id = 0x013f, param = 0x400000ae) {
  const payload = Buffer.from(hex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = profile.replay_version, stream = 2,
  packets = [packet(FIRST)] } = {}) {
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

test('0x013f has exact build, route, keyframe, and observed-shape gates', () => {
  assert.equal(profile.replay_block_packet_id, 0x013f);
  assert.equal(profile.packet_name, 'PKT_S2C_SetItemGroupData_Broadcast_s');
  assert.equal(decode(fixture({ version: '16.19.820.7193' })).status, 'UNSUPPORTED');
  assert.equal(decode(fixture({ packets: [packet(FIRST, 1000, 0x040a)] })).status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decode(fixture()).missing_input, 'runtime_image');
  assert.equal(decode(fixture({ stream: 1 })).status, 'DECODE_FAILED');
  assert.equal(decode(fixture({ packets: [packet(`${FIRST}000000`)] })).status,
    'DECODE_FAILED');
  assert.equal(decodeProtectedLookupU32('251064ea'), 5247418);
});

test('two original 0x013f packets produce ordered exact-image native lookup keys',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const replay = fixture({ packets: [packet(FIRST), packet(SECOND, 1100)] });
    const result = decode(replay, { runtimeImagePath: IMAGE });
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.input_count, 2);
    assert.equal(result.native_full_success_count, 2);
    assert.equal(result.native_batch_count, 1);
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.native_output_sha256, outputHash(result.events));
    assert.deepEqual(result.events.map((row) => row.native_callback_lookup_key_u32),
      [5247418, 6444154]);
    assert.deepEqual(result.events.map((row) => row.raw_packet_ref.raw_payload_hex),
      [FIRST, SECOND]);
    for (const row of result.events) {
      assert.equal(row.raw_packet_ref.chunk_stream, 'keyframe');
      assert.equal(row.native_receiver_lookup_status, 'NOT_OBSERVED');
      for (const field of ['group_identity_status', 'item_identity_status',
        'owner_status', 'participant_status', 'inventory_state_change_status',
        'semantic_effect_status']) assert.equal(row[field], 'UNKNOWN');
      assert.equal('item_id' in row, false);
      assert.equal('slot' in row, false);
    }
    const api = decodeSemanticReplay(replay, {
      capabilities: ['item_group_data_broadcast_packet'], runtimeImagePath: IMAGE,
    });
    assert.equal(api.capability_results.item_group_data_broadcast_packet.status,
      'CANDIDATE');
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
