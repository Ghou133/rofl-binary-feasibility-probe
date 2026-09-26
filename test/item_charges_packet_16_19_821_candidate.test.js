'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeSemanticReplay } = require('../src/semantic_api');
const {
  ITEM_CHARGES_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeItemChargesPacketCandidates821: decode,
  decodeProtectedItemChargesCallbackBytes,
} = require('../src/decoders/rofl_16_19_821_item_charges_packet_candidate');

const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;
const ORIGINAL = ['13', '36b1', '1e2e48', '0d631548'];
const EXPECTED = [[2, 2], [0, 35], [3, 3], [3, 129]];

function packet(hex, timeMs = 1000, id = 0x0437, param = 0x400000ae) {
  const payload = Buffer.from(hex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = profile.replay_version, stream = 1,
  packets = [packet(ORIGINAL[0])] } = {}) {
  return replayFromChunks([{ stream, body: Buffer.concat(packets) }], version);
}

function outputHash(rows) {
  const hash = crypto.createHash('sha256');
  for (const row of rows) {
    const args = Buffer.alloc(6);
    args.writeUInt32LE(row.native_callback_selector_u8, 0);
    args.writeUInt16LE(row.native_callback_value_u16, 4);
    hash.update(Buffer.from(row.native_protected_callback_bytes_hex, 'hex')).update(args);
  }
  return hash.digest('hex');
}

test('0x0437 is opt-in and bounded to the exact build, game stream and four lengths', () => {
  assert.equal(profile.replay_block_packet_id, 0x0437);
  assert.equal(profile.packet_name, 'PKT_S2C_SetItemCharges_s');
  assert.equal(decode(fixture({ version: '16.19.820.7193' })).status, 'UNSUPPORTED');
  assert.equal(decode(fixture({ packets: [packet('13', 1000, 0x040a)] })).status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decode(fixture()).missing_input, 'runtime_image');
  assert.equal(decode(fixture({ stream: 2 })).status, 'DECODE_FAILED');
  assert.equal(decode(fixture({ packets: [packet('13abcd0000')] })).status,
    'DECODE_FAILED');
  assert.deepEqual(decodeProtectedItemChargesCallbackBytes('b1c1eae6'),
    { selector_u8: 0, value_u16: 35 });
  assert.deepEqual(decodeProtectedItemChargesCallbackBytes('9fc136e6'),
    { selector_u8: 2, value_u16: 2 });
  assert.equal(decodeProtectedItemChargesCallbackBytes('zz'), null);
});

test('four original 0x0437 samples run the native reader and callback range check',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const replay = fixture({ packets: ORIGINAL.map((hex, index) =>
      packet(hex, 1000 + index * 100)) });
    const result = decode(replay, { runtimeImagePath: IMAGE });
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.native_full_success_count, 4);
    assert.equal(result.native_batch_count, 1);
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.native_pre_receiver_witness, 'NATIVE_RANGE_CHECK_PASSED');
    assert.equal(result.native_output_sha256, outputHash(result.events));
    assert.deepEqual(result.events.map(row => [row.native_callback_selector_u8,
      row.native_callback_value_u16]), EXPECTED);
    assert.deepEqual(result.events.map(row => row.raw_packet_ref.raw_payload_hex), ORIGINAL);
    for (const row of result.events) {
      assert.equal(row.raw_packet_ref.chunk_stream, 'game_chunk');
      assert.equal(row.native_receiver_status, 'NOT_EXECUTED');
      assert.equal(row.native_pre_receiver_witness, 'NATIVE_RANGE_CHECK_PASSED');
      for (const field of ['item_identity_status', 'charge_state_status',
        'slot_identity_status', 'owner_status', 'semantic_effect_status']) {
        assert.equal(row[field], 'UNKNOWN');
      }
      assert.equal('item_id' in row, false);
      assert.equal('slot' in row, false);
      assert.equal('charges' in row, false);
    }
    const api = decodeSemanticReplay(replay, {
      capabilities: ['item_charges_packet'], runtimeImagePath: IMAGE,
    });
    assert.equal(api.capability_results.item_charges_packet.status, 'CANDIDATE');
  });

test('native full-consumption gate rejects an appended or truncated original packet',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const appended = decode(fixture({ packets: [packet('0d63154800')] }),
      { runtimeImagePath: IMAGE });
    assert.equal(appended.status, 'DECODE_FAILED');
    assert.equal(appended.events, null);
    const truncated = decode(fixture({ packets: [packet('0d6315')] }),
      { runtimeImagePath: IMAGE });
    assert.equal(truncated.status, 'DECODE_FAILED');
    assert.equal(truncated.events, null);
  });

test('missing native runner is reported after image precheck without candidate rows',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 image unavailable' : false }, () => {
    const result = decode(fixture(), { runtimeImagePath: IMAGE,
      pythonExecutable: `${__filename}.missing-python` });
    assert.equal(result.status, 'MISSING_INPUT');
    assert.equal(result.missing_input, 'python_unicorn');
    assert.equal(result.runtime_image_status, 'MATCHED_PRECHECKED');
    assert.equal(result.runtime_image_used, false);
    assert.equal(result.events, null);
  });

test('wrong image never emits 0x0437 candidate rows', () => {
  const result = decode(fixture(), { runtimeImagePath: __filename });
  assert.equal(result.status, 'MISSING_INPUT');
  assert.equal(result.events, null);
});
