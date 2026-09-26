'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  NOTIFY_CONTEXTUAL_SITUATION_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeNotifyContextualSituationPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_notify_contextual_situation_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;
const REPLAY = process.env.ROFL_821_REPLAY;
const LEAD_IN = '0cc3aafbf72fbf89888831f7311f';
const HONEYFRUIT = '0c949876887d76a7c2dd06e8fb45f7';

function nativeOutputSha256(rows) {
  const digest = crypto.createHash('sha256');
  const header = Buffer.alloc(8);
  for (const row of rows) {
    const bytes = Buffer.from(row.contextual_situation_utf8_hex, 'hex');
    header.writeUInt32LE(row.native_string_length, 0);
    header.writeUInt32LE(row.native_string_capacity, 4);
    digest.update(header);
    digest.update(bytes);
  }
  return digest.digest('hex');
}

function packet(payloadHex, timeMs = 1000, packetId = 0x0113,
  rawParam = 0x400000b4) {
  const payload = Buffer.from(payloadHex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, stream = 1,
  packets = [packet(LEAD_IN)] } = {}) {
  return replayFromChunks([{ stream, body: Buffer.concat(packets) }], version);
}

test('821 route 0x0113 is a distinct opt-in packet candidate with exact source gates', () => {
  assert.equal(profile.replay_block_packet_id, 0x0113);
  assert.equal(profile.packet_name, 'PKT_S2C_NotifyContextualSituation_s');
  assert.equal(profile.runtime_image_required, true);
  assert.equal(decode(fixture({ version: '16.19.820.7193' })).status, 'UNSUPPORTED');
  assert.equal(decode(fixture({ packets: [packet(LEAD_IN, 1000, 0x0114)] })).status,
    'PROFILE_UNAVAILABLE');
  const missing = decode(fixture());
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.events, null);
  const foreignStream = decode(fixture({ stream: 2 }));
  assert.equal(foreignStream.status, 'DECODE_FAILED');
  assert.equal(foreignStream.events, null);
  const foreignLength = decode(fixture({ packets: [packet(`${LEAD_IN}00000000`)] }));
  assert.equal(foreignLength.status, 'DECODE_FAILED');
  assert.equal(foreignLength.first_failed_packet_ref.payload_length, 18);
});

test('exact runtime decodes two original packet strings and binds each to its source',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 runtime image unavailable' : false }, () => {
    const result = decode(fixture({ packets: [
      packet(LEAD_IN), packet(HONEYFRUIT, 1100, 0x0113, 0x400000b2),
    ] }), { runtimeImagePath: IMAGE });
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.input_count, 2);
    assert.equal(result.event_count, 2);
    assert.equal(result.native_full_success_count, 2);
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.native_output_sha256, nativeOutputSha256(result.events));
    assert.deepEqual(result.events.map((row) => row.contextual_situation),
      ['RecallLeadIn', 'EatHoneyfruit']);
    assert.deepEqual(result.events.map((row) => row.raw_packet_ref.raw_payload_hex),
      [LEAD_IN, HONEYFRUIT]);
    for (const row of result.events) {
      assert.equal(row.raw_packet_ref.packet_id, 0x0113);
      assert.equal(row.raw_packet_ref.replay_sha256, row.replay_sha256);
      assert.equal(row.semantic_effect_status, 'UNKNOWN');
      assert.equal(row.native_string_length,
        Buffer.from(row.contextual_situation, 'utf8').length);
      assert.equal(row.contextual_situation_utf8_hex,
        Buffer.from(row.contextual_situation, 'utf8').toString('hex'));
      assert.equal(row.raw_packet_ref.raw_payload_sha256,
        crypto.createHash('sha256').update(Buffer.from(row.raw_packet_ref.raw_payload_hex,
          'hex')).digest('hex'));
      for (const inferred of ['actor', 'team', 'effect', 'receiver', 'participant_id']) {
        assert.equal(inferred in row, false);
      }
    }
  });

test('exact native witness rejects trailing bytes and a wrong runtime image',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 runtime image unavailable' : false }, () => {
    const appended = decode(fixture({ packets: [packet(`${LEAD_IN}00`)] }),
      { runtimeImagePath: IMAGE });
    assert.equal(appended.status, 'DECODE_FAILED');
    assert.equal(appended.events, null);
    assert.equal(appended.native_witness_status, 'FAILED');
    const wrongImage = decode(fixture(), { runtimeImagePath: __filename });
    assert.equal(wrongImage.status, 'DECODE_FAILED');
    assert.equal(wrongImage.runtime_image_status, 'HASH_MISMATCH');
    assert.equal(wrongImage.events, null);
  });

test('missing Python leaves a matched image prechecked but unused',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 runtime image unavailable' : false }, () => {
    const result = decode(fixture(), {
      runtimeImagePath: IMAGE,
      pythonExecutable: path.join(__dirname, 'no-such-821-python-executable'),
    });
    assert.equal(result.status, 'MISSING_INPUT');
    assert.equal(result.missing_input, 'python_unicorn');
    assert.equal(result.runtime_image_status, 'MATCHED_PRECHECKED');
    assert.equal(result.runtime_image_used, false);
    assert.equal(result.native_witness_status, 'UNAVAILABLE');
    assert.equal(result.events, null);
  });

test('native helper returns an ordered packet string witness',
  { skip: !IMAGE || !fs.existsSync(IMAGE) ? 'exact 821 runtime image unavailable' : false }, () => {
    const helper = path.resolve(__dirname, '..', 'scripts',
      'decode_notify_contextual_situation_packet_16_19_821.py');
    const run = spawnSync(process.env.PYTHON || 'python', ['-B', helper, '--image', IMAGE], {
      input: JSON.stringify({ replay_version: BUILD, packet_id: 0x0113,
        packets: [[0x400000b4, LEAD_IN], [0x400000b2, HONEYFRUIT]] }),
      encoding: 'utf8', timeout: 120000,
    });
    assert.equal(run.status, 0, run.stderr);
    const native = JSON.parse(run.stdout);
    assert.equal(native.packet_count, 2);
    assert.equal(native.native_full_success_count, 2);
    assert.equal(native.native_output_sha256, nativeOutputSha256(native.rows));
    assert.deepEqual(native.rows.map((row) => row.contextual_situation),
      ['RecallLeadIn', 'EatHoneyfruit']);
  });

test('one supplied KR replay preserves every route 0x0113 packet as a candidate',
  { skip: !IMAGE || !REPLAY || !fs.existsSync(IMAGE) || !fs.existsSync(REPLAY)
    ? 'original Replay or exact runtime image unavailable' : false }, () => {
    const result = decode(parseReplayFile(REPLAY), { runtimeImagePath: IMAGE });
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.event_count, result.input_count);
    assert.equal(result.native_full_success_count, result.input_count);
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.ok(result.events.some((row) => row.contextual_situation === 'RecallCancel'));
  });
