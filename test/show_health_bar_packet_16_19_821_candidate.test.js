'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  SHOW_HEALTH_BAR_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeShowHealthBarPacketCandidates821: decode,
  decodeShowHealthBarPayload821: decodePayload,
} = require('../src/decoders/rofl_16_19_821_show_health_bar_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_PATH = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY_PATH = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');
const HAS_IMAGE = fs.existsSync(IMAGE_PATH);
const HAS_REPLAY = fs.existsSync(REPLAY_PATH);

function packet(rawPayloadHex, timeMs = 1000, packetId = 0x0165,
  rawParam = 0x40000088) {
  const payload = Buffer.from(rawPayloadHex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, keyframe = [packet('4a', 0)],
  game = [packet('4b', 1000)] } = {}) {
  return replayFromChunks([
    { stream: 2, body: Buffer.concat(keyframe) },
    { stream: 1, body: Buffer.concat(game) },
  ], version);
}

test('821 ShowHealthBar retains two observed native callback flags and packet refs',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const result = decode(fixture(), { runtimeImagePath: IMAGE_PATH });
    assert.equal(profile.packet_name, 'PKT_S2C_ShowHealthBar_s');
    assert.equal(result.status, 'CANDIDATE');
    assert.equal(result.input_count, 2);
    assert.equal(result.event_count, 2);
    assert.equal(result.native_witness_status, 'FULLY_CONSUMED_ALL');
    assert.equal(result.native_full_success_count, 2);
    assert.deepEqual(result.observed_payload_counts, { '4a': 1, '4b': 1 });
    assert.deepEqual(result.events.map((row) => row.native_object_byte_0x10_hex),
      ['a5', 'fd']);
    assert.deepEqual(result.events.map((row) => row.callback_byte_candidate), [1, 0]);
    assert.deepEqual(result.events.map((row) => row.callback_zero_flag_candidate), [0, 1]);
    assert.deepEqual(result.events.map((row) => row.raw_packet_ref.chunk_stream),
      ['keyframe', 'game_chunk']);
    assert.deepEqual(result.events.map((row) => row.raw_packet_ref.raw_payload_hex),
      ['4a', '4b']);
    for (const row of result.events) {
      assert.equal(row.semantic_effect_status, 'UNKNOWN');
      assert.equal(row.raw_packet_ref.replay_sha256, result.events[0].replay_sha256);
      for (const forbidden of ['health', 'damage', 'actor', 'participant_id',
        'source', 'target', 'effect']) assert.equal(forbidden in row, false);
    }
  });

test('821 ShowHealthBar saved payload decoder limits the observed raw byte family', () => {
  assert.deepEqual(decodePayload('4a'), {
    raw_payload_byte_hex: '4a', native_object_byte_0x10_hex: 'a5',
    callback_byte_candidate: 1, callback_zero_flag_candidate: 0,
  });
  assert.deepEqual(decodePayload('4b'), {
    raw_payload_byte_hex: '4b', native_object_byte_0x10_hex: 'fd',
    callback_byte_candidate: 0, callback_zero_flag_candidate: 1,
  });
  for (const foreign of ['00', '49', '4c', 'ff', '4a00', '4A', '', null]) {
    assert.equal(decodePayload(foreign), null);
  }
});

test('821 ShowHealthBar rejects an unobserved byte or length before emitting events', () => {
  for (const foreign of ['00', '49', '4c', 'ff', '4a00']) {
    const result = decode(fixture({ game: [packet('4b'), packet(foreign, 1100)] }),
      { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'DECODE_FAILED', foreign);
    assert.equal(result.runtime_image_status, 'NOT_CHECKED', foreign);
    assert.equal(result.input_count, 3, foreign);
    assert.equal(result.events, null, foreign);
    assert.equal(result.first_failed_packet_ref.raw_payload_hex, foreign);
  }
});

test('821 ShowHealthBar reports overflow without dropping a selected packet', () => {
  const one = packet('4a');
  const body = Buffer.alloc(one.length * 100_001);
  for (let offset = 0; offset < body.length; offset += one.length) one.copy(body, offset);
  const replay = replayFromChunks([{ stream: 1, body }], BUILD);
  const result = decode(replay);
  assert.equal(result.status, 'UNSUPPORTED');
  assert.equal(result.input_count, 100_001);
  assert.equal(result.observed_packet_count_minimum, 100_001);
  assert.equal(result.events, null);
});

test('821 ShowHealthBar distinguishes wrong build, absent route, missing image and wrong image', () => {
  assert.equal(decode(fixture({ version: '16.19.820.7193' }),
    { runtimeImagePath: IMAGE_PATH }).status, 'UNSUPPORTED');
  const absent = decode(fixture({ keyframe: [packet('4a', 0, 0x0166)], game: [] }),
    { runtimeImagePath: IMAGE_PATH });
  assert.equal(absent.status, 'PROFILE_UNAVAILABLE');
  const missing = decode(fixture());
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.events, null);
  const wrong = decode(fixture(), { runtimeImagePath: __filename });
  assert.equal(wrong.status, 'DECODE_FAILED');
  assert.equal(wrong.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(wrong.events, null);
});

test('821 ShowHealthBar fails closed when its native runtime is unavailable',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const absentPython = path.join(os.tmpdir(),
      `show-health-bar-821-no-python-${process.pid}-${Date.now()}`);
    const result = decode(fixture(), {
      runtimeImagePath: IMAGE_PATH, pythonExecutable: absentPython,
    });
    assert.equal(result.status, 'MISSING_INPUT');
    assert.equal(result.missing_input, 'python_unicorn');
    assert.equal(result.native_witness_status, 'UNAVAILABLE');
    assert.equal(result.events, null);
  });

test('821 ShowHealthBar rejects native witness output for different ordered bytes',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, (t) => {
    t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
      const request = JSON.parse(options.input);
      assert.deepEqual(request.packets.map((entry) => entry[1]), ['4a', '4b']);
      return { status: 0, stdout: JSON.stringify({
        replay_version: BUILD,
        runtime_image_sha256: profile.evidence_runtime_image_sha256,
        packet_id: 0x0165,
        packet_count: 2,
        input_sha256: '0'.repeat(64),
        native_full_success_count: 2,
        callback_flag_one_count: 1,
        first_failure: null,
      }), stderr: '' };
    });
    const result = decode(fixture(), { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.native_witness_status, 'FAILED');
    assert.equal(result.events, null);
  });

test('821 native probe exposes foreign one-byte acceptance as a negative control',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const helper = path.resolve(__dirname, '..', 'scripts',
      'decode_show_health_bar_packet_16_19_821.py');
    const inputs = ['4a', '4b', '00', '49', '4c', 'ff', '4a00', ''];
    const run = childProcess.spawnSync(process.env.PYTHON || 'python',
      ['-B', helper, '--image', IMAGE_PATH, '--probe'], {
        input: JSON.stringify({
          replay_version: BUILD, packet_id: 0x0165,
          packets: inputs.map((raw, index) => [0x40000088 + index, raw]),
        }),
        encoding: 'utf8', maxBuffer: 1_000_000,
      });
    assert.equal(run.status, 0, run.stderr);
    const probe = JSON.parse(run.stdout);
    assert.deepEqual(probe.rows.map((row) => row.observed_shape),
      [true, true, false, false, false, false, false, false]);
    for (const row of probe.rows.slice(0, 6)) {
      assert.equal(row.deserialize_return_al, 1);
      assert.equal(row.fully_consumed, true);
      assert.equal(row.bytes_consumed, 1);
      assert.equal(row.object_raw_param, 0x40000088 + row.index);
    }
    assert.equal(probe.rows[6].deserialize_return_al, 1);
    assert.equal(probe.rows[6].fully_consumed, false);
    assert.equal(probe.rows[6].bytes_consumed, 1);
    assert.equal(probe.rows[7].deserialize_return_al, 0);
  });

test('one supplied KR Replay preserves every 0x0165 packet under native witness',
  { skip: !(HAS_IMAGE && HAS_REPLAY) && 'original KR Replay and exact image are unavailable' }, () => {
    const result = decode(parseReplayFile(REPLAY_PATH), { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'CANDIDATE');
    assert.equal(result.input_count, 7_329);
    assert.equal(result.event_count, 7_329);
    assert.equal(result.native_full_success_count, 7_329);
    assert.deepEqual(result.observed_payload_counts, { '4a': 5_994, '4b': 1_335 });
    assert.equal(result.events.length, 7_329);
  });
