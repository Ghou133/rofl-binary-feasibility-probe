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
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeUnitApplyDamagePacketCandidates821: decode,
  decodeUnitApplyDamageCallbackF32FromRaw821: decodeFloat,
} = require('../src/decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_PATH = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY_PATH = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');
const HAS_IMAGE = fs.existsSync(IMAGE_PATH);
const HAS_REPLAY = fs.existsSync(REPLAY_PATH);
const COMMON_PACKET_HEX = '71875e460b083dbaef3ba6ec39b975';
const SAME_SHAPE_NONCONSUMED_HEX = '71875e460b083dbaef3aa6ec39b975';
const OTHER_PACKET_HEX = '54814747c6c4d9a90b6ef07c44e2ecaf5b75';

function packet(rawParam, payloadHex, timeMs = 1500) {
  const payload = Buffer.from(payloadHex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x005f, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, payloads = [COMMON_PACKET_HEX, OTHER_PACKET_HEX] } = {}) {
  return replayFromChunks([{
    stream: 1,
    body: Buffer.concat(payloads.map((payloadHex, index) =>
      packet(0x40004007, payloadHex, 1500 + 100 * index))),
  }], version);
}

test('821 UnitApplyDamage emits packet selectors and only the native-matched family float',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const result = decode(fixture(), { runtimeImagePath: IMAGE_PATH });
    assert.equal(profile.evidence_status,
      'CANDIDATE_EXACT_821_UNIT_APPLY_DAMAGE_PACKET_FIELDS');
    assert.equal(result.status, 'CANDIDATE');
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.input_count, 2);
    assert.equal(result.event_count, 2);
    assert.equal(result.callback_f32_available_count, 1);
    assert.equal(result.callback_f32_unavailable_count, 1);
    const [common, other] = result.events;
    assert.deepEqual([
      common.header_selector_bits_24_26,
      common.header_selector_bits_0_2,
      common.header_selector_bits_3_5,
    ], [6, 1, 6]);
    assert.equal(common.callback_f32_0x20_candidate, 0.5460192561149597);
    assert.equal(common.callback_f32_0x20_raw_bytes_hex, '083dbaef');
    assert.equal(common.callback_f32_0x20_status, 'NATIVE_MATCHED_SHAPE');
    assert.equal(other.callback_f32_0x20_candidate, null);
    assert.equal(other.callback_f32_0x20_status, 'UNAVAILABLE_SHAPE');
    assert.equal(other.raw_packet_ref.raw_payload_hex, OTHER_PACKET_HEX);
    assert.equal(other.raw_packet_ref.packet_id, 0x005f);
    for (const row of result.events) {
      for (const forbidden of ['source', 'target', 'damage_amount', 'amount',
        'actor_id', 'participant_id_candidate', 'effective_health_loss']) {
        assert.equal(forbidden in row, false);
      }
    }
  });

test('saved callback float can be rederived from exact raw bytes without an image', () => {
  assert.equal(decodeFloat('083dbaef'), 0.5460192561149597);
  assert.equal(decodeFloat('083DBAEF'), null);
  assert.equal(decodeFloat('083dba'), null);
});

test('821 UnitApplyDamage fails the capability for an unobserved shape', () => {
  const changed = Buffer.from(COMMON_PACKET_HEX, 'hex');
  changed[3] = (changed[3] & 0xf8) | 2;
  const result = decode(fixture({ payloads: [COMMON_PACKET_HEX, changed.toString('hex')] }),
    { runtimeImagePath: IMAGE_PATH });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.input_count, 2);
  assert.equal(result.events, null);
  assert.equal(result.first_failed_packet_ref.raw_payload_hex, changed.toString('hex'));
  const changedThird = Buffer.from(COMMON_PACKET_HEX, 'hex');
  changedThird[0] = (changedThird[0] & ~0x38) | (3 << 3);
  const third = decode(fixture({ payloads: [changedThird.toString('hex')] }),
    { runtimeImagePath: IMAGE_PATH });
  assert.equal(third.status, 'DECODE_FAILED');
  assert.equal(third.events, null);
});

test('821 UnitApplyDamage rejects a same-selector and same-length native partial parse',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const original = Buffer.from(COMMON_PACKET_HEX, 'hex');
    const changed = Buffer.from(SAME_SHAPE_NONCONSUMED_HEX, 'hex');
    assert.equal(original.length, changed.length);
    assert.equal(original[3] & 7, changed[3] & 7);
    assert.equal(original[0] & 63, changed[0] & 63);
    const result = decode(fixture({ payloads: [COMMON_PACKET_HEX, SAME_SHAPE_NONCONSUMED_HEX] }),
      { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
    assert.equal(result.native_witness_status, 'FAILED');
    assert.equal(result.native_full_success_count, 1);
    assert.equal(result.first_failed_packet_ref.raw_payload_hex, SAME_SHAPE_NONCONSUMED_HEX);
  });

test('821 UnitApplyDamage distinguishes missing and wrong runtime image', () => {
  const replay = fixture();
  const missing = decode(replay);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.input_count, 2);
  assert.equal(missing.events, null);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'unit-damage-821-'));
  try {
    const wrongPath = path.join(directory, 'wrong.bin');
    fs.writeFileSync(wrongPath, Buffer.alloc(256));
    const wrong = decode(replay, { runtimeImagePath: wrongPath });
    assert.equal(wrong.status, 'DECODE_FAILED');
    assert.equal(wrong.runtime_image_status, 'HASH_MISMATCH');
    assert.equal(wrong.events, null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('821 UnitApplyDamage fails closed when native runtime is unavailable',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const absentPython = path.join(os.tmpdir(),
      `unit-damage-821-no-python-${process.pid}-${Date.now()}`);
    const result = decode(fixture({ payloads: [COMMON_PACKET_HEX] }), {
      runtimeImagePath: IMAGE_PATH, pythonExecutable: absentPython,
    });
    assert.equal(result.status, 'MISSING_INPUT');
    assert.equal(result.missing_input, 'python_unicorn');
    assert.equal(result.native_witness_status, 'UNAVAILABLE');
    assert.equal(result.events, null);
  });

test('821 UnitApplyDamage rejects a native response for different input bytes',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, (t) => {
    t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
      const request = JSON.parse(options.input);
      assert.equal(request.packets.length, 1);
      return { status: 0, stdout: JSON.stringify({
        replay_version: BUILD,
        runtime_image_sha256: profile.evidence_runtime_image_sha256,
        packet_id: 0x005f,
        packet_count: 1,
        input_sha256: '0'.repeat(64),
        native_full_success_count: 1,
        first_failure: null,
        float_rows: [[0, 0.5460192561149597]],
      }), stderr: '' };
    });
    const result = decode(fixture({ payloads: [COMMON_PACKET_HEX] }),
      { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.native_witness_status, 'FAILED');
    assert.equal(result.events, null);
  });

test('821 UnitApplyDamage rejects a different full build', () => {
  const result = decode(fixture({ version: '16.19.820.7193' }),
    { runtimeImagePath: IMAGE_PATH });
  assert.equal(result.status, 'UNSUPPORTED');
  assert.equal(result.events, null);
});

test('821 native witness accepts the calibrated packet and rejects truncation and append',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const helper = path.resolve(__dirname, '..', 'scripts',
      'decode_unit_apply_damage_packet_16_19_821.py');
    const packets = [COMMON_PACKET_HEX,
      COMMON_PACKET_HEX.slice(0, -2), `${COMMON_PACKET_HEX}00`].map((payloadHex) => ({
      packet_id: 0x005f, stream_tag: 1, raw_param: 0x40004007, payload_hex: payloadHex,
    }));
    const run = childProcess.spawnSync(process.env.PYTHON || 'python',
      [helper, '--image', IMAGE_PATH], {
        input: JSON.stringify({ replay_version: BUILD, packets }),
        encoding: 'utf8', maxBuffer: 1_000_000,
      });
    assert.equal(run.status, 0, run.stderr);
    const native = JSON.parse(run.stdout);
    assert.equal(native.native_full_success_count, 1);
    assert.deepEqual(native.rows.map((row) => row.status),
      ['DECODED', 'FAILED', 'FAILED']);
    assert.equal(native.rows[0].callback_f32_0x20_candidate, 0.5460192561149597);
    assert.equal(native.rows[1].deserialize_return_al, 0);
    assert.equal(native.rows[2].fully_consumed, false);
  });

test('one supplied KR Replay keeps every 0x005f packet and reports unavailable floats',
  { skip: !(HAS_IMAGE && HAS_REPLAY) && 'original exact-build KR Replay and image are unavailable' }, () => {
    const result = decode(parseReplayFile(REPLAY_PATH), { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'CANDIDATE');
    assert.equal(result.input_count, 64_824);
    assert.equal(result.event_count, result.input_count);
    assert.equal(result.callback_f32_available_count, 684);
    assert.equal(result.callback_f32_unavailable_count, 64_140);
    assert.equal(result.observed_shape_family_count, 595);
    assert.equal(result.events[0].raw_packet_ref.raw_payload_hex, OTHER_PACKET_HEX);
  });
