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
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V1_ID_821: v1ProfileId,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V2_ID_821: v2ProfileId,
  decodeUnitApplyDamagePacketCandidates821: decode,
  decodeUnitApplyDamageCallbackF32FromRaw821: decodeFloat,
  decodeUnitApplyDamageLookupKeyFromRaw821: decodeLookupKey,
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
const CONSTANT_PACKETS = [
  { rawParam: 0x40013cb5, payloadHex: '5b814d4650a07e33c07422',
    source: 'CONSTANT_0', value: 0 },
  { rawParam: 0x40004a92, payloadHex: '6a87dd49ea0d8c9d0b3891ecac75',
    source: 'CONSTANT_1', value: 1 },
  { rawParam: 0x400001a3, payloadHex: '7901ad410aca18ce0b5eec3f5275',
    source: 'CONSTANT_2', value: 2 },
];
const SAME_TUPLE_DIFFERENT_FLOAT_OFFSETS = [
  { rawParam: 0x400000af, payloadHex: '618d8747e6680d069e0bc61098de8becd65275',
    offset: 10, value: 19.56043243408203 },
  { rawParam: 0x40004ff8, payloadHex: '61074d47d50fdc900b9ff46bf8f9deec2e2175',
    offset: 9, value: 9999 },
];

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

function fixtureWithPackets(packets) {
  return replayFromChunks([{
    stream: 1,
    body: Buffer.concat(packets.map(({ rawParam, payloadHex }, index) =>
      packet(rawParam, payloadHex, 1500 + 100 * index))),
  }], BUILD);
}

test('821 UnitApplyDamage emits packet selectors and only the native-matched family float',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const result = decode(fixture(), { runtimeImagePath: IMAGE_PATH });
    assert.equal(profile.evidence_status,
      'CANDIDATE_EXACT_821_UNIT_APPLY_DAMAGE_PACKET_FIELDS');
    assert.equal(v2ProfileId, `${v1ProfileId.slice(0, -1)}2`);
    assert.equal(profile.id, `${v1ProfileId.slice(0, -1)}3`);
    assert.equal(result.status, 'CANDIDATE');
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.input_count, 2);
    assert.equal(result.event_count, 2);
    assert.equal(result.callback_f32_available_count, 1);
    assert.equal(result.callback_f32_unavailable_count, 1);
    assert.equal(result.native_callback_f32_available_count, 2);
    assert.deepEqual(result.native_callback_f32_source_counts, {
      RAW_READER: 2, CONSTANT_0: 0, CONSTANT_1: 0, CONSTANT_2: 0,
    });
    assert.equal(result.native_callback_lookup_full_write_count, 2);
    assert.deepEqual(result.native_callback_lookup_key_0x24_raw_param_relation_counts, {
      EQUAL: 1, RAW_PARAM_IS_LOOKUP_PLUS_0X100: 0, OTHER: 1,
    });
    const [common, other] = result.events;
    assert.deepEqual([
      common.header_selector_bits_24_26,
      common.header_selector_bits_0_2,
      common.header_selector_bits_3_5,
    ], [6, 1, 6]);
    assert.equal(common.callback_f32_0x20_candidate, 0.5460192561149597);
    assert.equal(common.callback_f32_0x20_raw_bytes_hex, '083dbaef');
    assert.equal(common.callback_f32_0x20_status, 'NATIVE_MATCHED_SHAPE');
    assert.equal(common.native_callback_f32_0x20_candidate, 0.5460192561149597);
    assert.equal(common.native_callback_f32_0x20_source, 'RAW_READER');
    assert.equal(common.native_callback_f32_0x20_raw_offset, 5);
    assert.equal(common.native_callback_f32_0x20_raw_bytes_hex, '083dbaef');
    assert.equal(common.native_callback_lookup_key_u32_0x24_candidate, 0x40004007);
    assert.equal(common.native_callback_lookup_key_0x24_encoded_bytes_hex, 'b7294929');
    assert.equal(common.native_callback_lookup_key_u32_0x2c_candidate, 0x40004691);
    assert.equal(common.native_callback_lookup_key_0x2c_encoded_bytes_hex, '39e504c3');
    assert.equal(common.native_callback_lookup_key_0x24_raw_param_relation, 'EQUAL');
    assert.equal(other.callback_f32_0x20_candidate, null);
    assert.equal(other.callback_f32_0x20_status, 'UNAVAILABLE_SHAPE');
    assert.equal(other.native_callback_f32_0x20_candidate, 53.581398010253906);
    assert.equal(other.native_callback_f32_0x20_source, 'RAW_READER');
    assert.equal(other.native_callback_f32_0x20_raw_offset, 9);
    assert.equal(other.native_callback_f32_0x20_raw_bytes_hex, '6ef07c44');
    assert.equal(other.native_callback_lookup_key_u32_0x24_candidate, 0x400000b3);
    assert.equal(other.native_callback_lookup_key_0x24_encoded_bytes_hex, 'e2494929');
    assert.equal(other.native_callback_lookup_key_u32_0x2c_candidate, 0x400000ae);
    assert.equal(other.native_callback_lookup_key_0x2c_encoded_bytes_hex, '5b0404c3');
    assert.equal(other.native_callback_lookup_key_0x24_raw_param_relation, 'OTHER');
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

test('saved callback lookup keys can be rederived from protected native object bytes', () => {
  assert.equal(decodeLookupKey('b7294929', 0x24), 0x40004007);
  assert.equal(decodeLookupKey('39e504c3', 0x2c), 0x40004691);
  assert.equal(decodeLookupKey('e2494929', 0x24), 0x400000b3);
  assert.notEqual(decodeLookupKey('e2494929', 0x2c), 0x400000b3);
  assert.equal(decodeLookupKey('e2494929', 0x20), null);
  assert.equal(decodeLookupKey('E2494929', 0x24), null);
  assert.equal(decodeLookupKey('e24949', 0x24), null);
});

test('821 +0x100 raw route alias has a distinct exact callback lookup key',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const result = decode(fixtureWithPackets([{
      rawParam: 0x400001b3, payloadHex: OTHER_PACKET_HEX,
    }]), { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'CANDIDATE');
    assert.equal(result.events[0].raw_param, 0x400001b3);
    assert.equal(result.events[0].native_callback_lookup_key_u32_0x24_candidate,
      0x400000b3);
    assert.equal(result.events[0].native_callback_lookup_key_u32_0x2c_candidate,
      0x400000ae);
    assert.equal(result.events[0].native_callback_lookup_key_0x24_raw_param_relation,
      'RAW_PARAM_IS_LOOKUP_PLUS_0X100');
    assert.equal(result.events[0].semantic_effect_status, 'UNKNOWN');
  });

test('821 native +0x20 field distinguishes explicit constants from raw-reader values',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const result = decode(fixtureWithPackets(CONSTANT_PACKETS),
      { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'CANDIDATE');
    assert.equal(result.native_callback_f32_available_count, 3);
    assert.deepEqual(result.native_callback_f32_source_counts, {
      RAW_READER: 0, CONSTANT_0: 1, CONSTANT_1: 1, CONSTANT_2: 1,
    });
    assert.equal(result.callback_f32_available_count, 0);
    for (const [index, source] of CONSTANT_PACKETS.entries()) {
      const event = result.events[index];
      assert.equal(event.callback_f32_0x20_candidate, null);
      assert.equal(event.callback_f32_0x20_status, 'UNAVAILABLE_SHAPE');
      assert.equal(event.native_callback_f32_0x20_candidate, source.value);
      assert.equal(event.native_callback_f32_0x20_source, source.source);
      assert.equal(event.native_callback_f32_0x20_raw_offset, null);
      assert.equal(event.native_callback_f32_0x20_raw_bytes_hex, null);
    }
  });

test('821 native raw cursor locates different +0x20 bytes within one selector and length tuple',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const result = decode(fixtureWithPackets(SAME_TUPLE_DIFFERENT_FLOAT_OFFSETS),
      { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'CANDIDATE');
    for (const [index, source] of SAME_TUPLE_DIFFERENT_FLOAT_OFFSETS.entries()) {
      const event = result.events[index];
      assert.equal(event.callback_f32_0x20_candidate, null);
      assert.equal(event.native_callback_f32_0x20_source, 'RAW_READER');
      assert.equal(event.native_callback_f32_0x20_raw_offset, source.offset);
      assert.equal(event.native_callback_f32_0x20_candidate, source.value);
      const payload = Buffer.from(source.payloadHex, 'hex');
      assert.equal(event.native_callback_f32_0x20_raw_bytes_hex,
        payload.subarray(source.offset, source.offset + 4).toString('hex'));
    }
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

test('821 UnitApplyDamage rejects a native callback offset mismatch atomically',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, (t) => {
    const realSpawnSync = childProcess.spawnSync;
    t.mock.method(childProcess, 'spawnSync', (...args) => {
      const run = realSpawnSync(...args);
      assert.equal(run.status, 0, run.stderr);
      const native = JSON.parse(run.stdout);
      native.native_float_rows[0][3] = 6;
      return { ...run, stdout: JSON.stringify(native) };
    });
    const result = decode(fixture({ payloads: [COMMON_PACKET_HEX] }),
      { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.native_witness_status, 'FAILED');
    assert.equal(result.events, null);
    assert.match(result.error, /native callback raw transform differs/);
  });

test('821 UnitApplyDamage rejects a forged native lookup key atomically',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, (t) => {
    const realSpawnSync = childProcess.spawnSync;
    t.mock.method(childProcess, 'spawnSync', (...args) => {
      const run = realSpawnSync(...args);
      assert.equal(run.status, 0, run.stderr);
      const native = JSON.parse(run.stdout);
      native.lookup_rows[0][2] += 1;
      return { ...run, stdout: JSON.stringify(native) };
    });
    const result = decode(fixture({ payloads: [COMMON_PACKET_HEX] }),
      { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.native_witness_status, 'FAILED');
    assert.equal(result.events, null);
    assert.match(result.error, /lookup-key identity or transform differs/);
  });

test('821 UnitApplyDamage rejects incomplete native lookup writes atomically',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, (t) => {
    const realSpawnSync = childProcess.spawnSync;
    t.mock.method(childProcess, 'spawnSync', (...args) => {
      const run = realSpawnSync(...args);
      assert.equal(run.status, 0, run.stderr);
      const native = JSON.parse(run.stdout);
      native.native_lookup_full_write_count = 0;
      return { ...run, stdout: JSON.stringify(native) };
    });
    const result = decode(fixture({ payloads: [COMMON_PACKET_HEX] }),
      { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.native_witness_status, 'FAILED');
    assert.equal(result.events, null);
    assert.match(result.error, /lookup row or write count differs/);
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
    assert.equal(native.rows[0].native_callback_f32_0x20_source, 'RAW_READER');
    assert.equal(native.rows[0].native_callback_f32_0x20_raw_offset, 5);
    assert.equal(native.rows[0].lookup_key_u32_0x24_candidate, 0x40004007);
    assert.equal(native.rows[0].lookup_key_u32_0x2c_candidate, 0x40004691);
    assert.equal(native.rows[0].lookup_full_write, true);
    assert.equal(native.rows[1].deserialize_return_al, 0);
    assert.equal(native.rows[1].lookup_full_write, false);
    assert.equal(native.rows[2].fully_consumed, false);
    assert.equal(native.rows[2].lookup_full_write, false);
  });

test('one supplied KR Replay keeps every 0x005f packet and reports unavailable floats',
  { skip: !(HAS_IMAGE && HAS_REPLAY) && 'original exact-build KR Replay and image are unavailable' }, () => {
    const result = decode(parseReplayFile(REPLAY_PATH), { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'CANDIDATE');
    assert.equal(result.input_count, 64_824);
    assert.equal(result.event_count, result.input_count);
    assert.equal(result.callback_f32_available_count, 684);
    assert.equal(result.callback_f32_unavailable_count, 64_140);
    assert.equal(result.native_callback_f32_available_count, 64_824);
    assert.deepEqual(result.native_callback_f32_source_counts, {
      RAW_READER: 64_471,
      CONSTANT_0: 10,
      CONSTANT_1: 293,
      CONSTANT_2: 50,
    });
    assert.equal(result.observed_shape_family_count, 595);
    assert.equal(result.events[0].raw_packet_ref.raw_payload_hex, OTHER_PACKET_HEX);
    assert.equal(result.native_callback_lookup_full_write_count, 64_824);
    const alias = result.events.find((row) => row.raw_param === 0x400001b3
      && row.raw_packet_ref.raw_payload_hex === OTHER_PACKET_HEX);
    assert.ok(alias);
    assert.equal(alias.native_callback_lookup_key_u32_0x24_candidate, 0x400000b3);
    assert.equal(alias.native_callback_lookup_key_u32_0x2c_candidate, 0x400000ae);
    assert.equal(alias.native_callback_lookup_key_0x24_raw_param_relation,
      'RAW_PARAM_IS_LOOKUP_PLUS_0X100');
  });
