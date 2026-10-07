'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_821: v1,
  SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V1_ID_821: v1Id,
  SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V2_ID_821: v2Id,
  SET_SPELL_TIMER_FROM_BUFF_PACKET_CANDIDATE_PROFILE_V2_821: v2,
  SET_SPELL_TIMER_FROM_BUFF_V2_FIELD_CONFIDENCE_821: witnessConfidence,
  SET_SPELL_TIMER_FROM_BUFF_V2_EVENT_FIELD_CONFIDENCE_821: v2Confidence,
  decodeSetSpellTimerU8At20FromRaw821: decodeSelector,
  decodeSetSpellTimerRawFields821: decodeRawFields,
  decodeSetSpellTimerFromBuffPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_set_spell_timer_from_buff_packet_candidate');

const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE || path.resolve(__dirname, '..',
  'artifacts', '16_19_development', 'kr_821_runtime_capture',
  'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY = process.env.ROFL_821_REPLAY_DIR
  ? path.join(process.env.ROFL_821_REPLAY_DIR, 'KR_8393456728.rofl') : null;

const SAMPLES = [
  {
    payload: Buffer.from('3abf186252ad70', 'hex'),
    rawParam: 0x400000b0,
    fields: {
      opaque_u8_0x10: 0, opaque_u8_0x11: 1, opaque_f32_0x14: 0,
      opaque_u32_0x18: 2950734121, opaque_u32_0x1c: 0,
      opaque_u8_0x20: 2,
      raw_u8_0x10_hex: 'c0', raw_u8_0x11_hex: 'c4',
      raw_f32_0x14_hex: '6a6a6a6a', raw_u32_0x18_hex: '381ae999',
      raw_u32_0x1c_hex: '00000000', raw_u8_0x20_hex: 'ab',
    },
  },
  {
    payload: Buffer.from('1abe9dae5aa4b243', 'hex'),
    rawParam: 0x400000b3,
    fields: {
      opaque_u8_0x10: 0, opaque_u8_0x11: 1, opaque_f32_0x14: 0,
      opaque_u32_0x18: 996719039, opaque_u32_0x1c: 0,
      opaque_u8_0x20: 63,
      raw_u8_0x10_hex: 'c0', raw_u8_0x11_hex: 'c4',
      raw_f32_0x14_hex: '6a6a6a6a', raw_u32_0x18_hex: '9d1cc7bc',
      raw_u32_0x1c_hex: '00000000', raw_u8_0x20_hex: '43',
    },
  },
];

function packet(payload, rawParam) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x00fd, 9);
  header.writeUInt32LE(rawParam, 11);
  return Buffer.concat([header, payload]);
}

function syntheticReplay() {
  return replayFromChunks([{
    stream: 1,
    body: Buffer.concat(SAMPLES.map((sample) =>
      packet(sample.payload, sample.rawParam))),
  }], '16.19.821.7343');
}

function fakeImage(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-spell-timer-v2-'));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  t.after(() => { fs.unlinkSync(image); fs.rmdirSync(directory); });
  return image;
}

function nativeResponse(request, { v2Mode = true } = {}) {
  const output = {
    status: 'PASS',
    runtime_image_sha256: v1.evidence_runtime_image_sha256,
    callback_table_sha256: v1.evidence_callback_table_sha256,
    results: request.packets.map((input, index) => ({
      status: 'DECODED',
      input_index: index,
      raw_param: input.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1,
      bytes_consumed: input.payload_hex.length / 2,
      native_packet_id: 0x00fd,
      native_raw_param: input.raw_param,
      ...SAMPLES[index].fields,
      ...(v2Mode ? {
        native_receiver_slot_candidate: index ? 63 : 2,
        native_receiver_selection_path: index ? 'INDEX_63' : 'INDEX_0_TO_5',
        native_receiver_forwarded_fields_witnessed: true,
      } : {}),
    })),
  };
  if (v2Mode) Object.assign(output, {
    callback_rva: v2.evidence_callback_rva,
    receiver_lookup_rva: v2.evidence_receiver_lookup_rva,
    receiver_call_rva: v2.evidence_receiver_call_rva,
    callback_region_sha256: v2.evidence_callback_region_sha256,
    receiver_lookup_region_sha256: v2.evidence_receiver_lookup_region_sha256,
    callback_witness_mode: v2.evidence_callback_witness_mode,
  });
  return output;
}

test('821 SetSpellTimer V2 exact raw helper covers all forwarded fields', () => {
  assert.equal(v1.id, v1Id);
  assert.equal(v2.id, v2Id);
  assert.equal(decodeSelector('bb'), 0);
  assert.equal(decodeSelector('ab'), 2);
  assert.equal(decodeSelector('43'), 63);
  assert.equal(decodeSelector('AB'), null);
  const raw = SAMPLES[0].fields;
  assert.deepEqual(decodeRawFields({
    raw_object_u8_0x10_hex: raw.raw_u8_0x10_hex,
    raw_object_u8_0x11_hex: raw.raw_u8_0x11_hex,
    raw_object_f32_0x14_hex: raw.raw_f32_0x14_hex,
    raw_object_u32_0x18_hex: raw.raw_u32_0x18_hex,
    raw_object_u32_0x1c_hex: raw.raw_u32_0x1c_hex,
    raw_object_u8_0x20_hex: raw.raw_u8_0x20_hex,
  }), {
    opaque_u8_0x10: 0, opaque_u8_0x11: 1, opaque_f32_0x14: 0,
    opaque_u32_0x18: 2950734121, opaque_u32_0x1c: 0,
    opaque_u8_0x20: 2,
  });
  assert.equal(decodeRawFields({ raw_object_u8_0x20_hex: 'ab' }), null);
  assert.equal(v2Confidence.native_receiver_slot_candidate, witnessConfidence);
});

test('821 SetSpellTimer V2 opts in native witness while V1 stays default', (t) => {
  const image = fakeImage(t);
  const replay = syntheticReplay();
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    const selectedV2 = args.includes('--callback-witness-v2');
    return { status: 0, stderr: '',
      stdout: JSON.stringify(nativeResponse(JSON.parse(options.input),
        { v2Mode: selectedV2 })) };
  });
  const original = decode(replay, { runtimeImagePath: image });
  assert.equal(original.status, 'CANDIDATE');
  assert.equal(original.profile_id, v1Id);
  assert.equal('native_receiver_slot_candidate' in original.events[0], false);
  const result = decode(replay, {
    runtimeImagePath: image, setSpellTimerProfile: 'v2',
  });
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.profile_id, v2Id);
  assert.deepEqual(result.event_field_confidence, v2Confidence);
  assert.equal(result.event_count, 2);
  assert.deepEqual(result.events.map((row) => [
    row.native_receiver_slot_candidate, row.native_receiver_selection_path,
    row.native_receiver_forwarded_fields_witnessed,
  ]), [[2, 'INDEX_0_TO_5', true], [63, 'INDEX_63', true]]);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  for (const key of ['buff_identity', 'spell_identity', 'owner', 'timer_effect']) {
    assert.equal(key in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 2);
});

test('821 SetSpellTimer V2 fails atomically on metadata or last-row witness drift', (t) => {
  const image = fakeImage(t);
  const replay = syntheticReplay();
  const wrongMeta = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const response = nativeResponse(JSON.parse(options.input));
    response.receiver_lookup_region_sha256 = '0'.repeat(64);
    return { status: 0, stdout: JSON.stringify(response) };
  });
  const metadata = decode(replay, {
    runtimeImagePath: image, setSpellTimerProfile: 'v2',
  });
  assert.equal(metadata.status, 'DECODE_FAILED');
  assert.equal(metadata.events, null);
  wrongMeta.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const response = nativeResponse(JSON.parse(options.input));
    response.results[1].native_receiver_forwarded_fields_witnessed = false;
    return { status: 0, stdout: JSON.stringify(response) };
  });
  const later = decode(replay, {
    runtimeImagePath: image, setSpellTimerProfile: 'v2',
  });
  assert.equal(later.status, 'DECODE_FAILED');
  assert.equal(later.events, null);
  assert.equal(later.first_failed_packet_ref.packet_id, 0x00fd);
  childProcess.spawnSync.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const response = nativeResponse(JSON.parse(options.input));
    response.results[1].opaque_u32_0x18 += 1;
    return { status: 0, stdout: JSON.stringify(response) };
  });
  const forgedForwardedValue = decode(replay, {
    runtimeImagePath: image, setSpellTimerProfile: 'v2',
  });
  assert.equal(forgedForwardedValue.status, 'DECODE_FAILED');
  assert.equal(forgedForwardedValue.events, null);
  assert.equal(decode(replay, { setSpellTimerProfile: 'v3' }).status, 'UNSUPPORTED');
});

test('821 SetSpellTimer V2 witnesses original KR replay including slot 63', {
  skip: !fs.existsSync(IMAGE) || !REPLAY || !fs.existsSync(REPLAY),
}, () => {
  const replay = parseReplayFile(REPLAY);
  const result = decode(replay, {
    runtimeImagePath: IMAGE, setSpellTimerProfile: 'v2',
  });
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.input_count, 438);
  assert.equal(result.event_count, 438);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.ok(result.events.some((row) =>
    row.native_receiver_slot_candidate === 63
    && row.native_receiver_selection_path === 'INDEX_63'));
  assert.ok(result.events.every((row) =>
    row.native_receiver_forwarded_fields_witnessed === true));
});
