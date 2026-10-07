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
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_821: v1,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V1_ID_821: v1Id,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_ID_821: v2Id,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_821: v2,
  decodeSetSpellLevelU32At10FromRaw821: decodeAt10,
  decodeSetSpellLevelU32At14FromRaw821: decodeAt14,
  decodeSetSpellLevelPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_set_spell_level_packet_candidate');

const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE || path.resolve(__dirname, '..',
  'artifacts', '16_19_development', 'kr_821_runtime_capture',
  'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY = process.env.ROFL_821_REPLAY_DIR
  ? path.join(process.env.ROFL_821_REPLAY_DIR, 'KR_8392938200.rofl') : null;

function packet(payload, rawParam) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x025d, 9);
  header.writeUInt32LE(rawParam, 11);
  return Buffer.concat([header, payload]);
}

function syntheticReplay() {
  return replayFromChunks([{
    stream: 1,
    body: Buffer.concat([
      packet(Buffer.from('fa', 'hex'), 0x400000b6),
      packet(Buffer.from('c37b', 'hex'), 0x400000b4),
    ]),
  }], '16.19.821.7343');
}

function fakeImage(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-spell-v2-'));
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
    results: request.packets.map((input, index) => {
      const second = index === 1;
      return {
        status: 'DECODED',
        input_index: index,
        raw_param: input.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 1,
        bytes_consumed: input.payload_hex.length / 2,
        native_packet_id: 0x025d,
        native_raw_param: input.raw_param,
        raw_u32_0x10_hex: second ? '7bbbbbbb' : 'bbbbbbbb',
        opaque_u32_0x10: second ? 12 : 0,
        raw_u32_0x14_hex: second ? '72f1f1f1' : '32f1f1f1',
        opaque_u32_0x14: second ? 2 : 1,
        ...(v2Mode ? {
          native_receiver_slot_candidate: second ? 12 : 0,
          native_receiver_selection_source: 'INDEXED',
          native_clamped_scalar_candidate: second ? 2 : 1,
          native_positive_flag_written: true,
        } : {}),
      };
    }),
  };
  if (v2Mode) Object.assign(output, {
    callback_rva: v2.evidence_callback_rva,
    receiver_write_rva: v2.evidence_receiver_write_rva,
    callback_region_sha256: v2.evidence_callback_region_sha256,
    receiver_write_region_sha256: v2.evidence_receiver_write_region_sha256,
    callback_witness_mode: v2.evidence_callback_witness_mode,
  });
  return output;
}

test('821 SetSpellLevel V2 exact transform helpers reject malformed raw bytes', () => {
  assert.equal(v1.id, v1Id);
  assert.equal(v2.id, v2Id);
  assert.equal(decodeAt10('bbbbbbbb'), 0);
  assert.equal(decodeAt10('7bbbbbbb'), 12);
  assert.equal(decodeAt14('32f1f1f1'), 1);
  assert.equal(decodeAt14('72f1f1f1'), 2);
  assert.equal(decodeAt10(''), null);
  assert.equal(decodeAt14('32F1F1F1'), null);
});

test('821 SetSpellLevel V2 opt-in forwards native witness and keeps default V1', (t) => {
  const image = fakeImage(t);
  const replay = syntheticReplay();
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    const selectedV2 = args.includes('--callback-witness-v2');
    const response = nativeResponse(JSON.parse(options.input), { v2Mode: selectedV2 });
    return { status: 0, stderr: '', stdout: JSON.stringify(response) };
  });
  const defaultResult = decode(replay, { runtimeImagePath: image });
  assert.equal(defaultResult.status, 'CANDIDATE');
  assert.equal(defaultResult.profile_id, v1Id);
  assert.equal('native_receiver_slot_candidate' in defaultResult.events[0], false);
  const result = decode(replay, {
    runtimeImagePath: image, setSpellLevelProfile: 'v2',
  });
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.profile_id, v2Id);
  assert.equal(result.evidence_callback_witness_mode, 'NATIVE_SYNTHETIC_RECEIVER');
  assert.equal(result.event_count, 2);
  assert.deepEqual(result.events.map((row) => [
    row.native_receiver_slot_candidate,
    row.native_receiver_selection_source,
    row.native_clamped_scalar_candidate,
    row.native_positive_flag_written,
  ]), [[0, 'INDEXED', 1, true], [12, 'INDEXED', 2, true]]);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  for (const key of ['spell_identity', 'owner', 'level', 'effect']) {
    assert.equal(key in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 2);
});

test('821 SetSpellLevel V2 fails atomically on metadata or later native row drift', (t) => {
  const image = fakeImage(t);
  const replay = syntheticReplay();
  const wrongMeta = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const response = nativeResponse(JSON.parse(options.input));
    response.callback_region_sha256 = '0'.repeat(64);
    return { status: 0, stdout: JSON.stringify(response) };
  });
  const metadata = decode(replay, {
    runtimeImagePath: image, setSpellLevelProfile: 'v2',
  });
  assert.equal(metadata.status, 'DECODE_FAILED');
  assert.equal(metadata.events, null);
  wrongMeta.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const response = nativeResponse(JSON.parse(options.input));
    response.results[1].native_clamped_scalar_candidate = 6;
    return { status: 0, stdout: JSON.stringify(response) };
  });
  const later = decode(replay, {
    runtimeImagePath: image, setSpellLevelProfile: 'v2',
  });
  assert.equal(later.status, 'DECODE_FAILED');
  assert.equal(later.events, null);
  assert.equal(later.first_failed_packet_ref.packet_id, 0x025d);
  assert.equal(decode(replay, { setSpellLevelProfile: 'v3' }).status, 'UNSUPPORTED');
});

test('821 SetSpellLevel V2 native callback witnesses original KR replay packets', {
  skip: !fs.existsSync(IMAGE) || !REPLAY || !fs.existsSync(REPLAY),
}, () => {
  const replay = parseReplayFile(REPLAY);
  const result = decode(replay, {
    runtimeImagePath: IMAGE, setSpellLevelProfile: 'v2',
  });
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.input_count, 33);
  assert.equal(result.event_count, 33);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.deepEqual(result.events.slice(0, 2).map((row) => [
    row.native_receiver_slot_candidate, row.native_clamped_scalar_candidate,
    row.native_positive_flag_written,
  ]), [[0, 1, true], [12, 2, true]]);
  assert.ok(result.events.every((row) =>
    row.native_receiver_selection_source === 'INDEXED'
    && row.native_clamped_scalar_candidate >= 1
    && row.native_clamped_scalar_candidate <= 6));
});
