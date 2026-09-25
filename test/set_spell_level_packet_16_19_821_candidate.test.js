'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { collect821Routes } = require('../src/decoders/rofl_16_19_821_scan');
const {
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeSetSpellLevelPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_set_spell_level_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
// Three observed game-stream 0x025d payloads in KR_8392938200.rofl.
const PAYLOADS = [Buffer.from('fa', 'hex'), Buffer.from('c37b', 'hex'),
  Buffer.from('cd7bb2', 'hex')];
const PARAMS = [0x400000b6, 0x400000b4, 0x400000b4];

function packet(packetId = 0x025d, rawParam = 0x400000b4, payload = PAYLOADS[1]) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(1, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replayWithChunks(chunks, build = BUILD) {
  return replayFromChunks(chunks.map(({ stream = 1, packets }) => ({
    stream, body: Buffer.concat(packets),
  })), build);
}

function fakeImage(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-spell-level-'));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  t.after(() => { fs.unlinkSync(image); fs.rmdirSync(directory); });
  return image;
}

function nativeResult(request) {
  return {
    status: 'PASS',
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
    callback_table_sha256: profile.evidence_callback_table_sha256,
    results: request.packets.map((input, index) => ({
      status: 'DECODED', input_index: index,
      raw_param: input.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: input.payload_hex.length / 2,
      native_packet_id: 0x025d, native_raw_param: input.raw_param,
      opaque_u32_0x10: index + 12, opaque_u32_0x14: index + 2,
      raw_u32_0x10_hex: '7bbbbbbb', raw_u32_0x14_hex: '72f1f1f1',
    })),
  };
}

test('821 SetSpellLevel emits anonymous packet fields and source refs from a shared scan', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([
    { packets: [packet(0x025d, PARAMS[0], PAYLOADS[0])] },
    { packets: [packet(0x00fd), packet(0x025d, PARAMS[2], PAYLOADS[2])] },
  ]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_set_spell_level_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag]),
      [[0x025d, 1], [0x025d, 1]]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const token = collect821Routes(replay, ['set_spell_level_packet']);
  const result = decode(replay, { runtimeImagePath: image, precollected: token });
  assert.equal(profile.packet_name, 'PKT_S2C_SetSpellLevel_s');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].event_type, 'SET_SPELL_LEVEL_PACKET_CANDIDATE');
  assert.equal(result.events[0].opaque_u32_0x10, 12);
  assert.equal(result.events[0].opaque_u32_0x14, 2);
  assert.equal(result.events[0].raw_object_u32_0x10_hex, '7bbbbbbb');
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[1].raw_packet_ref.raw_param, PARAMS[2]);
  for (const field of ['owner', 'spell_identity', 'level', 'effect']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 SetSpellLevel distinguishes wrong build, absent route and missing image', () => {
  assert.equal(decode(replayWithChunks([{ packets: [packet()] }], '16.19.820.7193')).status,
    'UNSUPPORTED');
  assert.equal(decode(replayWithChunks([{ packets: [packet(0x00fd)] }])).status,
    'PROFILE_UNAVAILABLE');
  const missing = decode(replayWithChunks([{ packets: [packet()] }]));
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.input_count, 1);
});

test('821 SetSpellLevel rejects changed source, wrong stream, length and scan token', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('native decoder should not be invoked');
  });
  const changed = replayWithChunks([{ packets: [packet()] }]);
  changed.buffer[0] ^= 1;
  assert.match(decode(changed).error, /source integrity/);
  assert.equal(decode(replayWithChunks([{ stream: 2, packets: [packet()] }])).status,
    'DECODE_FAILED');
  assert.equal(decode(replayWithChunks([{ packets: [packet(0x025d, PARAMS[1],
    Buffer.alloc(4))] }])).status, 'DECODE_FAILED');
  const source = replayWithChunks([{ packets: [packet()] }]);
  const token = collect821Routes(source, ['set_spell_level_packet']);
  const other = replayWithChunks([{ packets: [packet()] }]);
  assert.equal(decode(other, { precollected: token }).status, 'DECODE_FAILED');
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 SetSpellLevel fails atomically on image, native cursor or transform drift', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet(), packet()] }]);
  const wrongInvoke = t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'runtime image SHA-256 mismatch: wrong image', stdout: '',
  }));
  const wrong = decode(replay, { runtimeImagePath: image });
  assert.equal(wrong.status, 'DECODE_FAILED');
  assert.equal(wrong.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(wrong.events, null);
  wrongInvoke.mock.restore();
  const partialInvoke = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    result.results[1].bytes_consumed -= 1;
    return { status: 0, stdout: JSON.stringify(result) };
  });
  const partial = decode(replay, { runtimeImagePath: image });
  assert.equal(partial.status, 'DECODE_FAILED');
  assert.equal(partial.first_failed_packet_ref.packet_id, 0x025d);
  assert.equal(partial.events, null);
  partialInvoke.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    result.callback_table_sha256 = {
      ...result.callback_table_sha256, opaque_u32_0x14: '0'.repeat(64),
    };
    return { status: 0, stdout: JSON.stringify(result) };
  });
  const drift = decode(replay, { runtimeImagePath: image });
  assert.equal(drift.status, 'DECODE_FAILED');
  assert.equal(drift.events, null);
});

test('821 SetSpellLevel caps both direct and shared scans at 10,000 packets', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('native decoder should not be invoked');
  });
  const replay = replayWithChunks([{ packets: Array.from({ length: 10_001 }, () => packet()) }]);
  const direct = decode(replay);
  assert.equal(direct.status, 'UNSUPPORTED');
  assert.equal(direct.observed_packet_count_minimum, 10_001);
  const token = collect821Routes(replay, ['set_spell_level_packet']);
  const shared = decode(replay, { precollected: token });
  assert.equal(shared.status, 'UNSUPPORTED');
  assert.equal(shared.observed_packet_count_minimum, 10_001);
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 SetSpellLevel native 1/2/3-byte packets decode and reject controls', {
  skip: !fs.existsSync(IMAGE),
}, () => {
  const inputs = PAYLOADS.map((payload, index) => ({
    packet_id: 0x025d, stream_tag: 1, raw_param: PARAMS[index],
    payload_hex: payload.toString('hex'),
  }));
  const controls = [PAYLOADS[2].subarray(0, -1),
    Buffer.concat([PAYLOADS[2], Buffer.from([0xa5])])]
    .map((payload) => ({ packet_id: 0x025d, stream_tag: 1,
      raw_param: PARAMS[2], payload_hex: payload.toString('hex') }))
    .concat([{ packet_id: 0x038e, stream_tag: 1, raw_param: PARAMS[2],
      payload_hex: PAYLOADS[2].toString('hex') }]);
  const run = childProcess.spawnSync(process.env.PYTHON || 'python', [
    '-B', path.resolve(__dirname, '..', 'scripts',
      'decode_set_spell_level_packet_16_19_821.py'), '--image', IMAGE,
  ], { input: JSON.stringify({ replay_version: BUILD, packets: inputs.concat(controls) }),
    encoding: 'utf8', timeout: 60000 });
  assert.equal(run.status, 0, run.stderr);
  const output = JSON.parse(run.stdout);
  assert.deepEqual(output.callback_table_sha256,
    profile.evidence_callback_table_sha256);
  const [one, two, three, truncated, appended, foreign] = output.results;
  assert.deepEqual([one, two, three].map((row) => [row.status,
    row.opaque_u32_0x10, row.opaque_u32_0x14]),
  [['DECODED', 0, 1], ['DECODED', 12, 2], ['DECODED', 12, 3]]);
  assert.equal(one.raw_u32_0x10_hex, 'bbbbbbbb');
  assert.equal(two.raw_u32_0x14_hex, '72f1f1f1');
  assert.equal(truncated.status, 'FAILED');
  assert.equal(truncated.deserialize_return_al, 0);
  assert.equal(appended.status, 'FAILED');
  assert.equal(appended.deserialize_return_al, null);
  assert.match(appended.error, /payload length/);
  assert.equal(foreign.status, 'FAILED');
  assert.match(foreign.error, /packet ID/);

  // Bypass the public length/route gates here to prove the native failure mode.
  // The foreign bytes are a 0x038e keyframe payload from KR_8392938200.rofl.
  const nativeControls = [
    'import json,sys',
    'from pathlib import Path',
    'sys.path.insert(0,sys.argv[1])',
    'from decode_set_spell_level_packet_16_19_821 import PROFILE, IMAGE_SHA256',
    'from decode_mapview_inventory_16_19_821 import read_image, make_emulator',
    'image,digest,_=read_image(Path(sys.argv[2]))',
    'assert digest==IMAGE_SHA256',
    "samples=['cd7b','cd7bb2a5','83230dd6f1f241e5e7dfdb8785']",
    'results=[]',
    'for payload_hex in samples:',
    ' emulator,_=make_emulator(image)',
    ' value=emulator.decode(bytes.fromhex(payload_hex),PROFILE)',
    " results.append([value['deserialize_return_al'],value['bytes_consumed'],value['fully_consumed']])",
    'print(json.dumps(results))',
  ].join('\n');
  const nativeRun = childProcess.spawnSync(process.env.PYTHON || 'python', [
    '-B', '-c', nativeControls, path.resolve(__dirname, '..', 'scripts'), IMAGE,
  ], { encoding: 'utf8', timeout: 60000 });
  assert.equal(nativeRun.status, 0, nativeRun.stderr);
  assert.deepEqual(JSON.parse(nativeRun.stdout), [
    [0, 2, true], [1, 3, false], [1, 2, false],
  ]);
});
