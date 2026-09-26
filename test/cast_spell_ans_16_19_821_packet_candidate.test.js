'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { parseReplayFile } = require('../src/rofl');
const { collect821Routes } = require('../src/decoders/rofl_16_19_821_scan');
const {
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_821: profile,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V4_ID_821,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V5_821: profileV5,
  CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V6_821: profileV6,
  decodeCastSpellAnsNestedU32FromRaw821,
  decodeCastSpellAnsNestedU32At4cFromRaw821,
  decodeCastSpellAnsPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_cast_spell_ans_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const TABLE_SHA256 = '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b';
const FLOAT_INVERSE_SHA256 = 'cce644f3775d31b6be55e5abc79ed029298be5110b8f81be8957bd3b066019f5';
const BYTE_INVERSE_SHA256 = 'b5d220967c423848c278651d068786e3aaedf4994c6d30dd1d3d0c8fe6892516';
const NESTED_U32_TRANSFORM_SHA256 = '5b858c9ef8d1393d05d867112316c3344ff777044719d839ad8cd64867d7f537';
const NESTED_U32_0X4C_TRANSFORM_SHA256 = 'ad5ff48a6d097a43b6880bcafd30d0f8ef7f30f3988c049e1add1261f626eb4c';
const PAYLOAD = Buffer.concat([Buffer.from([0x15]), Buffer.alloc(128)]);

function packet(packetId = 0x01da, rawParam = 0x400000ae, payload = PAYLOAD) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-cast-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request, values = []) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    callback_table_sha256: TABLE_SHA256,
    nested_float_inverse_sha256: FLOAT_INVERSE_SHA256,
    nested_byte_inverse_sha256: BYTE_INVERSE_SHA256,
    results: request.packets.map((input, inputIndex) => ({
      status: 'DECODED', input_index: inputIndex,
      raw_param: input.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(input.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: input.payload_hex.length / 2,
      native_packet_id: 0x01da, native_raw_param: input.raw_param,
      raw_flag_byte_hex: values[inputIndex]?.flag === 1 ? '4d' : 'fc',
      opaque_flag_0x148: values[inputIndex]?.flag ?? 0,
      raw_i32_bytes_hex: values[inputIndex]?.i32 ? '78e89bbb' : 'bbbbbbbb',
      opaque_i32_0x14c: values[inputIndex]?.i32 ?? 0,
      raw_f32_bytes_hex: values[inputIndex]?.float ? 'ff57f6cd' : 'ffffffff',
      opaque_f32_0xe0: values[inputIndex]?.float ?? 0,
      raw_u8_0x140_hex: values[inputIndex]?.byte === 13 ? '5f' : '2c',
      opaque_u8_0x140: values[inputIndex]?.byte ?? 0,
      raw_nested_bits_0x24_hex: values[inputIndex]?.nestedBits === 1 ? 'c6' : 'c8',
      opaque_nested_bits_0x24: values[inputIndex]?.nestedBits ?? 4,
    })),
  };
}

test('821 CastSpellAns candidate exposes only provenance and opaque packet fields', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([
    { stream: 1, packets: [packet()] },
    { stream: 2, packets: [packet(0x01da, 0x4000023c)] },
  ]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_cast_spell_ans_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => row.raw_param),
      [0x400000ae, 0x4000023c]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request, [
      { flag: 1 }, { i32: 80444, float: -0.06680679321289062,
        byte: 13, nestedBits: 1 },
    ])) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(profile.packet_name, 'PKT_NPC_CastSpellAns_s');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 2);
  assert.equal(result.event_count, 2);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].opaque_flag_0x148, 1);
  assert.equal(result.events[1].opaque_i32_0x14c, 80444);
  assert.equal(result.events[0].opaque_f32_0xe0, 0);
  assert.equal(result.events[1].opaque_f32_0xe0, -0.06680679321289062);
  assert.equal(result.events[1].raw_f32_0xe0_bytes_hex, 'ff57f6cd');
  assert.equal(result.events[0].opaque_u8_0x140, 0);
  assert.equal(result.events[1].raw_u8_0x140_hex, '5f');
  assert.equal(result.events[1].opaque_u8_0x140, 13);
  assert.equal(result.events[0].raw_nested_bits_0x24_hex, 'c8');
  assert.equal(result.events[0].opaque_nested_bits_0x24, 4);
  assert.equal(result.events[1].raw_nested_bits_0x24_hex, 'c6');
  assert.equal(result.events[1].opaque_nested_bits_0x24, 1);
  assert.equal(result.events[1].raw_packet_ref.chunk_stream, 'keyframe');
  assert.equal(result.events[1].raw_packet_ref.raw_param, 0x4000023c);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal('spell_slot' in result.events[0], false);
  assert.equal('owner' in result.events[0], false);
  assert.equal('target' in result.events[0], false);
  assert.equal('position' in result.events[0], false);
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 CastSpellAns V5 opt-in adds only exact anonymous nested u32', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.ok(args.includes('--nested-u32-0x1c'));
    const output = nativeResult(JSON.parse(options.input));
    output.nested_u32_transform_sha256 = NESTED_U32_TRANSFORM_SHA256;
    output.results[0].raw_u32_0x1c_hex = 'cee352e7';
    output.results[0].opaque_u32_0x1c = 1531465011;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  assert.equal(profile.id, CAST_SPELL_ANS_PACKET_CANDIDATE_PROFILE_V4_ID_821);
  assert.equal(decodeCastSpellAnsNestedU32FromRaw821('cee352e7'), 1531465011);
  assert.equal(decodeCastSpellAnsNestedU32FromRaw821('4f130fd8'), 1233081321);
  assert.equal(decodeCastSpellAnsNestedU32FromRaw821('cee352e'), null);
  const result = decode(replay, { runtimeImagePath: image, castPacketProfile: 'v5' });
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.profile_id, profileV5.id);
  assert.equal(result.evidence_nested_u32_transform_sha256,
    NESTED_U32_TRANSFORM_SHA256);
  assert.equal(result.events[0].build_profile, profileV5.id);
  assert.equal(result.events[0].raw_u32_0x1c_hex, 'cee352e7');
  assert.equal(result.events[0].opaque_u32_0x1c, 1531465011);
  assert.equal('raw_u32_0x4c_hex' in result.events[0], false);
  assert.equal('caster' in result.events[0], false);
  assert.equal('spell' in result.events[0], false);
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 CastSpellAns V6 opt-in retains V5 and adds only anonymous nested +0x4c u32', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.ok(args.includes('--nested-u32-0x1c'));
    assert.ok(args.includes('--nested-u32-0x4c'));
    const output = nativeResult(JSON.parse(options.input));
    output.nested_u32_transform_sha256 = NESTED_U32_TRANSFORM_SHA256;
    output.nested_u32_0x4c_transform_sha256 = NESTED_U32_0X4C_TRANSFORM_SHA256;
    output.results[0].raw_u32_0x1c_hex = 'cee352e7';
    output.results[0].opaque_u32_0x1c = 1531465011;
    output.results[0].raw_u32_0x4c_hex = '7525f20b';
    output.results[0].opaque_u32_0x4c = 1073742460;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  assert.equal(decodeCastSpellAnsNestedU32At4cFromRaw821('7525f20b'), 1073742460);
  assert.equal(decodeCastSpellAnsNestedU32At4cFromRaw821('40d4f20b'), 1073742837);
  assert.equal(decodeCastSpellAnsNestedU32At4cFromRaw821('7525f20'), null);
  const result = decode(replay, { runtimeImagePath: image, castPacketProfile: 'v6' });
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.profile_id, profileV6.id);
  assert.equal(result.evidence_nested_u32_transform_sha256, NESTED_U32_TRANSFORM_SHA256);
  assert.equal(result.evidence_nested_u32_0x4c_transform_sha256,
    NESTED_U32_0X4C_TRANSFORM_SHA256);
  assert.equal(result.events[0].build_profile, profileV6.id);
  assert.equal(result.events[0].raw_u32_0x1c_hex, 'cee352e7');
  assert.equal(result.events[0].opaque_u32_0x1c, 1531465011);
  assert.equal(result.events[0].raw_u32_0x4c_hex, '7525f20b');
  assert.equal(result.events[0].opaque_u32_0x4c, 1073742460);
  assert.equal('caster' in result.events[0], false);
  assert.equal('spell' in result.events[0], false);
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 CastSpellAns V6 rejects mismatched native +0x4c field and identity atomically', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  let mode = 'wrong-value';
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.nested_u32_transform_sha256 = NESTED_U32_TRANSFORM_SHA256;
    output.nested_u32_0x4c_transform_sha256 = mode === 'wrong-hash'
      ? '0'.repeat(64) : NESTED_U32_0X4C_TRANSFORM_SHA256;
    output.results[0].raw_u32_0x1c_hex = 'cee352e7';
    output.results[0].opaque_u32_0x1c = 1531465011;
    output.results[0].raw_u32_0x4c_hex = mode === 'wrong-raw'
      ? 'notbytes' : '7525f20b';
    output.results[0].opaque_u32_0x4c = mode === 'wrong-value'
      ? 1073742461 : 1073742460;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  for (const variant of ['wrong-value', 'wrong-raw', 'wrong-hash']) {
    mode = variant;
    const result = decode(replay, { runtimeImagePath: image, castPacketProfile: 'v6' });
    assert.equal(result.status, 'DECODE_FAILED', variant);
    assert.equal(result.events, null, variant);
  }
  assert.equal(invoke.mock.callCount(), 3);
});

test('821 CastSpellAns V5 rejects mismatched native field and transform atomically', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  let mode = 'wrong-value';
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.nested_u32_transform_sha256 = mode === 'wrong-hash'
      ? '0'.repeat(64) : NESTED_U32_TRANSFORM_SHA256;
    output.results[0].raw_u32_0x1c_hex = mode === 'wrong-raw'
      ? 'notbytes' : 'cee352e7';
    output.results[0].opaque_u32_0x1c = mode === 'wrong-value'
      ? 1531465012 : 1531465011;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  for (const variant of ['wrong-value', 'wrong-raw', 'wrong-hash']) {
    mode = variant;
    const result = decode(replay, { runtimeImagePath: image, castPacketProfile: 'v5' });
    assert.equal(result.status, 'DECODE_FAILED', variant);
    assert.equal(result.events, null, variant);
  }
  assert.equal(decode(replay, { runtimeImagePath: image,
    castPacketProfile: 'v7' }).status, 'UNSUPPORTED');
  assert.equal(invoke.mock.callCount(), 3);
});

test('821 CastSpellAns rejects malformed nested float without candidate events', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const invalidNumber = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].opaque_f32_0xe0 = null;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const first = decode(replay, { runtimeImagePath: image });
  assert.equal(first.status, 'DECODE_FAILED');
  assert.equal(first.events, null);
  invalidNumber.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].raw_f32_bytes_hex = 'not-native-bytes';
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const second = decode(replay, { runtimeImagePath: image });
  assert.equal(second.status, 'DECODE_FAILED');
  assert.equal(second.events, null);
});

test('821 CastSpellAns rejects a finite float inconsistent with native bytes', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].opaque_f32_0xe0 = 1;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.events, null);
  assert.equal(result.first_failed_packet_ref.packet_id, 0x01da);
});

test('821 CastSpellAns rejects a nested byte inconsistent with native bytes', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const wrongValue = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].opaque_u8_0x140 = 13;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const first = decode(replay, { runtimeImagePath: image });
  assert.equal(first.status, 'DECODE_FAILED');
  assert.equal(first.events, null);
  wrongValue.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].raw_u8_0x140_hex = 'gg';
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const second = decode(replay, { runtimeImagePath: image });
  assert.equal(second.status, 'DECODE_FAILED');
  assert.equal(second.events, null);
});

test('821 CastSpellAns rejects nested callback bits inconsistent with native bytes', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const wrongValue = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].opaque_nested_bits_0x24 = 3;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const first = decode(replay, { runtimeImagePath: image });
  assert.equal(first.status, 'DECODE_FAILED');
  assert.equal(first.events, null);
  wrongValue.mock.restore();
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].raw_nested_bits_0x24_hex = 'xx';
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const second = decode(replay, { runtimeImagePath: image });
  assert.equal(second.status, 'DECODE_FAILED');
  assert.equal(second.events, null);
});

test('821 native CastSpellAns reads callback bits at the pinned packet offset', (t) => {
  const image = process.env.ROFL_821_RUNTIME_IMAGE || path.resolve(__dirname, '..',
    'artifacts', '16_19_development', 'kr_821_runtime_capture',
    'LeagueOfLegends_16.19.821.7343.memory.bin');
  const rowsFile = process.env.ROFL_821_CAST_ROUTE_ROWS || path.resolve(__dirname,
    '..', 'artifacts', '16_19_development', 'kr_821_cast_probe',
    'route_01da_rows.jsonl');
  if (!fs.existsSync(image) || !fs.existsSync(rowsFile)) {
    t.skip('exact private 821 image and Replay route rows are unavailable');
    return;
  }
  const fixtures = [
    { name: 'KR_8392938200.rofl', chunkIndex: 20, blockOffset: 180878,
      payloadSha256: '73c3b3d126bc061cd20fd930bfa32f5ab95b6be545a1fd528b00bcf0583174be',
      raw: 'c6', value: 1 },
    { name: 'KR_8394000013.rofl', chunkIndex: 4, blockOffset: 151920,
      payloadSha256: '96168c950828b827eb445d3ea020376084e68b963d61431a491a61541a918610',
      raw: '18', value: 100 },
  ];
  const selected = new Map();
  for (const line of fs.readFileSync(rowsFile, 'utf8').split(/\r?\n/)) {
    if (!line) continue;
    const row = JSON.parse(line);
    const fixture = fixtures.find((entry) => entry.name === row.name
      && entry.chunkIndex === row.chunk_index
      && entry.blockOffset === row.block_offset);
    if (fixture) selected.set(fixture.name, row);
  }
  const packets = fixtures.map((fixture) => {
    const row = selected.get(fixture.name);
    assert.ok(row, `missing exact Replay packet ${fixture.name}`);
    assert.equal(crypto.createHash('sha256').update(Buffer.from(row.payload_hex, 'hex'))
      .digest('hex'), fixture.payloadSha256);
    return { raw_param: row.raw_param, payload_hex: row.payload_hex };
  });
  const script = path.resolve(__dirname, '..', 'scripts',
    'decode_cast_spell_ans_packet_16_19_821.py');
  const run = childProcess.spawnSync(process.env.PYTHON || 'python',
    ['-B', script, '--image', image], {
      input: JSON.stringify({ replay_version: BUILD, packets }),
      encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: 60000,
    });
  assert.equal(run.status, 0, run.error?.message || run.stderr);
  const decoded = JSON.parse(run.stdout);
  assert.equal(decoded.runtime_image_sha256, IMAGE_SHA256);
  assert.equal(decoded.status, 'PASS');
  for (let index = 0; index < fixtures.length; index += 1) {
    assert.equal(decoded.results[index].status, 'DECODED');
    assert.equal(decoded.results[index].bytes_consumed, packets[index].payload_hex.length / 2);
    assert.equal(decoded.results[index].raw_nested_bits_0x24_hex, fixtures[index].raw);
    assert.equal(decoded.results[index].opaque_nested_bits_0x24, fixtures[index].value);
  }
});

test('821 native CastSpellAns V5 reads +0x1c in original Replay packets', (t) => {
  const image = process.env.ROFL_821_RUNTIME_IMAGE;
  const rowsFile = process.env.ROFL_821_CAST_ROUTE_ROWS;
  const replayDirectory = process.env.ROFL_821_REPLAY_DIRECTORY;
  if (![image, rowsFile, replayDirectory].every(
    (filename) => filename && fs.existsSync(filename))) {
    t.skip('exact private 821 image, original Replays and route rows are unavailable');
    return;
  }
  const fixtures = [
    { name: 'KR_8392938200.rofl', chunkIndex: 4, blockOffset: 15809,
      payloadSha256: 'e2f4a80671b5e31143a322256c3dcadec0138140cd053ff31d83443e31756a0a',
      raw: 'cee352e7', value: 1531465011 },
    { name: 'KR_8392938200.rofl', chunkIndex: 5, blockOffset: 173877,
      payloadSha256: '679f7a69772b587f16cf30e0aee3a24f28e80f647b8b19b627accfc75c6f762f',
      raw: '4f130fd8', value: 1233081321 },
    { name: 'KR_8393456728.rofl', chunkIndex: 5, blockOffset: 175414,
      payloadSha256: 'a5da13e28e37419e7b9afa06c07278c407836f21ef3aabca4949cd9b9e34b732',
      raw: '4f130fd8', value: 1233081321 },
  ];
  const found = new Map();
  for (const line of fs.readFileSync(rowsFile, 'utf8').split(/\r?\n/)) {
    if (!line) continue;
    const row = JSON.parse(line);
    const fixture = fixtures.find((entry) => entry.name === row.name
      && entry.chunkIndex === row.chunk_index
      && entry.blockOffset === row.block_offset);
    if (fixture) found.set(fixture, row);
  }
  const packets = fixtures.map((fixture) => {
    const row = found.get(fixture);
    assert.ok(row, `missing exact Replay packet ${fixture.name}`);
    assert.equal(crypto.createHash('sha256').update(
      fs.readFileSync(path.join(replayDirectory, fixture.name))).digest('hex'),
    row.replay_sha256);
    assert.equal(crypto.createHash('sha256').update(Buffer.from(row.payload_hex, 'hex'))
      .digest('hex'), fixture.payloadSha256);
    return { raw_param: row.raw_param, payload_hex: row.payload_hex };
  });
  const first = Buffer.from(packets[0].payload_hex, 'hex');
  const controls = [first.subarray(0, -1), Buffer.concat([first, Buffer.from([0])])]
    .map((payload) => ({ raw_param: packets[0].raw_param,
      payload_hex: payload.toString('hex') }));
  const script = path.resolve(__dirname, '..', 'scripts',
    'decode_cast_spell_ans_packet_16_19_821.py');
  const run = childProcess.spawnSync(process.env.PYTHON || 'python',
    ['-B', script, '--image', image, '--nested-u32-0x1c'], {
      input: JSON.stringify({ replay_version: BUILD, packets: [...packets, ...controls] }),
      encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: 60000,
    });
  assert.equal(run.status, 0, run.error?.message || run.stderr);
  const decoded = JSON.parse(run.stdout);
  assert.equal(decoded.status, 'PASS');
  assert.equal(decoded.runtime_image_sha256, IMAGE_SHA256);
  assert.equal(decoded.nested_u32_transform_sha256, NESTED_U32_TRANSFORM_SHA256);
  for (const [index, fixture] of fixtures.entries()) {
    const row = decoded.results[index];
    assert.equal(row.status, 'DECODED');
    assert.equal(row.bytes_consumed, packets[index].payload_hex.length / 2);
    assert.equal(row.raw_u32_0x1c_hex, fixture.raw);
    assert.equal(row.opaque_u32_0x1c, fixture.value);
    assert.equal(decodeCastSpellAnsNestedU32FromRaw821(fixture.raw), fixture.value);
  }
  for (const row of decoded.results.slice(fixtures.length)) {
    assert.equal(row.status, 'FAILED');
  }
});

test('821 native CastSpellAns V6 reads +0x4c in original game and keyframe packets', (t) => {
  const image = process.env.ROFL_821_RUNTIME_IMAGE;
  const rowsFile = process.env.ROFL_821_CAST_ROUTE_ROWS;
  const replayDirectory = process.env.ROFL_821_REPLAY_DIRECTORY;
  if (![image, rowsFile, replayDirectory].every(
    (filename) => filename && fs.existsSync(filename))) {
    t.skip('exact private 821 image, original Replays and route rows are unavailable');
    return;
  }
  const fixtures = [
    { name: 'KR_8392938200.rofl', chunkIndex: 4, blockOffset: 15809,
      payloadSha256: 'e2f4a80671b5e31143a322256c3dcadec0138140cd053ff31d83443e31756a0a',
      raw: '7525f20b', value: 1073742460 },
    { name: 'KR_8392938200.rofl', chunkIndex: 5, blockOffset: 173877,
      payloadSha256: '679f7a69772b587f16cf30e0aee3a24f28e80f647b8b19b627accfc75c6f762f',
      raw: '40d4f20b', value: 1073742837 },
    { name: 'KR_8393456728.rofl', chunkIndex: 3, blockOffset: 105469,
      payloadSha256: '277d06c9b814313a70b2a87e221c4d0e580e70ee74cdd453b6b5c88b16741351',
      raw: 'c925f20b', value: 1073742385 },
    { name: 'KR_8393581977.rofl', chunkIndex: 3, blockOffset: 78097,
      payloadSha256: 'b7bf04e713ceff2386a8a43cdff691e1b439f7c07f2cc8b5c6b405ad69460abe',
      raw: '3325f20b', value: 1073742395 },
  ];
  const found = new Map();
  for (const line of fs.readFileSync(rowsFile, 'utf8').split(/\r?\n/)) {
    if (!line) continue;
    const row = JSON.parse(line);
    const fixture = fixtures.find((entry) => entry.name === row.name
      && entry.chunkIndex === row.chunk_index
      && entry.blockOffset === row.block_offset);
    if (fixture) found.set(fixture, row);
  }
  const packets = fixtures.map((fixture) => {
    const row = found.get(fixture);
    assert.ok(row, `missing exact Replay packet ${fixture.name}`);
    assert.equal(crypto.createHash('sha256').update(
      fs.readFileSync(path.join(replayDirectory, fixture.name))).digest('hex'),
    row.replay_sha256);
    assert.equal(crypto.createHash('sha256').update(Buffer.from(row.payload_hex, 'hex'))
      .digest('hex'), fixture.payloadSha256);
    return { raw_param: row.raw_param, payload_hex: row.payload_hex };
  });
  const first = Buffer.from(packets[0].payload_hex, 'hex');
  const controls = [first.subarray(0, -1), Buffer.concat([first, Buffer.from([0])])]
    .map((payload) => ({ raw_param: packets[0].raw_param,
      payload_hex: payload.toString('hex') }));
  const script = path.resolve(__dirname, '..', 'scripts',
    'decode_cast_spell_ans_packet_16_19_821.py');
  const run = childProcess.spawnSync(process.env.PYTHON || 'python',
    ['-B', script, '--image', image, '--nested-u32-0x1c', '--nested-u32-0x4c'], {
      input: JSON.stringify({ replay_version: BUILD, packets: [...packets, ...controls] }),
      encoding: 'utf8', maxBuffer: 8 * 1024 * 1024, timeout: 60000,
    });
  assert.equal(run.status, 0, run.error?.message || run.stderr);
  const decoded = JSON.parse(run.stdout);
  assert.equal(decoded.status, 'PASS');
  assert.equal(decoded.runtime_image_sha256, IMAGE_SHA256);
  assert.equal(decoded.nested_u32_transform_sha256, NESTED_U32_TRANSFORM_SHA256);
  assert.equal(decoded.nested_u32_0x4c_transform_sha256,
    NESTED_U32_0X4C_TRANSFORM_SHA256);
  for (const [index, fixture] of fixtures.entries()) {
    const row = decoded.results[index];
    assert.equal(row.status, 'DECODED');
    assert.equal(row.bytes_consumed, packets[index].payload_hex.length / 2);
    assert.equal(row.raw_u32_0x4c_hex, fixture.raw);
    assert.equal(row.opaque_u32_0x4c, fixture.value);
    assert.equal(decodeCastSpellAnsNestedU32At4cFromRaw821(fixture.raw), fixture.value);
    assert.match(row.raw_u32_0x1c_hex, /^[0-9a-f]{8}$/);
  }
  for (const row of decoded.results.slice(fixtures.length)) {
    assert.equal(row.status, 'FAILED');
  }
});

test('821 CastSpellAns V6 fully decodes three original exact-build Replays', (t) => {
  const image = process.env.ROFL_821_RUNTIME_IMAGE;
  const replayDirectory = process.env.ROFL_821_REPLAY_DIRECTORY;
  if (![image, replayDirectory].every((filename) => filename && fs.existsSync(filename))) {
    t.skip('exact private 821 image and original Replays are unavailable');
    return;
  }
  for (const [name, count] of [
    ['KR_8392938200.rofl', 5980],
    ['KR_8393456728.rofl', 5713],
    ['KR_8393581977.rofl', 5561],
  ]) {
    const replay = parseReplayFile(path.join(replayDirectory, name));
    assert.equal(replay.header.version, BUILD);
    const result = decode(replay, { runtimeImagePath: image, castPacketProfile: 'v6' });
    assert.equal(result.status, 'CANDIDATE', `${name}: ${result.error || ''}`);
    assert.equal(result.profile_id, profileV6.id);
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.input_count, count);
    assert.equal(result.event_count, count);
    assert.equal(result.events.length, count);
    for (const row of result.events) {
      assert.equal(row.build_profile, profileV6.id);
      assert.equal(row.opaque_u32_0x4c,
        decodeCastSpellAnsNestedU32At4cFromRaw821(row.raw_u32_0x4c_hex));
    }
  }
});

test('821 CastSpellAns requires exact Replay build and leaves absent route unavailable', () => {
  const older = replayWithChunks([{ packets: [packet()] }], '16.19.820.7193');
  assert.equal(decode(older).status, 'UNSUPPORTED');
  const absent = replayWithChunks([{ packets: [packet(0x018d)] }]);
  assert.equal(decode(absent).status, 'PROFILE_UNAVAILABLE');
  const present = replayWithChunks([{ packets: [packet()] }]);
  const missing = decode(present);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
});

test('821 CastSpellAns rejects changed Replay source and observed-scope shape errors before runtime', (t) => {
  const invoke = t.mock.method(childProcess, 'spawnSync', () => {
    throw new Error('runtime should not be invoked');
  });
  const mutated = replayWithChunks([{ packets: [packet()] }]);
  mutated.buffer[0] ^= 1;
  assert.match(decode(mutated).error, /source integrity/);
  const short = replayWithChunks([{ packets: [packet(0x01da, 0x400000ae,
    Buffer.concat([Buffer.from([0x15]), Buffer.alloc(95)]))] }]);
  assert.equal(decode(short).status, 'DECODE_FAILED');
  const wrongSelector = replayWithChunks([{ packets: [packet(0x01da, 0x400000ae,
    Buffer.concat([Buffer.from([0xff]), Buffer.alloc(128)]))] }]);
  assert.equal(decode(wrongSelector).status, 'DECODE_FAILED');
  const wrongStream = replayWithChunks([{ stream: 3, packets: [packet()] }]);
  assert.equal(decode(wrongStream).status, 'DECODE_FAILED');
  const mixedStream = replayWithChunks([
    { stream: 1, packets: [packet()] },
    { stream: 3, packets: [packet()] },
  ]);
  const mixed = decode(mixedStream);
  assert.equal(mixed.status, 'DECODE_FAILED');
  assert.equal(mixed.events, null);
  const collected = collect821Routes(mixedStream, ['cast_spell_ans_packet']);
  const shared = decode(mixedStream, { precollected: collected });
  assert.equal(shared.status, 'DECODE_FAILED');
  assert.equal(shared.events, null);
  assert.equal(invoke.mock.callCount(), 0);
});

test('821 CastSpellAns reports wrong image identity without candidate events', (t) => {
  const image = fakeImage(t);
  t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'runtime image SHA-256 mismatch: old image', stdout: '',
  }));
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(result.runtime_image_used, false);
  assert.equal(result.event_count, null);
  assert.equal(result.events, null);
});

test('821 CastSpellAns rejects incomplete native consumption and invalid field shape', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  const first = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].bytes_consumed -= 1;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const truncated = decode(replay, { runtimeImagePath: image });
  assert.equal(truncated.status, 'DECODE_FAILED');
  assert.equal(truncated.runtime_image_status, 'MATCHED_USED');
  assert.equal(truncated.first_failed_packet_ref.packet_id, 0x01da);
  assert.equal(truncated.events, null);
  first.mock.restore();
  const second = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const output = nativeResult(JSON.parse(options.input));
    output.results[0].opaque_flag_0x148 = 2;
    output.results[0].opaque_i32_0x14c = 0x80000000;
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  const invalid = decode(replay, { runtimeImagePath: image });
  assert.equal(invalid.status, 'DECODE_FAILED');
  assert.equal(invalid.events, null);
  assert.equal(second.mock.callCount(), 1);
});

test('821 CastSpellAns discards earlier batch events when a later native batch fails', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: Array.from({ length: 8193 }, () => packet()) }]);
  let calls = 0;
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    calls += 1;
    if (calls === 1) {
      const request = JSON.parse(options.input);
      assert.equal(request.packets.length, 8192);
      return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
    }
    assert.equal(JSON.parse(options.input).packets.length, 1);
    return { status: 1, stderr: 'native failure in second batch', stdout: '' };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(calls, 2);
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.input_count, 8193);
  assert.equal(result.runtime_image_used, true);
  assert.equal(result.event_count, null);
  assert.equal(result.events, null);
});
