'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { REPLAY_VERSION_821 } = require('../src/decoders/rofl_16_19_821_7343');
const { collect821Routes } = require('../src/decoders/rofl_16_19_821_scan');
const {
  HERO_ASSIST_CANDIDATE_PROFILE_821,
  assessHeroAssistTail821,
  decodeHeroAssistCandidates821,
} = require('../src/decoders/rofl_16_19_821_assist_candidate');

function packet(packetId, timeMs, rawParam, payload) {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timeMs / 1000, 1);
  header[5] = payload.length;
  header.writeUInt16LE(packetId, 6);
  header.writeUInt32LE(rawParam >>> 0, 8);
  return Buffer.concat([header, payload]);
}

function route(packetId, timeMs, rawParam, length) {
  return packet(packetId, timeMs, rawParam, Buffer.alloc(length, packetId & 0xff));
}

function pairPacket(part, timeMs, assistant, options = {}) {
  const payload = Buffer.alloc(44, 0x61);
  payload[0] = part === 'first' ? 0xe2 : 0xee;
  payload[1] = 0x35;
  payload[2] = part === 'first' ? 0xb9 : 0x0b;
  payload[3] = 0x4b;
  payload[4] = part === 'first' ? 0x3d : 0xb3;
  payload[43] = part === 'first' ? 0x14 : 0xd4;
  if (options.differentSharedByte) payload[10] ^= 1;
  const low = 0xad + assistant;
  const param = 0x40000000 | (part === 'first' ? 0x100 : 0) | low;
  return packet(0x040a, timeMs, param, payload);
}

function deathCore(timeMs, victim, sourceWire) {
  const victimParam = 0x400000ad + victim;
  const diePayload = Buffer.alloc(13, 0x38);
  Buffer.from(sourceWire, 'hex').copy(diePayload, 11);
  return [
    route(0x03d4, timeMs, 0, 3),
    route(0x031b, timeMs, 0, 12),
    route(0x0259, timeMs, victimParam, 5),
    packet(0x0438, timeMs, victimParam, diePayload),
  ];
}

function replayWithAssists(options = {}) {
  const first = pairPacket('first', 1000, options.assistant ?? 7);
  const second = pairPacket('second', options.secondOutsideDeath ? 1500 : 1000,
    options.secondAssistant ?? options.assistant ?? 7,
    { differentSharedByte: options.differentSharedByte });
  const pair = options.reversedOrder ? [second, first] : [first, second];
  const rows = [
    ...deathCore(1000, 1, '3678').slice(0, 3),
    ...pair.filter((_, index) => !options.missingSecond || index === 0),
    ...(options.duplicateSecond ? [second] : []),
    ...deathCore(1000, 1, '3678').slice(3),
    pairPacket('first', 1500, 9), // First shape alone also appears outside death.
    ...deathCore(2000, 4, options.nonheroSecondDeath ? '3478' : '3678'),
  ];
  const replay = replayFromChunks([{ body: Buffer.concat(rows) }],
    options.version ?? REPLAY_VERSION_821);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: String(index === 0 || index === 3 ? 1 : 0),
    CHAMPIONS_KILLED: String(index === 5 ? options.nonheroSecondDeath ? 1 : 2 : 0),
    ASSISTS: String(index === (options.assistant ?? 7) - 1 ? 1 : 0),
  }));
  return replay;
}

function fakeImage(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-assist-native-'));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  t.after(() => { fs.unlinkSync(image); fs.rmdirSync(directory); });
  return image;
}

function nativeResult(request) {
  return {
    status: 'PASS',
    runtime_image_sha256: HERO_ASSIST_CANDIDATE_PROFILE_821.evidence_runtime_image_sha256,
    results: request.packets.map((packetRow, index) => {
      const payload = Buffer.from(packetRow.payload_hex, 'hex');
      const first = payload[2] === 0xb9;
      return {
        status: 'DECODED', input_index: index, raw_param: packetRow.raw_param,
        raw_payload_sha256: crypto.createHash('sha256').update(payload).digest('hex'),
        deserialize_return_al: 1, bytes_consumed: 44,
        native_packet_id: 0x040a, native_raw_param: packetRow.raw_param,
        event_id: first ? 0x0056 : 0x0057,
        raw_event_id_hex: first ? '0x4914' : '0x49d4',
        event_blob_length: 36, event_blob_sha256: 'a'.repeat(64),
        event_u32_0x04: 0x400000ae,
        ...(first ? {} : { event_u32_0x20: 123 }),
      };
    }),
  };
}

test('821 assist requires all three exact-build Replay tail fields', () => {
  const replay = replayWithAssists();
  assert.equal(HERO_ASSIST_CANDIDATE_PROFILE_821.replay_version, REPLAY_VERSION_821);
  assert.deepEqual(assessHeroAssistTail821(replay).required_fields,
    ['NUM_DEATHS', 'CHAMPIONS_KILLED', 'ASSISTS']);
  for (const field of ['NUM_DEATHS', 'CHAMPIONS_KILLED', 'ASSISTS']) {
    const value = replay.tail.stats[0][field];
    replay.tail.stats[0][field] = null;
    assert.equal(assessHeroAssistTail821(replay).status, 'MISSING_INPUT', field);
    assert.equal(decodeHeroAssistCandidates821(replay).status, 'MISSING_INPUT', field);
    replay.tail.stats[0][field] = value;
  }
  const wrongBuild = replayWithAssists({ version: '16.19.820.7193' });
  assert.equal(decodeHeroAssistCandidates821(wrongBuild).status, 'UNSUPPORTED');
});

test('821 paired 0x040a/44 packets bind individual assistant to matched Hero_Die', () => {
  const replay = replayWithAssists();
  const standalone = decodeHeroAssistCandidates821(replay);
  const token = collect821Routes(replay, ['hero_assist']);
  const precollected = decodeHeroAssistCandidates821(replay, token);
  assert.equal(standalone.status, 'CANDIDATE');
  assert.equal(precollected.status, 'CANDIDATE');
  assert.equal(standalone.event_count, 2);
  assert.equal(standalone.assist_pair_count, 1);
  assert.equal(standalone.input_count, 3);
  assert.equal(standalone.nondeath_first_shape_count, 1);
  assert.equal(standalone.native_child_identity_status, 'NOT_CHECKED');
  assert.deepEqual(standalone.observed_assists_by_participant,
    [0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);
  assert.deepEqual(standalone.events.map((event) =>
    event.assisting_participant_ids_candidate), [[7], []]);
  assert.deepEqual(precollected.events.map((event) =>
    event.assisting_participant_ids_candidate), [[7], []]);
  const event = standalone.events[0];
  assert.equal(event.matched_hero_die_raw_packet_ref.packet_id, 0x0438);
  assert.equal(event.assist_pair_raw_packet_refs.length, 1);
  assert.deepEqual(event.assist_pair_raw_packet_refs[0].assistant_participant_id_candidate, 7);
  assert.deepEqual(event.assist_pair_raw_packet_refs[0].first_raw_packet_ref.packet_id, 0x040a);
  assert.equal(event.assist_pair_raw_packet_refs[0].first_raw_packet_ref.replay_sha256,
    replay.source_sha256);
  assert.ok(event.assist_pair_raw_packet_refs[0].first_raw_packet_ref
    .decompressed_block_offset < event.assist_pair_raw_packet_refs[0]
      .second_raw_packet_ref.decompressed_block_offset);
  assert.ok(event.assist_pair_raw_packet_refs[0].second_raw_packet_ref
    .decompressed_block_offset < event.matched_hero_die_raw_packet_ref
      .decompressed_block_offset);
});

test('821 assist optional exact-image child IDs bind matched and excluded packet refs', (t) => {
  const image = fakeImage(t);
  const replay = replayWithAssists();
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_assist_child_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, REPLAY_VERSION_821);
    assert.deepEqual(request.packets.map((row) => row.packet_id), [0x040a, 0x040a, 0x040a]);
    return { status: 0, stderr: '', stdout: JSON.stringify(nativeResult(request)) };
  });
  const result = decodeHeroAssistCandidates821(replay, null, { runtimeImagePath: image });
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.runtime_image_used, true);
  assert.equal(result.native_child_identity_status, 'MATCHED_USED');
  assert.equal(result.native_child_first_count, 2);
  assert.equal(result.native_child_second_count, 1);
  const pair = result.events[0].assist_pair_raw_packet_refs[0];
  assert.equal(pair.first_raw_packet_ref.native_child_event_id, 0x0056);
  assert.equal(pair.second_raw_packet_ref.native_child_event_id, 0x0057);
  assert.equal(pair.second_raw_packet_ref.event_u32_0x20, 123);
  assert.equal(result.nondeath_first_shape_packet_refs[0].native_child_event_id, 0x0056);
  assert.equal(result.events[1].assisting_participant_ids_candidate.length, 0);
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 assist native child disagreement and wrong image suppress candidate output', (t) => {
  const image = fakeImage(t);
  const replay = replayWithAssists();
  const wrongChild = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    result.results[0].event_id = 0x0057;
    result.results[0].raw_event_id_hex = '0x49d4';
    result.results[0].event_u32_0x20 = 123;
    return { status: 0, stderr: '', stdout: JSON.stringify(result) };
  });
  const mismatch = decodeHeroAssistCandidates821(replay, null, { runtimeImagePath: image });
  assert.equal(mismatch.status, 'DECODE_FAILED');
  assert.match(mismatch.error, /raw shape and exact native child ID disagree/);
  assert.equal(mismatch.events, null);
  assert.equal(mismatch.runtime_image_status, 'MATCHED_USED');
  wrongChild.mock.restore();
  const inconsistentRawId = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const result = nativeResult(JSON.parse(options.input));
    result.results[0].raw_event_id_hex = '0x1356';
    return { status: 0, stderr: '', stdout: JSON.stringify(result) };
  });
  const rawMismatch = decodeHeroAssistCandidates821(replay, null, { runtimeImagePath: image });
  assert.equal(rawMismatch.status, 'DECODE_FAILED');
  assert.match(rawMismatch.error, /did not match exact child identity/);
  assert.equal(rawMismatch.events, null);
  inconsistentRawId.mock.restore();
  t.mock.method(childProcess, 'spawnSync', () => ({
    status: 1, stderr: 'runtime image SHA-256 mismatch: wrong image', stdout: '',
  }));
  const wrongImage = decodeHeroAssistCandidates821(replay, null, { runtimeImagePath: image });
  assert.equal(wrongImage.status, 'DECODE_FAILED');
  assert.equal(wrongImage.runtime_image_status, 'HASH_MISMATCH');
  assert.equal(wrongImage.native_child_identity_status, 'FAILED');
  assert.equal(wrongImage.events, null);
});

test('nonhero death source preserves unavailable attribution', () => {
  const result = decodeHeroAssistCandidates821(replayWithAssists({ nonheroSecondDeath: true }));
  assert.equal(result.status, 'CANDIDATE');
  assert.deepEqual(result.events.map((event) =>
    event.assisting_participant_ids_candidate), [[7], null]);
  assert.equal(result.events[1].assist_observation_status, 'UNAVAILABLE_NONHERO_SOURCE');
  assert.equal(result.events[1].assist_pair_count, null);
});

for (const [name, options, expectedError] of [
  ['missing second half', { missingSecond: true }, /exactly one packet of each shape/],
  ['duplicate second half', { duplicateSecond: true }, /exactly one packet of each shape/],
  ['different bytes 5..42', { differentSharedByte: true }, /payload bytes 5..42 differ/],
  ['second half outside death', { secondOutsideDeath: true }, /without matched Hero_Die/],
  ['reversed source order', { reversedOrder: true }, /do not precede Hero_Die/],
  ['different assistant raw param', { secondAssistant: 8 }, /exactly one packet of each shape/],
  ['assistant equals killer', { assistant: 6 }, /equals the killer or victim/],
  ['assistant equals victim', { assistant: 1 }, /equals the killer or victim/],
]) {
  test(`821 assist candidate rejects ${name}`, () => {
    const result = decodeHeroAssistCandidates821(replayWithAssists(options));
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
    assert.match(result.error, expectedError);
  });
}

test('821 assist candidate rejects tail mismatch and replay-source changes', () => {
  const mismatch = replayWithAssists();
  mismatch.tail.stats[6].ASSISTS = '2';
  const result = decodeHeroAssistCandidates821(mismatch);
  assert.equal(result.status, 'DECODE_FAILED');
  assert.match(result.error, /do not match all ten Replay tail ASSISTS/);
  const changedSource = replayWithAssists();
  changedSource.buffer[0] ^= 1;
  const source = decodeHeroAssistCandidates821(changedSource);
  assert.equal(source.status, 'DECODE_FAILED');
  assert.match(source.error, /Replay source integrity failed/);
});
