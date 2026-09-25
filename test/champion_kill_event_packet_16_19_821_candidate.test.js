'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  CHAMPION_KILL_EVENT_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeChampionKillEventPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_champion_kill_event_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';

function packet(packetId = 0x040a, rawParam = 0x400000ae, payload = Buffer.alloc(104, 0x4a)) {
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
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-champion-kill-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const image = path.join(directory, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  return image;
}

function nativeResult(request, childIds) {
  return {
    status: 'PASS', runtime_image_sha256: IMAGE_SHA256,
    results: request.packets.map((row, index) => {
      const id = childIds[index];
      const blob = Buffer.alloc(96);
      if (id === 0x0007) {
        blob.writeUInt32LE(0x400000ae, 0x04);
        blob.writeUInt32LE(0xffffffff, 0x58);
        blob.writeUInt32LE(0, 0x5c);
      }
      return {
        status: id === 0x0007 ? 'DECODED' : 'EXCLUDED_CHILD',
        input_index: index, raw_param: row.raw_param,
        raw_payload_sha256: crypto.createHash('sha256')
          .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
        deserialize_return_al: 1, bytes_consumed: 104,
        native_packet_id: 0x040a, native_raw_param: row.raw_param,
        event_id: id, raw_event_id_hex: id === 0x0007 ? '0x49e8' : '0x0000',
        event_blob_length: 96, event_blob_hex: blob.toString('hex'),
        event_blob_sha256: crypto.createHash('sha256').update(blob).digest('hex'),
        ...(id === 0x0007 ? {
          event_u32_0x04: 0x400000ae,
          event_u32_0x58: 0xffffffff,
          event_u32_0x5c: 0,
        } : {}),
      };
    }),
  };
}

test('821 OnChampionKill selects exact child among three same-length controls', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [
    packet(), packet(0x040a, 0x400000af), packet(0x040a, 0x400000b0),
    packet(0x040a, 0x400000b1),
    packet(0x040a, 0x400000b2, Buffer.alloc(60)),
  ] }]);
  const invoke = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    assert.match(args[1], /decode_champion_kill_event_packet_16_19_821\.py$/);
    assert.equal(args[3], path.resolve(image));
    const request = JSON.parse(options.input);
    assert.equal(request.replay_version, BUILD);
    assert.deepEqual(request.packets.map((row) => [row.packet_id, row.stream_tag,
      row.payload_hex.length / 2]), Array(4).fill([0x040a, 1, 104]));
    return { status: 0, stderr: '',
      stdout: JSON.stringify(nativeResult(request, [0x0007, 0x000b, 0x000c, 0x000d])) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(profile.registered_event_name, 'OnChampionKill');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 4);
  assert.equal(result.target_packet_count, 1);
  assert.equal(result.excluded_child_count, 3);
  assert.deepEqual(result.excluded_child_ids,
    { '0x000b': 1, '0x000c': 1, '0x000d': 1 });
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.events[0].event_type, 'CHAMPION_KILL_EVENT_PACKET_CANDIDATE');
  assert.equal(result.events[0].registered_event_name, 'OnChampionKill');
  assert.equal(result.events[0].event_u32_0x04, 0x400000ae);
  assert.equal(result.events[0].event_u32_0x58, 0xffffffff);
  assert.equal(result.events[0].event_u32_0x5c, 0);
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  for (const field of ['killer', 'victim', 'source', 'target', 'effective_kill']) {
    assert.equal(field in result.events[0], false);
  }
  assert.equal(invoke.mock.callCount(), 1);
});

test('821 OnChampionKill distinguishes absent shape, missing image, wrong build, and source corruption', () => {
  const absent = replayWithChunks([{ packets: [packet(0x040a, 0x400000ae,
    Buffer.alloc(60))] }]);
  assert.equal(decode(absent).status, 'PROFILE_UNAVAILABLE');
  const present = replayWithChunks([{ packets: [packet()] }]);
  const missing = decode(present);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.input_count, 1);
  const wrongBuild = replayWithChunks([{ packets: [packet()] }], '16.19.820.7193');
  assert.equal(decode(wrongBuild).status, 'UNSUPPORTED');
  const mutated = replayWithChunks([{ packets: [packet()] }]);
  mutated.buffer[0] ^= 1;
  assert.equal(decode(mutated).status, 'DECODE_FAILED');
  assert.match(decode(mutated).error, /source integrity/);
});

test('821 OnChampionKill rejects foreign stream and unknown native child', (t) => {
  const image = fakeImage(t);
  const foreign = replayWithChunks([{ stream: 2, packets: [packet()] }]);
  assert.equal(decode(foreign, { runtimeImagePath: image }).status, 'DECODE_FAILED');
  const replay = replayWithChunks([{ packets: [packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    return { status: 0, stderr: '',
      stdout: JSON.stringify(nativeResult(request, [0x0004])) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.events, null);
  assert.equal(result.first_failed_packet_ref.packet_id, 0x040a);
});

test('821 OnChampionKill reports fully decoded foreign children without target events', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    return { status: 0, stderr: '',
      stdout: JSON.stringify(nativeResult(request, [0x000b])) };
  });
  const result = decode(replay, { runtimeImagePath: image });
  assert.equal(result.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.input_count, 1);
  assert.equal(result.target_packet_count, 0);
  assert.equal(result.excluded_child_count, 1);
  assert.deepEqual(result.events, []);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
});

test('821 OnChampionKill rejects tampered native blob hash and callback fields', (t) => {
  const image = fakeImage(t);
  const replay = replayWithChunks([{ packets: [packet()] }]);
  let tamper = 'event_u32_0x04';
  t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => {
    const request = JSON.parse(options.input);
    const output = nativeResult(request, [0x0007]);
    if (tamper === 'event_blob_sha256') {
      output.results[0].event_blob_sha256 = 'a'.repeat(64);
    } else {
      output.results[0][tamper] ^= 1;
    }
    return { status: 0, stderr: '', stdout: JSON.stringify(output) };
  });
  for (const field of ['event_u32_0x04', 'event_u32_0x58',
    'event_u32_0x5c', 'event_blob_sha256']) {
    tamper = field;
    const outcome = decode(replay, { runtimeImagePath: image });
    assert.equal(outcome.status, 'DECODE_FAILED', field);
    assert.equal(outcome.events, null, field);
    assert.equal(outcome.first_failed_packet_ref.packet_id, 0x040a, field);
  }
});
