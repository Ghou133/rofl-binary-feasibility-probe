'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  CIRCULAR_MOVEMENT_RESTRICTION_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeCircularMovementRestrictionPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_circular_movement_restriction_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_PATH = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY_DIR = 'C:/Users/26560/Documents/ChatGPT/kr-rofl-batch-collector/data/KR/16.19/builds/16.19.821.7343/rofl';
const HAS_IMAGE = fs.existsSync(IMAGE_PATH);
const HAS_REPLAYS = fs.existsSync(REPLAY_DIR);
const FIRST_RECORD = '37acbb2393d15e28d1dc507a4e65ef024e04681c4edc8989';
const GAME_RECORD = '37acabbdef01224ad1dcad7a07d4275707d59adae7ef8d55';

function removeTaskTempDirectory(directory) {
  const target = path.resolve(directory);
  const relative = path.relative(path.resolve(os.tmpdir()), target);
  assert.ok(relative && !relative.startsWith('..') && !path.isAbsolute(relative));
  fs.rmSync(target, { recursive: true, force: true });
}

function packet(payloadHex, rawParam = 0x400000ae, streamTimeMs = 1000,
  packetId = 0x0464) {
  const payload = Buffer.from(payloadHex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(streamTimeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, keyframe = [packet('36'), packet(FIRST_RECORD)],
  game = [packet(GAME_RECORD, 0x400000b6, 1500)] } = {}) {
  return replayFromChunks([
    { stream: 2, body: Buffer.concat(keyframe) },
    { stream: 1, body: Buffer.concat(game) },
  ], version);
}

test('821 circular restriction retains native-backed anonymous record fields and raw refs',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const replay = fixture();
    const result = decode(replay, { runtimeImagePath: IMAGE_PATH });
    assert.equal(profile.packet_name, 'PKT_S2C_SyncCircularMovementRestriction_s');
    assert.equal(result.status, 'CANDIDATE');
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.input_count, 3);
    assert.equal(result.event_count, 3);
    assert.deepEqual(result.observed_shape_counts, { empty1: 1, record24: 2 });
    assert.deepEqual(result.events.map((row) => row.packet_record_count_candidate), [0, 1, 1]);
    assert.equal(result.events[0].anonymous_scalar_f32_candidate, null);
    assert.equal(result.events[0].anonymous_vector_xyz_f32_candidate, null);
    assert.equal(result.events[0].raw_protected_scalar_bytes_hex, null);
    assert.equal(result.events[1].anonymous_scalar_f32_candidate, 375);
    assert.deepEqual(result.events[1].anonymous_vector_xyz_f32_candidate, {
      x: 410.6283874511719, y: 183, z: 416.9840087890625,
    });
    assert.equal(result.events[1].raw_protected_scalar_bytes_hex, 'd1dc507a');
    assert.equal(result.events[1].raw_protected_vector_bytes_hex,
      '02ef654e8989dc4e1c68044e');
    assert.equal(result.events[1].callback_scalar_bytes_hex, '0080bb43');
    assert.equal(result.events[1].callback_vector_bytes_hex,
      '6f50cd4300003743f47dd043');
    assert.equal(result.events[2].anonymous_scalar_f32_candidate, 425);
    assert.deepEqual(result.events[2].anonymous_vector_xyz_f32_candidate, {
      x: 6781.587890625, y: 52.083900451660156, z: 7111.6513671875,
    });
    assert.equal(result.events[2].raw_packet_ref.chunk_stream, 'game_chunk');
    assert.equal(result.events[2].raw_packet_ref.raw_param, 0x400000b6);
    assert.equal(result.events[2].raw_packet_ref.replay_sha256, replay.source_sha256);
    for (const row of result.events) {
      assert.equal(row.semantic_effect_status, 'UNKNOWN');
      for (const field of ['position', 'path', 'actor', 'participant_id',
        'owner', 'target', 'restriction_effect']) assert.equal(field in row, false);
    }
  });

test('821 circular restriction rejects foreign build, absent route and missing image', () => {
  assert.equal(decode(fixture({ version: '16.19.820.7193' }),
    { runtimeImagePath: IMAGE_PATH }).status, 'UNSUPPORTED');
  const absent = fixture({ keyframe: [packet('36', 0x400000ae, 1000, 0x00ba)], game: [] });
  assert.equal(decode(absent, { runtimeImagePath: IMAGE_PATH }).status, 'PROFILE_UNAVAILABLE');
  const missing = decode(fixture());
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.input_count, 3);
  assert.equal(missing.events, null);
});

test('821 circular restriction rejects invalid packet shapes before image use', () => {
  const bad = [
    fixture({ game: [packet(FIRST_RECORD.slice(0, -2))] }),
    fixture({ game: [packet('38' + FIRST_RECORD.slice(2))] }),
    fixture({ game: [packet('37ff' + FIRST_RECORD.slice(4))] }),
    fixture({ game: [packet('37ac002393d15e28' + FIRST_RECORD.slice(16))] }),
    replayFromChunks([{ stream: 3, body: packet('36') }], BUILD),
  ];
  for (const replay of bad) {
    const result = decode(replay, { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.runtime_image_status, 'NOT_CHECKED');
    assert.equal(result.events, null);
    assert.equal(result.first_failed_packet_ref.packet_id, 0x0464);
  }
});

test('821 circular restriction fails closed for changed source and wrong image', () => {
  const replay = fixture();
  replay.buffer[replay.buffer.length - 1] ^= 1;
  const tampered = decode(replay, { runtimeImagePath: IMAGE_PATH });
  assert.equal(tampered.status, 'DECODE_FAILED');
  assert.match(tampered.error, /source integrity/i);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-restriction-'));
  try {
    const wrongImage = path.join(directory, 'runtime.bin');
    fs.writeFileSync(wrongImage, Buffer.from([1, 2, 3]));
    const wrong = decode(fixture(), { runtimeImagePath: wrongImage });
    assert.equal(wrong.status, 'DECODE_FAILED');
    assert.equal(wrong.runtime_image_status, 'HASH_MISMATCH');
    assert.equal(wrong.events, null);
  } finally {
    removeTaskTempDirectory(directory);
  }
});

test('821 circular restriction rejects a same-size image with a changed hash',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-restriction-hash-'));
    try {
      const wrongImage = path.join(directory, 'runtime.bin');
      fs.copyFileSync(IMAGE_PATH, wrongImage);
      const file = fs.openSync(wrongImage, 'r+');
      try {
        const original = Buffer.alloc(1);
        fs.readSync(file, original, 0, 1, 0);
        fs.writeSync(file, Buffer.from([original[0] ^ 1]), 0, 1, 0);
      } finally {
        fs.closeSync(file);
      }
      const result = decode(fixture(), { runtimeImagePath: wrongImage });
      assert.equal(result.status, 'DECODE_FAILED');
      assert.equal(result.runtime_image_status, 'HASH_MISMATCH');
      assert.equal(result.events, null);
    } finally {
      removeTaskTempDirectory(directory);
    }
  });

test('821 circular restriction decodes all supplied KR route packets without dropping zero records',
  { skip: (!HAS_IMAGE || !HAS_REPLAYS) && 'exact mapped image or KR 821 Replays are unavailable' },
  () => {
    const names = fs.readdirSync(REPLAY_DIR).filter((name) => name.endsWith('.rofl')).sort();
    assert.equal(names.length, 11);
    let packets = 0;
    let empty = 0;
    let records = 0;
    for (const name of names) {
      const replay = parseReplayFile(path.join(REPLAY_DIR, name));
      const result = decode(replay, { runtimeImagePath: IMAGE_PATH });
      assert.equal(result.status, 'CANDIDATE', name);
      assert.equal(result.runtime_image_status, 'MATCHED_USED', name);
      assert.equal(result.input_count, result.event_count, name);
      assert.equal(result.events.length, result.event_count, name);
      packets += result.event_count;
      empty += result.observed_shape_counts.empty1;
      records += result.observed_shape_counts.record24;
    }
    assert.equal(packets, 68_242);
    assert.equal(empty, 68_113);
    assert.equal(records, 129);
  });
