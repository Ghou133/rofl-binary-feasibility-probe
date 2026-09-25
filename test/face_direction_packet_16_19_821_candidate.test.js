'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  FACE_DIRECTION_PACKET_CANDIDATE_PROFILE_821: profile,
  decodeFaceDirectionPacketCandidates821: decode,
  transformFaceDirectionVectorBytes821: transformVector,
} = require('../src/decoders/rofl_16_19_821_face_direction_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_PATH = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const HAS_IMAGE = fs.existsSync(IMAGE_PATH);

function packet(rawParam, payloadHex, timeMs = 1500) {
  const payload = Buffer.from(payloadHex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x038e, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, keyframeHex = '83230dd6f1f241e5e7dfdb8785',
  gamePackets = [
    [0x400000b9, '87fffa100ef3c590d4dfdbf8167bbdbdb1'],
    [0x400000b6, '93d3bb1ff2f37338a1033a9c0b'],
    [0x400000b7, '9bf352db11e7e7e7e7dfdb3876'],
  ],
} = {}) {
  return replayFromChunks([
    { stream: 2, body: packet(0x40000088, keyframeHex, 1000) },
    { stream: 1, body: Buffer.concat(gamePackets.map(([param, hex], index) =>
      packet(param, hex, 1500 + 100 * index))) },
  ], version);
}

test('821 native callback byte transform matches packet-local vectors without an image', () => {
  const cases = [
    ['83230dd6f1f241e5e7dfdb8785', '06f67f3f00206aad4def8ebc'],
    ['87fffa100ef3c590d4dfdbf8167bbdbdb1', 'e75d7f3fdf9b22bd2e976d3d'],
    ['93d3bb1ff2f37338a1033a9c0b', '7e1b65be445541bdad3779bf'],
    ['9bf352db11e7e7e7e7dfdb3876', 'd1557f3f00000000477f93bd'],
  ];
  for (const [wireHex, decodedHex] of cases) {
    assert.equal(transformVector(Buffer.from(wireHex, 'hex')).toString('hex'),
      decodedHex);
  }
  assert.throws(() => transformVector(Buffer.alloc(12)), RangeError);
});

test('821 FaceDirection accepts exact-image native-derived 13/17 shapes and keeps effect UNKNOWN',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const result = decode(fixture(), { runtimeImagePath: IMAGE_PATH });
    assert.equal(profile.evidence_status,
      'CANDIDATE_EXACT_821_FACE_DIRECTION_PACKET_UNIT_VECTOR');
    assert.equal(result.status, 'CANDIDATE');
    assert.equal(result.runtime_image_status, 'MATCHED_USED');
    assert.equal(result.runtime_image_sha256, profile.evidence_runtime_image_sha256);
    assert.equal(result.input_count, 4);
    assert.equal(result.event_count, 4);
    assert.deepEqual(result.observed_shape_counts,
      { keyframe13: 1, game13: 2, game17: 1 });
    assert.deepEqual(result.events.map((row) => row.packet_shape_candidate),
      ['keyframe13', 'game17', 'game13', 'game13']);
    assert.deepEqual(result.events.map((row) => row.raw_selector_byte),
      [0x83, 0x87, 0x93, 0x9b]);
    assert.deepEqual(result.events[0].packet_vector_xyz_f32_candidate, {
      x: 0.9998477697372437, y: -1.3308465440786676e-11,
      z: -0.017448091879487038,
    });
    assert.deepEqual(result.events[1].packet_vector_xyz_f32_candidate, {
      x: 0.9975265860557556, y: -0.039699431508779526,
      z: 0.05800550431013107,
    });
    assert.deepEqual(result.events[2].packet_vector_xyz_f32_candidate, {
      x: -0.2237376868724823, y: -0.04720045626163483,
      z: -0.9735057950019836,
    });
    assert.deepEqual(result.events[3].packet_vector_xyz_f32_candidate, {
      x: 0.9974032044410706, y: 0, z: -0.07202010601758957,
    });
    assert.deepEqual(result.events.map((row) => row.optional_scalar_f32_candidate),
      [null, 0.0833333358168602, null, null]);
    assert.equal(result.events[1].raw_optional_scalar_bytes_hex, '7bbdbdb1');
    assert.equal(result.events[1].raw_packet_ref.packet_id, 0x038e);
    assert.equal(result.events[1].raw_packet_ref.raw_param, 0x400000b9);
    assert.equal(result.events[1].raw_packet_ref.chunk_stream, 'game_chunk');
    for (const row of result.events) {
      assert.equal(row.semantic_direction_effect_status, 'UNKNOWN');
      for (const field of ['actor_id', 'participant_id_candidate', 'world_position',
        'path', 'direction_effect']) assert.equal(field in row, false);
    }
  });

test('821 FaceDirection reports missing image and wrong image separately', () => {
  const replay = fixture();
  const missing = decode(replay);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.missing_input, 'runtime_image');
  assert.equal(missing.input_count, 4);
  assert.equal(missing.events, null);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'face-direction-821-'));
  try {
    const wrongImage = path.join(directory, 'wrong-image.bin');
    fs.writeFileSync(wrongImage, Buffer.alloc(256));
    const wrong = decode(replay, { runtimeImagePath: wrongImage });
    assert.equal(wrong.status, 'DECODE_FAILED');
    assert.equal(wrong.runtime_image_status, 'HASH_MISMATCH');
    assert.equal(wrong.events, null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('821 FaceDirection accepts observed game/13 marker 0x83',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const replay = fixture({ gamePackets: [
      [0x400000b8, '83230dd6f1f241e5e7dfdb8785'],
    ] });
    const result = decode(replay, { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'CANDIDATE');
    assert.deepEqual(result.observed_shape_counts,
      { keyframe13: 1, game13: 1, game17: 0 });
    assert.equal(result.events[1].raw_selector_byte, 0x83);
    assert.equal(result.events[1].optional_scalar_f32_candidate, null);
  });

test('821 FaceDirection rejects a same-size image with the wrong hash',
  { skip: !HAS_IMAGE && 'exact mapped 821 runtime image is unavailable' }, () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'face-direction-821-hash-'));
    try {
      const wrongImage = path.join(directory, 'wrong-image.bin');
      fs.copyFileSync(IMAGE_PATH, wrongImage);
      const file = fs.openSync(wrongImage, 'r+');
      try {
        fs.writeSync(file, Buffer.from([0]), 0, 1, 0);
      } finally {
        fs.closeSync(file);
      }
      const result = decode(fixture(), { runtimeImagePath: wrongImage });
      assert.equal(result.status, 'DECODE_FAILED');
      assert.equal(result.runtime_image_status, 'HASH_MISMATCH');
      assert.equal(result.runtime_image_used, false);
      assert.equal(result.events, null);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });

test('821 FaceDirection rejects a different build and mutated source bytes', () => {
  const oldBuild = decode(fixture({ version: '16.19.820.7343' }),
    { runtimeImagePath: IMAGE_PATH });
  assert.equal(oldBuild.status, 'UNSUPPORTED');
  const replay = fixture();
  replay.buffer[replay.buffer.length - 1] ^= 1;
  const tampered = decode(replay, { runtimeImagePath: IMAGE_PATH });
  assert.equal(tampered.status, 'DECODE_FAILED');
  assert.match(tampered.error, /source integrity/i);
});

test('821 FaceDirection rejects unobserved stream, length and marker before image use', () => {
  const invalidCases = [
    fixture({ keyframeHex: '93d3bb1ff2f37338a1033a9c0b' }),
    fixture({ gamePackets: [[0x400000b9, '87fffa100ef3c590d4dfdbf8167bbdbd']] }),
    fixture({ gamePackets: [[0x400000b6, '9dd3bb1ff2f37338a1033a9c0b']] }),
  ];
  for (const replay of invalidCases) {
    const result = decode(replay, { runtimeImagePath: IMAGE_PATH });
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.runtime_image_status, 'NOT_CHECKED');
    assert.equal(result.events, null);
    assert.equal(result.first_failed_packet_ref.packet_id, 0x038e);
  }
});

test('821 FaceDirection absent route remains explicit', () => {
  const replay = replayFromChunks([{ stream: 1, body: Buffer.alloc(0) }], BUILD);
  const result = decode(replay, { runtimeImagePath: IMAGE_PATH });
  assert.equal(result.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.observed_raw_route_count, 0);
  assert.equal(result.events, null);
});

test('821 FaceDirection keeps valid uint32 raw parameters without a corpus-only bound', () => {
  const replay = fixture({ gamePackets: [
    [0, '93d3bb1ff2f37338a1033a9c0b'],
    [0xffffffff, '9bf352db11e7e7e7e7dfdb3876'],
  ] });
  const result = decode(replay);
  assert.equal(result.status, 'MISSING_INPUT');
  assert.equal(result.input_count, 3);
  assert.equal(result.first_failed_packet_ref, undefined);
});
