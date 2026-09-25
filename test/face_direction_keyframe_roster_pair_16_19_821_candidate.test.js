'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { walkBlocks } = require('../src/rofl');
const { PROFILES } = require('../src/decoders/rofl_16_19_821_float_stats_candidate');
const {
  RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256, decodeRuntimeCountByte,
} = require('../src/decoders/rofl_16_19_821_runtime_bytes');
const {
  FACE_DIRECTION_PACKET_CANDIDATE_PROFILE_821: FACE_PROFILE,
  transformFaceDirectionVectorBytes821,
} = require('../src/decoders/rofl_16_19_821_face_direction_packet_candidate');
const {
  FACE_DIRECTION_KEYFRAME_ROSTER_PAIR_821_PROFILE: profile,
  associateFaceDirectionKeyframeRosterPairs821: associate,
} = require('../src/decoders/rofl_16_19_821_face_direction_keyframe_roster_pair_candidate');

const BUILD = '16.19.821.7343';
const SNAPSHOT_PROFILE = PROFILES.hero_minions_killed_snapshot;
const FIRST_PARAM = 0x400000ae;
const KEYFRAME_FACE_HEX = '83230dd6f1f241e5e7dfdb8785';
const GAME_FACE_HEX = '87fffa100ef3c590d4dfdbf8167bbdbdb1';
const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));

function packet(packetId, rawParam, payload, timeMs = 1000) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function snapshotPayload() {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  for (let index = 0; index < 4; index += 1) {
    payload[1262 - 0x3c - index] = ENCODE.get(0);
  }
  return payload;
}

function ref(replay, block, chunk) {
  return {
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256,
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id,
    replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

// Synthetic outcomes model the two existing decoders' public result schemas.
// The association itself needs no runtime image or private Replay fixture.
function fixture({ faceKeys = Array.from({ length: 10 }, (_, i) => FIRST_PARAM + i),
  beforeStats = false, faceTime = 1000, includeAlias = true,
  includeGame = true } = {}) {
  const stats = Array.from({ length: 10 }, (_, index) =>
    packet(0x0089, FIRST_PARAM + index, snapshotPayload()));
  const face = faceKeys.map((rawParam) =>
    packet(0x038e, rawParam, Buffer.from(KEYFRAME_FACE_HEX, 'hex'), faceTime));
  const keyframeBody = Buffer.concat([
    ...(beforeStats ? face.slice(0, 1) : []),
    ...stats,
    ...(beforeStats ? face.slice(1) : face),
    ...(includeAlias ? [packet(0x038e, FIRST_PARAM + 0x200,
      Buffer.from(KEYFRAME_FACE_HEX, 'hex'))] : []),
  ]);
  const chunks = [{ stream: 2, body: keyframeBody }];
  if (includeGame) chunks.push({ stream: 1,
    body: packet(0x038e, 0x400000b9, Buffer.from(GAME_FACE_HEX, 'hex'), 1500) });
  const replay = replayFromChunks(chunks, BUILD);
  const faceEvents = [];
  const snapshotEvents = [];
  const shapes = { keyframe13: 0, game13: 0, game17: 0 };
  walkBlocks(replay, (block, chunk) => {
    const sourceRef = ref(replay, block, chunk);
    if (block.packet_id === 0x0089) {
      const rawBytesHex = Buffer.from(SNAPSHOT_PROFILE.raw_payload_byte_offsets
        .map((offset) => block.payload[offset])).toString('hex');
      snapshotEvents.push({
        event_type: 'HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: SNAPSHOT_PROFILE.id,
        replay_sha256: replay.source_sha256,
        replay_time_ms: block.timestamp_ms,
        hero_raw_param: block.param >>> 0,
        participant_id_candidate: (block.param >>> 0) - FIRST_PARAM + 1,
        observation_kind: 'KEYFRAME_SNAPSHOT',
        raw_payload_field_bytes_hex: rawBytesHex,
        minions_killed_raw_f32_candidate: 0,
        minions_killed_floor_candidate: 0,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL',
        raw_packet_ref: sourceRef,
      });
      return;
    }
    const payload = block.payload;
    const shape = chunk.stream === 'keyframe' ? 'keyframe13' : 'game17';
    shapes[shape] += 1;
    const vectorBytes = transformFaceDirectionVectorBytes821(payload);
    faceEvents.push({
      event_type: 'FACE_DIRECTION_PACKET_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: FACE_PROFILE.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: block.timestamp_ms,
      raw_param: block.param >>> 0,
      raw_payload_hex: payload.toString('hex'),
      raw_selector_byte: payload[0],
      raw_optional_scalar_bytes_hex: shape === 'game17'
        ? payload.subarray(13).toString('hex') : null,
      packet_shape_candidate: shape,
      packet_vector_xyz_f32_candidate: {
        x: vectorBytes.readFloatLE(0), y: vectorBytes.readFloatLE(4),
        z: vectorBytes.readFloatLE(8),
      },
      optional_scalar_f32_candidate: shape === 'game17'
        ? 0.0833333358168602 : null,
      semantic_direction_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE',
      semantic_status: FACE_PROFILE.evidence_status,
      raw_packet_ref: sourceRef,
    });
  }, { strict: true });
  const faceDirectionPacketOutcome = {
    status: 'CANDIDATE', profile_id: FACE_PROFILE.id,
    evidence_status: FACE_PROFILE.evidence_status,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    evidence_vector_transform_sha256: FACE_PROFILE.evidence_vector_transform_sha256,
    evidence_scalar_table_sha256: FACE_PROFILE.evidence_scalar_table_sha256,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    input_packet_id: 0x038e, input_count: faceEvents.length,
    event_count: faceEvents.length, observed_shape_counts: shapes,
    events: faceEvents,
  };
  const minionsKilledSnapshotOutcome = {
    status: 'CANDIDATE', profile_id: SNAPSHOT_PROFILE.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    runtime_image_status: 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED',
    runtime_image_used: false,
    input_packet_id: 0x0089, input_count: snapshotEvents.length,
    event_count: snapshotEvents.length, keyframe_count: 1,
    observed_participant_count: 10, events: snapshotEvents,
  };
  return { replay, faceDirectionPacketOutcome, minionsKilledSnapshotOutcome };
}

test('821 FaceDirection keyframe pair uses full key, same chunk/time and Stats-before-Face', () => {
  const values = fixture();
  const result = associate(values.replay, values);
  assert.equal(profile.capability, 'face_direction_keyframe_roster_pair');
  assert.deepEqual(profile.depends_on,
    ['face_direction_packet', 'hero_minions_killed_snapshot']);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.evidence_status,
    'CANDIDATE_821_FACE_DIRECTION_KEYFRAME_ROSTER_CO_KEY');
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.runtime_image_used, true);
  assert.equal(result.face_packet_count, 12);
  assert.equal(result.snapshot_count, 10);
  assert.equal(result.paired_packet_count, 10);
  assert.equal(result.excluded_game_packet_count, 1);
  assert.equal(result.excluded_noncanonical_keyframe_packet_count, 1);
  assert.equal(result.verified_raw_packet_count, 22);
  assert.equal(result.event_count, 10);
  assert.equal(result.events[0].hero_raw_param, FIRST_PARAM);
  assert.equal(result.events[0].hero_stats_participant_id_candidate, 1);
  assert.equal(result.events[0].pair_basis,
    'SAME_KEYFRAME_CHUNK_TIME_FULL_RAW_PARAM_STATS_BEFORE_FACE');
  assert.deepEqual(result.events[0].raw_packet_refs.map((row) => row.packet_id),
    [0x0089, 0x038e]);
  assert.deepEqual(result.events[0].hero_stats_raw_packet_ref,
    result.events[0].raw_packet_refs[0]);
  assert.deepEqual(result.events[0].face_direction_raw_packet_ref,
    result.events[0].raw_packet_refs[1]);
  assert.ok(result.events[0].raw_packet_refs[0].decompressed_block_offset
    < result.events[0].raw_packet_refs[1].decompressed_block_offset);
  assert.equal(result.first_excluded_face_packet_refs.noncanonical_keyframe.raw_param,
    FIRST_PARAM + 0x200);
  for (const event of result.events) {
    assert.equal(event.actor_assignment_status, 'UNKNOWN');
    assert.equal(event.semantic_direction_effect_status, 'UNKNOWN');
    assert.equal('participant_id_candidate' in event, false);
    assert.equal('world_position' in event, false);
  }
});

test('821 FaceDirection keyframe pair rejects missing, duplicate, wrong-time and wrong-order pairs', () => {
  const variants = [
    fixture({ faceKeys: Array.from({ length: 9 }, (_, i) => FIRST_PARAM + i) }),
    fixture({ faceKeys: [...Array.from({ length: 10 }, (_, i) => FIRST_PARAM + i),
      FIRST_PARAM] }),
    fixture({ faceTime: 1100 }),
    fixture({ beforeStats: true }),
  ];
  for (const values of variants) {
    const result = associate(values.replay, values);
    assert.equal(result.status, 'INCONSISTENT');
    assert.equal(result.events, null);
  }
});

test('821 FaceDirection keyframe pair excludes aliases even when chunk/time/order match', () => {
  const values = fixture({ faceKeys: [
    ...Array.from({ length: 9 }, (_, i) => FIRST_PARAM + i),
    FIRST_PARAM + 9 + 0x200,
  ], includeAlias: false });
  // Replace the tenth full key with a +0x200 alias. The matching low byte and
  // temporal order cannot substitute for the missing full raw parameter.
  const result = associate(values.replay, values);
  assert.equal(result.status, 'INCONSISTENT');
  assert.match(result.error, /missing/i);
});

test('821 FaceDirection keyframe pair rejects mutated provenance and source profile', () => {
  const source = fixture();
  source.faceDirectionPacketOutcome.events[0].raw_packet_ref.raw_payload_sha256 = '0'.repeat(64);
  assert.equal(associate(source.replay, source).status, 'INCONSISTENT');
  const profileMismatch = fixture();
  profileMismatch.faceDirectionPacketOutcome.profile_id = 'wrong';
  assert.equal(associate(profileMismatch.replay, profileMismatch).status, 'INCONSISTENT');
  const imageMismatch = fixture();
  imageMismatch.faceDirectionPacketOutcome.runtime_image_sha256 = '0'.repeat(64);
  assert.equal(associate(imageMismatch.replay, imageMismatch).status, 'INCONSISTENT');
});

test('821 FaceDirection keyframe pair preserves decisive source failure and missing inputs', () => {
  const values = fixture();
  assert.equal(associate(values.replay, {}).status, 'MISSING_INPUT');
  values.faceDirectionPacketOutcome.status = 'DECODE_FAILED';
  const result = associate(values.replay, values);
  assert.equal(result.status, 'DECODE_FAILED');
  assert.deepEqual(result.diagnostics.dependency_statuses, {
    face_direction_packet: 'DECODE_FAILED',
    hero_minions_killed_snapshot: 'CANDIDATE',
  });
});
