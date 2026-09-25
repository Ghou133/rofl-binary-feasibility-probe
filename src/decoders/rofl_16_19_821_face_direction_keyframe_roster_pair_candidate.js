'use strict';

// Co-key pairing within a sampled keyframe. The 0x0089 participant candidate
// belongs to the HeroStats roster; it does not identify a FaceDirection actor.
const crypto = require('node:crypto');
const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { PROFILES } = require('./rofl_16_19_821_float_stats_candidate');
const {
  FACE_DIRECTION_PACKET_CANDIDATE_PROFILE_821: FACE_PROFILE,
  transformFaceDirectionVectorBytes821,
} = require('./rofl_16_19_821_face_direction_packet_candidate');
const {
  RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256,
} = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const SNAPSHOT_PROFILE = PROFILES.hero_minions_killed_snapshot;
const FIRST_PARAM = 0x400000ae;
const LAST_PARAM = 0x400000b7;
const MAX_FACE_ROWS = 32_768;
const MAX_SNAPSHOT_ROWS = 10_000;
const EVIDENCE_STATUS = 'CANDIDATE_821_FACE_DIRECTION_KEYFRAME_ROSTER_CO_KEY';

const FACE_DIRECTION_KEYFRAME_ROSTER_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-face-direction-keyframe-roster-pair-candidate-v1',
  replay_version: BUILD,
  capability: 'face_direction_keyframe_roster_pair',
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  depends_on: Object.freeze(['face_direction_packet', 'hero_minions_killed_snapshot']),
  packet_ids: Object.freeze([0x038e, 0x0089]),
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays: 327 keyframes each have ten 0x0089 HeroStats and ten later same-key 0x038e FaceDirection rows; 3270/3270 full-key pairs, with 64729 noncanonical Face keyframe rows excluded',
  known_limits: Object.freeze([
    'The participant candidate comes only from the canonical 0x0089 HeroStats raw-parameter roster.',
    'The association proves a matching full raw parameter, keyframe chunk, timestamp, and packet order; it does not prove that the FaceDirection packet actor is that participant.',
    'Noncanonical FaceDirection keyframe packets and all game-stream packets are excluded, with counts and first source references retained.',
    'No world position, path, live receiver, or direction effect is inferred.',
    'Both source outcomes and their Replay packet references must be complete and physically verifiable.',
  ]),
});

function hash(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function count(value, maximum) {
  return Number.isSafeInteger(value) && value >= 0 && value <= maximum;
}

function nonnegative(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function u32(value) {
  return nonnegative(value) && value <= 0xffffffff;
}

function participantFor(rawParam) {
  return u32(rawParam) && rawParam >= FIRST_PARAM && rawParam <= LAST_PARAM
    ? rawParam - FIRST_PARAM + 1 : null;
}

function position(ref) {
  return `${ref.chunk_index}/${ref.decompressed_block_offset}`;
}

function validRef(replay, ref, packetId, stream, length) {
  const chunk = replay.chunks?.[ref?.chunk_index];
  return ref?.source_path === (replay.source_path ?? null)
    && ref.replay_sha256 === replay.source_sha256
    && nonnegative(ref.chunk_index) && nonnegative(ref.chunk_id)
    && ref.chunk_stream === stream && nonnegative(ref.chunk_file_offset)
    && nonnegative(ref.decompressed_block_offset)
    && nonnegative(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === packetId && nonnegative(ref.replay_time_ms)
    && ref.payload_length === length && u32(ref.raw_param)
    && sha(ref.raw_payload_sha256)
    && !!chunk && chunk.index === ref.chunk_index && chunk.chunk_id === ref.chunk_id
    && chunk.stream === stream && chunk.stream_tag === (stream === 'keyframe' ? 2 : 1)
    && chunk.offset === ref.chunk_file_offset
    && nonnegative(chunk.uncompressed_length)
    && ref.decompressed_payload_offset + length <= chunk.uncompressed_length;
}

function validFaceRow(replay, row) {
  const ref = row?.raw_packet_ref;
  const stream = ref?.chunk_stream;
  const length = ref?.payload_length;
  if (stream !== 'keyframe' && stream !== 'game_chunk') return false;
  if (!validRef(replay, ref, 0x038e, stream, length)
      || (length !== 13 && length !== 17)
      || row.event_type !== 'FACE_DIRECTION_PACKET_CANDIDATE'
      || row.game_version !== BUILD || row.patch !== '16.19'
      || row.build_profile !== FACE_PROFILE.id
      || row.replay_sha256 !== replay.source_sha256
      || row.replay_time_ms !== ref.replay_time_ms
      || row.raw_param !== ref.raw_param
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== FACE_PROFILE.evidence_status
      || row.semantic_direction_effect_status !== 'UNKNOWN'
      || typeof row.raw_payload_hex !== 'string'
      || !/^[0-9a-f]+$/.test(row.raw_payload_hex)
      || row.raw_payload_hex.length !== length * 2) return false;
  const payload = Buffer.from(row.raw_payload_hex, 'hex');
  if (row.raw_selector_byte !== payload[0]
      || hash(payload) !== ref.raw_payload_sha256) return false;
  const shape = stream === 'keyframe' && length === 13 && payload[0] === 0x83
    ? 'keyframe13' : stream === 'game_chunk' && length === 13
      && [0x93, 0x83, 0x9b].includes(payload[0]) ? 'game13'
        : stream === 'game_chunk' && length === 17
          && [0x87, 0x81, 0x85, 0x89, 0x95, 0x97, 0x99, 0x91].includes(payload[0])
          ? 'game17' : null;
  if (row.packet_shape_candidate !== shape || !shape) return false;
  if (shape === 'game17') {
    if (row.raw_optional_scalar_bytes_hex !== payload.subarray(13).toString('hex')
        || !Number.isFinite(row.optional_scalar_f32_candidate)
        || row.optional_scalar_f32_candidate < 0) return false;
  } else if (row.raw_optional_scalar_bytes_hex !== null
      || row.optional_scalar_f32_candidate !== null) return false;
  const bytes = transformFaceDirectionVectorBytes821(payload);
  const vector = row.packet_vector_xyz_f32_candidate;
  return vector?.x === bytes.readFloatLE(0)
    && vector.y === bytes.readFloatLE(4)
    && vector.z === bytes.readFloatLE(8);
}

function validSnapshotRow(replay, row) {
  const ref = row?.raw_packet_ref;
  const participant = participantFor(row?.hero_raw_param);
  return row?.event_type === 'HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE'
    && row.game_version === BUILD && row.patch === '16.19'
    && row.build_profile === SNAPSHOT_PROFILE.id
    && row.replay_sha256 === replay.source_sha256
    && row.replay_time_ms === ref?.replay_time_ms
    && row.hero_raw_param === ref?.raw_param
    && row.participant_id_candidate === participant && participant !== null
    && row.observation_kind === 'KEYFRAME_SNAPSHOT'
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL'
    && /^[0-9a-f]{8}$/.test(row.raw_payload_field_bytes_hex)
    && Number.isSafeInteger(row.minions_killed_raw_f32_candidate)
    && row.minions_killed_raw_f32_candidate >= 0
    && row.minions_killed_floor_candidate === row.minions_killed_raw_f32_candidate
    && validRef(replay, ref, 0x0089, 'keyframe', 1263);
}

class SourceMismatch extends Error {}

function verifyPhysicalRefs(replay, faceRows, snapshotRows) {
  const expected = new Map();
  for (const [route, rows] of [['face', faceRows], ['snapshot', snapshotRows]]) {
    for (const row of rows) {
      const ref = row.raw_packet_ref;
      const at = position(ref);
      if (expected.has(at)) return { error: `duplicate source packet reference at ${at}` };
      expected.set(at, { route, row, ref });
    }
  }
  try {
    const walked = walkBlocks(replay, (block, chunk) => {
      const required = block.packet_id === 0x038e
        || (chunk.stream === 'keyframe' && block.packet_id === 0x0089);
      if (!required) return;
      const at = `${chunk.index}/${block.offset}`;
      const selected = expected.get(at);
      if (!selected) throw new SourceMismatch(`source outcome omits route packet at ${at}`);
      const { route, row, ref } = selected;
      if (block.packet_id !== ref.packet_id
          || block.timestamp_ms !== ref.replay_time_ms
          || (block.param >>> 0) !== ref.raw_param
          || block.payload_offset !== ref.decompressed_payload_offset
          || block.payload_length !== ref.payload_length
          || hash(block.payload) !== ref.raw_payload_sha256
          || (route === 'face' && block.payload.toString('hex') !== row.raw_payload_hex)
          || (route === 'snapshot' && (
            block.payload.subarray(0, 3).toString('hex')
              !== SNAPSHOT_PROFILE.payload_prefix_hex
            || Buffer.from(SNAPSHOT_PROFILE.raw_payload_byte_offsets.map((offset) =>
              block.payload[offset])).toString('hex') !== row.raw_payload_field_bytes_hex))) {
        throw new SourceMismatch(`source packet reference or raw field differs at ${at}`);
      }
      expected.delete(at);
    }, { strict: true });
    if (walked.errors.length) return { error: 'Replay framing errors', scan_error: true };
  } catch (error) {
    return { error: error.message,
      scan_error: !(error instanceof SourceMismatch) };
  }
  if (expected.size) {
    return { error: `source packet reference absent at ${expected.keys().next().value}` };
  }
  return { verified_count: faceRows.length + snapshotRows.length };
}

function associateFaceDirectionKeyframeRosterPairs821(replay, {
  faceDirectionPacketOutcome, minionsKilledSnapshotOutcome,
} = {}) {
  const profile = FACE_DIRECTION_KEYFRAME_ROSTER_PAIR_821_PROFILE;
  const base = {
    profile_id: profile.id,
    depends_on: [...profile.depends_on],
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: null,
    replay_sha256: replay?.source_sha256 ?? null,
    runtime_image_status: faceDirectionPacketOutcome?.runtime_image_status ?? 'NOT_CHECKED',
    runtime_image_used: faceDirectionPacketOutcome?.runtime_image_used ?? false,
    runtime_image_sha256: faceDirectionPacketOutcome?.runtime_image_sha256 ?? null,
    face_packet_count: null, snapshot_count: null, keyframe_count: null,
    paired_packet_count: null, excluded_game_packet_count: null,
    excluded_noncanonical_keyframe_packet_count: null,
    first_excluded_face_packet_refs: null,
    verified_raw_packet_count: null,
    input_count: null, event_count: null, events: null, error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `FaceDirection keyframe roster pair supports only ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  if (!sha(replay.source_sha256)) {
    return fail('INCONSISTENT', 'Replay SHA-256 is missing or malformed');
  }
  if (!faceDirectionPacketOutcome || !minionsKilledSnapshotOutcome) {
    return fail('MISSING_INPUT', 'both exact-build source outcomes are required', {
      missing_inputs: [
        ...(!faceDirectionPacketOutcome ? ['face_direction_packet'] : []),
        ...(!minionsKilledSnapshotOutcome ? ['hero_minions_killed_snapshot'] : []),
      ],
    });
  }
  const face = faceDirectionPacketOutcome;
  const snapshot = minionsKilledSnapshotOutcome;
  if (face.status !== 'CANDIDATE' || snapshot.status !== 'CANDIDATE') {
    const priority = ['DECODE_FAILED', 'INCONSISTENT', 'UNSUPPORTED',
      'MISSING_INPUT', 'PROFILE_UNAVAILABLE'];
    const decisive = priority.find((status) =>
      face.status === status || snapshot.status === status) ?? 'INCONSISTENT';
    return fail(decisive, 'one or both exact-build source outcomes are unavailable', {
      dependency_statuses: {
        face_direction_packet: face.status ?? null,
        hero_minions_killed_snapshot: snapshot.status ?? null,
      },
    });
  }
  if (face.profile_id !== FACE_PROFILE.id
      || face.evidence_status !== FACE_PROFILE.evidence_status
      || face.evidence_runtime_image_sha256 !== RUNTIME_IMAGE_SHA256
      || face.evidence_vector_transform_sha256
        !== FACE_PROFILE.evidence_vector_transform_sha256
      || face.evidence_scalar_table_sha256
        !== FACE_PROFILE.evidence_scalar_table_sha256
      || face.runtime_image_sha256 !== RUNTIME_IMAGE_SHA256
      || face.runtime_image_status !== 'MATCHED_USED'
      || face.runtime_image_used !== true
      || face.input_packet_id !== 0x038e
      || !count(face.input_count, MAX_FACE_ROWS)
      || face.input_count === 0 || face.event_count !== face.input_count
      || !Array.isArray(face.events) || face.events.length !== face.event_count
      || !face.observed_shape_counts
      || Object.keys(face.observed_shape_counts).sort().join(',')
        !== 'game13,game17,keyframe13'
      || !Object.values(face.observed_shape_counts).every((value) =>
        count(value, MAX_FACE_ROWS))
      || Object.values(face.observed_shape_counts).reduce((a, b) => a + b, 0)
        !== face.event_count
      || snapshot.profile_id !== SNAPSHOT_PROFILE.id
      || snapshot.evidence_runtime_image_sha256 !== RUNTIME_IMAGE_SHA256
      || snapshot.lookup_table_sha256 !== LOOKUP_TABLE_SHA256
      || snapshot.runtime_image_status !== 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED'
      || snapshot.runtime_image_used !== false
      || snapshot.input_packet_id !== 0x0089
      || !count(snapshot.input_count, MAX_SNAPSHOT_ROWS)
      || !count(snapshot.event_count, MAX_SNAPSHOT_ROWS)
      || !count(snapshot.keyframe_count, MAX_SNAPSHOT_ROWS)
      || snapshot.keyframe_count === 0
      || snapshot.input_count !== snapshot.event_count
      || snapshot.event_count !== snapshot.keyframe_count * 10
      || snapshot.observed_participant_count !== 10
      || !Array.isArray(snapshot.events)
      || snapshot.events.length !== snapshot.event_count) {
    return fail('INCONSISTENT', 'exact-build source outcome profile, image, or counts differ');
  }
  const frames = new Map();
  for (const [index, row] of snapshot.events.entries()) {
    if (!validSnapshotRow(replay, row)) {
      return fail('INCONSISTENT', 'HeroStats roster row identity or source reference differs', {
        source: 'hero_minions_killed_snapshot', event_index: index,
      });
    }
    const ref = row.raw_packet_ref;
    const frame = frames.get(ref.chunk_index) ?? {
      time_ms: ref.replay_time_ms, participants: new Map(),
    };
    if (frame.time_ms !== ref.replay_time_ms
        || frame.participants.has(row.hero_raw_param)) {
      return fail('INCONSISTENT', 'HeroStats keyframe roster time or full key is ambiguous', {
        event_index: index, chunk_index: ref.chunk_index,
      });
    }
    frame.participants.set(row.hero_raw_param, row);
    frames.set(ref.chunk_index, frame);
  }
  const replayKeyframes = replay.chunks.filter((chunk) => chunk.stream === 'keyframe');
  if (replayKeyframes.length !== snapshot.keyframe_count
      || frames.size !== snapshot.keyframe_count
      || replayKeyframes.some((chunk) => !frames.has(chunk.index))
      || [...frames.values()].some((frame) => frame.participants.size !== 10)) {
    return fail('INCONSISTENT', 'Replay keyframe does not have a complete ten-key HeroStats roster');
  }
  const canonicalFace = new Map();
  const exclusions = { game: 0, noncanonical_keyframe: 0 };
  const firstExcluded = { game: null, noncanonical_keyframe: null };
  const shapeCounts = { keyframe13: 0, game13: 0, game17: 0 };
  for (const [index, row] of face.events.entries()) {
    if (!validFaceRow(replay, row)) {
      return fail('INCONSISTENT', 'FaceDirection row identity, vector, or source reference differs', {
        source: 'face_direction_packet', event_index: index,
      });
    }
    shapeCounts[row.packet_shape_candidate] += 1;
    const ref = row.raw_packet_ref;
    if (ref.chunk_stream === 'game_chunk') {
      exclusions.game += 1;
      firstExcluded.game ??= structuredClone(ref);
      continue;
    }
    if (participantFor(row.raw_param) === null) {
      exclusions.noncanonical_keyframe += 1;
      firstExcluded.noncanonical_keyframe ??= structuredClone(ref);
      continue;
    }
    const at = `${ref.chunk_index}/${row.raw_param}`;
    if (canonicalFace.has(at)) {
      return fail('INCONSISTENT', 'duplicate canonical FaceDirection full key within keyframe', {
        event_index: index, first_packet_ref: canonicalFace.get(at).raw_packet_ref,
        duplicate_packet_ref: ref,
      });
    }
    canonicalFace.set(at, row);
  }
  if (Object.keys(shapeCounts).some((shape) =>
    shapeCounts[shape] !== face.observed_shape_counts[shape])) {
    return fail('INCONSISTENT', 'FaceDirection shape counts differ from source outcome');
  }
  const physical = verifyPhysicalRefs(replay, face.events, snapshot.events);
  if (physical.error) {
    return fail(physical.scan_error ? 'DECODE_FAILED' : 'INCONSISTENT', physical.error);
  }
  const events = [];
  for (const keyframe of replayKeyframes) {
    const frame = frames.get(keyframe.index);
    for (let rawParam = FIRST_PARAM; rawParam <= LAST_PARAM; rawParam += 1) {
      const snapshotRow = frame.participants.get(rawParam);
      const faceRow = canonicalFace.get(`${keyframe.index}/${rawParam}`);
      if (!snapshotRow || !faceRow) {
        return fail('INCONSISTENT', 'canonical FaceDirection/HeroStats keyframe pair is missing', {
          chunk_index: keyframe.index, raw_param: rawParam,
          face_packet_ref: faceRow?.raw_packet_ref ?? null,
          hero_stats_packet_ref: snapshotRow?.raw_packet_ref ?? null,
        });
      }
      const faceRef = faceRow.raw_packet_ref;
      const statsRef = snapshotRow.raw_packet_ref;
      if (faceRef.replay_time_ms !== frame.time_ms
          || statsRef.replay_time_ms !== frame.time_ms
          || statsRef.decompressed_block_offset >= faceRef.decompressed_block_offset) {
        return fail('INCONSISTENT', 'paired keyframe time or Stats-before-Face order differs', {
          chunk_index: keyframe.index, raw_param: rawParam,
          face_packet_ref: faceRef, hero_stats_packet_ref: statsRef,
        });
      }
      events.push({
        event_type: 'FACE_DIRECTION_KEYFRAME_ROSTER_PAIR_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: profile.id,
        replay_sha256: replay.source_sha256,
        replay_time_ms: frame.time_ms,
        keyframe_chunk_index: keyframe.index,
        hero_raw_param: rawParam,
        hero_stats_participant_id_candidate: snapshotRow.participant_id_candidate,
        face_raw_payload_hex: faceRow.raw_payload_hex,
        face_raw_selector_byte: faceRow.raw_selector_byte,
        packet_vector_xyz_f32_candidate:
          structuredClone(faceRow.packet_vector_xyz_f32_candidate),
        pair_basis: 'SAME_KEYFRAME_CHUNK_TIME_FULL_RAW_PARAM_STATS_BEFORE_FACE',
        actor_assignment_status: 'UNKNOWN',
        semantic_direction_effect_status: 'UNKNOWN',
        confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
        hero_stats_raw_packet_ref: structuredClone(statsRef),
        face_direction_raw_packet_ref: structuredClone(faceRef),
        raw_packet_refs: [structuredClone(statsRef), structuredClone(faceRef)],
      });
    }
  }
  if (canonicalFace.size !== events.length) {
    return fail('INCONSISTENT', 'canonical FaceDirection keyframe roster has unpaired rows');
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    replay_sha256: replay.source_sha256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    dependency_statuses: {
      face_direction_packet: face.status,
      hero_minions_killed_snapshot: snapshot.status,
    },
    face_packet_count: face.event_count,
    snapshot_count: snapshot.event_count,
    keyframe_count: snapshot.keyframe_count,
    paired_packet_count: events.length,
    excluded_game_packet_count: exclusions.game,
    excluded_noncanonical_keyframe_packet_count: exclusions.noncanonical_keyframe,
    first_excluded_face_packet_refs: firstExcluded,
    verified_raw_packet_count: physical.verified_count,
    input_count: physical.verified_count,
    event_count: events.length, events,
  };
}

module.exports = {
  FACE_DIRECTION_KEYFRAME_ROSTER_PAIR_821_PROFILE,
  associateFaceDirectionKeyframeRosterPairs821,
};
