'use strict';

// Differences between sampled cumulative EXP candidate endpoints. The packet
// stream does not locate an intervening gain or identify its source.
const crypto = require('node:crypto');
const { decompressChunk, parseBlockAt } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { PROFILES, assessHeroFloatSnapshotTail821 } =
  require('./rofl_16_19_821_float_stats_candidate');
const { decodeRuntimeCountByte } = require('./rofl_16_19_821_runtime_bytes');

const SOURCE_PROFILE = PROFILES.hero_experience_snapshot;
const BUILD = '16.19.821.7343';
const FIRST_PARAM = 0x400000ae;
const LAST_PARAM = 0x400000b7;
const MAX_ROWS = 100_000;
const EVIDENCE_STATUS = 'CANDIDATE_821_ADJACENT_KEYFRAME_EXPERIENCE_ENDPOINT_DIFFERENCE';

const EXPERIENCE_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-experience-keyframe-interval-difference-candidate-v1',
  replay_version: BUILD,
  capability: 'experience_keyframe_interval_difference',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze(['hero_experience_snapshot']),
  packet_id: 0x0089,
  evidence_runtime_image_sha256: SOURCE_PROFILE.evidence_runtime_image_sha256,
  lookup_table_sha256: SOURCE_PROFILE.lookup_table_sha256,
  evidence_scope: 'exact 16.19.821.7343 EXP candidate packets with complete canonical ten-participant keyframes',
  known_limits: Object.freeze([
    'Each row subtracts two adjacent sampled cumulative EXP candidate endpoints for one candidate participant.',
    'The EXP label remains a Replay-tail-correlated candidate; the exact 821 runtime byte transform does not prove the field label.',
    'The time, number, and source of intervening gains are unresolved; this is not an experience gain event or level threshold.',
    'An unchanged pair of endpoints does not rule out intermediate activity; it is counted without an event row.',
    'No value is interpolated between keyframes or from the last keyframe to the Replay tail.',
    'Participant identity remains candidate-only from the canonical KR 821 raw-param family.',
    'Every Replay keyframe chunk must have one complete ten-participant source roster and strictly increasing keyframe times.',
  ]),
});

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_ROWS;
}

function nonnegative(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function participantFor(rawParam) {
  return nonnegative(rawParam) && rawParam >= FIRST_PARAM && rawParam <= LAST_PARAM
    ? rawParam - FIRST_PARAM + 1 : null;
}

function refPosition(ref) {
  return `${ref.chunk_index}/${ref.decompressed_block_offset}`;
}

function validRef(replay, ref) {
  const chunk = replay.chunks?.[ref?.chunk_index];
  return ref?.source_path === (replay.source_path ?? null)
    && ref.replay_sha256 === replay.source_sha256
    && nonnegative(ref.chunk_index) && nonnegative(ref.chunk_id)
    && ref.chunk_stream === 'keyframe' && nonnegative(ref.chunk_file_offset)
    && nonnegative(ref.decompressed_block_offset)
    && nonnegative(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === 0x0089 && nonnegative(ref.replay_time_ms)
    && ref.payload_length === 1263 && nonnegative(ref.raw_param)
    && sha(ref.raw_payload_sha256)
    && !!chunk && chunk.index === ref.chunk_index && chunk.chunk_id === ref.chunk_id
    && chunk.stream === 'keyframe' && chunk.stream_tag === 2
    && chunk.offset === ref.chunk_file_offset
    && nonnegative(chunk.uncompressed_length)
    && ref.decompressed_payload_offset + ref.payload_length <= chunk.uncompressed_length;
}

function decodeField(payload) {
  const offsets = Array.from({ length: 4 }, (_, i) =>
    1262 - SOURCE_PROFILE.blob_f32le_offset_candidate - i);
  const decoded = Buffer.from(offsets.map((offset) =>
    decodeRuntimeCountByte(payload[offset])));
  return {
    value: decoded.readFloatLE(0),
    rawHex: Buffer.from(offsets.slice().reverse().map((offset) =>
      payload[offset])).toString('hex'),
  };
}

function verifyRawPackets(replay, refs) {
  const expected = new Map();
  for (const ref of refs) {
    const at = refPosition(ref);
    if (expected.has(at)) return { error: `duplicate physical EXP packet reference at ${at}` };
    expected.set(at, ref);
  }
  try {
    for (const chunk of replay.chunks) {
      if (chunk.stream !== 'keyframe') continue;
      const body = decompressChunk(replay.buffer, chunk);
      const state = { timestamp: 0, packet_id: 0, param: 0 };
      let cursor = 0;
      while (cursor < body.length) {
        const block = parseBlockAt(body, cursor, state);
        const at = `${chunk.index}/${block.offset}`;
        const source = expected.get(at);
        if (block.packet_id === 0x0089 && !source) {
          return { error: `keyframe EXP carrier is missing from source outcome at ${at}` };
        }
        if (source) {
          const payloadSha = crypto.createHash('sha256').update(block.payload).digest('hex');
          if (block.packet_id !== source.packet_id
              || block.timestamp_ms !== source.replay_time_ms
              || (block.param >>> 0) !== source.raw_param
              || block.payload_offset !== source.decompressed_payload_offset
              || block.payload_length !== source.payload_length
              || payloadSha !== source.raw_payload_sha256
              || block.payload.subarray(0, 3).toString('hex') !== '6700de') {
            return { error: `EXP packet reference differs from Replay block at ${at}` };
          }
          const field = decodeField(block.payload);
          expected.delete(at);
          source.verifiedField = field;
        }
        cursor = block.next_offset;
      }
    }
  } catch (error) {
    return { error: `Replay packet verification failed: ${error.message}`, scan_error: true };
  }
  if (expected.size) {
    return { error: `EXP packet reference absent at ${expected.keys().next().value}` };
  }
  return { verified_count: refs.length };
}

function deriveExperienceKeyframeIntervalDifferenceCandidates821(replay, {
  experienceSnapshotOutcome,
} = {}) {
  const profile = EXPERIENCE_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE;
  const base = {
    profile_id: profile.id,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    lookup_table_sha256: profile.lookup_table_sha256,
    depends_on: [...profile.depends_on],
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: null,
    replay_sha256: replay?.source_sha256 ?? null,
    input_count: null, keyframe_count: null,
    observed_interval_count: null, changed_interval_count: null,
    unchanged_interval_count: null, verified_raw_packet_count: null,
    event_count: null, events: null, error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `experience keyframe interval difference supports only ${BUILD}`);
  }
  let sourceError;
  try {
    sourceError = replaySourceError(replay);
  } catch (error) {
    sourceError = error.message;
  }
  if (sourceError) return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  if (!sha(replay.source_sha256)) {
    return fail('INCONSISTENT', 'Replay SHA-256 is missing or malformed');
  }
  if (!experienceSnapshotOutcome) {
    return fail('MISSING_INPUT', 'exact-build experience snapshot outcome is required', {
      missing_input: 'hero_experience_snapshot',
    });
  }
  const source = experienceSnapshotOutcome;
  if (source.profile_id !== SOURCE_PROFILE.id
      || source.evidence_runtime_image_sha256 !== profile.evidence_runtime_image_sha256
      || source.lookup_table_sha256 !== profile.lookup_table_sha256
      || source.input_packet_id !== 0x0089) {
    return fail('INCONSISTENT', 'experience snapshot dependency identity differs', {
      dependency_status: source.status ?? null,
    });
  }
  if (source.status !== 'CANDIDATE') {
    const propagated = ['MISSING_INPUT', 'PROFILE_UNAVAILABLE', 'UNSUPPORTED',
      'DECODE_FAILED', 'INCONSISTENT'].includes(source.status)
      ? source.status : 'INCONSISTENT';
    return fail(propagated, 'experience snapshot candidate decoder is unavailable', {
      dependency_status: source.status ?? null,
    });
  }
  if (source.evidence_status !== 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL'
      || source.runtime_image_used !== false
      || source.runtime_image_status !== 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED'
      || !count(source.input_count) || !count(source.event_count)
      || !count(source.keyframe_count) || source.event_count === 0
      || source.input_count !== source.event_count
      || source.event_count !== source.keyframe_count * 10
      || source.observed_participant_count !== 10
      || source.descent_count !== 0
      || !Array.isArray(source.events) || source.events.length !== source.event_count) {
    return fail('INCONSISTENT', 'experience snapshot outcome identity or counts differ');
  }
  const assessed = assessHeroFloatSnapshotTail821(replay, 'hero_experience_snapshot');
  if (assessed.status !== 'PASS') {
    return fail('INCONSISTENT', `Replay EXP tail differs from source scope: ${assessed.error}`);
  }
  const tailValues = assessed.values;
  if (!Array.isArray(source.final_replay_tails)
      || source.final_replay_tails.length !== 10
      || source.final_replay_tails.some((value, index) => value !== tailValues[index])) {
    return fail('INCONSISTENT', 'Replay EXP tail or source final tails differ');
  }
  const keyframeChunks = replay.chunks.filter((chunk) => chunk.stream === 'keyframe');
  if (keyframeChunks.length !== source.keyframe_count) {
    return fail('INCONSISTENT', 'source keyframe count differs from Replay');
  }
  const frames = new Map();
  const refs = [];
  for (const [eventIndex, row] of source.events.entries()) {
    const ref = row?.raw_packet_ref;
    const participant = participantFor(row?.hero_raw_param);
    const value = row?.experience_raw_f32_candidate;
    if (row?.event_type !== 'HERO_EXPERIENCE_SNAPSHOT_CANDIDATE'
        || row.game_version !== BUILD || row.patch !== '16.19'
        || row.build_profile !== SOURCE_PROFILE.id
        || row.replay_sha256 !== replay.source_sha256
        || row.confidence !== 'CANDIDATE'
        || row.semantic_status !== source.evidence_status
        || row.observation_kind !== 'KEYFRAME_SNAPSHOT'
        || !validRef(replay, ref)
        || row.replay_time_ms !== ref.replay_time_ms
        || row.hero_raw_param !== ref.raw_param
        || participant === null || row.participant_id_candidate !== participant
        || !Number.isFinite(value) || value < 0
        || !Number.isSafeInteger(Math.floor(value))
        || Math.floor(value) !== row.experience_floor_candidate
        || row.experience_floor_candidate > tailValues[participant - 1]
        || typeof row.raw_payload_field_bytes_hex !== 'string'
        || !/^[0-9a-f]{8}$/.test(row.raw_payload_field_bytes_hex)) {
      return fail('INCONSISTENT', 'experience snapshot source row identity or value differs', {
        event_index: eventIndex,
      });
    }
    const frame = frames.get(ref.chunk_index) ?? {
      chunk_index: ref.chunk_index, replay_time_ms: row.replay_time_ms,
      participants: new Map(),
    };
    if (frame.replay_time_ms !== row.replay_time_ms
        || frame.participants.has(participant)) {
      return fail('INCONSISTENT', 'experience keyframe has multiple times or duplicate participant', {
        event_index: eventIndex, chunk_index: ref.chunk_index,
      });
    }
    frame.participants.set(participant, row);
    frames.set(ref.chunk_index, frame);
    refs.push({ ...ref, verifiedField: null });
  }
  if (frames.size !== keyframeChunks.length
      || keyframeChunks.some((chunk) => !frames.has(chunk.index))
      || [...frames.values()].some((frame) => frame.participants.size !== 10)) {
    return fail('INCONSISTENT', 'experience source lacks a complete Replay keyframe roster');
  }
  const orderedFrames = keyframeChunks.map((chunk) => frames.get(chunk.index));
  for (let index = 1; index < orderedFrames.length; index += 1) {
    if (orderedFrames[index].replay_time_ms <= orderedFrames[index - 1].replay_time_ms) {
      return fail('INCONSISTENT', 'experience keyframe times are not strictly increasing', {
        previous_chunk_index: orderedFrames[index - 1].chunk_index,
        current_chunk_index: orderedFrames[index].chunk_index,
      });
    }
  }
  const physical = verifyRawPackets(replay, refs);
  if (physical.error) {
    return fail(physical.scan_error ? 'DECODE_FAILED' : 'INCONSISTENT', physical.error);
  }
  const verified = new Map(refs.map((ref) => [refPosition(ref), ref.verifiedField]));
  const events = [];
  let unchangedIntervals = 0;
  for (let index = 0; index < orderedFrames.length; index += 1) {
    const frame = orderedFrames[index];
    const previous = index > 0 ? orderedFrames[index - 1] : null;
    for (let participant = 1; participant <= 10; participant += 1) {
      const row = frame.participants.get(participant);
      const field = verified.get(refPosition(row.raw_packet_ref));
      if (!field || field.value !== row.experience_raw_f32_candidate
          || field.rawHex !== row.raw_payload_field_bytes_hex) {
        return fail('INCONSISTENT', 'experience source field differs from physical Replay bytes', {
          chunk_index: frame.chunk_index, participant_id_candidate: participant,
        });
      }
      if (!previous) {
        if (field.value !== 0) {
          return fail('INCONSISTENT', 'first experience keyframe value differs from zero');
        }
        continue;
      }
      const previousRow = previous.participants.get(participant);
      const prior = previousRow.experience_raw_f32_candidate;
      const delta = field.value - prior;
      if (delta < 0) {
        return fail('INCONSISTENT', 'experience keyframe candidate decreased', {
          chunk_index: frame.chunk_index, participant_id_candidate: participant,
        });
      }
      if (delta === 0) {
        unchangedIntervals += 1;
        continue;
      }
      const previousRef = structuredClone(previousRow.raw_packet_ref);
      const currentRef = structuredClone(row.raw_packet_ref);
      events.push({
        event_type: 'EXPERIENCE_KEYFRAME_INTERVAL_DIFFERENCE_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: profile.id,
        replay_sha256: replay.source_sha256,
        replay_time_ms: frame.replay_time_ms,
        previous_observation_time_ms: previous.replay_time_ms,
        current_observation_time_ms: frame.replay_time_ms,
        observation_interval_ms: frame.replay_time_ms - previous.replay_time_ms,
        previous_keyframe_chunk_index: previous.chunk_index,
        current_keyframe_chunk_index: frame.chunk_index,
        hero_raw_param: row.hero_raw_param,
        participant_id_candidate: participant,
        previous_experience_raw_f32_candidate: prior,
        current_experience_raw_f32_candidate: field.value,
        previous_experience_floor_candidate: previousRow.experience_floor_candidate,
        current_experience_floor_candidate: row.experience_floor_candidate,
        experience_endpoint_delta_f32_candidate: delta,
        experience_endpoint_delta_floor_candidate:
          row.experience_floor_candidate - previousRow.experience_floor_candidate,
        previous_raw_payload_field_bytes_hex: previousRow.raw_payload_field_bytes_hex,
        current_raw_payload_field_bytes_hex: row.raw_payload_field_bytes_hex,
        observation_kind: 'ADJACENT_KEYFRAME_SAMPLED_ENDPOINTS',
        observation_scope: 'KEYFRAME_ENDPOINT_DIFFERENCE_ONLY',
        change_time_status: 'UNRESOLVED_WITHIN_INTERVAL',
        confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
        field_confidence: {
          previous_observation_time_ms: 'VERIFIED_DIRECT',
          current_observation_time_ms: 'VERIFIED_DIRECT',
          participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
          previous_raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
          current_raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
          previous_experience_raw_f32_candidate: source.evidence_status,
          current_experience_raw_f32_candidate: source.evidence_status,
          experience_endpoint_delta_f32_candidate: EVIDENCE_STATUS,
          experience_endpoint_delta_floor_candidate: EVIDENCE_STATUS,
        },
        raw_packet_ref: currentRef,
        previous_raw_packet_ref: previousRef,
        current_raw_packet_ref: currentRef,
        raw_packet_refs: [previousRef, currentRef],
        known_limits: [...profile.known_limits],
      });
    }
  }
  const observedIntervals = Math.max(0, orderedFrames.length - 1) * 10;
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    replay_sha256: replay.source_sha256,
    input_count: source.event_count,
    keyframe_count: orderedFrames.length,
    observed_interval_count: observedIntervals,
    changed_interval_count: events.length,
    unchanged_interval_count: unchangedIntervals,
    verified_raw_packet_count: physical.verified_count,
    event_count: events.length, events,
  };
}

module.exports = {
  EXPERIENCE_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE,
  deriveExperienceKeyframeIntervalDifferenceCandidates821,
};
