'use strict';

// This links a packet-local callback key to two sampled keyframe endpoints.
// It does not show a live object lookup, a counter write, or a last hit.
const crypto = require('node:crypto');
const { decompressChunk, parseBlockAt } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { PROFILES } = require('./rofl_16_19_821_float_stats_candidate');
const {
  INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821: PACKET_PROFILE,
  isObservedIncrementMinionKillsPayloadHex,
  lookupIncrementMinionKillsKeyFromNativeBytes,
} = require('./rofl_16_19_821_increment_minion_kills_packet_candidate');
const {
  RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256, decodeRuntimeCountByte,
} = require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const SNAPSHOT_PROFILE = PROFILES.hero_minions_killed_snapshot;
const FIRST_PARAM = 0x400000ae;
const LAST_PARAM = 0x400000b7;
const MAX_ROWS = 10_000;
const EVIDENCE_STATUS =
  'CANDIDATE_821_PACKET_KEY_AND_ADJACENT_MINIONS_KEYFRAME_BRACKET';

const INCREMENT_MINION_KEYFRAME_BRACKET_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-increment-minion-keyframe-bracket-candidate-v1',
  replay_version: BUILD,
  capability: 'increment_minion_keyframe_bracket',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze([
    'increment_minion_kills_packet', 'hero_minions_killed_snapshot',
  ]),
  packet_ids: Object.freeze([0x03a7, 0x0089]),
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays: 278/279 observed 0x03a7 packets fall strictly between adjacent same-key 0x0089 snapshots, one is on a keyframe time boundary; 148 distinct sampled intervals contain strict packet brackets',
  known_limits: Object.freeze([
    'The raw-param and native callback lookup key select only a candidate participant in the same Replay; no live object identity or lookup success is observed.',
    'The two 0x0089 values are sampled cumulative endpoint candidates. Their difference does not assign any increment to a 0x03a7 packet.',
    'The callback conditional write, effective CS effect, minion identity and last hit remain UNKNOWN.',
    'Only packets strictly inside adjacent keyframe endpoints get bracket rows; packets on or outside endpoints retain explicit unbracketed source references.',
    'Every Replay keyframe must have a complete ten-participant 0x0089 roster with strictly increasing times.',
    'The association requires exact-build source outcomes and physically verified Replay packet references.',
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

function validRef(replay, ref, packetId, stream, payloadLength) {
  const chunk = replay.chunks?.[ref?.chunk_index];
  return ref?.source_path === (replay.source_path ?? null)
    && ref.replay_sha256 === replay.source_sha256
    && nonnegative(ref.chunk_index) && nonnegative(ref.chunk_id)
    && ref.chunk_stream === stream && nonnegative(ref.chunk_file_offset)
    && nonnegative(ref.decompressed_block_offset)
    && nonnegative(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === packetId && nonnegative(ref.replay_time_ms)
    && ref.payload_length === payloadLength && u32(ref.raw_param)
    && sha(ref.raw_payload_sha256)
    && !!chunk && chunk.index === ref.chunk_index && chunk.chunk_id === ref.chunk_id
    && chunk.stream === stream && chunk.stream_tag === (stream === 'keyframe' ? 2 : 1)
    && chunk.offset === ref.chunk_file_offset
    && nonnegative(chunk.uncompressed_length)
    && ref.decompressed_payload_offset + payloadLength <= chunk.uncompressed_length;
}

function verifiedSnapshotValue(row, payload) {
  if (payload.subarray(0, 3).toString('hex') !== SNAPSHOT_PROFILE.payload_prefix_hex) {
    return false;
  }
  const offsets = Array.from({ length: 4 }, (_, index) =>
    1262 - SNAPSHOT_PROFILE.blob_f32le_offset_candidate - index);
  const encodedHex = Buffer.from(offsets.slice().reverse()
    .map((offset) => payload[offset])).toString('hex');
  const decoded = Buffer.from(offsets.map((offset) =>
    decodeRuntimeCountByte(payload[offset])));
  const value = decoded.readFloatLE(0);
  return row.raw_payload_field_bytes_hex === encodedHex
    && Number.isSafeInteger(value) && value >= 0
    && row.minions_killed_raw_f32_candidate === value
    && row.minions_killed_floor_candidate === value;
}

function verifyPhysicalRefs(replay, packetRows, snapshotRows) {
  const expected = new Map();
  const chunkIndices = new Set();
  for (const [route, rows] of [
    ['packet', packetRows], ['snapshot', snapshotRows],
  ]) {
    for (const row of rows) {
      const ref = row.raw_packet_ref;
      const at = position(ref);
      if (expected.has(at)) return { error: `duplicate source packet reference at ${at}` };
      expected.set(at, { route, row, ref });
      chunkIndices.add(ref.chunk_index);
    }
  }
  for (const chunk of replay.chunks) {
    if (chunk.stream === 'keyframe') chunkIndices.add(chunk.index);
  }
  const verifiedCount = expected.size;
  try {
    for (const chunkIndex of chunkIndices) {
      const chunk = replay.chunks[chunkIndex];
      const body = decompressChunk(replay.buffer, chunk);
      const state = { timestamp: 0, packet_id: 0, param: 0 };
      let cursor = 0;
      while (cursor < body.length) {
        const block = parseBlockAt(body, cursor, state);
        const at = `${chunkIndex}/${block.offset}`;
        const selected = expected.get(at);
        if (chunk.stream === 'keyframe' && block.packet_id === 0x0089 && !selected) {
          return { error: `keyframe 0x0089 is absent from snapshot outcome at ${at}` };
        }
        if (selected) {
          const { row, ref, route } = selected;
          const payloadSha = crypto.createHash('sha256').update(block.payload).digest('hex');
          if (block.packet_id !== ref.packet_id
              || block.timestamp_ms !== ref.replay_time_ms
              || (block.param >>> 0) !== ref.raw_param
              || block.payload_offset !== ref.decompressed_payload_offset
              || block.payload_length !== ref.payload_length
              || payloadSha !== ref.raw_payload_sha256
              || (route === 'snapshot' && !verifiedSnapshotValue(row, block.payload))
              || (route === 'packet'
                && block.payload.toString('hex') !== row.raw_payload_hex)) {
            return { error: `source packet reference or candidate bytes differ at ${at}` };
          }
          expected.delete(at);
        }
        cursor = block.next_offset;
      }
    }
  } catch (error) {
    return { error: `Replay packet scan failed: ${error.message}`, scan_error: true };
  }
  if (expected.size) {
    return { error: `source packet reference absent at ${expected.keys().next().value}` };
  }
  return { verified_count: verifiedCount };
}

function associateIncrementMinionKeyframeBracketCandidates821(replay, {
  incrementMinionKillsPacketOutcome, minionsKilledSnapshotOutcome,
} = {}) {
  const profile = INCREMENT_MINION_KEYFRAME_BRACKET_821_PROFILE;
  const base = {
    profile_id: profile.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    depends_on: [...profile.depends_on],
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: null,
    replay_sha256: replay?.source_sha256 ?? null,
    packet_count: null, snapshot_count: null, keyframe_count: null,
    observed_interval_count: null, bracketed_packet_count: null,
    distinct_bracket_count: null, unbracketed_packet_count: null,
    unbracketed_packets: null, verified_raw_packet_count: null,
    event_count: null, events: null, error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `minion packet/keyframe bracket supports only ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  if (!sha(replay.source_sha256)) {
    return fail('INCONSISTENT', 'Replay SHA-256 is missing or malformed');
  }
  if (!incrementMinionKillsPacketOutcome || !minionsKilledSnapshotOutcome) {
    return fail('MISSING_INPUT', 'both exact-build source outcomes are required', {
      missing_inputs: [
        ...(!incrementMinionKillsPacketOutcome ? ['increment_minion_kills_packet'] : []),
        ...(!minionsKilledSnapshotOutcome ? ['hero_minions_killed_snapshot'] : []),
      ],
    });
  }
  const packet = incrementMinionKillsPacketOutcome;
  const snapshot = minionsKilledSnapshotOutcome;
  if (packet.status !== 'CANDIDATE' || snapshot.status !== 'CANDIDATE') {
    const priority = ['DECODE_FAILED', 'INCONSISTENT', 'UNSUPPORTED',
      'MISSING_INPUT', 'PROFILE_UNAVAILABLE'];
    const decisive = priority.find((status) =>
      packet.status === status || snapshot.status === status) ?? 'INCONSISTENT';
    return fail(decisive, 'one or both exact-build source outcomes are unavailable', {
      dependency_statuses: {
        increment_minion_kills_packet: packet.status ?? null,
        hero_minions_killed_snapshot: snapshot.status ?? null,
      },
    });
  }
  if (packet.profile_id !== PACKET_PROFILE.id
      || packet.evidence_runtime_image_sha256 !== RUNTIME_IMAGE_SHA256
      || packet.evidence_callback_transform_sha256
        !== PACKET_PROFILE.evidence_callback_transform_sha256
      || packet.runtime_image_sha256 !== RUNTIME_IMAGE_SHA256
      || packet.runtime_image_status !== 'MATCHED_USED'
      || packet.runtime_image_used !== true
      || packet.input_packet_id !== 0x03a7
      || !count(packet.input_count) || !count(packet.event_count)
      || packet.event_count === 0 || packet.input_count !== packet.event_count
      || !Array.isArray(packet.events) || packet.events.length !== packet.event_count
      || snapshot.profile_id !== SNAPSHOT_PROFILE.id
      || snapshot.evidence_runtime_image_sha256 !== RUNTIME_IMAGE_SHA256
      || snapshot.lookup_table_sha256 !== LOOKUP_TABLE_SHA256
      || snapshot.runtime_image_status !== 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED'
      || snapshot.runtime_image_used !== false
      || snapshot.input_packet_id !== 0x0089
      || !count(snapshot.input_count) || !count(snapshot.event_count)
      || !count(snapshot.keyframe_count) || snapshot.keyframe_count === 0
      || snapshot.input_count !== snapshot.event_count
      || snapshot.event_count !== snapshot.keyframe_count * 10
      || snapshot.observed_participant_count !== 10
      || !count(snapshot.descent_count)
      || !Array.isArray(snapshot.events)
      || snapshot.events.length !== snapshot.event_count) {
    return fail('INCONSISTENT', 'exact-build source outcome profile, image, or counts differ');
  }
  const frames = new Map();
  for (const [index, row] of snapshot.events.entries()) {
    const ref = row?.raw_packet_ref;
    const participant = participantFor(row?.hero_raw_param);
    if (row?.event_type !== 'HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE'
        || row.game_version !== BUILD || row.patch !== '16.19'
        || row.build_profile !== SNAPSHOT_PROFILE.id
        || row.replay_sha256 !== replay.source_sha256
        || row.confidence !== 'CANDIDATE'
        || row.semantic_status !== 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL'
        || row.observation_kind !== 'KEYFRAME_SNAPSHOT'
        || participant === null || row.participant_id_candidate !== participant
        || !validRef(replay, ref, 0x0089, 'keyframe', 1263)
        || row.hero_raw_param !== ref.raw_param
        || row.replay_time_ms !== ref.replay_time_ms
        || !Number.isSafeInteger(row.minions_killed_raw_f32_candidate)
        || row.minions_killed_raw_f32_candidate < 0
        || row.minions_killed_floor_candidate
          !== row.minions_killed_raw_f32_candidate
        || !/^[0-9a-f]{8}$/.test(row.raw_payload_field_bytes_hex)) {
      return fail('INCONSISTENT', 'minions snapshot row identity, value, or source reference differs', {
        source: 'hero_minions_killed_snapshot', event_index: index,
      });
    }
    const frame = frames.get(ref.chunk_index) ?? {
      chunk_index: ref.chunk_index, time_ms: ref.replay_time_ms,
      participants: new Map(),
    };
    if (frame.time_ms !== ref.replay_time_ms
        || frame.participants.has(participant)) {
      return fail('INCONSISTENT', 'minions keyframe time or participant roster is ambiguous', {
        event_index: index, chunk_index: ref.chunk_index,
      });
    }
    frame.participants.set(participant, row);
    frames.set(ref.chunk_index, frame);
  }
  const replayKeyframes = replay.chunks.filter((chunk) => chunk.stream === 'keyframe');
  if (replayKeyframes.length !== snapshot.keyframe_count
      || frames.size !== snapshot.keyframe_count
      || replayKeyframes.some((chunk) => !frames.has(chunk.index))
      || [...frames.values()].some((frame) => frame.participants.size !== 10)) {
    return fail('INCONSISTENT', 'Replay keyframe does not have a complete ten-participant snapshot roster');
  }
  const orderedFrames = [...frames.values()].sort((a, b) => a.chunk_index - b.chunk_index);
  for (let index = 1; index < orderedFrames.length; index += 1) {
    const previous = orderedFrames[index - 1];
    const current = orderedFrames[index];
    if (current.time_ms <= previous.time_ms) {
      return fail('INCONSISTENT', 'keyframe times are not strictly increasing', {
        previous_chunk_index: previous.chunk_index,
        current_chunk_index: current.chunk_index,
      });
    }
  }
  for (const [index, row] of packet.events.entries()) {
    const ref = row?.raw_packet_ref;
    const participant = participantFor(row?.raw_param);
    if (row?.event_type !== 'INCREMENT_MINION_KILLS_PACKET_CANDIDATE'
        || row.game_version !== BUILD || row.patch !== '16.19'
        || row.build_profile !== PACKET_PROFILE.id
        || row.replay_sha256 !== replay.source_sha256
        || row.confidence !== 'CANDIDATE'
        || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_CALLBACK_LOOKUP_KEY'
        || participant === null || !validRef(replay, ref, 0x03a7, 'game_chunk', 3)
        || row.replay_time_ms !== ref.replay_time_ms
        || row.raw_param !== ref.raw_param
        || row.callback_lookup_key_candidate !== row.raw_param
        || row.callback_lookup_key_matches_raw_param !== true
        || lookupIncrementMinionKillsKeyFromNativeBytes(
          row.native_object_lookup_key_bytes_hex) !== row.raw_param
        || !/^[0-9a-f]{6}$/.test(row.raw_payload_hex)
        || !isObservedIncrementMinionKillsPayloadHex(row.raw_payload_hex)
        || row.raw_selector_byte !== parseInt(row.raw_payload_hex.slice(0, 2), 16)
        || row.conditional_counter_write_status !== 'UNKNOWN'
        || row.semantic_cs_effect_status !== 'UNKNOWN') {
      return fail('INCONSISTENT', 'IncrementMinionKills row identity, key, or source reference differs', {
        source: 'increment_minion_kills_packet', event_index: index,
      });
    }
  }
  const physical = verifyPhysicalRefs(replay, packet.events, snapshot.events);
  if (physical.error) {
    return fail(physical.scan_error ? 'DECODE_FAILED' : 'INCONSISTENT', physical.error);
  }
  const events = [];
  const distinctBrackets = new Set();
  const unbracketedPackets = [];
  for (const [index, packetRow] of packet.events.entries()) {
    const time = packetRow.replay_time_ms;
    const currentIndex = orderedFrames.findIndex((frame) => frame.time_ms >= time);
    const exclusionReason = currentIndex === -1 ? 'AFTER_LAST_SNAPSHOT'
      : orderedFrames[currentIndex].time_ms === time ? 'ON_KEYFRAME_BOUNDARY'
        : currentIndex === 0 ? 'BEFORE_FIRST_SNAPSHOT' : null;
    if (exclusionReason) {
      unbracketedPackets.push({
        replay_time_ms: time, raw_param: packetRow.raw_param,
        reason: exclusionReason,
        raw_packet_ref: structuredClone(packetRow.raw_packet_ref),
      });
      continue;
    }
    const previous = orderedFrames[currentIndex - 1];
    const current = orderedFrames[currentIndex];
    if (!(previous.time_ms < time && time < current.time_ms)) {
      return fail('INCONSISTENT', 'keyframe bracket ordering is inconsistent', {
        event_index: index, raw_param: packetRow.raw_param, replay_time_ms: time,
      });
    }
    const participant = participantFor(packetRow.raw_param);
    const previousSnapshot = previous.participants.get(participant);
    const currentSnapshot = current.participants.get(participant);
    const before = previousSnapshot.minions_killed_raw_f32_candidate;
    const after = currentSnapshot.minions_killed_raw_f32_candidate;
    const packetRef = structuredClone(packetRow.raw_packet_ref);
    const previousRef = structuredClone(previousSnapshot.raw_packet_ref);
    const currentRef = structuredClone(currentSnapshot.raw_packet_ref);
    distinctBrackets.add(`${previous.chunk_index}/${current.chunk_index}/${participant}`);
    events.push({
      event_type: 'INCREMENT_MINION_KEYFRAME_BRACKET_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: time,
      raw_param: packetRow.raw_param,
      callback_lookup_key_candidate: packetRow.callback_lookup_key_candidate,
      participant_id_candidate: participant,
      previous_observation_time_ms: previous.time_ms,
      current_observation_time_ms: current.time_ms,
      observation_interval_ms: current.time_ms - previous.time_ms,
      packet_offset_from_previous_ms: time - previous.time_ms,
      packet_offset_to_current_ms: current.time_ms - time,
      previous_snapshot_minions_killed_candidate: before,
      current_snapshot_minions_killed_candidate: after,
      observed_endpoint_delta_candidate: after - before,
      observation_kind: 'SAME_KEY_STRICT_ADJACENT_KEYFRAME_BRACKET',
      live_lookup_status: 'UNKNOWN',
      semantic_cs_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        raw_param: 'VERIFIED_DIRECT',
        callback_lookup_key_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
        participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
        previous_snapshot_minions_killed_candidate:
          'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL',
        current_snapshot_minions_killed_candidate:
          'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL',
        observed_endpoint_delta_candidate: 'DERIVED_FROM_CANDIDATE_ENDPOINTS',
      },
      raw_packet_ref: packetRef,
      increment_minion_kills_raw_packet_ref: packetRef,
      previous_snapshot_raw_packet_ref: previousRef,
      current_snapshot_raw_packet_ref: currentRef,
      raw_packet_refs: [packetRef, previousRef, currentRef],
    });
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    replay_sha256: replay.source_sha256,
    packet_count: packet.events.length,
    snapshot_count: snapshot.events.length,
    keyframe_count: orderedFrames.length,
    observed_interval_count: Math.max(0, orderedFrames.length - 1) * 10,
    bracketed_packet_count: events.length,
    distinct_bracket_count: distinctBrackets.size,
    unbracketed_packet_count: unbracketedPackets.length,
    unbracketed_packets: unbracketedPackets,
    verified_raw_packet_count: physical.verified_count,
    event_count: events.length, events,
  };
}

module.exports = {
  INCREMENT_MINION_KEYFRAME_BRACKET_821_PROFILE,
  associateIncrementMinionKeyframeBracketCandidates821,
};
