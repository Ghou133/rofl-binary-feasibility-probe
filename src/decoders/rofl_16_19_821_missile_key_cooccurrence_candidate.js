'use strict';

const crypto = require('node:crypto');
const { replaySourceError } = require('./replay_source_integrity');
const {
  FORCE_CREATE_MISSILE_PACKET_CANDIDATE_PROFILE_821: FORCE_PROFILE,
  decodeProtectedForceCreateMissileComparisonKeyU32,
  isObservedForceCreateMissilePayload,
} = require('./rofl_16_19_821_force_create_missile_packet_candidate');
const {
  CHANGE_MISSILE_TARGET_PACKET_CANDIDATE_PROFILE_821: CHANGE_PROFILE,
  CHANGE_MISSILE_TARGET_PACKET_CANDIDATE_PROFILE_V2_821: CHANGE_PROFILE_V2,
  decodeProtectedChangeMissileTargetComparisonKeyU32,
  isObservedChangeMissileTargetPayload,
} = require('./rofl_16_19_821_change_missile_target_packet_candidate');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'missile_key_cooccurrence';
const EVIDENCE_STATUS = 'CANDIDATE_821_MISSILE_CROSS_ROUTE_FULL_U32_PRECEDENCE';
const KEY_EQUALITY = 'CANDIDATE_PRECEDING_FULL_U32_KEY_EQUALITY';
const IMAGE_SHA256 = FORCE_PROFILE.evidence_runtime_image_sha256;
const MAX_FORCE_ROWS = 40_000;
const MAX_CHANGE_ROWS = 20_000;
const PRECEDENCE_WINDOW_MS = 2_000;

const MISSILE_KEY_COOCCURRENCE_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-missile-key-cooccurrence-candidate-v1',
  replay_version: BUILD,
  capability: CAPABILITY,
  status: 'CANDIDATE',
  evidence_status: EVIDENCE_STATUS,
  enabled: true,
  depends_on: Object.freeze(['force_create_missile_packet', 'change_missile_target_packet']),
  packet_ids: Object.freeze([0x0087, 0x040c]),
  evidence_runtime_image_sha256: IMAGE_SHA256,
  runtime_image_required: true,
  evidence_scope: 'same-Replay native 0x0087 comparison u32 versus 0x040c packet-header u32, with strict physical packet precedence and a 2000 ms lookback',
  known_limits: Object.freeze([
    'Full-u32 equality and physical packet precedence are candidate observations, not a missile-instance join or causal pair.',
    'The fixed 2000 ms lookback bounds the observed 0–1137 ms offsets in 11 Replays; it is not a gameplay duration or causal threshold.',
    'Multiple preceding equal keys within the window remain ambiguous; a single preceding key may still be unrelated or reused.',
    'Every ChangeMissileTarget source row is retained, including no-match and timestamp-order conflicts.',
    'The live receiver, missile identity, owner, target, creation, target change, effects, and causality remain unknown.',
  ]),
});

function nonnegative(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function u32(value) {
  return nonnegative(value) && value <= 0xffffffff;
}

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function refPosition(ref) {
  return [ref.chunk_index, ref.decompressed_payload_offset];
}

function comparePosition(a, b) {
  const [aChunk, aOffset] = refPosition(a);
  const [bChunk, bOffset] = refPosition(b);
  return aChunk === bChunk ? aOffset - bOffset : aChunk - bChunk;
}

function lowerBoundTime(rows, time) {
  let low = 0;
  let high = rows.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (rows[middle].replay_time_ms < time) low = middle + 1;
    else high = middle;
  }
  return low;
}

function upperBoundTime(rows, time) {
  let low = 0;
  let high = rows.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (rows[middle].replay_time_ms <= time) low = middle + 1;
    else high = middle;
  }
  return low;
}

function validRef(replay, ref, packetId, observedPayload) {
  const chunk = replay.chunks?.[ref?.chunk_index];
  if (!chunk || !nonnegative(ref.chunk_index) || !nonnegative(ref.chunk_id)
      || ref.chunk_stream !== 'game_chunk' || !nonnegative(ref.chunk_file_offset)
      || !nonnegative(ref.decompressed_block_offset)
      || !nonnegative(ref.decompressed_payload_offset)
      || ref.decompressed_payload_offset <= ref.decompressed_block_offset
      || ref.packet_id !== packetId || !nonnegative(ref.replay_time_ms)
      || !u32(ref.raw_param) || !nonnegative(ref.payload_length)
      || !sha(ref.raw_payload_sha256)
      || typeof ref.raw_payload_hex !== 'string'
      || ref.raw_payload_hex.length !== ref.payload_length * 2
      || !/^[0-9a-f]+$/.test(ref.raw_payload_hex)) return false;
  const payload = Buffer.from(ref.raw_payload_hex, 'hex');
  return ref.source_path === (replay.source_path ?? null)
    && ref.replay_sha256 === replay.source_sha256
    && chunk.index === ref.chunk_index && chunk.chunk_id === ref.chunk_id
    && chunk.stream === 'game_chunk' && chunk.stream_tag === 1
    && chunk.offset === ref.chunk_file_offset
    && ref.decompressed_payload_offset + ref.payload_length <= chunk.uncompressed_length
    && observedPayload(payload)
    && crypto.createHash('sha256').update(payload).digest('hex')
      === ref.raw_payload_sha256;
}

function validSourceRow(replay, row, profile, packetId, observedPayload, decodeKey) {
  const ref = row?.raw_packet_ref;
  return row?.game_version === BUILD && row.patch === '16.19'
    && row.replay_sha256 === replay.source_sha256
    && row.build_profile === profile.id
    && row.replay_time_ms === ref?.replay_time_ms
    && row.raw_param === ref?.raw_param
    && row.packet_name_candidate === profile.packet_name
    && row.native_callback_witness_status === 'SYNTHETIC_RECEIVER_PRE_COMPARE'
    && row.source_actor_status === 'UNKNOWN'
    && row.owner_status === 'UNKNOWN'
    && row.missile_identity_status === 'UNKNOWN'
    && row.target_status === 'UNKNOWN'
    && row.causality_status === 'UNKNOWN'
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === profile.evidence_status
    && u32(row.native_callback_comparison_key_u32)
    && decodeKey(row.native_protected_comparison_bytes_hex)
      === row.native_callback_comparison_key_u32
    && validRef(replay, ref, packetId, observedPayload);
}

function validOutcome(outcome, profile, maximum) {
  return outcome?.status === 'CANDIDATE'
    && outcome.profile_id === profile.id
    && outcome.evidence_status === profile.evidence_status
    && nonnegative(outcome.input_count) && outcome.input_count <= maximum
    && outcome.input_count === outcome.event_count
    && Array.isArray(outcome.events) && outcome.events.length === outcome.input_count
    && outcome.native_witness_status === 'FULLY_CONSUMED_ALL'
    && outcome.native_full_success_count === outcome.input_count
    && sha(outcome.native_input_sha256) && sha(outcome.native_output_sha256)
    && outcome.runtime_image_status === 'MATCHED_USED'
    && outcome.runtime_image_used === true
    && outcome.runtime_image_sha256 === IMAGE_SHA256;
}

function associateMissileKeyCooccurrence821(replay, {
  forceCreateMissilePacketOutcome, changeMissileTargetPacketOutcome,
} = {}) {
  const profile = MISSILE_KEY_COOCCURRENCE_821_PROFILE;
  const dependencies = {
    force_create_missile_packet: forceCreateMissilePacketOutcome?.status ?? 'UNEXECUTED',
    change_missile_target_packet: changeMissileTargetPacketOutcome?.status ?? 'UNEXECUTED',
  };
  const base = {
    profile_id: profile.id,
    input_packet_id: 0x040c,
    evidence_status: EVIDENCE_STATUS,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    dependency_statuses: dependencies,
    runtime_image_status: changeMissileTargetPacketOutcome?.runtime_image_status ?? 'NOT_CHECKED',
    runtime_image_used: changeMissileTargetPacketOutcome?.runtime_image_used ?? false,
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, extra = {}) => ({
    ...base, status, input_count: null, event_count: null, events: null,
    error, ...extra,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `${CAPABILITY} requires ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return fail('DECODE_FAILED', `Replay source failed: ${sourceError}`);
  for (const [name, status] of Object.entries(dependencies)) {
    if (status !== 'CANDIDATE') {
      return fail(status === 'UNEXECUTED' ? 'MISSING_INPUT' : status,
        `${CAPABILITY} requires ${name}: ${status}`);
    }
  }
  const force = forceCreateMissilePacketOutcome;
  const change = changeMissileTargetPacketOutcome;
  const changeProfile = change?.profile_id === CHANGE_PROFILE_V2.id
    ? CHANGE_PROFILE_V2 : CHANGE_PROFILE;
  if (!validOutcome(force, FORCE_PROFILE, MAX_FORCE_ROWS)
      || !validOutcome(change, changeProfile, MAX_CHANGE_ROWS)
      || force.input_packet_id !== 0x0087 || change.input_packet_id !== 0x040c) {
    return fail('DECODE_FAILED', 'Incomplete exact-build missile source outcome');
  }
  for (let i = 0; i < force.events.length; i += 1) {
    const row = force.events[i];
    if (row.event_type !== 'FORCE_CREATE_MISSILE_PACKET_CANDIDATE'
        || !validSourceRow(replay, row, FORCE_PROFILE, 0x0087,
          isObservedForceCreateMissilePayload,
          decodeProtectedForceCreateMissileComparisonKeyU32)
        || row.live_receiver_lookup_status !== 'UNKNOWN'
        || row.creation_effect_status !== 'UNKNOWN'
        || (i > 0 && (comparePosition(force.events[i - 1].raw_packet_ref,
          row.raw_packet_ref) >= 0
          || force.events[i - 1].replay_time_ms > row.replay_time_ms))) {
      return fail('DECODE_FAILED', `Malformed or out-of-order 0x0087 source row ${i}`);
    }
  }
  for (let i = 0; i < change.events.length; i += 1) {
    const row = change.events[i];
    if (row.event_type !== 'CHANGE_MISSILE_TARGET_PACKET_CANDIDATE'
        || !validSourceRow(replay, row, changeProfile, 0x040c,
          isObservedChangeMissileTargetPayload,
          decodeProtectedChangeMissileTargetComparisonKeyU32)
        || row.live_receiver_comparison_status !== 'UNKNOWN'
        || row.target_change_effect_status !== 'UNKNOWN'
        || (i > 0 && (comparePosition(change.events[i - 1].raw_packet_ref,
          row.raw_packet_ref) >= 0
          || change.events[i - 1].replay_time_ms > row.replay_time_ms))) {
      return fail('DECODE_FAILED', `Malformed or out-of-order 0x040c source row ${i}`);
    }
  }
  const allForceByKey = new Map();
  for (const row of force.events) {
    const key = row.native_callback_comparison_key_u32;
    const found = allForceByKey.get(key);
    if (found) found.push(row);
    else allForceByKey.set(key, [row]);
  }
  const precedingByKey = new Map();
  const events = [];
  const counts = {
    preceding_equal_key_count: 0,
    unique_preceding_equal_key_count: 0,
    ambiguous_multiple_preceding_count: 0,
    no_preceding_equal_key_count: 0,
    zero_change_header_count: 0,
    future_equal_key_only_count: 0,
    no_equal_key_anywhere_count: 0,
    old_preceding_equal_key_only_count: 0,
    timestamp_order_conflict_count: 0,
    plus_0x100_control_preceding_count: 0,
    future_equal_key_within_window_count: 0,
    preceding_and_future_equal_key_within_window_count: 0,
  };
  let forceIndex = 0;
  for (const row of change.events) {
    while (forceIndex < force.events.length
        && comparePosition(force.events[forceIndex].raw_packet_ref,
          row.raw_packet_ref) < 0) {
      const source = force.events[forceIndex++];
      const key = source.native_callback_comparison_key_u32;
      const found = precedingByKey.get(key);
      if (found) found.push(source);
      else precedingByKey.set(key, [source]);
    }
    const key = row.raw_param;
    const found = precedingByKey.get(key) ?? [];
    const lower = lowerBoundTime(found, row.replay_time_ms - PRECEDENCE_WINDOW_MS);
    const upper = upperBoundTime(found, row.replay_time_ms);
    const rawPrecedingCount = upper - lower;
    const precedingCount = key === 0 ? 0 : rawPrecedingCount;
    const olderCount = lower;
    const timestampConflictCount = found.length - upper;
    const allWithKey = allForceByKey.get(key) ?? [];
    const futureCount = allWithKey.length - found.length;
    const futureWindowCount = Math.max(0,
      upperBoundTime(allWithKey, row.replay_time_ms + PRECEDENCE_WINDOW_MS)
      - Math.max(found.length, lowerBoundTime(allWithKey, row.replay_time_ms)));
    if (key !== 0 && futureWindowCount) {
      counts.future_equal_key_within_window_count += 1;
    }
    if (key !== 0 && futureWindowCount && precedingCount) {
      counts.preceding_and_future_equal_key_within_window_count += 1;
    }
    const controlKey = (key + 0x100) >>> 0;
    const controlRows = precedingByKey.get(controlKey) ?? [];
    const controlCount = key === 0 ? 0
      : upperBoundTime(controlRows, row.replay_time_ms)
        - lowerBoundTime(controlRows,
          row.replay_time_ms - PRECEDENCE_WINDOW_MS);
    if (controlCount) counts.plus_0x100_control_preceding_count += 1;
    const unique = precedingCount === 1 ? found[lower] : null;
    const lag = unique ? row.replay_time_ms - unique.replay_time_ms : null;
    let associationStatus;
    if (key === 0) {
      associationStatus = 'ZERO_HEADER_KEY_EXCLUDED';
      counts.zero_change_header_count += 1;
    } else if (timestampConflictCount > 0) {
      associationStatus = 'TIMESTAMP_ORDER_CONFLICT';
      counts.timestamp_order_conflict_count += 1;
    } else if (precedingCount > 1) {
      associationStatus = 'AMBIGUOUS_MULTIPLE_PRECEDING_EQUAL_KEYS';
      counts.preceding_equal_key_count += 1;
      counts.ambiguous_multiple_preceding_count += 1;
    } else if (unique) {
      associationStatus = KEY_EQUALITY;
      counts.preceding_equal_key_count += 1;
      counts.unique_preceding_equal_key_count += 1;
    } else {
      associationStatus = 'NO_PRECEDING_EQUAL_KEY';
      counts.no_preceding_equal_key_count += 1;
      if (olderCount) counts.old_preceding_equal_key_only_count += 1;
      else if (futureCount) counts.future_equal_key_only_count += 1;
      else counts.no_equal_key_anywhere_count += 1;
    }
    events.push({
      event_type: 'MISSILE_KEY_COOCCURRENCE_CANDIDATE',
      game_version: BUILD,
      patch: '16.19',
      build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: row.replay_time_ms,
      change_packet_header_u32: key,
      change_packet_callback_comparison_key_u32:
        row.native_callback_comparison_key_u32,
      force_preceding_equal_key_count: precedingCount,
      zero_header_raw_preceding_equal_key_count:
        key === 0 ? rawPrecedingCount : 0,
      force_older_preceding_equal_key_count: olderCount,
      force_future_equal_key_count: futureCount,
      force_future_equal_key_within_window_count: futureWindowCount,
      plus_0x100_control_preceding_count: controlCount,
      preceding_lag_ms: associationStatus === KEY_EQUALITY ? lag : null,
      association_status: associationStatus,
      force_packet_ref: associationStatus === KEY_EQUALITY
        ? unique.raw_packet_ref : null,
      change_packet_ref: row.raw_packet_ref,
      live_receiver_status: 'UNKNOWN',
      missile_identity_status: 'UNKNOWN',
      owner_status: 'UNKNOWN',
      target_status: 'UNKNOWN',
      creation_effect_status: 'UNKNOWN',
      target_change_effect_status: 'UNKNOWN',
      causality_status: 'UNKNOWN',
      confidence: 'CANDIDATE',
      semantic_status: EVIDENCE_STATUS,
    });
  }
  return {
    ...base,
    status: 'CANDIDATE',
    input_count: change.input_count,
    event_count: events.length,
    force_source_count: force.input_count,
    change_source_count: change.input_count,
    zero_force_comparison_key_count: allForceByKey.get(0)?.length ?? 0,
    precedence_window_ms: PRECEDENCE_WINDOW_MS,
    ...counts,
    native_witness_status: 'FULLY_CONSUMED_BOTH_SOURCES',
    runtime_image_sha256: IMAGE_SHA256,
    force_native_input_sha256: force.native_input_sha256,
    force_native_output_sha256: force.native_output_sha256,
    change_native_input_sha256: change.native_input_sha256,
    change_native_output_sha256: change.native_output_sha256,
    events,
  };
}

module.exports = {
  MISSILE_KEY_COOCCURRENCE_821_PROFILE,
  associateMissileKeyCooccurrence821,
};
