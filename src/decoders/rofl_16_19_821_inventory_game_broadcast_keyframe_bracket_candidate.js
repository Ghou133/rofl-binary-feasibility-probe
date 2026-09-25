'use strict';

// Associates a game-stream Broadcast packet with adjacent, sampled keyframe
// packets. The three packet observations do not describe continuous inventory.
const { isDeepStrictEqual } = require('node:util');
const { replaySourceError } = require('./replay_source_integrity');
const {
  HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821: BROADCAST_PROFILE,
} = require('./rofl_16_19_821_inventory_broadcast_packet_candidate');
const {
  INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE: INTERVAL_PROFILE,
  deriveInventoryKeyframeIntervalDifferenceCandidates821,
} = require('./rofl_16_19_821_inventory_keyframe_interval_difference_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = BROADCAST_PROFILE.evidence_runtime_image_sha256;
const FIRST_PARAM = 0x400000ae;
const LAST_PARAM = 0x400000b7;
const VARIANT_PARAMS = new Set([0x400001af, 0x400001b1, 0x400001b3, 0x400002af]);
const MAX_ROWS = 10_000;
const EVIDENCE_STATUS =
  'CANDIDATE_821_GAME_BROADCAST_BETWEEN_ADJACENT_KEYFRAMES';

const INVENTORY_GAME_BROADCAST_KEYFRAME_BRACKET_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-inventory-game-broadcast-keyframe-bracket-candidate-v1',
  replay_version: BUILD,
  capability: 'inventory_game_broadcast_keyframe_bracket',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze(['hero_inventory_broadcast_packet']),
  prerequisite_association: INTERVAL_PROFILE.capability,
  packet_id: 0x0357,
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_scope: 'exact 821 Broadcast packet-local records strictly bracketed by adjacent complete ten-participant keyframes',
  known_limits: Object.freeze([
    'Each row reports one observed game-stream Broadcast packet and two sampled keyframe packets for the same canonical raw param.',
    'Only explicit game packet records are compared. Game slots without a record have no compared item key.',
    'A zero item key is an observed decoded candidate, not an unavailable value.',
    'Matching or differing observations do not establish continuous inventory, a transaction, or the time of a change.',
    'Participant identity and all slot/item keys remain exact-build candidates.',
    'Noncanonical, boundary, and unbracketed game packets are retained as exclusions with raw references.',
    'The prerequisite interval outcome must be the same-run, physically verified exact-build Broadcast derivation.',
  ]),
});

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_ROWS;
}

function nonnegative(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function u32(value) {
  return nonnegative(value) && value <= 0xffffffff;
}

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function participantFor(param) {
  return u32(param) && param >= FIRST_PARAM && param <= LAST_PARAM
    ? param - FIRST_PARAM + 1 : null;
}

function packetPosition(ref) {
  return `${ref.chunk_index}/${ref.decompressed_block_offset}`;
}

function validRef(replay, ref, stream) {
  const chunk = replay.chunks?.[ref?.chunk_index];
  return ref?.source_path === (replay.source_path ?? null)
    && ref.replay_sha256 === replay.source_sha256
    && nonnegative(ref.chunk_index) && nonnegative(ref.chunk_id)
    && ref.chunk_stream === stream && nonnegative(ref.chunk_file_offset)
    && nonnegative(ref.decompressed_block_offset)
    && nonnegative(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === 0x0357 && nonnegative(ref.replay_time_ms)
    && nonnegative(ref.payload_length)
    && ref.payload_length >= 76 && ref.payload_length <= 166
    && u32(ref.raw_param) && sha(ref.raw_payload_sha256)
    && !!chunk && chunk.index === ref.chunk_index && chunk.chunk_id === ref.chunk_id
    && chunk.stream === stream && chunk.stream_tag === (stream === 'keyframe' ? 2 : 1)
    && chunk.offset === ref.chunk_file_offset
    && nonnegative(chunk.uncompressed_length)
    && ref.decompressed_payload_offset + ref.payload_length <= chunk.uncompressed_length;
}

function packetValues(row, stream) {
  const records = row.records_candidate;
  const snapshot = row.packet_slot_snapshot_candidate;
  if (row.snapshot_application !== 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS'
      || !Array.isArray(records) || !Array.isArray(snapshot) || snapshot.length !== 10
      || row.record_count !== records.length
      || (stream === 'keyframe' ? records.length !== 10
        : records.length < 6 || records.length > 9)) return null;
  const values = Array(10).fill(null);
  let previousSlot = -1;
  for (const [index, record] of records.entries()) {
    const slot = record?.slot_candidate;
    if (record?.record_index !== index || !nonnegative(slot)
        || slot > (stream === 'keyframe' ? 9 : 8)
        || slot <= previousSlot || (stream === 'keyframe' && slot !== index)
        || !u32(record.item_id_candidate)) return null;
    previousSlot = slot;
    values[slot] = record.item_id_candidate;
  }
  if (!snapshot.every((entry, slot) => entry?.slot_candidate === slot
      && entry.item_id_candidate === values[slot]
      && entry.value_basis === (values[slot] === null
        ? 'CALLBACK_RESET_WITH_NO_PACKET_RECORD' : 'DECODED_PACKET_RECORD'))) {
    return null;
  }
  return values;
}

function comparison(previous, game, next) {
  if (previous === next) {
    return game === previous
      ? 'SAME_AS_BOTH_ENDPOINTS' : 'DIFFERS_FROM_EQUAL_ENDPOINTS';
  }
  if (game === previous) return 'SAME_AS_PREVIOUS_ENDPOINT';
  if (game === next) return 'SAME_AS_NEXT_ENDPOINT';
  return 'DIFFERS_FROM_BOTH_ENDPOINTS';
}

function associateInventoryGameBroadcastKeyframeBracketCandidates821(replay, {
  inventoryBroadcastOutcome, inventoryIntervalOutcome,
} = {}) {
  const profile = INVENTORY_GAME_BROADCAST_KEYFRAME_BRACKET_821_PROFILE;
  const base = {
    profile_id: profile.id,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    depends_on: [...profile.depends_on],
    prerequisite_association: profile.prerequisite_association,
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: null,
    replay_sha256: replay?.source_sha256 ?? null,
    runtime_image_status: inventoryBroadcastOutcome?.runtime_image_status ?? 'NOT_CHECKED',
    runtime_image_used: inventoryBroadcastOutcome?.runtime_image_used ?? false,
    runtime_image_sha256: inventoryBroadcastOutcome?.runtime_image_sha256 ?? null,
    input_count: null, keyframe_count: null, broadcast_keyframe_packet_count: null,
    game_broadcast_packet_count: null, bracketed_game_broadcast_count: null,
    excluded_noncanonical_game_broadcast_count: null,
    excluded_before_first_keyframe_count: null,
    excluded_after_last_keyframe_count: null, excluded_on_boundary_count: null,
    excluded_noncanonical_game_broadcast_packet_refs: null,
    excluded_before_first_keyframe_refs: null,
    excluded_after_last_keyframe_refs: null, excluded_on_boundary_refs: null,
    record_comparison_count: null, distinct_participant_interval_count: null,
    comparison_counts: null, verified_raw_packet_count: null,
    event_count: null, events: null, error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `inventory game Broadcast bracket supports only ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  if (!sha(replay.source_sha256)) {
    return fail('INCONSISTENT', 'Replay SHA-256 is missing or malformed');
  }
  if (!inventoryBroadcastOutcome) {
    return fail('MISSING_INPUT', 'exact-build inventory Broadcast outcome is required', {
      missing_input: 'hero_inventory_broadcast_packet',
    });
  }
  const source = inventoryBroadcastOutcome;
  if (source.profile_id !== BROADCAST_PROFILE.id
      || source.evidence_runtime_image_sha256 !== IMAGE_SHA256
      || source.input_packet_id !== 0x0357) {
    return fail('INCONSISTENT', 'inventory Broadcast dependency identity differs');
  }
  if (source.status !== 'CANDIDATE') {
    const propagated = ['MISSING_INPUT', 'PROFILE_UNAVAILABLE', 'UNSUPPORTED',
      'DECODE_FAILED', 'INCONSISTENT'].includes(source.status)
      ? source.status : 'INCONSISTENT';
    return fail(propagated, 'inventory Broadcast candidate decoder is unavailable', {
      dependency_status: source.status ?? null,
      dependency_error: source.error ?? null,
    });
  }
  if (source.runtime_image_sha256 !== IMAGE_SHA256
      || source.runtime_image_status !== 'MATCHED_USED'
      || source.runtime_image_used !== true
      || !count(source.input_count) || !count(source.event_count)
      || source.event_count > 512
      || source.event_count === 0 || source.input_count !== source.event_count
      || !count(source.decoded_record_count)
      || !Array.isArray(source.events) || source.events.length !== source.event_count) {
    return fail('INCONSISTENT', 'Broadcast image, source counts, or event list differ');
  }
  let interval = inventoryIntervalOutcome;
  if (interval === undefined) {
    interval = deriveInventoryKeyframeIntervalDifferenceCandidates821(replay, {
      inventoryBroadcastOutcome: source,
    });
  }
  if (!interval || typeof interval !== 'object') {
    return fail('MISSING_INPUT', 'same-run inventory keyframe interval outcome is required', {
      missing_input: 'inventory_keyframe_interval_difference',
    });
  }
  if (interval.status !== 'CANDIDATE') {
    if ((interval.profile_id !== undefined && interval.profile_id !== INTERVAL_PROFILE.id)
        || (interval.evidence_runtime_image_sha256 !== undefined
          && interval.evidence_runtime_image_sha256 !== IMAGE_SHA256)) {
      return fail('INCONSISTENT', 'unavailable interval prerequisite identity differs');
    }
    const propagated = ['MISSING_INPUT', 'PROFILE_UNAVAILABLE', 'UNSUPPORTED',
      'DECODE_FAILED', 'INCONSISTENT'].includes(interval.status)
      ? interval.status : 'INCONSISTENT';
    return fail(propagated, 'inventory interval prerequisite is unavailable', {
      dependency_status: interval.status ?? null,
      dependency_error: interval.error ?? null,
    });
  }
  if (interval.profile_id !== INTERVAL_PROFILE.id
      || interval.evidence_runtime_image_sha256 !== IMAGE_SHA256
      || interval.evidence_status
        !== 'CANDIDATE_821_ADJACENT_KEYFRAME_INVENTORY_SLOT_DIFFERENCE'
      || interval.replay_sha256 !== replay.source_sha256
      || !isDeepStrictEqual(interval.depends_on, [...INTERVAL_PROFILE.depends_on])
      || !count(interval.input_count) || interval.input_count !== source.event_count
      || !count(interval.keyframe_count) || interval.keyframe_count < 1
      || !count(interval.broadcast_keyframe_packet_count)
      || interval.broadcast_keyframe_packet_count !== 10 * interval.keyframe_count
      || !count(interval.excluded_game_broadcast_count)
      || interval.input_count !== interval.broadcast_keyframe_packet_count
        + interval.excluded_game_broadcast_count
      || !count(interval.observed_interval_count)
      || interval.observed_interval_count !== 10 * (interval.keyframe_count - 1)
      || !count(interval.changed_interval_count)
      || !count(interval.unchanged_interval_count)
      || interval.changed_interval_count + interval.unchanged_interval_count
        !== interval.observed_interval_count
      || !count(interval.changed_slot_count)
      || !count(interval.verified_raw_packet_count)
      || interval.verified_raw_packet_count !== source.event_count
      || interval.event_count !== interval.changed_interval_count
      || !Array.isArray(interval.events)
      || interval.events.length !== interval.event_count) {
    return fail('INCONSISTENT', 'verified interval prerequisite identity or counts differ');
  }

  const frames = new Map();
  const games = [];
  const positions = new Set();
  let decodedRecordCount = 0;
  let keyframePackets = 0;
  const noncanonicalRefs = [];
  for (const [eventIndex, row] of source.events.entries()) {
    const ref = row?.raw_packet_ref;
    const stream = row?.packet_stream;
    const participant = participantFor(row?.hero_raw_param);
    const values = packetValues(row ?? {}, stream);
    if (row?.event_type !== 'HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE'
        || row.game_version !== BUILD || row.patch !== '16.19'
        || row.build_profile !== BROADCAST_PROFILE.id
        || row.replay_sha256 !== replay.source_sha256
        || row.confidence !== 'CANDIDATE'
        || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS'
        || !['keyframe', 'game_chunk'].includes(stream)
        || !validRef(replay, ref, stream)
        || ref.replay_time_ms !== row.replay_time_ms
        || ref.raw_param !== row.hero_raw_param
        || (participant === null && !VARIANT_PARAMS.has(row.hero_raw_param))
        || row.participant_id_candidate !== participant
        || values === null) {
      return fail('INCONSISTENT', 'Broadcast source row identity, records, or reference differ', {
        event_index: eventIndex,
      });
    }
    const position = packetPosition(ref);
    if (positions.has(position)) {
      return fail('INCONSISTENT', 'duplicate physical Broadcast packet reference', {
        event_index: eventIndex, packet_position: position,
      });
    }
    positions.add(position);
    decodedRecordCount += row.record_count;
    if (stream === 'game_chunk') {
      games.push({ row, values });
      if (participant === null) noncanonicalRefs.push(ref);
      continue;
    }
    if (participant === null) {
      return fail('INCONSISTENT', 'keyframe Broadcast participant is noncanonical', {
        event_index: eventIndex,
      });
    }
    keyframePackets += 1;
    const frame = frames.get(ref.chunk_index)
      ?? { chunk_index: ref.chunk_index, replay_time_ms: ref.replay_time_ms,
        participants: new Map() };
    if (frame.replay_time_ms !== ref.replay_time_ms
        || frame.participants.has(participant)) {
      return fail('INCONSISTENT', 'keyframe Broadcast time or participant is duplicated', {
        event_index: eventIndex,
      });
    }
    frame.participants.set(participant, { row, values });
    frames.set(ref.chunk_index, frame);
  }
  if (decodedRecordCount !== source.decoded_record_count
      || source.unmapped_raw_param_count !== noncanonicalRefs.length
      || !isDeepStrictEqual(source.unmapped_raw_packet_refs, noncanonicalRefs)) {
    return fail('INCONSISTENT', 'Broadcast decoded record or noncanonical counts differ');
  }
  const replayKeyframeChunks = replay.chunks.filter((chunk) => chunk.stream === 'keyframe');
  if (frames.size !== replayKeyframeChunks.length
      || replayKeyframeChunks.some((chunk) => !frames.has(chunk.index))
      || keyframePackets !== frames.size * 10
      || [...frames.values()].some((frame) => frame.participants.size !== 10)
      || interval.keyframe_count !== frames.size
      || interval.broadcast_keyframe_packet_count !== keyframePackets
      || interval.excluded_game_broadcast_count !== games.length) {
    return fail('INCONSISTENT', 'Broadcast source lacks complete keyframes or counts differ');
  }
  const orderedFrames = [...frames.values()].sort((a, b) => a.chunk_index - b.chunk_index);
  for (let index = 1; index < orderedFrames.length; index += 1) {
    if (orderedFrames[index].replay_time_ms <= orderedFrames[index - 1].replay_time_ms) {
      return fail('INCONSISTENT', 'keyframe Broadcast times are not strictly increasing');
    }
  }

  // Cross-check the supplied interval events against all source keyframe
  // endpoints before using its verified-raw-packet claim for game rows.
  const expectedIntervals = new Map();
  let changedSlotCount = 0;
  for (let index = 1; index < orderedFrames.length; index += 1) {
    const previous = orderedFrames[index - 1];
    const next = orderedFrames[index];
    for (let participant = 1; participant <= 10; participant += 1) {
      const before = previous.participants.get(participant);
      const after = next.participants.get(participant);
      const changes = [];
      for (let slot = 0; slot < 10; slot += 1) {
        if (before.values[slot] !== after.values[slot]) {
          changes.push({ slot_candidate: slot,
            previous_item_id_candidate: before.values[slot],
            current_item_id_candidate: after.values[slot] });
        }
      }
      if (!changes.length) continue;
      changedSlotCount += changes.length;
      expectedIntervals.set(`${previous.chunk_index}/${next.chunk_index}/${participant}`, {
        before, after, changes, previous, next,
      });
    }
  }
  if (expectedIntervals.size !== interval.changed_interval_count
      || changedSlotCount !== interval.changed_slot_count) {
    return fail('INCONSISTENT', 'interval differences disagree with Broadcast keyframe rows');
  }
  for (const event of interval.events) {
    const key = `${event?.previous_keyframe_chunk_index}/${event?.current_keyframe_chunk_index}/${event?.participant_id_candidate}`;
    const expected = expectedIntervals.get(key);
    if (!expected || event.event_type !== 'INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_CANDIDATE'
        || event.game_version !== BUILD || event.patch !== '16.19'
        || event.build_profile !== INTERVAL_PROFILE.id
        || event.replay_sha256 !== replay.source_sha256
        || event.confidence !== 'CANDIDATE'
        || event.semantic_status !== interval.evidence_status
        || event.hero_raw_param !== expected.before.row.hero_raw_param
        || event.participant_id_candidate
          !== expected.before.row.participant_id_candidate
        || event.observation_kind !== 'ADJACENT_KEYFRAME_SAMPLED_ENDPOINTS'
        || event.observation_scope !== 'KEYFRAME_ENDPOINT_DIFFERENCE_ONLY'
        || event.change_time_status !== 'UNRESOLVED_WITHIN_INTERVAL'
        || event.replay_time_ms !== expected.next.replay_time_ms
        || event.previous_observation_time_ms !== expected.previous.replay_time_ms
        || event.current_observation_time_ms !== expected.next.replay_time_ms
        || event.observation_interval_ms
          !== expected.next.replay_time_ms - expected.previous.replay_time_ms
        || event.changed_slot_count !== expected.changes.length
        || !isDeepStrictEqual(event.changed_slots_candidate, expected.changes)
        || !isDeepStrictEqual(event.previous_raw_packet_ref,
          expected.before.row.raw_packet_ref)
        || !isDeepStrictEqual(event.current_raw_packet_ref,
          expected.after.row.raw_packet_ref)
        || !isDeepStrictEqual(event.raw_packet_ref,
          expected.after.row.raw_packet_ref)
        || !isDeepStrictEqual(event.raw_packet_refs,
          [expected.before.row.raw_packet_ref, expected.after.row.raw_packet_ref])) {
      return fail('INCONSISTENT', 'interval event differs from Broadcast keyframe endpoints');
    }
    expectedIntervals.delete(key);
  }
  if (expectedIntervals.size) {
    return fail('INCONSISTENT', 'verified interval prerequisite omits changed keyframes');
  }

  const events = [];
  const excludedBefore = [];
  const excludedAfter = [];
  const excludedBoundary = [];
  const distinctIntervals = new Set();
  const comparisonCounts = {
    SAME_AS_BOTH_ENDPOINTS: 0,
    DIFFERS_FROM_EQUAL_ENDPOINTS: 0,
    SAME_AS_PREVIOUS_ENDPOINT: 0,
    SAME_AS_NEXT_ENDPOINT: 0,
    DIFFERS_FROM_BOTH_ENDPOINTS: 0,
  };
  let recordComparisonCount = 0;
  for (const { row: game } of games) {
    const participant = participantFor(game.hero_raw_param);
    if (participant === null) continue;
    const gameRef = game.raw_packet_ref;
    const gameChunk = gameRef.chunk_index;
    const nextIndex = orderedFrames.findIndex((frame) => frame.chunk_index > gameChunk);
    if (nextIndex === 0) {
      if (game.replay_time_ms > orderedFrames[0].replay_time_ms) {
        return fail('INCONSISTENT', 'game packet before first frame has a later time');
      }
      (game.replay_time_ms === orderedFrames[0].replay_time_ms
        ? excludedBoundary : excludedBefore).push(gameRef);
      continue;
    }
    if (nextIndex === -1) {
      const last = orderedFrames[orderedFrames.length - 1];
      if (game.replay_time_ms < last.replay_time_ms) {
        return fail('INCONSISTENT', 'game packet after last frame has an earlier time');
      }
      (game.replay_time_ms === last.replay_time_ms
        ? excludedBoundary : excludedAfter).push(gameRef);
      continue;
    }
    const previous = orderedFrames[nextIndex - 1];
    const next = orderedFrames[nextIndex];
    if (game.replay_time_ms === previous.replay_time_ms
        || game.replay_time_ms === next.replay_time_ms) {
      excludedBoundary.push(gameRef);
      continue;
    }
    if (game.replay_time_ms < previous.replay_time_ms
        || game.replay_time_ms > next.replay_time_ms) {
      return fail('INCONSISTENT', 'game packet time disagrees with adjacent keyframe order');
    }
    const before = previous.participants.get(participant);
    const after = next.participants.get(participant);
    const records = game.records_candidate.map((record) => {
      const slot = record.slot_candidate;
      const prior = before.values[slot];
      const observed = record.item_id_candidate;
      const later = after.values[slot];
      const label = comparison(prior, observed, later);
      comparisonCounts[label] += 1;
      return {
        slot_candidate: slot,
        previous_item_id_candidate: prior,
        game_item_id_candidate: observed,
        next_item_id_candidate: later,
        comparison_to_endpoints: label,
      };
    });
    recordComparisonCount += records.length;
    distinctIntervals.add(`${previous.chunk_index}/${next.chunk_index}/${participant}`);
    const seenSlots = new Set(records.map((record) => record.slot_candidate));
    const previousRef = structuredClone(before.row.raw_packet_ref);
    const middleRef = structuredClone(gameRef);
    const nextRef = structuredClone(after.row.raw_packet_ref);
    events.push({
      event_type: 'INVENTORY_GAME_BROADCAST_KEYFRAME_BRACKET_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: game.replay_time_ms,
      previous_observation_time_ms: previous.replay_time_ms,
      game_observation_time_ms: game.replay_time_ms,
      next_observation_time_ms: next.replay_time_ms,
      observation_interval_ms: next.replay_time_ms - previous.replay_time_ms,
      previous_keyframe_chunk_index: previous.chunk_index,
      game_chunk_index: gameChunk,
      next_keyframe_chunk_index: next.chunk_index,
      hero_raw_param: game.hero_raw_param,
      participant_id_candidate: participant,
      observation_kind: 'GAME_BROADCAST_PACKET_BRACKETED_BY_ADJACENT_KEYFRAMES',
      observation_scope: 'EXPLICIT_GAME_PACKET_RECORDS_AND_KEYFRAME_ENDPOINTS',
      record_count: records.length,
      record_comparisons_candidate: records,
      unrecorded_game_slots_candidate: Array.from({ length: 10 }, (_, slot) => slot)
        .filter((slot) => !seenSlots.has(slot)),
      confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
      field_confidence: {
        previous_observation_time_ms: 'VERIFIED_DIRECT',
        game_observation_time_ms: 'VERIFIED_DIRECT',
        next_observation_time_ms: 'VERIFIED_DIRECT',
        participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
        record_comparisons_candidate: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS',
      },
      raw_packet_ref: middleRef,
      previous_raw_packet_ref: previousRef,
      game_raw_packet_ref: middleRef,
      next_raw_packet_ref: nextRef,
      raw_packet_refs: [previousRef, middleRef, nextRef],
    });
  }
  return {
    ...base,
    status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    replay_sha256: replay.source_sha256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256,
    input_count: source.event_count,
    keyframe_count: orderedFrames.length,
    broadcast_keyframe_packet_count: keyframePackets,
    game_broadcast_packet_count: games.length,
    bracketed_game_broadcast_count: events.length,
    excluded_noncanonical_game_broadcast_count: noncanonicalRefs.length,
    excluded_before_first_keyframe_count: excludedBefore.length,
    excluded_after_last_keyframe_count: excludedAfter.length,
    excluded_on_boundary_count: excludedBoundary.length,
    excluded_noncanonical_game_broadcast_packet_refs: structuredClone(noncanonicalRefs),
    excluded_before_first_keyframe_refs: structuredClone(excludedBefore),
    excluded_after_last_keyframe_refs: structuredClone(excludedAfter),
    excluded_on_boundary_refs: structuredClone(excludedBoundary),
    record_comparison_count: recordComparisonCount,
    distinct_participant_interval_count: distinctIntervals.size,
    comparison_counts: comparisonCounts,
    verified_raw_packet_count: interval.verified_raw_packet_count,
    event_count: events.length,
    events,
  };
}

module.exports = {
  INVENTORY_GAME_BROADCAST_KEYFRAME_BRACKET_821_PROFILE,
  associateInventoryGameBroadcastKeyframeBracketCandidates821,
};
