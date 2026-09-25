'use strict';

// This derives differences between two sampled keyframe packet values. It does
// not locate when a slot changed or classify any inventory action in between.
const crypto = require('node:crypto');
const { decompressChunk, parseBlockAt } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const {
  HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821: BROADCAST_PROFILE,
} = require('./rofl_16_19_821_inventory_broadcast_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = BROADCAST_PROFILE.evidence_runtime_image_sha256;
const FIRST_PARAM = 0x400000ae;
const LAST_PARAM = 0x400000b7;
const MAX_ROWS = 10_000;
const EVIDENCE_STATUS = 'CANDIDATE_821_ADJACENT_KEYFRAME_INVENTORY_SLOT_DIFFERENCE';

const INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-inventory-keyframe-interval-difference-candidate-v1',
  replay_version: BUILD,
  capability: 'inventory_keyframe_interval_difference',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze(['hero_inventory_broadcast_packet']),
  packet_id: 0x0357,
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_scope: 'exact 16.19.821.7343 Broadcast candidate packets with complete canonical ten-participant keyframes',
  known_limits: Object.freeze([
    'Each row compares two adjacent sampled keyframes for one candidate participant; game-stream Broadcast packets and other changes may occur between them.',
    'The previous and current item keys are packet-local exact-runtime candidates, including zero as an observed key.',
    'The time of any intervening change is unavailable; the row is not a purchase, sale, swap, replacement, or inventory lifecycle event.',
    'Participant identity remains candidate-only from the canonical KR 821 raw-param family.',
    'Every Replay keyframe chunk must have a complete ten-participant Broadcast roster and strictly increasing keyframe times.',
    'Pairing uses unique canonical roster entries and verified packet references, independent of participant packet order within a keyframe.',
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

function refPosition(ref) {
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
    && nonnegative(ref.payload_length) && u32(ref.raw_param)
    && sha(ref.raw_payload_sha256)
    && !!chunk && chunk.index === ref.chunk_index && chunk.chunk_id === ref.chunk_id
    && chunk.stream === stream && chunk.stream_tag === (stream === 'keyframe' ? 2 : 1)
    && chunk.offset === ref.chunk_file_offset
    && nonnegative(chunk.uncompressed_length)
    && ref.decompressed_payload_offset + ref.payload_length <= chunk.uncompressed_length;
}

function validRecords(row, stream) {
  const records = row.records_candidate;
  const snapshot = row.packet_slot_snapshot_candidate;
  if (row.snapshot_application !== 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS'
      || !Array.isArray(records) || !Array.isArray(snapshot) || snapshot.length !== 10
      || row.record_count !== records.length
      || (stream === 'keyframe' ? records.length !== 10
        : records.length < 6 || records.length > 9)) return false;
  const values = Array(10).fill(null);
  let priorSlot = -1;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (record?.record_index !== index || !nonnegative(record.slot_candidate)
        || record.slot_candidate > (stream === 'keyframe' ? 9 : 8)
        || record.slot_candidate <= priorSlot
        || (stream === 'keyframe' && record.slot_candidate !== index)
        || !u32(record.item_id_candidate)) return false;
    priorSlot = record.slot_candidate;
    values[priorSlot] = record.item_id_candidate;
  }
  return snapshot.every((entry, slot) => entry?.slot_candidate === slot
    && entry.item_id_candidate === values[slot]
    && entry.value_basis === (values[slot] === null
      ? 'CALLBACK_RESET_WITH_NO_PACKET_RECORD' : 'DECODED_PACKET_RECORD'));
}

function verifyRawPackets(replay, refs) {
  const expected = new Map();
  const chunkIndices = new Set();
  for (const ref of refs) {
    const at = refPosition(ref);
    if (expected.has(at)) {
      return { error: `duplicate physical Broadcast packet reference at ${at}` };
    }
    expected.set(at, ref);
    chunkIndices.add(ref.chunk_index);
  }
  for (const chunk of replay.chunks) {
    if (chunk.stream === 'keyframe') chunkIndices.add(chunk.index);
  }
  const verifiedCount = expected.size;
  try {
    for (const chunkIndex of chunkIndices) {
      const body = decompressChunk(replay.buffer, replay.chunks[chunkIndex]);
      const state = { timestamp: 0, packet_id: 0, param: 0 };
      let cursor = 0;
      while (cursor < body.length) {
        const block = parseBlockAt(body, cursor, state);
        const at = `${chunkIndex}/${block.offset}`;
        const ref = expected.get(at);
        if (replay.chunks[chunkIndex].stream === 'keyframe'
            && block.packet_id === 0x0357 && !ref) {
          return { error: `keyframe Broadcast packet is missing from source outcome at ${at}` };
        }
        if (ref) {
          const payloadSha = crypto.createHash('sha256').update(block.payload).digest('hex');
          if (block.packet_id !== ref.packet_id
              || block.timestamp_ms !== ref.replay_time_ms
              || (block.param >>> 0) !== ref.raw_param
              || block.payload_offset !== ref.decompressed_payload_offset
              || block.payload_length !== ref.payload_length
              || payloadSha !== ref.raw_payload_sha256) {
            return { error: `Broadcast packet reference differs from Replay block at ${at}` };
          }
          expected.delete(at);
        }
        cursor = block.next_offset;
      }
    }
  } catch (error) {
    return { error: `Replay packet verification failed: ${error.message}`, scan_error: true };
  }
  if (expected.size) {
    return { error: `Broadcast packet reference absent at ${expected.keys().next().value}` };
  }
  return { verified_count: verifiedCount };
}

function deriveInventoryKeyframeIntervalDifferenceCandidates821(replay, {
  inventoryBroadcastOutcome,
} = {}) {
  const profile = INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE;
  const base = {
    profile_id: profile.id,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    depends_on: [...profile.depends_on],
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: null, replay_sha256: replay?.source_sha256 ?? null,
    input_count: null, keyframe_count: null, broadcast_keyframe_packet_count: null,
    excluded_game_broadcast_count: null, observed_interval_count: null,
    changed_interval_count: null, unchanged_interval_count: null,
    changed_slot_count: null, verified_raw_packet_count: null,
    event_count: null, events: null, error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `inventory keyframe interval difference supports only ${BUILD}`);
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
    return fail('INCONSISTENT', 'inventory Broadcast dependency identity differs', {
      dependency_status: source.status ?? null,
    });
  }
  if (source.status !== 'CANDIDATE') {
    const propagated = ['MISSING_INPUT', 'PROFILE_UNAVAILABLE', 'UNSUPPORTED',
      'DECODE_FAILED', 'INCONSISTENT'].includes(source.status)
      ? source.status : 'INCONSISTENT';
    return fail(propagated, 'inventory Broadcast candidate decoder is unavailable', {
      dependency_status: source.status ?? null,
    });
  }
  if (source.runtime_image_sha256 !== IMAGE_SHA256
      || source.runtime_image_status !== 'MATCHED_USED'
      || source.runtime_image_used !== true
      || source.input_packet_id !== 0x0357
      || !count(source.input_count) || !count(source.event_count)
      || source.event_count === 0
      || source.input_count !== source.event_count
      || !count(source.decoded_record_count)
      || !Array.isArray(source.events) || source.events.length !== source.event_count) {
    return fail('INCONSISTENT', 'exact-build Broadcast outcome identity, image, or counts differ');
  }
  const frames = new Map();
  const refs = [];
  let gameCount = 0;
  let keyframePacketCount = 0;
  let decodedRecordCount = 0;
  for (const [eventIndex, row] of source.events.entries()) {
    const ref = row?.raw_packet_ref;
    const stream = row?.packet_stream;
    const participant = participantFor(row?.hero_raw_param);
    if (row?.event_type !== 'HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE'
        || row.game_version !== BUILD || row.patch !== '16.19'
        || row.build_profile !== BROADCAST_PROFILE.id
        || row.replay_sha256 !== replay.source_sha256
        || row.confidence !== 'CANDIDATE'
        || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS'
        || !['keyframe', 'game_chunk'].includes(stream)
        || !validRef(replay, ref, stream)
        || ref.payload_length < 76 || ref.payload_length > 166
        || row.replay_time_ms !== ref.replay_time_ms
        || row.hero_raw_param !== ref.raw_param
        || row.participant_id_candidate !== participant
        || !validRecords(row, stream)) {
      return fail('INCONSISTENT', 'Broadcast source row identity, records, or packet reference differ', {
        event_index: eventIndex,
      });
    }
    decodedRecordCount += row.record_count;
    refs.push(ref);
    if (stream === 'game_chunk') {
      gameCount += 1;
      continue;
    }
    if (participant === null) {
      return fail('INCONSISTENT', 'keyframe Broadcast participant is noncanonical', {
        event_index: eventIndex,
      });
    }
    keyframePacketCount += 1;
    const frame = frames.get(ref.chunk_index) ?? {
      chunk_index: ref.chunk_index, replay_time_ms: ref.replay_time_ms,
      participants: new Map(),
    };
    if (frame.replay_time_ms !== ref.replay_time_ms
        || frame.participants.has(participant)) {
      return fail('INCONSISTENT', 'keyframe Broadcast has multiple times or a duplicate participant', {
        event_index: eventIndex, chunk_index: ref.chunk_index,
      });
    }
    frame.participants.set(participant, row);
    frames.set(ref.chunk_index, frame);
  }
  if (decodedRecordCount !== source.decoded_record_count) {
    return fail('INCONSISTENT', 'Broadcast decoded record count differs from its rows');
  }
  const replayKeyframeChunks = replay.chunks.filter((chunk) => chunk.stream === 'keyframe');
  if (replayKeyframeChunks.length === 0) {
    return fail('PROFILE_UNAVAILABLE', 'Replay has no inventory Broadcast keyframe scope', {
      excluded_game_broadcast_count: gameCount,
    });
  }
  if (frames.size !== replayKeyframeChunks.length
      || replayKeyframeChunks.some((chunk) => !frames.has(chunk.index))) {
    return fail('INCONSISTENT', 'Broadcast source lacks one or more Replay keyframe chunks');
  }
  if (keyframePacketCount !== frames.size * 10
      || [...frames.values()].some((frame) => frame.participants.size !== 10)) {
    return fail('INCONSISTENT', 'inventory Broadcast keyframe lacks a complete ten-participant roster');
  }
  const orderedFrames = [...frames.values()].sort((a, b) => a.chunk_index - b.chunk_index);
  for (let index = 1; index < orderedFrames.length; index += 1) {
    if (orderedFrames[index].replay_time_ms <= orderedFrames[index - 1].replay_time_ms) {
      return fail('INCONSISTENT', 'inventory Broadcast keyframe times are not strictly increasing', {
        previous_chunk_index: orderedFrames[index - 1].chunk_index,
        current_chunk_index: orderedFrames[index].chunk_index,
      });
    }
  }
  const physical = verifyRawPackets(replay, refs);
  if (physical.error) {
    return fail(physical.scan_error ? 'DECODE_FAILED' : 'INCONSISTENT', physical.error);
  }
  const events = [];
  let unchangedIntervals = 0;
  let changedSlotCount = 0;
  for (let index = 1; index < orderedFrames.length; index += 1) {
    const previous = orderedFrames[index - 1];
    const current = orderedFrames[index];
    for (let participant = 1; participant <= 10; participant += 1) {
      const previousRow = previous.participants.get(participant);
      const currentRow = current.participants.get(participant);
      const changedSlots = [];
      for (let slot = 0; slot < 10; slot += 1) {
        const previousId = previousRow.packet_slot_snapshot_candidate[slot].item_id_candidate;
        const currentId = currentRow.packet_slot_snapshot_candidate[slot].item_id_candidate;
        if (previousId !== currentId) {
          changedSlots.push({
            slot_candidate: slot,
            previous_item_id_candidate: previousId,
            current_item_id_candidate: currentId,
          });
        }
      }
      if (!changedSlots.length) {
        unchangedIntervals += 1;
        continue;
      }
      changedSlotCount += changedSlots.length;
      const previousRef = structuredClone(previousRow.raw_packet_ref);
      const currentRef = structuredClone(currentRow.raw_packet_ref);
      events.push({
        event_type: 'INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: profile.id,
        replay_sha256: replay.source_sha256,
        replay_time_ms: current.replay_time_ms,
        previous_observation_time_ms: previous.replay_time_ms,
        current_observation_time_ms: current.replay_time_ms,
        observation_interval_ms: current.replay_time_ms - previous.replay_time_ms,
        previous_keyframe_chunk_index: previous.chunk_index,
        current_keyframe_chunk_index: current.chunk_index,
        hero_raw_param: currentRow.hero_raw_param,
        participant_id_candidate: participant,
        observation_kind: 'ADJACENT_KEYFRAME_SAMPLED_ENDPOINTS',
        observation_scope: 'KEYFRAME_ENDPOINT_DIFFERENCE_ONLY',
        change_time_status: 'UNRESOLVED_WITHIN_INTERVAL',
        changed_slot_count: changedSlots.length,
        changed_slots_candidate: changedSlots,
        confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
        field_confidence: {
          previous_observation_time_ms: 'VERIFIED_DIRECT',
          current_observation_time_ms: 'VERIFIED_DIRECT',
          participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
          changed_slots_candidate: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS',
        },
        raw_packet_ref: currentRef,
        previous_raw_packet_ref: previousRef,
        current_raw_packet_ref: currentRef,
        raw_packet_refs: [previousRef, currentRef],
      });
    }
  }
  const observedIntervals = Math.max(0, orderedFrames.length - 1) * 10;
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    replay_sha256: replay.source_sha256,
    input_count: source.event_count,
    keyframe_count: orderedFrames.length,
    broadcast_keyframe_packet_count: keyframePacketCount,
    excluded_game_broadcast_count: gameCount,
    observed_interval_count: observedIntervals,
    changed_interval_count: events.length,
    unchanged_interval_count: unchangedIntervals,
    changed_slot_count: changedSlotCount,
    verified_raw_packet_count: physical.verified_count,
    event_count: events.length, events,
  };
}

module.exports = {
  INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE,
  deriveInventoryKeyframeIntervalDifferenceCandidates821,
};
