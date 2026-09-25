'use strict';

// A physical keyframe join of two independent candidate decoders. It reports
// co-observed packet fields, not a ward action or inventory between packets.
const crypto = require('node:crypto');
const { decompressChunk, parseBlockAt } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { HERO_WARD_STATS_SNAPSHOT_821_CANDIDATE_PROFILE: WARD_PROFILE } =
  require('./rofl_16_19_821_aux_counts_candidate');
const { HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821: BROADCAST_PROFILE } =
  require('./rofl_16_19_821_inventory_broadcast_packet_candidate');
const { RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256, decodeRuntimeCountByte } =
  require('./rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const FIRST_PARAM = 0x400000ae;
const LAST_PARAM = 0x400000b7;
const MAX_ROWS = 10_000;
const EVIDENCE_STATUS = 'CANDIDATE_821_SAME_KEYFRAME_WARD_COUNT_INVENTORY_BROADCAST';

const WARD_INVENTORY_KEYFRAME_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-ward-inventory-keyframe-pair-candidate-v1',
  replay_version: BUILD,
  capability: 'ward_inventory_keyframe_pair',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze(['hero_ward_stats_snapshot', 'hero_inventory_broadcast_packet']),
  packet_ids: Object.freeze([0x0089, 0x0357]),
  evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
  evidence_scope: '11 exact KR 821 Replays: 3270 unique physical keyframe pairs; 61 game-stream Broadcast rows excluded',
  known_limits: Object.freeze([
    'A pair reports two candidate observations in the same Replay keyframe, time, and canonical raw-param scope; it is not one packet or a continuous state.',
    'Ward-count field labels remain Replay-tail candidate correlations, and Broadcast slot/item fields remain exact-image candidate decoding.',
    'No ward placement, removal, owner, location, purchase, item transaction, or inventory persistence is inferred.',
    'Unpaired, duplicate, source-mismatched, or contradictory keyframe rows fail the whole association.',
  ]),
});

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function nonnegative(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function u32(value) {
  return nonnegative(value) && value <= 0xffffffff;
}

function boundedCount(value) {
  return nonnegative(value) && value <= MAX_ROWS;
}

function canonicalParticipant(param) {
  return u32(param) && param >= FIRST_PARAM && param <= LAST_PARAM
    ? param - FIRST_PARAM + 1 : null;
}

function position(ref) {
  return `${ref.chunk_index}/${ref.decompressed_block_offset}`;
}

function key(ref) {
  return `${ref.chunk_index}/${ref.replay_time_ms}/${ref.raw_param}`;
}

function sameRef(a, b) {
  return a.source_path === b.source_path
    && a.replay_sha256 === b.replay_sha256
    && a.chunk_index === b.chunk_index
    && a.chunk_id === b.chunk_id
    && a.chunk_stream === b.chunk_stream
    && a.chunk_file_offset === b.chunk_file_offset
    && a.decompressed_block_offset === b.decompressed_block_offset
    && a.decompressed_payload_offset === b.decompressed_payload_offset
    && a.packet_id === b.packet_id
    && a.replay_time_ms === b.replay_time_ms
    && a.payload_length === b.payload_length
    && a.raw_param === b.raw_param
    && a.raw_payload_sha256 === b.raw_payload_sha256;
}

function validRef(replay, ref, packetId, stream) {
  const chunk = replay.chunks?.[ref?.chunk_index];
  return ref?.source_path === (replay.source_path ?? null)
    && ref.replay_sha256 === replay.source_sha256
    && nonnegative(ref.chunk_index) && nonnegative(ref.chunk_id)
    && ref.chunk_stream === stream && nonnegative(ref.chunk_file_offset)
    && nonnegative(ref.decompressed_block_offset)
    && nonnegative(ref.decompressed_payload_offset)
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.packet_id === packetId && nonnegative(ref.replay_time_ms)
    && nonnegative(ref.payload_length) && u32(ref.raw_param)
    && sha(ref.raw_payload_sha256)
    && !!chunk && chunk.index === ref.chunk_index && chunk.chunk_id === ref.chunk_id
    && chunk.stream === stream && chunk.stream_tag === (stream === 'keyframe' ? 2 : 1)
    && chunk.offset === ref.chunk_file_offset
    && nonnegative(chunk.uncompressed_length)
    && ref.decompressed_payload_offset + ref.payload_length <= chunk.uncompressed_length;
}

function validOutcome(outcome, profile, packetId) {
  return outcome?.status === 'CANDIDATE'
    && outcome.profile_id === profile.id
    && outcome.evidence_runtime_image_sha256 === RUNTIME_IMAGE_SHA256
    && outcome.input_packet_id === packetId
    && boundedCount(outcome.event_count) && outcome.event_count > 0
    && Array.isArray(outcome.events) && outcome.events.length === outcome.event_count;
}

function validBroadcastRecords(row, stream) {
  const records = row.records_candidate;
  const snapshot = row.packet_slot_snapshot_candidate;
  if (row.snapshot_application !== 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS'
      || !Array.isArray(records) || !Array.isArray(snapshot) || snapshot.length !== 10
      || row.record_count !== records.length
      || (stream === 'keyframe' ? records.length !== 10
        : records.length < 6 || records.length > 9)) return false;
  let previousSlot = -1;
  const values = Array(10).fill(null);
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (record?.record_index !== index || !nonnegative(record.slot_candidate)
        || record.slot_candidate > (stream === 'keyframe' ? 9 : 8)
        || record.slot_candidate <= previousSlot
        || (stream === 'keyframe' && record.slot_candidate !== index)
        || !u32(record.item_id_candidate)) return false;
    previousSlot = record.slot_candidate;
    values[previousSlot] = record.item_id_candidate;
  }
  return snapshot.every((entry, index) => entry?.slot_candidate === index
    && entry.item_id_candidate === values[index]
    && entry.value_basis === (values[index] === null
      ? 'CALLBACK_RESET_WITH_NO_PACKET_RECORD' : 'DECODED_PACKET_RECORD'));
}

function verifyPhysicalRefs(replay, refs) {
  const expected = new Map();
  const chunkIndices = new Set();
  const payloads = new Map();
  for (const ref of refs) {
    const at = position(ref);
    const prior = expected.get(at);
    if (prior && !sameRef(prior, ref)) {
      return { error: `conflicting raw packet references at ${at}` };
    }
    expected.set(at, ref);
    chunkIndices.add(ref.chunk_index);
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
        if (ref) {
          const payloadSha = crypto.createHash('sha256').update(block.payload).digest('hex');
          if (block.packet_id !== ref.packet_id
              || block.timestamp_ms !== ref.replay_time_ms
              || (block.param >>> 0) !== ref.raw_param
              || block.payload_offset !== ref.decompressed_payload_offset
              || block.payload_length !== ref.payload_length
              || payloadSha !== ref.raw_payload_sha256) {
            return { error: `raw packet reference differs from Replay block at ${at}` };
          }
          payloads.set(at, Buffer.from(block.payload));
          expected.delete(at);
        }
        cursor = block.next_offset;
      }
    }
  } catch (error) {
    return { error: `Replay packet scan failed: ${error.message}`, scan_error: true };
  }
  if (expected.size) {
    return { error: `raw packet reference is absent at ${expected.keys().next().value}` };
  }
  return { verified_count: verifiedCount, payloads };
}

function associateWardInventoryKeyframePairCandidates821(replay, {
  wardStatsOutcome, inventoryBroadcastOutcome,
} = {}) {
  const profile = WARD_INVENTORY_KEYFRAME_PAIR_821_PROFILE;
  const base = {
    profile_id: profile.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    depends_on: [...profile.depends_on],
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: null, event_count: null, events: null,
    ward_snapshot_count: null, broadcast_keyframe_count: null,
    excluded_game_broadcast_count: null, verified_raw_packet_count: null,
    error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `ward/inventory pair supports only ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  if (!sha(replay.source_sha256)) {
    return fail('INCONSISTENT', 'Replay SHA-256 is missing or malformed');
  }
  if (!wardStatsOutcome || !inventoryBroadcastOutcome) {
    return fail('MISSING_INPUT', 'both independently decoded outcomes are required', {
      missing_inputs: [
        ...(!wardStatsOutcome ? ['hero_ward_stats_snapshot'] : []),
        ...(!inventoryBroadcastOutcome ? ['hero_inventory_broadcast_packet'] : []),
      ],
    });
  }
  const ward = wardStatsOutcome;
  const broadcast = inventoryBroadcastOutcome;
  if (ward.status !== 'CANDIDATE' || broadcast.status !== 'CANDIDATE') {
    return fail('MISSING_INPUT', 'one or more candidate decoder outcomes are unavailable', {
      dependency_statuses: {
        hero_ward_stats_snapshot: ward.status ?? null,
        hero_inventory_broadcast_packet: broadcast.status ?? null,
      },
    });
  }
  if (!validOutcome(ward, WARD_PROFILE, 0x0089)
      || !validOutcome(broadcast, BROADCAST_PROFILE, 0x0357)
      || ward.lookup_table_sha256 !== LOOKUP_TABLE_SHA256
      || ward.runtime_image_used !== false
      || ward.runtime_image_status !== 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED'
      || ward.input_count !== ward.event_count
      || ward.observed_participant_count !== 10
      || broadcast.runtime_image_status !== 'MATCHED_USED'
      || broadcast.runtime_image_used !== true
      || broadcast.runtime_image_sha256 !== RUNTIME_IMAGE_SHA256
      || broadcast.input_count !== broadcast.event_count
      || !boundedCount(broadcast.decoded_record_count)) {
    return fail('INCONSISTENT', 'exact-build candidate outcome identity, image, or counts differ');
  }
  const wardByKey = new Map();
  const broadcastByKey = new Map();
  const refs = [];
  const keyframeRows = new Map();
  for (const [index, row] of ward.events.entries()) {
    const ref = row?.raw_packet_ref;
    const participant = canonicalParticipant(row?.hero_raw_param);
    if (row?.event_type !== 'HERO_WARD_STATS_SNAPSHOT_CANDIDATE'
        || row.game_version !== BUILD || row.build_profile !== WARD_PROFILE.id
        || row.replay_sha256 !== replay.source_sha256 || row.confidence !== 'CANDIDATE'
        || row.semantic_status !== 'CANDIDATE_821_RUNTIME_KEYFRAME_BYTE_AND_REPLAY_TAIL'
        || row.observation_kind !== 'KEYFRAME_SNAPSHOT'
        || !validRef(replay, ref, 0x0089, 'keyframe') || ref.payload_length !== 1263
        || participant === null || row.participant_id_candidate !== participant
        || row.replay_time_ms !== ref.replay_time_ms
        || row.hero_raw_param !== ref.raw_param
        || WARD_PROFILE.fields.some(({ key: name }) =>
          !nonnegative(row[`${name}_candidate`]) || row[`${name}_candidate`] > 255
          || !nonnegative(row[`raw_${name}_byte`]) || row[`raw_${name}_byte`] > 255)) {
      return fail('INCONSISTENT', 'ward snapshot row identity or packet reference differs',
        { source: 'hero_ward_stats_snapshot', event_index: index });
    }
    const at = key(ref);
    if (wardByKey.has(at)) {
      return fail('INCONSISTENT', 'duplicate ward keyframe participant', { key: at });
    }
    wardByKey.set(at, row);
    refs.push(ref);
    const frame = keyframeRows.get(ref.chunk_index) ?? {
      time: ref.replay_time_ms, count: 0, participants: new Set(),
    };
    if (frame.time !== ref.replay_time_ms) {
      return fail('INCONSISTENT', 'ward snapshot keyframe has multiple times',
        { chunk_index: ref.chunk_index });
    }
    frame.count += 1;
    frame.participants.add(participant);
    keyframeRows.set(ref.chunk_index, frame);
  }
  if (wardByKey.size % 10 !== 0
      || [...keyframeRows.values()].some((frame) =>
        frame.count !== 10 || frame.participants.size !== 10)) {
    return fail('INCONSISTENT', 'ward snapshot keyframe lacks a complete ten-participant roster');
  }
  let gameBroadcastCount = 0;
  let decodedRecordCount = 0;
  for (const [index, row] of broadcast.events.entries()) {
    const ref = row?.raw_packet_ref;
    const stream = row?.packet_stream;
    const participant = canonicalParticipant(row?.hero_raw_param);
    if (row?.event_type !== 'HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE'
        || row.game_version !== BUILD || row.build_profile !== BROADCAST_PROFILE.id
        || row.replay_sha256 !== replay.source_sha256 || row.confidence !== 'CANDIDATE'
        || row.semantic_status !== 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS'
        || !['keyframe', 'game_chunk'].includes(stream)
        || !validRef(replay, ref, 0x0357, stream)
        || ref.payload_length < 76 || ref.payload_length > 166
        || row.replay_time_ms !== ref.replay_time_ms
        || row.hero_raw_param !== ref.raw_param
        || row.participant_id_candidate !== participant
        || !validBroadcastRecords(row, stream)) {
      return fail('INCONSISTENT', 'Broadcast row identity, records, or packet reference differs',
        { source: 'hero_inventory_broadcast_packet', event_index: index });
    }
    decodedRecordCount += row.record_count;
    refs.push(ref);
    if (stream === 'game_chunk') {
      gameBroadcastCount += 1;
      continue;
    }
    if (participant === null) {
      return fail('INCONSISTENT', 'keyframe Broadcast row has noncanonical raw param',
        { event_index: index });
    }
    const at = key(ref);
    if (broadcastByKey.has(at)) {
      return fail('INCONSISTENT', 'duplicate Broadcast keyframe participant', { key: at });
    }
    broadcastByKey.set(at, row);
  }
  if (decodedRecordCount !== broadcast.decoded_record_count
      || wardByKey.size !== broadcastByKey.size) {
    return fail('INCONSISTENT', 'ward and Broadcast keyframe counts differ');
  }
  for (const at of wardByKey.keys()) {
    if (!broadcastByKey.has(at)) {
      return fail('INCONSISTENT', 'ward keyframe has no unique Broadcast partner', { key: at });
    }
  }
  if (new Set(refs.map(position)).size !== refs.length) {
    return fail('INCONSISTENT', 'candidate outcomes repeat a physical packet reference');
  }
  const physical = verifyPhysicalRefs(replay, refs);
  if (physical.error) {
    return fail(physical.scan_error ? 'DECODE_FAILED' : 'INCONSISTENT', physical.error);
  }
  const events = [];
  for (const [at, wardRow] of wardByKey) {
    const broadcastRow = broadcastByKey.get(at);
    const wardRef = wardRow.raw_packet_ref;
    const broadcastRef = broadcastRow.raw_packet_ref;
    const payload = physical.payloads.get(position(wardRef));
    if (!payload || WARD_PROFILE.fields.some(({ key: name, low_offset: offset }) =>
      payload[offset] !== wardRow[`raw_${name}_byte`]
      || [1, 2, 3].some((distance) => decodeRuntimeCountByte(payload[offset - distance]) !== 0)
      || decodeRuntimeCountByte(payload[offset]) !== wardRow[`${name}_candidate`])) {
      return fail('INCONSISTENT', 'ward candidate fields differ from physical Replay payload',
        { key: at });
    }
    if (broadcastRef.decompressed_block_offset >= wardRef.decompressed_block_offset) {
      return fail('INCONSISTENT', 'Broadcast/ward physical keyframe order differs', { key: at });
    }
    events.push({
      event_type: 'WARD_INVENTORY_KEYFRAME_PAIR_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: wardRow.replay_time_ms,
      hero_raw_param: wardRow.hero_raw_param,
      participant_id_candidate: wardRow.participant_id_candidate,
      observation_kind: 'SAME_KEYFRAME_PACKET_PAIR',
      ward_placed_detector_candidate: wardRow.ward_placed_detector_candidate,
      ward_killed_candidate: wardRow.ward_killed_candidate,
      ward_placed_candidate: wardRow.ward_placed_candidate,
      raw_ward_placed_detector_byte: wardRow.raw_ward_placed_detector_byte,
      raw_ward_killed_byte: wardRow.raw_ward_killed_byte,
      raw_ward_placed_byte: wardRow.raw_ward_placed_byte,
      inventory_record_count: broadcastRow.record_count,
      inventory_records_candidate: structuredClone(broadcastRow.records_candidate),
      inventory_packet_slot_snapshot_candidate:
        structuredClone(broadcastRow.packet_slot_snapshot_candidate),
      confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
      field_confidence: {
        replay_time_ms: 'VERIFIED_DIRECT',
        hero_raw_param: 'VERIFIED_DIRECT',
        participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
        ward_placed_detector_candidate: wardRow.field_confidence?.ward_placed_detector_candidate
          ?? 'CANDIDATE_821_RUNTIME_KEYFRAME_BYTE_AND_REPLAY_TAIL',
        ward_killed_candidate: wardRow.field_confidence?.ward_killed_candidate
          ?? 'CANDIDATE_821_RUNTIME_KEYFRAME_BYTE_AND_REPLAY_TAIL',
        ward_placed_candidate: wardRow.field_confidence?.ward_placed_candidate
          ?? 'CANDIDATE_821_RUNTIME_KEYFRAME_BYTE_AND_REPLAY_TAIL',
        inventory_records_candidate: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS',
        inventory_packet_slot_snapshot_candidate:
          'CANDIDATE_EXACT_RUNTIME_CALLBACK_APPLICATION_AND_RECORD_FIELDS',
      },
      raw_packet_ref: structuredClone(wardRef),
      ward_stats_raw_packet_ref: structuredClone(wardRef),
      inventory_broadcast_raw_packet_ref: structuredClone(broadcastRef),
      raw_packet_refs: [structuredClone(broadcastRef), structuredClone(wardRef)],
    });
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    replay_sha256: replay.source_sha256,
    ward_snapshot_count: wardByKey.size,
    broadcast_keyframe_count: broadcastByKey.size,
    excluded_game_broadcast_count: gameBroadcastCount,
    verified_raw_packet_count: physical.verified_count,
    event_count: events.length, events,
  };
}

module.exports = {
  WARD_INVENTORY_KEYFRAME_PAIR_821_PROFILE,
  associateWardInventoryKeyframePairCandidates821,
};
