'use strict';

// Replay-scoped cross-route research only. It does not assign an actor to any
// movement packet or modify the packet decoders' candidate events.
const { isDeepStrictEqual } = require('node:util');

const { parseMetadataTail } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { HERO_INVENTORY_PACKET_CANDIDATE_PROFILE_821 } =
  require('./rofl_16_19_821_inventory_packet_candidate');
const { DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE_PROFILE_821 } =
  require('./rofl_16_19_821_direct_input_turn_packet_candidate');
const { SET_MOVEMENT_DRIVER_PACKET_CANDIDATE_PROFILE_821 } =
  require('./rofl_16_19_821_set_movement_driver_packet_candidate');

const BUILD = '16.19.821.7343';
const CANONICAL_FIRST = 0x400000ae;
const CANONICAL_LAST = 0x400000b7;
const MAX_INPUT_EVENTS = 100_000;
const REASONS = Object.freeze([
  'noncanonical_raw_param', 'missing_snapshot_full_key', 'missing_inventory_full_key',
  'no_unique_exact_tail_match', 'snapshot_inventory_conflict',
]);
const ROUTES = Object.freeze({
  inventory: {
    packetId: 0x018d, stream: ['game_chunk'], field: 'hero_raw_param',
    eventType: 'HERO_INVENTORY_MAPVIEW_PACKET_CANDIDATE',
    profileId: HERO_INVENTORY_PACKET_CANDIDATE_PROFILE_821.id,
  },
  snapshot: {
    packetId: 0x0089, stream: ['keyframe'], field: 'hero_raw_param',
  },
  direct: {
    packetId: 0x00ba, stream: ['game_chunk', 'keyframe'], field: 'raw_param',
    eventType: 'DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE',
    profileId: DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE_PROFILE_821.id,
  },
  set: {
    packetId: 0x0335, stream: ['game_chunk'], field: 'raw_param',
    eventType: 'SET_MOVEMENT_DRIVER_PACKET_CANDIDATE',
    profileId: SET_MOVEMENT_DRIVER_PACKET_CANDIDATE_PROFILE_821.id,
  },
});

function u32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
}

function sameSourcePath(left, right) {
  return left === right || (typeof left === 'string' && typeof right === 'string'
    && process.platform === 'win32' && left.toLowerCase() === right.toLowerCase());
}

function position(row) {
  const ref = row.raw_packet_ref;
  return [ref.chunk_index, ref.decompressed_block_offset];
}

function comparePosition(left, right) {
  const a = position(left);
  const b = position(right);
  return a[0] - b[0] || a[1] - b[1];
}

function assertRow(replay, row, route, seenPositions) {
  const descriptor = ROUTES[route];
  const ref = row?.raw_packet_ref;
  const param = row?.[descriptor.field];
  const chunk = Number.isSafeInteger(ref?.chunk_index)
    ? replay.chunks[ref.chunk_index] : null;
  const snapshotProfile = route === 'snapshot'
    && /^rofl-16\.19\.821\.7343-kr-[a-z0-9-]+$/.test(row?.build_profile ?? '')
    && /^HERO_[A-Z0-9_]+_SNAPSHOT_CANDIDATE$/.test(row?.event_type ?? '');
  if (!row || row.game_version !== BUILD || row.confidence !== 'CANDIDATE'
      || typeof row.semantic_status !== 'string'
      || !row.semantic_status.startsWith('CANDIDATE_')
      || (route === 'snapshot' ? !snapshotProfile
        : row.event_type !== descriptor.eventType || row.build_profile !== descriptor.profileId)
      || row.replay_sha256 !== replay.source_sha256
      || !Number.isSafeInteger(row.replay_time_ms) || row.replay_time_ms < 0
      || !u32(param) || !ref || ref.replay_sha256 !== replay.source_sha256
      || !sameSourcePath(ref.source_path, replay.source_path)
      || ref.packet_id !== descriptor.packetId || ref.raw_param !== param
      || ref.replay_time_ms !== row.replay_time_ms
      || !descriptor.stream.includes(ref.chunk_stream)
      || !chunk || chunk.index !== ref.chunk_index
      || chunk.chunk_id !== ref.chunk_id || chunk.stream !== ref.chunk_stream
      || chunk.offset !== ref.chunk_file_offset
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || !Number.isSafeInteger(ref.payload_length)
      || ref.decompressed_block_offset < 0
      || ref.decompressed_payload_offset <= ref.decompressed_block_offset
      || ref.payload_length < 0
      || ref.decompressed_payload_offset + ref.payload_length > chunk.uncompressed_length
      || !/^[0-9a-f]{64}$/.test(ref.raw_payload_sha256 ?? '')) {
    throw new TypeError(`${route} candidate row has inconsistent Replay-scoped decoder reference metadata`);
  }
  const packetPosition = `${ref.chunk_index}:${ref.decompressed_block_offset}`;
  if (seenPositions.has(packetPosition)) {
    throw new TypeError('candidate raw packet position is duplicated across input routes');
  }
  seenPositions.add(packetPosition);
  if (route === 'snapshot') {
    if (ref.payload_length !== 1263
        || param < CANONICAL_FIRST || param > CANONICAL_LAST
        || !Number.isSafeInteger(row.participant_id_candidate)
        || row.participant_id_candidate < 1 || row.participant_id_candidate > 10) {
      throw new TypeError('snapshot candidate has invalid canonical participant evidence');
    }
  } else if (route === 'inventory') {
    if (ref.payload_length < 23 || ref.payload_length > 159
        || row.snapshot_application !== 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS'
        || !Array.isArray(row.records_candidate)
        || row.record_count !== row.records_candidate.length) {
      throw new TypeError('inventory candidate has invalid slot/item records');
    }
    let priorSlot = -1;
    for (let index = 0; index < row.records_candidate.length; index += 1) {
      const record = row.records_candidate[index];
      if (record?.record_index !== index
          || !Number.isSafeInteger(record.slot_candidate)
          || record.slot_candidate <= priorSlot || record.slot_candidate > 9
          || !u32(record.item_id_candidate) || record.item_id_candidate === 0) {
        throw new TypeError('inventory candidate has invalid slot/item records');
      }
      priorSlot = record.slot_candidate;
    }
    if (row.packet_slot_snapshot_candidate !== undefined) {
      const expected = Array.from({ length: 10 }, (_, slot) => ({
        slot_candidate: slot, item_id_candidate: null,
        value_basis: 'CALLBACK_RESET_WITH_NO_PACKET_RECORD',
      }));
      for (const record of row.records_candidate) expected[record.slot_candidate] = {
        slot_candidate: record.slot_candidate,
        item_id_candidate: record.item_id_candidate,
        value_basis: 'DECODED_PACKET_RECORD',
      };
      if (!isDeepStrictEqual(row.packet_slot_snapshot_candidate, expected)) {
        throw new TypeError('inventory packet slot snapshot disagrees with decoded records');
      }
    }
  } else if (route === 'direct') {
    if (ref.payload_length !== 13
        || ![row.opaque_f32_0x10, row.opaque_f32_0x14, row.opaque_f32_0x18]
      .every(Number.isFinite)) {
      throw new TypeError('direct-input candidate has invalid opaque packet fields');
    }
  } else if (!((row.raw_payload_byte_0 === 0x26 && ref.payload_length === 28
      && row.opaque_u8_0x2a === 2)
      || (row.raw_payload_byte_0 === 0x54 && ref.payload_length === 2
        && row.opaque_u8_0x2a === 1))) {
    throw new TypeError('SetMovementDriver candidate has invalid opaque packet fields');
  }
}

function appendByParam(map, row, field) {
  const key = row[field];
  const rows = map.get(key) ?? [];
  rows.push(row);
  map.set(key, rows);
}

function latest(rows) {
  return rows.reduce((best, row) => {
    if (!best || row.replay_time_ms > best.replay_time_ms
        || (row.replay_time_ms === best.replay_time_ms && comparePosition(row, best) > 0)) {
      return row;
    }
    return best;
  }, null);
}

function inventorySlots(row) {
  if (row.packet_slot_snapshot_candidate !== undefined) {
    return row.packet_slot_snapshot_candidate.slice(0, 7)
      .map((slot) => slot.item_id_candidate ?? 0);
  }
  const slots = Array(7).fill(0);
  for (const record of row.records_candidate) {
    if (record.slot_candidate < 7) slots[record.slot_candidate] = record.item_id_candidate;
  }
  return slots;
}

function refsFor(rows) {
  if (!rows?.length) return null;
  const sorted = [...rows].sort(comparePosition);
  return {
    packet_count: sorted.length,
    first_raw_packet_ref: structuredClone(sorted[0].raw_packet_ref),
    last_raw_packet_ref: structuredClone(sorted.at(-1).raw_packet_ref),
  };
}

function analyzeMovementParticipantAssociations821(replay, {
  inventoryEvents, snapshotEvents, directInputEvents = null,
  setMovementDriverEvents = null,
} = {}) {
  if (replay?.header?.version !== BUILD) {
    throw new TypeError(`movement participant association requires ${BUILD} Replay`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) throw new TypeError(`Replay source integrity failed: ${sourceError}`);
  const parsedTail = parseMetadataTail(replay.buffer, replay.header.size);
  if (!isDeepStrictEqual(parsedTail.stats, replay.tail?.stats)) {
    throw new TypeError('Replay tail participant rows differ from source bytes');
  }
  if (!Array.isArray(parsedTail.stats) || parsedTail.stats.length !== 10) {
    throw new TypeError('movement participant association requires ten Replay-tail participants');
  }
  const tailItems = parsedTail.stats.map((stat) => Array.from({ length: 7 }, (_, index) => {
    const raw = stat?.[`ITEM${index}`];
    if (!(typeof raw === 'string' && /^\d+$/.test(raw)) && !u32(raw)) {
      throw new TypeError(`Replay-tail ITEM${index} is missing or invalid`);
    }
    const value = Number(raw);
    if (!u32(value)) throw new TypeError(`Replay-tail ITEM${index} exceeds u32`);
    return value;
  }));
  if (!Array.isArray(inventoryEvents) || !Array.isArray(snapshotEvents)
      || (directInputEvents === null && setMovementDriverEvents === null)
      || (directInputEvents !== null && !Array.isArray(directInputEvents))
      || (setMovementDriverEvents !== null && !Array.isArray(setMovementDriverEvents))) {
    throw new TypeError('association requires inventory, one snapshot, and at least one movement event array');
  }
  const selected = { direct: directInputEvents, set: setMovementDriverEvents };
  const allArrays = [inventoryEvents, snapshotEvents,
    ...Object.values(selected).filter((rows) => rows !== null)];
  if (allArrays.reduce((count, rows) => count + rows.length, 0) > MAX_INPUT_EVENTS) {
    throw new TypeError('association event input exceeds bounded limit');
  }
  const seenPositions = new Set();
  for (const row of inventoryEvents) assertRow(replay, row, 'inventory', seenPositions);
  for (const row of snapshotEvents) assertRow(replay, row, 'snapshot', seenPositions);
  for (const [route, rows] of Object.entries(selected)) {
    if (rows !== null) for (const row of rows) assertRow(replay, row, route, seenPositions);
  }

  const snapshotByParam = new Map();
  const participantParams = new Map();
  const snapshotProfileIds = new Set();
  for (const row of snapshotEvents) {
    snapshotProfileIds.add(row.build_profile);
    const previous = snapshotByParam.get(row.hero_raw_param);
    if (previous && previous[0].participant_id_candidate !== row.participant_id_candidate) {
      throw new TypeError('0x0089 snapshot candidate participant assignment conflicts across rows');
    }
    appendByParam(snapshotByParam, row, 'hero_raw_param');
    const priorParam = participantParams.get(row.participant_id_candidate);
    if (priorParam !== undefined && priorParam !== row.hero_raw_param) {
      throw new TypeError('0x0089 snapshot candidate roster is not one-to-one');
    }
    participantParams.set(row.participant_id_candidate, row.hero_raw_param);
  }
  if (snapshotProfileIds.size !== 1 || snapshotByParam.size !== 10
      || participantParams.size !== 10) {
    throw new TypeError('association requires one complete 0x0089 snapshot candidate roster');
  }
  const inventoryByParam = new Map();
  for (const row of inventoryEvents) appendByParam(inventoryByParam, row, 'hero_raw_param');
  const movementByRoute = {};
  for (const [route, rows] of Object.entries(selected)) {
    if (rows === null) continue;
    const byParam = new Map();
    for (const row of rows) appendByParam(byParam, row, 'raw_param');
    movementByRoute[route] = byParam;
  }
  const routeNames = Object.keys(movementByRoute);
  const keys = new Set(routeNames.flatMap((route) => [...movementByRoute[route].keys()]));
  const excludedRowsByReason = Object.fromEntries(REASONS.map((reason) =>
    [reason, { direct: 0, set: 0 }]));
  const excludedKeySamples = [];
  const associations = [];
  const sharedKeyRows = { direct: 0, set: 0 };
  for (const rawParam of [...keys].sort((a, b) => a - b)) {
    const routeRows = Object.fromEntries(routeNames.map((route) =>
      [route, movementByRoute[route].get(rawParam) ?? []]));
    let reason = null;
    if (rawParam < CANONICAL_FIRST || rawParam > CANONICAL_LAST) {
      reason = 'noncanonical_raw_param';
    } else if (!snapshotByParam.has(rawParam)) {
      reason = 'missing_snapshot_full_key';
    } else if (!inventoryByParam.has(rawParam)) {
      reason = 'missing_inventory_full_key';
    }
    let matchedParticipant = null;
    let inventory = null;
    let snapshot = null;
    if (!reason) {
      inventory = latest(inventoryByParam.get(rawParam));
      snapshot = latest(snapshotByParam.get(rawParam));
      const slots = inventorySlots(inventory);
      const exact = tailItems.flatMap((tail, index) =>
        tail.every((value, slot) => value === slots[slot]) ? [index + 1] : []);
      if (exact.length !== 1) {
        reason = 'no_unique_exact_tail_match';
      } else if (exact[0] !== snapshot.participant_id_candidate
          || (inventory.participant_id_candidate !== null
            && inventory.participant_id_candidate !== exact[0])) {
        reason = 'snapshot_inventory_conflict';
      } else {
        matchedParticipant = exact[0];
      }
    }
    if (reason) {
      for (const [route, rows] of Object.entries(routeRows)) {
        excludedRowsByReason[reason][route] += rows.length;
      }
      if (excludedKeySamples.length < 20) {
        excludedKeySamples.push({ raw_param: rawParam,
          raw_param_hex: `0x${rawParam.toString(16).padStart(8, '0')}`,
          reason, packet_counts: Object.fromEntries(routeNames.map((route) =>
            [route, routeRows[route].length])) });
      }
      continue;
    }
    for (const [route, rows] of Object.entries(routeRows)) sharedKeyRows[route] += rows.length;
    associations.push({
      status: 'CANDIDATE',
      raw_param: rawParam,
      raw_param_hex: `0x${rawParam.toString(16).padStart(8, '0')}`,
      participant_id_candidate: matchedParticipant,
      inventory_snapshot_time_ms: inventory.replay_time_ms,
      replay_tail_item_slot_match_count: 7,
      inventory_raw_packet_ref: structuredClone(inventory.raw_packet_ref),
      snapshot_raw_packet_ref: structuredClone(snapshot.raw_packet_ref),
      movement_routes: Object.fromEntries(routeNames.filter((route) => routeRows[route].length > 0)
        .map((route) =>
        [route === 'direct' ? 'direct_input_movement_turn_packet'
          : 'set_movement_driver_packet', refsFor(routeRows[route])])),
    });
  }
  const selectedRows = Object.fromEntries(routeNames.map((route) =>
    [route, selected[route].length]));
  return {
    status: associations.length ? 'CANDIDATE' : 'UNAVAILABLE',
    evidence_status: 'CANDIDATE_821_FULL_PARAM_INVENTORY_TAIL_AND_KEYFRAME_ASSOCIATION',
    input_scope: 'CALLER_SUPPLIED_COMPLETE_TRUSTED_DECODER_EVENT_ARRAYS',
    game_version: BUILD,
    replay_sha256: replay.source_sha256,
    selected_movement_routes: routeNames.map((route) => route === 'direct'
      ? 'direct_input_movement_turn_packet' : 'set_movement_driver_packet'),
    snapshot_profile_id: [...snapshotProfileIds][0],
    input_counts: { inventory: inventoryEvents.length, snapshot: snapshotEvents.length,
      ...selectedRows },
    association_count: associations.length,
    movement_rows_sharing_candidate_full_key: Object.fromEntries(routeNames.map((route) =>
      [route, sharedKeyRows[route]])),
    excluded_movement_packet_counts_by_reason: Object.fromEntries(REASONS.map((reason) =>
      [reason, Object.fromEntries(routeNames.map((route) =>
        [route, excludedRowsByReason[reason][route]]))])),
    excluded_key_samples: excludedKeySamples,
    associations,
    known_limits: [
      'Replay-scoped, full-parameter cross-route candidate only; no per-packet callback hit or receiver-to-roster binding is proven.',
      'Only a unique 7/7 latest inventory-to-tail item match corroborated by one complete 0x0089 snapshot candidate roster is emitted.',
      'Movement row counts describe exact shared-key coverage, not independently observed per-packet actor identity.',
      'The supplied arrays are trusted decoder outputs: the utility rechecks Replay source bytes, tail, and reference metadata, but does not rewalk each referenced packet payload.',
      'The caller must supply complete selected decoder event arrays for this Replay; subsets can change the last inventory packet and shared-key row counts.',
      'Noncanonical +0x100/+0x200/+0x300 raw-parameter variants remain unbound even when their low byte matches a roster key.',
      'No movement event is modified; no actor, position, path or driver-state transition is inferred.',
    ],
  };
}

module.exports = { analyzeMovementParticipantAssociations821 };
