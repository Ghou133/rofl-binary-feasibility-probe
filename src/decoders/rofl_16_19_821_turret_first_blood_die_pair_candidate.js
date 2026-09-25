'use strict';

// Relates independently decoded exact-image OnEvent children. The packet
// relation does not establish a turret, an actor, or a gameplay transition.
const crypto = require('node:crypto');
const { decompressChunk, parseBlockAt } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { TURRET_FIRST_BLOOD_EVENT_PACKET_821_PROFILE } =
  require('./rofl_16_19_821_turret_first_blood_event_packet_candidate');
const { TURRET_DIE_EVENT_PACKET_821_PROFILE } =
  require('./rofl_16_19_821_turret_die_event_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const MAX_EVENTS = 2_000;
const CANDIDATE_STATUS = 'CANDIDATE_821_TURRET_FIRST_BLOOD_DIE_PACKET_PAIR';

const TURRET_FIRST_BLOOD_DIE_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-turret-first-blood-die-packet-pair-candidate-v1',
  replay_version: BUILD,
  capability: 'turret_first_blood_die_pair',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze([
    'turret_first_blood_event_packet', 'turret_die_event_packet',
  ]),
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays: each of 11 native OnTurretFirstBlood child 0x003d packets uniquely follows one of 136 native OnTurretDie child 0x003b packets in the same game chunk and millisecond, without an intervening 0x040a OnEvent packet',
  known_limits: Object.freeze([
    'This is a packet-order association, not proof of an actual first turret death, actor, structure identity, or game-state effect.',
    'The two native child blobs remain anonymous. Their raw params and blob +0x04 values differ in observed pairs and are not equality gates.',
    'Both candidate routes must independently match the pinned exact-build runtime image and the same Replay source.',
    'An absent, ambiguous, reordered, intervened, or conflicting pair fails the Replay association without partial rows.',
  ]),
});

function u32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
}

function boundedCount(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_EVENTS;
}

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function payloadSha(payload) {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function key(ref) {
  return `${ref.chunk_index}/${ref.replay_time_ms}`;
}

function position(ref) {
  return `${ref.chunk_index}/${ref.decompressed_block_offset}`;
}

function validOutcome(outcome, profile, childId) {
  return outcome?.status === 'CANDIDATE'
    && outcome.profile_id === profile.id
    && outcome.evidence_runtime_image_sha256 === IMAGE_SHA256
    && outcome.runtime_image_sha256 === IMAGE_SHA256
    && outcome.runtime_image_status === 'MATCHED_USED'
    && outcome.runtime_image_used === true
    && outcome.input_packet_id === 0x040a
    && outcome.child_event_id === childId
    && Array.isArray(outcome.events)
    && boundedCount(outcome.event_count) && outcome.event_count > 0
    && outcome.event_count === outcome.events.length
    && boundedCount(outcome.input_count)
    && outcome.input_count === outcome.event_count
    && boundedCount(outcome.observed_same_length_packet_count)
    && boundedCount(outcome.excluded_same_length_foreign_count)
    && outcome.observed_same_length_packet_count
      === outcome.event_count + outcome.excluded_same_length_foreign_count;
}

function validRef(replay, ref, row) {
  if (!ref || ref.source_path !== (replay.source_path ?? null)
      || ref.replay_sha256 !== replay.source_sha256
      || ref.packet_id !== 0x040a || ref.payload_length !== 116
      || ref.raw_param !== row.raw_param || ref.replay_time_ms !== row.replay_time_ms
      || ref.chunk_stream !== 'game_chunk'
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id)
      || !Number.isSafeInteger(ref.chunk_file_offset)
      || !Number.isSafeInteger(ref.decompressed_block_offset)
      || !Number.isSafeInteger(ref.decompressed_payload_offset)
      || !sha(ref.raw_payload_sha256)) return false;
  const chunk = replay.chunks?.[ref.chunk_index];
  return !!chunk && chunk.index === ref.chunk_index
    && chunk.chunk_id === ref.chunk_id && chunk.stream === ref.chunk_stream
    && chunk.stream_tag === 1 && chunk.offset === ref.chunk_file_offset
    && Number.isSafeInteger(chunk.uncompressed_length)
    && ref.decompressed_block_offset >= 0
    && ref.decompressed_payload_offset > ref.decompressed_block_offset
    && ref.decompressed_payload_offset + ref.payload_length <= chunk.uncompressed_length;
}

function validRow(replay, row, profile, {
  type, childId, name, rawId, semanticStatus,
}) {
  return row?.event_type === type && row.game_version === BUILD
    && row.build_profile === profile.id
    && row.confidence === 'CANDIDATE'
    && row.semantic_status === semanticStatus
    && row.replay_sha256 === replay.source_sha256
    && Number.isSafeInteger(row.replay_time_ms) && row.replay_time_ms >= 0
    && row.event_id === childId && row.event_name === name
    && row.raw_event_id_hex === rawId
    && u32(row.raw_param) && row.raw_param !== 0
    && typeof row.event_blob_hex === 'string'
    && /^[0-9a-f]{216}$/.test(row.event_blob_hex)
    && sha(row.event_blob_sha256)
    && payloadSha(Buffer.from(row.event_blob_hex, 'hex')) === row.event_blob_sha256
    && validRef(replay, row.raw_packet_ref, row);
}

function verifyReplayPacketRefs(replay, refs) {
  const expected = new Map();
  const neededChunks = new Set();
  for (const ref of refs) {
    const packetPosition = position(ref);
    if (expected.has(packetPosition)) {
      return { error: `duplicate candidate raw packet position ${packetPosition}` };
    }
    expected.set(packetPosition, ref);
    neededChunks.add(ref.chunk_index);
  }
  const onEventOffsets = new Map();
  try {
    for (const chunkIndex of neededChunks) {
      const chunk = replay.chunks[chunkIndex];
      const body = decompressChunk(replay.buffer, chunk);
      const state = { timestamp: 0, packet_id: 0, param: 0 };
      const onEvent = [];
      let cursor = 0;
      while (cursor < body.length) {
        const block = parseBlockAt(body, cursor, state);
        if (block.packet_id === 0x040a) onEvent.push(block.offset);
        const packetPosition = `${chunkIndex}/${block.offset}`;
        const ref = expected.get(packetPosition);
        if (ref) {
          if (block.packet_id !== ref.packet_id
              || block.timestamp_ms !== ref.replay_time_ms
              || (block.param >>> 0) !== ref.raw_param
              || block.payload_length !== ref.payload_length
              || block.payload_offset !== ref.decompressed_payload_offset
              || payloadSha(block.payload) !== ref.raw_payload_sha256) {
            return { error: `candidate raw packet reference differs from Replay block at ${packetPosition}` };
          }
          expected.delete(packetPosition);
        }
        cursor = block.next_offset;
      }
      onEventOffsets.set(chunkIndex, onEvent);
    }
  } catch (error) {
    return { error: `Replay packet scan failed: ${error.message}`, scan_error: true };
  }
  if (expected.size) {
    return { error: `candidate raw packet reference is absent at ${expected.keys().next().value}` };
  }
  return { onEventOffsets };
}

function associateTurretFirstBloodDieCandidates821(replay, {
  turretFirstBloodEventPacketOutcome, turretDieEventPacketOutcome,
} = {}) {
  const profile = TURRET_FIRST_BLOOD_DIE_PAIR_821_PROFILE;
  const base = {
    profile_id: profile.id,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    depends_on: [...profile.depends_on],
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status,
    evidence_status: status === 'INCONSISTENT' ? 'INCONSISTENT' : null,
    event_count: null, pair_count: null, events: null,
    turret_first_blood_count: Array.isArray(turretFirstBloodEventPacketOutcome?.events)
      ? turretFirstBloodEventPacketOutcome.events.length : null,
    turret_die_count: Array.isArray(turretDieEventPacketOutcome?.events)
      ? turretDieEventPacketOutcome.events.length : null,
    error, diagnostics,
  });
  if (replay?.header?.version !== BUILD) {
    return fail('UNSUPPORTED', `packet association supports only ${BUILD}`);
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) {
    return fail('DECODE_FAILED', `Replay source integrity failed: ${sourceError}`);
  }
  if (!sha(replay.source_sha256)) {
    return fail('INCONSISTENT', 'Replay source SHA-256 is missing or malformed');
  }
  const missing = [
    ...(!turretFirstBloodEventPacketOutcome ? ['turret_first_blood_event_packet'] : []),
    ...(!turretDieEventPacketOutcome ? ['turret_die_event_packet'] : []),
  ];
  if (missing.length) {
    return fail('MISSING_INPUT', 'both exact-build candidate decoder outcomes are required', {
      missing_inputs: missing,
    });
  }
  const first = turretFirstBloodEventPacketOutcome;
  const die = turretDieEventPacketOutcome;
  if (first.status !== 'CANDIDATE' || die.status !== 'CANDIDATE') {
    return fail('MISSING_INPUT', 'one or both candidate decoder outcomes are unavailable', {
      turret_first_blood_status: first.status ?? null,
      turret_die_status: die.status ?? null,
    });
  }
  if (!validOutcome(first, TURRET_FIRST_BLOOD_EVENT_PACKET_821_PROFILE, 0x003d)
      || !validOutcome(die, TURRET_DIE_EVENT_PACKET_821_PROFILE, 0x003b)) {
    return fail('INCONSISTENT', 'exact-image candidate outcome identity or counts differ');
  }
  const allRows = [
    ...first.events.map((row) => ({ row, route: 'turret_first_blood_event_packet',
      profile: TURRET_FIRST_BLOOD_EVENT_PACKET_821_PROFILE,
      shape: {
        type: 'TURRET_FIRST_BLOOD_EVENT_PACKET_CANDIDATE',
        childId: 0x003d, name: 'OnTurretFirstBlood', rawId: '0x4986',
        semanticStatus: 'CANDIDATE_EXACT_RUNTIME_ON_TURRET_FIRST_BLOOD_PACKET',
      } })),
    ...die.events.map((row) => ({ row, route: 'turret_die_event_packet',
      profile: TURRET_DIE_EVENT_PACKET_821_PROFILE,
      shape: {
        type: 'TURRET_DIE_EVENT_PACKET_CANDIDATE',
        childId: 0x003b, name: 'OnTurretDie', rawId: '0x4966',
        semanticStatus: 'CANDIDATE_EXACT_RUNTIME_ON_TURRET_DIE_PACKET',
      } })),
  ];
  for (let index = 0; index < allRows.length; index += 1) {
    const item = allRows[index];
    if (!validRow(replay, item.row, item.profile, item.shape)) {
      return fail('INCONSISTENT', 'candidate row identity or raw packet reference differs', {
        route: item.route, event_index: index,
      });
    }
  }
  const verified = verifyReplayPacketRefs(replay,
    allRows.map(({ row }) => row.raw_packet_ref));
  if (verified.error) {
    return fail(verified.scan_error ? 'DECODE_FAILED' : 'INCONSISTENT', verified.error);
  }
  const events = [];
  const pairedDiePositions = new Set();
  const orderedFirst = [...first.events].sort((left, right) => {
    const a = left.raw_packet_ref;
    const b = right.raw_packet_ref;
    return a.chunk_index - b.chunk_index
      || a.decompressed_block_offset - b.decompressed_block_offset;
  });
  for (const firstRow of orderedFirst) {
    const firstRef = firstRow.raw_packet_ref;
    const matches = die.events.filter((dieRow) => {
      const dieRef = dieRow.raw_packet_ref;
      return key(dieRef) === key(firstRef)
        && dieRef.decompressed_block_offset < firstRef.decompressed_block_offset;
    });
    if (matches.length !== 1) {
      return fail('INCONSISTENT', 'OnTurretFirstBlood has no unique earlier same-chunk, same-ms OnTurretDie candidate', {
        first_blood_packet_position: position(firstRef), earlier_die_candidate_count: matches.length,
      });
    }
    const dieRow = matches[0];
    const dieRef = dieRow.raw_packet_ref;
    if (pairedDiePositions.has(position(dieRef))) {
      return fail('INCONSISTENT', 'OnTurretDie candidate would be paired more than once', {
        die_packet_position: position(dieRef),
      });
    }
    const intervening = verified.onEventOffsets.get(firstRef.chunk_index)
      .filter((offset) => offset > dieRef.decompressed_block_offset
        && offset < firstRef.decompressed_block_offset);
    if (intervening.length) {
      return fail('INCONSISTENT', 'another 0x040a OnEvent packet intervenes between candidate pair', {
        die_packet_position: position(dieRef),
        first_blood_packet_position: position(firstRef),
        first_intervening_on_event_offset: intervening[0],
        intervening_on_event_count: intervening.length,
      });
    }
    pairedDiePositions.add(position(dieRef));
    const dieRefCopy = structuredClone(dieRef);
    const firstRefCopy = structuredClone(firstRef);
    events.push({
      event_type: 'TURRET_FIRST_BLOOD_DIE_PACKET_PAIR_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: firstRow.replay_time_ms,
      turret_die_child_event_id: 0x003b,
      turret_first_blood_child_event_id: 0x003d,
      turret_die_raw_param: dieRow.raw_param,
      turret_first_blood_raw_param: firstRow.raw_param,
      source_order_block_offset_gap:
        firstRef.decompressed_block_offset - dieRef.decompressed_block_offset,
      intervening_on_event_count: 0,
      raw_packet_ref: firstRefCopy,
      turret_die_raw_packet_ref: dieRefCopy,
      turret_first_blood_raw_packet_ref: firstRefCopy,
      raw_packet_refs: [dieRefCopy, firstRefCopy],
      confidence: 'CANDIDATE', semantic_status: CANDIDATE_STATUS,
    });
  }
  return {
    ...base, status: 'CANDIDATE', evidence_status: CANDIDATE_STATUS,
    replay_sha256: replay.source_sha256,
    turret_first_blood_count: first.events.length,
    turret_die_count: die.events.length,
    unmatched_turret_first_blood_count: 0,
    unpaired_turret_die_count: die.events.length - events.length,
    pair_count: events.length, event_count: events.length, events,
  };
}

module.exports = {
  TURRET_FIRST_BLOOD_DIE_PAIR_821_PROFILE,
  associateTurretFirstBloodDieCandidates821,
};
