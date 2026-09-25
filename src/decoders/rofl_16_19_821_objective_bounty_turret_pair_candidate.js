'use strict';

// Associates three independently decoded OnEvent children. The exact image
// supplies packet labels, but this relation does not establish a structure,
// actor, bounty payment, or game-state change.
const crypto = require('node:crypto');
const { decompressChunk, parseBlockAt } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');
const { OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE } =
  require('./rofl_16_19_821_objective_bounty_claimed_packet_candidate');
const { TURRET_PLATE_EVENT_PACKET_821_PROFILE } =
  require('./rofl_16_19_821_turret_plate_event_packet_candidate');
const { TURRET_DIE_EVENT_PACKET_821_PROFILE } =
  require('./rofl_16_19_821_turret_die_event_packet_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const MAX_REFS = 23_000;
const EVIDENCE_STATUS = 'CANDIDATE_821_ON_EVENT_PLATE_DIE_CLAIM_PACKET_TRIPLE';

const OBJECTIVE_BOUNTY_TURRET_PAIR_821_PROFILE = Object.freeze({
  id: 'rofl-16.19.821.7343-kr-on-event-plate-die-claim-packet-triple-candidate-v1',
  replay_version: BUILD,
  capability: 'objective_bounty_turret_pair',
  status: 'CANDIDATE',
  enabled: true,
  depends_on: Object.freeze([
    'objective_bounty_claimed_packet',
    'turret_plate_event_packet',
    'turret_die_event_packet',
  ]),
  evidence_runtime_image_sha256: IMAGE_SHA256,
  evidence_scope: '11 exact-build KR Replays: 10 unique same-chunk, same-millisecond plate < die < claim packet triples with equal anonymous native u32 words; 1 claim has no same-key pair',
  known_limits: Object.freeze([
    'The native event names are exact-image labels. This packet relation does not prove a bounty payment, turret destruction, actor, target, object identity, or game-state effect.',
    'The equal native words are anonymous. Replay raw params differ in observed triples and are not equality gates.',
    'Missing, reordered, word-mismatched, and nonunique groups remain unassociated; each packet-local candidate remains independently available.',
    'All three candidate routes must independently match the pinned exact-build runtime image and the same Replay source.',
  ]),
});

function u32(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
}

function count(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= MAX_REFS;
}

function sha(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function hash(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packetPosition(ref) {
  return `${ref.chunk_index}/${ref.decompressed_block_offset}`;
}

function groupKey(ref) {
  return `${ref.chunk_index}/${ref.chunk_id}/${ref.replay_time_ms}`;
}

function validOutcome(outcome, profile, childId, kind) {
  if (outcome?.status !== 'CANDIDATE'
      || outcome.profile_id !== profile.id
      || outcome.evidence_runtime_image_sha256 !== IMAGE_SHA256
      || outcome.runtime_image_sha256 !== IMAGE_SHA256
      || outcome.runtime_image_status !== 'MATCHED_USED'
      || outcome.runtime_image_used !== true
      || outcome.input_packet_id !== 0x040a
      || outcome.child_event_id !== childId
      || !Array.isArray(outcome.events)
      || !count(outcome.event_count) || outcome.event_count === 0
      || outcome.event_count !== outcome.events.length
      || !count(outcome.input_count) || outcome.input_count < outcome.event_count) {
    return false;
  }
  if (kind === 'die') {
    return outcome.input_count === outcome.event_count
      && count(outcome.observed_same_length_packet_count)
      && count(outcome.excluded_same_length_foreign_count)
      && outcome.observed_same_length_packet_count
        === outcome.event_count + outcome.excluded_same_length_foreign_count;
  }
  return outcome.target_packet_count === outcome.event_count
    && count(outcome.same_length_control_count)
    && outcome.input_count === outcome.event_count + outcome.same_length_control_count;
}

function validRef(replay, row, length) {
  const ref = row.raw_packet_ref;
  if (!ref || ref.source_path !== (replay.source_path ?? null)
      || ref.replay_sha256 !== replay.source_sha256
      || ref.packet_id !== 0x040a || ref.payload_length !== length
      || ref.raw_param !== row.raw_param
      || ref.replay_time_ms !== row.replay_time_ms
      || ref.chunk_stream !== 'game_chunk'
      || !Number.isSafeInteger(ref.chunk_index) || ref.chunk_index < 0
      || !Number.isSafeInteger(ref.chunk_id)
      || !Number.isSafeInteger(ref.chunk_file_offset) || ref.chunk_file_offset < 0
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
    && ref.decompressed_payload_offset + length <= chunk.uncompressed_length;
}

function validRow(replay, row, profile, kind) {
  const shapes = {
    claim: [0x0113, 'OnObjectiveBountyClaimed', '0x09e5',
      'OBJECTIVE_BOUNTY_CLAIMED_PACKET_CANDIDATE',
      'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD', 17],
    plate: [0x0107, 'OnTurretPlateDestroyed', '0x09e8',
      'TURRET_PLATE_EVENT_PACKET_CANDIDATE',
      'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD', 17],
    die: [0x003b, 'OnTurretDie', '0x4966',
      'TURRET_DIE_EVENT_PACKET_CANDIDATE',
      'CANDIDATE_EXACT_RUNTIME_ON_TURRET_DIE_PACKET', 116],
  };
  const [id, name, rawId, type, semanticStatus, length] = shapes[kind];
  if (row?.event_type !== type || row.game_version !== BUILD
      || row.patch !== '16.19' || row.build_profile !== profile.id
      || row.confidence !== 'CANDIDATE'
      || row.semantic_status !== semanticStatus
      || row.replay_sha256 !== replay.source_sha256
      || !Number.isSafeInteger(row.replay_time_ms) || row.replay_time_ms < 0
      || !u32(row.raw_param) || row.raw_param === 0
      || row.event_id !== id || row.event_name !== name
      || row.raw_event_id_hex !== rawId
      || !sha(row.event_blob_sha256)
      || !validRef(replay, row, length)) return false;
  if (kind === 'plate') {
    if (row.event_schema_u32_0x00 !== 469 || !u32(row.event_u32_0x04)) {
      return false;
    }
    // The plate route exposes both words and the hash of its entire 8-byte
    // native child blob, even though it omits the blob's hex rendering.
    const blob = Buffer.allocUnsafe(8);
    blob.writeUInt32LE(469, 0);
    blob.writeUInt32LE(row.event_u32_0x04, 4);
    return hash(blob) === row.event_blob_sha256;
  }
  const blobLength = kind === 'claim' ? 8 : 108;
  if (typeof row.event_blob_hex !== 'string'
      || row.event_blob_hex.length !== blobLength * 2
      || !/^[0-9a-f]+$/.test(row.event_blob_hex)) return false;
  const blob = Buffer.from(row.event_blob_hex, 'hex');
  if (hash(blob) !== row.event_blob_sha256) return false;
  if (kind === 'claim') {
    return row.event_schema_u32_0x00 === 469
      && u32(row.blob_u32_0x04)
      && blob.readUInt32LE(0) === 469
      && blob.readUInt32LE(4) === row.blob_u32_0x04;
  }
  return true;
}

function verifyPhysicalRefs(replay, rows) {
  const expected = new Map();
  const neededChunks = new Set();
  for (const row of rows) {
    const ref = row.raw_packet_ref;
    const position = packetPosition(ref);
    if (expected.has(position)) {
      return { error: `duplicate candidate raw packet position ${position}` };
    }
    expected.set(position, ref);
    neededChunks.add(ref.chunk_index);
  }
  try {
    for (const chunkIndex of neededChunks) {
      const body = decompressChunk(replay.buffer, replay.chunks[chunkIndex]);
      const state = { timestamp: 0, packet_id: 0, param: 0 };
      let cursor = 0;
      while (cursor < body.length) {
        const block = parseBlockAt(body, cursor, state);
        const position = `${chunkIndex}/${block.offset}`;
        const ref = expected.get(position);
        if (ref) {
          if (block.packet_id !== ref.packet_id
              || block.timestamp_ms !== ref.replay_time_ms
              || (block.param >>> 0) !== ref.raw_param
              || block.payload_length !== ref.payload_length
              || block.payload_offset !== ref.decompressed_payload_offset
              || hash(block.payload) !== ref.raw_payload_sha256) {
            return { error: `candidate raw packet reference differs from Replay block at ${position}` };
          }
          expected.delete(position);
        }
        cursor = block.next_offset;
      }
    }
  } catch (error) {
    return { error: `Replay packet scan failed: ${error.message}`, scan_error: true };
  }
  if (expected.size) {
    return { error: `candidate raw packet reference is absent at ${expected.keys().next().value}` };
  }
  return {};
}

function indexByGroup(rows) {
  const index = new Map();
  for (const row of rows) {
    const key = groupKey(row.raw_packet_ref);
    if (!index.has(key)) index.set(key, []);
    index.get(key).push(row);
  }
  return index;
}

function associateObjectiveBountyTurretPairCandidates821(replay, {
  objectiveBountyClaimedPacketOutcome,
  turretPlateEventPacketOutcome,
  turretDieEventPacketOutcome,
} = {}) {
  const profile = OBJECTIVE_BOUNTY_TURRET_PAIR_821_PROFILE;
  const base = {
    profile_id: profile.id,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    depends_on: [...profile.depends_on],
    known_limits: [...profile.known_limits],
  };
  const fail = (status, error, diagnostics = {}) => ({
    ...base, status, evidence_status: status === 'INCONSISTENT' ? 'INCONSISTENT' : null,
    event_count: null, triple_count: null, events: null,
    claim_packet_count: Array.isArray(objectiveBountyClaimedPacketOutcome?.events)
      ? objectiveBountyClaimedPacketOutcome.events.length : null,
    turret_plate_count: Array.isArray(turretPlateEventPacketOutcome?.events)
      ? turretPlateEventPacketOutcome.events.length : null,
    turret_die_count: Array.isArray(turretDieEventPacketOutcome?.events)
      ? turretDieEventPacketOutcome.events.length : null,
    unmatched_claim_count: null, nonunique_claim_count: null,
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
  const outcomes = [
    ['objective_bounty_claimed_packet', objectiveBountyClaimedPacketOutcome,
      OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE, 0x0113, 'claim'],
    ['turret_plate_event_packet', turretPlateEventPacketOutcome,
      TURRET_PLATE_EVENT_PACKET_821_PROFILE, 0x0107, 'plate'],
    ['turret_die_event_packet', turretDieEventPacketOutcome,
      TURRET_DIE_EVENT_PACKET_821_PROFILE, 0x003b, 'die'],
  ];
  const unavailable = outcomes.filter(([, outcome]) => outcome?.status !== 'CANDIDATE');
  if (unavailable.length) {
    return fail('MISSING_INPUT', 'all three exact-build candidate decoder outcomes are required', {
      dependency_statuses: Object.fromEntries(unavailable.map(([name, outcome]) =>
        [name, outcome?.status ?? null])),
    });
  }
  for (const [name, outcome, dependencyProfile, childId, kind] of outcomes) {
    if (!validOutcome(outcome, dependencyProfile, childId, kind)) {
      return fail('INCONSISTENT', 'exact-image candidate outcome identity or counts differ', {
        route: name,
      });
    }
  }
  const allRows = outcomes.flatMap(([name, outcome, dependencyProfile,, kind]) =>
    outcome.events.map((row) => ({ name, row, dependencyProfile, kind })));
  if (allRows.length > MAX_REFS) {
    return fail('UNSUPPORTED', `packet association exceeds ${MAX_REFS} candidate references`);
  }
  for (let index = 0; index < allRows.length; index += 1) {
    const item = allRows[index];
    if (!validRow(replay, item.row, item.dependencyProfile, item.kind)) {
      return fail('INCONSISTENT', 'candidate row identity or raw packet reference differs', {
        route: item.name, event_index: index,
      });
    }
  }
  const verified = verifyPhysicalRefs(replay, allRows.map(({ row }) => row));
  if (verified.error) {
    return fail(verified.scan_error ? 'DECODE_FAILED' : 'INCONSISTENT', verified.error);
  }

  const claimRows = objectiveBountyClaimedPacketOutcome.events;
  const plateRows = turretPlateEventPacketOutcome.events;
  const dieRows = turretDieEventPacketOutcome.events;
  const platesByGroup = indexByGroup(plateRows);
  const diesByGroup = indexByGroup(dieRows);
  const evaluations = claimRows.map((claim) => {
    const claimRef = claim.raw_packet_ref;
    const plates = platesByGroup.get(groupKey(claimRef)) ?? [];
    const dies = diesByGroup.get(groupKey(claimRef)) ?? [];
    const ordered = [];
    const triples = [];
    for (const plate of plates) {
      const plateOffset = plate.raw_packet_ref.decompressed_block_offset;
      for (const die of dies) {
        const dieOffset = die.raw_packet_ref.decompressed_block_offset;
        if (!(plateOffset < dieOffset
            && dieOffset < claimRef.decompressed_block_offset)) continue;
        ordered.push({ plate, die });
        if (plate.event_u32_0x04 === claim.blob_u32_0x04
            && Buffer.from(die.event_blob_hex, 'hex').readUInt32LE(12)
              === claim.blob_u32_0x04) {
          triples.push({ plate, die });
        }
      }
    }
    return { claim, plates, dies, ordered, triples };
  });
  const usage = new Map();
  for (const item of evaluations) {
    for (const triple of item.triples) {
      for (const row of [triple.plate, triple.die]) {
        const position = packetPosition(row.raw_packet_ref);
        usage.set(position, (usage.get(position) ?? 0) + 1);
      }
    }
  }
  const events = [];
  const unmatchedClaims = [];
  let nonuniqueClaimCount = 0;
  for (const item of evaluations) {
    const { claim, plates, dies, ordered, triples } = item;
    let reason;
    if (plates.length === 0 && dies.length === 0) reason = 'NO_SAME_KEY_PLATE_OR_DIE';
    else if (plates.length === 0) reason = 'NO_SAME_KEY_PLATE';
    else if (dies.length === 0) reason = 'NO_SAME_KEY_DIE';
    else if (ordered.length === 0) reason = 'PACKET_ORDER_MISMATCH';
    else if (triples.length === 0) reason = 'ANONYMOUS_WORD_MISMATCH';
    else if (triples.length > 1) reason = 'NONUNIQUE_TRIPLE';
    else if (usage.get(packetPosition(triples[0].plate.raw_packet_ref)) !== 1
        || usage.get(packetPosition(triples[0].die.raw_packet_ref)) !== 1) {
      reason = 'REUSED_SOURCE_PACKET';
    }
    if (reason) {
      if (reason === 'NONUNIQUE_TRIPLE' || reason === 'REUSED_SOURCE_PACKET') {
        nonuniqueClaimCount += 1;
      }
      unmatchedClaims.push({
        reason,
        claim_raw_packet_ref: structuredClone(claim.raw_packet_ref),
        same_key_plate_count: plates.length,
        same_key_die_count: dies.length,
        ordered_pair_count: ordered.length,
        equal_word_triple_count: triples.length,
      });
      continue;
    }
    const { plate, die } = triples[0];
    const plateRef = structuredClone(plate.raw_packet_ref);
    const dieRef = structuredClone(die.raw_packet_ref);
    const claimRef = structuredClone(claim.raw_packet_ref);
    events.push({
      event_type: 'OBJECTIVE_BOUNTY_TURRET_PACKET_TRIPLE_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: profile.id,
      replay_sha256: replay.source_sha256,
      replay_time_ms: claim.replay_time_ms,
      raw_param: claim.raw_param,
      plate_child_event_id: 0x0107,
      turret_die_child_event_id: 0x003b,
      claim_child_event_id: 0x0113,
      plate_raw_param: plate.raw_param,
      turret_die_raw_param: die.raw_param,
      claim_raw_param: claim.raw_param,
      plate_event_u32_0x04: plate.event_u32_0x04,
      turret_die_blob_u32_0x0c: claim.blob_u32_0x04,
      claim_blob_u32_0x04: claim.blob_u32_0x04,
      raw_packet_ref: claimRef,
      plate_raw_packet_ref: plateRef,
      turret_die_raw_packet_ref: dieRef,
      claim_raw_packet_ref: claimRef,
      raw_packet_refs: [plateRef, dieRef, claimRef],
      confidence: 'CANDIDATE', semantic_status: EVIDENCE_STATUS,
    });
  }
  events.sort((left, right) => {
    const a = left.claim_raw_packet_ref;
    const b = right.claim_raw_packet_ref;
    return a.chunk_index - b.chunk_index
      || a.decompressed_block_offset - b.decompressed_block_offset;
  });
  return {
    ...base, status: 'CANDIDATE', evidence_status: EVIDENCE_STATUS,
    replay_sha256: replay.source_sha256,
    claim_packet_count: claimRows.length,
    turret_plate_count: plateRows.length,
    turret_die_count: dieRows.length,
    unmatched_claim_count: unmatchedClaims.length,
    nonunique_claim_count: nonuniqueClaimCount,
    unmatched_claims: unmatchedClaims,
    triple_count: events.length, event_count: events.length, events,
  };
}

module.exports = {
  OBJECTIVE_BOUNTY_TURRET_PAIR_821_PROFILE,
  associateObjectiveBountyTurretPairCandidates821,
};
