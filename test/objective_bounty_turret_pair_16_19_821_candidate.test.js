'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { walkBlocks } = require('../src/rofl');
const { OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_objective_bounty_claimed_packet_candidate');
const { TURRET_PLATE_EVENT_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_turret_plate_event_packet_candidate');
const { TURRET_DIE_EVENT_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_turret_die_event_packet_candidate');
const {
  OBJECTIVE_BOUNTY_TURRET_PAIR_821_PROFILE,
  associateObjectiveBountyTurretPairCandidates821: associate,
} = require('../src/decoders/rofl_16_19_821_objective_bounty_turret_pair_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const WORD = 0x40000097;

function sha(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packet(rawParam, length, timeMs) {
  const payload = Buffer.alloc(length, rawParam & 0xff);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(length, 5);
  header.writeUInt16LE(0x040a, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function rawRef(replay, block, chunk) {
  return {
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256,
    chunk_index: chunk.index,
    chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream,
    chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id,
    replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_payload_sha256: sha(block.payload),
  };
}

function row(replay, entry, kind, word) {
  const { block, chunk } = entry;
  const common = {
    game_version: BUILD, patch: '16.19',
    replay_sha256: replay.source_sha256,
    replay_time_ms: block.timestamp_ms,
    raw_param: block.param >>> 0,
    confidence: 'CANDIDATE',
    raw_packet_ref: rawRef(replay, block, chunk),
  };
  if (kind === 'claim' || kind === 'plate') {
    const blob = Buffer.alloc(8);
    blob.writeUInt32LE(469, 0);
    blob.writeUInt32LE(word, 4);
    return {
      ...common,
      event_type: kind === 'claim'
        ? 'OBJECTIVE_BOUNTY_CLAIMED_PACKET_CANDIDATE'
        : 'TURRET_PLATE_EVENT_PACKET_CANDIDATE',
      build_profile: kind === 'claim'
        ? OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE.id
        : TURRET_PLATE_EVENT_PACKET_821_PROFILE.id,
      event_id: kind === 'claim' ? 0x0113 : 0x0107,
      event_name: kind === 'claim'
        ? 'OnObjectiveBountyClaimed' : 'OnTurretPlateDestroyed',
      raw_event_id_hex: kind === 'claim' ? '0x09e5' : '0x09e8',
      event_schema_u32_0x00: 469,
      ...(kind === 'claim' ? { blob_u32_0x04: word,
        event_blob_hex: blob.toString('hex') }
        : { event_u32_0x04: word }),
      event_blob_sha256: sha(blob),
      semantic_status: 'CANDIDATE_EXACT_RUNTIME_NAMED_ON_EVENT_CHILD',
    };
  }
  const blob = Buffer.alloc(108);
  blob.writeUInt32LE(word, 12);
  return {
    ...common,
    event_type: 'TURRET_DIE_EVENT_PACKET_CANDIDATE',
    build_profile: TURRET_DIE_EVENT_PACKET_821_PROFILE.id,
    event_id: 0x003b, event_name: 'OnTurretDie',
    raw_event_id_hex: '0x4966',
    event_blob_hex: blob.toString('hex'),
    event_blob_sha256: sha(blob),
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_ON_TURRET_DIE_PACKET',
  };
}

function outcome(kind, events, length17Count) {
  const profile = kind === 'claim' ? OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE
    : kind === 'plate' ? TURRET_PLATE_EVENT_PACKET_821_PROFILE
      : TURRET_DIE_EVENT_PACKET_821_PROFILE;
  const result = {
    status: 'CANDIDATE', profile_id: profile.id,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    runtime_image_sha256: IMAGE_SHA256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    input_packet_id: 0x040a,
    child_event_id: kind === 'claim' ? 0x0113 : kind === 'plate' ? 0x0107 : 0x003b,
    event_count: events.length, events,
  };
  if (kind === 'die') {
    return { ...result, input_count: events.length,
      observed_same_length_packet_count: events.length,
      excluded_same_length_foreign_count: 0 };
  }
  return { ...result, input_count: length17Count,
    target_packet_count: events.length,
    same_length_control_count: length17Count - events.length };
}

function fixture({ duplicatePlate = false, secondClaimSameKey = false,
  reverseDie = false, claimTimeMs = 1000, dieWord = WORD,
  plateInPriorChunk = false } = {}) {
  const plate = packet(0x400001ae, 17, 1000);
  const duplicate = packet(0x400001af, 17, 1000);
  const die = packet(0x40000097, 116, 1000);
  const interveningOnEvent = packet(0x400000bb, 20, 1000);
  const claim = packet(0x400000ae, 17, claimTimeMs);
  const secondClaim = packet(0x400000ad, 17, 1000);
  const unmatchedClaim = packet(0x400000af, 17, 2000);
  const firstChunk = plateInPriorChunk ? [plate] : [];
  const secondChunk = [
    ...(reverseDie ? [die, ...(plateInPriorChunk ? [] : [plate])]
      : [...(plateInPriorChunk ? [] : [plate]),
        ...(duplicatePlate ? [duplicate] : []),
        interveningOnEvent, die]),
    claim,
    ...(secondClaimSameKey ? [secondClaim] : []),
    unmatchedClaim,
  ];
  const replay = replayFromChunks((plateInPriorChunk
    ? [firstChunk, secondChunk] : [secondChunk]).map((packets) => ({
    stream: 1, body: Buffer.concat(packets),
  })), BUILD);
  const found = new Map();
  const scanned = walkBlocks(replay, (block, chunk) => {
    found.set(block.param >>> 0, { block, chunk });
  }, { strict: true });
  assert.equal(scanned.errors.length, 0);
  const claims = [row(replay, found.get(0x400000ae), 'claim', WORD),
    ...(secondClaimSameKey
      ? [row(replay, found.get(0x400000ad), 'claim', WORD)] : []),
    row(replay, found.get(0x400000af), 'claim', 0x40010b5a)];
  const plates = [row(replay, found.get(0x400001ae), 'plate', WORD),
    ...(duplicatePlate
      ? [row(replay, found.get(0x400001af), 'plate', WORD)] : [])];
  const dies = [row(replay, found.get(0x40000097), 'die', dieWord)];
  const length17Count = [...found.values()].filter(({ block }) =>
    block.packet_id === 0x040a && block.payload_length === 17).length;
  return {
    replay,
    objectiveBountyClaimedPacketOutcome: outcome('claim', claims, length17Count),
    turretPlateEventPacketOutcome: outcome('plate', plates, length17Count),
    turretDieEventPacketOutcome: outcome('die', dies, length17Count),
  };
}

test('821 packet triple relates ordered equal anonymous words and keeps unmatched claim', () => {
  const values = fixture();
  const result = associate(values.replay, values);
  assert.equal(OBJECTIVE_BOUNTY_TURRET_PAIR_821_PROFILE.capability,
    'objective_bounty_turret_pair');
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.triple_count, 1);
  assert.equal(result.claim_packet_count, 2);
  assert.equal(result.unmatched_claim_count, 1);
  assert.equal(result.nonunique_claim_count, 0);
  assert.equal(result.unmatched_claims[0].reason, 'NO_SAME_KEY_PLATE_OR_DIE');
  const triple = result.events[0];
  assert.equal(triple.claim_blob_u32_0x04, WORD);
  assert.equal(triple.plate_event_u32_0x04, WORD);
  assert.equal(triple.turret_die_blob_u32_0x0c, WORD);
  assert.deepEqual(triple.raw_packet_refs, [triple.plate_raw_packet_ref,
    triple.turret_die_raw_packet_ref, triple.claim_raw_packet_ref]);
  assert.ok(triple.plate_raw_packet_ref.decompressed_block_offset
    < triple.turret_die_raw_packet_ref.decompressed_block_offset);
  assert.ok(triple.turret_die_raw_packet_ref.decompressed_block_offset
    < triple.claim_raw_packet_ref.decompressed_block_offset);
  assert.notEqual(triple.plate_raw_param, triple.claim_raw_param);
  assert.notEqual(triple.turret_die_raw_param, triple.claim_raw_param);
  for (const field of ['paid', 'payout', 'turret_destroyed', 'actor',
    'target', 'structure', 'team', 'object_id']) {
    assert.equal(field in triple, false);
  }
});

test('821 packet triple leaves wrong time, chunk, order, and word unassociated', () => {
  const cases = [
    [{ claimTimeMs: 3000 }, 'NO_SAME_KEY_PLATE_OR_DIE'],
    [{ plateInPriorChunk: true }, 'NO_SAME_KEY_PLATE'],
    [{ reverseDie: true }, 'PACKET_ORDER_MISMATCH'],
    [{ dieWord: WORD + 1 }, 'ANONYMOUS_WORD_MISMATCH'],
  ];
  for (const [options, reason] of cases) {
    const values = fixture(options);
    const result = associate(values.replay, values);
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.triple_count, 0);
    assert.equal(result.claim_packet_count, 2);
    assert.equal(result.unmatched_claim_count, 2);
    assert.equal(result.unmatched_claims[0].reason, reason);
  }
});

test('821 packet triple rejects nonunique matches and reused source packets', () => {
  const ambiguous = fixture({ duplicatePlate: true });
  const result = associate(ambiguous.replay, ambiguous);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.triple_count, 0);
  assert.equal(result.nonunique_claim_count, 1);
  assert.equal(result.unmatched_claims[0].reason, 'NONUNIQUE_TRIPLE');
  assert.equal(result.unmatched_claims[0].equal_word_triple_count, 2);
  const reused = fixture({ secondClaimSameKey: true });
  const reusedResult = associate(reused.replay, reused);
  assert.equal(reusedResult.status, 'CANDIDATE');
  assert.equal(reusedResult.triple_count, 0);
  assert.equal(reusedResult.nonunique_claim_count, 2);
  assert.deepEqual(reusedResult.unmatched_claims.slice(0, 2).map((row) => row.reason),
    ['REUSED_SOURCE_PACKET', 'REUSED_SOURCE_PACKET']);
});

test('821 packet triple fails closed on altered image, native blob, ref, or Replay', () => {
  const wrongImage = fixture();
  wrongImage.turretPlateEventPacketOutcome.runtime_image_sha256 = 'f'.repeat(64);
  assert.equal(associate(wrongImage.replay, wrongImage).status, 'INCONSISTENT');
  const wrongBlob = fixture();
  wrongBlob.turretDieEventPacketOutcome.events[0].event_blob_hex = '00'.repeat(108);
  assert.equal(associate(wrongBlob.replay, wrongBlob).status, 'INCONSISTENT');
  const alteredPlateWord = fixture();
  alteredPlateWord.turretPlateEventPacketOutcome.events[0].event_u32_0x04 += 1;
  assert.equal(associate(alteredPlateWord.replay, alteredPlateWord).status, 'INCONSISTENT');
  const wrongRef = fixture();
  wrongRef.objectiveBountyClaimedPacketOutcome.events[0].raw_packet_ref
    .raw_payload_sha256 = 'f'.repeat(64);
  assert.equal(associate(wrongRef.replay, wrongRef).status, 'INCONSISTENT');
  const foreignStream = fixture();
  foreignStream.turretPlateEventPacketOutcome.events[0].raw_packet_ref.chunk_stream =
    'keyframe';
  assert.equal(associate(foreignStream.replay, foreignStream).status, 'INCONSISTENT');
  const changedSource = fixture();
  changedSource.replay.buffer[0] ^= 1;
  assert.equal(associate(changedSource.replay, changedSource).status, 'DECODE_FAILED');
});

test('821 packet triple distinguishes unavailable dependency and wrong build', () => {
  const values = fixture();
  assert.equal(associate(values.replay, {
    turretPlateEventPacketOutcome: values.turretPlateEventPacketOutcome,
    turretDieEventPacketOutcome: values.turretDieEventPacketOutcome,
  }).status, 'MISSING_INPUT');
  const unavailable = fixture();
  unavailable.objectiveBountyClaimedPacketOutcome.status = 'PROFILE_UNAVAILABLE';
  unavailable.objectiveBountyClaimedPacketOutcome.events = null;
  const missing = associate(unavailable.replay, unavailable);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.claim_packet_count, null);
  assert.deepEqual(missing.diagnostics.dependency_statuses,
    { objective_bounty_claimed_packet: 'PROFILE_UNAVAILABLE' });
  const wrongBuild = fixture();
  wrongBuild.replay.header.version = '16.19.820.7193';
  assert.equal(associate(wrongBuild.replay, wrongBuild).status, 'UNSUPPORTED');
});
