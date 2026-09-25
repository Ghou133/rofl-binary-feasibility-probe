'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const test = require('node:test');

const { parseReplayBuffer, walkBlocks } = require('../src/rofl');
const { analyzeMovementParticipantAssociations821: analyze } =
  require('../src/decoders/rofl_16_19_821_movement_participant_association_candidate');
const { HERO_INVENTORY_PACKET_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_inventory_packet_candidate');
const { DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_direct_input_turn_packet_candidate');
const { SET_MOVEMENT_DRIVER_PACKET_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_set_movement_driver_packet_candidate');

const BUILD = '16.19.821.7343';
const HERO_1 = 0x400000ae;
const HERO_2 = 0x400000af;
const HERO_1_VARIANT = 0x400001ae;

function packet(packetId, rawParam, timeMs, length) {
  const payload = Buffer.alloc(length, packetId & 0xff);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function chunk(index, stream, body) {
  const header = Buffer.alloc(17);
  header.writeUInt32LE(index + 1, 0);
  header[4] = 1;
  header.writeUInt32LE((stream * 0x1000000 + index + 1) >>> 0, 5);
  header.writeUInt32LE(body.length, 9);
  return Buffer.concat([header, body]);
}

function fixture({ ambiguousTail = false } = {}) {
  const stats = Array.from({ length: 10 }, (_, index) =>
    Object.fromEntries(Array.from({ length: 7 }, (_, slot) =>
      [`ITEM${slot}`, String((index + 1) * 100 + slot + 1)])));
  if (ambiguousTail) {
    for (let slot = 0; slot < 7; slot += 1) stats[1][`ITEM${slot}`] = stats[0][`ITEM${slot}`];
  }
  const game = Buffer.concat([
    packet(0x018d, HERO_1, 1000, 23),
    packet(0x018d, HERO_1, 2000, 23),
    packet(0x018d, HERO_2, 2050, 23),
    packet(0x018d, HERO_2 + 1, 2075, 23),
    packet(0x00ba, HERO_1, 2100, 13),
    packet(0x0335, HERO_1, 2150, 28),
    packet(0x00ba, HERO_2, 2200, 13),
    packet(0x00ba, HERO_1_VARIANT, 2250, 13),
    packet(0x0335, HERO_1_VARIANT, 2300, 2),
    packet(0x0335, HERO_2 + 1, 2325, 28),
  ]);
  const keyframe = Buffer.concat(Array.from({ length: 10 }, (_, index) =>
    packet(0x0089, HERO_1 + index, 0, 1263)));
  const version = Buffer.from(BUILD);
  const replayHeader = Buffer.alloc(15 + version.length);
  replayHeader.write('RIOT');
  replayHeader.writeUInt16LE(1, 4);
  replayHeader[14] = version.length;
  version.copy(replayHeader, 15);
  const metadata = Buffer.from(JSON.stringify({ gameLength: 600000,
    statsJson: JSON.stringify(stats) }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  const replay = parseReplayBuffer(Buffer.concat([
    replayHeader, chunk(0, 1, game), chunk(1, 2, keyframe),
    Buffer.alloc(256), metadata, trailer,
  ]), path.resolve('synthetic-821-movement-association.rofl'));
  const observed = [];
  walkBlocks(replay, (block, replayChunk) => observed.push({ block, chunk: replayChunk }),
    { includeStreams: [1, 2], strict: true });

  const rawRef = ({ block, chunk: replayChunk }) => ({
    source_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    chunk_index: replayChunk.index,
    chunk_id: replayChunk.chunk_id,
    chunk_stream: replayChunk.stream,
    chunk_file_offset: replayChunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id,
    replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length,
    raw_param: block.param,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  });
  const base = (entry, eventType, profile, semanticStatus) => ({
    event_type: eventType, game_version: BUILD, build_profile: profile,
    replay_sha256: replay.source_sha256,
    replay_time_ms: entry.block.timestamp_ms,
    confidence: 'CANDIDATE', semantic_status: semanticStatus,
    raw_packet_ref: rawRef(entry),
  });
  const records = (participant) => Array.from({ length: 7 }, (_, slot) => ({
    record_index: slot, slot_candidate: slot,
    item_id_candidate: participant * 100 + slot + 1,
  }));
  const inventory = observed.filter(({ block }) => block.packet_id === 0x018d)
    .map((entry, index) => {
      const packetRecords = records(index === 0 ? 9 : entry.block.param - HERO_1 + 1);
      if (index === 1) packetRecords.push({
        record_index: packetRecords.length, slot_candidate: 9, item_id_candidate: 9999,
      });
      const packetSlotSnapshot = Array.from({ length: 10 }, (_, slot) => ({
        slot_candidate: slot, item_id_candidate: null,
        value_basis: 'CALLBACK_RESET_WITH_NO_PACKET_RECORD',
      }));
      for (const record of packetRecords) packetSlotSnapshot[record.slot_candidate] = {
        slot_candidate: record.slot_candidate,
        item_id_candidate: record.item_id_candidate,
        value_basis: 'DECODED_PACKET_RECORD',
      };
      return {
        ...base(entry, 'HERO_INVENTORY_MAPVIEW_PACKET_CANDIDATE',
          HERO_INVENTORY_PACKET_CANDIDATE_PROFILE_821.id,
          'CANDIDATE_EXACT_RUNTIME_MAPVIEW_PACKET_FIELDS'),
        hero_raw_param: entry.block.param,
        participant_id_candidate: entry.block.param - 0x400000ad,
        snapshot_application: 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS',
        record_count: packetRecords.length,
        records_candidate: packetRecords,
        packet_slot_snapshot_candidate: packetSlotSnapshot,
      };
    });
  const snapshot = observed.filter(({ block }) => block.packet_id === 0x0089)
    .map((entry) => ({
      ...base(entry, 'HERO_DEATHS_SNAPSHOT_CANDIDATE',
        'rofl-16.19.821.7343-kr-hero-deaths-raw-byte-keyframe-candidate-v2',
        'CANDIDATE_EXACT_KR_821_RUNTIME_BYTE_DEATH_COUNT_TAIL_CORRELATION'),
      hero_raw_param: entry.block.param,
      participant_id_candidate: entry.block.param - 0x400000ad,
    }));
  const direct = observed.filter(({ block }) => block.packet_id === 0x00ba)
    .map((entry) => ({
      ...base(entry, 'DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE',
        DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE_PROFILE_821.id,
        'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS'),
      raw_param: entry.block.param,
      opaque_f32_0x10: 1, opaque_f32_0x14: 2, opaque_f32_0x18: 3,
    }));
  const set = observed.filter(({ block }) => block.packet_id === 0x0335)
    .map((entry, index) => ({
      ...base(entry, 'SET_MOVEMENT_DRIVER_PACKET_CANDIDATE',
        SET_MOVEMENT_DRIVER_PACKET_CANDIDATE_PROFILE_821.id,
        'CANDIDATE_EXACT_RUNTIME_PACKET_FIELD'),
      raw_param: entry.block.param,
      raw_payload_byte_0: index === 1 ? 0x54 : 0x26,
      opaque_u8_0x2a: index === 1 ? 1 : 2,
    }));
  return { replay, inventory, snapshot, direct, set };
}

function analyzeFixture(f, extra = {}) {
  return analyze(f.replay, {
    inventoryEvents: f.inventory,
    snapshotEvents: f.snapshot,
    directInputEvents: f.direct,
    setMovementDriverEvents: f.set,
    ...extra,
  });
}

test('821 association uses only a complete full-key inventory and snapshot anchor', () => {
  const f = fixture();
  const before = JSON.stringify([f.direct, f.set]);
  const result = analyzeFixture(f);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.association_count, 3);
  assert.equal(result.associations[0].raw_param, HERO_1);
  assert.equal(result.associations[0].participant_id_candidate, 1);
  assert.equal(result.associations[0].inventory_snapshot_time_ms, 2000);
  assert.equal(result.associations[0].replay_tail_item_slot_match_count, 7);
  assert.equal(result.associations[0].inventory_raw_packet_ref.packet_id, 0x018d);
  assert.equal(result.associations[0].snapshot_raw_packet_ref.packet_id, 0x0089);
  assert.equal(result.associations[0].movement_routes.direct_input_movement_turn_packet.packet_count, 1);
  assert.equal(result.associations[0].movement_routes.set_movement_driver_packet.packet_count, 1);
  assert.equal(result.associations[1].raw_param, HERO_2);
  assert.equal(Object.hasOwn(result.associations[1].movement_routes,
    'set_movement_driver_packet'), false);
  assert.equal(result.associations[2].raw_param, HERO_2 + 1);
  assert.equal(Object.hasOwn(result.associations[2].movement_routes,
    'direct_input_movement_turn_packet'), false);
  assert.deepEqual(result.movement_rows_sharing_candidate_full_key, { direct: 2, set: 2 });
  assert.deepEqual(result.excluded_movement_packet_counts_by_reason.noncanonical_raw_param,
    { direct: 1, set: 1 });
  assert.equal(JSON.stringify([f.direct, f.set]), before);
  assert.equal(Object.hasOwn(f.direct[0], 'participant_id_candidate'), false);
});

test('821 association permits one selected movement route and excludes ambiguous tails', () => {
  const f = fixture();
  const directOnly = analyzeFixture(f, { setMovementDriverEvents: null });
  assert.deepEqual(directOnly.associations.map((row) => row.participant_id_candidate), [1, 2]);
  assert.deepEqual(directOnly.movement_rows_sharing_candidate_full_key, { direct: 2 });
  const setOnly = analyzeFixture(f, { directInputEvents: null });
  assert.deepEqual(setOnly.associations.map((row) => row.participant_id_candidate), [1, 3]);
  assert.deepEqual(setOnly.movement_rows_sharing_candidate_full_key, { set: 2 });
  const ambiguous = fixture({ ambiguousTail: true });
  const noMatch = analyzeFixture(ambiguous, { setMovementDriverEvents: null });
  assert.equal(noMatch.status, 'UNAVAILABLE');
  assert.equal(noMatch.association_count, 0);
  assert.equal(noMatch.excluded_movement_packet_counts_by_reason.no_unique_exact_tail_match.direct, 2);
});

test('821 association excludes conflicting snapshot/tail labels instead of emitting an actor', () => {
  const f = fixture();
  for (const row of f.snapshot) {
    if (row.hero_raw_param === HERO_1) row.participant_id_candidate = 2;
    else if (row.hero_raw_param === HERO_2) row.participant_id_candidate = 1;
  }
  const result = analyzeFixture(f);
  assert.equal(result.status, 'CANDIDATE');
  assert.deepEqual(result.associations.map((row) => row.participant_id_candidate), [3]);
  assert.equal(result.excluded_movement_packet_counts_by_reason.snapshot_inventory_conflict.direct, 2);
});

test('821 association fails closed on Replay, route, reference and tail provenance mismatch', () => {
  const cases = [
    ['foreign Replay SHA', (f) => { f.direct[0].replay_sha256 = 'c'.repeat(64); }],
    ['wrong packet ID', (f) => { f.set[0].raw_packet_ref.packet_id = 0x00ba; }],
    ['wrong raw parameter', (f) => { f.direct[0].raw_packet_ref.raw_param = HERO_2; }],
    ['wrong source path', (f) => { f.inventory[0].raw_packet_ref.source_path = 'foreign.rofl'; }],
    ['wrong chunk offset', (f) => { f.snapshot[0].raw_packet_ref.chunk_file_offset += 1; }],
    ['duplicated packet position', (f) => {
      f.direct[1].raw_packet_ref.decompressed_block_offset =
        f.direct[0].raw_packet_ref.decompressed_block_offset;
    }],
    ['inconsistent packet slot snapshot', (f) => {
      f.inventory[1].packet_slot_snapshot_candidate[0].item_id_candidate = 9999;
    }],
    ['mutated tail', (f) => { f.replay.tail.stats[0].ITEM0 = '9999'; }],
    ['mutated source bytes', (f) => { f.replay.buffer[0] = 0; }],
  ];
  for (const [label, mutate] of cases) {
    const f = fixture();
    mutate(f);
    assert.throws(() => analyzeFixture(f), TypeError, label);
  }
});
