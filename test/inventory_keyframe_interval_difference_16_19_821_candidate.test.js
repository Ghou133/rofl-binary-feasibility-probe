'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { walkBlocks } = require('../src/rofl');
const {
  HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821: BROADCAST_PROFILE,
} = require('../src/decoders/rofl_16_19_821_inventory_broadcast_packet_candidate');
const {
  INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE: PROFILE,
  deriveInventoryKeyframeIntervalDifferenceCandidates821: derive,
} = require('../src/decoders/rofl_16_19_821_inventory_keyframe_interval_difference_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = BROADCAST_PROFILE.evidence_runtime_image_sha256;

function packet(rawParam, timeSeconds, size = 79) {
  const payload = Buffer.alloc(size, 0x1e);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeSeconds, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0357, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function snapshotValues(chunkIndex, participant) {
  const items = Array(10).fill(0);
  if (participant === 1 && chunkIndex >= 2) items[7] = 2001;
  if (participant === 2 && chunkIndex === 0) items[6] = 3340;
  return items;
}

function rowFromBlock(replay, block, chunk) {
  const isKeyframe = chunk.stream === 'keyframe';
  const participant = block.param - 0x400000ad;
  const slots = isKeyframe ? [...Array(10).keys()] : [0, 1, 2, 3, 4, 5];
  const values = isKeyframe ? snapshotValues(chunk.index, participant) : Array(10).fill(0);
  const records = slots.map((slot, index) => ({
    record_index: index, slot_candidate: slot, item_id_candidate: values[slot],
  }));
  const snapshot = Array.from({ length: 10 }, (_, slot) => ({
    slot_candidate: slot,
    item_id_candidate: slots.includes(slot) ? values[slot] : null,
    value_basis: slots.includes(slot)
      ? 'DECODED_PACKET_RECORD' : 'CALLBACK_RESET_WITH_NO_PACKET_RECORD',
  }));
  const rawRef = {
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256,
    chunk_index: chunk.index, chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream, chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id, replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length, raw_param: block.param >>> 0,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
  return {
    event_type: 'HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: BROADCAST_PROFILE.id,
    replay_sha256: replay.source_sha256, replay_time_ms: block.timestamp_ms,
    hero_raw_param: block.param >>> 0, participant_id_candidate: participant,
    packet_stream: chunk.stream,
    snapshot_application: 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS',
    record_count: records.length, records_candidate: records,
    packet_slot_snapshot_candidate: snapshot,
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS',
    raw_packet_ref: rawRef,
  };
}

function fixture(times = [0, 60, 120]) {
  const chunks = [];
  times.forEach((time, frameIndex) => {
    if (frameIndex === 1) chunks.push({ stream: 1,
      body: packet(0x400000ae, 45, 76) });
    chunks.push({ stream: 2,
      body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
        packet(0x400000ae + index, time))) });
  });
  const replay = replayFromChunks(chunks, BUILD);
  const events = [];
  walkBlocks(replay, (block, chunk) => events.push(rowFromBlock(replay, block, chunk)),
    { strict: true });
  const inventoryBroadcastOutcome = {
    status: 'CANDIDATE', profile_id: BROADCAST_PROFILE.id,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    runtime_image_sha256: IMAGE_SHA256, runtime_image_used: true,
    runtime_image_status: 'MATCHED_USED', input_packet_id: 0x0357,
    input_count: events.length, event_count: events.length,
    decoded_record_count: events.reduce((sum, row) => sum + row.record_count, 0),
    events,
  };
  return { replay, inventoryBroadcastOutcome };
}

function deriveFixture(values) {
  return derive(values.replay, { inventoryBroadcastOutcome: values.inventoryBroadcastOutcome });
}

test('821 inventory keyframe interval candidate emits only differing sampled endpoints', () => {
  const values = fixture();
  const result = deriveFixture(values);
  assert.equal(PROFILE.capability, 'inventory_keyframe_interval_difference');
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.input_count, 31);
  assert.equal(result.keyframe_count, 3);
  assert.equal(result.broadcast_keyframe_packet_count, 30);
  assert.equal(result.excluded_game_broadcast_count, 1);
  assert.equal(result.verified_raw_packet_count, 31);
  assert.equal(result.observed_interval_count, 20);
  assert.equal(result.changed_interval_count, 2);
  assert.equal(result.unchanged_interval_count, 18);
  assert.equal(result.changed_slot_count, 2);
  assert.equal(result.event_count, 2);
  const first = result.events[0];
  assert.equal(first.event_type, 'INVENTORY_KEYFRAME_INTERVAL_DIFFERENCE_CANDIDATE');
  assert.equal(first.observation_scope, 'KEYFRAME_ENDPOINT_DIFFERENCE_ONLY');
  assert.equal(first.change_time_status, 'UNRESOLVED_WITHIN_INTERVAL');
  assert.equal(first.participant_id_candidate, 1);
  assert.equal(first.previous_observation_time_ms, 0);
  assert.equal(first.current_observation_time_ms, 60000);
  assert.deepEqual(first.changed_slots_candidate, [{
    slot_candidate: 7, previous_item_id_candidate: 0,
    current_item_id_candidate: 2001,
  }]);
  assert.deepEqual(result.events[1].changed_slots_candidate, [{
    slot_candidate: 6, previous_item_id_candidate: 3340,
    current_item_id_candidate: 0,
  }]);
  assert.deepEqual(first.raw_packet_refs,
    [first.previous_raw_packet_ref, first.current_raw_packet_ref]);
  assert.equal(first.raw_packet_ref.chunk_index, 2);
  assert.equal('purchase_time_ms' in first, false);
  assert.equal('inventory_state_between_keyframes' in first, false);
});

test('821 inventory keyframe interval candidate requires matching source and runtime image', () => {
  const missing = fixture();
  assert.equal(derive(missing.replay).status, 'MISSING_INPUT');
  const unavailable = fixture();
  unavailable.inventoryBroadcastOutcome.status = 'MISSING_INPUT';
  assert.equal(deriveFixture(unavailable).status, 'MISSING_INPUT');
  const failed = fixture();
  failed.inventoryBroadcastOutcome.status = 'DECODE_FAILED';
  assert.equal(deriveFixture(failed).status, 'DECODE_FAILED');
  const absent = fixture();
  absent.inventoryBroadcastOutcome.status = 'PROFILE_UNAVAILABLE';
  assert.equal(deriveFixture(absent).status, 'PROFILE_UNAVAILABLE');
  const wrongDependency = fixture();
  wrongDependency.inventoryBroadcastOutcome.status = 'MISSING_INPUT';
  wrongDependency.inventoryBroadcastOutcome.profile_id = 'other-profile';
  assert.equal(deriveFixture(wrongDependency).status, 'INCONSISTENT');
  const wrongBuild = fixture();
  wrongBuild.replay.header.version = '16.19.820.7193';
  assert.equal(deriveFixture(wrongBuild).status, 'UNSUPPORTED');
  const wrongProfile = fixture();
  wrongProfile.inventoryBroadcastOutcome.profile_id = 'other-profile';
  assert.equal(deriveFixture(wrongProfile).status, 'INCONSISTENT');
  const wrongImage = fixture();
  wrongImage.inventoryBroadcastOutcome.runtime_image_sha256 = 'f'.repeat(64);
  assert.equal(deriveFixture(wrongImage).status, 'INCONSISTENT');
});

test('821 inventory keyframe interval candidate fails on missing or duplicate roster rows', () => {
  const missing = fixture();
  missing.inventoryBroadcastOutcome.events.splice(0, 1);
  missing.inventoryBroadcastOutcome.event_count -= 1;
  missing.inventoryBroadcastOutcome.input_count -= 1;
  missing.inventoryBroadcastOutcome.decoded_record_count -= 10;
  assert.equal(deriveFixture(missing).status, 'INCONSISTENT');
  const duplicate = fixture();
  duplicate.inventoryBroadcastOutcome.events[1] =
    duplicate.inventoryBroadcastOutcome.events[0];
  assert.equal(deriveFixture(duplicate).status, 'INCONSISTENT');
  const missingFrame = fixture();
  missingFrame.inventoryBroadcastOutcome.events =
    missingFrame.inventoryBroadcastOutcome.events.filter((row) =>
      row.raw_packet_ref.chunk_index !== 2);
  missingFrame.inventoryBroadcastOutcome.event_count -= 10;
  missingFrame.inventoryBroadcastOutcome.input_count -= 10;
  missingFrame.inventoryBroadcastOutcome.decoded_record_count -= 100;
  assert.equal(deriveFixture(missingFrame).status, 'INCONSISTENT');
});

test('821 inventory keyframe interval candidate rejects nonincreasing frame times', () => {
  const same = fixture([0, 60, 60]);
  assert.equal(deriveFixture(same).status, 'INCONSISTENT');
  const backwards = fixture([0, 60, 50]);
  assert.equal(deriveFixture(backwards).status, 'INCONSISTENT');
});

test('821 inventory keyframe interval candidate verifies packet bytes and slot records', () => {
  const forgedRef = fixture();
  forgedRef.inventoryBroadcastOutcome.events[0].raw_packet_ref.raw_payload_sha256 =
    'f'.repeat(64);
  assert.equal(deriveFixture(forgedRef).status, 'INCONSISTENT');
  const badSnapshot = fixture();
  badSnapshot.inventoryBroadcastOutcome.events[0]
    .packet_slot_snapshot_candidate[7].item_id_candidate = 9999;
  assert.equal(deriveFixture(badSnapshot).status, 'INCONSISTENT');
  const mutatedReplay = fixture();
  mutatedReplay.replay.buffer[0] ^= 1;
  assert.equal(deriveFixture(mutatedReplay).status, 'DECODE_FAILED');
});

test('one sampled keyframe has zero observed intervals and no fabricated rows', () => {
  const values = fixture([0]);
  const result = deriveFixture(values);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.keyframe_count, 1);
  assert.equal(result.observed_interval_count, 0);
  assert.equal(result.unchanged_interval_count, 0);
  assert.equal(result.event_count, 0);
});
