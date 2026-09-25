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
  deriveInventoryKeyframeIntervalDifferenceCandidates821: deriveInterval,
} = require('../src/decoders/rofl_16_19_821_inventory_keyframe_interval_difference_candidate');
const {
  INVENTORY_GAME_BROADCAST_KEYFRAME_BRACKET_821_PROFILE: PROFILE,
  associateInventoryGameBroadcastKeyframeBracketCandidates821: associate,
} = require('../src/decoders/rofl_16_19_821_inventory_game_broadcast_keyframe_bracket_candidate');

const BUILD = '16.19.821.7343';
const IMAGE_SHA256 = BROADCAST_PROFILE.evidence_runtime_image_sha256;
const FIRST_PARAM = 0x400000ae;
const NONCANONICAL_PARAM = 0x400001af;

function packet(rawParam, timeSeconds) {
  const payload = Buffer.alloc(76, 0x1e);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeSeconds, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0357, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function itemAt(chunkIndex, rawParam, slot) {
  if (rawParam === FIRST_PARAM && slot === 0) return 3865;
  if (rawParam === FIRST_PARAM + 1 && slot === 2) {
    return chunkIndex === 0 ? 1036 : 2055;
  }
  return 0;
}

function rowFromBlock(replay, block, chunk) {
  const keyframe = chunk.stream === 'keyframe';
  const rawParam = block.param >>> 0;
  const participant = rawParam >= FIRST_PARAM && rawParam <= FIRST_PARAM + 9
    ? rawParam - FIRST_PARAM + 1 : null;
  const slots = keyframe ? [...Array(10).keys()] : [0, 1, 2, 3, 4, 5];
  const records = slots.map((slot, index) => ({
    record_index: index, slot_candidate: slot,
    item_id_candidate: keyframe ? itemAt(chunk.index, rawParam, slot)
      : rawParam === FIRST_PARAM && block.timestamp_ms === 30000 && slot === 0
        ? 3866 : rawParam === FIRST_PARAM + 1 && slot === 2 ? 1036 : 0,
  }));
  const snapshot = Array.from({ length: 10 }, (_, slot) => {
    const record = records.find((entry) => entry.slot_candidate === slot);
    return {
      slot_candidate: slot, item_id_candidate: record?.item_id_candidate ?? null,
      value_basis: record ? 'DECODED_PACKET_RECORD'
        : 'CALLBACK_RESET_WITH_NO_PACKET_RECORD',
    };
  });
  const ref = {
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256,
    chunk_index: chunk.index, chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream, chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id, replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length, raw_param: rawParam,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
  return {
    event_type: 'HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: BROADCAST_PROFILE.id,
    replay_sha256: replay.source_sha256, replay_time_ms: block.timestamp_ms,
    hero_raw_param: rawParam, participant_id_candidate: participant,
    packet_stream: chunk.stream,
    snapshot_application: 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS',
    record_count: records.length, records_candidate: records,
    packet_slot_snapshot_candidate: snapshot,
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS',
    raw_packet_ref: ref,
  };
}

function fixture() {
  const frame = (time) => Buffer.concat(Array.from({ length: 10 }, (_, index) =>
    packet(FIRST_PARAM + index, time)));
  const replay = replayFromChunks([
    { stream: 2, body: frame(0) },
    { stream: 1, body: Buffer.concat([
      packet(FIRST_PARAM, 30), packet(NONCANONICAL_PARAM, 31),
      packet(FIRST_PARAM + 1, 40),
    ]) },
    { stream: 2, body: frame(60) },
    { stream: 1, body: packet(FIRST_PARAM, 90) },
  ], BUILD);
  const events = [];
  walkBlocks(replay, (block, chunk) => events.push(rowFromBlock(replay, block, chunk)),
    { strict: true });
  const unmapped = events.filter((row) => row.participant_id_candidate === null)
    .map((row) => row.raw_packet_ref);
  const inventoryBroadcastOutcome = {
    status: 'CANDIDATE', profile_id: BROADCAST_PROFILE.id,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: IMAGE_SHA256, input_packet_id: 0x0357,
    input_count: events.length, event_count: events.length,
    decoded_record_count: events.reduce((sum, row) => sum + row.record_count, 0),
    unmapped_raw_param_count: unmapped.length, unmapped_raw_packet_refs: unmapped,
    events,
  };
  const inventoryIntervalOutcome = deriveInterval(replay, { inventoryBroadcastOutcome });
  assert.equal(inventoryIntervalOutcome.status, 'CANDIDATE',
    inventoryIntervalOutcome.error);
  return { replay, inventoryBroadcastOutcome, inventoryIntervalOutcome };
}

function run(values) {
  return associate(values.replay, values);
}

test('821 game Broadcast bracket compares only explicit packet records', () => {
  const values = fixture();
  const result = run(values);
  assert.equal(PROFILE.capability, 'inventory_game_broadcast_keyframe_bracket');
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.runtime_image_status, 'MATCHED_USED');
  assert.equal(result.runtime_image_used, true);
  assert.equal(result.runtime_image_sha256, IMAGE_SHA256);
  assert.equal(result.input_count, 24);
  assert.equal(result.keyframe_count, 2);
  assert.equal(result.broadcast_keyframe_packet_count, 20);
  assert.equal(result.game_broadcast_packet_count, 4);
  assert.equal(result.bracketed_game_broadcast_count, 2);
  assert.equal(result.excluded_noncanonical_game_broadcast_count, 1);
  assert.equal(result.excluded_before_first_keyframe_count, 0);
  assert.equal(result.excluded_after_last_keyframe_count, 1);
  assert.equal(result.excluded_on_boundary_count, 0);
  assert.equal(result.excluded_noncanonical_game_broadcast_packet_refs.length, 1);
  assert.equal(result.excluded_after_last_keyframe_refs.length, 1);
  assert.equal(result.excluded_noncanonical_game_broadcast_packet_refs[0].raw_param,
    NONCANONICAL_PARAM);
  assert.equal(result.record_comparison_count, 12);
  assert.equal(result.distinct_participant_interval_count, 2);
  assert.deepEqual(result.comparison_counts, {
    SAME_AS_BOTH_ENDPOINTS: 10,
    DIFFERS_FROM_EQUAL_ENDPOINTS: 1,
    SAME_AS_PREVIOUS_ENDPOINT: 1,
    SAME_AS_NEXT_ENDPOINT: 0,
    DIFFERS_FROM_BOTH_ENDPOINTS: 0,
  });
  assert.equal(result.verified_raw_packet_count, 24);
  assert.equal(result.event_count, 2);
  assert.equal(result.events.length, 2);
  const first = result.events[0];
  assert.equal(first.event_type, 'INVENTORY_GAME_BROADCAST_KEYFRAME_BRACKET_CANDIDATE');
  assert.equal(first.hero_raw_param, FIRST_PARAM);
  assert.equal(first.participant_id_candidate, 1);
  assert.equal(first.previous_observation_time_ms, 0);
  assert.equal(first.game_observation_time_ms, 30000);
  assert.equal(first.next_observation_time_ms, 60000);
  assert.equal(first.replay_time_ms, 30000);
  assert.equal(first.observation_interval_ms, 60000);
  assert.deepEqual(first.record_comparisons_candidate[0], {
    slot_candidate: 0, previous_item_id_candidate: 3865,
    game_item_id_candidate: 3866, next_item_id_candidate: 3865,
    comparison_to_endpoints: 'DIFFERS_FROM_EQUAL_ENDPOINTS',
  });
  assert.deepEqual(first.unrecorded_game_slots_candidate, [6, 7, 8, 9]);
  assert.equal(first.record_comparisons_candidate.some((row) => row.slot_candidate === 9),
    false);
  assert.deepEqual(first.raw_packet_refs,
    [first.previous_raw_packet_ref, first.game_raw_packet_ref, first.next_raw_packet_ref]);
  assert.deepEqual(first.raw_packet_ref, first.game_raw_packet_ref);
  assert.equal('inventory_state_between_packets' in first, false);
  assert.equal('transaction_type' in first, false);
  assert.equal(result.events[1].record_comparisons_candidate[2]
    .comparison_to_endpoints, 'SAME_AS_PREVIOUS_ENDPOINT');
});

test('821 game Broadcast bracket derives a missing interval prerequisite', () => {
  const values = fixture();
  delete values.inventoryIntervalOutcome;
  const result = run(values);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.event_count, 2);
});

test('821 game Broadcast bracket propagates missing image and failed interval', () => {
  const missingImage = fixture();
  missingImage.inventoryBroadcastOutcome = {
    status: 'MISSING_INPUT', profile_id: BROADCAST_PROFILE.id,
    evidence_runtime_image_sha256: IMAGE_SHA256, input_packet_id: 0x0357,
    runtime_image_status: 'MISSING', runtime_image_used: false,
    error: 'runtime image is missing',
  };
  assert.equal(run(missingImage).status, 'MISSING_INPUT');
  const failed = fixture();
  failed.inventoryIntervalOutcome = { status: 'DECODE_FAILED', error: 'framing failed' };
  const result = run(failed);
  assert.equal(result.status, 'DECODE_FAILED');
  assert.equal(result.events, null);
  assert.equal(result.diagnostics.dependency_error, 'framing failed');
  const absent = fixture();
  delete absent.inventoryBroadcastOutcome;
  assert.equal(run(absent).status, 'MISSING_INPUT');
});

test('821 game Broadcast bracket rejects source, image, and interval identity drift', () => {
  const wrongBuild = fixture();
  wrongBuild.replay.header.version = '16.19.820.7193';
  assert.equal(run(wrongBuild).status, 'UNSUPPORTED');
  const wrongImage = fixture();
  wrongImage.inventoryBroadcastOutcome.runtime_image_sha256 = 'f'.repeat(64);
  assert.equal(run(wrongImage).status, 'INCONSISTENT');
  const wrongReplay = fixture();
  wrongReplay.inventoryBroadcastOutcome.events[0].replay_sha256 = 'f'.repeat(64);
  assert.equal(run(wrongReplay).status, 'INCONSISTENT');
  const wrongInterval = fixture();
  wrongInterval.inventoryIntervalOutcome.profile_id = 'other-profile';
  assert.equal(run(wrongInterval).status, 'INCONSISTENT');
  const wrongIntervalSlots = fixture();
  wrongIntervalSlots.inventoryIntervalOutcome.events[0]
    .changed_slots_candidate[0].current_item_id_candidate = 9999;
  assert.equal(run(wrongIntervalSlots).status, 'INCONSISTENT');
});

test('821 game Broadcast bracket fails closed on duplicate or malformed source rows', () => {
  const duplicate = fixture();
  duplicate.inventoryBroadcastOutcome.events[21] =
    structuredClone(duplicate.inventoryBroadcastOutcome.events[20]);
  assert.equal(run(duplicate).status, 'INCONSISTENT');
  const malformed = fixture();
  malformed.inventoryBroadcastOutcome.events[20].records_candidate[0]
    .item_id_candidate = -1;
  assert.equal(run(malformed).status, 'INCONSISTENT');
  const missingRoster = fixture();
  missingRoster.inventoryBroadcastOutcome.events.splice(0, 1);
  missingRoster.inventoryBroadcastOutcome.input_count -= 1;
  missingRoster.inventoryBroadcastOutcome.event_count -= 1;
  missingRoster.inventoryBroadcastOutcome.decoded_record_count -= 10;
  assert.equal(run(missingRoster).status, 'INCONSISTENT');
  const mutReplay = fixture();
  mutReplay.replay.buffer[0] ^= 1;
  assert.equal(run(mutReplay).status, 'DECODE_FAILED');
});
