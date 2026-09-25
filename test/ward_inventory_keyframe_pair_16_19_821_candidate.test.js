'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { parseReplayFile, walkBlocks } = require('../src/rofl');
const { HERO_WARD_STATS_SNAPSHOT_821_CANDIDATE_PROFILE: WARD_PROFILE } =
  require('../src/decoders/rofl_16_19_821_aux_counts_candidate');
const { HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821: BROADCAST_PROFILE } =
  require('../src/decoders/rofl_16_19_821_inventory_broadcast_packet_candidate');
const { RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256 } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const { WARD_INVENTORY_KEYFRAME_PAIR_821_PROFILE,
  associateWardInventoryKeyframePairCandidates821: associate } =
  require('../src/decoders/rofl_16_19_821_ward_inventory_keyframe_pair_candidate');

const BUILD = '16.19.821.7343';
const ZERO_BYTE = 0x97;

function packet(packetId, rawParam, body, timeMs = 1000) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(body.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, body]);
}

function wardPayload() {
  const body = Buffer.alloc(1263, ZERO_BYTE);
  Buffer.from('6700de', 'hex').copy(body);
  return body;
}

function broadcastPayload() {
  const body = Buffer.alloc(79);
  body[0] = 0x1e;
  return body;
}

function ref(replay, block, chunk) {
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
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function records(count) {
  return Array.from({ length: count }, (_, slot) => ({
    record_index: slot, slot_candidate: slot,
    item_id_candidate: slot === 7 ? 2001 : 0,
  }));
}

function slotSnapshot(rows) {
  const values = new Map(rows.map((row) => [row.slot_candidate, row.item_id_candidate]));
  return Array.from({ length: 10 }, (_, slot) => ({
    slot_candidate: slot,
    item_id_candidate: values.get(slot) ?? null,
    value_basis: values.has(slot) ? 'DECODED_PACKET_RECORD'
      : 'CALLBACK_RESET_WITH_NO_PACKET_RECORD',
  }));
}

function fixture() {
  const keyframe = [];
  for (let participant = 1; participant <= 10; participant += 1) {
    const param = 0x400000ad + participant;
    keyframe.push(packet(0x0357, param, broadcastPayload()));
    keyframe.push(packet(0x0089, param, wardPayload()));
  }
  const replay = replayFromChunks([
    { stream: 2, body: Buffer.concat(keyframe) },
    // Same param/time as the first keyframe pair; its different stream/chunk
    // must never make it a substitute for the keyframe Broadcast packet.
    { stream: 1, body: packet(0x0357, 0x400000ae, broadcastPayload(), 1000) },
  ], BUILD);
  const wardEvents = [];
  const broadcastEvents = [];
  walkBlocks(replay, (block, chunk) => {
    const raw = ref(replay, block, chunk);
    const participant = block.param - 0x400000ad;
    if (block.packet_id === 0x0089) {
      wardEvents.push({
        event_type: 'HERO_WARD_STATS_SNAPSHOT_CANDIDATE', game_version: BUILD,
        build_profile: WARD_PROFILE.id, replay_sha256: replay.source_sha256,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_821_RUNTIME_KEYFRAME_BYTE_AND_REPLAY_TAIL',
        observation_kind: 'KEYFRAME_SNAPSHOT',
        replay_time_ms: block.timestamp_ms,
        hero_raw_param: block.param >>> 0, participant_id_candidate: participant,
        ward_placed_detector_candidate: 0, ward_killed_candidate: 0,
        ward_placed_candidate: 0,
        raw_ward_placed_detector_byte: ZERO_BYTE,
        raw_ward_killed_byte: ZERO_BYTE, raw_ward_placed_byte: ZERO_BYTE,
        field_confidence: {}, raw_packet_ref: raw,
      });
    } else {
      const rows = records(chunk.stream === 'keyframe' ? 10 : 6);
      broadcastEvents.push({
        event_type: 'HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE', game_version: BUILD,
        build_profile: BROADCAST_PROFILE.id, replay_sha256: replay.source_sha256,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS',
        replay_time_ms: block.timestamp_ms,
        hero_raw_param: block.param >>> 0, participant_id_candidate: participant,
        packet_stream: chunk.stream,
        snapshot_application: 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS',
        record_count: rows.length, records_candidate: rows,
        packet_slot_snapshot_candidate: slotSnapshot(rows), raw_packet_ref: raw,
      });
    }
  }, { strict: true });
  const wardStatsOutcome = {
    status: 'CANDIDATE', profile_id: WARD_PROFILE.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    runtime_image_used: false,
    runtime_image_status: 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED',
    input_packet_id: 0x0089, input_count: 10, event_count: 10,
    observed_participant_count: 10, events: wardEvents,
  };
  const inventoryBroadcastOutcome = {
    status: 'CANDIDATE', profile_id: BROADCAST_PROFILE.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_image_used: true, runtime_image_status: 'MATCHED_USED',
    input_packet_id: 0x0357, input_count: 11, event_count: 11,
    decoded_record_count: 106, events: broadcastEvents,
  };
  return { replay, wardStatsOutcome, inventoryBroadcastOutcome };
}

test('821 ward/inventory pair joins only complete physical keyframe observations', () => {
  const values = fixture();
  const result = associate(values.replay, values);
  assert.equal(WARD_INVENTORY_KEYFRAME_PAIR_821_PROFILE.capability,
    'ward_inventory_keyframe_pair');
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.event_count, 10);
  assert.equal(result.ward_snapshot_count, 10);
  assert.equal(result.broadcast_keyframe_count, 10);
  assert.equal(result.excluded_game_broadcast_count, 1);
  assert.equal(result.verified_raw_packet_count, 21);
  assert.equal(result.events[0].event_type, 'WARD_INVENTORY_KEYFRAME_PAIR_CANDIDATE');
  assert.equal(result.events[0].inventory_records_candidate.length, 10);
  assert.equal(result.events[0].inventory_packet_slot_snapshot_candidate[7].item_id_candidate,
    2001);
  assert.deepEqual(result.events[0].raw_packet_refs.map((raw) => raw.packet_id),
    [0x0357, 0x0089]);
  assert.equal('ward_placed_time_ms' in result.events[0], false);
  assert.equal('inventory_state_between_packets' in result.events[0], false);
});

test('821 ward/inventory pair requires exact source outcomes and image', () => {
  const missing = fixture();
  assert.equal(associate(missing.replay, {
    wardStatsOutcome: missing.wardStatsOutcome,
  }).status, 'MISSING_INPUT');
  const unavailable = fixture();
  unavailable.inventoryBroadcastOutcome.status = 'MISSING_INPUT';
  assert.equal(associate(unavailable.replay, unavailable).status, 'MISSING_INPUT');
  const wrongBuild = fixture();
  wrongBuild.replay.header.version = '16.19.820.7193';
  assert.equal(associate(wrongBuild.replay, wrongBuild).status, 'UNSUPPORTED');
  const wrongProfile = fixture();
  wrongProfile.wardStatsOutcome.profile_id = 'wrong-profile';
  assert.equal(associate(wrongProfile.replay, wrongProfile).status, 'INCONSISTENT');
  const wrongImage = fixture();
  wrongImage.inventoryBroadcastOutcome.runtime_image_sha256 = 'f'.repeat(64);
  assert.equal(associate(wrongImage.replay, wrongImage).status, 'INCONSISTENT');
});

test('821 ward/inventory pair rejects missing, duplicate, and time-only matches', () => {
  const missing = fixture();
  missing.inventoryBroadcastOutcome.events.splice(0, 1);
  missing.inventoryBroadcastOutcome.event_count -= 1;
  missing.inventoryBroadcastOutcome.input_count -= 1;
  missing.inventoryBroadcastOutcome.decoded_record_count -= 10;
  const result = associate(missing.replay, missing);
  assert.equal(result.status, 'INCONSISTENT');
  assert.equal(result.events, null);
  const duplicate = fixture();
  duplicate.inventoryBroadcastOutcome.events[1] = duplicate.inventoryBroadcastOutcome.events[0];
  assert.equal(associate(duplicate.replay, duplicate).status, 'INCONSISTENT');
  const wrongChunk = fixture();
  wrongChunk.inventoryBroadcastOutcome.events[0].raw_packet_ref.chunk_index = 1;
  assert.equal(associate(wrongChunk.replay, wrongChunk).status, 'INCONSISTENT');
  const gameOnly = fixture();
  gameOnly.inventoryBroadcastOutcome.events.splice(0, 1);
  gameOnly.inventoryBroadcastOutcome.event_count -= 1;
  gameOnly.inventoryBroadcastOutcome.input_count -= 1;
  gameOnly.inventoryBroadcastOutcome.decoded_record_count -= 10;
  assert.equal(associate(gameOnly.replay, gameOnly).status, 'INCONSISTENT');
});

test('821 ward/inventory pair checks physical packet bytes and candidate values', () => {
  const mutatedSource = fixture();
  mutatedSource.replay.buffer[0] ^= 1;
  assert.equal(associate(mutatedSource.replay, mutatedSource).status, 'DECODE_FAILED');
  const forgedHash = fixture();
  forgedHash.wardStatsOutcome.events[0].raw_packet_ref.raw_payload_sha256 = 'f'.repeat(64);
  assert.equal(associate(forgedHash.replay, forgedHash).status, 'INCONSISTENT');
  const forgedValue = fixture();
  forgedValue.wardStatsOutcome.events[0].ward_placed_candidate = 1;
  assert.equal(associate(forgedValue.replay, forgedValue).status, 'INCONSISTENT');
  const forgedItem = fixture();
  forgedItem.inventoryBroadcastOutcome.events[0].records_candidate[0].item_id_candidate = 3340;
  assert.equal(associate(forgedItem.replay, forgedItem).status, 'INCONSISTENT');
});

test('one supplied KR Replay pairs independently decoded ward and Broadcast candidates', (t) => {
  const replayPath = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
    'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');
  const artifactRoot = path.resolve(__dirname, '..', 'artifacts', '16_19_development');
  const wardDir = path.join(artifactRoot, 'kr_821_ward_cannon_11', 'replays', 'KR_8392938200');
  const broadcastDir = path.join(artifactRoot, 'inventory_three_routes_cli_batch_821',
    'replays', 'KR_8392938200');
  const inputs = [
    replayPath,
    path.join(wardDir, 'semantic_run.json'),
    path.join(wardDir, 'hero_ward_stats_snapshot_candidates.jsonl'),
    path.join(broadcastDir, 'semantic_run.json'),
    path.join(broadcastDir, 'hero_inventory_broadcast_packet_candidates.jsonl'),
  ];
  if (!inputs.every(fs.existsSync)) {
    t.skip('supplied private Replay or independently decoded local outputs absent');
    return;
  }
  const outcome = (directory, capability, stream) => ({
    ...JSON.parse(fs.readFileSync(path.join(directory, 'semantic_run.json'), 'utf8'))
      .capability_results[capability],
    events: fs.readFileSync(path.join(directory, `${stream}.jsonl`), 'utf8')
      .trim().split(/\r?\n/).map(JSON.parse),
  });
  const result = associate(parseReplayFile(replayPath), {
    wardStatsOutcome: outcome(wardDir, 'hero_ward_stats_snapshot',
      'hero_ward_stats_snapshot_candidates'),
    inventoryBroadcastOutcome: outcome(broadcastDir, 'hero_inventory_broadcast_packet',
      'hero_inventory_broadcast_packet_candidates'),
  });
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.event_count, 330);
  assert.equal(result.excluded_game_broadcast_count, 11);
  assert.equal(result.verified_raw_packet_count, 671);
});
