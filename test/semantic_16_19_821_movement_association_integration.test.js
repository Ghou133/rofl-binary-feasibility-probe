'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const test = require('node:test');

const { parseReplayBuffer, walkBlocks } = require('../src/rofl');
const { RUNTIME_IMAGE_SHA256 } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const { HERO_DEATHS_SNAPSHOT_821_CANDIDATE_PROFILE } =
  require('../src/decoders/rofl_16_19_821_hero_stats_candidate');
const { HERO_INVENTORY_PACKET_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_inventory_packet_candidate');
const { DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_direct_input_turn_packet_candidate');
const { SET_MOVEMENT_DRIVER_PACKET_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_set_movement_driver_packet_candidate');

const BUILD = '16.19.821.7343';
const PARAM = 0x400000ae;
const SELECTED = ['hero_inventory_packet', 'hero_deaths_snapshot',
  'direct_input_movement_turn_packet', 'set_movement_driver_packet'];
const SPECS = {
  hero_inventory_packet: [HERO_INVENTORY_PACKET_CANDIDATE_PROFILE_821, 0x018d],
  hero_deaths_snapshot: [HERO_DEATHS_SNAPSHOT_821_CANDIDATE_PROFILE, 0x0089],
  direct_input_movement_turn_packet:
    [DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE_PROFILE_821, 0x00ba],
  set_movement_driver_packet: [SET_MOVEMENT_DRIVER_PACKET_CANDIDATE_PROFILE_821, 0x0335],
};

function packet(packetId, param, timeMs, length, prefix) {
  const payload = Buffer.alloc(length);
  Buffer.from(prefix, 'hex').copy(payload);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(param >>> 0, 11);
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

function fixture({ omitSet = false } = {}) {
  const stats = Array.from({ length: 10 }, (_, participant) =>
    Object.fromEntries(Array.from({ length: 7 }, (_, slot) =>
      [`ITEM${slot}`, String((participant + 1) * 100 + slot + 1)])));
  const game = Buffer.concat([
    packet(0x018d, PARAM, 1000, 23, '1e'),
    packet(0x00ba, PARAM, 1100, 13, '85'),
    ...(omitSet ? [] : [packet(0x0335, PARAM, 1200, 28, '26')]),
  ]);
  const keyframe = Buffer.concat(Array.from({ length: 10 }, (_, index) =>
    packet(0x0089, PARAM + index, 0, 1263, '6700de')));
  const version = Buffer.from(BUILD);
  const header = Buffer.alloc(15 + version.length);
  header.write('RIOT');
  header.writeUInt16LE(1, 4);
  header[14] = version.length;
  version.copy(header, 15);
  const metadata = Buffer.from(JSON.stringify({ gameLength: 600000,
    statsJson: JSON.stringify(stats) }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  const replay = parseReplayBuffer(Buffer.concat([
    header, chunk(0, 1, game), chunk(1, 2, keyframe),
    Buffer.alloc(256), metadata, trailer,
  ]), path.resolve('synthetic-821-movement-association-integration.rofl'));
  const observed = [];
  walkBlocks(replay, (block, sourceChunk) => observed.push({ block, chunk: sourceChunk }),
    { strict: true });
  const ref = ({ block, chunk: sourceChunk }) => ({
    source_path: replay.source_path, replay_sha256: replay.source_sha256,
    chunk_index: sourceChunk.index, chunk_id: sourceChunk.chunk_id,
    chunk_stream: sourceChunk.stream, chunk_file_offset: sourceChunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id, replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length, raw_param: block.param,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  });
  const base = (entry, eventType, profile, semanticStatus) => ({
    event_type: eventType, game_version: BUILD, build_profile: profile.id,
    replay_sha256: replay.source_sha256,
    replay_time_ms: entry.block.timestamp_ms,
    confidence: 'CANDIDATE', semantic_status: semanticStatus,
    raw_packet_ref: ref(entry),
  });
  const find = (id) => observed.filter(({ block }) => block.packet_id === id);
  const records = Array.from({ length: 7 }, (_, slot) => ({
    record_index: slot, slot_candidate: slot, item_id_candidate: 101 + slot,
  }));
  const inventory = [{
    ...base(find(0x018d)[0], 'HERO_INVENTORY_MAPVIEW_PACKET_CANDIDATE',
      SPECS.hero_inventory_packet[0], 'CANDIDATE_EXACT_RUNTIME_MAPVIEW_PACKET_FIELDS'),
    hero_raw_param: PARAM, participant_id_candidate: 1,
    snapshot_application: 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS',
    record_count: records.length, records_candidate: records,
  }];
  const snapshots = find(0x0089).map((entry, index) => ({
    ...base(entry, 'HERO_DEATHS_SNAPSHOT_CANDIDATE',
      SPECS.hero_deaths_snapshot[0],
      'CANDIDATE_EXACT_KR_821_RUNTIME_BYTE_DEATH_COUNT_TAIL_CORRELATION'),
    hero_raw_param: PARAM + index, participant_id_candidate: index + 1,
  }));
  const direct = [{
    ...base(find(0x00ba)[0], 'DIRECT_INPUT_MOVEMENT_TURN_PACKET_CANDIDATE',
      SPECS.direct_input_movement_turn_packet[0],
      'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS'),
    raw_param: PARAM, opaque_f32_0x10: 1, opaque_f32_0x14: 2, opaque_f32_0x18: 3,
  }];
  const set = omitSet ? [] : [{
    ...base(find(0x0335)[0], 'SET_MOVEMENT_DRIVER_PACKET_CANDIDATE',
      SPECS.set_movement_driver_packet[0],
      'CANDIDATE_EXACT_RUNTIME_PACKET_FIELD'),
    raw_param: PARAM, raw_payload_byte_0: 0x26, opaque_u8_0x2a: 2,
  }];
  return { replay, rows: {
    hero_inventory_packet: inventory,
    hero_deaths_snapshot: snapshots,
    direct_input_movement_turn_packet: direct,
    set_movement_driver_packet: set,
  } };
}

function outcomes(f) {
  return Object.fromEntries(Object.entries(f.rows).map(([name, events]) => {
    const [profile, packetId] = SPECS[name];
    const native = name !== 'hero_deaths_snapshot';
    return [name, {
      status: 'CANDIDATE', profile_id: profile.id, input_packet_id: packetId,
      evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
      input_count: events.length, event_count: events.length, events,
      scanned_block_count: native ? 13 : 10,
      runtime_image_status: native ? 'MATCHED_USED'
        : 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED',
      runtime_image_used: native,
      ...(native ? { runtime_image_sha256: RUNTIME_IMAGE_SHA256 }
        : { lookup_table_sha256: profile.lookup_table_sha256,
          observed_participant_count: 10 }),
    }];
  }));
}

test('selected 821 API association uses complete same-call outcomes and never labels movement rows', (t) => {
  const active = { values: null };
  const modules = [
    ['hero_inventory_packet',
      require('../src/decoders/rofl_16_19_821_inventory_packet_candidate'),
      'decodeHeroInventoryPacketCandidates821'],
    ['hero_deaths_snapshot',
      require('../src/decoders/rofl_16_19_821_hero_stats_candidate'),
      'decodeHeroDeathsSnapshotCandidates821'],
    ['direct_input_movement_turn_packet',
      require('../src/decoders/rofl_16_19_821_direct_input_turn_packet_candidate'),
      'decodeDirectInputMovementTurnPacketCandidates821'],
    ['set_movement_driver_packet',
      require('../src/decoders/rofl_16_19_821_set_movement_driver_packet_candidate'),
      'decodeSetMovementDriverPacketCandidates821'],
  ];
  for (const [name, module, method] of modules) {
    t.mock.method(module, method, () => structuredClone(active.values[name]));
  }
  delete require.cache[require.resolve('../src/semantic_api')];
  const { decodeSemanticReplay } = require('../src/semantic_api');
  t.after(() => { delete require.cache[require.resolve('../src/semantic_api')]; });
  const decode = (f, values = outcomes(f), selected = SELECTED) => {
    active.values = values;
    return decodeSemanticReplay(f.replay, {
      capabilities: selected,
      runtimeImagePath: 'mocked-exact-821-image',
    });
  };
  const association = (result) =>
    result.candidate_associations?.movement_full_param_participant_candidate;

  const full = fixture();
  const selected = decode(full);
  assert.equal(association(selected).status, 'CANDIDATE');
  assert.equal(association(selected).association_count, 1);
  assert.deepEqual(association(selected).movement_rows_sharing_candidate_full_key,
    { direct: 1, set: 1 });
  assert.equal(association(selected).association_scope,
    'REPLAY_FULL_RAW_PARAM_CANDIDATE_COVERAGE_ONLY');
  assert.equal(association(selected).per_packet_actor_status, 'UNVERIFIED');
  assert.equal(Object.hasOwn(selected.events.direct_input_movement_turn_packet_candidates[0],
    'participant_id_candidate'), false);
  assert.equal(Object.hasOwn(selected.events.set_movement_driver_packet_candidates[0],
    'participant_id_candidate'), false);
  assert.equal(association(decode(full, outcomes(full), SELECTED.slice(1))), undefined);
  assert.equal(association(decode(full, outcomes(full), SELECTED.slice(0, 3))).status,
    'CANDIDATE');

  const noSet = fixture({ omitSet: true });
  const absent = outcomes(noSet);
  absent.set_movement_driver_packet = {
    status: 'PROFILE_UNAVAILABLE', profile_id: SPECS.set_movement_driver_packet[0].id,
    input_packet_id: 0x0335, observed_raw_route_count: 0,
    input_count: null, event_count: null, events: null, scanned_block_count: 12,
  };
  const partial = decode(noSet, absent);
  assert.equal(partial.status, 'PARTIAL');
  assert.equal(association(partial).status, 'CANDIDATE');
  assert.deepEqual(association(partial).movement_rows_sharing_candidate_full_key,
    { direct: 1, set: 0 });
  assert.equal(association(partial).dependency_statuses.set_movement_driver_packet,
    'PROFILE_UNAVAILABLE');

  const missing = outcomes(full);
  missing.set_movement_driver_packet = { status: 'MISSING_INPUT', events: null };
  assert.equal(association(decode(full, missing)).status, 'UNAVAILABLE');
  const invalid = outcomes(full);
  invalid.direct_input_movement_turn_packet.runtime_image_sha256 = '0'.repeat(64);
  assert.equal(association(decode(full, invalid)).status, 'DECODE_FAILED');
  const incomplete = outcomes(full);
  incomplete.hero_inventory_packet.input_count += 1;
  assert.equal(association(decode(full, incomplete)).status, 'DECODE_FAILED');
  const mixedProfile = outcomes(full);
  mixedProfile.hero_deaths_snapshot.events[0].build_profile =
    'rofl-16.19.821.7343-kr-other-snapshot-candidate-v1';
  assert.equal(association(decode(full, mixedProfile)).status, 'DECODE_FAILED');
  const forged = outcomes(full);
  forged.direct_input_movement_turn_packet.events[0].raw_packet_ref.chunk_file_offset += 1;
  assert.equal(association(decode(full, forged)).status, 'DECODE_FAILED');
  const unprovenAbsence = outcomes(noSet);
  unprovenAbsence.set_movement_driver_packet = {
    ...absent.set_movement_driver_packet, observed_raw_route_count: 1,
  };
  assert.equal(association(decode(noSet, unprovenAbsence)).status, 'DECODE_FAILED');
});
