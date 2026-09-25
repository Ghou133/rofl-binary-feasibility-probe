'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { parseReplayBuffer, parseReplayFile, walkBlocks } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { collect821Routes } = require('../src/decoders/rofl_16_19_821_scan');
const { PROFILES } = require('../src/decoders/rofl_16_19_821_float_stats_candidate');
const {
  decodeHeroFloatSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_float_stats_candidate');
const {
  decodeHeroDeathCandidates821,
} = require('../src/decoders/rofl_16_19_821_7343');
const {
  RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256, decodeRuntimeCountByte,
} = require('../src/decoders/rofl_16_19_821_runtime_bytes');
const {
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: DAMAGE_PROFILE,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821: DAMAGE_V3_ID,
  decodeUnitApplyDamagePacketCandidates821,
  decodeUnitApplyDamageCallbackF32FromRaw821,
  decodeUnitApplyDamageLookupKeyFromRaw821,
} = require('../src/decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');
const {
  HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_821_PROFILE: profile,
  HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_PROFILE_V1_821: v1Profile,
  associateHeroDeathDamageLookupKeyCooccurrence821: associate,
} = require('../src/decoders/rofl_16_19_821_hero_death_damage_lookup_key_cooccurrence_candidate');

const BUILD = '16.19.821.7343';
const VICTIM_KEY = 0x400000ae;
const SOURCE_KEY = 0x400000b3;
const SNAPSHOT_PROFILE = PROFILES.hero_minions_killed_snapshot;
const DAMAGE_PAYLOAD = Buffer.from('71875e460b083dbaef3ba6ec39b975', 'hex');
const IMAGE_PATH = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY_PATH = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packet(packetId, rawParam, payload, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

const ENCODE_COUNT = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));

function snapshotPayload() {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  for (const offset of SNAPSHOT_PROFILE.raw_payload_byte_offsets) {
    payload[offset] = ENCODE_COUNT.get(0);
  }
  return payload;
}

function encodedLookupKey(key, objectOffset) {
  const seed = objectOffset === 0x24
    ? Buffer.from('b7294929', 'hex') : Buffer.from('39e504c3', 'hex');
  const desired = Buffer.alloc(4);
  desired.writeUInt32LE(key >>> 0);
  const encoded = Buffer.from(seed);
  for (let position = 0; position < 4; position += 1) {
    let found = false;
    for (let byte = 0; byte < 256; byte += 1) {
      const probe = Buffer.from(seed);
      probe[position] = byte;
      const decoded = decodeUnitApplyDamageLookupKeyFromRaw821(
        probe.toString('hex'), objectOffset);
      if (decoded !== null && ((decoded >>> (position * 8)) & 0xff)
          === desired[position]) {
        encoded[position] = byte;
        found = true;
        break;
      }
    }
    assert.equal(found, true);
  }
  assert.equal(decodeUnitApplyDamageLookupKeyFromRaw821(
    encoded.toString('hex'), objectOffset), key >>> 0);
  return encoded.toString('hex');
}

function ref(replay, block, chunk, damage = false) {
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
    ...(damage ? { raw_payload_hex: block.payload.toString('hex') } : {}),
    raw_payload_sha256: sha256(block.payload),
  };
}

function withPhysicalTail(replay, stats) {
  const metadata = Buffer.from(JSON.stringify({
    gameLength: 600000, statsJson: JSON.stringify(stats),
  }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  return parseReplayBuffer(Buffer.concat([
    replay.buffer.subarray(0, replay.tail.metadata_start), metadata, trailer,
  ]), replay.source_path);
}

// Physical synthetic Replay packets establish the row/reference integrity
// rules. They do not stand in for a native 821 runtime execution.
function fixture({ version = BUILD, firstKey24 = VICTIM_KEY,
  secondKey24 = VICTIM_KEY, sourceWire = '3678',
  firstKey2c = SOURCE_KEY, secondKey2c = VICTIM_KEY + 1 } = {}) {
  const rosterPackets = Array.from({ length: 10 }, (_, index) =>
    packet(0x0089, VICTIM_KEY + index, snapshotPayload(), 0));
  const diePayload = Buffer.alloc(37, 0x38);
  diePayload.set(Buffer.from(sourceWire, 'hex'), 35);
  const damageSpecs = [
    { rawParam: VICTIM_KEY + 0x100, key24: firstKey24,
      key2c: firstKey2c, time: 1000 },
    { rawParam: VICTIM_KEY + 1, key24: VICTIM_KEY + 1,
      key2c: SOURCE_KEY, time: 1000 },
    { rawParam: VICTIM_KEY, key24: secondKey24,
      key2c: secondKey2c, time: 1000 },
    { rawParam: VICTIM_KEY, key24: VICTIM_KEY,
      key2c: SOURCE_KEY, time: 1001 },
    { rawParam: VICTIM_KEY, key24: VICTIM_KEY,
      key2c: SOURCE_KEY, time: 1000 },
  ];
  const gameBody = Buffer.concat([
    packet(0x005f, damageSpecs[0].rawParam, DAMAGE_PAYLOAD, 1000),
    packet(0x005f, damageSpecs[1].rawParam, DAMAGE_PAYLOAD, 1000),
    packet(0x031b, 0, Buffer.alloc(12, 0x1b), 1000),
    packet(0x0259, VICTIM_KEY, Buffer.alloc(5, 0x59), 1000),
    packet(0x0438, VICTIM_KEY, diePayload, 1000),
    packet(0x005f, damageSpecs[2].rawParam, DAMAGE_PAYLOAD, 1000),
    packet(0x005f, damageSpecs[3].rawParam, DAMAGE_PAYLOAD, 1001),
  ]);
  let replay = replayFromChunks([
    { stream: 2, body: Buffer.concat(rosterPackets) },
    { stream: 1, body: gameBody },
    { stream: 1, body: packet(0x005f,
      damageSpecs[4].rawParam, DAMAGE_PAYLOAD, 1000) },
  ], version);
  const decodedSource = sourceWire === '0000' ? null
    : sourceWire === '3478' ? 0x400000a6 : SOURCE_KEY;
  replay = withPhysicalTail(replay, Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: String(index === 0 ? 1 : 0),
    CHAMPIONS_KILLED: String(decodedSource === SOURCE_KEY && index === 5 ? 1 : 0),
  })));
  const snapshotEvents = [];
  const damageEvents = [];
  const relations = { EQUAL: 0, RAW_PARAM_IS_LOOKUP_PLUS_0X100: 0, OTHER: 0 };
  const nativeInput = crypto.createHash('sha256');
  const nativeHeader = Buffer.alloc(8);
  walkBlocks(replay, (block, chunk) => {
    if (block.packet_id === 0x0089) {
      const rawField = Buffer.from(SNAPSHOT_PROFILE.raw_payload_byte_offsets
        .map((offset) => block.payload[offset])).toString('hex');
      snapshotEvents.push({
        event_type: 'HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: SNAPSHOT_PROFILE.id,
        replay_sha256: replay.source_sha256, replay_time_ms: block.timestamp_ms,
        hero_raw_param: block.param >>> 0,
        participant_id_candidate: (block.param >>> 0) - VICTIM_KEY + 1,
        observation_kind: 'KEYFRAME_SNAPSHOT',
        raw_payload_field_bytes_hex: rawField,
        minions_killed_raw_f32_candidate: 0,
        minions_killed_floor_candidate: 0,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL',
        raw_packet_ref: ref(replay, block, chunk),
      });
      return;
    }
    if (block.packet_id !== 0x005f) return;
    const spec = damageSpecs[damageEvents.length];
    nativeHeader.writeUInt32LE(block.param >>> 0, 0);
    nativeHeader.writeUInt32LE(block.payload.length, 4);
    nativeInput.update(nativeHeader);
    nativeInput.update(block.payload);
    const relation = (block.param >>> 0) === spec.key24 ? 'EQUAL'
      : (block.param >>> 0) - spec.key24 === 0x100
        ? 'RAW_PARAM_IS_LOOKUP_PLUS_0X100' : 'OTHER';
    relations[relation] += 1;
    damageEvents.push({
      event_type: 'UNIT_APPLY_DAMAGE_PACKET_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: DAMAGE_V3_ID,
      replay_sha256: replay.source_sha256, replay_time_ms: block.timestamp_ms,
      raw_param: block.param >>> 0,
      packet_name_candidate: DAMAGE_PROFILE.packet_name,
      header_selector_bits_24_26: block.payload[3] & 7,
      header_selector_bits_0_2: block.payload[0] & 7,
      header_selector_bits_3_5: (block.payload[0] >>> 3) & 7,
      native_callback_f32_0x20_candidate:
        decodeUnitApplyDamageCallbackF32FromRaw821('083dbaef'),
      native_callback_f32_0x20_source: 'RAW_READER',
      native_callback_f32_0x20_raw_offset: 5,
      native_callback_f32_0x20_raw_bytes_hex: '083dbaef',
      native_callback_lookup_key_u32_0x24_candidate: spec.key24,
      native_callback_lookup_key_0x24_encoded_bytes_hex:
        encodedLookupKey(spec.key24, 0x24),
      native_callback_lookup_key_u32_0x2c_candidate: spec.key2c,
      native_callback_lookup_key_0x2c_encoded_bytes_hex:
        encodedLookupKey(spec.key2c, 0x2c),
      native_callback_lookup_key_0x24_raw_param_relation: relation,
      semantic_effect_status: 'UNKNOWN', confidence: 'CANDIDATE',
      semantic_status: DAMAGE_PROFILE.evidence_status,
      raw_packet_ref: ref(replay, block, chunk, true),
    });
  }, { strict: true });
  const heroDeathOutcome = decodeHeroDeathCandidates821(replay);
  if (version === BUILD) {
    assert.equal(heroDeathOutcome.status, 'CANDIDATE', heroDeathOutcome.error);
  }
  const unitApplyDamagePacketOutcome = {
    status: 'CANDIDATE', profile_id: DAMAGE_V3_ID,
    evidence_status: DAMAGE_PROFILE.evidence_status,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    evidence_scalar_table_sha256: DAMAGE_PROFILE.evidence_scalar_table_sha256,
    evidence_shape_catalog_sha256: DAMAGE_PROFILE.evidence_shape_catalog_sha256,
    evidence_lookup_key_0x24_table_sha256:
      DAMAGE_PROFILE.evidence_lookup_key_0x24_table_sha256,
    evidence_lookup_key_0x2c_table_sha256:
      DAMAGE_PROFILE.evidence_lookup_key_0x2c_table_sha256,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    input_packet_id: 0x005f, input_count: damageEvents.length,
    event_count: damageEvents.length,
    native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: damageEvents.length,
    native_callback_f32_available_count: damageEvents.length,
    native_callback_f32_source_counts: {
      RAW_READER: damageEvents.length, CONSTANT_0: 0,
      CONSTANT_1: 0, CONSTANT_2: 0,
    },
    native_callback_lookup_full_write_count: damageEvents.length,
    native_callback_lookup_key_0x24_raw_param_relation_counts: relations,
    native_input_sha256: nativeInput.digest('hex'),
    events: damageEvents,
  };
  const minionsKilledSnapshotOutcome = {
    status: 'CANDIDATE', profile_id: SNAPSHOT_PROFILE.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    runtime_image_status: 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED',
    runtime_image_used: false,
    input_packet_id: 0x0089, input_count: snapshotEvents.length,
    event_count: snapshotEvents.length, keyframe_count: 1,
    observed_participant_count: 10, events: snapshotEvents,
  };
  return { replay, heroDeathOutcome, unitApplyDamagePacketOutcome,
    minionsKilledSnapshotOutcome };
}

test('same chunk/ms victim key retains all before/after packets and exact source equality', () => {
  const values = fixture();
  const result = associate(values.replay, values);
  assert.equal(profile.capability, 'hero_death_damage_lookup_key_cooccurrence');
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.profile_id, v1Profile.id);
  assert.equal(result.event_count, 1);
  assert.equal(result.damage_packet_count, 5);
  assert.equal(result.matched_victim_key24_packet_count, 2);
  assert.equal(result.death_anchor_with_victim_key24_packet_count, 1);
  assert.equal(result.multiple_victim_key24_packet_anchor_count, 1);
  assert.equal(result.max_victim_key24_packet_count_per_anchor, 2);
  assert.equal(result.matched_die_source_key2c_packet_count, 1);
  assert.equal(result.death_anchor_with_die_source_key2c_match_count, 1);
  assert.equal(result.verified_raw_damage_roster_packet_count, 15);
  assert.equal(result.verified_hero_death_route_packet_count, 3);
  const row = result.events[0];
  assert.equal(row.victim_lookup_roster_key_u32_candidate, VICTIM_KEY);
  assert.equal(row.die_source_network_id_candidate, SOURCE_KEY);
  assert.equal(row.die_source_key2c_match_status, 'HAS_SAME_TIME_MATCH');
  assert.deepEqual(row.same_time_victim_key24_packet_candidates.map((packetRow) =>
    packetRow.relative_to_death_primary), ['BEFORE_PRIMARY', 'AFTER_PRIMARY']);
  assert.deepEqual(row.same_time_victim_key24_packet_candidates.map((packetRow) =>
    packetRow.die_source_key2c_equal), [true, false]);
  assert.equal(row.same_time_victim_key24_packet_before_primary_count, 1);
  assert.equal(row.same_time_victim_key24_packet_after_primary_count, 1);
  assert.deepEqual(row.hero_death_raw_packet_refs,
    values.heroDeathOutcome.events[0].raw_packet_refs);
  assert.deepEqual(row.raw_packet_refs.map((item) => item.packet_id),
    [0x0259, 0x0438, 0x031b, 0x0089, 0x005f, 0x005f]);
  assert.equal(row.lookup_resolution_status, 'UNKNOWN');
  assert.equal(row.actor_assignment_status, 'UNKNOWN');
  assert.equal(row.source_target_role_status, 'UNKNOWN');
  assert.equal(row.semantic_effect_status, 'UNKNOWN');
  for (const forbidden of ['selected_fatal_packet', 'actual_damage',
    'source', 'target', 'damage_amount']) assert.equal(forbidden in row, false);
});

test('zero same-time matches stay a death anchor with an empty packet list', () => {
  const values = fixture({ firstKey24: VICTIM_KEY + 2,
    secondKey24: VICTIM_KEY + 3 });
  const result = associate(values.replay, values);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.event_count, 1);
  assert.equal(result.matched_victim_key24_packet_count, 0);
  assert.equal(result.death_anchor_without_victim_key24_packet_count, 1);
  assert.equal(result.death_anchor_without_die_source_key2c_match_count, 1);
  assert.equal(result.events[0].die_source_key2c_match_status, 'NO_SAME_TIME_MATCH');
  assert.deepEqual(result.events[0].same_time_victim_key24_packet_candidates, []);
});

test('nonhero source key equality and unavailable source remain distinct', () => {
  const nonhero = fixture({ sourceWire: '3478', firstKey2c: 0x400000a6 });
  const matched = associate(nonhero.replay, nonhero);
  assert.equal(matched.status, 'CANDIDATE', matched.error);
  assert.equal(nonhero.heroDeathOutcome.events[0].killer_participant_id_candidate, null);
  assert.equal(matched.events[0].same_time_die_source_key2c_packet_candidate_count, 1);
  assert.equal(matched.events[0].die_source_key2c_match_status, 'HAS_SAME_TIME_MATCH');
  const unavailable = fixture({ sourceWire: '0000' });
  const result = associate(unavailable.replay, unavailable);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.death_anchor_die_source_unavailable_count, 1);
  assert.equal(result.death_anchor_without_die_source_key2c_match_count, 0);
  assert.equal(result.events[0].same_time_die_source_key2c_packet_candidate_count, null);
  assert.equal(result.events[0].die_source_key2c_match_status, 'DIE_SOURCE_UNAVAILABLE');
  assert.deepEqual(result.events[0].same_time_victim_key24_packet_candidates
    .map((item) => item.die_source_key2c_equal), [null, null]);
});

test('wrong build and incomplete or altered source candidates fail closed', () => {
  const wrong = fixture({ version: '16.19.821.7344' });
  assert.equal(associate(wrong.replay, wrong).status, 'UNSUPPORTED');
  const missing = fixture();
  assert.equal(associate(missing.replay).status, 'MISSING_INPUT');
  const changedDeath = fixture();
  changedDeath.heroDeathOutcome.events[0].die_source_network_id_candidate += 1;
  assert.equal(associate(changedDeath.replay, changedDeath).status, 'INCONSISTENT');
  const changedLookup = fixture();
  changedLookup.unitApplyDamagePacketOutcome.events[0]
    .native_callback_lookup_key_0x2c_encoded_bytes_hex = '00000000';
  assert.equal(associate(changedLookup.replay, changedLookup).status, 'INCONSISTENT');
  const incomplete = fixture();
  incomplete.unitApplyDamagePacketOutcome.native_callback_lookup_full_write_count -= 1;
  assert.equal(associate(incomplete.replay, incomplete).status, 'INCONSISTENT');
  const changedTail = fixture();
  changedTail.replay.tail.stats[0].NUM_DEATHS = '2';
  assert.equal(associate(changedTail.replay, changedTail).status, 'INCONSISTENT');
  const changedBytes = fixture();
  changedBytes.replay.buffer[0] ^= 1;
  assert.equal(associate(changedBytes.replay, changedBytes).status, 'DECODE_FAILED');
});

test('same-run route scan reuse preserves rows and rejects foreign or changed sources', () => {
  const values = fixture();
  const token = collect821Routes(values.replay, ['hero_death']);
  const independent = associate(values.replay, values);
  const reused = associate(values.replay, { ...values, precollected: token });
  assert.equal(independent.status, 'CANDIDATE', independent.error);
  assert.deepEqual(reused, independent);

  const foreign = fixture();
  const foreignResult = associate(foreign.replay, {
    ...foreign, precollected: token,
  });
  assert.equal(foreignResult.status, 'DECODE_FAILED');

  values.replay.buffer[0] ^= 1;
  const changed = associate(values.replay, { ...values, precollected: token });
  assert.equal(changed.status, 'DECODE_FAILED');
});

test('one original KR exact-build Replay preserves full source-bound packet multiplicity', {
  skip: !fs.existsSync(IMAGE_PATH) || !fs.existsSync(REPLAY_PATH)
    ? 'exact private image or original KR Replay is unavailable' : false,
}, () => {
  const replay = parseReplayFile(REPLAY_PATH);
  const heroDeathOutcome = decodeHeroDeathCandidates821(replay);
  const unitApplyDamagePacketOutcome = decodeUnitApplyDamagePacketCandidates821(replay,
    { runtimeImagePath: IMAGE_PATH });
  const minionsKilledSnapshotOutcome = decodeHeroFloatSnapshotCandidates821(replay,
    'hero_minions_killed_snapshot');
  assert.equal(heroDeathOutcome.status, 'CANDIDATE', heroDeathOutcome.error);
  assert.equal(unitApplyDamagePacketOutcome.status, 'CANDIDATE',
    unitApplyDamagePacketOutcome.error);
  assert.equal(minionsKilledSnapshotOutcome.status, 'CANDIDATE',
    minionsKilledSnapshotOutcome.error);
  const result = associate(replay, {
    heroDeathOutcome, unitApplyDamagePacketOutcome,
    minionsKilledSnapshotOutcome,
  });
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.event_count, heroDeathOutcome.event_count);
  assert.equal(result.damage_packet_count, unitApplyDamagePacketOutcome.event_count);
  assert.equal(result.death_anchor_with_victim_key24_packet_count
    + result.death_anchor_without_victim_key24_packet_count, result.event_count);
  assert.equal(result.matched_victim_key24_packet_count,
    result.events.reduce((sum, row) =>
      sum + row.same_time_victim_key24_packet_candidates.length, 0));
  assert.ok(result.multiple_victim_key24_packet_anchor_count > 0);
  assert.ok(result.events.every((row) => row.semantic_effect_status === 'UNKNOWN'));
});
