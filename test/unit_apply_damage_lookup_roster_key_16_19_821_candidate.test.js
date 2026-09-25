'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile, walkBlocks } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { PROFILES } = require('../src/decoders/rofl_16_19_821_float_stats_candidate');
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
  decodeHeroFloatSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_float_stats_candidate');
const {
  associateUnitApplyDamageRosterKeys821,
} = require('../src/decoders/rofl_16_19_821_unit_apply_damage_roster_key_candidate');
const {
  UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_821_PROFILE: profile,
  UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V1_821: v1Profile,
  associateUnitApplyDamageLookupRosterKeys821: associate,
} = require('../src/decoders/rofl_16_19_821_unit_apply_damage_lookup_roster_key_candidate');

const BUILD = '16.19.821.7343';
const FIRST_KEY = 0x400000ae;
const SNAPSHOT_PROFILE = PROFILES.hero_minions_killed_snapshot;
const COMMON_PAYLOAD = Buffer.from('71875e460b083dbaef3ba6ec39b975', 'hex');
const IMAGE_PATH = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY_PATH = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function packet(packetId, rawParam, payload, timeMs = 1000) {
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
  for (let index = 0; index < 4; index += 1) {
    payload[1262 - 0x3c - index] = ENCODE_COUNT.get(0);
  }
  return payload;
}

// Use the public exact-build transform as a black box to create synthetic
// source rows. The production module never owns or copies its lookup table.
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
    ...(block.packet_id === 0x005f
      ? { raw_payload_hex: block.payload.toString('hex') } : {}),
    raw_payload_sha256: sha256(block.payload),
  };
}

// The source outcomes follow the existing decoder schema; these bytes do not
// claim a fresh native execution. One original Replay is tested separately.
function fixture({ version = BUILD, missingRosterKey = false,
  damagePairs = [
    [FIRST_KEY, FIRST_KEY],
    [FIRST_KEY + 0x100, FIRST_KEY],
    [0x40004007, FIRST_KEY + 1],
    [0x40004008, 0x40004007],
    [FIRST_KEY + 0x101, 0x40004007],
  ] } = {}) {
  const statsKeys = Array.from({ length: missingRosterKey ? 9 : 10 },
    (_, index) => FIRST_KEY + index);
  const chunks = [
    { stream: 2, body: Buffer.concat(statsKeys.map((key) =>
      packet(0x0089, key, snapshotPayload()))) },
    { stream: 1, body: Buffer.concat(damagePairs.map(([rawParam], index) =>
      packet(0x005f, rawParam, COMMON_PAYLOAD, 1500 + 100 * index))) },
  ];
  const replay = replayFromChunks(chunks, version);
  const damageEvents = [];
  const snapshotEvents = [];
  const relations = {
    EQUAL: 0, RAW_PARAM_IS_LOOKUP_PLUS_0X100: 0, OTHER: 0,
  };
  const nativeInput = crypto.createHash('sha256');
  const nativeHeader = Buffer.alloc(8);
  walkBlocks(replay, (block, chunk) => {
    if (block.packet_id !== 0x005f && block.packet_id !== 0x0089) return;
    const sourceRef = ref(replay, block, chunk);
    if (block.packet_id === 0x0089) {
      const rawField = Buffer.from(SNAPSHOT_PROFILE.raw_payload_byte_offsets
        .map((offset) => block.payload[offset])).toString('hex');
      snapshotEvents.push({
        event_type: 'HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: SNAPSHOT_PROFILE.id,
        replay_sha256: replay.source_sha256, replay_time_ms: block.timestamp_ms,
        hero_raw_param: block.param >>> 0,
        participant_id_candidate: (block.param >>> 0) - FIRST_KEY + 1,
        observation_kind: 'KEYFRAME_SNAPSHOT',
        raw_payload_field_bytes_hex: rawField,
        minions_killed_raw_f32_candidate: 0,
        minions_killed_floor_candidate: 0,
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL',
        raw_packet_ref: sourceRef,
      });
      return;
    }
    nativeHeader.writeUInt32LE(block.param >>> 0, 0);
    nativeHeader.writeUInt32LE(block.payload.length, 4);
    nativeInput.update(nativeHeader);
    nativeInput.update(block.payload);
    const lookupKey24 = damagePairs[damageEvents.length][1];
    const relation = (block.param >>> 0) === lookupKey24 ? 'EQUAL'
      : (block.param >>> 0) - lookupKey24 === 0x100
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
      native_callback_lookup_key_u32_0x24_candidate: lookupKey24,
      native_callback_lookup_key_0x24_encoded_bytes_hex:
        encodedLookupKey(lookupKey24, 0x24),
      native_callback_lookup_key_u32_0x2c_candidate: 0x40004691,
      native_callback_lookup_key_0x2c_encoded_bytes_hex: '39e504c3',
      native_callback_lookup_key_0x24_raw_param_relation: relation,
      semantic_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE',
      semantic_status: DAMAGE_PROFILE.evidence_status,
      raw_packet_ref: sourceRef,
    });
  }, { strict: true });
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
  return { replay, unitApplyDamagePacketOutcome, minionsKilledSnapshotOutcome };
}

test('821 native +0x24 roster association includes exact decoded aliases and other relations', () => {
  const values = fixture();
  const rawPair = associateUnitApplyDamageRosterKeys821(values.replay, values);
  assert.equal(rawPair.status, 'CANDIDATE', rawPair.error);
  const result = associate(values.replay, {
    ...values, validatedRawRosterPairOutcome: rawPair,
  });
  assert.equal(profile.capability, 'unit_apply_damage_lookup_roster_key_pair');
  assert.deepEqual(profile.depends_on, [
    'unit_apply_damage_packet', 'hero_minions_killed_snapshot',
    'unit_apply_damage_roster_key_pair',
  ]);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.profile_id, v1Profile.id);
  assert.equal(result.damage_packet_count, 5);
  assert.equal(result.snapshot_count, 10);
  assert.equal(result.matched_lookup_key_packet_count, 3);
  assert.equal(result.matched_equal_packet_count, 1);
  assert.equal(result.matched_alias_0x100_packet_count, 1);
  assert.equal(result.matched_other_relation_packet_count, 1);
  assert.equal(result.unmatched_packet_count, 2);
  assert.equal(result.unmatched_alias_0x100_packet_count, 1);
  assert.equal(result.verified_raw_packet_count, 15);
  assert.deepEqual(result.events.map((row) =>
    row.native_callback_lookup_key_0x24_raw_param_relation), [
    'EQUAL', 'RAW_PARAM_IS_LOOKUP_PLUS_0X100', 'OTHER',
  ]);
  assert.deepEqual(result.events.map((row) =>
    row.hero_stats_participant_id_candidate), [1, 1, 2]);
  assert.equal(result.events[1].raw_param, FIRST_KEY + 0x100);
  assert.equal(result.events[1].native_callback_lookup_key_u32_0x24_candidate,
    FIRST_KEY);
  assert.equal(result.events[1].hero_raw_param, FIRST_KEY);
  assert.equal(result.events[1].lookup_resolution_status, 'UNKNOWN');
  assert.equal(result.events[1].actor_assignment_status, 'UNKNOWN');
  assert.equal(result.events[1].source_target_role_status, 'UNKNOWN');
  assert.equal(result.events[1].semantic_effect_status, 'UNKNOWN');
  assert.equal(result.events[1].unit_apply_damage_raw_packet_ref.packet_id, 0x005f);
  assert.equal(result.events[1].hero_stats_roster_raw_packet_ref.packet_id, 0x0089);
  for (const forbidden of ['source', 'target', 'damage_amount', 'amount',
    'actor_id', 'effective_health_loss']) {
    assert.equal(forbidden in result.events[1], false);
  }
  const selfValidated = associate(values.replay, values);
  assert.deepEqual(selfValidated, result);
});

test('821 native lookup roster association rejects wrong build, v2, and missing inputs', () => {
  const wrong = fixture({ version: '16.19.821.7344' });
  assert.equal(associate(wrong.replay, wrong).status, 'UNSUPPORTED');
  const values = fixture();
  assert.equal(associate(values.replay).status, 'MISSING_INPUT');
  values.unitApplyDamagePacketOutcome.profile_id =
    'rofl-16.19.821.7343-kr-unit-apply-damage-packet-candidate-v2';
  assert.equal(associate(values.replay, values).status, 'PROFILE_UNAVAILABLE');
});

test('821 native lookup roster association fails closed on incomplete or altered evidence', () => {
  const incomplete = fixture();
  incomplete.unitApplyDamagePacketOutcome.native_callback_lookup_full_write_count -= 1;
  assert.equal(associate(incomplete.replay, incomplete).status, 'INCONSISTENT');
  const alteredKey = fixture();
  alteredKey.unitApplyDamagePacketOutcome.events[1]
    .native_callback_lookup_key_0x24_encoded_bytes_hex = '00000000';
  assert.equal(associate(alteredKey.replay, alteredKey).status, 'INCONSISTENT');
  const alteredRelation = fixture();
  alteredRelation.unitApplyDamagePacketOutcome.events[1]
    .native_callback_lookup_key_0x24_raw_param_relation = 'EQUAL';
  assert.equal(associate(alteredRelation.replay, alteredRelation).status, 'INCONSISTENT');
  const forgedRef = fixture();
  forgedRef.unitApplyDamagePacketOutcome.events[1].raw_packet_ref.raw_param += 1;
  assert.equal(associate(forgedRef.replay, forgedRef).status, 'INCONSISTENT');
  const roster = fixture({ missingRosterKey: true });
  assert.equal(associate(roster.replay, roster).status, 'INCONSISTENT');
});

test('821 cached raw-key proof must match current source rows', () => {
  const values = fixture();
  const rawPair = associateUnitApplyDamageRosterKeys821(values.replay, values);
  assert.equal(rawPair.status, 'CANDIDATE');
  rawPair.events[0].unit_apply_damage_raw_packet_ref.raw_param += 1;
  assert.equal(associate(values.replay, {
    ...values, validatedRawRosterPairOutcome: rawPair,
  }).status, 'INCONSISTENT');
  const stale = fixture({ damagePairs: [[FIRST_KEY, FIRST_KEY]] });
  const otherRawPair = associateUnitApplyDamageRosterKeys821(stale.replay, stale);
  assert.equal(associate(values.replay, {
    ...values, validatedRawRosterPairOutcome: otherRawPair,
  }).status, 'INCONSISTENT');
  const mutated = fixture();
  const freshPair = associateUnitApplyDamageRosterKeys821(mutated.replay, mutated);
  mutated.unitApplyDamagePacketOutcome.events[3].raw_packet_ref.raw_payload_hex =
    '71875e460b083dbaef3ba6ec39b974';
  assert.equal(associate(mutated.replay, {
    ...mutated, validatedRawRosterPairOutcome: freshPair,
  }).status, 'INCONSISTENT');
});

test('one original KR 821 Replay yields source-bound native lookup roster candidates', {
  skip: !fs.existsSync(IMAGE_PATH) || !fs.existsSync(REPLAY_PATH)
    ? 'exact private image or original KR Replay is unavailable' : false,
}, () => {
  const replay = parseReplayFile(REPLAY_PATH);
  const unitApplyDamagePacketOutcome = decodeUnitApplyDamagePacketCandidates821(replay,
    { runtimeImagePath: IMAGE_PATH });
  const minionsKilledSnapshotOutcome = decodeHeroFloatSnapshotCandidates821(replay,
    'hero_minions_killed_snapshot');
  assert.equal(unitApplyDamagePacketOutcome.status, 'CANDIDATE');
  assert.equal(minionsKilledSnapshotOutcome.status, 'CANDIDATE');
  const rawPair = associateUnitApplyDamageRosterKeys821(replay, {
    unitApplyDamagePacketOutcome, minionsKilledSnapshotOutcome,
  });
  assert.equal(rawPair.status, 'CANDIDATE', rawPair.error);
  const result = associate(replay, {
    unitApplyDamagePacketOutcome, minionsKilledSnapshotOutcome,
    validatedRawRosterPairOutcome: rawPair,
  });
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.ok(result.matched_lookup_key_packet_count > rawPair.event_count);
  assert.ok(result.matched_alias_0x100_packet_count > 0);
  assert.equal(result.matched_lookup_key_packet_count + result.unmatched_packet_count,
    result.damage_packet_count);
  assert.equal(result.verified_raw_packet_count,
    result.damage_packet_count + result.snapshot_count);
  assert.ok(result.events.every((row) => row.lookup_resolution_status === 'UNKNOWN'
    && row.actor_assignment_status === 'UNKNOWN'
    && row.semantic_effect_status === 'UNKNOWN'));
});
