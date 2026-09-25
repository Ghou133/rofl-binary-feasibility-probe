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
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V2_ID_821: DAMAGE_V2_ID,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821: DAMAGE_V3_ID,
  decodeUnitApplyDamagePacketCandidates821,
  decodeUnitApplyDamageCallbackF32FromRaw821,
  decodeUnitApplyDamageLookupKeyFromRaw821,
} = require('../src/decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');
const {
  decodeHeroFloatSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_float_stats_candidate');
const {
  UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE: profile,
  UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821: v1Profile,
  associateUnitApplyDamageRosterKeys821: associate,
} = require('../src/decoders/rofl_16_19_821_unit_apply_damage_roster_key_candidate');

const BUILD = '16.19.821.7343';
const SNAPSHOT_PROFILE = PROFILES.hero_minions_killed_snapshot;
const FIRST_PARAM = 0x400000ae;
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

const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));

function snapshotPayload() {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  for (let index = 0; index < 4; index += 1) {
    payload[1262 - 0x3c - index] = ENCODE.get(0);
  }
  return payload;
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

// Synthetic source outcomes follow the two existing decoder schemas. The
// association's own tests do not claim to re-run native code on these bytes.
function fixture({ version = BUILD,
  damageProfile = 'v2',
  statsKeys = Array.from({ length: 10 }, (_, i) => FIRST_PARAM + i),
  damageKeys = [FIRST_PARAM, FIRST_PARAM + 0x100,
    FIRST_PARAM + 0x200, 0x40004ff8],
  extraEmptyKeyframe = false } = {}) {
  const chunks = [{ stream: 2, body: Buffer.concat(statsKeys.map((rawParam) =>
    packet(0x0089, rawParam, snapshotPayload()))) }];
  if (extraEmptyKeyframe) chunks.push({ stream: 2, body: packet(0x038e,
    0x40003000, Buffer.from([0x83])) });
  chunks.push({ stream: 1, body: Buffer.concat(damageKeys.map((rawParam, i) =>
    packet(0x005f, rawParam, COMMON_PAYLOAD, 1500 + i * 100))) });
  const replay = replayFromChunks(chunks, version);
  const damageProfileId = damageProfile === 'v4' ? DAMAGE_PROFILE.id
    : damageProfile === 'v3' ? DAMAGE_V3_ID : DAMAGE_V2_ID;
  const hasLookupKeys = damageProfile === 'v3' || damageProfile === 'v4';
  const damageEvents = [];
  const snapshotEvents = [];
  const lookupRelationCounts = {
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
        participant_id_candidate: (block.param >>> 0) - FIRST_PARAM + 1,
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
    const lookupKey24 = decodeUnitApplyDamageLookupKeyFromRaw821('b7294929', 0x24);
    const lookupKey2c = decodeUnitApplyDamageLookupKeyFromRaw821('39e504c3', 0x2c);
    const lookupRelation = (block.param >>> 0) === lookupKey24 ? 'EQUAL'
      : (block.param >>> 0) - lookupKey24 === 0x100
        ? 'RAW_PARAM_IS_LOOKUP_PLUS_0X100' : 'OTHER';
    if (hasLookupKeys) lookupRelationCounts[lookupRelation] += 1;
    damageEvents.push({
      event_type: 'UNIT_APPLY_DAMAGE_PACKET_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: damageProfileId,
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
      ...(hasLookupKeys ? {
        native_callback_lookup_key_u32_0x24_candidate: lookupKey24,
        native_callback_lookup_key_0x24_encoded_bytes_hex: 'b7294929',
        native_callback_lookup_key_u32_0x2c_candidate: lookupKey2c,
        native_callback_lookup_key_0x2c_encoded_bytes_hex: '39e504c3',
        native_callback_lookup_key_0x24_raw_param_relation: lookupRelation,
      } : {}),
      ...(damageProfile === 'v4' ? {
        native_callback_u32_0x10_candidate: 0,
        native_callback_u32_0x10_encoded_bytes_hex: '85858585',
        native_callback_u32_0x10_source: 'CONSTANT_0',
      } : {}),
      semantic_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE',
      semantic_status: DAMAGE_PROFILE.evidence_status,
      raw_packet_ref: sourceRef,
    });
  }, { strict: true });
  const unitApplyDamagePacketOutcome = {
    status: 'CANDIDATE', profile_id: damageProfileId,
    evidence_status: DAMAGE_PROFILE.evidence_status,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    evidence_scalar_table_sha256: DAMAGE_PROFILE.evidence_scalar_table_sha256,
    evidence_shape_catalog_sha256: DAMAGE_PROFILE.evidence_shape_catalog_sha256,
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
    ...(hasLookupKeys ? {
      evidence_lookup_key_0x24_table_sha256:
        DAMAGE_PROFILE.evidence_lookup_key_0x24_table_sha256,
      evidence_lookup_key_0x2c_table_sha256:
        DAMAGE_PROFILE.evidence_lookup_key_0x2c_table_sha256,
      native_callback_lookup_full_write_count: damageEvents.length,
      native_callback_lookup_key_0x24_raw_param_relation_counts:
        lookupRelationCounts,
    } : {}),
    ...(damageProfile === 'v4' ? {
      evidence_callback_u32_0x10_table_sha256:
        DAMAGE_PROFILE.evidence_callback_u32_0x10_table_sha256,
      native_callback_u32_0x10_full_write_count: damageEvents.length,
      native_callback_u32_0x10_source_counts: {
        RAW_READER: 0, CONSTANT_0: damageEvents.length,
      },
    } : {}),
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

test('821 UnitApplyDamage roster association uses the full key and excludes aliases', () => {
  const values = fixture();
  const result = associate(values.replay, values);
  assert.equal(profile.capability, 'unit_apply_damage_roster_key_pair');
  assert.deepEqual(profile.depends_on,
    ['unit_apply_damage_packet', 'hero_minions_killed_snapshot']);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.profile_id, v1Profile.id);
  assert.equal(result.damage_packet_count, 4);
  assert.equal(result.snapshot_count, 10);
  assert.equal(result.keyframe_count, 1);
  assert.equal(result.canonical_roster_key_count, 10);
  assert.equal(result.matched_full_key_packet_count, 1);
  assert.equal(result.unmatched_packet_count, 3);
  assert.equal(result.excluded_alias_0x100_packet_count, 1);
  assert.equal(result.verified_raw_packet_count, 14);
  assert.equal(result.first_excluded_packet_refs.alias_0x100.raw_param,
    FIRST_PARAM + 0x100);
  const event = result.events[0];
  assert.equal(event.raw_param, FIRST_PARAM);
  assert.equal(event.hero_stats_participant_id_candidate, 1);
  assert.equal(event.native_callback_f32_0x20_candidate, 0.5460192561149597);
  assert.equal(event.pair_basis,
    'EXACT_FULL_RAW_PARAM_IN_CANONICAL_HEROSTATS_ROSTER');
  assert.equal(event.actor_assignment_status, 'UNKNOWN');
  assert.equal(event.source_target_role_status, 'UNKNOWN');
  assert.equal(event.semantic_effect_status, 'UNKNOWN');
  assert.equal(event.unit_apply_damage_raw_packet_ref.packet_id, 0x005f);
  assert.equal(event.hero_stats_roster_raw_packet_ref.packet_id, 0x0089);
  assert.equal(event.raw_packet_refs.length, 2);
  for (const forbidden of ['source', 'target', 'damage_amount', 'amount',
    'actor_id', 'effective_health_loss']) {
    assert.equal(forbidden in event, false);
  }
});

test('821 UnitApplyDamage roster association accepts native v3 and validates lookup fields', () => {
  const values = fixture({ damageProfile: 'v3',
    damageKeys: [FIRST_PARAM, 0x40004007, 0x40004107, FIRST_PARAM + 0x100] });
  const result = associate(values.replay, values);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.profile_id, v1Profile.id);
  assert.equal(result.matched_full_key_packet_count, 1);
  assert.equal(result.unmatched_packet_count, 3);
  assert.equal(result.excluded_alias_0x100_packet_count, 1);
  assert.deepEqual(values.unitApplyDamagePacketOutcome
    .native_callback_lookup_key_0x24_raw_param_relation_counts, {
    EQUAL: 1, RAW_PARAM_IS_LOOKUP_PLUS_0X100: 1, OTHER: 2,
  });
  const malformed = fixture({ damageProfile: 'v3' });
  malformed.unitApplyDamagePacketOutcome.events[0]
    .native_callback_lookup_key_0x24_encoded_bytes_hex = '00000000';
  assert.equal(associate(malformed.replay, malformed).status, 'INCONSISTENT');
  const incomplete = fixture({ damageProfile: 'v3' });
  incomplete.unitApplyDamagePacketOutcome.native_callback_lookup_full_write_count -= 1;
  assert.equal(associate(incomplete.replay, incomplete).status, 'INCONSISTENT');
  const falseRelation = fixture({ damageProfile: 'v3' });
  falseRelation.unitApplyDamagePacketOutcome.events[0]
    .native_callback_lookup_key_0x24_raw_param_relation = 'EQUAL';
  assert.equal(associate(falseRelation.replay, falseRelation).status, 'INCONSISTENT');
});

test('821 UnitApplyDamage roster association accepts v4 and checks anonymous +0x10 witness', () => {
  const values = fixture({ damageProfile: 'v4' });
  const result = associate(values.replay, values);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.profile_id, profile.id);
  assert.equal(result.events[0].semantic_effect_status, 'UNKNOWN');

  for (const mutate of [
    (damage) => { damage.evidence_callback_u32_0x10_table_sha256 = '0'.repeat(64); },
    (damage) => { damage.native_callback_u32_0x10_full_write_count -= 1; },
    (damage) => { damage.native_callback_u32_0x10_source_counts.CONSTANT_0 -= 1; },
    (damage) => { damage.events[0].native_callback_u32_0x10_candidate = 1; },
    (damage) => { damage.events[0].native_callback_u32_0x10_encoded_bytes_hex = '00000000'; },
    (damage) => { damage.events[0].native_callback_u32_0x10_source = 'RAW_READER'; },
  ]) {
    const forged = fixture({ damageProfile: 'v4' });
    mutate(forged.unitApplyDamagePacketOutcome);
    assert.equal(associate(forged.replay, forged).status, 'INCONSISTENT');
  }
});

test('821 UnitApplyDamage roster association rejects wrong build or missing inputs', () => {
  const wrong = fixture({ version: '16.19.821.7344' });
  assert.equal(associate(wrong.replay, wrong).status, 'UNSUPPORTED');
  const values = fixture();
  assert.equal(associate(values.replay).status, 'MISSING_INPUT');
  values.unitApplyDamagePacketOutcome.profile_id =
    'rofl-16.19.821.7343-kr-unit-apply-damage-packet-candidate-v1';
  assert.equal(associate(values.replay, values).status, 'INCONSISTENT');
});

test('821 UnitApplyDamage roster association rejects incomplete or colliding rosters', () => {
  const incomplete = fixture({ statsKeys: Array.from({ length: 9 },
    (_, index) => FIRST_PARAM + index) });
  assert.equal(associate(incomplete.replay, incomplete).status, 'INCONSISTENT');
  const collisionKeys = Array.from({ length: 10 }, (_, index) =>
    index === 9 ? FIRST_PARAM : FIRST_PARAM + index);
  const collision = fixture({ statsKeys: collisionKeys });
  assert.equal(associate(collision.replay, collision).status, 'INCONSISTENT');
  assert.match(associate(collision.replay, collision).error, /ambiguous/);
  const extra = fixture({ extraEmptyKeyframe: true });
  assert.equal(associate(extra.replay, extra).status, 'INCONSISTENT');
});

test('821 UnitApplyDamage roster association rejects incomplete native witness and forged references', () => {
  const values = fixture();
  values.unitApplyDamagePacketOutcome.native_full_success_count -= 1;
  assert.equal(associate(values.replay, values).status, 'INCONSISTENT');
  const forged = fixture();
  forged.unitApplyDamagePacketOutcome.events[0].raw_packet_ref.raw_payload_hex =
    '71875e460b083dbaef3ba6ec39b974';
  assert.equal(associate(forged.replay, forged).status, 'INCONSISTENT');
  const omitted = fixture();
  omitted.unitApplyDamagePacketOutcome.events.pop();
  omitted.unitApplyDamagePacketOutcome.input_count -= 1;
  omitted.unitApplyDamagePacketOutcome.event_count -= 1;
  omitted.unitApplyDamagePacketOutcome.native_full_success_count -= 1;
  omitted.unitApplyDamagePacketOutcome.native_callback_f32_available_count -= 1;
  omitted.unitApplyDamagePacketOutcome.native_callback_f32_source_counts.RAW_READER -= 1;
  const failed = associate(omitted.replay, omitted);
  assert.equal(failed.status, 'INCONSISTENT');
  assert.match(failed.error, /omits route packet/);
});

test('one original KR 821 Replay yields source-bound full-key associations', {
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
  const result = associate(replay,
    { unitApplyDamagePacketOutcome, minionsKilledSnapshotOutcome });
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.matched_full_key_packet_count, result.event_count);
  assert.equal(result.matched_full_key_packet_count
    + result.unmatched_packet_count, result.damage_packet_count);
  assert.ok(result.matched_full_key_packet_count > 0);
  assert.ok(result.excluded_alias_0x100_packet_count > 0);
  assert.equal(result.verified_raw_packet_count,
    result.damage_packet_count + result.snapshot_count);
  assert.ok(result.events.every((row) => row.actor_assignment_status === 'UNKNOWN'
    && row.semantic_effect_status === 'UNKNOWN'));
});
