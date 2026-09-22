'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  canonicalGameplayRouteTailEvent,
  canonicalizeSemanticEvent,
  getCanonicalSemanticSchema,
  validateCanonicalRecord,
} = require('../src/semantic_api');

test('public canonicalize entry preserves public semantic facts while removing adapter internals', () => {
  const canonical = canonicalizeSemanticEvent('DamageEvent', {
    event_id: 'damage:1',
    game_version: '16.16.805.0442',
    replay_sha256: 'a'.repeat(64),
    replay_time_ms: 44,
    source_network_id: 0x400000ae,
    target_network_id: 0x400000af,
    amount: 0,
    amount_semantic_stage: null,
    damage_type: 'magic',
    spell: null,
    is_critical: null,
    semantic_status: 'VERIFIED_DIRECT',
    field_confidence: {
      source_network_id: 'VERIFIED_DIRECT',
      target_network_id: 'VERIFIED_DIRECT',
      amount: 'VERIFIED_DIRECT',
      amount_semantic_stage: 'UNKNOWN',
      damage_type: 'VERIFIED_DIRECT',
      spell: 'UNAVAILABLE',
      is_critical: 'UNAVAILABLE',
    },
    build_profile: 'rofl-16.16.805.0442-unit-apply-damage-unicorn-v1',
    decoder_profile: 'rofl-16.16.805.0442-unit-apply-damage-unicorn-v1',
    raw_payload_sha256: 'b'.repeat(64),
    raw_packet_ref: { replay_sha256: 'a'.repeat(64), packet_id: 0x017f, payload_sha256: 'b'.repeat(64) },
    packet_id: 0x017f,
    decoded_opcode: 0x017f,
    protocol_route: '0x017f',
  });
  assert.equal(canonical.fields.amount, 0);
  assert.equal(canonical.fields.amount_semantic_stage, null);
  assert.equal(canonical.field_evidence.amount_semantic_stage, 'UNKNOWN');
  assert.equal(canonical.field_evidence.spell_identifier, 'UNAVAILABLE');
  assert.equal(canonical.evidence.status, 'VERIFIED_DIRECT');
  assert.equal(canonical.provenance.source_artifact_sha256, 'b'.repeat(64));
  assert.equal(canonical.provenance.exact_build_adapter_id, 'rofl-16.16.805.0442-unit-apply-damage-unicorn-v1');
  const text = JSON.stringify(canonical);
  assert.equal(text.includes('packet_id'), false);
  assert.equal(text.includes('opcode'), false);
  assert.equal(text.includes('protocol_route'), false);
  assert.deepEqual(validateCanonicalRecord(canonical), canonical);
});

test('bounded gameplay-tail events map into canonical attack, spell, position, missile, and component records', () => {
  const common = {
    exact_build: '16.16.805.0442',
    replay_sha256: 'a'.repeat(64),
    replay_time_ms: 123,
    subject_network_id: 0x400000ae,
    confidence: 'VERIFIED_DIRECT',
    semantic_status: 'VERIFIED_DIRECT_BOUNDED_RESEARCH_EVENT',
    build_profile: 'exact-test-profile',
    decoder_profile: 'exact-test-profile',
    raw_payload_sha256: 'b'.repeat(64),
    known_limits: [],
  };
  const rows = [
    canonicalGameplayRouteTailEvent({
      ...common, event_type: 'FACE_DIRECTION_VECTOR',
      direction_x_f32: 0, direction_y_f32: 0, direction_z_f32: 1,
    }),
    canonicalGameplayRouteTailEvent({
      ...common, event_type: 'INSTANT_STOP_ATTACK',
      attack_sequence_14_u32: 7, target_network_id_candidate_1c_u32: 0,
    }),
    canonicalGameplayRouteTailEvent({
      ...common, event_type: 'ABILITY_COOLDOWN_BROADCAST', spell_slot_key_1c_u8: 2,
      numeric_10_f32: 0, numeric_18_f32: 1, numeric_20_f32: 2,
      numeric_24_f32: 3, flag_14_u8: 0,
    }),
    canonicalGameplayRouteTailEvent({
      ...common, event_type: 'WALL_TRACKING_CACHE_SNAPSHOT', cache_selector_10_u16: 1,
      coordinate_x_18_f32: 10, coordinate_z_1c_f32: 20, numeric_14_f32: 0,
      field_20_u8: 0, field_21_u8: 0, field_22_u8: 0,
    }),
    canonicalGameplayRouteTailEvent({
      ...common, event_type: 'MISSILE_MOVEMENT_COMPLETE', movement_complete_count_u8: 1,
    }),
  ];
  assert.deepEqual(rows.map((row) => row.semantic_type), [
    'PositionEvent', 'AttackEvent', 'SpellState', 'EntityComponentState', 'MissileEvent',
  ]);
  assert.deepEqual(rows[0].fields.direction, { x: 0, y: 0, z: 1 });
  assert.equal(rows[1].fields.target_entity_id, null);
  assert.equal(rows[1].field_evidence.target_entity_id, 'UNKNOWN');
  assert.equal(rows[2].fields.spell_slot_key, 2);
  assert.equal(rows[2].field_evidence.protocol_numeric_values, 'UNKNOWN');
  assert.equal(rows[3].fields.component, 'WallTrackingComponentCacheData');
  assert.equal(rows[4].fields.movement_complete_count, 1);
  for (const row of rows) {
    assert.deepEqual(validateCanonicalRecord(row), row);
    assert.equal(JSON.stringify(row).includes('packet_id'), false);
  }
});

test('public canonical entry is fail-closed to an explicit exact build and preserves unsupported facts as null/unknown', () => {
  assert.throws(() => canonicalizeSemanticEvent('DamageEvent', { amount: 1 }), /explicit exact four-component build/);
  const blankWard = canonicalizeSemanticEvent('WardEvent', {
    game_version: '16.16.805.0442',
    replay_time_ms: null,
    ward_network_id: null,
    ward_type: null,
    semantic_status: 'UNVERIFIED',
  });
  assert.equal(blankWard.exact_build, '16.16.805.0442');
  assert.equal(blankWard.fields.ward_entity_id, null);
  assert.equal(blankWard.field_evidence.ward_entity_id, 'UNKNOWN');
  assert.equal(blankWard.evidence.status, 'UNKNOWN');
  assert.throws(() => canonicalizeSemanticEvent('NoSuchSemanticType', { game_version: '16.16.805.0442' }), /unsupported canonical semantic type/);
});

test('public schema contract has no route or opcode and exposes validator-compatible event schemas', () => {
  const schema = getCanonicalSemanticSchema();
  assert.equal(schema.consumer_contract.nearest_build_fallback, 'FORBIDDEN');
  assert.equal(JSON.stringify(schema).includes('0x017f'), false);
  assert.ok(schema.canonical_event_types.some((row) => row.semantic_type === 'HeroState'));
  assert.ok(schema.canonical_event_types.some((row) => row.semantic_type === 'ObjectiveEvent'));
  assert.ok(schema.canonical_event_types.some((row) => row.semantic_type === 'AttackEvent'));
  assert.ok(schema.canonical_event_types.some((row) => row.semantic_type === 'SpellState'));
  assert.ok(schema.canonical_event_types.some((row) => row.semantic_type === 'EntityComponentState'));
});

test('public canonical lifecycle adapter exposes verified HeroDeath without leaking its route', () => {
  const canonical = canonicalizeSemanticEvent('EntityLifecycle', {
    game_version: '16.16.805.0442',
    replay_sha256: 'a'.repeat(64),
    replay_time_ms: 727429,
    event_type: 'death',
    victim_network_id: 0x400001b2,
    victim_participant_id: 5,
    victim_entity_type: 'CHAMPION',
    killer_network_id: 0x400000b6,
    killer_participant_id: 9,
    assists: null,
    semantic_status: 'VERIFIED_DIRECT',
    field_confidence: {
      victim_network_id: 'VERIFIED_DIRECT_RAW_PARAM',
      victim_participant_id: 'VERIFIED_DERIVED',
      victim_entity_type: 'VERIFIED_DIRECT_ROUTE_CONTRACT',
      killer_network_id: 'VERIFIED_DIRECT',
      killer_participant_id: 'VERIFIED_DERIVED',
      assists: 'UNAVAILABLE',
    },
    decoder_profile: 'rofl-16.16.805.0442-hero-death-unicorn-v2',
    raw_payload_sha256: 'b'.repeat(64),
    packet_id: 0x0112,
    raw_param: 0x400001b2,
  });
  assert.equal(canonical.fields.entity_id, 0x400001b2);
  assert.equal(canonical.fields.participant_id, 5);
  assert.equal(canonical.fields.entity_type, 'CHAMPION');
  assert.equal(canonical.fields.lifecycle_operation, 'death');
  assert.equal(canonical.fields.killer_entity_id, 0x400000b6);
  assert.equal(canonical.fields.killer_participant_id, 9);
  assert.equal(canonical.fields.assisting_entity_ids, null);
  assert.equal(canonical.field_evidence.assisting_entity_ids, 'UNAVAILABLE');
  assert.equal(canonical.field_evidence.owner_entity_id, 'UNKNOWN');
  assert.equal(JSON.stringify(canonical).includes('0x0112'), false);
  assert.equal(JSON.stringify(canonical).includes('packet_id'), false);
});

test('public canonical HeroState keeps zero XP/CS and candidate nulls distinct', () => {
  const canonical = canonicalizeSemanticEvent('HeroState', {
    game_version: '16.16.805.0442',
    replay_sha256: 'a'.repeat(64),
    replay_time_ms: 60000,
    entity_network_id: 0x400000ae,
    participant_id: 1,
    experience_points: 0,
    lane_minions_killed: 0,
    total_gold: null,
    jungle_minions_killed: null,
    semantic_status: 'VERIFIED_DIRECT',
    field_confidence: {
      entity_network_id: 'VERIFIED_DIRECT',
      participant_id: 'VERIFIED_DERIVED',
      experience_points: 'VERIFIED_DIRECT',
      lane_minions_killed: 'VERIFIED_DIRECT',
      total_gold: 'CANDIDATE',
      jungle_minions_killed: 'CANDIDATE',
    },
  });
  assert.equal(canonical.fields.experience_points, 0);
  assert.equal(canonical.fields.lane_minions_killed, 0);
  assert.equal(canonical.fields.total_gold, null);
  assert.equal(canonical.field_evidence.total_gold, 'CANDIDATE');
  assert.deepEqual(validateCanonicalRecord(canonical), canonical);
});
