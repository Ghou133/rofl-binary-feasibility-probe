'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const oldProfile = require('../src/decoders/rofl_16_15_801_3452');
const {
  REPLAY_VERSION,
  RUNTIME_IMAGE_SHA256,
  CONTAINER_PROFILE,
  SEMANTIC_PROFILE_REGISTRY,
  semanticProfileFor,
} = require('../src/decoders/rofl_16_16_805_0442');

test('16.16 registry is exact-build bound and does not alter the frozen 16.15 profile', () => {
  assert.equal(REPLAY_VERSION, '16.16.805.0442');
  assert.equal(RUNTIME_IMAGE_SHA256,
    '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55');
  assert.equal(CONTAINER_PROFILE.status, 'VERIFIED_DIRECT');
  assert.equal(oldProfile.PROFILE.replay_version, '16.15.801.3452');
  assert.equal(oldProfile.LEVEL_UP_PROFILE.replay_version, '16.15.801.3452');
});

test('16.16 promotes evidence-backed P0 and WardSpawn profiles only', () => {
  for (const profile of Object.values(SEMANTIC_PROFILE_REGISTRY)) {
    assert.equal(profile.replay_version, REPLAY_VERSION);
  }
  assert.equal(SEMANTIC_PROFILE_REGISTRY.participant_mapping.enabled, true);
  assert.equal(SEMANTIC_PROFILE_REGISTRY.hero_path.enabled, true);
  assert.equal(SEMANTIC_PROFILE_REGISTRY.hero_path.replay_block_packet_id, 0x00f6);
  assert.equal(SEMANTIC_PROFILE_REGISTRY.level_transition.enabled, true);
  assert.equal(SEMANTIC_PROFILE_REGISTRY.level_transition.replay_block_packet_id, 0x0314);
  assert.equal(SEMANTIC_PROFILE_REGISTRY.level_transition.rejected_candidate_replay_block_packet_id,
    0x01e8);
  assert.equal(SEMANTIC_PROFILE_REGISTRY.level_transition.level_after_status,
    'SEMANTIC_VERIFIED_DERIVED_BUILD_BOUND');
  assert.equal(SEMANTIC_PROFILE_REGISTRY.ward_spawn.enabled, true);
  assert.equal(SEMANTIC_PROFILE_REGISTRY.ward_spawn.replay_block_packet_id, 0x049a);
  assert.equal(SEMANTIC_PROFILE_REGISTRY.ward_spawn.constructor_rva, 0x00eabb20);
  assert.equal(SEMANTIC_PROFILE_REGISTRY.ward_spawn.deserialize_rva, 0x01025d50);
  assert.equal(SEMANTIC_PROFILE_REGISTRY.ward_spawn.rejected_deserialize_candidate_rva,
    0x00fc7770);
  assert.equal(SEMANTIC_PROFILE_REGISTRY.ward_spawn.field_evidence.position,
    'VERIFIED_DIRECT');
  assert.equal(SEMANTIC_PROFILE_REGISTRY.ward_spawn.lifecycle_status,
    'SEMANTIC_PARTIAL_DERIVED');
  assert.equal(SEMANTIC_PROFILE_REGISTRY.hero_damage.enabled, true);
  assert.equal(SEMANTIC_PROFILE_REGISTRY.hero_damage.status, 'SEMANTIC_VERIFIED_DIRECT');
  assert.equal(SEMANTIC_PROFILE_REGISTRY.hero_damage.runtime_type_name,
    'PKT_UnitApplyDamage_s');
});

test('exact lookup exposes verified profiles and never falls back across builds', () => {
  const path = semanticProfileFor('hero_path', REPLAY_VERSION);
  assert.equal(path.status, 'SEMANTIC_VERIFIED_DERIVED');
  assert.equal(path.profile.replay_block_packet_id, 0x00f6);
  assert.equal(path.candidate, path.profile);

  assert.deepEqual(semanticProfileFor('hero_path', '16.15.801.3452'), {
    status: 'UNSUPPORTED_VERSION', profile: null, candidate: null,
  });
});
