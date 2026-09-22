'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  DEEP_RECOVERY_SEMANTIC_PROFILES,
  EXACT_BUILD,
  deepRecoveryProfileFor,
} = require('../src/deep_recovery_semantic_profiles_16_16');

const ROOT = path.resolve(__dirname, '..');

function sha256(relativePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(path.join(ROOT, relativePath))).digest('hex');
}

test('deep-recovery profiles are exact-build enabled records with no fallback', () => {
  assert.deepEqual(Object.keys(DEEP_RECOVERY_SEMANTIC_PROFILES), [
    'hero_death_timer', 'buff', 'cast_spell', 'protection', 'item_state',
    'item_swap', 'item_substitution_map', 'support_quest_item_stage',
  ]);
  for (const profile of Object.values(DEEP_RECOVERY_SEMANTIC_PROFILES)) {
    assert.equal(profile.replay_version, EXACT_BUILD);
    assert.equal(profile.enabled, true);
    assert.match(profile.status, /^SEMANTIC_VERIFIED_(DIRECT|DERIVED)/);
    assert.equal(JSON.stringify(profile).toLowerCase().includes('holdout'), false);
  }
  assert.equal(deepRecoveryProfileFor('buff', EXACT_BUILD).profile,
    DEEP_RECOVERY_SEMANTIC_PROFILES.buff);
  assert.deepEqual(deepRecoveryProfileFor('buff', '16.16.805.0443'), {
    status: 'UNSUPPORTED_VERSION', profile: null, candidate: null,
  });
});

test('profile provenance hashes match the exact safe artifacts', () => {
  const timer = DEEP_RECOVERY_SEMANTIC_PROFILES.hero_death_timer;
  assert.equal(sha256(timer.decoded_event_artifact), timer.decoded_event_artifact_sha256);
  assert.equal(sha256(timer.validation_artifact), timer.validation_artifact_sha256);
  assert.equal(sha256(timer.runtime_decoder_profile), timer.runtime_decoder_profile_sha256);
  for (const name of [
    'buff', 'cast_spell', 'protection', 'item_state', 'item_swap',
    'item_substitution_map', 'support_quest_item_stage',
  ]) {
    const profile = DEEP_RECOVERY_SEMANTIC_PROFILES[name];
    assert.equal(sha256(profile.validation_artifact), profile.validation_artifact_sha256);
    if (profile.runtime_validation_artifact) {
      assert.equal(sha256(profile.runtime_validation_artifact),
        profile.runtime_validation_artifact_sha256);
    }
  }
});

test('publication boundaries retain semantic stage and attribution unknowns', () => {
  const timer = DEEP_RECOVERY_SEMANTIC_PROFILES.hero_death_timer;
  assert.equal(timer.sample_count.exact_full_consume_count, 608);
  assert.equal(timer.field_evidence.respawn_timestamp_ms, 'UNAVAILABLE_TIMER_IS_NOT_EXACT_RESPAWN');
  const buff = DEEP_RECOVERY_SEMANTIC_PROFILES.buff;
  assert.equal(buff.sample_count.event_count, 354854);
  assert.equal(buff.field_evidence.stack_count, 'CANDIDATE_WITH_COUNTEREXAMPLES');
  const cast = DEEP_RECOVERY_SEMANTIC_PROFILES.cast_spell;
  assert.equal(cast.field_evidence.human_readable_ability_id, 'UNAVAILABLE');
  assert.equal(cast.field_evidence.damage_causality, 'UNAVAILABLE');
  const protection = DEEP_RECOVERY_SEMANTIC_PROFILES.protection;
  assert.equal(protection.sample_count.heal_reported_event_count, 28404);
  assert.equal(protection.sample_count.shield_application_event_count, 1107);
  assert.equal(protection.field_evidence.effective_amount, 'UNAVAILABLE');
  assert.equal(protection.field_evidence.shield_absorbed, 'UNAVAILABLE');
  const itemState = DEEP_RECOVERY_SEMANTIC_PROFILES.item_state;
  assert.equal(itemState.sample_count.broadcast_conserved_failure_count, 154);
  assert.equal(itemState.field_evidence.buy_sell_undo_cause,
    'UNAVAILABLE_ROUTE_IS_GENERIC_STATE');
  const quest = DEEP_RECOVERY_SEMANTIC_PROFILES.support_quest_item_stage;
  assert.equal(quest.sample_count.exact_full_consume_count, 169654);
  assert.equal(quest.exact_build_stage_code_map['1.47'], 2);
});
