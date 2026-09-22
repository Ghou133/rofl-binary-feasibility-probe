'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { assertFrozenOrPublicSourceHash } = require('./support/public_release_hash_bridge');

const {
  EXACT_BUILD,
  ROUTE_IDS,
  RUNTIME_SHA256,
  classifyNativeFailure,
  rejectProtectedPath,
  sha256,
} = require('../src/residual_p6_wave_v2');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT_ROOT = path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2',
  'residual_p6_wave');
const RUNTIME_PATH = path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1',
  'runtime', 'league_16.16.805.0442.memory.bin');

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACT_ROOT, name), 'utf8'));
}

function fileSha(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

test('exact-build scope is fixed to the nine delegated routes', () => {
  assert.equal(EXACT_BUILD, '16.16.805.0442');
  assert.deepEqual(ROUTE_IDS, [
    0x0063, 0x04a6, 0x02fb, 0x0499, 0x030b,
    0x020d, 0x02ed, 0x001a, 0x02a6,
  ]);
  assert.equal(new Set(ROUTE_IDS).size, 9);
  assert.equal(sha256(fs.readFileSync(RUNTIME_PATH)), RUNTIME_SHA256);
});

test('protected Holdout paths are rejected before reads or hashes', () => {
  assert.throws(
    () => rejectProtectedPath(path.join(ROOT, 'Jungle Objective Holdout', 'forbidden.rofl')),
    /protected Holdout path is forbidden/,
  );
  assert.doesNotThrow(() => rejectProtectedPath(path.join(ARTIFACT_ROOT, 'safe.json')));
});

test('native failures distinguish exact external process state from local failures', () => {
  assert.equal(classifyNativeFailure(
    'Invalid memory read (UC_ERR_READ_UNMAPPED); rip=0x140001234; address=0x25cc4670',
  ).class, 'EXTERNAL_RUNTIME_HEAP_TLS_OR_PROCESS_STATE');
  assert.equal(classifyNativeFailure(
    'deserialize_return_al=0;fully_consumed=false',
  ).class, 'UNCLASSIFIED_NATIVE_FAILURE');
});

test('generated audit closes every exact factory and conserves all rows', () => {
  const report = readJson('residual_p6_wave_audit_16_16.json');
  assert.equal(report.exact_build, EXACT_BUILD);
  assert.equal(report.architecture_gate, 'PASS');
  assert.equal(report.scope.length, 9);
  assert.equal(report.conservation.target_row_count, 7007);
  assert.equal(report.conservation.target_occurrence_weight_conserved, true);
  assert.equal(report.conservation.registry_counts_match, true);
  assert.equal(report.runtime_static_recovery.all_routes_factory_closed, true);
  assert.equal(report.runtime_static_recovery.all_receive_static_surfaces_exhausted, true);
  assert.equal(report.native_determinism.all_match, true);
  assert.equal(report.decision_summary.all_current_local_evidence_exhausted, true);
  assert.equal(report.saturation.current_safe_local_resource_saturated, true);
  assert.equal(report.saturation.local_actionable_hypothesis_count, 0);
  assert.equal(report.validations.all_pass, true);
  for (const route of Object.values(report.routes)) {
    assert.equal(route.payload.occurrence_weight_conserved, true);
    for (const family of ['hero_path', 'verified_damage', 'hero_death', 'cast_spell',
      'buff', 'item', 'scoreboard']) {
      const correlation = route.anchor_correlations_with_shifted_controls[family];
      assert.equal(typeof correlation.shifted_137ms_within_10ms_count, 'number');
      assert.equal(typeof correlation.shifted_997ms_within_10ms_count, 'number');
      assert.equal(correlation.semantic_claim, null);
    }
  }
  for (const route of Object.values(report.native_exact_emulation.routes)) {
    assert.equal(route.all_distinct_payloads_attempted, true);
    assert.equal(route.full_occurrence_weight_conserved, true);
    assert.equal(route.all_failures_external_runtime_state, true);
  }
});

test('all unique RTTI callback identities are verified and 0x001a closes its fragmented constructor', () => {
  const report = readJson('residual_p6_wave_audit_16_16.json');
  const expected = {
    '0x0063': ['PKT_S2C_StopSpellTargeter_s', 'AIHeroClient'],
    '0x04a6': ['PKT_S2C_MoveMarker_s', 'AIMarker'],
    '0x02fb': ['PKT_S2C_AddItemModifier_s', 'HeroInventoryClient'],
    '0x0499': ['PKT_NPC_BuffLockFacing_s', 'BuffManagerClient'],
    '0x030b': ['PKT_DirectInputMovementDriverServerTurnData_s', 'AIBaseClient'],
    '0x020d': ['PKT_S2C_UpdateSpellNumericalDisplay_s', 'AIHeroClient'],
    '0x02ed': ['PKT_S2C_ChangeMissileTarget_s', 'MissileClient'],
    '0x001a': ['PKT_S2C_UpdateUnitInfoBar_s', 'AIBaseClient'],
    '0x02a6': ['PKT_NPC_RemoveFakeBuff_s', 'BuffManagerClient'],
  };
  for (const [packetType, [name, owner]] of Object.entries(expected)) {
    const identity = report.runtime_static_recovery.routes[packetType].receive_identity;
    assert.equal(identity.status, 'STATIC_CALLBACK_RTTI_AND_RECEIVE_TARGET_VERIFIED');
    assert.equal(identity.runtime_type_name, name);
    assert.equal(identity.callback_owner_type, owner);
    assert.match(identity.callback_receive_target_rva_hex, /^0x[0-9a-f]+$/);
    assert.equal(identity.type_descriptor_decorated_name.includes(name), true);
    assert.equal(identity.type_descriptor_decorated_name.includes(owner), true);
    assert.equal(identity.direct_rtti_packet_name_verified, true);
    assert.equal(identity.direct_rtti_callback_owner_verified, true);
    assert.equal(identity.direct_receive_target_executable_verified, true);
  }
  const fragmented = report.runtime_static_recovery.routes['0x001a'];
  assert.equal(fragmented.factory_chain.object_size, 104);
  assert.equal(fragmented.factory_chain.constructor_boundary.source,
    'FACTORY_PROVEN_ENTRY_TO_FIRST_REAL_RET');
  assert.equal(fragmented.validations.fragmented_pdata_constructor_recovered, true);
});

test('machine decisions are exhausted and require external-only evidence', () => {
  const decisions = readJson('residual_p6_wave_machine_decisions_16_16.json');
  assert.equal(decisions.route_decisions.length, 9);
  assert.equal(decisions.capability_decisions.length, 9);
  assert.equal(decisions.domain_decisions.length, 9);
  assert.deepEqual(decisions.decision_counts, {
    PROMOTE: 9,
    REPURPOSE: 0,
    KEEP_CANDIDATE: 0,
    REJECT: 0,
  });
  for (const group of ['route_decisions', 'capability_decisions', 'domain_decisions']) {
    for (const row of decisions[group]) {
      assert.equal(row.actual_reverse_engineering_executed, true);
      assert.equal(row.evidence_exhausted, true);
      assert.deepEqual(row.actionable_hypotheses, []);
      assert.equal(row.external_only_gate.required, true);
      assert.equal(row.external_only_gate.local_safe_evidence_remaining, false);
    }
  }
  assert.equal(decisions.route_decisions.every((row) => row.semantic_claim
    && row.semantic_claim.includes('callback RTTI identity')), true);
});

test('hash manifest verifies every listed artifact and excludes its own hash', () => {
  const manifest = readJson('hashes_16_16.json');
  assert.equal(manifest.exact_build, EXACT_BUILD);
  assert.equal(manifest.files.length > 35, true);
  assert.equal(manifest.files.some((entry) => entry.path.endsWith('/hashes_16_16.json')), false);
  for (const entry of manifest.files) {
    const filePath = path.join(ROOT, entry.path);
    assertFrozenOrPublicSourceHash(entry, filePath, fileSha);
  }
  assert.equal(manifest.protected_holdout.enumerated, false);
  assert.equal(manifest.protected_holdout.consumed, false);
});
