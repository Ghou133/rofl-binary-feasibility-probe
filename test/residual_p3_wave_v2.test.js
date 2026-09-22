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
} = require('../src/residual_p3_wave_v2');
const { prior0178Boundary } = require('../scripts/audit_residual_p3_wave_v2');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT_ROOT = path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2',
  'residual_p3_wave');
const RUNTIME_PATH = path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1',
  'runtime', 'league_16.16.805.0442.memory.bin');
const PRIOR_PROFILE_PATH = path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'profiler',
  'field_behavior_profile_16_16_0x0178_object.json');

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACT_ROOT, name), 'utf8'));
}

function fileSha(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

test('exact-build scope is fixed to the twelve delegated routes', () => {
  assert.equal(EXACT_BUILD, '16.16.805.0442');
  assert.deepEqual(ROUTE_IDS, [
    0x0255, 0x046d, 0x038d, 0x0274, 0x023f, 0x018c,
    0x01aa, 0x0178, 0x01c8, 0x02f2, 0x0232, 0x0008,
  ]);
  assert.equal(new Set(ROUTE_IDS).size, 12);
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

test('prior 0x0178 profile remains candidate-only negative evidence', () => {
  const profile = JSON.parse(fs.readFileSync(PRIOR_PROFILE_PATH, 'utf8'));
  const boundary = prior0178Boundary(profile);
  assert.equal(boundary.semantic_claim, null);
  assert.equal(boundary.typed_field_schema, null);
  assert.equal(boundary.independent_anchor_count, 0);
  assert.equal(boundary.profiled_record_count, 800);
  assert.equal(boundary.promotion_allowed, false);
});

test('generated audit closes every exact factory and conserves all rows', () => {
  const report = readJson('residual_p3_wave_audit_16_16.json');
  assert.equal(report.exact_build, EXACT_BUILD);
  assert.equal(report.architecture_gate, 'PASS');
  assert.equal(report.scope.length, 12);
  assert.equal(report.conservation.target_row_count, 108185);
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

test('0x018c exact shared codec is retained as a semantic-transfer counterexample', () => {
  const report = readJson('residual_p3_wave_audit_16_16.json');
  const route = report.runtime_static_recovery.routes['0x018c'];
  const names = route.shared_codec_routes.flatMap((row) => row.callback_names).sort();
  assert.deepEqual(names, ['PKT_OnLeaveVisibilityClient_s', 'PKT_S2C_DestroyClientMissile_s']);
  assert.equal(route.shared_codec_routes.every((row) => row.semantic_transfer_allowed === false), true);
  const decision = report.decision_summary.route_decisions
    .find((row) => row.packet_discriminator === '0x018c');
  assert.equal(decision.decision, 'REPURPOSE');
  assert.equal(decision.semantic_claim, null);
});

test('machine decisions are exhausted and require external-only evidence', () => {
  const decisions = readJson('residual_p3_wave_machine_decisions_16_16.json');
  assert.equal(decisions.route_decisions.length, 12);
  assert.equal(decisions.capability_decisions.length, 12);
  assert.equal(decisions.domain_decisions.length, 4);
  assert.deepEqual(decisions.decision_counts, {
    PROMOTE: 0,
    REPURPOSE: 1,
    KEEP_CANDIDATE: 11,
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
  const heroWide = decisions.route_decisions
    .find((row) => row.packet_discriminator === '0x0178');
  assert.equal(heroWide.decision, 'KEEP_CANDIDATE');
  assert.equal(heroWide.prior_0178_profile_boundary.independent_anchor_count, 0);
});

test('hash manifest verifies every listed artifact and excludes its own hash', () => {
  const manifest = readJson('hashes_16_16.json');
  assert.equal(manifest.exact_build, EXACT_BUILD);
  assert.equal(manifest.files.length > 40, true);
  assert.equal(manifest.files.some((entry) => entry.path.endsWith('/hashes_16_16.json')), false);
  for (const entry of manifest.files) {
    const filePath = path.join(ROOT, entry.path);
    assertFrozenOrPublicSourceHash(entry, filePath, fileSha);
  }
  assert.equal(manifest.protected_holdout.enumerated, false);
  assert.equal(manifest.protected_holdout.consumed, false);
});
