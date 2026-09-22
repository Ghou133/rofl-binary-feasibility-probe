'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  EXACT_BUILD,
  FAMILY_BY_ROUTE,
  ROUTE_IDS,
  RUNTIME_SHA256,
  classifyNativeFailure,
  packetHex,
  rejectProtectedPath,
  validateDecisionBundle,
} = require('../src/residual_p5_wave_v2');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT_ROOT = path.join(
  ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'residual_p5_wave',
);

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACT_ROOT, name), 'utf8'));
}

test('residual P5 scope is exact and stable', () => {
  assert.equal(EXACT_BUILD, '16.16.805.0442');
  assert.equal(RUNTIME_SHA256.length, 64);
  assert.equal(ROUTE_IDS.length, 8);
  assert.equal(new Set(ROUTE_IDS).size, 8);
  assert.deepEqual(ROUTE_IDS, [
    0x0288, 0x0093, 0x00bf, 0x04b2, 0x017d, 0x02e5, 0x01b2, 0x0041,
  ]);
  assert.equal(Object.keys(FAMILY_BY_ROUTE).length, 8);
  assert.deepEqual(new Set(ROUTE_IDS.map(packetHex)), new Set(Object.keys(FAMILY_BY_ROUTE)));
  assert.doesNotThrow(() => rejectProtectedPath(path.join(ARTIFACT_ROOT, 'safe.json')));
});

test('native failure classification preserves exact fault evidence', () => {
  const result = classifyNativeFailure(
    'invalid memory access address=0x25cc4670 rip=0x140f526f0',
  );
  assert.equal(result.class, 'EXTERNAL_RUNTIME_HEAP_OR_TLS_STATE');
  assert.equal(result.missing_address, '0x25cc4670');
  assert.equal(result.fault_rip, '0x140f526f0');
  assert.equal(classifyNativeFailure('return=0;fully_consumed=false').class,
    'UNCLASSIFIED_NATIVE_FAILURE');
});

test('generated report conserves the complete eight-route inventory', () => {
  const report = readJson('residual_p5_wave_audit_16_16.json');
  assert.equal(report.exact_build, EXACT_BUILD);
  assert.equal(report.project_context_loaded, true);
  assert.equal(report.architecture_gate, 'PASS');
  assert.equal(report.scope.length, 8);
  assert.equal(report.conservation.target_row_count, 14174);
  assert.ok(report.conservation.distinct_payload_row_count > 0);
  assert.equal(report.conservation.target_occurrence_weight_conserved, true);
  assert.equal(report.validations.all_pass, true);
  assert.equal(report.saturation.current_safe_local_resource_saturated, true);
  assert.equal(report.saturation.local_actionable_hypothesis_count, 0);
  assert.deepEqual(report.protected_holdout, {
    enumerated: false,
    read: false,
    hashed: false,
    decoded: false,
    tested: false,
    consumed: false,
  });
  for (const route of Object.values(report.raw_route_profiles)) {
    assert.equal(route.payload.occurrence_weight_conserved, true);
    for (const anchor of Object.values(route.anchor_correlations_with_shifted_controls)) {
      assert.equal(typeof anchor.shifted_137ms_within_10ms_count, 'number');
      assert.equal(typeof anchor.shifted_997ms_within_10ms_count, 'number');
      assert.equal(anchor.semantic_claim, null);
    }
  }
});

test('factory chains, deserializer fields, and bounded callback-negative surface are exact', () => {
  const report = readJson('residual_p5_static_runtime_16_16.json');
  assert.equal(report.runtime_sha256, RUNTIME_SHA256);
  assert.equal(report.all_routes_factory_closed, true);
  assert.equal(report.all_deserializer_object_access_scans_executed, true);
  assert.equal(report.all_direct_xref_surfaces_scanned, true);
  assert.equal(report.all_receive_static_surfaces_exhausted, true);
  assert.equal(Object.keys(report.routes).length, 8);
  assert.ok(report.pdata_scan.function_count > 100000);
  assert.ok(report.pdata_scan.instruction_byte_count > 20000000);
  assert.equal(report.structural_family_relationships.all_pairs_examined, true);
  assert.equal(report.structural_family_relationships.pair_count, 28);
  for (const route of Object.values(report.routes)) {
    assert.equal(route.validations.all_factory_checks_pass, true);
    assert.equal(route.validations.deserializer_object_access_scan_executed, true);
    assert.equal(route.validations.direct_xref_surfaces_scanned, true);
    assert.equal(route.static_identity_xrefs.all_direct_xref_surfaces_scanned, true);
    assert.equal(route.full_pdata_immediate_reference_scan.candidate_function_rva_inventory_complete,
      true);
    assert.equal(route.full_pdata_immediate_reference_scan.bounded_disposition.semantic_claim, null);
    assert.equal(route.deserializer_static_analysis.analysis_method,
      'CAPSTONE_ALIAS_TRACKING_FROM_CALLBACK_RDX_OR_DESERIALIZER_RCX');
    assert.ok(route.deserializer_static_analysis.bounded_instruction_count > 0);
    assert.equal(route.receive_identity.bounded_static_surfaces_exhausted, true);
    assert.equal(route.factory_chain.allocation_size, route.factory_chain.object_size);
  }
});

test('every distinct payload has deterministic double native disposition', () => {
  const report = readJson('residual_p5_wave_audit_16_16.json');
  assert.equal(report.native_determinism.exact_native_execution_rerun, true);
  assert.equal(report.native_determinism.route_count, 8);
  assert.equal(report.native_determinism.all_match, true);
  for (const route of Object.values(report.native_exact_emulation.routes)) {
    assert.equal(route.all_distinct_payloads_attempted, true);
    assert.equal(route.full_occurrence_weight_conserved, true);
    assert.equal(route.all_failures_external_runtime_state, true);
    assert.equal(route.successful_full_consume_occurrence_weight
      + route.conserved_failure_occurrence_weight, route.full_inventory_occurrence_weight);
  }
});

test('machine decisions exhaust route, capability, and domain local hypotheses', () => {
  const decisions = readJson('residual_p5_wave_decisions_16_16.json');
  assert.equal(validateDecisionBundle(decisions), true);
  assert.equal(decisions.route_decisions.length, 8);
  assert.equal(decisions.capability_decisions.length, 8);
  assert.equal(decisions.domain_decisions.length, 1);
  assert.equal(decisions.decision_counts.REPURPOSE, 8);
  assert.equal(decisions.decision_counts_by_level.capability.PROMOTE, 8);
  assert.equal(decisions.decision_counts_by_level.domain.REPURPOSE, 1);
  assert.equal(decisions.saturation.current_safe_local_resource_saturated, true);
  assert.equal(decisions.saturation.local_actionable_hypothesis_count, 0);
  for (const group of ['route_decisions', 'capability_decisions', 'domain_decisions']) {
    for (const row of decisions[group]) {
      assert.equal(row.actual_reverse_engineering_executed, true);
      assert.equal(row.evidence_exhausted, true);
      assert.deepEqual(row.actionable_hypotheses, []);
      assert.ok(Array.isArray(row.next_required_evidence));
      assert.ok(row.next_required_evidence.length > 0);
      assert.equal(row.external_only_gate.required, true);
      assert.equal(row.external_only_gate.local_safe_evidence_remaining, false);
    }
  }
});
