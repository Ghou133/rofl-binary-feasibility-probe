'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const {
  EXACT_BUILD,
  ROUTE_IDS,
  RUNTIME_SHA256,
  classifyNativeFailure,
  packetHex,
  rejectProtectedPath,
  validateDecisionBundle,
} = require('../src/residual_p4_wave_v2');

const ROOT = path.resolve(__dirname, '..');
const ARTIFACT_ROOT = path.join(
  ROOT,
  'artifacts',
  'full_semantic_deep_recovery_v2',
  'residual_p4_wave',
);

function readJson(name) {
  return JSON.parse(fs.readFileSync(path.join(ARTIFACT_ROOT, name), 'utf8'));
}

test('residual P4 scope is exact, unique, and exact-build bound', () => {
  assert.equal(EXACT_BUILD, '16.16.805.0442');
  assert.equal(RUNTIME_SHA256.length, 64);
  assert.deepEqual(ROUTE_IDS, [
    0x012b, 0x0229, 0x025f, 0x043d, 0x022e, 0x02b5,
    0x01e4, 0x026e, 0x0313, 0x0339, 0x02bf, 0x005f,
  ]);
  assert.equal(new Set(ROUTE_IDS).size, 12);
  assert.equal(new Set(ROUTE_IDS.map(packetHex)).size, 12);
  assert.doesNotThrow(() => rejectProtectedPath(path.join(ARTIFACT_ROOT, 'safe.json')));
});

test('protected Holdout is rejected before file IO', () => {
  assert.throws(
    () => rejectProtectedPath(path.join(ROOT, 'Jungle Objective Holdout', 'forbidden.rofl')),
    /protected Holdout path is forbidden/,
  );
});

test('native external-state failures retain precise fault evidence', () => {
  const classified = classifyNativeFailure(
    'invalid memory access address=0x25cc4670 rip=0x140f526f0',
  );
  assert.equal(classified.class, 'EXTERNAL_RUNTIME_HEAP_TLS_OR_CODEC_STATE');
  assert.equal(classified.missing_address, '0x25cc4670');
  assert.equal(classified.fault_rip, '0x140f526f0');
  assert.equal(
    classifyNativeFailure('return=0;fully_consumed=false').class,
    'UNCLASSIFIED_NATIVE_FAILURE',
  );
});

test('generated report conserves every observed route and payload weight', () => {
  const report = readJson('residual_p4_wave_audit_16_16.json');
  assert.equal(report.exact_build, EXACT_BUILD);
  assert.equal(report.project_context_loaded, true);
  assert.equal(report.architecture_gate, 'PASS');
  assert.equal(report.scope.length, 12);
  assert.equal(report.conservation.target_row_count, 116561);
  assert.equal(report.conservation.distinct_payload_row_count, 65194);
  assert.equal(report.conservation.target_occurrence_weight_conserved, true);
  assert.equal(report.conservation.deterministic_extraction_match, true);
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
    assert.equal(route.raw_param.zero_only, true);
    for (const anchor of Object.values(route.anchor_correlations_with_shifted_controls)) {
      assert.equal(typeof anchor.shifted_137ms_within_10ms_count, 'number');
      assert.equal(typeof anchor.shifted_997ms_within_10ms_count, 'number');
      assert.equal(anchor.semantic_claim, null);
    }
  }
});

test('RTTI/callback negative surface and every factory chain are exact', () => {
  const report = readJson('residual_p4_static_runtime_16_16.json');
  assert.equal(report.runtime_sha256, RUNTIME_SHA256);
  assert.equal(report.all_routes_factory_closed, true);
  assert.equal(report.all_receive_static_surfaces_exhausted, true);
  assert.equal(report.generic_dispatcher_heap_boundary_precisely_localized, true);
  assert.equal(
    report.generic_dispatcher_heap_boundary.precisely_localized,
    true,
  );
  assert.ok(report.generic_dispatcher_heap_boundary.generic_dispatchers.length > 0);
  assert.ok(report.generic_dispatcher_heap_boundary.callback_tree_headers.length > 0);
  assert.equal(Object.keys(report.routes).length, 12);
  assert.ok(report.pdata_scan.function_count > 100000);
  assert.ok(report.pdata_scan.instruction_byte_count > 20000000);
  for (const route of Object.values(report.routes)) {
    assert.equal(route.validations.all_factory_checks_pass, true);
    assert.equal(route.validations.makefunction_rtti_callback_surface_checked, true);
    assert.equal(route.receive_identity.bounded_static_surfaces_exhausted, true);
    assert.equal(route.factory_chain.allocation_size, route.factory_chain.object_size);
    assert.equal(
      route.receive_identity.status,
      'PACKET_SPECIFIC_RTTI_CALLBACK_REQUIRES_RUNTIME_HEAP_CALLBACK_TREE',
    );
  }
  const shared = report.routes['0x01e4'].shared_named_codec_routes;
  assert.ok(shared.length >= 3);
  assert.ok(shared.every((row) => row.semantic_transfer_allowed === false));
  assert.deepEqual(
    report.routes['0x022e'].shared_in_wave_codec_routes.map(
      (row) => row.packet_discriminator,
    ),
    ['0x0313'],
  );
});

test('every distinct payload has deterministic double native disposition', () => {
  const report = readJson('residual_p4_wave_audit_16_16.json');
  assert.equal(report.native_determinism.exact_native_execution_rerun, true);
  assert.equal(report.native_determinism.route_count, 12);
  assert.equal(report.native_determinism.all_match, true);
  for (const route of Object.values(report.native_exact_emulation.routes)) {
    assert.equal(route.all_distinct_payloads_attempted, true);
    assert.equal(route.full_occurrence_weight_conserved, true);
    assert.equal(route.all_failures_external_runtime_state, true);
    assert.equal(
      route.successful_full_consume_occurrence_weight
        + route.conserved_failure_occurrence_weight,
      route.full_inventory_occurrence_weight,
    );
  }
});

test('route, capability, and domain decisions have no local actionable work', () => {
  const decisions = readJson('residual_p4_wave_decisions_16_16.json');
  assert.equal(validateDecisionBundle(decisions), true);
  assert.equal(decisions.route_decisions.length, 12);
  assert.equal(decisions.capability_decisions.length, 12);
  assert.equal(decisions.domain_decisions.length, 1);
  assert.equal(decisions.decision_counts.REPURPOSE, 12);
  assert.equal(decisions.saturation.current_safe_local_resource_saturated, true);
  assert.equal(decisions.saturation.local_actionable_hypothesis_count, 0);
  for (const group of ['route_decisions', 'capability_decisions', 'domain_decisions']) {
    for (const row of decisions[group]) {
      assert.equal(row.actual_reverse_engineering_executed, true);
      assert.equal(row.evidence_exhausted, true);
      assert.deepEqual(row.actionable_hypotheses, []);
      assert.equal(row.external_only_gate.required, true);
      assert.equal(row.external_only_gate.local_safe_evidence_remaining, false);
    }
  }
});
