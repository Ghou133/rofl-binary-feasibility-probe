'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { ExceptionRegistry } = require('../src/semantic_fingerprint');
const { matchSemanticFingerprint } = require('../src/semantic_fingerprint_matcher');
const { createGroundTruthOracle, alignGroundTruthOracle } = require('../src/controlled_calibration');
const { createMigrationDecision } = require('../src/semantic_migration_oracle');
const { REGRESSION_REPORT_SCHEMA, REGRESSION_SCHEMA_DOCUMENT, regressionIntegrationSchemaDocument, runRegressionIntegration } = require('../src/semantic_regression_oracle');

const SOURCE = '16.16.805.0442';
const TARGET = '16.17.900.0001';
const SHA_A = 'a'.repeat(64); const SHA_B = 'b'.repeat(64);
function fpProvenance(build) { return { exact_build: build, replay_sha256: SHA_A, source_sha256: SHA_B, source_kind: 'CONTROLLED_REPLAY' }; }
function provenance(sourceBuild = SOURCE, targetBuild = SOURCE) { return { source_build: sourceBuild, target_build: targetBuild, run_id: 'regression-run-1' }; }
function fingerprint() { return {
  schema: 'ROFL_SEMANTIC_FINGERPRINT_V1', schema_version: 1, semantic_name: 'CURRENT_HP', canonical_schema_version: 'ROFL_SEMANTIC_SCHEMA_V2', availability: 'VERIFIED', promotion_eligible: true, provenance: fpProvenance(SOURCE),
  structural_fingerprint: { runtime_type: 'AIHeroClient', registration: 'health family', callback: 'update', constructor: 'constructor', vtable: 'shape', deserializer: 'decode', serializer: 'receive', component: 'hero', field_type: 'float32', field_position: 'ordinal', payload_shape: ['state'], surrounding_fields: ['level'], entity_relationship: 'hero subject' },
  behavioral_fingerprint: { value_range: { minimum: 0 }, temporal_behavior: 'damage and heal transitions', update_frequency: 'event driven', event_correlations: ['damage'], reset_behavior: 'respawn', persistence_behavior: 'persists' },
  build_bindings: [{ binding_id: 'source', exact_build: SOURCE, provenance: fpProvenance(SOURCE), binding: { route: '0x010c' } }],
  exact_builds_verified: [{ exact_build: SOURCE, binding_id: 'source', provenance: fpProvenance(SOURCE) }],
  cross_field_invariants: [{ invariant_id: 'nonnegative', expression: 'CURRENT_HP >= 0', mode: 'STRICT', rationale: 'domain' }],
  ground_truth_oracles: [{ reference_id: 'oracle-1', case_id: 'case-1', oracle_kind: 'MACHINE', provenance: fpProvenance(SOURCE) }],
  negative_controls: [{ reference_id: 'control-1', control_kind: 'SCOREBOARD', rejection_reason: 'coarse', provenance: fpProvenance(SOURCE) }], known_exceptions: [], migration_policy: 'AUTO_IF_UNIQUE',
}; }
function candidate(targetBuild = SOURCE) { const source = fingerprint(); return {
  schema: 'ROFL_SEMANTIC_FINGERPRINT_CANDIDATE_EVIDENCE_V1', schema_version: 1, candidate_id: `candidate-${targetBuild}`, source_build: SOURCE, run_id: 'matcher-run-1', semantic_name: 'CURRENT_HP', exact_build: targetBuild, exact_build_only: true, nearest_build_fallback: 'FORBIDDEN', promotion_eligible: false, candidate_role: 'MIGRATION_EVIDENCE_ONLY', provenance: fpProvenance(targetBuild), build_binding: { route: '0x0200' },
  structural: { evidence_status: 'VERIFIED', observations: source.structural_fingerprint }, behavioral: { evidence_status: 'VERIFIED', observations: source.behavioral_fingerprint },
  cross_field: { evidence_status: 'VERIFIED', results: [{ reference_id: 'nonnegative', status: 'PASS', reason: 'all rows nonnegative' }] }, ground_truth_oracle: { evidence_status: 'VERIFIED', results: [{ reference_id: 'oracle-1', status: 'PASS', reason: 'anchor matched' }] }, negative_controls: { evidence_status: 'VERIFIED', results: [{ reference_id: 'control-1', status: 'PASS', reason: 'control rejected' }] },
}; }
function oracle() { return createGroundTruthOracle([{ case_id: 'case-1', replay_sha: SHA_A, exact_build: SOURCE, timestamp: 1000, entity: { participant_id: 1, champion: 'Ahri' }, semantic: 'CURRENT_HP', observed_value: 731, before_after: 'SNAPSHOT', source: { kind: 'REPLAY_UI' }, manual_or_machine: 'MACHINE', confidence: 'HIGH', notes: 'controlled' }]); }
function alignment(value = 731) { return alignGroundTruthOracle(oracle(), [{ replay_sha: SHA_A, exact_build: SOURCE, timestamp: 1000, entity: { participant_id: 1, champion: 'Ahri' }, semantic: 'CURRENT_HP', value }]); }
function input(overrides = {}) { const matcher = matchSemanticFingerprint(fingerprint(), candidate()); return { schema: 'SEMANTIC_REGRESSION_INTEGRATION_V1', schema_version: 1, semantic_name: 'CURRENT_HP', source_build: SOURCE, target_build: SOURCE, provenance: provenance(), semantic_fingerprint: fingerprint(), matcher_score_report: matcher, ground_truth_alignment: alignment(), exception_registry: new ExceptionRegistry(), machine_suite_attestations: [{ suite_id: 'semantic-regression', target_build: SOURCE, status: 'PASS', provenance: provenance() }], ...overrides }; }

test('actual fingerprint matcher and GroundTruthAlignment outputs produce a non-promoting decision-ready candidate', () => {
  const report = runRegressionIntegration(input());
  assert.equal(report.schema, REGRESSION_REPORT_SCHEMA);
  assert.deepEqual(report.gates, { invariant_gate: 'PASS', regression_gate: 'PASS', negative_control_gate: 'PASS' });
  assert.equal(report.alignment.results[0].status, 'MATCHED');
  assert.equal(report.conservation.oracle_cases, 1);
  assert.equal(report.promotion_authority, 'NONE');
  const decision = createMigrationDecision({ semantic_name: 'CURRENT_HP', source_build: SOURCE, target_build: SOURCE, provenance: report.provenance, candidates: [report.migration_decision_candidate] });
  assert.equal(decision.status, 'REVALIDATED_MACHINE_ONLY');
});

test('known alignment residual and matcher negative-control failures are preserved as gates, not rejected as malformed', () => {
  const failedAlignment = runRegressionIntegration(input({ ground_truth_alignment: alignment(730) }));
  assert.equal(failedAlignment.gates.regression_gate, 'FAIL');
  assert.equal(failedAlignment.alignment_failures.length, 1);
  const failedMatcher = matchSemanticFingerprint(fingerprint(), candidate(SOURCE));
  failedMatcher.gates.negative_control_gate.status = 'FAIL';
  const report = runRegressionIntegration(input({ matcher_score_report: failedMatcher }));
  assert.equal(report.gates.negative_control_gate, 'FAIL');
  assert.equal(report.promotion_status, 'NOT_PROMOTED');
  const failedMachine = runRegressionIntegration(input({ machine_suite_attestations: [{ suite_id: 'semantic-regression', target_build: SOURCE, status: 'FAIL', provenance: provenance() }] }));
  assert.equal(failedMachine.gates.regression_gate, 'FAIL');
  assert.equal(failedMachine.failed_machine_suite_attestations.length, 1);
});

test('cross-build evaluation requires explicit adapter provenance and malformed/holdout inputs fail closed', () => {
  const matcher = matchSemanticFingerprint(fingerprint(), candidate(TARGET));
  const cross = input({ target_build: TARGET, provenance: provenance(SOURCE, TARGET), matcher_score_report: matcher, machine_suite_attestations: [{ suite_id: 'semantic-regression', target_build: TARGET, status: 'PASS', provenance: provenance(SOURCE, TARGET) }] });
  assert.throws(() => runRegressionIntegration(cross), /cross_build_alignment_adapter/);
  const report = runRegressionIntegration({ ...cross, cross_build_alignment_adapter: { schema: 'GROUND_TRUTH_CROSS_BUILD_ALIGNMENT_ADAPTER_V1', schema_version: 1, source_build: SOURCE, target_build: TARGET, status: 'PASS', provenance: provenance(SOURCE, TARGET) } });
  assert.equal(report.gates.regression_gate, 'PASS');
  assert.throws(() => runRegressionIntegration(input({ source_build: '16.16' })), /strict N\.N\.N\.N/);
  assert.throws(() => runRegressionIntegration(input({ provenance: { ...provenance(), input: 'Jungle Objective Holdout/x.json' } })), /protected Holdout/);
});

test('schema document describes actual upstream contracts and no-promotion constraint', () => {
  const document = regressionIntegrationSchemaDocument();
  assert.equal(document.schema, REGRESSION_SCHEMA_DOCUMENT);
  assert.equal(document.matcher_result_schema, 'ROFL_SEMANTIC_FINGERPRINT_MATCH_RESULT_V1');
  assert.equal(document.alignment_schema_version, 'GROUND_TRUTH_ALIGNMENT_V1');
  assert.equal(document.rules.cross_build_adapter_required, true);
  assert.equal(document.rules.promotion_authority, 'NONE');
  assert.ok(document.required_inputs.includes('machine_suite_attestations'));
});
