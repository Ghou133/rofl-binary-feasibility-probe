'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { matchSemanticFingerprint, matcherSchemaDocument, validateMatcherSchemaDocument } = require('../src/semantic_fingerprint_matcher');
const { createMigrationDecision } = require('../src/semantic_migration_oracle');

const BUILD = '16.16.805.0442';
const TARGET_BUILD = '16.17.900.0001';
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const STRUCTURAL_FIELDS = ['runtime_type', 'registration', 'callback', 'constructor', 'vtable', 'deserializer', 'serializer', 'component', 'field_type', 'field_position', 'payload_shape', 'surrounding_fields', 'entity_relationship'];
const BEHAVIORAL_FIELDS = ['value_range', 'temporal_behavior', 'update_frequency', 'event_correlations', 'reset_behavior', 'persistence_behavior'];

function provenance(build, replay = SHA_A) { return { exact_build: build, replay_sha256: replay, source_sha256: SHA_B, source_kind: 'CONTROLLED_REPLAY' }; }
function fingerprint() {
  return {
    schema: 'ROFL_SEMANTIC_FINGERPRINT_V1', schema_version: 1, semantic_name: 'CURRENT_HP', canonical_schema_version: 'ROFL_SEMANTIC_SCHEMA_V2', availability: 'VERIFIED', promotion_eligible: true, provenance: provenance(BUILD),
    structural_fingerprint: { runtime_type: 'AIHeroClient', registration: 'health family', callback: 'update', constructor: 'constructor', vtable: 'shape', deserializer: 'decode', serializer: 'receive', component: 'hero', field_type: 'float32', field_position: 'ordinal', payload_shape: ['state'], surrounding_fields: ['level'], entity_relationship: 'hero subject' },
    behavioral_fingerprint: { value_range: { minimum: 0 }, temporal_behavior: 'damage and heal transitions', update_frequency: 'event driven', event_correlations: ['damage'], reset_behavior: 'respawn', persistence_behavior: 'persists' },
    build_bindings: [{ binding_id: 'old', exact_build: BUILD, provenance: provenance(BUILD), binding: { route: '0x010c', field_offset: 40 } }],
    exact_builds_verified: [{ exact_build: BUILD, binding_id: 'old', provenance: provenance(BUILD) }],
    cross_field_invariants: [{ invariant_id: 'nonnegative', expression: 'CURRENT_HP >= 0', mode: 'STRICT', rationale: 'domain' }],
    ground_truth_oracles: [{ reference_id: 'oracle-1', case_id: 'case-1', oracle_kind: 'MACHINE', provenance: provenance(BUILD) }],
    negative_controls: [{ reference_id: 'control-1', control_kind: 'SCOREBOARD', rejection_reason: 'coarse', provenance: provenance(BUILD) }],
    known_exceptions: [], migration_policy: 'AUTO_IF_UNIQUE',
  };
}
function candidate(overrides = {}) {
  const source = fingerprint();
  return {
    schema: 'ROFL_SEMANTIC_FINGERPRINT_CANDIDATE_EVIDENCE_V1', schema_version: 1, candidate_id: 'candidate-16-17', semantic_name: 'CURRENT_HP', exact_build: TARGET_BUILD,
    source_build: BUILD, run_id: 'matcher-run-16-17-001', exact_build_only: true, nearest_build_fallback: 'FORBIDDEN', promotion_eligible: false, candidate_role: 'MIGRATION_EVIDENCE_ONLY', provenance: provenance(TARGET_BUILD),
    build_binding: { route: '0x0200', field_offset: 52 },
    structural: { evidence_status: 'VERIFIED', observations: source.structural_fingerprint },
    behavioral: { evidence_status: 'VERIFIED', observations: source.behavioral_fingerprint },
    cross_field: { evidence_status: 'VERIFIED', results: [{ reference_id: 'nonnegative', status: 'PASS', reason: 'all rows nonnegative' }] },
    ground_truth_oracle: { evidence_status: 'VERIFIED', results: [{ reference_id: 'oracle-1', status: 'PASS', reason: 'anchor matched' }] },
    negative_controls: { evidence_status: 'VERIFIED', results: [{ reference_id: 'control-1', status: 'PASS', reason: 'control rejected' }] },
    ...overrides,
  };
}

test('route move retains semantic match, four scores, gates, conservation, and no promotion', () => {
  const result = matchSemanticFingerprint(fingerprint(), candidate());
  assert.equal(result.candidate.build_binding.route, '0x0200');
  for (const score of Object.values(result.migration_oracle_scores)) assert.equal(score.score, 1);
  assert.deepEqual(result.migration_decision_scores, {
    structural_match_score: 1, behavioral_match_score: 1, cross_field_match_score: 1, ground_truth_oracle_score: 1,
  });
  assert.equal(result.source_build, BUILD);
  assert.equal(result.target_build, TARGET_BUILD);
  assert.equal(result.provenance.run_id, 'matcher-run-16-17-001');
  assert.equal(result.regression_matcher_score_report.schema, 'SEMANTIC_MATCHER_SCORE_REPORT_V1');
  assert.equal(result.gates.invariant_gate.status, 'PASS');
  assert.equal(result.gates.regression_gate.status, 'PASS');
  assert.equal(result.gates.negative_control_gate.status, 'PASS');
  assert.equal(result.candidate_conservation.negative_control.mismatched_count, 0);
  assert.equal(result.decision.status, 'MATCH_COMPLETE_NO_PROMOTION');
  assert.equal(result.decision.promotion, 'FORBIDDEN');
  assert.equal(result.nearest_build_fallback, 'FORBIDDEN');
});

test('ambiguous unknown evidence receives no score and negative-control failure is conserved', () => {
  const result = matchSemanticFingerprint(fingerprint(), candidate({
    structural: { evidence_status: 'UNKNOWN', observations: null },
    ground_truth_oracle: { evidence_status: 'VERIFIED', results: [{ reference_id: 'oracle-1', status: 'UNKNOWN', reason: 'anchor not available' }] },
    negative_controls: { evidence_status: 'VERIFIED', results: [{ reference_id: 'control-1', status: 'FAIL', reason: 'candidate resembles rejected control' }] },
  }));
  assert.equal(result.migration_oracle_scores.structural.score, 0);
  assert.equal(result.migration_oracle_scores.structural.status, 'UNKNOWN');
  assert.equal(result.migration_oracle_scores.ground_truth_oracle.score, 0);
  assert.equal(result.migration_oracle_scores.ground_truth_oracle.status, 'UNKNOWN');
  assert.ok(Object.values(result.migration_decision_scores).every(Number.isFinite));
  assert.equal(result.gates.negative_control_gate.status, 'FAIL');
  assert.equal(result.candidate_conservation.negative_control.mismatched_count, 1);
  assert.equal(result.decision.status, 'MATCH_INCOMPLETE_OR_FAILED_NO_PROMOTION');
});

test('an UNKNOWN source fingerprint field cannot be copied into a full-pass structural score', () => {
  const source = fingerprint();
  source.structural_fingerprint.payload_shape = { status: 'UNKNOWN', retained: 'opaque shape' };
  source.promotion_eligible = false;
  source.migration_policy = 'REVALIDATE_IF_AMBIGUOUS';
  source.completeness = {
    status: 'INCOMPLETE', incomplete_dimensions: ['structural_fingerprint.payload_shape'],
    blocking_policy: 'REVALIDATE_IF_AMBIGUOUS', rationale: 'opaque shape is retained as unknown',
  };
  const target = candidate({ structural: { evidence_status: 'VERIFIED', observations: source.structural_fingerprint } });
  const result = matchSemanticFingerprint(source, target);
  assert.equal(result.migration_oracle_scores.structural.score, 0);
  assert.equal(result.migration_oracle_scores.structural.status, 'UNKNOWN');
  assert.equal(result.migration_decision_scores.structural_match_score, 0);
  assert.equal(result.decision.status, 'MATCH_INCOMPLETE_OR_FAILED_NO_PROMOTION');
});

test('flat migration decision candidate is directly consumable after gates and exception audit are mapped', () => {
  const result = matchSemanticFingerprint(fingerprint(), candidate({ migration_class: 'ROUTE_MOVED' }));
  const decisionCandidate = {
    ...result.migration_decision_candidate,
    invariant_gate: result.gates.invariant_gate.status,
    regression_gate: result.gates.regression_gate.status,
    negative_control_gate: result.gates.negative_control_gate.status,
    exception_audit: { status: 'PASS', exceptions: [] },
  };
  const decision = createMigrationDecision({
    semantic_name: result.semantic_name, source_build: result.source_build, target_build: result.target_build,
    provenance: result.provenance, candidates: [decisionCandidate],
  });
  assert.equal(decision.status, 'AUTO_VERIFIED_WITH_ROUTE_MOVE');
  assert.equal(decision.selected_candidate_id, 'candidate-16-17');
});

test('candidate contract rejects fallback, protected Holdout, parser ownership, and omitted results', () => {
  assert.throws(() => matchSemanticFingerprint(fingerprint(), candidate({ nearest_build_fallback: 'ALLOWED' })), /forbid nearest-build fallback/);
  assert.throws(() => matchSemanticFingerprint(fingerprint(), candidate({ provenance: { ...provenance(TARGET_BUILD), source_kind: 'JUNGLE_OBJECTIVE_HOLDOUT' } })), /Holdout/);
  assert.throws(() => matchSemanticFingerprint(fingerprint(), candidate({ semantic_name: 'MAP_MECHANIC' })), /ownership boundary/);
  assert.throws(() => matchSemanticFingerprint(fingerprint(), candidate({ ground_truth_oracle: { evidence_status: 'VERIFIED', results: [] } })), /missing required results/);
});

test('matcher schema document validates its no-credit and no-promotion contract', () => {
  const document = matcherSchemaDocument();
  assert.deepEqual(validateMatcherSchemaDocument(document), []);
  assert.equal(document.rules.incomplete_verified_source_matching, 'ZERO_SCORE_NO_PROMOTION');
  assert.throws(() => validateMatcherSchemaDocument({ ...document, rules: { ...document.rules, automatic_promotion: 'ALLOWED' } }), /rules/);
});
