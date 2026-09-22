'use strict';

const ORACLE_SCHEMA = 'SEMANTIC_MIGRATION_ORACLE_V1';
const DECISION_SCHEMA = 'SEMANTIC_MIGRATION_DECISION_V1';
const DECISION_SCHEMA_DOCUMENT = 'SEMANTIC_MIGRATION_DECISION_SCHEMA_DOCUMENT_V1';
const EXACT_BUILD_PATTERN = /^\d+\.\d+\.\d+\.\d+$/;
const SHA256_PATTERN = /^[a-f0-9]{64}$/i;
const REGRESSION_REPORT_SCHEMA = 'SEMANTIC_REGRESSION_ORACLE_REPORT_V1';

const DECISION_STATUSES = Object.freeze([
  'AUTO_VERIFIED',
  'AUTO_VERIFIED_WITH_ROUTE_MOVE',
  'AUTO_VERIFIED_WITH_FIELD_SHIFT',
  'REVALIDATED_MACHINE_ONLY',
  'MANUAL_VALIDATION_REQUIRED',
  'SEMANTIC_CHANGED',
  'UNSUPPORTED',
]);

const REQUIRED_SCORES = Object.freeze([
  'structural_match_score',
  'behavioral_match_score',
  'cross_field_match_score',
  'ground_truth_oracle_score',
]);
const REQUIRED_GATES = Object.freeze([
  'invariant_gate',
  'regression_gate',
  'negative_control_gate',
]);
const PASSING_GATES = new Set(['PASS', 'EXCEPTION_ACCOUNTED']);
const DEFAULT_THRESHOLDS = Object.freeze(Object.fromEntries(
  REQUIRED_SCORES.map((name) => [name, 1]),
));

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function hasProtectedHoldoutReference(value, seen = new Set()) {
  if (typeof value === 'string') return /holdout/i.test(value);
  if (!value || typeof value !== 'object' || seen.has(value)) return false;
  seen.add(value);
  return Object.entries(value).some(([key, item]) => /holdout/i.test(key)
    || hasProtectedHoldoutReference(item, seen));
}

function rejectProtectedHoldout(value) {
  invariant(!hasProtectedHoldoutReference(value),
    'protected Holdout references are forbidden before oracle evaluation');
}

function validateExactBuild(value, label) {
  invariant(typeof value === 'string' && EXACT_BUILD_PATTERN.test(value),
    `${label} must use strict N.N.N.N exact-build form`);
  return value;
}

function createDecisionSchemaDocument() {
  return {
    schema: DECISION_SCHEMA_DOCUMENT,
    schema_version: 1,
    decision_schema: DECISION_SCHEMA,
    oracle_schema: ORACLE_SCHEMA,
    exact_build_format: 'N.N.N.N',
    required_input_fields: [
      'semantic_name', 'source_build', 'target_build', 'provenance', 'candidates',
    ],
    candidate_required_fields: [
      'candidate_id', 'exact_build', ...REQUIRED_SCORES, ...REQUIRED_GATES,
      'exception_audit', 'provenance',
    ],
    provenance_required_fields: ['source_build', 'target_build', 'run_id'],
    provenance_evidence_binding: [
      'source_fingerprint_sha256',
      `regression_report_schema=${REGRESSION_REPORT_SCHEMA} plus run_id`,
    ],
    statuses: [...DECISION_STATUSES],
    conservation_fields: ['input_candidates', 'assessed_candidates', 'preserved_candidates',
      'silent_discard', 'silent_fallback'],
  };
}

function normalizedThresholds(thresholds = {}) {
  invariant(isObject(thresholds), 'thresholds must be an object');
  const result = {};
  for (const scoreName of REQUIRED_SCORES) {
    const threshold = thresholds[scoreName] ?? DEFAULT_THRESHOLDS[scoreName];
    invariant(typeof threshold === 'number' && Number.isFinite(threshold)
      && threshold >= 0 && threshold <= 1,
    `threshold ${scoreName} must be a finite score from 0 to 1`);
    result[scoreName] = threshold;
  }
  return result;
}

function validateProvenance(provenance, sourceBuild, targetBuild, label = 'candidate provenance') {
  invariant(isObject(provenance), `${label} is required`);
  validateExactBuild(provenance.source_build, `${label}.source_build`);
  validateExactBuild(provenance.target_build, `${label}.target_build`);
  invariant(provenance.source_build === sourceBuild && provenance.target_build === targetBuild,
    `${label} source/target build binding mismatch`);
  invariant(typeof provenance.run_id === 'string' && provenance.run_id.length > 0,
    `${label}.run_id is required`);
  const sourceFingerprint = provenance.source_fingerprint_sha256;
  const stableSourceEvidence = typeof sourceFingerprint === 'string' && SHA256_PATTERN.test(sourceFingerprint);
  const regressionBinding = provenance.regression_report_schema === REGRESSION_REPORT_SCHEMA;
  invariant(stableSourceEvidence || regressionBinding,
    `${label} requires source_fingerprint_sha256 or ${REGRESSION_REPORT_SCHEMA} run binding`);
}

function validateExceptionAudit(exceptionAudit) {
  invariant(isObject(exceptionAudit), 'exception_audit is required');
  invariant(typeof exceptionAudit.status === 'string', 'exception_audit.status is required');
  invariant(Array.isArray(exceptionAudit.exceptions), 'exception_audit.exceptions is required');
}

function validateCandidate(candidate, sourceBuild, targetBuild) {
  invariant(isObject(candidate), 'candidate must be an object');
  invariant(typeof candidate.candidate_id === 'string' && candidate.candidate_id.length > 0,
    'candidate_id is required');
  invariant(typeof candidate.exact_build === 'string' && candidate.exact_build.length > 0,
    'candidate exact_build is required');
  validateExactBuild(candidate.exact_build, `candidate ${candidate.candidate_id} exact_build`);
  invariant(candidate.exact_build === targetBuild,
    `candidate ${candidate.candidate_id} does not match target build ${targetBuild}`);
  for (const scoreName of REQUIRED_SCORES) {
    invariant(typeof candidate[scoreName] === 'number'
      && Number.isFinite(candidate[scoreName])
      && candidate[scoreName] >= 0 && candidate[scoreName] <= 1,
    `candidate ${candidate.candidate_id} ${scoreName} must be a finite score from 0 to 1`);
  }
  for (const gateName of REQUIRED_GATES) {
    invariant(typeof candidate[gateName] === 'string',
      `candidate ${candidate.candidate_id} ${gateName} is required`);
  }
  validateExceptionAudit(candidate.exception_audit);
  validateProvenance(candidate.provenance, sourceBuild, targetBuild,
    `candidate ${candidate.candidate_id} provenance`);
}

function scoreEvaluation(candidate, thresholds) {
  const failed = REQUIRED_SCORES.filter((name) => candidate[name] < thresholds[name]);
  return { passed: failed.length === 0, failed, thresholds };
}

function gateEvaluation(candidate) {
  const failed = REQUIRED_GATES.filter((name) => !PASSING_GATES.has(candidate[name]));
  if (!PASSING_GATES.has(candidate.exception_audit.status)) failed.push('exception_audit.status');
  return { passed: failed.length === 0, failed };
}

function semanticChangeIsExplicit(candidate) {
  const evidence = candidate.semantic_change_evidence;
  return isObject(evidence)
    && typeof evidence.kind === 'string' && evidence.kind.length > 0
    && Array.isArray(evidence.evidence_ids) && evidence.evidence_ids.length > 0
    && evidence.evidence_ids.every((id) => typeof id === 'string' && id.length > 0);
}

function automaticStatus(candidate) {
  switch (candidate.migration_class) {
    case 'ROUTE_MOVED': return 'AUTO_VERIFIED_WITH_ROUTE_MOVE';
    case 'FIELD_SHIFT': return 'AUTO_VERIFIED_WITH_FIELD_SHIFT';
    case 'UNCHANGED':
    case 'UNCHANGED_VERIFIED': return 'AUTO_VERIFIED';
    default: return 'REVALIDATED_MACHINE_ONLY';
  }
}

function candidateAssessment(candidate, thresholds) {
  const score = scoreEvaluation(candidate, thresholds);
  const gates = gateEvaluation(candidate);
  const reasons = [
    ...score.failed.map((name) => `BELOW_THRESHOLD:${name}`),
    ...gates.failed.map((name) => `GATE_FAILED:${name}`),
  ];
  if (semanticChangeIsExplicit(candidate)) reasons.push('EXPLICIT_SEMANTIC_CHANGE_EVIDENCE');
  return {
    candidate_id: candidate.candidate_id,
    exact_build: candidate.exact_build,
    score_evaluation: score,
    gate_evaluation: gates,
    eligible: score.passed && gates.passed,
    reasons,
    candidate,
  };
}

function decisionReasons(assessments, status, selected) {
  if (status === 'UNSUPPORTED') return ['CAPABILITY_OR_ORACLE_INPUT_UNAVAILABLE'];
  if (status === 'MANUAL_VALIDATION_REQUIRED') {
    return ['AMBIGUOUS_OR_NO_ELIGIBLE_CANDIDATE'];
  }
  if (selected?.eligible) return ['UNIQUE_CANDIDATE_ALL_SCORES_AND_GATES_PASS'];
  const explicit = assessments.find(({ candidate }) => semanticChangeIsExplicit(candidate));
  if (status === 'SEMANTIC_CHANGED' && explicit) return explicit.reasons;
  return assessments.flatMap((assessment) => assessment.reasons);
}

function createMigrationDecision(input) {
  rejectProtectedHoldout(input);
  invariant(isObject(input), 'oracle input must be an object');
  invariant(typeof input.semantic_name === 'string' && input.semantic_name.length > 0,
    'semantic_name is required');
  validateExactBuild(input.source_build, 'source_build');
  validateExactBuild(input.target_build, 'target_build');
  if (input.exact_build !== undefined) {
    invariant(input.exact_build === input.target_build,
      'exact_build compatibility alias must equal target_build');
  }
  validateProvenance(input.provenance, input.source_build, input.target_build, 'oracle provenance');
  const thresholds = normalizedThresholds(input.thresholds);
  const unavailable = input.availability === 'UNAVAILABLE' || input.status === 'UNSUPPORTED';
  const candidates = input.candidates ?? [];
  invariant(Array.isArray(candidates), 'candidates must be an array');
  for (const candidate of candidates) validateCandidate(candidate, input.source_build, input.target_build);
  const assessments = candidates.map((candidate) => candidateAssessment(candidate, thresholds));
  const eligible = assessments.filter((assessment) => assessment.eligible);
  const explicitSemanticChange = assessments.some(({ candidate }) => semanticChangeIsExplicit(candidate));
  const selected = eligible.length === 1 && !explicitSemanticChange ? eligible[0] : null;
  let status;
  if (unavailable || assessments.length === 0) status = 'UNSUPPORTED';
  else if (explicitSemanticChange) status = 'SEMANTIC_CHANGED';
  else if (eligible.length === 1) status = automaticStatus(selected.candidate);
  else if (eligible.length > 1) status = 'MANUAL_VALIDATION_REQUIRED';
  else status = 'MANUAL_VALIDATION_REQUIRED';
  return {
    schema: DECISION_SCHEMA,
    schema_version: 1,
    oracle_schema: ORACLE_SCHEMA,
    semantic_name: input.semantic_name,
    source_build: input.source_build,
    target_build: input.target_build,
    exact_build: input.target_build,
    status,
    thresholds,
    provenance: input.provenance,
    availability: unavailable ? 'UNAVAILABLE' : 'AVAILABLE',
    candidates: assessments,
    candidate_count: assessments.length,
    eligible_candidate_count: eligible.length,
    selected_candidate_id: selected?.candidate_id ?? null,
    reasons: decisionReasons(assessments, status, selected),
    conservation: {
      input_candidates: candidates.length,
      assessed_candidates: assessments.length,
      preserved_candidates: assessments.length === candidates.length ? 'PASS' : 'FAIL',
      silent_discard: 'FORBIDDEN',
      silent_fallback: 'FORBIDDEN',
    },
  };
}

function migrationClassFromCapabilityRow(row) {
  switch (row.status) {
    case 'UNCHANGED_VERIFIED': return 'UNCHANGED';
    case 'ROUTE_MOVED': return 'ROUTE_MOVED';
    case 'FIELD_SHIFT': return 'FIELD_SHIFT';
    default: return 'REVALIDATED';
  }
}

function decisionInputsFromFullSemanticMigration(capabilityMigration, options = {}) {
  rejectProtectedHoldout({ capabilityMigration, options });
  invariant(isObject(capabilityMigration) && Array.isArray(capabilityMigration.capabilities),
    'full_semantic_migration capability_migration.capabilities is required');
  validateExactBuild(options.source_build, 'source_build');
  validateExactBuild(options.target_build, 'target_build');
  validateProvenance(options.provenance, options.source_build, options.target_build,
    'migration integration provenance');
  const evidenceByCapability = options.evidence_by_capability ?? {};
  invariant(isObject(evidenceByCapability), 'evidence_by_capability must be an object');
  return capabilityMigration.capabilities.map((row) => {
    invariant(isObject(row) && typeof row.capability === 'string' && typeof row.status === 'string',
      'each full_semantic_migration capability row requires capability and status');
    const supplied = evidenceByCapability[row.capability];
    const availability = row.status === 'UNSUPPORTED' ? 'UNAVAILABLE' : 'AVAILABLE';
    const candidates = supplied?.candidates ?? [];
    return {
      semantic_name: row.capability,
      source_build: options.source_build,
      target_build: options.target_build,
      exact_build: options.target_build,
      availability,
      thresholds: supplied?.thresholds ?? options.thresholds,
      candidates: candidates.map((candidate) => ({
        ...candidate,
        exact_build: candidate.exact_build ?? options.target_build,
        migration_class: candidate.migration_class ?? migrationClassFromCapabilityRow(row),
        provenance: {
          ...candidate.provenance,
          full_semantic_migration: {
            status: row.status,
            reasons: row.reasons ?? [],
            previous: row.previous ?? null,
            current: row.current ?? null,
          },
        },
      })),
      provenance: {
        ...options.provenance,
        full_semantic_migration_row: {
          capability: row.capability,
          status: row.status,
          reasons: row.reasons ?? [],
        },
      },
    };
  });
}

function decideFullSemanticMigration(capabilityMigration, options) {
  const inputs = decisionInputsFromFullSemanticMigration(capabilityMigration, options);
  const decisions = inputs.map(createMigrationDecision);
  invariant(decisions.length === capabilityMigration.capabilities.length,
    'full_semantic_migration row conservation failed');
  return {
    schema: ORACLE_SCHEMA,
    schema_version: 1,
    source_build: options.source_build,
    target_build: options.target_build,
    exact_build: options.target_build,
    decisions,
    conservation: {
      input_capability_rows: capabilityMigration.capabilities.length,
      decision_rows: decisions.length,
      preserved_rows: 'PASS',
      silent_discard: 'FORBIDDEN',
    },
  };
}

module.exports = {
  DECISION_SCHEMA,
  DECISION_SCHEMA_DOCUMENT,
  DECISION_STATUSES,
  DEFAULT_THRESHOLDS,
  ORACLE_SCHEMA,
  REQUIRED_GATES,
  REQUIRED_SCORES,
  candidateAssessment,
  createDecisionSchemaDocument,
  createMigrationDecision,
  decideFullSemanticMigration,
  decisionInputsFromFullSemanticMigration,
  hasProtectedHoldoutReference,
  rejectProtectedHoldout,
  validateExactBuild,
  validateCandidate,
  validateProvenance,
};
