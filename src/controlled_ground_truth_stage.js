'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  ExceptionRegistry,
  SemanticFingerprint,
  bootstrapFingerprintFromManifestRecord,
  exceptionRegistrySchemaDocument,
  semanticFingerprintSchemaDocument,
  stableHash,
} = require('./semantic_fingerprint');
const {
  CONTROLLED_REPLAY_REQUEST_SPECS,
  P0_SEMANTICS,
  alignGroundTruthOracle,
  assertNoProtectedReference,
  controlledCalibrationBatchSchemaDocument,
  formatManualGroundTruthTasks,
  generateManualValidationCases,
  groundTruthAlignmentSchemaDocument,
  groundTruthOracleSchemaDocument,
  importControlledCalibrationBatch,
  manualValidationTasksSchemaDocument,
  oracleRecordsFromDetailsP0,
} = require('./controlled_calibration');
const {
  DECISION_STATUSES,
  createDecisionSchemaDocument,
  createMigrationDecision,
} = require('./semantic_migration_oracle');
const { matcherSchemaDocument } = require('./semantic_fingerprint_matcher');
const { regressionIntegrationSchemaDocument } = require('./semantic_regression_oracle');

const STAGE_SCHEMA = 'ROFL_CONTROLLED_GROUND_TRUTH_AND_SEMANTIC_FINGERPRINT_V1';
const STAGE_SCHEMA_VERSION = 1;
const FINGERPRINT_REGISTRY_SCHEMA = 'ROFL_SEMANTIC_FINGERPRINT_REGISTRY_V1';
const CURRENT_BUILD = '16.16.805.0442';
const PREVIOUS_BUILD = '16.15.801.3452';
const DEFAULT_OUTPUT_DIRECTORY = path.join(
  'artifacts',
  'controlled_ground_truth_semantic_fingerprint_v1',
);

// Explicit safe allowlist only. The stage never discovers input directories.
const DEFAULT_INPUT_PATHS = Object.freeze({
  v2_final_report: 'docs/ROFL_FULL_SEMANTIC_DEEP_RECOVERY_V2_REPORT.md',
  capability_manifest: 'artifacts/semantic_coverage_v1/capability_manifest.json',
  semantic_saturation_report: 'artifacts/full_semantic_deep_recovery_v2/semantic_saturation_report.json',
  semantic_research_queue: 'artifacts/full_semantic_deep_recovery_v2/semantic_research_queue.json',
  decision_ledger: 'artifacts/full_semantic_deep_recovery_v2/decision_ledger/decision_ledger.json',
  negative_evidence_registry: 'artifacts/full_semantic_baseline_v1/negative_evidence_registry.json',
  runtime_registration_map: 'artifacts/hero_combat_state_v2/runtime/observed_packet_callback_route_map_16_16.json',
  packet_component_inventory: 'artifacts/hero_combat_state_v2/inventory/latest_four_16_16_packet_inventory.json',
  exact_build_profiles: 'artifacts/multi_build_rofl_support_v1/build_profile_registry.json',
  legacy_semantic_fingerprints: 'artifacts/multi_build_rofl_support_v1/semantic_fingerprints.json',
  full_semantic_migration: 'artifacts/full_semantic_deep_recovery_v2/migration/migration_16_15_to_16_16_deep_semantics.json',
  regression_attestation: 'artifacts/full_semantic_baseline_v1/regression/regression_attestation_16_16.json',
  details_p0_manifest: 'artifacts/hero_combat_state_v2/anchors/details_p0_manifest.json',
  details_p0_ground_truth: 'artifacts/hero_combat_state_v2/anchors/details_p0_ground_truth.jsonl',
  hero_state_damage_defense_report: 'artifacts/full_semantic_deep_recovery_v2/hero_state/hero_state_damage_defense_deep_report_16_16.json',
  hero_respawn_audit: 'artifacts/full_semantic_deep_recovery_v2/hero_respawn/hero_reincarnate_alive_audit_16_16.json',
  semantic_api: 'src/semantic_api.js',
  migration_pipeline: 'src/full_semantic_migration.js',
  controlled_replay_specification: 'src/controlled_calibration.js',
  regression_suite_entrypoint: 'package.json',
});

function invariant(condition, message) {
  if (!condition) throw new Error(`controlled ground-truth stage: ${message}`);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactBuild(value, label) {
  invariant(typeof value === 'string' && /^\d+\.\d+\.\d+\.\d+$/.test(value),
    `${label} must use strict N.N.N.N exact-build form`);
  return value;
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function readJsonl(filePath) {
  const text = fs.readFileSync(filePath, 'utf8').trim();
  if (!text) return [];
  return text.split(/\r?\n/).map((line, index) => {
    try {
      return JSON.parse(line);
    } catch (error) {
      throw new Error(`invalid JSONL at ${filePath}:${index + 1}: ${error.message}`);
    }
  });
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
  return filePath;
}

function writeText(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, value);
  return filePath;
}

function resolveSafeInput(repositoryRoot, suppliedPath, label) {
  invariant(typeof suppliedPath === 'string' && suppliedPath.length > 0, `${label} path is required`);
  assertNoProtectedReference(suppliedPath, label);
  const root = path.resolve(repositoryRoot);
  const resolved = path.resolve(root, suppliedPath);
  invariant(resolved.startsWith(`${root}${path.sep}`), `${label} must remain inside the repository root`);
  invariant(fs.existsSync(resolved) && fs.statSync(resolved).isFile(), `${label} is not a readable file: ${resolved}`);
  return resolved;
}

function resolveSafeInputs(repositoryRoot, overrides = {}) {
  const unknown = Object.keys(overrides).filter((key) => !Object.hasOwn(DEFAULT_INPUT_PATHS, key));
  invariant(unknown.length === 0, `unknown input override(s): ${unknown.join(', ')}`);
  return Object.fromEntries(Object.entries(DEFAULT_INPUT_PATHS).map(([key, relative]) => [
    key,
    resolveSafeInput(repositoryRoot, overrides[key] ?? relative, key),
  ]));
}

function controlledBatch(paths, currentBuild) {
  return importControlledCalibrationBatch({
    files: Object.entries(paths).map(([id, filePath]) => ({
      id,
      kind: id === 'details_p0_ground_truth' ? 'GROUND_TRUTH_JSONL' : 'EXPLICIT_SAFE_ARTIFACT',
      path: filePath,
      exact_build: currentBuild,
      source: { role: id, acquisition: 'PREEXISTING_LOCAL_ARTIFACT' },
      hash: true,
    })),
    objects: [{
      id: 'controlled_replay_request_specification',
      kind: 'CONTROLLED_REPLAY_REQUEST_SPECIFICATION',
      exact_build: currentBuild,
      source: { role: 'FROZEN_MACHINE_READABLE_SPECIFICATION' },
      object: CONTROLLED_REPLAY_REQUEST_SPECS.CALIBRATION_SET_A_HP_DEFENSE_V1,
      hash: true,
    }],
  });
}

function batchEntry(batch, id) {
  const entry = batch.inputs.find((item) => item.id === id);
  invariant(entry && /^[a-f0-9]{64}$/.test(entry.sha256 ?? ''), `missing hashed batch entry ${id}`);
  return entry;
}

function fingerprintProvenance(currentBuild, sourceSha256, replaySetManifestSha256, sourceKind) {
  return {
    exact_build: currentBuild,
    replay_set_manifest_sha256: replaySetManifestSha256,
    source_sha256: sourceSha256,
    source_kind: sourceKind,
  };
}

function evidenceState(status, details = {}) {
  return { status, ...details };
}

function containsExplicitUnknownOrUnavailable(value, seen = new WeakSet()) {
  if (!isObject(value) && !Array.isArray(value)) return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (isObject(value) && ['UNKNOWN', 'UNAVAILABLE'].includes(value.status)) return true;
  return Object.values(value).some((child) => containsExplicitUnknownOrUnavailable(child, seen));
}

function incompleteFingerprintDimensions(structural, behavioral) {
  return [
    ...Object.entries(structural)
      .filter(([, value]) => containsExplicitUnknownOrUnavailable(value))
      .map(([field]) => `structural_fingerprint.${field}`),
    ...Object.entries(behavioral)
      .filter(([, value]) => containsExplicitUnknownOrUnavailable(value))
      .map(([field]) => `behavioral_fingerprint.${field}`),
  ].sort();
}

function legacyFingerprintFor(legacyDocument, build, semanticName) {
  const key = semanticName.toLowerCase();
  return legacyDocument?.builds?.[build]?.[key] ?? null;
}

function structuralFingerprint(record, legacy) {
  const staticIdentity = legacy?.static_identity ?? null;
  const packetShape = legacy?.packet_shape ?? null;
  const fieldNames = Object.keys(record.field_mapping ?? {}).sort();
  const staticFields = Array.isArray(staticIdentity?.fields)
    ? staticIdentity.fields.map((field) => ({ name: field.name, type: field.type })).sort((a, b) => a.name.localeCompare(b.name))
    : [];
  return {
    runtime_type: staticIdentity?.id
      ? evidenceState('VERIFIED_BUILD_STRUCTURAL_IDENTITY', { identity: staticIdentity.id })
      : evidenceState('UNKNOWN'),
    registration: record.packet_registration_route
      ? evidenceState('PRESENT_BUILD_BOUND', { semantic_registration_role: 'REGISTERED_CALLBACK_OR_ROUTE' })
      : evidenceState('UNKNOWN'),
    callback: record.packet_registration_route
      ? evidenceState('PRESENT_BUILD_BOUND') : evidenceState('UNKNOWN'),
    constructor: staticIdentity?.constructor_rva !== undefined
      ? evidenceState('PRESENT_BUILD_BOUND') : evidenceState('UNKNOWN'),
    vtable: staticIdentity && (staticIdentity.vtable_rva !== undefined || staticIdentity.object_vtable_rva !== undefined)
      ? evidenceState('PRESENT_BUILD_BOUND') : evidenceState('UNKNOWN'),
    deserializer: staticIdentity?.deserialize_rva !== undefined || record.decoder_version
      ? evidenceState('PRESENT_BUILD_BOUND') : evidenceState('UNKNOWN'),
    serializer: evidenceState('UNKNOWN'),
    component: evidenceState('UNKNOWN'),
    field_type: staticFields.length
      ? evidenceState('VERIFIED_BUILD_STRUCTURE', { fields: staticFields })
      : fieldNames.length ? evidenceState('PARTIAL_CANONICAL_FIELD_SET', { fields: fieldNames }) : evidenceState('UNKNOWN'),
    field_position: evidenceState('BUILD_BOUND_ONLY'),
    payload_shape: packetShape
      ? evidenceState('VERIFIED_BUILD_STRUCTURE', {
        payload_lengths: (packetShape.payload_length_top ?? []).map((row) => row.value).sort((a, b) => a - b),
      }) : evidenceState('UNKNOWN'),
    surrounding_fields: staticFields.length
      ? evidenceState('VERIFIED_BUILD_STRUCTURE', { fields: staticFields }) : evidenceState('UNKNOWN'),
    entity_relationship: evidenceState('UNKNOWN'),
  };
}

function behavioralFingerprint(record, legacy) {
  const timestampRange = legacy?.packet_shape?.timestamp_range_ms ?? null;
  const participantCoverage = legacy?.participant_coverage ?? null;
  const valueRange = legacy?.coordinate_error
    ? { coordinate_error: legacy.coordinate_error }
    : legacy?.raw_field_10_level_after_mapping
      ? { level_after_mapping_values: Object.values(legacy.raw_field_10_level_after_mapping).sort((a, b) => a - b) }
      : null;
  return {
    value_range: valueRange
      ? evidenceState('VERIFIED_BUILD_OBSERVATION', valueRange) : evidenceState('UNKNOWN'),
    temporal_behavior: timestampRange
      ? evidenceState('VERIFIED_BUILD_OBSERVATION', { timestamp_range_ms: timestampRange })
      : evidenceState('EVIDENCE_SCOPE_ONLY', { scope: record.sample_count?.scope ?? 'UNKNOWN' }),
    update_frequency: evidenceState('OBSERVED_COUNT_ONLY', {
      replay_count: record.sample_count?.replay_count ?? null,
      event_count: record.sample_count?.event_count ?? null,
    }),
    event_correlations: evidenceState('REGISTERED_MACHINE_EVIDENCE', {
      positive_reference_count: record.positive_examples?.length ?? 0,
    }),
    reset_behavior: legacy?.timestamp_zero_initialization_count !== undefined
      ? evidenceState('VERIFIED_BUILD_OBSERVATION', {
        timestamp_zero_initialization_count: legacy.timestamp_zero_initialization_count,
      }) : evidenceState('UNKNOWN'),
    persistence_behavior: participantCoverage?.status === 'PASS'
      ? evidenceState('VERIFIED_BUILD_OBSERVATION', {
        participant_coverage_status: participantCoverage.status,
        ten_participant_replay_count: participantCoverage.ten_participant_replay_count,
      }) : evidenceState('UNKNOWN'),
  };
}

function buildBinding(record, provenance, legacy) {
  return {
    binding_id: `BUILD_BINDING:${record.build}:${record.semantic_capability}`,
    exact_build: record.build,
    provenance,
    binding: {
      protocol_route: record.protocol_route,
      packet_registration_route: record.packet_registration_route,
      decoder_version: record.decoder_version,
      field_mapping: record.field_mapping,
      legacy_static_identity: legacy?.static_identity ?? null,
      legacy_route: legacy?.route ?? null,
      legacy_fingerprint_sha256: legacy?.fingerprint_sha256 ?? null,
    },
  };
}

function buildVerifiedFingerprint(record, context) {
  const {
    capabilityManifestSha256,
    replaySetManifestSha256,
    exceptionRegistry,
    legacyDocument,
  } = context;
  const provenance = fingerprintProvenance(
    record.build,
    capabilityManifestSha256,
    replaySetManifestSha256,
    'CAPABILITY_MANIFEST_PLUS_EXPLICIT_EXACT_BUILD_REPLAY_SET',
  );
  const legacy = legacyFingerprintFor(legacyDocument, record.build, record.semantic_capability);
  const knownExceptions = record.semantic_capability === 'HERO_RESPAWN'
    ? ['HERO_RESPAWN_YONE_REINCARNATE_SCALAR_V1'] : [];
  const structural = structuralFingerprint(record, legacy);
  const behavioral = behavioralFingerprint(record, legacy);
  const incompleteDimensions = incompleteFingerprintDimensions(structural, behavioral);
  const promotionEligible = incompleteDimensions.length === 0;
  const invariants = [{
    invariant_id: `${record.semantic_capability}:EXACT_BUILD_BINDING_REQUIRED`,
    expression: 'candidate exact build must equal the selected build binding exact build',
    mode: 'STRICT',
    rationale: 'Nearest-build decoder fallback is forbidden.',
    exception_references: [],
  }];
  if (knownExceptions.length) invariants.push({
    invariant_id: 'HERO_RESPAWN:REINCARNATE_SCALAR_NOT_UNIVERSAL_RESOURCE',
    expression: 'reincarnate scalar must not be treated as a universal current/max resource field',
    mode: 'CHAMPION_EXCEPTION',
    rationale: 'The Yone counterexample invalidates a universal resource interpretation without invalidating respawn occurrence.',
    exception_references: knownExceptions,
  });
  const fingerprint = {
    schema: 'ROFL_SEMANTIC_FINGERPRINT_V1',
    schema_version: 1,
    semantic_name: record.semantic_capability,
    canonical_schema_version: record.canonical_schema_version,
    availability: 'VERIFIED',
    promotion_eligible: promotionEligible,
    provenance,
    structural_fingerprint: structural,
    behavioral_fingerprint: behavioral,
    cross_field_invariants: invariants,
    ground_truth_oracles: [{
      reference_id: `MACHINE_ORACLE:${record.build}:${record.semantic_capability}`,
      case_id: `CAPABILITY_MANIFEST:${record.build}:${record.semantic_capability}`,
      oracle_kind: 'EXISTING_EXACT_BUILD_MACHINE_VALIDATION',
      provenance,
    }],
    negative_controls: [{
      reference_id: `NEGATIVE_CONTROL:${record.build}:${record.semantic_capability}`,
      control_kind: 'REGISTERED_NEGATIVE_EVIDENCE_AND_KNOWN_LIMITS',
      rejection_reason: 'Lookalikes and unsupported interpretations registered by the source capability record must remain rejected.',
      provenance,
    }],
    known_exceptions: knownExceptions,
    exact_builds_verified: [{
      exact_build: record.build,
      binding_id: `BUILD_BINDING:${record.build}:${record.semantic_capability}`,
      provenance,
    }],
    build_bindings: [buildBinding(record, provenance, legacy)],
    migration_policy: promotionEligible && record.validation_status === 'PASS'
      ? 'AUTO_IF_UNIQUE' : 'REVALIDATE_IF_AMBIGUOUS',
    ...(promotionEligible ? {} : {
      completeness: {
        status: 'INCOMPLETE',
        incomplete_dimensions: incompleteDimensions,
        blocking_policy: 'REVALIDATE_IF_AMBIGUOUS',
        rationale: 'The semantic is verified for this build, but required fingerprint dimensions remain explicitly unknown and cannot authorize automatic migration.',
      },
    }),
    fingerprint_completeness: {
      status: promotionEligible
        ? 'COMPLETE_FOR_AUTOMATIC_MIGRATION'
        : legacy ? 'LEGACY_MACHINE_FINGERPRINT_ENRICHED_BUT_INCOMPLETE' : 'CAPABILITY_MANIFEST_BOOTSTRAP_PARTIAL',
      complete_for_automatic_migration: promotionEligible,
      incomplete_dimension_count: incompleteDimensions.length,
      unknown_dimensions_award_migration_credit: false,
      positive_reference_count: record.positive_examples?.length ?? 0,
      negative_reference_count: record.negative_examples?.length ?? 0,
      known_limit_count: record.known_limits?.length ?? 0,
    },
  };
  const value = new SemanticFingerprint(fingerprint, { exceptionRegistry });
  return { fingerprint: value.toJSON(), fingerprint_sha256: value.hash };
}

function buildFingerprintRegistry(manifest, currentBuild, context) {
  const profile = manifest.build_profiles?.[currentBuild];
  invariant(profile && Array.isArray(profile.records), `capability manifest lacks exact build ${currentBuild}`);
  invariant(profile.records.length === manifest.capability_vocabulary.length,
    'capability manifest current-build row conservation failed');
  const records = profile.records.map((record) => {
    const verified = ['VERIFIED_DIRECT', 'VERIFIED_DERIVED'].includes(record.evidence_grade)
      && ['PASS', 'PARTIAL'].includes(record.validation_status);
    if (verified) return buildVerifiedFingerprint(record, context);
    const fingerprint = bootstrapFingerprintFromManifestRecord(record, {
      manifest_sha256: context.capabilityManifestSha256,
    });
    return { fingerprint, fingerprint_sha256: stableHash(fingerprint) };
  });
  const counts = Object.fromEntries(['VERIFIED', 'UNKNOWN', 'UNAVAILABLE'].map((availability) => [
    availability,
    records.filter((row) => row.fingerprint.availability === availability).length,
  ]));
  invariant(Object.values(counts).reduce((sum, value) => sum + value, 0) === profile.records.length,
    'fingerprint registry row conservation failed');
  const promotionEligibleCount = records.filter((row) => row.fingerprint.promotion_eligible === true).length;
  const incompleteVerifiedCount = records.filter((row) => row.fingerprint.availability === 'VERIFIED'
    && row.fingerprint.promotion_eligible === false).length;
  return {
    schema: FINGERPRINT_REGISTRY_SCHEMA,
    schema_version: 1,
    exact_build: currentBuild,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    source_capability_manifest_sha256: context.capabilityManifestSha256,
    replay_set_manifest_sha256: context.replaySetManifestSha256,
    capability_count: manifest.capability_vocabulary.length,
    record_count: records.length,
    availability_counts: counts,
    promotion_eligible_count: promotionEligibleCount,
    verified_incomplete_revalidation_count: incompleteVerifiedCount,
    non_promotion_eligible_count: records.length - promotionEligibleCount,
    records,
  };
}

function buildExceptionRegistry(currentBuild, replaySetManifestSha256, respawnAuditSha256) {
  return new ExceptionRegistry([{
    exception_id: 'HERO_RESPAWN_YONE_REINCARNATE_SCALAR_V1',
    scope: 'CHAMPION',
    semantic_name: 'HERO_RESPAWN',
    exact_builds: [currentBuild],
    champion: 'Yone',
    field: 'reincarnate_scalar',
    exception: 'The scalar is not a universal current/max/seed resource and must retain a neutral protocol name.',
    rationale: 'A champion-specific counterexample rejects the universal resource interpretation without invalidating the direct respawn occurrence.',
    provenance: fingerprintProvenance(
      currentBuild,
      respawnAuditSha256,
      replaySetManifestSha256,
      'HERO_REINCARNATE_ALIVE_EXACT_BUILD_AUDIT',
    ),
  }]);
}

function machineCalibrationCases(detailsManifest) {
  const cases = detailsManifest.replays.map((replay) => {
    const validation = replay.key_sample_validation;
    invariant(validation?.status === 'VALIDATED', `missing validated key sample for ${replay.game_id}`);
    const frames = validation.frame_p0;
    invariant(Array.isArray(frames) && frames.length >= 2, `key sample ${replay.game_id} requires at least two frames`);
    const before = frames[0];
    const after = frames[frames.length - 1];
    return {
      case_id: `MACHINE_CALIBRATION:${replay.game_id}:${validation.role}`,
      exact_build: replay.replay_build,
      replay_sha256: replay.replay.sha256,
      game_id: replay.game_id,
      participant_id: validation.participant_id,
      champion: validation.champion,
      role: validation.role,
      event: validation.event,
      frame_anchor_ids: validation.frame_anchor_ids,
      before: frames[0],
      after: frames[frames.length - 1],
      observed_step: {
        current_hp_delta: after.current_hp - before.current_hp,
        max_hp_delta: after.max_hp - before.max_hp,
        armor_delta: after.armor - before.armor,
        magic_resist_delta: after.magic_resist - before.magic_resist,
      },
      frame_count: frames.length,
      causal_authority: 'BOUNDED_GROUND_TRUTH_CASE_ONLY_NOT_PROTOCOL_FIELD_PROOF',
      promotion_authority: 'NONE',
    };
  }).sort((a, b) => a.case_id.localeCompare(b.case_id));
  return {
    schema: 'ROFL_MACHINE_CALIBRATION_CASES_V1',
    schema_version: 1,
    exact_build: detailsManifest.target.replay_header_build,
    case_count: cases.length,
    cases,
  };
}

function p0AlignmentBaseline(groundTruthOracle) {
  const rows = P0_SEMANTICS.map((semantic) => {
    const subset = {
      ...groundTruthOracle,
      records: groundTruthOracle.records.filter((row) => row.semantic === semantic),
    };
    const aligned = alignGroundTruthOracle(subset, [], { timestamp_tolerance_ms: 0 });
    return {
      semantic,
      oracle_record_count: subset.records.length,
      supplied_candidate_row_count: 0,
      alignment_counts: aligned.counts,
      status: 'NO_DECODER_CANDIDATE_ROWS_AVAILABLE',
      automatic_promotion: 'FORBIDDEN',
    };
  });
  const total = rows.reduce((sum, row) => sum + row.oracle_record_count, 0);
  invariant(total === groundTruthOracle.records.length, 'P0 alignment row conservation failed');
  return {
    schema: 'ROFL_P0_GROUND_TRUTH_ALIGNMENT_BASELINE_V1',
    schema_version: 1,
    exact_build: CURRENT_BUILD,
    oracle_record_count: total,
    matched_candidate_count: 0,
    unmatched_oracle_count: total,
    promotion_count: 0,
    rows,
    conclusion: 'GROUND_TRUTH_EXISTS_BUT_NO_PROTOCOL_FIELD_CANDIDATE_IS_AVAILABLE',
  };
}

function migrationContractTest() {
  const provenance = {
    source_build: PREVIOUS_BUILD,
    target_build: CURRENT_BUILD,
    run_id: 'MIGRATION_ORACLE_CONTRACT_TEST_V1',
    source_fingerprint_sha256: stableHash({
      schema: 'SYNTHETIC_MIGRATION_CONTRACT_SOURCE_V1',
      source_build: PREVIOUS_BUILD,
      target_build: CURRENT_BUILD,
    }),
    synthetic_contract_test: true,
  };
  const baseCandidate = (id, migrationClass = 'UNCHANGED') => ({
    candidate_id: id,
    exact_build: CURRENT_BUILD,
    structural_match_score: 1,
    behavioral_match_score: 1,
    cross_field_match_score: 1,
    ground_truth_oracle_score: 1,
    invariant_gate: 'PASS',
    regression_gate: 'PASS',
    negative_control_gate: 'PASS',
    exception_audit: { status: 'PASS', exceptions: [] },
    provenance,
    migration_class: migrationClass,
  });
  const decide = (suffix, candidates, extra = {}) => createMigrationDecision({
    semantic_name: `CONTRACT_PROBE_${suffix}`,
    source_build: PREVIOUS_BUILD,
    target_build: CURRENT_BUILD,
    provenance,
    candidates,
    ...extra,
  });
  const decisions = [
    decide('AUTO', [baseCandidate('unchanged')]),
    decide('ROUTE', [baseCandidate('route', 'ROUTE_MOVED')]),
    decide('FIELD', [baseCandidate('field', 'FIELD_SHIFT')]),
    decide('MACHINE', [baseCandidate('machine', 'REVALIDATED')]),
    decide('MANUAL', [baseCandidate('manual-a'), baseCandidate('manual-b')]),
    decide('CHANGED', [{
      ...baseCandidate('changed'),
      behavioral_match_score: 0,
      semantic_change_evidence: { kind: 'CONTRACT_TEST_CHANGE', evidence_ids: ['synthetic-change'] },
    }]),
    decide('UNSUPPORTED', [], { availability: 'UNAVAILABLE' }),
  ];
  const observed = decisions.map((decision) => decision.status).sort();
  const expected = [...DECISION_STATUSES].sort();
  invariant(JSON.stringify(observed) === JSON.stringify(expected),
    `migration decision status coverage failed: ${observed.join(', ')}`);
  return {
    schema: 'ROFL_SEMANTIC_MIGRATION_ORACLE_CONTRACT_TEST_V1',
    schema_version: 1,
    synthetic_contract_test: true,
    semantic_evidence: false,
    source_build: PREVIOUS_BUILD,
    target_build: CURRENT_BUILD,
    status_coverage: DECISION_STATUSES,
    decisions,
    result: 'PASS',
  };
}

function migrationReadiness(manifest, migrationArtifact, fingerprintRegistry) {
  const registeredBuilds = Object.keys(manifest.build_profiles).sort();
  const unexpectedBuilds = registeredBuilds.filter((build) => ![PREVIOUS_BUILD, CURRENT_BUILD].includes(build));
  const rows = migrationArtifact.capability_migration?.capabilities ?? [];
  invariant(rows.length === manifest.capability_vocabulary.length,
    'historical full semantic migration did not traverse all public capabilities');
  const historicalCounts = migrationArtifact.capability_migration.status_counts;
  invariant(Object.values(historicalCounts).reduce((sum, value) => sum + value, 0) === rows.length,
    'historical migration status conservation failed');
  return {
    schema: 'ROFL_NEXT_BUILD_SEMANTIC_MIGRATION_READINESS_V1',
    schema_version: 1,
    current_build: CURRENT_BUILD,
    registered_exact_builds: registeredBuilds,
    new_build_detected: unexpectedBuilds.length > 0,
    detected_new_builds: unexpectedBuilds,
    automatic_new_build_decision_status: unexpectedBuilds.length
      ? 'NEW_BUILD_REQUIRES_EXPLICIT_EXACT_BUILD_EVIDENCE_PIPELINE'
      : 'NOT_RUN_NO_NEW_EXACT_BUILD_REGISTERED_OR_SUPPLIED',
    all_public_capabilities_traversed: true,
    public_capability_count: rows.length,
    fingerprint_record_count: fingerprintRegistry.record_count,
    historical_migration: {
      source_build: migrationArtifact.previous_build,
      target_build: migrationArtifact.current_build,
      status_counts: historicalCounts,
      retrospective_fingerprint_scores_available: false,
      automatic_reclassification_without_scores: 'FORBIDDEN',
    },
    future_required_diffs: [
      'NEW_PACKET', 'NEW_COMPONENT', 'NEW_RUNTIME_TYPE', 'NEW_CALLBACK', 'NEW_ENTITY_FAMILY',
    ],
    policy: {
      auto_first: true,
      manual_last: true,
      passing_capability_manual_revalidation: 'FORBIDDEN',
      nearest_build_fallback: 'FORBIDDEN',
    },
  };
}

function capabilityStatus(manifest, semantic) {
  const row = manifest.build_profiles[CURRENT_BUILD].records
    .find((record) => record.semantic_capability === semantic);
  invariant(row, `missing current-build capability ${semantic}`);
  return {
    evidence_grade: row.evidence_grade,
    validation_status: row.validation_status,
    protocol_route: row.protocol_route,
    known_limits: row.known_limits,
  };
}

function deepCapabilityDecision(heroStateReport, semantic) {
  const decision = heroStateReport.capability_decisions
    .find((row) => row.capability === semantic);
  invariant(decision, `deep recovery report lacks capability decision ${semantic}`);
  return decision;
}

function sourceEvidenceSummary(documents) {
  return {
    v2_final_report_loaded: true,
    decision_ledger: {
      exact_build: documents.decisionLedger.exact_build,
      ...documents.decisionLedger.summary,
    },
    negative_evidence_registry: {
      exact_build: documents.negativeEvidenceRegistry.exact_build,
      route_negative_control_count: documents.negativeEvidenceRegistry.route_negative_control_count,
    },
    exact_build_profiles: Object.keys(documents.exactBuildProfiles).sort(),
    regression_suite_entrypoint: documents.packageManifest.scripts.test,
    controlled_replay_specification_loaded: true,
    migration_pipeline_artifact_loaded: true,
  };
}

function stageReport(context) {
  const {
    manifest,
    saturation,
    fingerprintRegistry,
    groundTruthOracle,
    machineCases,
    manualTasks,
    p0Alignment,
    exceptionRegistry,
    migrationReadinessDocument,
    migrationContract,
    regressionAttestation,
    heroStateReport,
    evidenceSummary,
  } = context;
  const p0AvailabilityKey = {
    CURRENT_HP: 'current_hp',
    MAX_HP: 'max_hp',
    ARMOR: 'armor',
    MAGIC_RESIST: 'magic_resist',
  };
  const p0Status = (semantic) => {
    const decision = deepCapabilityDecision(heroStateReport, semantic);
    return {
      ...capabilityStatus(manifest, semantic),
      deep_recovery_availability: heroStateReport.semantic_availability[p0AvailabilityKey[semantic]],
      deep_recovery_decision: decision.decision,
      decision_scope: decision.decision_scope,
      evidence_exhausted: decision.evidence_exhausted,
      next_required_evidence: decision.next_required_evidence,
      ground_truth_oracle_records: groundTruthOracle.records.filter((row) => row.semantic === semantic).length,
      protocol_candidate_alignment: p0Alignment.rows.find((row) => row.semantic === semantic).status,
      promotion: 'NOT_PROMOTED',
    };
  };
  return {
    schema: STAGE_SCHEMA,
    schema_version: STAGE_SCHEMA_VERSION,
    A_STATUS: {
      status: 'EXTERNAL_INPUT_REQUIRED',
      infrastructure_success: true,
      p0_semantic_breakthrough: false,
      reason: 'All local actionable hypotheses remain exhausted; machine ground truth exists but no unique protocol-field candidate exists.',
    },
    B_CURRENT_BUILD: { exact_build: CURRENT_BUILD, saturation_status: saturation.status },
    C_CALIBRATION_INFRASTRUCTURE: {
      implemented: [
        'SemanticFingerprint', 'GroundTruthOracle', 'MigrationOracle',
        'ManualValidationCaseGenerator', 'ControlledCalibrationImporter', 'ExceptionRegistry',
        'AutomatedMigrationDecision', 'RegressionIntegration',
      ],
      machine_calibration_case_count: machineCases.case_count,
      source_evidence: evidenceSummary,
    },
    D_SEMANTIC_FINGERPRINT_SYSTEM: {
      capability_count: fingerprintRegistry.capability_count,
      fingerprint_count: fingerprintRegistry.record_count,
      availability_counts: fingerprintRegistry.availability_counts,
      promotion_eligible_count: fingerprintRegistry.promotion_eligible_count,
      verified_incomplete_revalidation_count: fingerprintRegistry.verified_incomplete_revalidation_count,
      non_promotion_eligible_count: fingerprintRegistry.non_promotion_eligible_count,
      build_binding_separate_from_semantic_truth: true,
    },
    E_GROUND_TRUTH_ORACLE: {
      record_count: groundTruthOracle.records.length,
      source_anchor_count: groundTruthOracle.records.length / P0_SEMANTICS.length,
      machine_generated: true,
      route_or_offset_in_truth: false,
    },
    F_MIGRATION_ORACLE: {
      statuses: DECISION_STATUSES,
      deterministic_contract_test: migrationContract.result,
      all_capabilities_required: true,
    },
    G_CURRENT_HP: p0Status('CURRENT_HP'),
    H_MAX_HP: p0Status('MAX_HP'),
    I_ARMOR: p0Status('ARMOR'),
    J_MAGIC_RESIST: p0Status('MAGIC_RESIST'),
    K_OTHER_HERO_STATE: {
      current_mana: capabilityStatus(manifest, 'CURRENT_MANA'),
      max_mana: capabilityStatus(manifest, 'MAX_MANA'),
      attack_damage: capabilityStatus(manifest, 'ATTACK_DAMAGE'),
      ability_power: capabilityStatus(manifest, 'ABILITY_POWER'),
      attack_speed: capabilityStatus(manifest, 'ATTACK_SPEED'),
      move_speed: capabilityStatus(manifest, 'MOVE_SPEED'),
      current_resource_deep_recovery: deepCapabilityDecision(heroStateReport, 'CURRENT_RESOURCE'),
      temporary_adjustments_next_evidence: heroStateReport.next_evidence_required.temporary_adjustments,
    },
    L_DAMAGE_STAGE: {
      ...capabilityStatus(manifest, 'DAMAGE_STAGE'),
      decoded_row_count: heroStateReport.damage_stage.decoded_row_count,
      matched_anchor_count: heroStateReport.damage_stage.matched_anchor_count,
      damage_type_match_counts: heroStateReport.damage_stage.damage_type_match_counts,
      damage_type_mismatch_count: heroStateReport.damage_stage.damage_type_mismatch_count,
      recorded_component_residual: heroStateReport.damage_stage.recorded_component_residual,
      amount_semantic_stage: heroStateReport.damage_stage.amount_semantic_stage,
      promotion_recommended: heroStateReport.damage_stage.promotion_recommended,
      next_required_evidence: heroStateReport.next_evidence_required.damage_stage,
    },
    M_DAMAGE_MITIGATION: {
      ...capabilityStatus(manifest, 'DAMAGE_MITIGATION'),
      effective_hp_loss_residual: heroStateReport.damage_stage.effective_hp_loss_residual,
      pre_mitigation_residual: heroStateReport.damage_stage.pre_mitigation_residual,
      post_mitigation_stage_test: heroStateReport.damage_stage.post_mitigation_stage_test,
      promotion: 'NOT_PROMOTED',
      next_required_evidence: heroStateReport.next_evidence_required.damage_stage,
    },
    N_SHIELD: {
      generated: capabilityStatus(manifest, 'SHIELD_GENERATED'),
      absorbed: capabilityStatus(manifest, 'SHIELD_ABSORBED'),
      remaining: capabilityStatus(manifest, 'SHIELD_REMAINING'),
    },
    O_HEAL: {
      reported: capabilityStatus(manifest, 'HEAL_REPORTED'),
      effective: capabilityStatus(manifest, 'HEAL_EFFECTIVE'),
      overheal: capabilityStatus(manifest, 'OVERHEAL'),
    },
    P_SPELL_MISSILE: {
      cast_spell: capabilityStatus(manifest, 'CAST_SPELL'),
      missile: capabilityStatus(manifest, 'MISSILE'),
      timestamp_proximity_causality: 'FORBIDDEN',
    },
    Q_ENTITY_CALIBRATION: {
      npc_classification: capabilityStatus(manifest, 'NPC_CLASSIFICATION'),
      generic_taxonomy_truth_available: false,
    },
    R_ITEM_CALIBRATION: {
      buy: capabilityStatus(manifest, 'ITEM_BUY'),
      sell: capabilityStatus(manifest, 'ITEM_SELL'),
      undo: capabilityStatus(manifest, 'ITEM_UNDO'),
      transform: capabilityStatus(manifest, 'ITEM_TRANSFORM'),
      state: capabilityStatus(manifest, 'ITEM_STATE'),
    },
    S_VISION_CALIBRATION: {
      ward_spawn: capabilityStatus(manifest, 'WARD_SPAWN'),
      sweeper: capabilityStatus(manifest, 'SWEEPER'),
    },
    T_EXCEPTION_REGISTRY: {
      entry_count: exceptionRegistry.toJSON().entries.length,
      champion_exception_count: exceptionRegistry.toJSON().entries.filter((row) => row.scope === 'CHAMPION').length,
      mechanic_exception_count: exceptionRegistry.toJSON().entries.filter((row) => row.scope === 'MECHANIC').length,
    },
    U_AUTOMATIC_MIGRATION_TEST: {
      contract_test: migrationContract.result,
      status_coverage: migrationContract.status_coverage,
      real_new_build_run: migrationReadinessDocument.automatic_new_build_decision_status,
    },
    V_MANUAL_VALIDATION_REQUIRED: {
      current_task_count: manualTasks.task_count,
      status: 'NOT_YET_ACTIONABLE_WITHOUT_A_CONTROLLED_REPLAY',
      policy: manualTasks.manual_validation_default,
    },
    W_NEW_REPLAY_REQUIRED: {
      NEED_CALIBRATION_REPLAY: 'YES',
      priority: 'HP_ARMOR_MR',
      recommended_count: 1,
      maximum_count_only_if_first_replay_remains_ambiguous: 3,
      request_id: 'CALIBRATION_SET_A_HP_DEFENSE_V1',
      preferred_exact_build: CURRENT_BUILD,
      if_preferred_build_is_unavailable: 'SUPPLY_ONE_REPLAY_FROM_THE_CURRENT_RUNNABLE_EXACT_BUILD_AND_RUN_NEW_BUILD_MIGRATION_FIRST',
      nearest_build_fallback: 'FORBIDDEN',
    },
    X_REGRESSION: {
      prior_attestation_status: regressionAttestation.status,
      prior_test_count: regressionAttestation.test_count,
      new_oracle_record_count: groundTruthOracle.records.length,
      p0_candidate_match_count: p0Alignment.matched_candidate_count,
      no_false_promotion: p0Alignment.promotion_count === 0,
    },
    Y_NEXT_BUILD_READINESS: migrationReadinessDocument,
    Z_HARD_BLOCKER: {
      blocker: 'NO_INDEPENDENT_HIGH_DENSITY_CONTROLLED_REPLAY_WITH_ONE_VARIABLE_STEPS',
      local_actionable_route_count: saturation.queue_summary.actionable_route_count,
      local_actionable_capability_count: saturation.queue_summary.actionable_capability_count,
      persistent_state_promotion_decision: heroStateReport.promotion_decision.persistent_hero_state,
      damage_stage_promotion_decision: heroStateReport.promotion_decision.damage_amount_stage,
      exhausted_search_space: heroStateReport.exhausted_search_space,
      next_evidence_required: heroStateReport.next_evidence_required,
      all_independent_local_work_complete: true,
    },
  };
}

function schemaDocuments() {
  return {
    semantic_fingerprint: semanticFingerprintSchemaDocument(),
    exception_registry: exceptionRegistrySchemaDocument(),
    ground_truth_oracle: groundTruthOracleSchemaDocument(),
    controlled_calibration_batch: controlledCalibrationBatchSchemaDocument(),
    ground_truth_alignment: groundTruthAlignmentSchemaDocument(),
    manual_validation_tasks: manualValidationTasksSchemaDocument(),
    semantic_fingerprint_matcher: matcherSchemaDocument(),
    semantic_migration_decision: createDecisionSchemaDocument(),
    semantic_regression_integration: regressionIntegrationSchemaDocument(),
  };
}

function validateSourceState(documents, paths, batch) {
  const {
    manifest,
    saturation,
    queue,
    detailsManifest,
    detailsAnchors,
    runtimeRegistrationMap,
    packetInventory,
    regressionAttestation,
    migrationArtifact,
    heroStateReport,
    decisionLedger,
    negativeEvidenceRegistry,
    exactBuildProfiles,
    packageManifest,
    v2FinalReport,
  } = documents;
  exactBuild(CURRENT_BUILD, 'CURRENT_BUILD');
  invariant(manifest.exact_build_only === true && manifest.nearest_build_fallback === 'FORBIDDEN',
    'capability manifest must be exact-build only');
  invariant(manifest.build_profiles?.[CURRENT_BUILD], `capability manifest lacks ${CURRENT_BUILD}`);
  invariant(saturation.exact_build === CURRENT_BUILD && saturation.status === 'SEMANTIC_RECOVERY_SATURATED',
    'semantic saturation source does not match the current saturated exact build');
  invariant(saturation.queue_summary?.actionable_route_count === 0
    && saturation.queue_summary?.actionable_capability_count === 0,
  'local actionable queue is not exhausted');
  invariant(queue.exact_build === CURRENT_BUILD && queue.exact_build_only === true,
    'semantic research queue is not current-build exact scoped');
  invariant(detailsManifest.target?.replay_header_build === CURRENT_BUILD,
    'DETAILS P0 manifest build mismatch');
  invariant(detailsAnchors.length === detailsManifest.record_count,
    'DETAILS P0 record count does not match manifest');
  invariant(sha256File(paths.details_p0_ground_truth) === detailsManifest.jsonl.sha256,
    'DETAILS P0 JSONL SHA-256 does not match manifest');
  invariant(batchEntry(batch, 'details_p0_ground_truth').sha256 === detailsManifest.jsonl.sha256,
    'controlled importer hash does not match DETAILS P0 manifest');
  invariant(runtimeRegistrationMap.build === CURRENT_BUILD,
    'runtime registration map build mismatch');
  invariant(packetInventory.builds?.length === 1
    && packetInventory.builds[0].game_version === CURRENT_BUILD,
  'packet/component inventory must contain only the current exact build');
  invariant(regressionAttestation.exact_build === CURRENT_BUILD && regressionAttestation.status === 'PASS',
    'regression attestation is not a current-build PASS');
  invariant(migrationArtifact.previous_build === PREVIOUS_BUILD
    && migrationArtifact.current_build === CURRENT_BUILD,
  'historical migration source/target build mismatch');
  invariant(heroStateReport.exact_build === CURRENT_BUILD
    && heroStateReport.status === 'SATURATED_NO_PERSISTENT_STATE_PROMOTION',
  'hero-state damage/defense report is not the saturated current-build source');
  invariant(P0_SEMANTICS.every((semantic) => heroStateReport.capability_decisions
    .some((row) => row.capability === semantic && row.decision === 'REJECT'
      && row.evidence_exhausted === true)),
  'hero-state report does not conserve all exhausted P0 rejection decisions');
  const heroStateLedgerSource = decisionLedger.input_sources
    .find((source) => source.source_id === 'hero_state_damage_defense');
  invariant(decisionLedger.exact_build === CURRENT_BUILD && decisionLedger.exact_build_only === true,
    'decision ledger is not current-build exact scoped');
  invariant(heroStateLedgerSource?.sha256 === batchEntry(batch, 'hero_state_damage_defense_report').sha256,
    'hero-state report hash does not match the decision-ledger provenance');
  invariant(negativeEvidenceRegistry.exact_build === CURRENT_BUILD
    && negativeEvidenceRegistry.route_negative_control_count === negativeEvidenceRegistry.route_negative_controls.length,
  'negative-evidence registry is not conserved for the current build');
  invariant(queue.negative_evidence_loaded === true
    && queue.source_provenance?.negative_evidence_registry?.sha256
      === batchEntry(batch, 'negative_evidence_registry').sha256,
  'semantic research queue does not conserve the loaded negative-evidence registry');
  invariant(exactBuildProfiles[CURRENT_BUILD]?.game_version === CURRENT_BUILD
    && exactBuildProfiles[PREVIOUS_BUILD]?.game_version === PREVIOUS_BUILD,
  'exact-build profile registry lacks a strict current/previous build profile pair');
  invariant(typeof packageManifest.scripts?.test === 'string'
    && typeof packageManifest.scripts?.['test:semantic-fingerprint-oracle'] === 'string',
  'regression suite entrypoint lacks the full or focused semantic-oracle suite');
  invariant(v2FinalReport.includes(CURRENT_BUILD) && v2FinalReport.includes('SEMANTIC_RECOVERY_SATURATED'),
    'V2 final report does not identify the current saturated exact build');
}

function writeArtifactManifest(outputDirectory, writtenFiles, inputBatch) {
  const files = writtenFiles.map((filePath) => ({
    path: path.relative(outputDirectory, filePath).replaceAll('\\', '/'),
    sha256: sha256File(filePath),
    byte_size: fs.statSync(filePath).size,
  })).sort((a, b) => a.path.localeCompare(b.path));
  return writeJson(path.join(outputDirectory, 'artifact_manifest.json'), {
    schema: 'ROFL_CONTROLLED_GROUND_TRUTH_ARTIFACT_MANIFEST_V1',
    schema_version: 1,
    exact_build: CURRENT_BUILD,
    generated_at_omitted_for_reproducibility: true,
    input_count: inputBatch.inputs.length,
    output_count: files.length,
    outputs: files,
    protected_boundary: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  });
}

function buildControlledGroundTruthStage(options = {}) {
  const repositoryRoot = path.resolve(options.repository_root ?? path.resolve(__dirname, '..'));
  const currentBuild = exactBuild(options.current_build ?? CURRENT_BUILD, 'current_build');
  invariant(currentBuild === CURRENT_BUILD,
    `this stage is pinned to ${CURRENT_BUILD}; received ${currentBuild}`);
  const outputDirectory = path.resolve(repositoryRoot, options.output_directory ?? DEFAULT_OUTPUT_DIRECTORY);
  assertNoProtectedReference(outputDirectory, 'output_directory');
  const paths = resolveSafeInputs(repositoryRoot, options.input_paths ?? {});
  const batch = controlledBatch(paths, currentBuild);
  const documents = {
    v2FinalReport: fs.readFileSync(paths.v2_final_report, 'utf8'),
    manifest: readJson(paths.capability_manifest),
    saturation: readJson(paths.semantic_saturation_report),
    queue: readJson(paths.semantic_research_queue),
    decisionLedger: readJson(paths.decision_ledger),
    negativeEvidenceRegistry: readJson(paths.negative_evidence_registry),
    detailsManifest: readJson(paths.details_p0_manifest),
    detailsAnchors: readJsonl(paths.details_p0_ground_truth),
    heroStateReport: readJson(paths.hero_state_damage_defense_report),
    runtimeRegistrationMap: readJson(paths.runtime_registration_map),
    packetInventory: readJson(paths.packet_component_inventory),
    exactBuildProfiles: readJson(paths.exact_build_profiles),
    regressionAttestation: readJson(paths.regression_attestation),
    migrationArtifact: readJson(paths.full_semantic_migration),
    legacyFingerprints: readJson(paths.legacy_semantic_fingerprints),
    packageManifest: readJson(paths.regression_suite_entrypoint),
  };
  validateSourceState(documents, paths, batch);

  const replaySetManifestSha256 = batchEntry(batch, 'details_p0_manifest').sha256;
  const capabilityManifestSha256 = batchEntry(batch, 'capability_manifest').sha256;
  const exceptionRegistry = buildExceptionRegistry(
    currentBuild,
    replaySetManifestSha256,
    batchEntry(batch, 'hero_respawn_audit').sha256,
  );
  const groundTruthOracle = oracleRecordsFromDetailsP0(documents.detailsAnchors);
  invariant(groundTruthOracle.records.length === documents.detailsAnchors.length * P0_SEMANTICS.length,
    'ground-truth oracle conversion row conservation failed');
  const fingerprintRegistry = buildFingerprintRegistry(documents.manifest, currentBuild, {
    capabilityManifestSha256,
    replaySetManifestSha256,
    exceptionRegistry,
    legacyDocument: documents.legacyFingerprints,
  });
  const machineCases = machineCalibrationCases(documents.detailsManifest);
  const manualTasks = {
    ...generateManualValidationCases([], { max_cases: 20 }),
    generation_basis: 'LOCAL_ACTIONABLE_HYPOTHESES_ZERO_AND_NO_UNIQUE_PROTOCOL_FIELD_CANDIDATE',
    next_generation_trigger: 'CONTROLLED_REPLAY_IMPORTED_AND_AUTOMATIC_MATCHING_REMAINS_AMBIGUOUS',
  };
  const p0Alignment = p0AlignmentBaseline(groundTruthOracle);
  const migrationContract = migrationContractTest();
  const readiness = migrationReadiness(
    documents.manifest,
    documents.migrationArtifact,
    fingerprintRegistry,
  );
  const report = stageReport({
    manifest: documents.manifest,
    saturation: documents.saturation,
    fingerprintRegistry,
    groundTruthOracle,
    machineCases,
    manualTasks,
    p0Alignment,
    exceptionRegistry,
    migrationReadinessDocument: readiness,
    migrationContract,
    regressionAttestation: documents.regressionAttestation,
    heroStateReport: documents.heroStateReport,
    evidenceSummary: sourceEvidenceSummary(documents),
  });
  const replayRequest = {
    ...CONTROLLED_REPLAY_REQUEST_SPECS.CALIBRATION_SET_A_HP_DEFENSE_V1,
    NEED_CALIBRATION_REPLAY: 'YES',
    exact_build: CURRENT_BUILD,
    recommended_replay_count: 1,
    maximum_replay_count_only_if_first_is_ambiguous: 3,
    exact_build_handling: {
      preferred_exact_build: CURRENT_BUILD,
      nearest_build_fallback: 'FORBIDDEN',
      if_preferred_build_is_unavailable: 'SUPPLY_CURRENT_RUNNABLE_EXACT_BUILD_REPLAY_FOR_NEW_BUILD_FULL_SEMANTIC_MIGRATION',
    },
    environment_controls: [
      'ONE_SUBJECT_CHAMPION',
      'ONE_HELPER_AT_MOST_FOR_DAMAGE_HEAL_OR_SHIELD',
      'NO_TEAM_FIGHT',
      'NO_SIMULTANEOUS_DAMAGE_HEAL_SHIELD_OR_BUFF',
      'WAIT_BETWEEN_STEPS_AND_RECORD_MM_SS_ACTION_LOG',
      'CHANGE_ONLY_ONE_ITEM_STAT_FAMILY_AT_A_TIME',
    ],
    experimental_sequence: [
      'RECORD_BASELINE_CHAMPION_AND_START_TIME',
      'TAKE_ONE_ISOLATED_HIT_THEN_WAIT_WITHOUT_HEAL_FOR_NATURAL_REGEN',
      'PERFORM_ONE_CONTROLLED_HEAL_WITH_NO_CONCURRENT_DAMAGE_OR_SHIELD',
      'APPLY_ONE_SHIELD_THEN_TAKE_ONE_ISOLATED_HIT_WITH_NO_CONCURRENT_HEAL',
      'DIE_ONCE_THEN_RECORD_RESPAWN_TIME',
      'LEVEL_UP_ONCE_WITH_NO_ITEM_OR_BUFF_CHANGE',
      'BUY_ONE_HP_ONLY_ITEM_THEN_UNDO; BUY_AGAIN_THEN_SELL',
      'BUY_ONE_ARMOR_ONLY_ITEM_THEN_UNDO; BUY_AGAIN_THEN_SELL',
      'BUY_ONE_MAGIC_RESIST_ONLY_ITEM_THEN_UNDO; BUY_AGAIN_THEN_SELL',
    ],
    action_log_format: 'MM:SS | ACTION | ITEM_OR_EFFECT_NAME | OPTIONAL_SHORT_NOTE',
    delivery: [
      'ONE_ROFL_FILE',
      'ACTION_TIMESTAMPS_OR_A_SHORT_ACTION_LOG',
      'CHAMPION_NAME',
    ],
    note: 'No binary knowledge is required from the user; the importer and case generator select machine work.',
  };

  fs.mkdirSync(outputDirectory, { recursive: true });
  const written = [];
  written.push(writeJson(path.join(outputDirectory, 'controlled_calibration_batch.json'), batch));
  written.push(writeJson(path.join(outputDirectory, 'ground_truth_oracle.json'), groundTruthOracle));
  written.push(writeJson(path.join(outputDirectory, 'semantic_fingerprints.json'), fingerprintRegistry));
  written.push(writeJson(path.join(outputDirectory, 'exception_registry.json'), exceptionRegistry.toJSON()));
  written.push(writeJson(path.join(outputDirectory, 'machine_calibration_cases.json'), machineCases));
  written.push(writeJson(path.join(outputDirectory, 'p0_alignment_baseline.json'), p0Alignment));
  written.push(writeJson(path.join(outputDirectory, 'manual_ground_truth_tasks.json'), manualTasks));
  written.push(writeText(path.join(outputDirectory, 'manual_ground_truth_tasks.txt'), formatManualGroundTruthTasks(manualTasks)));
  written.push(writeJson(path.join(outputDirectory, 'controlled_replay_request.json'), replayRequest));
  written.push(writeJson(path.join(outputDirectory, 'migration_oracle_contract_test.json'), migrationContract));
  written.push(writeJson(path.join(outputDirectory, 'next_build_readiness.json'), readiness));
  written.push(writeJson(path.join(outputDirectory, 'stage_report.json'), report));
  for (const [name, schema] of Object.entries(schemaDocuments())) {
    written.push(writeJson(path.join(outputDirectory, 'schemas', `${name}.schema.json`), schema));
  }
  const artifactManifestPath = writeArtifactManifest(outputDirectory, written, batch);
  return {
    schema: STAGE_SCHEMA,
    schema_version: STAGE_SCHEMA_VERSION,
    status: report.A_STATUS.status,
    exact_build: currentBuild,
    output_directory: outputDirectory,
    artifact_manifest: artifactManifestPath,
    ground_truth_oracle_record_count: groundTruthOracle.records.length,
    semantic_fingerprint_count: fingerprintRegistry.record_count,
    machine_calibration_case_count: machineCases.case_count,
    manual_validation_task_count: manualTasks.task_count,
    p0_promotion_count: p0Alignment.promotion_count,
    need_calibration_replay: true,
  };
}

module.exports = {
  CURRENT_BUILD,
  DEFAULT_INPUT_PATHS,
  DEFAULT_OUTPUT_DIRECTORY,
  FINGERPRINT_REGISTRY_SCHEMA,
  PREVIOUS_BUILD,
  STAGE_SCHEMA,
  STAGE_SCHEMA_VERSION,
  buildControlledGroundTruthStage,
  buildExceptionRegistry,
  buildFingerprintRegistry,
  machineCalibrationCases,
  migrationContractTest,
  migrationReadiness,
  p0AlignmentBaseline,
  resolveSafeInputs,
};
