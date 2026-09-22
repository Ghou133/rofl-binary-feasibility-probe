'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  BASELINE_STATUS_VOCABULARY,
  DEFAULT_EXACT_BUILD,
  DOMAIN_VOCABULARY,
  REQUESTED_BASELINE_CAPABILITIES,
  assertAllowedInputPath,
  buildFullSemanticBaseline,
  buildFullSemanticBaselineFromPaths,
  classifyRttiNames,
  routeIdsFromManifestRecord,
  writeFullSemanticBaselineArtifacts,
} = require('../src/full_semantic_baseline');
const { parseArgs } = require('../scripts/build_full_semantic_baseline');

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function fixturePacket(packetId, count, overrides = {}) {
  return {
    build: DEFAULT_EXACT_BUILD,
    packet_id: packetId,
    packet_discriminator: `0x${packetId.toString(16).padStart(4, '0')}`,
    count,
    payload_size_distribution: [{ payload_length: packetId, count }],
    payload_size_observation_status: 'OBSERVED_FOR_ALL_PACKETS',
    currently_decoded_as_status: overrides.decodeStatus ?? 'UNREGISTERED_EXACT_BUILD_RAW_ONLY',
    decoded_as: overrides.decodedAs ?? [{
      capability: null,
      status: 'UNREGISTERED_EXACT_BUILD_RAW_ONLY',
      possible_category: 'UNKNOWN',
    }],
    entity_candidate: {
      status: 'CANDIDATE',
      kind: 'RAW_PARAM_MAY_BE_ENTITY_OR_EVENT_KEY',
      observed_distinct_raw_params: count,
    },
    temporal_behavior: {
      status: 'CANDIDATE',
      pattern: 'RECURRING_CANDIDATE',
      first_observed_time_ms: packetId,
      last_observed_time_ms: packetId + count,
    },
    possible_category: overrides.category ?? 'UNKNOWN',
    confidence: overrides.confidence ?? 'CANDIDATE',
    provenance: [{ source_kind: 'FIXTURE', replay_sha256: `replay-${packetId}` }],
  };
}

function fixtureInputs() {
  const packets = [
    fixturePacket(1, 10, {
      decodeStatus: 'EXACT_BUILD_ROUTE_REGISTERED',
      decodedAs: [{ capability: 'hero_path', status: 'SEMANTIC_VERIFIED_DERIVED' }],
      category: 'MOVEMENT',
      confidence: 'VERIFIED_DIRECT',
    }),
    fixturePacket(2, 20),
    fixturePacket(3, 30),
    fixturePacket(4, 40),
  ];
  const inventory = {
    schema_version: 'PACKET_COVERAGE_INVENTORY_V1',
    exact_build_policy: 'RAW_PACKET_ROWS_ARE_NEVER_MERGED_ACROSS_EXACT_GAME_VERSION',
    input_record_count: 100,
    builds: [{
      game_version: DEFAULT_EXACT_BUILD,
      build_profile_status: 'SUPPORTED',
      packet_type_count: 4,
      packet_count: 100,
    }],
    packets,
  };
  const callbackRoutes = packets.map((packet) => ({
    packet_id: packet.packet_id,
    packet_id_hex: packet.packet_discriminator,
    observed_count: packet.count,
    payload_size_distribution: packet.payload_size_distribution,
    existing_decode_status: packet.currently_decoded_as_status,
    callback_mapping_status: packet.packet_id === 3
      ? 'UNIQUE_CALLBACK_RTTI_NAME'
      : 'UNMAPPED_ON_MAKEFUNCTION_CALLBACK_REGISTRATION_SURFACE',
    callback_names: packet.packet_id === 3 ? ['PKT_UnitApplyDamage_s'] : [],
    callbacks: packet.packet_id === 3 ? [{
      name: 'PKT_UnitApplyDamage_s',
      callback_owner_type: 'AttackableUnit',
      type_descriptor_rva_hex: '0x1',
      callback_receive_target_rva_hex: '0x2',
    }] : [],
    factory_packets: packet.packet_id === 4 ? [{
      case_rva_hex: '0x3',
      deserializer_rva_hex: '0x4',
      object_size: 8,
    }] : [],
  }));
  const callbackMap = {
    schema_version: 1,
    build: DEFAULT_EXACT_BUILD,
    observed_route_count: 4,
    status_counts: {
      UNIQUE_CALLBACK_RTTI_NAME: 1,
      UNMAPPED_ON_MAKEFUNCTION_CALLBACK_REGISTRATION_SURFACE: 3,
    },
    mapped_observed_packet_count: 30,
    total_observed_packet_count: 100,
    routes: callbackRoutes,
  };
  const capabilityManifest = {
    schema: 'ROFL_CAPABILITY_MANIFEST_V1',
    generated_at: '2026-08-20',
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    build_profiles: {
      [DEFAULT_EXACT_BUILD]: {
        release_status: 'FIXTURE',
        records: [
          {
            semantic_capability: 'HERO_PATH',
            build: DEFAULT_EXACT_BUILD,
            protocol_route: '0x0001',
            packet_registration_route: '0x0001 fixture',
            decoder_version: 'fixture-decoder',
            field_mapping: { entity: 'direct' },
            evidence_grade: 'VERIFIED_DERIVED',
            validation_status: 'PASS',
            sample_count: { replay_count: 1, event_count: 10 },
            positive_examples: ['fixture'],
            negative_examples: [],
            known_limits: [],
          },
          {
            semantic_capability: 'CAST_SPELL',
            build: DEFAULT_EXACT_BUILD,
            protocol_route: null,
            packet_registration_route: null,
            decoder_version: null,
            field_mapping: {},
            evidence_grade: 'UNAVAILABLE',
            validation_status: 'UNAVAILABLE',
            sample_count: { replay_count: 0, event_count: 0 },
            positive_examples: [],
            negative_examples: ['missing'],
            known_limits: ['No verified route.'],
          },
        ],
      },
    },
  };
  const profilerCoverage = {
    schema: 'FIELD_BEHAVIOR_PROFILER_COVERAGE_MATRIX_V1',
    promotion_authority: 'NONE',
    value_representations: [{
      family: 'strings',
      status: 'UNSUPPORTED_GENERICALLY',
      actual_behavior: 'No generic claim.',
      minimum_gap: 'Typed adapter required.',
    }],
    statistics: { minimum_gaps: ['No categorical association.'] },
    input_adapters: { minimum_gap: 'Typed decoded values required.' },
    minimal_priority_order: ['Typed values.'],
  };
  const profilerProfiles = [{
    schema: 'FIELD_BEHAVIOR_PROFILE_V1',
    analyzer_version: 'fixture-profiler',
    target_build: DEFAULT_EXACT_BUILD,
    evidence_grade: 'CANDIDATE',
    semantic_claim: null,
    input: {
      input_mode: 'DECODED_HEX_FIELD_EXPORT',
      packet_record_extraction: {
        input_row_count: 20,
        accepted_row_count: 20,
        rejected_row_count: 0,
        rejected: { wrong_build: 0, not_fully_consumed: 0 },
        hex_field: 'decoded_fields.blob_hex',
        require_fully_consumed: true,
      },
    },
    route_profiles: [{
      packet_id: 2,
      packet_discriminator: '0x0002',
      build: DEFAULT_EXACT_BUILD,
      status: 'NEGATIVE_CONTROL_PROFILE_AVAILABLE',
      route_role: 'NEGATIVE_CONTROL',
      known_route_semantics: 'HERO_CUMULATIVE_SCOREBOARD_STATS',
      excluded_from_combat_state_ranking: true,
      observed_record_count: 20,
      profiled_record_count: 20,
      profiled_value_source: 'decoded_fields.blob_hex',
    }],
    ranked_candidates: [],
  }];
  return {
    inventory,
    callbackMap,
    capabilityManifest,
    profilerCoverage,
    profilerProfiles,
    negativeAudits: [],
    sourceDescriptors: [{
      label: 'fixture',
      path: 'fixture.json',
      sha256: '0'.repeat(64),
      byte_count: 1,
      schema: 'FIXTURE',
    }],
  };
}

function addExternalManifestRoute(input, semanticCapability = 'SHIELD_ABSORBED') {
  input.capabilityManifest.build_profiles[DEFAULT_EXACT_BUILD].records.push({
    semantic_capability: semanticCapability,
    build: DEFAULT_EXACT_BUILD,
    protocol_route: '0x01e1',
    packet_registration_route: '0x01e1 fixture',
    decoder_version: 'fixture-external-decoder',
    field_mapping: { amount: 'direct' },
    evidence_grade: 'VERIFIED_DIRECT',
    validation_status: 'PASS',
    sample_count: { replay_count: 4, event_count: 12 },
    positive_examples: ['fixture-external-fingerprint'],
    negative_examples: [],
    known_limits: ['Route is observed in a separate exact-build governed corpus.'],
  });
}

test('domain and status vocabularies are exact and RTTI classification never claims semantics', () => {
  assert.deepEqual(DOMAIN_VOCABULARY, [
    'entity', 'state', 'movement', 'combat', 'spell', 'missile', 'buff', 'vision',
    'economy', 'objective', 'structure', 'map', 'UI', 'system', 'noise', 'unknown',
  ]);
  assert.deepEqual(BASELINE_STATUS_VOCABULARY, ['KNOWN', 'DECODED', 'CLASSIFIED', 'UNKNOWN']);
  const damage = classifyRttiNames(['PKT_UnitApplyDamage_s']);
  assert.equal(damage.primary_domain, 'combat');
  assert.equal(damage.classification_status, 'RTTI_NAME_DOMAIN_CANDIDATE');
  assert.equal(damage.evidence_grade, 'CANDIDATE');
  assert.equal(damage.semantic_claim, null);
  const absent = classifyRttiNames([]);
  assert.equal(absent.primary_domain, 'unknown');
  assert.equal(absent.classification_status, 'UNKNOWN_NO_RTTI_NAME');
  const unmatched = classifyRttiNames(['PKT_S2C_ObscureFamily_s']);
  assert.equal(unmatched.primary_domain, 'unknown');
  assert.equal(unmatched.semantic_claim, null);
  const buffRemove = classifyRttiNames(['PKT_NPC_BuffRemove2_s']);
  assert.equal(buffRemove.primary_domain, 'buff');
  assert.ok(buffRemove.candidate_domains.includes('buff'));
  assert.ok(!buffRemove.candidate_domains.includes('movement'));
  const itemBroadcast = classifyRttiNames(['PKT_S2C_SetItemGroupData_Broadcast_s']);
  assert.equal(itemBroadcast.primary_domain, 'economy');
  assert.deepEqual(itemBroadcast.candidate_domains, ['economy']);
  assert.deepEqual(routeIdsFromManifestRecord({
    protocol_route: '0x0010 / 0x0020 candidate',
    packet_registration_route: '0x0010',
  }), [0x10, 0x20]);
});

test('baseline partitions known, decoded, classified, and unknown without losing route evidence', () => {
  const result = buildFullSemanticBaseline(fixtureInputs());
  assert.deepEqual(result.baseline.metrics.route_status_counts, {
    known: 1,
    decoded: 1,
    classified: 1,
    unknown: 1,
  });
  assert.deepEqual(result.baseline.metrics.packet_status_counts, {
    known: 10,
    decoded: 20,
    classified: 30,
    unknown: 40,
  });
  assert.equal(result.observedRouteRegistry.routes.length, 4);
  assert.equal(result.observedRouteRegistry.routes[3].observed.payload_size_distribution[0].count, 40);
  assert.equal(result.observedRouteRegistry.routes[3].observed.entity_candidate.observed_distinct_raw_params, 40);
  assert.equal(result.observedRouteRegistry.routes[3].observed.temporal_behavior.first_observed_time_ms, 4);
  assert.equal(result.observedRouteRegistry.routes[3].runtime_registration.factory_packets[0].object_size, 8);
  assert.equal(result.observedRouteRegistry.routes[2].runtime_registration.callback_names[0], 'PKT_UnitApplyDamage_s');
  assert.equal(result.observedRouteRegistry.routes[0].decoder.manifest_route_records[0].decoder_version, 'fixture-decoder');
  assert.equal(result.observedRouteRegistry.routes[2].evidence.semantic_claim, null);
  assert.equal(result.unknownPacketRegistry.route_count, 3);
  assert.equal(result.negativeEvidenceRegistry.route_negative_control_count, 1);
  assert.equal(result.completenessGate.ready, false);
  assert.equal(result.completenessGate.status, 'BLOCKED_NOT_READY');
  assert.equal(result.baseline.conservation.route_conservation_pass, true);
  assert.equal(result.baseline.conservation.packet_conservation_pass, true);
  assert.deepEqual(result.domainDashboard.domains.map((row) => row.domain), DOMAIN_VOCABULARY);
});

test('readiness permits explicit UNKNOWN and unavailable capabilities when accounting, evidence tiers, profiler scope, and regression attestation are complete', () => {
  const input = fixtureInputs();
  input.profilerCoverage = {
    ...input.profilerCoverage,
    value_representations: [
      'float32', 'float64', 'integers', 'bitfields', 'packed_fields', 'identifiers',
      'vectors', 'strings', 'hashes',
    ].map((family) => ({ family, status: 'SUPPORTED_FIXTURE', minimum_gap: null })),
    statistics: {
      supported: [
        'range', 'mean', 'median', 'population_variance', 'delta_distribution',
        'per_entity_stability', 'per_entity_bounded_trajectory', 'change_rate',
      ],
      minimum_gaps: ['Disclosed fixture limitation that must not erase supported scope.'],
    },
    anchor_matrix: [
      'Damage', 'Death', 'Heal', 'Shield', 'Level', 'Item', 'Cast', 'Ward', 'Movement',
    ].map((anchor) => ({ anchor, status: 'SUPPORTED_CANDIDATE_CORRELATION' })),
    input_adapters: {
      raw_rofl: 'fixture', decoded_hex: 'fixture', typed_decoded_fields: 'fixture',
      minimum_gap: 'Explicit schema remains required and is a disclosed non-blocking limit.',
    },
  };
  const existingCapabilities = new Set(
    input.capabilityManifest.build_profiles[DEFAULT_EXACT_BUILD].records
      .map((row) => row.semantic_capability),
  );
  const requiredCapabilities = REQUESTED_BASELINE_CAPABILITIES
    .filter((capability) => !existingCapabilities.has(capability));
  input.capabilityManifest.build_profiles[DEFAULT_EXACT_BUILD].records.push(...requiredCapabilities.map((semantic_capability) => ({
    semantic_capability,
    build: DEFAULT_EXACT_BUILD,
    protocol_route: null,
    packet_registration_route: null,
    decoder_version: null,
    field_mapping: {},
    evidence_grade: 'UNAVAILABLE',
    validation_status: 'UNAVAILABLE',
    sample_count: { replay_count: 0, event_count: 0 },
    positive_examples: [],
    negative_examples: [],
    known_limits: ['Fixture: no exact-build positive route is available.'],
  })));
  input.supplementalEvidence = [
    {
      schema: 'RUNTIME_CANDIDATE_SHAPE_V1',
      build: DEFAULT_EXACT_BUILD,
      routes: [{ packet_id: 4, evidence_class: 'EXACT_STATIC_SHAPE_EMULATION' }],
    },
    {
      schema: 'REGRESSION_ATTESTATION_V1',
      exact_build: DEFAULT_EXACT_BUILD,
      status: 'PASS',
      test_count: 3,
    },
  ];
  const result = buildFullSemanticBaseline(input);
  const unknown = result.observedRouteRegistry.routes.find((route) => route.packet_id === 4);
  assert.equal(unknown.status.baseline_status, 'UNKNOWN');
  assert.equal(unknown.evidence.semantic_claim, null);
  assert.ok(unknown.research.evidence_tiers.includes('EXACT_RUNTIME_STRUCTURAL_CANDIDATE'));
  assert.equal(result.completenessGate.ready, true);
  assert.equal(result.completenessGate.status, 'READY');
  assert.equal(result.completenessGate.blockers.length, 0);
  const enumeration = result.completenessGate.checks
    .find((row) => row.check === 'REQUESTED_CAPABILITY_ENUMERATION_COMPLETE');
  assert.equal(enumeration.pass, true);
  assert.deepEqual(enumeration.observed.missing, []);
  assert.equal(result.baseline.supplemental_evidence.regression_attestation.pass, true);
  assert.ok(result.unknownPacketRegistry.routes.every((route) => route.research.next_required_evidence.length > 0));

  input.capabilityManifest.build_profiles[DEFAULT_EXACT_BUILD].records =
    input.capabilityManifest.build_profiles[DEFAULT_EXACT_BUILD].records
      .filter((row) => row.semantic_capability !== 'MAP_MECHANIC');
  const incomplete = buildFullSemanticBaseline(input);
  const missingEnumeration = incomplete.completenessGate.checks
    .find((row) => row.check === 'REQUESTED_CAPABILITY_ENUMERATION_COMPLETE');
  assert.equal(incomplete.completenessGate.ready, false);
  assert.equal(missingEnumeration.pass, false);
  assert.deepEqual(missingEnumeration.observed.missing, ['MAP_MECHANIC']);
});

test('exact-build joins fail closed on route/count drift and Holdout paths are rejected before reads', () => {
  const countDrift = fixtureInputs();
  countDrift.callbackMap.routes[0].observed_count += 1;
  assert.throws(() => buildFullSemanticBaseline(countDrift), /count mismatch/);

  const buildDrift = fixtureInputs();
  buildDrift.callbackMap.build = '16.16.805.0443';
  assert.throws(() => buildFullSemanticBaseline(buildDrift), /build mismatch/);

  assert.throws(
    () => assertAllowedInputPath('artifacts/Jungle_Objective_Holdout/secret.json'),
    /Holdout paths are forbidden/,
  );
});

test('manifest routes absent from the core inventory cannot use an unauthenticated in-memory attestation', () => {
  const missing = fixtureInputs();
  addExternalManifestRoute(missing);
  const missingResult = buildFullSemanticBaseline(missing);
  assert.equal(
    missingResult.baseline.capability_manifest_overview.unobserved_manifest_route_records.length,
    1,
  );
  assert.equal(
    missingResult.completenessGate.checks.find((row) =>
      row.check === 'MANIFEST_ROUTES_ARE_IN_INVENTORY_OR_EXACT_EXTERNAL_ATTESTATION').pass,
    false,
  );

  const forged = fixtureInputs();
  addExternalManifestRoute(forged);
  forged.supplementalEvidence = [
    {
      document: {
        schema: 'EXTERNAL_EXACT_BUILD_ROUTE_ATTESTATION_MANIFEST_V1',
        exact_build: DEFAULT_EXACT_BUILD,
      },
      source: { sha256: 'a'.repeat(64), byte_count: 1 },
    },
    {
      document: {
        schema: 'EXTERNAL_EXACT_BUILD_ROUTE_ATTESTATION_V1',
        exact_build: DEFAULT_EXACT_BUILD,
        semantic_name: 'SHIELD_ABSORBED',
      },
      source: { sha256: 'b'.repeat(64), byte_count: 1 },
    },
  ];
  assert.throws(
    () => buildFullSemanticBaseline(forged),
    /must be authenticated by the filesystem loader/,
  );
});

test('published external attestation bytes are pinned and tampering fails before route exemption', (t) => {
  const outputDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'external-route-attestation-'));
  t.after(() => fs.rmSync(outputDirectory, { recursive: true, force: true }));
  const root = path.resolve(__dirname, '..');
  const sourceManifestPath = path.join(root, 'evidence', 'exact_build_route_attestations',
    'artifact_manifest.json');
  const sourceAttestationPath = path.join(root, 'evidence', 'exact_build_route_attestations',
    'shield_absorbed_16_16.json');
  const tamperedManifestPath = path.join(outputDirectory, 'artifact_manifest.json');
  const tamperedAttestationPath = path.join(outputDirectory, 'shield_absorbed_16_16.json');
  fs.copyFileSync(sourceManifestPath, tamperedManifestPath);
  const tampered = JSON.parse(fs.readFileSync(sourceAttestationPath, 'utf8'));
  tampered.observations[0].object_hex = `${tampered.observations[0].object_hex.slice(0, -2)}00`;
  fs.writeFileSync(tamperedAttestationPath, `${JSON.stringify(tampered, null, 2)}\n`, 'utf8');
  assert.throws(
    () => buildFullSemanticBaselineFromPaths({
      supplementalEvidencePaths: [tamperedManifestPath, tamperedAttestationPath],
    }),
    /attestation artifact identity mismatch/,
  );
});

test('checked-in 16.16 evidence conserves all 288 routes and satisfies the semantic baseline gate', () => {
  const result = buildFullSemanticBaselineFromPaths();
  const metrics = result.baseline.metrics;
  assert.equal(metrics.total_route_count, 288);
  assert.equal(metrics.total_packet_count, 7223748);
  assert.equal(metrics.route_partition_sum, 288);
  assert.equal(metrics.packet_partition_sum, 7223748);
  assert.equal(result.baseline.conservation.route_conservation_pass, true);
  assert.equal(result.baseline.conservation.packet_conservation_pass, true);
  assert.ok(metrics.route_status_counts.known > 0);
  assert.equal(metrics.route_status_counts.decoded, 3);
  assert.ok(metrics.route_status_counts.unknown > 0);
  assert.deepEqual(metrics.stale_inventory_decode_status_routes, []);
  assert.equal(result.observedRouteRegistry.routes
    .find((route) => route.packet_discriminator === '0x017f')
    .decoder.input_status_reconciliation,
  'NO_STALE_VERIFIED_MANIFEST_OVERRIDE_REQUIRED');
  assert.equal(result.unknownPacketRegistry.route_count, 288 - metrics.route_status_counts.known);
  assert.equal(result.negativeEvidenceRegistry.route_negative_control_count, 3);
  assert.deepEqual(result.negativeEvidenceRegistry.route_negative_controls
    .map((row) => row.packet_discriminator), ['0x010c', '0x0302', '0x04ca']);
  assert.equal(result.completenessGate.ready, true);
  assert.equal(result.completenessGate.status, 'READY');
  assert.deepEqual(result.completenessGate.blockers, []);
  assert.ok(result.baseline.source_inputs.every((source) => !/holdout/i.test(source.path)));
  assert.ok(result.baseline.source_inputs.every((source) => !/(?:^|\/)\.omo(?:\/|$)/i.test(source.path)));
  const externallyAttested = result.baseline.capability_manifest_overview
    .externally_attested_manifest_route_records;
  assert.equal(externallyAttested.length, 1);
  assert.equal(externallyAttested[0].packet_discriminator, '0x01e1');
  assert.equal(externallyAttested[0].semantic_capability, 'SHIELD_ABSORBED');
  assert.equal(externallyAttested[0].validation_status, 'PASS');
  assert.equal(externallyAttested[0].evidence_grade, 'VERIFIED_DIRECT');
  assert.equal(externallyAttested[0].attestation.observed_count, 12);
  assert.equal(
    externallyAttested[0].attestation.exact_build_provenance.source_kind,
    'EXACT_BUILD_RUNTIME_AND_PUBLISHED_MACHINE_ROWS',
  );
  for (const route of result.observedRouteRegistry.routes) {
    assert.ok(Number.isSafeInteger(route.observed.count));
    assert.ok(Array.isArray(route.observed.payload_size_distribution));
    assert.ok(route.observed.entity_candidate);
    assert.ok(route.observed.temporal_behavior);
    assert.ok(Array.isArray(route.runtime_registration.callback_names));
    assert.ok(Array.isArray(route.runtime_registration.factory_packets));
    assert.ok(route.decoder.decoder_status);
    assert.ok(route.status.baseline_status);
    assert.ok(route.evidence.aggregate_evidence_grades.length > 0);
  }
});

test('external route exemption is denied when the manifest record is not PASS and VERIFIED_DIRECT', (t) => {
  const outputDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'external-route-manifest-status-'));
  t.after(() => fs.rmSync(outputDirectory, { recursive: true, force: true }));
  const root = path.resolve(__dirname, '..');
  const manifest = JSON.parse(fs.readFileSync(
    path.join(root, 'artifacts', 'semantic_coverage_v1', 'capability_manifest.json'),
    'utf8',
  ));
  const record = manifest.build_profiles[DEFAULT_EXACT_BUILD].records.find((row) =>
    row.semantic_capability === 'SHIELD_ABSORBED');
  assert.ok(record);
  record.validation_status = 'EVIDENCE_EXHAUSTED';
  record.evidence_grade = 'CANDIDATE';
  const manifestPath = path.join(outputDirectory, 'capability_manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  const result = buildFullSemanticBaselineFromPaths({ capabilityManifestPath: manifestPath });
  assert.equal(
    result.baseline.capability_manifest_overview.externally_attested_manifest_route_records.length,
    0,
  );
  assert.ok(result.baseline.capability_manifest_overview.unobserved_manifest_route_records
    .some((row) => row.packet_discriminator === '0x01e1'
      && row.semantic_capability === 'SHIELD_ABSORBED'));
  assert.equal(
    result.completenessGate.checks.find((row) =>
      row.check === 'MANIFEST_ROUTES_ARE_IN_INVENTORY_OR_EXACT_EXTERNAL_ATTESTATION').pass,
    false,
  );
});

test('artifact writer emits standalone registries and a hash manifest excluding self-reference', (t) => {
  const outputDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'full-semantic-baseline-'));
  t.after(() => fs.rmSync(outputDirectory, { recursive: true, force: true }));
  const result = buildFullSemanticBaseline(fixtureInputs());
  const written = writeFullSemanticBaselineArtifacts(outputDirectory, result);
  assert.equal(written.files.length, 7);
  const manifest = JSON.parse(fs.readFileSync(path.join(outputDirectory, 'artifact_manifest.json'), 'utf8'));
  assert.equal(manifest.self_hash_excluded, true);
  assert.equal(manifest.files.length, 6);
  for (const row of manifest.files) {
    assert.equal(sha256File(path.join(outputDirectory, row.file)), row.sha256);
  }
  assert.equal(JSON.parse(fs.readFileSync(
    path.join(outputDirectory, 'unknown_packet_registry.json'),
    'utf8',
  )).route_count, 3);
});

test('CLI accepts explicit sources while retaining exact-build defaults', () => {
  const defaults = parseArgs([]);
  assert.equal(defaults.targetBuild, DEFAULT_EXACT_BUILD);
  assert.equal(defaults.profilerProfilePaths, null);
  assert.equal(defaults.supplementalEvidencePaths, null);
  const parsed = parseArgs([
    '--build', DEFAULT_EXACT_BUILD,
    '--inventory', 'inventory.json',
    '--callback-map', 'callbacks.json',
    '--capability-manifest', 'manifest.json',
    '--profiler-coverage', 'coverage.json',
    '--profiler-profile', 'negative-a.json',
    '--profiler-profile', 'negative-b.json',
    '--negative-audit', 'audit.json',
    '--supplemental-evidence', 'regression.json',
    '--output-dir', 'out',
  ]);
  assert.deepEqual(parsed.profilerProfilePaths, ['negative-a.json', 'negative-b.json']);
  assert.deepEqual(parsed.negativeAuditPaths, ['audit.json']);
  assert.deepEqual(parsed.supplementalEvidencePaths, ['regression.json']);
  assert.equal(parsed.outputDirectory, 'out');
  assert.throws(() => parseArgs(['--unknown']), /unknown option/);
});
