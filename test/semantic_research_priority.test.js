'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  DEEP_RECOVERY_BUILD,
  SCORE_WEIGHTS,
  assertAllowedInputPath,
  buildDeepRecoveryPriority,
  buildRouteQueue,
  buildSaturationReport,
  inferResearchDomain,
  writeDeepRecoveryArtifacts,
} = require('../src/semantic_research_priority');
const { parseArgs } = require('../scripts/build_semantic_deep_recovery');

function route(packetId, count, overrides = {}) {
  return {
    exact_build: DEEP_RECOVERY_BUILD,
    packet_id: packetId,
    packet_discriminator: `0x${packetId.toString(16).padStart(4, '0')}`,
    observed: {
      count,
      payload_size_distribution: overrides.payloads ?? [{ payload_length: 8, count }],
      entity_candidate: overrides.entity ?? {
        status: 'CANDIDATE',
        kind: 'RAW_PARAM_MAY_BE_ENTITY_OR_EVENT_KEY',
        observed_distinct_raw_params: 40,
      },
      source_provenance: [1, 2, 3, 4].map((value) => ({ replay_sha256: `replay-${value}` })),
    },
    runtime_registration: {
      callback_mapping_status: overrides.callbackName
        ? 'UNIQUE_CALLBACK_RTTI_NAME'
        : 'UNMAPPED_ON_MAKEFUNCTION_CALLBACK_REGISTRATION_SURFACE',
      callback_names: overrides.callbackName ? [overrides.callbackName] : [],
      callbacks: overrides.callbackName ? [{
        name: overrides.callbackName,
        callback_receive_target_rva_hex: '0x10',
      }] : [],
      factory_packets: overrides.callbackName ? [{ deserializer_rva_hex: '0x20' }] : [],
    },
    decoder: {
      decoder_status: overrides.decoderStatus ?? 'NOT_DECODED_UNKNOWN',
      profiler_or_negative_evidence: overrides.profilerEvidence ?? [],
    },
    domain: {
      primary_domain: overrides.domain ?? 'unknown',
    },
    status: {
      baseline_status: overrides.status ?? 'UNKNOWN',
      positive_semantic_coverage: overrides.positive ?? false,
      negative_control: overrides.negative ?? false,
      exact_structural_decode_evidence: overrides.structural ?? false,
    },
    research: {
      next_required_evidence: ['next evidence'],
    },
  };
}

function fixture() {
  const routes = [
    route(0x042f, 61465, { callbackName: 'PKT_S2C_StatFormulaOutputs_s' }),
    route(0x0326, 143422, { callbackName: 'PKT_NPC_BuffAdd2_s', status: 'CLASSIFIED', domain: 'buff' }),
    route(0x0199, 362796),
    route(0x0001, 200000, { callbackName: 'PKT_UI_Chat_s', domain: 'UI' }),
    route(0x017f, 266332, { callbackName: 'PKT_UnitApplyDamage_s', domain: 'combat', positive: true, status: 'KNOWN' }),
  ];
  return {
    observedRegistry: {
      schema: 'FULL_SEMANTIC_OBSERVED_ROUTE_REGISTRY_V1',
      exact_build: DEEP_RECOVERY_BUILD,
      nearest_build_fallback: 'FORBIDDEN',
      routes,
    },
    capabilityManifest: {
      exact_build_only: true,
      nearest_build_fallback: 'FORBIDDEN',
      build_profiles: {
        [DEEP_RECOVERY_BUILD]: {
          records: [
            {
              semantic_capability: 'CURRENT_HP',
              validation_status: 'UNAVAILABLE',
              evidence_grade: 'UNAVAILABLE',
              protocol_route: null,
              known_limits: ['unknown'],
            },
            {
              semantic_capability: 'DAMAGE',
              validation_status: 'PASS',
              evidence_grade: 'VERIFIED_DIRECT',
              protocol_route: '0x017f',
              known_limits: [],
            },
          ],
        },
      },
    },
    negativeEvidence: { schema: 'NEGATIVE' },
    regressionAttestation: { status: 'PASS', failed_test_count: 0 },
  };
}

test('factor weights are complete, normalized, and explicitly cost-aware', () => {
  const sum = Object.values(SCORE_WEIGHTS).reduce((left, right) => left + right, 0);
  assert.equal(Math.round(sum * 1e12) / 1e12, 1);
  assert.ok(Object.hasOwn(SCORE_WEIGHTS, 'reverse_engineering_cost_feasibility'));
});

test('runtime names refine research priority without becoming semantic claims', () => {
  assert.equal(inferResearchDomain(route(1, 1, { callbackName: 'PKT_S2C_StatFormulaOutputs_s' })), 'state');
  assert.equal(inferResearchDomain(route(2, 1, { callbackName: 'PKT_NPC_BuffAdd2_s' })), 'buff');
  assert.equal(inferResearchDomain(route(3, 1, {
    callbackName: 'PKT_S2C_SetMinimapIconOverride_s',
  })), 'UI');
  const queue = buildRouteQueue(fixture().observedRegistry.routes);
  assert.equal(queue.some((row) => row.packet_discriminator === '0x0001'), false);
  assert.equal(queue.some((row) => row.packet_discriminator === '0x017f'), false);
  assert.ok(queue.find((row) => row.packet_discriminator === '0x042f').priority_score
    > queue.find((row) => row.packet_discriminator === '0x0199').priority_score);
  assert.ok(queue.every((row) => row.promotion_authority === 'NONE_RESEARCH_PRIORITY_ONLY'));
});

test('strong UI and system RTTI identities override coarse gameplay family labels', () => {
  const rows = buildRouteQueue([
    route(0x0139, 1000, { callbackName: 'PKT_S2C_DisplaySummonerEmote_s', domain: 'spell' }),
    route(0x02e4, 1000, { callbackName: 'PKT_S2C_CameraPosition_s', domain: 'movement' }),
    route(0x03e4, 1000, { callbackName: 'PKT_NPC_MessageToClient_Broadcast_s', domain: 'entity' }),
  ]);
  assert.deepEqual(rows, []);
});

test('deep recovery remains active while current resources expose actionable hypotheses', () => {
  const result = buildDeepRecoveryPriority({ ...fixture(), generatedAt: 'fixture' });
  assert.equal(result.saturation.status, 'ACTIVE_RESEARCH');
  assert.equal(result.saturation.saturated, false);
  assert.ok(result.queue.summary.actionable_route_count > 0);
  assert.ok(result.queue.summary.actionable_capability_count > 0);
  assert.ok(result.saturation.saturation_checks.some((row) => row.pass === false));
});

test('domain execution fact comes from the effective decision, never route structure OR', () => {
  const stateRoute = route(0x042f, 1, {
    callbackName: 'PKT_S2C_StatFormulaOutputs_s',
    structural: true,
    domain: 'state',
  });
  const report = buildSaturationReport({
    exactBuild: DEEP_RECOVERY_BUILD,
    routes: [stateRoute],
    routeQueue: [],
    capabilityQueue: [],
    decisionDocuments: [{
      domain_decisions: [{
        domain: 'state',
        actual_reverse_engineering_executed: false,
        evidence_exhausted: true,
        actionable_hypotheses: [],
      }],
    }],
    regressionAttestation: { status: 'PASS', failed_test_count: 0 },
  });
  assert.equal(report.domains.find((row) => row.domain === 'state')
    .actual_reverse_engineering_executed, false);
  assert.equal(report.saturated, false);
});

test('later route evidence may supersede sampling only when explicitly declared', () => {
  const first = { route_decisions: [{ packet_id: 0x0199, decision: 'KEEP_CANDIDATE' }] };
  const replacement = {
    route_decisions: [{
      packet_id: 0x0199,
      decision: 'REPURPOSE',
      supersedes_previous_decision: true,
      evidence_exhausted: false,
    }],
  };
  assert.throws(() => buildRouteQueue([route(0x0199, 100000)], [first, first]),
    /requires explicit supersedes_previous_decision/);
  const rows = buildRouteQueue([route(0x0199, 100000)], [first, replacement]);
  assert.equal(rows[0].current_decision, 'REPURPOSE');
});

test('wrong exact build and fallback-enabled evidence fail closed', () => {
  assert.throws(() => buildDeepRecoveryPriority({
    ...fixture(),
    exactBuild: '16.16.805.442',
  }), /supports exact build/);
  const inputs = fixture();
  inputs.observedRegistry.nearest_build_fallback = 'ALLOWED';
  assert.throws(() => buildDeepRecoveryPriority(inputs), /fallback must be FORBIDDEN/);
});

test('Holdout paths are rejected before any read or output', () => {
  assert.throws(() => assertAllowedInputPath(path.join('protected', 'Jungle_Objective_Holdout', 'x.json')), /forbidden/);
  const result = buildDeepRecoveryPriority(fixture());
  assert.throws(() => writeDeepRecoveryArtifacts(path.join(os.tmpdir(), 'Holdout', 'out'), result), /protected Holdout/);
});

test('writer rejects non-exact boundaries and canonical missing-descendant aliases before writes', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'semantic-priority-writer-gate-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  {
    const result = buildDeepRecoveryPriority(fixture());
    delete result.queue.protected_holdout.consumed;
    const output = path.join(root, 'missing-boundary-output');
    assert.throws(() => writeDeepRecoveryArtifacts(output, result),
      /queue protected_holdout must contain exactly six/);
    assert.equal(fs.existsSync(output), false);
  }
  {
    const result = buildDeepRecoveryPriority(fixture());
    result.saturation.protected_holdout.extra = false;
    const output = path.join(root, 'extra-boundary-output');
    assert.throws(() => writeDeepRecoveryArtifacts(output, result),
      /saturation protected_holdout must contain exactly six/);
    assert.equal(fs.existsSync(output), false);
  }
  {
    const syntheticProtected = path.join(root, 'Synthetic-Holdout-target');
    const alias = path.join(root, 'safe-output-alias');
    fs.mkdirSync(syntheticProtected);
    fs.symlinkSync(syntheticProtected, alias, process.platform === 'win32' ? 'junction' : 'dir');
    const missingOutput = path.join(alias, 'missing', 'deep');
    assert.throws(() => writeDeepRecoveryArtifacts(
      missingOutput, buildDeepRecoveryPriority(fixture()),
    ), /canonical output directory cannot target protected Holdout/);
    assert.equal(fs.existsSync(path.join(alias, 'missing')), false);
  }
});

test('artifact output is deterministic and manifest excludes self hash', () => {
  const result = buildDeepRecoveryPriority({ ...fixture(), generatedAt: 'fixture' });
  const first = fs.mkdtempSync(path.join(os.tmpdir(), 'semantic-deep-a-'));
  const second = fs.mkdtempSync(path.join(os.tmpdir(), 'semantic-deep-b-'));
  const left = writeDeepRecoveryArtifacts(first, result);
  const right = writeDeepRecoveryArtifacts(second, result);
  assert.deepEqual(left.files.map((row) => row.sha256), right.files.map((row) => row.sha256));
  const manifest = JSON.parse(fs.readFileSync(path.join(first, 'artifact_manifest.json')));
  assert.equal(manifest.self_hash_excluded, true);
  assert.equal(manifest.files.some((row) => row.file === 'artifact_manifest.json'), false);
});

test('CLI accepts one final ledger and rejects additive decision documents', () => {
  const options = parseArgs(['--decision', 'final-ledger.json']);
  assert.equal(options.exactBuild, DEEP_RECOVERY_BUILD);
  assert.deepEqual(options.decisionPaths, ['final-ledger.json']);
  assert.equal(options.outputDirectory, 'artifacts/full_semantic_deep_recovery_v2');
  assert.throws(() => parseArgs(['--decision', 'a.json', '--decision', 'b.json']),
    /exactly one validated final decision ledger/);
});
