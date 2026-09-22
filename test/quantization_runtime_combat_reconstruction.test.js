'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  EXACT_BUILD, P0, allRequiredQuantizedCount, defaultInputs, runIntegratedReconstruction,
  validateArtifactManifest, validateStaticData,
} = require('../src/quantization_runtime_combat_reconstruction');

const ROOT = path.resolve(__dirname, '..');
const hash = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');

test('patch static-data dependency is pinned but cannot masquerade as exact-build derived state', () => {
  const file = defaultInputs(ROOT).staticData;
  const snapshot = JSON.parse(fs.readFileSync(file, 'utf8'));
  validateStaticData(snapshot);
  assert.equal(snapshot.replay_exact_build, EXACT_BUILD);
  assert.equal(snapshot.controlled_items['1028'].stats.FlatHPPoolMod, 150);
  assert.equal(snapshot.controlled_items['1029'].stats.FlatArmorMod, 15);
  assert.equal(snapshot.controlled_items['1033'].stats.FlatSpellBlockMod, 20);
  assert.match(snapshot.binding_status, /EXACT_BUILD_EQUIVALENCE_NOT_INDEPENDENTLY_PROVEN/);
  assert.match(snapshot.deterministic_reconstruction_limits.derived_value_emission, /^FORBIDDEN/);
});

test('all upstream evidence manifests independently bind every listed artifact', () => {
  const inputs = defaultInputs(ROOT);
  for (const file of [inputs.quantManifest, inputs.runtimeManifest, inputs.combatManifest]) {
    const result = validateArtifactManifest(file);
    assert.ok(result.verified_count > 0);
    assert.ok(result.artifacts.every((row) => row.match));
  }
});

test('legacy ambiguous quantization funnel cannot masquerade as all-required compatibility', () => {
  assert.throws(() => allRequiredQuantizedCount({ after_quantization_aware_audit: 7 }),
    /lacks all-required transition count/);
  assert.throws(() => allRequiredQuantizedCount({
    all_required_transitions_quantized_compatible: 0,
    after_quantization_aware_audit: 7,
  }), /aliases after-audit to a different population/);
  assert.equal(allRequiredQuantizedCount({
    all_required_transitions_quantized_compatible: 0,
    after_quantization_aware_audit: 0,
  }), 0);
});

test('fresh integrated reconstruction conserves A-Z, 79 capabilities, and fail-closed P0 results', () => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'quant-runtime-combat-'));
  try {
    const { report, paths } = runIntegratedReconstruction({ rootDir: ROOT, outputDir });
    assert.equal(report.status, 'EVIDENCE_EXHAUSTED');
    assert.equal(Object.keys(report.final_report_A_to_Z).length, 26);
    assert.deepEqual(Object.keys(report.final_report_A_to_Z), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split(''));
    assert.equal(report.derivable_capability_audit.capability_count, 79);
    assert.equal(Object.values(report.derivable_capability_audit.classification_counts)
      .reduce((sum, count) => sum + count, 0), 79);
    for (const semantic of P0) {
      const counts = report.p0_candidate_counts[semantic];
      assert.equal(counts.after_quantization_aware_audit, 0);
      assert.equal(counts.after_runtime_tracing, 0);
      assert.equal(counts.after_negative_controls, 0);
      assert.equal(counts.promoted, 0);
    }
    assert.equal(report.public_capability_changes.length, 1);
    assert.equal(report.public_capability_changes[0].semantic, 'SHIELD_ABSORBED');
    assert.equal(report.shared_hero_stat_runtime.selector_identity, 'UNMAPPED');
    assert.equal(report.shared_hero_stat_runtime.lane_identity, 'UNMAPPED');
    assert.equal(report.shared_hero_stat_runtime.reader.status,
      'VERIFIED_DIRECT_GENERIC_SELECTOR_LANE_READER');
    assert.deepEqual(report.local_evidence_exhaustion.runtime_static.remaining_bounded_local_routes, []);
    assert.equal(report.local_evidence_exhaustion.shield_protocol.direct_recovery.event_count, 12);
    assert.equal(report.migration_integration.shield_absorbed.migration_oracle_status,
      'AUTO_VERIFIED_WITH_ROUTE_MOVE');
    assert.match(report.research_questions.Q1, /^NO\./);
    assert.match(report.research_questions.Q4, /^NO UNIQUE STAGE\./);
    assert.ok(Object.values(report.protected_holdout).every((value) => value === false));
    const manifest = JSON.parse(fs.readFileSync(paths.manifestPath, 'utf8'));
    for (const artifact of manifest.artifacts) {
      const file = path.join(outputDir, artifact.path);
      assert.equal(fs.statSync(file).size, artifact.bytes);
      assert.equal(hash(file), artifact.sha256);
    }
  } finally {
    fs.rmSync(outputDir, { recursive: true, force: true });
  }
});

test('integrated report is deterministic across two fresh output directories', () => {
  const first = fs.mkdtempSync(path.join(os.tmpdir(), 'quant-runtime-combat-a-'));
  const second = fs.mkdtempSync(path.join(os.tmpdir(), 'quant-runtime-combat-b-'));
  try {
    const a = runIntegratedReconstruction({ rootDir: ROOT, outputDir: first }).report;
    const b = runIntegratedReconstruction({ rootDir: ROOT, outputDir: second }).report;
    assert.deepEqual(a, b);
  } finally {
    fs.rmSync(first, { recursive: true, force: true });
    fs.rmSync(second, { recursive: true, force: true });
  }
});
