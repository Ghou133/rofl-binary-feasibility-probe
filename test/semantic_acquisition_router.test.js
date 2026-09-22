'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  ACTION_OWNERS,
  CURRENT_CAPABILITIES,
  EXHAUSTION_STATUS,
  OWNERSHIP_REGISTRY,
  SEMANTIC_DEPENDENCY_GRAPH,
  SOURCE_CLASSES,
  assertSafeOutputDirectory,
  createSemanticAcquisitionPlan,
  writeSemanticAcquisitionArtifacts,
} = require('../src/semantic_acquisition_router');

test('router publishes the required source classes and preserves Parser ownership limits', () => {
  assert.deepEqual(SOURCE_CLASSES, [
    'REPLAY_DIRECT', 'REPLAY_RUNTIME_SEMANTIC', 'REPLAY_PLUS_MECHANICS_DERIVED',
    'STATIC_GAME_DATA', 'DETAILS_LOW_PRECISION', 'CONTROLLED_GROUND_TRUTH_REQUIRED',
    'CLIENT_LOCAL_RUNTIME_ONLY', 'UNAVAILABLE_WITH_CURRENT_EVIDENCE',
  ]);
  assert.ok(OWNERSHIP_REGISTRY.ROFL_PARSER.forbids.includes('REPLAY_ACQUISITION'));
  assert.ok(OWNERSHIP_REGISTRY.ROFL_PARSER.forbids.includes('DETAILS_REINTERPRETATION'));
  assert.ok(OWNERSHIP_REGISTRY.ROFL_PARSER.forbids.includes('LIVE_CLIENT_RUNTIME'));
  assert.deepEqual(ACTION_OWNERS.DETAILS_REINTERPRETATION, ['LOL_INFERENCE_LAB']);
});

test('Armor routes through targeted runtime semantics and exposes exact current gaps', () => {
  const plan = createSemanticAcquisitionPlan({ semantic_name: 'current armor', desired_precision: 'EXACT_BUILD' });
  assert.equal(plan.semantic_name, 'ARMOR');
  assert.equal(plan.best_primary_source, 'REPLAY_RUNTIME_SEMANTIC');
  assert.equal(plan.fallback_source, 'REPLAY_PLUS_MECHANICS_DERIVED');
  assert.equal(plan.reverse_engineering_required, true);
  assert.equal(plan.mechanics_required, true);
  assert.equal(plan.no_untargeted_full_replay_scan, true);
  assert.ok(plan.existing_capabilities.some((row) => row.capability === 'LEVEL_TRANSITION'));
  assert.ok(plan.missing_capabilities.some((row) => row.capability === 'RUNE_STATE' && row.status === 'UNAVAILABLE'));
  assert.ok(plan.missing_capabilities.some((row) => row.capability === 'BUFF_STAT_MODIFIER_SEMANTICS'));
});

test('effective defense stays event-aligned and refuses to invent mitigation order', () => {
  const plan = createSemanticAcquisitionPlan({ semantic_name: 'effective armor for damage event' });
  assert.equal(plan.semantic_name, 'EFFECTIVE_DEFENSE_FOR_DAMAGE_EVENT');
  assert.equal(plan.best_primary_source, 'REPLAY_PLUS_MECHANICS_DERIVED');
  assert.equal(plan.ground_truth_required, true);
  assert.equal(plan.expected_evidence_grade, 'UNAVAILABLE');
  assert.ok(plan.dependencies.includes('HERO_DAMAGE'));
  assert.ok(plan.missing_capabilities.some((row) => row.capability === 'EXACT_BUILD_MITIGATION_ORDER'));
});

test('ability haste prefers existing formula-output lineage over a whole Replay scan', () => {
  const plan = createSemanticAcquisitionPlan({ semantic_name: 'ability haste' });
  assert.equal(plan.best_primary_source, 'REPLAY_RUNTIME_SEMANTIC');
  assert.ok(plan.dependencies.includes('STAT_FORMULA_OUTPUTS'));
  assert.ok(plan.missing_capabilities.some((row) => row.capability === 'STAT_FORMULA_OUTPUTS' && row.status === 'PARTIAL'));
  assert.equal(plan.no_untargeted_full_replay_scan, true);
});

test('dynamic defense combat questions route through explicit dependency families', () => {
  const base = createSemanticAcquisitionPlan({ semantic_name: 'base armor at level' });
  assert.equal(base.semantic_name, 'BASE_STAT_AT_LEVEL');
  assert.equal(base.best_primary_source, 'STATIC_GAME_DATA');
  assert.ok(base.existing_capabilities.some((row) =>
    row.capability === 'EXACT_BUILD_CHAMPION_STAT_ROWS'));
  assert.ok(base.missing_capabilities.some((row) =>
    row.capability === 'EXACT_BUILD_GROWTH_FORMULA'));

  const item = createSemanticAcquisitionPlan({ semantic_name: 'item stats' });
  assert.equal(item.semantic_name, 'ITEM_STAT_CONTRIBUTION');
  assert.ok(item.missing_capabilities.some((row) =>
    row.capability === 'EXACT_BUILD_ITEM_MECHANICS'));

  const hp = createSemanticAcquisitionPlan({ semantic_name: 'current hp state' });
  assert.equal(hp.semantic_name, 'CURRENT_HP');
  assert.ok(hp.missing_capabilities.some((row) => row.capability === 'ABSOLUTE_HP_ANCHOR'));

  const shield = createSemanticAcquisitionPlan({ semantic_name: 'shield remaining' });
  assert.equal(shield.semantic_name, 'SHIELD_LIFECYCLE');
  assert.ok(shield.existing_capabilities.some((row) => row.capability === 'SHIELD_GENERATED'));
  assert.ok(shield.missing_capabilities.some((row) =>
    row.capability === 'SHIELD_INSTANCE_LIFECYCLE'));
});

test('objective and camp rules distinguish targeted ground truth from current unavailability', () => {
  const objective = createSemanticAcquisitionPlan({ semantic_name: 'objective state' });
  const camp = createSemanticAcquisitionPlan({ semantic_name: 'camp clear' });
  assert.equal(objective.best_primary_source, 'CONTROLLED_GROUND_TRUTH_REQUIRED');
  assert.equal(objective.ground_truth_required, true);
  assert.equal(camp.best_primary_source, 'UNAVAILABLE_WITH_CURRENT_EVIDENCE');
  assert.equal(camp.expected_evidence_grade, 'UNAVAILABLE');
  assert.ok(camp.missing_capabilities.some((row) => row.capability === 'ORDINARY_MONSTER_CAMP_CLEAR'));
});

test('router rejects protected Holdout access and ownership violations', () => {
  assert.throws(() => createSemanticAcquisitionPlan({ semantic_name: 'Jungle Objective Holdout V1' }), /protected Holdout/);
  assert.throws(() => createSemanticAcquisitionPlan({ semantic_name: 'Armor', action: 'REPLAY_ACQUISITION', action_owner: 'ROFL_PARSER' }), /ownership violation/);
  assert.throws(() => createSemanticAcquisitionPlan({ semantic_name: 'Armor', owner_project: 'UNKNOWN_PROJECT' }), /unknown owner project/);
});

test('dependency graph preserves explicit exhaustion distinctions and capability bindings', () => {
  assert.equal(SEMANTIC_DEPENDENCY_GRAPH.nodes.ARMOR.includes('RUNE_STATE'), true);
  assert.match(EXHAUSTION_STATUS.LOCAL_HYPOTHESIS_EXHAUSTED, /not Replay/);
  assert.match(EXHAUSTION_STATUS.GLOBAL_REPLAY_NOT_EXHAUSTIVELY_SEMANTIC, /non-exhaustively-semantic/);
  assert.equal(CURRENT_CAPABILITIES.ORDINARY_MONSTER_CAMP_CLEAR.status, 'UNAVAILABLE');
});

test('artifact writer creates a hash-bound manifest and advisory plans', () => {
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'semantic-router-'));
  try {
    const result = writeSemanticAcquisitionArtifacts({
      outputDir: output,
      requests: [{ semantic_name: 'Armor' }, { semantic_name: 'Camp state' }],
    });
    const manifest = JSON.parse(fs.readFileSync(result.manifest_path, 'utf8'));
    assert.equal(manifest.status, 'ADVISORY_PLAN_ARTIFACTS_ONLY_NO_SOURCE_ACQUISITION');
    assert.equal(manifest.closure_status, 'HASHED_PLANS_AND_REGISTRIES_ONLY');
    assert.equal(manifest.source_acquisition.performed, false);
    assert.equal(manifest.source_acquisition.replay_acquisition, false);
    assert.equal(manifest.artifacts.length, 3);
    for (const artifact of manifest.artifacts) {
      const bytes = fs.readFileSync(path.join(output, artifact.path));
      assert.equal(bytes.length, artifact.bytes);
      assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'), artifact.sha256);
    }
    assert.equal(manifest.protected_holdout.consumed, false);
  } finally {
    fs.rmSync(output, { recursive: true, force: true });
  }
});

test('artifact writer rejects direct and directory-link Holdout output paths without writing', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'semantic-router-link-'));
  try {
    const direct = path.join(root, 'Jungle Objective Holdout fixture');
    assert.throws(() => assertSafeOutputDirectory(direct), /protected Holdout output path/);
    assert.throws(() => writeSemanticAcquisitionArtifacts({
      outputDir: direct,
      requests: [{ semantic_name: 'Armor' }],
    }), /protected Holdout output path/);

    const protectedFixture = path.join(root, 'protected-Holdout-fixture');
    const redirect = path.join(root, 'normal-looking-output');
    fs.mkdirSync(protectedFixture);
    try {
      fs.symlinkSync(protectedFixture, redirect, 'junction');
    } catch (error) {
      t.skip('directory links unavailable: ' + (error.code || error.message));
      return;
    }
    assert.throws(() => writeSemanticAcquisitionArtifacts({
      outputDir: redirect,
      requests: [{ semantic_name: 'Armor' }],
    }), /protected Holdout output path/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
