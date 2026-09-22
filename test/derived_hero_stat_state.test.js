'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  HOLDOUT_ACCESS,
  REQUIRED_CALCULATION_ORDER,
  auditDerivedCombatState,
  deriveHeroStatState,
  mechanicsPayloadSha256,
  mintAlgorithmConformanceAuthority,
} = require('../src/derived_hero_stat_state');
const {
  loadGovernedHudOracle,
  parseArgs,
} = require('../scripts/build_derived_hero_stat_state');

const EXACT_BUILD = '16.16.805.0442';
const HUD = loadGovernedHudOracle();
const ALGORITHM_AUTHORITY = mintAlgorithmConformanceAuthority();

function modifier(targetStat, value, operation = 'ADD_FLAT') {
  return {
    target_stat: targetStat,
    operation,
    value,
    status: 'VERIFIED',
    exact_build: EXACT_BUILD,
    evidence: { kind: 'CONFORMANCE_FIXTURE_ONLY' },
  };
}

function mechanics(binding = {}) {
  const stat = (value) => ({
    values_by_level: { 2: value },
    calculation_formula_id: 'ALGORITHM_STAT_PIPELINE_V1',
    display: { rule: 'ROUND_NEAREST_INTEGER' },
  });
  const result = {
    binding: {
      status: 'EXACT_BUILD_VERIFIED',
      identity_proof: true,
      exact_build: EXACT_BUILD,
      source_registry_ref: 'INTERNAL_ALGORITHM_FIXTURE_REGISTRY:V1',
      source_artifact_sha256: 'c'.repeat(64),
      ...binding,
    },
    formulas: {
      stat_calculation: {
        ALGORITHM_STAT_PIPELINE_V1: {
          steps: [
            { operation: 'BASE_AT_LEVEL', semantics: 'BOUND_BASE_VALUE' },
            { operation: 'ADD_FLAT', semantics: 'SUM_THEN_ADD_TO_RUNNING' },
            { operation: 'ADD_PERCENT_BASE', semantics: 'SUM_TIMES_BASE_THEN_ADD_TO_RUNNING' },
            { operation: 'ADD_PERCENT_TOTAL', semantics: 'MULTIPLY_RUNNING_BY_ONE_PLUS_SUM' },
            { operation: 'MULTIPLY_TOTAL', semantics: 'MULTIPLY_RUNNING_BY_PRODUCT' },
          ],
        },
      },
      growth: {},
    },
    coverage: {
      max_hp: true,
      armor: true,
      magic_resist: true,
      item_catalog_complete: true,
      rune_mechanics_complete: true,
      buff_operation_model_complete: true,
      exception_registry_complete: true,
    },
    champions: {
      Kayn: {
        requires_exception_state: false,
        stats: {
          max_hp: stat(HUD.ruby[0]),
          armor: stat(HUD.cloth[0]),
          magic_resist: stat(HUD.mantle[0]),
        },
      },
    },
    items: {
      1028: { modifiers: { max_hp: [modifier('max_hp', 150)] } },
      1029: { modifiers: { armor: [modifier('armor', 15)] } },
      1033: { modifiers: { magic_resist: [modifier('magic_resist', 20)] } },
    },
  };
  result.binding.payload_sha256 = mechanicsPayloadSha256(result);
  return result;
}

function derive(input, authority = ALGORITHM_AUTHORITY) {
  return deriveHeroStatState(input, { authority });
}

function completeState(overrides = {}) {
  return {
    exact_build: EXACT_BUILD,
    game_time: 120000,
    entity: { participant_id: 1, champion: 'Kayn' },
    champion_identity: { champion: 'Kayn', evidence: 'VERIFIED_DIRECT', game_time: 120000 },
    level_state: { level: 2, status: 'COMPLETE', exact_build: EXACT_BUILD, game_time: 120000 },
    inventory_state: {
      status: 'COMPLETE',
      exact_build: EXACT_BUILD,
      ambiguous_mutation: false,
      game_time: 120000,
      items: [],
    },
    rune_state: {
      status: 'COMPLETE',
      exact_build: EXACT_BUILD,
      unmapped_modifier_count: 0,
      modifiers: [],
      game_time: 120000,
    },
    buff_state: {
      status: 'COMPLETE',
      exact_build: EXACT_BUILD,
      unmapped_modifier_count: 0,
      modifiers: [],
      game_time: 120000,
    },
    mechanics: mechanics(),
    ...overrides,
  };
}

test('trusted fixture mechanics conform to governed manual HUD item observations', () => {
  const baseline = derive(completeState());
  assert.deepEqual(
    [baseline.fields.max_hp.display_value, baseline.fields.armor.display_value,
      baseline.fields.magic_resist.display_value],
    [HUD.ruby[0], HUD.cloth[0], HUD.mantle[0]],
  );
  assert.equal(baseline.fields.max_hp.publication_eligible, false);
  assert.equal(baseline.fields.armor.publication_eligible, false);
  assert.equal(baseline.fields.magic_resist.publication_eligible, false);
  assert.deepEqual(
    [baseline.fields.max_hp.status, baseline.fields.armor.status,
      baseline.fields.magic_resist.status],
    ['MAX_HP_DERIVED_COMPLETE', 'ARMOR_DERIVED_COMPLETE', 'MAGIC_RESIST_DERIVED_COMPLETE'],
  );

  const ruby = derive(completeState({
    inventory_state: { ...completeState().inventory_state, items: [{ item_id: 1028 }] },
  }));
  const cloth = derive(completeState({
    inventory_state: { ...completeState().inventory_state, items: [{ item_id: 1029 }] },
  }));
  const mantle = derive(completeState({
    inventory_state: { ...completeState().inventory_state, items: [{ item_id: 1033 }] },
  }));
  assert.equal(ruby.fields.max_hp.display_value, HUD.ruby[1]);
  assert.equal(cloth.fields.armor.display_value, HUD.cloth[1]);
  assert.equal(mantle.fields.magic_resist.display_value, HUD.mantle[1]);
  assert.equal(derive(completeState()).fields.max_hp.display_value, HUD.ruby[2]);
  assert.equal(derive(completeState()).fields.armor.display_value, HUD.cloth[2]);
  assert.equal(derive(completeState()).fields.magic_resist.display_value, HUD.mantle[2]);
});

test('patch-family binding is not accepted as exact-build mechanics proof', () => {
  const output = derive(completeState({
    mechanics: mechanics({
      status: 'PATCH_FAMILY_PINNED',
      identity_proof: false,
      exact_build: null,
    }),
  }));
  assert.equal(output.max_hp, null);
  assert.equal(output.armor, null);
  assert.equal(output.magic_resist, null);
  assert.equal(output.build.exact_build_mechanics_verified, false);
  assert.equal(output.build.patch_family_is_exact_build, false);
  assert.ok(output.missing_inputs.max_hp.includes('mechanics.TRUSTED_EXACT_BUILD_BINDING'));
  assert.equal(output.fields.max_hp.status, 'MAX_HP_DERIVED_CONDITIONAL');
});

test('caller callbacks, fabricated authority objects, and payload tampering cannot establish trust', () => {
  const noVerifier = deriveHeroStatState(completeState());
  assert.equal(noVerifier.max_hp, null);
  assert.ok(noVerifier.missing_inputs.max_hp.includes('mechanics.TRUSTED_EXACT_BUILD_BINDING'));

  const tampered = completeState();
  tampered.mechanics.champions.Kayn.stats.max_hp.values_by_level['2'] = 9999;
  const tamperedOutput = derive(tampered);
  assert.equal(tamperedOutput.max_hp, null);
  assert.equal(tamperedOutput.build.exact_build_mechanics_verified, false);

  const fabricatedCallback = deriveHeroStatState(completeState(), {
    verifyMechanicsBinding: () => ({
      trusted: true,
      evidence_grade: 'VERIFIED_DERIVED_MECHANICS',
      publication_eligible: true,
    }),
  });
  const fabricatedAuthority = deriveHeroStatState(completeState(), {
    authority: {
      schema: 'HERO_STAT_INTERNAL_AUTHORITY_TOKEN_V1',
      evidence_grade: 'VERIFIED_DERIVED_MECHANICS',
      publication_eligible: true,
    },
  });
  for (const output of [fabricatedCallback, fabricatedAuthority]) {
    assert.equal(output.max_hp, null);
    assert.equal(output.fields.max_hp.publication_eligible, false);
    assert.equal(output.build.exact_build_mechanics_verified, false);
  }
});

test('every constituent state must cover the requested game_time', () => {
  const state = completeState();
  state.rune_state.game_time = 119999;
  const output = derive(state);
  for (const field of ['max_hp', 'armor', 'magic_resist']) {
    assert.equal(output.fields[field].value, null);
    assert.ok(output.fields[field].missing_inputs.includes('rune_state.covers_game_time'));
  }

  const staleLevel = completeState();
  staleLevel.level_state.game_time = 119999;
  const staleLevelOutput = derive(staleLevel);
  assert.equal(staleLevelOutput.max_hp, null);
  assert.ok(staleLevelOutput.missing_inputs.max_hp.includes('level_state.covers_game_time'));
});

test('percent and multiply operations require the trusted bound formula and execute in bound order', () => {
  const state = completeState();
  state.mechanics.items['2000'] = {
    modifiers: {
      max_hp: [
        modifier('max_hp', 10, 'ADD_FLAT'),
        modifier('max_hp', 0.1, 'ADD_PERCENT_BASE'),
        modifier('max_hp', 0.2, 'ADD_PERCENT_TOTAL'),
        modifier('max_hp', 2, 'MULTIPLY_TOTAL'),
      ],
    },
  };
  state.inventory_state.items = [{ item_id: 2000 }];
  state.mechanics.binding.payload_sha256 = mechanicsPayloadSha256(state.mechanics);
  const output = derive(state);
  assert.equal(output.max_hp, null);
  assert.ok(output.missing_inputs.max_hp.includes('mechanics.TRUSTED_EXACT_BUILD_BINDING'));

  const unsupported = completeState();
  unsupported.mechanics.formulas.stat_calculation.ALGORITHM_STAT_PIPELINE_V1
    .steps[2].semantics = 'UNPROVEN_PERCENT_SEMANTICS';
  unsupported.mechanics.binding.payload_sha256 = mechanicsPayloadSha256(unsupported.mechanics);
  const unsupportedOutput = derive(unsupported);
  assert.equal(unsupportedOutput.max_hp, null);
  assert.ok(unsupportedOutput.missing_inputs.max_hp
    .includes('mechanics.TRUSTED_EXACT_BUILD_BINDING'));
});

test('field completeness is independent and an unavailable rune input never becomes zero', () => {
  const state = completeState();
  state.rune_state.complete_for = ['max_hp', 'magic_resist'];
  const output = derive(state);
  assert.equal(output.max_hp, HUD.ruby[0]);
  assert.equal(output.armor, null);
  assert.equal(output.magic_resist, 33);
  assert.ok(output.fields.armor.missing_inputs.includes('rune_state.COMPLETE_FOR_ARMOR'));
  assert.equal(output.fields.armor.evidence, 'NOT_COMPUTABLE');
  assert.equal(output.fields.max_hp.evidence, 'ALGORITHM_CONFORMANCE_ONLY');
});

test('ambiguous inventory interval and unmapped buff each close only affected publication gates', () => {
  const state = completeState();
  state.inventory_state.ambiguous_mutation = true;
  state.buff_state.unmapped_modifier_count = 1;
  const output = derive(state);
  for (const field of ['max_hp', 'armor', 'magic_resist']) {
    assert.equal(output.fields[field].value, null);
    assert.ok(output.fields[field].missing_inputs.includes('inventory_state.unambiguous_interval'));
    assert.ok(output.fields[field].missing_inputs.includes('buff_state.unmapped_modifier_count_zero'));
  }
});

test('combat audit retains narrow direct facts without promoting derived closure', () => {
  const audit = auditDerivedCombatState({
    damage_recorded_amount_verified: true,
    damage_type_verified: true,
    heal_reported_verified: true,
    shield_generated_verified: true,
    shield_absorbed_target_total_verified: true,
    damage_stage: { stage: 'RECORDED_COMPONENT_STAGE_UNKNOWN' },
  });
  assert.deepEqual(audit.retained_direct_semantics, {
    damage_recorded_amount: true,
    heal_reported: true,
    shield_generated: true,
    shield_absorbed_target_total: true,
  });
  for (const field of [
    'damage_stage', 'damage_mitigation', 'heal_effective_overheal', 'shield_remaining', 'current_hp',
  ]) {
    assert.equal(audit[field].status, 'NOT_COMPUTABLE');
    assert.equal(audit[field].value, null);
    assert.ok(audit[field].missing_inputs.length > 0);
  }
});

test('protected Holdout access is false on every derived output', () => {
  assert.deepEqual(HOLDOUT_ACCESS, {
    read: false,
    enumerate: false,
    hash: false,
    decode: false,
    test: false,
    consume: false,
  });
  assert.deepEqual(derive(completeState()).protected_holdout_access, HOLDOUT_ACCESS);
  assert.deepEqual(auditDerivedCombatState().protected_holdout_access, HOLDOUT_ACCESS);
  assert.throws(() => parseArgs(['--input', 'C:\\evidence\\Holdout\\input.json']), /holdout/i);
  assert.throws(() => parseArgs(['--output', 'C:\\evidence\\HOLDOUT-output.json']), /holdout/i);
});

test('canonical path guard rejects a safe-looking symlink or junction into synthetic Holdout', (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hero-stat-path-guard-'));
  const forbiddenDirectory = path.join(fixtureRoot, 'synthetic-Holdout-target');
  const safeAlias = path.join(fixtureRoot, 'safe-alias');
  const forbiddenOutput = path.join(forbiddenDirectory, 'must-not-exist.json');
  fs.mkdirSync(forbiddenDirectory);
  try {
    try {
      fs.symlinkSync(
        forbiddenDirectory,
        safeAlias,
        process.platform === 'win32' ? 'junction' : 'dir',
      );
    } catch (error) {
      t.skip(`symlink/junction creation unsupported: ${error.code ?? error.message}`);
      return;
    }
    assert.throws(
      () => parseArgs(['--output', path.join(safeAlias, 'must-not-exist.json')]),
      /canonical.*holdout/i,
    );
    assert.equal(fs.existsSync(forbiddenOutput), false);
  } finally {
    fs.rmSync(fixtureRoot, { recursive: true, force: true });
  }
});
