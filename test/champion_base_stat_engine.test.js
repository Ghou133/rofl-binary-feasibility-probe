'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  ADDITIVE_GROWTH_MODEL, ATTACK_SPEED_RATIO_MODEL, EXACT_BUILD, STAT_CALCULATION_REQUIREMENTS,
  STAT_NAMES, baseStatAtLevel, canonicalJson, contentSha256,
} = require('../src/champion_base_stat_engine');
const crypto = require('node:crypto');

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function mechanicsManifest() {
  const sourceInventory = [
    { descriptor_id: 'champion-exact', sha256: 'a'.repeat(64), status: 'ACCEPTED_FOR_EXACT_BUILD_NORMALIZATION' },
    { descriptor_id: 'item-exact', sha256: 'b'.repeat(64), status: 'ACCEPTED_FOR_EXACT_BUILD_NORMALIZATION' },
  ];
  return {
    schema: 'ROFL_EXACT_BUILD_MECHANICS_MANIFEST_V1', exact_build: EXACT_BUILD, consumer_permission: true,
    source_inventory: sourceInventory,
    components: {
      champion: {
        status: 'VERIFIED_EXACT_BUILD_NORMALIZED', source_descriptor_ids: ['champion-exact'],
        semantic_scope: { component: 'champion', coverage_status: 'COMPLETE_EXACT_BUILD_COMPONENT_COVERAGE', validation_status: 'VERIFIED_COMPONENT_SEMANTICS', evidence_grade: 'VERIFIED_DIRECT' },
        rows: [{
          id: 'Ashe', resource_type: 'MANA',
          base_stats: { hp: 630, hp_regen: 3.5, armor: 26, magic_resist: 30, attack_damage: 59, attack_speed: 0.625, attack_speed_ratio: 0.658, movement_speed: 325, primary_resource: 280, primary_resource_regen: 6.97 },
          growth_stats: { hp: 101, hp_regen: 0.55, armor: 4.7, magic_resist: 1.3, attack_damage: 2.95, attack_speed_percent: 2.5, movement_speed: 0, primary_resource: 32, primary_resource_regen: 0.4 },
        }],
      },
    },
  };
}

function calculationDefinition(stat, coefficients = [0, 1]) {
  const requirement = STAT_CALCULATION_REQUIREMENTS[stat];
  return {
    model: requirement.model,
    base_field: requirement.base_field,
    ...(requirement.ratio_field ? { ratio_field: requirement.ratio_field } : {}),
    growth_field: requirement.growth_field,
    output_unit: requirement.output_unit,
    ...(requirement.growth_unit ? { growth_unit: requirement.growth_unit } : {}),
    coefficients,
  };
}

function exactMetadata(manifest, overrides = {}) {
  const statCalculations = Object.fromEntries(STAT_NAMES.map((stat) => {
    const definition = calculationDefinition(stat, overrides[stat] || [0, 1]);
    return [stat, { ...definition, pinned_definition_sha256: sha256(canonicalJson({
      ...definition,
      ratio_field: definition.ratio_field || null,
      growth_unit: definition.growth_unit || null,
    })) }];
  }));
  return {
    exact_build: EXACT_BUILD,
    publication_eligibility: { status: 'ELIGIBLE_FOR_EXACT_BUILD_BASE_STAT_DERIVATION', evidence_grade: 'VERIFIED_DIRECT' },
    normalized_mechanics_content_sha256: contentSha256(manifest),
    source_hashes: manifest.source_inventory.filter((row) => row.descriptor_id === 'champion-exact').map(({ descriptor_id, sha256: sourceHash }) => ({ descriptor_id, sha256: sourceHash })),
    stat_calculations: statCalculations,
  };
}

test('BASE_STAT_AT_LEVEL derives all required exact-build base stats with pinned formula provenance', () => {
  const manifest = mechanicsManifest();
  const metadata = exactMetadata(manifest);
  const expectedLevelThree = { HP: 832, HP_REGEN: 4.6, ARMOR: 35.4, MAGIC_RESIST: 32.6, AD: 64.9, AS: 0.6579, MS: 325, PRIMARY_RESOURCE: 344, PRIMARY_RESOURCE_REGEN: 7.77 };
  for (const [stat, expected] of Object.entries(expectedLevelThree)) {
    const result = baseStatAtLevel({ mechanicsManifest: manifest, mechanicsMetadata: metadata, championId: 'Ashe', stat, level: 3 });
    assert.equal(result.status, 'VERIFIED_DERIVED_MECHANICS');
    assert.equal(result.evidence_grade, 'VERIFIED_DERIVED_MECHANICS');
    assert.equal(result.publication_eligible, true);
    assert.ok(Math.abs(result.value - expected) < 1e-10, stat);
    assert.equal(result.state_scope, 'BASE_STAT_AT_LEVEL');
    assert.equal(result.state_distinction.baseline_state, 'NOT_COMPUTED');
    assert.equal(result.state_distinction.current_state, 'NOT_COMPUTED');
    assert.equal(result.provenance.stat_calculation.pinned_definition_sha256, metadata.stat_calculations[stat].pinned_definition_sha256);
  }
});

test('each stat uses a supplied, pinned calculation definition rather than a remembered default', () => {
  const manifest = mechanicsManifest();
  const metadata = exactMetadata(manifest, { ARMOR: [0, 0.7, 0.0175] });
  const result = baseStatAtLevel({ mechanicsManifest: manifest, mechanicsMetadata: metadata, championId: 'Ashe', stat: 'ARMOR', level: 10 });
  assert.equal(result.status, 'VERIFIED_DERIVED_MECHANICS');
  assert.equal(result.provenance.growth_multiplier, 7.7175);
  assert.equal(result.value, 26 + 4.7 * 7.7175);
});

test('missing or unpinned stat-specific calculation fails closed', () => {
  const manifest = mechanicsManifest();
  const missing = exactMetadata(manifest); delete missing.stat_calculations.ARMOR;
  const missingResult = baseStatAtLevel({ mechanicsManifest: manifest, mechanicsMetadata: missing, championId: 'Ashe', stat: 'ARMOR', level: 3 });
  assert.equal(missingResult.value, null);
  assert.equal(missingResult.status, 'UNKNOWN');
  assert.ok(missingResult.missing_inputs.includes('stat_specific_calculation_definition'));
  const badPin = exactMetadata(manifest); badPin.stat_calculations.ARMOR.pinned_definition_sha256 = '0'.repeat(64);
  const pinResult = baseStatAtLevel({ mechanicsManifest: manifest, mechanicsMetadata: badPin, championId: 'Ashe', stat: 'ARMOR', level: 3 });
  assert.equal(pinResult.value, null);
  assert.ok(pinResult.missing_inputs.includes('pinned_stat_specific_calculation_definition'));
});

test('attack speed requires its own pinned ratio-times-percent calculation model', () => {
  const manifest = mechanicsManifest();
  const metadata = exactMetadata(manifest);
  const result = baseStatAtLevel({ mechanicsManifest: manifest, mechanicsMetadata: metadata, championId: 'Ashe', stat: 'AS', level: 3 });
  assert.equal(result.status, 'VERIFIED_DERIVED_MECHANICS');
  assert.equal(result.value, 0.625 + 0.658 * 0.05);
  assert.equal(result.provenance.ratio_value, 0.658);
  assert.equal(result.provenance.stat_calculation.model, ATTACK_SPEED_RATIO_MODEL);
  assert.equal(result.provenance.output_unit, 'ATTACKS_PER_SECOND');
  const invalid = exactMetadata(manifest);
  invalid.stat_calculations.AS.model = ADDITIVE_GROWTH_MODEL;
  const rejected = baseStatAtLevel({ mechanicsManifest: manifest, mechanicsMetadata: invalid, championId: 'Ashe', stat: 'AS', level: 3 });
  assert.equal(rejected.value, null);
  assert.ok(rejected.missing_inputs.includes('pinned_stat_specific_calculation_definition'));
});

test('publication eligibility and hash provenance are mandatory', () => {
  const manifest = mechanicsManifest();
  const metadata = exactMetadata(manifest); metadata.source_hashes[0].sha256 = '0'.repeat(64);
  const result = baseStatAtLevel({ mechanicsManifest: manifest, mechanicsMetadata: metadata, championId: 'Ashe', stat: 'HP', level: 2 });
  assert.equal(result.status, 'UNKNOWN');
  assert.equal(result.publication_eligible, false);
  assert.ok(result.missing_inputs.includes('publication_eligible_hash_provenance'));
  const ineligible = exactMetadata(manifest); ineligible.publication_eligibility.status = 'CANDIDATE';
  assert.equal(baseStatAtLevel({ mechanicsManifest: manifest, mechanicsMetadata: ineligible, championId: 'Ashe', stat: 'HP', level: 2 }).value, null);
});

test('a complete eligible champion component can publish despite incomplete unrelated components', () => {
  const manifest = mechanicsManifest();
  manifest.consumer_permission = false;
  manifest.components.item = { status: 'MISSING_REQUIRED_INPUT', source_descriptor_ids: [], rows: [] };
  const metadata = exactMetadata(manifest);
  const result = baseStatAtLevel({ mechanicsManifest: manifest, mechanicsMetadata: metadata, championId: 'Ashe', stat: 'ARMOR', level: 3 });
  assert.equal(result.status, 'VERIFIED_DERIVED_MECHANICS');
  assert.equal(result.publication_eligible, true);
});

test('missing champion fields, invalid levels, and non-exact build requests fail closed', () => {
  const manifest = mechanicsManifest();
  delete manifest.components.champion.rows[0].growth_stats.armor;
  const metadata = exactMetadata(manifest);
  const missingStat = baseStatAtLevel({ mechanicsManifest: manifest, mechanicsMetadata: metadata, championId: 'Ashe', stat: 'ARMOR', level: 3 });
  assert.equal(missingStat.value, null);
  assert.ok(missingStat.missing_inputs.includes('champion_armor_base_and_armor_growth'));
  const levelManifest = mechanicsManifest();
  const invalidLevel = baseStatAtLevel({ mechanicsManifest: levelManifest, mechanicsMetadata: exactMetadata(levelManifest), championId: 'Ashe', stat: 'HP', level: 19 });
  assert.equal(invalidLevel.value, null);
  assert.ok(invalidLevel.missing_inputs.includes('level_1_to_18'));
  const buildManifest = mechanicsManifest();
  const wrongBuild = baseStatAtLevel({ mechanicsManifest: buildManifest, mechanicsMetadata: exactMetadata(buildManifest), championId: 'Ashe', stat: 'HP', level: 2, requestedBuild: '16.16.805.0443' });
  assert.equal(wrongBuild.value, null);
  assert.ok(wrongBuild.missing_inputs.includes('exact_build_request'));
});
