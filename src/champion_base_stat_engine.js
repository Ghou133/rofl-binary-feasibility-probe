'use strict';

const crypto = require('node:crypto');

const EXACT_BUILD = '16.16.805.0442';
const BASE_STAT_SCOPE = 'BASE_STAT_AT_LEVEL';
const STATS = Object.freeze({
  HP: 'hp',
  HP_REGEN: 'hp_regen',
  ARMOR: 'armor',
  MAGIC_RESIST: 'magic_resist',
  AD: 'attack_damage',
  AS: 'attack_speed',
  MS: 'movement_speed',
  PRIMARY_RESOURCE: 'primary_resource',
  PRIMARY_RESOURCE_REGEN: 'primary_resource_regen',
});
const STAT_NAMES = Object.freeze(Object.keys(STATS));
const ADDITIVE_GROWTH_MODEL = 'ADDITIVE_BASE_PLUS_GROWTH_TIMES_LEVEL_DELTA_POLYNOMIAL_V1';
const ATTACK_SPEED_RATIO_MODEL = 'BASE_MODIFIER_PLUS_RATIO_TIMES_PERCENT_LEVEL_DELTA_POLYNOMIAL_V1';
const STAT_CALCULATION_REQUIREMENTS = Object.freeze({
  HP: Object.freeze({ model: ADDITIVE_GROWTH_MODEL, base_field: 'hp', growth_field: 'hp', output_unit: 'HEALTH_POINTS' }),
  HP_REGEN: Object.freeze({ model: ADDITIVE_GROWTH_MODEL, base_field: 'hp_regen', growth_field: 'hp_regen', output_unit: 'HEALTH_PER_SECOND' }),
  ARMOR: Object.freeze({ model: ADDITIVE_GROWTH_MODEL, base_field: 'armor', growth_field: 'armor', output_unit: 'ARMOR' }),
  MAGIC_RESIST: Object.freeze({ model: ADDITIVE_GROWTH_MODEL, base_field: 'magic_resist', growth_field: 'magic_resist', output_unit: 'MAGIC_RESIST' }),
  AD: Object.freeze({ model: ADDITIVE_GROWTH_MODEL, base_field: 'attack_damage', growth_field: 'attack_damage', output_unit: 'ATTACK_DAMAGE' }),
  AS: Object.freeze({ model: ATTACK_SPEED_RATIO_MODEL, base_field: 'attack_speed', ratio_field: 'attack_speed_ratio', growth_field: 'attack_speed_percent', output_unit: 'ATTACKS_PER_SECOND', growth_unit: 'PERCENT_POINTS' }),
  MS: Object.freeze({ model: ADDITIVE_GROWTH_MODEL, base_field: 'movement_speed', growth_field: 'movement_speed', output_unit: 'MOVEMENT_SPEED' }),
  PRIMARY_RESOURCE: Object.freeze({ model: ADDITIVE_GROWTH_MODEL, base_field: 'primary_resource', growth_field: 'primary_resource', output_unit: 'RESOURCE_POINTS' }),
  PRIMARY_RESOURCE_REGEN: Object.freeze({ model: ADDITIVE_GROWTH_MODEL, base_field: 'primary_resource_regen', growth_field: 'primary_resource_regen', output_unit: 'RESOURCE_PER_SECOND' }),
});

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(stableValue(value));
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function contentSha256(value) {
  return sha256(canonicalJson(value));
}

function unknownResult({ requestedBuild, championId, stat, level, missingInputs, provenance = {} }) {
  return stableValue({
    schema: 'ROFL_BASE_STAT_AT_LEVEL_V1',
    exact_build: EXACT_BUILD,
    requested_build: requestedBuild,
    champion_id: championId ?? null,
    stat: stat ?? null,
    level: level ?? null,
    value: null,
    status: 'UNKNOWN',
    evidence_grade: 'UNAVAILABLE',
    publication_eligible: false,
    missing_inputs: [...new Set(missingInputs)].sort(),
    provenance,
    state_scope: BASE_STAT_SCOPE,
    state_distinction: {
      emitted_state: 'BASE_STAT_AT_LEVEL',
      baseline_state: 'NOT_COMPUTED',
      current_state: 'NOT_COMPUTED',
      excluded_inputs: ['items', 'runes', 'persistent_modifiers', 'temporary_buffs', 'debuffs',
        'target_reductions', 'attacker_penetration', 'event_specific_modifiers'],
    },
  });
}

function sourceHashProvenance(manifest, component = 'champion') {
  const descriptorIds = new Set(manifest?.components?.[component]?.source_descriptor_ids || []);
  return (manifest?.source_inventory || [])
    .filter((row) => descriptorIds.has(row.descriptor_id)
      && row.status === 'ACCEPTED_FOR_EXACT_BUILD_NORMALIZATION')
    .map((row) => ({ descriptor_id: row.descriptor_id, sha256: row.sha256 }))
    .sort((left, right) => left.descriptor_id.localeCompare(right.descriptor_id));
}

function sameHashProvenance(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function validCalculation(metadata, stat) {
  const calculation = metadata?.stat_calculations?.[stat];
  const requirement = STAT_CALCULATION_REQUIREMENTS[stat];
  if (!calculation || typeof calculation !== 'object') return { valid: false, missing: 'stat_specific_calculation_definition' };
  const definition = {
    model: calculation.model,
    base_field: calculation.base_field,
    ratio_field: calculation.ratio_field || null,
    growth_field: calculation.growth_field,
    output_unit: calculation.output_unit,
    growth_unit: calculation.growth_unit || null,
    coefficients: calculation.coefficients,
  };
  if (calculation.model !== requirement.model
    || calculation.base_field !== requirement.base_field
    || (requirement.ratio_field && calculation.ratio_field !== requirement.ratio_field)
    || (!requirement.ratio_field && calculation.ratio_field !== undefined)
    || calculation.growth_field !== requirement.growth_field
    || calculation.output_unit !== requirement.output_unit
    || (requirement.growth_unit && calculation.growth_unit !== requirement.growth_unit)
    || (!requirement.growth_unit && calculation.growth_unit !== undefined)
    || !Array.isArray(calculation.coefficients)
    || calculation.coefficients.length === 0
    || !calculation.coefficients.every(Number.isFinite)
    || !/^[a-f0-9]{64}$/iu.test(calculation.pinned_definition_sha256 || '')
    || contentSha256(definition) !== calculation.pinned_definition_sha256.toLowerCase()) {
    return { valid: false, missing: 'pinned_stat_specific_calculation_definition' };
  }
  return { valid: true, calculation };
}

function evaluateGrowth(coefficients, level) {
  const levelDelta = level - 1;
  return coefficients.reduce((total, coefficient, power) =>
    total + coefficient * (levelDelta ** power), 0);
}

function championComponentReady(manifest) {
  const component = manifest?.components?.champion;
  const scope = component?.semantic_scope;
  return component?.status === 'VERIFIED_EXACT_BUILD_NORMALIZED'
    && Array.isArray(component.source_descriptor_ids) && component.source_descriptor_ids.length > 0
    && scope?.component === 'champion'
    && scope.coverage_status === 'COMPLETE_EXACT_BUILD_COMPONENT_COVERAGE'
    && scope.validation_status === 'VERIFIED_COMPONENT_SEMANTICS'
    && scope.evidence_grade === 'VERIFIED_DIRECT';
}

function metadataEligible(metadata, manifest) {
  const eligibility = metadata?.publication_eligibility;
  const sourceHashes = sourceHashProvenance(manifest, 'champion');
  return eligibility?.status === 'ELIGIBLE_FOR_EXACT_BUILD_BASE_STAT_DERIVATION'
    && eligibility.evidence_grade === 'VERIFIED_DIRECT'
    && metadata?.exact_build === EXACT_BUILD
    && metadata?.normalized_mechanics_content_sha256 === contentSha256(manifest)
    && sameHashProvenance(metadata?.source_hashes || [], sourceHashes);
}

function baseStatAtLevel({
  mechanicsManifest,
  mechanicsMetadata,
  championId,
  stat,
  level,
  requestedBuild = EXACT_BUILD,
} = {}) {
  const missingInputs = [];
  if (requestedBuild !== EXACT_BUILD) missingInputs.push('exact_build_request');
  if (!STAT_NAMES.includes(stat)) missingInputs.push('supported_stat');
  if (!Number.isInteger(level) || level < 1 || level > 18) missingInputs.push('level_1_to_18');
  const manifestValid = mechanicsManifest?.schema === 'ROFL_EXACT_BUILD_MECHANICS_MANIFEST_V1'
    && mechanicsManifest.exact_build === EXACT_BUILD
    && championComponentReady(mechanicsManifest);
  if (!manifestValid) missingInputs.push('normalized_exact_build_champion_mechanics');
  if (!metadataEligible(mechanicsMetadata, mechanicsManifest)) missingInputs.push('publication_eligible_hash_provenance');
  const calculationResult = validCalculation(mechanicsMetadata, stat);
  if (!calculationResult.valid) missingInputs.push(calculationResult.missing);
  const provenance = {
    normalized_mechanics_content_sha256: mechanicsManifest ? contentSha256(mechanicsManifest) : null,
    source_hashes: sourceHashProvenance(mechanicsManifest, 'champion'),
    stat_calculation: calculationResult.valid ? {
      model: calculationResult.calculation.model,
      base_field: calculationResult.calculation.base_field,
      ratio_field: calculationResult.calculation.ratio_field || null,
      growth_field: calculationResult.calculation.growth_field,
      output_unit: calculationResult.calculation.output_unit,
      growth_unit: calculationResult.calculation.growth_unit || null,
      pinned_definition_sha256: calculationResult.calculation.pinned_definition_sha256,
      coefficients: calculationResult.calculation.coefficients,
    } : null,
    publication_eligibility: mechanicsMetadata?.publication_eligibility || null,
  };
  if (missingInputs.length) return unknownResult({ requestedBuild, championId, stat, level, missingInputs, provenance });

  const champion = mechanicsManifest.components.champion.rows.find((row) => row.id === championId);
  if (!champion) return unknownResult({ requestedBuild, championId, stat, level,
    missingInputs: ['champion_exact_build_record'], provenance });
  const calculation = calculationResult.calculation;
  const baseValue = champion.base_stats?.[calculation.base_field];
  const ratioValue = calculation.ratio_field
    ? champion.base_stats?.[calculation.ratio_field] : null;
  const growthValue = champion.growth_stats?.[calculation.growth_field];
  if (!Number.isFinite(baseValue) || !Number.isFinite(growthValue)
    || (calculation.ratio_field && !Number.isFinite(ratioValue))) {
    const championFields = calculation.ratio_field
      ? `champion_${calculation.base_field}_base_and_${calculation.ratio_field}_ratio_and_${calculation.growth_field}_growth`
      : `champion_${calculation.base_field}_base_and_${calculation.growth_field}_growth`;
    return unknownResult({ requestedBuild, championId, stat, level,
      missingInputs: [championFields], provenance });
  }
  if ((stat === 'PRIMARY_RESOURCE' || stat === 'PRIMARY_RESOURCE_REGEN')
    && (typeof champion.resource_type !== 'string' || champion.resource_type.length === 0)) {
    return unknownResult({ requestedBuild, championId, stat, level,
      missingInputs: ['champion_primary_resource_type'], provenance });
  }
  const growthMultiplier = evaluateGrowth(calculation.coefficients, level);
  const value = calculation.model === ADDITIVE_GROWTH_MODEL
    ? baseValue + growthValue * growthMultiplier
    : baseValue + ratioValue * (growthValue * growthMultiplier) / 100;
  return stableValue({
    schema: 'ROFL_BASE_STAT_AT_LEVEL_V1',
    exact_build: EXACT_BUILD,
    requested_build: requestedBuild,
    champion_id: championId,
    stat,
    level,
    value,
    status: 'VERIFIED_DERIVED_MECHANICS',
    evidence_grade: 'VERIFIED_DERIVED_MECHANICS',
    publication_eligible: true,
    missing_inputs: [],
    provenance: {
      ...provenance,
      champion_source_descriptor_ids: mechanicsManifest.components.champion.source_descriptor_ids,
      champion_record_id: champion.id,
      base_value: baseValue,
      ratio_value: ratioValue,
      growth_value: growthValue,
      growth_multiplier: growthMultiplier,
      output_unit: calculation.output_unit,
      resource_type: champion.resource_type || null,
    },
    state_scope: BASE_STAT_SCOPE,
    state_distinction: {
      emitted_state: 'BASE_STAT_AT_LEVEL',
      baseline_state: 'NOT_COMPUTED',
      current_state: 'NOT_COMPUTED',
      excluded_inputs: ['items', 'runes', 'persistent_modifiers', 'temporary_buffs', 'debuffs',
        'target_reductions', 'attacker_penetration', 'event_specific_modifiers'],
    },
  });
}

module.exports = {
  BASE_STAT_SCOPE,
  EXACT_BUILD,
  STAT_NAMES,
  STATS,
  ADDITIVE_GROWTH_MODEL,
  ATTACK_SPEED_RATIO_MODEL,
  STAT_CALCULATION_REQUIREMENTS,
  baseStatAtLevel,
  canonicalJson,
  contentSha256,
};
