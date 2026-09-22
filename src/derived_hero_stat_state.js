'use strict';

const crypto = require('node:crypto');

const HERO_STAT_STATE_SCHEMA = 'HERO_STAT_STATE_V1';
const DERIVED_COMBAT_AUDIT_SCHEMA = 'DERIVED_COMBAT_COMPUTABILITY_AUDIT_V1';
const SUPPORTED_STATS = Object.freeze(['max_hp', 'armor', 'magic_resist']);
const REQUIRED_CALCULATION_ORDER = Object.freeze([
  'BASE_AT_LEVEL',
  'ADD_FLAT',
  'ADD_PERCENT_BASE',
  'ADD_PERCENT_TOTAL',
  'MULTIPLY_TOTAL',
]);
const HOLDOUT_ACCESS = Object.freeze({
  read: false,
  enumerate: false,
  hash: false,
  decode: false,
  test: false,
  consume: false,
});
const AUTHORITY_TOKENS = new WeakMap();
const ALGORITHM_MECHANICS_ALLOWLIST = Object.freeze({
  '16e837949f292097851885329d433f5064e800ce3bac51995e6c739b6ef97b74': Object.freeze({
    exact_build: '16.16.805.0442',
    source_registry_ref: 'INTERNAL_ALGORITHM_FIXTURE_REGISTRY:V1',
    source_artifact_sha256: 'c'.repeat(64),
    registry_entry_id: 'INTERNAL_ALGORITHM_FIXTURE_ALLOWLIST',
  }),
});

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function assertObject(value, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${name} must be an object`);
  }
}

function requireExactBuild(value, name = 'exact_build') {
  if (typeof value !== 'string' || !/^\d+\.\d+\.\d+\.\d+$/.test(value)) {
    throw new Error(`${name} must be an exact four-component build`);
  }
  return value;
}

function finiteNumber(value, name) {
  if (!Number.isFinite(value)) throw new Error(`${name} must be finite`);
  return value;
}

function isSha256(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value);
}

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${stableStringify(value[key])}`
    )).join(',')}}`;
  }
  return JSON.stringify(value);
}

function mechanicsPayload(mechanics) {
  if (!mechanics || typeof mechanics !== 'object' || Array.isArray(mechanics)) return null;
  const { binding: ignoredBinding, ...payload } = mechanics;
  return payload;
}

function mechanicsPayloadSha256(mechanics) {
  const payload = mechanicsPayload(mechanics);
  if (payload === null) return null;
  return crypto.createHash('sha256').update(stableStringify(payload)).digest('hex');
}

function buildMatches(state, exactBuild) {
  return state && state.exact_build === exactBuild;
}

function completeFor(state, stat) {
  if (!state || state.status !== 'COMPLETE') return false;
  if (!Array.isArray(state.complete_for)) return true;
  return state.complete_for.includes(stat);
}

function mintAlgorithmConformanceAuthority() {
  const token = Object.freeze({ schema: 'HERO_STAT_INTERNAL_AUTHORITY_TOKEN_V1' });
  AUTHORITY_TOKENS.set(token, Object.freeze({ kind: 'ALGORITHM_CONFORMANCE' }));
  return token;
}

function verifyMechanicsTrust(mechanics, exactBuild, authority) {
  const binding = mechanics?.binding;
  const payloadSha256 = mechanicsPayloadSha256(mechanics);
  if (!binding
      || binding.status !== 'EXACT_BUILD_VERIFIED'
      || binding.identity_proof !== true
      || binding.exact_build !== exactBuild
      || typeof binding.source_registry_ref !== 'string'
      || binding.source_registry_ref.length === 0
      || !isSha256(binding.source_artifact_sha256)
      || !isSha256(binding.payload_sha256)
      || binding.payload_sha256.toLowerCase() !== payloadSha256) return null;
  const authorityRecord = authority && typeof authority === 'object'
    ? AUTHORITY_TOKENS.get(authority) : null;
  if (authorityRecord?.kind !== 'ALGORITHM_CONFORMANCE') return null;
  const pinned = ALGORITHM_MECHANICS_ALLOWLIST[payloadSha256];
  if (!pinned
      || pinned.exact_build !== exactBuild
      || pinned.source_registry_ref !== binding.source_registry_ref
      || pinned.source_artifact_sha256 !== binding.source_artifact_sha256.toLowerCase()) return null;
  return {
    trusted: true,
    authority_kind: 'ALGORITHM_CONFORMANCE',
    exact_build: exactBuild,
    payload_sha256: payloadSha256,
    source_registry_ref: pinned.source_registry_ref,
    source_artifact_sha256: pinned.source_artifact_sha256,
    registry_entry_id: pinned.registry_entry_id,
    evidence_grade: 'ALGORITHM_CONFORMANCE_ONLY',
    publication_eligible: false,
  };
}

function stateCoversTime(state, gameTime) {
  if (!state || typeof state !== 'object') return false;
  if (Number.isFinite(state.game_time)) return state.game_time === gameTime;
  return Number.isFinite(state.valid_from_time)
    && Number.isFinite(state.valid_to_time)
    && state.valid_from_time <= gameTime
    && state.valid_to_time >= gameTime;
}

function baseAtLevel(rule, level, stat, mechanics) {
  if (rule.values_by_level && hasOwn(rule.values_by_level, String(level))) {
    return finiteNumber(rule.values_by_level[String(level)], `${stat}.values_by_level[${level}]`);
  }
  const base = finiteNumber(rule.base, `${stat}.base`);
  const growth = finiteNumber(rule.growth, `${stat}.growth`);
  const levelsGained = level - 1;
  const formula = mechanics?.formulas?.growth?.[rule.growth_formula_id];
  switch (formula?.kind) {
    case 'POLYNOMIAL_LEVELS_GAINED':
      return base + growth * levelsGained * (
        finiteNumber(formula.base_coefficient, `${stat}.growth.base_coefficient`)
        + finiteNumber(formula.per_level_coefficient, `${stat}.growth.per_level_coefficient`)
          * levelsGained
      );
    case 'LINEAR_LEVELS_GAINED':
      return base + growth * levelsGained * finiteNumber(formula.coefficient, `${stat}.growth.coefficient`);
    case 'NO_GROWTH':
      if (growth !== 0) throw new Error(`${stat}.growth must be zero for NO_GROWTH`);
      return base;
    default:
      throw new Error(`${stat}.growth_formula_id is unsupported or unbound`);
  }
}

function validateCalculationRule(rule, stat, mechanics, missing) {
  if (!rule || typeof rule !== 'object') {
    missing.push(`mechanics.champion_stats.${stat}`);
    return false;
  }
  const formula = mechanics?.formulas?.stat_calculation?.[rule.calculation_formula_id];
  const expectedSteps = [
    ['BASE_AT_LEVEL', 'BOUND_BASE_VALUE'],
    ['ADD_FLAT', 'SUM_THEN_ADD_TO_RUNNING'],
    ['ADD_PERCENT_BASE', 'SUM_TIMES_BASE_THEN_ADD_TO_RUNNING'],
    ['ADD_PERCENT_TOTAL', 'MULTIPLY_RUNNING_BY_ONE_PLUS_SUM'],
    ['MULTIPLY_TOTAL', 'MULTIPLY_RUNNING_BY_PRODUCT'],
  ];
  if (!formula || !Array.isArray(formula.steps)
      || formula.steps.length !== expectedSteps.length
      || formula.steps.some((step, index) => step.operation !== expectedSteps[index][0]
        || step.semantics !== expectedSteps[index][1])) {
    missing.push(`mechanics.champion_stats.${stat}.bound_calculation_formula`);
    return false;
  }
  return true;
}

function collectModifier(modifiers, descriptor, origin, stat, exactBuild, missing) {
  if (!descriptor || typeof descriptor !== 'object') {
    missing.push(`${origin}.modifier_descriptor`);
    return;
  }
  if (descriptor.target_stat !== stat) return;
  if (descriptor.status !== 'VERIFIED' || descriptor.exact_build !== exactBuild) {
    missing.push(`${origin}.verified_exact_build_modifier`);
    return;
  }
  if (!REQUIRED_CALCULATION_ORDER.includes(descriptor.operation)
      || descriptor.operation === 'BASE_AT_LEVEL') {
    missing.push(`${origin}.supported_operation`);
    return;
  }
  if (!Number.isFinite(descriptor.value)) {
    missing.push(`${origin}.finite_value`);
    return;
  }
  modifiers.push({
    operation: descriptor.operation,
    value: descriptor.value,
    origin,
    evidence: clone(descriptor.evidence ?? null),
  });
}

function itemModifiersForStat(input, stat, exactBuild, missing) {
  const inventory = input.inventory_state;
  const mechanics = input.mechanics;
  const result = [];
  if (!completeFor(inventory, stat)) missing.push(`inventory_state.COMPLETE_FOR_${stat.toUpperCase()}`);
  if (!buildMatches(inventory, exactBuild)) missing.push('inventory_state.exact_build');
  if (inventory?.ambiguous_mutation === true) missing.push('inventory_state.unambiguous_interval');
  if (mechanics?.coverage?.item_catalog_complete !== true) missing.push('mechanics.item_catalog_complete');
  if (missing.some((value) => value.startsWith('inventory_state.')
      || value === 'mechanics.item_catalog_complete')) return result;
  if (!Array.isArray(inventory.items)) {
    missing.push('inventory_state.items');
    return result;
  }
  inventory.items.forEach((slot, index) => {
    if (!slot || slot.item_id === null || slot.item_id === undefined) return;
    const count = slot.count ?? slot.stack ?? 1;
    if (!Number.isInteger(count) || count < 1) {
      missing.push(`inventory_state.items[${index}].count`);
      return;
    }
    const item = mechanics.items?.[String(slot.item_id)];
    if (!item) {
      missing.push(`mechanics.items.${slot.item_id}`);
      return;
    }
    const descriptors = item.modifiers?.[stat] ?? [];
    if (!Array.isArray(descriptors)) {
      missing.push(`mechanics.items.${slot.item_id}.modifiers.${stat}`);
      return;
    }
    for (let copy = 0; copy < count; copy += 1) {
      descriptors.forEach((descriptor, modifierIndex) => collectModifier(
        result,
        descriptor,
        `item:${slot.item_id}:${index}:${modifierIndex}`,
        stat,
        exactBuild,
        missing,
      ));
    }
  });
  return result;
}

function stateModifiersForStat(state, stateName, stat, exactBuild, missing) {
  const result = [];
  if (!completeFor(state, stat)) missing.push(`${stateName}.COMPLETE_FOR_${stat.toUpperCase()}`);
  if (!buildMatches(state, exactBuild)) missing.push(`${stateName}.exact_build`);
  if (state?.unmapped_modifier_count !== 0) missing.push(`${stateName}.unmapped_modifier_count_zero`);
  if (!completeFor(state, stat) || !buildMatches(state, exactBuild)
      || state.unmapped_modifier_count !== 0) return result;
  if (!Array.isArray(state.modifiers)) {
    missing.push(`${stateName}.modifiers`);
    return result;
  }
  state.modifiers.forEach((descriptor, index) => collectModifier(
    result,
    descriptor,
    `${stateName}:${index}`,
    stat,
    exactBuild,
    missing,
  ));
  return result;
}

function applyModifiers(base, modifiers) {
  const byOperation = Object.fromEntries(REQUIRED_CALCULATION_ORDER.map((operation) => [operation, []]));
  modifiers.forEach((modifier) => byOperation[modifier.operation].push(modifier.value));
  let value = base;
  value += byOperation.ADD_FLAT.reduce((sum, item) => sum + item, 0);
  value += base * byOperation.ADD_PERCENT_BASE.reduce((sum, item) => sum + item, 0);
  value *= 1 + byOperation.ADD_PERCENT_TOTAL.reduce((sum, item) => sum + item, 0);
  value *= byOperation.MULTIPLY_TOTAL.reduce((product, item) => product * item, 1);
  return value;
}

function displayProjection(value, display) {
  if (!display) return { display_value: null, display_rule: null };
  if (display.rule === 'ROUND_NEAREST_INTEGER') {
    return { display_value: Math.round(value), display_rule: display.rule };
  }
  if (display.rule === 'FLOOR') return { display_value: Math.floor(value), display_rule: display.rule };
  if (display.rule === 'CEIL') return { display_value: Math.ceil(value), display_rule: display.rule };
  return { display_value: null, display_rule: null };
}

function deriveField(input, stat, exactBuild, gameTime, champion, level, mechanicsTrust) {
  const missing = [];
  const mechanics = input.mechanics;
  const championDefinition = mechanics?.champions?.[champion];
  const rule = championDefinition?.stats?.[stat];
  if (!mechanicsTrust) missing.push('mechanics.TRUSTED_EXACT_BUILD_BINDING');
  if (mechanics?.coverage?.[stat] !== true) missing.push(`mechanics.coverage.${stat}`);
  if (mechanics?.coverage?.rune_mechanics_complete !== true) missing.push('mechanics.rune_mechanics_complete');
  if (mechanics?.coverage?.buff_operation_model_complete !== true) missing.push('mechanics.buff_operation_model_complete');
  if (mechanics?.coverage?.exception_registry_complete !== true) missing.push('mechanics.exception_registry_complete');
  if (!championDefinition) missing.push(`mechanics.champions.${champion}`);
  if (championDefinition?.requires_exception_state === true) {
    if (!completeFor(input.exception_state, stat)) missing.push(`exception_state.COMPLETE_FOR_${stat.toUpperCase()}`);
    if (!buildMatches(input.exception_state, exactBuild)) missing.push('exception_state.exact_build');
  }
  validateCalculationRule(rule, stat, mechanics, missing);
  for (const [name, state] of [
    ['inventory_state', input.inventory_state],
    ['rune_state', input.rune_state],
    ['buff_state', input.buff_state],
  ]) if (!stateCoversTime(state, gameTime)) missing.push(`${name}.covers_game_time`);
  if (input.exception_state !== null && input.exception_state !== undefined
      && !stateCoversTime(input.exception_state, gameTime)) {
    missing.push('exception_state.covers_game_time');
  }
  const modifiers = [
    ...itemModifiersForStat(input, stat, exactBuild, missing),
    ...stateModifiersForStat(input.rune_state, 'rune_state', stat, exactBuild, missing),
    ...stateModifiersForStat(input.buff_state, 'buff_state', stat, exactBuild, missing),
  ];
  if (input.exception_state !== null && input.exception_state !== undefined) {
    modifiers.push(...stateModifiersForStat(
      input.exception_state, 'exception_state', stat, exactBuild, missing,
    ));
  }
  const uniqueMissing = [...new Set(missing)].sort();
  if (uniqueMissing.length > 0) {
    return {
      value: null,
      internal_value: null,
      display_value: null,
      display_rule: null,
      status: mechanicsTrust
        ? `${stat.toUpperCase()}_UNKNOWN` : `${stat.toUpperCase()}_DERIVED_CONDITIONAL`,
      evidence: 'NOT_COMPUTABLE',
      publication_eligible: false,
      missing_inputs: uniqueMissing,
      inputs: { champion, level, modifier_count: null },
      derivation: null,
    };
  }
  let base;
  try {
    base = baseAtLevel(rule, level, stat, mechanics);
  } catch (error) {
    return {
      value: null,
      internal_value: null,
      display_value: null,
      display_rule: null,
      status: `${stat.toUpperCase()}_UNKNOWN`,
      evidence: 'NOT_COMPUTABLE',
      publication_eligible: false,
      missing_inputs: [`mechanics.champion_stats.${stat}.${error.message}`],
      inputs: { champion, level, modifier_count: modifiers.length },
      derivation: null,
    };
  }
  const value = applyModifiers(base, modifiers);
  if (!Number.isFinite(value)) throw new Error(`${stat} derivation produced a non-finite value`);
  const projection = displayProjection(value, rule.display);
  return {
    value,
    internal_value: value,
    ...projection,
    status: `${stat.toUpperCase()}_DERIVED_COMPLETE`,
    evidence: mechanicsTrust.evidence_grade,
    publication_eligible: mechanicsTrust.publication_eligible === true,
    missing_inputs: [],
    inputs: { champion, level, base_at_level: base, modifier_count: modifiers.length },
    derivation: {
      growth_rule: rule.values_by_level ? 'EXACT_LEVEL_LOOKUP' : rule.growth_formula_id,
      calculation_formula_id: rule.calculation_formula_id,
      calculation_order: mechanics.formulas.stat_calculation[rule.calculation_formula_id]
        .steps.map((step) => step.operation),
      modifiers,
      mechanics_trust: clone(mechanicsTrust),
    },
  };
}

function deriveHeroStatState(input, options = {}) {
  assertObject(input, 'input');
  assertObject(options, 'options');
  const exactBuild = requireExactBuild(input.exact_build);
  const gameTime = finiteNumber(input.game_time, 'game_time');
  if (gameTime < 0) throw new Error('game_time must be non-negative');
  const champion = input.champion_identity?.champion ?? input.entity?.champion ?? null;
  const level = input.level_state?.level;
  const mechanicsTrust = verifyMechanicsTrust(input.mechanics, exactBuild, options.authority);
  const commonMissing = [];
  if (typeof champion !== 'string' || champion.length === 0) commonMissing.push('champion_identity');
  if (!stateCoversTime(input.champion_identity, gameTime)) commonMissing.push('champion_identity.covers_game_time');
  if (!Number.isInteger(level) || level < 1 || level > 18) commonMissing.push('level_state.level_1_to_18');
  if (!completeFor(input.level_state, 'level')) commonMissing.push('level_state.COMPLETE');
  if (!buildMatches(input.level_state, exactBuild)) commonMissing.push('level_state.exact_build');
  if (!stateCoversTime(input.level_state, gameTime)) commonMissing.push('level_state.covers_game_time');

  const fields = {};
  for (const stat of SUPPORTED_STATS) {
    if (commonMissing.length > 0) {
      fields[stat] = {
        value: null,
        internal_value: null,
        display_value: null,
        display_rule: null,
        status: `${stat.toUpperCase()}_UNKNOWN`,
        evidence: 'NOT_COMPUTABLE',
        publication_eligible: false,
        missing_inputs: [...new Set(commonMissing)].sort(),
        inputs: { champion, level: Number.isInteger(level) ? level : null, modifier_count: null },
        derivation: null,
      };
    } else {
      fields[stat] = deriveField(
        input, stat, exactBuild, gameTime, champion, level, mechanicsTrust,
      );
    }
  }
  return {
    schema: HERO_STAT_STATE_SCHEMA,
    schema_version: 1,
    game_time: gameTime,
    entity: clone(input.entity ?? null),
    exact_build: exactBuild,
    build: {
      replay_exact_build: exactBuild,
      mechanics_binding: clone(input.mechanics?.binding ?? null),
      exact_build_mechanics_verified: mechanicsTrust !== null,
      mechanics_trust_attestation: clone(mechanicsTrust),
      patch_family_is_exact_build: false,
    },
    max_hp: fields.max_hp.value,
    armor: fields.armor.value,
    magic_resist: fields.magic_resist.value,
    fields,
    inputs: {
      champion_identity: clone(input.champion_identity ?? null),
      level_state: clone(input.level_state ?? null),
      inventory_state: clone(input.inventory_state ?? null),
      rune_state: clone(input.rune_state ?? null),
      buff_state: clone(input.buff_state ?? null),
      exception_state: clone(input.exception_state ?? null),
    },
    missing_inputs: Object.fromEntries(SUPPORTED_STATS.map((stat) => [stat, fields[stat].missing_inputs])),
    evidence: Object.fromEntries(SUPPORTED_STATS.map((stat) => [stat, fields[stat].evidence])),
    derivation: Object.fromEntries(SUPPORTED_STATS.map((stat) => [stat, fields[stat].derivation])),
    protected_holdout_access: { ...HOLDOUT_ACCESS },
  };
}

function gate(name, ready, missing, availableStatus = 'DERIVABLE_NOW') {
  return {
    capability: name,
    status: ready ? availableStatus : 'NOT_COMPUTABLE',
    value: null,
    missing_inputs: [...new Set(missing)].sort(),
  };
}

function auditDerivedCombatState(input = {}) {
  assertObject(input, 'combat audit input');
  const stage = input.damage_stage ?? {};
  const stageMissing = [];
  if (stage.exact_build_verified !== true) stageMissing.push('damage_stage.exact_build_verified');
  if (stage.static_dataflow_edge_verified !== true) stageMissing.push('damage_stage.static_dataflow_edge_verified');
  if (stage.behavior_and_counterexamples_pass !== true) stageMissing.push('damage_stage.behavior_and_counterexamples_pass');
  if (!['RAW_PRE_MITIGATION', 'POST_MITIGATION', 'POST_SHIELD', 'APPLIED_TO_HEALTH',
    'HEALTH_OR_SHIELD_COMPONENT', 'DISPLAY_AMOUNT', 'OTHER'].includes(stage.stage)) {
    stageMissing.push('damage_stage.named_stage');
  }
  const stageReady = stageMissing.length === 0;

  const mitigationMissing = [];
  if (!stageReady) mitigationMissing.push('damage_stage');
  if (input.damage_type_verified !== true) mitigationMissing.push('damage_type_verified');
  if (input.target_defense_complete !== true) mitigationMissing.push('target_defense_complete');
  if (input.exact_build_combat_formula_verified !== true) mitigationMissing.push('exact_build_combat_formula_verified');
  if (input.penetration_and_reduction_state_complete !== true) mitigationMissing.push('penetration_and_reduction_state_complete');
  if (input.hp_shield_ordering_complete !== true) mitigationMissing.push('hp_shield_ordering_complete');

  const healMissing = [];
  if (input.heal_application_semantics_verified !== true) healMissing.push('heal_application_semantics_verified');
  if (input.health_before_anchor_verified !== true) healMissing.push('health_before_anchor_verified');
  if (input.health_after_anchor_verified !== true) healMissing.push('health_after_anchor_verified');
  if (input.max_hp_complete !== true) healMissing.push('max_hp_complete');
  if (input.intervening_hp_events_complete !== true) healMissing.push('intervening_hp_events_complete');

  const shieldMissing = [];
  if (input.shield_generated_verified !== true) shieldMissing.push('shield_generated_verified');
  if (input.shield_absorbed_target_total_verified !== true) shieldMissing.push('shield_absorbed_target_total_verified');
  if (input.shield_instance_identity_complete !== true) shieldMissing.push('shield_instance_identity_complete');
  if (input.shield_lifecycle_complete !== true) shieldMissing.push('shield_lifecycle_complete');
  if (input.shield_layer_ordering_complete !== true) shieldMissing.push('shield_layer_ordering_complete');

  const hpMissing = [];
  for (const required of [
    'absolute_health_anchor_verified',
    'damage_applied_to_health_complete',
    'effective_heal_complete',
    'regen_complete',
    'death_respawn_ordering_complete',
    'shield_temporary_health_ordering_complete',
    'all_hp_mutation_families_complete',
  ]) if (input[required] !== true) hpMissing.push(required);

  return {
    schema: DERIVED_COMBAT_AUDIT_SCHEMA,
    schema_version: 1,
    damage_stage: gate('DAMAGE_STAGE', stageReady, stageMissing),
    damage_mitigation: gate('DAMAGE_MITIGATION', mitigationMissing.length === 0, mitigationMissing),
    heal_effective_overheal: gate('HEAL_EFFECTIVE_OVERHEAL', healMissing.length === 0, healMissing),
    shield_remaining: gate('SHIELD_REMAINING', shieldMissing.length === 0, shieldMissing),
    current_hp: gate('CURRENT_HP_DERIVED_STATE', hpMissing.length === 0, hpMissing),
    retained_direct_semantics: {
      damage_recorded_amount: input.damage_recorded_amount_verified === true,
      heal_reported: input.heal_reported_verified === true,
      shield_generated: input.shield_generated_verified === true,
      shield_absorbed_target_total: input.shield_absorbed_target_total_verified === true,
    },
    protected_holdout_access: { ...HOLDOUT_ACCESS },
  };
}

module.exports = {
  DERIVED_COMBAT_AUDIT_SCHEMA,
  HERO_STAT_STATE_SCHEMA,
  HOLDOUT_ACCESS,
  REQUIRED_CALCULATION_ORDER,
  SUPPORTED_STATS,
  auditDerivedCombatState,
  deriveHeroStatState,
  mechanicsPayloadSha256,
  mintAlgorithmConformanceAuthority,
  stateCoversTime,
};
