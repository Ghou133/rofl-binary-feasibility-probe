'use strict';

const crypto = require('node:crypto');

const EXACT_BUILD = '16.16.805.0442';
const SCHEMA = 'ROFL_DYNAMIC_DEFENSE_EVENT_STATE_V1';

// A direct final-defense row may only be published after an exact row attestation
// is registered in code.  There is no verified direct Armor/MR output for this
// build yet, so the registry is intentionally empty and caller assertions cannot
// create publication authority.
const DIRECT_EFFECTIVE_OUTPUT_REGISTRY = Object.freeze({});
const STATE_EVIDENCE_CONTRACT_REGISTRY = Object.freeze({});

const HOLDOUT_ACCESS = Object.freeze({
  read: false,
  enumerate: false,
  hash: false,
  decode: false,
  test: false,
  consume: false,
});

const OPERATION_TAXONOMY = Object.freeze({
  TARGET_REDUCTION: Object.freeze(['TARGET_FLAT_REDUCTION', 'TARGET_PERCENT_REDUCTION']),
  ATTACKER_PENETRATION: Object.freeze([
    'ATTACKER_FLAT_PENETRATION',
    'ATTACKER_PERCENT_PENETRATION',
  ]),
  EVENT_MODIFIER: Object.freeze([
    'EVENT_ADD_FLAT',
    'EVENT_SUBTRACT_FLAT',
    'EVENT_ADD_PERCENT',
    'EVENT_SUBTRACT_PERCENT',
    'EVENT_MULTIPLY',
    'EVENT_OVERRIDE',
    'EVENT_CAP',
    'EVENT_FLOOR',
  ]),
  LIFECYCLE: Object.freeze(['ADD', 'UPDATE', 'REMOVE', 'REPLACE']),
});

const OPERATION_SEMANTICS = Object.freeze({
  TARGET_FLAT_REDUCTION: 'SUBTRACT_AMOUNT_FROM_RUNNING_DEFENSE',
  TARGET_PERCENT_REDUCTION: 'MULTIPLY_RUNNING_DEFENSE_BY_ONE_MINUS_AMOUNT',
  ATTACKER_FLAT_PENETRATION: 'SUBTRACT_AMOUNT_FROM_RUNNING_DEFENSE',
  ATTACKER_PERCENT_PENETRATION: 'MULTIPLY_RUNNING_DEFENSE_BY_ONE_MINUS_AMOUNT',
  EVENT_ADD_FLAT: 'ADD_AMOUNT_TO_RUNNING_DEFENSE',
  EVENT_SUBTRACT_FLAT: 'SUBTRACT_AMOUNT_FROM_RUNNING_DEFENSE',
  EVENT_ADD_PERCENT: 'MULTIPLY_RUNNING_DEFENSE_BY_ONE_PLUS_AMOUNT',
  EVENT_SUBTRACT_PERCENT: 'MULTIPLY_RUNNING_DEFENSE_BY_ONE_MINUS_AMOUNT',
  EVENT_MULTIPLY: 'MULTIPLY_RUNNING_DEFENSE_BY_AMOUNT',
  EVENT_OVERRIDE: 'REPLACE_RUNNING_DEFENSE_WITH_AMOUNT',
  EVENT_CAP: 'MINIMUM_OF_RUNNING_DEFENSE_AND_AMOUNT',
  EVENT_FLOOR: 'MAXIMUM_OF_RUNNING_DEFENSE_AND_AMOUNT',
});

const ALL_EFFECT_OPERATIONS = Object.freeze(Object.keys(OPERATION_SEMANTICS));

function clone(value) {
  return value === undefined ? undefined : structuredClone(value);
}

function hasText(value) {
  return typeof value === 'string' && value.length > 0;
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort()
    .map((key) => [key, stableValue(value[key])]));
  return value;
}

function directRecordSha256(record) {
  const attested = {
    status: record?.status,
    semantic: record?.semantic,
    value: record?.value,
    exact_build: record?.exact_build,
    game_time: record?.game_time,
    event_id: record?.event_id,
    source_entity_id: record?.source_entity_id,
    target_entity_id: record?.target_entity_id,
    evidence_grade: record?.evidence_grade,
    provenance: record?.provenance,
  };
  return crypto.createHash('sha256').update(JSON.stringify(stableValue(attested))).digest('hex');
}

function stateRecordSha256(record) {
  return crypto.createHash('sha256').update(JSON.stringify(stableValue(record))).digest('hex');
}

function timeAligned(record, gameTime) {
  if (!record || typeof record !== 'object') return false;
  if (Number.isFinite(record.game_time)) return record.game_time === gameTime;
  return Number.isFinite(record.valid_from_time)
    && Number.isFinite(record.valid_to_time)
    && record.valid_from_time <= gameTime
    && record.valid_to_time >= gameTime;
}

function field(value, status, evidenceGrade, missingInputs, provenance = null,
  publicationEligible = false) {
  return {
    value,
    status,
    evidence_grade: evidenceGrade,
    publication_eligible: publicationEligible === true,
    missing_inputs: uniqueSorted(missingInputs),
    provenance: clone(provenance),
  };
}

function recordPublicationEligible(record) {
  const contract = hasText(record?.evidence_contract_id)
    ? STATE_EVIDENCE_CONTRACT_REGISTRY[record.evidence_contract_id] : null;
  return Boolean(contract)
    && contract.exact_build === EXACT_BUILD
    && contract.record_sha256 === stateRecordSha256(record)
    && record?.provenance?.source_artifact_sha256 === contract.source_artifact_sha256
    && record?.provenance?.decoder_profile_id === contract.decoder_profile_id
    && record?.provenance?.decoder_profile_sha256 === contract.decoder_profile_sha256
    && record?.publication_eligible === true
    && record.evidence_grade !== 'ALGORITHM_CONFORMANCE_ONLY'
    && record.synthetic !== true;
}

function mechanicsPublicationEligible(binding) {
  return recordPublicationEligible(binding)
    && binding.evidence_grade === 'VERIFIED_EXACT_BUILD_MECHANICS'
    && binding.verification_scope === 'PUBLICATION'
    && /^[0-9a-f]{64}$/i.test(binding.provenance?.source_artifact_sha256 ?? '');
}

function inspectScalarState(record, name, context, entityRole) {
  const missing = [];
  if (!record || typeof record !== 'object') return field(null, 'UNKNOWN', 'NOT_COMPUTABLE', [name]);
  if (record.status !== 'COMPLETE') missing.push(`${name}.status_COMPLETE`);
  if (!Number.isFinite(record.value)) missing.push(`${name}.finite_value`);
  if (record.exact_build !== EXACT_BUILD || record.exact_build !== context.exactBuild) {
    missing.push(`${name}.exact_build`);
  }
  if (!timeAligned(record, context.gameTime)) missing.push(`${name}.covers_game_time`);
  if (record.entity_id !== context[entityRole]) missing.push(`${name}.${entityRole}`);
  if (!hasText(record.evidence_grade)) missing.push(`${name}.evidence_grade`);
  if (!record.provenance || typeof record.provenance !== 'object') missing.push(`${name}.provenance`);
  return missing.length > 0
    ? field(null, 'UNKNOWN', 'NOT_COMPUTABLE', missing, record.provenance)
    : field(record.value, 'COMPLETE', record.evidence_grade, [], record.provenance,
      recordPublicationEligible(record));
}

function inspectOperationState(record, name, context, entityRole, allowedOperations) {
  const missing = [];
  if (!record || typeof record !== 'object') {
    return { ...field(null, 'UNKNOWN', 'NOT_COMPUTABLE', [name]), operations: [] };
  }
  if (record.status !== 'COMPLETE') missing.push(`${name}.status_COMPLETE`);
  if (record.exact_build !== EXACT_BUILD || record.exact_build !== context.exactBuild) {
    missing.push(`${name}.exact_build`);
  }
  if (!timeAligned(record, context.gameTime)) missing.push(`${name}.covers_game_time`);
  if (record.entity_id !== context[entityRole]) missing.push(`${name}.${entityRole}`);
  if (!hasText(record.evidence_grade)) missing.push(`${name}.evidence_grade`);
  if (!record.provenance || typeof record.provenance !== 'object') missing.push(`${name}.provenance`);
  if (!Array.isArray(record.operations)) {
    missing.push(`${name}.operations`);
  } else {
    record.operations.forEach((operation, index) => {
      if (!operation || !allowedOperations.includes(operation.operation)) {
        missing.push(`${name}.operations[${index}].operation_taxonomy`);
      }
      if (!Number.isFinite(operation?.amount)) missing.push(`${name}.operations[${index}].finite_amount`);
      if (!hasText(operation?.evidence_grade)) missing.push(`${name}.operations[${index}].evidence_grade`);
      if (!operation?.provenance || typeof operation.provenance !== 'object') {
        missing.push(`${name}.operations[${index}].provenance`);
      }
    });
  }
  return {
    ...field(null, missing.length > 0 ? 'UNKNOWN' : 'COMPLETE',
      missing.length > 0 ? 'NOT_COMPUTABLE' : record.evidence_grade,
      missing, record.provenance,
      missing.length === 0 && recordPublicationEligible(record)
        && record.operations.every(recordPublicationEligible)),
    operations: missing.length > 0 ? [] : clone(record.operations),
  };
}

function inspectEventModifiers(record, name, context) {
  const result = inspectOperationState(
    record, name, context, 'targetEntityId', OPERATION_TAXONOMY.EVENT_MODIFIER,
  );
  const missing = [...result.missing_inputs];
  if (record && record.source_entity_id !== context.sourceEntityId) {
    missing.push(`${name}.sourceEntityId`);
  }
  if (record && record.event_id !== context.eventId) missing.push(`${name}.event_id`);
  return missing.length === 0 ? result : {
    ...result,
    status: 'UNKNOWN',
    evidence_grade: 'NOT_COMPUTABLE',
    missing_inputs: uniqueSorted(missing),
    operations: [],
  };
}

function inspectMechanicsBinding(binding, damageClass, context, requiredOperations) {
  const name = 'mechanics_binding';
  const missing = [];
  if (!binding || typeof binding !== 'object') {
    return { ...field(null, 'UNKNOWN', 'NOT_COMPUTABLE', [name]), steps: [] };
  }
  if (binding.status !== 'EXACT_BUILD_VERIFIED') missing.push(`${name}.status_EXACT_BUILD_VERIFIED`);
  if (binding.identity_proof !== true) missing.push(`${name}.identity_proof`);
  if (binding.exact_build !== EXACT_BUILD || binding.exact_build !== context.exactBuild) {
    missing.push(`${name}.exact_build`);
  }
  if (!hasText(binding.evidence_grade)) missing.push(`${name}.evidence_grade`);
  if (!binding.provenance || typeof binding.provenance !== 'object') missing.push(`${name}.provenance`);
  const definition = binding.defense_order?.[damageClass];
  if (!definition || definition.ordering_complete !== true || !Array.isArray(definition.steps)) {
    missing.push(`${name}.defense_order.${damageClass}.ordering_complete`);
  } else {
    const seen = new Set();
    definition.steps.forEach((step, index) => {
      if (!step || !ALL_EFFECT_OPERATIONS.includes(step.operation) || seen.has(step.operation)) {
        missing.push(`${name}.defense_order.${damageClass}.steps[${index}].operation_taxonomy`);
      } else {
        seen.add(step.operation);
        if (step.semantics !== OPERATION_SEMANTICS[step.operation]) {
          missing.push(`${name}.defense_order.${damageClass}.steps[${index}].verified_semantics`);
        }
      }
    });
    requiredOperations.forEach((operation) => {
      if (!seen.has(operation)) missing.push(`${name}.defense_order.${damageClass}.missing_${operation}`);
    });
  }
  return {
    ...field(null, missing.length > 0 ? 'UNKNOWN' : 'COMPLETE',
      missing.length > 0 ? 'NOT_COMPUTABLE' : binding.evidence_grade,
      missing, binding.provenance,
      missing.length === 0 && mechanicsPublicationEligible(binding)),
    steps: missing.length > 0 ? [] : clone(definition.steps),
  };
}

function applyOperation(value, operation, amount) {
  switch (operation) {
    case 'TARGET_FLAT_REDUCTION':
    case 'ATTACKER_FLAT_PENETRATION':
    case 'EVENT_SUBTRACT_FLAT': return value - amount;
    case 'TARGET_PERCENT_REDUCTION':
    case 'ATTACKER_PERCENT_PENETRATION':
    case 'EVENT_SUBTRACT_PERCENT': return value * (1 - amount);
    case 'EVENT_ADD_FLAT': return value + amount;
    case 'EVENT_ADD_PERCENT': return value * (1 + amount);
    case 'EVENT_MULTIPLY': return value * amount;
    case 'EVENT_OVERRIDE': return amount;
    case 'EVENT_CAP': return Math.min(value, amount);
    case 'EVENT_FLOOR': return Math.max(value, amount);
    default: throw new Error(`unsupported defense operation: ${operation}`);
  }
}

function inspectDirectEffective(record, name, context) {
  const missing = [];
  if (!record) return field(null, 'ABSENT', 'NO_DIRECT_OBSERVATION', [], null);
  const contractId = record.direct_output_contract_id;
  const contract = hasText(contractId) ? DIRECT_EFFECTIVE_OUTPUT_REGISTRY[contractId] : null;
  if (!contract) missing.push(`${name}.registered_exact_build_direct_output_contract`);
  if (contract) {
    if (contract.exact_build !== EXACT_BUILD) missing.push(`${name}.contract_exact_build`);
    if (contract.input_name !== name) missing.push(`${name}.contract_input_name`);
    if (contract.record_sha256 !== directRecordSha256(record)) {
      missing.push(`${name}.record_attestation_sha256`);
    }
    if (record.provenance?.source_artifact_sha256 !== contract.source_artifact_sha256) {
      missing.push(`${name}.registered_source_artifact_sha256`);
    }
    if (record.provenance?.decoder_profile_id !== contract.decoder_profile_id
        || record.provenance?.decoder_profile_sha256 !== contract.decoder_profile_sha256) {
      missing.push(`${name}.registered_decoder_profile`);
    }
  }
  if (record.status !== 'COMPLETE') missing.push(`${name}.status_COMPLETE`);
  if (record.semantic !== 'FINAL_FORMULA_OUTPUT') missing.push(`${name}.semantic_FINAL_FORMULA_OUTPUT`);
  if (!Number.isFinite(record.value)) missing.push(`${name}.finite_value`);
  if (record.exact_build !== EXACT_BUILD || record.exact_build !== context.exactBuild) {
    missing.push(`${name}.exact_build`);
  }
  if (record.game_time !== context.gameTime) missing.push(`${name}.game_time`);
  if (record.event_id !== context.eventId) missing.push(`${name}.event_id`);
  if (record.source_entity_id !== context.sourceEntityId) missing.push(`${name}.sourceEntityId`);
  if (record.target_entity_id !== context.targetEntityId) missing.push(`${name}.targetEntityId`);
  if (record.evidence_grade !== 'VERIFIED_DIRECT') missing.push(`${name}.evidence_grade_VERIFIED_DIRECT`);
  if (!record.provenance || typeof record.provenance !== 'object') missing.push(`${name}.provenance`);
  return missing.length > 0
    ? field(null, 'UNKNOWN', 'NOT_COMPUTABLE', missing, record.provenance)
    : field(record.value, 'VERIFIED_DIRECT', 'VERIFIED_DIRECT', [], record.provenance, true);
}

function reconstructDefense({ damageClass, current, reduction, penetration, modifiers, binding }) {
  const missing = uniqueSorted([
    ...current.missing_inputs,
    ...reduction.missing_inputs,
    ...penetration.missing_inputs,
    ...modifiers.missing_inputs,
    ...binding.missing_inputs,
  ]);
  if (missing.length > 0) return {
    ...field(null, 'UNKNOWN', 'NOT_COMPUTABLE', missing),
    calculation_trace: [],
  };
  const all = [...reduction.operations, ...penetration.operations, ...modifiers.operations];
  let value = current.value;
  const calculationTrace = [];
  for (const step of binding.steps) {
    all.filter((operation) => operation.operation === step.operation).forEach((operation) => {
      const before = value;
      value = applyOperation(value, operation.operation, operation.amount);
      calculationTrace.push({
        operation: operation.operation,
        semantics: step.semantics,
        amount: operation.amount,
        before,
        after: value,
        evidence_grade: operation.evidence_grade,
        provenance: clone(operation.provenance),
      });
    });
  }
  if (!Number.isFinite(value)) {
    return {
      ...field(null, 'UNKNOWN', 'NOT_COMPUTABLE', [`${damageClass}.finite_result`]),
      calculation_trace: calculationTrace,
    };
  }
  const publicationEligible = current.publication_eligible
    && reduction.publication_eligible
    && penetration.publication_eligible
    && modifiers.publication_eligible
    && binding.publication_eligible;
  const conformanceOnly = [current, reduction, penetration, modifiers, binding]
    .some((record) => record.evidence_grade === 'ALGORITHM_CONFORMANCE_ONLY');
  return {
    ...field(value,
      publicationEligible ? 'VERIFIED_DERIVED_MECHANICS' : 'CONDITIONALLY_DERIVED',
      publicationEligible ? 'VERIFIED_DERIVED_MECHANICS'
        : (conformanceOnly ? 'ALGORITHM_CONFORMANCE_ONLY' : 'CONDITIONALLY_DERIVED'),
      [], { mechanics: binding.provenance }, publicationEligible),
    publication_blockers: publicationEligible ? [] : uniqueSorted([
      ...(!current.publication_eligible ? ['current_state.not_publication_eligible'] : []),
      ...(!reduction.publication_eligible ? ['target_reduction.not_publication_eligible'] : []),
      ...(!penetration.publication_eligible ? ['attacker_penetration.not_publication_eligible'] : []),
      ...(!modifiers.publication_eligible ? ['event_modifiers.not_publication_eligible'] : []),
      ...(!binding.publication_eligible ? ['mechanics_binding.not_publication_eligible'] : []),
    ]),
    calculation_trace: calculationTrace,
  };
}

function defensePath(input, stat, context) {
  const upper = stat === 'armor' ? 'ARMOR' : 'MR';
  const damageClass = stat === 'armor' ? 'physical' : 'magic';
  const reductionName = stat === 'armor' ? 'armor_reduction_state' : 'magic_resist_reduction_state';
  const penetrationName = stat === 'armor'
    ? 'attacker_armor_pen_state' : 'attacker_magic_pen_state';
  const current = inspectScalarState(input[`current_${stat}_state`], `current_${stat}_state`, context,
    'targetEntityId');
  const reduction = inspectOperationState(input[reductionName], reductionName, context,
    'targetEntityId', OPERATION_TAXONOMY.TARGET_REDUCTION);
  const penetration = inspectOperationState(input[penetrationName], penetrationName, context,
    'sourceEntityId', OPERATION_TAXONOMY.ATTACKER_PENETRATION);
  const modifiers = inspectEventModifiers(input[`${stat}_event_modifier_state`],
    `${stat}_event_modifier_state`, context);
  const requiredOperations = [...reduction.operations, ...penetration.operations, ...modifiers.operations]
    .map((operation) => operation.operation);
  const binding = inspectMechanicsBinding(input.mechanics_binding, damageClass, context,
    requiredOperations);
  const reconstruction = reconstructDefense({
    damageClass, current, reduction, penetration, modifiers, binding,
  });
  const direct = inspectDirectEffective(input[`direct_effective_${stat}`],
    `direct_effective_${stat}`, context);
  const selected = direct.status === 'VERIFIED_DIRECT' ? direct : reconstruction;
  return {
    semantic: `EFFECTIVE_${upper}_FOR_DAMAGE_EVENT`,
    ...selected,
    selected_source: direct.status === 'VERIFIED_DIRECT' ? 'DIRECT_FINAL_FORMULA_OUTPUT' : 'RECONSTRUCTION',
    direct_final_formula_output: direct,
    reconstruction: {
      ...reconstruction,
      cross_validation_delta: direct.status === 'VERIFIED_DIRECT'
        && reconstruction.value !== null ? direct.value - reconstruction.value : null,
    },
    inputs: { current, target_reduction: reduction, attacker_penetration: penetration, event_modifiers: modifiers,
      mechanics_order: binding },
  };
}

function effectiveDefenseForDamageEvent(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('input must be an object');
  }
  const event = input.damage_event;
  if (!event || typeof event !== 'object') throw new TypeError('damage_event must be an object');
  const context = {
    exactBuild: input.exact_build,
    eventId: event.event_id,
    sourceEntityId: event.source_entity_id,
    targetEntityId: event.target_entity_id,
    gameTime: event.game_time,
  };
  const eventMissing = [];
  if (input.exact_build !== EXACT_BUILD) eventMissing.push('exact_build_16.16.805.0442');
  if (!hasText(context.eventId)) eventMissing.push('damage_event.event_id');
  if (!hasText(context.sourceEntityId)) eventMissing.push('damage_event.source_entity_id');
  if (!hasText(context.targetEntityId)) eventMissing.push('damage_event.target_entity_id');
  if (!Number.isFinite(context.gameTime)) eventMissing.push('damage_event.game_time');
  if (!['PHYSICAL', 'MAGIC', 'TRUE'].includes(event.damage_type)) {
    eventMissing.push('damage_event.damage_type');
  }
  if (eventMissing.length > 0) {
    const unknown = field(null, 'UNKNOWN', 'NOT_COMPUTABLE', eventMissing);
    return {
      schema: SCHEMA,
      exact_build: input.exact_build ?? null,
      damage_event: clone(event),
      damage_recorded_amount: clone(event.recorded_amount),
      damage_stage: clone(event.damage_stage),
      EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT: clone(unknown),
      EFFECTIVE_MR_FOR_DAMAGE_EVENT: clone(unknown),
      defense_bypass: null,
      protected_holdout_access: { ...HOLDOUT_ACCESS },
    };
  }

  const baseArmor = inspectScalarState(input.base_armor_at_level, 'base_armor_at_level', context,
    'targetEntityId');
  const baselineArmor = inspectScalarState(input.baseline_armor_state, 'baseline_armor_state', context,
    'targetEntityId');
  const currentArmor = inspectScalarState(input.current_armor_state, 'current_armor_state', context,
    'targetEntityId');
  const baseMr = inspectScalarState(input.base_magic_resist_at_level,
    'base_magic_resist_at_level', context, 'targetEntityId');
  const baselineMr = inspectScalarState(input.baseline_magic_resist_state,
    'baseline_magic_resist_state', context, 'targetEntityId');
  const currentMr = inspectScalarState(input.current_magic_resist_state,
    'current_magic_resist_state', context, 'targetEntityId');
  const armorReduction = inspectOperationState(input.armor_reduction_state,
    'armor_reduction_state', context, 'targetEntityId', OPERATION_TAXONOMY.TARGET_REDUCTION);
  const magicResistReduction = inspectOperationState(input.magic_resist_reduction_state,
    'magic_resist_reduction_state', context, 'targetEntityId',
    OPERATION_TAXONOMY.TARGET_REDUCTION);
  const attackerArmorPen = inspectOperationState(input.attacker_armor_pen_state,
    'attacker_armor_pen_state', context, 'sourceEntityId',
    OPERATION_TAXONOMY.ATTACKER_PENETRATION);
  const attackerMagicPen = inspectOperationState(input.attacker_magic_pen_state,
    'attacker_magic_pen_state', context, 'sourceEntityId',
    OPERATION_TAXONOMY.ATTACKER_PENETRATION);

  let armor = field(null, 'NOT_APPLICABLE', 'NOT_APPLICABLE', []);
  let magicResist = field(null, 'NOT_APPLICABLE', 'NOT_APPLICABLE', []);
  let bypass = null;
  if (event.damage_type === 'PHYSICAL') armor = defensePath(input, 'armor', context);
  if (event.damage_type === 'MAGIC') magicResist = defensePath(input, 'magic_resist', context);
  if (event.damage_type === 'TRUE') {
    bypass = {
      status: 'VERIFIED_EXPLICIT_BYPASS',
      bypasses_armor: true,
      bypasses_magic_resist: true,
      effective_defense_value: null,
      semantics: 'TRUE_DAMAGE_DOES_NOT_USE_ARMOR_OR_MAGIC_RESIST',
      evidence_grade: event.damage_type_evidence_grade ?? 'VERIFIED_DIRECT',
      missing_inputs: [],
    };
    armor = field(null, 'BYPASSED_BY_TRUE_DAMAGE', bypass.evidence_grade, []);
    magicResist = field(null, 'BYPASSED_BY_TRUE_DAMAGE', bypass.evidence_grade, []);
  }

  return {
    schema: SCHEMA,
    schema_version: 1,
    exact_build: EXACT_BUILD,
    damage_event: clone(event),
    damage_recorded_amount: clone(event.recorded_amount),
    damage_stage: clone(event.damage_stage),
    BASE_ARMOR_AT_LEVEL: baseArmor,
    BASELINE_ARMOR_STATE: baselineArmor,
    CURRENT_ARMOR_STATE: currentArmor,
    BASE_MAGIC_RESIST_AT_LEVEL: baseMr,
    BASELINE_MAGIC_RESIST_STATE: baselineMr,
    CURRENT_MAGIC_RESIST_STATE: currentMr,
    ARMOR_REDUCTION_STATE: armorReduction,
    MAGIC_RESIST_REDUCTION_STATE: magicResistReduction,
    ATTACKER_ARMOR_PEN_STATE: attackerArmorPen,
    ATTACKER_MAGIC_PEN_STATE: attackerMagicPen,
    EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT: armor,
    EFFECTIVE_MR_FOR_DAMAGE_EVENT: magicResist,
    defense_bypass: bypass,
    boundaries: {
      counterfactual: false,
      recommendation: false,
      map_behavior: false,
      damage_amount_reinterpreted: false,
      damage_stage_reinterpreted: false,
    },
    protected_holdout_access: { ...HOLDOUT_ACCESS },
  };
}

module.exports = {
  DIRECT_EFFECTIVE_OUTPUT_REGISTRY,
  STATE_EVIDENCE_CONTRACT_REGISTRY,
  EXACT_BUILD,
  HOLDOUT_ACCESS,
  OPERATION_SEMANTICS,
  OPERATION_TAXONOMY,
  SCHEMA,
  effectiveDefenseForDamageEvent,
};
