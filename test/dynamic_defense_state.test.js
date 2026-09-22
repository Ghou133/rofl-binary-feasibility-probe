'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  DIRECT_EFFECTIVE_OUTPUT_REGISTRY,
  EXACT_BUILD,
  HOLDOUT_ACCESS,
  OPERATION_SEMANTICS,
  STATE_EVIDENCE_CONTRACT_REGISTRY,
  effectiveDefenseForDamageEvent,
} = require('../src/dynamic_defense_state');

const TIME = 420000;
const EVENT_ID = 'damage-17';
const SOURCE = 'hero:1';
const TARGET = 'hero:2';

function provenance(source) {
  return { source, fixture: 'SYNTHETIC_ALGORITHM_CONFORMANCE_ONLY' };
}

function scalar(value, entityId = TARGET, extra = {}) {
  return {
    status: 'COMPLETE', value, exact_build: EXACT_BUILD, game_time: TIME,
    entity_id: entityId, evidence_grade: 'ALGORITHM_CONFORMANCE_ONLY',
    provenance: provenance('fixture-scalar'), ...extra,
  };
}

function operation(operationName, amount) {
  return {
    operation: operationName, amount, evidence_grade: 'ALGORITHM_CONFORMANCE_ONLY',
    provenance: provenance(`fixture-${operationName}`),
  };
}

function operationState(entityId, operations, extra = {}) {
  return {
    status: 'COMPLETE', exact_build: EXACT_BUILD, game_time: TIME, entity_id: entityId,
    evidence_grade: 'ALGORITHM_CONFORMANCE_ONLY', provenance: provenance('fixture-state'),
    operations, ...extra,
  };
}

function mechanics(physicalSteps = [], magicSteps = []) {
  const steps = (names) => names.map((operationName) => ({
    operation: operationName,
    semantics: OPERATION_SEMANTICS[operationName],
  }));
  return {
    status: 'EXACT_BUILD_VERIFIED', identity_proof: true, exact_build: EXACT_BUILD,
    evidence_grade: 'ALGORITHM_CONFORMANCE_ONLY', provenance: provenance('synthetic-binding'),
    defense_order: {
      physical: { ordering_complete: true, steps: steps(physicalSteps) },
      magic: { ordering_complete: true, steps: steps(magicSteps) },
    },
  };
}

function completeInput(damageType = 'PHYSICAL') {
  return {
    exact_build: EXACT_BUILD,
    damage_event: {
      event_id: EVENT_ID, source_entity_id: SOURCE, target_entity_id: TARGET,
      game_time: TIME, damage_type: damageType, damage_type_evidence_grade: 'VERIFIED_DIRECT',
      recorded_amount: { value: 77.25, evidence_grade: 'VERIFIED_DIRECT', stage: 'UNKNOWN' },
      damage_stage: { value: null, status: 'NO_UNIQUE_STAGE' },
    },
    base_armor_at_level: scalar(50),
    baseline_armor_state: scalar(80),
    current_armor_state: scalar(100),
    base_magic_resist_at_level: scalar(32),
    baseline_magic_resist_state: scalar(50),
    current_magic_resist_state: scalar(60),
    armor_reduction_state: operationState(TARGET, []),
    magic_resist_reduction_state: operationState(TARGET, []),
    attacker_armor_pen_state: operationState(SOURCE, []),
    attacker_magic_pen_state: operationState(SOURCE, []),
    armor_event_modifier_state: operationState(TARGET, [], {
      source_entity_id: SOURCE, event_id: EVENT_ID,
    }),
    magic_resist_event_modifier_state: operationState(TARGET, [], {
      source_entity_id: SOURCE, event_id: EVENT_ID,
    }),
    mechanics_binding: mechanics(),
  };
}

test('incomplete dynamic state fails closed with deterministic missing inputs and no silent zero', () => {
  const input = completeInput();
  delete input.current_armor_state;
  input.armor_reduction_state.status = 'UNKNOWN';
  input.attacker_armor_pen_state.operations = null;
  delete input.mechanics_binding;
  const output = effectiveDefenseForDamageEvent(input);
  const effective = output.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT;
  assert.equal(effective.value, null);
  assert.equal(effective.status, 'UNKNOWN');
  assert.equal(effective.evidence_grade, 'NOT_COMPUTABLE');
  assert.deepEqual(effective.missing_inputs, [...effective.missing_inputs].sort());
  assert.ok(effective.missing_inputs.includes('current_armor_state'));
  assert.ok(effective.missing_inputs.includes('armor_reduction_state.status_COMPLETE'));
  assert.ok(effective.missing_inputs.includes('attacker_armor_pen_state.operations'));
  assert.ok(effective.missing_inputs.includes('mechanics_binding'));
  assert.notEqual(effective.value, 0);
  assert.equal(output.BASE_ARMOR_AT_LEVEL.value, 50);
  assert.equal(output.BASELINE_ARMOR_STATE.value, 80);
  assert.equal(output.CURRENT_ARMOR_STATE.value, null);
});

test('target reduction and attacker penetration use separate strict state taxonomies', () => {
  const input = completeInput();
  input.armor_reduction_state.operations = [operation('ATTACKER_FLAT_PENETRATION', 10)];
  input.attacker_armor_pen_state.operations = [operation('TARGET_FLAT_REDUCTION', 20)];
  const output = effectiveDefenseForDamageEvent(input).EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT;
  assert.equal(output.value, null);
  assert.ok(output.missing_inputs.includes(
    'armor_reduction_state.operations[0].operation_taxonomy'));
  assert.ok(output.missing_inputs.includes(
    'attacker_armor_pen_state.operations[0].operation_taxonomy'));
});

test('verified synthetic binding supplies ordering and yields provenance-rich physical conformance value', () => {
  const input = completeInput();
  input.armor_reduction_state.operations = [operation('TARGET_FLAT_REDUCTION', 10)];
  input.attacker_armor_pen_state.operations = [
    operation('ATTACKER_PERCENT_PENETRATION', 0.2),
    operation('ATTACKER_FLAT_PENETRATION', 5),
  ];
  input.mechanics_binding = mechanics([
    'TARGET_FLAT_REDUCTION',
    'ATTACKER_PERCENT_PENETRATION',
    'ATTACKER_FLAT_PENETRATION',
  ]);
  const output = effectiveDefenseForDamageEvent(input);
  const effective = output.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT;
  assert.equal(effective.value, 67); // (100 - 10) * (1 - .2) - 5
  assert.equal(effective.status, 'CONDITIONALLY_DERIVED');
  assert.equal(effective.evidence_grade, 'ALGORITHM_CONFORMANCE_ONLY');
  assert.equal(effective.publication_eligible, false);
  assert.ok(effective.publication_blockers.includes('mechanics_binding.not_publication_eligible'));
  assert.equal(effective.selected_source, 'RECONSTRUCTION');
  assert.equal(effective.reconstruction.calculation_trace.length, 3);
  assert.equal(effective.reconstruction.calculation_trace[0].provenance.source,
    'fixture-TARGET_FLAT_REDUCTION');
  assert.equal(effective.inputs.target_reduction.operations[0].operation,
    'TARGET_FLAT_REDUCTION');
  assert.equal(effective.inputs.attacker_penetration.operations[0].operation,
    'ATTACKER_PERCENT_PENETRATION');
});

test('caller publication flags cannot mint verified derived state without a registered evidence contract', () => {
  const input = completeInput();
  const publishable = (record, evidenceGrade) => {
    record.publication_eligible = true;
    record.evidence_grade = evidenceGrade;
    if (Array.isArray(record.operations)) record.operations.forEach((entry) => {
      entry.publication_eligible = true;
      entry.evidence_grade = evidenceGrade;
    });
  };
  publishable(input.current_armor_state, 'VERIFIED_DERIVED_STATE');
  publishable(input.armor_reduction_state, 'VERIFIED_DERIVED_STATE');
  publishable(input.attacker_armor_pen_state, 'VERIFIED_DERIVED_STATE');
  publishable(input.armor_event_modifier_state, 'VERIFIED_DERIVED_STATE');
  publishable(input.mechanics_binding, 'VERIFIED_EXACT_BUILD_MECHANICS');
  input.mechanics_binding.verification_scope = 'PUBLICATION';
  input.mechanics_binding.provenance = {
    source: 'hash-pinned-exact-build-mechanics',
    source_artifact_sha256: 'a'.repeat(64),
  };

  input.current_armor_state.evidence_contract_id = 'caller-invented';
  input.mechanics_binding.evidence_contract_id = 'caller-invented';
  let effective = effectiveDefenseForDamageEvent(input).EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT;
  assert.equal(effective.value, 100);
  assert.deepEqual(STATE_EVIDENCE_CONTRACT_REGISTRY, {});
  assert.equal(effective.status, 'CONDITIONALLY_DERIVED');
  assert.equal(effective.evidence_grade, 'CONDITIONALLY_DERIVED');
  assert.equal(effective.publication_eligible, false);
  assert.ok(effective.publication_blockers.includes('current_state.not_publication_eligible'));
  assert.ok(effective.publication_blockers.includes('mechanics_binding.not_publication_eligible'));

  input.mechanics_binding.synthetic = true;
  effective = effectiveDefenseForDamageEvent(input).EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT;
  assert.equal(effective.value, 100);
  assert.equal(effective.status, 'CONDITIONALLY_DERIVED');
  assert.notEqual(effective.evidence_grade, 'VERIFIED_DERIVED_MECHANICS');
  assert.equal(effective.publication_eligible, false);

  input.mechanics_binding.synthetic = false;
  input.mechanics_binding.evidence_grade = 'ALGORITHM_CONFORMANCE_ONLY';
  effective = effectiveDefenseForDamageEvent(input).EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT;
  assert.equal(effective.value, 100);
  assert.equal(effective.status, 'CONDITIONALLY_DERIVED');
  assert.equal(effective.evidence_grade, 'ALGORITHM_CONFORMANCE_ONLY');
  assert.equal(effective.publication_eligible, false);
});

test('event-specific modifier is event-bound and participates only through supplied mechanics order', () => {
  const input = completeInput('MAGIC');
  input.magic_resist_event_modifier_state.operations = [operation('EVENT_MULTIPLY', 0.5)];
  input.mechanics_binding = mechanics([], ['EVENT_MULTIPLY']);
  let output = effectiveDefenseForDamageEvent(input).EFFECTIVE_MR_FOR_DAMAGE_EVENT;
  assert.equal(output.value, 30);
  assert.equal(output.reconstruction.calculation_trace[0].operation, 'EVENT_MULTIPLY');

  input.magic_resist_event_modifier_state.event_id = 'different-event';
  output = effectiveDefenseForDamageEvent(input).EFFECTIVE_MR_FOR_DAMAGE_EVENT;
  assert.equal(output.value, null);
  assert.ok(output.missing_inputs.includes('magic_resist_event_modifier_state.event_id'));
});

test('true damage publishes explicit defense bypass without manufacturing a zero defense', () => {
  const input = completeInput('TRUE');
  delete input.current_armor_state;
  delete input.current_magic_resist_state;
  const output = effectiveDefenseForDamageEvent(input);
  assert.equal(output.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT.value, null);
  assert.equal(output.EFFECTIVE_MR_FOR_DAMAGE_EVENT.value, null);
  assert.equal(output.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT.status, 'BYPASSED_BY_TRUE_DAMAGE');
  assert.deepEqual(output.defense_bypass, {
    status: 'VERIFIED_EXPLICIT_BYPASS',
    bypasses_armor: true,
    bypasses_magic_resist: true,
    effective_defense_value: null,
    semantics: 'TRUE_DAMAGE_DOES_NOT_USE_ARMOR_OR_MAGIC_RESIST',
    evidence_grade: 'VERIFIED_DIRECT',
    missing_inputs: [],
  });
});

test('unregistered caller-supplied direct final output cannot override reconstruction', () => {
  const input = completeInput();
  input.direct_effective_armor = {
    status: 'COMPLETE', semantic: 'FINAL_FORMULA_OUTPUT', value: 91.5,
    exact_build: EXACT_BUILD, game_time: TIME, event_id: EVENT_ID,
    source_entity_id: SOURCE, target_entity_id: TARGET,
    evidence_grade: 'VERIFIED_DIRECT', direct_output_contract_id: 'caller-invented',
    provenance: {
      source_artifact_sha256: 'a'.repeat(64),
      decoder_profile_id: 'caller-invented',
      decoder_profile_sha256: 'b'.repeat(64),
    },
  };
  const effective = effectiveDefenseForDamageEvent(input).EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT;
  assert.deepEqual(DIRECT_EFFECTIVE_OUTPUT_REGISTRY, {});
  assert.equal(effective.value, 100);
  assert.equal(effective.status, 'CONDITIONALLY_DERIVED');
  assert.equal(effective.publication_eligible, false);
  assert.equal(effective.selected_source, 'RECONSTRUCTION');
  assert.equal(effective.reconstruction.value, 100);
  assert.equal(effective.reconstruction.cross_validation_delta, null);
  assert.equal(effective.direct_final_formula_output.value, null);
  assert.ok(effective.direct_final_formula_output.missing_inputs
    .includes('direct_effective_armor.registered_exact_build_direct_output_contract'));
});

test('build, time, entity, and direct-event mismatches fail closed independently', () => {
  const cases = [
    ['build', (input) => { input.current_armor_state.exact_build = '16.16.0.0'; },
      'current_armor_state.exact_build'],
    ['time', (input) => { input.current_armor_state.game_time = TIME - 1; },
      'current_armor_state.covers_game_time'],
    ['target', (input) => { input.armor_reduction_state.entity_id = 'hero:9'; },
      'armor_reduction_state.targetEntityId'],
    ['source', (input) => { input.attacker_armor_pen_state.entity_id = 'hero:9'; },
      'attacker_armor_pen_state.sourceEntityId'],
  ];
  cases.forEach(([name, mutate, expected]) => {
    const input = completeInput();
    mutate(input);
    const effective = effectiveDefenseForDamageEvent(input).EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT;
    assert.equal(effective.value, null, name);
    assert.ok(effective.missing_inputs.includes(expected), name);
  });

  const input = completeInput();
  input.direct_effective_armor = {
    status: 'COMPLETE', semantic: 'FINAL_FORMULA_OUTPUT', value: 99,
    exact_build: EXACT_BUILD, game_time: TIME, event_id: 'wrong',
    source_entity_id: SOURCE, target_entity_id: TARGET,
    evidence_grade: 'VERIFIED_DIRECT', provenance: provenance('wrong-event'),
  };
  const effective = effectiveDefenseForDamageEvent(input).EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT;
  assert.equal(effective.selected_source, 'RECONSTRUCTION');
  assert.equal(effective.value, 100);
  assert.ok(effective.direct_final_formula_output.missing_inputs
    .includes('direct_effective_armor.event_id'));
});

test('recorded damage amount and unresolved stage are retained verbatim, with prohibited scope false', () => {
  const input = completeInput();
  const output = effectiveDefenseForDamageEvent(input);
  assert.deepEqual(output.damage_recorded_amount, input.damage_event.recorded_amount);
  assert.deepEqual(output.damage_stage, input.damage_event.damage_stage);
  assert.deepEqual(output.boundaries, {
    counterfactual: false,
    recommendation: false,
    map_behavior: false,
    damage_amount_reinterpreted: false,
    damage_stage_reinterpreted: false,
  });
  assert.deepEqual(output.protected_holdout_access, HOLDOUT_ACCESS);
  assert.deepEqual(HOLDOUT_ACCESS, {
    read: false, enumerate: false, hash: false, decode: false,
    test: false, consume: false,
  });
});
