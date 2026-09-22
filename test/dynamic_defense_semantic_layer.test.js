'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  buildDynamicDefensePhaseReport,
  effectiveDefenseForDamageEvent,
  effective_defense_for_damage_event,
  writeDynamicDefensePhaseArtifacts,
} = require('../src/dynamic_defense_semantic_layer');

const EXACT_BUILD = '16.16.805.0442';

function event(damageType = 'PHYSICAL') {
  return {
    exact_build: EXACT_BUILD,
    damage_event: {
      event_id: 'damage-1', source_entity_id: 'attacker', target_entity_id: 'target',
      game_time: 30, damage_type: damageType, damage_type_evidence_grade: 'VERIFIED_DIRECT',
      recorded_amount: 100, damage_stage: 'UNKNOWN',
    },
  };
}

test('integration exports camel and snake effective-defense APIs', () => {
  assert.equal(effective_defense_for_damage_event, effectiveDefenseForDamageEvent);
  const semanticApi = require('../src/semantic_api');
  assert.equal(typeof semanticApi.baseStatAtLevel, 'function');
  assert.equal(semanticApi.base_stat_at_level, semanticApi.baseStatAtLevel);
  assert.equal(typeof semanticApi.effectiveDefenseForDamageEvent, 'function');
  assert.equal(semanticApi.effective_defense_for_damage_event,
    semanticApi.effectiveDefenseForDamageEvent);
  assert.equal(typeof semanticApi.createSemanticAcquisitionPlan, 'function');
});

test('missing current state and ordering fail closed without familiar defaults', () => {
  const result = effectiveDefenseForDamageEvent(event());
  assert.equal(result.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT.status, 'UNKNOWN');
  assert.equal(result.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT.value, null);
  assert.ok(result.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT.missing_inputs
    .some((value) => value.includes('mechanics_binding')));
});

test('base-stat request does not promote a familiar growth formula', () => {
  const report = buildDynamicDefensePhaseReport({
    exact_build: EXACT_BUILD,
    base_stat_requests: [{ championId: 'Annie', stat: 'ARMOR', level: 18 }],
  });
  assert.equal(report.base_stat_results[0].status, 'UNKNOWN');
  assert.equal(report.base_stat_results[0].value, null);
  assert.equal(report.final_report_A_to_Z.C.status, 'FAIL_CLOSED');
});

test('true damage explicitly bypasses both defenses', () => {
  const result = effectiveDefenseForDamageEvent(event('TRUE'));
  assert.equal(result.defense_bypass.status, 'VERIFIED_EXPLICIT_BYPASS');
  assert.equal(result.defense_bypass.bypasses_armor, true);
  assert.equal(result.defense_bypass.bypasses_magic_resist, true);
  assert.equal(result.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT.status, 'BYPASSED_BY_TRUE_DAMAGE');
});

test('phase report is deterministic, complete A-Z/Q1-Q6, and does not claim global Replay exhaustion', () => {
  const evidence = {
    exact_build: EXACT_BUILD,
    damage_event_inputs: [event('TRUE')],
    acquisition_requests: [{ semantic_name: 'CURRENT_ARMOR' }],
    exhausted_edges: [{ id: 'damage-stage', capability: 'DAMAGE_STAGE',
      route_family: 'EXACT_RUNTIME_CONSUMER_EDGE', status: 'EXHAUSTED',
      missing_evidence: 'unique field consumer stage', reopening_trigger: 'new exact-build xref',
      owner: 'ROFL_PARSER', independent_routes_executed: true }],
  };
  const left = buildDynamicDefensePhaseReport(evidence);
  const right = buildDynamicDefensePhaseReport(evidence);
  assert.deepEqual(left, right);
  assert.equal(Object.keys(left.final_report_A_to_Z).join(''), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  assert.deepEqual(Object.keys(left.research_questions), ['Q1', 'Q2', 'Q3', 'Q4', 'Q5', 'Q6']);
  assert.match(left.research_questions.Q1, /YES_FOR_REGISTERED_RULES_FAIL_CLOSED_FOR_UNREGISTERED/u);
  assert.match(left.research_questions.Q2, /CURRENT_DECLARED_HYPOTHESES_EXHAUSTED/u);
  assert.match(left.research_questions.Q2, /GLOBAL_REPLAY_NOT_EXHAUSTIVELY_SEMANTIC/u);
  assert.match(left.research_questions.Q3, /POTENTIALLY_PRESENT_WITHOUT_HIGH_INFORMATION_ANCHOR/u);
  assert.match(left.research_questions.Q4, /DETERMINISTIC_MECHANICS_FIRST/u);
  assert.match(left.research_questions.Q5, /NO_SPECIFIC_DYNAMIC_DEFENSE_SEMANTIC_PROVEN_CLIENT_LOCAL/u);
  assert.match(left.research_questions.Q6, /SEMANTIC_ACQUISITION_PLAN/u);
  assert.deepEqual(Object.keys(left.combat_closure_snapshot), [
    'base_defense', 'current_defense', 'damage', 'effective_defense', 'heal_and_hp', 'shield',
  ]);
  assert.equal(left.status, 'EVIDENCE_EXHAUSTED');
  assert.equal(left.defense_state_summary.non_equivalence_rule,
    'BASE_AT_LEVEL_NE_BASELINE_NE_CURRENT_NE_EFFECTIVE_FOR_EVENT');
  assert.equal(left.global_replay_exhausted, false);
  assert.equal(left.source_acquisition_performed, false);
});

test('a partial external edge cannot claim TRUE_EXTERNAL_INPUT_REQUIRED', () => {
  const report = buildDynamicDefensePhaseReport({
    exhausted_edges: [{ id: 'external', capability: 'CURRENT_HP',
      route_family: 'CLIENT_RUNTIME', status: 'EXHAUSTED', missing_evidence: 'absolute HP anchor',
      reopening_trigger: 'new governed runtime input', owner: 'AKARI',
      independent_routes_executed: true }],
  });
  assert.equal(report.status, 'EVIDENCE_EXHAUSTED');
});

test('self-declared direct grades and publication flags cannot upgrade report rows', () => {
  const report = buildDynamicDefensePhaseReport({
    current_armor_state: { status: 'COMPLETE', evidence_grade: 'VERIFIED_DIRECT' },
    combat_closure: {
      shield_generated: {
        status: 'VERIFIED_DIRECT', evidence_grade: 'VERIFIED_DIRECT', publication_eligible: true,
      },
    },
  });
  assert.equal(report.final_report_A_to_Z.K.status, 'UNKNOWN');
  assert.equal(report.final_report_A_to_Z.Q.status, 'UNVERIFIED_PUBLICATION_CLAIM');
  assert.notEqual(report.final_report_A_to_Z.Q.status, 'PUBLICATION_ELIGIBLE');
});

test('unregistered direct output cannot manufacture publication authority', () => {
  const input = event();
  input.direct_effective_armor = {
    status: 'COMPLETE', semantic: 'FINAL_FORMULA_OUTPUT', value: 17,
    exact_build: EXACT_BUILD, game_time: 30, event_id: 'damage-1',
    source_entity_id: 'attacker', target_entity_id: 'target',
    evidence_grade: 'VERIFIED_DIRECT', provenance: { route: 'caller-supplied' },
  };
  const result = effectiveDefenseForDamageEvent(input);
  assert.equal(result.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT.value, null);
  assert.equal(result.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT.publication_eligible, false);
  assert.equal(result.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT.selected_source, 'RECONSTRUCTION');
  assert.ok(result.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT.direct_final_formula_output.missing_inputs
    .includes('direct_effective_armor.registered_exact_build_direct_output_contract'));
  assert.equal(result.EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT.reconstruction.status, 'UNKNOWN');
});

test('artifact builder records nonempty hashed outputs and rejects Holdout paths', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dynamic-defense-layer-'));
  const result = writeDynamicDefensePhaseArtifacts({ outputDir: path.join(root, 'evidence'), evidence: {} });
  assert.equal(result.manifest.artifacts.length, 6);
  for (const artifact of result.manifest.artifacts) {
    assert.ok(artifact.bytes > 0);
    assert.match(artifact.sha256, /^[0-9a-f]{64}$/u);
    assert.ok(fs.statSync(path.join(root, 'evidence', artifact.path)).size > 0);
  }
  assert.throws(() => writeDynamicDefensePhaseArtifacts({
    outputDir: path.join(root, 'Jungle Objective Holdout'), evidence: {},
  }), /Holdout/iu);
});

test('exhausted-edge registry rejects protected Holdout references', () => {
  assert.throws(() => buildDynamicDefensePhaseReport({ exhausted_edges: [{
    id: 'bad', capability: 'DAMAGE_STAGE', route_family: 'Holdout replay', status: 'EXHAUSTED',
    missing_evidence: 'x', reopening_trigger: 'y', owner: 'ROFL_PARSER',
  }] }), /Holdout/iu);
});
