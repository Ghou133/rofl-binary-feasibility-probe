'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { composeEvidence, exhaustedEdges } = require('../scripts/build_dynamic_defense_v1_evidence');
const { buildDynamicDefensePhaseReport } = require('../src/dynamic_defense_semantic_layer');

const EXACT_BUILD = '16.16.805.0442';
const hash = (character) => character.repeat(64);

function unavailable(capability) {
  return { capability, status: 'NOT_COMPUTABLE', value: null,
    evidence_grade: 'UNAVAILABLE', publication_eligible: false, missing_inputs: [capability] };
}

function fixtures() {
  const evidenceInventory = [
    { label: 'mechanics manifest', path: 'C:\\evidence\\mechanics.json', sha256: hash('1') },
    { label: 'defense field registry', path: 'C:\\evidence\\registry.json', sha256: hash('2') },
    { label: 'item presentation inventory', path: 'C:\\evidence\\items.json', sha256: hash('3') },
    { label: 'prior stat/combat baseline', path: 'C:\\evidence\\prior.json', sha256: hash('4') },
    { label: 'damage anchor validation', path: 'C:\\evidence\\damage.json', sha256: hash('5') },
  ];
  const matches = ['physical', 'magic', 'true'].map((damageType, index) => ({
    damage_type: damageType,
    source_network_id: 10 + index,
    target_network_id: 20 + index,
    replay_packet_time_ms: 1000 + index,
    recorded_amount: 50 + index,
    raw_packet_ref: { replay_sha256: hash(String(index + 6)),
      raw_payload_sha256: hash(String(index + 1)) },
  }));
  return {
    mechanics: { schema: 'ROFL_EXACT_BUILD_MECHANICS_MANIFEST_V1', exact_build: EXACT_BUILD,
      status: 'FAIL_CLOSED_MISSING_OR_REJECTED_INPUTS', components: {
        champion: { status: 'VERIFIED_EXACT_BUILD_NORMALIZED', rows: [] },
      } },
    defenseRegistry: { artifact_type: 'VERIFIED_EXACT_IMAGE_FIELD_REGISTRY_OFFSETS',
      exact_build: EXACT_BUILD, status: 'VERIFIED_EXACT_IMAGE_FIELD_REGISTRY_OFFSETS',
      runtime_image: { sha256: hash('a') } },
    itemInventory: { schema: 'ROFL_EXACT_CLIENT_ITEM_PRESENTATION_INVENTORY_V1',
      exact_build: EXACT_BUILD, status: 'PRESENTATION_ONLY', mechanics_consumer_eligible: false,
      source: { sha256: hash('b') } },
    priorBaseline: { schema: 'ROFL_STAT_COMBAT_SEMANTIC_BASELINE_V1', exact_build: EXACT_BUILD,
      status: 'EVIDENCE_EXHAUSTED', retained_direct_semantics: {
        shield_generated: true, shield_absorbed_target_total: true, heal_reported: true,
      }, combat_state: {
        damage_stage: unavailable('damage_stage'),
        damage_mitigation: unavailable('damage_mitigation'),
        shield_remaining: unavailable('shield_remaining'),
        heal_effective_overheal: unavailable('heal_effective_overheal'),
        current_hp: unavailable('current_hp'),
      } },
    damageValidation: { path: evidenceInventory[4].path, sha256: evidenceInventory[4].sha256,
      value: { schema: 'ROFL_16_16_DAMAGE_ANCHOR_VALIDATION_V1', exact_build: EXACT_BUILD,
        status: 'PASS', amount_semantic_stage: 'UNKNOWN', matches } },
    evidenceInventory,
  };
}

test('composer reuses exact existing artifacts and keeps unresolved semantics fail closed', () => {
  const evidence = composeEvidence(fixtures());
  assert.deepEqual(evidence.damage_event_inputs.map((row) => row.damage_event.damage_type),
    ['PHYSICAL', 'MAGIC', 'TRUE']);
  assert.equal(evidence.mechanics_metadata, null);
  assert.equal(evidence.combat_closure.shield_generated.status,
    'RETAINED_VERIFIED_DIRECT_CAPABILITY');
  assert.equal(evidence.combat_closure.shield_generated.publication_eligible, false);
  assert.match(evidence.combat_closure.shield_generated.provenance.authority_scope,
    /CAPABILITY_RETENTION_ONLY/u);
  assert.equal(evidence.exhausted_edges.length, exhaustedEdges().length);
  assert.equal(evidence.exhaustion_registry_complete, true);
  assert.equal(JSON.stringify(evidence).toLowerCase().includes('holdout'), false);

  const report = buildDynamicDefensePhaseReport(evidence);
  assert.equal(report.status, 'EVIDENCE_EXHAUSTED');
  assert.equal(report.final_report_A_to_Z.B.status, 'PARTIAL_EXACT_BUILD_COMPONENTS');
  assert.equal(report.final_report_A_to_Z.D.status, 'PRESENTATION_ONLY_NOT_MECHANICS');
  assert.equal(report.final_report_A_to_Z.K.status, 'UNKNOWN');
  assert.equal(report.final_report_A_to_Z.M.status, 'UNKNOWN');
  assert.equal(report.final_report_A_to_Z.Q.status, 'RETAINED_VERIFIED_DIRECT_CAPABILITY');
  assert.equal(report.final_report_A_to_Z.R.status, 'RETAINED_VERIFIED_DIRECT_CAPABILITY');
  assert.equal(report.final_report_A_to_Z.T.status, 'RETAINED_VERIFIED_DIRECT_CAPABILITY');
  assert.match(report.research_questions.Q1, /router deterministically selects Replay/u);
  assert.match(report.research_questions.Q2, /FULLY_EXHAUSTED is expressly rejected/u);
  assert.match(report.research_questions.Q6, /performs no source acquisition or full Replay scan/u);
  assert.equal(report.global_replay_exhausted, false);
});
