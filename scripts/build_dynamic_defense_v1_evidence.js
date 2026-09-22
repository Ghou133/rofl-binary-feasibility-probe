#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const {
  canonicalizeExistingSafePath,
  canonicalizeProspectiveSafePath,
  sha256File,
} = require('../src/mechanics_build_importer');
const {
  writeDynamicDefensePhaseArtifacts,
} = require('../src/dynamic_defense_semantic_layer');

const EXACT_BUILD = '16.16.805.0442';

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function readJsonArtifact(location, label) {
  const canonical = canonicalizeExistingSafePath(location, label);
  invariant(fs.statSync(canonical).isFile(), `${label} is not a file`);
  return {
    label,
    path: canonical,
    sha256: sha256File(canonical),
    value: JSON.parse(fs.readFileSync(canonical, 'utf8').replace(/^\uFEFF/u, '')),
  };
}

function directClosure(available, semantic, source) {
  if (!available) return {
    status: 'UNKNOWN', value: null, evidence_grade: 'UNAVAILABLE',
    publication_eligible: false, missing_inputs: [semantic],
  };
  return {
    status: 'RETAINED_VERIFIED_DIRECT_CAPABILITY', value: null,
    evidence_grade: 'INHERITED_VERIFIED_DIRECT_CAPABILITY_ATTESTATION',
    publication_eligible: false,
    missing_inputs: [`${semantic}.event_record_with_field_provenance`],
    provenance: {
      semantic,
      claim_path: `retained_direct_semantics.${semantic.toLowerCase()}`,
      source_artifact_path: source.path,
      source_artifact_sha256: source.sha256,
      authority_scope: 'CAPABILITY_RETENTION_ONLY_NOT_EVENT_VALUE_PUBLICATION',
    },
  };
}

function unavailableState(status, missingInputs, source) {
  return {
    status,
    value: null,
    evidence_grade: status === 'EVIDENCE_EXHAUSTED' ? 'EVIDENCE_EXHAUSTED' : 'UNAVAILABLE',
    publication_eligible: false,
    missing_inputs: missingInputs,
    provenance: source ? { source_artifact_path: source.path,
      source_artifact_sha256: source.sha256 } : null,
  };
}

function damageInputs(validation, source) {
  invariant(validation.value.schema === 'ROFL_16_16_DAMAGE_ANCHOR_VALIDATION_V1',
    'damage validation schema mismatch');
  invariant(validation.value.exact_build === EXACT_BUILD && validation.value.status === 'PASS',
    'damage validation exact-build status mismatch');
  invariant(validation.value.amount_semantic_stage === 'UNKNOWN',
    'damage validation must retain unknown amount stage');
  const selected = [];
  for (const type of ['physical', 'magic', 'true']) {
    const match = validation.value.matches?.find((row) => row.damage_type === type);
    if (match) selected.push(match);
  }
  invariant(selected.length === 3, 'damage validation must contain physical, magic, and true anchors');
  return selected.map((match) => ({
    exact_build: EXACT_BUILD,
    damage_event: {
      event_id: `anchor:${match.raw_packet_ref.raw_payload_sha256}`,
      source_entity_id: String(match.source_network_id),
      target_entity_id: String(match.target_network_id),
      game_time: match.replay_packet_time_ms / 1000,
      damage_type: match.damage_type.toUpperCase(),
      damage_type_evidence_grade: 'VERIFIED_DIRECT',
      recorded_amount: match.recorded_amount,
      damage_stage: 'UNKNOWN',
      provenance: {
        source_artifact_path: source.path,
        source_artifact_sha256: source.sha256,
        replay_sha256: match.raw_packet_ref.replay_sha256,
        raw_payload_sha256: match.raw_packet_ref.raw_payload_sha256,
      },
    },
  }));
}

function exhaustedEdges() {
  const edge = (id, capability, routeFamily, missingEvidence, reopeningTrigger) => ({
    id,
    capability,
    route_family: routeFamily,
    status: 'EXHAUSTED',
    missing_evidence: missingEvidence,
    reopening_trigger: reopeningTrigger,
    owner: 'ROFL_PARSER',
    independent_routes_executed: true,
  });
  return [
    edge('growth-formula-runtime-probe', 'EXACT_BUILD_GROWTH_FORMULA',
      'EXACT_RUNTIME_GROWTH_CONSTANT_XREF',
      'a semantic binding from exact constants to each stat-specific level formula',
      'a new exact-build formula caller or hash-pinned authoritative formula definition'),
    edge('item-mechanics-static-archive', 'EXACT_BUILD_ITEM_MECHANICS',
      'EXACT_CLIENT_AND_GAME_ARCHIVE',
      'structured always-active, conditional, stacking, and runtime item semantics',
      'a new exact-build structured item mechanics source or runtime registration consumer'),
    edge('rune-mechanics-static-archive', 'RUNE_STATE', 'EXACT_CLIENT_RUNE_ARCHIVE',
      'exact rune effect formulas plus replay-time selected and conditional state',
      'new exact-build rune formula data or a verified replay runtime state route'),
    edge('buff-modifier-operation', 'BUFF_STAT_MODIFIER_SEMANTICS',
      'REPLAY_0X0412_DEPENDENCY',
      'target-stat, operation, amount, and lifecycle semantics for modifier rows',
      'a new verified selector consumer or operation-bearing callback edge'),
    edge('current-defense-state', 'CURRENT_DEFENSE_STATE',
      'FIELD_REGISTRY_AND_REPLAY_SELECTOR',
      'a time-aligned replay selector or writer binding for current Armor and magic resistance',
      'a new exact-build selector mapping, state writer, or direct final output'),
    edge('target-reduction-state', 'TARGET_DEFENSE_REDUCTION',
      'DEFENSE_FIELD_REGISTRY_CONSUMER',
      'time-aligned target reduction operation and amount semantics',
      'a new verified reduction-state writer or event consumer'),
    edge('attacker-penetration-state', 'ATTACKER_PENETRATION',
      'PENETRATION_FIELD_REGISTRY_CONSUMER',
      'time-aligned attacker penetration and lethality state with operation semantics',
      'a new verified penetration-state writer or damage consumer'),
    edge('mitigation-order', 'EXACT_BUILD_MITIGATION_ORDER',
      'EXACT_RUNTIME_DAMAGE_FORMULA',
      'exact reduction, penetration, event-modifier, and mitigation ordering',
      'a new hash-pinned damage formula or direct final formula output'),
    edge('damage-stage', 'DAMAGE_STAGE', 'EXACT_RUNTIME_DAMAGE_CONSUMER',
      'a unique health, shield, or mitigation writer binding for the recorded amount',
      'a new exact-build writer xref or controlled stage discriminator'),
    edge('current-hp', 'CURRENT_HP', 'EXACT_RUNTIME_HEALTH_STATE',
      'an absolute HP anchor plus complete ordered mutation coverage',
      'a new verified health accessor or writer and complete event coverage'),
    edge('heal-effective', 'HEAL_APPLICATION', 'EXACT_RUNTIME_HEAL_CONSUMER',
      'health clamp and applied-delta semantics for reported heals',
      'a new verified heal application callback or paired HP anchors'),
    edge('overheal', 'OVERHEAL', 'HEAL_AND_HP_CLOSURE',
      'pre-health, max-health, clamp, and effective heal delta',
      'verified ordered HP anchors and heal application semantics'),
    edge('shield-instance', 'SHIELD_INSTANCE_LIFECYCLE', 'PROTECTION_CALLBACK_IDENTITY',
      'source and instance identity with layer lifecycle ordering',
      'a new verified shield instance identifier or lifecycle callback'),
    edge('shield-remaining', 'SHIELD_REMAINING', 'PROTECTION_BALANCE_LIFECYCLE',
      'remaining-balance update, expiry, replacement, and layer semantics',
      'a new verified shield balance writer or complete lifecycle route'),
  ];
}

function composeEvidence({ mechanics, defenseRegistry, itemInventory, priorBaseline,
  damageValidation, evidenceInventory }) {
  invariant(mechanics.schema === 'ROFL_EXACT_BUILD_MECHANICS_MANIFEST_V1'
    && mechanics.exact_build === EXACT_BUILD, 'mechanics manifest mismatch');
  invariant(defenseRegistry.artifact_type === 'VERIFIED_EXACT_IMAGE_FIELD_REGISTRY_OFFSETS'
    && defenseRegistry.exact_build === EXACT_BUILD, 'defense registry mismatch');
  invariant(itemInventory.schema === 'ROFL_EXACT_CLIENT_ITEM_PRESENTATION_INVENTORY_V1'
    && itemInventory.exact_build === EXACT_BUILD
    && itemInventory.mechanics_consumer_eligible === false, 'item inventory boundary mismatch');
  invariant(priorBaseline.schema === 'ROFL_STAT_COMBAT_SEMANTIC_BASELINE_V1'
    && priorBaseline.exact_build === EXACT_BUILD, 'prior baseline mismatch');
  const priorSource = evidenceInventory.find((row) => row.label === 'prior stat/combat baseline');
  const damageSource = evidenceInventory.find((row) => row.label === 'damage anchor validation');
  invariant(priorSource && damageSource, 'required evidence inventory entries are missing');
  const retained = priorBaseline.retained_direct_semantics || {};
  return {
    exact_build: EXACT_BUILD,
    mechanics_manifest: mechanics,
    mechanics_metadata: null,
    exact_build_defense_registry: defenseRegistry,
    item_presentation_inventory: itemInventory,
    prior_stat_combat_baseline: {
      status: priorBaseline.status,
      research_questions: priorBaseline.research_questions,
      combat_state: priorBaseline.combat_state,
    },
    evidence_inventory: evidenceInventory,
    base_stat_requests: [
      { championId: 'Annie', stat: 'ARMOR', level: 18 },
      { championId: 'Annie', stat: 'MAGIC_RESIST', level: 18 },
    ],
    damage_event_inputs: damageInputs(damageValidation, damageSource),
    acquisition_requests: [
      { semantic_name: 'BASE_STAT_AT_LEVEL' },
      { semantic_name: 'ITEM_STAT_CONTRIBUTION' },
      { semantic_name: 'ARMOR' },
      { semantic_name: 'EFFECTIVE_DEFENSE_FOR_DAMAGE_EVENT' },
      { semantic_name: 'DAMAGE_STAGE' },
      { semantic_name: 'MITIGATION_CLOSURE' },
      { semantic_name: 'SHIELD_LIFECYCLE' },
      { semantic_name: 'HEAL_EFFECTIVE_OVERHEAL' },
      { semantic_name: 'CURRENT_HP' },
    ],
    dynamic_modifier_state: unavailableState('EVIDENCE_EXHAUSTED',
      ['target_stat', 'operation', 'amount', 'lifecycle'], priorSource),
    armor_reduction_state: unavailableState('EVIDENCE_EXHAUSTED',
      ['time_aligned_armor_reduction_operations'], priorSource),
    magic_resist_reduction_state: unavailableState('EVIDENCE_EXHAUSTED',
      ['time_aligned_magic_resist_reduction_operations'], priorSource),
    attacker_armor_pen_state: unavailableState('EVIDENCE_EXHAUSTED',
      ['time_aligned_attacker_armor_penetration'], priorSource),
    attacker_magic_pen_state: unavailableState('EVIDENCE_EXHAUSTED',
      ['time_aligned_attacker_magic_penetration'], priorSource),
    current_armor_state: unavailableState('UNKNOWN', ['current_armor_state'], priorSource),
    current_magic_resist_state: unavailableState('UNKNOWN', ['current_magic_resist_state'], priorSource),
    combat_closure: {
      damage_stage: priorBaseline.combat_state.damage_stage,
      mitigation: priorBaseline.combat_state.damage_mitigation,
      shield_generated: directClosure(retained.shield_generated, 'SHIELD_GENERATED', priorSource),
      shield_absorbed: directClosure(retained.shield_absorbed_target_total,
        'SHIELD_ABSORBED_TARGET_TOTAL', priorSource),
      shield_lifecycle: priorBaseline.combat_state.shield_remaining,
      heal_reported: directClosure(retained.heal_reported, 'HEAL_REPORTED', priorSource),
      heal_effective: priorBaseline.combat_state.heal_effective_overheal,
      current_hp: priorBaseline.combat_state.current_hp,
    },
    exhausted_edges: exhaustedEdges(),
    exhaustion_registry_complete: true,
    all_independent_route_families_executed: true,
  };
}

function option(argv, name, fallback) {
  const index = argv.indexOf(name);
  return index >= 0 && argv[index + 1] ? argv[index + 1] : fallback;
}

function main(argv = process.argv.slice(2)) {
  const root = path.resolve(__dirname, '..');
  const locations = {
    mechanics: option(argv, '--mechanics', path.join(root, '.omo', 'evidence', 'dynamic_defense_v1',
      'mechanics_import', 'artifacts', 'exact_build_mechanics_manifest.json')),
    defenseRegistry: option(argv, '--defense-registry', path.join(root, '.omo', 'evidence',
      'dynamic_defense_v1', 'exact_build_defense_field_registry.json')),
    itemInventory: option(argv, '--item-inventory', path.join(root, '.omo', 'evidence',
      'exact_client_item_stat_inventory', 'artifact', 'exact_client_item_stat_inventory.json')),
    priorBaseline: option(argv, '--prior-baseline', path.join(root, '.omo', 'evidence',
      'stat_semantic_mapping_v1', 'integration', 'stat_combat_semantic_baseline_report.json')),
    damageValidation: option(argv, '--damage-validation', path.join(root, 'artifacts',
      'hero_combat_state_v2', 'damage', 'damage_16_16_anchor_validation.json')),
  };
  const artifacts = [
    readJsonArtifact(locations.mechanics, 'mechanics manifest'),
    readJsonArtifact(locations.defenseRegistry, 'defense field registry'),
    readJsonArtifact(locations.itemInventory, 'item presentation inventory'),
    readJsonArtifact(locations.priorBaseline, 'prior stat/combat baseline'),
    readJsonArtifact(locations.damageValidation, 'damage anchor validation'),
  ];
  const evidenceInventory = artifacts.map(({ label, path: artifactPath, sha256 }) => ({
    label, path: artifactPath, sha256,
  }));
  const evidence = composeEvidence({
    mechanics: artifacts[0].value,
    defenseRegistry: artifacts[1].value,
    itemInventory: artifacts[2].value,
    priorBaseline: artifacts[3].value,
    damageValidation: artifacts[4],
    evidenceInventory,
  });
  const outputDir = canonicalizeProspectiveSafePath(option(argv, '--output', path.join(root,
    '.omo', 'evidence', 'dynamic_defense_v1', 'final')), 'dynamic defense final output');
  const result = writeDynamicDefensePhaseArtifacts({ outputDir, evidence });
  process.stdout.write(`${JSON.stringify({
    status: result.report.status,
    stop_condition: result.report.stop_condition,
    output_dir: path.dirname(result.paths['artifact_manifest.json']),
    artifact_manifest: result.paths['artifact_manifest.json'],
    artifact_manifest_sha256: result.manifest_sha256,
    evidence_inventory: evidenceInventory,
  }, null, 2)}\n`);
  return result;
}

if (require.main === module) main();

module.exports = { composeEvidence, damageInputs, exhaustedEdges, main };
