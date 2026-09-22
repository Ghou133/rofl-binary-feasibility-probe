'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  EXACT_BUILD,
  canonicalizeExistingSafePath,
  canonicalizeProspectiveSafePath,
  sha256File,
} = require('./mechanics_build_importer');
const { baseStatAtLevel } = require('./champion_base_stat_engine');
const { effectiveDefenseForDamageEvent: reconstructEffectiveDefense } = require('./dynamic_defense_state');
const { createSemanticAcquisitionPlan } = require('./semantic_acquisition_router');
const { researchQuestions: priorResearchQuestions } = require('./stat_combat_semantic_layer');

const SCHEMA = 'ROFL_DYNAMIC_DEFENSE_SEMANTIC_LAYER_V1';
const HOLDOUT_ACCESS = Object.freeze({
  read: false, enumerated: false, hashed: false, decoded: false, tested: false, consumed: false,
});

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort()
    .map((key) => [key, stableValue(value[key])]));
  return value;
}

function stableJson(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function effectiveDefenseForDamageEvent(input) {
  return reconstructEffectiveDefense(input);
}

function statusOf(value, fallback = 'UNKNOWN') {
  return typeof value?.status === 'string' ? value.status : fallback;
}

function eligible(value) {
  return value?.publication_eligible === true;
}

function untrustedPublicationStatus(value) {
  return eligible(value) ? 'UNVERIFIED_PUBLICATION_CLAIM' : statusOf(value);
}

function summarizeEventResults(eventResults, field) {
  const applicable = eventResults.map((row) => row[field])
    .filter((row) => row && !['NOT_APPLICABLE', 'BYPASSED_BY_TRUE_DAMAGE'].includes(row.status));
  if (applicable.length === 0) return { status: 'NO_APPLICABLE_EVENT', publication_eligible: false };
  if (applicable.every(eligible)) return { status: 'PUBLICATION_ELIGIBLE', publication_eligible: true };
  if (applicable.some((row) => row.status === 'CONDITIONALLY_DERIVED')) {
    return { status: 'CONDITIONALLY_DERIVED', publication_eligible: false };
  }
  return { status: 'UNKNOWN', publication_eligible: false };
}

function summarizeStateResults(eventResults, field) {
  const states = eventResults.map((result) => result[field]).filter(Boolean);
  if (states.length === 0) return { status: 'UNKNOWN', publication_eligible: false };
  if (states.every(eligible)) return { status: 'PUBLICATION_ELIGIBLE', publication_eligible: true };
  return { status: 'UNKNOWN', publication_eligible: false };
}

function normalizeExhaustedEdges(edges) {
  invariant(Array.isArray(edges), 'exhausted_edges must be an array');
  const ids = new Set();
  return edges.map((edge, index) => {
    invariant(edge && typeof edge === 'object' && !Array.isArray(edge),
      `exhausted edge ${index} must be an object`);
    for (const key of ['id', 'capability', 'route_family', 'status', 'missing_evidence',
      'reopening_trigger', 'owner']) {
      invariant(typeof edge[key] === 'string' && edge[key].length > 0,
        `exhausted edge ${index} missing ${key}`);
    }
    invariant(!/holdout/iu.test(`${edge.route_family} ${edge.missing_evidence} ${edge.reopening_trigger}`),
      `exhausted edge ${index} references protected Holdout`);
    invariant(!ids.has(edge.id), `duplicate exhausted edge ${edge.id}`);
    ids.add(edge.id);
    return stableValue({ ...edge });
  }).sort((left, right) => left.id.localeCompare(right.id));
}

function componentStatus(manifest, component) {
  return statusOf(manifest?.components?.[component], 'MISSING_REQUIRED_INPUT');
}

function mechanicsStatus(manifest) {
  if (!manifest) return 'MISSING_REQUIRED_INPUT';
  if (manifest.status === 'READY') return 'READY';
  const verifiedComponents = Object.values(manifest.components || {})
    .filter((component) => component?.status === 'VERIFIED_EXACT_BUILD_NORMALIZED');
  return verifiedComponents.length > 0
    ? 'PARTIAL_EXACT_BUILD_COMPONENTS'
    : statusOf(manifest, 'MISSING_REQUIRED_INPUT');
}

function closureState(evidence, key) {
  const value = evidence.combat_closure?.[key] ?? evidence.prior_stat_combat_baseline?.combat_state?.[key];
  return value && typeof value === 'object' ? value : { status: 'UNKNOWN', publication_eligible: false };
}

function row(topic, status, decision, provenance = []) {
  return { topic, status, decision, provenance: stableValue(provenance) };
}

function computePhaseStatus({ matrix, exhaustedEdges, eventResults,
  exhaustionRegistryComplete, allIndependentRouteFamiliesExecuted }) {
  const requiredReady = ['K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V'];
  const ready = requiredReady.every((letter) => matrix[letter].status === 'PUBLICATION_ELIGIBLE')
    && eventResults.length > 0;
  if (ready) return {
    status: 'DYNAMIC_DEFENSE_AND_COMBAT_BASELINE_READY',
    stop_condition: 'A_DYNAMIC_DEFENSE_AND_COMBAT_BASELINE_READY',
  };
  const externalOnly = exhaustionRegistryComplete === true
    && allIndependentRouteFamiliesExecuted === true
    && exhaustedEdges.length > 0
    && exhaustedEdges.every((edge) => edge.status === 'EXHAUSTED'
      && edge.owner !== 'ROFL_PARSER'
      && edge.independent_routes_executed === true);
  if (externalOnly) return {
    status: 'TRUE_EXTERNAL_INPUT_REQUIRED',
    stop_condition: 'B_TRUE_EXTERNAL_INPUT_REQUIRED',
  };
  return { status: 'EVIDENCE_EXHAUSTED', stop_condition: 'C_EVIDENCE_EXHAUSTED' };
}

function buildDynamicDefensePhaseReport(evidence = {}) {
  invariant(evidence && typeof evidence === 'object' && !Array.isArray(evidence),
    'evidence must be an object');
  invariant((evidence.exact_build ?? EXACT_BUILD) === EXACT_BUILD, 'exact-build mismatch');
  const mechanicsManifest = evidence.mechanics_manifest || null;
  if (mechanicsManifest) {
    invariant(mechanicsManifest.schema === 'ROFL_EXACT_BUILD_MECHANICS_MANIFEST_V1',
      'mechanics manifest schema mismatch');
    invariant(mechanicsManifest.exact_build === EXACT_BUILD, 'mechanics manifest exact-build mismatch');
  }
  const baseStats = (evidence.base_stat_requests || []).map((request) => baseStatAtLevel({
    ...request,
    mechanicsManifest,
    mechanicsMetadata: evidence.mechanics_metadata,
    requestedBuild: EXACT_BUILD,
  }));
  const eventResults = (evidence.damage_event_inputs || []).map(effectiveDefenseForDamageEvent);
  const routerPlans = (evidence.acquisition_requests || []).map(createSemanticAcquisitionPlan);
  const exhaustedEdges = normalizeExhaustedEdges(evidence.exhausted_edges || []);
  const armorEffective = summarizeEventResults(eventResults, 'EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT');
  const mrEffective = summarizeEventResults(eventResults, 'EFFECTIVE_MR_FOR_DAMAGE_EVENT');
  const currentArmor = summarizeStateResults(eventResults, 'CURRENT_ARMOR_STATE');
  const currentMr = summarizeStateResults(eventResults, 'CURRENT_MAGIC_RESIST_STATE');
  const baseArmor = baseStats.filter((stat) => stat.stat === 'ARMOR');
  const baseMr = baseStats.filter((stat) => stat.stat === 'MAGIC_RESIST');
  const baseArmorStatus = baseArmor.length > 0 && baseArmor.every(eligible)
    ? 'PUBLICATION_ELIGIBLE' : 'UNKNOWN';
  const baseMrStatus = baseMr.length > 0 && baseMr.every(eligible)
    ? 'PUBLICATION_ELIGIBLE' : 'UNKNOWN';
  const priorQuestions = evidence.prior_stat_combat_baseline?.research_questions
    || priorResearchQuestions();
  const matrix = {
    A: row('STATUS', 'PENDING_PHASE_STATUS', 'Computed after all A-Z rows and exhaustion edges are evaluated.'),
    B: row('EXACT-BUILD MECHANICS', mechanicsStatus(mechanicsManifest),
      `Exact-build identity does not itself authorize component semantics or formulas. Defense field registry: ${statusOf(evidence.exact_build_defense_registry, 'MISSING_REQUIRED_INPUT')}.`,
    evidence.exact_build_defense_registry ? [{
      artifact_type: evidence.exact_build_defense_registry.artifact_type,
      runtime_image_sha256: evidence.exact_build_defense_registry.runtime_image?.sha256,
    }] : []),
    C: row('BASE STAT ENGINE', baseArmorStatus === 'PUBLICATION_ELIGIBLE'
      && baseMrStatus === 'PUBLICATION_ELIGIBLE' ? 'PUBLICATION_ELIGIBLE' : 'FAIL_CLOSED',
    'Only hash-pinned, stat-specific mechanics definitions may emit base values.'),
    D: row('ITEM STAT ENGINE', evidence.item_presentation_inventory?.mechanics_consumer_eligible === false
      ? 'PRESENTATION_ONLY_NOT_MECHANICS' : componentStatus(mechanicsManifest, 'item'),
    'Always-active and conditional item effects remain distinct; client presentation text cannot authorize mechanics.',
    evidence.item_presentation_inventory ? [{
      status: evidence.item_presentation_inventory.status,
      source_sha256: evidence.item_presentation_inventory.source?.sha256,
    }] : []),
    E: row('RUNE STATE', componentStatus(mechanicsManifest, 'rune'),
      'Absent rune state is never treated as a zero modifier.'),
    F: row('DYNAMIC STAT MODIFIERS', statusOf(evidence.dynamic_modifier_state),
      'Persistent, temporary, lifecycle, and event modifiers require time-aligned provenance.'),
    G: row('ARMOR REDUCTION', statusOf(evidence.armor_reduction_state),
      'Target reduction operation and amount semantics must be direct or exact-build verified.'),
    H: row('MR REDUCTION', statusOf(evidence.magic_resist_reduction_state),
      'Target reduction operation and amount semantics must be direct or exact-build verified.'),
    I: row('ATTACKER ARMOR PENETRATION', statusOf(evidence.attacker_armor_pen_state),
      'No remembered penetration ordering is supplied.'),
    J: row('ATTACKER MAGIC PENETRATION', statusOf(evidence.attacker_magic_pen_state),
      'No remembered penetration ordering is supplied.'),
    K: row('CURRENT ARMOR STATE', currentArmor.status,
      'Current armor is distinct from base and baseline armor.'),
    L: row('CURRENT MAGIC RESIST STATE', currentMr.status,
      'Current magic resist is distinct from base and baseline magic resist.'),
    M: row('EFFECTIVE ARMOR PER DAMAGE EVENT', armorEffective.status,
      'Direct final formula output may prevail only when the dynamic-defense contract verifies it; otherwise reconstruction requires complete current state and exact ordering.'),
    N: row('EFFECTIVE MR PER DAMAGE EVENT', mrEffective.status,
      'Direct final formula output may prevail only when the dynamic-defense contract verifies it; otherwise reconstruction requires complete current state and exact ordering.'),
    O: row('DAMAGE STAGE', untrustedPublicationStatus(closureState(evidence, 'damage_stage')),
      'Recorded damage amount is not reinterpreted as pre- or post-mitigation.'),
    P: row('DAMAGE MITIGATION', untrustedPublicationStatus(closureState(evidence, 'mitigation')),
      'Mitigation requires damage stage and event-level effective defense.'),
    Q: row('SHIELD GENERATED', untrustedPublicationStatus(closureState(evidence, 'shield_generated')),
      'Generated shield amount is kept separate from absorption.'),
    R: row('SHIELD ABSORBED', untrustedPublicationStatus(closureState(evidence, 'shield_absorbed')),
      'Target-total absorption does not imply source or instance identity.'),
    S: row('SHIELD INSTANCE/SOURCE/REMAINING', untrustedPublicationStatus(closureState(evidence, 'shield_lifecycle')),
      'Instance identity, layer ordering, expiry, replacement, and remaining value must close together.'),
    T: row('HEAL REPORTED', untrustedPublicationStatus(closureState(evidence, 'heal_reported')),
      'Reported heal is retained without claiming health application.'),
    U: row('HEAL EFFECTIVE/OVERHEAL', untrustedPublicationStatus(closureState(evidence, 'heal_effective')),
      'Effective heal and overheal require ordered HP anchors and clamp semantics.'),
    V: row('CURRENT HP/REGEN', untrustedPublicationStatus(closureState(evidence, 'current_hp')),
      'CurrentHP requires an absolute anchor and complete ordered mutation families.'),
    W: row('SEMANTIC ACQUISITION ROUTER', routerPlans.length ? 'ADVISORY_PLANS_READY' : 'NO_REQUESTS',
      'Plans route dependencies and ownership only; no acquisition was performed.'),
    X: row('SEMANTIC DEPENDENCY GRAPH', routerPlans.length ? 'BOUND_TO_ROUTER' : 'AVAILABLE_ADVISORY',
      'Dependencies do not promote missing semantics.'),
    Y: row('VERSION MIGRATION IMPACT', 'AUTO_FIRST_MANUAL_LAST',
      'Future builds must rebind exact-build hashes, component semantics, and runtime fingerprints.'),
    Z: row('TRUE REMAINING BLOCKERS', exhaustedEdges.length ? 'EXHAUSTED_EDGES_ENUMERATED' : 'MISSING_EXHAUSTION_REGISTRY',
      exhaustedEdges.length ? `${exhaustedEdges.length} bounded exhausted edges recorded.`
        : 'No bounded exhausted-edge record was supplied.'),
  };
  const phase = computePhaseStatus({
    matrix,
    exhaustedEdges,
    eventResults,
    exhaustionRegistryComplete: evidence.exhaustion_registry_complete === true,
    allIndependentRouteFamiliesExecuted:
      evidence.all_independent_route_families_executed === true,
  });
  matrix.A = row('STATUS', phase.status,
    'The status reflects publication closure and supplied bounded-route exhaustion; partial mechanics do not imply global Replay exhaustion.');
  const researchQuestions = {
    Q1: 'YES_FOR_REGISTERED_RULES_FAIL_CLOSED_FOR_UNREGISTERED — The router deterministically selects Replay, static mechanics, derived state, DETAILS, controlled truth, client-local, or unavailable source classes for registered semantics. An unregistered request receives an UNAVAILABLE_WITH_CURRENT_EVIDENCE/CONTROLLED_GROUND_TRUTH_REQUIRED plan and never authorizes an untargeted Replay scan.',
    Q2: 'CURRENT_DECLARED_HYPOTHESES_EXHAUSTED — Build 16.16 is DOMAIN_EVIDENCE_EXHAUSTED and LOCAL_HYPOTHESIS_EXHAUSTED only for the bounded routes recorded here. GLOBAL_REPLAY_NOT_EXHAUSTIVELY_SEMANTIC remains true; FULLY_EXHAUSTED is expressly rejected.',
    Q3: 'POTENTIALLY_PRESENT_WITHOUT_HIGH_INFORMATION_ANCHOR — Preserved Replay candidates include 0x0412 modifier target/operation/amount/lifecycle semantics; current Armor/MR selectors or writers; time-aligned reduction and penetration state; damage-stage consumers; shield instance/source/remaining lifecycle; heal application/effective delta; CurrentHP/regen transitions; and rune selection/proc state. This is a candidate inventory, not a claim that every semantic is present.',
    Q4: 'DETERMINISTIC_MECHANICS_FIRST — Champion base/growth formulas, structured item and rune effects, stat enums, modifier operation definitions, reduction/penetration ordering, mitigation formulas, caps, and exact-build constants belong in the version-bound mechanics layer. Replay is needed for actual participants, timing, conditions, and event state, not for blind rediscovery of deterministic rules.',
    Q5: 'NO_SPECIFIC_DYNAMIC_DEFENSE_SEMANTIC_PROVEN_CLIENT_LOCAL — No unresolved dynamic-defense field is promoted to client-local merely because Replay evidence is missing. UI/HUD-only presentation or locally computed runtime values with no replicated/accessor evidence must remain CLIENT_LOCAL_RUNTIME_ONLY or UNAVAILABLE_WITH_CURRENT_EVIDENCE until exact-build evidence binds them.',
    Q6: 'YES — SEMANTIC_ACQUISITION_PLAN is generated directly with desired precision, candidate and preferred sources, fallback, dependencies, existing and missing capabilities, reverse-engineering/mechanics/ground-truth flags, expected evidence grade, ownership, and reopening triggers. The router is advisory and performs no source acquisition or full Replay scan.',
  };
  const combatClosureSnapshot = {
    base_defense: `Base Armor/MR at level: ${baseArmorStatus}/${baseMrStatus}. No familiar level-growth formula was assumed.`,
    current_defense: `Current Armor/MR: ${matrix.K.status}/${matrix.L.status}. Base, baseline, and current states are not conflated.`,
    effective_defense: `Effective Armor/MR: ${matrix.M.status}/${matrix.N.status}. Missing order or state fails closed.`,
    damage: `Damage stage/mitigation: ${matrix.O.status}/${matrix.P.status}. ${priorQuestions.Q4 || ''}`.trim(),
    shield: `Generated/absorbed/lifecycle: ${matrix.Q.status}/${matrix.R.status}/${matrix.S.status}.`,
    heal_and_hp: `Reported heal/effective heal/CurrentHP: ${matrix.T.status}/${matrix.U.status}/${matrix.V.status}.`,
  };
  return stableValue({
    schema: SCHEMA,
    schema_version: 1,
    exact_build: EXACT_BUILD,
    status: phase.status,
    stop_condition: phase.stop_condition,
    architecture_gate: 'PASS',
    parser_boundary: 'FACTUAL_SEMANTIC_SUPPORT_ONLY_NO_ACQUISITION_NO_MAP_NO_BEHAVIOR_NO_UI',
    defense_state_summary: {
      armor: {
        base_at_level: { status: baseArmorStatus, publication_eligible: baseArmorStatus === 'PUBLICATION_ELIGIBLE' },
        baseline: summarizeStateResults(eventResults, 'BASELINE_ARMOR_STATE'),
        current: summarizeStateResults(eventResults, 'CURRENT_ARMOR_STATE'),
        effective_for_event: armorEffective,
      },
      magic_resist: {
        base_at_level: { status: baseMrStatus, publication_eligible: baseMrStatus === 'PUBLICATION_ELIGIBLE' },
        baseline: summarizeStateResults(eventResults, 'BASELINE_MAGIC_RESIST_STATE'),
        current: summarizeStateResults(eventResults, 'CURRENT_MAGIC_RESIST_STATE'),
        effective_for_event: mrEffective,
      },
      non_equivalence_rule: 'BASE_AT_LEVEL_NE_BASELINE_NE_CURRENT_NE_EFFECTIVE_FOR_EVENT',
    },
    base_stat_results: baseStats,
    effective_defense_results: eventResults,
    acquisition_plans: routerPlans,
    final_report_A_to_Z: matrix,
    research_questions: researchQuestions,
    combat_closure_snapshot: combatClosureSnapshot,
    exhausted_edge_registry: exhaustedEdges,
    evidence_inventory: stableValue(evidence.evidence_inventory || []),
    global_replay_exhausted: false,
    new_replay_required: 'NO_BY_DEFAULT',
    source_acquisition_performed: false,
    boundaries: { data_discovery: false, replay_acquisition: false, map_truth: false,
      behavior_inference: false, ui: false, counterfactual: false },
    protected_holdout: HOLDOUT_ACCESS,
  });
}

function renderDynamicDefenseMarkdown(report) {
  const lines = ['# ROFL dynamic defense and combat semantic phase', '',
    `Status: **${report.status}** (${report.stop_condition})`, '', '## A–Z', ''];
  for (const [letter, value] of Object.entries(report.final_report_A_to_Z)) {
    lines.push(`### ${letter}. ${value.topic}`, '', `**${value.status}** — ${value.decision}`, '');
  }
  lines.push('## Q1–Q6', '');
  for (const [question, answer] of Object.entries(report.research_questions)) {
    lines.push(`- **${question}:** ${answer}`);
  }
  lines.push('', '## Supplemental combat closure snapshot', '');
  for (const [topic, answer] of Object.entries(report.combat_closure_snapshot)) {
    lines.push(`- **${topic}:** ${answer}`);
  }
  lines.push('', 'Protected Holdout access: none.', '');
  return `${lines.join('\n')}\n`;
}

function writeDynamicDefensePhaseArtifacts({ outputDir, evidence = {} } = {}) {
  invariant(typeof outputDir === 'string' && outputDir.length > 0, 'outputDir is required');
  const prospective = canonicalizeProspectiveSafePath(outputDir, 'dynamic defense output directory');
  fs.mkdirSync(prospective, { recursive: true });
  const target = canonicalizeExistingSafePath(prospective, 'dynamic defense output directory');
  const report = buildDynamicDefensePhaseReport(evidence);
  const documents = {
    'dynamic_defense_semantic_report.json': stableJson(report),
    'DYNAMIC_DEFENSE_SEMANTIC_REPORT.md': renderDynamicDefenseMarkdown(report),
    'effective_defense_results.json': stableJson({ schema: 'ROFL_EFFECTIVE_DEFENSE_RESULT_SET_V1',
      exact_build: EXACT_BUILD, results: report.effective_defense_results }),
    'semantic_acquisition_plans.json': stableJson({ schema: 'SEMANTIC_ACQUISITION_PLAN_SET_V1',
      exact_build: EXACT_BUILD, plans: report.acquisition_plans }),
    'exhausted_edge_registry.json': stableJson({ schema: 'ROFL_EXHAUSTED_EDGE_REGISTRY_V1',
      exact_build: EXACT_BUILD, global_replay_exhausted: false, edges: report.exhausted_edge_registry }),
    'evidence_inventory.json': stableJson({ schema: 'ROFL_DYNAMIC_DEFENSE_EVIDENCE_INVENTORY_V1',
      exact_build: EXACT_BUILD, sources: report.evidence_inventory }),
  };
  const artifacts = [];
  const paths = {};
  for (const [name, text] of Object.entries(documents)) {
    const file = canonicalizeProspectiveSafePath(path.join(target, name), `dynamic defense artifact ${name}`);
    fs.writeFileSync(file, text, 'utf8');
    paths[name] = canonicalizeExistingSafePath(file, `dynamic defense artifact ${name}`);
    artifacts.push({ path: name, bytes: fs.statSync(file).size, sha256: sha256File(file) });
  }
  artifacts.sort((left, right) => left.path.localeCompare(right.path));
  const manifest = stableValue({
    schema: 'ROFL_DYNAMIC_DEFENSE_SEMANTIC_ARTIFACT_MANIFEST_V1',
    exact_build: EXACT_BUILD,
    status: report.status,
    artifacts,
    protected_holdout: HOLDOUT_ACCESS,
  });
  const manifestFile = canonicalizeProspectiveSafePath(path.join(target, 'artifact_manifest.json'),
    'dynamic defense artifact manifest');
  fs.writeFileSync(manifestFile, stableJson(manifest), 'utf8');
  paths['artifact_manifest.json'] = canonicalizeExistingSafePath(manifestFile,
    'dynamic defense artifact manifest');
  return { report, manifest, paths: stableValue(paths), manifest_sha256: digest(stableJson(manifest)) };
}

module.exports = {
  EXACT_BUILD,
  HOLDOUT_ACCESS,
  SCHEMA,
  buildDynamicDefensePhaseReport,
  effectiveDefenseForDamageEvent,
  effective_defense_for_damage_event: effectiveDefenseForDamageEvent,
  renderDynamicDefenseMarkdown,
  stableJson,
  writeDynamicDefensePhaseArtifacts,
};
