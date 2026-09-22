'use strict';

// This module is deliberately advisory.  It records what a semantic question
// needs and who owns the next action; it never acquires inputs or reinterprets
// another project's evidence.

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SCHEMA = 'ROFL_SEMANTIC_ACQUISITION_ROUTER_V1';
const EXACT_BUILD = '16.16.805.0442';

const SOURCE_CLASSES = Object.freeze([
  'REPLAY_DIRECT',
  'REPLAY_RUNTIME_SEMANTIC',
  'REPLAY_PLUS_MECHANICS_DERIVED',
  'STATIC_GAME_DATA',
  'DETAILS_LOW_PRECISION',
  'CONTROLLED_GROUND_TRUTH_REQUIRED',
  'CLIENT_LOCAL_RUNTIME_ONLY',
  'UNAVAILABLE_WITH_CURRENT_EVIDENCE',
]);

const OWNERSHIP_REGISTRY = Object.freeze({
  ROFL_PARSER: Object.freeze({
    owns: Object.freeze(['REPLAY_PROTOCOL_SEMANTICS', 'EXACT_BUILD_CAPABILITY_MANIFEST',
      'SEMANTIC_DEPENDENCY_GRAPH', 'SEMANTIC_ACQUISITION_PLAN_ROUTING']),
    forbids: Object.freeze(['REPLAY_ACQUISITION', 'OFFLINE_CORPUS_ACQUISITION',
      'DETAILS_REINTERPRETATION', 'LIVE_CLIENT_RUNTIME', 'MAP_TRUTH', 'BEHAVIOR_INFERENCE']),
  }),
  RESEARCH_COLLECTOR: Object.freeze({
    owns: Object.freeze(['OFFLINE_CORPUS_ACQUISITION', 'PAIRED_DETAILS_REPLAY_PRESERVATION']),
    forbids: Object.freeze(['REPLAY_PROTOCOL_SEMANTICS', 'LIVE_CLIENT_RUNTIME', 'MAP_TRUTH']),
  }),
  LOL_INFERENCE_LAB: Object.freeze({
    owns: Object.freeze(['DETAILS_REINTERPRETATION', 'MAP_TRUTH', 'BEHAVIOR_INFERENCE',
      'MECHANICS_INTERPRETATION', 'GROUND_TRUTH_INTERPRETATION']),
    forbids: Object.freeze(['REPLAY_ACQUISITION', 'LIVE_CLIENT_RUNTIME', 'REPLAY_PROTOCOL_SEMANTICS']),
  }),
  AKARI: Object.freeze({
    owns: Object.freeze(['REPLAY_ACQUISITION', 'LIVE_CLIENT_RUNTIME', 'RUNTIME_HISTORY_ACQUISITION',
      'CACHE_SCHEDULING_UI']),
    forbids: Object.freeze(['REPLAY_PROTOCOL_SEMANTICS', 'MAP_TRUTH', 'BEHAVIOR_INFERENCE']),
  }),
});

const ACTION_OWNERS = Object.freeze({
  REPLAY_ACQUISITION: Object.freeze(['RESEARCH_COLLECTOR', 'AKARI']),
  OFFLINE_CORPUS_ACQUISITION: Object.freeze(['RESEARCH_COLLECTOR']),
  DETAILS_REINTERPRETATION: Object.freeze(['LOL_INFERENCE_LAB']),
  LIVE_CLIENT_RUNTIME: Object.freeze(['AKARI']),
  MAP_TRUTH: Object.freeze(['LOL_INFERENCE_LAB']),
  BEHAVIOR_INFERENCE: Object.freeze(['LOL_INFERENCE_LAB']),
  REPLAY_PROTOCOL_SEMANTICS: Object.freeze(['ROFL_PARSER']),
  SEMANTIC_ACQUISITION_PLAN_ROUTING: Object.freeze(['ROFL_PARSER']),
});

const EXHAUSTION_STATUS = Object.freeze({
  DOMAIN_EVIDENCE_EXHAUSTED: 'Current declared route family has no remaining supported edge.',
  LOCAL_HYPOTHESIS_EXHAUSTED: 'The bounded hypothesis/search plan is exhausted, not Replay.',
  GLOBAL_REPLAY_NOT_EXHAUSTIVELY_SEMANTIC:
    'The exact-build Replay corpus remains a preserved, non-exhaustively-semantic space.',
});

const CURRENT_CAPABILITIES = Object.freeze({
  ARMOR: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'CONDITIONALLY_DERIVED', limitations: ['complete exact-build dynamic state unavailable'] }),
  LEVEL_TRANSITION: Object.freeze({ owner: 'ROFL_PARSER', status: 'AVAILABLE', grade: 'VERIFIED_DIRECT_OR_BUILD_BOUND_DERIVED' }),
  HERO_DAMAGE: Object.freeze({ owner: 'ROFL_PARSER', status: 'AVAILABLE', grade: 'VERIFIED_DIRECT', limitations: ['amount_stage_unknown'] }),
  INVENTORY_STATE: Object.freeze({ owner: 'ROFL_PARSER', status: 'AVAILABLE', grade: 'VERIFIED_DIRECT_PARTIAL', limitations: ['cause_agnostic', 'complete_state_not_available'] }),
  STAT_FORMULA_OUTPUTS: Object.freeze({ owner: 'ROFL_PARSER', status: 'PARTIAL', grade: 'VERIFIED_STRUCTURE', limitations: ['only ManaRegen selector mapped', 'Armor/AbilityHaste selector unavailable'] }),
  BUFF_STAT_MODIFIER_SEMANTICS: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNKNOWN', grade: 'VERIFIED_STRUCTURE_ONLY', limitations: ['target_stat_operation_amount_unresolved'] }),
  RUNE_STATE: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'UNAVAILABLE' }),
  EXACT_BUILD_MECHANICS_MANIFEST: Object.freeze({ owner: 'ROFL_PARSER', status: 'PARTIAL', grade: 'VERIFIED_DIRECT_PARTIAL', limitations: ['champion root rows only', 'no verified growth formula', 'no item/rune/buff mechanics permission'] }),
  EXACT_BUILD_CHAMPION_STAT_ROWS: Object.freeze({ owner: 'ROFL_PARSER', status: 'AVAILABLE', grade: 'VERIFIED_DIRECT_PARTIAL_PER_FIELD', limitations: ['alternate-mode and special rows preserve explicit missing fields', 'no level-growth formula permission'] }),
  EXACT_BUILD_DEFENSE_FIELD_REGISTRY: Object.freeze({ owner: 'ROFL_PARSER', status: 'AVAILABLE', grade: 'VERIFIED_DIRECT_STATIC_REGISTRY', limitations: ['field identity and struct offset only', 'no selector, operation, stacking, or order semantics'] }),
  EXACT_BUILD_GROWTH_FORMULA: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'UNAVAILABLE' }),
  EXACT_BUILD_ITEM_MECHANICS: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'PRESENTATION_ONLY_NOT_MECHANICS' }),
  EXACT_BUILD_MITIGATION_ORDER: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'UNAVAILABLE' }),
  ARMOR_REDUCTION_STATE: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'UNAVAILABLE' }),
  ATTACKER_ARMOR_PEN_STATE: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'UNAVAILABLE' }),
  DYNAMIC_DEFENSE_MODIFIER_STATE: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNKNOWN', grade: 'VERIFIED_STRUCTURE_ONLY' }),
  DAMAGE_STAGE: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'EVIDENCE_EXHAUSTED' }),
  CURRENT_HP: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'EVIDENCE_EXHAUSTED' }),
  ABSOLUTE_HP_ANCHOR: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'UNAVAILABLE' }),
  HP_MUTATION_COVERAGE: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'UNAVAILABLE' }),
  MAX_HP: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'CONDITIONALLY_DERIVED' }),
  SHIELD_GENERATED: Object.freeze({ owner: 'ROFL_PARSER', status: 'AVAILABLE', grade: 'VERIFIED_DIRECT' }),
  SHIELD_ABSORBED_TARGET_TOTAL: Object.freeze({ owner: 'ROFL_PARSER', status: 'AVAILABLE', grade: 'VERIFIED_DIRECT' }),
  SHIELD_INSTANCE_LIFECYCLE: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'EVIDENCE_EXHAUSTED' }),
  HEAL_REPORTED: Object.freeze({ owner: 'ROFL_PARSER', status: 'AVAILABLE', grade: 'VERIFIED_DIRECT' }),
  HEAL_APPLICATION: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'EVIDENCE_EXHAUSTED' }),
  OBJECTIVE_ENTITY_LIFECYCLE: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'UNAVAILABLE' }),
  ORDINARY_MONSTER_CAMP_CLEAR: Object.freeze({ owner: 'ROFL_PARSER', status: 'UNAVAILABLE', grade: 'CAMP_CLEAR_DIRECT_UNAVAILABLE' }),
  DETAILS_TIMING: Object.freeze({ owner: 'RESEARCH_COLLECTOR', status: 'AVAILABLE', grade: 'DETAILS_DIRECT_OR_DERIVED' }),
  DETAILS_PROXY_CALIBRATION: Object.freeze({ owner: 'LOL_INFERENCE_LAB', status: 'CONDITIONAL', grade: 'DETAILS_CALIBRATED' }),
  CURRENT_MATCH: Object.freeze({ owner: 'AKARI', status: 'AVAILABLE', grade: 'RUNTIME_SOURCE' }),
});

const SEMANTIC_DEPENDENCY_GRAPH = Object.freeze({
  schema: 'ROFL_SEMANTIC_DEPENDENCY_GRAPH_V1',
  exact_build: EXACT_BUILD,
  boundary: 'PARSER_FACTS_AND_CROSS_PROJECT_INTERFACES_ONLY',
  nodes: Object.freeze({
    BASE_STAT_AT_LEVEL: Object.freeze(['LEVEL_TRANSITION', 'EXACT_BUILD_CHAMPION_STAT_ROWS',
      'EXACT_BUILD_GROWTH_FORMULA']),
    ITEM_STAT_CONTRIBUTION: Object.freeze(['INVENTORY_STATE', 'EXACT_BUILD_ITEM_MECHANICS']),
    ARMOR: Object.freeze(['LEVEL_TRANSITION', 'INVENTORY_STATE', 'RUNE_STATE',
      'BUFF_STAT_MODIFIER_SEMANTICS', 'EXACT_BUILD_MECHANICS_MANIFEST',
      'EXACT_BUILD_CHAMPION_STAT_ROWS', 'EXACT_BUILD_DEFENSE_FIELD_REGISTRY',
      'DYNAMIC_DEFENSE_MODIFIER_STATE']),
    EFFECTIVE_DEFENSE_FOR_DAMAGE_EVENT: Object.freeze(['HERO_DAMAGE', 'ARMOR',
      'ARMOR_REDUCTION_STATE', 'ATTACKER_ARMOR_PEN_STATE', 'EXACT_BUILD_MITIGATION_ORDER']),
    ABILITY_HASTE: Object.freeze(['STAT_FORMULA_OUTPUTS', 'INVENTORY_STATE', 'RUNE_STATE',
      'BUFF_STAT_MODIFIER_SEMANTICS', 'EXACT_BUILD_MECHANICS_MANIFEST']),
    DAMAGE_STAGE: Object.freeze(['HERO_DAMAGE', 'CURRENT_HP']),
    MITIGATION_CLOSURE: Object.freeze(['HERO_DAMAGE', 'ARMOR', 'DAMAGE_STAGE',
      'EXACT_BUILD_MITIGATION_ORDER']),
    SHIELD_LIFECYCLE: Object.freeze(['SHIELD_GENERATED', 'SHIELD_ABSORBED_TARGET_TOTAL',
      'SHIELD_INSTANCE_LIFECYCLE']),
    HEAL_EFFECTIVE_OVERHEAL: Object.freeze(['HEAL_REPORTED', 'HEAL_APPLICATION',
      'CURRENT_HP', 'MAX_HP']),
    CURRENT_HP: Object.freeze(['ABSOLUTE_HP_ANCHOR', 'HP_MUTATION_COVERAGE']),
    OBJECTIVE_STATE: Object.freeze(['OBJECTIVE_ENTITY_LIFECYCLE']),
    CAMP_STATE: Object.freeze(['ORDINARY_MONSTER_CAMP_CLEAR']),
  }),
  exhaustion_status: EXHAUSTION_STATUS,
  protected_holdout: Object.freeze({ read: false, enumerated: false, hashed: false, decoded: false, tested: false, consumed: false }),
});

const SEMANTIC_RULES = Object.freeze({
  BASE_STAT_AT_LEVEL: Object.freeze({
    candidate_sources: ['STATIC_GAME_DATA', 'REPLAY_RUNTIME_SEMANTIC', 'UNAVAILABLE_WITH_CURRENT_EVIDENCE'],
    best_primary_source: 'STATIC_GAME_DATA', fallback_source: 'REPLAY_RUNTIME_SEMANTIC',
    dependencies: SEMANTIC_DEPENDENCY_GRAPH.nodes.BASE_STAT_AT_LEVEL,
    reverse_engineering_required: true, mechanics_required: true, ground_truth_required: false,
    expected_evidence_grade: 'PARTIAL',
  }),
  ITEM_STAT_CONTRIBUTION: Object.freeze({
    candidate_sources: ['STATIC_GAME_DATA', 'REPLAY_RUNTIME_SEMANTIC', 'UNAVAILABLE_WITH_CURRENT_EVIDENCE'],
    best_primary_source: 'STATIC_GAME_DATA', fallback_source: 'REPLAY_RUNTIME_SEMANTIC',
    dependencies: SEMANTIC_DEPENDENCY_GRAPH.nodes.ITEM_STAT_CONTRIBUTION,
    reverse_engineering_required: true, mechanics_required: true, ground_truth_required: false,
    expected_evidence_grade: 'UNAVAILABLE',
  }),
  ARMOR: Object.freeze({
    candidate_sources: ['REPLAY_RUNTIME_SEMANTIC', 'REPLAY_PLUS_MECHANICS_DERIVED', 'STATIC_GAME_DATA'],
    best_primary_source: 'REPLAY_RUNTIME_SEMANTIC', fallback_source: 'REPLAY_PLUS_MECHANICS_DERIVED',
    dependencies: SEMANTIC_DEPENDENCY_GRAPH.nodes.ARMOR, reverse_engineering_required: true,
    mechanics_required: true, ground_truth_required: false, expected_evidence_grade: 'CANDIDATE',
  }),
  EFFECTIVE_DEFENSE_FOR_DAMAGE_EVENT: Object.freeze({
    candidate_sources: ['REPLAY_PLUS_MECHANICS_DERIVED', 'REPLAY_RUNTIME_SEMANTIC', 'CONTROLLED_GROUND_TRUTH_REQUIRED'],
    best_primary_source: 'REPLAY_PLUS_MECHANICS_DERIVED', fallback_source: 'REPLAY_RUNTIME_SEMANTIC',
    dependencies: SEMANTIC_DEPENDENCY_GRAPH.nodes.EFFECTIVE_DEFENSE_FOR_DAMAGE_EVENT,
    reverse_engineering_required: true, mechanics_required: true, ground_truth_required: true,
    expected_evidence_grade: 'UNAVAILABLE',
  }),
  ABILITY_HASTE: Object.freeze({
    candidate_sources: ['REPLAY_RUNTIME_SEMANTIC', 'STATIC_GAME_DATA', 'REPLAY_PLUS_MECHANICS_DERIVED'],
    best_primary_source: 'REPLAY_RUNTIME_SEMANTIC', fallback_source: 'STATIC_GAME_DATA',
    dependencies: SEMANTIC_DEPENDENCY_GRAPH.nodes.ABILITY_HASTE, reverse_engineering_required: true,
    mechanics_required: true, ground_truth_required: false, expected_evidence_grade: 'CANDIDATE',
  }),
  DAMAGE_STAGE: Object.freeze({
    candidate_sources: ['REPLAY_RUNTIME_SEMANTIC', 'CONTROLLED_GROUND_TRUTH_REQUIRED',
      'UNAVAILABLE_WITH_CURRENT_EVIDENCE'],
    best_primary_source: 'REPLAY_RUNTIME_SEMANTIC', fallback_source: 'CONTROLLED_GROUND_TRUTH_REQUIRED',
    dependencies: SEMANTIC_DEPENDENCY_GRAPH.nodes.DAMAGE_STAGE,
    reverse_engineering_required: true, mechanics_required: false, ground_truth_required: true,
    expected_evidence_grade: 'UNAVAILABLE',
  }),
  MITIGATION_CLOSURE: Object.freeze({
    candidate_sources: ['REPLAY_PLUS_MECHANICS_DERIVED', 'REPLAY_RUNTIME_SEMANTIC',
      'CONTROLLED_GROUND_TRUTH_REQUIRED'],
    best_primary_source: 'REPLAY_PLUS_MECHANICS_DERIVED', fallback_source: 'REPLAY_RUNTIME_SEMANTIC',
    dependencies: SEMANTIC_DEPENDENCY_GRAPH.nodes.MITIGATION_CLOSURE,
    reverse_engineering_required: true, mechanics_required: true, ground_truth_required: true,
    expected_evidence_grade: 'UNAVAILABLE',
  }),
  SHIELD_LIFECYCLE: Object.freeze({
    candidate_sources: ['REPLAY_RUNTIME_SEMANTIC', 'CONTROLLED_GROUND_TRUTH_REQUIRED',
      'UNAVAILABLE_WITH_CURRENT_EVIDENCE'],
    best_primary_source: 'REPLAY_RUNTIME_SEMANTIC', fallback_source: 'CONTROLLED_GROUND_TRUTH_REQUIRED',
    dependencies: SEMANTIC_DEPENDENCY_GRAPH.nodes.SHIELD_LIFECYCLE,
    reverse_engineering_required: true, mechanics_required: false, ground_truth_required: true,
    expected_evidence_grade: 'PARTIAL',
  }),
  HEAL_EFFECTIVE_OVERHEAL: Object.freeze({
    candidate_sources: ['REPLAY_RUNTIME_SEMANTIC', 'CONTROLLED_GROUND_TRUTH_REQUIRED',
      'UNAVAILABLE_WITH_CURRENT_EVIDENCE'],
    best_primary_source: 'REPLAY_RUNTIME_SEMANTIC', fallback_source: 'CONTROLLED_GROUND_TRUTH_REQUIRED',
    dependencies: SEMANTIC_DEPENDENCY_GRAPH.nodes.HEAL_EFFECTIVE_OVERHEAL,
    reverse_engineering_required: true, mechanics_required: false, ground_truth_required: true,
    expected_evidence_grade: 'UNAVAILABLE',
  }),
  CURRENT_HP: Object.freeze({
    candidate_sources: ['REPLAY_RUNTIME_SEMANTIC', 'CLIENT_LOCAL_RUNTIME_ONLY',
      'CONTROLLED_GROUND_TRUTH_REQUIRED'],
    best_primary_source: 'REPLAY_RUNTIME_SEMANTIC', fallback_source: 'CLIENT_LOCAL_RUNTIME_ONLY',
    dependencies: SEMANTIC_DEPENDENCY_GRAPH.nodes.CURRENT_HP,
    reverse_engineering_required: true, mechanics_required: false, ground_truth_required: true,
    expected_evidence_grade: 'UNAVAILABLE',
  }),
  OBJECTIVE_STATE: Object.freeze({
    candidate_sources: ['REPLAY_RUNTIME_SEMANTIC', 'CONTROLLED_GROUND_TRUTH_REQUIRED', 'DETAILS_LOW_PRECISION'],
    best_primary_source: 'CONTROLLED_GROUND_TRUTH_REQUIRED', fallback_source: 'DETAILS_LOW_PRECISION',
    dependencies: SEMANTIC_DEPENDENCY_GRAPH.nodes.OBJECTIVE_STATE, reverse_engineering_required: true,
    mechanics_required: false, ground_truth_required: true, expected_evidence_grade: 'CANDIDATE',
  }),
  CAMP_STATE: Object.freeze({
    candidate_sources: ['UNAVAILABLE_WITH_CURRENT_EVIDENCE', 'CONTROLLED_GROUND_TRUTH_REQUIRED', 'DETAILS_LOW_PRECISION'],
    best_primary_source: 'UNAVAILABLE_WITH_CURRENT_EVIDENCE', fallback_source: 'DETAILS_LOW_PRECISION',
    dependencies: SEMANTIC_DEPENDENCY_GRAPH.nodes.CAMP_STATE, reverse_engineering_required: false,
    mechanics_required: false, ground_truth_required: true, expected_evidence_grade: 'UNAVAILABLE',
  }),
});

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort()
    .map((key) => [key, stableValue(value[key])]));
  return value;
}

function stableJson(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function hasProtectedHoldoutReference(location) {
  return /holdout/i.test(location.replaceAll('/', '\\'));
}

function nearestExistingAncestor(location) {
  let current = location;
  while (!fs.existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) return current;
    current = parent;
  }
  return current;
}

function realpath(location) {
  return fs.realpathSync.native ? fs.realpathSync.native(location) : fs.realpathSync(location);
}

function assertSafeOutputDirectory(outputDir) {
  const declared = path.resolve(outputDir);
  if (hasProtectedHoldoutReference(declared)) {
    throw new Error('protected Holdout output path is forbidden');
  }
  // Resolve the nearest existing parent before mkdir so a directory link cannot
  // redirect creation into a protected location. This is path metadata only.
  const ancestor = nearestExistingAncestor(declared);
  const physicalAncestor = realpath(ancestor);
  if (hasProtectedHoldoutReference(physicalAncestor)) {
    throw new Error('protected Holdout output path is forbidden after realpath resolution');
  }
  if (fs.existsSync(declared) && hasProtectedHoldoutReference(realpath(declared))) {
    throw new Error('protected Holdout output path is forbidden after realpath resolution');
  }
  return declared;
}

function normalizeSemanticName(value) {
  if (typeof value !== 'string' || !value.trim()) throw new TypeError('semantic_name must be a non-empty string');
  const normalized = value.trim().toUpperCase().replace(/[\s-]+/g, '_');
  if (/HOLDOUT|JUNGLE_OBJECTIVE_HOLDOUT/.test(normalized)) {
    throw new Error('protected Holdout references are forbidden');
  }
  const aliases = {
    CURRENT_ARMOR: 'ARMOR', CURRENT_ARMOR_STATE: 'ARMOR',
    CURRENT_MAGIC_RESIST: 'ARMOR', CURRENT_MAGIC_RESIST_STATE: 'ARMOR', CURRENT_MR: 'ARMOR',
    BASE_ARMOR_AT_LEVEL: 'BASE_STAT_AT_LEVEL', BASE_MAGIC_RESIST_AT_LEVEL: 'BASE_STAT_AT_LEVEL',
    CHAMPION_BASE_STAT: 'BASE_STAT_AT_LEVEL', ITEM_STATS: 'ITEM_STAT_CONTRIBUTION',
    EFFECTIVE_ARMOR_FOR_DAMAGE_EVENT: 'EFFECTIVE_DEFENSE_FOR_DAMAGE_EVENT',
    EFFECTIVE_ARMOR_FOR_HIT: 'EFFECTIVE_DEFENSE_FOR_DAMAGE_EVENT',
    EFFECTIVE_MR_FOR_DAMAGE_EVENT: 'EFFECTIVE_DEFENSE_FOR_DAMAGE_EVENT',
    DAMAGE_AMOUNT_STAGE: 'DAMAGE_STAGE', DAMAGE_MITIGATION: 'MITIGATION_CLOSURE',
    MITIGATION: 'MITIGATION_CLOSURE', SHIELD_GENERATED: 'SHIELD_LIFECYCLE',
    SHIELD_ABSORBED: 'SHIELD_LIFECYCLE', SHIELD_REMAINING: 'SHIELD_LIFECYCLE',
    SHIELD_INSTANCE: 'SHIELD_LIFECYCLE', HEAL_REPORTED: 'HEAL_EFFECTIVE_OVERHEAL',
    HEAL_EFFECTIVE: 'HEAL_EFFECTIVE_OVERHEAL', OVERHEAL: 'HEAL_EFFECTIVE_OVERHEAL',
    CURRENT_HP_STATE: 'CURRENT_HP', HEALTH_REGEN: 'CURRENT_HP',
    OBJECTIVE: 'OBJECTIVE_STATE', CAMP_CLEAR: 'CAMP_STATE', ORDINARY_MONSTER_CAMP_CLEAR: 'CAMP_STATE',
  };
  return aliases[normalized] || normalized;
}

function assertOwnership(action, owner) {
  if (!ACTION_OWNERS[action]) throw new Error(`unknown ownership action: ${action}`);
  if (!OWNERSHIP_REGISTRY[owner]) throw new Error(`unknown owner project: ${owner}`);
  if (!ACTION_OWNERS[action].includes(owner)) {
    throw new Error(`ownership violation: ${owner} cannot perform ${action}`);
  }
}

function validateRequest(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new TypeError('semantic acquisition request must be an object');
  }
  const semanticName = normalizeSemanticName(request.semantic_name);
  if (request.action || request.action_owner) assertOwnership(request.action, request.action_owner);
  if (request.owner_project && !OWNERSHIP_REGISTRY[request.owner_project]) {
    throw new Error(`unknown owner project: ${request.owner_project}`);
  }
  return semanticName;
}

function capabilitySlices(dependencies) {
  const existingCapabilities = [];
  const missingCapabilities = [];
  for (const capability of dependencies) {
    const state = CURRENT_CAPABILITIES[capability];
    if (!state) throw new Error(`unknown graph capability: ${capability}`);
    const row = { capability, ...state };
    if (state.status === 'AVAILABLE') existingCapabilities.push(row);
    else missingCapabilities.push(row);
  }
  return { existingCapabilities, missingCapabilities };
}

function genericRule(semanticName, request) {
  const source = request.source_hint === 'CLIENT_LOCAL_RUNTIME_ONLY'
    ? 'CLIENT_LOCAL_RUNTIME_ONLY' : 'UNAVAILABLE_WITH_CURRENT_EVIDENCE';
  return {
    candidate_sources: [source, 'CONTROLLED_GROUND_TRUTH_REQUIRED'], best_primary_source: source,
    fallback_source: 'CONTROLLED_GROUND_TRUTH_REQUIRED', dependencies: [], reverse_engineering_required: false,
    mechanics_required: false, ground_truth_required: true, expected_evidence_grade: 'UNAVAILABLE',
    note: `No registered Parser dependency rule exists for ${semanticName}; no packet scan is authorized.`,
  };
}

function createSemanticAcquisitionPlan(request) {
  const semanticName = validateRequest(request);
  const rule = SEMANTIC_RULES[semanticName] || genericRule(semanticName, request);
  const { existingCapabilities, missingCapabilities } = capabilitySlices(rule.dependencies);
  const desiredPrecision = request.desired_precision || 'EXACT_BUILD_SEMANTIC';
  return {
    schema: 'SEMANTIC_ACQUISITION_PLAN_V1',
    exact_build: EXACT_BUILD,
    semantic_name: semanticName,
    desired_precision: desiredPrecision,
    classification: rule.best_primary_source,
    candidate_sources: rule.candidate_sources.map((source_class) => ({
      source_class,
      owner: source_class === 'DETAILS_LOW_PRECISION' ? 'LOL_INFERENCE_LAB'
        : source_class === 'CLIENT_LOCAL_RUNTIME_ONLY' ? 'AKARI'
          : source_class === 'CONTROLLED_GROUND_TRUTH_REQUIRED' ? 'LOL_INFERENCE_LAB'
            : source_class === 'STATIC_GAME_DATA' ? 'ROFL_PARSER' : 'ROFL_PARSER',
    })),
    best_primary_source: rule.best_primary_source,
    fallback_source: rule.fallback_source,
    dependencies: [...rule.dependencies],
    known_dependencies: [...rule.dependencies],
    existing_capabilities: existingCapabilities,
    missing_capabilities: missingCapabilities,
    reverse_engineering_required: rule.reverse_engineering_required,
    mechanics_required: rule.mechanics_required,
    ground_truth_required: rule.ground_truth_required,
    expected_evidence_grade: rule.expected_evidence_grade,
    no_untargeted_full_replay_scan: true,
    allowed_reopening_triggers: ['new_semantic_question', 'runtime_cross_reference',
      'new_entity_system_evidence', 'new_exact_build_evidence'],
    exhaustion_status: EXHAUSTION_STATUS,
    parser_boundary: 'PLAN_ONLY_NO_ACQUISITION_NO_DETAILS_REINTERPRETATION_NO_LIVE_CLIENT',
    source_acquisition: {
      performed: false,
      status: 'NOT_PERFORMED_BY_ADVISORY_ROUTER',
    },
    protected_holdout: SEMANTIC_DEPENDENCY_GRAPH.protected_holdout,
    ...(rule.note ? { note: rule.note } : {}),
  };
}

function writeSemanticAcquisitionArtifacts({ outputDir, requests }) {
  if (!outputDir || typeof outputDir !== 'string') throw new TypeError('outputDir is required');
  if (!Array.isArray(requests) || requests.length === 0) throw new TypeError('requests must be a non-empty array');
  const safeOutput = assertSafeOutputDirectory(outputDir);
  fs.mkdirSync(safeOutput, { recursive: true });
  assertSafeOutputDirectory(safeOutput);
  const plans = requests.map(createSemanticAcquisitionPlan);
  const documents = {
    'semantic_acquisition_plans.json': { schema: 'SEMANTIC_ACQUISITION_PLAN_SET_V1', exact_build: EXACT_BUILD, plans },
    'semantic_dependency_graph.json': SEMANTIC_DEPENDENCY_GRAPH,
    'ownership_registry.json': { schema: 'ROFL_SEMANTIC_ROUTER_OWNERSHIP_V1', ownership_registry: OWNERSHIP_REGISTRY, action_owners: ACTION_OWNERS },
  };
  const artifacts = Object.entries(documents).map(([name, document]) => {
    const text = stableJson(document);
    fs.writeFileSync(path.join(safeOutput, name), text, 'utf8');
    return { path: name, bytes: Buffer.byteLength(text), sha256: sha256(text) };
  });
  const manifest = {
    schema: 'ROFL_SEMANTIC_ACQUISITION_ROUTER_ARTIFACT_MANIFEST_V1',
    exact_build: EXACT_BUILD,
    status: 'ADVISORY_PLAN_ARTIFACTS_ONLY_NO_SOURCE_ACQUISITION',
    closure_status: 'HASHED_PLANS_AND_REGISTRIES_ONLY',
    source_acquisition: {
      performed: false,
      replay_acquisition: false,
      details_reinterpretation: false,
      live_client_access: false,
    },
    artifacts,
    protected_holdout: SEMANTIC_DEPENDENCY_GRAPH.protected_holdout,
  };
  const manifestPath = path.join(safeOutput, 'artifact_manifest.json');
  fs.writeFileSync(manifestPath, stableJson(manifest), 'utf8');
  return { plans, manifest, output_dir: safeOutput, manifest_path: manifestPath };
}

module.exports = {
  ACTION_OWNERS,
  CURRENT_CAPABILITIES,
  EXACT_BUILD,
  EXHAUSTION_STATUS,
  OWNERSHIP_REGISTRY,
  SCHEMA,
  SEMANTIC_DEPENDENCY_GRAPH,
  SOURCE_CLASSES,
  assertSafeOutputDirectory,
  assertOwnership,
  createSemanticAcquisitionPlan,
  normalizeSemanticName,
  stableJson,
  writeSemanticAcquisitionArtifacts,
};
