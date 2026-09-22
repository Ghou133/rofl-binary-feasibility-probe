'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  BUILD_16_16,
  CAPABILITY_VOCABULARY,
  createCapabilityManifest,
} = require('./capability_manifest');
const { assertSafePath } = require('./stat_semantic_system');
const { deriveHeroStatState } = require('./derived_hero_stat_state');

const SCHEMA = 'ROFL_STAT_COMBAT_SEMANTIC_BASELINE_V1';
const EXACT_BUILD = '16.16.805.0442';
const RUNTIME_IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const INVENTORY_ITEM_SET_PROFILE_ID = 'entity_item_deep_16_16_006c';
const INVENTORY_ITEM_SET_PROFILE_SHA256 = '7004600e61ec9db84895526b12401d90fd2edd433449f2a3fe7967a8bdb01c72';

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function digest(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function readBoundJson(file) {
  const resolved = assertSafePath(file);
  const buffer = fs.readFileSync(resolved);
  return {
    file: resolved,
    bytes: buffer.length,
    sha256: digest(buffer),
    value: JSON.parse(buffer.toString('utf8').replace(/^\uFEFF/, '')),
  };
}

function readBoundText(file) {
  const resolved = assertSafePath(file);
  const buffer = fs.readFileSync(resolved);
  return {
    file: resolved,
    bytes: buffer.length,
    sha256: digest(buffer),
    text: buffer.toString('utf8').replace(/^\uFEFF/, ''),
  };
}

function manifestEntries(manifest) {
  if (Array.isArray(manifest.artifacts)) return manifest.artifacts;
  if (Array.isArray(manifest.outputs)) return manifest.outputs;
  if (Array.isArray(manifest.scenarios)) {
    return manifest.scenarios.map((scenario) => scenario.artifact).filter(Boolean);
  }
  return [];
}

function verifyArtifactManifest(file) {
  const bound = readBoundJson(file);
  const entries = manifestEntries(bound.value);
  invariant(entries.length > 0, `${file}: no artifact entries`);
  const base = path.dirname(bound.file);
  const seen = new Set();
  const verified = entries.map((entry) => {
    invariant(typeof entry.path === 'string' && entry.path.length > 0,
      `${file}: artifact path is missing`);
    const artifact = assertSafePath(path.resolve(base, entry.path));
    const relative = path.relative(base, artifact);
    invariant(relative.length > 0 && relative !== '..'
      && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative),
    `${file}: artifact escapes manifest directory: ${entry.path}`);
    const physicalKey = process.platform === 'win32' ? artifact.toLowerCase() : artifact;
    invariant(!seen.has(physicalKey), `${file}: duplicate physical artifact ${entry.path}`);
    seen.add(physicalKey);
    const buffer = fs.readFileSync(artifact);
    const expectedBytes = entry.bytes ?? entry.byte_size;
    invariant(Number.isInteger(expectedBytes) && expectedBytes >= 0,
      `${file}: invalid byte count for ${entry.path}`);
    invariant(typeof entry.sha256 === 'string' && /^[0-9a-f]{64}$/.test(entry.sha256),
      `${file}: invalid SHA-256 for ${entry.path}`);
    invariant(buffer.length === expectedBytes, `${file}: byte mismatch for ${entry.path}`);
    const sha256 = digest(buffer);
    invariant(sha256 === entry.sha256, `${file}: SHA mismatch for ${entry.path}`);
    return { path: relative.replaceAll('\\', '/'), bytes: buffer.length, sha256 };
  });
  return {
    schema: bound.value.schema || bound.value.schema_version,
    exact_build: bound.value.exact_build || bound.value.build || null,
    runtime_image_sha256: bound.value.runtime_image_sha256 || null,
    status: bound.value.status || bound.value.engine_status || null,
    governed_input_binding: bound.value.governed_input_binding || null,
    manifest_sha256: bound.sha256,
    manifest_bytes: bound.bytes,
    verified_artifacts: verified,
  };
}

function assertManifestMember(manifestFile, verification, boundDocument, name) {
  const base = path.dirname(assertSafePath(manifestFile));
  const relative = path.relative(base, boundDocument.file);
  invariant(relative.length > 0 && relative !== '..'
    && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative),
  `${name}: document is outside its evidence manifest directory`);
  const normalized = relative.replaceAll('\\', '/');
  const member = verification.verified_artifacts.find((entry) => entry.path === normalized);
  invariant(member, `${name}: document is not a member of its evidence manifest`);
  invariant(member.bytes === boundDocument.bytes && member.sha256 === boundDocument.sha256,
    `${name}: document bytes/hash do not match its evidence manifest member`);
  return { path: normalized, bytes: member.bytes, sha256: member.sha256 };
}

function validateNodeTestLog(boundLog, name) {
  const metric = (label) => {
    const match = boundLog.text.match(new RegExp(`(?:^|\\n)[^\\n]*\\b${label}\\s+(\\d+)\\s*(?:\\n|$)`, 'i'));
    invariant(match, `${name}: missing ${label} summary`);
    return Number(match[1]);
  };
  const tests = metric('tests');
  const pass = metric('pass');
  const fail = metric('fail');
  const cancelled = metric('cancelled');
  const skipped = metric('skipped');
  invariant(tests > 0 && pass > 0, `${name}: no passing tests recorded`);
  invariant(fail === 0 && cancelled === 0, `${name}: test failures or cancellations recorded`);
  invariant(pass + skipped === tests, `${name}: test summary does not conserve tests`);
  return { tests, pass, fail, cancelled, skipped };
}

function defaultInputs(rootDir) {
  const stage = path.join(rootDir, '.omo', 'evidence', 'stat_semantic_mapping_v1');
  const combat = path.join(rootDir, '.omo', 'evidence',
    'quantization_runtime_combat_reconstruction_v1');
  return {
    registryManifest: path.join(stage, 'registry', 'manifest.json'),
    registry: path.join(stage, 'registry', 'stat_selector_registry.json'),
    selectorManifest: path.join(stage, 'selector_runtime', 'evidence_manifest.json'),
    selectorRuntime: path.join(stage, 'selector_runtime', 'stat_selector_runtime_trace.json'),
    modifierManifest: path.join(stage, 'modifier_dependency', 'manifest.json'),
    modifierReport: path.join(stage, 'modifier_dependency', 'modifier_dependency_report.json'),
    dependencyGraph: path.join(stage, 'modifier_dependency', 'stat_formula_dependency_graph.json'),
    derivedManifest: path.join(stage, 'derived_combat', 'artifact_manifest.json'),
    derivedReport: path.join(stage, 'derived_combat', 'derived_hero_stat_state_build.json'),
    derivedTestLog: path.join(stage, 'derived_combat', 'derived_hero_stat_state_test.log'),
    mechanicsManifest: path.join(stage, 'exact_mechanics', 'artifact_manifest.json'),
    mechanics: path.join(stage, 'exact_mechanics', 'exact_build_mechanics_data.json'),
    exceptionRegistry: path.join(stage, 'exact_mechanics', 'exception_registry.json'),
    inventoryManifest: path.join(stage, 'inventory_state', 'artifact_manifest.json'),
    inventoryReport: path.join(stage, 'inventory_state', 'inventory_state_at_audit.json'),
    combatDataflowManifest: path.join(stage, 'combat_dataflow', 'artifact_manifest.json'),
    combatDataflowReport: path.join(stage, 'combat_dataflow', 'exact_combat_dataflow_report.json'),
    combatManifest: path.join(combat, 'artifact_manifest.json'),
    combatReport: path.join(combat, 'quantization_runtime_combat_reconstruction_report.json'),
  };
}

function relativeBinding(rootDir, bound) {
  return {
    path: path.relative(rootDir, bound.file).replaceAll('\\', '/'),
    bytes: bound.bytes,
    sha256: bound.sha256,
  };
}

function requireBuild(document, name) {
  const build = document.exact_build || document.build;
  invariant(build === EXACT_BUILD, `${name}: exact-build mismatch`);
}

function loadBoundInputs(rootDir, inputs = defaultInputs(rootDir)) {
  const manifestKeys = [
    'registryManifest', 'selectorManifest', 'modifierManifest', 'derivedManifest',
    'mechanicsManifest', 'inventoryManifest', 'combatDataflowManifest', 'combatManifest',
  ];
  const manifestVerification = Object.fromEntries(manifestKeys.map((key) => [
    key,
    verifyArtifactManifest(inputs[key]),
  ]));
  for (const [key, verification] of Object.entries(manifestVerification)) {
    invariant(verification.exact_build === EXACT_BUILD,
      `${key}: evidence manifest exact-build mismatch`);
  }
  const documentKeys = [
    'registry', 'selectorRuntime', 'modifierReport', 'dependencyGraph', 'derivedReport',
    'mechanics', 'exceptionRegistry', 'inventoryReport', 'combatDataflowReport', 'combatReport',
  ];
  const bound = Object.fromEntries(documentKeys.map((key) => [key, readBoundJson(inputs[key])]));
  const documentManifests = {
    registry: 'registryManifest',
    selectorRuntime: 'selectorManifest',
    modifierReport: 'modifierManifest',
    dependencyGraph: 'modifierManifest',
    derivedReport: 'derivedManifest',
    mechanics: 'mechanicsManifest',
    exceptionRegistry: 'mechanicsManifest',
    inventoryReport: 'inventoryManifest',
    combatDataflowReport: 'combatDataflowManifest',
    combatReport: 'combatManifest',
  };
  const documentMembership = Object.fromEntries(Object.entries(documentManifests).map(
    ([documentKey, manifestKey]) => [documentKey, assertManifestMember(
      inputs[manifestKey], manifestVerification[manifestKey], bound[documentKey], documentKey,
    )],
  ));
  for (const key of ['registry', 'selectorRuntime', 'modifierReport', 'derivedReport', 'mechanics',
    'exceptionRegistry', 'inventoryReport', 'combatDataflowReport']) {
    requireBuild(bound[key].value, key);
  }
  invariant(bound.dependencyGraph.value.exact_build === EXACT_BUILD,
    'dependency graph exact-build mismatch');
  invariant(bound.combatReport.value.exact_build === EXACT_BUILD,
    'combat report exact-build mismatch');
  invariant(bound.registry.value.exact_runtime_image_sha256 === RUNTIME_IMAGE_SHA256,
    'registry runtime image mismatch');
  invariant(bound.selectorRuntime.value.image?.sha256 === RUNTIME_IMAGE_SHA256,
    'selector trace runtime image mismatch');
  invariant(bound.modifierReport.value.runtime_image_sha256 === RUNTIME_IMAGE_SHA256,
    'modifier report runtime image mismatch');
  invariant(bound.mechanics.value.exact_runtime_image_sha256 === RUNTIME_IMAGE_SHA256,
    'mechanics runtime image mismatch');
  const inventoryBinding = bound.inventoryReport.value.governed_input_binding;
  invariant(inventoryBinding?.exact_build === EXACT_BUILD
    && inventoryBinding.runtime_image_sha256 === RUNTIME_IMAGE_SHA256
    && inventoryBinding.route === '0x006c' && inventoryBinding.opcode === 0x006c
    && inventoryBinding.decoder_profile_id === INVENTORY_ITEM_SET_PROFILE_ID
    && inventoryBinding.decoder_profile_sha256 === INVENTORY_ITEM_SET_PROFILE_SHA256,
  'inventory audit exact route/runtime/profile binding mismatch');
  invariant(inventoryBinding.input_row_count
    === bound.inventoryReport.value.published_event_audit?.ITEM_STATE_SET?.direct_rows_observed,
  'inventory audit row-count conservation mismatch');
  const inventoryManifestBinding = manifestVerification.inventoryManifest.governed_input_binding;
  invariant(JSON.stringify(inventoryManifestBinding) === JSON.stringify(inventoryBinding),
    'inventory manifest/report governed input binding mismatch');
  invariant(bound.combatDataflowReport.value.image?.sha256 === RUNTIME_IMAGE_SHA256,
    'combat dataflow runtime image mismatch');
  invariant(bound.combatDataflowReport.value.status === 'EVIDENCE_EXHAUSTED',
    'combat dataflow probe is not in its audited terminal state');
  invariant(bound.combatReport.value.status === 'EVIDENCE_EXHAUSTED',
    'combat closure is not in its audited terminal state');
  const logKeys = ['derivedTestLog'];
  const logBindings = Object.fromEntries(logKeys.map((key) => [key, readBoundText(inputs[key])]));
  const logMembership = {
    derivedTestLog: assertManifestMember(
      inputs.derivedManifest, manifestVerification.derivedManifest,
      logBindings.derivedTestLog, 'derivedTestLog',
    ),
  };
  const testAttestations = {
    derivedTestLog: validateNodeTestLog(logBindings.derivedTestLog, 'derivedTestLog'),
  };
  return {
    documents: Object.fromEntries(documentKeys.map((key) => [key, bound[key].value])),
    sourceBindings: {
      manifests: manifestVerification,
      documents: Object.fromEntries(documentKeys.map((key) => [key, relativeBinding(rootDir, bound[key])])),
      logs: Object.fromEntries(logKeys.map((key) => [key, relativeBinding(rootDir, logBindings[key])])),
      manifest_membership: { ...documentMembership, ...logMembership },
      test_attestations: testAttestations,
    },
  };
}

const REFINED_DERIVABILITY = Object.freeze({
  MAX_HP: {
    state: 'DERIVABLE_IF_EXACT_BUILD_MECHANICS_AND_COMPLETE_STATE',
    missing: ['exact-build champion/base/growth', 'complete inventory', 'runes', 'mapped buff modifiers', 'exception state'],
  },
  ARMOR: {
    state: 'DERIVABLE_IF_EXACT_BUILD_MECHANICS_AND_COMPLETE_STATE',
    missing: ['exact-build champion/base/growth', 'complete inventory', 'runes', 'mapped flat/percent buffs', 'exception state'],
  },
  MAGIC_RESIST: {
    state: 'DERIVABLE_IF_EXACT_BUILD_MECHANICS_AND_COMPLETE_STATE',
    missing: ['exact-build champion/base/growth', 'complete inventory', 'runes', 'mapped flat/percent buffs', 'special forms'],
  },
  CURRENT_HP: {
    state: 'DERIVABLE_IF_RUNTIME_HEALTH_WRITER_AND_COMPLETE_HP_EVENT_COVERAGE',
    missing: ['absolute internal HP anchor', 'applied-to-health damage', 'effective heal', 'regen', 'death/respawn ordering', 'shield/temporary-health ordering'],
  },
  DAMAGE_STAGE: {
    state: 'DERIVABLE_IF_RUNTIME_DAMAGE_DATAFLOW_EDGE_FOUND',
    missing: ['field_24 consumer edge into mitigation/shield/health/display stage'],
  },
  DAMAGE_MITIGATION: {
    state: 'DERIVABLE_IF_DEFENSE_STAGE_AND_MECHANICS_COMPLETE',
    missing: ['target Armor/MR at hit', 'penetration/reduction state', 'damage stage', 'exact-build combat formula'],
  },
  SHIELD_REMAINING: {
    state: 'DERIVABLE_IF_SHIELD_INSTANCE_LIFECYCLE_COMPLETE',
    missing: ['instance identity', 'layer ordering', 'expiry/replacement/removal'],
  },
  SHIELD_LIFECYCLE: {
    state: 'DERIVABLE_IF_SHIELD_INSTANCE_LIFECYCLE_COMPLETE',
    missing: ['instance identity', 'expiry/replacement/removal semantics'],
  },
  HEAL_EFFECTIVE: {
    state: 'DERIVABLE_IF_HEALTH_APPLICATION_AND_ANCHORS_COMPLETE',
    missing: ['health before/after', 'max HP', 'intervening HP events', 'heal clamp semantics'],
  },
  OVERHEAL: {
    state: 'DERIVABLE_IF_HEALTH_APPLICATION_AND_ANCHORS_COMPLETE',
    missing: ['requested heal', 'effective heal', 'max HP', 'health before'],
  },
  RUNE_STATE: {
    state: 'REQUIRES_GOVERNED_RUNE_INPUT',
    missing: ['exact-build rune loadout/shard/proc state and stat contributions'],
  },
});

const OTHER_FORMULA_STATS = new Set([
  'ATTACK_DAMAGE', 'ABILITY_POWER', 'MOVE_SPEED', 'ATTACK_SPEED', 'MANA', 'MAX_MANA',
  'TEMPORARY_HP', 'TEMPORARY_STATS',
]);

function buildDerivableCapabilityAudit(combatReport) {
  const manifest = createCapabilityManifest();
  const records = manifest.build_profiles[BUILD_16_16].records;
  invariant(records.length === CAPABILITY_VOCABULARY.length,
    'capability manifest does not conserve its vocabulary');
  const priorRows = new Map((combatReport.derivable_capability_audit?.rows || [])
    .map((row) => [row.semantic_capability, row]));
  const rows = records.map((record) => {
    const capability = record.semantic_capability;
    const refined = REFINED_DERIVABILITY[capability];
    let state;
    let missingInputs;
    if (refined) {
      state = refined.state;
      missingInputs = refined.missing;
    } else if (OTHER_FORMULA_STATS.has(capability)) {
      state = 'DERIVABLE_IF_SELECTOR_AND_MODIFIER_MAPPING_COMPLETE';
      missingInputs = ['selector/lane semantic', 'exact-build mechanics', 'complete modifiers'];
    } else if (record.evidence_grade === 'VERIFIED_DIRECT') {
      state = 'AVAILABLE_DIRECT_NOW';
      missingInputs = [];
    } else if (record.evidence_grade === 'VERIFIED_DERIVED') {
      state = 'AVAILABLE_DERIVED_NOW';
      missingInputs = [];
    } else {
      state = priorRows.get(capability)?.derivability_classification
        || 'INSUFFICIENT_EVIDENCE';
      missingInputs = priorRows.get(capability)?.missing_inputs || [];
    }
    return {
      semantic_capability: capability,
      manifest_evidence_grade: record.evidence_grade,
      manifest_validation_status: record.validation_status,
      derivability_state_v2: state,
      missing_inputs: missingInputs,
      public_manifest_changed_this_stage: false,
      boundary: 'AUDIT_ONLY; NULL UNTIL THE LISTED INPUTS AND EVIDENCE GATES ARE COMPLETE',
    };
  });
  const counts = {};
  for (const row of rows) counts[row.derivability_state_v2] = (counts[row.derivability_state_v2] || 0) + 1;
  invariant(rows.length === 79, `expected 79 governed capabilities, got ${rows.length}`);
  invariant(Object.values(counts).reduce((sum, count) => sum + count, 0) === 79,
    'derivability audit conservation failed');
  return {
    schema: 'ROFL_DERIVABLE_CAPABILITY_AUDIT_V2',
    exact_build: EXACT_BUILD,
    capability_count: rows.length,
    classification_counts: counts,
    rows,
  };
}

function mappingSummary(registry, selectorRuntime) {
  const verified = registry.verified_static_mappings.filter((mapping) =>
    mapping.evidence_grade === 'VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING');
  const observed = registry.selectors.filter((selector) => selector.observed_in_local_042f_corpus);
  const selector194 = registry.selectors.find((selector) => selector.selector === 194) || null;
  return {
    verified_mapping_count: verified.length,
    verified_mappings: verified,
    observed_selector_ids: observed.map((selector) => selector.selector),
    observed_selector_count: observed.length,
    selector_194: selector194 && {
      observed_output_record_count: selector194.observed_output_record_count,
      lane_relationships: selector194.lane_relationships,
      semantic_status: selector194.selector_semantic_status,
      stat_name_promotions: 0,
    },
    runtime_caller_counts: {
      wrapper: selectorRuntime.caller_enumeration.wrapper.length,
      storage_accessor: selectorRuntime.caller_enumeration.storage_accessor.length,
      lookup: selectorRuntime.caller_enumeration.selector_lane_lookup.length,
    },
    enum_table_status: selectorRuntime.selector_enum_table_search.status,
  };
}

function semanticFingerprints(registry, selectorRuntime, dependencyGraph, combatReport) {
  const mana = registry.verified_static_mappings.find((mapping) => mapping.semantic === 'MANA_REGEN');
  invariant(mana, 'ManaRegen mapping missing');
  const manaFingerprint = {
    semantic: 'MANA_REGEN_SELECTOR_OUTPUT',
    exact_build: EXACT_BUILD,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    route: '0x042f',
    selector: mana.selector,
    lane: mana.lane,
    writer_rva: '0x00999e40',
    reader_lookup_rva: selectorRuntime.reader.lookup_rva_hex,
    consumer_call_rva: '0x00b36bbe',
    formatter_call_rva: '0x00b36c5d',
    formatter: mana.display_format,
    localization_token: mana.localization_token,
    control_and_value_flow_status:
      selectorRuntime.mana_regen_neighborhood.control_flow_and_value_flow_proof?.status
      || selectorRuntime.mana_regen_neighborhood.status,
    observed_packet_count: 0,
    formula_dependencies: [],
  };
  const modifierFingerprint = {
    semantic: 'STAT_MODIFIER_DEPENDENCY_GRAPH',
    exact_build: EXACT_BUILD,
    route: '0x0412→0x042f',
    promoted_edge_count: dependencyGraph.promoted_edges.length,
    status: dependencyGraph.status,
  };
  const shield = combatReport.migration_integration?.shield_absorbed;
  const rows = [manaFingerprint, modifierFingerprint, shield && {
    semantic: 'SHIELD_ABSORBED_TARGET_TOTAL',
    exact_build: EXACT_BUILD,
    route: '0x01e1',
    prior_route: shield.source_route,
    existing_semantic_fingerprint_sha256: shield.semantic_fingerprint_sha256,
    status: shield.migration_oracle_status,
  }].filter(Boolean);
  return {
    schema: 'ROFL_STAT_COMBAT_SEMANTIC_FINGERPRINT_SET_V1',
    exact_build: EXACT_BUILD,
    fingerprints: rows.map((fingerprint) => ({
      ...fingerprint,
      fingerprint_sha256: digest(Buffer.from(JSON.stringify(fingerprint), 'utf8')),
    })),
  };
}

function researchQuestions() {
  return {
    Q1: 'YES, ONE exact-build stat mapping: selector 11/lane 0 = MANA_REGEN. It is a verified static consumer mapping but has zero observations in the governed 0x042f corpus. No P0 selector/lane is mapped.',
    Q2: 'MAX_HP, ARMOR, and MAGIC_RESIST are CONDITIONAL. The fail-closed engine exists, but exact-build mechanics and complete time-aligned inventory/rune/buff/exception inputs do not; no value is emitted.',
    Q3: 'NO. 0x0412 proves a 28-byte adjustment structure, not flat/percent semantics or target stat. All 714 kinds are zero; 660 strict brackets have selector 194→194 and lane delta [0,0,0,0]; promoted dependency edges = 0.',
    Q4: 'NO UNIQUE STAGE. 0x017f field_24 remains a HUD-quantized HP-decrease-compatible component; the exact-image probe still lacks a resolved edge that distinguishes mitigation, shield debit, health application, and presentation/component stages.',
    Q5: 'NO for an arbitrary DamageEvent. Damage type and recorded amount are direct; target Armor/MR and mitigation interpretation are unavailable.',
    Q6: 'SHIELD_GENERATED and target-total SHIELD_ABSORBED are direct. SHIELD_REMAINING and source/instance attribution are unavailable.',
    Q7: 'HEAL_REPORTED is direct. HEAL_EFFECTIVE and OVERHEAL are unavailable.',
    Q8: 'UNAVAILABLE for a complete CurrentHP or HP-delta state capability. There are narrow direct components and manual anchors, but no complete applied-to-health/effective-heal/regen/order stream; it is not publishable as HP_DELTA_ONLY.',
  };
}

function statsAt(hero, gameTime, inputs = {}, options = {}) {
  invariant(typeof inputs === 'object' && inputs !== null && !Array.isArray(inputs),
    'statsAt inputs must be an object');
  const entity = typeof hero === 'string' ? { champion: hero } : hero;
  invariant(typeof entity === 'object' && entity !== null && !Array.isArray(entity),
    'statsAt hero must be a champion name or entity object');
  return deriveHeroStatState({
    ...inputs,
    exact_build: inputs.exact_build ?? EXACT_BUILD,
    game_time: gameTime,
    entity,
  }, options);
}

function az(topic, status, decision, evidence = []) {
  return { topic, status, decision, evidence };
}

function finalReportAtoZ({ registry, selectorRuntime, modifierReport, dependencyGraph,
  derivedReport, mechanics, exceptionRegistry, inventoryReport, combatDataflowReport,
  combatReport, audit }) {
  const mapping = mappingSummary(registry, selectorRuntime);
  const combat = combatReport.combat_closure;
  return {
    A: az('STATUS', 'EVIDENCE_EXHAUSTED', 'All bounded selector, modifier, exact-image mechanics, fail-closed derivation, and combat closure routes were executed. No new public stat value was promoted.'),
    B: az('0x042f STATFORMULAOUTPUTS', 'VERIFIED_STRUCTURE_WRITER_READER', `${registry.corpus_scope.accepted_unique_packet_count} unique governed packets; 32-byte records, selector plus four float lanes, persistent writer and generic lookup are bound to the exact runtime image.`),
    C: az('STAT SELECTOR/LANE REGISTRY', 'PARTIAL_SEMANTIC_MAPPING', `${mapping.observed_selector_count} selector is observed locally (${mapping.observed_selector_ids.join(', ')}); all four lanes are inventoried with entity/value/time/event distributions. Corpus observation is not protocol-wide enumeration.`),
    D: az('VERIFIED STAT MAPPINGS', 'ONE_MAPPING', 'selector 11/lane 0 = MANA_REGEN via explicit lookup-to-formatter-to-localization control/value flow; local observed count is zero.'),
    E: az('CANDIDATE STAT MAPPINGS', 'STRUCTURAL_ONLY', 'selector 194 obeys lane0=lane1+lane2 and lane3=0 across the governed corpus, but no gameplay stat name is promoted.'),
    F: az('0x0412 BUFF STAT ADJUSTMENTS', 'STRUCTURE_VERIFIED_SEMANTICS_UNKNOWN', `${modifierReport.adjustment_observations.record_count} exact records; 28-byte layout is verified, selector/stat/value meanings are unresolved.`),
    G: az('STAT MODIFIER OPERATIONS', 'NO_PROMOTED_EDGES', `${dependencyGraph.temporal_observations.bracketed_by_strict_before_after_count} strict brackets all have zero lane delta; flat/percent/add/remove/replace and target stat remain unknown.`),
    H: az('EXACT-BUILD MECHANICS DATA', mechanics.status, `${mechanics.decision}; exact image binds the bounded growth constant/name evidence, but not champion rows, item-ID values, runes, P0 formula order, or P0 HUD projection.`, exceptionRegistry.exceptions.map((entry) => entry.exception_id)),
    I: az('INVENTORY STATE RECONSTRUCTION', 'PARTIAL_CAUSE_AGNOSTIC', `inventory_state_at(entity,t) is implemented fail-closed. The governed corpus contributes ${inventoryReport.published_event_audit.ITEM_STATE_SET.direct_rows_observed} direct special-slot sets only; full snapshot/swap/map/stage streams are absent from this bounded input, so complete inventory is not claimed.`),
    J: az('LEVEL / BASE STAT ENGINE', 'LEVEL_AVAILABLE_FORMULA_UNBOUND', 'LEVEL_TRANSITION is available; no exact-image slice closes champion row + level operand + named stat output, so BASE_STAT_AT_LEVEL is not publishable.'),
    K: az('RUNE INPUTS', 'UNAVAILABLE', `${inventoryReport.rune_input_availability.map((row) => `${row.capability}=${row.published_status}`).join(', ')}; absence is never treated as a zero modifier.`),
    L: az('DERIVED MAX_HP', 'CONDITIONAL', derivedReport.publication_boundary.max_hp),
    M: az('DERIVED ARMOR', 'CONDITIONAL', derivedReport.publication_boundary.armor),
    N: az('DERIVED MAGIC_RESIST', 'CONDITIONAL', derivedReport.publication_boundary.magic_resist),
    O: az('OTHER DERIVED HERO STATS', 'MAPPING_ONLY_NO_VALUE', 'ManaRegen identity is mapped statically; no Replay value is observed. AD/AP/AS/MS/Mana and other formula outputs remain unmapped.'),
    P: az('CURRENT_HP RUNTIME TRACE', 'UNAVAILABLE', combatDataflowReport.promotion_decisions.CURRENT_HP.reason),
    Q: az('HP DELTA / HEALTH STATE MACHINE', 'NOT_COMPUTABLE', derivedReport.combat_computability_audit.current_hp.missing_inputs.join('; ')),
    R: az('DAMAGE_STAGE', 'NO_UNIQUE_STAGE', `${combat.damage_stage_promotion_audit.stage_conclusion} Exact-image result: ${combatDataflowReport.promotion_decisions.DAMAGE_STAGE.reason}`),
    S: az('DAMAGE MITIGATION', 'NOT_COMPUTABLE', combat.mitigation.missing_inputs.join('; ')),
    T: az('SHIELD GENERATED / ABSORBED', 'VERIFIED_DIRECT_NARROW', 'SHIELD_GENERATED is direct; 16.16 0x01e1 yields 12/12 direct target-total absorbed events.'),
    U: az('SHIELD REMAINING / INSTANCE', 'UNAVAILABLE', `${combatDataflowReport.promotion_decisions.SHIELD_REMAINING.reason} ${combatDataflowReport.promotion_decisions.SHIELD_INSTANCE.reason}`),
    V: az('HEAL REPORTED / EFFECTIVE / OVERHEAL', 'REPORTED_ONLY', `HEAL_REPORTED is direct. ${combatDataflowReport.promotion_decisions.HEAL_EFFECTIVE.reason} ${combatDataflowReport.promotion_decisions.OVERHEAL.reason}`),
    W: az('DERIVABLE CAPABILITY AUDIT', 'COMPLETE_79_CONSERVED', `${audit.capability_count} capabilities re-audited; classifications sum to ${Object.values(audit.classification_counts).reduce((a, b) => a + b, 0)}.`),
    X: az('NEW PUBLIC SEMANTICS', 'NONE_THIS_STAGE', 'New machine layers are publishable internally, but no new gameplay capability/value passed public promotion. Existing SHIELD_ABSORBED remains retained.'),
    Y: az('REGRESSION / MIGRATION', 'BOUND', 'Selector mapping fingerprints include runtime consumer, writer, format, token, behavior, and dependencies; future migration remains AUTO_FIRST/MANUAL_LAST.'),
    Z: az('TRUE REMAINING BLOCKERS', 'ENUMERATED', 'Exact-build champion/item/rune/formula data; P0 selector consumers; labeled modifier operations; CurrentHP writer/full mutation stream; damage-stage edge and target defense; shield instance lifecycle.'),
  };
}

function assembleBaseline(documents, sourceBindings = {}) {
  const {
    registry, selectorRuntime, modifierReport, dependencyGraph, derivedReport,
    mechanics, exceptionRegistry, inventoryReport, combatDataflowReport, combatReport,
  } = documents;
  const audit = buildDerivableCapabilityAudit(combatReport);
  const mapping = mappingSummary(registry, selectorRuntime);
  invariant(mapping.verified_mapping_count === 1, 'expected exactly one verified stat mapping');
  invariant(mapping.verified_mappings[0].semantic === 'MANA_REGEN',
    'unexpected verified stat mapping');
  invariant(dependencyGraph.promoted_edges.length === 0,
    'modifier dependency graph contains an unreviewed promotion');
  invariant(['EVIDENCE_EXHAUSTED', 'READY_FAIL_CLOSED'].includes(mechanics.status),
    'mechanics report is not fail-closed');
  invariant(derivedReport.engine_status === 'READY_FAIL_CLOSED',
    'HeroStatState engine is not ready fail-closed');
  invariant(inventoryReport.schema === 'ROFL_INVENTORY_STATE_AT_AUDIT_V1',
    'inventory state audit schema mismatch');
  invariant(combatDataflowReport.status === 'EVIDENCE_EXHAUSTED',
    'combat dataflow probe is not fail-closed');
  const fingerprints = semanticFingerprints(registry, selectorRuntime, dependencyGraph, combatReport);
  const finalAtoZ = finalReportAtoZ({
    registry, selectorRuntime, modifierReport, dependencyGraph, derivedReport,
    mechanics, exceptionRegistry, inventoryReport, combatDataflowReport, combatReport, audit,
  });
  invariant(Object.keys(finalAtoZ).join('') === 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'A-Z final report is incomplete');
  return {
    schema: SCHEMA,
    exact_build: EXACT_BUILD,
    exact_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    status: 'EVIDENCE_EXHAUSTED',
    stop_condition: 'C_EVIDENCE_EXHAUSTED',
    architecture_gate: 'PASS',
    parser_boundary: 'REPLAY_PROTOCOL_AND_EXACT_BUILD_MECHANICS_ONLY',
    stat_selector_summary: mapping,
    stat_modifier_summary: {
      adjustment_record_count: modifierReport.adjustment_observations.record_count,
      formula_record_count: modifierReport.formula_output_observations?.record_count
        ?? dependencyGraph.temporal_observations.formula_record_count
        ?? registry.corpus_scope.count_scope_reconciliation.upstream_runtime_report_count,
      strict_bracket_count: dependencyGraph.temporal_observations.bracketed_by_strict_before_after_count,
      zero_lane_delta_count: dependencyGraph.temporal_observations.zero_lane_delta_count,
      promoted_dependency_edge_count: dependencyGraph.promoted_edges.length,
      selector_semantics: 'UNKNOWN',
      operation_semantics: 'UNKNOWN',
      flat_percent_semantics: 'UNRESOLVED',
    },
    mechanics_summary: {
      status: mechanics.status,
      decision: mechanics.decision,
      components: mechanics.components,
      exception_count: exceptionRegistry.exception_count,
      patch_family_accepted_as_exact_build: mechanics.patch_family_negative_control.accepted_as_exact_build_mechanics,
    },
    hero_stat_state_api: {
      schema: 'HERO_STAT_STATE_V1',
      query: 'statsAt(hero, game_time, inputs, options)',
      engine_status: derivedReport.engine_status,
      field_independent_nullability: true,
      max_hp: derivedReport.publication_boundary.max_hp,
      armor: derivedReport.publication_boundary.armor,
      magic_resist: derivedReport.publication_boundary.magic_resist,
      algorithm_conformance_pass: derivedReport.algorithm_conformance.pass,
      algorithm_conformance_is_public_evidence: false,
      public_value_emission_now: false,
    },
    inventory_state_api: {
      schema: 'ROFL_INVENTORY_STATE_AT_V1',
      query: 'inventory_state_at(index, entity_id, replay_time_ms, options)',
      governed_direct_special_slot_set_count:
        inventoryReport.published_event_audit.ITEM_STATE_SET.direct_rows_observed,
      complete_inventory_available_in_bounded_corpus: false,
      ambiguity_policy: 'FAIL_CLOSED_UNTIL_A_NEW_PUBLISHED_FULL_SNAPSHOT',
    },
    exact_combat_dataflow: combatDataflowReport.promotion_decisions,
    combat_state: derivedReport.combat_computability_audit,
    retained_direct_semantics: derivedReport.combat_computability_audit.retained_direct_semantics,
    derivable_capability_audit_v2: audit,
    public_semantic_changes_this_stage: [],
    semantic_fingerprints: fingerprints,
    research_questions: researchQuestions(),
    final_report_A_to_Z: finalAtoZ,
    true_remaining_blockers: [
      'authoritative champion/base/growth/item/rune/formula inputs independently bound to exact build 16.16.805.0442',
      'P0 selector/lane consumer identity or equivalent exact-build dataflow proof',
      'labeled 0x0412 operation/value/target-stat semantics or exact static mapping',
      'absolute internal CurrentHP plus complete ordered health mutation families',
      'field_24 runtime consumer edge and target defense/pre-mitigation truth',
      'shield instance/source/lifecycle/layer ordering truth',
    ],
    new_replay_required: 'NO_BY_DEFAULT',
    runtime_dynamic_access: combatReport.runtime_dynamic_access,
    source_bindings: sourceBindings,
    protected_holdout: {
      read: false,
      enumerated: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  };
}

function renderBaselineMarkdown(report) {
  const lines = [
    '# ROFL stat semantic mapping and derived combat-state baseline',
    '',
    `Status: **${report.status}** (${report.stop_condition})`,
    '',
    '## A–Z',
    '',
  ];
  for (const [letter, row] of Object.entries(report.final_report_A_to_Z)) {
    lines.push(`### ${letter}. ${row.topic}`, '', `**${row.status}** — ${row.decision}`, '');
  }
  lines.push('## Q1–Q8', '');
  for (const [question, answer] of Object.entries(report.research_questions)) {
    lines.push(`- **${question}:** ${answer}`);
  }
  lines.push('', 'Protected Holdout access: none.', '');
  return `${lines.join('\n')}\n`;
}

function writeBaselineArtifacts({ rootDir, outputDir, inputs = defaultInputs(rootDir) }) {
  const safeOutputDir = assertSafePath(outputDir);
  fs.mkdirSync(safeOutputDir, { recursive: true });
  const { documents, sourceBindings } = loadBoundInputs(rootDir, inputs);
  const report = assembleBaseline(documents, sourceBindings);
  const outputs = {
    'stat_combat_semantic_baseline_report.json': `${JSON.stringify(report, null, 2)}\n`,
    'STAT_COMBAT_SEMANTIC_BASELINE_REPORT.md': renderBaselineMarkdown(report),
    'semantic_fingerprints.json': `${JSON.stringify(report.semantic_fingerprints, null, 2)}\n`,
    'derivable_capability_audit_v2.json': `${JSON.stringify(report.derivable_capability_audit_v2, null, 2)}\n`,
  };
  const artifacts = [];
  for (const [name, text] of Object.entries(outputs)) {
    const file = assertSafePath(path.join(safeOutputDir, name));
    const buffer = Buffer.from(text, 'utf8');
    fs.writeFileSync(file, buffer);
    artifacts.push({ path: name, bytes: buffer.length, sha256: digest(buffer) });
  }
  const manifest = {
    schema: 'ROFL_STAT_COMBAT_SEMANTIC_BASELINE_ARTIFACT_MANIFEST_V1',
    exact_build: EXACT_BUILD,
    artifacts,
    protected_holdout: report.protected_holdout,
  };
  const manifestPath = assertSafePath(path.join(safeOutputDir, 'artifact_manifest.json'));
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return {
    report,
    manifest,
    paths: {
      reportPath: path.join(safeOutputDir, 'stat_combat_semantic_baseline_report.json'),
      markdownPath: path.join(safeOutputDir, 'STAT_COMBAT_SEMANTIC_BASELINE_REPORT.md'),
      fingerprintPath: path.join(safeOutputDir, 'semantic_fingerprints.json'),
      auditPath: path.join(safeOutputDir, 'derivable_capability_audit_v2.json'),
      manifestPath,
    },
  };
}

module.exports = {
  SCHEMA,
  EXACT_BUILD,
  RUNTIME_IMAGE_SHA256,
  assertManifestMember,
  assembleBaseline,
  buildDerivableCapabilityAudit,
  defaultInputs,
  loadBoundInputs,
  manifestEntries,
  renderBaselineMarkdown,
  researchQuestions,
  statsAt,
  validateNodeTestLog,
  verifyArtifactManifest,
  writeBaselineArtifacts,
};
