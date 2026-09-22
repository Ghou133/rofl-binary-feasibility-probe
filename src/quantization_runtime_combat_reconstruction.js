'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const EXACT_BUILD = '16.16.805.0442';
const CONTROLLED_REPLAY_SHA256 = '1fb1321e802103ce8e20e670b981b8b59d43a1fbbdc911f79ba249257ed672ff';
const RUNTIME_IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const P0 = Object.freeze(['MAX_HP', 'ARMOR', 'MAGIC_RESIST', 'CURRENT_HP']);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function assertSafePath(file) {
  invariant(!/holdout/i.test(path.resolve(file)), 'protected holdout path is forbidden');
}

function sha256File(file) {
  assertSafePath(file);
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function readJson(file) {
  assertSafePath(file);
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}

function defaultInputs(rootDir) {
  return {
    quantReport: path.join(rootDir, '.omo', 'evidence', 'quantization_aware_p0_recovery',
      'quantization_aware_p0_recovery_report.json'),
    quantManifest: path.join(rootDir, '.omo', 'evidence', 'quantization_aware_p0_recovery',
      'artifact_manifest.json'),
    runtimeReport: path.join(rootDir, '.omo', 'evidence', 'quant_runtime_bridge',
      'hud_runtime_state_bridge_report.json'),
    runtimeManifest: path.join(rootDir, '.omo', 'evidence', 'quant_runtime_bridge',
      'artifact_manifest.json'),
    combatReport: path.join(rootDir, '.omo', 'evidence', 'quant_combat_closure',
      'quantized_combat_reconstruction_report.json'),
    combatManifest: path.join(rootDir, '.omo', 'evidence', 'quant_combat_closure',
      'artifact_manifest.json'),
    staticData: path.join(rootDir, 'artifacts', 'quantization_runtime_combat_v1', 'static_data',
      'patch_16_16_1_controlled_inputs.json'),
  };
}

function validateArtifactManifest(manifestPath) {
  const manifest = readJson(manifestPath);
  const entries = manifest.outputs || manifest.artifacts;
  invariant(Array.isArray(entries) && entries.length > 0, `${manifestPath}: artifact list missing`);
  const base = path.dirname(manifestPath);
  const verified = entries.map((entry) => {
    const file = path.isAbsolute(entry.path) ? entry.path : path.resolve(base, entry.path);
    assertSafePath(file);
    invariant(fs.existsSync(file), `${manifestPath}: missing artifact ${entry.path}`);
    const bytes = fs.statSync(file).size;
    const expectedBytes = entry.byte_size ?? entry.bytes;
    invariant(bytes === expectedBytes, `${manifestPath}: byte-size mismatch for ${entry.path}`);
    const digest = sha256File(file);
    invariant(digest === entry.sha256, `${manifestPath}: SHA-256 mismatch for ${entry.path}`);
    return { path: entry.path, bytes, sha256: digest, match: true };
  });
  return { schema: manifest.schema || manifest.schema_version, verified_count: verified.length, artifacts: verified };
}

function countBy(rows, key) {
  const counts = {};
  for (const row of rows) counts[row[key]] = (counts[row[key]] || 0) + 1;
  return counts;
}

function strongestNearMiss(rows, semantic) {
  const ranked = [...rows].sort((left, right) => {
    const l = left.strict_delta_match_count * 10000 + left.target_covered_count * 100
      + left.quantized_compatible_count - left.cross_stat_response_count;
    const r = right.strict_delta_match_count * 10000 + right.target_covered_count * 100
      + right.quantized_compatible_count - right.cross_stat_response_count;
    return r - l;
  });
  const row = ranked[0];
  if (!row) return null;
  return {
    semantic,
    route: row.route,
    component: row.component,
    field: row.field,
    representation: row.representation,
    failure_gate: row.failure_gate,
    failure_reason: row.failure_reason,
    covered_required_transitions: `${row.target_covered_count}/${row.target_transition_count}`,
    strict_delta_matches: `${row.strict_delta_match_count}/${row.target_transition_count}`,
    quantized_compatible_responses: row.quantized_compatible_count,
    item_negative_control_response_count: row.item_negative_control_response_count
      ?? row.cross_stat_response_count,
    target_responses: row.responses.filter((response) => response.semantic === semantic
      && response.HUD_delta !== 0).map((response) => ({
      transition_id: response.transition_id,
      internal_before: response.internal_before,
      internal_after: response.internal_after,
      internal_delta: response.internal_delta,
      HUD_delta: response.HUD_delta,
      strict_flat_delta_match: response.strict_flat_delta_match,
      quantized_compatible: response.any_quantized_HUD_hypothesis_compatible,
    })),
  };
}

function allRequiredQuantizedCount(counts) {
  const value = counts.all_required_transitions_quantized_compatible;
  invariant(Number.isInteger(value), 'quantization report lacks all-required transition count');
  invariant(counts.after_quantization_aware_audit === value,
    'quantization report aliases after-audit to a different population');
  return value;
}

function anyQuantizedCount(counts) {
  const value = counts.at_least_one_quantized_compatible
    ?? counts.quantized_compatible_at_least_one;
  invariant(Number.isInteger(value), 'quantization report lacks at-least-one compatibility count');
  return value;
}

function validateStaticData(staticData) {
  invariant(staticData.schema === 'ROFL_PATCH_STATIC_DATA_DEPENDENCY_SNAPSHOT_V1', 'static-data schema mismatch');
  invariant(staticData.replay_exact_build === EXACT_BUILD, 'static-data replay build mismatch');
  invariant(staticData.binding_status === 'PATCH_FAMILY_PINNED_EXACT_BUILD_EQUIVALENCE_NOT_INDEPENDENTLY_PROVEN',
    'static-data exact-build boundary changed');
  invariant(staticData.controlled_items['1028'].stats.FlatHPPoolMod === 150, 'Ruby Crystal HP mismatch');
  invariant(staticData.controlled_items['1029'].stats.FlatArmorMod === 15, 'Cloth Armor mismatch');
  invariant(staticData.controlled_items['1033'].stats.FlatSpellBlockMod === 20, 'Null-Magic Mantle mismatch');
  invariant(staticData.champion.id === 'Kayn' && staticData.champion.stats.hp === 655,
    'controlled champion static data mismatch');
  invariant(staticData.deterministic_reconstruction_limits.derived_value_emission.startsWith('FORBIDDEN'),
    'unverified static inputs must not emit derived state');
}

function buildAZ({ quant, runtime, combat, staticData }) {
  const commonDerived = 'PARTIAL — item/base rows are patch-pinned, but exact-build equivalence, level-growth formula, rune state, and complete buff flat/percent operations are not all verified.';
  const reader = runtime.stat_formula_outputs.reader;
  const shield = combat.shield_route_migration_audit.direct_16_16_absorption_recovery;
  return {
    A: { topic: 'STATUS', status: 'EVIDENCE_EXHAUSTED', decision: 'All declared quantized scan, bounded static runtime, formula-output, deterministic-derived, Damage, Heal, Shield, and 79-capability paths were executed. No P0 scalar or Damage stage was promoted; 16.16 target-total SHIELD_ABSORBED was directly recovered and published.' },
    B: { topic: 'OLD P0 REJECTION-GATE AUDIT', status: 'COMPLETE', decision: `All ${P0.map((name) => quant.p0_candidate_counts[name].before_quantization_aware_audit).join('/')} prior partial candidates were reconstructed; old absolute HUD/internal equality was not a survivor gate.` },
    C: { topic: 'QUANTIZED HUD MODEL', status: 'DIRECT RECOVERED (ORACLE INTERPRETATION)', decision: 'All 50 immutable manual observations have an additive HUD_QUANTIZED_SCALAR interpretation with interval hypotheses; no raw observation was changed.' },
    D: { topic: 'HUD DISPLAY FUNCTION', status: 'EVIDENCE EXHAUSTED', decision: 'The bounded exact-image reader/caller/string/format slice found no P0 formatter. Floor, nearest-round, truncate, and other deterministic projections remain open and non-exhaustive. ManaRegen uses %0.f, but that evidence is not transferable to HP/Armor/MR.' },
    E: { topic: 'MAX_HP DIRECT CANDIDATES', status: 'EVIDENCE EXHAUSTED', decision: 'No candidate satisfies all four reversible item transitions, strict delta/direction, runtime selector mapping, and item negative controls.' },
    F: { topic: 'MAX_HP DERIVED', status: 'PARTIAL', decision: commonDerived },
    G: { topic: 'ARMOR DIRECT CANDIDATES', status: 'EVIDENCE EXHAUSTED', decision: 'No candidate satisfies both BUY→UNDO and BUY→SELL paths plus strict +15/-15 direction and Ruby/Mantle negative controls.' },
    H: { topic: 'ARMOR DERIVED', status: 'PARTIAL', decision: commonDerived },
    I: { topic: 'MAGIC_RESIST DIRECT CANDIDATES', status: 'EVIDENCE EXHAUSTED', decision: 'The strongest repeated near-miss has a +120 response where +20 is required and also responds outside the target item experiment; it is rejected.' },
    J: { topic: 'MAGIC_RESIST DERIVED', status: 'PARTIAL', decision: commonDerived },
    K: { topic: 'CURRENT_HP DIRECT', status: 'EVIDENCE EXHAUSTED', decision: 'No persistent direct current-health scalar or mapped formula-output lane survived controlled recovery and static tracing.' },
    L: { topic: 'CURRENT_HP / HP_DELTA DERIVED', status: 'PARTIAL', decision: 'HUD absolute anchors and Damage/Heal event components exist, but regen, effective heal, shield/temporary-health ordering, special effects, and a verified applied-to-health stage are incomplete.' },
    M: { topic: 'SHARED HEROSTAT CONTAINER', status: 'DIRECT RECOVERED (STRUCTURE ONLY)', decision: '0x042f is linked to a shared persistent formula-output writer/container and its generic selector/lane reader; P0 selector and lane identities remain unmapped.' },
    N: { topic: 'STATFORMULAOUTPUTS', status: 'DIRECT RECOVERED (STRUCTURE/WRITER/GENERIC READER)', decision: `${runtime.stat_formula_outputs.exact_full_consume_count} exact rows plus the exact-image callback/writer/reader chain establish 32-byte records, four float lanes, selector/lane lookup, and one static ManaRegen consumer mapping—not P0 identities.` },
    O: { topic: 'HUD → RUNTIME TRACE', status: 'PARTIAL', decision: `Packet deserializer→callback→writer→generic reader is recovered (${reader.wrapper_rva}→${reader.lookup_rva}); the bounded P0 getter/formatter linkage is exhausted without a match.` },
    P: { topic: 'BUFF STAT MODIFIERS', status: 'PARTIAL', decision: `${runtime.buff_stat_modifiers.exact_full_consume_count} exact 0x0412 rows and record structure are known; stat selector, operation, flat/percent meaning, and formula dependency are unmapped.` },
    Q: { topic: 'ITEM STAT CONTRIBUTIONS', status: 'CONDITIONALLY DERIVED', decision: `Official patch data records +150/+15/+20 for the controlled items and agrees with HUD steps, but ${staticData.binding_status}; no internal stat is emitted from it.` },
    R: { topic: 'LEVEL / BASE STAT RECONSTRUCTION', status: 'PARTIAL', decision: 'LEVEL_TRANSITION is available and Kayn patch data is pinned, but the exact-build nonlinear growth rule, rune inputs, and all modifiers are not verified. Level-Up remains HOLD.' },
    S: { topic: 'OTHER HERO STATS', status: 'PARTIAL', decision: 'ManaRegen selector 11/lane 0 → @ManaRegen@ → %0.f is VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING, but selector 11 is absent from the observed 0x042f corpus (selector 194 only), so no Replay ManaRegen value is published. Other stats remain candidates.' },
    T: { topic: 'DAMAGE_STAGE', status: 'CANDIDATE', decision: '3/3 controlled field_24 amounts are compatible with quantized HUD HP-decrease intervals; four cross-replay components join lethal contexts, but none isolates full lethal HP loss.' },
    U: { topic: 'DAMAGE_STAGE PROMOTION', status: 'EVIDENCE EXHAUSTED / NOT PROMOTED', decision: `${combat.damage_stage_promotion_audit.candidate_stage}; compatibility does not distinguish post-mitigation, applied-to-health, or health/shield component semantics.` },
    V: { topic: 'DAMAGE MITIGATION', status: 'EXTERNAL INPUT REQUIRED', decision: 'Missing target Armor/MR at hit, source raw damage/formula truth, exact-build modifiers, and a verified recorded-amount stage.' },
    W: { topic: 'HEAL EFFECTIVE / OVERHEAL', status: 'PARTIAL', decision: 'HEAL_REPORTED is verified direct and the controlled 80 is quantized-compatible; effective heal and overheal require event-level internal HP/max-HP and overlap truth.' },
    X: { topic: 'SHIELD ABSORB / REMAINING', status: 'DIRECT RECOVERED + PARTIAL', decision: `SHIELD_GENERATED remains verified direct. 16.16 route 0x01e1 yields ${shield.event_count}/${shield.exact_full_consume_count} direct target-total absorbed events with duplicate target agreement; source/instance and SHIELD_REMAINING remain unavailable.` },
    Y: { topic: 'DERIVABLE CAPABILITY AUDIT', status: 'COMPLETE', decision: `All ${combat.derivable_capability_audit.capability_count} governed capabilities were classified with conservation. The sole public mutation is 16.16 SHIELD_ABSORBED → VERIFIED_DIRECT/PASS.` },
    Z: { topic: 'TRUE EXTERNAL BLOCKERS', status: 'EXTERNAL INPUT REQUIRED FOR FURTHER PROMOTION', decision: 'Further P0/combat closure requires independently observed internal stat/HP truth or P0 display behavior; authoritative exact-build mechanics and buff mapping; event-level HP/heal/shield-layer labels; target defense/pre-mitigation truth; and complete shield application/expiry/replacement/instance truth for remaining amount.' },
  };
}

function renderMarkdown(report) {
  const lines = [
    '# ROFL_QUANTIZATION_AWARE_RUNTIME_STATE_AND_COMBAT_RECONSTRUCTION_V1', '',
    `Status: **${report.status}**`, '',
    `Stop condition: **${report.stop_condition}**`, '',
    '## P0 candidate funnel', '',
    '| semantic | prior partial | ≥1 quantized-compatible | all required compatible | repeated+direction | after runtime trace | after item negative controls | promoted |',
    '|---|---:|---:|---:|---:|---:|---:|---:|',
  ];
  for (const semantic of P0) {
    const row = report.p0_candidate_counts[semantic];
    lines.push(`| ${semantic} | ${row.before_quantization_aware_audit} | ${row.at_least_one_quantized_compatible} | ${row.after_quantization_aware_audit} | ${row.after_repeated_directional_gate} | ${row.after_runtime_tracing} | ${row.after_negative_controls} | ${row.promoted} |`);
  }
  lines.push('', '## A–Z decisions', '', '| key | topic | status | decision |', '|---|---|---|---|');
  for (const [key, row] of Object.entries(report.final_report_A_to_Z)) {
    lines.push(`| ${key} | ${row.topic} | ${row.status} | ${row.decision.replace(/\|/g, '\\|')} |`);
  }
  lines.push('', '## Five governing questions', '');
  for (const [key, value] of Object.entries(report.research_questions)) lines.push(`- **${key}:** ${value}`);
  lines.push('', '## Publication and migration', '',
    'No P0 or Damage-stage scalar was added to the public capability manifest. 16.16 target-total SHIELD_ABSORBED is the sole promotion; its exact-build decoder, semantic fingerprint, MigrationOracle decision, and regressions are published. Missing source/instance/remaining values stay UNKNOWN.', '',
    'Protected holdout access: enumerated/read/hashed/decoded/tested/consumed = false/false/false/false/false/false.', '');
  return `${lines.join('\n')}\n`;
}

function renderEvidence(report) {
  return `# Integrated quantization/runtime/combat evidence\n\n` +
    `- Canonical invocation: \`node scripts/run_quantization_runtime_combat_reconstruction.js --output-dir .omo/evidence/quantization_runtime_combat_reconstruction_v1\`\n` +
    `- Exact build/replay/runtime: \`${report.exact_build}\` / \`${report.controlled_replay_sha256}\` / \`${report.runtime_image_sha256}\`\n` +
    `- Sub-manifests independently verified: quant=${report.source_validation.quant_manifest.verified_count}, runtime=${report.source_validation.runtime_manifest.verified_count}, combat=${report.source_validation.combat_manifest.verified_count}.\n` +
    `- Candidate promotion count: 0 for all four P0 semantics; 1 direct non-P0 promotion (SHIELD_ABSORBED).\n` +
    `- 79-capability conservation: ${report.derivable_capability_audit.capability_count}; public manifest changes: ${report.public_capability_changes.length}.\n` +
    `- Protected holdout access remained false for all six operations.\n`;
}

function runIntegratedReconstruction({ rootDir = path.resolve(__dirname, '..'), outputDir,
  inputs = defaultInputs(rootDir) } = {}) {
  outputDir ||= path.join(rootDir, '.omo', 'evidence', 'quantization_runtime_combat_reconstruction_v1');
  assertSafePath(outputDir);
  for (const file of Object.values(inputs)) assertSafePath(file);

  const quant = readJson(inputs.quantReport);
  const runtime = readJson(inputs.runtimeReport);
  const combat = readJson(inputs.combatReport);
  const staticData = readJson(inputs.staticData);
  validateStaticData(staticData);

  invariant(quant.exact_build === EXACT_BUILD && runtime.exact_build === EXACT_BUILD
    && combat.exact_build === EXACT_BUILD, 'sub-report exact-build mismatch');
  invariant(quant.replay_sha256 === CONTROLLED_REPLAY_SHA256
    && combat.controlled_replay_sha256 === CONTROLLED_REPLAY_SHA256,
  'sub-report controlled replay mismatch');
  invariant(runtime.exact_runtime_image_sha256 === RUNTIME_IMAGE_SHA256,
    'runtime report image mismatch');
  invariant(combat.derivable_capability_audit.capability_count === 79, '79-capability conservation failed');
  invariant(Object.values(runtime.protected_holdout).every((value) => value === false),
    'runtime protected boundary failed');
  invariant(Object.values(combat.protected_holdout).every((value) => value === false),
    'combat protected boundary failed');
  invariant(Object.values(quant.protected_holdout_access).every((value) => value === false),
    'quant protected boundary failed');
  invariant(runtime.stat_formula_outputs.selector_identity === 'UNMAPPED'
    && runtime.stat_formula_outputs.lane_identity === 'UNMAPPED',
  'unverified formula-output semantic mapping must fail closed');
  invariant(runtime.stat_formula_outputs.reader?.status === 'VERIFIED_DIRECT_GENERIC_SELECTOR_LANE_READER',
    'generic formula-output reader proof missing');
  invariant(runtime.local_static_exhaustion_boundary?.status === 'LOCAL_STATIC_BOUNDED_ROUTES_EXHAUSTED'
    && Array.isArray(runtime.local_static_exhaustion_boundary.remaining_bounded_local_routes)
    && runtime.local_static_exhaustion_boundary.remaining_bounded_local_routes.length === 0,
  'bounded local runtime routes are not exhausted');
  const shieldRecovery = combat.shield_route_migration_audit?.direct_16_16_absorption_recovery;
  invariant(shieldRecovery?.status === 'DIRECT_RECOVERED_TARGET_TOTAL'
    && shieldRecovery.event_count === 12 && shieldRecovery.exact_full_consume_count === 12
    && shieldRecovery.target_fields_agree_count === 12
    && shieldRecovery.target_matches_raw_param_low_byte_count === 12
    && shieldRecovery.positive_finite_amount_count === 12,
  '16.16 SHIELD_ABSORBED direct recovery gates failed');
  invariant(combat.shield_route_migration_audit.migration_oracle?.status === 'AUTO_VERIFIED_WITH_ROUTE_MOVE',
    'SHIELD_ABSORBED migration oracle did not auto-verify the route move');
  invariant(combat.public_capability_changes?.length === 1
    && combat.public_capability_changes[0].semantic === 'SHIELD_ABSORBED',
  'unexpected public capability mutation set');

  const sourceValidation = {
    quant_manifest: validateArtifactManifest(inputs.quantManifest),
    runtime_manifest: validateArtifactManifest(inputs.runtimeManifest),
    combat_manifest: validateArtifactManifest(inputs.combatManifest),
  };
  const candidateCounts = {};
  const rejectionSummary = {};
  const nearMisses = {};
  for (const semantic of P0) {
    const counts = quant.p0_candidate_counts[semantic];
    const afterAllQuantized = allRequiredQuantizedCount(counts);
    const anyQuantized = anyQuantizedCount(counts);
    candidateCounts[semantic] = {
      before_quantization_aware_audit: counts.before_quantization_aware_audit,
      reconstructed_partial_count: counts.reconstructed_partial_count,
      at_least_one_quantized_compatible: anyQuantized,
      after_quantization_aware_audit: afterAllQuantized,
      after_repeated_directional_gate: counts.after_repeated_directional_gate,
      after_runtime_tracing: 0,
      after_negative_controls: counts.after_negative_controls,
      promoted: counts.promoted,
      runtime_trace_reason: '0x042f selector/lane remained unmapped; no new direct candidate was introduced',
    };
    invariant(candidateCounts[semantic].promoted === 0, `${semantic}: unexpected promotion`);
    rejectionSummary[semantic] = countBy(quant.rejection_gate_audit[semantic], 'failure_gate');
    nearMisses[semantic] = strongestNearMiss(quant.rejection_gate_audit[semantic], semantic);
  }

  const report = {
    schema: 'ROFL_QUANTIZATION_AWARE_RUNTIME_STATE_AND_COMBAT_RECONSTRUCTION_V1',
    schema_version: 1,
    status: 'EVIDENCE_EXHAUSTED',
    stop_condition: 'C_EVIDENCE_EXHAUSTED_WITH_ENUMERATED_TRUE_EXTERNAL_INPUTS',
    exact_build: EXACT_BUILD,
    controlled_replay_sha256: CONTROLLED_REPLAY_SHA256,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    project_context_loaded: true,
    architecture_gate: 'PASS',
    scope: 'PARSER_REPLAY_PROTOCOL_AND_DETERMINISTIC_DERIVED_SEMANTICS_ONLY',
    p0_candidate_counts: candidateCounts,
    old_rejection_gate_distribution: rejectionSummary,
    strongest_near_miss_by_semantic: nearMisses,
    quantized_hud_model: quant.quantized_hud_model,
    hud_display_function: runtime.hud_display_function,
    shared_hero_stat_runtime: runtime.stat_formula_outputs,
    hud_runtime_state_access_map: runtime.hud_runtime_state_access_map,
    buff_stat_modifiers: runtime.buff_stat_modifiers,
    local_evidence_exhaustion: {
      runtime_static: runtime.local_static_exhaustion_boundary,
      shield_protocol: {
        migration_relation: combat.shield_route_migration_audit.migration_relation,
        governed_corpus_scan: combat.shield_route_migration_audit.governed_corpus_scan,
        direct_recovery: shieldRecovery,
      },
    },
    static_data_dependency: { ...staticData, local_snapshot_sha256: sha256File(inputs.staticData) },
    combat_closure: {
      damage_stage_promotion_audit: combat.damage_stage_promotion_audit,
      mitigation: combat.mitigation,
      current_hp_reconstruction: combat.current_hp_reconstruction,
      heal_shield: combat.heal_shield,
      corpus_search: combat.corpus_search,
    },
    derivable_capability_audit: combat.derivable_capability_audit,
    public_capability_changes: combat.public_capability_changes,
    migration_integration: {
      status: 'REGRESSION_BOUND_ONE_DIRECT_PROTECTION_PROMOTION_NO_P0_OR_DAMAGE_STAGE_PROMOTION',
      source_oracle_sha256: quant.oracle.sha256,
      quantized_oracle_record_count: quant.oracle.immutable_record_count,
      exact_build: EXACT_BUILD,
      replay_sha256: CONTROLLED_REPLAY_SHA256,
      runtime_image_sha256: RUNTIME_IMAGE_SHA256,
      shield_absorbed: {
        source_route: '0x0017', target_route: '0x01e1',
        semantic_fingerprint_sha256: combat.shield_route_migration_audit.semantic_fingerprint.sha256,
        migration_oracle_status: combat.shield_route_migration_audit.migration_oracle.status,
        capability_status: 'VERIFIED_DIRECT/PASS',
        boundary: 'TARGET_TOTAL_ONLY; SOURCE_INSTANCE_AND_REMAINING_UNAVAILABLE',
      },
      gates: ['structural fingerprint', 'repeated delta signatures', 'directionality',
        'item-specific negative controls', 'all transitions share one stat-specific HUD display projection',
        'quantized HUD compatibility', 'counterexample regression'],
      future_build_policy: 'AUTO_FIRST_ONLY_AFTER_A_UNIQUE_CANDIDATE_PASSES_ALL_GATES; OTHERWISE_TARGETED_RECALIBRATION',
      major_version_policy: 'AUTO_FIRST_SAME_AS_MINOR_VERSION; NO VERSION-BASED MANUAL DEFAULT',
      manifest_mutation: 'SHIELD_ABSORBED_16_16_ONLY; NO_P0_OR_DAMAGE_STAGE_PROMOTION',
    },
    research_questions: {
      Q1: 'NO. The old absolute_snapshot_match/HUD-integer equality field was diagnostic only and never entered survivor gating; every reconstructed partial fails repeated coverage/strict delta/direction or item-specific controls independently.',
      Q2: 'Replay/runtime evidence proves a shared 0x042f formula-output record/container, its generic selector/lane reader, and a 0x0412 buff-adjustment structure. ManaRegen selector 11/lane 0 is statically mapped but absent from observed 0x042f rows; no selector/lane is mapped to a P0 final/base/modifier/formula output.',
      Q3: 'NOT YET. MaxHP/Armor/MR are conditionally derivable in principle, but exact-build growth, rune state, complete inventory semantics, and flat/percent buff operations are not all verified; outputs therefore remain UNKNOWN.',
      Q4: 'NO UNIQUE STAGE. 0x017f field_24 is compatible with all three controlled quantized HP-decrease intervals, but this does not distinguish post-mitigation, applied-to-health, or health/shield component stages.',
      Q5: 'PARTIAL, NOT COMPLETE. Damage/type, HealReported, ShieldGenerated, and target-total ShieldAbsorbed are direct event facts; mitigation, effective heal, shield remaining/instance/layer ordering, and complete current-HP integration remain missing.',
    },
    final_report_A_to_Z: null,
    true_external_blockers: [
      'independently observed internal P0 stat/HP values paired with HUD output, or independently verified P0 display behavior',
      'authoritative exact-build champion/base/growth/rune/item mechanics with version and hashes',
      'independently labeled buff selector/operation/flat-percent truth or an authoritative exact-build mapping',
      'cross-replay event-level HP-before/after with heal/regen/shield-layer overlap labels',
      'target defense and independently labeled pre-mitigation/raw damage truth',
      'complete shield application/expiry/replacement/instance truth for SHIELD_REMAINING',
    ],
    new_replay_required: 'NO_BY_DEFAULT',
    level_up_hold: { status: 'HOLD', blocker: false, new_frame_requested: false },
    runtime_dynamic_access: runtime.runtime_dynamic_access,
    protected_holdout: { enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false },
    source_validation: sourceValidation,
    input_bindings: Object.fromEntries(Object.entries(inputs).map(([name, file]) => [name, {
      path: path.relative(rootDir, file).replace(/\\/g, '/'), sha256: sha256File(file), bytes: fs.statSync(file).size,
    }])),
  };
  report.final_report_A_to_Z = buildAZ({ quant, runtime, combat, staticData });
  invariant(Object.keys(report.final_report_A_to_Z).length === 26, 'A-Z report must contain 26 decisions');

  fs.mkdirSync(outputDir, { recursive: true });
  const jsonPath = path.join(outputDir, 'quantization_runtime_combat_reconstruction_report.json');
  const mdPath = path.join(outputDir, 'ROFL_QUANTIZATION_AWARE_RUNTIME_STATE_AND_COMBAT_RECONSTRUCTION_V1_REPORT.md');
  const evidencePath = path.join(outputDir, 'EVIDENCE.md');
  fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync(mdPath, renderMarkdown(report));
  fs.writeFileSync(evidencePath, renderEvidence(report));
  const artifacts = [jsonPath, mdPath, evidencePath].map((file) => ({
    path: path.basename(file), bytes: fs.statSync(file).size, sha256: sha256File(file),
  }));
  const manifestPath = path.join(outputDir, 'artifact_manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify({
    schema: 'ROFL_QUANTIZATION_RUNTIME_COMBAT_ARTIFACT_MANIFEST_V1', exact_build: EXACT_BUILD,
    artifacts, protected_holdout: report.protected_holdout,
  }, null, 2)}\n`);
  return { report, paths: { jsonPath, mdPath, evidencePath, manifestPath } };
}

module.exports = {
  CONTROLLED_REPLAY_SHA256, EXACT_BUILD, P0, RUNTIME_IMAGE_SHA256,
  allRequiredQuantizedCount, defaultInputs, runIntegratedReconstruction,
  validateArtifactManifest, validateStaticData,
};
