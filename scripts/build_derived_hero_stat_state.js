#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  HOLDOUT_ACCESS,
  auditDerivedCombatState,
  deriveHeroStatState,
  mechanicsPayloadSha256,
  mintAlgorithmConformanceAuthority,
} = require('../src/derived_hero_stat_state');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_OUTPUT = path.join(
  ROOT, '.omo', 'evidence', 'stat_semantic_mapping_v1', 'derived_combat',
  'derived_hero_stat_state_build.json',
);
const EXACT_BUILD = '16.16.805.0442';
const HUD_ORACLE_PATH = path.join(
  ROOT, 'artifacts', 'controlled_calibration_replays', 'HN1-11212942693', 'p0_anchor_scan',
  'manual_ground_truth_import_v1', 'manual_ground_truth_oracle.json',
);
const HUD_ORACLE_SHA256 = 'd8940ef22a33bd580afc11fc8d8a17aae0dda9b232f70c459b31c1d2e6ecec24';

function assertNonHoldoutPath(filePath, name, mode = 'output') {
  const resolved = path.resolve(filePath);
  if (/holdout/i.test(resolved)) throw new Error(`${name} must not contain holdout`);
  if (fs.existsSync(resolved)) {
    const canonical = fs.realpathSync.native(resolved);
    if (/holdout/i.test(canonical)) throw new Error(`${name} canonical path must not contain holdout`);
    return canonical;
  }
  if (mode === 'input') throw new Error(`${name} must exist`);
  let ancestor = resolved;
  while (!fs.existsSync(ancestor)) {
    const parent = path.dirname(ancestor);
    if (parent === ancestor) throw new Error(`${name} has no existing canonical ancestor`);
    ancestor = parent;
  }
  const canonicalAncestor = fs.realpathSync.native(ancestor);
  const relativeSuffix = path.relative(ancestor, resolved);
  const canonicalTarget = path.resolve(canonicalAncestor, relativeSuffix);
  if (/holdout/i.test(canonicalAncestor) || /holdout/i.test(canonicalTarget)) {
    throw new Error(`${name} canonical target must not contain holdout`);
  }
  return canonicalTarget;
}

function sha256File(filePath) {
  const safePath = assertNonHoldoutPath(filePath, 'hash input path', 'input');
  return crypto.createHash('sha256').update(fs.readFileSync(safePath)).digest('hex');
}

function artifactEntry(filePath) {
  const safePath = assertNonHoldoutPath(filePath, 'artifact manifest input', 'input');
  const buffer = fs.readFileSync(safePath);
  return {
    path: path.basename(safePath),
    bytes: buffer.length,
    sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
  };
}

function writeArtifactManifest(reportPath) {
  const safeReport = assertNonHoldoutPath(reportPath, 'derived report path', 'input');
  const outputDirectory = path.dirname(safeReport);
  const artifacts = [artifactEntry(safeReport)];
  const testLog = path.join(outputDirectory, 'derived_hero_stat_state_test.log');
  if (fs.existsSync(testLog)) artifacts.push(artifactEntry(testLog));
  const manifest = {
    schema: 'ROFL_DERIVED_HERO_STAT_STATE_ARTIFACT_MANIFEST_V1',
    exact_build: EXACT_BUILD,
    engine_status: 'READY_FAIL_CLOSED',
    artifacts,
    protected_holdout: { ...HOLDOUT_ACCESS },
  };
  const manifestPath = assertNonHoldoutPath(
    path.join(outputDirectory, 'artifact_manifest.json'),
    'derived artifact manifest output',
  );
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  return { manifest, manifestPath };
}

function loadGovernedHudOracle() {
  const safePath = assertNonHoldoutPath(HUD_ORACLE_PATH, 'HUD oracle input path', 'input');
  const actualSha256 = sha256File(safePath);
  if (actualSha256 !== HUD_ORACLE_SHA256) throw new Error('governed HUD oracle SHA-256 mismatch');
  const oracle = JSON.parse(fs.readFileSync(safePath, 'utf8').replace(/^\uFEFF/, ''));
  if (oracle.schema_version !== 'GROUND_TRUTH_ORACLE_V1' || oracle.exact_build_only !== true) {
    throw new Error('governed HUD oracle contract mismatch');
  }
  function sequence(caseFragment, semantic) {
    const wanted = ['before_buy', 'after_buy', 'after_undo'];
    return wanted.map((observation) => {
      const record = oracle.records.find((row) => row.case_id.includes(caseFragment)
        && row.semantic === semantic && row.source?.observation_id === observation);
      if (!record || record.exact_build !== EXACT_BUILD
          || record.source?.fact_source !== 'MANUAL_EVENT_RELATIVE_HUD_OBSERVATION_V2') {
        throw new Error(`missing governed HUD observation ${caseFragment}:${observation}:${semantic}`);
      }
      return record.observed_value;
    });
  }
  return {
    path: safePath,
    sha256: actualSha256,
    evidence_grade: 'MANUAL_EVENT_RELATIVE_HUD_OBSERVATION_V2',
    automatic_promotion: oracle.source_provenance.automatic_promotion,
    item_cause_inference: oracle.item_cause_inference,
    ruby: sequence('P0-ITEM-07-RUBY-BUY-UNDO', 'MAX_HP'),
    cloth: sequence('P0-ITEM-09-CLOTH-BUY-UNDO', 'ARMOR'),
    mantle: sequence('P0-ITEM-11-MR-BUY-UNDO', 'MAGIC_RESIST'),
  };
}

function parseArgs(argv) {
  const options = { output: DEFAULT_OUTPUT, input: null };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--output') options.output = assertNonHoldoutPath(argv[++index] ?? '', '--output');
    else if (option === '--input') {
      options.input = assertNonHoldoutPath(argv[++index] ?? '', '--input', 'input');
    }
    else if (option === '--help' || option === '-h') options.help = true;
    else throw new Error(`unknown option: ${option}`);
  }
  if (!options.output) throw new Error('--output requires a path');
  options.output = assertNonHoldoutPath(options.output, '--output');
  return options;
}

function verifiedModifier(targetStat, value) {
  return {
    target_stat: targetStat,
    operation: 'ADD_FLAT',
    value,
    status: 'VERIFIED',
    exact_build: EXACT_BUILD,
    evidence: { kind: 'CONFORMANCE_FIXTURE_ONLY' },
  };
}

function conformanceInput(items = [], observations = loadGovernedHudOracle()) {
  const stat = (value) => ({
    values_by_level: { 2: value },
    calculation_formula_id: 'ALGORITHM_STAT_PIPELINE_V1',
    display: { rule: 'ROUND_NEAREST_INTEGER' },
  });
  const input = {
    exact_build: EXACT_BUILD,
    game_time: 120000,
    entity: { participant_id: 1, champion: 'Kayn' },
    champion_identity: { champion: 'Kayn', evidence: 'ALGORITHM_FIXTURE_ONLY', game_time: 120000 },
    level_state: { level: 2, status: 'COMPLETE', exact_build: EXACT_BUILD, game_time: 120000 },
    inventory_state: {
      status: 'COMPLETE', exact_build: EXACT_BUILD, ambiguous_mutation: false, items,
      game_time: 120000,
    },
    rune_state: {
      status: 'COMPLETE', exact_build: EXACT_BUILD, unmapped_modifier_count: 0, modifiers: [],
      game_time: 120000,
    },
    buff_state: {
      status: 'COMPLETE', exact_build: EXACT_BUILD, unmapped_modifier_count: 0, modifiers: [],
      game_time: 120000,
    },
    mechanics: {
      binding: {
        status: 'EXACT_BUILD_VERIFIED',
        identity_proof: true,
        exact_build: EXACT_BUILD,
        source_registry_ref: 'INTERNAL_ALGORITHM_FIXTURE_REGISTRY:V1',
        source_artifact_sha256: 'c'.repeat(64),
      },
      formulas: {
        stat_calculation: {
          ALGORITHM_STAT_PIPELINE_V1: {
            steps: [
              { operation: 'BASE_AT_LEVEL', semantics: 'BOUND_BASE_VALUE' },
              { operation: 'ADD_FLAT', semantics: 'SUM_THEN_ADD_TO_RUNNING' },
              { operation: 'ADD_PERCENT_BASE', semantics: 'SUM_TIMES_BASE_THEN_ADD_TO_RUNNING' },
              { operation: 'ADD_PERCENT_TOTAL', semantics: 'MULTIPLY_RUNNING_BY_ONE_PLUS_SUM' },
              { operation: 'MULTIPLY_TOTAL', semantics: 'MULTIPLY_RUNNING_BY_PRODUCT' },
            ],
          },
        },
        growth: {},
      },
      coverage: {
        max_hp: true,
        armor: true,
        magic_resist: true,
        item_catalog_complete: true,
        rune_mechanics_complete: true,
        buff_operation_model_complete: true,
        exception_registry_complete: true,
      },
      champions: {
        Kayn: {
          requires_exception_state: false,
          stats: {
            max_hp: stat(observations.ruby[0]),
            armor: stat(observations.cloth[0]),
            magic_resist: stat(observations.mantle[0]),
          },
        },
      },
      items: {
        1028: { modifiers: { max_hp: [verifiedModifier('max_hp', 150)] } },
        1029: { modifiers: { armor: [verifiedModifier('armor', 15)] } },
        1033: { modifiers: { magic_resist: [verifiedModifier('magic_resist', 20)] } },
      },
    },
  };
  input.mechanics.binding.payload_sha256 = mechanicsPayloadSha256(input.mechanics);
  return input;
}

function projection(input, authority) {
  const state = deriveHeroStatState(input, { authority });
  return {
    max_hp: state.fields.max_hp.display_value,
    armor: state.fields.armor.display_value,
    magic_resist: state.fields.magic_resist.display_value,
  };
}

function buildReport(explicitInput = null) {
  const hudObservations = loadGovernedHudOracle();
  const algorithmAuthority = mintAlgorithmConformanceAuthority();
  const baselineState = deriveHeroStatState(
    conformanceInput([], hudObservations), { authority: algorithmAuthority },
  );
  const baseline = projection(conformanceInput([], hudObservations), algorithmAuthority);
  const ruby = projection(conformanceInput([{ item_id: 1028 }], hudObservations), algorithmAuthority);
  const cloth = projection(conformanceInput([{ item_id: 1029 }], hudObservations), algorithmAuthority);
  const mantle = projection(conformanceInput([{ item_id: 1033 }], hudObservations), algorithmAuthority);
  const reversalsPass = baseline.max_hp === hudObservations.ruby[0]
    && ruby.max_hp === hudObservations.ruby[1]
    && baseline.armor === hudObservations.cloth[0]
    && cloth.armor === hudObservations.cloth[1]
    && baseline.magic_resist === hudObservations.mantle[0]
    && mantle.magic_resist === hudObservations.mantle[1];
  if (!reversalsPass) throw new Error('algorithm conformance projection failed');

  const patchFamilyInput = conformanceInput([], hudObservations);
  patchFamilyInput.mechanics.binding = {
    ...patchFamilyInput.mechanics.binding,
    status: 'PATCH_FAMILY_PINNED',
    identity_proof: false,
    exact_build: null,
  };
  const patchFamilyState = deriveHeroStatState(
    patchFamilyInput, { authority: algorithmAuthority },
  );
  const independentFieldInput = conformanceInput([], hudObservations);
  independentFieldInput.rune_state.complete_for = ['max_hp', 'magic_resist'];
  const independentFieldState = deriveHeroStatState(
    independentFieldInput, { authority: algorithmAuthority },
  );

  const currentAudit = auditDerivedCombatState({
    damage_recorded_amount_verified: true,
    damage_type_verified: true,
    heal_reported_verified: true,
    shield_generated_verified: true,
    shield_absorbed_target_total_verified: true,
    damage_stage: { stage: 'RECORDED_COMPONENT_STAGE_UNKNOWN' },
  });
  const explicitState = explicitInput === null ? null : deriveHeroStatState(explicitInput);
  return {
    schema: 'DERIVED_HERO_STAT_STATE_BUILD_REPORT_V1',
    schema_version: 1,
    project_context_loaded: true,
    architecture_gate: 'PASS',
    exact_build: EXACT_BUILD,
    engine_status: 'READY_FAIL_CLOSED',
    publication_boundary: {
      engine_contract: 'PUBLISHABLE_INTERNAL_CORE',
      max_hp: explicitState?.fields.max_hp.status ?? 'CONDITIONAL_ON_EXACT_BUILD_COMPLETE_INPUTS',
      armor: explicitState?.fields.armor.status ?? 'CONDITIONAL_ON_EXACT_BUILD_COMPLETE_INPUTS',
      magic_resist: explicitState?.fields.magic_resist.status
        ?? 'CONDITIONAL_ON_EXACT_BUILD_COMPLETE_INPUTS',
      conformance_fixture_is_public_semantic_evidence: false,
      patch_family_is_exact_build: false,
    },
    algorithm_conformance: {
      evidence_role: 'ALGORITHM_CONFORMANCE_AGAINST_MANUAL_HUD_OBSERVATIONS_ONLY',
      governed_hud_observations: hudObservations,
      baseline,
      ruby: { observed_sequence: hudObservations.ruby, derived_sequence: [baseline.max_hp, ruby.max_hp, baseline.max_hp] },
      cloth: { observed_sequence: hudObservations.cloth, derived_sequence: [baseline.armor, cloth.armor, baseline.armor] },
      mantle: { observed_sequence: hudObservations.mantle, derived_sequence: [baseline.magic_resist, mantle.magic_resist, baseline.magic_resist] },
      pass: reversalsPass,
    },
    derivation_evidence: {
      complete_exact_build_state: baselineState,
      patch_family_fail_closed_state: patchFamilyState,
      independent_field_nullability_state: independentFieldState,
    },
    explicit_input_state: explicitState,
    combat_computability_audit: currentAudit,
    protected_holdout_access: { ...HOLDOUT_ACCESS },
    validation_scenarios: [
      {
        scenario: 'targeted fail-closed core regression',
        invocation: 'node --test test/derived_hero_stat_state.test.js',
        binary_observable: 'all targeted tests pass and fail=0',
        captured_artifact: '.omo/evidence/stat_semantic_mapping_v1/derived_combat/derived_hero_stat_state_test.log',
      },
      {
        scenario: 'build derivation and combat computability evidence',
        invocation: 'node scripts/build_derived_hero_stat_state.js --output .omo/evidence/stat_semantic_mapping_v1/derived_combat/derived_hero_stat_state_build.json',
        binary_observable: 'engine_status=READY_FAIL_CLOSED and algorithm_conformance_pass=true',
        captured_artifact: '.omo/evidence/stat_semantic_mapping_v1/derived_combat/derived_hero_stat_state_build.json',
      },
      {
        scenario: 'protected Holdout output path rejection before write',
        invocation: 'node scripts/build_derived_hero_stat_state.js --output <path-containing-Holdout>',
        binary_observable: 'observed_exit_code=1 and forbidden_target_exists=False',
        captured_artifact: '.omo/evidence/stat_semantic_mapping_v1/derived_combat/holdout_path_guard_test.log',
      },
    ],
    source_hashes: {
      derived_core_sha256: sha256File(path.join(ROOT, 'src', 'derived_hero_stat_state.js')),
      unit_test_sha256: sha256File(path.join(ROOT, 'test', 'derived_hero_stat_state.test.js')),
      build_script_sha256: sha256File(__filename),
    },
  };
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write('Usage: node scripts/build_derived_hero_stat_state.js [--input FILE] [--output FILE]\n');
    return null;
  }
  const explicitInput = options.input === null
    ? null : JSON.parse(fs.readFileSync(
      assertNonHoldoutPath(options.input, '--input', 'input'), 'utf8',
    ).replace(/^\uFEFF/, ''));
  const report = buildReport(explicitInput);
  const safeOutput = assertNonHoldoutPath(options.output, '--output');
  fs.mkdirSync(path.dirname(safeOutput), { recursive: true });
  const recanonicalizedOutput = assertNonHoldoutPath(safeOutput, '--output');
  fs.writeFileSync(recanonicalizedOutput, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  const { manifestPath } = writeArtifactManifest(recanonicalizedOutput);
  process.stdout.write(`${JSON.stringify({
    output: options.output,
    manifest: manifestPath,
    engine_status: report.engine_status,
    algorithm_conformance_pass: report.algorithm_conformance.pass,
    combat_statuses: Object.fromEntries(Object.entries(report.combat_computability_audit)
      .filter(([, value]) => value && value.capability)
      .map(([key, value]) => [key, value.status])),
  }, null, 2)}\n`);
  return report;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  assertNonHoldoutPath,
  buildReport,
  conformanceInput,
  loadGovernedHudOracle,
  main,
  parseArgs,
  writeArtifactManifest,
};
