#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const TEST_COMMAND = 'node --test test/*.test.js';
const PORTABLE_TEST_FILES = [
  'test/path_v2.test.js',
  'test/ward_v2.test.js',
  'test/ward_analysis_v2.test.js',
  'test/package_portability.test.js',
];
const manifestPath = path.join(root, 'artifacts', 'v2_research', 'v2_regression_manifest.json');
const tracked = [
  'README.md',
  'AI_HANDOFF.md',
  'package.json',
  'src/rofl.js',
  'src/cli.js',
  'src/ward_pipeline_v2.js',
  'src/path_pipeline_v2.js',
  'src/ward_analysis_v2.js',
  'test/ward_v2.test.js',
  'test/path_v2.test.js',
  'test/ward_analysis_v2.test.js',
  'scripts/build_ward_outputs_v2.js',
  'scripts/validate_ward_v2.js',
  'scripts/decode_ward_spawn_16_15.py',
  'scripts/validate_ward_spawn_16_15.js',
  'scripts/analyze_packet_factory_registration.py',
  'scripts/emulate_ward_spawn_candidates.py',
  'scripts/migrate_path_packet_16_15.py',
  'scripts/enrich_path_hero_position_provenance.py',
  'scripts/list_ward_entity_params.js',
  'scripts/summarize_ward_entity_scan.js',
  'scripts/verify_v2_regression.js',
  'scripts/package_handoff.py',
  'artifacts/v2_research/ward_dataset/ward_validation_report.json',
  'artifacts/v2_research/ward_dataset/V2_HOLDOUT_STATUS.json',
  'artifacts/v2_research/ward_dataset/ward_spell_inventory.json',
  'artifacts/v2_research/ward_dataset/ward_cast_candidates.jsonl',
  'artifacts/v2_research/ward_dataset/ward_events.jsonl',
  'artifacts/v2_research/ward_dataset/ward_events.csv',
  'artifacts/v2_research/ward_dataset/ward_lifecycles.jsonl',
  'artifacts/v2_research/ward_dataset/ward_cast_spawn_matches.jsonl',
  'artifacts/v2_research/ward_dataset/ward_heatmap_input.jsonl',
  'artifacts/v2_research/ward_dataset/ward_heatmap_input.csv',
  'artifacts/v2_research/ward_dataset/ward_timeline_oracle_matches.jsonl',
  'artifacts/v2_ward_spawn/upstream_reference_manifest.json',
  'artifacts/v2_ward_spawn/old_build_ward_spawn_signature.json',
  'artifacts/v2_ward_spawn/current_registration_analysis.json',
  'artifacts/v2_ward_spawn/current_ward_emulation_summary.json',
  'artifacts/v2_ward_spawn/ward_spawn_profile_16_15.json',
  'artifacts/v2_ward_spawn/current_full_decode/summary.json',
  'artifacts/v2_ward_spawn/current_full_decode/validation.json',
  'artifacts/v2_ward_spawn/current_full_decode/packet_0353.jsonl.manifest.json',
  'artifacts/v2_ward_spawn/current_path_packet_analysis.json',
  'artifacts/v2_ward_spawn/current_path_summary.json',
  'artifacts/v2_ward_spawn/path_packet_profile_16_15.json',
  'artifacts/v2_ward_spawn/current_path_raw_packets_all10.jsonl.manifest.json',
  'artifacts/v2_ward_spawn/current_path_hero_positions_1s_all10_enriched_provenance_manifest.json',
  'artifacts/v2_research/ward_entity_params_11154791609_fixed.json',
  'artifacts/v2_research/ward_entity_params_holdout_fixed.json',
  'artifacts/v2_research/ward_entity_params_summary.json',
  'artifacts/v2_research/ward_neighbors_holdout.json',
  'artifacts/v2_research/ward_neighbors_11154791609.json',
  'artifacts/v2_research/ward_entity_params_holdout.json',
  'artifacts/v2_research/ward_entity_params_holdout2.json',
  'artifacts/v2_research/ward_entity_params_holdout3.json',
  'artifacts/v2_research/ward_coordinate_echoes_11154791609.json',
  'artifacts/v2_research/ward_coordinate_echoes_11154791609_fixed.json',
  'artifacts/v2_research/ward_coordinate_echoes_holdout_fixed.json',
  'docs/V2_WARD_STATUS.md',
  'docs/V2_REGRESSION.md',
  'docs/WARD_SPAWN_UPSTREAM_REVERSE_ENGINEERING.md',
];

function sha256(filePath) {
  const hash = crypto.createHash('sha256');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  const descriptor = fs.openSync(filePath, 'r');
  try {
    for (;;) {
      const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return hash.digest('hex');
}

function runValidator(name, args, expectedStatus) {
  const result = spawnSync(process.execPath, args, {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  let report = null;
  let parseError = null;
  try {
    report = JSON.parse(result.stdout);
  } catch (error) {
    parseError = error.message;
  }
  return {
    name,
    command: [process.execPath, ...args],
    exit_code: result.status,
    status: report?.status ?? null,
    expected_status: expectedStatus,
    pass: result.status === 0 && report?.status === expectedStatus,
    parse_error: parseError,
    stderr: result.stderr.trim() || null,
  };
}

function verifyIntegrationSourceHashes(report) {
  const rows = Array.isArray(report.source_files) ? report.source_files : [];
  const results = rows.map((entry, index) => {
    const sourcePath = typeof entry?.path === 'string' ? entry.path : null;
    const expectedSha256 = typeof entry?.sha256 === 'string' ? entry.sha256.toLowerCase() : null;
    const resolved = sourcePath && path.isAbsolute(sourcePath)
      ? path.normalize(sourcePath)
      : sourcePath ? path.resolve(root, sourcePath) : null;
    const exists = Boolean(resolved && fs.existsSync(resolved));
    const actualSha256 = exists ? sha256(resolved) : null;
    return {
      index,
      path: sourcePath,
      expected_sha256: expectedSha256,
      actual_sha256: actualSha256,
      pass: exists && /^[a-f0-9]{64}$/.test(expectedSha256 ?? '')
        && actualSha256 === expectedSha256,
    };
  });
  return {
    declared_source_file_count: report.source_file_count ?? null,
    checked_source_file_count: results.length,
    pass: results.length > 0
      && report.source_file_count === results.length
      && results.every((result) => result.pass),
    results,
  };
}

function verifyPathProvenanceManifest() {
  const manifestPath = path.join(root, 'artifacts', 'v2_ward_spawn',
    'current_path_hero_positions_1s_all10_enriched_provenance_manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const evidence = [];
  const verifyFileEvidence = (name, fileEvidence) => {
    const sourcePath = fileEvidence?.path;
    const exists = typeof sourcePath === 'string' && fs.existsSync(sourcePath);
    const actual = exists ? {
      bytes: fs.statSync(sourcePath).size,
      sha256: sha256(sourcePath),
    } : null;
    const pass = exists && actual.bytes === fileEvidence.bytes
      && actual.sha256 === fileEvidence.sha256;
    evidence.push({ name, path: sourcePath ?? null, pass, expected: fileEvidence ?? null, actual });
    return pass;
  };
  const inputPass = Object.entries(manifest.inputs ?? {}).map(
    ([name, value]) => verifyFileEvidence(`input:${name}`, value),
  );
  const outputPass = verifyFileEvidence('output', manifest.output);
  const generatorPass = verifyFileEvidence('generator', manifest.generator);
  const checks = manifest.checks ?? {};
  const declaredChecksPass = checks.all_raw_packets_are_0x02d1 === true
    && checks.all_hero_events_link_to_raw_packets === true
    && checks.all_event_packet_timestamps_match === true
    && checks.all_hero_positions_linked === true
    && checks.linked_count_matches_expected === true;
  const countPass = manifest.counts?.hero_positions_1s === 159765
    && manifest.counts?.linked_hero_positions_1s === 159765;
  const linkagePass = manifest.linkage?.packet_id === 0x02d1
    && manifest.linkage?.packet_type === '0x02d1';
  return {
    manifest_path: path.relative(root, manifestPath).replaceAll('\\', '/'),
    pass: inputPass.every(Boolean) && outputPass && generatorPass
      && declaredChecksPass && countPass && linkagePass,
    declared_checks_pass: declaredChecksPass,
    count_pass: countPass,
    linkage_pass: linkagePass,
    files: evidence,
  };
}

function verifyLitePackage() {
  const packageManifestPath = path.join(root, 'package_manifest.json');
  if (!fs.existsSync(packageManifestPath)) return false;
  const packageManifest = JSON.parse(fs.readFileSync(packageManifestPath, 'utf8'));
  const checks = {};
  const failures = [];
  const check = (name, pass, detail) => {
    checks[name] = { pass: Boolean(pass), detail };
    if (!pass) failures.push(`${name}: ${detail}`);
  };
  const entries = Object.entries(packageManifest.files ?? {});
  const payloads = entries.map(([relative, expected]) => {
    const safe = !path.isAbsolute(relative) && !relative.split(/[\\/]/).includes('..');
    const file = safe ? path.resolve(root, relative) : null;
    const exists = Boolean(file && file.startsWith(`${root}${path.sep}`) && fs.existsSync(file));
    const actual = exists ? { size: fs.statSync(file).size, sha256: sha256(file) } : null;
    return { relative, pass: safe && actual?.size === expected.size && actual?.sha256 === expected.sha256 };
  });
  check('handoff_package_metadata', packageManifest.package === 'rofl-analyzer-ai-handoff'
    && packageManifest.verification_mode === 'SOURCE_AND_BOUNDED_EVIDENCE'
    && packageManifest.raw_redecode_performed === false,
  'package manifest must explicitly declare source-and-bounded-evidence verification');
  check('included_payload_hashes', entries.length === packageManifest.file_count
    && payloads.every((payload) => payload.pass), `checked=${payloads.length}`);
  check('exclusions_declared', Array.isArray(packageManifest.deliberately_excluded)
    && packageManifest.deliberately_excluded.some((item) => item.includes('.rofl'))
    && packageManifest.deliberately_excluded.some((item) => item.includes('memory.bin')),
  'raw replay and runtime image exclusions must be explicit');

  const packageTests = spawnSync(process.execPath, ['--test', ...PORTABLE_TEST_FILES], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  check('package_test_suite', packageTests.status === 0, `exit=${packageTests.status}`);

  let boundedWard = null;
  try {
    boundedWard = JSON.parse(fs.readFileSync(path.join(
      root, 'artifacts', 'v2_ward_spawn', 'ward_spawn_profile_16_15.json',
    ), 'utf8'));
  } catch (error) {
    failures.push(`bounded_ward_evidence: ${error.message}`);
  }
  check('bounded_ward_evidence', boundedWard?.validation_status === 'CURRENT_WARD_SPAWN_VERIFIED_DIRECT'
    && boundedWard?.target_replay_version === '16.15.801.3452'
    && boundedWard?.full_decode_validation?.selected_packet_count === 17406
    && boundedWard?.full_decode_validation?.ward_spawn_count === 1357
    && boundedWard?.full_decode_validation?.lifecycle_match_count === 637,
  'included profile must retain the patch gate and attested Ward counts');
  const result = {
    schema_version: 3,
    status: failures.length === 0 ? 'PASS' : 'FAIL',
    verification_mode: 'SOURCE_AND_BOUNDED_EVIDENCE',
    raw_redecode_performed: false,
    generated_at_utc: new Date().toISOString(),
    test_status: packageTests.status === 0 ? 'PASS' : 'FAIL',
    test_exit_code: packageTests.status,
    ward_validators: [],
    evidence_status: failures.length === 0 ? 'PASS' : 'FAIL',
    evidence_checks: checks,
    evidence_failures: failures,
    manifest_path: 'package_manifest.json',
    verified_payload_count: payloads.length,
    deliberately_excluded: packageManifest.deliberately_excluded,
    note: 'Portable verification validates the closed payload, portable tests and bounded historical Ward evidence. It does not re-decode excluded raw artifacts.',
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.status === 'PASS' ? 0 : 1;
  return true;
}

function enumerateRepositoryTestFiles() {
  const testRoot = path.join(root, 'test');
  return fs.readdirSync(testRoot, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.test.js'))
    .map((entry) => path.join('test', entry.name))
    .sort();
}

if (verifyLitePackage()) process.exit();

const focusedTest = spawnSync(process.execPath, [
  '--test', 'test/ward_v2.test.js', 'test/path_v2.test.js',
], {
  cwd: root,
  encoding: 'utf8',
});
const fullTest = spawnSync(process.execPath, ['--test', ...enumerateRepositoryTestFiles()], {
  cwd: root,
  encoding: 'utf8',
  maxBuffer: 16 * 1024 * 1024,
});
const temporaryValidatorOutput = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-v2-ward-validator-'));
let wardValidators;
try {
  wardValidators = [
    runValidator('ward_spawn_16_15', ['scripts/validate_ward_spawn_16_15.js'], 'PASS'),
  ];
  const replayManifest = JSON.parse(fs.readFileSync(path.join(
    root, 'artifacts', 'replay_manifest.json',
  ), 'utf8'));
  const allReplayInputsPresent = (replayManifest.replays ?? []).every(
    (replay) => typeof replay.replay_path === 'string' && fs.existsSync(replay.replay_path),
  );
  wardValidators.push(allReplayInputsPresent
    ? runValidator('ward_pipeline_v2', [
      'scripts/validate_ward_v2.js', '--output', temporaryValidatorOutput,
    ], 'RESEARCH_READY_V2_COMPLETE')
    : {
      name: 'ward_pipeline_v2',
      command: [process.execPath, 'scripts/validate_ward_v2.js', '--output', temporaryValidatorOutput],
      exit_code: null,
      status: 'NOT_RUN_MISSING_PRIVATE_REPLAY_INPUTS',
      expected_status: 'RESEARCH_READY_V2_COMPLETE',
      pass: null,
      parse_error: null,
      stderr: null,
    });
} finally {
  fs.rmSync(temporaryValidatorOutput, { recursive: true, force: true });
}
const missing = tracked.filter((relative) => !fs.existsSync(path.join(root, relative)));
const files = Object.fromEntries(tracked.filter((relative) => !missing.includes(relative)).map((relative) => {
  const full = path.join(root, relative);
  return [relative, { size: fs.statSync(full).size, sha256: sha256(full) }];
}));

const evidenceChecks = {};
const evidenceFailures = [];
function check(name, condition, detail) {
  evidenceChecks[name] = { pass: Boolean(condition), detail };
  if (!condition) evidenceFailures.push(`${name}: ${detail}`);
}
try {
  const ward = JSON.parse(fs.readFileSync(path.join(
    root, 'artifacts', 'v2_ward_spawn', 'current_full_decode', 'summary.json',
  ), 'utf8'));
  const wardValidation = JSON.parse(fs.readFileSync(path.join(
    root, 'artifacts', 'v2_ward_spawn', 'current_full_decode', 'validation.json',
  ), 'utf8'));
  const pathSummary = JSON.parse(fs.readFileSync(path.join(
    root, 'artifacts', 'v2_ward_spawn', 'current_path_summary.json',
  ), 'utf8'));
  const integrated = JSON.parse(fs.readFileSync(path.join(
    root, 'artifacts', 'v2_research', 'ward_dataset', 'ward_validation_report.json',
  ), 'utf8'));
  const integrationSourceHashes = verifyIntegrationSourceHashes(integrated);
  const pathProvenance = verifyPathProvenanceManifest();
  check('ward_full_decode', ward.status === 'PASS'
    && ward.counts.input_packets === 17406
    && ward.counts.cast_spawn_matches === 464
    && ward.counts.unmatched_casts === 0,
  `status=${ward.status}, packets=${ward.counts.input_packets}, matches=${ward.counts.cast_spawn_matches}`);
  check('ward_independent_validator', wardValidation.status === 'PASS'
    && wardValidation.validated_match_count === 464
    && wardValidation.validated_lifecycle_count === 637,
  `status=${wardValidation.status}, matches=${wardValidation.validated_match_count}`);
  check('path_full_decode', pathSummary.validation?.all_checks_pass === true
    && pathSummary.full_decode?.packet_count === 374368
    && pathSummary.hero_positions_1s?.position_count === 159765,
  `status=${pathSummary.validation?.status}, packets=${pathSummary.full_decode?.packet_count}`);
  check('path_coordinate_calibration', pathSummary.calibration?.transform_verified === true
    && pathSummary.calibration?.match_count === 27452
    && pathSummary.calibration?.candidate_error?.p95 < 100
    && pathSummary.calibration?.swapped_axis_error?.p50 > 6000,
  `matches=${pathSummary.calibration?.match_count}, p95=${pathSummary.calibration?.candidate_error?.p95}`);
  check('integrated_ward_dataset', integrated.status === 'RESEARCH_READY_V2_COMPLETE'
    && integrated.counts?.ward_events_entity_spawn_direct === 464
    && integrated.counts?.ward_lifecycles === 637,
  `status=${integrated.status}, direct=${integrated.counts?.ward_events_entity_spawn_direct}`);
  check('current_ward_validators', wardValidators.every(
    (validator) => validator.pass === true || validator.status === 'NOT_RUN_MISSING_PRIVATE_REPLAY_INPUTS'
  ),
    wardValidators.map((validator) => `${validator.name}: exit=${validator.exit_code}, status=${validator.status}`).join('; '));
  check('integration_source_hashes', integrationSourceHashes.pass,
    `checked=${integrationSourceHashes.checked_source_file_count}, declared=${integrationSourceHashes.declared_source_file_count}`);
  check('path_position_provenance', pathProvenance.pass,
    `manifest=${pathProvenance.manifest_path}, files=${pathProvenance.files.length}`);
  evidenceChecks.current_ward_validators.validators = wardValidators;
  evidenceChecks.integration_source_hashes.sources = integrationSourceHashes;
  evidenceChecks.path_position_provenance.provenance = pathProvenance;
} catch (error) {
  evidenceFailures.push(`evidence_read: ${error.message}`);
}
const result = {
  schema_version: 2,
  generated_at_utc: new Date().toISOString(),
  command: TEST_COMMAND,
  test_status: focusedTest.status === 0 && fullTest.status === 0 ? 'PASS' : 'FAIL',
  test_exit_code: fullTest.status,
  focused_test_exit_code: focusedTest.status,
  full_test_exit_code: fullTest.status,
  ward_validators: wardValidators,
  package_metadata: {
    command: 'npm run package:handoff',
    platform: 'Python 3.10+ (cross-platform)',
    archive_entry_path_separator: '/',
    enriched_path_jsonl: 'excluded; its SHA-256 is independently rechecked through the included provenance manifest',
  },
  evidence_status: evidenceFailures.length === 0 ? 'PASS' : 'FAIL',
  evidence_checks: evidenceChecks,
  evidence_failures: evidenceFailures,
  tracked_files: files,
  missing_files: missing,
  manifest_path: path.relative(root, manifestPath).replaceAll('\\', '/'),
};

if (process.argv.includes('--write-manifest')) {
  fs.mkdirSync(path.dirname(manifestPath), { recursive: true });
  fs.writeFileSync(manifestPath, `${JSON.stringify(result, null, 2)}\n`);
}
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
process.exitCode = focusedTest.status === 0 && fullTest.status === 0
  && missing.length === 0 && evidenceFailures.length === 0 ? 0 : 1;
