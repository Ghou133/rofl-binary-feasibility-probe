'use strict';

// Adapter for the deliberately narrow root-CharacterRecord extractor.  This
// is not a champion-stat formula engine: values remain direct BIN fields (or
// null) and the component never grants a global mechanics consumer permission.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const EXACT_BUILD = '16.16.805.0442';
const REPORT_SCHEMA = 'ROFL_EXACT_BUILD_CHAMPION_STATS_V1';
const COMPONENT_SCHEMA = 'ROFL_EXACT_BUILD_CHAMPION_COMPONENT_V1';
const VALIDATION_SCHEMA = 'ROFL_EXACT_BUILD_CHAMPION_COMPONENT_VALIDATION_V1';
const VERIFIED_COMPONENT_STATUS = 'VERIFIED_EXACT_BUILD_ROOT_CHARACTER_RECORDS_NORMALIZED';
const UNVERIFIED_COMPONENT_STATUS = 'UNVERIFIED_SOURCE_BYTES_ROOT_CHARACTER_RECORDS_NORMALIZED';
const VERIFIED_VALIDATION_STATUS = 'VERIFIED_COMPONENT_SEMANTICS';
const UNVERIFIED_VALIDATION_STATUS = 'SOURCE_BYTES_NOT_VERIFIED';
const VERIFIED_EVIDENCE_GRADE = 'VERIFIED_DIRECT';
const UNVERIFIED_EVIDENCE_GRADE = 'UNVERIFIED_SOURCE_BYTES';
const REQUIRED_CDTB_HASH_NAMES = Object.freeze([
  'hashes.game.txt', 'hashes.binentries.txt', 'hashes.bintypes.txt', 'hashes.binfields.txt', 'hashes.binhashes.txt',
]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(stableValue(value));
}

function sha256Buffer(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sha256File(filePath) {
  return sha256Buffer(fs.readFileSync(filePath));
}

function isSha256(value) {
  return typeof value === 'string' && /^[a-f0-9]{64}$/iu.test(value);
}

function assertNoHoldoutPath(candidate, label) {
  const absolute = path.resolve(String(candidate));
  invariant(!absolute.split(/[\\/]+/u).some((segment) => /holdout/iu.test(segment)),
    `${label} resolves through a restricted Holdout path`);
}

function canonicalizeExistingSafePath(candidate, label = 'input') {
  assertNoHoldoutPath(candidate, label);
  const canonical = fs.realpathSync.native(path.resolve(String(candidate)));
  assertNoHoldoutPath(canonical, label);
  return canonical;
}

function canonicalizeProspectiveSafePath(candidate, label = 'output') {
  const absolute = path.resolve(String(candidate));
  assertNoHoldoutPath(absolute, label);
  let ancestor = absolute;
  while (!fs.existsSync(ancestor)) {
    const parent = path.dirname(ancestor);
    invariant(parent !== ancestor, `${label} has no existing ancestor`);
    ancestor = parent;
  }
  const canonicalAncestor = fs.realpathSync.native(ancestor);
  assertNoHoldoutPath(canonicalAncestor, label);
  const result = path.resolve(canonicalAncestor, path.relative(ancestor, absolute));
  assertNoHoldoutPath(result, label);
  return result;
}

function requiredObject(value, label) {
  invariant(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
  return value;
}

function validateHashSource(source, label, verifySourceBytes) {
  requiredObject(source, label);
  invariant(typeof source.path === 'string' && source.path.length > 0, `${label} missing path`);
  invariant(isSha256(source.sha256), `${label} missing SHA-256`);
  const canonical = canonicalizeExistingSafePath(source.path, label);
  invariant(fs.statSync(canonical).isFile(), `${label} is not a file`);
  const actualSha256 = verifySourceBytes ? sha256File(canonical) : null;
  if (verifySourceBytes) invariant(actualSha256 === source.sha256.toLowerCase(), `${label} hash mismatch`);
  return stableValue({ path: canonical, declared_sha256: source.sha256.toLowerCase(), actual_sha256: actualSha256,
    byte_verification: verifySourceBytes ? 'PASS' : 'SKIPPED_BY_EXPLICIT_CALLER_OPTION' });
}

function validateReport({
  reportPath,
  expectedSha256,
  requestedBuild = EXACT_BUILD,
  verifySourceBytes = true,
  allowUnverifiedTestFixture = false,
} = {}) {
  invariant(requestedBuild === EXACT_BUILD, 'exact-build request mismatch');
  invariant(verifySourceBytes || allowUnverifiedTestFixture === true,
    'source-byte verification may be disabled only for an explicit unverified test fixture');
  invariant(typeof reportPath === 'string' && reportPath.length > 0, 'reportPath is required');
  invariant(isSha256(expectedSha256), 'expectedSha256 must be a SHA-256');
  const canonicalReport = canonicalizeExistingSafePath(reportPath, 'champion extraction report');
  const actualReportSha256 = sha256File(canonicalReport);
  invariant(actualReportSha256 === expectedSha256.toLowerCase(), 'champion extraction report hash mismatch');
  const report = JSON.parse(fs.readFileSync(canonicalReport, 'utf8'));
  invariant(report.schema === REPORT_SCHEMA, 'champion extraction report schema mismatch');
  invariant(report.status === 'EXACT_BUILD_EXTRACTED', 'champion extraction report status is not exact-build extracted');
  invariant(report.exact_build === requestedBuild, 'champion extraction report build mismatch');
  const binding = requiredObject(report.build_binding, 'build_binding');
  invariant(binding.status === 'EXACT_BUILD_MATCH', 'build binding is not exact-build matched');
  invariant(binding.requested_canonical === requestedBuild && binding.observed_canonical === requestedBuild,
    'build binding canonical exact-build mismatch');
  const buildSource = validateHashSource({ path: binding.path, sha256: binding.sha256 }, 'build binding executable', verifySourceBytes);
  const sourceHashes = requiredObject(report.source_hashes, 'source_hashes');
  const metadata = validateHashSource(sourceHashes.build_metadata, 'build metadata source', verifySourceBytes);
  invariant(metadata.declared_sha256 === buildSource.declared_sha256,
    'build_binding and source_hashes.build_metadata disagree');
  invariant(Array.isArray(sourceHashes.cdtb_hash_files) && sourceHashes.cdtb_hash_files.length > 0,
    'CDTB hash sources are missing');
  const cdtb = sourceHashes.cdtb_hash_files.map((source, index) => validateHashSource(source,
    `CDTB hash source ${index}`, verifySourceBytes));
  invariant(Array.isArray(sourceHashes.champion_wads) && sourceHashes.champion_wads.length > 0,
    'champion WAD sources are missing');
  const championWads = sourceHashes.champion_wads.map((source, index) => validateHashSource(source,
    `champion WAD source ${index}`, verifySourceBytes));
  const wadByPath = new Map();
  for (const source of championWads) {
    invariant(!wadByPath.has(source.path), `duplicate champion WAD source path ${source.path}`);
    wadByPath.set(source.path, source);
  }
  const scope = requiredObject(report.scope, 'report scope');
  invariant(scope.enumeration === 'NONLOCALIZED_CHAMPIONS_DIRECT_CHILDREN_ONLY',
    'report does not declare direct nonlocalized champion WAD enumeration');
  invariant(scope.parsed_member_per_wad === 'data/characters/<champion>/<champion>.bin ONLY',
    'report does not declare root BIN-only parsing');
  invariant(scope.parsed_entry_per_bin === 'Characters/<champion>/CharacterRecords/Root ONLY',
    'report does not declare root CharacterRecord-only parsing');
  invariant(typeof scope.wad_directory === 'string' && scope.wad_directory.length > 0,
    'report does not declare the enumerated champion WAD directory');
  const canonicalWadDirectory = canonicalizeExistingSafePath(scope.wad_directory, 'enumerated champion WAD directory');
  invariant(fs.statSync(canonicalWadDirectory).isDirectory(), 'enumerated champion WAD directory is not a directory');
  invariant(new Set(sourceHashes.cdtb_hash_files.map((source) => source?.name)).size === REQUIRED_CDTB_HASH_NAMES.length
    && REQUIRED_CDTB_HASH_NAMES.every((name) => sourceHashes.cdtb_hash_files.some((source) => source?.name === name)),
  'CDTB hash sources do not match the extractor-required source set');
  for (const wad of championWads) {
    invariant(path.dirname(wad.path) === canonicalWadDirectory,
      `champion WAD source is not a direct child of the declared nonlocalized directory: ${wad.path}`);
  }
  invariant(report.protected_holdout && Object.values(report.protected_holdout).every((value) => value === false),
    'report does not affirm protected Holdout non-consumption');
  invariant(Array.isArray(report.champions), 'champion extraction report has no champion rows');
  invariant(report.champion_count === report.champions.length, 'champion count disagrees with rows');
  invariant(championWads.length === report.champions.length,
    'enumerated champion WAD count disagrees with root CharacterRecord rows');
  return { report, report_path: canonicalReport, report_sha256: actualReportSha256,
    sources: { build_metadata: metadata, cdtb_hash_files: cdtb, champion_wads: championWads, wad_by_path: wadByPath },
    champion_wad_directory: canonicalWadDirectory, verify_source_bytes: verifySourceBytes };
}

function fieldValue(field, label) {
  requiredObject(field, label);
  if (field.missing === true || field.value === null || field.value === undefined) return null;
  invariant(typeof field.value === 'number' && Number.isFinite(field.value), `${label} must be a finite number or null`);
  return field.value;
}

function provenance(field, sourcePath) {
  return stableValue({ source_path: sourcePath, source_field: field?.source_field ?? null,
    source_wrapper_field: field?.source_wrapper_field ?? null, source_container_field: field?.source_container_field ?? null,
    missing: field?.missing === true || field?.value === null || field?.value === undefined });
}

function mapChampion(champion, wadByPath) {
  requiredObject(champion, 'champion row');
  invariant(typeof champion.champion_wad_name === 'string' && champion.champion_wad_name.length > 0,
    'champion row missing champion_wad_name');
  invariant(typeof champion.character_name === 'string' && champion.character_name.length > 0,
    `champion ${champion.champion_wad_name} missing character_name`);
  const wad = requiredObject(champion.wad, `champion ${champion.champion_wad_name} wad`);
  const canonicalWad = canonicalizeExistingSafePath(wad.path, `champion ${champion.champion_wad_name} WAD`);
  const sourceWad = wadByPath.get(canonicalWad);
  invariant(sourceWad, `champion ${champion.champion_wad_name} WAD is absent from source hash inventory`);
  invariant(isSha256(wad.sha256) && wad.sha256.toLowerCase() === sourceWad.declared_sha256,
    `champion ${champion.champion_wad_name} WAD hash disagrees with source inventory`);
  const rootBin = requiredObject(champion.root_bin, `champion ${champion.champion_wad_name} root_bin`);
  invariant(isSha256(rootBin.sha256) && Number.isSafeInteger(rootBin.byte_size) && rootBin.byte_size >= 0,
    `champion ${champion.champion_wad_name} root BIN provenance is invalid`);
  const record = requiredObject(champion.root_character_record, `champion ${champion.champion_wad_name} root CharacterRecord`);
  invariant(record.type === 'CharacterRecord', `champion ${champion.champion_wad_name} is not a CharacterRecord`);
  const stats = requiredObject(champion.normalized_stats, `champion ${champion.champion_wad_name} normalized_stats`);
  const baseFields = {
    hp: stats.health?.base,
    hp_regen: stats.health_regen?.base,
    armor: stats.armor?.base,
    magic_resist: stats.magic_resist?.base,
    attack_damage: stats.attack_damage?.base,
    attack_speed: stats.attack_speed?.base_modifier,
    attack_speed_ratio: stats.attack_speed?.ratio,
    movement_speed: stats.movement_speed?.base,
  };
  const growthFields = {
    hp: stats.health?.per_level,
    hp_regen: stats.health_regen?.per_level,
    armor: stats.armor?.per_level,
    magic_resist: stats.magic_resist?.per_level,
    attack_damage: stats.attack_damage?.per_level,
    attack_speed_percent: stats.attack_speed?.per_level_percent,
  };
  const resource = stats.resources?.primary?.type;
  requiredObject(resource, `champion ${champion.champion_wad_name} primary resource type`);
  const fieldProvenance = {};
  const baseStats = {};
  const growthStats = {};
  const mappedMissing = [];
  for (const [name, field] of Object.entries(baseFields)) {
    baseStats[name] = fieldValue(field, `champion ${champion.champion_wad_name} base ${name}`);
    fieldProvenance[`base_stats.${name}`] = provenance(field, `normalized_stats`);
    if (baseStats[name] === null) mappedMissing.push(`base_stats.${name}`);
  }
  for (const [name, field] of Object.entries(growthFields)) {
    growthStats[name] = fieldValue(field, `champion ${champion.champion_wad_name} growth ${name}`);
    fieldProvenance[`growth_stats.${name}`] = provenance(field, `normalized_stats`);
    if (growthStats[name] === null) mappedMissing.push(`growth_stats.${name}`);
  }
  const resourceType = fieldValue(resource, `champion ${champion.champion_wad_name} resource type`);
  fieldProvenance.resource_type = provenance(resource, 'normalized_stats.resources.primary.type');
  if (resourceType === null) mappedMissing.push('resource_type');
  const missing = new Set([...(Array.isArray(champion.missing_fields) ? champion.missing_fields : []), ...mappedMissing]);
  return stableValue({
    id: champion.character_name,
    base_stats: baseStats,
    growth_stats: growthStats,
    resource_type: resourceType,
    field_provenance: fieldProvenance,
    missing_fields: [...missing].sort(),
    root_record_provenance: {
      champion_wad_name: champion.champion_wad_name,
      wad_path: canonicalWad,
      wad_sha256: wad.sha256.toLowerCase(),
      root_bin_path: rootBin.wad_member_path,
      root_bin_sha256: rootBin.sha256.toLowerCase(),
      root_bin_byte_size: rootBin.byte_size,
      character_record_path: record.entry_path,
      character_record_type: record.type,
    },
  });
}

function coverage(rows) {
  const fields = [
    'base_stats.hp', 'base_stats.hp_regen', 'base_stats.armor', 'base_stats.magic_resist',
    'base_stats.attack_damage', 'base_stats.attack_speed', 'base_stats.attack_speed_ratio',
    'base_stats.movement_speed', 'growth_stats.hp', 'growth_stats.hp_regen',
    'growth_stats.armor', 'growth_stats.magic_resist', 'growth_stats.attack_damage',
    'growth_stats.attack_speed_percent', 'resource_type',
  ];
  const counts = {};
  for (const dotted of fields) {
    const segments = dotted.split('.');
    counts[dotted] = rows.reduce((total, row) => {
      const value = segments.reduce((current, segment) => current?.[segment], row);
      return total + (value !== null && value !== undefined ? 1 : 0);
    }, 0);
  }
  return stableValue({ enumerated_root_wad_rows: rows.length, mapped_root_character_records: rows.length,
    unmapped_root_wad_rows: 0, mapped_row_coverage_status: 'COMPLETE_ENUMERATED_ROOT_WAD_ROW_MAPPING',
    per_stat_populated_rows: counts,
    stat_population_interpretation: 'Per-stat counts describe direct populated BIN fields only; they do not affect complete root-WAD row mapping.' });
}

function buildExactBuildChampionComponent(options = {}) {
  const verified = validateReport(options);
  const sourceBytesVerified = verified.verify_source_bytes;
  const rows = verified.report.champions.map((champion) => mapChampion(champion, verified.sources.wad_by_path));
  rows.sort((left, right) => left.id.localeCompare(right.id) || left.root_record_provenance.champion_wad_name.localeCompare(right.root_record_provenance.champion_wad_name));
  const identities = new Set();
  for (const row of rows) {
    invariant(!identities.has(row.id), `duplicate root CharacterRecord id ${row.id}`);
    identities.add(row.id);
  }
  const reportWadPaths = new Set(verified.sources.champion_wads.map((source) => source.path));
  const mappedWadPaths = new Set(rows.map((row) => row.root_record_provenance.wad_path));
  invariant(reportWadPaths.size === mappedWadPaths.size && [...reportWadPaths].every((value) => mappedWadPaths.has(value)),
    'not every enumerated direct nonlocalized WAD was mapped');
  const rowCoverage = coverage(rows);
  const component = stableValue({
    schema: COMPONENT_SCHEMA,
    schema_version: 1,
    status: sourceBytesVerified ? VERIFIED_COMPONENT_STATUS : UNVERIFIED_COMPONENT_STATUS,
    exact_build: EXACT_BUILD,
    component: 'champion',
    consumer_permission: false,
    publication_eligible: sourceBytesVerified,
    formula_semantics: 'NOT_CLAIMED',
    source_report: { path: verified.report_path, sha256: verified.report_sha256 },
    exact_build_binding: {
      status: sourceBytesVerified ? verified.report.build_binding.status : 'REPORTED_EXACT_BUILD_MATCH_SOURCE_BYTES_UNVERIFIED',
      observed_canonical: verified.report.build_binding.observed_canonical,
      requested_canonical: verified.report.build_binding.requested_canonical,
      executable_sha256: verified.sources.build_metadata.declared_sha256,
    },
    coverage: rowCoverage,
    // mechanics_build_importer intentionally accepts component-plural record
    // arrays.  Keep `rows` for component consumers and this alias for the
    // importer contract; both reference the same deterministic values.
    champions: rows,
    rows,
  });
  const evidenceCore = stableValue({
    schema: VALIDATION_SCHEMA,
    exact_build: EXACT_BUILD,
    validation_status: sourceBytesVerified ? VERIFIED_VALIDATION_STATUS : UNVERIFIED_VALIDATION_STATUS,
    evidence_grade: sourceBytesVerified ? VERIFIED_EVIDENCE_GRADE : UNVERIFIED_EVIDENCE_GRADE,
    publication_eligible: sourceBytesVerified,
    verification_mode: sourceBytesVerified ? 'REPORT_AND_DECLARED_SOURCE_BYTES_VERIFIED'
      : 'UNVERIFIED_TEST_FIXTURE_SOURCE_BYTES_SKIPPED',
    report: component.source_report,
    build_binding: component.exact_build_binding,
    source_verification: {
      build_metadata: verified.sources.build_metadata,
      cdtb_hash_files: verified.sources.cdtb_hash_files,
      champion_wad_count: verified.sources.champion_wads.length,
      champion_wad_sha256s: verified.sources.champion_wads.map((source) => ({ path: source.path, sha256: source.declared_sha256 })),
    },
    coverage: rowCoverage,
    protected_holdout: verified.report.protected_holdout,
    non_claims: ['NO_CHAMPION_LEVEL_FORMULA', 'NO_ITEM_OR_RUNE_SEMANTICS', 'NO_GLOBAL_CONSUMER_PERMISSION'],
  });
  const validationEvidenceSha256 = sha256Buffer(canonicalJson(evidenceCore));
  const semanticScope = stableValue({
    schema: 'ROFL_COMPONENT_SEMANTIC_SCOPE_V1', component: 'champion', scope: 'CHAMPION_BASE_AND_GROWTH',
    coverage_status: sourceBytesVerified ? 'COMPLETE_EXACT_BUILD_COMPONENT_COVERAGE' : 'SOURCE_BYTES_NOT_VERIFIED',
    validation_status: sourceBytesVerified ? VERIFIED_VALIDATION_STATUS : UNVERIFIED_VALIDATION_STATUS,
    evidence_grade: sourceBytesVerified ? VERIFIED_EVIDENCE_GRADE : UNVERIFIED_EVIDENCE_GRADE,
    publication_eligible: sourceBytesVerified, validation_evidence_sha256: validationEvidenceSha256,
    validated_fields: ['id', 'base_stats', 'growth_stats'],
    completeness_basis: 'Every enumerated direct nonlocalized champion WAD has one mapped root CharacterRecord row. This does not assert every stat is populated.',
  });
  const validationEvidence = stableValue({ ...evidenceCore, validation_evidence_sha256: validationEvidenceSha256,
    descriptor_ready_semantic_scope: semanticScope });
  return { component, validationEvidence, semanticScope };
}

function writeJsonSafe(filePath, value, label) {
  const target = canonicalizeProspectiveSafePath(filePath, label);
  fs.writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  return canonicalizeExistingSafePath(target, label);
}

function writeExactBuildChampionComponentArtifacts({ outputDir, ...options } = {}) {
  invariant(outputDir, 'outputDir is required');
  const target = canonicalizeProspectiveSafePath(outputDir, 'output directory');
  fs.mkdirSync(target, { recursive: true });
  const output = canonicalizeExistingSafePath(target, 'output directory');
  const result = buildExactBuildChampionComponent(options);
  const componentPath = writeJsonSafe(path.join(output, 'exact_build_champion_component.json'), result.component,
    'champion component output');
  const validationPath = writeJsonSafe(path.join(output, 'champion_component_validation_evidence.json'), result.validationEvidence,
    'champion component validation output');
  const descriptor = stableValue({
    id: `exact-build-champion-component-${EXACT_BUILD}`,
    component: 'champion', path: componentPath, expected_sha256: sha256File(componentPath),
    source: result.component.publication_eligible ? 'EXACT_BUILD_ROOT_CHARACTER_RECORDS'
      : 'UNVERIFIED_TEST_FIXTURE_ROOT_CHARACTER_RECORDS', declared_version: 'ROFL_EXACT_BUILD_CHAMPION_COMPONENT_V1',
    declared_build: EXACT_BUILD, evidence_grade: result.validationEvidence.evidence_grade, exact_build_identity: {
      build: EXACT_BUILD, status: result.component.publication_eligible
        ? 'VERIFIED_EXACT_BUILD_IDENTITY' : 'SOURCE_BYTES_NOT_VERIFIED',
    }, semantic_scope: result.semanticScope, consumer_permission: false,
    publication_eligible: result.component.publication_eligible,
  });
  const descriptorPath = writeJsonSafe(path.join(output, 'champion_component_descriptor.json'), descriptor,
    'champion component descriptor output');
  const artifacts = [componentPath, validationPath, descriptorPath].map((filePath) => ({
    path: path.basename(filePath), bytes: fs.statSync(filePath).size, sha256: sha256File(filePath),
  })).sort((left, right) => left.path.localeCompare(right.path));
  const closure = stableValue({ schema: 'ROFL_EXACT_BUILD_CHAMPION_COMPONENT_ARTIFACT_CLOSURE_V1', exact_build: EXACT_BUILD,
    source_report: result.component.source_report, artifacts });
  const closurePath = writeJsonSafe(path.join(output, 'artifact_closure.json'), closure, 'champion component closure output');
  return { ...result, descriptor, closure, paths: { component: componentPath, validation: validationPath,
    descriptor: descriptorPath, closure: closurePath } };
}

module.exports = {
  COMPONENT_SCHEMA,
  EXACT_BUILD,
  REPORT_SCHEMA,
  VALIDATION_SCHEMA,
  assertNoHoldoutPath,
  buildExactBuildChampionComponent,
  canonicalizeExistingSafePath,
  canonicalizeProspectiveSafePath,
  sha256File,
  validateReport,
  writeExactBuildChampionComponentArtifacts,
};
