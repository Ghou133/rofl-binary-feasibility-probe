'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const EXACT_BUILD = '16.16.805.0442';
const RUNTIME_IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const GROWTH_CONSTANT_RVA = 0x01a510c8;
const GROWTH_CONSTANT_BITS_LE = '6666263f';

const REGISTERED_INPUT_HASHES = Object.freeze({
  growthXrefs: 'a26b58d765b40d9e502f20ce826d83474bd9e6fb62c11ea0c39452f379635a24',
  growthCallSites: 'fa3a4e2498826b061016983e91622f99e4947fd2ca91ae60c4737a138615c0ae',
  itemModifierXrefs: 'df8ad57d777f11ceca2e9693b03b0cf4db1c1b21ef9ad16bdc5299d4b0651058',
  runtimeAudit: 'ff6a373b23438e2bb20268e9339b867efac5754143c47661559c84f7eb814701',
  patchStaticSnapshot: '275289996c6ffa9cf01ac61dc7944671d67d6029de37dcfa336de8ac1c9a8d23',
});

const ITEM_MODIFIER_NAMES = Object.freeze([
  'FlatHPPoolMod', 'PercentHPPoolMod',
  'FlatArmorMod', 'PercentArmorMod',
  'FlatSpellBlockMod', 'PercentSpellBlockMod',
]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function assertNoRestrictedPathName(candidate, label) {
  const segments = path.resolve(candidate).split(/[\\/]+/u);
  invariant(!segments.some((segment) => /holdout/iu.test(segment)),
    `${label} resolves through a restricted path`);
}

function canonicalizeExistingSafePath(candidate, label) {
  const absolute = path.resolve(candidate);
  assertNoRestrictedPathName(absolute, label);
  const canonical = fs.realpathSync.native(absolute);
  assertNoRestrictedPathName(canonical, label);
  return canonical;
}

function canonicalizeProspectiveSafePath(candidate, label) {
  const absolute = path.resolve(candidate);
  assertNoRestrictedPathName(absolute, label);
  let ancestor = absolute;
  while (!fs.existsSync(ancestor)) {
    const parent = path.dirname(ancestor);
    invariant(parent !== ancestor, `${label} has no existing ancestor`);
    ancestor = parent;
  }
  const canonicalAncestor = fs.realpathSync.native(ancestor);
  assertNoRestrictedPathName(canonicalAncestor, label);
  const projected = path.resolve(canonicalAncestor, path.relative(ancestor, absolute));
  assertNoRestrictedPathName(projected, label);
  return projected;
}

function sha256File(file) {
  const canonical = canonicalizeExistingSafePath(file, 'hash input');
  return crypto.createHash('sha256').update(fs.readFileSync(canonical)).digest('hex');
}

function readJson(file) {
  const canonical = canonicalizeExistingSafePath(file, 'JSON input');
  return JSON.parse(fs.readFileSync(canonical, 'utf8'));
}

function defaultInputs(rootDir = path.resolve(__dirname, '..')) {
  return {
    runtimeImage: path.join(rootDir, 'artifacts', 'new_build_rofl_compatibility_gate_v1',
      'runtime', 'league_16.16.805.0442.memory.bin'),
    growthXrefs: path.join(rootDir, '.omo', 'evidence', 'quant_runtime_bridge',
      'growth_constant_xrefs.json'),
    growthCallSites: path.join(rootDir, '.omo', 'evidence', 'quant_runtime_bridge',
      'growth_constant_call_sites.json'),
    itemModifierXrefs: path.join(rootDir, '.omo', 'evidence', 'quant_runtime_bridge',
      'item_stat_modifier_xrefs.json'),
    runtimeAudit: path.join(rootDir, '.omo', 'evidence', 'quant_runtime_bridge',
      'hud_runtime_state_bridge_report.json'),
    patchStaticSnapshot: path.join(rootDir, 'artifacts', 'quantization_runtime_combat_v1',
      'static_data', 'patch_16_16_1_controlled_inputs.json'),
  };
}

function verifyRegisteredFile(file, expectedHash, label) {
  const canonical = canonicalizeExistingSafePath(file, label);
  invariant(fs.statSync(canonical).isFile(), `${label} is not a file`);
  const actual = sha256File(canonical);
  invariant(actual === expectedHash, `${label} source hash mismatch`);
  return { path: canonical, bytes: fs.statSync(canonical).size, sha256: actual };
}

function readCString(image, rva, maxLength = 128) {
  invariant(Number.isSafeInteger(rva) && rva >= 0 && rva < image.length, 'string RVA out of range');
  let end = rva;
  while (end < image.length && end - rva < maxLength && image[end] !== 0) end += 1;
  invariant(end < image.length && image[end] === 0, 'unterminated registered string');
  return image.subarray(rva, end).toString('utf8');
}

function verifyRipReference(image, reference, targetRva) {
  const start = reference.source_rva;
  const size = reference.instruction_size;
  invariant(Number.isSafeInteger(start) && Number.isSafeInteger(size) && size >= 5,
    'invalid xref instruction identity');
  invariant(start >= 0 && start + size <= image.length, 'xref instruction outside exact image');
  const displacement = image.readInt32LE(start + size - 4);
  const resolved = start + size + displacement;
  invariant(resolved === targetRva, `xref at 0x${start.toString(16)} does not resolve registered target`);
  return {
    source_rva: `0x${start.toString(16).padStart(8, '0')}`,
    instruction_bytes: image.subarray(start, start + size).toString('hex'),
    resolved_target_rva: `0x${resolved.toString(16).padStart(8, '0')}`,
    mnemonic: reference.mnemonic,
  };
}

function verifyDisassemblyBytes(image, artifact) {
  let count = 0;
  for (const slice of artifact.disassembly || []) {
    for (const instruction of slice.instructions || []) {
      const expected = instruction.bytes.toLowerCase();
      const actual = image.subarray(instruction.rva, instruction.rva + expected.length / 2).toString('hex');
      invariant(actual === expected, `disassembly byte mismatch at 0x${instruction.rva.toString(16)}`);
      count += 1;
    }
  }
  return count;
}

function buildExactBuildMechanicsData({
  rootDir = path.resolve(__dirname, '..'), inputs = defaultInputs(rootDir), requestedBuild = EXACT_BUILD,
} = {}) {
  invariant(requestedBuild === EXACT_BUILD, 'exact-build request mismatch');

  const sourceIdentity = {
    runtimeImage: verifyRegisteredFile(inputs.runtimeImage, RUNTIME_IMAGE_SHA256, 'runtime image'),
    growthXrefs: verifyRegisteredFile(inputs.growthXrefs, REGISTERED_INPUT_HASHES.growthXrefs,
      'growth xrefs'),
    growthCallSites: verifyRegisteredFile(inputs.growthCallSites,
      REGISTERED_INPUT_HASHES.growthCallSites, 'growth call sites'),
    itemModifierXrefs: verifyRegisteredFile(inputs.itemModifierXrefs,
      REGISTERED_INPUT_HASHES.itemModifierXrefs, 'item modifier xrefs'),
    runtimeAudit: verifyRegisteredFile(inputs.runtimeAudit, REGISTERED_INPUT_HASHES.runtimeAudit,
      'runtime audit'),
    patchStaticSnapshot: verifyRegisteredFile(inputs.patchStaticSnapshot,
      REGISTERED_INPUT_HASHES.patchStaticSnapshot, 'patch static snapshot'),
  };

  const image = fs.readFileSync(sourceIdentity.runtimeImage.path);
  const growthXrefs = readJson(sourceIdentity.growthXrefs.path);
  const growthCallSites = readJson(sourceIdentity.growthCallSites.path);
  const itemXrefs = readJson(sourceIdentity.itemModifierXrefs.path);
  const runtimeAudit = readJson(sourceIdentity.runtimeAudit.path);
  const patchSnapshot = readJson(sourceIdentity.patchStaticSnapshot.path);

  invariant(runtimeAudit.schema === 'HUD_RUNTIME_STATE_BRIDGE_AUDIT_V1'
    && runtimeAudit.exact_build === EXACT_BUILD
    && runtimeAudit.exact_runtime_image_sha256 === RUNTIME_IMAGE_SHA256,
  'runtime audit identity mismatch');
  invariant(patchSnapshot.schema === 'ROFL_PATCH_STATIC_DATA_DEPENDENCY_SNAPSHOT_V1'
    && patchSnapshot.replay_exact_build === EXACT_BUILD,
  'patch snapshot replay identity mismatch');
  invariant(patchSnapshot.binding_status
    === 'PATCH_FAMILY_PINNED_EXACT_BUILD_EQUIVALENCE_NOT_INDEPENDENTLY_PROVEN',
  'patch snapshot boundary was weakened');

  const growthTarget = String(GROWTH_CONSTANT_RVA);
  const growthReferences = growthXrefs.semantic_xrefs?.[growthTarget];
  invariant(Array.isArray(growthReferences) && growthReferences.length === 8,
    'registered growth constant xref population changed');
  invariant(image.subarray(GROWTH_CONSTANT_RVA, GROWTH_CONSTANT_RVA + 4).toString('hex')
    === GROWTH_CONSTANT_BITS_LE, 'growth constant bytes changed');
  const verifiedGrowthReferences = growthReferences.map((reference) =>
    verifyRipReference(image, reference, GROWTH_CONSTANT_RVA));
  const callSiteInstructionCount = verifyDisassemblyBytes(image, growthCallSites);
  invariant(callSiteInstructionCount === 204, 'growth call-site byte coverage changed');

  const verifiedModifierNames = [];
  let modifierReferenceCount = 0;
  for (const [target, references] of Object.entries(itemXrefs.semantic_xrefs || {})) {
    const targetRva = Number(target);
    const name = readCString(image, targetRva);
    invariant(ITEM_MODIFIER_NAMES.includes(name), `unexpected item modifier name ${name}`);
    const verifiedReferences = references.map((reference) => verifyRipReference(image, reference, targetRva));
    modifierReferenceCount += verifiedReferences.length;
    verifiedModifierNames.push({ name, target_rva: `0x${targetRva.toString(16)}`, references: verifiedReferences });
  }
  verifiedModifierNames.sort((a, b) => a.name.localeCompare(b.name));
  invariant(verifiedModifierNames.length === ITEM_MODIFIER_NAMES.length && modifierReferenceCount === 12,
    'item modifier registry population changed');

  const exceptions = [
    {
      exception_id: 'LEVEL_GROWTH_SEMANTIC_EDGE_MISSING',
      component: 'level_growth_rule',
      status: 'EVIDENCE_EXHAUSTED',
      missing_edge: 'No verified constant-reference slice joins a governed champion base/growth row, an identified level operand, and a stat output consumer.',
      consumer_permission: false,
    },
    {
      exception_id: 'CHAMPION_ROWS_PATCH_FAMILY_ONLY',
      component: 'champion_base_and_growth',
      status: 'PATCH_FAMILY_REJECTED_FOR_EXACT_BUILD',
      missing_edge: 'No independently versioned and hashed champion row source is bound to the exact runtime image.',
      consumer_permission: false,
    },
    {
      exception_id: 'ITEM_ROWS_PATCH_FAMILY_ONLY',
      component: 'item_stat_contributions',
      status: 'PATCH_FAMILY_REJECTED_FOR_EXACT_BUILD',
      missing_edge: 'Exact-image modifier names are verified, but no item-ID-to-value table is bound to those registrations for this build.',
      consumer_permission: false,
    },
    {
      exception_id: 'RUNE_STATE_SOURCE_ABSENT',
      component: 'runes',
      status: 'EVIDENCE_EXHAUSTED',
      missing_edge: 'No governed exact-build rune selection and stat-contribution source is present in the bounded input set.',
      consumer_permission: false,
    },
    {
      exception_id: 'P0_FORMULA_ORDER_UNBOUND',
      component: 'formula_order',
      status: 'EVIDENCE_EXHAUSTED',
      missing_edge: 'The formula-output container is structurally known, but P0 selectors, modifier operations, and flat/percent ordering are not identified.',
      consumer_permission: false,
    },
    {
      exception_id: 'P0_HUD_PROJECTION_UNBOUND',
      component: 'hud_projection',
      status: 'EVIDENCE_EXHAUSTED',
      missing_edge: 'The exact static audit maps only ManaRegen to a zero-decimal formatter; no P0 getter-to-formatter edge is verified.',
      consumer_permission: false,
    },
  ];

  const data = {
    schema: 'ROFL_EXACT_BUILD_MECHANICS_DATA_V1',
    exact_build: EXACT_BUILD,
    exact_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    status: 'EVIDENCE_EXHAUSTED',
    decision: 'NO_EXACT_BUILD_DERIVED_P0_STAT_PERMISSION',
    level_growth_static_probe: {
      constant_rva: `0x${GROWTH_CONSTANT_RVA.toString(16)}`,
      float32_value: image.readFloatLE(GROWTH_CONSTANT_RVA),
      float32_bits_le: GROWTH_CONSTANT_BITS_LE,
      exact_image_xref_count: verifiedGrowthReferences.length,
      exact_image_call_site_instruction_count: callSiteInstructionCount,
      verified_references: verifiedGrowthReferences,
      exact_build_growth_rule_bound: false,
      status: 'EVIDENCE_EXHAUSTED',
    },
    bounded_exact_image_modifier_name_targets: {
      names: verifiedModifierNames,
      exact_image_reference_count: modifierReferenceCount,
      item_id_value_table_bound: false,
      target_set_complete: false,
      selection_basis: 'SIX_ALLOWLISTED_HP_ARMOR_MAGIC_RESIST_NAMES_FROM_THE_PRIOR_BOUNDED_PROBE',
      rationale: 'These targets verify only that the six selected strings and their references exist; they are not a unique or complete modifier registry.',
      status: 'VERIFIED_BOUNDED_ALLOWLISTED_NAMES_ONLY',
    },
    components: {
      champion_base_and_growth: { exact_build_bound: false, status: 'UNAVAILABLE' },
      item_stat_contributions: { exact_build_bound: false, status: 'UNAVAILABLE' },
      runes: { exact_build_bound: false, status: 'UNAVAILABLE' },
      formula_order: { exact_build_bound: false, status: 'UNAVAILABLE' },
      hud_projection: {
        exact_build_bound: false,
        status: 'PARTIAL_NON_P0_ONLY',
        verified_non_p0_mapping: runtimeAudit.hud_display_function.non_p0_verified_formatter,
      },
    },
    patch_family_negative_control: {
      source_schema: patchSnapshot.schema,
      source_sha256: sourceIdentity.patchStaticSnapshot.sha256,
      declared_binding_status: patchSnapshot.binding_status,
      observed_examples: {
        champion: patchSnapshot.champion.id,
        champion_hp: patchSnapshot.champion.stats.hp,
        item_1028_hp: patchSnapshot.controlled_items['1028'].stats.FlatHPPoolMod,
        item_1029_armor: patchSnapshot.controlled_items['1029'].stats.FlatArmorMod,
        item_1033_magic_resist: patchSnapshot.controlled_items['1033'].stats.FlatSpellBlockMod,
      },
      accepted_as_exact_build_mechanics: false,
      status: 'REJECTED_FOR_EXACT_BUILD_DERIVATION',
    },
    source_identity: sourceIdentity,
    stop_condition: 'EVIDENCE_EXHAUSTED',
    precise_external_requirements: [
      'An authoritative champion base/growth table independently bound by version and hash to 16.16.805.0442.',
      'An authoritative item-ID stat table independently bound by version and hash to 16.16.805.0442.',
      'A governed rune-state/stat source for the replay participants.',
      'A verified level-growth dataflow or formula linking level and champion rows to named final stat outputs.',
      'Named P0 selector/lane consumers plus verified flat/percent modifier operation ordering.',
      'A verified P0 scalar getter-to-HUD formatter/projection edge.',
    ],
  };

  return {
    exact_build_mechanics_data: data,
    exception_registry: {
      schema: 'ROFL_EXACT_BUILD_MECHANICS_EXCEPTION_REGISTRY_V1',
      exact_build: EXACT_BUILD,
      exception_count: exceptions.length,
      exceptions,
    },
  };
}

function renderMarkdown(result) {
  const data = result.exact_build_mechanics_data;
  const lines = [
    '# Exact-build mechanics probe', '',
    `- Build: \`${data.exact_build}\``,
    `- Runtime image: \`${data.exact_runtime_image_sha256}\``,
    `- Status: **${data.status}**`,
    `- Decision: **${data.decision}**`, '',
    'The exact image directly verifies the 0.65 float and eight references, plus a bounded allowlist of six selected HP/Armor/MR modifier-name targets. That target set is neither unique nor complete. It does not bind the missing semantic dataflow or exact-build value tables, so derived P0 stat emission remains forbidden.', '',
    '## Exceptions', '',
  ];
  for (const row of result.exception_registry.exceptions) {
    lines.push(`- \`${row.exception_id}\`: ${row.missing_edge}`);
  }
  return `${lines.join('\n')}\n`;
}

function writeProbeArtifacts({ outputDir, ...options } = {}) {
  invariant(outputDir, 'outputDir is required');
  const canonicalOutputDir = canonicalizeProspectiveSafePath(outputDir, 'output directory');
  const result = buildExactBuildMechanicsData(options);
  fs.mkdirSync(canonicalOutputDir, { recursive: true });
  const verifiedOutputDir = canonicalizeExistingSafePath(canonicalOutputDir, 'output directory');
  const files = {
    mechanics: canonicalizeProspectiveSafePath(path.join(verifiedOutputDir,
      'exact_build_mechanics_data.json'), 'mechanics output'),
    exceptions: canonicalizeProspectiveSafePath(path.join(verifiedOutputDir,
      'exception_registry.json'), 'exceptions output'),
    report: canonicalizeProspectiveSafePath(path.join(verifiedOutputDir,
      'exact_build_mechanics_report.md'), 'report output'),
  };
  fs.writeFileSync(files.mechanics, `${JSON.stringify(result.exact_build_mechanics_data, null, 2)}\n`);
  fs.writeFileSync(files.exceptions, `${JSON.stringify(result.exception_registry, null, 2)}\n`);
  fs.writeFileSync(files.report, renderMarkdown(result));
  const artifacts = Object.entries(files).map(([name, file]) => ({
    name, path: path.basename(file), bytes: fs.statSync(file).size, sha256: sha256File(file),
  }));
  const freshTestLog = canonicalizeProspectiveSafePath(path.join(verifiedOutputDir,
    'fresh_test.tap'), 'test evidence output');
  if (fs.existsSync(freshTestLog)) {
    artifacts.push({ name: 'fresh_test', path: path.basename(freshTestLog),
      bytes: fs.statSync(freshTestLog).size, sha256: sha256File(freshTestLog) });
  }
  const manifest = {
    schema: 'ROFL_EXACT_BUILD_MECHANICS_ARTIFACT_MANIFEST_V1',
    exact_build: EXACT_BUILD,
    artifacts,
  };
  files.manifest = canonicalizeProspectiveSafePath(path.join(verifiedOutputDir,
    'artifact_manifest.json'), 'manifest output');
  fs.writeFileSync(files.manifest, `${JSON.stringify(manifest, null, 2)}\n`);
  return { ...result, manifest, paths: files };
}

module.exports = {
  EXACT_BUILD, GROWTH_CONSTANT_RVA, REGISTERED_INPUT_HASHES, RUNTIME_IMAGE_SHA256,
  buildExactBuildMechanicsData, canonicalizeExistingSafePath,
  canonicalizeProspectiveSafePath, defaultInputs, sha256File, writeProbeArtifacts,
};
