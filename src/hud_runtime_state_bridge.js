'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const EXACT_BUILD = '16.16.805.0442';
const EXACT_IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const DISPLAY_PROJECTIONS = Object.freeze(['FLOOR', 'ROUND_NEAREST', 'TRUNCATE_TOWARD_ZERO']);
const HERO_STATS_SOURCE_SHA256 = Object.freeze({
  heroStatsSummary: '23121f155a32d760a11ff6c0192ae76f2c60662e2ef98ce34520c8f7782ba20e',
  heroStatsCrossCheck: '9714032109f97fd12a6340463ecfc76997e6050dcfff1dfcc6531ffc6ba312f7',
  deepHeroStateReport: 'fc13dce5e0c89b9d556074af3c2b7b13138eb855b9c101327dbddd9c4e900eab',
});
const STATIC_ARTIFACT_SHA256 = Object.freeze({
  hudXrefs: '93e15a8edb6e852436008cafe8a8311e057d1dfa57b13a0c14c7c4e69910150d',
  hudDisassembly: '6e615d71ecf05832e849006fa55281074948bea0607917e86b241f446a21b239',
  writerDisassembly: '54145dafc360c9e194fd54fa38578fb213cfe440c6a30d3c65bfea467ba9a253',
  selectorDisassembly: 'd62bf7dabc062792223275b8e3fc44d71f697e360cf4a89895b8204cf20f8e7b',
  boundedUniverse: 'b99b8cb6f6e8ed2ace52e6af3f63ea23d129ce76fc89d5b45873b7aee3fec16e',
  growthXrefs: 'a26b58d765b40d9e502f20ce826d83474bd9e6fb62c11ea0c39452f379635a24',
  numericFormatXrefs: '730bad2ce025084f5a6b97ee1f5f4aeb5e2a96a2925caaf81df024b1f5645a81',
  boundedContexts: 'a451ad188af16f39dd894014d93be39b6321697d2abdbd25ca9efd445372e18d',
  formulaReaderXrefs: 'f52ca7f099a632968fd783fd55a3c71687936e389f761b96b4075f3910a0b202',
  accessorCallSites: '03a4088a660eedf24ae3e6e12472b152dd707565b10d662573a04a4150104d30',
  growthCallSites: 'fa3a4e2498826b061016983e91622f99e4947fd2ca91ae60c4737a138615c0ae',
  itemModifierXrefs: 'df8ad57d777f11ceca2e9693b03b0cf4db1c1b21ef9ad16bdc5299d4b0651058',
  buffConsumer: '4aa24f5a1ab2efc71e40c86fc2fadce86cf2d3487bbea923ba41719e1c562e35',
});
const XREF_ONLY_ARTIFACTS = new Set(['hudXrefs', 'boundedUniverse', 'growthXrefs', 'numericFormatXrefs', 'itemModifierXrefs']);

function assertSafePath(file) {
  if (/holdout/i.test(path.resolve(file))) throw new Error('protected holdout path is forbidden');
}

function readJson(file) {
  assertSafePath(file);
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}

function sha256File(file) {
  assertSafePath(file);
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function displayIntervalHypotheses(displayValue) {
  if (!Number.isInteger(displayValue)) throw new Error('HUD display value must be an integer');
  return [
    { projection: 'FLOOR', lower: displayValue, upper: displayValue + 1, lower_closed: true, upper_closed: false },
    { projection: 'ROUND_NEAREST', lower: displayValue - 0.5, upper: displayValue + 0.5,
      lower_closed: null, upper_closed: null, boundary_rule: 'TIE_BEHAVIOR_UNRESOLVED' },
    { projection: 'TRUNCATE_TOWARD_ZERO', lower: displayValue, upper: displayValue + 1,
      lower_closed: true, upper_closed: false, scope: 'NONNEGATIVE_HERO_STATS' },
  ];
}

function defaultInputs(rootDir) {
  const deep = path.join(rootDir, 'artifacts', 'full_semantic_deep_recovery_v2', 'hero_state');
  const runtime = path.join(rootDir, 'artifacts', 'hero_combat_state_v2', 'runtime');
  const evidence = path.join(rootDir, '.omo', 'evidence', 'quant_runtime_bridge');
  return {
    runtimeImage: path.join(rootDir, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime',
      'league_16.16.805.0442.memory.bin'),
    runtimeTrace: path.join(runtime, 'hero_combat_state_runtime_trace_16_16.json'),
    formulaLatestSummary: path.join(deep, 'packet_042f_latest_four_all_decoded.summary.json'),
    formulaP0Summary: path.join(deep, 'packet_042f_p0_decoded.summary.json'),
    buffAllSummary: path.join(runtime, 'packet_0412_all_decoded_16_16.summary.json'),
    buffP0Summary: path.join(deep, 'packet_0412_p0_decoded.summary.json'),
    heroStatsSummary: path.join(rootDir, 'artifacts', 'hero_combat_state_v2', 'emulation',
      'packet_010c_all_latest_four_decoded.jsonl.summary.json'),
    heroStatsCrossCheck: path.join(rootDir, 'artifacts', 'hero_combat_state_v2', 'profiler',
      'packet_010c_hero_stats_cross_check.json'),
    deepHeroStateReport: path.join(deep, 'hero_state_damage_defense_deep_report_16_16.json'),
    hudXrefs: path.join(evidence, 'hud_string_semantic_xrefs.json'),
    hudDisassembly: path.join(evidence, 'hud_and_state_consumer_disassembly.json'),
    writerDisassembly: path.join(evidence, 'state_writer_disassembly_and_xrefs.json'),
    selectorDisassembly: path.join(evidence, 'stat_formula_selector_writer_slice.json'),
    boundedUniverse: path.join(evidence, 'hud_runtime_bounded_static_universe.json'),
    growthXrefs: path.join(evidence, 'growth_constant_xrefs.json'),
    numericFormatXrefs: path.join(evidence, 'hud_numeric_format_all_xrefs.json'),
    boundedContexts: path.join(evidence, 'hud_runtime_bounded_static_contexts.json'),
    formulaReaderXrefs: path.join(evidence, 'stat_formula_reader_xrefs_v2.json'),
    accessorCallSites: path.join(evidence, 'stat_formula_storage_accessor_call_sites_v2.json'),
    growthCallSites: path.join(evidence, 'growth_constant_call_sites.json'),
    itemModifierXrefs: path.join(evidence, 'item_stat_modifier_xrefs.json'),
    buffConsumer: path.join(deep, 'runtime_0412_adjustment_consumer_disassembly.json'),
  };
}

function requireBuildEvidence(doc, label) {
  const build = doc.build || doc.runtime_profile;
  if (build !== EXACT_BUILD) throw new Error(`${label} build mismatch: ${build}`);
  const imageSha = doc.image_sha256 || (doc.image && doc.image.sha256);
  if (imageSha !== EXACT_IMAGE_SHA256) throw new Error(`${label} image mismatch: ${imageSha}`);
}

function flattenInstructions(document) {
  return (document.disassembly || []).flatMap((slice) => slice.instructions || []);
}

function verifyStaticArtifact(document, runtimeImage, label, artifactFile, suppliedImageBuffer) {
  if (document.schema_version !== 1) throw new Error(`${label} schema mismatch`);
  if (!document.image_path || path.resolve(document.image_path) !== path.resolve(runtimeImage)) {
    throw new Error(`${label} is not bound to the exact runtime image path`);
  }
  const expectedArtifactSha = STATIC_ARTIFACT_SHA256[label];
  if (!expectedArtifactSha || !artifactFile) throw new Error(`${label} has no pinned static artifact identity`);
  const actualArtifactSha = sha256File(artifactFile);
  if (actualArtifactSha !== expectedArtifactSha) {
    throw new Error(`${label} static artifact hash mismatch: ${actualArtifactSha}`);
  }
  if (document.image_base !== 0x140000000) throw new Error(`${label} image base mismatch`);
  const image = suppliedImageBuffer || fs.readFileSync(runtimeImage);
  let verifiedInstructionCount = 0;
  for (const instruction of flattenInstructions(document)) {
    if (!Number.isInteger(instruction.rva) || typeof instruction.bytes !== 'string' ||
        !/^[0-9a-f]+$/i.test(instruction.bytes) || instruction.bytes.length % 2 !== 0) {
      throw new Error(`${label} malformed instruction evidence`);
    }
    const byteCount = instruction.bytes.length / 2;
    if (instruction.rva < 0 || instruction.rva + byteCount > image.length) {
      throw new Error(`${label} instruction RVA is outside runtime image`);
    }
    const actualBytes = image.subarray(instruction.rva, instruction.rva + byteCount).toString('hex');
    if (actualBytes !== instruction.bytes.toLowerCase()) {
      throw new Error(`${label} instruction bytes mismatch at RVA 0x${instruction.rva.toString(16)}`);
    }
    verifiedInstructionCount += 1;
  }
  if (!XREF_ONLY_ARTIFACTS.has(label) && verifiedInstructionCount === 0) throw new Error(`${label} has no byte-bound instructions`);
  return { artifact_sha256: actualArtifactSha, byte_bound_instruction_count: verifiedInstructionCount,
    rva_mapping: 'MEMORY_IMAGE_FILE_OFFSET_EQUALS_RVA' };
}

function verifyCallback(disassembly) {
  const instructions = flattenInstructions(disassembly);
  const at = (rva) => instructions.find((instruction) => instruction.rva === rva);
  const add = at(0x002a5c04);
  const call = at(0x002a5c0b);
  if (!add || add.mnemonic !== 'add' || add.operands !== 'rcx, 0x49b8') {
    throw new Error('0x042f callback owner offset not verified');
  }
  if (!call || call.mnemonic !== 'call' || call.operands !== '0x140999e40') {
    throw new Error('0x042f callback writer call not verified');
  }
  return { owner_add_rva: '0x002a5c04', owner_storage_offset_hex: '0x49b8', writer_call_rva: '0x002a5c0b' };
}

function verifyFormulaWriter(disassembly, selectorDisassembly) {
  const instructions = flattenInstructions(disassembly);
  const at = (rva) => instructions.find((instruction) => instruction.rva === rva);
  const vector = at(0x00999e49);
  const count = at(0x00999e50);
  const stride = at(0x00999e53);
  const selector = at(0x00999e70);
  const laneCount = at(0x00999e74);
  const laneRead = at(0x00999ea1);
  const helperCall = at(0x00999ea6);
  const laneAdvance = at(0x00999eab);
  const write = at(0x00999eb2);
  const laneDecrement = at(0x00999eb8);
  const laneLoop = at(0x00999ebc);
  const recordAdvance = at(0x00999ebe);
  const recordLoop = at(0x00999ec5);
  if (!vector || !/\[rdx \+ 0x18\]/.test(vector.operands)) throw new Error('0x042f writer vector read not verified');
  if (!count || !/\[rdx \+ 0x20\]/.test(count.operands)) throw new Error('0x042f writer count read not verified');
  if (!stride || stride.mnemonic !== 'shl' || stride.operands !== 'rbp, 5') throw new Error('0x042f record stride not verified');
  if (!selector || !/\[rbx \+ 8\]/.test(selector.operands)) throw new Error('0x042f selector read not verified');
  if (!laneCount || laneCount.mnemonic !== 'mov' || laneCount.operands !== 'esi, 4') throw new Error('0x042f lane count not verified');
  if (!laneRead || laneRead.mnemonic !== 'movss' || laneRead.operands !== 'xmm6, dword ptr [rdi + rax]') {
    throw new Error('0x042f lane read not verified');
  }
  if (!helperCall || helperCall.mnemonic !== 'call' || helperCall.operands !== '0x140982690') {
    throw new Error('0x042f selector helper call not verified');
  }
  if (!laneAdvance || laneAdvance.mnemonic !== 'lea' || laneAdvance.operands !== 'rdi, [rdi + 4]') {
    throw new Error('0x042f pre-store lane advance not verified');
  }
  if (!write || write.mnemonic !== 'movss' || !/\+ 0x10\]/.test(write.operands)) {
    throw new Error('0x042f persistent float lane write not verified');
  }
  if (!laneDecrement || laneDecrement.operands !== 'rsi, 1' || !laneLoop || laneLoop.operands !== '0x140999e90') {
    throw new Error('0x042f four-lane loop not verified');
  }
  if (!recordAdvance || recordAdvance.operands !== 'rbx, 0x20' || !recordLoop || recordLoop.operands !== '0x140999e70') {
    throw new Error('0x042f record loop not verified');
  }
  const helperXrefs = selectorDisassembly && selectorDisassembly.direct_xrefs && selectorDisassembly.direct_xrefs['9971344'];
  if (!Array.isArray(helperXrefs) || helperXrefs.length !== 1 || helperXrefs[0].source_rva !== 0x00999ea6 || helperXrefs[0].kind !== 'call') {
    throw new Error('0x042f selector helper xref not verified');
  }
  return {
    packet_vector_read_rva: '0x00999e49', packet_count_read_rva: '0x00999e50',
    selector_read_rva: '0x00999e70', float_lane_write_rva: '0x00999eb2',
    store_expression_displacement_hex: '0x10', pre_store_lane_advance_bytes: 4,
    destination_lane_offsets_hex: ['0x14', '0x18', '0x1c', '0x20'], record_stride_bytes: 32, lane_count: 4,
  };
}

function directXrefCount(document, targetRva) {
  const rows = document.direct_xrefs && document.direct_xrefs[String(targetRva)];
  return Array.isArray(rows) ? rows.length : 0;
}

function semanticXrefCount(document, targetRva) {
  const rows = document.semantic_xrefs && document.semantic_xrefs[String(targetRva)];
  return Array.isArray(rows) ? rows.length : 0;
}

function instructionAt(document, rva) {
  return flattenInstructions(document).find((instruction) => instruction.rva === rva);
}

function verifyFormulaReader(contexts, readerXrefs, accessorCallSites, runtimeImageBytes) {
  const requireInstruction = (document, rva, mnemonic, operands, label) => {
    const instruction = instructionAt(document, rva);
    if (!instruction || instruction.mnemonic !== mnemonic || instruction.operands !== operands) {
      throw new Error(`formula reader ${label} not verified`);
    }
  };
  requireInstruction(contexts, 0x0028b634, 'mov', 'rcx, qword ptr [rcx + 8]', 'owner unwrap');
  requireInstruction(contexts, 0x0028b63d, 'add', 'rcx, 0x49b8', 'storage offset');
  requireInstruction(contexts, 0x0028b64c, 'call', '0x140995c40', 'lookup call');
  requireInstruction(contexts, 0x0028b651, 'movss', 'xmm0, dword ptr [rsp + 0x30]', 'float return');
  requireInstruction(contexts, 0x0028b670, 'lea', 'rax, [rcx + 0x49b8]', 'storage accessor');
  requireInstruction(readerXrefs, 0x00995c45, 'movzx', 'eax, dl', 'selector argument');
  requireInstruction(readerXrefs, 0x00995c48, 'mov', 'r11, r9', 'output argument');
  requireInstruction(readerXrefs, 0x00995c5c, 'movzx', 'ebx, r8b', 'lane argument');
  requireInstruction(readerXrefs, 0x00995cb6, 'mov', 'ecx, dword ptr [rdx + rbx*4 + 0x14]', 'lane load');
  requireInstruction(readerXrefs, 0x00995cc1, 'mov', 'dword ptr [r11], ecx', 'output write');
  requireInstruction(accessorCallSites, 0x00b36bac, 'call', '0x14028b670', 'ManaRegen accessor call');
  requireInstruction(accessorCallSites, 0x00b36bb6, 'xor', 'r8d, r8d', 'ManaRegen lane zero');
  requireInstruction(accessorCallSites, 0x00b36bb9, 'mov', 'dl, 0xb', 'ManaRegen selector');
  requireInstruction(accessorCallSites, 0x00b36bbe, 'call', '0x140995c40', 'ManaRegen lookup');
  requireInstruction(accessorCallSites, 0x00b36c22, 'cvtps2pd', 'xmm2, xmm7', 'ManaRegen formatter conversion');
  requireInstruction(accessorCallSites, 0x00b36c5d, 'call', '0x1411aaaa0', 'ManaRegen formatter call');
  if (runtimeImageBytes.subarray(0x01ace414, 0x01ace419).toString('ascii') !== '%0.f\0' ||
      runtimeImageBytes.subarray(0x01ace420, 0x01ace42c).toString('ascii') !== '@ManaRegen@\0') {
    throw new Error('ManaRegen formatter strings not verified');
  }
  const wrapperDirectCallers = directXrefCount(readerXrefs, 0x0028b630);
  const accessorDirectCallers = directXrefCount(readerXrefs, 0x0028b670);
  const lookupDirectCallers = directXrefCount(readerXrefs, 0x00995c40);
  if (wrapperDirectCallers !== 0 || accessorDirectCallers !== 4 || lookupDirectCallers !== 9) {
    throw new Error('formula reader bounded caller universe mismatch');
  }
  return {
    status: 'VERIFIED_DIRECT_GENERIC_SELECTOR_LANE_READER', wrapper_rva: '0x0028b630',
    storage_accessor_rva: '0x0028b670', lookup_rva: '0x00995c40', owner_storage_offset_hex: '0x49b8',
    selector_argument: 'DL_U8', lane_argument: 'R8B_U8', output_argument: 'R9_FLOAT32_POINTER',
    lane_load_expression: 'node+0x14+(lane*4)', destination_lane_offsets_hex: ['0x14', '0x18', '0x1c', '0x20'],
    wrapper_direct_caller_count: wrapperDirectCallers, storage_accessor_direct_caller_count: accessorDirectCallers,
    lookup_direct_caller_count: lookupDirectCallers,
    verified_static_consumer_mappings: [{ semantic: 'MANA_REGEN', selector: 11, lane: 0,
      localization_token: '@ManaRegen@', numeric_format: '%0.f', formatter_call_rva: '0x00b36c5d',
      status: 'VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING',
      replay_route_availability: 'NOT_OBSERVED_IN_0x042f_CORPUS_SELECTOR_194_ONLY' }],
    hud_consumer_link: 'NOT_FOUND_IN_BOUNDED_STATIC_UNIVERSE',
  };
}

function verifyHeroStatsNegativeEvidence(summary, crossCheck, deepReport) {
  requireBuildEvidence(summary, 'heroStatsSummary');
  if (eventCount(summary) !== 1370 || summary.stream_counts.keyframe !== 1370 || Object.keys(summary.stream_counts).length !== 1) {
    throw new Error('0x010c latest-four keyframe-only/full-consume behavior mismatch');
  }
  if (crossCheck.exact_build !== EXACT_BUILD || crossCheck.packet_discriminator !== '0x010c' ||
      crossCheck.decoded_source_row_count !== 800 || crossCheck.decoded_source_full_consume_count !== 800 ||
      crossCheck.known_route_semantics !== 'HERO_CUMULATIVE_SCOREBOARD_STATS' || crossCheck.route_role !== 'NEGATIVE_CONTROL') {
    throw new Error('0x010c independent behavior cross-check mismatch');
  }
  const route = deepReport.routes && deepReport.routes['0x010c_hero_stats_negative_control'];
  if (deepReport.exact_build !== EXACT_BUILD || !route || route.classification !== 'CUMULATIVE_SCOREBOARD_SNAPSHOT_NEGATIVE_CONTROL' ||
      route.direct_live_hp_defense_resource_carrier !== false || route.latest_four_full_corpus.event_count !== 1370 ||
      route.latest_four_full_corpus.exact_success_full_consume_count !== 1370 || route.latest_four_full_corpus.stream_counts.keyframe !== 1370) {
    throw new Error('0x010c deep-report negative-control behavior mismatch');
  }
  return { latest_four_full_consume_count: 1370, independent_cross_check_full_consume_count: 800,
    stream_scope: 'KEYFRAME_ONLY', classification: route.classification };
}

function target(trace, name) {
  const match = trace.target_chains.find((row) => row.target_name === name);
  if (!match) throw new Error(`missing runtime target chain: ${name}`);
  return match;
}

function eventCount(summary) {
  if (!Number.isInteger(summary.event_count)) throw new Error('summary event_count missing');
  if (summary.event_count !== summary.successful_full_consume_count) throw new Error('summary is not exact full-consume');
  return summary.event_count;
}

function derivedSemantic(semantic, missing) {
  return {
    semantic,
    direct: { status: 'EVIDENCE_EXHAUSTED', reason: 'No selector/lane was identified by controlled steps or static consumer linkage.' },
    derived: { status: 'PARTIAL', value: 'UNKNOWN', missing_inputs: missing },
    publication: 'NO_PUBLIC_PROMOTION',
  };
}

function renderMarkdown(report) {
  const semanticLines = report.p0_semantics.map((row) =>
    `| ${row.semantic} | ${row.direct.status} | ${row.derived.status} | ${row.derived.missing_inputs.join('; ')} |`).join('\n');
  return `# HUD Runtime State Bridge — ${report.exact_build}\n\n` +
    `Status: **${report.status}**. Dynamic process access: **${report.runtime_dynamic_access.status}**.\n\n` +
    `## Static backward trace\n\n` +
    `${report.hud_runtime_state_access_map.edges.map((edge) => `- ${edge.from} → ${edge.to}: ${edge.status}`).join('\n')}\n\n` +
    `The exact-build 0x042f callback reaches writer ${report.stat_formula_outputs.writer.function_rva}, which reads 32-byte records, resolves the selector at +8, and writes four float32 lanes to persistent formula-output storage. Generic reader 0x0028b630/0x00995c40 performs the inverse selector/lane lookup. One caller maps selector 11/lane 0 to @ManaRegen@ and %0.f; no P0 selector maps to that consumer.\n\n` +
    `## HUD projection\n\nThe complete declared executable literal/xref/caller universe did not link a P0 formatter implementation to the formula reader. FLOOR, ROUND_NEAREST, and TRUNCATE_TOWARD_ZERO remain a non-exhaustive P0 hypothesis set; HUD integers are not treated as exact internal values.\n\n` +
    `## Local static exhaustion\n\n${report.local_static_exhaustion_boundary.negative_results.map((row) => `- ${row}`).join('\n')}\n\n` +
    `## P0 closure\n\n| Semantic | Direct | Derived | Missing deterministic inputs |\n|---|---|---|---|\n${semanticLines}\n\n` +
    `## Boundaries\n\nNo game process was started or attached, and no injection, hooking, Vanguard modification, map truth, behavior inference, or protected holdout input was used.\n`;
}

function writeManifest(outputDir, files) {
  const artifacts = files.map((file) => ({
    path: path.relative(outputDir, file).replace(/\\/g, '/'), bytes: fs.statSync(file).size, sha256: sha256File(file),
  }));
  const manifest = { schema: 'HUD_RUNTIME_STATE_BRIDGE_ARTIFACT_MANIFEST_V1', exact_build: EXACT_BUILD, artifacts };
  const file = path.join(outputDir, 'artifact_manifest.json');
  fs.writeFileSync(file, `${JSON.stringify(manifest, null, 2)}\n`);
  return file;
}

function runHudRuntimeStateBridge({ rootDir = path.resolve(__dirname, '..'), outputDir, inputs = defaultInputs(rootDir) } = {}) {
  outputDir ||= path.join(rootDir, '.omo', 'evidence', 'quant_runtime_bridge');
  assertSafePath(outputDir);
  fs.mkdirSync(outputDir, { recursive: true });
  const imageSha = sha256File(inputs.runtimeImage);
  if (imageSha !== EXACT_IMAGE_SHA256) throw new Error(`runtime image mismatch: ${imageSha}`);

  const trace = readJson(inputs.runtimeTrace);
  const formulaLatest = readJson(inputs.formulaLatestSummary);
  const formulaP0 = readJson(inputs.formulaP0Summary);
  const buffAll = readJson(inputs.buffAllSummary);
  const buffP0 = readJson(inputs.buffP0Summary);
  const heroStatsSummary = readJson(inputs.heroStatsSummary);
  const heroStatsCrossCheck = readJson(inputs.heroStatsCrossCheck);
  const deepHeroStateReport = readJson(inputs.deepHeroStateReport);
  for (const [name, expected] of Object.entries(HERO_STATS_SOURCE_SHA256)) {
    const actual = sha256File(inputs[name]);
    if (actual !== expected) throw new Error(`0x010c source hash mismatch for ${name}: ${actual}`);
  }
  for (const [label, doc] of Object.entries({ trace, formulaLatest, formulaP0, buffAll, buffP0 })) requireBuildEvidence(doc, label);

  const hudXrefs = readJson(inputs.hudXrefs);
  const hudDisassembly = readJson(inputs.hudDisassembly);
  const writerDisassembly = readJson(inputs.writerDisassembly);
  const selectorDisassembly = readJson(inputs.selectorDisassembly);
  const boundedUniverse = readJson(inputs.boundedUniverse);
  const growthXrefs = readJson(inputs.growthXrefs);
  const numericFormatXrefs = readJson(inputs.numericFormatXrefs);
  const boundedContexts = readJson(inputs.boundedContexts);
  const formulaReaderXrefs = readJson(inputs.formulaReaderXrefs);
  const accessorCallSites = readJson(inputs.accessorCallSites);
  const growthCallSites = readJson(inputs.growthCallSites);
  const itemModifierXrefs = readJson(inputs.itemModifierXrefs);
  const buffConsumer = readJson(inputs.buffConsumer);
  const runtimeImageBytes = fs.readFileSync(inputs.runtimeImage);
  const staticArtifactBindings = {};
  const staticDocuments = { hudXrefs, hudDisassembly, writerDisassembly, selectorDisassembly, boundedUniverse,
    growthXrefs, numericFormatXrefs, boundedContexts, formulaReaderXrefs, accessorCallSites, growthCallSites,
    itemModifierXrefs, buffConsumer };
  for (const [label, doc] of Object.entries(staticDocuments)) {
    staticArtifactBindings[label] = verifyStaticArtifact(doc, inputs.runtimeImage, label, inputs[label], runtimeImageBytes);
  }
  const callback = verifyCallback(hudDisassembly);
  const writer = verifyFormulaWriter(writerDisassembly, selectorDisassembly);
  const formulaReader = verifyFormulaReader(boundedContexts, formulaReaderXrefs, accessorCallSites, runtimeImageBytes);
  const heroStatsBehavior = verifyHeroStatsNegativeEvidence(heroStatsSummary, heroStatsCrossCheck, deepHeroStateReport);
  const formula = target(trace, 'PKT_S2C_StatFormulaOutputs_s');
  const heroStats = target(trace, 'PKT_S2C_HeroStats_s');
  const buff = target(trace, 'PKT_NPC_BuffUpdateStatAdjustments_s');
  const formulaCount = eventCount(formulaLatest) + eventCount(formulaP0);
  const buffCount = eventCount(buffAll) + eventCount(buffP0);
  const xrefCounts = Object.fromEntries(Object.entries(hudXrefs.semantic_xrefs || {}).map(([key, rows]) => [key, rows.length]));
  const boundedDirectCounts = Object.fromEntries(Object.entries(boundedUniverse.direct_xrefs || {})
    .map(([key, rows]) => [`0x${Number(key).toString(16)}`, rows.length]));
  const boundedImmediateCounts = Object.fromEntries([0x49b8, 194, 0x32, 0x33].map((value) => [String(value),
    boundedUniverse.immediate_references.filter((row) => row.value === value).length]));
  const numericFormatDirectXrefCount = Object.values(numericFormatXrefs.semantic_xrefs).reduce((sum, rows) => sum + rows.length, 0);
  const growthConstantXrefCount = semanticXrefCount(growthXrefs, 0x01a510c8);
  const itemModifierXrefCount = Object.values(itemModifierXrefs.semantic_xrefs).reduce((sum, rows) => sum + rows.length, 0);
  const healthLayerXrefs = Object.fromEntries([
    ['IncomingDamage', 0x01b1a0b8], ['IncomingHealingAllied', 0x01b1a0c8],
    ['PhysicalShield', 0x01b1a0e0], ['MagicalShield', 0x01b1a108],
  ].map(([name, rva]) => [name, semanticXrefCount(boundedUniverse, rva)]));
  const baseGrowthXrefs = Object.fromEntries([
    ['BaseArmor', 0x01a4c720], ['ArmorPerLevel', 0x01a4c730], ['MagicResist', 0x01a4c740],
    ['MagicResistPerLevel', 0x01a4c750], ['BaseHP', 0x01a4c7b4], ['HPPerLevel', 0x01a4c7c0],
  ].map(([name, rva]) => [name, semanticXrefCount(boundedUniverse, rva)]));

  const commonMissing = ['exact-build champion base/growth table with source hash',
    'exact-build item stat table with source hash', '0x0412 stat selector/operation/flat-percent identities'];
  const report = {
    schema: 'HUD_RUNTIME_STATE_BRIDGE_AUDIT_V1', exact_build: EXACT_BUILD,
    exact_runtime_image_sha256: imageSha, status: 'EVIDENCE_EXHAUSTED', architecture_gate: 'PASS',
    parser_boundary: 'REPLAY_PROTOCOL_SEMANTICS_ONLY',
    runtime_dynamic_access: {
      status: 'RUNTIME_DYNAMIC_ACCESS_BLOCKED', process_started: false, process_attached: false,
      injection_or_hooking: false, vanguard_modified_or_bypassed: false,
      reason: 'Static exact-image analysis was sufficient and the governed safe boundary forbids invasive runtime acquisition.',
    },
    hud_display_function: {
      status: 'LOCAL_STATIC_BOUNDED_SEARCH_EXHAUSTED_NO_FORMATTER_LINK', promoted_function: null,
      searched_consumers: ['Armor', 'Magic Resistance', 'Health & Regeneration', 'GetUnitCurrentHealthPercentage',
        'CurrentHealth', 'IncomingDamage', 'IncomingHealingAllied', 'PhysicalShield', 'MagicalShield',
        'FLOATTEXT_Armor', 'FLOATTEXT_MagicResist', 'BaseArmor', 'ArmorPerLevel', 'MagicResist',
        'MagicResistPerLevel', 'BaseHP', 'HPPerLevel', '%.1f', '%.0f'],
      semantic_xref_counts_by_string_rva_decimal: xrefCounts,
      result: 'Full executable xref enumeration resolves metadata/category, reflection layout, character-record balance fields, or float-text registration surfaces. ManaRegen selector 11/lane 0 joins the generic reader to %0.f; no MAX_HP/ARMOR/MAGIC_RESIST/CURRENT_HP path does.',
      non_p0_verified_formatter: { semantic: 'MANA_REGEN', selector: 11, lane: 0, format: '%0.f',
        localization_token: '@ManaRegen@', status: 'VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING',
        projection_note: 'Zero-decimal formatting is verified; half-tie/rounding-mode behavior is not inferred for P0 stats.' },
      hypothesis_set_scope: 'NON_EXHAUSTIVE', hypotheses_for_display_41: displayIntervalHypotheses(41),
    },
    hud_runtime_state_access_map: {
      status: 'PARTIAL',
      edges: [
        { from: 'HUD/stat labels', to: 'metadata and FLOATTEXT registrations', status: 'VERIFIED_DIRECT_STATIC' },
        { from: 'metadata/FLOATTEXT registrations', to: 'scalar getter and formatter', status: 'UNRESOLVED' },
        { from: '0x042f deserializer', to: 'StatFormulaOutputs callback 0x002a5c00', status: 'VERIFIED_DIRECT_STATIC' },
        { from: 'callback + AIBaseClient+0x49b8', to: 'writer 0x00999e40', status: 'VERIFIED_DIRECT_STATIC' },
        { from: 'writer selector helper 0x00982690', to: 'persistent four-lane formula output', status: 'VERIFIED_DIRECT_STATIC' },
        { from: 'persistent formula output +0x49b8', to: 'generic selector/lane reader 0x0028b630 → 0x00995c40', status: 'VERIFIED_DIRECT_STATIC' },
        { from: 'storage accessor 0x0028b670 + selector 11/lane 0', to: '@ManaRegen@ + %0.f formatter', status: 'VERIFIED_DIRECT_STATIC' },
        { from: 'generic selector/lane reader', to: 'P0 HUD numeric formatter/stat labels', status: 'LOCAL_STATIC_BOUNDED_SEARCH_EXHAUSTED_NO_LINK' },
        { from: 'persistent formula output selector/lane', to: 'MAX_HP/ARMOR/MAGIC_RESIST/CURRENT_HP', status: 'UNRESOLVED' },
      ],
    },
    stat_formula_outputs: {
      status: 'VERIFIED_DIRECT_STRUCTURE_AND_WRITER_RELATION', route: '0x042f', owner: 'AIBaseClient',
      callback_rva: '0x002a5c00', owner_storage_offset_hex: '0x49b8', callback_proof: callback,
      constructor_rva: '0x00ea12c0', deserializer_rva: '0x00f1b8d0', exact_full_consume_count: formulaCount,
      writer: { function_rva: '0x00999e40', selector_helper_rva: '0x00982690', ...writer },
      reader: formulaReader,
      selector_identity: 'UNMAPPED', lane_identity: 'UNMAPPED',
      p0_conclusion: 'Shared final/intermediate formula output storage exists, but no controlled P0 final stat, base stat, or modifier identity is established.',
    },
    hero_stats_010c: {
      status: 'NEGATIVE_CONTROL_REJECTED_AS_LIVE_HERO_STATE', route: '0x010c', owner: 'AIHeroClient',
      callback_rva: '0x003304c0', owner_storage_offset_hex: '0x5360',
      reason: 'Decoded behavior is latest-four keyframe scoreboard/tail statistics, not live HP/defense/resource.',
      static_chain_status: heroStats.status, behavior_proof: heroStatsBehavior,
    },
    buff_stat_modifiers: {
      status: 'PARTIAL', route: '0x0412', owner: 'BuffManagerClient', exact_full_consume_count: buffCount,
      static_chain_status: buff.status, record_stride_bytes: 28, encoded_dword_offsets: [8, 12, 16, 20, 24],
      known: 'Transient BuffUpdateStatAdjustments records are directly decoded.',
      missing: ['stat index/name', 'flat modifier', 'percent modifier', 'operation/add-remove', 'persistent target formula-output relation'],
      promotion: 'NO_PUBLIC_STAT_MODIFIER_PROMOTION',
    },
    derived_inputs: {
      inventory_state: { status: 'VERIFIED_DIRECT', capability: 'ITEM_STATE', scope: 'state_at(t), cause-agnostic',
        usable: 'item identifiers, stack and slot', missing: 'exact-build item-to-stat contribution data' },
      level: { status: 'VERIFIED_DERIVED_PROTOCOL', capability: 'LEVEL_TRANSITION', usable: 'exact level at governed transitions',
        missing: 'exact-build nonlinear stat-growth data' },
      champion_base_and_growth: { status: 'UNAVAILABLE', missing: 'pinned exact-build source/version/hash and champion row binding' },
      item_stat_contribution: { status: 'CONDITIONALLY_DERIVED', missing: 'pinned exact-build item mechanics table/source/hash' },
      buff_modifiers: { status: 'PARTIAL', missing: 'selector, operation, flat/percent semantics and formula dependency' },
    },
    p0_semantics: [
      derivedSemantic('MAX_HP', commonMissing), derivedSemantic('ARMOR', commonMissing),
      derivedSemantic('MAGIC_RESIST', commonMissing),
      derivedSemantic('CURRENT_HP', ['direct health anchor or verified HP delta integrator', 'verified shield/temporary-health layer ordering']),
    ],
    other_hero_stats: {
      status: 'CANDIDATE', shared_container: '0x042f StatFormulaOutputs',
      possible_surface: ['HP', 'resource', 'AD', 'AP', 'AS', 'MS', 'regen', 'crit', 'haste', 'penetration'],
      promoted: [{ semantic: 'MANA_REGEN', evidence: 'VERIFIED_DIRECT_STATIC_CONSUMER_MAPPING', selector: 11, lane: 0,
        parser_availability: 'UNAVAILABLE_IN_OBSERVED_0x042f_SELECTOR_194_CORPUS' }],
      reason: 'ManaRegen has direct static consumer linkage; remaining selector/lane identities lack consumer linkage, controls, and counterexample validation.',
    },
    static_growth_formula_check: {
      status: 'LOCAL_STATIC_ROUTE_EXHAUSTED_NOT_BOUND_TO_STAT_GROWTH', constant: 0.65,
      constant_rva: '0x01a510c8', code_xref_count: growthConstantXrefCount,
      base_growth_metadata_xref_counts: baseGrowthXrefs,
      reason: 'All eight constant xrefs and all direct Base*/PerLevel metadata xrefs were sliced. None jointly references level plus a governed base-stat row, 0x042f selector/lane, or replay writer. The constant occurs in unrelated generic float paths and cannot identify the game stat-growth formula.',
    },
    local_static_exhaustion_boundary: {
      status: 'LOCAL_STATIC_BOUNDED_ROUTES_EXHAUSTED', exact_image_sha256: imageSha,
      executable_universe: boundedUniverse.executable_ranges,
      search_definition: {
        direct_call_targets: ['0x00982690 selector helper', '0x00999e40 writer', '0x00379f30/0x0037a190 FLOATTEXT registries',
          '0x0028b630 generic reader wrapper', '0x0028b670 storage accessor', '0x00995c40 selector/lane lookup'],
        direct_call_xref_counts: { ...boundedDirectCounts, reader_wrapper_0x28b630: formulaReader.wrapper_direct_caller_count,
          storage_accessor_0x28b670: formulaReader.storage_accessor_direct_caller_count,
          selector_lane_lookup_0x995c40: formulaReader.lookup_direct_caller_count },
        immediate_values_and_counts: boundedImmediateCounts,
        semantic_string_groups: {
          hud_and_floattext: ['Armor', 'Magic Resistance', 'Health & Regeneration', 'FLOATTEXT_Armor',
            'FLOATTEXT_MagicResist', 'GetUnitCurrentHealthPercentage'],
          runtime_health_layers: healthLayerXrefs,
          base_and_growth: baseGrowthXrefs,
          item_modifiers: ['FlatHPPoolMod', 'PercentHPPoolMod', 'FlatArmorMod', 'PercentArmorMod',
            'FlatSpellBlockMod', 'PercentSpellBlockMod'],
          numeric_formats: { occurrence_count: 16, executable_direct_xref_count: numericFormatDirectXrefCount },
        },
        byte_validation: 'Every disassembled instruction is compared with exact runtime image bytes at its RVA; xref-only artifacts have pinned SHA-256.',
      },
      recovered_local_structure: {
        formula_reader: formulaReader.status,
        selector_lane_lookup: 'selector=DL byte; lane=R8B byte; float32 output through R9; node lane offsets +0x14..+0x20',
        verified_consumer_mapping: formulaReader.verified_static_consumer_mappings[0],
      },
      negative_results: [
        'Selector helper has one direct caller, the 0x042f writer; writer has one direct caller, the packet callback.',
        'Generic reader wrapper has zero direct call xrefs; storage accessor has four direct callers and selector/lane lookup has nine. The only literal semantic binding recovered is selector 11/lane 0 → @ManaRegen@ with %0.f.',
        'No P0 HUD/FLOATTEXT/base-stat/numeric-format xref converges on selector/lane calls for MAX_HP, ARMOR, MAGIC_RESIST, or CURRENT_HP.',
        'CurrentHealth has no direct executable string xref; the four health/shield layer names each have seven xrefs in repeated reflection-layout registration patterns, not scalar reads.',
        'All 16 exact %.1f/%.0f string occurrences were searched; 13 executable direct xrefs exist, with no shared function or dataflow to the formula reader or P0 stat labels.',
        'All six HP/Armor/MR flat/percent modifier names have two xrefs each (12 total) in one registry-initialization cluster; they provide names, not exact item values or item-ID bindings.',
        '0x0412 callback/consumer and 714 decoded records expose structure only; no stat selector, operation, flat/percent interpretation, or 0x042f dependency is statically bound.',
      ],
      derived_local_routes: {
        champion_base_growth: { status: 'LOCAL_STATIC_EXHAUSTED_PARTIAL_METADATA_ONLY', xref_counts: baseGrowthXrefs,
          missing_external_truth: 'authoritative exact-build champion row/formula/version binding' },
        item_contributions: { status: 'LOCAL_STATIC_EXHAUSTED_NAMES_ONLY', modifier_name_xref_count: itemModifierXrefCount,
          missing_external_truth: 'authoritative exact-build item ID→stat contribution table and hash' },
        buff_adjustments: { status: 'LOCAL_STATIC_EXHAUSTED_STRUCTURE_ONLY', decoded_record_count: buffCount,
          missing_external_truth: 'independently labeled buff selector/operation/flat-percent truth or exact-build authoritative mapping' },
      },
      remaining_bounded_local_routes: [],
      scope_note: 'This exhausts the declared literal/xref/caller/byte-slice universe; it does not claim mathematical whole-program equivalence or authorize dynamic attachment.',
    },
    route_reaudit: {
      '0x042f': 'FORMULA_OUTPUT_CONTAINER_AND_WRITER_VERIFIED; P0_SELECTOR_UNMAPPED',
      '0x010c': 'SCOREBOARD_NEGATIVE_CONTROL; NOT_LIVE_HERO_STATE',
      '0x0412': 'BUFF_ADJUSTMENT_STRUCTURE_VERIFIED; MODIFIER_SEMANTICS_UNMAPPED',
      '0x01dc': 'REPLICATION_DISPATCH_EXISTS; DECODED_VALUE_VECTORS_EMPTY_AND_NO_P0_IDENTITY',
      ItemState: 'DIRECT_INVENTORY_STATE_AVAILABLE; EXACT_BUILD_STAT_TABLE_MISSING',
      Level: 'DERIVED_PROTOCOL_INPUT_AVAILABLE; EXACT_BUILD_GROWTH_TABLE_MISSING',
    },
    public_capability_changes: [],
    protected_holdout: { enumerated: false, read: false, hashed: false, decoded: false, tested: false, consumed: false },
    source_artifacts: Object.entries(inputs).map(([name, file]) => ({ name, path: path.relative(rootDir, file).replace(/\\/g, '/'), sha256: sha256File(file) })),
    static_chain_attestations: { formula: formula.status, hero_stats: heroStats.status, buff: buff.status,
      static_artifact_bindings: staticArtifactBindings,
      hud_disassembly_loaded: hudDisassembly.schema_version === 1, selector_disassembly_loaded: selectorDisassembly.schema_version === 1 },
  };

  const jsonPath = path.join(outputDir, 'hud_runtime_state_bridge_report.json');
  const markdownPath = path.join(outputDir, 'HUD_RUNTIME_STATE_ACCESS_MAP.md');
  fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync(markdownPath, renderMarkdown(report));
  const manifestPath = writeManifest(outputDir, [jsonPath, markdownPath]);
  return { report, paths: { jsonPath, markdownPath, manifestPath } };
}

module.exports = {
  DISPLAY_PROJECTIONS, EXACT_BUILD, EXACT_IMAGE_SHA256, defaultInputs, displayIntervalHypotheses,
  runHudRuntimeStateBridge, verifyCallback, verifyFormulaReader, verifyFormulaWriter,
  verifyHeroStatsNegativeEvidence, verifyStaticArtifact,
};
