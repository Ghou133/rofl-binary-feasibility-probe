#!/usr/bin/env node
'use strict';

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const {
  EXACT_BUILD,
  EXPECTED_INPUT_SHA256,
  PROTECTED_HOLDOUT,
  ROUTES,
  RUNTIME_SHA256,
  buildDecisionBundle,
  classifyExtras,
  countBy,
  invariant,
  nearestAdjacency,
  participantId,
  readJson,
  readJsonl,
  rejectProtectedPath,
  sha256,
  sha256File,
  validateDecisionBundle,
  validateDecodedRows,
  validateProtectedHoldoutVector,
  validateSafeP0Identity,
} = require('../src/item_family_saturation_v2');

const ROOT = path.resolve(__dirname, '..');
const OUT_DIR = path.join(
  ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'item_family_saturation',
);
const P0_DIR = path.join(ROOT, 'artifacts', 'full_semantic_baseline_v1', 'runtime_candidates');
const ENTITY_DIR = path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'entity_item');
const PATHS = Object.freeze({
  runtime_image: path.join(
    ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime',
    'league_16.16.805.0442.memory.bin',
  ),
  aligned: path.join(P0_DIR, 'packet_0137_04b3_item_route_aligned_16_16.jsonl'),
  details: path.join(P0_DIR, 'packet_0137_04b3_item_details_events_16_16.jsonl'),
  differential: path.join(P0_DIR, 'packet_0137_04b3_item_route_differential_16_16.json'),
  buy_profile: path.join(P0_DIR, 'packet_0137_static_profile.json'),
  remove_profile: path.join(P0_DIR, 'packet_04b3_static_profile.json'),
  buy_summary: path.join(P0_DIR, 'packet_0137_p0_native_decode_summary_16_16.json'),
  remove_summary: path.join(P0_DIR, 'packet_04b3_p0_native_decode_summary_16_16.json'),
  buy_decoded: path.join(P0_DIR, 'packet_0137_p0_native_decoded_16_16.jsonl'),
  remove_decoded: path.join(P0_DIR, 'packet_04b3_p0_native_decoded_16_16.jsonl'),
  entity_summary: path.join(ENTITY_DIR, 'entity_item_deep_recovery_summary_16_16.json'),
  entity_alignment: path.join(ENTITY_DIR, 'entity_item_transition_alignment_16_16.jsonl'),
  inventory_manifest: path.join(ENTITY_DIR, 'hero_inventory_route_shape_sample_16_16.jsonl.manifest.json'),
  p005a: path.join(ENTITY_DIR, 'packet_005a_native_decoded_16_16.jsonl'),
  p0064_audit: path.join(
    ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'unknown_mining',
    'route_0064_support_quest_audit.json',
  ),
  p006c: path.join(ENTITY_DIR, 'packet_006c_native_decoded_16_16.jsonl'),
  p01e8: path.join(ENTITY_DIR, 'packet_01e8_native_decoded_16_16.jsonl'),
  p02ea: path.join(ENTITY_DIR, 'packet_02ea_native_decoded_16_16.jsonl'),
  p0310: path.join(ENTITY_DIR, 'packet_0310_native_decoded_all_16_16.jsonl'),
  p0311: path.join(ENTITY_DIR, 'packet_0311_native_decoded_16_16.jsonl'),
  p0405: path.join(ENTITY_DIR, 'packet_0405_shape_native_decoded_16_16.jsonl'),
});

const OUTPUTS = Object.freeze({
  state_probe: path.join(OUT_DIR, 'item_family_state_probe_16_16.json'),
  classifications: path.join(OUT_DIR, 'item_family_extra_classification_16_16.jsonl'),
  decisions: path.join(OUT_DIR, 'item_family_saturation_decisions_16_16.json'),
  audit: path.join(OUT_DIR, 'item_family_saturation_audit_16_16.json'),
  report: path.join(OUT_DIR, 'ITEM_FAMILY_SATURATION_REPORT.md'),
  hashes: path.join(OUT_DIR, 'item_family_saturation_hashes_16_16.json'),
});

const PYTHON_STATE_PROBE = String.raw`
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
if 'holdout' in str(root).lower():
    raise ValueError('protected Holdout path is forbidden')
module_path = root / 'scripts' / 'analyze_entity_item_deep_recovery_v2.py'
explicit_paths = [
    root / 'artifacts' / 'new_build_rofl_compatibility_gate_v1' / 'runtime' / 'league_16.16.805.0442.memory.bin',
    root / 'artifacts' / 'full_semantic_baseline_v1' / 'runtime_candidates' / 'packet_0137_04b3_item_route_aligned_16_16.jsonl',
    root / 'artifacts' / 'full_semantic_deep_recovery_v2' / 'entity_item' / 'packet_005a_native_decoded_16_16.jsonl',
    root / 'artifacts' / 'full_semantic_deep_recovery_v2' / 'entity_item' / 'packet_006c_native_decoded_16_16.jsonl',
    root / 'artifacts' / 'full_semantic_deep_recovery_v2' / 'entity_item' / 'packet_01e8_native_decoded_16_16.jsonl',
    root / 'artifacts' / 'full_semantic_deep_recovery_v2' / 'entity_item' / 'packet_02ea_native_decoded_16_16.jsonl',
    root / 'artifacts' / 'full_semantic_deep_recovery_v2' / 'entity_item' / 'packet_0311_native_decoded_16_16.jsonl',
]
for source in [module_path, *explicit_paths]:
    if 'holdout' in str(source).lower():
        raise ValueError('protected Holdout path is forbidden')
    if not source.is_file():
        raise FileNotFoundError(source)

spec = importlib.util.spec_from_file_location('entity_item_deep_recovery_for_p8', module_path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
if module.BUILD != '16.16.805.0442':
    raise ValueError('imported analyzer build mismatch')
image = explicit_paths[0].read_bytes()
image_sha256 = hashlib.sha256(image).hexdigest()
if image_sha256 != '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55':
    raise ValueError('runtime image hash mismatch')

tables = module.build_helper_tables(image)
aligned = module.load_jsonl(explicit_paths[1], validate_replays=False)
rows005a = module.load_jsonl(explicit_paths[2])
rows006c = module.load_jsonl(explicit_paths[3])
rows01e8 = module.load_jsonl(explicit_paths[4])
rows02ea = module.load_jsonl(explicit_paths[5])
rows0311 = module.load_jsonl(explicit_paths[6])
snapshot_summary, decoded_snapshots = module.analyze_snapshots(
    {'0x0311': rows0311, '0x02ea': rows02ea}, tables
)
events = module.build_state_events(
    aligned, rows006c, rows01e8, rows0311 + rows02ea, decoded_snapshots, image
)
state_summary, removal_capture, _ = module.simulate_inventory_state(events)
substitution_summary, substitution_mapping = module.analyze_shop_item_substitutions(rows005a, image)
substitution_events = []
for row in rows005a:
    decoded = module.decode_shop_item_substitution(row, image)
    substitution_events.append({
        'event_uid': module.event_uid(row),
        'game_id': row['replay_label'],
        'replay_sha256': row['replay_sha256'],
        'participant_id': module.participant_id(row['raw_param']),
        'timestamp_ms': row['replay_time_ms'],
        'source_item_id': decoded['source_item_id'],
        'target_item_id': decoded['target_item_id'],
    })

output = {
    'schema': 'ITEM_FAMILY_STATE_PROBE_V2',
    'schema_version': 2,
    'exact_build': module.BUILD,
    'runtime_image_sha256': image_sha256,
    'method': 'EXACT_NATIVE_HELPER_TABLE_EMULATION_PLUS_FULL_CHRONOLOGICAL_INVENTORY_REPLAY',
    'helper_table_sha256': {
        f'0x{rva:08x}': hashlib.sha256(table).hexdigest()
        for rva, table in sorted(tables.items())
    },
    'source_counts': {
        'aligned': len(aligned),
        '0x005a': len(rows005a),
        '0x006c': len(rows006c),
        '0x01e8': len(rows01e8),
        '0x02ea': len(rows02ea),
        '0x0311': len(rows0311),
        'decoded_snapshot_count': len(decoded_snapshots),
    },
    'snapshot_summary': snapshot_summary,
    'inventory_state_simulation': state_summary,
    'removal_capture': removal_capture,
    'substitution_summary': substitution_summary,
    'substitution_mapping': substitution_mapping,
    'substitution_events': substitution_events,
    'actual_reverse_engineering_executed': True,
    'protected_holdout': {
        'enumerated': False,
        'read': False,
        'hashed': False,
        'decoded': False,
        'tested': False,
        'consumed': False,
    },
}
print(json.dumps(output, ensure_ascii=False, sort_keys=True, separators=(',', ':')))
`;

function writeJson(filePath, value) {
  fs.writeFileSync(rejectProtectedPath(filePath), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function writeJsonl(filePath, rows) {
  fs.writeFileSync(
    rejectProtectedPath(filePath),
    `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`,
    'utf8',
  );
}

function runStateProbe() {
  const result = spawnSync('python', ['-c', PYTHON_STATE_PROBE, ROOT], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 32 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(`state probe failed (${result.status}): ${result.stderr || result.stdout}`);
  }
  return { raw: result.stdout.trim(), parsed: JSON.parse(result.stdout) };
}

function fileRecord(name, filePath, rows = null) {
  const source = rejectProtectedPath(filePath);
  const stat = fs.statSync(source);
  return {
    name,
    path: path.relative(ROOT, source).replaceAll('\\', '/'),
    byte_size: stat.size,
    sha256: sha256File(source),
    row_count: rows === null ? null : rows.length,
  };
}

function verifyPinnedInputs() {
  const records = [];
  for (const [name, expected] of Object.entries(EXPECTED_INPUT_SHA256)) {
    const source = PATHS[name];
    invariant(source, `missing explicit path for ${name}`);
    const actual = sha256File(source);
    invariant(actual === expected, `${name}: pinned SHA mismatch (${actual})`);
    records.push(fileRecord(name, source));
  }
  return records;
}

function groupBy(rows, select) {
  const output = new Map();
  for (const row of rows) {
    const key = select(row);
    if (!output.has(key)) output.set(key, []);
    output.get(key).push(row);
  }
  return output;
}

function annotateCrossArtifactClasses(classifications, supportAudit) {
  const byRouteKey = new Map(classifications.map((row) => [row.route_key, row]));
  const removalRows = classifications.filter((row) => row.route === ROUTES.remove.packet_type);
  const stageOnePairs = removalRows.filter((row) => (
    row.prior_item_id === 3865 && row.same_slot_add_item_ids.includes(3866)
  ));
  const stageTwoPairs = removalRows.filter((row) => (
    row.prior_item_id === 3866 && row.same_slot_add_item_ids.includes(3867)
  ));
  const alignments = supportAudit.details_ground_truth_alignment.alignments;
  const stageOneAlignments = alignments.filter((row) => row.stage_after === 1);
  const stageTwoAlignments = alignments.filter((row) => row.stage_after === 2);

  function matchesIdentity(pair, alignment) {
    return pair.game_id === alignment.game_id && pair.participant_id === alignment.participant_id;
  }

  const stageOneDeltas = [];
  for (const pair of stageOnePairs) {
    const alignment = stageOneAlignments.find((row) => matchesIdentity(pair, row));
    invariant(alignment, `missing 0x0064 stage-one alignment for ${pair.route_key}`);
    const delta = pair.timestamp_ms - alignment.details_anchor.timestamp_ms;
    invariant(Math.abs(delta) <= 1, `stage-one transition outside 1ms: ${pair.route_key}`);
    pair.support_quest_stage_link = 'STAGE_0_TO_1_DETAILS_ANCHOR_WITHIN_1MS';
    stageOneDeltas.push(delta);
    for (const routeKey of pair.same_slot_add_route_keys) {
      const addition = byRouteKey.get(routeKey);
      if (addition?.item_id === 3866) {
        addition.support_quest_stage_link = 'STAGE_0_TO_1_DETAILS_ANCHOR_WITHIN_1MS';
      }
    }
  }
  const stageTwoLeadDeltas = [];
  for (const pair of stageTwoPairs) {
    const alignment = stageTwoAlignments.find((row) => matchesIdentity(pair, row));
    invariant(alignment, `missing 0x0064 stage-two alignment for ${pair.route_key}`);
    const lead = alignment.details_anchor.timestamp_ms - pair.timestamp_ms;
    invariant(lead >= 0 && lead <= 5000, `stage-two transient outside 5s: ${pair.route_key}`);
    pair.support_quest_stage_link = 'TRANSIENT_3867_PRECEDES_STAGE_1_TO_2_DETAILS_ANCHOR';
    stageTwoLeadDeltas.push(lead);
    for (const routeKey of pair.same_slot_add_route_keys) {
      const addition = byRouteKey.get(routeKey);
      if (addition?.item_id === 3867) {
        addition.support_quest_stage_link = 'TRANSIENT_3867_PRECEDES_STAGE_1_TO_2_DETAILS_ANCHOR';
      }
    }
  }
  invariant(stageOnePairs.length === 8 && stageTwoPairs.length === 8,
    `support item transition counts changed: ${stageOnePairs.length}/${stageTwoPairs.length}`);
  return {
    imported_audit_sha256: EXPECTED_INPUT_SHA256.p0064_audit,
    imported_exact_build_fields_only: true,
    imported_evidence_grade: supportAudit.recovered_bounded_structure.evidence_grade,
    imported_scope: supportAudit.recovered_bounded_structure.semantic_scope,
    imported_alignment_count: alignments.length,
    stage_0_to_1_pair_count: stageOnePairs.length,
    stage_0_to_1_route_minus_details_delta_ms: {
      min: Math.min(...stageOneDeltas), max: Math.max(...stageOneDeltas),
    },
    stage_1_to_transient_3867_pair_count: stageTwoPairs.length,
    transient_3867_lead_before_details_destroy_ms: {
      min: Math.min(...stageTwoLeadDeltas), max: Math.max(...stageTwoLeadDeltas),
    },
    durable_3867_snapshot_count: 0,
    boundary: 'The 16 structural item trajectories corroborate the canonical UTILITY-only 0x0064 stage audit; they do not generalize 0x0064 or name all 0x0137/0x04b3 rows.',
  };
}

function analyzeSubstitutionJoin(classifications, probe) {
  const byIdentityTime = groupBy(
    classifications,
    (row) => `${row.game_id}:${row.participant_id}:${row.timestamp_ms}`,
  );
  const pairCounter = new Map();
  let directTransitionCount = 0;
  let noSameTimeMembershipTransitionCount = 0;
  const rows = [];
  for (const event of probe.substitution_events) {
    const key = `${event.game_id}:${event.participant_id}:${event.timestamp_ms}`;
    const candidates = byIdentityTime.get(key) || [];
    const targetAdditions = candidates.filter((row) => (
      row.route === ROUTES.add.packet_type && row.item_id === event.target_item_id
    ));
    const sourceRemovals = candidates.filter((row) => (
      row.route === ROUTES.remove.packet_type
      && row.prior_item_id === event.source_item_id
      && row.same_slot_add_item_ids.includes(event.target_item_id)
    ));
    const direct = targetAdditions.length > 0 && sourceRemovals.length > 0;
    directTransitionCount += direct;
    noSameTimeMembershipTransitionCount += !direct;
    const pair = `${event.source_item_id}->${event.target_item_id}`;
    pairCounter.set(pair, (pairCounter.get(pair) || 0) + 1);
    rows.push({
      ...event,
      direct_same_time_same_slot_transition: direct,
      target_add_route_keys: targetAdditions.map((row) => row.route_key),
      source_remove_route_keys: sourceRemovals.map((row) => row.route_key),
    });
  }
  invariant(directTransitionCount === 6 && noSameTimeMembershipTransitionCount === 2,
    `0x005a join changed: ${directTransitionCount}/${noSameTimeMembershipTransitionCount}`);
  return {
    event_count: probe.substitution_events.length,
    decoded_pair_counts: Object.fromEntries([...pairCounter.entries()].sort()),
    direct_same_time_same_slot_transition_count: directTransitionCount,
    no_same_time_membership_transition_count: noSameTimeMembershipTransitionCount,
    joined_events: rows,
    boundary: 'Only six 2420->2421 rows close a same-time same-slot membership transition. The two time-zero 1001->2422 map rows have no same-time 0x0137/0x04b3 membership transition.',
  };
}

function buildMarkdown(report) {
  const add = report.classification['0x0137'];
  const remove = report.classification['0x04b3'];
  return `# Item-family saturation closure — ${EXACT_BUILD}

## Outcome

The full explicit-safe P0 surface is conserved: ${report.conservation.aligned_row_count} decoded
route rows, including ${add.extra_count} \`0x0137\` extras and ${remove.extra_count}
\`0x04b3\` non-sale extras. The routes remain exact HeroInventoryClient transition
carriers; they are not promoted as universal BUY/SELL events.

## 0x0137 extras (${add.extra_count})

${Object.entries(add.structural_class_counts).map(([name, count]) => `- ${name}: ${count}`).join('\n')}

The 48 time-zero rows are bounded initial synchronization. The 258 no-DETAILS
paired rows partition into single-slot, multi-write, and other-slot transitions.
The 41 grouped item-2055 rows remain grouped co-transitions. The 100 unpaired
sets have no current local cause oracle and remain opaque.

## 0x04b3 extras (${remove.extra_count})

${Object.entries(remove.structural_class_counts).map(([name, count]) => `- ${name}: ${count}`).join('\n')}

Complete inventory state exists for ${remove.complete_state_count}; ${remove.incomplete_state_count}
remain explicitly incomplete. Only six rows close the exact \`0x005a\`
\`2420->2421\` substitution path. Same-slot coincidence, even with complete state,
does not prove purchase, sale, component consumption, or a recipe edge.

## Cross-artifact counterexamples

${report.counterexamples.map((row) => `- ${row.id}: ${row.observation}`).join('\n')}

## Closure

\`actual_reverse_engineering_executed = true\`. Exact native helper-table
emulation and full chronological inventory replay were executed twice with
stable hash \`${report.native_probe_determinism.probe_sha256}\`. Current safe
local evidence is exhausted, \`actionable_hypotheses = []\`. Further semantic
work is externally gated to controlled request/answer correlation, a complete
live inventory plus exact recipe graph, or a new labeled exact-build Replay.

The protected Jungle Objective Holdout was not enumerated, read, hashed,
decoded, tested, or consumed.
`;
}

function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  for (const source of Object.values(PATHS)) rejectProtectedPath(source);
  const gate = fs.readFileSync(path.join(OUT_DIR, 'ARCHITECTURE_GATE.md'), 'utf8');
  invariant(gate.includes('ARCHITECTURE_GATE = PASS'), 'P8 architecture gate is not PASS');
  const pinnedInputs = verifyPinnedInputs();

  const aligned = readJsonl(PATHS.aligned);
  const details = readJsonl(PATHS.details);
  const buyDecoded = readJsonl(PATHS.buy_decoded);
  const removeDecoded = readJsonl(PATHS.remove_decoded);
  const entityAlignment = readJsonl(PATHS.entity_alignment);
  const p005a = readJsonl(PATHS.p005a);
  const p006c = readJsonl(PATHS.p006c);
  const p01e8 = readJsonl(PATHS.p01e8);
  const p02ea = readJsonl(PATHS.p02ea);
  const p0310 = readJsonl(PATHS.p0310);
  const p0311 = readJsonl(PATHS.p0311);
  const p0405 = readJsonl(PATHS.p0405);
  const buyProfile = readJson(PATHS.buy_profile);
  const removeProfile = readJson(PATHS.remove_profile);
  const buySummary = readJson(PATHS.buy_summary);
  const removeSummary = readJson(PATHS.remove_summary);
  const differential = readJson(PATHS.differential);
  const entitySummary = readJson(PATHS.entity_summary);
  const inventoryManifest = readJson(PATHS.inventory_manifest);
  const supportAudit = readJson(PATHS.p0064_audit);

  for (const [index, row] of aligned.entries()) validateSafeP0Identity(row, `aligned:${index + 1}`);
  invariant(aligned.length === 2614, `aligned row count changed: ${aligned.length}`);
  invariant(details.length === 1288, `DETAILS event count changed: ${details.length}`);
  invariant(entityAlignment.length === 1526, `entity alignment count changed: ${entityAlignment.length}`);
  invariant(supportAudit.exact_build === EXACT_BUILD, '0x0064 audit build mismatch');
  validateProtectedHoldoutVector(supportAudit.protected_holdout);

  const nativeAudit = {
    '0x0137': validateDecodedRows(buyDecoded, '0x0137', 1601),
    '0x04b3': validateDecodedRows(removeDecoded, '0x04b3', 1013),
    '0x005a': validateDecodedRows(p005a, '0x005a', 8),
    '0x006c': validateDecodedRows(p006c, '0x006c', 53),
    '0x01e8': validateDecodedRows(p01e8, '0x01e8', 258),
    '0x02ea': validateDecodedRows(p02ea, '0x02ea', 299),
    '0x0310': validateDecodedRows(p0310, '0x0310', 17802),
    '0x0311': validateDecodedRows(p0311, '0x0311', 1425, { expectedFailureCount: 154 }),
    '0x0405': validateDecodedRows(p0405, '0x0405', 12),
  };
  invariant(buySummary.event_count === 1601 && buySummary.successful_full_consume_count === 1601,
    '0x0137 native summary changed');
  invariant(removeSummary.event_count === 1013 && removeSummary.successful_full_consume_count === 1013,
    '0x04b3 native summary changed');
  invariant(buyProfile.profile.name === ROUTES.add.rtti_name
    && buyProfile.registration.owner === 'HeroInventoryClient', '0x0137 static identity changed');
  invariant(removeProfile.profile.name === ROUTES.remove.rtti_name
    && removeProfile.registration.owner === 'HeroInventoryClient', '0x04b3 static identity changed');

  const probeOne = runStateProbe();
  const probeTwo = runStateProbe();
  invariant(probeOne.raw === probeTwo.raw, 'exact native/state probe is not deterministic');
  const probe = probeOne.parsed;
  invariant(probe.exact_build === EXACT_BUILD, 'state probe build mismatch');
  invariant(probe.runtime_image_sha256 === RUNTIME_SHA256, 'state probe runtime mismatch');
  invariant(probe.actual_reverse_engineering_executed === true, 'state probe did not execute');
  validateProtectedHoldoutVector(probe.protected_holdout);

  const classifications = classifyExtras(aligned, probe.removal_capture, probe.substitution_mapping);
  const supportCrossAudit = annotateCrossArtifactClasses(classifications, supportAudit);
  const substitutionCrossAudit = analyzeSubstitutionJoin(classifications, probe);
  classifications.sort((left, right) => left.route.localeCompare(right.route)
    || left.route_key.localeCompare(right.route_key));

  const addExtras = classifications.filter((row) => row.route === ROUTES.add.packet_type);
  const removeExtras = classifications.filter((row) => row.route === ROUTES.remove.packet_type);
  const addClassCounts = countBy(addExtras, (row) => row.structural_class);
  const removeClassCounts = countBy(removeExtras, (row) => row.structural_class);
  const expectedAddClasses = {
    PAIRED_MULTI_WRITE_SAME_SLOT_SET: 18,
    PAIRED_OTHER_SLOT_ONLY_MULTI_SLOT_SET: 16,
    PAIRED_SINGLE_SAME_SLOT_SET: 224,
    PURCHASE_GROUP_EXTRA_2055_SAME_SLOT_CO_TRANSITION: 41,
    TIME_ZERO_INITIAL_SYNC_SET: 48,
    UNPAIRED_SET_REFRESH_OR_AUTOMATIC_ADDITION_OPAQUE: 100,
  };
  const expectedRemoveClasses = {
    COMPLETE_STATE_EXACT_005A_SUBSTITUTION_PAIR: 6,
    COMPLETE_STATE_MULTI_WRITE_SAME_SLOT_AMBIGUOUS: 18,
    COMPLETE_STATE_OTHER_SLOT_ONLY_CO_TRANSITION: 255,
    COMPLETE_STATE_SAME_SLOT_DIFFERENT_ITEM_REPLACEMENT: 512,
    COMPLETE_STATE_SAME_SLOT_SAME_ITEM_REWRITE: 46,
    INCOMPLETE_STATE_MULTI_WRITE_SAME_SLOT_OPAQUE: 5,
    INCOMPLETE_STATE_OTHER_SLOT_ONLY_CO_TRANSITION_OPAQUE: 39,
    INCOMPLETE_STATE_PRIOR_EMPTY_OR_UNRECOVERED_SAME_SLOT_OPAQUE: 1,
    INCOMPLETE_STATE_SAME_SLOT_DIFFERENT_ITEM_CANDIDATE: 68,
    INCOMPLETE_STATE_SAME_SLOT_SAME_ITEM_REWRITE_CANDIDATE: 3,
  };
  invariant(JSON.stringify(addClassCounts) === JSON.stringify(expectedAddClasses),
    `0x0137 class counts changed: ${JSON.stringify(addClassCounts)}`);
  invariant(JSON.stringify(removeClassCounts) === JSON.stringify(expectedRemoveClasses),
    `0x04b3 class counts changed: ${JSON.stringify(removeClassCounts)}`);
  invariant(addExtras.length === 447 && removeExtras.length === 953,
    `extra conservation changed: ${addExtras.length}/${removeExtras.length}`);
  invariant(new Set(classifications.map((row) => row.route_key)).size === 1400,
    'extra route-key bijection failed');

  const publishedExtraKeys = new Set(entityAlignment
    .filter((row) => row.kind === 'route_extra')
    .map((row) => row.route_key));
  invariant(publishedExtraKeys.size === 1400, 'published alignment extra count changed');
  invariant(classifications.every((row) => publishedExtraKeys.has(row.route_key)),
    'P8 extra classification is not a bijection over published alignment extras');

  const adjacency = {
    '0x0310': nearestAdjacency(classifications, p0310, '0x0310'),
    '0x0311': nearestAdjacency(classifications, p0311, '0x0311'),
    '0x02ea': nearestAdjacency(classifications, p02ea, '0x02ea'),
  };
  invariant(adjacency['0x0310'].by_extra_route['0x0137'].shift_0ms_within_10ms === 230,
    '0x0310/0x0137 adjacency changed');
  invariant(adjacency['0x0310'].by_extra_route['0x04b3'].shift_0ms_within_10ms === 319,
    '0x0310/0x04b3 adjacency changed');
  invariant(adjacency['0x0311'].by_extra_route['0x0137'].shift_0ms_within_10ms === 49,
    '0x0311/0x0137 adjacency changed');
  invariant(adjacency['0x0311'].by_extra_route['0x04b3'].shift_0ms_within_10ms === 3,
    '0x0311/0x04b3 adjacency changed');
  invariant(adjacency['0x02ea'].by_extra_route['0x0137'].shift_0ms_within_10ms === 0
    && adjacency['0x02ea'].by_extra_route['0x04b3'].shift_0ms_within_10ms === 0,
  '0x02ea immediate adjacency changed');

  const routeClassCounts = countBy(aligned, (row) => `${row.route}:${row.classification}`);
  invariant(routeClassCounts['0x0137:exact_details_purchase'] === 1154, 'purchase count changed');
  invariant(routeClassCounts['0x04b3:exact_details_sale_time_subject'] === 60, 'sale count changed');
  invariant(differential.route_04b3_removal_differential.route_class_counts
    .purchase_coincident_removal_candidate === 684, 'P0 0x04b3 purchase-coincident count changed');

  const itemBoundary = entitySummary.item_group_data_boundary;
  invariant(itemBoundary.observed_count === 518470, '0x0405 observed count changed');
  invariant(p0405.every((row) => row.chunk_stream === 'keyframe' && row.replay_time_ms === 0),
    '0x0405 bounded sample boundary changed');
  invariant(inventoryManifest.target_replay_version === EXACT_BUILD, 'inventory manifest build mismatch');

  const decisions = buildDecisionBundle();
  validateDecisionBundle(decisions);
  const counterexamples = [
    {
      id: 'ROUTE_NAMES_ARE_NOT_ROUTE_WIDE_BUSINESS_EVENTS',
      observation: '0x0137 has 447 non-purchase extras and 0x04b3 has 953 non-sale extras; all weights are decoded and conserved.',
      count: 1400,
    },
    {
      id: 'SAME_TIME_SET_DISTINGUISHES_SALES_BUT_NOT_CAUSE',
      observation: 'All 953 non-sale removals have a same-time 0x0137 set, while all 60 DETAILS-aligned sales have none; this separates the subset but does not identify recipe or request cause.',
      positive_count: 953,
      negative_control_count: 60,
    },
    {
      id: 'SAME_ITEM_AND_OTHER_SLOT_NEGATIVES',
      observation: '46 complete-state removals rewrite the same item in the same slot and 255 complete-state removals have only other-slot additions, contradicting a universal one-component-to-one-result interpretation.',
      same_item_count: 46,
      other_slot_only_count: 255,
    },
    {
      id: 'STATE_MODEL_IS_NOT_COMPLETE',
      observation: '116 removal extras precede an authoritative game-chunk reset; 57 later reset comparisons disagree with the recovered live state.',
      incomplete_extra_count: 116,
      snapshot_mismatch_count: probe.inventory_state_simulation.snapshot_comparison_counts.mismatch,
    },
    {
      id: 'SUBSTITUTION_MAP_IS_NARROW',
      observation: 'Only 6/953 extras close the exact same-time 2420->2421 0x005a path; two time-zero 1001->2422 map rows have no same-time membership transition.',
      direct_count: 6,
      negative_count: 2,
    },
    {
      id: 'ADJACENCY_IS_NOT_IDENTITY',
      observation: '0x0310 is exact-time adjacent to only 230/447 additions and 319/953 removals; shifted controls remain nonzero. 0x02ea has zero immediate joins.',
      p0310_add_exact: adjacency['0x0310'].by_extra_route['0x0137'].exact_time,
      p0310_remove_exact: adjacency['0x0310'].by_extra_route['0x04b3'].exact_time,
    },
    {
      id: 'GENERIC_SNAPSHOT_ROUTES_ARE_NOT_UNDO_OR_RECIPE_EVENTS',
      observation: '0x0311/0x02ea retain 1672 non-undo negatives; 0x0311 retains 154 native failures and keyframes are excluded from live mutation.',
      generic_snapshot_negative_count: entitySummary.undo_snapshot_path.generic_snapshot_route_negative_count,
      p0311_native_failure_count: nativeAudit['0x0311'].failure_count,
    },
    {
      id: '0x0405_IS_NOT_INVENTORY_MEMBERSHIP',
      observation: 'All 518470 observed 0x0405 rows are keyframe-side group-data/cooldown adjacency; the bounded 12-row native shape sample is time-zero keyframe only.',
      observed_count: itemBoundary.observed_count,
      shape_sample_count: p0405.length,
    },
    {
      id: 'UNPAIRED_ADDITION_CAUSE_REMAINS_OPAQUE',
      observation: '100 non-time-zero 0x0137 extras have no same-time removal and cannot be separated into refresh versus automatic addition locally.',
      count: 100,
    },
  ];

  const report = {
    schema: 'ITEM_FAMILY_SATURATION_AUDIT_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    runtime_image_sha256: RUNTIME_SHA256,
    project_context_loaded: true,
    architecture_gate: 'PASS',
    actual_reverse_engineering_executed: true,
    purpose: 'P8 closure over existing exact structural decodes; no layout reimplementation and no semantic API promotion.',
    scope: {
      routes: [
        `${ROUTES.add.packet_type} ${ROUTES.add.rtti_name}`,
        `${ROUTES.remove.packet_type} ${ROUTES.remove.rtti_name}`,
      ],
      explicit_safe_p0_replay_count: 4,
      exact_build_only: true,
      nearest_build_fallback: 'FORBIDDEN',
      directory_replay_discovery: false,
    },
    static_identity_audit: {
      reused_existing_structure_not_redecoded: true,
      '0x0137': {
        rtti_name: buyProfile.profile.name,
        owner: buyProfile.registration.owner,
        receive_target_rva: buyProfile.registration.receive_target_rva,
        factory_case_rva: buyProfile.registration.factory_case_rva,
        constructor_rva: buyProfile.registration.constructor_rva,
        vtable_rva: buyProfile.registration.final_vtable_rva,
        deserializer_rva: buyProfile.registration.deserializer_rva,
        object_size: buyProfile.registration.factory_allocation_size,
      },
      '0x04b3': {
        rtti_name: removeProfile.profile.name,
        owner: removeProfile.registration.owner,
        receive_target_rva: removeProfile.registration.receive_target_rva,
        factory_case_rva: removeProfile.registration.factory_case_rva,
        constructor_rva: removeProfile.registration.constructor_rva,
        vtable_rva: removeProfile.registration.final_vtable_rva,
        deserializer_rva: removeProfile.registration.deserializer_rva,
        object_size: removeProfile.registration.factory_allocation_size,
      },
      semantic_boundary: 'RTTI names and exact structural identity do not authorize route-wide BUY or SELL semantics.',
    },
    full_native_artifact_audit: nativeAudit,
    native_probe_determinism: {
      method: probe.method,
      exact_native_execution_rerun: true,
      run_count: 2,
      all_match: true,
      probe_sha256: sha256(probeOne.raw),
      helper_table_sha256: probe.helper_table_sha256,
    },
    conservation: {
      aligned_row_count: aligned.length,
      details_event_count: details.length,
      route_counts: countBy(aligned, (row) => row.route),
      source_class_counts: routeClassCounts,
      exact_details_purchase_count: 1154,
      exact_details_sale_count: 60,
      add_extra_count: addExtras.length,
      remove_extra_count: removeExtras.length,
      classified_extra_row_count: classifications.length,
      classified_route_key_distinct_count: new Set(classifications.map((row) => row.route_key)).size,
      published_alignment_extra_key_count: publishedExtraKeys.size,
      input_weight_conserved: 1154 + 60 + classifications.length === aligned.length,
      extra_weight_conserved: classifications.length === addExtras.length + removeExtras.length,
      published_extra_bijection: classifications.every((row) => publishedExtraKeys.has(row.route_key)),
    },
    classification: {
      '0x0137': {
        extra_count: addExtras.length,
        structural_class_counts: addClassCounts,
        structurally_partitioned_count: 447,
        cause_bounded_initial_sync_count: 48,
        cause_semantics_opaque_count: 399,
        locally_unpartitionable_unpaired_count: 100,
        support_quest_annotated_count: addExtras.filter((row) => row.support_quest_stage_link).length,
        exact_0x005a_pair_count: addExtras.filter((row) => row.exact_0x005a_substitution_pair).length,
        boundary: 'Only time-zero sync is cause-bounded. Other classes are transition shapes; the 100 unpaired rows remain refresh-or-automatic-addition opaque.',
      },
      '0x04b3': {
        extra_count: removeExtras.length,
        structural_class_counts: removeClassCounts,
        complete_state_count: removeExtras.filter((row) => row.state_complete).length,
        incomplete_state_count: removeExtras.filter((row) => !row.state_complete).length,
        support_quest_annotated_count: removeExtras.filter((row) => row.support_quest_stage_link).length,
        exact_0x005a_pair_count: removeExtras.filter((row) => row.exact_0x005a_substitution_pair).length,
        cause_semantics_opaque_count: removeExtras.length,
        boundary: 'All 953 receive a structural class; none receives a recipe, purchase, sale, or component-consumption cause label.',
      },
    },
    inventory_state_simulation: probe.inventory_state_simulation,
    inventory_snapshot_native_summary: probe.snapshot_summary,
    cross_artifact_audits: {
      '0x005a_substitution': substitutionCrossAudit,
      '0x0064_support_quest': supportCrossAudit,
      adjacency,
      '0x0405_boundary': {
        observed_count: itemBoundary.observed_count,
        stream_distribution: itemBoundary.stream_distribution,
        bounded_shape_sample_count: p0405.length,
        bounded_sample_streams: countBy(p0405, (row) => row.chunk_stream),
        bounded_sample_times: countBy(p0405, (row) => row.replay_time_ms),
        decision: 'REJECT_INVENTORY_MEMBERSHIP_RETAIN_GROUP_DATA_COOLDOWN_ADJACENCY',
      },
    },
    counterexamples,
    decisions_summary: {
      decision_counts: decisions.decision_counts,
      route_decision_count: decisions.route_decisions.length,
      capability_decision_count: decisions.capability_decisions.length,
      domain_decision_count: decisions.domain_decisions.length,
    },
    saturation: decisions.saturation,
    evidence_exhausted: true,
    actionable_hypotheses: [],
    validations: {
      governance_pass: true,
      pinned_input_hashes_pass: true,
      exact_build_identity_pass: true,
      full_native_artifact_counts_pass: true,
      double_native_state_probe_stable: true,
      full_route_weight_conservation_pass: true,
      extra_route_key_bijection_pass: true,
      structural_class_counts_pass: true,
      counterexamples_preserved: true,
      decisions_valid: true,
      current_safe_local_resource_saturated: true,
      all_pass: true,
    },
    protected_holdout: { ...PROTECTED_HOLDOUT },
    input_provenance: pinnedInputs,
  };
  invariant(report.conservation.input_weight_conserved, 'full P0 route weight is not conserved');
  invariant(report.conservation.extra_weight_conserved, 'extra weight is not conserved');
  invariant(report.classification['0x04b3'].complete_state_count === 837, 'complete state count changed');
  invariant(report.classification['0x04b3'].incomplete_state_count === 116, 'incomplete state count changed');
  invariant(report.classification['0x0137'].support_quest_annotated_count === 16,
    '0x0137 support annotation count changed');
  invariant(report.classification['0x04b3'].support_quest_annotated_count === 16,
    '0x04b3 support annotation count changed');

  writeJson(OUTPUTS.state_probe, probe);
  writeJsonl(OUTPUTS.classifications, classifications);
  writeJson(OUTPUTS.decisions, decisions);
  writeJson(OUTPUTS.audit, report);
  fs.writeFileSync(OUTPUTS.report, buildMarkdown(report), 'utf8');

  const outputRecords = Object.entries(OUTPUTS)
    .filter(([name]) => name !== 'hashes')
    .map(([name, filePath]) => fileRecord(
      name, filePath, name === 'classifications' ? classifications : null,
    ));
  const hashes = {
    schema: 'ITEM_FAMILY_SATURATION_HASH_MANIFEST_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    deterministic: true,
    state_probe_double_run_sha256: sha256(probeOne.raw),
    inputs: pinnedInputs,
    outputs: outputRecords,
    protected_holdout: { ...PROTECTED_HOLDOUT },
  };
  writeJson(OUTPUTS.hashes, hashes);
  process.stdout.write(`${JSON.stringify({
    architecture_gate: 'PASS',
    aligned_rows: aligned.length,
    add_extras: addExtras.length,
    remove_extras: removeExtras.length,
    complete_remove_state: report.classification['0x04b3'].complete_state_count,
    incomplete_remove_state: report.classification['0x04b3'].incomplete_state_count,
    direct_0x005a_pairs: substitutionCrossAudit.direct_same_time_same_slot_transition_count,
    support_quest_pairs: supportCrossAudit.stage_0_to_1_pair_count
      + supportCrossAudit.stage_1_to_transient_3867_pair_count,
    decision_counts: decisions.decision_counts,
    state_probe_sha256: hashes.state_probe_double_run_sha256,
    audit_sha256: sha256File(OUTPUTS.audit),
    hash_manifest_sha256: sha256File(OUTPUTS.hashes),
    all_pass: report.validations.all_pass,
  }, null, 2)}\n`);
}

main();
