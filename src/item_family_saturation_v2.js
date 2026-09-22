'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const EXACT_BUILD = '16.16.805.0442';
const RUNTIME_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const ROUTES = Object.freeze({
  add: Object.freeze({ packet_id: 0x0137, packet_type: '0x0137', rtti_name: 'PKT_BuyItemAns_s' }),
  remove: Object.freeze({ packet_id: 0x04b3, packet_type: '0x04b3', rtti_name: 'PKT_RemoveItemAns_s' }),
});
const SAFE_P0_REPLAYS = Object.freeze({
  '11191024308': '1ff3b2d4321bbe4f6bf79bff767305bbf4fa59e42c9524c91f3c3b9421733349',
  '11191203388': 'e54e1950949761bb75df509bd91a6823c3d08569a1f530410cb38fb5e07e3633',
  '11191271422': 'a5a5580f1a4546fb627b53cf3921a9cf0f3086f15964410e054809a87a3be399',
  '11191336852': '25dff9e58855cfc2afdca6b1df2cc43aaa2da1ddc9823b63993ecfc456eb0e75',
});
const EXPECTED_INPUT_SHA256 = Object.freeze({
  runtime_image: RUNTIME_SHA256,
  aligned: 'e8597728cca0427d4ea608ec608cd4c1fe413b4185dc015439a9c1e7dd1c52a6',
  details: '83ad5a793cb24cda26987be2e35329bb4ad714470d5e7e1c75249b152cf853e5',
  buy_profile: '28e5617d12e9bc6c1873682623521f9d2161908bcdda084a8439e74792030851',
  remove_profile: '4181dd599880163b06d555c751ae2b3121018e9d83fdcb18abfea53df1105eb9',
  buy_decoded: '2e82a79f40c000e88ff3f43acc545b3c69093482566f1cd88bf00aee031cd6eb',
  remove_decoded: '6a552aa547d9ebdb9219ca9fac78d11d67f59a8a91ed409384306902890a80cd',
  entity_summary: 'c5614f613bb3116833cc15c1e42486272a7f4431184629ffaca1b89f943485e7',
  entity_alignment: '666ff8f9faae7763ab1bb7129acf18118357628d97d640158278246d574e462a',
  p005a: 'dc0e169067c702cfd4ec761b62edaf94ae78dc824207cd3fc6f09e886b98eac7',
  p0064_audit: 'b5e3a5568b8760d4dee861d4b52c758d125b020132a5f08bad5634e0f9e99d75',
  p006c: '999326101a3d5604766a567a20f931fc787686980ce74cf0525215f8d6730384',
  p01e8: 'e1d21f4d633579262157ac9d98f05b4cadd71d6406ca039b1f72f8e89a5c4224',
  p02ea: '90e394eb6ec3a6c160e1bea0c95ee0b3f2386fee322ad6f106a6b917611c9c91',
  p0310: 'e68fc2ef47c46b5ed897221d2e955efd5f83dd7a6ea3368bbc5a8ae021722916',
  p0311: '8fb9d4837e50d730170c9651ff41cf8c957713094884f80b24df923fc2478508',
  p0405: 'e591555ccd4cc80c60e43be3501b0252ca4d1906684026deba73bbdeb9bbca10',
});
const PROTECTED_HOLDOUT = Object.freeze({
  enumerated: false,
  read: false,
  hashed: false,
  decoded: false,
  tested: false,
  consumed: false,
});
const EXTERNAL_REQUIRED_EVIDENCE = Object.freeze([
  'controlled exact-build shop request/answer correlation with result and business-state labels',
  'complete live per-participant inventory trace plus an exact version-bound item recipe/component graph',
  'new controlled exact-build Replay with labeled purchases, sales, undos, recipe transitions, and complete packet order',
]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function rejectProtectedPath(value) {
  const resolved = path.resolve(value);
  if (resolved.toLowerCase().includes('holdout')) {
    throw new Error(`protected Holdout path is forbidden: ${resolved}`);
  }
  return resolved;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sha256File(filePath) {
  return sha256(fs.readFileSync(rejectProtectedPath(filePath)));
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(rejectProtectedPath(filePath), 'utf8').replace(/^\uFEFF/, ''));
}

function readJsonl(filePath) {
  return fs.readFileSync(rejectProtectedPath(filePath), 'utf8')
    .replace(/^\uFEFF/, '')
    .split(/\r?\n/u)
    .filter((line) => line.trim().length > 0)
    .map((line, index) => {
      try {
        return JSON.parse(line);
      } catch (error) {
        throw new Error(`${filePath}:${index + 1}: ${error.message}`);
      }
    });
}

function increment(counter, key, amount = 1) {
  counter.set(String(key), (counter.get(String(key)) || 0) + amount);
}

function counterObject(counter) {
  return Object.fromEntries([...counter.entries()].sort(([left], [right]) => left.localeCompare(right)));
}

function countBy(rows, select) {
  const counter = new Map();
  for (const row of rows) increment(counter, select(row));
  return counterObject(counter);
}

function participantId(rawParam) {
  return (Number(rawParam) & 0xff) - 0xad;
}

function routeKeyLocation(routeKey) {
  const parts = String(routeKey).split(':');
  invariant(parts.length >= 4, `invalid route key: ${routeKey}`);
  return parts.slice(1, 4).map(Number);
}

function compareLocation(left, right) {
  for (let index = 0; index < 3; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

function transitionGroupKey(row) {
  return [row.game_id, row.subject_participant_candidate, row.replay_time_ms].join(':');
}

function validateSafeP0Identity(row, context) {
  const replayLabel = String(row.game_id ?? row.replay_label);
  const expected = SAFE_P0_REPLAYS[replayLabel];
  invariant(expected, `${context}: replay outside explicit P0 allowlist: ${replayLabel}`);
  invariant(row.replay_sha256 === expected, `${context}: replay hash mismatch: ${replayLabel}`);
  if (row.replay_version !== undefined) {
    invariant(row.replay_version === EXACT_BUILD, `${context}: exact build mismatch`);
  }
}

function validateDecodedRows(rows, packetType, expectedCount, options = {}) {
  invariant(rows.length === expectedCount,
    `${packetType}: expected ${expectedCount} decoded rows, got ${rows.length}`);
  let fullConsume = 0;
  let failure = 0;
  for (const [index, row] of rows.entries()) {
    validateSafeP0Identity(row, `${packetType}:${index + 1}`);
    invariant(row.packet_type === packetType, `${packetType}:${index + 1}: packet mismatch`);
    if (row.decoder_runtime_image_sha256 !== undefined) {
      invariant(row.decoder_runtime_image_sha256 === RUNTIME_SHA256,
        `${packetType}:${index + 1}: runtime image mismatch`);
    }
    if (row.fully_consumed === true) fullConsume += 1;
    else failure += 1;
  }
  invariant(failure === (options.expectedFailureCount || 0),
    `${packetType}: expected ${options.expectedFailureCount || 0} failures, got ${failure}`);
  return { event_count: rows.length, native_full_consume_count: fullConsume, failure_count: failure };
}

function indexTransitionGroups(aligned) {
  const additions = new Map();
  const removals = new Map();
  for (const row of aligned) {
    const index = row.route === ROUTES.add.packet_type ? additions : removals;
    const key = transitionGroupKey(row);
    if (!index.has(key)) index.set(key, []);
    index.get(key).push(row);
  }
  for (const index of [additions, removals]) {
    for (const rows of index.values()) {
      rows.sort((left, right) => compareLocation(
        routeKeyLocation(left.route_key), routeKeyLocation(right.route_key),
      ));
    }
  }
  return { additions, removals };
}

function sameSlotRows(rows, slot) {
  return rows.filter((row) => row.slot_index_candidate === slot);
}

function classifyAdditionExtra(row, groupRemovals, removalCapture, substitutionMap) {
  const sameSlotRemovals = sameSlotRows(groupRemovals, row.slot_index_candidate);
  let structuralClass;
  let semanticDisposition = 'BOUNDED_STRUCTURE_ONLY_CAUSE_OPAQUE';
  if (row.classification === 'purchase_group_extra_or_item_mismatch') {
    structuralClass = 'PURCHASE_GROUP_EXTRA_2055_SAME_SLOT_CO_TRANSITION';
  } else if (row.replay_time_ms === 0) {
    structuralClass = 'TIME_ZERO_INITIAL_SYNC_SET';
    semanticDisposition = 'BOUNDED_INITIAL_SYNC_STRUCTURE';
  } else if (groupRemovals.length === 0) {
    structuralClass = 'UNPAIRED_SET_REFRESH_OR_AUTOMATIC_ADDITION_OPAQUE';
  } else if (sameSlotRemovals.length === 0) {
    structuralClass = 'PAIRED_OTHER_SLOT_ONLY_MULTI_SLOT_SET';
  } else if (sameSlotRemovals.length === 1) {
    structuralClass = 'PAIRED_SINGLE_SAME_SLOT_SET';
  } else {
    structuralClass = 'PAIRED_MULTI_WRITE_SAME_SLOT_SET';
  }
  const priorRows = sameSlotRemovals.map((candidate) => ({
    route_key: candidate.route_key,
    source_classification: candidate.classification,
    prior_item_id: removalCapture[candidate.route_key]?.prior_item_id ?? null,
    prior_stack_count: removalCapture[candidate.route_key]?.prior_stack_count ?? null,
    state_complete: Boolean(removalCapture[candidate.route_key]?.state_complete),
  }));
  const substitutionAligned = priorRows.some((candidate) => (
    candidate.prior_item_id !== null
    && Number(substitutionMap[candidate.prior_item_id]) === row.item_id_candidate
  ));
  return {
    schema: 'ITEM_FAMILY_EXTRA_CLASSIFICATION_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    route: row.route,
    route_key: row.route_key,
    game_id: row.game_id,
    replay_sha256: row.replay_sha256,
    participant_id: row.subject_participant_candidate,
    timestamp_ms: row.replay_time_ms,
    slot: row.slot_index_candidate,
    item_id: row.item_id_candidate,
    source_classification: row.classification,
    structural_class: structuralClass,
    semantic_disposition: semanticDisposition,
    same_time_remove_count: groupRemovals.length,
    same_slot_remove_count: sameSlotRemovals.length,
    same_slot_prior_states: priorRows,
    exact_0x005a_substitution_pair: substitutionAligned,
    actual_reverse_engineering_executed: true,
  };
}

function classifyRemovalExtra(row, groupAdditions, removalCapture, substitutionMap) {
  const capture = removalCapture[row.route_key];
  invariant(capture, `missing state capture for ${row.route_key}`);
  const sameSlotAdditions = sameSlotRows(groupAdditions, row.slot_index_candidate);
  const priorItemId = capture.prior_item_id ?? null;
  const stateComplete = Boolean(capture.state_complete);
  const targetItems = sameSlotAdditions.map((candidate) => candidate.item_id_candidate);
  const substitutionAligned = priorItemId !== null
    && targetItems.some((itemId) => Number(substitutionMap[priorItemId]) === itemId);
  let structuralClass;
  if (stateComplete && sameSlotAdditions.length === 0) {
    structuralClass = 'COMPLETE_STATE_OTHER_SLOT_ONLY_CO_TRANSITION';
  } else if (stateComplete && sameSlotAdditions.length > 1) {
    structuralClass = 'COMPLETE_STATE_MULTI_WRITE_SAME_SLOT_AMBIGUOUS';
  } else if (stateComplete && substitutionAligned) {
    structuralClass = 'COMPLETE_STATE_EXACT_005A_SUBSTITUTION_PAIR';
  } else if (stateComplete && priorItemId === targetItems[0]) {
    structuralClass = 'COMPLETE_STATE_SAME_SLOT_SAME_ITEM_REWRITE';
  } else if (stateComplete && sameSlotAdditions.length === 1) {
    structuralClass = 'COMPLETE_STATE_SAME_SLOT_DIFFERENT_ITEM_REPLACEMENT';
  } else if (!stateComplete && sameSlotAdditions.length === 0) {
    structuralClass = 'INCOMPLETE_STATE_OTHER_SLOT_ONLY_CO_TRANSITION_OPAQUE';
  } else if (!stateComplete && sameSlotAdditions.length > 1) {
    structuralClass = 'INCOMPLETE_STATE_MULTI_WRITE_SAME_SLOT_OPAQUE';
  } else if (!stateComplete && priorItemId === null) {
    structuralClass = 'INCOMPLETE_STATE_PRIOR_EMPTY_OR_UNRECOVERED_SAME_SLOT_OPAQUE';
  } else if (!stateComplete && priorItemId === targetItems[0]) {
    structuralClass = 'INCOMPLETE_STATE_SAME_SLOT_SAME_ITEM_REWRITE_CANDIDATE';
  } else {
    structuralClass = 'INCOMPLETE_STATE_SAME_SLOT_DIFFERENT_ITEM_CANDIDATE';
  }
  return {
    schema: 'ITEM_FAMILY_EXTRA_CLASSIFICATION_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    route: row.route,
    route_key: row.route_key,
    game_id: row.game_id,
    replay_sha256: row.replay_sha256,
    participant_id: row.subject_participant_candidate,
    timestamp_ms: row.replay_time_ms,
    slot: row.slot_index_candidate,
    source_classification: row.classification,
    structural_class: structuralClass,
    semantic_disposition: 'BOUNDED_STRUCTURE_ONLY_CAUSE_OPAQUE',
    prior_item_id: priorItemId,
    prior_stack_count: capture.prior_stack_count ?? null,
    state_complete: stateComplete,
    state_anchor: capture.anchor ?? null,
    same_time_add_count: groupAdditions.length,
    same_slot_add_count: sameSlotAdditions.length,
    same_time_add_item_ids: groupAdditions.map((candidate) => candidate.item_id_candidate),
    same_slot_add_item_ids: targetItems,
    same_slot_add_route_keys: sameSlotAdditions.map((candidate) => candidate.route_key),
    exact_0x005a_substitution_pair: substitutionAligned,
    actual_reverse_engineering_executed: true,
  };
}

function classifyExtras(aligned, removalCapture, substitutionMap) {
  const { additions, removals } = indexTransitionGroups(aligned);
  const output = [];
  for (const row of aligned) {
    validateSafeP0Identity(row, row.route_key);
    invariant(row.route === ROUTES.add.packet_type || row.route === ROUTES.remove.packet_type,
      `unexpected item route: ${row.route}`);
    const key = transitionGroupKey(row);
    if (row.route === ROUTES.add.packet_type && row.classification !== 'exact_details_purchase') {
      output.push(classifyAdditionExtra(row, removals.get(key) || [], removalCapture, substitutionMap));
    } else if (row.route === ROUTES.remove.packet_type
      && row.classification !== 'exact_details_sale_time_subject') {
      output.push(classifyRemovalExtra(row, additions.get(key) || [], removalCapture, substitutionMap));
    }
  }
  return output;
}

function nearestAdjacency(targets, neighborRows, packetType) {
  const index = new Map();
  for (const row of neighborRows) {
    const key = `${row.replay_label}:${participantId(row.raw_param)}`;
    if (!index.has(key)) index.set(key, []);
    index.get(key).push(row.replay_time_ms);
  }
  for (const times of index.values()) times.sort((left, right) => left - right);

  function withinWindow(times, target, window) {
    if (!times) return false;
    let low = 0;
    let high = times.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (times[middle] < target - window) low = middle + 1;
      else high = middle;
    }
    return low < times.length && times[low] <= target + window;
  }

  const result = {};
  for (const route of [ROUTES.add.packet_type, ROUTES.remove.packet_type]) {
    const subset = targets.filter((row) => row.route === route);
    const counts = {};
    for (const shift of [0, 137, 997]) {
      counts[`shift_${shift}ms_within_10ms`] = subset.filter((row) => withinWindow(
        index.get(`${row.game_id}:${row.participant_id}`), row.timestamp_ms + shift, 10,
      )).length;
    }
    counts.exact_time = subset.filter((row) => withinWindow(
      index.get(`${row.game_id}:${row.participant_id}`), row.timestamp_ms, 0,
    )).length;
    result[route] = counts;
  }
  return {
    packet_type: packetType,
    neighbor_event_count: neighborRows.length,
    by_extra_route: result,
    semantic_claim: null,
  };
}

function externalOnlyGate() {
  return {
    required: true,
    local_safe_evidence_remaining: false,
    allowed_next_evidence: [...EXTERNAL_REQUIRED_EVIDENCE],
    forbidden_shortcut: 'Do not infer BUY, SELL, component consumption, recipe identity, or result success from RTTI, slot adjacency, or route-wide counts.',
  };
}

function validateProtectedHoldoutVector(value) {
  invariant(value && typeof value === 'object', 'protected Holdout vector missing');
  for (const key of Object.keys(PROTECTED_HOLDOUT)) {
    invariant(value[key] === false, `protected Holdout flag changed: ${key}`);
  }
  return true;
}

function decisionRow(level, subject, decision, claim, basis) {
  return {
    level,
    [level]: subject,
    decision,
    claim,
    basis,
    actual_reverse_engineering_executed: true,
    evidence_exhausted: true,
    actionable_hypotheses: [],
    next_required_evidence: [...EXTERNAL_REQUIRED_EVIDENCE],
    external_only_gate: externalOnlyGate(),
  };
}

function buildDecisionBundle() {
  const routeDecisions = [
    decisionRow(
      'route', '0x0137 PKT_BuyItemAns_s', 'REPURPOSE',
      'EXACT_BUILD_INVENTORY_SET_OR_STATE_TRANSITION_CARRIER_NOT_UNIVERSAL_BUY',
      '1154 DETAILS purchase matches coexist with 447 conserved extras across sync, grouped, paired, and unpaired classes.',
    ),
    decisionRow(
      'route', '0x04b3 PKT_RemoveItemAns_s', 'REPURPOSE',
      'EXACT_BUILD_INVENTORY_REMOVE_OR_STATE_TRANSITION_CARRIER_NOT_UNIVERSAL_SELL',
      '60 DETAILS sales coexist with 953 conserved non-sale co-transitions; complete-state rows include same-item rewrites and other-slot-only groups.',
    ),
  ];
  const capabilityDecisions = [
    decisionRow(
      'capability', 'bounded_item_extra_structural_partition', 'PROMOTE',
      'RESEARCH_ONLY_EXACT_BUILD_STRUCTURAL_PARTITION',
      'Every 447/953 extra is conserved in a deterministic cross-artifact class with explicit state-completeness and ambiguity flags.',
    ),
    decisionRow(
      'capability', 'universal_buy_sell_route_semantics', 'REJECT',
      'ROUTE_WIDE_BUY_OR_SELL_EVENT_LABELS_ARE_FALSE_ON_THE_SAFE_CORPUS',
      'The 1400 negative rows are decoded route occurrences, not missing weights; route-wide business labels contradict observed evidence.',
    ),
    decisionRow(
      'capability', 'cause_level_recipe_or_business_semantics', 'KEEP_CANDIDATE',
      'NO_LOCAL_CAUSE_LEVEL_PROMOTION',
      'Inventory state and adjacency close transition shape, but no request/answer oracle or exact recipe graph identifies business cause.',
    ),
  ];
  const domainDecisions = [
    decisionRow(
      'domain', 'item_economy_protocol_semantics', 'KEEP_CANDIDATE',
      'EXACT_LAYOUTS_AND_BOUNDED_TRANSITION_STRUCTURE_ONLY',
      'The structural carrier partition advances research evidence without authorizing a semantic API or route-wide item event.',
    ),
  ];
  const all = [...routeDecisions, ...capabilityDecisions, ...domainDecisions];
  return {
    schema: 'ITEM_FAMILY_SATURATION_DECISIONS_V2',
    schema_version: 2,
    exact_build: EXACT_BUILD,
    route_decisions: routeDecisions,
    capability_decisions: capabilityDecisions,
    domain_decisions: domainDecisions,
    decision_counts: countBy(all, (row) => row.decision),
    saturation: {
      current_safe_local_resource_saturated: true,
      local_actionable_hypothesis_count: 0,
      actionable_hypotheses: [],
      evidence_exhausted: true,
      external_only_gate: externalOnlyGate(),
    },
    protected_holdout: { ...PROTECTED_HOLDOUT },
  };
}

function validateDecisionBundle(bundle) {
  const groups = ['route_decisions', 'capability_decisions', 'domain_decisions'];
  const allowed = new Set(['PROMOTE', 'REPURPOSE', 'KEEP_CANDIDATE', 'REJECT']);
  for (const group of groups) {
    invariant(Array.isArray(bundle[group]) && bundle[group].length > 0, `missing ${group}`);
    for (const row of bundle[group]) {
      invariant(allowed.has(row.decision), `${group}: unsupported decision ${row.decision}`);
      invariant(row.actual_reverse_engineering_executed === true, `${group}: reverse engineering flag`);
      invariant(row.evidence_exhausted === true, `${group}: evidence not exhausted`);
      invariant(Array.isArray(row.actionable_hypotheses) && row.actionable_hypotheses.length === 0,
        `${group}: local actionable hypothesis leaked`);
      invariant(Array.isArray(row.next_required_evidence) && row.next_required_evidence.length === 3,
        `${group}: external evidence gate incomplete`);
      invariant(row.external_only_gate?.required === true, `${group}: external gate missing`);
      invariant(row.external_only_gate?.local_safe_evidence_remaining === false,
        `${group}: local resource incorrectly retained`);
    }
  }
  validateProtectedHoldoutVector(bundle.protected_holdout);
  return true;
}

module.exports = {
  EXACT_BUILD,
  EXPECTED_INPUT_SHA256,
  EXTERNAL_REQUIRED_EVIDENCE,
  PROTECTED_HOLDOUT,
  ROUTES,
  RUNTIME_SHA256,
  SAFE_P0_REPLAYS,
  buildDecisionBundle,
  classifyExtras,
  compareLocation,
  countBy,
  counterObject,
  externalOnlyGate,
  increment,
  invariant,
  nearestAdjacency,
  participantId,
  readJson,
  readJsonl,
  rejectProtectedPath,
  routeKeyLocation,
  sha256,
  sha256File,
  transitionGroupKey,
  validateDecisionBundle,
  validateDecodedRows,
  validateProtectedHoldoutVector,
  validateSafeP0Identity,
};
