'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { decisionIdentity } = require('./deep_recovery_decision_ledger');

const EXACT_BUILD = '16.16.805.0442';
const SCHEMA = 'ROFL_SEMANTIC_CAPABILITY_DOMAIN_CLOSURE_V2';

const HIGH_VALUE_DOMAINS = Object.freeze([
  'state', 'combat', 'protection', 'buff', 'spell', 'missile', 'entity', 'item',
  'economy', 'minion', 'jungle', 'objective', 'structure', 'vision', 'movement', 'map',
]);

const SOURCE_BY_DOMAIN = Object.freeze({
  state: ['hero_state'],
  combat: ['hero_state', 'buff_spell'],
  protection: ['buff_spell'],
  buff: ['buff_spell'],
  spell: ['buff_spell', 'named_gameplay'],
  missile: ['buff_spell', 'gameplay_tail'],
  entity: ['entity_item'],
  item: ['item_family'],
  economy: ['hero_stats', 'item_family'],
  minion: ['entity_item', 'named_gameplay'],
  jungle: ['entity_item', 'named_gameplay'],
  objective: ['entity_item'],
  structure: ['residual_p7'],
  vision: ['ward'],
  movement: ['gameplay_tail', 'named_gameplay'],
  map: ['gameplay_tail'],
});

const DEFAULT_SOURCE_SPECS = Object.freeze([
  ['decision_ledger', 'artifacts/full_semantic_deep_recovery_v2/decision_ledger/decision_ledger.json'],
  ['hero_state', 'artifacts/full_semantic_deep_recovery_v2/hero_state/hero_state_damage_defense_deep_report_16_16.json'],
  ['buff_spell', 'artifacts/full_semantic_deep_recovery_v2/buff_spell/PROMOTION_MATRIX.json'],
  ['entity_item', 'artifacts/full_semantic_deep_recovery_v2/entity_item/entity_item_deep_recovery_summary_16_16.json'],
  ['hero_stats', 'artifacts/full_semantic_baseline_v1/hero_stats/hero_stats_scoreboard_validation_16_16.json'],
  ['ward', 'artifacts/16_16_ward_semantic_recovery_v1/runtime/ward_validation_summary.json'],
  ['gameplay_tail', 'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/gameplay_route_tail_audit_16_16.json'],
  ['named_gameplay', 'artifacts/full_semantic_deep_recovery_v2/named_gameplay_wave/named_gameplay_wave_decisions_16_16.json'],
  ['residual_p7', 'artifacts/full_semantic_deep_recovery_v2/residual_p7_wave/residual_p7_wave_machine_decisions_16_16.json'],
  ['item_family', 'artifacts/full_semantic_deep_recovery_v2/item_family_saturation/item_family_saturation_decisions_16_16.json'],
]);

const SOURCE_SCHEMA_CONTRACTS = Object.freeze({
  decision_ledger: Object.freeze(['ROFL_DEEP_RECOVERY_DECISION_LEDGER_V1']),
  hero_state: Object.freeze(['ROFL_FULL_SEMANTIC_DEEP_RECOVERY_HERO_STATE_DAMAGE_DEFENSE_V2']),
  buff_spell: Object.freeze(['ROFL_FULL_SEMANTIC_DEEP_RECOVERY_V2_BUFF_SPELL_PROMOTION_MATRIX_V1']),
  entity_item: Object.freeze(['ENTITY_ITEM_DEEP_RECOVERY_V2']),
  hero_stats: Object.freeze(['ROFL_16_16_HERO_STATS_SCOREBOARD_VALIDATION_V1']),
  ward: Object.freeze(['WARD_VALIDATION_SUMMARY_LEGACY_V1']),
  gameplay_tail: Object.freeze(['GAMEPLAY_ROUTE_TAIL_SATURATION_AUDIT_V2']),
  named_gameplay: Object.freeze(['ROFL_NAMED_GAMEPLAY_WAVE_DECISIONS_V1']),
  residual_p7: Object.freeze(['RESIDUAL_P7_WAVE_MACHINE_DECISIONS_V2']),
  item_family: Object.freeze(['ITEM_FAMILY_SATURATION_DECISIONS_V2']),
});

const CAPABILITY_DOMAINS = Object.freeze({
  ABILITY_POWER: 'state',
  ATTACK_DAMAGE: 'combat',
  ATTACK_SPEED: 'state',
  CAMP_CLEAR: 'jungle',
  CAMP_STATE: 'jungle',
  CS: 'economy',
  CURRENT_MANA: 'state',
  DAMAGE_MITIGATION: 'protection',
  DAMAGE_SOURCE_ATTRIBUTION: 'combat',
  DAMAGE_STAGE: 'combat',
  DEBUFF: 'buff',
  GOLD: 'economy',
  HEAL_EFFECTIVE: 'protection',
  HERO_ASSIST: 'combat',
  HERO_KILL_CREDIT: 'combat',
  ITEM_BUY: 'item',
  ITEM_DESTROY: 'item',
  ITEM_SELL: 'item',
  ITEM_STATE: 'item',
  ITEM_TRANSFORM: 'item',
  ITEM_UNDO: 'item',
  JUNGLE_MONSTER_LIFECYCLE: 'jungle',
  LANE_MINION_LIFECYCLE: 'minion',
  MANA: 'state',
  MAP_MECHANIC: 'map',
  MAX_MANA: 'state',
  MOVEMENT_SPECIAL: 'movement',
  MOVE_SPEED: 'state',
  NPC_CLASSIFICATION: 'entity',
  NPC_DEATH: 'combat',
  NPC_DESPAWN: 'entity',
  NPC_SPAWN: 'entity',
  OBJECTIVE: 'objective',
  OVERHEAL: 'protection',
  PASSIVE_PROC: 'spell',
  PASSIVE_STATE: 'spell',
  RUNE_PROC: 'spell',
  RUNE_STATE: 'spell',
  SHIELD_ABSORBED: 'protection',
  SHIELD_LIFECYCLE: 'protection',
  SHIELD_REMAINING: 'protection',
  STRUCTURE: 'structure',
  SUMMONER_CAST: 'spell',
  SUMMONER_SPELL_STATE: 'spell',
  SWEEPER: 'vision',
  TEMPORARY_HP: 'state',
  TEMPORARY_STATS: 'state',
  VISIBILITY_STATE: 'vision',
  WARD_LIFECYCLE: 'vision',
});

const GROUPS = Object.freeze({
  live_hero_scalar: Object.freeze({
    capabilities: Object.freeze([
      'ABILITY_POWER', 'ATTACK_SPEED', 'CURRENT_MANA', 'MANA', 'MAX_MANA',
      'MOVE_SPEED', 'TEMPORARY_HP', 'TEMPORARY_STATS', 'ATTACK_DAMAGE',
    ]),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'No current safe exact-build route survived as a universal live hero scalar carrier.',
    next: Object.freeze([
      'A governed controlled exact-build stat toggle with a sub-second independent state oracle.',
      'A receive-side plaintext consumer trace that identifies the field role rather than only its protected value.',
    ]),
  }),
  damage_attribution: Object.freeze({
    capabilities: Object.freeze(['DAMAGE_SOURCE_ATTRIBUTION']),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'Source entity and numeric protocol keys are direct, but basic/spell/passive/item/rune/on-hit/DoT roles are not independently identified.',
    next: Object.freeze([
      'Controlled one-action exact-build casts/attacks/items/runes with an independent script-key dictionary and negative controls.',
    ]),
  }),
  damage_stage: Object.freeze({
    capabilities: Object.freeze(['DAMAGE_STAGE', 'DAMAGE_MITIGATION']),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'Recorded damage is direct, but pre/post-mitigation and effective-HP-loss stages remain unproved.',
    next: Object.freeze([
      'Same-timestamp pre/post HP plus Armor/MR, shield, heal, and raw-input anchors from a controlled exact-build case.',
    ]),
  }),
  kill_assist: Object.freeze({
    capabilities: Object.freeze(['HERO_ASSIST', 'HERO_KILL_CREDIT']),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'Hero death exposes verified victim/killer identity, but tested scalar, mask, and fixed-triplet assist/credit interpretations have counterexamples.',
    next: Object.freeze([
      'A controlled exact-build multi-assist oracle plus a plaintext consumer or a separately registered assist/credit route.',
    ]),
  }),
  protection_effectiveness: Object.freeze({
    capabilities: Object.freeze([
      'HEAL_EFFECTIVE', 'OVERHEAL', 'SHIELD_ABSORBED', 'SHIELD_LIFECYCLE',
      'SHIELD_REMAINING',
    ]),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'Reported/gross heal and generated/application shield amounts are bounded; effective, overheal, absorbed, remaining, and instance lifecycle are not.',
    next: Object.freeze([
      'Controlled exact-build pre/post HP and shield-instance instrumentation with simultaneous damage/heal negative controls.',
    ]),
  }),
  buff_category: Object.freeze({
    capabilities: Object.freeze(['DEBUFF']),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'Buff operation carriers are recovered, but hash-to-category and universal stack/duration roles are not independently verified.',
    next: Object.freeze([
      'A governed buff dictionary or controlled add/update/remove capture with plaintext stack and expiry instrumentation.',
    ]),
  }),
  spell_specialization: Object.freeze({
    capabilities: Object.freeze([
      'PASSIVE_PROC', 'PASSIVE_STATE', 'RUNE_PROC', 'RUNE_STATE', 'SUMMONER_CAST',
      'SUMMONER_SPELL_STATE',
    ]),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'Cast and spell-state protocol carriers are recovered, but passive/rune/summoner classification is not established by numeric keys alone.',
    next: Object.freeze([
      'Controlled exact-build per-slot passive/rune/summoner toggles plus a version-pinned spell/script dictionary.',
    ]),
  }),
  item_operation: Object.freeze({
    capabilities: Object.freeze([
      'ITEM_BUY', 'ITEM_SELL', 'ITEM_UNDO', 'ITEM_TRANSFORM', 'ITEM_DESTROY',
    ]),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'Inventory transition and snapshot routes are structurally recovered, but route extras and cause ambiguity prevent universal operation naming.',
    next: Object.freeze([
      'Controlled exact-build one-operation inventory traces with request/answer correlation, full before/after state, and recipe/substitution provenance.',
    ]),
  }),
  item_snapshot: Object.freeze({
    capabilities: Object.freeze(['ITEM_STATE']),
    decision: 'PROMOTE',
    conclusion: 'Exact snapshot/set fields are published for successful rows; 154 complex 0x0311 rows remain explicitly conserved as failures.',
    next: Object.freeze([
      'An authorized live heap/TLS capture or new runtime image that closes the 154 external-state-dependent 0x0311 rows.',
    ]),
  }),
  scoreboard_gold: Object.freeze({
    capabilities: Object.freeze(['GOLD']),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'The total-gold float is a near-exact cumulative candidate; current gold, gain, and spend events are not verified.',
    next: Object.freeze([
      'Controlled exact-build purchases and passive-gold ticks with exact current/total-gold ground truth at packet cadence.',
    ]),
  }),
  scoreboard_cs: Object.freeze({
    capabilities: Object.freeze(['CS']),
    decision: 'PROMOTE',
    conclusion: 'Cumulative lane CS is verified direct at keyframe cadence; jungle and combined CS remain candidate/unavailable.',
    next: Object.freeze([
      'A controlled exact-build lane/jungle last-hit oracle is required for event timing and jungle/combined CS.',
    ]),
  }),
  npc_identity_lifecycle: Object.freeze({
    capabilities: Object.freeze(['NPC_CLASSIFICATION', 'NPC_SPAWN', 'NPC_DEATH', 'NPC_DESPAWN']),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'The safe corpus exposes structural entity/lifecycle carriers but no independently labeled general NPC identity lifecycle.',
    next: Object.freeze([
      'A governed controlled exact-build replay with independently labeled NPC templates, spawn, death, and despawn timestamps.',
    ]),
  }),
  vision_residual: Object.freeze({
    capabilities: Object.freeze(['SWEEPER', 'VISIBILITY_STATE']),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'Ward spawn and conservative observed-end semantics are published; held/activation intervals and generic visibility state are not.',
    next: Object.freeze([
      'Controlled exact-build trinket swaps and sweeper activations with owner, interval, and position ground truth.',
    ]),
  }),
  ward_lifecycle: Object.freeze({
    capabilities: Object.freeze(['WARD_LIFECYCLE']),
    decision: 'PROMOTE',
    conclusion: 'Conservative direct-spawn/corpse observed ends are published; removal reason remains UNKNOWN.',
    next: Object.freeze([
      'Controlled expiration, destruction, replacement, and sweeper cases to identify end reasons without inference.',
    ]),
  }),
  movement_special: Object.freeze({
    capabilities: Object.freeze(['MOVEMENT_SPECIAL']),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'Several bounded movement protocol events are recovered, but the umbrella capability has no universal operation taxonomy.',
    next: Object.freeze([
      'Controlled exact-build dash, knockback, turn-lock, stop, and movement-driver cases with plaintext consumer traces.',
    ]),
  }),
  lane_minion: Object.freeze({
    capabilities: Object.freeze(['LANE_MINION_LIFECYCLE']),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'A basic-attack minion-position carrier and lane-CS snapshots do not establish minion identity or lifecycle.',
    next: Object.freeze([
      'Controlled exact-build wave spawns with independently labeled minion network IDs and death/despawn timestamps.',
    ]),
  }),
  jungle: Object.freeze({
    capabilities: Object.freeze(['CAMP_CLEAR', 'CAMP_STATE', 'JUNGLE_MONSTER_LIFECYCLE']),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'No safe current input independently labels ordinary monsters or camp lifecycle; spatial contact is not a clear.',
    next: Object.freeze([
      'A newly governed, non-Holdout controlled replay with labeled monster identities, resets, deaths, respawns, and camp transitions.',
    ]),
  }),
  objective: Object.freeze({
    capabilities: Object.freeze(['OBJECTIVE']),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'Runtime/entity surfaces were searched, but the safe corpus provides no independent objective identity/lifecycle oracle.',
    next: Object.freeze([
      'A newly governed, non-Holdout controlled replay with labeled objective spawn, damage, death, team credit, and consequence state.',
    ]),
  }),
  structure: Object.freeze({
    capabilities: Object.freeze(['STRUCTURE']),
    decision: 'KEEP_CANDIDATE',
    conclusion: 'Named structure carriers do not by themselves prove stable structure identity, HP state, or destruction semantics.',
    next: Object.freeze([
      'Controlled exact-build turret/plate/inhibitor/Nexus cases with independent entity IDs, state changes, and destruction timestamps.',
    ]),
  }),
  map: Object.freeze({
    capabilities: Object.freeze(['MAP_MECHANIC']),
    decision: 'REJECT',
    conclusion: 'Protocol coordinates/components do not authorize strategic map truth; map knowledge is owned outside the Parser.',
    next: Object.freeze([
      'A versioned Map Knowledge artifact and QA provenance from the owning Inference Lab, not a Parser route guess.',
    ]),
  }),
});

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasCleanHoldoutBoundary(boundary) {
  if (!isPlainObject(boundary)) return false;
  const keys = ['enumerated', 'read', 'hashed', 'decoded', 'tested', 'consumed'];
  return Object.keys(boundary).length === keys.length
    && keys.every((operation) => Object.prototype.hasOwnProperty.call(boundary, operation)
      && boundary[operation] === false);
}

function assertNoProtectedPath(value, label = 'path') {
  invariant(typeof value === 'string' && value.length > 0, `${label} must be a non-empty string`);
  invariant(!/holdout/i.test(value), `${label} resolves through a protected Holdout path`);
}

function pathIsInside(root, target) {
  const relative = path.relative(root, target);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function canonicalizeNearestExisting(target) {
  let cursor = path.resolve(target);
  const suffix = [];
  while (!fs.existsSync(cursor)) {
    const parent = path.dirname(cursor);
    invariant(parent !== cursor, `no existing ancestor for ${target}`);
    suffix.unshift(path.basename(cursor));
    cursor = parent;
  }
  return path.join(fs.realpathSync.native(cursor), ...suffix);
}

function safeResolvedPath(root, target, { label = 'path', mustExist = false } = {}) {
  assertNoProtectedPath(String(root), 'root');
  assertNoProtectedPath(String(target), label);
  const resolvedRoot = path.resolve(String(root));
  const resolvedTarget = path.resolve(resolvedRoot, String(target));
  assertNoProtectedPath(resolvedRoot, 'resolved root');
  assertNoProtectedPath(resolvedTarget, `resolved ${label}`);
  invariant(pathIsInside(resolvedRoot, resolvedTarget), `${label} must remain inside the workspace root`);

  const realRoot = canonicalizeNearestExisting(resolvedRoot);
  const realTarget = canonicalizeNearestExisting(resolvedTarget);
  assertNoProtectedPath(realRoot, 'canonical root');
  assertNoProtectedPath(realTarget, `canonical ${label}`);
  invariant(pathIsInside(realRoot, realTarget), `${label} canonical target escapes the workspace root`);
  invariant(!mustExist || fs.existsSync(resolvedTarget), `${label} does not exist`);
  return {
    absolutePath: resolvedTarget,
    relativePath: path.relative(resolvedRoot, resolvedTarget).replaceAll('\\', '/'),
    rootPath: resolvedRoot,
  };
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function capabilityRuleMap() {
  const map = new Map();
  for (const [group, rule] of Object.entries(GROUPS)) {
    for (const capability of rule.capabilities) {
      invariant(!map.has(capability), `duplicate closure rule for ${capability}`);
      invariant(CAPABILITY_DOMAINS[capability], `missing expected domain for ${capability}`);
      map.set(capability, { group, expectedDomain: CAPABILITY_DOMAINS[capability], ...rule });
    }
  }
  invariant(map.size === Object.keys(CAPABILITY_DOMAINS).length,
    'closure rule set and capability-domain contract must be identical');
  return map;
}

function sourceExactBuild(id, document) {
  const candidate = document.exact_build ?? document.build ?? document.game_version;
  invariant(candidate === EXACT_BUILD, `${id} must attest exact build ${EXACT_BUILD}`);
  invariant(document.exact_build_only !== false, `${id} cannot disable exact-build-only semantics`);
  invariant(document.nearest_build_fallback !== 'ALLOWED', `${id} cannot allow nearest-build fallback`);
  return candidate;
}

function sourceSchema(id, document) {
  if (id === 'ward') {
    invariant(document.schema === undefined || document.schema === null,
      'ward legacy source unexpectedly changed schema identity');
    invariant(document.schema_version === 1
      && document.task_status === '16_16_WARD_SEMANTIC_RECOVERY_V1_COMPLETE',
    'ward legacy source contract mismatch');
    return 'WARD_VALIDATION_SUMMARY_LEGACY_V1';
  }
  invariant(typeof document.schema === 'string', `${id} source schema is required`);
  invariant(SOURCE_SCHEMA_CONTRACTS[id]?.includes(document.schema),
    `${id} source schema is not allowlisted: ${document.schema}`);
  return document.schema;
}

function decisionArrays(document) {
  const nested = isPlainObject(document.decisions) ? document.decisions : {};
  return {
    routes: document.route_decisions ?? nested.route_decisions ?? [],
    capabilities: document.capability_decisions ?? nested.capability_decisions ?? [],
    domains: document.domain_decisions ?? nested.domain_decisions ?? [],
  };
}

function allMachineRowsClosed(rows) {
  return Array.isArray(rows) && rows.length > 0 && rows.every((row) =>
    row.actual_reverse_engineering_executed === true
    && row.evidence_exhausted === true
    && Array.isArray(row.actionable_hypotheses)
    && row.actionable_hypotheses.length === 0);
}

function assertNoNegativeMachineRows(document, id) {
  const arrays = decisionArrays(document);
  for (const [kind, rows] of Object.entries(arrays)) {
    invariant(Array.isArray(rows), `${id} ${kind} machine rows must be an array`);
    for (const [index, row] of rows.entries()) {
      const label = `${id} ${kind}[${index}]`;
      const machineRow = Object.prototype.hasOwnProperty.call(
        row, 'actual_reverse_engineering_executed',
      ) || Object.prototype.hasOwnProperty.call(row, 'actual_reverse_engineering')
        || Object.prototype.hasOwnProperty.call(row, 'actionable_hypotheses');
      if (!machineRow) continue;
      invariant(row.actual_reverse_engineering_executed !== false
        && row.actual_reverse_engineering !== false,
      `${label} explicitly denies actual reverse engineering`);
      invariant(row.evidence_exhausted !== false,
        `${label} explicitly denies evidence exhaustion`);
      invariant(!Array.isArray(row.actionable_hypotheses)
        || row.actionable_hypotheses.length === 0,
      `${label} retains actionable hypotheses`);
    }
  }
}

function assertNoProtectedAccessClaim(value, trail = 'source') {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoProtectedAccessClaim(entry, `${trail}[${index}]`));
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    const nextTrail = `${trail}.${key}`;
    const sensitive = /holdout/i.test(key)
      || /protected.*(?:read|enumerat|hash|decode|test|consume|access)/i.test(key);
    invariant(!(sensitive && entry === true), `${nextTrail} reports protected evidence access`);
    assertNoProtectedAccessClaim(entry, nextTrail);
  }
}

function validateResearchSource(id, document) {
  assertNoProtectedAccessClaim(document, id);
  // A summary/status/count is never allowed to erase an explicit negative
  // machine decision. Older neutral rows may omit these fields, but an explicit
  // false or non-empty hypothesis fails closed unless a later, hash-bound
  // closure supersedes that exact ledger decision (which is consumed as the
  // decision_ledger source, not by mutating this historical source).
  if (id !== 'decision_ledger') assertNoNegativeMachineRows(document, id);
  const arrays = decisionArrays(document);
  let actual = false;
  let exhausted = false;
  let hypotheses = [];

  if (id === 'decision_ledger') {
    invariant(document.schema === 'ROFL_DEEP_RECOVERY_DECISION_LEDGER_V1'
      && Array.isArray(document.route_decisions)
      && Array.isArray(document.capability_decisions)
      && Array.isArray(document.domain_decisions),
    'decision ledger source contract mismatch');
    actual = true;
    exhausted = true;
  } else if (id === 'hero_state') {
    actual = document.project_context_loaded === true
      && document.architecture_gate === 'PASS'
      && Array.isArray(document.route_decisions)
      && document.route_decisions.length >= 18;
    exhausted = document.status === 'SATURATED_NO_PERSISTENT_STATE_PROMOTION'
      && Array.isArray(document.exhausted_search_space)
      && document.exhausted_search_space.length > 0;
  } else if (id === 'buff_spell') {
    actual = document.project_context_loaded === true
      && document.architecture_gate === 'PASS'
      && Array.isArray(document.promotions)
      && document.promotions.length >= 5
      && Array.isArray(document.rejections)
      && document.rejections.length > 0;
    exhausted = document.status === 'SATURATED_WITH_RESEARCH_ONLY_PROMOTIONS_AND_BOUNDED_UNKNOWNS'
      && Array.isArray(document.exhausted_or_bounded_absence)
      && document.exhausted_or_bounded_absence.length > 0;
  } else if (id === 'entity_item') {
    const generic = arrays.domains.find((row) => row.domain === 'generic_entity_semantics');
    actual = document.project_context_loaded === true
      && document.architecture_gate === 'PASS'
      && arrays.routes.length >= 10;
    exhausted = generic?.evidence_exhausted === true
      && generic?.decision === 'REJECT'
      && generic?.scope === 'NO_GENERIC_CREATE_OR_OWNER_TEAM_CLASS_EVENT';
  } else if (id === 'hero_stats') {
    actual = document.status === 'PASS'
      && document.decoded_packet_count > 0
      && document.matched_count > 0
      && isPlainObject(document.fields);
    exhausted = document.unmatched_packet_count >= 0
      && Array.isArray(document.comparison_rows)
      && document.comparison_rows.length === document.matched_count;
  } else if (id === 'ward') {
    actual = document.status === 'PASS'
      && document.task_status === '16_16_WARD_SEMANTIC_RECOVERY_V1_COMPLETE'
      && document.runtime_image_sha256_verified === true;
    exhausted = document.full_consume_rate === 1
      && document.acceptance_gates
      && Object.values(document.acceptance_gates).every((value) => value === true);
  } else if (id === 'gameplay_tail') {
    actual = document.project_context_loaded === true
      && document.architecture_gate === 'PASS'
      && arrays.routes.length > 0
      && allMachineRowsClosed(arrays.domains);
    exhausted = document.saturation?.current_local_evidence_saturated === true
      && allMachineRowsClosed(arrays.domains);
    hypotheses = arrays.domains.flatMap((row) => row.actionable_hypotheses ?? []);
  } else if (['named_gameplay', 'residual_p7', 'item_family'].includes(id)) {
    actual = allMachineRowsClosed(arrays.routes);
    exhausted = allMachineRowsClosed(arrays.routes)
      && allMachineRowsClosed(arrays.capabilities)
      && allMachineRowsClosed(arrays.domains);
    hypotheses = [...arrays.routes, ...arrays.capabilities, ...arrays.domains]
      .flatMap((row) => row.actionable_hypotheses ?? []);
  }

  invariant(actual === true, `${id} does not prove actual reverse engineering`);
  invariant(exhausted === true, `${id} does not prove current local evidence exhaustion`);
  invariant(Array.isArray(hypotheses) && hypotheses.length === 0,
    `${id} retains actionable hypotheses`);
  return {
    actual_reverse_engineering_executed: actual,
    evidence_exhausted: exhausted,
    actionable_hypotheses: hypotheses,
  };
}

function readSafeJsonBytes(root, sourcePath, label = 'JSON source') {
  const resolved = safeResolvedPath(root, sourcePath, { label, mustExist: true });
  const bytes = fs.readFileSync(resolved.absolutePath);
  return {
    bytes,
    document: JSON.parse(bytes.toString('utf8')),
    path: resolved.relativePath,
    sha256: sha256(bytes),
    byte_count: bytes.length,
  };
}

function loadSources(root, specs = DEFAULT_SOURCE_SPECS, { preloaded = {} } = {}) {
  invariant(Array.isArray(specs) && specs.length > 0, 'source specs must be a non-empty array');
  const seen = new Set();
  return Object.fromEntries(specs.map(([id, sourcePath]) => {
    invariant(SOURCE_SCHEMA_CONTRACTS[id], `unknown source contract ${id}`);
    invariant(!seen.has(id), `duplicate source id ${id}`);
    seen.add(id);
    const loaded = preloaded[id] ?? readSafeJsonBytes(root, sourcePath, `${id} source`);
    invariant(Buffer.isBuffer(loaded.bytes) && isPlainObject(loaded.document),
      `${id} preloaded source must retain exact bytes and parsed document`);
    const bytes = loaded.bytes;
    const document = loaded.document;
    invariant(sha256(bytes) === loaded.sha256 && bytes.length === loaded.byte_count,
      `${id} preloaded source bytes do not match its pinned metadata`);
    assertNoProtectedPath(loaded.path, `${id} preloaded source path`);
    invariant(document.schema !== SCHEMA, `${id} source would create closure provenance cycle`);
    const schema = sourceSchema(id, document);
    const exactBuild = sourceExactBuild(id, document);
    const attestation = validateResearchSource(id, document);
    return [id, {
      id,
      path: loaded.path.replaceAll('\\', '/'),
      sha256: sha256(bytes),
      byte_count: bytes.length,
      schema,
      schema_version: document.schema_version ?? 1,
      exact_build: exactBuild,
      bytes,
      document,
      attestation,
    }];
  }));
}

function closureMarker(value) {
  return typeof value === 'string'
    && (/semantic[_-].*saturation[_-]closure/i.test(value)
      || /semantic[_-]capability[_-]domain[_-]closure/i.test(value)
      || value === SCHEMA);
}

function assertPreclosureLedger(ledger) {
  invariant(ledger?.schema === 'ROFL_DEEP_RECOVERY_DECISION_LEDGER_V1',
    'ledger schema must be ROFL_DEEP_RECOVERY_DECISION_LEDGER_V1');
  invariant(ledger.schema_version === 1, 'ledger schema_version must be 1');
  invariant(ledger.exact_build === EXACT_BUILD, `ledger must target exact build ${EXACT_BUILD}`);
  invariant(ledger.exact_build_only === true, 'ledger must be exact-build-only');
  invariant(ledger.nearest_build_fallback === 'FORBIDDEN', 'ledger nearest-build fallback must be forbidden');
  invariant(Array.isArray(ledger.input_sources)
    && Array.isArray(ledger.route_decisions)
    && Array.isArray(ledger.capability_decisions)
    && Array.isArray(ledger.domain_decisions),
  'ledger decision arrays are required');
  const boundaryKeys = [
    'jungle_objective_fixture_enumerated',
    'jungle_objective_fixture_read',
    'jungle_objective_fixture_hashed',
    'jungle_objective_fixture_decoded',
    'jungle_objective_fixture_tested',
    'jungle_objective_fixture_consumed',
  ];
  invariant(isPlainObject(ledger.protected_evidence_boundary)
    && Object.keys(ledger.protected_evidence_boundary).length === boundaryKeys.length
    && boundaryKeys.every((key) => Object.prototype.hasOwnProperty.call(
      ledger.protected_evidence_boundary, key,
    ) && ledger.protected_evidence_boundary[key] === false),
    'ledger protected evidence boundary must be clean');

  const provenanceRows = [
    ...ledger.input_sources,
    ...ledger.route_decisions.flatMap((row) => row.decision_history ?? []),
    ...ledger.capability_decisions.flatMap((row) => row.decision_history ?? []),
    ...ledger.domain_decisions.flatMap((row) => row.decision_history ?? []),
  ];
  invariant(!provenanceRows.some((row) => {
    const provenance = row?.provenance ?? row ?? {};
    return [
      provenance.source_id,
      provenance.source_schema,
      provenance.schema,
      provenance.artifact,
      provenance.path,
    ].some(closureMarker);
  }), 'closure must consume a pre-closure ledger without aliased closure provenance');
}

function assertQueue(queue) {
  invariant(queue?.schema === 'SEMANTIC_RESEARCH_QUEUE_V2',
    'queue schema must be SEMANTIC_RESEARCH_QUEUE_V2');
  invariant(queue.schema_version === 2, 'queue schema_version must be 2');
  invariant(queue.exact_build === EXACT_BUILD, `queue must target exact build ${EXACT_BUILD}`);
  invariant(queue.exact_build_only === true, 'queue must be exact-build-only');
  invariant(queue.nearest_build_fallback === 'FORBIDDEN', 'queue nearest-build fallback must be forbidden');
  invariant(Array.isArray(queue.route_queue) && Array.isArray(queue.capability_queue),
    'queue route_queue and capability_queue arrays are required');
  invariant(queue.route_queue.every((row) => typeof row.actionable === 'boolean')
    && queue.capability_queue.every((row) => typeof row.actionable === 'boolean'),
  'every queue actionable field must be boolean');
  invariant(hasCleanHoldoutBoundary(queue.protected_holdout),
    'queue Holdout boundary must be explicitly clean');

  const activeRoutes = queue.route_queue.filter((row) => row.actionable);
  const activeCapabilities = queue.capability_queue.filter((row) => row.actionable);
  invariant(isPlainObject(queue.summary), 'queue summary is required');
  invariant(queue.summary.route_row_count === queue.route_queue.length,
    'queue summary route row count mismatch');
  invariant(queue.summary.actionable_route_count === activeRoutes.length,
    'queue summary actionable route count mismatch');
  invariant(queue.summary.capability_row_count === queue.capability_queue.length,
    'queue summary capability row count mismatch');
  invariant(queue.summary.actionable_capability_count === activeCapabilities.length,
    'queue summary actionable capability count mismatch');
  invariant(activeRoutes.length === 0,
    `capability closure cannot precede route exhaustion: ${activeRoutes.length} actionable routes remain`);

  const rules = capabilityRuleMap();
  invariant(activeCapabilities.length === rules.size,
    `active capability set must contain exactly ${rules.size} rows`);
  const names = activeCapabilities.map((row) => row.semantic_capability);
  invariant(new Set(names).size === names.length, 'active capability rows must be unique');
  const expected = [...rules.keys()].sort();
  const observed = [...names].sort();
  invariant(stableStringify(observed) === stableStringify(expected),
    'active capability set must exactly match the 49-capability closure contract');
  for (const row of activeCapabilities) {
    const rule = rules.get(row.semantic_capability);
    invariant(row.domain === rule.expectedDomain,
      `${row.semantic_capability} must remain in expected domain ${rule.expectedDomain}`);
  }
  return { activeRoutes, activeCapabilities, rules };
}

function publicSource(source) {
  invariant(source && isPlainObject(source.document) && isPlainObject(source.attestation),
    `source ${source?.id ?? 'UNKNOWN'} must retain its validated document and attestation`);
  return {
    id: source.id,
    path: source.path,
    sha256: source.sha256,
    byte_count: source.byte_count,
    schema: source.schema,
    schema_version: source.schema_version,
    exact_build: source.exact_build,
    attestation: { ...source.attestation },
  };
}

function domainEvidence(domain, sources) {
  const sourceIds = SOURCE_BY_DOMAIN[domain];
  invariant(Array.isArray(sourceIds) && sourceIds.length > 0,
    `domain ${domain} has no source attestation contract`);
  const evidenceSources = sourceIds.map((id) => {
    invariant(sources[id], `required domain source ${id} is missing`);
    invariant(sources[id].attestation.actual_reverse_engineering_executed === true,
      `${id} does not attest actual reverse engineering for ${domain}`);
    invariant(sources[id].attestation.evidence_exhausted === true,
      `${id} does not attest current local exhaustion for ${domain}`);
    invariant(Array.isArray(sources[id].attestation.actionable_hypotheses)
      && sources[id].attestation.actionable_hypotheses.length === 0,
    `${id} retains actionable hypotheses for ${domain}`);
    return publicSource(sources[id]);
  });
  return {
    actual_reverse_engineering_executed: evidenceSources.every((row) =>
      row.attestation.actual_reverse_engineering_executed),
    evidence_exhausted: evidenceSources.every((row) => row.attestation.evidence_exhausted),
    actionable_hypotheses: evidenceSources.flatMap((row) => row.attestation.actionable_hypotheses),
    evidence_sources: evidenceSources,
  };
}

function assertValidatedSources(sources) {
  invariant(isPlainObject(sources), 'validated source map is required');
  const requiredIds = DEFAULT_SOURCE_SPECS.map(([id]) => id).sort();
  invariant(stableStringify(Object.keys(sources).sort()) === stableStringify(requiredIds),
    'source map must exactly match the explicit safe source contract');
  for (const id of requiredIds) {
    const source = sources[id];
    invariant(Buffer.isBuffer(source.bytes), `${id} must retain its exact source bytes`);
    invariant(sha256(source.bytes) === source.sha256 && source.bytes.length === source.byte_count,
      `${id} source bytes do not match pinned provenance`);
    const schema = sourceSchema(id, source.document);
    const exactBuild = sourceExactBuild(id, source.document);
    const attestation = validateResearchSource(id, source.document);
    invariant(source.schema === schema && source.exact_build === exactBuild,
      `${id} retained source identity is inconsistent`);
    invariant(stableStringify(source.attestation) === stableStringify(attestation),
      `${id} retained attestation is inconsistent with its source document`);
  }
}

function activeDecisionIds(kind, key, rows) {
  const keyField = kind === 'capability' ? 'semantic_capability' : 'domain';
  const record = rows.find((row) => row[keyField] === key);
  if (!record) return [];
  const histories = record.decision_history ?? [];
  invariant(Array.isArray(histories), `${kind} ${key} decision history must be an array`);
  const effective = histories.filter((row) => row.effective !== false && !row.superseded_by);
  invariant(effective.every((row) => /^[0-9a-f]{64}$/.test(row.decision_id ?? '')),
    `${kind} ${key} effective history must carry stable decision_id values`);
  return effective.map((row) => row.decision_id).sort();
}

function supersession(kind, key, rows, ledgerSha256) {
  const decisionIds = activeDecisionIds(kind, key, rows);
  if (decisionIds.length === 0) {
    return { supersedes_previous_decision: false, supersedes: null };
  }
  return {
    supersedes_previous_decision: true,
    supersedes: {
      preclosure_ledger_sha256: ledgerSha256,
      decision_kind: kind,
      decision_key: key,
      superseded_decision_ids: decisionIds,
    },
  };
}

function validatePinnedInput(input, document, label) {
  invariant(isPlainObject(input) && Buffer.isBuffer(input.bytes),
    `${label} exact input bytes are required`);
  invariant(input.document === document, `${label} parsed object must come from the pinned bytes`);
  invariant(sha256(input.bytes) === input.sha256 && input.bytes.length === input.byte_count,
    `${label} bytes do not match pinned SHA-256 provenance`);
  invariant(input.schema === document.schema && input.schema_version === document.schema_version,
    `${label} schema provenance mismatch`);
  assertNoProtectedPath(input.path, `${label} provenance path`);
  return {
    path: input.path,
    sha256: input.sha256,
    byte_count: input.byte_count,
    schema: input.schema,
    schema_version: input.schema_version,
  };
}

function buildCapabilityDomainClosure({
  queue,
  ledger,
  sources,
  queueInput,
  ledgerInput,
  generatedAt = '2026-08-20',
}) {
  const { activeRoutes, activeCapabilities, rules } = assertQueue(queue);
  assertPreclosureLedger(ledger);
  assertValidatedSources(sources);
  const publicQueueInput = validatePinnedInput(queueInput, queue, 'queue');
  const publicLedgerInput = validatePinnedInput(ledgerInput, ledger, 'ledger');
  invariant(sources.decision_ledger?.sha256 === ledgerInput.sha256,
    'validated decision-ledger source must match the pinned preclosure ledger bytes');
  invariant(sources.decision_ledger?.document === ledger,
    'closure must use the same parsed ledger object retained by source loading');

  const capabilityDecisions = activeCapabilities.map((row) => {
    const rule = rules.get(row.semantic_capability);
    const evidence = domainEvidence(row.domain, sources);
    const base = {
      semantic_capability: row.semantic_capability,
      domain: row.domain,
      decision: rule.decision,
      decision_scope: 'CURRENT_EXPLICIT_SAFE_LOCAL_EVIDENCE_ONLY',
      semantic_claim: rule.decision === 'PROMOTE' ? rule.conclusion : null,
      current_local_conclusion: rule.conclusion,
      manifest_status_before_closure: row.validation_status,
      manifest_evidence_grade_before_closure: row.evidence_grade,
      actual_reverse_engineering_executed: evidence.actual_reverse_engineering_executed,
      evidence_exhausted: evidence.evidence_exhausted,
      evidence_exhausted_scope: 'PINNED_RUNTIME_EXPLICIT_SAFE_CORPUS_AND_ALL_ACTIONABLE_ROUTE_AUDITS',
      actionable_hypotheses: evidence.actionable_hypotheses,
      next_required_evidence: [...rule.next],
      external_only_gate: {
        required: true,
        local_safe_evidence_remaining: false,
        new_authority_or_external_state_required: true,
      },
      evidence_sources: evidence.evidence_sources,
      group: rule.group,
      ...supersession('capability', row.semantic_capability, ledger.capability_decisions, ledgerInput.sha256),
    };
    base.decision_id = decisionIdentity('capability', row.semantic_capability, base);
    return base;
  });

  const domainDecisions = HIGH_VALUE_DOMAINS.map((domain) => {
    const domainCapabilities = capabilityDecisions.filter((row) => row.domain === domain);
    const domainRoutes = queue.route_queue.filter((row) => row.research_domain === domain);
    const evidence = domainEvidence(domain, sources);
    const promotedCapabilities = domainCapabilities
      .filter((row) => row.decision === 'PROMOTE')
      .map((row) => row.semantic_capability);
    const base = {
      domain,
      decision: domain === 'map' ? 'REJECT' : 'KEEP_CANDIDATE',
      decision_scope: 'DOMAIN_RESEARCH_EXHAUSTION_WITH_BOUNDED_CAPABILITY_PROMOTIONS',
      promoted_capability_scope: promotedCapabilities,
      kept_capability_scope: domainCapabilities
        .filter((row) => row.decision === 'KEEP_CANDIDATE')
        .map((row) => row.semantic_capability),
      rejected_capability_scope: domainCapabilities
        .filter((row) => row.decision === 'REJECT')
        .map((row) => row.semantic_capability),
      actual_reverse_engineering_executed: evidence.actual_reverse_engineering_executed,
      evidence_exhausted: evidence.evidence_exhausted,
      evidence_exhausted_scope: 'ALL_CURRENT_SAFE_LOCAL_ROUTE_AND_CAPABILITY_ACTIONS_COMPLETE',
      actionable_hypotheses: evidence.actionable_hypotheses,
      next_required_evidence: [...new Set(domainCapabilities.flatMap((row) => row.next_required_evidence))],
      external_only_gate: {
        required: true,
        local_safe_evidence_remaining: false,
      },
      observed_route_count: domainRoutes.length,
      capability_gap_count_closed: domainCapabilities.length,
      evidence_sources: evidence.evidence_sources,
      ...supersession('domain', domain, ledger.domain_decisions, ledgerInput.sha256),
    };
    base.decision_id = decisionIdentity('domain', domain, base);
    return base;
  });

  return {
    schema: SCHEMA,
    schema_version: 1,
    generated_at: generatedAt,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    scope: 'SEMANTIC_SATURATION_DECISION_NOT_FULL_PARSE_CLAIM',
    preclosure_inputs: {
      research_queue: publicQueueInput,
      decision_ledger: publicLedgerInput,
    },
    preconditions: {
      actionable_route_count: activeRoutes.length,
      active_capability_count_closed: activeCapabilities.length,
      ledger_route_decision_count: ledger.route_decisions?.length ?? 0,
      ledger_capability_decision_count: ledger.capability_decisions?.length ?? 0,
      ledger_domain_decision_count: ledger.domain_decisions?.length ?? 0,
    },
    source_manifest: Object.values(sources).map(publicSource),
    route_decisions: [],
    capability_decisions: capabilityDecisions,
    domain_decisions: domainDecisions,
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
    claim_boundary: {
      allowed_status_if_final_gate_passes: 'SEMANTIC_RECOVERY_SATURATED',
      forbidden_status: 'FULLY_PARSED',
      unknown_and_unavailable_fields_remain_explicit: true,
      research_decisions_do_not_override_public_capability_authority: true,
    },
  };
}

module.exports = {
  CAPABILITY_DOMAINS,
  DEFAULT_SOURCE_SPECS,
  EXACT_BUILD,
  GROUPS,
  HIGH_VALUE_DOMAINS,
  SCHEMA,
  SOURCE_BY_DOMAIN,
  SOURCE_SCHEMA_CONTRACTS,
  assertNoProtectedPath,
  buildCapabilityDomainClosure,
  capabilityRuleMap,
  loadSources,
  readSafeJsonBytes,
  safeResolvedPath,
  sha256,
  stableStringify,
  validateResearchSource,
};
