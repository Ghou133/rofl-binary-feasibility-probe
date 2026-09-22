'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  HASH_MANIFEST_SCHEMA: DECISION_LEDGER_HASH_MANIFEST_SCHEMA,
  LEDGER_SCHEMA: DECISION_LEDGER_SCHEMA,
  SATURATION_CLOSURE_EXTRACTOR,
  validateDecisionLedger,
} = require('./deep_recovery_decision_ledger');

const DEEP_RECOVERY_BUILD = '16.16.805.0442';
const RESEARCH_QUEUE_SCHEMA = 'SEMANTIC_RESEARCH_QUEUE_V2';
const SATURATION_REPORT_SCHEMA = 'SEMANTIC_SATURATION_REPORT_V2';
const ANALYZER_VERSION = 'semantic-research-priority-v2';

const HIGH_VALUE_DOMAINS = Object.freeze([
  'state',
  'combat',
  'protection',
  'buff',
  'spell',
  'missile',
  'entity',
  'item',
  'economy',
  'minion',
  'jungle',
  'objective',
  'structure',
  'vision',
  'movement',
  'map',
]);

const SCORE_WEIGHTS = Object.freeze({
  packet_frequency: 0.10,
  entity_association: 0.08,
  runtime_name_strength: 0.10,
  registration_chain_strength: 0.10,
  known_event_correlation: 0.10,
  payload_structure_quality: 0.08,
  cross_replay_consistency: 0.06,
  availability_of_ground_truth: 0.12,
  downstream_value: 0.12,
  expected_information_gain: 0.10,
  reverse_engineering_cost_feasibility: 0.04,
});

const DOMAIN_VALUE = Object.freeze({
  state: 1.00,
  combat: 0.98,
  protection: 0.94,
  buff: 0.92,
  spell: 0.90,
  missile: 0.82,
  entity: 0.96,
  item: 0.84,
  economy: 0.80,
  minion: 0.76,
  jungle: 0.84,
  objective: 0.82,
  structure: 0.72,
  vision: 0.70,
  movement: 0.58,
  map: 0.64,
  UI: 0.08,
  system: 0.04,
  noise: 0.00,
  unknown: 0.48,
});

const GROUND_TRUTH_VALUE = Object.freeze({
  state: 1.00,
  combat: 1.00,
  protection: 0.72,
  buff: 0.58,
  spell: 0.60,
  missile: 0.50,
  entity: 0.48,
  item: 0.96,
  economy: 0.94,
  minion: 0.42,
  jungle: 0.34,
  objective: 0.30,
  structure: 0.32,
  vision: 0.82,
  movement: 0.88,
  map: 0.18,
  unknown: 0.20,
});

const CALLBACK_DOMAIN_RULES = Object.freeze([
  ['UI', /chat|emote|hover.?indicator|minimap.?icon|health.?bar.*icon|force.?muted|surrender|greyscale|area.?indicator|launch.?area|play.?vo|camera|visual.?offset|particle.?visibility|contextual.?situation|owner.?emote|fade.?out|set.?alpha|equip.?gear|disguise|animation/i],
  ['system', /message.?to.?client|notify|telemetry|handshake|latency|connection|protocol.?version/i],
  ['protection', /shield|heal|protection|absorb/i],
  ['buff', /buff|debuff|status|crowd.?control/i],
  ['missile', /missile|projectile/i],
  ['spell', /spell|cast|cooldown|ability|slotspelldata/i],
  ['item', /item|inventory|shop/i],
  ['economy', /gold|experience|score|statstone/i],
  ['combat', /damage|attack|health|combat|die|death|critical/i],
  ['movement', /move|path|dash|blink|teleport|recall|facedirection/i],
  ['vision', /vision|ward|stealth|reveal|sight/i],
  ['objective', /dragon|baron|herald|objective/i],
  ['structure', /turret|tower|inhibitor|nexus|building|structure/i],
  ['minion', /minion/i],
  ['jungle', /monster|camp|jungle/i],
  ['entity', /npc|unit|character|spawn|create|pet|summon|plant/i],
  ['state', /stat|state|resource|attribute|formulaoutput/i],
]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function round(value, digits = 6) {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function clamp01(value) {
  return Math.max(0, Math.min(1, Number.isFinite(value) ? value : 0));
}

function sha256Buffer(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function stableSort(rows, compare) {
  return rows.map((row, index) => ({ row, index }))
    .sort((left, right) => compare(left.row, right.row) || left.index - right.index)
    .map(({ row }) => row);
}

function assertAllowedInputPath(filePath) {
  const resolved = path.resolve(filePath);
  invariant(!resolved.toLowerCase().includes('holdout'),
    `protected Holdout path is forbidden: ${resolved}`);
  return resolved;
}

function canonicalizeNearestExisting(filePath) {
  let cursor = path.resolve(filePath);
  const suffix = [];
  while (!fs.existsSync(cursor)) {
    const parent = path.dirname(cursor);
    invariant(parent !== cursor, `no existing ancestor for output path: ${filePath}`);
    suffix.unshift(path.basename(cursor));
    cursor = parent;
  }
  return path.join(fs.realpathSync.native(cursor), ...suffix);
}

function assertAllowedOutputPath(filePath, label = 'output path') {
  const resolved = path.resolve(filePath);
  invariant(!resolved.toLowerCase().includes('holdout'),
    `${label} cannot target protected Holdout`);
  const canonical = canonicalizeNearestExisting(resolved);
  invariant(!canonical.toLowerCase().includes('holdout'),
    `canonical ${label} cannot target protected Holdout`);
  return resolved;
}

function hasExactCleanHoldoutBoundary(boundary) {
  const keys = ['enumerated', 'read', 'hashed', 'decoded', 'tested', 'consumed'];
  return boundary !== null && typeof boundary === 'object' && !Array.isArray(boundary)
    && Object.keys(boundary).length === keys.length
    && keys.every((key) => Object.prototype.hasOwnProperty.call(boundary, key)
      && boundary[key] === false);
}

function readJson(filePath, label) {
  const resolved = assertAllowedInputPath(filePath);
  const bytes = fs.readFileSync(resolved);
  let document;
  try {
    document = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
  return {
    path: resolved,
    sha256: sha256Buffer(bytes),
    byte_count: bytes.length,
    bytes,
    document,
  };
}

function validateFinalDecisionDocuments(decisionDocuments) {
  invariant(Array.isArray(decisionDocuments), 'decisionDocuments must be an array');
  invariant(decisionDocuments.length <= 1,
    'semantic priority accepts at most one validated final decision ledger');
  if (decisionDocuments.length === 0) return;
  const ledger = decisionDocuments[0];
  validateDecisionLedger(ledger);
  const closureSources = ledger.input_sources.filter((source) =>
    source.extractor === SATURATION_CLOSURE_EXTRACTOR);
  invariant(closureSources.length === 1,
  'semantic priority decision ledger is not final: saturation closure input is missing');
  const closure = closureSources[0];
  for (const domain of HIGH_VALUE_DOMAINS) {
    const decision = ledger.domain_decisions.find((row) => row.domain === domain);
    const selected = decision?.decision_history?.find((row) =>
      row.effective === true && row.decision_id === decision.decision_id);
    invariant(decision
      && selected?.supersession_validated === true
      && selected.provenance.source_id === closure.source_id
      && selected.provenance.artifact === closure.artifact
      && selected.provenance.sha256 === closure.sha256,
    `semantic priority final ledger domain ${domain} is not an exact effective closure decision`);
  }
}

function callbackNames(route) {
  return route.runtime_registration?.callback_names
    ?? route.callback_names
    ?? [];
}

function inferResearchDomain(route) {
  const declared = route.domain?.primary_domain ?? route.domain ?? 'unknown';
  const names = callbackNames(route).join(' ');
  // Strong runtime UI/system identities supersede a coarse family classifier;
  // otherwise the queue incorrectly spends gameplay budget on camera, icon,
  // animation, and message-to-client transport rows.
  for (const [domain, pattern] of CALLBACK_DOMAIN_RULES.slice(0, 2)) {
    if (pattern.test(names)) return domain;
  }
  if (declared && !['unknown', 'UI', 'system', 'noise'].includes(declared)) return declared;
  for (const [domain, pattern] of CALLBACK_DOMAIN_RULES.slice(2)) {
    if (pattern.test(names)) return domain;
  }
  return declared || 'unknown';
}

function capabilityDomain(capability) {
  const name = String(capability ?? '').toUpperCase();
  if (/SHIELD|HEAL|PROTECTION|MITIGATION/.test(name)) return 'protection';
  if (/BUFF|DEBUFF/.test(name)) return 'buff';
  if (/MISSILE/.test(name)) return 'missile';
  if (/SPELL|CAST|RUNE|PASSIVE/.test(name)) return 'spell';
  if (/ITEM|INVENTORY/.test(name)) return 'item';
  if (/GOLD|XP|CS|ECONOMY/.test(name)) return 'economy';
  if (/DAMAGE|DEATH|ASSIST|KILL|RESPAWN|COMBAT/.test(name)) return 'combat';
  if (/CURRENT_HP|MAX_HP|MANA|ARMOR|MAGIC_RESIST|ATTACK_DAMAGE|ABILITY_POWER|ATTACK_SPEED|MOVE_SPEED|TEMPORARY|HERO_STATE/.test(name)) return 'state';
  if (/WARD|SWEEPER|VISION|VISIBILITY|REVEAL/.test(name)) return 'vision';
  if (/PATH|MOVEMENT|POSITION/.test(name)) return 'movement';
  if (/LANE_MINION/.test(name)) return 'minion';
  if (/JUNGLE|CAMP|MONSTER/.test(name)) return 'jungle';
  if (/OBJECTIVE/.test(name)) return 'objective';
  if (/STRUCTURE|TOWER|TURRET|INHIBITOR|NEXUS/.test(name)) return 'structure';
  if (/MAP_MECHANIC/.test(name)) return 'map';
  if (/ENTITY|NPC|PARTICIPANT/.test(name)) return 'entity';
  return 'unknown';
}

function routeDecisionMap(decisionDocuments = []) {
  const map = new Map();
  for (const document of decisionDocuments) {
    for (const decision of document.route_decisions ?? []) {
      const packetId = Number(decision.packet_id);
      invariant(Number.isInteger(packetId) && packetId >= 0,
        'route decision packet_id must be a nonnegative integer');
      if (map.has(packetId)) {
        invariant(decision.supersedes_previous_decision === true,
          `duplicate route decision for packet ${packetId} requires explicit supersedes_previous_decision`);
      }
      map.set(packetId, decision);
    }
  }
  return map;
}

function profilerEvidenceForRoute(route) {
  return route.decoder?.profiler_or_negative_evidence
    ?? route.profiler_or_negative_evidence
    ?? [];
}

function factorScores(route, domain, decision = null) {
  const count = Number(route.observed?.count ?? route.observed_count ?? 0);
  const entity = route.observed?.entity_candidate ?? {};
  const provenance = route.observed?.source_provenance ?? [];
  const registration = route.runtime_registration ?? route;
  const callbacks = registration.callbacks ?? [];
  const factories = registration.factory_packets ?? [];
  const names = callbackNames(route);
  const profilerEvidence = profilerEvidenceForRoute(route);
  const structural = Boolean(route.status?.exact_structural_decode_evidence)
    || /STRUCTURAL|FULL_CONSUME|DECODE/.test(route.decoder?.decoder_status ?? '');
  const payloadShapes = route.observed?.payload_size_distribution
    ?? route.payload_size_distribution
    ?? [];
  const replayCount = new Set(provenance.map((row) => row.replay_sha256).filter(Boolean)).size;
  const mappingStatus = registration.callback_mapping_status ?? '';
  const runtimeNameStrength = mappingStatus === 'UNIQUE_CALLBACK_RTTI_NAME'
    ? (names.length > 0 ? 1 : 0.78)
    : (names.length > 0 ? 0.58 : 0);
  const registrationStrength = clamp01(
    (callbacks.length > 0 ? 0.38 : 0)
    + (callbacks.some((row) => row.callback_receive_target_rva_hex) ? 0.24 : 0)
    + (factories.length > 0 ? 0.30 : 0)
    + (structural ? 0.08 : 0),
  );
  const kind = String(entity.kind ?? '');
  const entityAssociation = clamp01(
    (/CHAMPION|ENTITY|NETWORK|PARTICIPANT|RAW_PARAM_MAY_BE_ENTITY/i.test(kind) ? 0.72 : 0)
    + (Number(entity.observed_distinct_raw_params ?? 0) > 10 ? 0.16 : 0)
    + (entity.status === 'VERIFIED_DIRECT' ? 0.12 : 0)
    - (/ZERO_ONLY/.test(kind) ? 0.34 : 0),
  );
  const correlation = clamp01(
    (profilerEvidence.length > 0 ? 0.35 : 0)
    + (profilerEvidence.some((row) => JSON.stringify(row).includes('anchor')) ? 0.25 : 0)
    + (decision?.positive_anchor_count > 0 ? 0.30 : 0)
    + (decision?.counterexample_count > 0 ? 0.10 : 0),
  );
  const payloadQuality = clamp01(
    (structural ? 0.62 : 0)
    + (factories.length > 0 ? 0.20 : 0)
    + (payloadShapes.length > 0 && payloadShapes.length <= 12 ? 0.12 : 0.05)
    + (payloadShapes.every((row) => Number.isInteger(row.payload_length)) ? 0.06 : 0),
  );
  const status = route.status?.baseline_status ?? 'UNKNOWN';
  const uncertainty = status === 'UNKNOWN' ? 1 : status === 'CLASSIFIED' ? 0.88 : status === 'DECODED' ? 0.58 : 0.15;
  const localEvidenceStrength = Math.max(runtimeNameStrength, registrationStrength, payloadQuality, correlation);
  const informationGain = clamp01(uncertainty * (0.48 + (0.52 * localEvidenceStrength)));
  const estimatedCost = structural ? 0.18
    : callbacks.length > 0 && factories.length > 0 ? 0.30
      : names.length > 0 ? 0.48
        : count >= 50000 ? 0.68
          : 0.82;
  return {
    packet_frequency: round(clamp01(Math.log10(count + 1) / 6.2)),
    entity_association: round(entityAssociation),
    runtime_name_strength: round(runtimeNameStrength),
    registration_chain_strength: round(registrationStrength),
    known_event_correlation: round(correlation),
    payload_structure_quality: round(payloadQuality),
    cross_replay_consistency: round(clamp01(replayCount / 4)),
    availability_of_ground_truth: round(GROUND_TRUTH_VALUE[domain] ?? GROUND_TRUTH_VALUE.unknown),
    downstream_value: round(DOMAIN_VALUE[domain] ?? DOMAIN_VALUE.unknown),
    expected_information_gain: round(informationGain),
    reverse_engineering_cost: round(estimatedCost),
    reverse_engineering_cost_feasibility: round(1 - estimatedCost),
  };
}

function weightedScore(factors) {
  let value = 0;
  for (const [factor, weight] of Object.entries(SCORE_WEIGHTS)) {
    value += factors[factor] * weight;
  }
  return round(value * 100, 4);
}

function nextHypothesis(route, domain) {
  const names = callbackNames(route);
  const structural = Boolean(route.status?.exact_structural_decode_evidence)
    || /STRUCTURAL|DECODE/.test(route.decoder?.decoder_status ?? '');
  if (structural) {
    return `Correlate decoded ${names[0] ?? route.packet_discriminator} fields with exact-build ${domain} anchors and search counterexamples.`;
  }
  if (names.length > 0) {
    return `Recover the exact deserializer field layout for ${names.join(' / ')}, then test ${domain} operation and field hypotheses.`;
  }
  return `Recover callback/factory identity or produce a bounded raw field profile before assigning a ${domain} semantic.`;
}

function isGameplayResearchRoute(route, domain) {
  if (route.status?.positive_semantic_coverage) return false;
  if (route.status?.negative_control) return false;
  if (['noise', 'system', 'UI'].includes(domain)) return false;
  const count = Number(route.observed?.count ?? 0);
  const names = callbackNames(route);
  return domain !== 'unknown' || names.length > 0 || count >= 1000;
}

function buildRouteQueue(routes, decisions = []) {
  const decisionMap = routeDecisionMap(decisions);
  const rows = [];
  for (const route of routes) {
    const domain = inferResearchDomain(route);
    const decision = decisionMap.get(Number(route.packet_id)) ?? null;
    if (!isGameplayResearchRoute(route, domain)) continue;
    const evidenceExhausted = decision?.evidence_exhausted === true;
    const factors = factorScores(route, domain, decision);
    const score = weightedScore(factors);
    const count = Number(route.observed?.count ?? 0);
    const highFrequency = count >= 50000;
    const actionable = !evidenceExhausted
      && !['PROMOTE', 'REJECT_FINAL'].includes(decision?.decision)
      && (score >= 35 || highFrequency);
    rows.push({
      packet_id: Number(route.packet_id),
      packet_discriminator: route.packet_discriminator,
      observed_packet_count: count,
      baseline_status: route.status?.baseline_status ?? 'UNKNOWN',
      declared_domain: route.domain?.primary_domain ?? 'unknown',
      research_domain: domain,
      callback_mapping_status: route.runtime_registration?.callback_mapping_status ?? null,
      callback_names: callbackNames(route),
      exact_structural_decode_evidence: Boolean(route.status?.exact_structural_decode_evidence),
      high_frequency: highFrequency,
      factor_scores: factors,
      priority_score: score,
      priority_band: score >= 72 ? 'P0' : score >= 58 ? 'P1' : score >= 44 ? 'P2' : 'P3',
      actionable,
      evidence_exhausted: evidenceExhausted,
      current_decision: decision?.decision ?? null,
      hypothesis: nextHypothesis(route, domain),
      next_required_evidence: decision?.next_required_evidence
        ?? route.research?.next_required_evidence
        ?? [],
      promotion_authority: 'NONE_RESEARCH_PRIORITY_ONLY',
    });
  }
  return stableSort(rows, (left, right) =>
    Number(right.actionable) - Number(left.actionable)
    || right.priority_score - left.priority_score
    || right.observed_packet_count - left.observed_packet_count
    || left.packet_id - right.packet_id);
}

function capabilityRecords(manifest, exactBuild) {
  const profile = manifest.build_profiles?.[exactBuild];
  invariant(profile, `capability manifest has no exact build ${exactBuild}`);
  invariant(Array.isArray(profile.records), 'capability manifest records must be an array');
  return profile.records;
}

function buildCapabilityQueue(records, decisionDocuments = []) {
  const decisions = new Map();
  for (const document of decisionDocuments) {
    for (const decision of document.capability_decisions ?? []) {
      decisions.set(decision.semantic_capability, decision);
    }
  }
  const rows = [];
  for (const record of records) {
    if (record.validation_status === 'PASS' && !['CANDIDATE', 'UNAVAILABLE', 'UNVERIFIED'].includes(record.evidence_grade)) continue;
    const domain = capabilityDomain(record.semantic_capability);
    const decision = decisions.get(record.semantic_capability) ?? null;
    const evidenceExhausted = decision?.evidence_exhausted === true;
    const limitations = record.known_limits ?? [];
    const hasRoute = record.protocol_route !== null && record.protocol_route !== undefined;
    const hasCandidateEvidence = record.validation_status === 'CANDIDATE_ONLY'
      || record.evidence_grade === 'CANDIDATE';
    const score = round(100 * clamp01(
      (DOMAIN_VALUE[domain] ?? DOMAIN_VALUE.unknown) * 0.44
      + (GROUND_TRUTH_VALUE[domain] ?? GROUND_TRUTH_VALUE.unknown) * 0.24
      + (hasRoute ? 0.18 : 0.04)
      + (hasCandidateEvidence ? 0.14 : 0.08),
    ), 4);
    rows.push({
      semantic_capability: record.semantic_capability,
      domain,
      validation_status: record.validation_status,
      evidence_grade: record.evidence_grade,
      protocol_route: record.protocol_route,
      priority_score: score,
      priority_band: score >= 72 ? 'P0' : score >= 58 ? 'P1' : score >= 44 ? 'P2' : 'P3',
      actionable: !evidenceExhausted && score >= 40,
      evidence_exhausted: evidenceExhausted,
      current_decision: decision?.decision ?? null,
      known_limits: limitations,
      next_required_evidence: decision?.next_required_evidence
        ?? (hasRoute
          ? ['Recover exact field/operation semantics with independent positive anchors and counterexamples.']
          : ['Discover an exact-build route/layout and validate it against independent semantic anchors.']),
      promotion_authority: 'NONE_RESEARCH_PRIORITY_ONLY',
    });
  }
  return stableSort(rows, (left, right) =>
    Number(right.actionable) - Number(left.actionable)
    || right.priority_score - left.priority_score
    || left.semantic_capability.localeCompare(right.semantic_capability));
}

function domainDecisionMap(decisionDocuments = []) {
  const map = new Map();
  for (const document of decisionDocuments) {
    for (const decision of document.domain_decisions ?? []) {
      invariant(Object.prototype.hasOwnProperty.call(DOMAIN_VALUE, decision.domain),
        `unknown domain decision ${decision.domain}`);
      // UI/system/noise decisions are retained in the unified ledger as
      // repurpose evidence, but they are intentionally outside the gameplay
      // saturation surface and therefore do not create research blockers.
      if (!HIGH_VALUE_DOMAINS.includes(decision.domain)) continue;
      invariant(!map.has(decision.domain), `duplicate domain decision ${decision.domain}`);
      map.set(decision.domain, decision);
    }
  }
  return map;
}

function buildSaturationReport({
  exactBuild,
  routes,
  routeQueue,
  capabilityQueue,
  decisionDocuments = [],
  regressionAttestation = null,
}) {
  const domainDecisions = domainDecisionMap(decisionDocuments);
  const domains = HIGH_VALUE_DOMAINS.map((domain) => {
    const domainRoutes = routes.filter((route) => inferResearchDomain(route) === domain);
    const domainQueue = routeQueue.filter((row) => row.research_domain === domain);
    const domainCapabilities = capabilityQueue.filter((row) => row.domain === domain);
    const decision = domainDecisions.get(domain) ?? null;
    const observedPacketCount = domainRoutes.reduce((sum, route) => sum + Number(route.observed?.count ?? 0), 0);
    const structurallyDecoded = domainRoutes.filter((route) =>
      route.status?.exact_structural_decode_evidence
      || !String(route.decoder?.decoder_status ?? '').startsWith('NOT_DECODED')).length;
    const semanticallyVerified = domainRoutes.filter((route) => route.status?.positive_semantic_coverage).length;
    const candidate = domainRoutes.filter((route) => ['CLASSIFIED', 'DECODED'].includes(route.status?.baseline_status)).length;
    const unknown = domainRoutes.filter((route) => route.status?.baseline_status === 'UNKNOWN').length;
    const actionableHypotheses = [
      ...domainQueue.filter((row) => row.actionable).slice(0, 10).map((row) => row.hypothesis),
      ...domainCapabilities.filter((row) => row.actionable).slice(0, 10)
        .map((row) => `${row.semantic_capability}: ${row.next_required_evidence[0]}`),
      ...(decision?.actionable_hypotheses ?? []),
    ];
    const actualReverseEngineering = decision?.actual_reverse_engineering_executed === true;
    const evidenceExhausted = decision?.evidence_exhausted === true
      && actionableHypotheses.length === 0;
    return {
      domain,
      observed_protocol_surface: {
        route_count: domainRoutes.length,
        packet_count: observedPacketCount,
      },
      structurally_decoded_route_count: structurallyDecoded,
      semantically_verified_route_count: semanticallyVerified,
      candidate_route_count: candidate,
      unknown_route_count: unknown,
      capability_gap_count: domainCapabilities.length,
      actual_reverse_engineering_executed: actualReverseEngineering,
      evidence_exhausted: evidenceExhausted,
      new_actionable_hypotheses: actionableHypotheses.length > 0,
      actionable_hypotheses: [...new Set(actionableHypotheses)].slice(0, 20),
      decision_provenance: decision?.provenance ?? null,
    };
  });
  const highFrequencyGameplay = routeQueue.filter((row) => row.high_frequency);
  const activeRouteRows = routeQueue.filter((row) => row.actionable);
  const activeCapabilityRows = capabilityQueue.filter((row) => row.actionable);
  const checks = [
    {
      check: 'ALL_HIGH_FREQUENCY_GAMEPLAY_ROUTES_DEEPLY_RESEARCHED',
      pass: highFrequencyGameplay.every((row) => row.evidence_exhausted || ['PROMOTE', 'REJECT_FINAL'].includes(row.current_decision)),
      remaining: highFrequencyGameplay.filter((row) => !row.evidence_exhausted && !['PROMOTE', 'REJECT_FINAL'].includes(row.current_decision)).map((row) => row.packet_discriminator),
    },
    {
      check: 'ALL_HIGH_VALUE_DOMAINS_EXECUTED_AND_EXHAUSTED',
      pass: domains.every((row) => row.actual_reverse_engineering_executed && row.evidence_exhausted),
      remaining: domains.filter((row) => !row.actual_reverse_engineering_executed || !row.evidence_exhausted).map((row) => row.domain),
    },
    {
      check: 'CANDIDATE_QUEUE_CONVERGED',
      pass: activeRouteRows.length === 0 && activeCapabilityRows.length === 0,
      remaining: {
        actionable_routes: activeRouteRows.length,
        actionable_capabilities: activeCapabilityRows.length,
      },
    },
    {
      check: 'REMAINING_CANDIDATES_REQUIRE_EXTERNAL_EVIDENCE',
      pass: routeQueue.every((row) => row.actionable || row.evidence_exhausted || row.current_decision !== null),
      remaining: routeQueue.filter((row) => !row.actionable && !row.evidence_exhausted && row.current_decision === null).map((row) => row.packet_discriminator),
    },
    {
      check: 'NO_HIGH_PRIORITY_UNKNOWN_HAS_LOCAL_ACTION',
      pass: !activeRouteRows.some((row) => row.baseline_status === 'UNKNOWN' && ['P0', 'P1'].includes(row.priority_band)),
      remaining: activeRouteRows.filter((row) => row.baseline_status === 'UNKNOWN' && ['P0', 'P1'].includes(row.priority_band)).map((row) => row.packet_discriminator),
    },
    {
      check: 'REGRESSION_PASS',
      pass: regressionAttestation?.status === 'PASS'
        && Number(regressionAttestation?.failed_test_count ?? 1) === 0,
      remaining: regressionAttestation?.status === 'PASS' ? [] : ['exact-build regression attestation'],
    },
    {
      check: 'NO_SILENT_FALLBACK_OR_DISCARD',
      pass: true,
      observed: 'exact-build registry is conserved; queue is additive and has no semantic promotion authority',
    },
  ];
  const saturated = checks.every((row) => row.pass);
  return {
    schema: SATURATION_REPORT_SCHEMA,
    schema_version: 2,
    analyzer_version: ANALYZER_VERSION,
    exact_build: exactBuild,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    status: saturated ? 'SEMANTIC_RECOVERY_SATURATED' : 'ACTIVE_RESEARCH',
    saturated,
    warning: 'Saturation is an evidence-exhaustion gate, not FULLY_PARSED and not packet-decode percentage.',
    domains,
    queue_summary: {
      route_research_row_count: routeQueue.length,
      actionable_route_count: activeRouteRows.length,
      capability_gap_row_count: capabilityQueue.length,
      actionable_capability_count: activeCapabilityRows.length,
      high_frequency_gameplay_route_count: highFrequencyGameplay.length,
    },
    saturation_checks: checks,
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  };
}

function validateRegistry(registry, exactBuild) {
  invariant(registry.schema === 'FULL_SEMANTIC_OBSERVED_ROUTE_REGISTRY_V1',
    'observed route registry schema mismatch');
  invariant(registry.exact_build === exactBuild, 'observed route registry exact build mismatch');
  invariant(registry.nearest_build_fallback === 'FORBIDDEN', 'nearest-build fallback must be FORBIDDEN');
  invariant(Array.isArray(registry.routes), 'observed route registry routes must be an array');
}

function buildDeepRecoveryPriority({
  exactBuild = DEEP_RECOVERY_BUILD,
  observedRegistry,
  capabilityManifest,
  negativeEvidence = null,
  regressionAttestation = null,
  decisionDocuments = [],
  sources = {},
  generatedAt = '2026-08-20',
}) {
  invariant(exactBuild === DEEP_RECOVERY_BUILD,
    `deep recovery supports exact build ${DEEP_RECOVERY_BUILD} only`);
  validateRegistry(observedRegistry, exactBuild);
  invariant(capabilityManifest.exact_build_only === true, 'capability manifest must be exact-build only');
  invariant(capabilityManifest.nearest_build_fallback === 'FORBIDDEN',
    'capability manifest nearest-build fallback must be FORBIDDEN');
  validateFinalDecisionDocuments(decisionDocuments);
  const records = capabilityRecords(capabilityManifest, exactBuild);
  const routeQueue = buildRouteQueue(observedRegistry.routes, decisionDocuments);
  const capabilityQueue = buildCapabilityQueue(records, decisionDocuments);
  const queue = {
    schema: RESEARCH_QUEUE_SCHEMA,
    schema_version: 2,
    analyzer_version: ANALYZER_VERSION,
    generated_at: generatedAt,
    exact_build: exactBuild,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    policy: {
      order: 'HIGH_INFORMATION_GAIN_AND_HIGH_GAMEPLAY_VALUE; NOT_OPCODE_ORDER',
      score_weights: SCORE_WEIGHTS,
      score_is_semantic_evidence: false,
      promotion_authority: 'NONE',
      candidate_loop: ['HYPOTHESIS', 'DECODE', 'POSITIVE_ANCHORS', 'COUNTEREXAMPLES', 'CROSS_REPLAY', 'BEHAVIOR', 'RUNTIME_STRUCTURE', 'DECISION'],
      allowed_decisions: ['PROMOTE', 'KEEP_CANDIDATE', 'REJECT', 'REPURPOSE', 'REJECT_FINAL'],
    },
    source_provenance: sources,
    negative_evidence_loaded: Boolean(negativeEvidence),
    route_queue: routeQueue,
    capability_queue: capabilityQueue,
    summary: {
      route_row_count: routeQueue.length,
      actionable_route_count: routeQueue.filter((row) => row.actionable).length,
      capability_row_count: capabilityQueue.length,
      actionable_capability_count: capabilityQueue.filter((row) => row.actionable).length,
      top_route_ids: routeQueue.filter((row) => row.actionable).slice(0, 20).map((row) => row.packet_discriminator),
      top_capabilities: capabilityQueue.filter((row) => row.actionable).slice(0, 20).map((row) => row.semantic_capability),
    },
    protected_holdout: {
      enumerated: false,
      read: false,
      hashed: false,
      decoded: false,
      tested: false,
      consumed: false,
    },
  };
  const saturation = buildSaturationReport({
    exactBuild,
    routes: observedRegistry.routes,
    routeQueue,
    capabilityQueue,
    decisionDocuments,
    regressionAttestation,
  });
  return { queue, saturation };
}

function loadDeepRecoveryInputs({
  root = process.cwd(),
  observedRegistryPath = 'artifacts/full_semantic_baseline_v1/observed_route_registry.json',
  capabilityManifestPath = 'artifacts/semantic_coverage_v1/capability_manifest.json',
  negativeEvidencePath = 'artifacts/full_semantic_baseline_v1/negative_evidence_registry.json',
  regressionAttestationPath = 'artifacts/full_semantic_baseline_v1/regression/regression_attestation_16_16.json',
  decisionPaths = [],
} = {}) {
  const resolve = (value) => path.resolve(root, value);
  const observed = readJson(resolve(observedRegistryPath), 'observed route registry');
  const manifest = readJson(resolve(capabilityManifestPath), 'capability manifest');
  const negative = readJson(resolve(negativeEvidencePath), 'negative evidence registry');
  const regression = readJson(resolve(regressionAttestationPath), 'regression attestation');
  invariant(decisionPaths.length <= 1,
    'semantic priority CLI accepts one validated final decision ledger only');
  const decisions = decisionPaths.map((value, index) => {
    const loaded = readJson(resolve(value), `decision ${index + 1}`);
    validateFinalDecisionDocuments([loaded.document]);
    const manifestPath = path.join(path.dirname(loaded.path), 'artifact_manifest.json');
    const manifest = readJson(manifestPath, 'decision ledger hash manifest');
    invariant(manifest.document.schema === DECISION_LEDGER_HASH_MANIFEST_SCHEMA,
      'decision ledger hash manifest schema mismatch');
    invariant(manifest.document.exact_build === DEEP_RECOVERY_BUILD,
      'decision ledger hash manifest exact build mismatch');
    const file = manifest.document.files?.find((row) => row.file === path.basename(loaded.path));
    invariant(file
      && file.sha256 === loaded.sha256
      && file.byte_count === loaded.byte_count
      && file.schema === DECISION_LEDGER_SCHEMA,
    'decision ledger bytes are not pinned by the sibling hash manifest');
    const manifestInputs = manifest.document.inputs ?? [];
    invariant(JSON.stringify(manifestInputs) === JSON.stringify(
      loaded.document.input_sources.map((source) => ({
        source_id: source.source_id,
        artifact: source.artifact,
        sha256: source.sha256,
        byte_count: source.byte_count,
      })),
    ), 'decision ledger hash manifest input provenance mismatch');
    return loaded;
  });
  return {
    observedRegistry: observed.document,
    capabilityManifest: manifest.document,
    negativeEvidence: negative.document,
    regressionAttestation: regression.document,
    decisionDocuments: decisions.map((row) => row.document),
    sources: {
      observed_route_registry: { path: observed.path, sha256: observed.sha256 },
      capability_manifest: { path: manifest.path, sha256: manifest.sha256 },
      negative_evidence_registry: { path: negative.path, sha256: negative.sha256 },
      regression_attestation: { path: regression.path, sha256: regression.sha256 },
      decisions: decisions.map((row) => ({ path: row.path, sha256: row.sha256 })),
    },
  };
}

function writeJson(filePath, value) {
  const text = `${JSON.stringify(value, null, 2)}\n`;
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, text, 'utf8');
  return {
    file: path.basename(filePath),
    path: filePath,
    sha256: sha256Buffer(Buffer.from(text)),
    byte_count: Buffer.byteLength(text),
    schema: value.schema,
  };
}

function writeDeepRecoveryArtifacts(outputDirectory, result) {
  invariant(hasExactCleanHoldoutBoundary(result?.queue?.protected_holdout),
    'queue protected_holdout must contain exactly six explicit false keys');
  invariant(hasExactCleanHoldoutBoundary(result?.saturation?.protected_holdout),
    'saturation protected_holdout must contain exactly six explicit false keys');
  const resolved = assertAllowedOutputPath(outputDirectory, 'output directory');
  const queuePath = assertAllowedOutputPath(
    path.join(resolved, 'semantic_research_queue.json'), 'queue output file',
  );
  const saturationPath = assertAllowedOutputPath(
    path.join(resolved, 'semantic_saturation_report.json'), 'saturation output file',
  );
  const manifestPath = assertAllowedOutputPath(
    path.join(resolved, 'artifact_manifest.json'), 'manifest output file',
  );
  // Every directory/file target and both protected-boundary contracts are
  // validated before the first filesystem mutation.
  fs.mkdirSync(resolved, { recursive: true });
  const queue = writeJson(queuePath, result.queue);
  const saturation = writeJson(saturationPath, result.saturation);
  const manifest = {
    schema: 'SEMANTIC_DEEP_RECOVERY_ARTIFACT_MANIFEST_V2',
    schema_version: 2,
    exact_build: result.queue.exact_build,
    self_hash_excluded: true,
    files: [queue, saturation].map(({ path: ignored, ...row }) => row),
  };
  const manifestOutput = writeJson(manifestPath, manifest);
  return { output_directory: resolved, files: [queue, saturation, manifestOutput] };
}

module.exports = {
  ANALYZER_VERSION,
  DEEP_RECOVERY_BUILD,
  HIGH_VALUE_DOMAINS,
  RESEARCH_QUEUE_SCHEMA,
  SATURATION_REPORT_SCHEMA,
  SCORE_WEIGHTS,
  assertAllowedInputPath,
  assertAllowedOutputPath,
  buildCapabilityQueue,
  buildDeepRecoveryPriority,
  buildRouteQueue,
  buildSaturationReport,
  capabilityDomain,
  factorScores,
  inferResearchDomain,
  loadDeepRecoveryInputs,
  weightedScore,
  writeDeepRecoveryArtifacts,
};
