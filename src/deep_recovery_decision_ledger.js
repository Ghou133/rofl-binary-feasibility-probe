'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const EXACT_BUILD = '16.16.805.0442';
const LEDGER_SCHEMA = 'ROFL_DEEP_RECOVERY_DECISION_LEDGER_V1';
const HASH_MANIFEST_SCHEMA = 'ROFL_DEEP_RECOVERY_DECISION_LEDGER_HASH_MANIFEST_V1';
const ANALYZER_VERSION = 'deep-recovery-decision-ledger-v1';
const SATURATION_CLOSURE_SCHEMA = 'ROFL_SEMANTIC_CAPABILITY_DOMAIN_CLOSURE_V2';
const SATURATION_CLOSURE_EXTRACTOR = 'saturation_closure';
const SATURATION_CLOSURE_SOURCE_ID = 'semantic_capability_domain_saturation_closure';
const RESEARCH_QUEUE_SCHEMA = 'SEMANTIC_RESEARCH_QUEUE_V2';

const ALLOWED_DECISIONS = Object.freeze([
  'PROMOTE',
  'KEEP_CANDIDATE',
  'REJECT',
  'REPURPOSE',
  'REJECT_FINAL',
]);

const STATUS_BY_DECISION = Object.freeze({
  PROMOTE: 'PROMOTED',
  KEEP_CANDIDATE: 'CANDIDATE',
  REJECT: 'REJECTED_CURRENT_EVIDENCE',
  REPURPOSE: 'REPURPOSED',
  REJECT_FINAL: 'REJECTED_FINAL',
});

const ALLOWED_STATUSES = Object.freeze(Object.values(STATUS_BY_DECISION));

// Must stay aligned with semantic_research_priority.js. Deliberately repeated
// here so that the ledger can be validated without importing the queue engine.
const ALLOWED_DOMAINS = Object.freeze([
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
  'UI',
  'system',
  'noise',
  'unknown',
]);

// This is an allowlist, not a directory scan. Adding a source is an explicit
// review act, and protected evidence can therefore never be discovered by the
// builder as a side effect of traversal.
const DEFAULT_SAFE_SOURCE_SPECS = Object.freeze([
  {
    id: 'high_frequency_unknown_baseline',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/high_frequency_unknown_deep_mining.json',
    extractor: 'high_frequency',
    precedence: 10,
  },
  {
    id: 'buff_spell_promotion_matrix',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/buff_spell/PROMOTION_MATRIX.json',
    extractor: 'buff_spell',
    precedence: 20,
  },
  {
    id: 'hero_state_damage_defense',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/hero_state/hero_state_damage_defense_deep_report_16_16.json',
    extractor: 'direct',
    precedence: 30,
  },
  {
    id: 'entity_item_deep_recovery',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/entity_item/entity_item_deep_recovery_summary_16_16.json',
    extractor: 'entity_item',
    precedence: 30,
  },
  {
    id: 'route_pair_0092_00b9_exact_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_pair_0092_00b9_exact_audit.json',
    extractor: 'direct',
    precedence: 50,
  },
  {
    id: 'route_0474_champion_specific_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_0474_champion_specific_audit.json',
    extractor: 'direct',
    precedence: 50,
  },
  {
    id: 'route_pair_004a_0199_batch_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_pair_004a_0199_batch_audit.json',
    extractor: 'direct',
    precedence: 50,
  },
  {
    id: 'route_0064_support_quest_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_0064_support_quest_audit.json',
    extractor: 'direct',
    precedence: 50,
  },
  {
    id: 'route_0064_runtime_residual_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_0064_runtime_residual_audit.json',
    extractor: 'supporting_only',
    precedence: 55,
  },
  {
    id: 'route_02d4_auxiliary_batch_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_02d4_auxiliary_batch_audit.json',
    extractor: 'direct',
    precedence: 50,
  },
  {
    id: 'route_pair_01c2_0473_batch_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/route_pair_01c2_0473_batch_audit.json',
    extractor: 'direct',
    precedence: 60,
  },
  {
    id: 'remaining_high_frequency_deep_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/remaining_highfreq/remaining_highfreq_deep_audit.json',
    extractor: 'direct',
    precedence: 60,
  },
  {
    id: 'gameplay_route_tail_saturation_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/gameplay_route_tail/gameplay_route_tail_audit_16_16.json',
    extractor: 'direct',
    precedence: 60,
  },
  {
    id: 'named_gameplay_wave_saturation_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/named_gameplay_wave/named_gameplay_wave_decisions_16_16.json',
    extractor: 'direct',
    precedence: 70,
  },
  {
    id: 'next_priority_wave_saturation_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/next_priority_wave/next_priority_wave_machine_decisions_16_16.json',
    extractor: 'direct',
    precedence: 70,
  },
  {
    id: 'hero_reincarnate_alive_saturation_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/hero_respawn/hero_reincarnate_alive_audit_16_16.json',
    extractor: 'direct',
    precedence: 80,
  },
  {
    id: 'high_frequency_leftover_exhaustion_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/highfreq_leftover_exhaustion/highfreq_leftover_exhaustion_v2.json',
    extractor: 'direct',
    precedence: 80,
  },
  {
    id: 'unknown_p1_wave_saturation_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/unknown_p1_wave/unknown_p1_wave_machine_decisions_16_16.json',
    extractor: 'direct',
    precedence: 80,
  },
  {
    id: 'residual_p2_wave_saturation_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/residual_p2_wave/residual_p2_wave_decisions_16_16.json',
    extractor: 'direct',
    precedence: 80,
  },
  {
    id: 'residual_p3_wave_saturation_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/residual_p3_wave/residual_p3_wave_machine_decisions_16_16.json',
    extractor: 'direct',
    precedence: 80,
  },
  {
    id: 'residual_p4_wave_saturation_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/residual_p4_wave/residual_p4_wave_decisions_16_16.json',
    extractor: 'direct',
    precedence: 80,
  },
  {
    id: 'residual_p5_wave_saturation_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/residual_p5_wave/residual_p5_wave_decisions_16_16.json',
    extractor: 'direct',
    precedence: 80,
  },
  {
    id: 'residual_p6_wave_saturation_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/residual_p6_wave/residual_p6_wave_machine_decisions_16_16.json',
    extractor: 'direct',
    precedence: 80,
  },
  {
    id: 'residual_p7_wave_saturation_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/residual_p7_wave/residual_p7_wave_machine_decisions_16_16.json',
    extractor: 'direct',
    precedence: 80,
  },
  {
    id: 'item_family_saturation_audit',
    artifact: 'artifacts/full_semantic_deep_recovery_v2/item_family_saturation/item_family_saturation_decisions_16_16.json',
    extractor: 'direct',
    precedence: 90,
  },
  {
    id: SATURATION_CLOSURE_SOURCE_ID,
    artifact: 'artifacts/full_semantic_deep_recovery_v2/saturation_closure/semantic_capability_domain_closure_16_16.json',
    preclosure_ledger_artifact: 'artifacts/full_semantic_deep_recovery_v2/saturation_closure/preclosure_decision_ledger_16_16.json',
    extractor: SATURATION_CLOSURE_EXTRACTOR,
    precedence: 100,
  },
]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

const DERIVED_IDENTITY_FIELDS = new Set([
  'decision_id',
  'decision_identity_material',
  'source_decision_identity_material',
  'source_decision_id',
  'decision_key',
  'effective',
  'superseded_by',
  'supersession_validated',
  'precedence',
]);

function canonicalIdentityValue(value) {
  if (Array.isArray(value)) return value.map(canonicalIdentityValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value)
      .filter((key) => !DERIVED_IDENTITY_FIELDS.has(key) && value[key] !== undefined)
      .sort()
      .map((key) => [key, canonicalIdentityValue(value[key])]));
  }
  return value;
}

function decisionKey(kind, key) {
  invariant(['route', 'capability', 'domain'].includes(kind),
    `unsupported decision kind ${kind}`);
  if (kind === 'route') {
    const packetId = typeof key === 'string' && /^0x[0-9a-f]+$/i.test(key)
      ? Number.parseInt(key.slice(2), 16)
      : Number(key);
    invariant(Number.isInteger(packetId) && packetId >= 0,
      `route decision key must be a nonnegative packet id: ${key}`);
    return `route:${packetDiscriminator(packetId)}`;
  }
  const value = String(key ?? '').trim();
  invariant(value.length > 0, `${kind} decision key must not be empty`);
  return `${kind}:${value}`;
}

function decisionIdentity(kind, key, row) {
  invariant(row && typeof row === 'object' && !Array.isArray(row),
    'decision identity row must be an object');
  const material = decisionIdentityMaterial(kind, key, row);
  return sha256(Buffer.from(JSON.stringify(material), 'utf8'));
}

function decisionIdentityMaterial(kind, key, row) {
  invariant(row && typeof row === 'object' && !Array.isArray(row),
    'decision identity row must be an object');
  return {
    decision_kind: kind,
    decision_key: decisionKey(kind, key),
    decision: canonicalIdentityValue(row),
  };
}

function toPosix(value) {
  return value.replaceAll('\\', '/');
}

function assertSafePath(filePath) {
  const resolved = path.resolve(filePath);
  invariant(!resolved.toLowerCase().includes('holdout'),
    `protected evidence path is forbidden: ${resolved}`);
  return resolved;
}

function exactBuildOf(document) {
  return document.exact_build ?? document.target_build ?? document.build ?? null;
}

function normalizeDecision(value) {
  const normalized = String(value ?? '').toUpperCase();
  if (ALLOWED_DECISIONS.includes(normalized)) return normalized;
  if (normalized.startsWith('PROMOTE')) return 'PROMOTE';
  if (normalized.startsWith('KEEP') || normalized.startsWith('CANDIDATE')) {
    return 'KEEP_CANDIDATE';
  }
  if (normalized.startsWith('REPURPOSE')) return 'REPURPOSE';
  if (normalized.startsWith('REJECT_FINAL')) return 'REJECT_FINAL';
  if (normalized.startsWith('REJECT')) return 'REJECT';
  throw new Error(`unsupported decision ${value}`);
}

function normalizeCapabilityName(value) {
  const normalized = String(value ?? '')
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  invariant(normalized.length > 0, 'semantic capability must not be empty');
  const aliases = {
    DEATH_TIMER_SECONDS: 'HERO_DEATH_TIMER',
    INVENTORY_SNAPSHOT_EXACT_LAYOUT: 'ITEM_STATE',
    SUPPORT_QUEST_ITEM_STAGE_SNAPSHOT: 'SUPPORT_QUEST_ITEM_STAGE',
  };
  return aliases[normalized] ?? normalized;
}

function packetIdsFromRecord(record) {
  if (Number.isInteger(record.packet_id)) return [record.packet_id];
  if (typeof record.packet_id === 'string' && /^\d+$/.test(record.packet_id)) {
    return [Number(record.packet_id)];
  }
  const candidate = record.packet_discriminator ?? record.route ?? '';
  if (typeof candidate !== 'string') return [];
  return [...candidate.matchAll(/0x([0-9a-f]{1,4})/gi)]
    .map((match) => Number.parseInt(match[1], 16));
}

function packetDiscriminator(packetId) {
  return `0x${packetId.toString(16).padStart(4, '0')}`;
}

function nextRequiredEvidence(record, fallback = []) {
  const value = record.next_required_evidence ?? fallback;
  if (Array.isArray(value)) return value.map(String);
  if (value === null || value === undefined || value === '') return [];
  return [String(value)];
}

function requiresOnlyExternalEvidence(requirements) {
  if (!Array.isArray(requirements) || requirements.length === 0) return false;
  const external = /controlled|external|new exact-build|new governed|new replay|live[- ]heap|live runtime|instrumentation|ground truth|oracle|dictionary|symbol|pdb|manual|provider|client-visible|source contract|business-state evidence|independent pre\/post/i;
  const local = /recover exact|recover the|decode the|decode bounded|search the|trace the|profile the|identify whether|explain the|full native decode|analy[sz]e the|bounded raw field profile/i;
  return requirements.every((value) => external.test(String(value)) && !local.test(String(value)));
}

function uniqueStrings(values) {
  return [...new Set(values.filter((value) => value !== null && value !== undefined)
    .map((value) => String(value)))]
    .sort((left, right) => left.localeCompare(right));
}

function compactContext(record) {
  const keys = [
    'candidate',
    'hypothesis',
    'claim',
    'resulting_classification',
    'reason',
    'scope',
    'decision_scope',
    'promotion_scope',
    'semantic_role_decision',
    'semantic_claim',
    'evidence_grade',
    'evidence_scope',
  ];
  const result = {};
  for (const key of keys) {
    if (record[key] !== undefined) result[key] = record[key];
  }
  return result;
}

function negativeEvidenceFromDocument(document) {
  const rows = [];
  for (const negative of [document.negative_evidence, document.negative_evidence_summary]) {
    if (!negative || typeof negative !== 'object') continue;
    for (const [key, value] of Object.entries(negative)) {
      if (key === 'semantic_claim' || value === false || value === null) continue;
      if (Array.isArray(value)) {
        for (const entry of value) rows.push(`${key}:${String(entry)}`);
      } else if (value === true) {
        rows.push(key);
      } else if (typeof value === 'string' || typeof value === 'number') {
        rows.push(`${key}:${String(value)}`);
      }
    }
  }
  return uniqueStrings(rows);
}

function provenanceFor(source) {
  return {
    artifact: source.artifact,
    sha256: source.sha256,
    source_id: source.id,
    source_schema: source.document.schema ?? null,
  };
}

function decisionHistoryEntry(record, source, negativeEvidence = []) {
  const decision = normalizeDecision(record.decision);
  const requirements = nextRequiredEvidence(record);
  const sourceEvidenceExhausted = record.evidence_exhausted === true;
  const currentResourceExhausted = sourceEvidenceExhausted
    || requiresOnlyExternalEvidence(requirements);
  const rowNegative = [...negativeEvidence];
  if (record.reason) rowNegative.push(`reason:${record.reason}`);
  if (record.counterexample) rowNegative.push(`counterexample:${record.counterexample}`);
  for (const hypothesis of record.rejected_hypotheses ?? []) {
    rowNegative.push(`rejected_hypotheses:${String(hypothesis)}`);
  }
  const isSaturationClosure = source.extractor === SATURATION_CLOSURE_EXTRACTOR;
  return {
    decision,
    status: STATUS_BY_DECISION[decision],
    evidence_exhausted: currentResourceExhausted,
    source_evidence_exhausted: sourceEvidenceExhausted,
    exhaustion_basis: sourceEvidenceExhausted
      ? 'SOURCE_DECLARED_EXHAUSTED'
      : currentResourceExhausted
        ? 'NORMALIZED_EXTERNAL_EVIDENCE_GATE'
        : 'LOCAL_ACTION_REMAINS',
    next_required_evidence: requirements,
    actual_reverse_engineering_executed: record.actual_reverse_engineering_executed === true
      || record.actual_reverse_engineering === true,
    actionable_hypotheses: Array.isArray(record.actionable_hypotheses)
      ? record.actionable_hypotheses.map(String) : [],
    provenance: provenanceFor(source),
    negative_evidence: uniqueStrings(rowNegative),
    source_context: compactContext(record),
    supersedes_previous_decision: isSaturationClosure
      ? record.supersedes_previous_decision === true
      : false,
    supersedes: isSaturationClosure && record.supersedes
      ? JSON.parse(JSON.stringify(record.supersedes))
      : null,
    precedence: source.precedence,
  };
}

function directRecords(source) {
  const documentNegative = negativeEvidenceFromDocument(source.document);
  const decisions = source.document.decisions ?? source.document;
  const route = [];
  for (const record of decisions.route_decisions ?? []) {
    for (const packetId of packetIdsFromRecord(record)) {
      route.push({
        packet_id: packetId,
        history: decisionHistoryEntry(record, source, documentNegative),
        identity_row: source.extractor === SATURATION_CLOSURE_EXTRACTOR ? record : null,
        source_decision_id: typeof record.decision_id === 'string' ? record.decision_id : null,
      });
    }
  }
  const capability = [];
  for (const record of decisions.capability_decisions ?? []) {
    const semanticCapability = normalizeCapabilityName(
      record.semantic_capability ?? record.capability,
    );
    capability.push({
      semantic_capability: semanticCapability,
      history: decisionHistoryEntry(record, source, documentNegative),
      identity_row: source.extractor === SATURATION_CLOSURE_EXTRACTOR ? record : null,
      source_decision_id: typeof record.decision_id === 'string' ? record.decision_id : null,
    });
  }
  const domain = [];
  for (const record of decisions.domain_decisions ?? []) {
    for (const name of allowedDomainsFor(record.domain)) {
      domain.push({
        domain: name,
        history: decisionHistoryEntry({ ...record, raw_domain: record.domain }, source, documentNegative),
        identity_row: source.extractor === SATURATION_CLOSURE_EXTRACTOR ? record : null,
        source_decision_id: typeof record.decision_id === 'string' ? record.decision_id : null,
      });
    }
  }
  return { route, capability, domain };
}

function highFrequencyRecords(source) {
  const route = [];
  for (const observed of source.document.routes ?? []) {
    const record = observed.research_decision;
    if (!record) continue;
    route.push({
      packet_id: Number(observed.packet_id),
      history: decisionHistoryEntry({
        ...record,
        evidence_scope: 'EVERY_FIFTH_SAFE_FOUR_REPLAY_SAMPLE',
      }, source),
    });
  }
  return { route, capability: [], domain: [] };
}

function entityItemRecords(source) {
  const result = directRecords(source);
  const specialized = (source.document.route_decisions ?? [])
    .find((record) => record.route === 'specialized_entity_route_set');
  if (specialized) {
    result.capability.push({
      semantic_capability: 'ENTITY_STRUCTURAL_TAXONOMY',
      history: decisionHistoryEntry(specialized, source),
    });
  }
  return result;
}

function buffSpellRecords(source) {
  const matrix = source.document;
  const promotions = new Map((matrix.promotions ?? []).map((row) => [row.id, row]));
  const candidates = new Map((matrix.candidates ?? []).map((row) => [row.id, row]));
  const route = [];
  const capability = [];
  const domain = [];
  const addRoute = (hex, record) => route.push({
    packet_id: Number.parseInt(hex.slice(2), 16),
    history: decisionHistoryEntry(record, source, record.negative_evidence ?? []),
  });
  const addCapability = (name, record) => capability.push({
    semantic_capability: normalizeCapabilityName(name),
    history: decisionHistoryEntry(record, source, record.negative_evidence ?? []),
  });
  const addDomain = (name, record) => domain.push({
    domain: name,
    history: decisionHistoryEntry(record, source, record.negative_evidence ?? []),
  });

  const buff = promotions.get('BUFF_ROUTE_OPERATION_AND_STABLE_FIELDS');
  if (buff) {
    const record = {
      decision: 'PROMOTE',
      evidence_exhausted: true,
      next_required_evidence: buff.limits,
      claim: buff.id,
      promotion_scope: buff.status,
      negative_evidence: buff.limits,
    };
    for (const hex of Object.keys(buff.routes ?? {})) addRoute(hex, record);
    addCapability('BUFF', record);
  }

  const cast = promotions.get('CAST_OCCURRENCE_TRANSLATOR_LAYOUT');
  if (cast) {
    const record = {
      decision: 'PROMOTE',
      evidence_exhausted: true,
      next_required_evidence: cast.limits,
      claim: cast.id,
      promotion_scope: cast.status,
      negative_evidence: cast.limits,
    };
    addRoute(cast.route, record);
    addCapability('CAST_SPELL', record);
  }

  const protection = promotions.get('HEAL_SHIELD_EVENT_LAYOUT_AND_AMOUNT_STAGE');
  if (protection) {
    const record = {
      decision: 'PROMOTE',
      evidence_exhausted: true,
      next_required_evidence: protection.limits,
      claim: protection.id,
      promotion_scope: protection.status,
      negative_evidence: protection.limits,
    };
    addRoute('0x0371', record);
    addCapability('HEAL_REPORTED', record);
    addCapability('SHIELD_GENERATED', record);
  }

  const damage = promotions.get('DAMAGE_STRUCTURAL_RECORD');
  if (damage) {
    const record = {
      decision: 'PROMOTE',
      evidence_exhausted: true,
      next_required_evidence: damage.limits,
      claim: damage.id,
      promotion_scope: damage.status,
      negative_evidence: damage.limits,
    };
    addRoute(damage.route, record);
    addCapability('DAMAGE_REPORTED', record);
  }

  const missile = promotions.get('MISSILE_ROUTE_AND_SAME_PARAM_LIFECYCLE');
  if (missile) {
    const record = {
      decision: 'PROMOTE',
      evidence_exhausted: true,
      next_required_evidence: missile.limits,
      claim: missile.id,
      promotion_scope: missile.status,
      negative_evidence: missile.limits,
    };
    for (const hex of missile.routes ?? []) addRoute(hex, record);
    addCapability('MISSILE', record);
  }

  for (const candidate of candidates.values()) {
    addCapability(candidate.id, {
      decision: 'KEEP_CANDIDATE',
      evidence_exhausted: true,
      next_required_evidence: [candidate.counterexample],
      counterexample: candidate.counterexample,
      claim: candidate.id,
      scope: candidate.status,
    });
  }

  for (const rejection of matrix.rejections ?? []) {
    addCapability(rejection.id, {
      decision: 'REJECT',
      evidence_exhausted: true,
      next_required_evidence: [],
      reason: rejection.decision,
      claim: rejection.id,
    });
  }

  for (const absence of matrix.exhausted_or_bounded_absence ?? []) {
    addCapability(absence.id, {
      decision: 'KEEP_CANDIDATE',
      evidence_exhausted: true,
      next_required_evidence: [absence.boundary ?? absence.status],
      reason: absence.status,
      claim: absence.id,
    });
  }

  const packet0199 = (matrix.rejections ?? [])
    .find((row) => row.id === 'PACKET_0x0199_GAMEPLAY_SPELL');
  if (packet0199) addRoute('0x0199', {
    decision: 'REPURPOSE',
    evidence_exhausted: true,
    next_required_evidence: [],
    resulting_classification: packet0199.decision,
    reason: 'Low-entropy periodic cluster is a spell negative control.',
  });
  const packet0310 = (matrix.rejections ?? [])
    .find((row) => row.id === 'PACKET_0x0310_SPELL_OR_MISSILE');
  if (packet0310) addRoute('0x0310', {
    decision: 'REPURPOSE',
    evidence_exhausted: true,
    next_required_evidence: [],
    resulting_classification: packet0310.decision,
    reason: String(packet0310.evidence),
  });

  addDomain('buff', {
    decision: 'KEEP_CANDIDATE',
    evidence_exhausted: true,
    next_required_evidence: ['Controlled safe exact-build calibration is required for universal stack and time roles.'],
    scope: matrix.status,
  });
  addDomain('spell', {
    decision: 'KEEP_CANDIDATE',
    evidence_exhausted: true,
    next_required_evidence: ['Independent exact key/source causal anchors are required for cast attribution.'],
    scope: matrix.status,
  });
  addDomain('protection', {
    decision: 'PROMOTE',
    evidence_exhausted: true,
    next_required_evidence: ['Independent pre/post state is required to distinguish effective, remaining, or absorbed amounts.'],
    scope: 'REPORTED_OR_GROSS_AND_GENERATED_AMOUNT_STAGE_ONLY',
  });
  addDomain('missile', {
    decision: 'KEEP_CANDIDATE',
    evidence_exhausted: true,
    next_required_evidence: ['A payload identity/owner/target anchor beyond same-param lifecycle association.'],
    scope: 'ROUTE_IDENTITY_PROMOTED_PAYLOAD_ROLES_UNRESOLVED',
  });
  addDomain('combat', {
    decision: 'KEEP_CANDIDATE',
    evidence_exhausted: true,
    next_required_evidence: ['Independent damage type, source kind, mitigation stage, or kill-credit anchors.'],
    scope: matrix.status,
  });

  return { route, capability, domain };
}

function allowedDomainsFor(value) {
  const raw = String(value ?? '').trim();
  if (ALLOWED_DOMAINS.includes(raw)) return [raw];
  const upper = raw.toUpperCase();
  if (/TARGET.*SELECTION/.test(upper)) return ['entity'];
  if (/CHARACTER.*DATA/.test(upper)) return ['entity', 'state'];
  if (/PRESENTATION.*ATTACHMENT/.test(upper)) return ['UI'];
  if (/HERO.*SNAPSHOT/.test(upper)) return ['state'];
  if (/UNIT.*INFO.*BAR/.test(upper)) return ['state'];
  if (/GENERIC.*PROTOCOL.*SIGNAL/.test(upper)) return ['system'];
  if (/ENTITY.*STATE|STATE.*ENTITY/.test(upper)) return ['entity', 'state'];
  if (/ENTITY.*LIFECYCLE|LIFECYCLE.*ENTITY/.test(upper)) return ['entity'];
  if (/SPELL.*BUFF|BUFF.*SPELL/.test(upper)) return ['spell', 'buff'];
  if (/ITEM.*ECONOMY|ECONOMY.*ITEM/.test(upper)) return ['item', 'economy'];
  if (/PROTECTION|SHIELD|HEAL/.test(upper)) return ['protection'];
  if (/BUFF|DEBUFF/.test(upper)) return ['buff'];
  if (/MISSILE|PROJECTILE/.test(upper)) return ['missile'];
  if (/SPELL|CAST|ABILITY/.test(upper)) return ['spell'];
  if (/DAMAGE|COMBAT|DEATH|LIFECYCLE/.test(upper)) return ['combat'];
  if (/HP|DEFENSE|RESOURCE|STAT|STATE/.test(upper)) return ['state'];
  if (/ITEM|INVENTORY/.test(upper)) return ['item'];
  if (/ECONOMY|GOLD|SALE|SHOP/.test(upper)) return ['economy'];
  if (/ENTITY|REPLICATION|BITSTREAM/.test(upper)) return ['entity'];
  if (/MINION/.test(upper)) return ['minion'];
  if (/JUNGLE/.test(upper)) return ['jungle'];
  if (/OBJECTIVE/.test(upper)) return ['objective'];
  if (/STRUCTURE|TOWER|TURRET/.test(upper)) return ['structure'];
  if (/VISION|WARD/.test(upper)) return ['vision'];
  if (/VISIBILITY|REVEAL|SIGHT/.test(upper)) return ['vision'];
  if (/MOVEMENT|POSITION|PATH|DASH|TELEPORT/.test(upper)) return ['movement'];
  if (/MAP/.test(upper)) return ['map'];
  if (/UI|RENDER|VISUAL/.test(upper)) return ['UI'];
  if (/SYSTEM|MESSAGE|TELEMETRY/.test(upper)) return ['system'];
  if (/NOISE/.test(upper)) return ['noise'];
  if (/UNKNOWN|OPAQUE|UNMAPPED/.test(upper)) return ['unknown'];
  throw new Error(`cannot map domain decision ${value} to allowed vocabulary`);
}

function sourceRecords(source) {
  if (source.extractor === 'high_frequency') return highFrequencyRecords(source);
  if (source.extractor === 'buff_spell') return buffSpellRecords(source);
  if (source.extractor === 'entity_item') return entityItemRecords(source);
  if (source.extractor === 'direct') return directRecords(source);
  if (source.extractor === SATURATION_CLOSURE_EXTRACTOR) return directRecords(source);
  if (source.extractor === 'supporting_only') return { route: [], capability: [], domain: [] };
  throw new Error(`unknown source extractor ${source.extractor}`);
}

function selectionRank(history) {
  const open = history.evidence_exhausted ? 0 : 100;
  const decision = {
    KEEP_CANDIDATE: 50,
    PROMOTE: 40,
    REPURPOSE: 30,
    REJECT: 20,
    REJECT_FINAL: 10,
  }[history.decision];
  return (history.precedence * 1000) + open + decision;
}

function decisionKindForKeyName(keyName) {
  return {
    packet_id: 'route',
    semantic_capability: 'capability',
    domain: 'domain',
  }[keyName];
}

function attachDecisionIdentities(records, keyName) {
  const kind = decisionKindForKeyName(keyName);
  invariant(kind, `unsupported decision key field ${keyName}`);
  const ordinals = new Map();
  return records.map((record) => {
    const key = record[keyName];
    const canonicalKey = decisionKey(kind, key);
    const history = {
      ...record.history,
      decision_key: canonicalKey,
      effective: true,
      superseded_by: null,
    };
    if (record.identity_row) {
      invariant(typeof record.identity_row.decision_id === 'string',
        `${canonicalKey} closure decision_id is required`);
      const expected = decisionIdentity(kind, key, record.identity_row);
      invariant(record.identity_row.decision_id === expected,
        `${canonicalKey} closure decision_id mismatch`);
      history.source_decision_id = expected;
      history.source_decision_identity_material = decisionIdentityMaterial(
        kind, key, record.identity_row,
      );
    } else {
      const ordinalKey = `${history.provenance.source_id}\u0000${canonicalKey}`;
      const identityOrdinal = ordinals.get(ordinalKey) ?? 0;
      ordinals.set(ordinalKey, identityOrdinal + 1);
      history.identity_ordinal = identityOrdinal;
      history.source_decision_id = record.source_decision_id ?? null;
      history.source_decision_identity_material = null;
    }
    history.decision_identity_material = decisionIdentityMaterial(kind, key, history);
    history.decision_id = sha256(Buffer.from(
      JSON.stringify(history.decision_identity_material), 'utf8',
    ));
    return { [keyName]: key, history, identity_row: record.identity_row ?? null };
  });
}

function canonicalSupersessionKey(kind, value) {
  const raw = String(value ?? '');
  return raw.startsWith(`${kind}:`) ? raw : decisionKey(kind, value);
}

function closureIdentityMatches(row, closureSource) {
  if (!row || typeof row !== 'object') return false;
  return row.source_id === closureSource.id
    || row.artifact === closureSource.artifact
    || row.sha256 === closureSource.sha256
    || row.source_schema === SATURATION_CLOSURE_SCHEMA;
}

function assertPreclosureHasNoClosureCycle(preclosureLedger, closureSource) {
  invariant(!(preclosureLedger.input_sources ?? []).some((row) =>
    closureIdentityMatches(row, closureSource)),
  'preclosure ledger contains circular closure input provenance');
  for (const collection of [
    preclosureLedger.route_decisions ?? [],
    preclosureLedger.capability_decisions ?? [],
    preclosureLedger.domain_decisions ?? [],
  ]) {
    for (const decision of collection) {
      invariant(!closureIdentityMatches(decision.provenance, closureSource),
        `preclosure decision ${decision.decision_key ?? 'unknown'} selects circular closure provenance`);
      invariant(!(decision.decision_history ?? []).some((history) =>
        closureIdentityMatches(history.provenance, closureSource)),
      `preclosure decision ${decision.decision_key ?? 'unknown'} contains circular closure history`);
    }
  }
}

function preclosureLedgerBinding(document) {
  const binding = document?.preclosure_inputs?.decision_ledger;
  invariant(binding && typeof binding === 'object' && !Array.isArray(binding),
    'saturation closure preclosure decision_ledger binding is required');
  invariant(typeof binding.path === 'string' && binding.path.length > 0,
    'saturation closure preclosure decision_ledger path is required');
  invariant(/^[0-9a-f]{64}$/.test(binding.sha256 ?? ''),
    'saturation closure preclosure decision_ledger sha256 is invalid');
  invariant(Number.isInteger(binding.byte_count) && binding.byte_count >= 0,
    'saturation closure preclosure decision_ledger byte_count is invalid');
  invariant(binding.schema === LEDGER_SCHEMA,
    'saturation closure preclosure decision_ledger schema mismatch');
  invariant(binding.schema_version === 1,
    'saturation closure preclosure decision_ledger schema_version mismatch');
  return binding;
}

function validateClosureDocumentHeader(document) {
  invariant(document.schema === SATURATION_CLOSURE_SCHEMA,
    'saturation closure source schema mismatch');
  invariant(document.schema_version === 1,
    'saturation closure source schema_version mismatch');
  invariant(document.exact_build === EXACT_BUILD,
    'saturation closure exact build mismatch');
  invariant(document.exact_build_only === true,
    'saturation closure must be exact-build only');
  invariant(document.nearest_build_fallback === 'FORBIDDEN',
    'saturation closure nearest-build fallback must be FORBIDDEN');
  invariant(Array.isArray(document.route_decisions),
    'saturation closure route_decisions must be an array');
  invariant(Array.isArray(document.capability_decisions),
    'saturation closure capability_decisions must be an array');
  invariant(Array.isArray(document.domain_decisions),
    'saturation closure domain_decisions must be an array');
  const queue = document.preclosure_inputs?.research_queue;
  invariant(queue && typeof queue === 'object' && !Array.isArray(queue),
    'saturation closure preclosure research_queue binding is required');
  invariant(typeof queue.path === 'string' && queue.path.length > 0,
    'saturation closure preclosure research_queue path is required');
  invariant(/^[0-9a-f]{64}$/.test(queue.sha256 ?? ''),
    'saturation closure preclosure research_queue sha256 is invalid');
  invariant(Number.isInteger(queue.byte_count) && queue.byte_count >= 0,
    'saturation closure preclosure research_queue byte_count is invalid');
  invariant(queue.schema === RESEARCH_QUEUE_SCHEMA,
    'saturation closure preclosure research_queue schema mismatch');
  invariant(queue.schema_version === 2,
    'saturation closure preclosure research_queue schema_version mismatch');
  const boundary = document.protected_holdout;
  invariant(boundary?.enumerated === false
    && boundary.read === false
    && boundary.hashed === false
    && boundary.decoded === false
    && boundary.tested === false
    && boundary.consumed === false,
  'saturation closure protected evidence boundary must be explicitly clean');
}

function validateClosureRecordBoundary(record, canonicalKey) {
  invariant(record.actual_reverse_engineering_executed === true,
    `${canonicalKey} closure must attest actual reverse engineering`);
  invariant(record.evidence_exhausted === true,
    `${canonicalKey} closure must attest evidence exhaustion`);
  invariant(Array.isArray(record.actionable_hypotheses)
    && record.actionable_hypotheses.length === 0,
  `${canonicalKey} closure actionable_hypotheses must be an empty array`);
  invariant(Array.isArray(record.next_required_evidence),
    `${canonicalKey} closure next_required_evidence must be an array`);
  invariant(typeof record.supersedes_previous_decision === 'boolean',
    `${canonicalKey} closure supersedes_previous_decision must be boolean`);
}

function setEquals(left, right) {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

function validateAndApplyClosureSupersession({
  sources,
  generatedAt,
  routeRecords,
  capabilityRecords,
  domainRecords,
}) {
  const closureSources = sources.filter((source) =>
    source.extractor === SATURATION_CLOSURE_EXTRACTOR);
  invariant(closureSources.length <= 1,
    'at most one saturation closure source may be integrated per ledger build');
  if (closureSources.length === 0) return;

  const closureSource = closureSources[0];
  invariant(closureSource.id === SATURATION_CLOSURE_SOURCE_ID,
    `saturation closure source id must be ${SATURATION_CLOSURE_SOURCE_ID}`);
  validateClosureDocumentHeader(closureSource.document);
  invariant(closureSource.preclosure_ledger?.document,
    'saturation closure requires an explicitly allowlisted preclosure ledger snapshot');
  invariant(Buffer.isBuffer(closureSource.preclosure_ledger.bytes),
    'saturation closure preclosure ledger bytes are required');

  const binding = preclosureLedgerBinding(closureSource.document);
  const preclosure = closureSource.preclosure_ledger;
  invariant(toPosix(binding.path) === toPosix(preclosure.artifact),
    'saturation closure preclosure ledger path does not match the allowlisted snapshot');
  invariant(binding.sha256 === preclosure.sha256,
    'saturation closure preclosure ledger sha256 mismatch');
  invariant(binding.byte_count === preclosure.byte_count,
    'saturation closure preclosure ledger byte_count mismatch');
  invariant(binding.schema === preclosure.document.schema,
    'saturation closure preclosure ledger bound schema mismatch');
  invariant(binding.schema_version === preclosure.document.schema_version,
    'saturation closure preclosure ledger bound schema_version mismatch');
  invariant(preclosure.sha256 === sha256(preclosure.bytes),
    'saturation closure preclosure ledger loaded-byte hash mismatch');
  invariant(preclosure.byte_count === preclosure.bytes.length,
    'saturation closure preclosure ledger loaded-byte count mismatch');
  assertPreclosureHasNoClosureCycle(preclosure.document, closureSource);
  validateDecisionLedger(preclosure.document);

  const baseSources = sources.filter((source) => source !== closureSource);
  const rebuiltPreclosure = buildDecisionLedger({
    sources: baseSources,
    generatedAt: preclosure.document.generated_at ?? generatedAt,
  });
  const rebuiltBytes = jsonBytes(rebuiltPreclosure);
  invariant(rebuiltBytes.equals(preclosure.bytes),
    'preclosure ledger snapshot is not the exact deterministic ledger for the current base sources');

  const descriptors = [
    {
      kind: 'route', keyName: 'packet_id', records: routeRecords,
      snapshot: preclosure.document.route_decisions,
    },
    {
      kind: 'capability', keyName: 'semantic_capability', records: capabilityRecords,
      snapshot: preclosure.document.capability_decisions,
    },
    {
      kind: 'domain', keyName: 'domain', records: domainRecords,
      snapshot: preclosure.document.domain_decisions,
    },
  ];

  for (const descriptor of descriptors) {
    const snapshotByKey = new Map(descriptor.snapshot.map((row) => [row.decision_key, row]));
    const closureRecords = descriptor.records.filter((record) =>
      record.history.provenance.source_id === closureSource.id);
    const seenKeys = new Set();
    for (const record of closureRecords) {
      const key = record[descriptor.keyName];
      const canonicalKey = decisionKey(descriptor.kind, key);
      invariant(!seenKeys.has(canonicalKey),
        `duplicate saturation closure decision ${canonicalKey}`);
      seenKeys.add(canonicalKey);
      const rawRecord = record.identity_row;
      validateClosureRecordBoundary(rawRecord, canonicalKey);
      const previous = snapshotByKey.get(canonicalKey) ?? null;
      if (!previous) {
        invariant(rawRecord.supersedes_previous_decision === false
          && rawRecord.supersedes === null,
        `${canonicalKey} has no preclosure decision and must not declare supersession`);
        record.history.supersession_validated = true;
        continue;
      }

      invariant(rawRecord.supersedes_previous_decision === true,
        `${canonicalKey} must explicitly supersede its preclosure decision chain`);
      const supersedes = rawRecord.supersedes;
      invariant(supersedes && typeof supersedes === 'object' && !Array.isArray(supersedes),
        `${canonicalKey} supersedes binding is required`);
      invariant(supersedes.preclosure_ledger_sha256 === preclosure.sha256,
        `${canonicalKey} supersedes binding has a stale preclosure ledger sha256`);
      invariant(supersedes.decision_kind === descriptor.kind,
        `${canonicalKey} supersedes decision_kind mismatch`);
      invariant(canonicalSupersessionKey(descriptor.kind, supersedes.decision_key) === canonicalKey,
        `${canonicalKey} supersedes decision_key mismatch`);
      invariant(Array.isArray(supersedes.superseded_decision_ids)
        && supersedes.superseded_decision_ids.length > 0,
      `${canonicalKey} superseded_decision_ids must be a non-empty array`);
      invariant(supersedes.superseded_decision_ids.every((id) =>
        typeof id === 'string' && /^[0-9a-f]{64}$/.test(id)),
      `${canonicalKey} superseded_decision_ids contains an invalid id`);
      const declaredIds = new Set(supersedes.superseded_decision_ids);
      invariant(declaredIds.size === supersedes.superseded_decision_ids.length,
        `${canonicalKey} superseded_decision_ids must be unique`);
      const effectivePreviousIds = new Set(previous.decision_history
        .filter((history) => history.effective !== false)
        .map((history) => history.decision_id));
      invariant(setEquals(declaredIds, effectivePreviousIds),
        `${canonicalKey} superseded_decision_ids must exactly match the pinned effective decision chain`);

      const currentPrevious = descriptor.records.filter((candidate) =>
        candidate.history.provenance.source_id !== closureSource.id
        && candidate.history.decision_key === canonicalKey
        && declaredIds.has(candidate.history.decision_id));
      invariant(currentPrevious.length === declaredIds.size,
        `${canonicalKey} superseded decision ids do not resolve exactly once in current base histories`);
      const supersededBy = {
        decision_id: record.history.decision_id,
        decision_kind: descriptor.kind,
        decision_key: canonicalKey,
        preclosure_ledger_sha256: preclosure.sha256,
        provenance: record.history.provenance,
      };
      for (const candidate of currentPrevious) {
        candidate.history.effective = false;
        candidate.history.superseded_by = supersededBy;
      }
      record.history.supersession_validated = true;
    }
  }
}

function stripInternalHistoryFields(history) {
  const { precedence: ignored, ...publicHistory } = history;
  return publicHistory;
}

function aggregateByKey(records, keyName) {
  const buckets = new Map();
  for (const record of records) {
    const key = record[keyName];
    if (!buckets.has(key)) buckets.set(key, []);
    buckets.get(key).push(record.history);
  }
  return [...buckets.entries()].map(([key, histories]) => {
    const ordered = [...histories].sort((left, right) =>
      selectionRank(right) - selectionRank(left)
      || left.provenance.artifact.localeCompare(right.provenance.artifact));
    const effective = ordered.filter((history) => history.effective !== false);
    invariant(effective.length > 0, `${decisionKey(decisionKindForKeyName(keyName), key)} has no effective decision history`);
    const selected = effective[0];
    return {
      [keyName]: key,
      ...(keyName === 'packet_id' ? { packet_discriminator: packetDiscriminator(key) } : {}),
      decision_key: selected.decision_key,
      decision_id: selected.decision_id,
      decision: selected.decision,
      status: selected.status,
      evidence_exhausted: selected.evidence_exhausted,
      exhaustion_basis: selected.exhaustion_basis,
      actual_reverse_engineering_executed: selected.actual_reverse_engineering_executed === true,
      actionable_hypotheses: uniqueStrings(selected.actionable_hypotheses),
      next_required_evidence: selected.next_required_evidence,
      provenance: selected.provenance,
      negative_evidence: uniqueStrings(effective.flatMap((row) => row.negative_evidence)),
      superseded_decision_count: ordered.length - effective.length,
      decision_history: ordered.map(stripInternalHistoryFields),
    };
  });
}

function aggregateDomains(records) {
  const buckets = new Map();
  for (const record of records) {
    if (!buckets.has(record.domain)) buckets.set(record.domain, []);
    buckets.get(record.domain).push(record.history);
  }
  return [...buckets.entries()].map(([domain, histories]) => {
    const ordered = [...histories].sort((left, right) =>
      selectionRank(right) - selectionRank(left)
      || left.provenance.artifact.localeCompare(right.provenance.artifact));
    const effective = ordered.filter((history) => history.effective !== false);
    invariant(effective.length > 0, `${decisionKey('domain', domain)} has no effective decision history`);
    const open = effective.filter((row) => !row.evidence_exhausted);
    const selected = (open.length > 0 ? open : effective)[0];
    return {
      domain,
      decision_key: selected.decision_key,
      decision_id: selected.decision_id,
      decision: selected.decision,
      status: selected.status,
      evidence_exhausted: selected.evidence_exhausted,
      actual_reverse_engineering_executed: selected.actual_reverse_engineering_executed === true,
      actionable_hypotheses: uniqueStrings(selected.actionable_hypotheses),
      next_required_evidence: uniqueStrings(selected.next_required_evidence),
      provenance: selected.provenance,
      negative_evidence: uniqueStrings(effective.flatMap((row) => row.negative_evidence)),
      superseded_decision_count: ordered.length - effective.length,
      decision_history: ordered.map(stripInternalHistoryFields),
    };
  });
}

function loadSafeSources(root = process.cwd(), specs = DEFAULT_SAFE_SOURCE_SPECS) {
  return specs.map((spec) => {
    invariant(!String(spec.artifact).toLowerCase().includes('holdout'),
      `protected source is forbidden: ${spec.artifact}`);
    const resolved = assertSafePath(path.resolve(root, spec.artifact));
    const bytes = fs.readFileSync(resolved);
    const document = JSON.parse(bytes.toString('utf8'));
    invariant(exactBuildOf(document) === EXACT_BUILD,
      `${spec.id} exact build mismatch`);
    if (document.nearest_build_fallback !== undefined) {
      invariant(document.nearest_build_fallback === 'FORBIDDEN',
        `${spec.id} nearest-build fallback must be FORBIDDEN`);
    }
    const source = {
      ...spec,
      artifact: toPosix(spec.artifact),
      resolved,
      bytes,
      byte_count: bytes.length,
      sha256: sha256(bytes),
      document,
    };
    if (spec.extractor === SATURATION_CLOSURE_EXTRACTOR) {
      const preclosureArtifact = spec.preclosure_ledger_artifact
        ?? spec.preclosure_artifact;
      invariant(typeof preclosureArtifact === 'string' && preclosureArtifact.length > 0,
        `${spec.id} preclosure_ledger_artifact is required`);
      invariant(!preclosureArtifact.toLowerCase().includes('holdout'),
        `protected preclosure source is forbidden: ${preclosureArtifact}`);
      const preclosureResolved = assertSafePath(path.resolve(root, preclosureArtifact));
      const preclosureBytes = fs.readFileSync(preclosureResolved);
      const preclosureDocument = JSON.parse(preclosureBytes.toString('utf8'));
      invariant(exactBuildOf(preclosureDocument) === EXACT_BUILD,
        `${spec.id} preclosure ledger exact build mismatch`);
      source.preclosure_ledger = {
        artifact: toPosix(preclosureArtifact),
        resolved: preclosureResolved,
        bytes: preclosureBytes,
        byte_count: preclosureBytes.length,
        sha256: sha256(preclosureBytes),
        document: preclosureDocument,
      };
    }
    return source;
  });
}

function validateDecisionRecord(record, keyName) {
  invariant(ALLOWED_DECISIONS.includes(record.decision), `${keyName} decision vocabulary mismatch`);
  invariant(ALLOWED_STATUSES.includes(record.status), `${keyName} status vocabulary mismatch`);
  invariant(typeof record.evidence_exhausted === 'boolean', `${keyName} evidence_exhausted must be boolean`);
  invariant(typeof record.actual_reverse_engineering_executed === 'boolean',
    `${keyName} actual_reverse_engineering_executed must be boolean`);
  invariant(Array.isArray(record.actionable_hypotheses),
    `${keyName} actionable_hypotheses must be an array`);
  invariant(Array.isArray(record.next_required_evidence), `${keyName} next_required_evidence must be an array`);
  invariant(typeof record.decision_key === 'string' && record.decision_key.length > 0,
    `${keyName} decision_key missing`);
  invariant(/^[0-9a-f]{64}$/.test(record.decision_id ?? ''),
    `${keyName} decision_id invalid`);
  invariant(record.provenance && typeof record.provenance.artifact === 'string', `${keyName} provenance artifact missing`);
  invariant(/^[0-9a-f]{64}$/.test(record.provenance.sha256), `${keyName} provenance sha256 invalid`);
  invariant(!record.provenance.artifact.toLowerCase().includes('holdout'), `${keyName} protected provenance forbidden`);
  invariant(Array.isArray(record.decision_history) && record.decision_history.length > 0,
    `${keyName} decision history missing`);
  invariant(Number.isInteger(record.superseded_decision_count)
    && record.superseded_decision_count >= 0,
  `${keyName} superseded_decision_count invalid`);
  const historyIds = new Set();
  const effectiveIds = new Set();
  let supersededCount = 0;
  for (const history of record.decision_history) {
    invariant(history.decision_key === record.decision_key,
      `${keyName} history decision_key mismatch`);
    invariant(/^[0-9a-f]{64}$/.test(history.decision_id ?? ''),
      `${keyName} history decision_id invalid`);
    const kind = decisionKindForKeyName(
      Object.prototype.hasOwnProperty.call(record, 'packet_id') ? 'packet_id'
        : Object.prototype.hasOwnProperty.call(record, 'semantic_capability')
          ? 'semantic_capability' : 'domain',
    );
    const rawKey = kind === 'route' ? record.packet_id
      : kind === 'capability' ? record.semantic_capability : record.domain;
    const expectedMaterial = decisionIdentityMaterial(kind, rawKey, history);
    invariant(JSON.stringify(history.decision_identity_material)
      === JSON.stringify(expectedMaterial),
    `${keyName} history decision_identity_material mismatch`);
    invariant(history.decision_id === sha256(Buffer.from(
      JSON.stringify(expectedMaterial), 'utf8',
    )), `${keyName} history decision_id content identity mismatch`);
    invariant(history.source_decision_id === null
      || typeof history.source_decision_id === 'string',
    `${keyName} history source_decision_id must be string or null`);
    if (history.source_decision_identity_material !== null) {
      invariant(/^[0-9a-f]{64}$/.test(history.source_decision_id ?? ''),
        `${keyName} history source_decision_id must be a content hash`);
      invariant(history.source_decision_id === sha256(Buffer.from(JSON.stringify(
        history.source_decision_identity_material,
      ), 'utf8')), `${keyName} history source_decision_id content identity mismatch`);
      invariant(history.source_decision_identity_material.decision_kind === kind
        && history.source_decision_identity_material.decision_key
          === decisionKey(kind, rawKey),
      `${keyName} source decision identity boundary mismatch`);
      const sourceDecision = history.source_decision_identity_material.decision;
      invariant(sourceDecision?.decision === history.decision
        && sourceDecision.evidence_exhausted === history.source_evidence_exhausted
        && sourceDecision.actual_reverse_engineering_executed
          === history.actual_reverse_engineering_executed
        && JSON.stringify(sourceDecision.actionable_hypotheses)
          === JSON.stringify(history.actionable_hypotheses)
        && sourceDecision.supersedes_previous_decision
          === history.supersedes_previous_decision
        && JSON.stringify(sourceDecision.supersedes)
          === JSON.stringify(canonicalIdentityValue(history.supersedes)),
      `${keyName} normalized history is not bound to its source decision identity`);
    }
    invariant(!historyIds.has(history.decision_id),
      `${keyName} duplicate history decision_id ${history.decision_id}`);
    historyIds.add(history.decision_id);
    invariant(typeof history.effective === 'boolean',
      `${keyName} history effective must be boolean`);
    invariant(typeof history.supersedes_previous_decision === 'boolean',
      `${keyName} history supersedes_previous_decision must be boolean`);
    if (history.supersedes_previous_decision) {
      invariant(history.supersedes && typeof history.supersedes === 'object',
        `${keyName} superseding history must retain its binding`);
      invariant(history.supersession_validated === true,
        `${keyName} superseding history was not cryptographically validated`);
    } else {
      invariant(history.supersedes === null,
        `${keyName} non-superseding history cannot carry a supersedes binding`);
    }
    if (history.effective) {
      invariant(history.superseded_by === null,
        `${keyName} effective history cannot be marked superseded`);
      effectiveIds.add(history.decision_id);
    } else {
      supersededCount += 1;
      invariant(history.superseded_by && typeof history.superseded_by === 'object',
        `${keyName} ineffective history must identify its superseding decision`);
      invariant(/^[0-9a-f]{64}$/.test(history.superseded_by.decision_id ?? ''),
        `${keyName} superseded_by decision_id invalid`);
      invariant(history.superseded_by.decision_key === record.decision_key,
        `${keyName} superseded_by decision_key mismatch`);
      invariant(/^[0-9a-f]{64}$/.test(
        history.superseded_by.preclosure_ledger_sha256 ?? ''),
      `${keyName} superseded_by preclosure ledger sha256 invalid`);
    }
  }
  invariant(effectiveIds.has(record.decision_id),
    `${keyName} selected decision_id is not effective`);
  const selectedHistory = record.decision_history.find((row) =>
    row.effective && row.decision_id === record.decision_id);
  invariant(selectedHistory
    && record.decision === selectedHistory.decision
    && record.status === selectedHistory.status
    && record.evidence_exhausted === selectedHistory.evidence_exhausted
    && record.actual_reverse_engineering_executed
      === selectedHistory.actual_reverse_engineering_executed
    && JSON.stringify(record.actionable_hypotheses)
      === JSON.stringify(uniqueStrings(selectedHistory.actionable_hypotheses))
    && record.provenance.artifact === selectedHistory.provenance.artifact
    && record.provenance.sha256 === selectedHistory.provenance.sha256
    && record.provenance.source_id === selectedHistory.provenance.source_id
    && record.provenance.source_schema === selectedHistory.provenance.source_schema,
  `${keyName} selected fields must come directly from its effective decision`);
  invariant(record.superseded_decision_count === supersededCount,
    `${keyName} superseded_decision_count mismatch`);
  for (const history of record.decision_history.filter((row) => !row.effective)) {
    invariant(effectiveIds.has(history.superseded_by.decision_id),
      `${keyName} superseded_by decision_id is not an effective history`);
  }
  for (const history of record.decision_history
    .filter((row) => row.supersedes_previous_decision)) {
    invariant(history.supersedes.decision_key === record.decision_key
      || canonicalSupersessionKey(
        history.supersedes.decision_kind,
        history.supersedes.decision_key,
      ) === record.decision_key,
    `${keyName} supersedes decision_key mismatch`);
    invariant(/^[0-9a-f]{64}$/.test(
      history.supersedes.preclosure_ledger_sha256 ?? ''),
    `${keyName} supersedes preclosure ledger sha256 invalid`);
    invariant(Array.isArray(history.supersedes.superseded_decision_ids),
      `${keyName} superseded_decision_ids must be an array`);
    const declared = new Set(history.supersedes.superseded_decision_ids);
    invariant(declared.size === history.supersedes.superseded_decision_ids.length,
      `${keyName} superseded_decision_ids must be unique`);
    const actual = new Set(record.decision_history
      .filter((candidate) => !candidate.effective
        && candidate.superseded_by.decision_id === history.decision_id)
      .map((candidate) => candidate.decision_id));
    invariant(setEquals(declared, actual),
      `${keyName} supersedes binding does not match marked superseded history`);
  }
}

function validateDecisionLedger(ledger) {
  invariant(ledger.schema === LEDGER_SCHEMA, 'decision ledger schema mismatch');
  invariant(ledger.exact_build === EXACT_BUILD, 'decision ledger exact build mismatch');
  invariant(ledger.exact_build_only === true, 'decision ledger must be exact-build only');
  invariant(ledger.nearest_build_fallback === 'FORBIDDEN', 'nearest-build fallback must be FORBIDDEN');
  invariant(Array.isArray(ledger.route_decisions), 'route_decisions must be an array');
  invariant(Array.isArray(ledger.capability_decisions), 'capability_decisions must be an array');
  invariant(Array.isArray(ledger.domain_decisions), 'domain_decisions must be an array');
  invariant(Array.isArray(ledger.input_sources) && ledger.input_sources.length > 0,
    'input_sources must be a non-empty array');
  const routeIds = new Set();
  for (const record of ledger.route_decisions) {
    invariant(Number.isInteger(record.packet_id) && record.packet_id >= 0,
      'route packet_id must be a nonnegative integer');
    invariant(!routeIds.has(record.packet_id), `duplicate route ${record.packet_id}`);
    routeIds.add(record.packet_id);
    invariant(record.decision_key === decisionKey('route', record.packet_id),
      `route ${record.packet_id} decision_key mismatch`);
    validateDecisionRecord(record, `route ${record.packet_id}`);
  }
  const capabilities = new Set();
  for (const record of ledger.capability_decisions) {
    invariant(typeof record.semantic_capability === 'string' && record.semantic_capability.length > 0,
      'capability semantic_capability missing');
    invariant(!capabilities.has(record.semantic_capability),
      `duplicate capability ${record.semantic_capability}`);
    capabilities.add(record.semantic_capability);
    invariant(record.decision_key === decisionKey('capability', record.semantic_capability),
      `capability ${record.semantic_capability} decision_key mismatch`);
    validateDecisionRecord(record, `capability ${record.semantic_capability}`);
  }
  const domains = new Set();
  for (const record of ledger.domain_decisions) {
    invariant(ALLOWED_DOMAINS.includes(record.domain), `unknown domain ${record.domain}`);
    invariant(!domains.has(record.domain), `duplicate domain ${record.domain}`);
    domains.add(record.domain);
    invariant(record.decision_key === decisionKey('domain', record.domain),
      `domain ${record.domain} decision_key mismatch`);
    validateDecisionRecord(record, `domain ${record.domain}`);
  }
  const inputSourceIds = new Set();
  const inputSourcesById = new Map();
  let closureInput = null;
  for (const source of ledger.input_sources) {
    invariant(typeof source.source_id === 'string' && source.source_id.length > 0,
      'input source id missing');
    invariant(!inputSourceIds.has(source.source_id),
      `duplicate input source ${source.source_id}`);
    inputSourceIds.add(source.source_id);
    inputSourcesById.set(source.source_id, source);
    invariant(!source.artifact.toLowerCase().includes('holdout'), 'protected input source forbidden');
    invariant(/^[0-9a-f]{64}$/.test(source.sha256), 'input source sha256 invalid');
    if (source.extractor === SATURATION_CLOSURE_EXTRACTOR) {
      invariant(closureInput === null, 'multiple closure input sources are forbidden');
      invariant(source.source_id === SATURATION_CLOSURE_SOURCE_ID,
        'closure input source id mismatch');
      invariant(source.source_schema === SATURATION_CLOSURE_SCHEMA,
        'closure input source schema mismatch');
      closureInput = source;
      const preclosure = source.preclosure_decision_ledger;
      invariant(preclosure && typeof preclosure === 'object',
        'closure input source preclosure ledger attestation missing');
      invariant(preclosure.schema === LEDGER_SCHEMA,
        'closure input source preclosure ledger schema mismatch');
      invariant(preclosure.schema_version === 1,
        'closure input source preclosure ledger schema_version mismatch');
      invariant(/^[0-9a-f]{64}$/.test(preclosure.sha256 ?? ''),
        'closure input source preclosure ledger sha256 invalid');
      invariant(!String(preclosure.artifact).toLowerCase().includes('holdout'),
        'protected preclosure input source forbidden');
    }
  }
  for (const record of [
    ...ledger.route_decisions,
    ...ledger.capability_decisions,
    ...ledger.domain_decisions,
  ]) {
    for (const history of record.decision_history) {
      const pinnedSource = inputSourcesById.get(history.provenance?.source_id);
      invariant(pinnedSource
        && history.provenance.artifact === pinnedSource.artifact
        && history.provenance.sha256 === pinnedSource.sha256
        && history.provenance.source_schema === pinnedSource.source_schema,
      `${record.decision_key} history provenance is not pinned by an exact input source`);
      if (history.supersession_validated === true || history.effective === false) {
        invariant(closureInput !== null,
          `${record.decision_key} supersession history requires a closure input source`);
      }
      if (history.supersession_validated === true) {
        invariant(history.provenance.source_id === closureInput.source_id
          && history.provenance.artifact === closureInput.artifact
          && history.provenance.sha256 === closureInput.sha256
          && history.provenance.source_schema === closureInput.source_schema,
        `${record.decision_key} validated supersession provenance does not match closure input`);
      }
      if (history.effective === false) {
        invariant(history.superseded_by.preclosure_ledger_sha256
          === closureInput.preclosure_decision_ledger.sha256,
        `${record.decision_key} superseded history preclosure sha256 mismatch`);
        invariant(history.superseded_by.provenance.source_id === closureInput.source_id
          && history.superseded_by.provenance.artifact === closureInput.artifact
          && history.superseded_by.provenance.sha256 === closureInput.sha256
          && history.superseded_by.provenance.source_schema === closureInput.source_schema,
        `${record.decision_key} superseded_by provenance does not match closure input`);
      }
    }
  }
  const boundaryKeys = [
    'jungle_objective_fixture_enumerated',
    'jungle_objective_fixture_read',
    'jungle_objective_fixture_hashed',
    'jungle_objective_fixture_decoded',
    'jungle_objective_fixture_tested',
    'jungle_objective_fixture_consumed',
  ];
  invariant(ledger.protected_evidence_boundary
    && Object.keys(ledger.protected_evidence_boundary).length === boundaryKeys.length
    && boundaryKeys.every((key) => Object.prototype.hasOwnProperty.call(
      ledger.protected_evidence_boundary, key,
    ) && ledger.protected_evidence_boundary[key] === false),
  'protected evidence boundary must contain exactly six explicit false keys');
  return true;
}

function buildDecisionLedger({
  sources,
  generatedAt = '2026-08-20',
} = {}) {
  invariant(Array.isArray(sources) && sources.length > 0, 'sources are required');
  const allRoute = [];
  const allCapability = [];
  const allDomain = [];
  const sourceSummaries = [];
  const sourceIds = new Set();
  for (const source of sources) {
    invariant(typeof source.id === 'string' && source.id.length > 0,
      'every decision source requires a source id');
    invariant(!sourceIds.has(source.id), `duplicate decision source id ${source.id}`);
    sourceIds.add(source.id);
    invariant(typeof source.artifact === 'string' && source.artifact.length > 0,
      `${source.id} source artifact is required`);
    invariant(!source.artifact.toLowerCase().includes('holdout'),
      `${source.id} protected source artifact is forbidden`);
    invariant(Buffer.isBuffer(source.bytes), `${source.id} exact source bytes are required`);
    invariant(source.byte_count === source.bytes.length,
      `${source.id} source byte_count mismatch`);
    invariant(source.sha256 === sha256(source.bytes),
      `${source.id} source sha256 mismatch`);
    invariant(source.document && typeof source.document === 'object'
      && !Array.isArray(source.document),
    `${source.id} parsed source document is required`);
    invariant(JSON.stringify(JSON.parse(source.bytes.toString('utf8')))
      === JSON.stringify(source.document),
    `${source.id} source document does not match retained bytes`);
    invariant(exactBuildOf(source.document) === EXACT_BUILD,
      `${source.id} exact build mismatch`);
    if (source.document.nearest_build_fallback !== undefined) {
      invariant(source.document.nearest_build_fallback === 'FORBIDDEN',
        `${source.id} nearest-build fallback must be FORBIDDEN`);
    }
    const records = sourceRecords(source);
    allRoute.push(...records.route);
    allCapability.push(...records.capability);
    allDomain.push(...records.domain);
    sourceSummaries.push({
      source_id: source.id,
      artifact: source.artifact,
      sha256: source.sha256,
      byte_count: source.byte_count,
      source_schema: source.document.schema ?? null,
      extractor: source.extractor,
      route_decision_instance_count: records.route.length,
      capability_decision_instance_count: records.capability.length,
      domain_decision_instance_count: records.domain.length,
      ...(source.preclosure_ledger ? {
        preclosure_decision_ledger: {
          artifact: source.preclosure_ledger.artifact,
          sha256: source.preclosure_ledger.sha256,
          byte_count: source.preclosure_ledger.byte_count,
          schema: source.preclosure_ledger.document.schema ?? null,
          schema_version: source.preclosure_ledger.document.schema_version ?? null,
        },
      } : {}),
    });
  }

  const identifiedRoute = attachDecisionIdentities(allRoute, 'packet_id');
  const identifiedCapability = attachDecisionIdentities(allCapability, 'semantic_capability');
  const identifiedDomain = attachDecisionIdentities(allDomain, 'domain');
  validateAndApplyClosureSupersession({
    sources,
    generatedAt,
    routeRecords: identifiedRoute,
    capabilityRecords: identifiedCapability,
    domainRecords: identifiedDomain,
  });

  const routeDecisions = aggregateByKey(identifiedRoute, 'packet_id')
    .sort((left, right) => left.packet_id - right.packet_id);
  const capabilityDecisions = aggregateByKey(identifiedCapability, 'semantic_capability')
    .sort((left, right) => left.semantic_capability.localeCompare(right.semantic_capability));
  const domainOrder = new Map(ALLOWED_DOMAINS.map((domain, index) => [domain, index]));
  const domainDecisions = aggregateDomains(identifiedDomain)
    .sort((left, right) => domainOrder.get(left.domain) - domainOrder.get(right.domain));

  const ledger = {
    schema: LEDGER_SCHEMA,
    schema_version: 1,
    analyzer_version: ANALYZER_VERSION,
    generated_at: generatedAt,
    exact_build: EXACT_BUILD,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    policy: {
      source_discovery: 'EXPLICIT_SAFE_ALLOWLIST_ONLY_NO_DIRECTORY_ENUMERATION',
      precedence: 'ROUTE_SPECIFIC_AUDIT_OVER_BRANCH_SUMMARY_OVER_SAMPLED_BASELINE',
      structural_promotion_does_not_erase_narrower_semantic_candidates: true,
      negative_evidence_preserved: true,
      supersession: 'PINNED_PRECLOSURE_LEDGER_SHA_AND_EXACT_DECISION_ID_SET_ONLY',
      superseded_history_preserved: true,
      allowed_decisions: ALLOWED_DECISIONS,
      allowed_statuses: ALLOWED_STATUSES,
      allowed_domains: ALLOWED_DOMAINS,
      promotion_authority: 'RESEARCH_DECISION_LEDGER_ONLY',
    },
    input_sources: sourceSummaries,
    route_decisions: routeDecisions,
    capability_decisions: capabilityDecisions,
    domain_decisions: domainDecisions,
    summary: {
      input_source_count: sourceSummaries.length,
      route_decision_count: routeDecisions.length,
      route_decision_instance_count: allRoute.length,
      capability_decision_count: capabilityDecisions.length,
      capability_decision_instance_count: allCapability.length,
      domain_decision_count: domainDecisions.length,
      domain_decision_instance_count: allDomain.length,
      exhausted_route_count: routeDecisions.filter((row) => row.evidence_exhausted).length,
      exhausted_capability_count: capabilityDecisions.filter((row) => row.evidence_exhausted).length,
      exhausted_domain_count: domainDecisions.filter((row) => row.evidence_exhausted).length,
      superseded_route_decision_instance_count: routeDecisions.reduce(
        (sum, row) => sum + row.superseded_decision_count, 0,
      ),
      superseded_capability_decision_instance_count: capabilityDecisions.reduce(
        (sum, row) => sum + row.superseded_decision_count, 0,
      ),
      superseded_domain_decision_instance_count: domainDecisions.reduce(
        (sum, row) => sum + row.superseded_decision_count, 0,
      ),
      negative_evidence_statement_count: routeDecisions.reduce((sum, row) => sum + row.negative_evidence.length, 0)
        + capabilityDecisions.reduce((sum, row) => sum + row.negative_evidence.length, 0)
        + domainDecisions.reduce((sum, row) => sum + row.negative_evidence.length, 0),
    },
    protected_evidence_boundary: {
      jungle_objective_fixture_enumerated: false,
      jungle_objective_fixture_read: false,
      jungle_objective_fixture_hashed: false,
      jungle_objective_fixture_decoded: false,
      jungle_objective_fixture_tested: false,
      jungle_objective_fixture_consumed: false,
    },
  };
  validateDecisionLedger(ledger);
  return ledger;
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function buildHashManifest(ledger, ledgerBytes = jsonBytes(ledger)) {
  return {
    schema: HASH_MANIFEST_SCHEMA,
    schema_version: 1,
    exact_build: EXACT_BUILD,
    hash_algorithm: 'SHA-256',
    self_hash_excluded: true,
    files: [{
      file: 'decision_ledger.json',
      sha256: sha256(ledgerBytes),
      byte_count: ledgerBytes.length,
      schema: ledger.schema,
    }],
    inputs: ledger.input_sources.map((source) => ({
      source_id: source.source_id,
      artifact: source.artifact,
      sha256: source.sha256,
      byte_count: source.byte_count,
    })),
  };
}

function writeDecisionLedgerArtifacts(outputDirectory, ledger) {
  validateDecisionLedger(ledger);
  const resolved = assertSafePath(outputDirectory);
  fs.mkdirSync(resolved, { recursive: true });
  const ledgerBytes = jsonBytes(ledger);
  const manifest = buildHashManifest(ledger, ledgerBytes);
  const manifestBytes = jsonBytes(manifest);
  const ledgerPath = path.join(resolved, 'decision_ledger.json');
  const manifestPath = path.join(resolved, 'artifact_manifest.json');
  fs.writeFileSync(ledgerPath, ledgerBytes);
  fs.writeFileSync(manifestPath, manifestBytes);
  return {
    output_directory: resolved,
    ledger: {
      path: ledgerPath,
      sha256: sha256(ledgerBytes),
      byte_count: ledgerBytes.length,
    },
    manifest: {
      path: manifestPath,
      sha256: sha256(manifestBytes),
      byte_count: manifestBytes.length,
    },
  };
}

module.exports = {
  ALLOWED_DECISIONS,
  ALLOWED_DOMAINS,
  ALLOWED_STATUSES,
  ANALYZER_VERSION,
  DEFAULT_SAFE_SOURCE_SPECS,
  EXACT_BUILD,
  HASH_MANIFEST_SCHEMA,
  LEDGER_SCHEMA,
  SATURATION_CLOSURE_EXTRACTOR,
  SATURATION_CLOSURE_SCHEMA,
  SATURATION_CLOSURE_SOURCE_ID,
  STATUS_BY_DECISION,
  allowedDomainsFor,
  assertSafePath,
  buildDecisionLedger,
  buildHashManifest,
  decisionIdentity,
  decisionIdentityMaterial,
  decisionKey,
  jsonBytes,
  loadSafeSources,
  normalizeCapabilityName,
  packetIdsFromRecord,
  requiresOnlyExternalEvidence,
  sha256,
  validateDecisionLedger,
  writeDecisionLedgerArtifacts,
};
