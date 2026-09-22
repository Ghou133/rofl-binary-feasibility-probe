'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const {
  RUNTIME_IMAGE_SHA256: SHIELD_RUNTIME_IMAGE_SHA256,
  SHIELD_ABSORBED_PROFILE,
  shieldAbsorbedFromFullyConsumedRow,
} = require('./decoders/shield_absorbed_16_16');

const FULL_SEMANTIC_BASELINE_SCHEMA = 'FULL_SEMANTIC_BASELINE_V1';
const ANALYZER_VERSION = 'full-semantic-baseline-v1';
const DEFAULT_EXACT_BUILD = '16.16.805.0442';
const LOADER_AUTHENTICATED_SOURCE_DESCRIPTORS = new WeakSet();
const EXTERNAL_ROUTE_ATTESTATION_SPEC = Object.freeze({
  manifestPath: 'evidence/exact_build_route_attestations/artifact_manifest.json',
  manifestSha256: 'a7d21107ade92ae4c74828c59f6ee7fb3bf56a1669d6eb9fc11fbf09f88eb3f8',
  artifactPath: 'evidence/exact_build_route_attestations/shield_absorbed_16_16.json',
  artifactBytes: 12030,
  artifactSha256: '78c0187c9cdebbd88e690fa7468d6adcb8090dc166b68c05139caf7832eb3947',
  semanticName: 'SHIELD_ABSORBED',
  route: '0x01e1',
  observationCount: 12,
  distinctReplayCount: 4,
  replaySetManifestSha256: '70e5fc3e03043619746331c9f83f0190bdac9d100c78555fb20496a1e00b333d',
  upstream: Object.freeze({
    research_scan_sha256: '29adeac8050699eece71964183c87faa3e0b2cc4d7330c28158b7c4628c3b5b8',
    research_neutral_rows_sha256: 'c2e26d6c2c38bc1ddd955abc13ae360644e0f1999bbc1c34e6f02ec33aa2acc6',
    research_direct_rows_sha256: '4fcaa3ff90900ea83f1ed690ba7627d2774c7f720786490fb3fa948b4b1bebaa',
    research_fingerprint_sha256: '42cf7a064f9fb01ca174bb7345ec3cbc5a57cb97d8060c28e9515f93291d2b5f',
  }),
});

const DOMAIN_VOCABULARY = Object.freeze([
  'entity',
  'state',
  'movement',
  'combat',
  'spell',
  'missile',
  'buff',
  'vision',
  'economy',
  'objective',
  'structure',
  'map',
  'UI',
  'system',
  'noise',
  'unknown',
]);

const BASELINE_STATUS_VOCABULARY = Object.freeze([
  'KNOWN',
  'DECODED',
  'CLASSIFIED',
  'UNKNOWN',
]);

const DEFAULT_INPUT_PATHS = Object.freeze({
  inventory: 'artifacts/hero_combat_state_v2/inventory/latest_four_16_16_packet_inventory.json',
  callbackMap: 'artifacts/hero_combat_state_v2/runtime/observed_packet_callback_route_map_16_16.json',
  capabilityManifest: 'artifacts/semantic_coverage_v1/capability_manifest.json',
  profilerCoverage: 'artifacts/hero_combat_state_v2/profiler/field_behavior_profiler_coverage_matrix.json',
  profilerProfiles: Object.freeze([
    'artifacts/hero_combat_state_v2/profiler/field_behavior_profile_16_16_0x04ca_negative_control.json',
    'artifacts/full_semantic_baseline_v1/high_frequency_unknown_profile_16_16.json',
    'artifacts/hero_combat_state_v2/profiler/high_frequency_raw_profiles_latest_four_v1_2.json',
    'artifacts/hero_combat_state_v2/profiler/field_behavior_profile_16_16_0x0178_object.json',
  ]),
  negativeAudits: Object.freeze([
    'artifacts/hero_combat_state_v2/profiler/packet_010c_hero_stats_cross_check.json',
    'artifacts/hero_combat_state_v2/profiler/packet_0302_raw_structure_audit.json',
  ]),
  // These documents are provenance only.  They may describe exact runtime
  // structure or validation, but never promote a candidate to a semantic fact.
  supplementalEvidence: Object.freeze([
    'artifacts/full_semantic_baseline_v1/runtime_candidates/buff_spell_item_runtime_candidates_16_16.json',
    'artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0137_04b3_item_route_differential_16_16.json',
    'artifacts/hero_combat_state_v2/death/death_16_16_route_anchor_validation.json',
    'artifacts/full_semantic_baseline_v1/runtime_candidates/packet_0112_p0_semantic_differential_16_16.json',
    'artifacts/full_semantic_baseline_v1/hero_stats/hero_stats_scoreboard_validation_16_16.json',
    'artifacts/full_semantic_baseline_v1/schema/canonical_semantic_schema.json',
    'artifacts/full_semantic_baseline_v1/regression/regression_attestation_16_16.json',
    EXTERNAL_ROUTE_ATTESTATION_SPEC.manifestPath,
    EXTERNAL_ROUTE_ATTESTATION_SPEC.artifactPath,
  ]),
});

const RTTI_DOMAIN_RULES = Object.freeze([
  Object.freeze({ domain: 'missile', terms: Object.freeze(['missile', 'projectile', 'trajectory']) }),
  Object.freeze({ domain: 'vision', terms: Object.freeze(['vision', 'visible', 'visibility', 'sight', 'fog', 'ward', 'reveal']) }),
  Object.freeze({ domain: 'movement', terms: Object.freeze(['movement', 'move', 'path', 'waypoint', 'position', 'teleport', 'dash', 'knockback', 'displacement', 'visualoffset', 'facing']) }),
  Object.freeze({ domain: 'combat', terms: Object.freeze(['damage', 'attack', 'combat', 'aggro', 'health', 'death', 'kill', 'hit', 'critical', 'lifesteal']) }),
  Object.freeze({ domain: 'spell', terms: Object.freeze(['spell', 'cast', 'ability', 'cooldown', 'summoner', 'skill']) }),
  Object.freeze({ domain: 'buff', terms: Object.freeze(['buff', 'debuff', 'aura', 'crowdcontrol']) }),
  Object.freeze({ domain: 'economy', terms: Object.freeze(['gold', 'item', 'shop', 'inventory', 'purchase', 'sell', 'scoreboard']) }),
  Object.freeze({ domain: 'objective', terms: Object.freeze(['objective', 'dragon', 'baron', 'herald', 'junglecamp', 'neutralcamp']) }),
  Object.freeze({ domain: 'structure', terms: Object.freeze(['turret', 'inhibitor', 'nexus', 'building', 'barracks', 'structure']) }),
  Object.freeze({ domain: 'map', terms: Object.freeze(['terrain', 'navgrid', 'navigationgrid', 'mapregion', 'worldgrid']) }),
  Object.freeze({ domain: 'UI', terms: Object.freeze(['hud', 'ping', 'chat', 'announce', 'notification', 'floatingtext', 'playvo', 'voice', 'emote', 'sound']) }),
  Object.freeze({ domain: 'system', terms: Object.freeze(['handshake', 'synchronize', 'checksum', 'latency', 'connection', 'telemetry', 'protocolversion', 'gametime', 'clock']) }),
  Object.freeze({ domain: 'noise', terms: Object.freeze(['heartbeat', 'keepalive', 'noop', 'dummy', 'unused', 'reserved', 'padding']) }),
  Object.freeze({ domain: 'state', terms: Object.freeze(['state', 'stats', 'attribute', 'mana', 'resource', 'levelup', 'level', 'infobar', 'unitinfo']) }),
  Object.freeze({ domain: 'entity', terms: Object.freeze(['spawn', 'create', 'destroy', 'despawn', 'entity', 'minion', 'monster', 'pet', 'npc']) }),
]);

const CAPABILITY_DOMAIN_RULES = Object.freeze({
  ROFL_CONTAINER: 'system',
  PACKET_FRAMING: 'system',
  PARTICIPANT_MAPPING: 'entity',
  HERO_PATH: 'movement',
  HERO_DEATH: 'combat',
  HERO_RESPAWN: 'combat',
  HERO_KILL_CREDIT: 'combat',
  HERO_ASSIST: 'combat',
  LEVEL_TRANSITION: 'state',
  WARD_SPAWN: 'vision',
  WARD_LIFECYCLE: 'vision',
  SWEEPER: 'vision',
  CAST_SPELL: 'spell',
  MISSILE: 'missile',
  DAMAGE: 'combat',
  DAMAGE_TYPE: 'combat',
  DAMAGE_SOURCE_ATTRIBUTION: 'combat',
  DAMAGE_STAGE: 'combat',
  DAMAGE_MITIGATION: 'combat',
  CURRENT_HP: 'state',
  MAX_HP: 'state',
  ARMOR: 'state',
  MAGIC_RESIST: 'state',
  ATTACK_DAMAGE: 'state',
  ABILITY_POWER: 'state',
  MOVE_SPEED: 'state',
  ATTACK_SPEED: 'state',
  MANA: 'state',
  CURRENT_MANA: 'state',
  MAX_MANA: 'state',
  TEMPORARY_HP: 'state',
  TEMPORARY_STATS: 'state',
  MOVEMENT_SPECIAL: 'movement',
  BUFF: 'buff',
  DEBUFF: 'buff',
  SHIELD_GENERATED: 'combat',
  SHIELD_ABSORBED: 'combat',
  SHIELD_REMAINING: 'combat',
  SHIELD_LIFECYCLE: 'combat',
  HEAL_REPORTED: 'combat',
  HEAL_EFFECTIVE: 'combat',
  OVERHEAL: 'combat',
  ITEM_BUY: 'economy',
  ITEM_SELL: 'economy',
  ITEM_UNDO: 'economy',
  ITEM_TRANSFORM: 'economy',
  ITEM_DESTROY: 'economy',
  ITEM_STATE: 'economy',
  SUMMONER_SPELL_STATE: 'spell',
  SUMMONER_CAST: 'spell',
  RUNE_STATE: 'spell',
  RUNE_PROC: 'spell',
  PASSIVE_STATE: 'spell',
  PASSIVE_PROC: 'spell',
  VISIBILITY_STATE: 'vision',
  XP: 'economy',
  GOLD: 'economy',
  CS: 'economy',
  NPC_SPAWN: 'entity',
  NPC_DEATH: 'entity',
  NPC_DESPAWN: 'entity',
  NPC_CLASSIFICATION: 'entity',
  LANE_MINION_LIFECYCLE: 'entity',
  JUNGLE_MONSTER_LIFECYCLE: 'entity',
  CAMP_CLEAR: 'objective',
  CAMP_STATE: 'objective',
  OBJECTIVE: 'objective',
  STRUCTURE: 'structure',
  MAP_MECHANIC: 'map',
});

const REQUESTED_BASELINE_CAPABILITIES = Object.freeze([
  'ROFL_CONTAINER', 'PACKET_FRAMING', 'PARTICIPANT_MAPPING',
  'HERO_PATH', 'HERO_DEATH', 'HERO_RESPAWN', 'HERO_KILL_CREDIT', 'HERO_ASSIST',
  'LEVEL_TRANSITION', 'WARD_SPAWN', 'WARD_LIFECYCLE', 'SWEEPER', 'VISIBILITY_STATE',
  'CAST_SPELL', 'MISSILE', 'SUMMONER_SPELL_STATE', 'SUMMONER_CAST',
  'RUNE_STATE', 'RUNE_PROC', 'PASSIVE_STATE', 'PASSIVE_PROC',
  'DAMAGE', 'DAMAGE_TYPE', 'DAMAGE_SOURCE_ATTRIBUTION', 'DAMAGE_STAGE',
  'DAMAGE_MITIGATION', 'CURRENT_HP', 'MAX_HP', 'ARMOR', 'MAGIC_RESIST',
  'ATTACK_DAMAGE', 'ABILITY_POWER', 'MOVE_SPEED', 'ATTACK_SPEED', 'MANA',
  'CURRENT_MANA', 'MAX_MANA', 'TEMPORARY_HP', 'TEMPORARY_STATS', 'MOVEMENT_SPECIAL',
  'BUFF', 'DEBUFF', 'SHIELD_GENERATED', 'SHIELD_ABSORBED', 'SHIELD_REMAINING',
  'SHIELD_LIFECYCLE', 'HEAL_REPORTED', 'HEAL_EFFECTIVE', 'OVERHEAL',
  'ITEM_BUY', 'ITEM_SELL', 'ITEM_UNDO', 'ITEM_TRANSFORM', 'ITEM_DESTROY', 'ITEM_STATE',
  'XP', 'GOLD', 'CS', 'NPC_SPAWN', 'NPC_DEATH', 'NPC_DESPAWN',
  'NPC_CLASSIFICATION', 'LANE_MINION_LIFECYCLE', 'JUNGLE_MONSTER_LIFECYCLE',
  'CAMP_CLEAR', 'CAMP_STATE', 'OBJECTIVE', 'STRUCTURE', 'MAP_MECHANIC',
]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function strictCompare(left, right) {
  const a = String(left);
  const b = String(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function ratio(numerator, denominator) {
  return denominator === 0 ? null : Number((numerator / denominator).toPrecision(12));
}

function formatPacketId(packetId) {
  invariant(Number.isSafeInteger(packetId) && packetId >= 0 && packetId <= 0xffff,
    `invalid packet id: ${String(packetId)}`);
  return `0x${packetId.toString(16).padStart(4, '0')}`;
}

function numericPacketId(value) {
  if (Number.isSafeInteger(value) && value >= 0 && value <= 0xffff) return value;
  if (typeof value === 'string' && /^(?:0x)?[0-9a-f]{1,4}$/i.test(value)) {
    return Number.parseInt(value.replace(/^0x/i, ''), 16);
  }
  throw new TypeError(`invalid packet route: ${String(value)}`);
}

function sha256Buffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function assertAllowedInputPath(filePath) {
  invariant(typeof filePath === 'string' && filePath.length > 0, 'input path must be non-empty');
  if (/holdout/i.test(filePath)) {
    throw new Error('Holdout paths are forbidden before read, enumeration, or hashing');
  }
}

function portablePath(filePath, root = process.cwd()) {
  const resolved = path.resolve(filePath);
  const relative = path.relative(path.resolve(root), resolved);
  return relative && !relative.startsWith('..') && !path.isAbsolute(relative)
    ? relative.split(path.sep).join('/')
    : resolved.split(path.sep).join('/');
}

function readJsonSource(filePath, label, root = process.cwd()) {
  assertAllowedInputPath(filePath);
  const resolved = path.resolve(root, filePath);
  const bytes = fs.readFileSync(resolved);
  let document;
  try {
    document = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
  return {
    label,
    path: portablePath(resolved, root),
    sha256: sha256Buffer(bytes),
    byte_count: bytes.length,
    schema: document.schema ?? document.schema_version ?? null,
    document,
  };
}

function loaderAuthenticatedDescriptor(source) {
  const descriptor = {
    label: source.label,
    path: source.path,
    sha256: source.sha256,
    byte_count: source.byte_count,
    schema: source.schema,
  };
  LOADER_AUTHENTICATED_SOURCE_DESCRIPTORS.add(descriptor);
  return descriptor;
}

function uniqueSorted(values) {
  return [...new Set(values.filter((value) => value !== null && value !== undefined))]
    .sort(strictCompare);
}

function countBy(values, vocabulary = []) {
  const result = Object.fromEntries(vocabulary.map((value) => [value, 0]));
  for (const value of values) result[value] = (result[value] ?? 0) + 1;
  return result;
}

function routeIdsFromManifestRecord(record) {
  const values = [record?.protocol_route, record?.packet_registration_route]
    .filter((value) => typeof value === 'string');
  const routes = [];
  for (const value of values) {
    for (const match of value.matchAll(/\b0x([0-9a-f]{1,4})\b/gi)) {
      routes.push(Number.parseInt(match[1], 16));
    }
  }
  return [...new Set(routes)].sort((left, right) => left - right);
}

function isVerifiedManifestRecord(record) {
  return ['PASS', 'PARTIAL'].includes(record?.validation_status)
    && ['VERIFIED_DIRECT', 'VERIFIED_DERIVED'].includes(record?.evidence_grade);
}

function summarizeManifestRecord(record) {
  return {
    semantic_capability: record.semantic_capability,
    build: record.build,
    protocol_route: record.protocol_route,
    packet_registration_route: record.packet_registration_route,
    decoder_version: record.decoder_version,
    field_mapping: record.field_mapping,
    evidence_grade: record.evidence_grade,
    validation_status: record.validation_status,
    sample_count: record.sample_count,
    positive_examples: record.positive_examples ?? [],
    negative_examples: record.negative_examples ?? [],
    known_limits: record.known_limits ?? [],
    canonical_schema_version: record.canonical_schema_version ?? null,
  };
}

function domainForCapability(capability) {
  return CAPABILITY_DOMAIN_RULES[capability] ?? 'unknown';
}

function rttiTokens(callbackNames) {
  return callbackNames.flatMap((name) => String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Za-z])([0-9])/g, '$1 $2')
    .replace(/([0-9])([A-Za-z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean));
}

function rttiTermMatches(tokens, term) {
  const normalizedTerm = term.toLowerCase().replace(/[^a-z0-9]+/g, '');
  if (tokens.includes(normalizedTerm)) return true;
  for (let start = 0; start < tokens.length; start += 1) {
    let joined = '';
    for (let end = start; end < Math.min(tokens.length, start + 4); end += 1) {
      joined += tokens[end];
      if (joined === normalizedTerm) return true;
      if (joined.length >= normalizedTerm.length) break;
    }
  }
  return false;
}

function classifyRttiNames(callbackNames = []) {
  const names = uniqueSorted(callbackNames.map((value) => String(value)));
  if (names.length === 0) {
    return {
      primary_domain: 'unknown',
      candidate_domains: ['unknown'],
      classification_status: 'UNKNOWN_NO_RTTI_NAME',
      classification_basis: 'NO_CALLBACK_RTTI_NAME; FACTORY_FREQUENCY_SIZE_ENTITY_AND_TIME_DO_NOT_CLASSIFY',
      candidate_family_names: [],
      evidence_grade: 'UNAVAILABLE',
      semantic_claim: null,
    };
  }
  const tokens = rttiTokens(names);
  const matchedDomains = RTTI_DOMAIN_RULES
    .filter((rule) => rule.terms.some((term) => rttiTermMatches(tokens, term)))
    .map((rule) => rule.domain);
  const candidateDomains = uniqueSorted(matchedDomains);
  if (candidateDomains.length === 0) {
    return {
      primary_domain: 'unknown',
      candidate_domains: ['unknown'],
      classification_status: 'UNKNOWN_RTTI_NAME_NO_DOMAIN_RULE_MATCH',
      classification_basis: 'RTTI_NAME_RETAINED_AS_CANDIDATE_FAMILY_ONLY',
      candidate_family_names: names,
      evidence_grade: 'CANDIDATE',
      semantic_claim: null,
    };
  }
  const primaryDomain = RTTI_DOMAIN_RULES.find((rule) => candidateDomains.includes(rule.domain)).domain;
  return {
    primary_domain: primaryDomain,
    candidate_domains: candidateDomains,
    classification_status: 'RTTI_NAME_DOMAIN_CANDIDATE',
    classification_basis: 'CALLBACK_RTTI_KEYWORD_RULE_CANDIDATE_ONLY',
    candidate_family_names: names,
    evidence_grade: 'CANDIDATE',
    semantic_claim: null,
  };
}

function domainsFromNegativeSemantics(value) {
  if (value === 'HERO_CUMULATIVE_SCOREBOARD_STATS') return ['state', 'economy', 'combat'];
  if (value === 'SUMMONER_SPELL_NAME_VECTOR_ASCII') return ['spell'];
  return [];
}

function normalizeProfilerProfile(profile, source = null, routeOverride = null) {
  invariant(profile && typeof profile === 'object', 'profiler profile must be an object');
  const routeProfiles = Array.isArray(profile.route_profiles) ? profile.route_profiles : [];
  invariant(routeOverride || routeProfiles.length === 1,
    'each profiler evidence normalization must select exactly one route');
  const route = routeOverride ?? routeProfiles[0];
  const packetId = numericPacketId(route.packet_id ?? route.packet_discriminator);
  const extraction = profile.input?.packet_record_extraction ?? null;
  const decodedExport = profile.input?.input_mode === 'DECODED_HEX_FIELD_EXPORT'
    && extraction?.require_fully_consumed === true
    && Number(extraction?.accepted_row_count) > 0
    && Number(extraction?.rejected?.wrong_build ?? 0) === 0
    && Number(extraction?.rejected?.not_fully_consumed ?? 0) === 0;
  const exactNegative = route.route_role === 'NEGATIVE_CONTROL'
    && typeof route.known_route_semantics === 'string'
    && route.known_route_semantics.length > 0;
  return {
    packet_id: packetId,
    packet_discriminator: route.packet_discriminator ?? formatPacketId(route.packet_id),
    source,
    analyzer_version: profile.analyzer_version ?? null,
    target_build: profile.target_build ?? route.build ?? null,
    evidence_grade: profile.evidence_grade ?? 'CANDIDATE',
    semantic_claim: profile.semantic_claim ?? null,
    route_role: route.route_role ?? 'CANDIDATE',
    known_route_semantics: route.known_route_semantics ?? null,
    profile_status: route.status ?? null,
    excluded_from_combat_state_ranking: route.excluded_from_combat_state_ranking === true,
    observed_record_count: route.observed_record_count ?? null,
    profiled_record_count: route.profiled_record_count ?? null,
    input_mode: profile.input?.input_mode ?? null,
    profiled_value_source: route.profiled_value_source ?? null,
    extraction: extraction ? {
      input_row_count: extraction.input_row_count,
      accepted_row_count: extraction.accepted_row_count,
      rejected_row_count: extraction.rejected_row_count,
      rejected: extraction.rejected,
      hex_field: extraction.hex_field,
      require_fully_consumed: extraction.require_fully_consumed,
    } : null,
    ranked_candidate_count: Array.isArray(profile.ranked_candidates)
      ? profile.ranked_candidates.filter((candidate) => (
        numericPacketId(candidate.packet_id ?? candidate.packet_discriminator) === packetId
      )).length : null,
    exact_structural_decode_evidence: decodedExport || exactNegative,
    exact_structural_decode_basis: decodedExport
      ? 'FULLY_CONSUMED_EXACT_BUILD_DECODED_HEX_EXPORT'
      : exactNegative ? 'EXPLICIT_EXACT_BUILD_NEGATIVE_CONTROL_ROUTE_SEMANTICS' : null,
  };
}

function normalizeNegativeAudit(audit, source = null) {
  invariant(audit && typeof audit === 'object', 'negative audit must be an object');
  const packetId = numericPacketId(audit.packet_id ?? audit.packet_discriminator);
  const explicitNegative = audit.route_role === 'NEGATIVE_CONTROL'
    || String(audit.profile_role ?? '').startsWith('NEGATIVE_CONTROL');
  invariant(explicitNegative, `negative audit ${formatPacketId(packetId)} is not marked as a negative control`);
  const combatAssessment = audit.combat_state_assessment ?? null;
  const negativeScope = combatAssessment
    ? Object.entries(combatAssessment)
      .filter(([key, value]) => !['basis', 'warning'].includes(key) && String(value).startsWith('NEGATIVE_CONTROL'))
      .map(([key]) => key.toUpperCase())
    : [];
  const exactStructuralDecode = Number(audit.decoded_source_full_consume_count ?? 0) > 0
    || audit.exact_static_decode_shape?.decoded_field_width_bytes > 0;
  return {
    packet_id: packetId,
    packet_discriminator: audit.packet_discriminator ?? formatPacketId(packetId),
    source,
    schema: audit.schema ?? audit.schema_version ?? null,
    exact_build: audit.exact_build ?? null,
    evidence_grade: audit.evidence_grade ?? 'CANDIDATE',
    semantic_claim: audit.semantic_claim ?? null,
    route_role: 'NEGATIVE_CONTROL',
    known_route_semantics: audit.known_route_semantics ?? null,
    excluded_from_combat_state_ranking: audit.excluded_from_combat_state_ranking !== false,
    negative_scope: negativeScope,
    exact_structural_decode_evidence: exactStructuralDecode,
    exact_structural_decode_basis: Number(audit.decoded_source_full_consume_count ?? 0) > 0
      ? 'FULLY_CONSUMED_EXACT_BUILD_DECODED_SOURCE'
      : exactStructuralDecode ? 'EXACT_STATIC_DECODE_SHAPE' : null,
    decoded_source: audit.decoded_source ?? null,
    decoded_source_row_count: audit.decoded_source_row_count ?? null,
    decoded_source_full_consume_count: audit.decoded_source_full_consume_count ?? null,
    combat_state_assessment: combatAssessment,
    requested_boundary_audit: audit.requested_boundary_audit ?? null,
    independent_tail_alignment: audit.independent_tail_alignment ?? null,
    exact_static_decode_shape: audit.exact_static_decode_shape ?? null,
    raw_structure: audit.raw_structure ?? null,
    raw_parameter_distribution: audit.raw_parameter_distribution ?? null,
    hero_side_and_time_behavior: audit.hero_side_and_time_behavior ?? null,
  };
}

function validateInventory(inventory, targetBuild) {
  invariant(inventory?.schema_version === 'PACKET_COVERAGE_INVENTORY_V1',
    'unsupported packet inventory schema');
  invariant(inventory.exact_build_policy === 'RAW_PACKET_ROWS_ARE_NEVER_MERGED_ACROSS_EXACT_GAME_VERSION',
    'packet inventory exact-build policy is missing');
  invariant(Array.isArray(inventory.builds) && inventory.builds.length === 1,
    'packet inventory must contain exactly one exact build');
  invariant(inventory.builds[0].game_version === targetBuild,
    `packet inventory build mismatch: expected ${targetBuild}`);
  invariant(Array.isArray(inventory.packets), 'packet inventory packets must be an array');
  const ids = new Set();
  let packetCount = 0;
  for (const row of inventory.packets) {
    invariant(row.build === targetBuild, `inventory route ${row.packet_discriminator} has wrong build`);
    const packetId = numericPacketId(row.packet_id ?? row.packet_discriminator);
    invariant(!ids.has(packetId), `duplicate inventory route ${formatPacketId(packetId)}`);
    ids.add(packetId);
    invariant(Number.isSafeInteger(row.count) && row.count >= 0,
      `inventory route ${formatPacketId(packetId)} has invalid count`);
    invariant(Array.isArray(row.payload_size_distribution),
      `inventory route ${formatPacketId(packetId)} has no payload distribution`);
    const sizeCount = row.payload_size_distribution.reduce((sum, item) => {
      invariant(Number.isSafeInteger(item.payload_length) && item.payload_length >= 0,
        `inventory route ${formatPacketId(packetId)} has invalid payload length`);
      invariant(Number.isSafeInteger(item.count) && item.count >= 0,
        `inventory route ${formatPacketId(packetId)} has invalid payload count`);
      return sum + item.count;
    }, 0);
    invariant(sizeCount === row.count,
      `payload distribution does not conserve count for ${formatPacketId(packetId)}`);
    packetCount += row.count;
  }
  invariant(inventory.builds[0].packet_type_count === inventory.packets.length,
    'inventory route count does not match build summary');
  invariant(inventory.builds[0].packet_count === packetCount,
    'inventory packet count does not match build summary');
  invariant(inventory.input_record_count === packetCount,
    'inventory packet count does not match input record count');
  return { route_count: inventory.packets.length, packet_count: packetCount };
}

function canonicalSizeDistribution(value) {
  return (value ?? []).map((row) => ({
    payload_length: Number(row.payload_length),
    count: Number(row.count),
  })).sort((left, right) => left.payload_length - right.payload_length);
}

function validateCallbackMap(callbackMap, inventory, targetBuild) {
  invariant(callbackMap?.build === targetBuild,
    `callback route map build mismatch: expected ${targetBuild}`);
  invariant(Array.isArray(callbackMap.routes), 'callback route map routes must be an array');
  invariant(callbackMap.observed_route_count === callbackMap.routes.length,
    'callback route map route summary mismatch');
  const inventoryById = new Map(inventory.packets.map((row) => [numericPacketId(row.packet_id), row]));
  const sideIds = new Set();
  let totalCount = 0;
  let mappedCount = 0;
  for (const row of callbackMap.routes) {
    const packetId = numericPacketId(row.packet_id ?? row.packet_id_hex);
    invariant(!sideIds.has(packetId), `duplicate callback-map route ${formatPacketId(packetId)}`);
    sideIds.add(packetId);
    const inventoryRow = inventoryById.get(packetId);
    invariant(inventoryRow, `callback-map route ${formatPacketId(packetId)} is absent from inventory`);
    invariant(row.observed_count === inventoryRow.count,
      `callback-map count mismatch for ${formatPacketId(packetId)}`);
    invariant(JSON.stringify(canonicalSizeDistribution(row.payload_size_distribution))
      === JSON.stringify(canonicalSizeDistribution(inventoryRow.payload_size_distribution)),
    `callback-map payload distribution mismatch for ${formatPacketId(packetId)}`);
    totalCount += row.observed_count;
    if (row.callback_mapping_status === 'UNIQUE_CALLBACK_RTTI_NAME') mappedCount += row.observed_count;
  }
  invariant(sideIds.size === inventoryById.size,
    'callback-map and inventory route sets are not one-to-one');
  invariant(callbackMap.total_observed_packet_count === totalCount,
    'callback-map total packet count mismatch');
  invariant(callbackMap.mapped_observed_packet_count === mappedCount,
    'callback-map mapped packet count mismatch');
  const computedStatusCounts = countBy(callbackMap.routes.map((row) => row.callback_mapping_status));
  invariant(Object.entries(callbackMap.status_counts ?? {})
    .every(([key, value]) => computedStatusCounts[key] === value),
  'callback-map status counts mismatch');
  return {
    route_count: sideIds.size,
    packet_count: totalCount,
    mapped_packet_count: mappedCount,
  };
}

function classifyRouteDomain(knownManifestRecords, negativeEvidence, rttiClassification) {
  const manifestDomainSet = new Set(knownManifestRecords
    .map((record) => domainForCapability(record.semantic_capability))
    .filter((domain) => domain !== 'unknown'));
  const manifestDomains = DOMAIN_VOCABULARY.filter((domain) => manifestDomainSet.has(domain));
  if (manifestDomains.length > 0) {
    return {
      primary_domain: manifestDomains[0],
      candidate_domains: manifestDomains,
      classification_status: 'VERIFIED_EXACT_BUILD_SEMANTIC_DOMAIN',
      classification_basis: 'EXACT_BUILD_CAPABILITY_MANIFEST',
      candidate_family_names: rttiClassification.candidate_family_names,
      evidence_grade: uniqueSorted(knownManifestRecords.map((record) => record.evidence_grade)),
      semantic_claim: uniqueSorted(knownManifestRecords.map((record) => record.semantic_capability)),
    };
  }
  const negativeDomainSet = new Set(negativeEvidence
    .flatMap((item) => domainsFromNegativeSemantics(item.known_route_semantics)));
  const negativeDomains = DOMAIN_VOCABULARY.filter((domain) => negativeDomainSet.has(domain));
  if (negativeDomains.length > 0) {
    return {
      primary_domain: negativeDomains[0],
      candidate_domains: negativeDomains,
      classification_status: 'EXACT_NEGATIVE_CONTROL_DOMAIN_ONLY',
      classification_basis: 'KNOWN_NEGATIVE_CONTROL_ROUTE_SEMANTICS_NOT_POSITIVE_CAPABILITY',
      candidate_family_names: rttiClassification.candidate_family_names,
      evidence_grade: 'CANDIDATE',
      semantic_claim: null,
    };
  }
  return rttiClassification;
}

function summarizeProfilerCoverageLimits(profilerCoverage) {
  const valueLimits = (profilerCoverage?.value_representations ?? [])
    .filter((row) => row.minimum_gap || !String(row.status).startsWith('SUPPORTED'))
    .map((row) => ({
      family: row.family,
      status: row.status,
      actual_behavior: row.actual_behavior,
      minimum_gap: row.minimum_gap ?? null,
    }));
  return {
    promotion_authority: profilerCoverage?.promotion_authority ?? null,
    value_representation_limits: valueLimits,
    statistics_minimum_gaps: profilerCoverage?.statistics?.minimum_gaps ?? [],
    input_adapter_minimum_gap: profilerCoverage?.input_adapters?.minimum_gap ?? null,
    minimal_priority_order: profilerCoverage?.minimal_priority_order ?? [],
    required_support: assessProfilerRequiredSupport(profilerCoverage),
  };
}

function assessProfilerRequiredSupport(profilerCoverage) {
  const representations = new Map((profilerCoverage?.value_representations ?? [])
    .map((row) => [String(row.family), row]));
  const supported = (family) => String(representations.get(family)?.status ?? '')
    .startsWith('SUPPORTED');
  const representationChecks = {
    floats: supported('float32') && supported('float64'),
    integers: supported('integers'),
    bitfields: supported('bitfields'),
    packed_fields: supported('packed_fields'),
    identifiers: supported('identifiers'),
    vectors: supported('vectors'),
    strings: supported('strings'),
    hashes: supported('hashes'),
  };
  const statisticNames = new Set(profilerCoverage?.statistics?.supported ?? []);
  const hasStatisticTerm = (term) => [...statisticNames]
    .some((value) => String(value).includes(term));
  const requiredAnchors = [
    'Damage', 'Death', 'Heal', 'Shield', 'Level', 'Item', 'Cast', 'Ward', 'Movement',
  ];
  const anchorRows = new Map((profilerCoverage?.anchor_matrix ?? [])
    .map((row) => [String(row.anchor), row]));
  const anchorChecks = Object.fromEntries(requiredAnchors.map((anchor) => [
    anchor,
    String(anchorRows.get(anchor)?.status ?? '').startsWith('SUPPORTED'),
  ]));
  const statisticChecks = {
    range: statisticNames.has('range'),
    distribution: hasStatisticTerm('distribution')
      || (statisticNames.has('mean') && statisticNames.has('median')
        && statisticNames.has('population_variance')),
    delta: hasStatisticTerm('delta'),
    entity_consistency: hasStatisticTerm('per_entity'),
    temporal_behavior: statisticNames.has('change_rate')
      && (hasStatisticTerm('trajectory') || hasStatisticTerm('transition')),
    event_correlation: Object.values(anchorChecks).every(Boolean),
  };
  const adapters = profilerCoverage?.input_adapters ?? {};
  const adapterChecks = {
    raw_rofl: typeof adapters.raw_rofl === 'string' && adapters.raw_rofl.length > 0,
    decoded_hex: typeof adapters.decoded_hex === 'string' && adapters.decoded_hex.length > 0,
    typed_decoded_fields: typeof adapters.typed_decoded_fields === 'string'
      && adapters.typed_decoded_fields.length > 0,
  };
  const missing = [
    ...Object.entries(representationChecks).filter(([, pass]) => !pass)
      .map(([name]) => `representation:${name}`),
    ...Object.entries(statisticChecks).filter(([, pass]) => !pass)
      .map(([name]) => `statistic:${name}`),
    ...Object.entries(anchorChecks).filter(([, pass]) => !pass)
      .map(([name]) => `anchor:${name}`),
    ...Object.entries(adapterChecks).filter(([, pass]) => !pass)
      .map(([name]) => `adapter:${name}`),
  ];
  if (profilerCoverage?.promotion_authority !== 'NONE') {
    missing.push('governance:promotion_authority_must_be_NONE');
  }
  return {
    pass: missing.length === 0,
    missing,
    representation_checks: representationChecks,
    statistic_checks: statisticChecks,
    anchor_checks: anchorChecks,
    adapter_checks: adapterChecks,
    disclosed_limitations_are_non_blocking: true,
    rationale:
      'Section 26 requires generic representation/statistic/anchor support; explicit codec, inference, and approximation limits remain required disclosures rather than readiness blockers.',
  };
}

function nextRequiredEvidenceForStatus(status) {
  switch (status) {
    case 'KNOWN':
      return ['Maintain exact-build regression attestation and field-level provenance.'];
    case 'DECODED':
      return ['Independent exact-build semantic anchor validation and canonical field contract.'];
    case 'CLASSIFIED':
      return ['Exact deserializer/layout recovery followed by independent semantic anchors.'];
    default:
      return ['Callback/factory registration recovery or bounded exact-build packet profiling.'];
  }
}

function supplementalKind(document) {
  const schema = String(document?.schema ?? document?.schema_version ?? '');
  const analysis = String(document?.analysis ?? document?.attestation_kind ?? '');
  const text = `${schema} ${analysis}`.toUpperCase();
  if (schema === 'EXTERNAL_EXACT_BUILD_ROUTE_ATTESTATION_V1') return 'EXTERNAL_ROUTE_ATTESTATION';
  if (schema === 'EXTERNAL_EXACT_BUILD_ROUTE_ATTESTATION_MANIFEST_V1') {
    return 'EXTERNAL_ROUTE_ATTESTATION_MANIFEST';
  }
  if (text.includes('REGRESSION_ATTESTATION')) return 'REGRESSION_ATTESTATION';
  if (text.includes('CANONICAL_SEMANTIC_SCHEMA')) return 'CANONICAL_SCHEMA';
  if (text.includes('DEATH') && text.includes('VALIDATION')) return 'DEATH_VALIDATION';
  if (text.includes('ITEM_ROUTE_DIFFERENTIAL')) return 'ITEM_ROUTE_DIFFERENTIAL';
  if (text.includes('RUNTIME') || Array.isArray(document?.routes)) return 'RUNTIME_CANDIDATE';
  return 'SUPPLEMENTAL_PROVENANCE';
}

function exactExternalAttestationRows(entries, targetBuild) {
  const manifests = entries.filter((entry) =>
    (entry.document ?? entry)?.schema === 'EXTERNAL_EXACT_BUILD_ROUTE_ATTESTATION_MANIFEST_V1');
  const attestations = entries.filter((entry) =>
    (entry.document ?? entry)?.schema === 'EXTERNAL_EXACT_BUILD_ROUTE_ATTESTATION_V1');
  if (manifests.length === 0 && attestations.length === 0) return new Map();
  invariant(targetBuild === DEFAULT_EXACT_BUILD,
    'published external route attestation only supports the pinned exact build');
  invariant(manifests.length === 1 && attestations.length === 1,
    'external route attestation requires exactly one publication manifest and one artifact');

  const manifestEntry = manifests[0];
  const attestationEntry = attestations[0];
  const manifest = manifestEntry.document ?? manifestEntry;
  const attestation = attestationEntry.document ?? attestationEntry;
  const manifestSource = manifestEntry.source ?? manifestEntry.descriptor ?? null;
  const attestationSource = attestationEntry.source ?? attestationEntry.descriptor ?? null;
  invariant(LOADER_AUTHENTICATED_SOURCE_DESCRIPTORS.has(manifestSource)
    && LOADER_AUTHENTICATED_SOURCE_DESCRIPTORS.has(attestationSource),
  'external route attestation sources must be authenticated by the filesystem loader');
  invariant(manifestSource.sha256 === EXTERNAL_ROUTE_ATTESTATION_SPEC.manifestSha256,
    'external route attestation publication manifest SHA mismatch');
  invariant(attestationSource.sha256 === EXTERNAL_ROUTE_ATTESTATION_SPEC.artifactSha256
    && attestationSource.byte_count === EXTERNAL_ROUTE_ATTESTATION_SPEC.artifactBytes,
  'external route attestation artifact identity mismatch');

  invariant(manifest.exact_build === targetBuild
    && manifest.self_hash_excluded === true
    && Array.isArray(manifest.artifacts)
    && manifest.artifacts.length === 1,
  'external route attestation publication manifest is malformed');
  const published = manifest.artifacts[0];
  invariant(published.path === EXTERNAL_ROUTE_ATTESTATION_SPEC.artifactPath
    && published.bytes === attestationSource.byte_count
    && published.sha256 === attestationSource.sha256,
  'external route attestation artifact is not bound by its publication manifest');
  invariant(manifest.upstream_lineage?.runtime_image_sha256 === SHIELD_RUNTIME_IMAGE_SHA256
    && manifest.upstream_lineage?.replay_set_manifest_sha256
      === EXTERNAL_ROUTE_ATTESTATION_SPEC.replaySetManifestSha256
    && Object.entries(EXTERNAL_ROUTE_ATTESTATION_SPEC.upstream)
      .every(([key, value]) => manifest.upstream_lineage?.[key] === value),
  'external route attestation upstream lineage mismatch');

  const binding = attestation.route_binding;
  invariant(attestation.exact_build === targetBuild
    && attestation.semantic_name === EXTERNAL_ROUTE_ATTESTATION_SPEC.semanticName
    && attestation.protocol_route === EXTERNAL_ROUTE_ATTESTATION_SPEC.route
    && attestation.validation_status === 'PASS'
    && attestation.evidence_grade === 'VERIFIED_DIRECT'
    && attestation.decoder_profile === SHIELD_ABSORBED_PROFILE.id
    && attestation.runtime_image_sha256 === SHIELD_RUNTIME_IMAGE_SHA256
    && attestation.replay_set_manifest_sha256
      === EXTERNAL_ROUTE_ATTESTATION_SPEC.replaySetManifestSha256,
  'external route attestation semantic or exact-build identity mismatch');
  invariant(binding?.runtime_type_name === SHIELD_ABSORBED_PROFILE.runtime_type_name
    && binding.packet_id === SHIELD_ABSORBED_PROFILE.replay_block_packet_id
    && binding.client_opcode === EXTERNAL_ROUTE_ATTESTATION_SPEC.route
    && binding.constructor_rva === '0x00eac9b0'
    && binding.deserializer_rva === '0x00f22400'
    && binding.callback_rva === '0x002a77b0'
    && binding.object_size === SHIELD_ABSORBED_PROFILE.object_size,
  'external route attestation runtime binding mismatch');

  invariant(typeof attestation.callback_lookup_table_hex === 'string'
    && /^[0-9a-f]{512}$/.test(attestation.callback_lookup_table_hex),
  'external route attestation callback table is malformed');
  const lookupTable = Buffer.from(attestation.callback_lookup_table_hex, 'hex');
  invariant(Array.isArray(attestation.observations)
    && attestation.observations.length === EXTERNAL_ROUTE_ATTESTATION_SPEC.observationCount,
  'external route attestation observation count mismatch');
  const canonicals = attestation.observations.map((row) =>
    shieldAbsorbedFromFullyConsumedRow(row, lookupTable));
  invariant(canonicals.every((row) => row?.semantic === EXTERNAL_ROUTE_ATTESTATION_SPEC.semanticName
    && row.evidence === 'VERIFIED_DIRECT'
    && row.protocol_route === EXTERNAL_ROUTE_ATTESTATION_SPEC.route
    && Number.isFinite(row.absorbed_amount)
    && row.absorbed_amount > 0),
  'external route attestation contains a row that fails exact decoder semantic gates');
  const observationIdentities = attestation.observations.map((row) =>
    `${row.replay_sha256}|${row.replay_time_ms}|${row.raw_payload_sha256}`);
  invariant(new Set(observationIdentities).size === observationIdentities.length,
    'external route attestation contains duplicate observations');
  invariant(new Set(attestation.observations.map((row) => row.replay_sha256)).size
    === EXTERNAL_ROUTE_ATTESTATION_SPEC.distinctReplayCount,
  'external route attestation replay diversity mismatch');
  invariant(attestation.expected?.observation_count === canonicals.length
    && attestation.expected?.distinct_replay_count
      === EXTERNAL_ROUTE_ATTESTATION_SPEC.distinctReplayCount
    && attestation.expected?.positive_finite_amount_count === canonicals.length
    && attestation.expected?.duplicate_target_agreement_count === canonicals.length
    && attestation.expected?.raw_target_agreement_count === canonicals.length,
  'external route attestation expected invariants mismatch');
  invariant(attestation.protected_holdout
    && Object.keys(attestation.protected_holdout).length === 6
    && Object.values(attestation.protected_holdout).every((value) => value === false)
    && manifest.protected_holdout
    && Object.keys(manifest.protected_holdout).length === 6
    && Object.values(manifest.protected_holdout).every((value) => value === false),
  'external route attestation protected-input boundary mismatch');

  return new Map([[attestation, [{
    packet_id: EXTERNAL_ROUTE_ATTESTATION_SPEC.route,
    evidence_class: 'VERIFIED_EXTERNAL_EXACT_BUILD_MACHINE_ROWS',
    semantic_name: EXTERNAL_ROUTE_ATTESTATION_SPEC.semanticName,
    binding_id: 'published-shield-absorbed-16-16',
    observed_count: canonicals.length,
    provenance: {
      exact_build: targetBuild,
      replay_set_manifest_sha256: EXTERNAL_ROUTE_ATTESTATION_SPEC.replaySetManifestSha256,
      source_sha256: SHIELD_RUNTIME_IMAGE_SHA256,
      source_kind: 'EXACT_BUILD_RUNTIME_AND_PUBLISHED_MACHINE_ROWS',
      publication_manifest_sha256: manifestSource.sha256,
      publication_artifact_sha256: attestationSource.sha256,
    },
  }]]]);
}

function declaredSupplementalBuild(document) {
  return document?.exact_build ?? document?.target_build ?? document?.build
    ?? document?.target?.build ?? null;
}

function normalizeSupplementalEvidence(entries, targetBuild) {
  const routeEvidence = new Map();
  const externalAttestationRows = exactExternalAttestationRows(entries, targetBuild);
  const documents = entries.map((entry, index) => {
    const document = entry.document ?? entry;
    invariant(document && typeof document === 'object', `supplemental evidence ${index + 1} must be an object`);
    const source = entry.source ?? entry.descriptor ?? null;
    const kind = supplementalKind(document);
    const declaredBuild = kind === 'EXTERNAL_ROUTE_ATTESTATION'
      || kind === 'EXTERNAL_ROUTE_ATTESTATION_MANIFEST'
      ? targetBuild : declaredSupplementalBuild(document);
    invariant(declaredBuild === null || declaredBuild === targetBuild,
      `supplemental evidence ${source?.label ?? index + 1} build mismatch`);
    const descriptor = {
      kind,
      source,
      schema: document.schema ?? document.schema_version ?? null,
      declared_build: declaredBuild,
      semantic_promotion_authority: 'NONE',
    };
    const nestedTargetRoutes = document?.target?.routes && typeof document.target.routes === 'object'
      ? Object.keys(document.target.routes).map((packetId) => ({
        packet_id: packetId,
        evidence_class: 'EXACT_STATIC_RUNTIME_FULL_CONSUME_AND_ANCHOR_DIFFERENTIAL',
      })) : [];
    const routeRows = kind === 'EXTERNAL_ROUTE_ATTESTATION'
      ? externalAttestationRows.get(document) ?? []
      : Array.isArray(document.routes) ? document.routes : nestedTargetRoutes;
    const directRoute = document.packet_id ?? document.packet_discriminator ?? document.packet_id_hex;
    const candidates = directRoute === undefined || directRoute === null
      ? routeRows : [{ packet_id: directRoute, evidence_class: document.evidence_grade ?? document.status ?? null }];
    for (const row of candidates) {
      const value = row.packet_id ?? row.packet_discriminator ?? row.packet_id_hex;
      if (value === undefined || value === null) continue;
      const packetId = numericPacketId(value);
      const evidenceClass = String(row.evidence_class ?? row.evidence_grade ?? document.evidence_grade ?? '');
      const exactStructural = ['RUNTIME_CANDIDATE', 'ITEM_ROUTE_DIFFERENTIAL'].includes(kind)
        && /STATIC|EMULATION|SHAPE|STRUCTURAL/i.test(evidenceClass);
      const externalExactBuildAttestation = kind === 'EXTERNAL_ROUTE_ATTESTATION'
        && evidenceClass === 'VERIFIED_EXTERNAL_EXACT_BUILD_MACHINE_ROWS';
      const routeRow = {
        ...descriptor,
        route_evidence_class: evidenceClass || null,
        exact_structural_candidate_evidence: exactStructural,
        external_exact_build_route_attestation: externalExactBuildAttestation,
        semantic_name: row.semantic_name ?? null,
        binding_id: row.binding_id ?? null,
        observed_count: row.observed_count ?? null,
        exact_build_provenance: row.provenance ?? null,
      };
      if (!routeEvidence.has(packetId)) routeEvidence.set(packetId, []);
      routeEvidence.get(packetId).push(routeRow);
    }
    return descriptor;
  });
  return { documents, routeEvidence };
}

function normalizeRegressionAttestations(entries, targetBuild) {
  const rows = [];
  for (const entry of entries) {
    const document = entry.document ?? entry;
    if (supplementalKind(document) !== 'REGRESSION_ATTESTATION') continue;
    const status = String(document.status ?? document.overall_status ?? document.result ?? '').toUpperCase();
    const declaredBuild = declaredSupplementalBuild(document);
    rows.push({
      source: entry.source ?? entry.descriptor ?? null,
      declared_build: declaredBuild,
      status: status || null,
      test_count: Number(document.test_count ?? document.scenario_count ?? document.passed_test_count ?? 0),
      pass: declaredBuild === targetBuild && status === 'PASS'
        && Number(document.test_count ?? document.scenario_count ?? document.passed_test_count ?? 0) > 0,
    });
  }
  return {
    required_schema: 'REGRESSION_ATTESTATION',
    exact_build: targetBuild,
    candidate_count: rows.length,
    passing_attestation_count: rows.filter((row) => row.pass).length,
    pass: rows.some((row) => row.pass),
    rows,
  };
}

function buildStatusMetrics(routes) {
  const routeStatusCounts = Object.fromEntries(BASELINE_STATUS_VOCABULARY
    .map((status) => [status.toLowerCase(), 0]));
  const packetStatusCounts = Object.fromEntries(BASELINE_STATUS_VOCABULARY
    .map((status) => [status.toLowerCase(), 0]));
  for (const route of routes) {
    const key = route.status.baseline_status.toLowerCase();
    routeStatusCounts[key] += 1;
    packetStatusCounts[key] += route.observed.count;
  }
  const routeTotal = routes.length;
  const packetTotal = routes.reduce((sum, route) => sum + route.observed.count, 0);
  return {
    definitions: {
      known: 'Verified exact-build canonical semantic route from the capability manifest.',
      decoded: 'Exact structural decode or explicit negative-control decode without canonical positive semantics.',
      classified: 'Undecoded route whose callback RTTI name matches a candidate domain rule.',
      unknown: 'No verified semantic, exact structural/negative decode, or RTTI domain-rule match.',
    },
    route_status_counts: routeStatusCounts,
    route_status_fractions: Object.fromEntries(Object.entries(routeStatusCounts)
      .map(([key, value]) => [key, ratio(value, routeTotal)])),
    packet_status_counts: packetStatusCounts,
    packet_status_fractions: Object.fromEntries(Object.entries(packetStatusCounts)
      .map(([key, value]) => [key, ratio(value, packetTotal)])),
    total_route_count: routeTotal,
    total_packet_count: packetTotal,
    route_partition_sum: Object.values(routeStatusCounts).reduce((sum, count) => sum + count, 0),
    packet_partition_sum: Object.values(packetStatusCounts).reduce((sum, count) => sum + count, 0),
  };
}

function buildDomainDashboard(routes, capabilityRecords, targetBuild) {
  const domains = DOMAIN_VOCABULARY.map((domain) => {
    const rows = routes.filter((route) => route.domain.primary_domain === domain);
    const capabilityRows = capabilityRecords.filter((record) => domainForCapability(record.semantic_capability) === domain);
    const routeStatusCounts = Object.fromEntries(BASELINE_STATUS_VOCABULARY
      .map((status) => [status.toLowerCase(), rows.filter((route) => route.status.baseline_status === status).length]));
    const packetStatusCounts = Object.fromEntries(BASELINE_STATUS_VOCABULARY
      .map((status) => [status.toLowerCase(), rows
        .filter((route) => route.status.baseline_status === status)
        .reduce((sum, route) => sum + route.observed.count, 0)]));
    const knownLimits = uniqueSorted(capabilityRows.flatMap((record) => record.known_limits ?? []));
    const researchStatus = rows.length > 0 || capabilityRows.length > 0
      ? 'SYSTEMATIC_RECORD_PRESENT' : 'NOT_OBSERVED_OR_CAPABILITY_REGISTERED';
    return {
      domain,
      observed_route_count: rows.length,
      observed_packet_count: rows.reduce((sum, route) => sum + route.observed.count, 0),
      route_status_counts: routeStatusCounts,
      packet_status_counts: packetStatusCounts,
      positive_known_route_count: routeStatusCounts.known,
      positive_coverage_status: routeStatusCounts.known > 0
        ? 'PARTIAL_OBSERVED_ROUTE_COVERAGE' : 'NO_KNOWN_OBSERVED_ROUTE',
      systematic_research_record: {
        status: researchStatus,
        route_statuses: uniqueSorted(rows.map((route) => route.status.baseline_status)),
        capability_validation_statuses: uniqueSorted(capabilityRows.map((record) => record.validation_status)),
        known_limits: knownLimits.length > 0 ? knownLimits : [
          'No exact-build positive capability record is available for this domain.',
        ],
        next_required_evidence: rows.length > 0
          ? uniqueSorted(rows.flatMap((route) => route.research.next_required_evidence))
          : capabilityRows.length > 0
            ? ['Recover an exact-build runtime route/layout and validate it against independent semantic anchors.']
            : ['Register exact-build observed routes or an explicit unavailable capability record.'],
      },
    };
  });
  const capabilityRows = capabilityRecords.map((record) => ({
    semantic_capability: record.semantic_capability,
    domain: domainForCapability(record.semantic_capability),
    validation_status: record.validation_status,
    evidence_grade: record.evidence_grade,
    protocol_route: record.protocol_route,
  }));
  return {
    schema: 'FULL_SEMANTIC_DOMAIN_COVERAGE_DASHBOARD_V1',
    analyzer_version: ANALYZER_VERSION,
    exact_build: targetBuild,
    domain_vocabulary: DOMAIN_VOCABULARY,
    classification_policy: {
      verified_semantics: 'Exact-build verified capability-manifest records may supply a positive domain.',
      negative_controls: 'Known negative-control route semantics may supply a domain but never positive coverage.',
      rtti: 'Callback RTTI keyword matches are CANDIDATE classification only and never semantics.',
      missing_rtti: 'Without verified semantics, negative-control domain evidence, or a matching RTTI rule, the domain remains unknown.',
      forbidden_upgrades: ['frequency', 'payload size', 'entity candidate', 'time pattern', 'factory address'],
    },
    domains,
    capability_records: capabilityRows,
    capability_validation_status_counts: countBy(capabilityRows.map((row) => row.validation_status)),
    capability_evidence_grade_counts: countBy(capabilityRows.map((row) => row.evidence_grade)),
  };
}

function buildCompletenessGate({
  routes,
  metrics,
  profilerLimits,
  conservation,
  unobservedManifestRoutes,
  staleInventoryStatusRouteCount,
  targetBuild,
  domainDashboard,
  unknownPacketRegistry,
  regressionAttestation,
}) {
  const requiredSemanticDomains = [
    'entity', 'state', 'movement', 'combat', 'spell', 'missile', 'buff', 'vision',
    'economy', 'objective', 'structure', 'map',
  ];
  const profilerGapCount = profilerLimits.value_representation_limits.length
    + profilerLimits.statistics_minimum_gaps.length
    + (profilerLimits.input_adapter_minimum_gap ? 1 : 0);
  const highFrequencyRoutes = routes.filter((route) => route.observed.count >= 50000);
  const highFrequencyWithoutEvidence = highFrequencyRoutes
    .filter((route) => !route.research.high_frequency_analysis.pass)
    .map((route) => ({
      packet_discriminator: route.packet_discriminator,
      observed_packet_count: route.observed.count,
      evidence_tiers: route.research.evidence_tiers,
      next_required_evidence: route.research.next_required_evidence,
    }));
  const routeResearchGaps = routes
    .filter((route) => !BASELINE_STATUS_VOCABULARY.includes(route.status.baseline_status)
      || route.evidence.raw_evidence.length === 0
      || route.research.next_required_evidence.length === 0)
    .map((route) => route.packet_discriminator);
  const gameplayCandidateGaps = routes
    .filter((route) => !['KNOWN', 'DECODED'].includes(route.status.baseline_status)
      && !['unknown', 'noise', 'UI', 'system', 'map'].includes(route.domain.primary_domain)
      && (!route.status.baseline_status || !route.research.gameplay_candidate_status))
    .map((route) => route.packet_discriminator);
  const domainResearchGaps = domainDashboard.domains
    .filter((row) => requiredSemanticDomains.includes(row.domain)
      && (row.systematic_research_record.status !== 'SYSTEMATIC_RECORD_PRESENT'
        || row.systematic_research_record.known_limits.length === 0
        || row.systematic_research_record.next_required_evidence.length === 0))
    .map((row) => row.domain);
  const enumeratedCapabilities = new Set(
    domainDashboard.capability_records.map((row) => row.semantic_capability),
  );
  const missingRequestedCapabilities = REQUESTED_BASELINE_CAPABILITIES
    .filter((capability) => !enumeratedCapabilities.has(capability));
  const expectedUnknownRoutes = routes.filter((route) => route.status.baseline_status !== 'KNOWN');
  const unknownRegistryIds = new Set(unknownPacketRegistry.routes.map((route) => route.packet_id));
  const unknownRegistryComplete = unknownPacketRegistry.route_count === expectedUnknownRoutes.length
    && unknownPacketRegistry.packet_count === expectedUnknownRoutes.reduce((sum, route) => sum + route.observed.count, 0)
    && expectedUnknownRoutes.every((route) => unknownRegistryIds.has(route.packet_id))
    && unknownPacketRegistry.routes.every((route) => route.research.next_required_evidence.length > 0);
  const noSilentDiscardOrFallback = conservation.join_policy === 'EXACT_BUILD_AND_PACKET_ID_ONE_TO_ONE; NO_FALLBACK; NO_SILENT_DISCARD'
    && routes.every((route) => route.observed.count >= 0
      && route.observed.source_provenance.length > 0
      && route.evidence.raw_evidence.length > 0);
  const checks = [
    {
      check: 'EXACT_BUILD_BOUND_NO_FALLBACK',
      required_for_ready: true,
      pass: conservation.exact_build_pass === true,
      observed: targetBuild,
      expected: DEFAULT_EXACT_BUILD,
    },
    {
      check: 'ROUTE_AND_PACKET_COUNT_CONSERVATION',
      required_for_ready: true,
      pass: conservation.route_conservation_pass === true && conservation.packet_conservation_pass === true,
      observed: conservation,
      expected: 'all joined inputs conserve every observed route and packet count',
    },
    {
      check: 'EVERY_OBSERVED_ROUTE_HAS_PARTITION_RAW_EVIDENCE_AND_NEXT_REQUIRED_EVIDENCE',
      required_for_ready: true,
      pass: routeResearchGaps.length === 0,
      observed: { gap_count: routeResearchGaps.length, routes: routeResearchGaps },
      expected: 'all observed routes have an explicit KNOWN/DECODED/CLASSIFIED/UNKNOWN partition, raw evidence, and next evidence',
    },
    {
      check: 'HIGH_FREQUENCY_ROUTES_HAVE_ANALYSIS_EVIDENCE_TIER',
      required_for_ready: true,
      pass: highFrequencyWithoutEvidence.length === 0,
      observed: {
        threshold_packets: 50000,
        qualifying_route_count: highFrequencyRoutes.length,
        missing: highFrequencyWithoutEvidence,
      },
      expected: 'each >=50,000 packet route has VERIFIED manifest, exact structural/negative/profile evidence, or unique RTTI + registration/factory analysis',
    },
    {
      check: 'GAMEPLAY_CANDIDATES_HAVE_EXPLICIT_STATUS',
      required_for_ready: true,
      pass: gameplayCandidateGaps.length === 0,
      observed: gameplayCandidateGaps,
      expected: 'every gameplay-domain candidate has a non-empty baseline/research status; UNKNOWN is allowed',
    },
    {
      check: 'HIGH_VALUE_DOMAINS_HAVE_SYSTEMATIC_RESEARCH_RECORDS',
      required_for_ready: true,
      pass: domainResearchGaps.length === 0,
      observed: domainResearchGaps,
      expected: 'each required domain dashboard row has a research record, known limits, and next evidence; UNAVAILABLE/UNKNOWN are allowed',
    },
    {
      check: 'REQUESTED_CAPABILITY_ENUMERATION_COMPLETE',
      required_for_ready: true,
      pass: missingRequestedCapabilities.length === 0,
      observed: {
        required_capability_count: REQUESTED_BASELINE_CAPABILITIES.length,
        missing: missingRequestedCapabilities,
      },
      expected: 'every requested A-Z fact-layer capability has an explicit exact-build manifest record; UNAVAILABLE/UNKNOWN are allowed',
    },
    {
      check: 'UNKNOWN_PACKET_REGISTRY_IS_COMPLETE_AND_ACTIONABLE',
      required_for_ready: true,
      pass: unknownRegistryComplete,
      observed: {
        registry_route_count: unknownPacketRegistry.route_count,
        expected_route_count: expectedUnknownRoutes.length,
        registry_packet_count: unknownPacketRegistry.packet_count,
        expected_packet_count: expectedUnknownRoutes.reduce((sum, route) => sum + route.observed.count, 0),
      },
      expected: 'all non-KNOWN observed routes appear exactly once with explicit next evidence',
    },
    {
      check: 'PROFILER_REQUIRED_REPRESENTATIONS_STATISTICS_AND_ANCHORS_SUPPORTED',
      required_for_ready: true,
      pass: profilerLimits.required_support?.pass === true,
      observed: {
        required_support: profilerLimits.required_support,
        disclosed_non_blocking_limit_entry_count: profilerGapCount,
      },
      expected: 'floats/integers/bitfields/packed fields/IDs/vectors/strings/hashes, required statistics, and all declared anchor families are supported; disclosed methodological limits remain explicit',
    },
    {
      check: 'MANIFEST_ROUTES_ARE_IN_INVENTORY_OR_EXACT_EXTERNAL_ATTESTATION',
      required_for_ready: true,
      pass: unobservedManifestRoutes.length === 0,
      observed: unobservedManifestRoutes,
      expected: [],
    },
    {
      check: 'INVENTORY_DECODE_STATUS_MATCHES_AUTHORITATIVE_CAPABILITY_MANIFEST',
      required_for_ready: true,
      pass: staleInventoryStatusRouteCount === 0,
      observed: staleInventoryStatusRouteCount,
      expected: 0,
    },
    {
      check: 'REGRESSION_ATTESTATION_IS_EXPLICIT_AND_PASSING',
      required_for_ready: true,
      pass: regressionAttestation.pass,
      observed: regressionAttestation,
      expected: 'an exact-build REGRESSION_ATTESTATION with PASS and a nonzero scenario/test count',
    },
    {
      check: 'NO_SILENT_DISCARD_OR_FALLBACK',
      required_for_ready: true,
      pass: noSilentDiscardOrFallback,
      observed: conservation.join_policy,
      expected: 'one-to-one exact-build route join, preserved raw inventory provenance, no fallback, and no silent discard',
    },
  ];
  const blockers = checks.filter((row) => row.required_for_ready && !row.pass)
    .map((row) => ({ check: row.check, observed: row.observed, expected: row.expected }));
  return {
    schema: 'FULL_SEMANTIC_COMPLETENESS_GATE_V1',
    analyzer_version: ANALYZER_VERSION,
    exact_build: targetBuild,
    ready: blockers.length === 0,
    status: blockers.length === 0 ? 'READY' : 'BLOCKED_NOT_READY',
    checks,
    blockers,
    policy: 'SEMANTIC_BASELINE_READY requires complete inventory/research accounting, not universal positive semantic verification. Remaining UNKNOWN/UNAVAILABLE states are allowed only when explicit, evidenced, and actionable.',
    warning: 'Candidate classification, structural evidence, and supplemental provenance never establish positive packet semantics.',
  };
}

function buildFullSemanticBaseline({
  inventory,
  callbackMap,
  capabilityManifest,
  profilerCoverage,
  profilerProfiles = [],
  negativeAudits = [],
  supplementalEvidence = [],
  sourceDescriptors = [],
} = {}, options = {}) {
  const targetBuild = options.targetBuild ?? DEFAULT_EXACT_BUILD;
  invariant(capabilityManifest?.exact_build_only === true,
    'capability manifest must be exact-build-only');
  invariant(capabilityManifest?.nearest_build_fallback === 'FORBIDDEN',
    'capability manifest must forbid nearest-build fallback');
  invariant(profilerCoverage?.promotion_authority === 'NONE',
    'profiler coverage must have no promotion authority');
  const inventorySummary = validateInventory(inventory, targetBuild);
  const callbackSummary = validateCallbackMap(callbackMap, inventory, targetBuild);
  const capabilityProfile = capabilityManifest.build_profiles?.[targetBuild];
  invariant(capabilityProfile && Array.isArray(capabilityProfile.records),
    `capability manifest has no exact profile for ${targetBuild}`);
  const capabilityRecords = capabilityProfile.records;
  const normalizedSupplemental = normalizeSupplementalEvidence(supplementalEvidence, targetBuild);
  const regressionAttestation = normalizeRegressionAttestations(supplementalEvidence, targetBuild);

  const manifestByRoute = new Map();
  const unobservedManifestRoutes = [];
  const externallyAttestedManifestRoutes = [];
  const inventoryIds = new Set(inventory.packets.map((row) => numericPacketId(row.packet_id)));
  for (const [packetId, rows] of normalizedSupplemental.routeEvidence.entries()) {
    invariant(inventoryIds.has(packetId)
      || rows.every((row) => row.external_exact_build_route_attestation === true),
    `supplemental evidence route ${formatPacketId(packetId)} is absent from exact-build inventory and lacks an exact external attestation`);
  }
  for (const record of capabilityRecords) {
    for (const packetId of routeIdsFromManifestRecord(record)) {
      if (!manifestByRoute.has(packetId)) manifestByRoute.set(packetId, []);
      manifestByRoute.get(packetId).push(record);
      if (!inventoryIds.has(packetId)) {
        const matchingExternalAttestations = (normalizedSupplemental.routeEvidence.get(packetId) ?? [])
          .filter((row) => row.external_exact_build_route_attestation === true
            && row.semantic_name === record.semantic_capability
            && record.validation_status === 'PASS'
            && record.evidence_grade === 'VERIFIED_DIRECT');
        const summary = {
          packet_id: packetId,
          packet_discriminator: formatPacketId(packetId),
          semantic_capability: record.semantic_capability,
          validation_status: record.validation_status,
          evidence_grade: record.evidence_grade,
        };
        if (matchingExternalAttestations.length === 1) {
          externallyAttestedManifestRoutes.push({
            ...summary,
            attestation: matchingExternalAttestations[0],
          });
        } else {
          unobservedManifestRoutes.push(summary);
        }
      }
    }
  }

  const normalizedProfiles = profilerProfiles.flatMap((entry) => {
    const document = entry.document ?? entry;
    const source = entry.source ?? entry.descriptor ?? null;
    const routeProfiles = Array.isArray(document.route_profiles) ? document.route_profiles : [];
    invariant(routeProfiles.length > 0, 'profiler evidence document must describe at least one route');
    return routeProfiles.map((route) => normalizeProfilerProfile(document, source, route));
  });
  const normalizedAudits = negativeAudits.map((entry) => normalizeNegativeAudit(
    entry.document ?? entry,
    entry.source ?? entry.descriptor ?? null,
  ));
  const profilerByRoute = new Map();
  for (const item of [...normalizedProfiles, ...normalizedAudits]) {
    invariant(item.target_build === undefined || item.target_build === null || item.target_build === targetBuild,
      `profiler evidence build mismatch for ${item.packet_discriminator}`);
    invariant(item.exact_build === undefined || item.exact_build === null || item.exact_build === targetBuild,
      `negative audit build mismatch for ${item.packet_discriminator}`);
    invariant(inventoryIds.has(item.packet_id),
      `profiler evidence route ${item.packet_discriminator} is absent from exact-build inventory`);
    if (!profilerByRoute.has(item.packet_id)) profilerByRoute.set(item.packet_id, []);
    profilerByRoute.get(item.packet_id).push(item);
  }

  const sidecarByRoute = new Map(callbackMap.routes
    .map((row) => [numericPacketId(row.packet_id), row]));
  const routes = inventory.packets.map((packet) => {
    const packetId = numericPacketId(packet.packet_id);
    const runtime = sidecarByRoute.get(packetId);
    const manifestRecords = manifestByRoute.get(packetId) ?? [];
    const knownManifestRecords = manifestRecords.filter(isVerifiedManifestRecord);
    const profileEvidence = profilerByRoute.get(packetId) ?? [];
    const supplementalRouteEvidence = normalizedSupplemental.routeEvidence.get(packetId) ?? [];
    const negativeEvidence = profileEvidence.filter((item) => item.route_role === 'NEGATIVE_CONTROL');
    const rttiClassification = classifyRttiNames(runtime.callback_names ?? []);
    const domain = classifyRouteDomain(knownManifestRecords, negativeEvidence, rttiClassification);
    const exactDecoded = profileEvidence.some((item) => item.exact_structural_decode_evidence === true);
    let baselineStatus;
    if (knownManifestRecords.length > 0) baselineStatus = 'KNOWN';
    else if (exactDecoded) baselineStatus = 'DECODED';
    else if (rttiClassification.primary_domain !== 'unknown') baselineStatus = 'CLASSIFIED';
    else baselineStatus = 'UNKNOWN';
    const knownCapabilities = uniqueSorted(knownManifestRecords
      .map((record) => record.semantic_capability));
    const candidateCapabilities = uniqueSorted(manifestRecords
      .filter((record) => !isVerifiedManifestRecord(record))
      .map((record) => record.semantic_capability));
    const routeEvidenceGrade = baselineStatus === 'KNOWN'
      ? uniqueSorted(knownManifestRecords.map((record) => record.evidence_grade))
      : baselineStatus === 'UNKNOWN' ? ['UNAVAILABLE'] : ['CANDIDATE'];
    const manifestOverridesInventory = baselineStatus === 'KNOWN'
      && packet.currently_decoded_as_status !== 'EXACT_BUILD_ROUTE_REGISTERED';
    const profileAnalysis = profileEvidence.some((item) => Number(item.profiled_record_count) > 0
      || Number(item.decoded_source_full_consume_count) > 0);
    const runtimeRegistrationAndFactory = runtime.callback_mapping_status === 'UNIQUE_CALLBACK_RTTI_NAME'
      && (runtime.callback_names ?? []).length > 0
      && (runtime.factory_packets ?? []).length > 0;
    const evidenceTiers = uniqueSorted([
      baselineStatus === 'KNOWN' ? 'VERIFIED_EXACT_BUILD_MANIFEST' : null,
      exactDecoded ? 'EXACT_STRUCTURAL_OR_NEGATIVE_DECODE' : null,
      profileAnalysis ? 'EXACT_BUILD_PROFILE_ANALYSIS' : null,
      supplementalRouteEvidence.some((item) => item.exact_structural_candidate_evidence)
        ? 'EXACT_RUNTIME_STRUCTURAL_CANDIDATE' : null,
      runtimeRegistrationAndFactory ? 'UNIQUE_RTTI_REGISTRATION_AND_FACTORY' : null,
    ]);
    const highFrequencyAnalysisTiers = new Set([
      'VERIFIED_EXACT_BUILD_MANIFEST',
      'EXACT_STRUCTURAL_OR_NEGATIVE_DECODE',
      'EXACT_BUILD_PROFILE_ANALYSIS',
      'EXACT_RUNTIME_STRUCTURAL_CANDIDATE',
      'UNIQUE_RTTI_REGISTRATION_AND_FACTORY',
    ]);
    const nextRequiredEvidence = nextRequiredEvidenceForStatus(baselineStatus);
    return {
      exact_build: targetBuild,
      packet_id: packetId,
      packet_discriminator: packet.packet_discriminator ?? formatPacketId(packetId),
      observed: {
        count: packet.count,
        payload_size_distribution: packet.payload_size_distribution,
        payload_size_observation_status: packet.payload_size_observation_status,
        entity_candidate: packet.entity_candidate,
        temporal_behavior: packet.temporal_behavior,
        source_provenance: packet.provenance ?? [],
      },
      runtime_registration: {
        callback_mapping_status: runtime.callback_mapping_status,
        callback_names: runtime.callback_names ?? [],
        callbacks: runtime.callbacks ?? [],
        factory_packets: runtime.factory_packets ?? [],
        factory_status: (runtime.factory_packets ?? []).length > 0
          ? 'FACTORY_DESERIALIZER_SHAPE_AVAILABLE' : 'NO_FACTORY_SHAPE_IN_SIDECAR',
        semantic_warning: 'RTTI names and factory shapes are structural evidence. They cannot promote packet semantics.',
      },
      decoder: {
        inventory_decode_status: packet.currently_decoded_as_status,
        authoritative_status_source: baselineStatus === 'KNOWN'
          ? 'EXACT_BUILD_CAPABILITY_MANIFEST' : 'COMPOSED_BASELINE_EVIDENCE',
        input_status_reconciliation: manifestOverridesInventory
          ? 'CAPABILITY_MANIFEST_OVERRIDES_STALE_INVENTORY_DECODE_STATUS'
          : 'NO_STALE_VERIFIED_MANIFEST_OVERRIDE_REQUIRED',
        inventory_refresh_required: manifestOverridesInventory,
        inventory_decoded_as: packet.decoded_as ?? [],
        manifest_route_records: manifestRecords.map(summarizeManifestRecord),
        profiler_or_negative_evidence: profileEvidence,
        decoder_status: baselineStatus === 'KNOWN'
          ? 'VERIFIED_SEMANTIC_EXACT_BUILD'
          : baselineStatus === 'DECODED'
            ? 'EXACT_STRUCTURAL_OR_NEGATIVE_DECODE_NO_CANONICAL_POSITIVE_SEMANTIC'
            : baselineStatus === 'CLASSIFIED'
              ? 'NOT_DECODED_RTTI_CANDIDATE_ONLY'
              : 'NOT_DECODED_UNKNOWN',
      },
      domain,
      status: {
        baseline_status: baselineStatus,
        known_semantic_capabilities: knownCapabilities,
        candidate_manifest_capabilities: candidateCapabilities,
        positive_semantic_coverage: baselineStatus === 'KNOWN',
        negative_control: negativeEvidence.length > 0,
        exact_structural_decode_evidence: exactDecoded,
      },
      evidence: {
        aggregate_evidence_grades: routeEvidenceGrade,
        inventory_confidence: packet.confidence ?? null,
        manifest_evidence_grades: uniqueSorted(manifestRecords.map((record) => record.evidence_grade)),
        manifest_validation_statuses: uniqueSorted(manifestRecords.map((record) => record.validation_status)),
        runtime_name_evidence: runtime.callback_mapping_status,
        profiler_evidence_grades: uniqueSorted(profileEvidence.map((item) => item.evidence_grade)),
        semantic_claim: baselineStatus === 'KNOWN' ? knownCapabilities : null,
        raw_evidence: [
          {
            kind: 'EXACT_BUILD_PACKET_INVENTORY',
            observed_packet_count: packet.count,
            payload_size_observation_status: packet.payload_size_observation_status,
            source_provenance: packet.provenance ?? [],
          },
          {
            kind: 'OBSERVED_RUNTIME_REGISTRATION_MAP',
            callback_mapping_status: runtime.callback_mapping_status,
            callback_name_count: (runtime.callback_names ?? []).length,
            factory_packet_count: (runtime.factory_packets ?? []).length,
          },
          ...profileEvidence.map((item) => ({
            kind: 'FIELD_PROFILER_OR_NEGATIVE_AUDIT',
            source: item.source,
            route_role: item.route_role,
            profiled_record_count: item.profiled_record_count,
            exact_structural_decode_evidence: item.exact_structural_decode_evidence,
          })),
          ...supplementalRouteEvidence.map((item) => ({
            kind: 'SUPPLEMENTAL_PROVENANCE_ONLY',
            supplemental_kind: item.kind,
            source: item.source,
            route_evidence_class: item.route_evidence_class,
            exact_structural_candidate_evidence: item.exact_structural_candidate_evidence,
            semantic_promotion_authority: 'NONE',
          })),
        ],
        evidence_warning: baselineStatus === 'KNOWN'
          ? 'Semantics are limited to the named exact-build manifest capabilities and field-specific evidence.'
          : 'Classification, structural decode, scores, and negative evidence do not establish positive packet semantics.',
      },
      research: {
        evidence_tiers: evidenceTiers,
        high_frequency_analysis: {
          threshold_packets: 50000,
          applies: packet.count >= 50000,
          pass: packet.count < 50000 || evidenceTiers.some((tier) => highFrequencyAnalysisTiers.has(tier)),
          qualifying_tiers: evidenceTiers.filter((tier) => highFrequencyAnalysisTiers.has(tier)),
        },
        gameplay_candidate_status: !['unknown', 'noise', 'UI', 'system', 'map'].includes(domain.primary_domain)
          ? `STATUS_${baselineStatus}` : 'NOT_GAMEPLAY_CANDIDATE_OR_UNKNOWN_DOMAIN',
        next_required_evidence: nextRequiredEvidence,
      },
    };
  }).sort((left, right) => left.packet_id - right.packet_id);

  const metrics = buildStatusMetrics(routes);
  metrics.stale_inventory_decode_status_route_count = routes
    .filter((route) => route.decoder.inventory_refresh_required).length;
  metrics.stale_inventory_decode_status_routes = routes
    .filter((route) => route.decoder.inventory_refresh_required)
    .map((route) => route.packet_discriminator);
  const profilerLimits = summarizeProfilerCoverageLimits(profilerCoverage);
  const conservation = {
    exact_build_pass: inventory.builds[0].game_version === targetBuild
      && callbackMap.build === targetBuild,
    inventory_route_count: inventorySummary.route_count,
    callback_route_count: callbackSummary.route_count,
    output_route_count: routes.length,
    route_conservation_pass: inventorySummary.route_count === callbackSummary.route_count
      && callbackSummary.route_count === routes.length
      && metrics.route_partition_sum === routes.length,
    inventory_packet_count: inventorySummary.packet_count,
    callback_packet_count: callbackSummary.packet_count,
    output_packet_count: metrics.total_packet_count,
    packet_conservation_pass: inventorySummary.packet_count === callbackSummary.packet_count
      && callbackSummary.packet_count === metrics.total_packet_count
      && metrics.packet_partition_sum === metrics.total_packet_count,
    join_policy: 'EXACT_BUILD_AND_PACKET_ID_ONE_TO_ONE; NO_FALLBACK; NO_SILENT_DISCARD',
  };
  const domainDashboard = buildDomainDashboard(routes, capabilityRecords, targetBuild);
  const unknownRoutes = routes.filter((route) => route.status.baseline_status !== 'KNOWN');
  const unknownPacketRegistry = {
    schema: 'FULL_SEMANTIC_UNKNOWN_PACKET_REGISTRY_V1',
    analyzer_version: ANALYZER_VERSION,
    generated_at: options.generatedAt ?? capabilityManifest.generated_at ?? null,
    exact_build: targetBuild,
    scope: 'Every observed route without verified canonical positive semantics; includes DECODED, CLASSIFIED, and UNKNOWN backlog states.',
    route_count: unknownRoutes.length,
    packet_count: unknownRoutes.reduce((sum, route) => sum + route.observed.count, 0),
    status_counts: countBy(unknownRoutes.map((route) => route.status.baseline_status), BASELINE_STATUS_VOCABULARY),
    unclassified_unknown_route_count: unknownRoutes
      .filter((route) => route.status.baseline_status === 'UNKNOWN').length,
    routes: unknownRoutes,
  };
  const completenessGate = buildCompletenessGate({
    routes,
    metrics,
    profilerLimits,
    conservation,
    unobservedManifestRoutes,
    staleInventoryStatusRouteCount: metrics.stale_inventory_decode_status_route_count,
    targetBuild,
    domainDashboard,
    unknownPacketRegistry,
    regressionAttestation,
  });
  const negativeRoutes = routes.filter((route) => route.status.negative_control);
  const nonpositiveCapabilityRecords = capabilityRecords
    .filter((record) => !isVerifiedManifestRecord(record))
    .map(summarizeManifestRecord);
  const generatedAt = options.generatedAt ?? capabilityManifest.generated_at ?? null;
  const sourceInputs = sourceDescriptors.map((source) => ({ ...source }));

  const observedRouteRegistry = {
    schema: 'FULL_SEMANTIC_OBSERVED_ROUTE_REGISTRY_V1',
    analyzer_version: ANALYZER_VERSION,
    generated_at: generatedAt,
    exact_build: targetBuild,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    route_count: routes.length,
    packet_count: metrics.total_packet_count,
    conservation,
    routes,
  };
  const negativeEvidenceRegistry = {
    schema: 'FULL_SEMANTIC_NEGATIVE_EVIDENCE_REGISTRY_V1',
    analyzer_version: ANALYZER_VERSION,
    generated_at: generatedAt,
    exact_build: targetBuild,
    policy: 'Negative evidence excludes claims or routes from positive coverage; missing/unavailable is never observed zero.',
    route_negative_control_count: negativeRoutes.length,
    route_negative_controls: negativeRoutes,
    nonpositive_capability_record_count: nonpositiveCapabilityRecords.length,
    nonpositive_capability_records: nonpositiveCapabilityRecords,
    profiler_coverage_limits: profilerLimits,
  };
  const baseline = {
    schema: FULL_SEMANTIC_BASELINE_SCHEMA,
    analyzer_version: ANALYZER_VERSION,
    generated_at: generatedAt,
    exact_build: targetBuild,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    promotion_authority: 'NONE',
    source_inputs: sourceInputs,
    supplemental_evidence: {
      policy: 'Provenance-only; supplemental documents do not promote a candidate classification, field, or event to a semantic fact.',
      documents: normalizedSupplemental.documents,
      regression_attestation: regressionAttestation,
    },
    policies: {
      route_join: conservation.join_policy,
      rtti: 'CANDIDATE_FAMILY_OR_DOMAIN_CLASSIFICATION_ONLY; NEVER_SEMANTIC_PROMOTION',
      no_rtti: 'UNKNOWN_UNLESS_VERIFIED_MANIFEST_SEMANTICS_OR_EXACT_STRUCTURAL_NEGATIVE_DECODE_EXISTS',
      negative_evidence: negativeEvidenceRegistry.policy,
      map_behavior_boundary: 'NO_MAP_TRUTH_OR_BEHAVIOR_INFERENCE',
      holdout: 'NOT_AN_INPUT; MUST_NOT_BE_READ_ENUMERATED_HASHED_OR_CONSUMED',
    },
    metrics,
    conservation,
    capability_manifest_overview: {
      release_status: capabilityProfile.release_status,
      record_count: capabilityRecords.length,
      validation_status_counts: countBy(capabilityRecords.map((record) => record.validation_status)),
      evidence_grade_counts: countBy(capabilityRecords.map((record) => record.evidence_grade)),
      unobserved_manifest_route_records: unobservedManifestRoutes,
      externally_attested_manifest_route_records: externallyAttestedManifestRoutes,
    },
    registry_summaries: {
      observed_route_registry: { route_count: routes.length, packet_count: metrics.total_packet_count },
      unknown_packet_registry: {
        route_count: unknownPacketRegistry.route_count,
        packet_count: unknownPacketRegistry.packet_count,
      },
      negative_evidence_registry: {
        route_negative_control_count: negativeEvidenceRegistry.route_negative_control_count,
        nonpositive_capability_record_count: negativeEvidenceRegistry.nonpositive_capability_record_count,
      },
    },
    domain_coverage_dashboard: domainDashboard,
    completeness_gate: completenessGate,
    routes,
  };

  return {
    baseline,
    observedRouteRegistry,
    unknownPacketRegistry,
    negativeEvidenceRegistry,
    domainDashboard,
    completenessGate,
  };
}

function loadBaselineInputs(config = {}) {
  const root = path.resolve(config.root ?? process.cwd());
  const inventorySource = readJsonSource(
    config.inventoryPath ?? DEFAULT_INPUT_PATHS.inventory,
    'packet_inventory',
    root,
  );
  const callbackSource = readJsonSource(
    config.callbackMapPath ?? DEFAULT_INPUT_PATHS.callbackMap,
    'callback_route_map',
    root,
  );
  const manifestSource = readJsonSource(
    config.capabilityManifestPath ?? DEFAULT_INPUT_PATHS.capabilityManifest,
    'capability_manifest',
    root,
  );
  const coverageSource = readJsonSource(
    config.profilerCoveragePath ?? DEFAULT_INPUT_PATHS.profilerCoverage,
    'profiler_coverage',
    root,
  );
  const profilePaths = config.profilerProfilePaths ?? DEFAULT_INPUT_PATHS.profilerProfiles;
  const auditPaths = config.negativeAuditPaths ?? DEFAULT_INPUT_PATHS.negativeAudits;
  const supplementalPaths = config.supplementalEvidencePaths ?? DEFAULT_INPUT_PATHS.supplementalEvidence;
  const profileSources = profilePaths.map((filePath, index) => readJsonSource(
    filePath,
    `profiler_profile_${index + 1}`,
    root,
  ));
  const auditSources = auditPaths.map((filePath, index) => readJsonSource(
    filePath,
    `negative_audit_${index + 1}`,
    root,
  ));
  const supplementalSources = supplementalPaths.map((filePath, index) => readJsonSource(
    filePath,
    `supplemental_evidence_${index + 1}`,
    root,
  ));
  const allSources = [
    inventorySource,
    callbackSource,
    manifestSource,
    coverageSource,
    ...profileSources,
    ...auditSources,
    ...supplementalSources,
  ];
  invariant(callbackSource.document.inventory?.sha256 === inventorySource.sha256,
    'callback route map was not built from the supplied inventory hash');
  return {
    inventory: inventorySource.document,
    callbackMap: callbackSource.document,
    capabilityManifest: manifestSource.document,
    profilerCoverage: coverageSource.document,
    profilerProfiles: profileSources.map((source) => ({
      document: source.document,
      source: loaderAuthenticatedDescriptor(source),
    })),
    negativeAudits: auditSources.map((source) => ({
      document: source.document,
      source: loaderAuthenticatedDescriptor(source),
    })),
    supplementalEvidence: supplementalSources.map((source) => ({
      document: source.document,
      source: loaderAuthenticatedDescriptor(source),
    })),
    sourceDescriptors: allSources.map((source) => ({
      label: source.label,
      path: source.path,
      sha256: source.sha256,
      byte_count: source.byte_count,
      schema: source.schema,
    })),
  };
}

function buildFullSemanticBaselineFromPaths(config = {}) {
  const inputs = loadBaselineInputs(config);
  return buildFullSemanticBaseline(inputs, {
    targetBuild: config.targetBuild ?? DEFAULT_EXACT_BUILD,
    generatedAt: config.generatedAt,
  });
}

function writeJsonFile(filePath, value) {
  const text = `${JSON.stringify(value, null, 2)}\n`;
  fs.writeFileSync(filePath, text, 'utf8');
  return {
    file: path.basename(filePath),
    sha256: sha256Buffer(Buffer.from(text, 'utf8')),
    byte_count: Buffer.byteLength(text),
    schema: value.schema ?? value.schema_version ?? null,
  };
}

function writeFullSemanticBaselineArtifacts(outputDirectory, result) {
  invariant(result?.baseline?.schema === FULL_SEMANTIC_BASELINE_SCHEMA,
    'invalid full semantic baseline result');
  const target = path.resolve(outputDirectory);
  fs.mkdirSync(target, { recursive: true });
  const outputs = [
    ['full_semantic_baseline.json', result.baseline],
    ['observed_route_registry.json', result.observedRouteRegistry],
    ['unknown_packet_registry.json', result.unknownPacketRegistry],
    ['negative_evidence_registry.json', result.negativeEvidenceRegistry],
    ['domain_coverage_dashboard.json', result.domainDashboard],
    ['completeness_gate.json', result.completenessGate],
  ].map(([name, value]) => writeJsonFile(path.join(target, name), value));
  const artifactManifest = {
    schema: 'FULL_SEMANTIC_BASELINE_ARTIFACT_MANIFEST_V1',
    analyzer_version: ANALYZER_VERSION,
    generated_at: result.baseline.generated_at,
    exact_build: result.baseline.exact_build,
    self_hash_excluded: true,
    files: outputs,
  };
  const manifestOutput = writeJsonFile(path.join(target, 'artifact_manifest.json'), artifactManifest);
  return {
    output_directory: target,
    files: [...outputs, manifestOutput],
  };
}

module.exports = {
  ANALYZER_VERSION,
  BASELINE_STATUS_VOCABULARY,
  DEFAULT_EXACT_BUILD,
  DEFAULT_INPUT_PATHS,
  DOMAIN_VOCABULARY,
  FULL_SEMANTIC_BASELINE_SCHEMA,
  REQUESTED_BASELINE_CAPABILITIES,
  assessProfilerRequiredSupport,
  assertAllowedInputPath,
  buildFullSemanticBaseline,
  buildFullSemanticBaselineFromPaths,
  classifyRttiNames,
  domainForCapability,
  formatPacketId,
  loadBaselineInputs,
  normalizeNegativeAudit,
  normalizeProfilerProfile,
  numericPacketId,
  routeIdsFromManifestRecord,
  rttiTermMatches,
  rttiTokens,
  sha256Buffer,
  validateCallbackMap,
  validateInventory,
  writeFullSemanticBaselineArtifacts,
};
