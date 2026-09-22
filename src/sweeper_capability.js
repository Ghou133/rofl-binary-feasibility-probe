'use strict';

const fs = require('node:fs');
const path = require('node:path');

const SWEEPER_CAPABILITY_SCHEMA_VERSION = 1;
const SWEEPER_REPLAY_VERSION = '16.16.805.0442';
const SWEEPER_PATCH = '16.16';
const SWEEPER_CAPABILITY_CONTRACT_ID = 'rofl-16.16.805.0442-sweeper-capability-v1';
const SWEEPER_EVIDENCE_SOURCE = 'docs/SWEEPER_CAPABILITY_V1.md';
const SWEEPER_ENTITY_ROUTE_EVIDENCE = Object.freeze({
  artifact: 'artifacts/16_16_ward_semantic_recovery_v1/runtime/all_entity_events.jsonl',
  scope: '20_NON_HOLDOUT_EXACT_16_16_REPLAYS__31862_ROUTE_0x049a_ROWS',
  observation: 'NO_ORACLE_SWEEPER_LENS_OR_SCANNER_NAME_TOKEN_OBSERVED',
  non_activation_named_rows: 'YELLOWTRINKET_797__BLUETRINKET_170',
  limitation: 'BOUNDED_NEGATIVE_ENTITY_ROUTE_EVIDENCE_NOT_PROTOCOL_NONEXISTENCE_PROOF',
});

const CAPABILITY_DEFINITIONS = Object.freeze({
  TRINKET_STATE: Object.freeze({
    event_key: 'trinket_state_events',
    status: 'UNVERIFIED',
    routes: ['ITEM_OR_TRINKET_SLOT_STATE'],
    blocker: 'NO_EXACT_16_16_ITEM_OR_TRINKET_SLOT_REPLAY_ROUTE_AND_LAYOUT_VALIDATION',
  }),
  TRINKET_SLOT_STATE: Object.freeze({
    event_key: 'trinket_slot_state_events',
    status: 'UNVERIFIED',
    routes: ['ITEM_OR_TRINKET_SLOT_STATE'],
    blocker: 'NO_EXACT_16_16_SLOT_FIELD_OR_INITIAL_STATE_VALIDATION',
  }),
  TRINKET_SWAP: Object.freeze({
    event_key: 'trinket_swap_events',
    status: 'UNVERIFIED',
    routes: ['SWAP_OR_REPLACEMENT_EVENT'],
    blocker: 'NO_EXACT_16_16_OLD_ITEM_NEW_ITEM_PARTICIPANT_TIMESTAMP_ROUTE_VALIDATION',
  }),
  TRINKET_PURCHASE_OR_SWAP: Object.freeze({
    event_key: 'trinket_purchase_or_swap_events',
    status: 'UNVERIFIED',
    routes: ['ITEM_OR_TRINKET_SLOT_STATE', 'SWAP_OR_REPLACEMENT_EVENT'],
    blocker: 'NO_EXACT_16_16_PURCHASE_OR_SWAP_ROUTE_VALIDATION',
  }),
  SWEEPER_HELD: Object.freeze({
    event_key: 'sweeper_held_events',
    status: 'UNVERIFIED',
    routes: ['ITEM_OR_TRINKET_SLOT_STATE', 'SWAP_OR_REPLACEMENT_EVENT'],
    blocker: 'ORACLE_LENS_HOLDING_STATE_IS_NOT_RECOVERED_FOR_16_16',
  }),
  SWEEPER_ACTIVATION: Object.freeze({
    event_key: 'sweeper_activation_events',
    status: 'UNAVAILABLE',
    routes: ['CAST_OR_ITEM_ACTIVE', 'BUFF_OR_OWNER_LINKED_STATE'],
    blocker: '16_16_CASTSPELL_AND_BUFF_ROUTES_HAVE_NO_VERIFIED_REPLAY_ROUTE_OR_PAYLOAD_LAYOUT',
  }),
  SWEEPER_ACTIVE_INTERVAL: Object.freeze({
    event_key: 'sweeper_active_interval_events',
    status: 'UNAVAILABLE',
    routes: ['CAST_OR_ITEM_ACTIVE', 'BUFF_OR_OWNER_LINKED_STATE'],
    blocker: 'ACTIVATION_START_END_OR_DURATION_IS_NOT_RECOVERED_FOR_16_16',
  }),
  SWEEPER_POSITION: Object.freeze({
    event_key: 'sweeper_position_events',
    status: 'UNAVAILABLE',
    routes: ['CAST_OR_ITEM_ACTIVE', 'SPAWNED_VISION_REVEAL_ENTITY'],
    blocker: 'NO_VERIFIED_16_16_ACTIVATION_OR_OWNER_LINKED_POSITION_ROUTE',
  }),
  SWEEPER_OWNER: Object.freeze({
    event_key: 'sweeper_owner_events',
    status: 'UNAVAILABLE',
    routes: ['CAST_OR_ITEM_ACTIVE', 'BUFF_OR_OWNER_LINKED_STATE'],
    blocker: 'NO_VERIFIED_16_16_ACTIVATION_OWNER_LINKAGE',
  }),
});

const SWEEPER_CAPABILITY_NAMES = Object.freeze(Object.keys(CAPABILITY_DEFINITIONS));
const SWEEPER_EVENT_KEYS = Object.freeze(SWEEPER_CAPABILITY_NAMES.map(
  (name) => CAPABILITY_DEFINITIONS[name].event_key,
));

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function inputVersion(input) {
  if (typeof input === 'string') return input;
  return input?.header?.version ?? input?.game_version ?? input?.replay_version ?? null;
}

function capabilityRecord(name, definition, gameVersion) {
  const exactBuild = gameVersion === SWEEPER_REPLAY_VERSION;
  return {
    id: `${SWEEPER_CAPABILITY_CONTRACT_ID}-${name.toLowerCase()}`,
    capability: name,
    event_key: definition.event_key,
    status: exactBuild ? definition.status : 'UNSUPPORTED_VERSION',
    evidence_grade: exactBuild ? definition.status : 'UNSUPPORTED_VERSION',
    evidence_source: SWEEPER_EVIDENCE_SOURCE,
    game_version: exactBuild ? SWEEPER_REPLAY_VERSION : gameVersion,
    patch: exactBuild ? SWEEPER_PATCH : null,
    build_binding: exactBuild ? `EXACT_BUILD_${SWEEPER_REPLAY_VERSION}` : 'NO_CROSS_BUILD_INFERENCE',
    routes_considered: definition.routes,
    blocker: exactBuild ? definition.blocker : 'NO_SWEEPER_CAPABILITY_PROFILE_FOR_THIS_BUILD',
    enabled: false,
  };
}

function emptySweeperEvents() {
  return Object.fromEntries(SWEEPER_EVENT_KEYS.map((key) => [key, []]));
}

function createSweeperCapabilityExport(input) {
  const gameVersion = inputVersion(input);
  const exactBuild = gameVersion === SWEEPER_REPLAY_VERSION;
  const capabilities = Object.fromEntries(SWEEPER_CAPABILITY_NAMES.map((name) => [
    name,
    capabilityRecord(name, CAPABILITY_DEFINITIONS[name], gameVersion),
  ]));
  return deepFreeze({
    schema_version: SWEEPER_CAPABILITY_SCHEMA_VERSION,
    contract_id: SWEEPER_CAPABILITY_CONTRACT_ID,
    status: exactBuild ? 'CAPABILITY_BOUNDARY_PUBLISHED' : 'UNSUPPORTED_VERSION',
    game_version: exactBuild ? SWEEPER_REPLAY_VERSION : gameVersion,
    patch: exactBuild ? SWEEPER_PATCH : null,
    source: SWEEPER_EVIDENCE_SOURCE,
    spawned_entity_route_evidence: exactBuild ? SWEEPER_ENTITY_ROUTE_EVIDENCE : null,
    observation_status: exactBuild
      ? 'NO_VERIFIED_SWEEPER_EVENTS_EMITTED'
      : 'NOT_APPLICABLE_UNSUPPORTED_VERSION',
    event_count_interpretation: 'EMPTY_EVENT_ARRAY_IS_NOT_A_ZERO_BEHAVIOR_CLAIM',
    held_activation_relation: 'SWEEPER_HELD_NE_SWEEPER_ACTIVATION',
    capabilities,
    events: emptySweeperEvents(),
  });
}

const SWEEPER_DECODER_CAPABILITY_PROFILES = deepFreeze(Object.fromEntries(
  SWEEPER_CAPABILITY_NAMES.map((name) => {
    const record = capabilityRecord(name, CAPABILITY_DEFINITIONS[name], SWEEPER_REPLAY_VERSION);
    return [name.toLowerCase(), {
      ...record,
      replay_version: SWEEPER_REPLAY_VERSION,
      semantic_status: record.status,
      candidate_replay_block_packet_id: null,
      export_contract: SWEEPER_CAPABILITY_CONTRACT_ID,
    }];
  }),
));

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
}

function stableManifestJson(input = SWEEPER_REPLAY_VERSION) {
  return `${JSON.stringify(stableValue(createSweeperCapabilityExport(input)), null, 2)}\n`;
}

function writeSweeperCapabilityManifest(outputPath, input = SWEEPER_REPLAY_VERSION) {
  const resolvedPath = path.resolve(outputPath);
  fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });
  fs.writeFileSync(resolvedPath, stableManifestJson(input), 'utf8');
  return resolvedPath;
}

module.exports = {
  CAPABILITY_DEFINITIONS,
  SWEEPER_CAPABILITY_CONTRACT_ID,
  SWEEPER_CAPABILITY_NAMES,
  SWEEPER_CAPABILITY_SCHEMA_VERSION,
  SWEEPER_DECODER_CAPABILITY_PROFILES,
  SWEEPER_EVIDENCE_SOURCE,
  SWEEPER_ENTITY_ROUTE_EVIDENCE,
  SWEEPER_EVENT_KEYS,
  SWEEPER_PATCH,
  SWEEPER_REPLAY_VERSION,
  createSweeperCapabilityExport,
  emptySweeperEvents,
  stableManifestJson,
  writeSweeperCapabilityManifest,
};
