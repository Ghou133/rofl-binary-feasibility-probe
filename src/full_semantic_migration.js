'use strict';

const crypto = require('node:crypto');

const MIGRATION_SCHEMA = 'NEW_BUILD_FULL_SEMANTIC_MIGRATION_V1';
const MIGRATION_STATUSES = Object.freeze([
  'UNCHANGED_VERIFIED',
  'ROUTE_MOVED',
  'FIELD_SHIFT',
  'NEEDS_REVALIDATION',
  'SEMANTIC_CHANGED',
  'UNKNOWN',
  'UNSUPPORTED',
]);

const VERIFIED_GRADES = new Set(['VERIFIED_DIRECT', 'VERIFIED_DERIVED']);
const VERIFIED_VALIDATION = new Set(['PASS', 'PARTIAL']);

function strictCompare(left, right) {
  return String(left).localeCompare(String(right), 'en', { numeric: true });
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort(strictCompare)
    .map((key) => [key, stable(value[key])]));
}

function stableHash(value) {
  return crypto.createHash('sha256').update(JSON.stringify(stable(value))).digest('hex');
}

function assertExactInventory(inventory, build, label) {
  if (!inventory || !Array.isArray(inventory.packets)) {
    throw new TypeError(`${label} must be a packet coverage inventory`);
  }
  const builds = new Set(inventory.packets.map((row) => row.build));
  if (builds.size !== 1 || !builds.has(build)) {
    throw new Error(`${label} must contain exactly build ${build}; nearest-build fallback is forbidden`);
  }
  const total = inventory.packets.reduce((sum, row) => sum + row.count, 0);
  if (total !== inventory.input_record_count) {
    throw new Error(`${label} packet conservation failed: ${total} != ${inventory.input_record_count}`);
  }
}

function packetMap(inventory) {
  return new Map(inventory.packets.map((row) => [row.packet_id, row]));
}

function payloadShape(row) {
  return (row.payload_size_distribution || [])
    .map((entry) => entry.payload_length)
    .sort((left, right) => left - right);
}

function diffPacketInventories(previousInventory, currentInventory, previousBuild, currentBuild) {
  assertExactInventory(previousInventory, previousBuild, 'previous inventory');
  assertExactInventory(currentInventory, currentBuild, 'current inventory');
  const previous = packetMap(previousInventory);
  const current = packetMap(currentInventory);
  const ids = [...new Set([...previous.keys(), ...current.keys()])].sort((a, b) => a - b);
  const rows = ids.map((packetId) => {
    const before = previous.get(packetId) || null;
    const after = current.get(packetId) || null;
    let status = 'UNCHANGED_ROUTE_AND_PAYLOAD_SHAPE';
    if (!before) status = 'NEW_PACKET';
    else if (!after) status = 'REMOVED_PACKET';
    else if (JSON.stringify(payloadShape(before)) !== JSON.stringify(payloadShape(after))) {
      status = 'PAYLOAD_SHAPE_CHANGED';
    }
    return {
      packet_id: packetId,
      packet_id_hex: `0x${packetId.toString(16).padStart(4, '0')}`,
      status,
      previous_count: before?.count ?? 0,
      current_count: after?.count ?? 0,
      previous_payload_lengths: before ? payloadShape(before) : [],
      current_payload_lengths: after ? payloadShape(after) : [],
      current_decode_status: after?.currently_decoded_as_status ?? null,
      current_possible_category: after?.possible_category ?? null,
      current_confidence: after?.confidence ?? null,
    };
  });
  const statusCounts = Object.fromEntries([...new Set(rows.map((row) => row.status))]
    .sort(strictCompare).map((status) => [status, rows.filter((row) => row.status === status).length]));
  const newPacketDiff = rows.filter((row) => row.status === 'NEW_PACKET');
  const removedPacketDiff = rows.filter((row) => row.status === 'REMOVED_PACKET');
  const commonCount = rows.length - newPacketDiff.length - removedPacketDiff.length;
  if (commonCount + newPacketDiff.length !== current.size
      || commonCount + removedPacketDiff.length !== previous.size) {
    throw new Error('packet route conservation failed');
  }
  return {
    previous_build: previousBuild,
    current_build: currentBuild,
    previous_route_count: previous.size,
    current_route_count: current.size,
    status_counts: statusCounts,
    routes: rows,
    NEW_PACKET_DIFF: newPacketDiff,
    REMOVED_PACKET_DIFF: removedPacketDiff,
    conservation: {
      status: 'PASS',
      current_routes: `${commonCount}+${newPacketDiff.length}=${current.size}`,
      previous_routes: `${commonCount}+${removedPacketDiff.length}=${previous.size}`,
    },
  };
}

function recordsForBuild(manifest, build) {
  const profile = manifest?.build_profiles?.[build];
  if (!profile || !Array.isArray(profile.records)) return [];
  return profile.records;
}

function recordMap(manifest, build) {
  return new Map(recordsForBuild(manifest, build)
    .map((row) => [row.semantic_capability, row]));
}

function isVerified(record) {
  return Boolean(record)
    && VERIFIED_GRADES.has(record.evidence_grade)
    && VERIFIED_VALIDATION.has(record.validation_status);
}

function compareCapability(previous, current, sameBuild) {
  if (!previous && !current) return { status: 'UNKNOWN', reasons: ['NO_BUILD_RECORD'] };
  if (!current) return { status: 'UNKNOWN', reasons: ['NO_CURRENT_BUILD_RECORD'] };
  if (current.validation_status === 'UNAVAILABLE' || current.evidence_grade === 'UNAVAILABLE') {
    return { status: 'UNSUPPORTED', reasons: ['CURRENT_BUILD_CAPABILITY_UNAVAILABLE'] };
  }
  if (!previous) {
    return { status: 'NEEDS_REVALIDATION', reasons: ['NO_PREVIOUS_CAPABILITY_BASELINE'] };
  }
  if (!isVerified(current)) {
    return {
      status: 'NEEDS_REVALIDATION',
      reasons: [`CURRENT_${current.evidence_grade}_${current.validation_status}`],
    };
  }
  const previousRoute = previous.protocol_route ?? previous.packet_registration_route ?? null;
  const currentRoute = current.protocol_route ?? current.packet_registration_route ?? null;
  if (previousRoute !== currentRoute && previousRoute !== null && currentRoute !== null) {
    return { status: 'ROUTE_MOVED', reasons: [`${previousRoute} -> ${currentRoute}`] };
  }
  if (stableHash(previous.field_mapping ?? {}) !== stableHash(current.field_mapping ?? {})) {
    return { status: 'FIELD_SHIFT', reasons: ['FIELD_MAPPING_CHANGED'] };
  }
  if (previous.evidence_grade !== current.evidence_grade
      || previous.validation_status !== current.validation_status) {
    return { status: 'SEMANTIC_CHANGED', reasons: ['EVIDENCE_OR_VALIDATION_GRADE_CHANGED'] };
  }
  if (!isVerified(previous)) {
    return { status: 'NEEDS_REVALIDATION', reasons: ['PREVIOUS_BASELINE_WAS_NOT_VERIFIED'] };
  }
  return {
    status: 'UNCHANGED_VERIFIED',
    reasons: [sameBuild ? 'EXACT_BUILD_REGRESSION_MATCH' : 'INDEPENDENT_CURRENT_BUILD_VALIDATION_MATCH'],
  };
}

function migrateCapabilities(manifest, previousBuild, currentBuild) {
  if (!manifest?.exact_build_only || manifest.nearest_build_fallback !== 'FORBIDDEN') {
    throw new Error('capability manifest must forbid nearest-build fallback');
  }
  const previous = recordMap(manifest, previousBuild);
  const current = recordMap(manifest, currentBuild);
  const vocabulary = new Set([
    ...(manifest.capability_vocabulary || []),
    ...previous.keys(),
    ...current.keys(),
  ]);
  const rows = [...vocabulary].sort(strictCompare).map((capability) => {
    const before = previous.get(capability) || null;
    const after = current.get(capability) || null;
    return {
      capability,
      ...compareCapability(before, after, previousBuild === currentBuild),
      previous: before ? {
        evidence_grade: before.evidence_grade,
        validation_status: before.validation_status,
        protocol_route: before.protocol_route,
        decoder_version: before.decoder_version,
      } : null,
      current: after ? {
        evidence_grade: after.evidence_grade,
        validation_status: after.validation_status,
        protocol_route: after.protocol_route,
        decoder_version: after.decoder_version,
      } : null,
    };
  });
  const statusCounts = Object.fromEntries(MIGRATION_STATUSES.map((status) => [
    status, rows.filter((row) => row.status === status).length,
  ]));
  if (Object.values(statusCounts).reduce((sum, value) => sum + value, 0) !== rows.length) {
    throw new Error('capability migration conservation failed');
  }
  return { status_counts: statusCounts, capabilities: rows };
}

function registrationSets(map) {
  if (!map) return null;
  const callbackNames = new Set();
  const componentNames = new Set();
  const nameToRoutes = new Map();
  for (const route of map.routes || []) {
    for (const callback of route.callbacks || []) {
      if (callback.name) {
        callbackNames.add(callback.name);
        if (!nameToRoutes.has(callback.name)) nameToRoutes.set(callback.name, new Set());
        nameToRoutes.get(callback.name).add(route.packet_id);
      }
      if (callback.callback_owner_type) componentNames.add(callback.callback_owner_type);
    }
  }
  return { callbackNames, componentNames, nameToRoutes };
}

function diffRegistrationMaps(previousMap, currentMap, previousBuild, currentBuild) {
  if (currentMap && currentMap.build !== currentBuild) {
    throw new Error(`current registration map build ${currentMap.build} != ${currentBuild}`);
  }
  if (previousMap && previousMap.build !== previousBuild) {
    throw new Error(`previous registration map build ${previousMap.build} != ${previousBuild}`);
  }
  const before = registrationSets(previousMap);
  const after = registrationSets(currentMap);
  if (!after) {
    return {
      status: 'NEEDS_REVALIDATION',
      NEW_COMPONENT_DIFF: [],
      NEW_RUNTIME_NAME_DIFF: [],
      ROUTE_DIFF: [],
      blocker: 'CURRENT_RUNTIME_REGISTRATION_MAP_NOT_PROVIDED',
    };
  }
  const newComponents = [...after.componentNames]
    .filter((name) => !before?.componentNames.has(name)).sort(strictCompare);
  const newNames = [...after.callbackNames]
    .filter((name) => !before?.callbackNames.has(name)).sort(strictCompare);
  const moved = before ? [...after.nameToRoutes].flatMap(([name, routes]) => {
    const previousRoutes = before.nameToRoutes.get(name);
    if (!previousRoutes) return [];
    const from = [...previousRoutes].sort((a, b) => a - b);
    const to = [...routes].sort((a, b) => a - b);
    return JSON.stringify(from) === JSON.stringify(to) ? [] : [{ name, previous_routes: from, current_routes: to }];
  }).sort((left, right) => strictCompare(left.name, right.name)) : [];
  return {
    status: before ? 'DIFF_COMPLETE' : 'CURRENT_ONLY_PREVIOUS_MAP_UNAVAILABLE',
    NEW_COMPONENT_DIFF: newComponents,
    NEW_RUNTIME_NAME_DIFF: newNames,
    ROUTE_DIFF: moved,
    current_observed_route_count: currentMap.observed_route_count ?? currentMap.routes?.length ?? 0,
    current_callback_mapping_status_counts: currentMap.status_counts ?? null,
  };
}

function researchQueue(packetDiff, capabilityMigration, registrationDiff, currentRegistrationMap) {
  const queue = [];
  for (const row of packetDiff.routes) {
    if (row.status === 'NEW_PACKET' || row.status === 'PAYLOAD_SHAPE_CHANGED') {
      queue.push({
        kind: row.status,
        key: row.packet_id_hex,
        observed_count: row.current_count,
        priority_score: row.current_count,
        next_evidence: 'EXACT_RUNTIME_REGISTRATION_LAYOUT_AND_SEMANTIC_ANCHOR',
      });
    }
  }
  for (const row of capabilityMigration.capabilities) {
    if (['NEEDS_REVALIDATION', 'UNKNOWN'].includes(row.status)) {
      queue.push({
        kind: 'CAPABILITY', key: row.capability, observed_count: null,
        priority_score: 0, next_evidence: row.reasons.join(';'),
      });
    }
  }
  for (const route of currentRegistrationMap?.routes || []) {
    if (route.callback_mapping_status === 'UNMAPPED_ON_MAKEFUNCTION_CALLBACK_REGISTRATION_SURFACE') {
      queue.push({
        kind: 'UNMAPPED_RUNTIME_ROUTE', key: route.packet_id_hex,
        observed_count: route.observed_count, priority_score: route.observed_count,
        next_evidence: 'ALTERNATE_REGISTRATION_SURFACE_OR_FACTORY_LAYOUT',
      });
    }
  }
  for (const name of registrationDiff.NEW_RUNTIME_NAME_DIFF || []) {
    queue.push({
      kind: 'NEW_RUNTIME_NAME', key: name, observed_count: null,
      priority_score: 1, next_evidence: 'ROUTE_OBSERVATION_AND_FIELD_LAYOUT',
    });
  }
  return queue.sort((left, right) => right.priority_score - left.priority_score
    || strictCompare(left.kind, right.kind) || strictCompare(left.key, right.key));
}

function buildFullSemanticMigration(input) {
  const {
    previous_build: previousBuild,
    current_build: currentBuild,
    previous_inventory: previousInventory,
    current_inventory: currentInventory,
    capability_manifest: capabilityManifest,
    previous_registration_map: previousRegistrationMap = null,
    current_registration_map: currentRegistrationMap = null,
    runtime_attestation: runtimeAttestation,
    replay_samples: replaySamples,
  } = input || {};
  if (!previousBuild || !currentBuild) throw new TypeError('previous_build and current_build are required');
  if (!runtimeAttestation || runtimeAttestation.build !== currentBuild) {
    throw new Error('runtime attestation must be exact-current-build scoped');
  }
  if (!Array.isArray(replaySamples) || replaySamples.length === 0
      || replaySamples.some((sample) => sample.build !== currentBuild)) {
    throw new Error('all explicit Replay samples must match the exact current build');
  }
  const packetDiff = diffPacketInventories(
    previousInventory, currentInventory, previousBuild, currentBuild,
  );
  const capabilityMigration = migrateCapabilities(
    capabilityManifest, previousBuild, currentBuild,
  );
  const registrationDiff = diffRegistrationMaps(
    previousRegistrationMap, currentRegistrationMap, previousBuild, currentBuild,
  );
  const queue = researchQueue(
    packetDiff, capabilityMigration, registrationDiff, currentRegistrationMap,
  );
  return {
    schema: MIGRATION_SCHEMA,
    schema_version: 1,
    exact_build_only: true,
    nearest_build_fallback: 'FORBIDDEN',
    previous_build: previousBuild,
    current_build: currentBuild,
    mode: previousBuild === currentBuild ? 'EXACT_BUILD_REGRESSION_SELF_CHECK' : 'NEW_BUILD_MIGRATION',
    status: runtimeAttestation.status === 'VERIFIED_EXACT_BUILD'
      ? 'MIGRATION_ANALYSIS_COMPLETE' : 'MIGRATION_ANALYSIS_COMPLETE_RUNTIME_NEEDS_REVALIDATION',
    runtime_attestation: runtimeAttestation,
    replay_samples: [...replaySamples].sort((a, b) => strictCompare(a.sha256, b.sha256)),
    packet_inventory_diff: packetDiff,
    capability_migration: capabilityMigration,
    runtime_registration_diff: registrationDiff,
    NEW_PACKET_DIFF: packetDiff.NEW_PACKET_DIFF,
    NEW_COMPONENT_DIFF: registrationDiff.NEW_COMPONENT_DIFF,
    NEW_RUNTIME_NAME_DIFF: registrationDiff.NEW_RUNTIME_NAME_DIFF,
    research_queue: queue,
    regression_requirements: [
      'BUILD_DETECTION', 'CONTAINER_VALIDATION', 'PACKET_INVENTORY_DIFF', 'ROUTE_DIFF',
      'SIZE_LAYOUT_DIFF', 'REGISTRATION_DIFF', 'KNOWN_SEMANTIC_ANCHOR_TESTS',
      'DECODER_REPLAY', 'FIELD_BEHAVIOR_REGRESSION',
    ],
    conservation: {
      packet_routes: packetDiff.conservation.status,
      capability_rows: 'PASS',
      silent_discard: 'FORBIDDEN',
      silent_fallback: 'FORBIDDEN',
    },
  };
}

module.exports = {
  MIGRATION_SCHEMA,
  MIGRATION_STATUSES,
  assertExactInventory,
  buildFullSemanticMigration,
  compareCapability,
  diffPacketInventories,
  diffRegistrationMaps,
  migrateCapabilities,
  payloadShape,
  researchQueue,
  stableHash,
};
