'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { resolveCapability } = require('../src/build_registry');
const { decodeSemanticReplay, getSweeperCapability } = require('../src/semantic_api');
const {
  SWEEPER_CAPABILITY_NAMES,
  SWEEPER_EVENT_KEYS,
  createSweeperCapabilityExport,
  writeSweeperCapabilityManifest,
} = require('../src/sweeper_capability');

test('16.16 Sweeper contract keeps held and activation as separate unavailable boundaries', () => {
  const contract = createSweeperCapabilityExport('16.16.805.0442');
  assert.equal(contract.game_version, '16.16.805.0442');
  assert.equal(contract.patch, '16.16');
  assert.equal(contract.held_activation_relation, 'SWEEPER_HELD_NE_SWEEPER_ACTIVATION');
  assert.equal(contract.capabilities.SWEEPER_HELD.status, 'UNVERIFIED');
  assert.equal(contract.capabilities.SWEEPER_ACTIVATION.status, 'UNAVAILABLE');
  assert.equal(contract.spawned_entity_route_evidence.observation,
    'NO_ORACLE_SWEEPER_LENS_OR_SCANNER_NAME_TOKEN_OBSERVED');
  assert.equal(contract.spawned_entity_route_evidence.limitation,
    'BOUNDED_NEGATIVE_ENTITY_ROUTE_EVIDENCE_NOT_PROTOCOL_NONEXISTENCE_PROOF');
  assert.notEqual(contract.capabilities.SWEEPER_HELD.event_key,
    contract.capabilities.SWEEPER_ACTIVATION.event_key);
  assert.deepEqual(contract.events.sweeper_held_events, []);
  assert.deepEqual(contract.events.sweeper_activation_events, []);
});

test('empty Sweeper events carry explicit status and never claim a zero behavioral count', () => {
  const contract = createSweeperCapabilityExport('16.16.805.0442');
  assert.equal(contract.observation_status, 'NO_VERIFIED_SWEEPER_EVENTS_EMITTED');
  assert.equal(contract.event_count_interpretation, 'EMPTY_EVENT_ARRAY_IS_NOT_A_ZERO_BEHAVIOR_CLAIM');
  assert.deepEqual(Object.keys(contract.events), SWEEPER_EVENT_KEYS);
  for (const name of SWEEPER_CAPABILITY_NAMES) {
    const capability = contract.capabilities[name];
    assert.ok(['UNAVAILABLE', 'PARTIAL', 'UNVERIFIED'].includes(capability.status));
    assert.equal(capability.evidence_grade, capability.status);
    assert.equal(capability.evidence_source, 'docs/SWEEPER_CAPABILITY_V1.md');
    assert.equal(capability.game_version, '16.16.805.0442');
  }
});

test('registry and public semantic API bind Sweeper capability to exact 16.16 only', () => {
  const held = resolveCapability('16.16.805.0442', 'sweeper_held');
  assert.equal(held.status, 'UNVERIFIED');
  assert.equal(held.capability_profile.enabled, false);
  assert.equal(held.capability_profile.replay_version, '16.16.805.0442');

  const oldBuild = createSweeperCapabilityExport('16.15.801.3452');
  assert.equal(oldBuild.status, 'UNSUPPORTED_VERSION');
  assert.equal(oldBuild.capabilities.SWEEPER_HELD.status, 'UNSUPPORTED_VERSION');
  assert.equal(oldBuild.capabilities.SWEEPER_ACTIVATION.status, 'UNSUPPORTED_VERSION');
  assert.equal(oldBuild.capabilities.SWEEPER_HELD.build_binding, 'NO_CROSS_BUILD_INFERENCE');

  const decoded = decodeSemanticReplay({ header: { version: '16.16.805.0442' } }, {
    profileResolutionOnly: true,
  });
  assert.equal(getSweeperCapability(decoded).capabilities.SWEEPER_HELD.status, 'UNVERIFIED');
  assert.deepEqual(decoded.sweeper_capability.events.sweeper_activation_events, []);
});

test('stable Sweeper manifest generator writes a deterministic machine-readable boundary', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-sweeper-capability-'));
  const manifestPath = path.join(directory, 'sweeper-capability.json');
  try {
    assert.equal(writeSweeperCapabilityManifest(manifestPath), manifestPath);
    const first = fs.readFileSync(manifestPath, 'utf8');
    writeSweeperCapabilityManifest(manifestPath);
    const second = fs.readFileSync(manifestPath, 'utf8');
    assert.equal(second, first);
    const manifest = JSON.parse(first);
    assert.equal(manifest.contract_id, 'rofl-16.16.805.0442-sweeper-capability-v1');
    assert.equal(manifest.capabilities.SWEEPER_ACTIVATION.status, 'UNAVAILABLE');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
