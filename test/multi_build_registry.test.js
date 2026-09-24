'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { baseEvent } = require('../src/events');
const { levelMapping } = require('../src/level_transition');
const {
  BUILD_PROFILES,
  ROLLING_COMPATIBILITY_WINDOW,
  resolveBuildProfile,
  resolveCapability,
  rollingCompatibilityWindow,
} = require('../src/build_registry');
const {
  decodeSemanticReplay,
  getHeroDamage,
  getHeroDeaths,
  getHeroPaths,
  getHeroStates,
  getLevelTransitions,
  getWardSpawns,
  levelTransitionFromRuntimeRow,
  queryWardEvents,
  queryWardLifecycles,
  queryWardSpawns,
  withBuildMetadata,
} = require('../src/semantic_api');

test('build registry keeps three exact profiles in a three-build rolling window', () => {
  assert.equal(ROLLING_COMPATIBILITY_WINDOW, 3);
  assert.deepEqual(Object.keys(BUILD_PROFILES), [
    '16.15.801.3452', '16.16.805.0442', '16.19.820.7193',
  ]);
  assert.equal(BUILD_PROFILES['16.15.801.3452'].support_level, 'FULL_PLATFORM_READY');
  assert.equal(BUILD_PROFILES['16.16.805.0442'].support_level, 'DEEP_SEMANTIC_READY');
  assert.equal(BUILD_PROFILES['16.19.820.7193'].release_status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(BUILD_PROFILES['16.16.805.0442'].downstream_release_gate,
    'RELEASE_16_16_EXACT_BUILD_DEEP_SEMANTICS');
  assert.deepEqual(rollingCompatibilityWindow(), [
    {
      position: 'CURRENT',
      game_version: '16.19.820.7193',
      support_level: 'CORE_READY',
      release_status: 'EXPERIMENTAL_CANDIDATE',
    },
    {
      position: 'CURRENT-1',
      game_version: '16.16.805.0442',
      support_level: 'DEEP_SEMANTIC_READY',
      release_status: 'SUPPORTED_VERIFIED_DEEP_SEMANTICS_PARTIAL',
    },
    {
      position: 'CURRENT-2',
      game_version: '16.15.801.3452',
      support_level: 'FULL_PLATFORM_READY',
      release_status: 'SUPPORTED',
    },
  ]);
});

test('profile resolution is exact and never chooses a neighbouring build', () => {
  assert.equal(resolveBuildProfile({ header: { version: '16.16.805.0442' } }).profile.patch,
    '16.16');
  assert.deepEqual(resolveBuildProfile('16.17.0.0'), {
    status: 'UNSUPPORTED_VERSION',
    game_version: '16.17.0.0',
    profile: null,
  });
  const ward = resolveCapability('16.16.805.0442', 'ward_spawn');
  assert.equal(ward.status, 'SEMANTIC_VERIFIED_DERIVED');
  assert.equal(ward.capability_profile.enabled, true);
  assert.equal(ward.capability_profile.replay_block_packet_id, 0x049a);
  const faceDirection = resolveCapability('16.16.805.0442', 'face_direction_vector');
  assert.equal(faceDirection.status, 'SEMANTIC_VERIFIED_DIRECT');
  assert.equal(faceDirection.capability_profile.replay_block_packet_id, 0x01ab);
  assert.equal(faceDirection.capability_profile.runtime_type_name, 'PKT_S2C_FaceDirection_s');
  assert.equal(resolveCapability('16.15.801.3452', 'face_direction_vector').status,
    'UNAVAILABLE');
});

test('16.16 level-after mapping is build-bound and independently calibrated', () => {
  assert.equal(levelMapping(242, '16.16.805.0442').level_after, 2);
  assert.equal(levelMapping(194, '16.16.805.0442').level_after, 3);
  assert.equal(levelMapping(210, '16.16.805.0442').level_after, 4);
  assert.equal(levelMapping(224, '16.15.801.3452').level_after, 2);
  assert.equal(levelMapping(242, '16.15.801.3452').level_after, null);
  assert.equal(levelMapping(242, '16.17.0.0').evidence, 'UNSUPPORTED_VERSION');
});

test('16.16 public level event distinguishes direct transition fields from derived LevelAfter', () => {
  const event = levelTransitionFromRuntimeRow({
    build_profile: 'rofl-16.16.805.0442-level-transition-unicorn-v1',
    replay_sha256: 'a'.repeat(64),
    replay_time_ms: 1234,
    entity_network_id: 0x400000ae,
    participant_id: 1,
    raw_field_10: 242,
    raw_field_11: 68,
    packet_id: 0x0314,
    chunk_index: 3,
    decompressed_block_offset: 77,
    payload_length: 2,
    raw_param: 0x400000ae,
    raw_payload_sha256: 'b'.repeat(64),
  }, BUILD_PROFILES['16.16.805.0442']);
  assert.equal(event.confidence, 'VERIFIED_DERIVED');
  assert.equal(event.semantic_status, 'SEMANTIC_VERIFIED_DERIVED_BUILD_BOUND');
  assert.equal(event.transition_evidence, 'VERIFIED_DIRECT');
  assert.equal(event.level_after, 2);
  assert.equal(event.level_mapping_evidence, 'VERIFIED_DERIVED');
  assert.equal(event.field_confidence.raw_field_10, 'VERIFIED_DIRECT');
  assert.equal(event.field_confidence.level_after, 'VERIFIED_DERIVED_BUILD_BOUND');

  const unmapped = levelTransitionFromRuntimeRow({
    build_profile: event.build_profile,
    replay_sha256: 'a'.repeat(64),
    replay_time_ms: 0,
    entity_network_id: 0x400000ae,
    participant_id: 1,
    raw_field_10: 226,
    raw_field_11: 69,
    packet_id: 0x0314,
    chunk_index: 0,
    decompressed_block_offset: 1,
    payload_length: 1,
    raw_param: 0x400000ae,
    raw_payload_sha256: 'c'.repeat(64),
  }, BUILD_PROFILES['16.16.805.0442']);
  assert.equal(unmapped.confidence, 'PARTIAL');
  assert.equal(unmapped.level_after, null);
  assert.equal(unmapped.field_confidence.level_after, 'UNAVAILABLE');
  assert.equal(unmapped.is_initialization, true);
});

test('public semantic events carry build metadata and selectors hide packet routes', () => {
  const empty = baseEvent('damage');
  assert.equal(empty.game_version, null);
  assert.equal(empty.patch, null);
  assert.equal(empty.build_profile, null);
  const profile = BUILD_PROFILES['16.16.805.0442'];
  const decorated = withBuildMetadata(empty, profile);
  assert.equal(decorated.game_version, '16.16.805.0442');
  assert.equal(decorated.patch, '16.16');
  assert.match(decorated.build_profile, /^rofl-/);

  const result = {
    events: {
      hero_path_events: [{ id: 1 }],
      level_transition_events: [{ id: 2 }],
      ward_events: [{ id: 3 }],
      damage_events: [{ id: 4 }],
      death_events: [{ id: 5 }],
      hero_state_events: [{ id: 6 }],
    },
  };
  assert.deepEqual(getHeroPaths(result), [{ id: 1 }]);
  assert.deepEqual(getLevelTransitions(result), [{ id: 2 }]);
  assert.deepEqual(getWardSpawns(result), [{ id: 3 }]);
  assert.deepEqual(getHeroDamage(result), [{ id: 4 }]);
  assert.deepEqual(getHeroDeaths(result), [{ id: 5 }]);
  assert.deepEqual(getHeroStates(result), [{ id: 6 }]);
});

test('Ward selectors expose spawn, special, and lifecycle rows without packet knowledge', () => {
  const decoded = { events: {
    ward_events: [{ id: 'confirmed', timestamp_ms: 100, owner_participant: 1,
      owner_team: 100, ward_type: 'CONTROL_WARD', ward_network_id: 7,
      vision_entity_class: 'PLAYER_ACTIVE_WARD_CONFIRMED', player_active_ward_confirmed: true }],
    ward_spawn_events: [
      { id: 'confirmed', timestamp_ms: 100, owner_participant: 1, owner_team: 100,
        ward_type: 'CONTROL_WARD', ward_network_id: 7,
        vision_entity_class: 'PLAYER_ACTIVE_WARD_CONFIRMED', player_active_ward_confirmed: true },
      { id: 'special', timestamp_ms: 200, owner_participant: null, owner_team: null,
        ward_type: 'UNKNOWN_WARD_TYPE', ward_network_id: 8,
        vision_entity_class: 'MAP_MECHANIC_VISION', player_active_ward_confirmed: false },
    ],
    vision_entity_events: [
      { id: 'confirmed', timestamp_ms: 100, owner_participant: 1, owner_team: 100,
        ward_type: 'CONTROL_WARD', ward_network_id: 7,
        vision_entity_class: 'PLAYER_ACTIVE_WARD_CONFIRMED', player_active_ward_confirmed: true },
      { id: 'special', timestamp_ms: 200, owner_participant: null, owner_team: null,
        ward_type: 'UNKNOWN_WARD_TYPE', ward_network_id: 8,
        vision_entity_class: 'MAP_MECHANIC_VISION', player_active_ward_confirmed: false },
    ],
    ward_lifecycle_events: [
      { ward_network_id: 7, spawn_time_ms: 100, owner_participant: 1, owner_team: 100 },
    ],
  } };
  assert.deepEqual(queryWardEvents(decoded).map((row) => row.id), ['confirmed', 'special']);
  assert.deepEqual(queryWardSpawns(decoded, { team_id: 100 }).map((row) => row.id), ['confirmed']);
  assert.deepEqual(queryWardSpawns(decoded, { vision_entity_class: 'MAP_MECHANIC_VISION' })
    .map((row) => row.id), ['special']);
  assert.equal(queryWardSpawns(decoded, { player_active_only: true }).length, 1);
  assert.equal(queryWardLifecycles(decoded, { ward_network_id: 7 }).length, 1);
  assert.deepEqual(queryWardLifecycles({ events: {} }), []);
  assert.equal(decoded.events.ward_spawn_events.length, 2);
});

test('automatic semantic entry point rejects unsupported builds without fallback', () => {
  const result = decodeSemanticReplay({ header: { version: '16.17.0.0' } }, {
    profileResolutionOnly: true,
  });
  assert.equal(result.status, 'UNSUPPORTED_VERSION');
  assert.equal(result.profile, null);
  assert.equal(result.events, null);
});
