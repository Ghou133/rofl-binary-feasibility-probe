const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { ENTITY_EVENT_TYPES, GenericEntityRegistry, writeEntityRegistry } = require('../src/generic_entity_registry');
const { buildEntityRegistry } = require('../scripts/build_entity_registry');

test('registry preserves an unknown raw entity, aliases, direct fields, and provenance without classifying it', () => {
  const registry = new GenericEntityRegistry();
  const event = registry.ingest({
    event_type: 'route_entity_spawn', entity_network_id: 42, network_ids: [42, 420],
    owner_network_id: 7, owner_team: 200, replay_time_ms: 1200,
    generic_name: 'UncataloguedThing', entity_name: 'UnknownUnit',
    position: { x: 1, height: 2, y: 3 }, game_version: '16.16.805.0442',
    confidence: 'VERIFIED_DIRECT', raw_packet_ref: { packet_id: 1178, raw_payload_sha256: 'abc' },
  });
  const entity = registry.get(420);
  assert.equal(event.event_type, 'ENTITY_SPAWN');
  assert.equal(entity.entity_type, 'UNKNOWN_ENTITY');
  assert.deepEqual(entity.network_ids, [42, 420]);
  assert.equal(entity.owner_network_id, 7);
  assert.equal(entity.team_id, 200);
  assert.equal(entity.spawn_time_ms, 1200);
  assert.deepEqual(entity.positions, [{ replay_time_ms: 1200, x: 1, y: 3, z: null, height: 2 }]);
  assert.deepEqual(entity.names, ['UncataloguedThing', 'UnknownUnit']);
  assert.equal(entity.evidence[0].raw_packet_ref.packet_id, 1178);
});

test('registry gives lifecycle records canonical events and keeps death, destroy, and despawn distinct', () => {
  const registry = new GenericEntityRegistry();
  const scope = { replay_sha256: 'synthetic-replay', game_version: 'synthetic-build' };
  registry.ingest({ ...scope, event_type: 'entity_spawn', entity_id: 'x', replay_time_ms: 10, entity_type: 'SUPPLIED_TYPE' });
  registry.ingest({ ...scope, event_type: 'entity_update', entity_id: 'x', replay_time_ms: 20, x: 5, y: 6 });
  registry.ingest({ ...scope, event_type: 'entity_death', entity_id: 'x', replay_time_ms: 30 });
  registry.ingest({ ...scope, event_type: 'entity_destroy', entity_id: 'x', replay_time_ms: 40 });
  registry.ingest({ ...scope, event_type: 'entity_despawn', entity_id: 'x', replay_time_ms: 50 });
  const entity = registry.get('x', scope);
  assert.deepEqual(ENTITY_EVENT_TYPES, ['ENTITY_SPAWN', 'ENTITY_UPDATE', 'ENTITY_DEATH', 'ENTITY_DESTROY', 'ENTITY_DESPAWN']);
  assert.equal(entity.entity_type, 'SUPPLIED_TYPE');
  assert.equal(entity.last_update_time_ms, 20);
  assert.equal(entity.death_time_ms, 30);
  assert.equal(entity.destroy_time_ms, 40);
  assert.equal(entity.despawn_time_ms, 50);
  assert.deepEqual(registry.query({ entity_id: 'x', ...scope }).map((event) => event.event_type), ENTITY_EVENT_TYPES);
});

test('registry accepts an existing semantic death victim identifier without treating its killer as an alias', () => {
  const registry = new GenericEntityRegistry();
  registry.ingest({ event_type: 'death', victim_network_id: 11, killer_network_id: 22, replay_time_ms: 88 });
  assert.equal(registry.get(11).death_time_ms, 88);
  assert.equal(registry.get(22), null);
});

test('registry rejects records without an entity identifier or a canonicalizable lifecycle event', () => {
  const registry = new GenericEntityRegistry();
  assert.throws(() => registry.ingest({ event_type: 'entity_spawn' }), /requires entity_id/);
  assert.throws(() => registry.ingest({ event_type: 'unrelated_event', entity_id: 1 }), /Unsupported entity lifecycle/);
});

test('registry event IDs stay distinct for separate same-timestamp observations', () => {
  const registry = new GenericEntityRegistry();
  const scope = { replay_sha256: 'same-time-replay', game_version: 'synthetic-build' };
  registry.ingest({ ...scope, event_type: 'entity_update', entity_id: 1, replay_time_ms: 5, x: 10, y: 10 });
  registry.ingest({ ...scope, event_type: 'entity_update', entity_id: 1, replay_time_ms: 5, x: 11, y: 10 });
  const events = registry.query({ entity_id: 1, ...scope });
  assert.notEqual(events[0].event_id, events[1].event_id);
});

test('identical numeric network IDs stay isolated across replay SHA and exact build scopes', () => {
  const registry = new GenericEntityRegistry();
  const replayA = { replay_sha256: 'replay-a', game_version: '16.15.801.3452' };
  const replayB = { replay_sha256: 'replay-b', game_version: '16.15.801.3452' };
  const buildB = { replay_sha256: 'replay-a', game_version: '16.16.805.0442' };
  const eventA = registry.ingest({ ...replayA, event_type: 'route_entity_spawn', entity_network_id: 99, network_ids: [99, 199], replay_time_ms: 1 });
  const eventB = registry.ingest({ ...replayB, event_type: 'route_entity_spawn', entity_network_id: 99, network_ids: [99, 299], replay_time_ms: 1 });
  const eventBuildB = registry.ingest({ ...buildB, event_type: 'route_entity_spawn', entity_network_id: 99, replay_time_ms: 1 });
  assert.equal(registry.toJSON().entity_count, 3);
  assert.equal(registry.get(99), null);
  assert.equal(registry.get(199, replayA).entity_id, 99);
  assert.equal(registry.get(299, replayB).entity_id, 99);
  assert.equal(registry.get(99, buildB).exact_build, '16.16.805.0442');
  assert.notEqual(eventA.event_id, eventB.event_id);
  assert.notEqual(eventA.event_id, eventBuildB.event_id);
  assert.equal(registry.query({ entity_id: 99, ...replayA }).length, 1);
  assert.equal(registry.query({ entity_id: 99 }).length, 0);
  assert.equal(registry.get(99, { replay_sha256: 'replay-a' }), null);
  assert.deepEqual(registry.query({ replay_sha256: 'replay-a' }), []);
});

test('missing replay or build provenance isolates matching numeric IDs instead of merging them', () => {
  const registry = new GenericEntityRegistry();
  registry.ingest({ event_type: 'route_entity_spawn', entity_network_id: 7, replay_time_ms: 1 });
  registry.ingest({ event_type: 'route_entity_spawn', entity_network_id: 7, replay_time_ms: 2 });
  assert.equal(registry.toJSON().entity_count, 2);
  assert.equal(registry.get(7), null);
  assert.equal(registry.toJSON().entities.every((entity) => entity.provenance_status === 'UNVERIFIED_PROVENANCE_ISOLATED'), true);
});

test('writer and builder produce deterministic bounded JSON from semantic JSONL', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'generic-entity-registry-'));
  const input = path.join(directory, 'entities.jsonl');
  const output = path.join(directory, 'registry.json');
  fs.writeFileSync(input, [
    JSON.stringify({ event_type: 'route_entity_spawn', entity_network_id: 3, replay_time_ms: 2 }),
    JSON.stringify({ event_type: 'route_entity_spawn', entity_network_id: 2, replay_time_ms: 1 }),
  ].join('\n'));
  const registry = buildEntityRegistry([input], { limit: 1 });
  writeEntityRegistry(output, registry);
  const document = JSON.parse(fs.readFileSync(output, 'utf8'));
  assert.equal(document.entity_count, 1);
  assert.equal(document.events[0].entity_id, 3);
  assert.ok(fs.readFileSync(output, 'utf8').endsWith('\n'));
});
