'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  STATE_UPDATE,
  VERIFIED_DERIVED_STATE,
  SemanticStateEngine,
  stateUpdateFromGroundTruthFrame,
} = require('../src/semantic_state_engine');

const REPLAY_SHA = 'a'.repeat(64);
const OTHER_REPLAY_SHA = 'b'.repeat(64);
const BUILD = '16.16.805.0442';
const OTHER_BUILD = '16.15.801.3452';
const SCOPE = Object.freeze({ replay_sha256: REPLAY_SHA, exact_build: BUILD });

function directState(fields = {}) {
  return {
    ...SCOPE,
    event_type: STATE_UPDATE,
    replay_time_ms: 1000,
    entity: { participant_id: 2, champion: 'Talon', team_id: 100 },
    participant_id: 2,
    state: fields,
    evidence_grade: 'VERIFIED_DIRECT',
  };
}

test('engine and every record are fail-closed to one exact Replay SHA and build', () => {
  assert.throws(
    () => new SemanticStateEngine({ replay_sha256: 'not-a-sha', exact_build: BUILD }),
    /64-character Replay SHA-256/,
  );
  assert.throws(
    () => new SemanticStateEngine({ replay_sha256: REPLAY_SHA, exact_build: '16.16' }),
    /four-component Replay build/,
  );

  const engine = new SemanticStateEngine(SCOPE);
  assert.throws(
    () => engine.ingestEvent({ event_type: 'damage', replay_time_ms: 1 }),
    /missing exact replay_sha256/,
  );
  assert.throws(
    () => engine.ingestEvent({ ...SCOPE, replay_sha256: OTHER_REPLAY_SHA, event_type: 'damage' }),
    /does not match engine scope/,
  );
  assert.throws(
    () => engine.ingestEvent({ ...SCOPE, exact_build: OTHER_BUILD, event_type: 'damage' }),
    /does not match engine scope/,
  );
  assert.throws(() => engine.queryTimeline({ exact_build: OTHER_BUILD }), /does not match engine scope/);

  assert.throws(() => engine.ingestEvent({
    ...SCOPE,
    event_type: 'damage',
    raw_packet_ref: { replay_sha256: OTHER_REPLAY_SHA },
  }), /conflicting replay_sha256/);
});

test('stateAt carries only observed fields, retains explicit null, and keeps per-field provenance', () => {
  const engine = new SemanticStateEngine(SCOPE);
  engine.ingestStateUpdate({
    ...directState({ current_hp: 500, max_hp: 1000, magic_resist: null }),
    field_evidence: {
      current_hp: { evidence_grade: 'VERIFIED_DIRECT', json_path: '$.stats.health' },
      max_hp: 'VERIFIED_DIRECT',
      magic_resist: 'VERIFIED_DIRECT',
    },
    raw_packet_ref: {
      replay_sha256: REPLAY_SHA,
      exact_build: BUILD,
      packet_id: 12,
      payload_sha256: 'payload-one',
    },
  });
  engine.ingestStateUpdate({
    ...directState({ current_hp: 450 }),
    replay_time_ms: 2000,
    state_update_id: 'hp-two',
    source: { decoder: 'synthetic-direct-state' },
  });

  assert.equal(engine.stateAt(999).entity_count, 0);
  const snapshot = engine.stateAt(2500);
  assert.equal(snapshot.entity_count, 1);
  const state = snapshot.entities[0];
  assert.deepEqual(state.observed_fields, ['current_hp', 'magic_resist', 'max_hp']);
  assert.deepEqual(state.values, { current_hp: 450, magic_resist: null, max_hp: 1000 });
  assert.equal(hasOwn(state.values, 'armor'), false);
  assert.equal(state.fields.current_hp.observed_at_ms, 2000);
  assert.equal(state.fields.current_hp.state_event_type, STATE_UPDATE);
  assert.equal(state.fields.current_hp.provenance.source_record_id, 'hp-two');
  assert.deepEqual(state.fields.current_hp.provenance.record_evidence.source, {
    decoder: 'synthetic-direct-state',
  });
  assert.equal(state.fields.max_hp.observed_at_ms, 1000);
  assert.equal(state.fields.max_hp.provenance.record_evidence.raw_packet_ref.packet_id, 12);
  assert.equal(state.fields.magic_resist.value, null);
  assert.notEqual(state.fields.magic_resist.value, 0);
});

test('direct and verified-derived state records cannot silently impersonate one another', () => {
  const engine = new SemanticStateEngine(SCOPE);
  assert.throws(() => engine.ingestStateUpdate({
    ...directState({ current_hp: 100 }),
    evidence_grade: 'VERIFIED_DERIVED',
  }), /requires explicit direct evidence/);
  assert.throws(() => engine.ingestStateUpdate({
    ...directState({ current_hp: 80 }),
    event_type: VERIFIED_DERIVED_STATE,
    evidence_grade: 'VERIFIED_DIRECT',
  }), /requires VERIFIED_DERIVED evidence/);

  engine.ingest(directState({ current_hp: 100 }));
  engine.ingest({
    ...SCOPE,
    event_type: VERIFIED_DERIVED_STATE,
    replay_time_ms: 1500,
    participant_id: 2,
    state: {
      current_hp: {
        value: 80,
        evidence_grade: 'VERIFIED_DERIVED',
        provenance: { formula: 'previous_hp - observed_damage' },
      },
    },
    evidence_grade: 'VERIFIED_DERIVED',
    source_record_id: 'derived-hp',
  });
  const field = engine.stateAt(1500).entities[0].fields.current_hp;
  assert.equal(field.value, 80);
  assert.equal(field.state_event_type, VERIFIED_DERIVED_STATE);
  assert.equal(field.evidence_grade, 'VERIFIED_DERIVED');
  assert.deepEqual(field.provenance.field_provenance, {
    formula: 'previous_hp - observed_damage',
  });
});

test('unknown canonical events and their raw references remain lossless in the timeline', () => {
  const engine = new SemanticStateEngine(SCOPE);
  const unknown = {
    ...SCOPE,
    event_type: 'opaque_future_event',
    replay_time_ms: null,
    evidence_grade: 'UNVERIFIED',
    unknown_payload: { zero: 0, absent_meaning: null, bytes_hex: '00ff' },
    raw_packet_ref: {
      replay_sha256: REPLAY_SHA,
      exact_build: BUILD,
      packet_id: 999,
      payload_sha256: 'opaque-payload',
    },
  };
  const ingested = engine.ingestEvent(unknown);
  assert.equal(ingested.canonical_event_type, 'UNKNOWN');
  assert.equal(ingested.source_event_type, 'opaque_future_event');
  assert.deepEqual(ingested.original_record, unknown);
  assert.deepEqual(ingested.evidence.raw_packet_ref, unknown.raw_packet_ref);
  assert.equal(engine.queryTimeline().length, 1);
  assert.equal(engine.queryTimeline({ from_ms: 0 }).length, 0);
  assert.equal(engine.toJSON().unknown_event_count, 1);
});

test('combat timeline selects combat events and observed combat state without dropping domain-tagged unknowns', () => {
  const engine = new SemanticStateEngine(SCOPE);
  engine.ingestEvent({
    ...SCOPE,
    event_type: 'damage',
    replay_time_ms: 1000,
    source_network_id: 10,
    target_network_id: 20,
    target_participant_id: 2,
    amount: 25,
    evidence_grade: 'VERIFIED_DIRECT',
  });
  engine.ingestEvent({
    ...SCOPE,
    event_type: 'position',
    replay_time_ms: 1100,
    network_id: 20,
    x: 1,
    y: 2,
    evidence_grade: 'VERIFIED_DERIVED',
  });
  engine.ingestEvent({
    ...SCOPE,
    event_type: 'opaque_combat_row',
    semantic_domain: 'combat',
    replay_time_ms: 1200,
    participant_id: 2,
    raw_packet_ref: { replay_sha256: REPLAY_SHA, exact_build: BUILD, packet_id: 777 },
  });
  engine.ingest({ ...directState({ current_hp: 475 }), replay_time_ms: 1300 });
  engine.ingest({ ...directState({ x: 10, y: 20 }), replay_time_ms: 1400 });

  const combat = engine.queryCombatTimeline({ participant_id: 2 });
  assert.deepEqual(combat.map((entry) => entry.canonical_event_type), [
    'DAMAGE', 'UNKNOWN', STATE_UPDATE,
  ]);
  assert.equal(combat[1].evidence.raw_packet_ref.packet_id, 777);
  assert.deepEqual(
    engine.queryCombatTimeline({ participant_id: 2, include_state_updates: false })
      .map((entry) => entry.canonical_event_type),
    ['DAMAGE', 'UNKNOWN'],
  );
  assert.deepEqual(
    engine.queryCombatTimeline({ participant_id: 2, from_ms: 1050, to_ms: 1250 })
      .map((entry) => entry.canonical_event_type),
    ['UNKNOWN'],
  );
});

test('exact HeroReincarnateAlive events enter the canonical combat timeline as RESPAWN occurrences', () => {
  const engine = new SemanticStateEngine(SCOPE);
  const ingested = engine.ingestEvent({
    ...SCOPE,
    event_type: 'HERO_REINCARNATE_ALIVE',
    replay_time_ms: 250195,
    participant_id: 2,
    subject_network_id: 0x400000af,
    lifecycle_operation: 'REINCARNATE_ALIVE',
    position: { x: 394, y: 0, z: 461 },
    evidence_grade: 'VERIFIED_DIRECT',
  });
  assert.equal(ingested.canonical_event_type, 'RESPAWN');
  const combat = engine.queryCombatTimeline({ participant_id: 2 });
  assert.equal(combat.length, 1);
  assert.equal(combat[0].canonical_event_type, 'RESPAWN');
  assert.equal(combat[0].original_record.replay_time_ms, 250195);
});

test('canonical EntityLifecycle reincarnate records retain participant filtering', () => {
  const engine = new SemanticStateEngine(SCOPE);
  engine.ingestEvent({
    ...SCOPE,
    semantic_type: 'EntityLifecycle',
    replay_time_ms: 250195,
    fields: {
      entity_id: 0x400000af,
      participant_id: 2,
      lifecycle_operation: 'REINCARNATE_ALIVE',
      position: { x: 394, y: 0, z: 461 },
    },
    evidence: { status: 'VERIFIED_DIRECT' },
  });
  assert.equal(engine.queryCombatTimeline({ participant_id: 2 }).length, 1);
  assert.equal(engine.queryCombatTimeline({ participant_id: 3 }).length, 0);
  assert.equal(engine.queryCombatTimeline({ participant_id: 2 })[0].canonical_event_type, 'RESPAWN');
});

test('same-timestamp updates retain input order and the latest observation wins without coercion', () => {
  const engine = new SemanticStateEngine(SCOPE);
  const first = engine.ingest({ ...directState({ current_hp: 100 }), replay_time_ms: 500 });
  const second = engine.ingest({ ...directState({ current_hp: null }), replay_time_ms: 500 });
  assert.notEqual(first.timeline_id, second.timeline_id);
  const field = engine.stateAt(500).entities[0].fields.current_hp;
  assert.equal(field.value, null);
  assert.equal(field.source_timeline_id, second.timeline_id);
});

test('DETAILS P0 ground-truth frames adapt to direct state while retaining JSON-path evidence', () => {
  const engine = new SemanticStateEngine(SCOPE);
  const update = stateUpdateFromGroundTruthFrame({
    schema_version: 'DETAILS_P0_GROUND_TRUTH_V1',
    anchor_type: 'GROUND_TRUTH_FRAME_SNAPSHOT',
    anchor_id: 'game:60000:2:p0',
    semantic_scope: 'P0_HERO_COMBAT_STATE',
    replay_sha256: REPLAY_SHA,
    replay_build: BUILD,
    timestamp_ms: 60000,
    entity: { id_kind: 'DETAILS_PARTICIPANT_ID', participant_id: 2, champion: 'Talon', team_id: 100 },
    participant_id: 2,
    champion: 'Talon',
    level: 6,
    current_hp: null,
    max_hp: 883,
    armor: 36,
    magic_resist: 39,
    health_state: null,
    frame_boundary_evidence: { health_transition: 'UNKNOWN' },
    source: {
      fact_source: 'LCU_SGP_MATCH_DETAILS_PARTICIPANT_FRAME',
      field_json_paths: { current_hp: '$.json.frames[1].participantFrames["2"].championStats.health' },
      field_keys: { current_hp: 'health' },
    },
  });
  engine.ingest(update);
  const state = engine.stateAt(60000).entities[0];
  assert.equal(state.values.current_hp, null);
  assert.equal(state.fields.current_hp.evidence_grade, 'GROUND_TRUTH_FRAME_SNAPSHOT');
  assert.equal(
    state.fields.current_hp.provenance.field_evidence.json_path,
    '$.json.frames[1].participantFrames["2"].championStats.health',
  );
  assert.equal(state.fields.current_hp.provenance.source_record_id, 'game:60000:2:p0');
  assert.deepEqual(update.upstream_anchor.frame_boundary_evidence, { health_transition: 'UNKNOWN' });
});

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}
