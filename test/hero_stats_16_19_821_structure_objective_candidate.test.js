'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const {
  PROFILES, assessHeroDamageSnapshotTail821, decodeHeroDamageSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_damage_float_candidate');
const { decodeSemanticReplay } = require('../src/semantic_api');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'hero_structure_objective_damage_snapshot';
const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));

function writeFloat(payload, offset, value) {
  const bytes = Buffer.alloc(4);
  bytes.writeFloatLE(value);
  for (let i = 0; i < 4; i += 1) {
    payload[1262 - offset - i] = ENCODE.get(bytes[i]);
  }
}

function packet(participant, building, objective, timeMs, change = null) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  writeFloat(payload, 0x210, building);
  writeFloat(payload, 0x214, building);
  writeFloat(payload, 0x218, objective);
  if (change) change(payload);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participant, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, change = null, buildingTail = 105,
  turretTail = 105, objectiveTail = 145 } = {}) {
  const replay = replayFromChunks(Array.from({ length: 2 }, (_, frame) => ({
    stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) => packet(index + 1,
      frame && index === 0 ? 100.5 : 0,
      frame && index === 0 ? 140.75 : 0,
      frame * 1000,
      frame && index === 0 ? change : null))),
  })), version);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    TOTAL_DAMAGE_DEALT_TO_BUILDINGS: index === 0 ? String(buildingTail) : '0',
    TOTAL_DAMAGE_DEALT_TO_TURRETS: index === 0 ? String(turretTail) : '0',
    TOTAL_DAMAGE_DEALT_TO_OBJECTIVES: index === 0 ? String(objectiveTail) : '0',
  }));
  return replay;
}

test('821 structure/objective candidate exposes bounded f32 snapshots and mirror evidence', () => {
  const replay = fixture();
  assert.equal(PROFILES[CAPABILITY].replay_version, BUILD);
  assert.equal(assessHeroDamageSnapshotTail821(replay, CAPABILITY).status, 'PASS');
  const output = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  const result = output.capability_results[CAPABILITY];
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 20);
  assert.equal(result.total_unobserved_tail_gap_by_field.TOTAL_DAMAGE_DEALT_TO_BUILDINGS, 5);
  assert.equal(result.total_unobserved_tail_gap_by_field.TOTAL_DAMAGE_DEALT_TO_OBJECTIVES, 5);
  const event = output.events.hero_structure_objective_damage_snapshot_candidates[10];
  assert.equal(event.building_or_turret_damage_raw_f32_candidate, 100.5);
  assert.equal(event.structure_damage_mirror_raw_f32_candidate, 100.5);
  assert.equal(event.objective_damage_raw_f32_candidate, 140.75);
  assert.equal(event.raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(event.confidence, 'CANDIDATE');
});

test('821 structure/objective candidate keeps the building/turret ambiguity fail closed', () => {
  const divergentTail = decodeHeroDamageSnapshotCandidates821(
    fixture({ turretTail: 106 }), CAPABILITY);
  assert.equal(divergentTail.status, 'UNSUPPORTED');
  assert.match(divergentTail.error, /BUILDINGS and TURRETS differ/);

  const missingTail = fixture();
  delete missingTail.tail.stats[0].TOTAL_DAMAGE_DEALT_TO_TURRETS;
  assert.equal(decodeHeroDamageSnapshotCandidates821(missingTail, CAPABILITY).status,
    'MISSING_INPUT');

  const mismatchedMirror = decodeHeroDamageSnapshotCandidates821(fixture({
    change(payload) { writeFloat(payload, 0x214, 99); },
  }), CAPABILITY);
  assert.equal(mismatchedMirror.status, 'DECODE_FAILED');
  assert.match(mismatchedMirror.error, /structure f32 mirror differs/);
});

test('821 structure/objective candidate rejects wrong build, above-tail and mutated Replay', () => {
  assert.equal(decodeHeroDamageSnapshotCandidates821(
    fixture({ version: '16.19.820.7193' }), CAPABILITY).status, 'UNSUPPORTED');
  const above = decodeHeroDamageSnapshotCandidates821(
    fixture({ objectiveTail: 139 }), CAPABILITY);
  assert.equal(above.status, 'DECODE_FAILED');
  assert.match(above.error, /exceeds Replay tail TOTAL_DAMAGE_DEALT_TO_OBJECTIVES/);
  const mutated = fixture();
  mutated.buffer[mutated.chunks[0].body_offset + 15 + 800] ^= 1;
  assert.equal(decodeHeroDamageSnapshotCandidates821(mutated, CAPABILITY).status,
    'DECODE_FAILED');
});
