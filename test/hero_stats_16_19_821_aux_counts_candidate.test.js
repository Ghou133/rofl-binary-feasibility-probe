'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  decodeHeroWardStatsSnapshotCandidates821,
  decodeHeroMissionsCannonMinionsKilledSnapshotCandidates821,
  assessHeroWardStatsTail821,
} = require('../src/decoders/rofl_16_19_821_aux_counts_candidate');

const BUILD = '16.19.821.7343';
const OFFSETS = [834, 838, 842, 450];

function packet(participant, count, timeMs, change = null) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  for (const offset of OFFSETS) payload[offset] = count === 0 ? 0x97 : 0xcc;
  if (change) change(payload);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participant, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, tail = 1, change = null } = {}) {
  const chunks = [0, 1].map((frame) => ({ stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) => packet(
      index + 1, frame === 1 && index === 0 ? 1 : 0, frame * 1000,
      frame === 1 && index === 0 ? change : null))),
  }));
  const replay = replayFromChunks(chunks, version);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    WARD_PLACED_DETECTOR: String(index === 0 ? tail : 0),
    WARD_KILLED: String(index === 0 ? tail : 0),
    WARD_PLACED: String(index === 0 ? tail : 0),
    Missions_CannonMinionsKilled: String(index === 0 ? tail : 0),
  }));
  return replay;
}

test('821 ward and cannon byte snapshots retain distinct candidate values and raw refs', () => {
  const replay = fixture();
  const assessed = assessHeroWardStatsTail821(replay);
  assert.deepEqual(assessed.required_fields.map((row) => row.status),
    ['PASS', 'PASS', 'PASS']);
  const ward = decodeHeroWardStatsSnapshotCandidates821(replay);
  const cannon = decodeHeroMissionsCannonMinionsKilledSnapshotCandidates821(replay);
  assert.equal(ward.status, 'CANDIDATE');
  assert.equal(cannon.status, 'CANDIDATE');
  assert.equal(ward.event_count, 20);
  assert.equal(cannon.event_count, 20);
  assert.equal(ward.events[10].ward_placed_detector_candidate, 1);
  assert.equal(ward.events[10].ward_killed_candidate, 1);
  assert.equal(ward.events[10].ward_placed_candidate, 1);
  assert.equal(cannon.events[10].missions_cannon_minions_killed_candidate, 1);
  assert.equal(ward.events[10].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.deepEqual(ward.tail_gap_totals_by_field,
    { ward_placed_detector: 0, ward_killed: 0, ward_placed: 0 });
  assert.deepEqual(cannon.tail_gap_totals_by_field,
    { missions_cannon_minions_killed: 0 });
  assert.equal(ward.runtime_image_used, false);
  assert.equal(ward.runtime_image_status, 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED');
});

test('821 auxiliary counters fail closed on missing tails, foreign builds and high bytes', () => {
  const foreign = decodeHeroWardStatsSnapshotCandidates821(
    fixture({ version: '16.19.820.7193' }));
  assert.equal(foreign.status, 'UNSUPPORTED');
  const missing = fixture();
  delete missing.tail.stats[0].WARD_KILLED;
  assert.equal(decodeHeroWardStatsSnapshotCandidates821(missing).status, 'MISSING_INPUT');
  const above = decodeHeroMissionsCannonMinionsKilledSnapshotCandidates821(
    fixture({ tail: 0 }));
  assert.equal(above.status, 'DECODE_FAILED');
  assert.match(above.error, /exceeds Replay tail Missions_CannonMinionsKilled/);
  assert.equal(above.events, null);
  const high = decodeHeroWardStatsSnapshotCandidates821(fixture({
    change(payload) { payload[841] = 0xcc; },
  }));
  assert.equal(high.status, 'DECODE_FAILED');
  assert.match(high.error, /decoded upper bytes are nonzero/);
  assert.ok(high.first_unmatched_packet_ref);
});

test('821 auxiliary snapshots reject Replay source mutation', () => {
  const replay = fixture();
  replay.buffer[replay.chunks[0].body_offset + 15 + 842] ^= 1;
  const result = decodeHeroWardStatsSnapshotCandidates821(replay);
  assert.equal(result.status, 'DECODE_FAILED');
  assert.match(result.error, /Replay source failed/);
  assert.equal(result.events, null);
});
