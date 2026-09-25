'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const {
  HERO_MISSIONS_MINIONS_KILLED_SNAPSHOT_821_CANDIDATE_PROFILE,
  assessHeroMissionsMinionsKilledSnapshotTail821,
  decodeHeroMissionsMinionsKilledSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_hero_stats_candidate');

const BUILD = '16.19.821.7343';
const BYTE_FOR_VALUE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  BYTE_FOR_VALUE[decodeRuntimeCountByte(encoded)] = encoded;
}
assert.equal(BYTE_FOR_VALUE.filter((value) => value !== null).length, 256);

function block(param, timeMs, payload) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(param >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function fixture({
  version = BUILD,
  frames = [Array(10).fill(0), [255, ...Array(9).fill(0)],
    [256, ...Array(9).fill(0)], [258, ...Array(9).fill(0)]],
  missionTails = [260, ...Array(9).fill(0)],
  mutate = null,
} = {}) {
  const chunks = frames.map((counts, frameIndex) => ({
    stream: 2,
    body: Buffer.concat(counts.map((count, participantIndex) => {
      const item = {
        param: 0x400000ae + participantIndex,
        timeMs: frameIndex * 1000,
        payload: Buffer.alloc(1263, BYTE_FOR_VALUE[0]),
      };
      item.payload.set([0x67, 0x00, 0xde]);
      item.payload[374] = BYTE_FOR_VALUE[count & 0xff];
      item.payload[373] = BYTE_FOR_VALUE[count >>> 8];
      if (mutate) mutate(item, frameIndex, participantIndex);
      return block(item.param, item.timeMs, item.payload);
    })),
  }));
  const replay = replayFromChunks(chunks, version);
  replay.tail.stats = missionTails.map((count) => ({
    Missions_MinionsKilled: String(count),
    MINIONS_KILLED: String(count + 10),
  }));
  return replay;
}

test('821 mission minions snapshot decodes the observed reverse-order two-byte count', () => {
  const replay = fixture();
  const profile = HERO_MISSIONS_MINIONS_KILLED_SNAPSHOT_821_CANDIDATE_PROFILE;
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.raw_low_byte_index, 374);
  assert.equal(profile.raw_high_byte_index, 373);
  assert.equal(profile.replay_tail_field, 'Missions_MinionsKilled');
  assert.match(profile.known_limits.join(' '), /MINIONS_KILLED, zero of 110/);
  assert.equal(assessHeroMissionsMinionsKilledSnapshotTail821(replay).status, 'PASS');

  const result = decodeHeroMissionsMinionsKilledSnapshotCandidates821(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 40);
  assert.equal(result.input_count, 40);
  assert.equal(result.keyframe_count, 4);
  assert.equal(result.events[10].missions_minions_killed_candidate, 255);
  assert.equal(result.events[20].missions_minions_killed_candidate, 256);
  assert.equal(result.events[20].decoded_missions_minions_low_byte, 0);
  assert.equal(result.events[20].decoded_missions_minions_high_byte, 1);
  assert.equal(result.events[30].missions_minions_killed_candidate, 258);
  assert.equal(result.events[30].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.deepEqual(result.observed_max_missions_minions_killed,
    [258, ...Array(9).fill(0)]);
  assert.equal(result.tail_gaps[0].unobserved_tail_gap, 2);
  assert.equal(result.tail_gap_total, 2);
  assert.equal(result.runtime_image_used, false);
});

test('821 mission tail and exact-build gates preserve missing, invalid and above-tail states', () => {
  assert.equal(decodeHeroMissionsMinionsKilledSnapshotCandidates821(
    fixture({ version: '16.19.820.7193' })).status, 'UNSUPPORTED');
  const missing = fixture();
  delete missing.tail.stats[0].Missions_MinionsKilled;
  assert.equal(decodeHeroMissionsMinionsKilledSnapshotCandidates821(missing).status,
    'MISSING_INPUT');
  const invalid = fixture();
  invalid.tail.stats[0].Missions_MinionsKilled = 'unknown';
  assert.equal(decodeHeroMissionsMinionsKilledSnapshotCandidates821(invalid).status,
    'UNSUPPORTED');
  const above = decodeHeroMissionsMinionsKilledSnapshotCandidates821(fixture({
    missionTails: [257, ...Array(9).fill(0)],
  }));
  assert.equal(above.status, 'DECODE_FAILED');
  assert.match(above.error, /exceeds Replay tail Missions_MinionsKilled/);
  assert.equal(above.events, null);
  assert.equal(above.first_unmatched_packet_ref.raw_param, 0x400000ae);
});

test('821 mission count rejects sequence and keyframe shape violations', () => {
  const first = decodeHeroMissionsMinionsKilledSnapshotCandidates821(fixture({
    frames: [Array(10).fill(1)], missionTails: Array(10).fill(1),
  }));
  assert.match(first.error, /first observed.*not zero/);
  const decline = decodeHeroMissionsMinionsKilledSnapshotCandidates821(fixture({
    frames: [Array(10).fill(0), Array(10).fill(2), Array(10).fill(1)],
    missionTails: Array(10).fill(2),
  }));
  assert.match(decline.error, /decreasing/);
  for (const [change, message] of [
    [(item) => { item.param = 0x400000bd; }, /unsupported raw param/],
    [(item) => { item.payload = item.payload.subarray(0, 1262); }, /length or prefix/],
    [(item) => { item.payload[372] = BYTE_FOR_VALUE[1]; }, /upper count bytes/],
  ]) {
    const replay = fixture({ mutate(item, frame, participant) {
      if (frame === 1 && participant === 0) change(item);
    } });
    const result = decodeHeroMissionsMinionsKilledSnapshotCandidates821(replay);
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
    assert.match(result.error, message);
    assert.ok(result.first_unmatched_packet_ref);
  }
});

test('821 mission count rejects mutated source bytes before emitting snapshots', () => {
  const replay = fixture();
  replay.buffer[replay.chunks[0].body_offset + 15 + 374] ^= 1;
  const result = decodeHeroMissionsMinionsKilledSnapshotCandidates821(replay);
  assert.equal(result.status, 'DECODE_FAILED');
  assert.match(result.error, /Replay source failed/);
  assert.equal(result.events, null);
});
