'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  HERO_DEATHS_SNAPSHOT_821_CANDIDATE_PROFILE,
  assessHeroDeathsSnapshotTail821,
  decodeHeroDeathsSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_hero_stats_candidate');

const BUILD = '16.19.821.7343';
const CODES = [
  0x97, 0xcc, 0x55, 0xf1, 0x6f, 0x8d, 0x58,
  0x02, 0xb7, 0xde, 0x3f, 0xb6, 0xbe,
];

function payloadFor(count) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde], 0);
  payload[1182] = CODES[count];
  return payload;
}

function block(packetId, rawParam, timeMs, payload) {
  const header = Buffer.alloc(15);
  header[0] = 0;
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function fixture({
  version = BUILD,
  frames = [Array(10).fill(0), Array.from({ length: 10 }, (_, index) => index === 0 ? 12 : index)],
  tails = null,
  mutatePacket = null,
  includeStartRoute = false,
} = {}) {
  const chunks = [];
  if (includeStartRoute) {
    chunks.push({ stream: 3, body: block(0x0089, 0x400000ae, 0, payloadFor(0)) });
  }
  for (const [frameIndex, counts] of frames.entries()) {
    const packets = counts.map((count, participantIndex) => {
      const item = {
        packetId: 0x0089,
        rawParam: 0x400000ae + participantIndex,
        timeMs: frameIndex * 1000,
        payload: payloadFor(count),
      };
      if (mutatePacket) mutatePacket(item, frameIndex, participantIndex);
      return block(item.packetId, item.rawParam, item.timeMs, item.payload);
    });
    chunks.push({ stream: 2, body: Buffer.concat(packets) });
  }
  const replay = replayFromChunks(chunks, version);
  replay.tail.stats = (tails ?? frames.at(-1).map((count, index) => count + (index % 2)))
    .map((count) => ({ NUM_DEATHS: String(count) }));
  return replay;
}

test('821 raw-byte candidate emits bounded snapshots and packet provenance', () => {
  const replay = fixture();
  const profile = HERO_DEATHS_SNAPSHOT_821_CANDIDATE_PROFILE;
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.raw_deaths_byte_index, 1182);
  assert.equal(profile.evidence_runtime_image_sha256, null);
  assert.deepEqual(profile.encoded_byte_for_death_count_candidate, CODES);
  const assessed = assessHeroDeathsSnapshotTail821(replay);
  assert.equal(assessed.status, 'PASS');
  const result = decodeHeroDeathsSnapshotCandidates821(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 20);
  assert.equal(result.input_count, 20);
  assert.equal(result.keyframe_count, 2);
  assert.equal(result.observed_participant_count, 10);
  assert.equal(result.tail_gap_total, 5);
  assert.deepEqual(result.observed_max_deaths, [12, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.equal(result.events[0].deaths_candidate, 0);
  assert.equal(result.events[0].raw_deaths_byte, 0x97);
  assert.equal(result.events[10].deaths_candidate, 12);
  assert.equal(result.events[10].raw_deaths_byte, 0xbe);
  assert.equal(result.events[10].participant_id_candidate, 1);
  assert.equal(result.events[10].replay_time_ms, 1000);
  assert.equal(result.events[10].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[10].raw_packet_ref.chunk_stream, 'keyframe');
  assert.equal(result.events[10].raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(12)).digest('hex'));
  assert.equal(result.events[10].observation_kind, 'KEYFRAME_SNAPSHOT');
  assert.equal(result.events[10].confidence, 'CANDIDATE');
  assert.equal(result.events[10].field_confidence.raw_deaths_byte, 'VERIFIED_DIRECT');
});

test('wrong build and missing or malformed tail stay unavailable', () => {
  const wrongBuild = fixture({ version: '16.19.820.7193' });
  assert.equal(assessHeroDeathsSnapshotTail821(wrongBuild).status, 'UNSUPPORTED');
  assert.equal(decodeHeroDeathsSnapshotCandidates821(wrongBuild).status, 'UNSUPPORTED');
  const missingTail = fixture();
  missingTail.tail.stats = null;
  assert.equal(decodeHeroDeathsSnapshotCandidates821(missingTail).status, 'MISSING_INPUT');
  const malformedTail = fixture();
  malformedTail.tail.stats[0].NUM_DEATHS = 'unknown';
  assert.equal(decodeHeroDeathsSnapshotCandidates821(malformedTail).status, 'UNSUPPORTED');
});

test('unknown code and foreign length or prefix reject the whole candidate', () => {
  for (const change of [
    (item) => { item.payload[1182] = 0xfa; },
    (item) => { item.payload = item.payload.subarray(0, 1262); },
    (item) => { item.payload[0] ^= 1; },
  ]) {
    const replay = fixture({ mutatePacket(item, frame, participant) {
      if (frame === 1 && participant === 0) change(item);
    } });
    const result = decodeHeroDeathsSnapshotCandidates821(replay);
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
    assert.equal(result.event_count, null);
    assert.equal(result.first_unmatched_packet_ref.raw_param, 0x400000ae);
  }
});

test('keyframe route requires ten exact hero params and consistent Replay time', () => {
  for (const mutatePacket of [
    (item, frame, participant) => {
      if (frame === 1 && participant === 9) item.rawParam = 0x400000bd;
    },
    (item, frame, participant) => {
      if (frame === 1 && participant === 9) item.rawParam = 0x400000ae;
    },
    (item, frame, participant) => {
      if (frame === 1 && participant === 9) item.timeMs = 1100;
    },
  ]) {
    const result = decodeHeroDeathsSnapshotCandidates821(fixture({ mutatePacket }));
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
  }
  const partial = fixture({ frames: [Array(10).fill(0), Array(9).fill(0)],
    tails: Array(10).fill(0) });
  assert.match(decodeHeroDeathsSnapshotCandidates821(partial).error, /expected 10/);
  const startRoute = fixture({ includeStartRoute: true });
  assert.match(decodeHeroDeathsSnapshotCandidates821(startRoute).error, /start_keyframe/);
});

test('first value, sequence decline and final tail gap must stay inside evidence', () => {
  const nonzeroFirst = fixture({ frames: [Array(10).fill(1)] });
  assert.match(decodeHeroDeathsSnapshotCandidates821(nonzeroFirst).error, /not zero/);
  const declining = fixture({
    frames: [Array(10).fill(0), Array(10).fill(2), Array(10).fill(1)],
    tails: Array(10).fill(2),
  });
  assert.match(decodeHeroDeathsSnapshotCandidates821(declining).error, /decreasing/);
  const gapTwo = fixture({ frames: [Array(10).fill(0)], tails: Array(10).fill(2) });
  assert.match(decodeHeroDeathsSnapshotCandidates821(gapTwo).error, /outside 0\.\.1/);
  assert.equal(decodeHeroDeathsSnapshotCandidates821(gapTwo).events, null);
});

test('source mutation and framing errors reject candidate packet references', () => {
  const changedBytes = fixture();
  changedBytes.buffer[changedBytes.chunks[0].body_offset + 15 + 1182] ^= 1;
  const changed = decodeHeroDeathsSnapshotCandidates821(changedBytes);
  assert.equal(changed.status, 'DECODE_FAILED');
  assert.match(changed.error, /Replay source failed/);
  const brokenFrame = replayFromChunks([{ stream: 2, body: Buffer.from([0]) }], BUILD);
  brokenFrame.tail.stats = Array.from({ length: 10 }, () => ({ NUM_DEATHS: '0' }));
  const framing = decodeHeroDeathsSnapshotCandidates821(brokenFrame);
  assert.equal(framing.status, 'DECODE_FAILED');
  assert.match(framing.error, /framing failed/);
});
