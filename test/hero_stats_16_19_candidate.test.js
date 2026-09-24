'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  HERO_EXPERIENCE_SNAPSHOT_CANDIDATE_PROFILE: experienceProfile,
  HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE: profile,
  assessHeroExperienceSnapshotTail,
  assessHeroMinionsKilledSnapshotTail,
  decodeHeroStatsByte,
  decodeHeroExperiencePayload,
  decodeHeroExperienceSnapshotCandidates,
  decodeHeroMinionsKilledPayload,
  decodeHeroMinionsKilledSnapshotCandidates,
} = require('../src/decoders/rofl_16_19_hero_stats_candidate');

// A fixture encoder is confined to tests. The production module only decodes.
const ENCODE_BYTE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  const plain = decodeHeroStatsByte(encoded);
  assert.equal(ENCODE_BYTE[plain], null);
  ENCODE_BYTE[plain] = encoded;
}
assert.ok(ENCODE_BYTE.every((value) => value !== null));

function payloadFor(value, experience = 0) {
  const blob = Buffer.alloc(1260);
  blob.writeFloatLE(experience, 0x28);
  blob.writeFloatLE(value, 0x3c);
  const payload = Buffer.alloc(1263);
  payload.set([0x1c, 0xa6, 0xe8], 0);
  for (let index = 0; index < blob.length; index += 1) {
    payload[index + 3] = ENCODE_BYTE[blob[blob.length - 1 - index]];
  }
  return payload;
}

function blockFor(participantId, timeMs, payload = payloadFor(0), packetId = 0x0276) {
  const header = Buffer.alloc(15);
  header[0] = 0x00; // absolute f32 time, u32 length, absolute u16 route, absolute u32 param
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(0x400000ad + participantId, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ times = [0, 1000], values = null, tails = null,
  experienceValues = null, experienceTails = null, stream = 2,
  version = '16.19.820.7193', extraBlocks = [], omitParticipant = null } = {}) {
  const rows = values || times.map((_, timeIndex) =>
    Array.from({ length: 10 }, (__, playerIndex) => timeIndex * (playerIndex + 1)));
  const chunks = [{ stream, body: Buffer.concat([
    ...times.flatMap((time, timeIndex) => rows[timeIndex].flatMap((value, playerIndex) =>
      playerIndex + 1 === omitParticipant && timeIndex === 0 ? []
        : [blockFor(playerIndex + 1, time,
          payloadFor(value, experienceValues?.[timeIndex]?.[playerIndex] ?? 0))])),
    ...extraBlocks,
  ]) }];
  const replay = replayFromChunks(chunks, version);
  replay.tail.stats = (tails || rows.at(-1).map((value) => value + 2))
    .map((value, index) => ({ MINIONS_KILLED: String(value),
      EXP: String(experienceTails?.[index]
        ?? (Math.floor(experienceValues?.at(-1)?.[index] ?? 0) + 2)) }));
  return replay;
}

test('the exact image table inverse has independently known byte and prefix anchors', () => {
  assert.equal(profile.replay_version, '16.19.820.7193');
  assert.equal(profile.replay_block_packet_id, 0x0276);
  assert.equal(profile.lookup_table_sha256,
    '328528d693ab5d96a815b6706694025a980e609019304aeb2e5e32797011c04b');
  assert.equal(decodeHeroStatsByte(0xf6), 0x00);
  assert.equal(decodeHeroStatsByte(0xa6), 0xec);
  assert.equal(decodeHeroStatsByte(0xe8), 0x09);
  const zeroPayload = Buffer.concat([Buffer.from([0x1c, 0xa6, 0xe8]), Buffer.alloc(1260, 0xf6)]);
  assert.deepEqual(decodeHeroMinionsKilledPayload(zeroPayload),
    { status: 'PASS', minions_killed_candidate: 0 });
  assert.deepEqual(decodeHeroMinionsKilledPayload(payloadFor(42)),
    { status: 'PASS', minions_killed_candidate: 42 });
});

test('keyframe snapshots retain raw refs, ten hero params, repeated CS, and unfilled tail gaps', () => {
  const replay = fixture();
  const result = decodeHeroMinionsKilledSnapshotCandidates(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_packet_id, 0x0276);
  assert.equal(result.input_count, 20);
  assert.equal(result.event_count, 20);
  assert.equal(result.scanned_block_count, 20);
  assert.equal(result.keyframe_timestamp_count, 2);
  assert.equal(result.observed_participant_count, 10);
  assert.deepEqual(result.observed_max_minions_killed, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.deepEqual(result.tail_gaps.map((row) => row.unobserved_tail_gap), Array(10).fill(2));
  assert.equal(result.tail_gap_total, 20);
  assert.equal(result.events[0].minions_killed_candidate, 0);
  assert.equal(result.events.at(-1).minions_killed_candidate, 10);
  assert.equal(result.events.at(-1).raw_packet_ref.chunk_stream, 'keyframe');
  assert.equal(result.events.at(-1).raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(result.events.at(-1).raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(10)).digest('hex'));
  assert.equal(result.events[0].observation_kind, 'KEYFRAME_SNAPSHOT');
});

test('tail preflight distinguishes missing and invalid values without packet scanning', () => {
  const replay = fixture();
  assert.equal(assessHeroMinionsKilledSnapshotTail(replay).status, 'PASS');
  replay.tail.stats[0].MINIONS_KILLED = undefined;
  assert.equal(assessHeroMinionsKilledSnapshotTail(replay).status, 'MISSING_INPUT');
  assert.equal(decodeHeroMinionsKilledSnapshotCandidates(replay).status, 'MISSING_INPUT');
  replay.tail.stats[0].MINIONS_KILLED = '-1';
  assert.equal(assessHeroMinionsKilledSnapshotTail(replay).status, 'UNSUPPORTED');
  replay.tail.stats = [];
  assert.equal(assessHeroMinionsKilledSnapshotTail(replay).status, 'UNSUPPORTED');
});

test('wrong exact build and absent keyframe route remain unavailable', () => {
  assert.equal(decodeHeroMinionsKilledSnapshotCandidates(
    fixture({ version: '16.19.820.7194' })).status, 'UNSUPPORTED');
  const gameStreamOnly = fixture({ stream: 1 });
  const result = decodeHeroMinionsKilledSnapshotCandidates(gameStreamOnly);
  assert.equal(result.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.input_count, null);
  assert.equal(result.event_count, null);
});

test('a foreign 0x0276 keyframe shape is unavailable, while mixed shapes fail closed', () => {
  const foreign = replayFromChunks([{ stream: 2, body: Buffer.concat(
    Array.from({ length: 10 }, (_, index) => blockFor(index + 1, 0, Buffer.from([1, 2]))),
  ) }], '16.19.820.7193');
  const unavailable = decodeHeroMinionsKilledSnapshotCandidates(foreign);
  assert.equal(unavailable.status, 'PROFILE_UNAVAILABLE');
  assert.equal(unavailable.observed_raw_route_count, 10);
  assert.equal(unavailable.input_count, null);
  const mixed = fixture({ times: [0], extraBlocks: [blockFor(1, 0, Buffer.from([1, 2]))] });
  assert.equal(decodeHeroMinionsKilledSnapshotCandidates(mixed).status, 'DECODE_FAILED');
});

test('malformed exact route payloads fail closed', () => {
  const badPrefix = payloadFor(0);
  badPrefix[0] = 0x1d;
  assert.equal(decodeHeroMinionsKilledPayload(badPrefix).status, 'DECODE_FAILED');
  assert.equal(decodeHeroMinionsKilledPayload(badPrefix.subarray(1)).status, 'DECODE_FAILED');
  assert.equal(decodeHeroMinionsKilledPayload(payloadFor(1.5)).status, 'DECODE_FAILED');
  assert.equal(decodeHeroMinionsKilledPayload(payloadFor(-1)).status, 'DECODE_FAILED');
  assert.equal(decodeHeroMinionsKilledPayload(payloadFor(NaN)).status, 'DECODE_FAILED');
  const replay = fixture({ times: [0], extraBlocks: [blockFor(1, 0, badPrefix)] });
  assert.equal(decodeHeroMinionsKilledSnapshotCandidates(replay).status, 'DECODE_FAILED');
});

test('unsupported hero param, missing hero, decrease, and values above tail fail closed', () => {
  const unknownParam = fixture({ times: [0], extraBlocks: [blockFor(11, 0)] });
  assert.equal(decodeHeroMinionsKilledSnapshotCandidates(unknownParam).status, 'DECODE_FAILED');
  const missingHero = fixture({ times: [0], omitParticipant: 3 });
  assert.match(decodeHeroMinionsKilledSnapshotCandidates(missingHero).error, /lacks one or more hero params/);
  const decreasing = fixture({ values: [Array(10).fill(3), Array(10).fill(2)] });
  assert.match(decodeHeroMinionsKilledSnapshotCandidates(decreasing).error, /decreasing/);
  const aboveTail = fixture({ tails: Array(10).fill(0) });
  assert.match(decodeHeroMinionsKilledSnapshotCandidates(aboveTail).error, /exceeds Replay tail/);
});

test('experience offset remains a one-Replay candidate over the exact HN HeroStats transform', () => {
  assert.equal(experienceProfile.replay_version, '16.19.820.7193');
  assert.equal(experienceProfile.replay_block_packet_id, 0x0276);
  assert.equal(experienceProfile.experience_f32le_offset_candidate, 0x28);
  assert.equal(experienceProfile.lookup_table_sha256, profile.lookup_table_sha256);
  assert.deepEqual(decodeHeroExperiencePayload(payloadFor(7, 1234.75)), {
    status: 'PASS', experience_points_candidate: 1234.75,
    experience_floor_candidate: 1234,
  });
  assert.equal(decodeHeroExperiencePayload(payloadFor(0, -1)).status, 'DECODE_FAILED');
  assert.equal(decodeHeroExperiencePayload(payloadFor(0, NaN)).status, 'DECODE_FAILED');
  assert.equal(decodeHeroExperiencePayload(payloadFor(0, Infinity)).status, 'DECODE_FAILED');
});

test('experience snapshots retain raw f32, floor, provenance, and unobserved EXP gaps', () => {
  const experienceValues = [
    Array.from({ length: 10 }, (_, index) => index + 0.25),
    Array.from({ length: 10 }, (_, index) => (index + 1) * 100 + 0.75),
  ];
  const replay = fixture({ experienceValues,
    experienceTails: experienceValues.at(-1).map((value) => Math.floor(value) + 5) });
  const result = decodeHeroExperienceSnapshotCandidates(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 20);
  assert.equal(result.input_count, 20);
  assert.equal(result.keyframe_timestamp_count, 2);
  assert.equal(result.observed_participant_count, 10);
  assert.equal(result.evidence_status, 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_FIELD_CORRELATION');
  assert.deepEqual(result.observed_max_experience_floor,
    Array.from({ length: 10 }, (_, index) => (index + 1) * 100));
  assert.deepEqual(result.tail_gaps.map((row) => row.unobserved_tail_floor_gap),
    Array(10).fill(5));
  assert.equal(result.tail_gap_total, 50);
  assert.equal(result.events[0].event_type, 'HERO_EXPERIENCE_SNAPSHOT_CANDIDATE');
  assert.equal(result.events[0].experience_points_candidate, 0.25);
  assert.equal(result.events[0].experience_floor_candidate, 0);
  assert.equal(result.events.at(-1).experience_points_candidate, 1000.75);
  assert.equal(result.events.at(-1).experience_floor_candidate, 1000);
  assert.equal(result.events.at(-1).raw_packet_ref.chunk_stream, 'keyframe');
  assert.equal(result.events.at(-1).raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(result.events.at(-1).raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(10, 1000.75)).digest('hex'));
  assert.equal(result.events[0].field_confidence.experience_points_candidate,
    'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION');
  assert.equal(result.events[0].observation_kind, 'KEYFRAME_SNAPSHOT');
});

test('experience tail preflight does not affect the independent CS candidate', () => {
  const replay = fixture();
  assert.equal(assessHeroExperienceSnapshotTail(replay).status, 'PASS');
  replay.tail.stats[0].EXP = undefined;
  assert.equal(assessHeroExperienceSnapshotTail(replay).status, 'MISSING_INPUT');
  assert.equal(decodeHeroExperienceSnapshotCandidates(replay).status, 'MISSING_INPUT');
  assert.equal(decodeHeroMinionsKilledSnapshotCandidates(replay).status, 'CANDIDATE');
  replay.tail.stats[0].EXP = '-1';
  assert.equal(assessHeroExperienceSnapshotTail(replay).status, 'UNSUPPORTED');
  replay.tail.stats = [];
  assert.equal(assessHeroExperienceSnapshotTail(replay).status, 'UNSUPPORTED');
});

test('experience candidate rejects wrong build, foreign keyframe shape, and mixed profile', () => {
  assert.equal(decodeHeroExperienceSnapshotCandidates(
    fixture({ version: '16.19.820.7194' })).status, 'UNSUPPORTED');
  assert.equal(decodeHeroExperienceSnapshotCandidates(
    fixture({ stream: 1 })).status, 'PROFILE_UNAVAILABLE');
  const foreign = replayFromChunks([{ stream: 2, body: Buffer.concat(
    Array.from({ length: 10 }, (_, index) => blockFor(index + 1, 0, Buffer.from([1, 2]))),
  ) }], '16.19.820.7193');
  const unavailable = decodeHeroExperienceSnapshotCandidates(foreign);
  assert.equal(unavailable.status, 'PROFILE_UNAVAILABLE');
  assert.equal(unavailable.observed_raw_route_count, 10);
  assert.equal(unavailable.event_count, null);
  const mixed = fixture({ times: [0], extraBlocks: [blockFor(1, 0, Buffer.from([1, 2]))] });
  assert.equal(decodeHeroExperienceSnapshotCandidates(mixed).status, 'DECODE_FAILED');
});

test('experience snapshots fail closed on broken hero group, decrease, and tail overrun', () => {
  const missingHero = fixture({ times: [0], omitParticipant: 3 });
  assert.match(decodeHeroExperienceSnapshotCandidates(missingHero).error,
    /lacks one or more hero params/);
  const decreasing = fixture({
    experienceValues: [Array(10).fill(3), Array(10).fill(2)],
    experienceTails: Array(10).fill(5),
  });
  assert.match(decodeHeroExperienceSnapshotCandidates(decreasing).error,
    /decreasing observed EXP/);
  const aboveTail = fixture({
    experienceValues: [Array(10).fill(0), Array(10).fill(3)],
    experienceTails: Array(10).fill(2),
  });
  assert.match(decodeHeroExperienceSnapshotCandidates(aboveTail).error,
    /exceeds Replay tail EXP/);
});
