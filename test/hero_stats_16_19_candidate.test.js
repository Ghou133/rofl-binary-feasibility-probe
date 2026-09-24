'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  HERO_CHAMPION_KILLS_SNAPSHOT_CANDIDATE_PROFILE: championKillsProfile,
  HERO_EXPERIENCE_SNAPSHOT_CANDIDATE_PROFILE: experienceProfile,
  HERO_GOLD_EARNED_SNAPSHOT_CANDIDATE_PROFILE: goldEarnedProfile,
  HERO_GOLD_SPENT_SNAPSHOT_CANDIDATE_PROFILE: goldSpentProfile,
  HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE_PROFILE: profile,
  assessHeroChampionKillsSnapshotTail,
  assessHeroExperienceSnapshotTail,
  assessHeroGoldEarnedSnapshotTail,
  assessHeroGoldSpentSnapshotTail,
  assessHeroMinionsKilledSnapshotTail,
  decodeHeroStatsByte,
  decodeHeroChampionKillsPayload,
  decodeHeroChampionKillsSnapshotCandidates,
  decodeHeroExperiencePayload,
  decodeHeroExperienceSnapshotCandidates,
  decodeHeroGoldEarnedPayload,
  decodeHeroGoldEarnedSnapshotCandidates,
  decodeHeroGoldSpentPayload,
  decodeHeroGoldSpentSnapshotCandidates,
  decodeHeroStatsSnapshotCandidateSet,
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

function payloadFor(value, experience = 0, goldEarned = 0, goldSpent = 0,
  championKills = 0, championKillsMirror = championKills) {
  const blob = Buffer.alloc(1260);
  blob.writeFloatLE(experience, 0x28);
  blob.writeFloatLE(goldSpent, 0x34);
  blob.writeFloatLE(goldEarned, 0x38);
  blob.writeFloatLE(value, 0x3c);
  blob.writeUInt32LE(championKills, 0x4c);
  blob.writeUInt32LE(championKillsMirror, 0x33c);
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
  experienceValues = null, experienceTails = null,
  goldEarnedValues = null, goldEarnedTails = null,
  goldSpentValues = null, goldSpentTails = null,
  championKillsValues = null, championKillsTails = null,
  championKillsMirrorValues = null, stream = 2,
  version = '16.19.820.7193', extraBlocks = [], omitParticipant = null } = {}) {
  const rows = values || times.map((_, timeIndex) =>
    Array.from({ length: 10 }, (__, playerIndex) => timeIndex * (playerIndex + 1)));
  const chunks = [{ stream, body: Buffer.concat([
    ...times.flatMap((time, timeIndex) => rows[timeIndex].flatMap((value, playerIndex) =>
      playerIndex + 1 === omitParticipant && timeIndex === 0 ? []
        : [blockFor(playerIndex + 1, time,
          payloadFor(value, experienceValues?.[timeIndex]?.[playerIndex] ?? 0,
            goldEarnedValues?.[timeIndex]?.[playerIndex] ?? 0,
            goldSpentValues?.[timeIndex]?.[playerIndex] ?? 0,
            championKillsValues?.[timeIndex]?.[playerIndex] ?? 0,
            championKillsMirrorValues?.[timeIndex]?.[playerIndex]
              ?? championKillsValues?.[timeIndex]?.[playerIndex] ?? 0))])),
    ...extraBlocks,
  ]) }];
  const replay = replayFromChunks(chunks, version);
  replay.tail.stats = (tails || rows.at(-1).map((value) => value + 2))
    .map((value, index) => ({ MINIONS_KILLED: String(value),
      EXP: String(experienceTails?.[index]
        ?? (Math.floor(experienceValues?.at(-1)?.[index] ?? 0) + 2)),
      GOLD_EARNED: String(goldEarnedTails?.[index]
        ?? (Math.floor(goldEarnedValues?.at(-1)?.[index] ?? 0) + 2)),
      GOLD_SPENT: String(goldSpentTails?.[index]
        ?? (Math.floor(goldSpentValues?.at(-1)?.[index] ?? 0) + 2)),
      CHAMPIONS_KILLED: String(championKillsTails?.[index]
        ?? ((championKillsValues?.at(-1)?.[index] ?? 0) + 2)) }));
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

test('combined HeroStats selection walks keyframe chunks once and returns five candidates', () => {
  const experienceValues = [Array(10).fill(0.25), Array(10).fill(100.75)];
  const goldEarnedValues = [Array(10).fill(500.25), Array(10).fill(750.75)];
  const goldSpentValues = [Array(10).fill(100), Array(10).fill(250)];
  const championKillsValues = [Array(10).fill(0),
    Array.from({ length: 10 }, (_, index) => index + 1)];
  const replay = fixture({ experienceValues, experienceTails: Array(10).fill(102),
    goldEarnedValues, goldEarnedTails: Array(10).fill(752),
    goldSpentValues, goldSpentTails: Array(10).fill(252),
    championKillsValues });
  const chunks = replay.chunks;
  let chunkTraversalCount = 0;
  Object.defineProperty(replay, 'chunks', { get() {
    chunkTraversalCount += 1;
    return chunks;
  } });
  const results = decodeHeroStatsSnapshotCandidateSet(replay,
    ['hero_minions_killed_snapshot', 'hero_experience_snapshot',
      'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot',
      'hero_champion_kills_snapshot']);
  assert.equal(chunkTraversalCount, 1);
  assert.deepEqual(Object.keys(results),
    ['hero_minions_killed_snapshot', 'hero_experience_snapshot',
      'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot',
      'hero_champion_kills_snapshot']);
  assert.equal(results.hero_minions_killed_snapshot.status, 'CANDIDATE');
  assert.equal(results.hero_experience_snapshot.status, 'CANDIDATE');
  assert.equal(results.hero_gold_earned_snapshot.status, 'CANDIDATE');
  assert.equal(results.hero_gold_spent_snapshot.status, 'CANDIDATE');
  assert.equal(results.hero_champion_kills_snapshot.status, 'CANDIDATE');
  assert.equal(results.hero_minions_killed_snapshot.event_count, 20);
  assert.equal(results.hero_experience_snapshot.event_count, 20);
  assert.equal(results.hero_gold_earned_snapshot.event_count, 20);
  assert.equal(results.hero_gold_spent_snapshot.event_count, 20);
  assert.equal(results.hero_champion_kills_snapshot.event_count, 20);
  assert.equal(results.hero_minions_killed_snapshot.events[0].raw_packet_ref.raw_payload_sha256,
    results.hero_experience_snapshot.events[0].raw_packet_ref.raw_payload_sha256);
  assert.equal(results.hero_experience_snapshot.events[0].raw_packet_ref.raw_payload_sha256,
    results.hero_gold_earned_snapshot.events[0].raw_packet_ref.raw_payload_sha256);
  assert.equal(results.hero_gold_earned_snapshot.events[0].raw_packet_ref.raw_payload_sha256,
    results.hero_gold_spent_snapshot.events[0].raw_packet_ref.raw_payload_sha256);
  assert.equal(results.hero_gold_spent_snapshot.events[0].raw_packet_ref.raw_payload_sha256,
    results.hero_champion_kills_snapshot.events[0].raw_packet_ref.raw_payload_sha256);
});

test('gold-earned offset is an observed float candidate over the exact HN transform', () => {
  assert.equal(goldEarnedProfile.replay_version, '16.19.820.7193');
  assert.equal(goldEarnedProfile.replay_block_packet_id, 0x0276);
  assert.equal(goldEarnedProfile.gold_earned_f32le_offset_candidate, 0x38);
  assert.equal(goldEarnedProfile.lookup_table_sha256, profile.lookup_table_sha256);
  assert.deepEqual(decodeHeroGoldEarnedPayload(payloadFor(7, 10, 1234.75)), {
    status: 'PASS', gold_earned_candidate: 1234.75,
  });
  assert.equal(decodeHeroGoldEarnedPayload(payloadFor(0, 0, -1)).status, 'DECODE_FAILED');
  assert.equal(decodeHeroGoldEarnedPayload(payloadFor(0, 0, NaN)).status, 'DECODE_FAILED');
  assert.equal(decodeHeroGoldEarnedPayload(payloadFor(0, 0, Infinity)).status, 'DECODE_FAILED');
  assert.equal(decodeHeroGoldEarnedPayload(payloadFor(0, 0, 2 ** 54)).status, 'DECODE_FAILED');
});

test('gold-earned snapshots retain raw floats, refs, and float tail differences', () => {
  const goldEarnedValues = [
    Array.from({ length: 10 }, (_, index) => 500 + index + 0.25),
    Array.from({ length: 10 }, (_, index) => 1000 + index * 100 + 0.75),
  ];
  const replay = fixture({ goldEarnedValues,
    goldEarnedTails: goldEarnedValues.at(-1).map((value) => Math.floor(value) + 2) });
  const result = decodeHeroGoldEarnedSnapshotCandidates(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 20);
  assert.equal(result.input_count, 20);
  assert.equal(result.keyframe_timestamp_count, 2);
  assert.equal(result.evidence_status, 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_FIELD_CORRELATION');
  assert.equal(result.events[0].event_type, 'HERO_GOLD_EARNED_SNAPSHOT_CANDIDATE');
  assert.equal(result.events[0].gold_earned_candidate, 500.25);
  assert.equal(result.events.at(-1).gold_earned_candidate, 1900.75);
  assert.equal(result.events.at(-1).raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(result.events.at(-1).raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(10, 0, 1900.75)).digest('hex'));
  assert.deepEqual(result.tail_gaps.map((row) => row.unobserved_tail_difference_candidate),
    Array(10).fill(1.25));
  assert.equal(result.tail_gap_total, 12.5);
  assert.equal(result.events[0].field_confidence.gold_earned_candidate,
    'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION');
});

test('gold-earned tail and sequence failures stay independent of CS and XP', () => {
  const missingGold = fixture();
  assert.equal(assessHeroGoldEarnedSnapshotTail(missingGold).status, 'PASS');
  missingGold.tail.stats[0].GOLD_EARNED = undefined;
  assert.equal(assessHeroGoldEarnedSnapshotTail(missingGold).status, 'MISSING_INPUT');
  const missing = decodeHeroStatsSnapshotCandidateSet(missingGold,
    ['hero_minions_killed_snapshot', 'hero_experience_snapshot', 'hero_gold_earned_snapshot']);
  assert.equal(missing.hero_gold_earned_snapshot.status, 'MISSING_INPUT');
  assert.equal(missing.hero_minions_killed_snapshot.status, 'CANDIDATE');
  assert.equal(missing.hero_experience_snapshot.status, 'CANDIDATE');
  missingGold.tail.stats[0].GOLD_EARNED = '-1';
  assert.equal(assessHeroGoldEarnedSnapshotTail(missingGold).status, 'UNSUPPORTED');

  const decreasingGold = fixture({
    goldEarnedValues: [Array(10).fill(503), Array(10).fill(502)],
    goldEarnedTails: Array(10).fill(505),
  });
  const decreasing = decodeHeroStatsSnapshotCandidateSet(decreasingGold,
    ['hero_gold_earned_snapshot', 'hero_minions_killed_snapshot', 'hero_experience_snapshot']);
  assert.equal(decreasing.hero_gold_earned_snapshot.status, 'DECODE_FAILED');
  assert.match(decreasing.hero_gold_earned_snapshot.error, /decreasing observed GOLD_EARNED/);
  assert.equal(decreasing.hero_minions_killed_snapshot.status, 'CANDIDATE');
  assert.equal(decreasing.hero_experience_snapshot.status, 'CANDIDATE');
  const aboveTail = fixture({
    goldEarnedValues: [Array(10).fill(0), Array(10).fill(3.25)],
    goldEarnedTails: Array(10).fill(3),
  });
  assert.match(decodeHeroGoldEarnedSnapshotCandidates(aboveTail).error,
    /exceeds Replay tail GOLD_EARNED/);
});

test('gold-earned profile rejects wrong build and foreign 0x0276 keyframe shape', () => {
  assert.equal(decodeHeroGoldEarnedSnapshotCandidates(
    fixture({ version: '16.19.820.7194' })).status, 'UNSUPPORTED');
  const foreign = replayFromChunks([{ stream: 2, body: Buffer.concat(
    Array.from({ length: 10 }, (_, index) => blockFor(index + 1, 0, Buffer.from([1, 2]))),
  ) }], '16.19.820.7193');
  const result = decodeHeroGoldEarnedSnapshotCandidates(foreign);
  assert.equal(result.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.observed_raw_route_count, 10);
  assert.equal(result.event_count, null);
});

test('gold-spent offset is a safe integer candidate over the exact HN transform', () => {
  assert.equal(goldSpentProfile.replay_version, '16.19.820.7193');
  assert.equal(goldSpentProfile.replay_block_packet_id, 0x0276);
  assert.equal(goldSpentProfile.gold_spent_f32le_offset_candidate, 0x34);
  assert.equal(goldSpentProfile.lookup_table_sha256, profile.lookup_table_sha256);
  assert.deepEqual(decodeHeroGoldSpentPayload(payloadFor(7, 10, 20, 1234)), {
    status: 'PASS', gold_spent_candidate: 1234,
  });
  assert.equal(decodeHeroGoldSpentPayload(payloadFor(0, 0, 0, -1)).status, 'DECODE_FAILED');
  assert.equal(decodeHeroGoldSpentPayload(payloadFor(0, 0, 0, 1.5)).status, 'DECODE_FAILED');
  assert.equal(decodeHeroGoldSpentPayload(payloadFor(0, 0, 0, NaN)).status, 'DECODE_FAILED');
  assert.equal(decodeHeroGoldSpentPayload(payloadFor(0, 0, 0, Infinity)).status, 'DECODE_FAILED');
  assert.equal(decodeHeroGoldSpentPayload(payloadFor(0, 0, 0, 2 ** 54)).status, 'DECODE_FAILED');
});

test('gold-spent candidate preserves an observed -100 decline and signed negative tail delta', () => {
  const first = Array(10).fill(0);
  const second = Array(10).fill(0);
  first[0] = 200;
  second[0] = 100;
  const tails = Array(10).fill(0);
  tails[0] = 90;
  const replay = fixture({ goldSpentValues: [first, second], goldSpentTails: tails });
  const result = decodeHeroGoldSpentSnapshotCandidates(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 20);
  assert.equal(result.observed_decline_count, 1);
  assert.equal(result.observed_declines[0].participant_id_candidate, 1);
  assert.equal(result.observed_declines[0].from_gold_spent_candidate, 200);
  assert.equal(result.observed_declines[0].to_gold_spent_candidate, 100);
  assert.equal(result.observed_declines[0].observed_delta_candidate, -100);
  assert.equal(result.observed_declines[0].from_raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(0, 0, 0, 200)).digest('hex'));
  assert.equal(result.observed_declines[0].to_raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(1, 0, 0, 100)).digest('hex'));
  assert.equal(result.tail_differences[0].tail_minus_last_snapshot_candidate, -10);
  assert.equal(result.tail_difference_total, -10);
  assert.equal(result.events[0].event_type, 'HERO_GOLD_SPENT_SNAPSHOT_CANDIDATE');
  assert.equal(result.events[0].gold_spent_candidate, 200);
  assert.equal(result.events[10].gold_spent_candidate, 100);
  assert.equal(result.events[0].observation_kind, 'KEYFRAME_SNAPSHOT');
  assert.equal(result.events[0].field_confidence.gold_spent_candidate,
    'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION');
  assert.equal(Object.hasOwn(result, 'tail_gaps'), false);
});

test('gold-spent tail and payload failures do not suppress other HeroStats candidates', () => {
  const missingGoldSpent = fixture();
  assert.equal(assessHeroGoldSpentSnapshotTail(missingGoldSpent).status, 'PASS');
  missingGoldSpent.tail.stats[0].GOLD_SPENT = undefined;
  assert.equal(assessHeroGoldSpentSnapshotTail(missingGoldSpent).status, 'MISSING_INPUT');
  const missing = decodeHeroStatsSnapshotCandidateSet(missingGoldSpent,
    ['hero_minions_killed_snapshot', 'hero_experience_snapshot',
      'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot']);
  assert.equal(missing.hero_gold_spent_snapshot.status, 'MISSING_INPUT');
  assert.equal(missing.hero_minions_killed_snapshot.status, 'CANDIDATE');
  assert.equal(missing.hero_experience_snapshot.status, 'CANDIDATE');
  assert.equal(missing.hero_gold_earned_snapshot.status, 'CANDIDATE');
  missingGoldSpent.tail.stats[0].GOLD_SPENT = '-1';
  assert.equal(assessHeroGoldSpentSnapshotTail(missingGoldSpent).status, 'UNSUPPORTED');

  const malformed = fixture({ goldSpentValues: [Array(10).fill(NaN)],
    goldSpentTails: Array(10).fill(10), times: [0] });
  const results = decodeHeroStatsSnapshotCandidateSet(malformed,
    ['hero_minions_killed_snapshot', 'hero_experience_snapshot',
      'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot']);
  assert.equal(results.hero_gold_spent_snapshot.status, 'DECODE_FAILED');
  assert.equal(results.hero_minions_killed_snapshot.status, 'CANDIDATE');
  assert.equal(results.hero_experience_snapshot.status, 'CANDIDATE');
  assert.equal(results.hero_gold_earned_snapshot.status, 'CANDIDATE');
});

test('gold-spent profile rejects wrong build and foreign 0x0276 keyframe shape', () => {
  assert.equal(decodeHeroGoldSpentSnapshotCandidates(
    fixture({ version: '16.19.820.7194' })).status, 'UNSUPPORTED');
  const foreign = replayFromChunks([{ stream: 2, body: Buffer.concat(
    Array.from({ length: 10 }, (_, index) => blockFor(index + 1, 0, Buffer.from([1, 2]))),
  ) }], '16.19.820.7193');
  const result = decodeHeroGoldSpentSnapshotCandidates(foreign);
  assert.equal(result.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.observed_raw_route_count, 10);
  assert.equal(result.event_count, null);
});

test('combined selection isolates field-specific tail and sequence failures', () => {
  const decreasingXp = fixture({
    experienceValues: [Array(10).fill(3), Array(10).fill(2)],
    experienceTails: Array(10).fill(5),
  });
  const chunks = decreasingXp.chunks;
  let chunkTraversalCount = 0;
  Object.defineProperty(decreasingXp, 'chunks', { get() {
    chunkTraversalCount += 1;
    return chunks;
  } });
  const first = decodeHeroStatsSnapshotCandidateSet(decreasingXp,
    new Set(['hero_experience_snapshot', 'hero_minions_killed_snapshot']));
  assert.equal(chunkTraversalCount, 1);
  assert.equal(first.hero_minions_killed_snapshot.status, 'CANDIDATE');
  assert.equal(first.hero_experience_snapshot.status, 'DECODE_FAILED');
  assert.match(first.hero_experience_snapshot.error, /decreasing observed EXP/);

  const missingCs = fixture();
  missingCs.tail.stats[0].MINIONS_KILLED = undefined;
  const second = decodeHeroStatsSnapshotCandidateSet(missingCs,
    ['hero_minions_killed_snapshot', 'hero_experience_snapshot']);
  assert.equal(second.hero_minions_killed_snapshot.status, 'MISSING_INPUT');
  assert.equal(second.hero_experience_snapshot.status, 'CANDIDATE');
});

test('champion-kills offsets are mirrored candidate integers, not a uniquely located field', () => {
  assert.equal(championKillsProfile.replay_version, '16.19.820.7193');
  assert.equal(championKillsProfile.replay_block_packet_id, 0x0276);
  assert.equal(championKillsProfile.champion_kills_u32le_offset_candidate, 0x4c);
  assert.equal(championKillsProfile.champion_kills_mirror_u32le_offset_candidate, 0x33c);
  assert.equal(championKillsProfile.storage_offset_status,
    'AMBIGUOUS_MIRRORED_COPIES_ONE_REPLAY');
  assert.equal(championKillsProfile.lookup_table_sha256, profile.lookup_table_sha256);
  assert.ok(championKillsProfile.known_limits.some((limit) => /no champion kill event/.test(limit)));
  assert.deepEqual(decodeHeroChampionKillsPayload(payloadFor(0, 0, 0, 0, 7)),
    { status: 'PASS', champion_kills_candidate: 7 });
  const mismatch = decodeHeroChampionKillsPayload(payloadFor(0, 0, 0, 0, 7, 8));
  assert.equal(mismatch.status, 'DECODE_FAILED');
  assert.match(mismatch.error, /0x4c and 0x33c disagree/);
});

test('champion-kills output retains observed keyframe values, raw refs, and tail gaps', () => {
  const championKillsValues = [Array(10).fill(0),
    Array.from({ length: 10 }, (_, index) => index + 1)];
  const replay = fixture({ championKillsValues });
  const result = decodeHeroChampionKillsSnapshotCandidates(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 20);
  assert.equal(result.event_count, 20);
  assert.equal(result.keyframe_timestamp_count, 2);
  assert.equal(result.observed_participant_count, 10);
  assert.equal(result.evidence_status,
    'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_MIRRORED_FIELD_AND_TAIL_BOUND');
  assert.deepEqual(result.observed_max_champion_kills,
    Array.from({ length: 10 }, (_, index) => index + 1));
  assert.deepEqual(result.tail_gaps.map((row) => row.unobserved_tail_gap),
    Array(10).fill(2));
  assert.equal(result.tail_gap_total, 20);
  assert.equal(result.events[0].event_type, 'HERO_CHAMPION_KILLS_SNAPSHOT_CANDIDATE');
  assert.equal(result.events[0].champion_kills_candidate, 0);
  assert.equal(result.events.at(-1).champion_kills_candidate, 10);
  assert.equal(result.events.at(-1).raw_packet_ref.chunk_stream, 'keyframe');
  assert.equal(result.events.at(-1).raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(result.events.at(-1).raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(10, 0, 0, 0, 10)).digest('hex'));
  assert.equal(result.events[0].field_confidence.champion_kills_candidate,
    'CANDIDATE_ONE_REPLAY_MIRRORED_FIELD_AND_TAIL_CORRELATION');
  assert.equal(result.events[0].observation_kind, 'KEYFRAME_SNAPSHOT');
});

test('champion-kills mirror and tail failures remain local to that selected field', () => {
  const missing = fixture();
  assert.equal(assessHeroChampionKillsSnapshotTail(missing).status, 'PASS');
  delete missing.tail.stats[0].CHAMPIONS_KILLED;
  assert.equal(assessHeroChampionKillsSnapshotTail(missing).status, 'MISSING_INPUT');
  const missingResults = decodeHeroStatsSnapshotCandidateSet(missing,
    ['hero_minions_killed_snapshot', 'hero_experience_snapshot',
      'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot',
      'hero_champion_kills_snapshot']);
  assert.equal(missingResults.hero_champion_kills_snapshot.status, 'MISSING_INPUT');
  for (const field of ['hero_minions_killed_snapshot', 'hero_experience_snapshot',
    'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot']) {
    assert.equal(missingResults[field].status, 'CANDIDATE');
  }
  missing.tail.stats[0].CHAMPIONS_KILLED = '-1';
  assert.equal(assessHeroChampionKillsSnapshotTail(missing).status, 'UNSUPPORTED');

  const wrongMirror = fixture({ times: [0],
    championKillsValues: [Array(10).fill(0)],
    championKillsMirrorValues: [[1, ...Array(9).fill(0)]] });
  const mirrorResults = decodeHeroStatsSnapshotCandidateSet(wrongMirror,
    ['hero_minions_killed_snapshot', 'hero_experience_snapshot',
      'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot',
      'hero_champion_kills_snapshot']);
  assert.equal(mirrorResults.hero_champion_kills_snapshot.status, 'DECODE_FAILED');
  assert.match(mirrorResults.hero_champion_kills_snapshot.error, /0x4c and 0x33c disagree/);
  for (const field of ['hero_minions_killed_snapshot', 'hero_experience_snapshot',
    'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot']) {
    assert.equal(mirrorResults[field].status, 'CANDIDATE');
  }
});

test('champion-kills candidate fails on decreases and values above its own tail', () => {
  const declining = fixture({ championKillsValues: [Array(10).fill(3), Array(10).fill(2)],
    championKillsTails: Array(10).fill(5) });
  assert.match(decodeHeroChampionKillsSnapshotCandidates(declining).error,
    /decreasing observed CHAMPIONS_KILLED/);
  const aboveTail = fixture({ championKillsValues: [Array(10).fill(0), Array(10).fill(3)],
    championKillsTails: Array(10).fill(2) });
  assert.match(decodeHeroChampionKillsSnapshotCandidates(aboveTail).error,
    /exceeds Replay tail CHAMPIONS_KILLED/);
});

test('champion-kills candidate rejects wrong build and foreign keyframe shape', () => {
  assert.equal(decodeHeroChampionKillsSnapshotCandidates(
    fixture({ version: '16.19.820.7194' })).status, 'UNSUPPORTED');
  const foreign = replayFromChunks([{ stream: 2, body: Buffer.concat(
    Array.from({ length: 10 }, (_, index) => blockFor(index + 1, 0, Buffer.from([1, 2]))),
  ) }], '16.19.820.7193');
  const result = decodeHeroChampionKillsSnapshotCandidates(foreign);
  assert.equal(result.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.observed_raw_route_count, 10);
  assert.equal(result.event_count, null);
});
