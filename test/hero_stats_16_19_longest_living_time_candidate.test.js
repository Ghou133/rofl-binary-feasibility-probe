'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { capabilityQuery } = require('../src/cli');
const { resolveCapability } = require('../src/build_registry');
const {
  HERO_STATS_SNAPSHOT_CAPABILITIES,
  HERO_LONGEST_LIVING_TIME_SNAPSHOT_CANDIDATE_PROFILE: profile,
  analyzeReplayWithHeroStats,
  assessHeroLongestLivingTimeSnapshotTail: assessTail,
  decodeHeroStatsByte,
  decodeHeroLongestLivingTimePayload: decodePayload,
  decodeHeroLongestLivingTimeSnapshotCandidates: decodeCandidates,
  decodeHeroStatsSnapshotCandidateSet,
} = require('../src/decoders/rofl_16_19_hero_stats_candidate');
const {
  decodeSemanticReplay,
  getHeroLongestLivingTimeSnapshotCandidates,
} = require('../src/semantic_api');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_longest_living_time_snapshot';
const TAIL_FIELD = 'LONGEST_TIME_SPENT_LIVING';
const RAW_KEY = 'longest_living_time_raw_f32_candidate';
const FLOOR_KEY = 'longest_living_time_floor_candidate';
const ENCODE_BYTE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  ENCODE_BYTE[decodeHeroStatsByte(encoded)] = encoded;
}
assert.ok(ENCODE_BYTE.every((value) => value !== null));

function payloadFor(value, neighbors = 0) {
  const blob = Buffer.alloc(1260);
  blob.writeFloatLE(value, 0x244);
  blob.writeFloatLE(neighbors, 0x240);
  blob.writeFloatLE(neighbors, 0x248);
  const payload = Buffer.alloc(1263);
  payload.set([0x1c, 0xa6, 0xe8]);
  for (let index = 0; index < blob.length; index += 1) {
    payload[index + 3] = ENCODE_BYTE[blob[blob.length - 1 - index]];
  }
  return payload;
}

function blockFor(participantId, timeMs, payload) {
  const header = Buffer.alloc(15);
  header[0] = 0;
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0276, 9);
  header.writeUInt32LE(0x400000ad + participantId, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, stream = 2, malformed = false,
  omitParticipant = null, rows = [Array(10).fill(0), Array.from({ length: 10 },
    (_, index) => index === 4 ? 0 : (index + 1) * 5 + 0.25)] } = {}) {
  const body = Buffer.concat([0, 1000].flatMap((timeMs, timeIndex) => rows[timeIndex]
    .flatMap((value, index) => omitParticipant === index + 1 && timeIndex === 0 ? []
      : [blockFor(index + 1, timeMs,
        malformed && index === 0 && timeIndex === 1 ? Buffer.from([1, 2])
          : payloadFor(value, 9000))])));
  const replay = replayFromChunks([{ stream, body }], version);
  replay.tail.stats = rows.at(-1).map((value, index) => ({
    [TAIL_FIELD]: String(index === 4 ? 1706 : Math.floor(value)),
  }));
  replay.tail.metadata.gameLength = 2000;
  return replay;
}

test('exact HN profile selects decoded f32 0x244 and rejects invalid scalars', () => {
  assert.ok(HERO_STATS_SNAPSHOT_CAPABILITIES.includes(CAPABILITY));
  assert.equal(profile.capability, CAPABILITY);
  assert.equal(profile.status, 'CANDIDATE');
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.longest_living_time_f32le_offset_candidate, 0x244);
  assert.match(profile.evidence_scope, /three HN Replays/);
  assert.match(profile.known_limits.join(' '), /third Replay participant 5/);
  assert.deepEqual(decodePayload(payloadFor(17.75, 9000)), {
    status: 'PASS', [RAW_KEY]: 17.75, [FLOOR_KEY]: 17,
  });
  for (const value of [-1, Infinity, NaN, 2 ** 53]) {
    assert.equal(decodePayload(payloadFor(value)).status, 'DECODE_FAILED');
  }
  const malformed = payloadFor(17.75);
  malformed[0] = 0x1d;
  assert.equal(decodePayload(malformed).status, 'DECODE_FAILED');
});

test('opt-in API retains raw f32, floor, packet provenance and a late tail gap', () => {
  const replay = fixture();
  assert.equal(resolveCapability(replay, CAPABILITY).status, 'CANDIDATE');
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.deepEqual(Object.keys(decoded.events), [`${CAPABILITY}_candidates`]);
  const outcome = decoded.capability_results[CAPABILITY];
  assert.equal(outcome.status, 'CANDIDATE');
  assert.equal(outcome.event_count, 20);
  assert.equal(outcome.keyframe_timestamp_count, 2);
  assert.equal(outcome.observed_participant_count, 10);
  assert.equal(outcome.tail_gap_total, 1706);
  assert.deepEqual(outcome.tail_gaps[4], {
    participant_id_candidate: 5,
    last_snapshot_replay_time_ms: 1000,
    last_snapshot_raw_f32_candidate: 0,
    last_snapshot_floor_candidate: 0,
    final_tail: 1706,
    unobserved_tail_floor_gap: 1706,
    unobserved_tail_time_ms: 1000,
  });
  const events = getHeroLongestLivingTimeSnapshotCandidates(decoded);
  assert.equal(events.length, 20);
  const last = events.at(-1);
  assert.equal(last.event_type, 'HERO_LONGEST_LIVING_TIME_SNAPSHOT_CANDIDATE');
  assert.equal(last[RAW_KEY], 50.25);
  assert.equal(last[FLOOR_KEY], 50);
  assert.equal(last.field_confidence[RAW_KEY], 'CANDIDATE_THREE_REPLAY_TAIL_CORRELATION');
  assert.equal(last.field_confidence[FLOOR_KEY], 'DERIVED_FROM_CANDIDATE');
  assert.equal(last.raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(last.raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(last.raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(50.25, 9000)).digest('hex'));
  for (const key of ['death_time_ms', 'life_span_ms', 'death_duration_ms']) {
    assert.equal(Object.hasOwn(last, key), false);
  }
});

test('missing tail, overrun, decline, wrong build and incomplete roster fail closed', () => {
  const replay = fixture();
  assert.equal(assessTail(replay).status, 'PASS');
  delete replay.tail.stats[0][TAIL_FIELD];
  assert.equal(decodeCandidates(replay).status, 'MISSING_INPUT');
  replay.tail.stats[0][TAIL_FIELD] = '-1';
  assert.equal(decodeCandidates(replay).status, 'UNSUPPORTED');

  const overrun = fixture();
  overrun.tail.stats[0][TAIL_FIELD] = '0';
  assert.match(decodeCandidates(overrun).error, /exceeds Replay tail LONGEST_TIME_SPENT_LIVING/);
  const rows = [Array(10).fill(0), Array.from({ length: 10 },
    (_, index) => index === 4 ? 0 : (index + 1) * 5 + 0.25)];
  rows[0][0] = 9.5;
  rows[1][0] = 8.5;
  const decline = fixture({ rows });
  decline.tail.stats[0][TAIL_FIELD] = '100';
  assert.match(decodeCandidates(decline).error,
    /decreasing observed LONGEST_TIME_SPENT_LIVING/);
  assert.equal(decodeCandidates(fixture({ version: '16.19.820.7194' })).status,
    'UNSUPPORTED');
  assert.equal(decodeCandidates(fixture({ stream: 1 })).status, 'PROFILE_UNAVAILABLE');
  assert.equal(decodeCandidates(fixture({ omitParticipant: 3 })).status, 'DECODE_FAILED');
  assert.equal(decodeCandidates(fixture({ malformed: true })).status, 'DECODE_FAILED');
});

test('precollected same-Replay HeroStats scan yields the direct candidate result', () => {
  const replay = fixture();
  const direct = decodeCandidates(replay);
  const { heroStatsScan } = analyzeReplayWithHeroStats(replay, { strict: true });
  Object.defineProperty(replay, 'chunks', { get() {
    throw new Error('precollected scan must avoid Replay walk');
  } });
  const reused = decodeHeroStatsSnapshotCandidateSet(replay, [CAPABILITY],
    heroStatsScan)[CAPABILITY];
  assert.deepEqual(reused, direct);
});

test('CLI preflight names the candidate output and reports missing tail values', () => {
  const replay = fixture();
  const ready = capabilityQuery(replay).capabilities.find((row) => row.capability === CAPABILITY);
  assert.equal(ready.status, 'CANDIDATE');
  assert.equal(ready.output, `${CAPABILITY}_candidates`);
  assert.deepEqual(ready.missing_inputs, []);
  assert.ok(ready.required_inputs.some((input) => input.name ===
    `replay_tail_${TAIL_FIELD}` && input.status === 'PRESENT_UNVALIDATED'));
  delete replay.tail.stats[0][TAIL_FIELD];
  const missing = capabilityQuery(replay).capabilities.find((row) => row.capability === CAPABILITY);
  assert.deepEqual(missing.missing_inputs, [`replay_tail_${TAIL_FIELD}`]);
});
