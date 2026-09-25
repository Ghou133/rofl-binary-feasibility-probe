'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { resolveCapability } = require('../src/build_registry');
const {
  HERO_STATS_SNAPSHOT_CAPABILITIES,
  HERO_TOTAL_UNITS_HEALED_SNAPSHOT_CANDIDATE_PROFILE: profile,
  analyzeReplayWithHeroStats,
  assessHeroTotalUnitsHealedSnapshotTail: assessTail,
  decodeHeroStatsByte,
  decodeHeroTotalUnitsHealedPayload: decodePayload,
  decodeHeroTotalUnitsHealedSnapshotCandidates: decodeCandidates,
  decodeHeroStatsSnapshotCandidateSet,
} = require('../src/decoders/rofl_16_19_hero_stats_candidate');
const {
  decodeSemanticReplay,
  getHeroTotalUnitsHealedSnapshotCandidates,
} = require('../src/semantic_api');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_total_units_healed_snapshot';
const TAIL_FIELD = 'TOTAL_UNITS_HEALED';
const CANDIDATE_KEY = 'total_units_healed_candidate';
const ENCODE_BYTE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  ENCODE_BYTE[decodeHeroStatsByte(encoded)] = encoded;
}
assert.ok(ENCODE_BYTE.every((value) => value !== null));

function payloadFor(value, neighbors = 9000) {
  const blob = Buffer.alloc(1260);
  blob.writeUInt32LE(value, 0x23c);
  blob.writeFloatLE(neighbors, 0x238);
  blob.writeFloatLE(neighbors, 0x240);
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
  omitParticipant = null, rows = [Array(10).fill(0),
    [1, 1, 1, 1, 2, 1, 1, 1, 1, 4]] } = {}) {
  const body = Buffer.concat([0, 1000].flatMap((timeMs, timeIndex) =>
    rows[timeIndex].flatMap((value, index) =>
      omitParticipant === index + 1 && timeIndex === 0 ? []
        : [blockFor(index + 1, timeMs,
          malformed && index === 0 && timeIndex === 1 ? Buffer.from([1, 2])
            : payloadFor(value))])));
  const replay = replayFromChunks([{ stream, body }], version);
  replay.tail.stats = rows.at(-1).map((value, index) => ({
    [TAIL_FIELD]: String(value + (index === 9 ? 1 : 0)), ASSISTS: '0',
  }));
  replay.tail.metadata.gameLength = 2000;
  return replay;
}

test('exact HN candidate reads only u32 0x23c and retains its evidence limits', () => {
  assert.ok(HERO_STATS_SNAPSHOT_CAPABILITIES.includes(CAPABILITY));
  assert.equal(profile.status, 'CANDIDATE');
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.total_units_healed_u32le_offset_candidate, 0x23c);
  assert.match(profile.evidence_scope, /three HN Replays/);
  assert.match(profile.known_limits.join(' '), /shift five/);
  assert.deepEqual(decodePayload(payloadFor(5, 9000)),
    { status: 'PASS', [CANDIDATE_KEY]: 5 });
  assert.deepEqual(decodePayload(payloadFor(0xffffffff)),
    { status: 'PASS', [CANDIDATE_KEY]: 0xffffffff });
  const malformed = payloadFor(5);
  malformed[0] = 0x1d;
  assert.equal(decodePayload(malformed).status, 'DECODE_FAILED');
  assert.equal(decodePayload(malformed.subarray(1)).status, 'DECODE_FAILED');
});

test('selected API emits observed u32 snapshots with packet refs and unobserved tail gaps', () => {
  const replay = fixture();
  assert.equal(resolveCapability(replay, CAPABILITY).status, 'CANDIDATE');
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.deepEqual(Object.keys(decoded.events), [`${CAPABILITY}_candidates`]);
  const outcome = decoded.capability_results[CAPABILITY];
  assert.equal(outcome.event_count, 20);
  assert.equal(outcome.keyframe_timestamp_count, 2);
  assert.equal(outcome.observed_participant_count, 10);
  assert.equal(outcome.tail_gap_total, 1);
  assert.deepEqual(outcome.tail_gaps[9], {
    participant_id_candidate: 10,
    last_snapshot_replay_time_ms: 1000,
    last_snapshot_total_units_healed_candidate: 4,
    final_total_units_healed_tail: 5,
    unobserved_tail_gap: 1,
    unobserved_tail_time_ms: 1000,
  });
  const events = getHeroTotalUnitsHealedSnapshotCandidates(decoded);
  assert.equal(events.length, 20);
  const last = events.at(-1);
  assert.equal(last.event_type, 'HERO_TOTAL_UNITS_HEALED_SNAPSHOT_CANDIDATE');
  assert.equal(last.observation_kind, 'KEYFRAME_SNAPSHOT');
  assert.equal(last[CANDIDATE_KEY], 4);
  assert.equal(last.field_confidence[CANDIDATE_KEY],
    'CANDIDATE_THREE_REPLAY_TAIL_CORRELATION');
  assert.equal(last.raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(last.raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(last.raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(4)).digest('hex'));
  for (const key of ['heal_event_time_ms', 'recipient', 'heal_amount']) {
    assert.equal(Object.hasOwn(last, key), false);
  }
});

test('missing or invalid tail, decline, overrun, wrong build and malformed keyframes fail closed', () => {
  assert.equal(assessTail(fixture()).status, 'PASS');
  const missing = fixture();
  delete missing.tail.stats[0][TAIL_FIELD];
  const outcomes = decodeHeroStatsSnapshotCandidateSet(missing,
    [CAPABILITY, 'hero_assists_snapshot']);
  assert.equal(outcomes[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(outcomes.hero_assists_snapshot.status, 'CANDIDATE');
  for (const invalid of ['-1', '4294967296']) {
    const replay = fixture();
    replay.tail.stats[0][TAIL_FIELD] = invalid;
    assert.equal(decodeCandidates(replay).status, 'UNSUPPORTED');
  }
  const overrun = fixture();
  overrun.tail.stats[4][TAIL_FIELD] = '1';
  assert.match(decodeCandidates(overrun).error,
    /exceeds Replay tail TOTAL_UNITS_HEALED/);
  const rows = [Array(10).fill(0), [1, 1, 1, 1, 2, 1, 1, 1, 1, 4]];
  rows[0][0] = 2;
  const declined = fixture({ rows });
  declined.tail.stats[0][TAIL_FIELD] = '2';
  assert.match(decodeCandidates(declined).error,
    /decreasing observed TOTAL_UNITS_HEALED/);
  assert.equal(decodeCandidates(fixture({ version: '16.19.820.7194' })).status,
    'UNSUPPORTED');
  assert.equal(decodeCandidates(fixture({ stream: 1 })).status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decodeCandidates(fixture({ omitParticipant: 3 })).status,
    'DECODE_FAILED');
  assert.equal(decodeCandidates(fixture({ malformed: true })).status,
    'DECODE_FAILED');
});

test('bound precollected scan reuses the same Replay without a second packet walk', () => {
  const replay = fixture();
  const direct = decodeCandidates(replay);
  const { heroStatsScan } = analyzeReplayWithHeroStats(replay, { strict: true });
  Object.defineProperty(replay, 'chunks', { get() {
    throw new Error('precollected scan must avoid Replay walk');
  } });
  assert.deepEqual(decodeHeroStatsSnapshotCandidateSet(replay, [CAPABILITY],
    heroStatsScan)[CAPABILITY], direct);
});

test('CLI capability preflight requires the exact tail field for the candidate', () => {
  const { capabilityQuery } = require('../src/cli');
  const replay = fixture();
  const entry = capabilityQuery(replay).capabilities.find((row) =>
    row.capability === CAPABILITY);
  assert.equal(entry.status, 'CANDIDATE');
  assert.equal(entry.output, `${CAPABILITY}_candidates`);
  assert.equal(entry.runtime_image_requirement, 'NOT_REQUIRED');
  assert.ok(entry.required_inputs.some((input) => input.name ===
    `replay_tail_${TAIL_FIELD}` && input.status === 'PRESENT_UNVALIDATED'));
  delete replay.tail.stats[0][TAIL_FIELD];
  assert.deepEqual(capabilityQuery(replay).capabilities.find((row) =>
    row.capability === CAPABILITY).missing_inputs, [`replay_tail_${TAIL_FIELD}`]);
});
