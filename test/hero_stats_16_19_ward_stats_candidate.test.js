'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  HERO_WARD_STATS_SNAPSHOT_CANDIDATE_PROFILE: profile,
  HERO_STATS_SNAPSHOT_CAPABILITIES,
  analyzeReplayWithHeroStats,
  assessHeroWardStatsSnapshotTail,
  decodeHeroStatsByte,
  decodeHeroWardStatsPayload,
  decodeHeroWardStatsSnapshotCandidates,
  decodeHeroStatsSnapshotCandidateSet,
} = require('../src/decoders/rofl_16_19_hero_stats_candidate');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_ward_stats_snapshot';
const OUTPUT = 'hero_ward_stats_snapshot_candidates';
const FIELDS = [
  ['WARD_PLACED', 'ward_placed_candidate', 0x1a4],
  ['WARD_KILLED', 'ward_killed_candidate', 0x1a8],
  ['WARD_PLACED_DETECTOR', 'ward_placed_detector_candidate', 0x1ac],
];

// Synthetic inverse only. Production decoding remains bound to the exact-image transform.
const ENCODE_BYTE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  ENCODE_BYTE[decodeHeroStatsByte(encoded)] = encoded;
}
assert.ok(ENCODE_BYTE.every((value) => value !== null));

function valueRow(value = 0) {
  return Object.fromEntries(FIELDS.map(([, key]) => [key, value]));
}

function payloadFor(values = valueRow()) {
  const blob = Buffer.alloc(1260);
  for (const [, key, offset] of FIELDS) blob.writeUInt32LE(values[key] ?? 0, offset);
  const payload = Buffer.alloc(1263);
  payload.set([0x1c, 0xa6, 0xe8]);
  for (let index = 0; index < blob.length; index += 1) {
    payload[index + 3] = ENCODE_BYTE[blob[blob.length - 1 - index]];
  }
  return payload;
}

function blockFor(participantId, timeMs, payload, packetId = 0x0276) {
  const header = Buffer.alloc(15);
  header[0] = 0;
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(0x400000ad + participantId, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ times = [0, 1000], values, tails, version = BUILD, stream = 2,
  extraBlocks = [], omitParticipant = null } = {}) {
  const rows = values ?? times.map((_, timeIndex) => Array.from({ length: 10 }, (__, index) =>
    timeIndex === 0 ? valueRow() : {
      ward_placed_candidate: index + 1,
      ward_killed_candidate: index % 4,
      ward_placed_detector_candidate: index % 3,
    }));
  const body = Buffer.concat([
    ...times.flatMap((timeMs, timeIndex) => rows[timeIndex].flatMap((row, index) =>
      omitParticipant === index + 1 && timeIndex === 0 ? []
        : [blockFor(index + 1, timeMs, payloadFor(row))])),
    ...extraBlocks,
  ]);
  const replay = replayFromChunks([{ stream, body }], version);
  replay.tail.stats = (tails ?? rows.at(-1).map((row, index) =>
    Object.fromEntries(FIELDS.map(([tailField, key]) =>
      [tailField, row[key] + (tailField === 'WARD_PLACED' && index === 1 ? 1 : 0)]))))
    .map((row) => Object.fromEntries(Object.entries(row).map(([key, value]) =>
      [key, String(value)])));
  for (const row of replay.tail.stats) row.ASSISTS = '0';
  replay.tail.metadata.gameLength = times.at(-1) + 1000;
  return replay;
}

function writeReplayWithTailStats(replay, outputPath) {
  const original = replay.buffer;
  const metadataLength = original.readUInt32LE(original.length - 4);
  const metadata = Buffer.from(JSON.stringify({ ...replay.tail.metadata,
    statsJson: JSON.stringify(replay.tail.stats) }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  fs.writeFileSync(outputPath, Buffer.concat([
    original.subarray(0, original.length - metadataLength - 4), metadata, trailer,
  ]));
}

test('profile pins three candidate u32 offsets and limits the output to observed snapshots', () => {
  assert.ok(HERO_STATS_SNAPSHOT_CAPABILITIES.includes(CAPABILITY));
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.replay_block_packet_id, 0x0276);
  assert.equal(profile.status, 'CANDIDATE');
  for (const [, key, offset] of FIELDS) {
    assert.equal(profile[`${key.replace(/_candidate$/, '')}_u32le_offset_candidate`], offset);
  }
  assert.match(profile.evidence_scope, /one HN Replay/);
  assert.ok(profile.known_limits.some((limit) => /no ward placement.*event/.test(limit)));
  assert.deepEqual(decodeHeroWardStatsPayload(payloadFor({
    ward_placed_candidate: 17,
    ward_killed_candidate: 3,
    ward_placed_detector_candidate: 2,
  })), {
    status: 'PASS', ward_placed_candidate: 17, ward_killed_candidate: 3,
    ward_placed_detector_candidate: 2,
  });
  const badPrefix = payloadFor();
  badPrefix[0] = 0x1d;
  assert.equal(decodeHeroWardStatsPayload(badPrefix).status, 'DECODE_FAILED');
  assert.equal(decodeHeroWardStatsPayload(badPrefix.subarray(1)).status, 'DECODE_FAILED');
});

test('observed keyframes retain three raw counts, provenance, and the placement tail gap', () => {
  const replay = fixture();
  const result = decodeHeroWardStatsSnapshotCandidates(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 20);
  assert.equal(result.input_count, 20);
  assert.equal(result.keyframe_timestamp_count, 2);
  assert.equal(result.observed_participant_count, 10);
  assert.equal(result.evidence_status, 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_THREE_FIELD_TAIL_BOUND');
  assert.deepEqual(result.tail_gap_totals,
    { WARD_PLACED: 1, WARD_KILLED: 0, WARD_PLACED_DETECTOR: 0 });
  assert.deepEqual(result.tail_gaps[1].field_gaps.WARD_PLACED,
    { last_snapshot_candidate: 2, final_tail: 3, unobserved_tail_gap: 1 });
  assert.equal(result.tail_gaps[1].unobserved_tail_time_ms, 1000);
  const last = result.events.at(-1);
  assert.equal(last.event_type, 'HERO_WARD_STATS_SNAPSHOT_CANDIDATE');
  assert.equal(last.observation_kind, 'KEYFRAME_SNAPSHOT');
  assert.equal(last.confidence, 'CANDIDATE');
  assert.equal(last.raw_packet_ref.packet_id, 0x0276);
  assert.equal(last.raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(last.raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(last.raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor({ ward_placed_candidate: 10,
      ward_killed_candidate: 1, ward_placed_detector_candidate: 0 })).digest('hex'));
  for (const [, key] of FIELDS) {
    assert.equal(last.field_confidence[key], 'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION');
  }
  assert.equal(Object.hasOwn(last, 'ward_event_time_ms'), false);
  assert.equal(Object.hasOwn(last, 'ward_location'), false);
});

test('all three tail fields are required and failures stay local to the selected capability', () => {
  const replay = fixture();
  assert.deepEqual(assessHeroWardStatsSnapshotTail(replay).required_fields.map((row) => row.field),
    FIELDS.map(([field]) => field));
  for (const [field] of FIELDS) {
    const missing = fixture();
    delete missing.tail.stats[0][field];
    assert.equal(assessHeroWardStatsSnapshotTail(missing).status, 'MISSING_INPUT');
    const outcomes = decodeHeroStatsSnapshotCandidateSet(missing,
      [CAPABILITY, 'hero_assists_snapshot']);
    assert.equal(outcomes[CAPABILITY].status, 'MISSING_INPUT');
    assert.equal(outcomes.hero_assists_snapshot.status, 'CANDIDATE');
    const invalid = fixture();
    invalid.tail.stats[0][field] = '-1';
    assert.equal(decodeHeroWardStatsSnapshotCandidates(invalid).status, 'UNSUPPORTED');
    const beyondU32 = fixture();
    beyondU32.tail.stats[0][field] = '4294967296';
    assert.equal(decodeHeroWardStatsSnapshotCandidates(beyondU32).status, 'UNSUPPORTED');
  }
  const noTail = fixture();
  noTail.tail.stats = null;
  assert.equal(decodeHeroWardStatsSnapshotCandidates(noTail).status, 'MISSING_INPUT');
});

test('each count rejects decreases and Replay-tail overruns independently', () => {
  for (const [field, key] of FIELDS) {
    const first = Array.from({ length: 10 }, () => valueRow(3));
    const second = Array.from({ length: 10 }, () => valueRow(3));
    second[0][key] = 2;
    const tails = Array.from({ length: 10 }, () =>
      Object.fromEntries(FIELDS.map(([tailField]) => [tailField, 5])));
    const decreasing = decodeHeroWardStatsSnapshotCandidates(fixture({
      values: [first, second], tails,
    }));
    assert.equal(decreasing.status, 'DECODE_FAILED', field);
    assert.match(decreasing.error, new RegExp(`decreasing observed ${field}`));
    const aboveTail = fixture();
    aboveTail.tail.stats[1][field] = '0';
    const overrun = decodeHeroWardStatsSnapshotCandidates(aboveTail);
    assert.equal(overrun.status, 'DECODE_FAILED', field);
    assert.match(overrun.error, new RegExp(`exceeds Replay tail ${field}`));
    assert.equal(overrun.events, null);
  }
});

test('wrong build, foreign route, malformed packet, source mutation, and incomplete roster fail closed', () => {
  assert.equal(decodeHeroWardStatsSnapshotCandidates(
    fixture({ version: '16.19.820.7194' })).status, 'UNSUPPORTED');
  assert.equal(decodeHeroWardStatsSnapshotCandidates(fixture({ stream: 1 })).status,
    'PROFILE_UNAVAILABLE');
  const foreign = replayFromChunks([{ stream: 2, body: Buffer.concat(
    Array.from({ length: 10 }, (_, index) =>
      blockFor(index + 1, 0, Buffer.from([1, 2]))),
  ) }], BUILD);
  assert.equal(decodeHeroWardStatsSnapshotCandidates(foreign).status, 'PROFILE_UNAVAILABLE');
  const mixed = fixture({ times: [0], extraBlocks: [blockFor(1, 0, Buffer.from([1, 2]))] });
  assert.equal(decodeHeroWardStatsSnapshotCandidates(mixed).status, 'DECODE_FAILED');
  const tampered = fixture();
  tampered.buffer[0] = 0;
  assert.match(decodeHeroWardStatsSnapshotCandidates(tampered).error, /Replay source failed/);
  const missingHero = fixture({ times: [0], omitParticipant: 3 });
  assert.match(decodeHeroWardStatsSnapshotCandidates(missingHero).error,
    /lacks one or more hero params/);
});

test('bound HeroStats scan reuses observations without a second chunk walk', () => {
  const replay = fixture();
  const standalone = decodeHeroWardStatsSnapshotCandidates(replay);
  const { heroStatsScan } = analyzeReplayWithHeroStats(replay, { strict: true });
  Object.defineProperty(replay, 'chunks', { get() {
    throw new Error('precollected decode must not scan Replay chunks');
  } });
  assert.deepEqual(decodeHeroStatsSnapshotCandidateSet(replay, [CAPABILITY], heroStatsScan)[CAPABILITY],
    standalone);
});

test('selected API and capability query expose only bounded candidate snapshots', () => {
  const { decodeSemanticReplay, getHeroWardStatsSnapshotCandidates } = require('../src/semantic_api');
  const { capabilityQuery } = require('../src/cli');
  const replay = fixture();
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.deepEqual(Object.keys(decoded.events), [OUTPUT]);
  assert.equal(getHeroWardStatsSnapshotCandidates(decoded).length, 20);
  assert.equal(decoded.events.ward_events, undefined);
  const row = capabilityQuery(replay).capabilities.find((entry) => entry.capability === CAPABILITY);
  assert.equal(row.status, 'CANDIDATE');
  assert.equal(row.output, OUTPUT);
  assert.deepEqual(row.required_inputs.map((input) => input.name), [
    'replay', 'replay_tail_statsJson', ...FIELDS.map(([field]) => `replay_tail_${field}`),
  ]);
  assert.deepEqual(row.missing_inputs, []);
  delete replay.tail.stats[2].WARD_KILLED;
  assert.deepEqual(capabilityQuery(replay).capabilities
    .find((entry) => entry.capability === CAPABILITY).missing_inputs,
  ['replay_tail_WARD_KILLED']);
});

test('selected CLI writes three-count snapshot candidates as JSONL', async (t) => {
  const { main } = require('../src/cli');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-ward-stats-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailStats(fixture(), input);
  assert.equal(await main(['decode', input, '--events', CAPABILITY, '--out-dir', output]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDirectory = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[CAPABILITY].tail_gap_totals.WARD_PLACED, 1);
  const rows = fs.readFileSync(path.join(replayDirectory, `${OUTPUT}.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(rows.length, 20);
  assert.equal(rows.at(-1).ward_placed_candidate, 10);
  assert.equal(rows.at(-1).ward_killed_candidate, 1);
  assert.equal(rows.at(-1).raw_packet_ref.packet_id, 0x0276);
});
