'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  HERO_TOTAL_HEAL_SNAPSHOT_CANDIDATE_PROFILE: profile,
  HERO_STATS_SNAPSHOT_CAPABILITIES,
  analyzeReplayWithHeroStats,
  assessHeroTotalHealSnapshotTail,
  decodeHeroStatsByte,
  decodeHeroStatsSnapshotCandidateSet,
  decodeHeroTotalHealPayload,
  decodeHeroTotalHealSnapshotCandidates,
} = require('../src/decoders/rofl_16_19_hero_stats_candidate');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_total_heal_snapshot';
const IMAGE_SHA = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';
const ENCODE_BYTE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  ENCODE_BYTE[decodeHeroStatsByte(encoded)] = encoded;
}
assert.ok(ENCODE_BYTE.every((value) => value !== null));

function payloadFor(totalHeal = 0) {
  const blob = Buffer.alloc(1260);
  blob.writeUInt32LE(totalHeal, 0x234);
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
  const rows = values ?? times.map((_, timeIndex) => Array.from({ length: 10 },
    (__, index) => timeIndex === 0 ? 0 : (index + 1) * 100));
  const body = Buffer.concat([
    ...times.flatMap((timeMs, timeIndex) => rows[timeIndex].flatMap((value, index) =>
      omitParticipant === index + 1 && timeIndex === 0 ? []
        : [blockFor(index + 1, timeMs, payloadFor(value))])),
    ...extraBlocks,
  ]);
  const replay = replayFromChunks([{ stream, body }], version);
  replay.tail.stats = (tails ?? rows.at(-1).map((value, index) =>
    value + (index === 1 ? 4 : 0))).map((value) => ({
    TOTAL_HEAL: String(value), ASSISTS: '0',
  }));
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

test('exact-build profile and payload expose only candidate u32 total heal', () => {
  assert.ok(HERO_STATS_SNAPSHOT_CAPABILITIES.includes(CAPABILITY));
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.status, 'CANDIDATE');
  assert.equal(profile.replay_block_packet_id, 0x0276);
  assert.equal(profile.payload_length, 1263);
  assert.equal(profile.total_heal_u32le_offset_candidate, 0x234);
  assert.equal(profile.evidence_runtime_image_sha256, IMAGE_SHA);
  assert.match(profile.evidence_scope, /one HN Replay/);
  assert.ok(profile.known_limits.some((limit) => /effective healing/.test(limit)));
  assert.deepEqual(decodeHeroTotalHealPayload(payloadFor(4294967295)),
    { status: 'PASS', total_heal_candidate: 4294967295 });
  const malformed = payloadFor(17);
  malformed[0] = 0x1d;
  assert.equal(decodeHeroTotalHealPayload(malformed).status, 'DECODE_FAILED');
  assert.equal(decodeHeroTotalHealPayload(malformed.subarray(1)).status, 'DECODE_FAILED');
});

test('keyframes retain observed values, raw packet reference, and unobserved tail gap', () => {
  const replay = fixture();
  const result = decodeHeroTotalHealSnapshotCandidates(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 20);
  assert.equal(result.input_count, 20);
  assert.equal(result.keyframe_timestamp_count, 2);
  assert.equal(result.observed_participant_count, 10);
  assert.equal(result.evidence_status,
    'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_TOTAL_HEAL_TAIL_CORRELATION');
  assert.deepEqual(result.tail_gaps[1], {
    participant_id_candidate: 2,
    last_snapshot_replay_time_ms: 1000,
    last_snapshot_total_heal_candidate: 200,
    final_total_heal_tail: 204,
    unobserved_tail_gap: 4,
    unobserved_tail_time_ms: 1000,
  });
  assert.equal(result.tail_gap_total, 4);
  const last = result.events.at(-1);
  assert.equal(last.event_type, 'HERO_TOTAL_HEAL_SNAPSHOT_CANDIDATE');
  assert.equal(last.observation_kind, 'KEYFRAME_SNAPSHOT');
  assert.equal(last.confidence, 'CANDIDATE');
  assert.equal(last.total_heal_candidate, 1000);
  assert.equal(last.participant_id_candidate, 10);
  assert.equal(last.raw_packet_ref.packet_id, 0x0276);
  assert.equal(last.raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(last.raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(last.raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(1000)).digest('hex'));
  assert.equal(last.field_confidence.total_heal_candidate,
    'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION');
  for (const key of ['heal_event_time_ms', 'recipient', 'hp_change',
    'effective_heal_amount', 'overheal_amount']) assert.equal(Object.hasOwn(last, key), false);
});

test('required tail, u32 range, monotonicity, and tail bound fail closed for this capability', () => {
  assert.equal(assessHeroTotalHealSnapshotTail(fixture()).status, 'PASS');
  const missing = fixture();
  delete missing.tail.stats[0].TOTAL_HEAL;
  const outcomes = decodeHeroStatsSnapshotCandidateSet(missing,
    [CAPABILITY, 'hero_assists_snapshot']);
  assert.equal(outcomes[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(outcomes.hero_assists_snapshot.status, 'CANDIDATE');
  const noTail = fixture();
  noTail.tail.stats = null;
  assert.equal(decodeHeroTotalHealSnapshotCandidates(noTail).status, 'MISSING_INPUT');
  for (const invalid of ['-1', '4294967296']) {
    const replay = fixture();
    replay.tail.stats[0].TOTAL_HEAL = invalid;
    assert.equal(decodeHeroTotalHealSnapshotCandidates(replay).status, 'UNSUPPORTED');
  }
  const decreasing = fixture({ values: [Array(10).fill(30),
    [20, ...Array(9).fill(30)]], tails: Array(10).fill(40) });
  const declined = decodeHeroTotalHealSnapshotCandidates(decreasing);
  assert.equal(declined.status, 'DECODE_FAILED');
  assert.match(declined.error, /decreasing observed TOTAL_HEAL/);
  assert.equal(declined.events, null);
  const overrun = fixture();
  overrun.tail.stats[0].TOTAL_HEAL = '99';
  const bounded = decodeHeroTotalHealSnapshotCandidates(overrun);
  assert.equal(bounded.status, 'DECODE_FAILED');
  assert.match(bounded.error, /exceeds Replay tail TOTAL_HEAL/);
  assert.equal(bounded.events, null);
});

test('wrong build, foreign stream/shape, malformed row, source mutation and incomplete roster fail closed', () => {
  assert.equal(decodeHeroTotalHealSnapshotCandidates(
    fixture({ version: '16.19.820.7194' })).status, 'UNSUPPORTED');
  assert.equal(decodeHeroTotalHealSnapshotCandidates(fixture({ stream: 1 })).status,
    'PROFILE_UNAVAILABLE');
  const foreign = replayFromChunks([{ stream: 2, body: Buffer.concat(
    Array.from({ length: 10 }, (_, index) =>
      blockFor(index + 1, 0, Buffer.from([1, 2]))),
  ) }], BUILD);
  assert.equal(decodeHeroTotalHealSnapshotCandidates(foreign).status,
    'PROFILE_UNAVAILABLE');
  const mixed = fixture({ times: [0], extraBlocks: [blockFor(1, 0, Buffer.from([1, 2]))] });
  assert.equal(decodeHeroTotalHealSnapshotCandidates(mixed).status, 'DECODE_FAILED');
  const tampered = fixture();
  tampered.buffer[0] = 0;
  assert.match(decodeHeroTotalHealSnapshotCandidates(tampered).error,
    /Replay source failed/);
  const missingHero = fixture({ times: [0], omitParticipant: 3 });
  assert.match(decodeHeroTotalHealSnapshotCandidates(missingHero).error,
    /lacks one or more hero params/);
});

test('bound precollected scan yields identical output without walking chunks again', () => {
  const replay = fixture();
  const standalone = decodeHeroTotalHealSnapshotCandidates(replay);
  const { heroStatsScan } = analyzeReplayWithHeroStats(replay, { strict: true });
  Object.defineProperty(replay, 'chunks', { get() {
    throw new Error('precollected decode must not rescan Replay chunks');
  } });
  assert.deepEqual(decodeHeroStatsSnapshotCandidateSet(replay, [CAPABILITY], heroStatsScan)[CAPABILITY],
    standalone);
});

test('selected API and capability query expose only the candidate with its tail dependency', () => {
  const { decodeSemanticReplay, getHeroTotalHealSnapshotCandidates } = require('../src/semantic_api');
  const { capabilityQuery } = require('../src/cli');
  const replay = fixture();
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].event_count, 20);
  assert.deepEqual(Object.keys(decoded.events), ['hero_total_heal_snapshot_candidates']);
  assert.equal(getHeroTotalHealSnapshotCandidates(decoded).at(-1).total_heal_candidate, 1000);
  assert.equal(decoded.events.heal_events, undefined);
  const row = capabilityQuery(replay).capabilities.find((entry) => entry.capability === CAPABILITY);
  assert.equal(row.output, 'hero_total_heal_snapshot_candidates');
  assert.equal(row.runtime_image_requirement, 'NOT_REQUIRED');
  assert.deepEqual(row.required_inputs.map((input) => input.name),
    ['replay', 'replay_tail_statsJson', 'replay_tail_TOTAL_HEAL']);
  delete replay.tail.stats[0].TOTAL_HEAL;
  assert.deepEqual(capabilityQuery(replay).capabilities
    .find((entry) => entry.capability === CAPABILITY).missing_inputs,
  ['replay_tail_TOTAL_HEAL']);
});

test('selected CLI writes bounded total-heal candidate JSONL with packet provenance', async (t) => {
  const { main } = require('../src/cli');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-total-heal-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailStats(fixture(), input);
  assert.equal(await main(['decode', input, '--events', CAPABILITY, '--out-dir', output]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDir = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDir, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[CAPABILITY].tail_gap_total, 4);
  const rows = fs.readFileSync(path.join(replayDir, 'hero_total_heal_snapshot_candidates.jsonl'), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(rows.length, 20);
  assert.equal(rows.at(-1).total_heal_candidate, 1000);
  assert.equal(rows.at(-1).raw_packet_ref.replay_sha256,
    crypto.createHash('sha256').update(fs.readFileSync(input)).digest('hex'));
});
