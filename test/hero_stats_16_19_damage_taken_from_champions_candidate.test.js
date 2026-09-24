'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  HERO_STATS_SNAPSHOT_CAPABILITIES,
  HERO_DAMAGE_TAKEN_FROM_CHAMPIONS_SNAPSHOT_CANDIDATE_PROFILE: profile,
  assessHeroDamageTakenFromChampionsSnapshotTail: assessTail,
  decodeHeroStatsByte,
  decodeHeroDamageTakenFromChampionsPayload: decodePayload,
  decodeHeroDamageTakenFromChampionsSnapshotCandidates: decodeCandidates,
  decodeHeroStatsSnapshotCandidateSet,
} = require('../src/decoders/rofl_16_19_hero_stats_candidate');
const {
  decodeSemanticReplay,
  getHeroDamageTakenFromChampionsSnapshotCandidates,
} = require('../src/semantic_api');
const { capabilityQuery, main } = require('../src/cli');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_damage_taken_from_champions_snapshot';
const TAIL_FIELD = 'TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS';
const RAW_KEY = 'damage_taken_from_champions_raw_f32_candidate';
const FLOOR_KEY = 'damage_taken_from_champions_floor_candidate';
const ENCODE_BYTE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  ENCODE_BYTE[decodeHeroStatsByte(encoded)] = encoded;
}
assert.ok(ENCODE_BYTE.every((value) => value !== null));

function payloadFor(value, adjacent = 0) {
  const blob = Buffer.alloc(1260);
  blob.writeFloatLE(value, 0x200);
  blob.writeFloatLE(adjacent, 0x1f0);
  blob.writeFloatLE(adjacent, 0x208);
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

function defaultRows() {
  return [Array(10).fill(0), Array.from({ length: 10 }, (_, index) =>
    (index + 1) * 3 + 0.5)];
}

function fixture({ rows = defaultRows(), version = BUILD, stream = 2,
  omitParticipant = null, extraBlocks = [] } = {}) {
  const body = Buffer.concat([
    ...[0, 1000].flatMap((timeMs, timeIndex) => rows[timeIndex].flatMap((value, index) =>
      omitParticipant === index + 1 && timeIndex === 0 ? []
        : [blockFor(index + 1, timeMs, payloadFor(value, 1000))])),
    ...extraBlocks,
  ]);
  const replay = replayFromChunks([{ stream, body }], version);
  replay.tail.stats = rows.at(-1).map((value, index) => ({
    [TAIL_FIELD]: String(Math.floor(value) + (index === 1 ? 1 : 0)),
    VISION_SCORE: '0',
  }));
  replay.tail.metadata.gameLength = 2000;
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

test('exact HN 0x200 candidate decodes the observed f32 independently of adjacent offsets', () => {
  assert.ok(HERO_STATS_SNAPSHOT_CAPABILITIES.includes(CAPABILITY));
  assert.equal(profile.capability, CAPABILITY);
  assert.equal(profile.status, 'CANDIDATE');
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.damage_taken_from_champions_f32le_offset_candidate, 0x200);
  assert.match(profile.evidence_scope, /two HN Replays/);
  assert.match(profile.known_limits.join(' '), /no individual damage event/);
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

test('candidate snapshots retain packet provenance, raw value, floor, and tail gap', () => {
  const replay = fixture();
  const outcome = decodeCandidates(replay);
  assert.equal(outcome.status, 'CANDIDATE');
  assert.equal(outcome.event_count, 20);
  assert.equal(outcome.keyframe_timestamp_count, 2);
  assert.equal(outcome.observed_participant_count, 10);
  assert.equal(outcome.tail_gap_total, 1);
  assert.deepEqual(outcome.tail_gaps[1], {
    participant_id_candidate: 2,
    last_snapshot_replay_time_ms: 1000,
    last_snapshot_raw_f32_candidate: 6.5,
    last_snapshot_floor_candidate: 6,
    final_tail: 7,
    unobserved_tail_floor_gap: 1,
    unobserved_tail_time_ms: 1000,
  });
  const last = outcome.events.at(-1);
  assert.equal(last.event_type, 'HERO_DAMAGE_TAKEN_FROM_CHAMPIONS_SNAPSHOT_CANDIDATE');
  assert.equal(last[RAW_KEY], 30.5);
  assert.equal(last[FLOOR_KEY], 30);
  assert.equal(last.confidence, 'CANDIDATE');
  assert.equal(last.field_confidence[RAW_KEY], 'CANDIDATE_TWO_REPLAY_TAIL_CORRELATION');
  assert.equal(last.field_confidence[FLOOR_KEY], 'DERIVED_FROM_CANDIDATE');
  assert.equal(last.raw_packet_ref.packet_id, 0x0276);
  assert.equal(last.raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(last.raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(last.raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(30.5, 1000)).digest('hex'));
  for (const key of ['damage_event_time_ms', 'source_participant_id',
    'target_network_id', 'mitigation_amount']) {
    assert.equal(Object.hasOwn(last, key), false);
  }
});

test('tail input, bound, monotonicity, build, and keyframe roster fail closed', () => {
  const replay = fixture();
  assert.equal(assessTail(replay).status, 'PASS');
  delete replay.tail.stats[0][TAIL_FIELD];
  const selected = decodeHeroStatsSnapshotCandidateSet(replay,
    [CAPABILITY, 'hero_vision_score_snapshot']);
  assert.equal(selected[CAPABILITY].status, 'MISSING_INPUT');
  assert.equal(selected.hero_vision_score_snapshot.status, 'CANDIDATE');
  replay.tail.stats[0][TAIL_FIELD] = '-1';
  assert.equal(decodeCandidates(replay).status, 'UNSUPPORTED');
  replay.tail.stats = null;
  assert.equal(decodeCandidates(replay).status, 'MISSING_INPUT');

  const overrun = fixture();
  overrun.tail.stats[0][TAIL_FIELD] = '0';
  assert.match(decodeCandidates(overrun).error,
    /exceeds Replay tail TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS/);
  const rows = defaultRows();
  rows[0][0] = 9.5;
  rows[1][0] = 8.5;
  const decline = fixture({ rows });
  decline.tail.stats[0][TAIL_FIELD] = '100';
  assert.match(decodeCandidates(decline).error,
    /decreasing observed TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS/);
  assert.equal(decodeCandidates(fixture({ version: '16.19.820.7194' })).status,
    'UNSUPPORTED');
  assert.equal(decodeCandidates(fixture({ stream: 1 })).status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decodeCandidates(fixture({ omitParticipant: 3 })).status,
    'DECODE_FAILED');
  assert.equal(decodeCandidates(fixture({ extraBlocks: [
    blockFor(1, 1000, Buffer.from([1, 2]))] })).status, 'DECODE_FAILED');
});

test('exact-build API and capability query expose only the selected candidate', () => {
  const replay = fixture();
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].event_count, 20);
  assert.equal(getHeroDamageTakenFromChampionsSnapshotCandidates(decoded).at(-1)[FLOOR_KEY], 30);
  assert.deepEqual(Object.keys(decoded.events), [`${CAPABILITY}_candidates`]);
  const capability = capabilityQuery(replay).capabilities.find((row) =>
    row.capability === CAPABILITY);
  assert.equal(capability.status, 'CANDIDATE');
  assert.equal(capability.output, `${CAPABILITY}_candidates`);
  assert.equal(capability.runtime_image_requirement, 'NOT_REQUIRED');
  assert.deepEqual(capability.required_inputs.map((input) => input.name), [
    'replay', 'replay_tail_statsJson', `replay_tail_${TAIL_FIELD}`,
  ]);
  delete replay.tail.stats[0][TAIL_FIELD];
  assert.deepEqual(capabilityQuery(replay).capabilities.find((row) =>
    row.capability === CAPABILITY).missing_inputs, [`replay_tail_${TAIL_FIELD}`]);
});

test('selected CLI emits only the candidate JSONL with real file provenance', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-champion-taken-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailStats(fixture(), input);
  assert.equal(await main(['decode', input, '--events', CAPABILITY,
    '--out-dir', output]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDir = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDir, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[CAPABILITY].event_count, 20);
  assert.equal(semantic.capability_results[CAPABILITY].tail_gap_total, 1);
  const rows = fs.readFileSync(path.join(replayDir, `${CAPABILITY}_candidates.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(rows.length, 20);
  assert.equal(rows.at(-1)[RAW_KEY], 30.5);
  assert.equal(rows.at(-1)[FLOOR_KEY], 30);
  assert.equal(rows.at(-1).raw_packet_ref.replay_sha256,
    crypto.createHash('sha256').update(fs.readFileSync(input)).digest('hex'));
});
