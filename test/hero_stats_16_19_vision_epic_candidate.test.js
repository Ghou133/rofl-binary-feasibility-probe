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
  HERO_VISION_SCORE_SNAPSHOT_CANDIDATE_PROFILE,
  HERO_EPIC_MONSTER_DAMAGE_SNAPSHOT_CANDIDATE_PROFILE,
  analyzeReplayWithHeroStats,
  assessHeroVisionScoreSnapshotTail,
  assessHeroEpicMonsterDamageSnapshotTail,
  decodeHeroStatsByte,
  decodeHeroStatsSnapshotCandidateSet,
  decodeHeroVisionScorePayload,
  decodeHeroVisionScoreSnapshotCandidates,
  decodeHeroEpicMonsterDamagePayload,
  decodeHeroEpicMonsterDamageSnapshotCandidates,
} = require('../src/decoders/rofl_16_19_hero_stats_candidate');

const BUILD = '16.19.820.7193';
const IMAGE_SHA = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';
const CASES = [
  {
    capability: 'hero_vision_score_snapshot',
    field: 'VISION_SCORE',
    offset: 0x1b0,
    rawKey: 'vision_score_raw_f32_candidate',
    floorKey: 'vision_score_floor_candidate',
    eventType: 'HERO_VISION_SCORE_SNAPSHOT_CANDIDATE',
    evidenceStatus: 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_VISION_SCORE_TAIL_CORRELATION',
    profile: HERO_VISION_SCORE_SNAPSHOT_CANDIDATE_PROFILE,
    assess: assessHeroVisionScoreSnapshotTail,
    decodePayload: decodeHeroVisionScorePayload,
    decode: decodeHeroVisionScoreSnapshotCandidates,
  },
  {
    capability: 'hero_epic_monster_damage_snapshot',
    field: 'TOTAL_DAMAGE_DEALT_TO_EPIC_MONSTERS',
    offset: 0x21c,
    rawKey: 'epic_monster_damage_raw_f32_candidate',
    floorKey: 'epic_monster_damage_floor_candidate',
    eventType: 'HERO_EPIC_MONSTER_DAMAGE_SNAPSHOT_CANDIDATE',
    evidenceStatus: 'CANDIDATE_EXACT_ROUTE_ONE_REPLAY_EPIC_MONSTER_DAMAGE_TAIL_CORRELATION',
    profile: HERO_EPIC_MONSTER_DAMAGE_SNAPSHOT_CANDIDATE_PROFILE,
    assess: assessHeroEpicMonsterDamageSnapshotTail,
    decodePayload: decodeHeroEpicMonsterDamagePayload,
    decode: decodeHeroEpicMonsterDamageSnapshotCandidates,
  },
];
const VISION = CASES[0];
const EPIC = CASES[1];
const ENCODE_BYTE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  ENCODE_BYTE[decodeHeroStatsByte(encoded)] = encoded;
}
assert.ok(ENCODE_BYTE.every((value) => value !== null));

function payloadFor(values = {}) {
  const blob = Buffer.alloc(1260);
  for (const spec of CASES) blob.writeFloatLE(values[spec.rawKey] ?? 0, spec.offset);
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
  return [Array.from({ length: 10 }, () => ({
    [VISION.rawKey]: 0, [EPIC.rawKey]: 0,
  })), Array.from({ length: 10 }, (_, index) => ({
    [VISION.rawKey]: (index + 1) * 5 + 0.5,
    [EPIC.rawKey]: (index + 1) * 100 + 0.25,
  }))];
}

function fixture({ rows = defaultRows(), tailRows = null, version = BUILD,
  stream = 2, extraBlocks = [], omitParticipant = null } = {}) {
  const body = Buffer.concat([
    ...[0, 1000].flatMap((timeMs, timeIndex) => rows[timeIndex].flatMap((values, index) =>
      omitParticipant === index + 1 && timeIndex === 0 ? []
        : [blockFor(index + 1, timeMs, payloadFor(values))])),
    ...extraBlocks,
  ]);
  const replay = replayFromChunks([{ stream, body }], version);
  replay.tail.stats = tailRows ?? rows.at(-1).map((values, index) => ({
    VISION_SCORE: String(Math.floor(values[VISION.rawKey]) + (index === 1 ? 1 : 0)),
    TOTAL_DAMAGE_DEALT_TO_EPIC_MONSTERS:
      String(Math.floor(values[EPIC.rawKey]) + (index === 3 ? 2 : 0)),
    ASSISTS: '0',
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

test('two exact HN profiles and payload decoders retain fractional raw values and derived floors', () => {
  const payload = payloadFor({ [VISION.rawKey]: 17.75, [EPIC.rawKey]: 1200.5 });
  for (const spec of CASES) {
    assert.ok(HERO_STATS_SNAPSHOT_CAPABILITIES.includes(spec.capability));
    assert.equal(spec.profile.status, 'CANDIDATE');
    assert.equal(spec.profile.replay_version, BUILD);
    assert.equal(spec.profile.replay_block_packet_id, 0x0276);
    assert.equal(spec.profile.payload_length, 1263);
    assert.equal(spec.profile.evidence_runtime_image_sha256, IMAGE_SHA);
    assert.match(spec.profile.evidence_scope, /one HN Replay/);
    assert.equal(spec.profile[`${spec.rawKey.replace(/_raw_f32_candidate$/, '')}_f32le_offset_candidate`],
      spec.offset);
    const decoded = spec.decodePayload(payload);
    assert.equal(decoded.status, 'PASS');
    assert.equal(decoded[spec.rawKey], spec === VISION ? 17.75 : 1200.5);
    assert.equal(decoded[spec.floorKey], spec === VISION ? 17 : 1200);
    for (const invalid of [-1, Infinity, NaN, 2 ** 53]) {
      assert.equal(spec.decodePayload(payloadFor({ [spec.rawKey]: invalid })).status,
        'DECODE_FAILED', `${spec.capability}: ${invalid}`);
    }
    const malformed = Buffer.from(payload);
    malformed[0] = 0x1d;
    assert.equal(spec.decodePayload(malformed).status, 'DECODE_FAILED');
    assert.equal(spec.decodePayload(malformed.subarray(1)).status, 'DECODE_FAILED');
  }
  assert.match(VISION.profile.known_limits.join(' '), /no vision event/);
  assert.match(EPIC.profile.known_limits.join(' '), /no damage event/);
});

test('shared exact-build scan emits separate candidate snapshots with source refs and tail gaps', () => {
  const replay = fixture();
  const result = decodeHeroStatsSnapshotCandidateSet(replay, CASES.map((spec) => spec.capability));
  for (const spec of CASES) {
    const outcome = result[spec.capability];
    assert.equal(outcome.status, 'CANDIDATE');
    assert.equal(outcome.event_count, 20);
    assert.equal(outcome.input_count, 20);
    assert.equal(outcome.keyframe_timestamp_count, 2);
    assert.equal(outcome.observed_participant_count, 10);
    assert.equal(outcome.evidence_status, spec.evidenceStatus);
    assert.equal(outcome.evidence_runtime_image_sha256, IMAGE_SHA);
    assert.equal(outcome.tail_gaps.length, 10);
    assert.equal(outcome.tail_gaps[1].unobserved_tail_time_ms, 1000);
    const last = outcome.events.at(-1);
    assert.equal(last.event_type, spec.eventType);
    assert.equal(last.observation_kind, 'KEYFRAME_SNAPSHOT');
    assert.equal(last.confidence, 'CANDIDATE');
    assert.equal(last.semantic_status, spec.evidenceStatus);
    assert.equal(last.participant_id_candidate, 10);
    assert.equal(last[spec.rawKey], spec === VISION ? 50.5 : 1000.25);
    assert.equal(last[spec.floorKey], spec === VISION ? 50 : 1000);
    assert.equal(last.field_confidence[spec.rawKey], 'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION');
    assert.equal(last.field_confidence[spec.floorKey], 'DERIVED_FROM_CANDIDATE');
    assert.equal(last.raw_packet_ref.packet_id, 0x0276);
    assert.equal(last.raw_packet_ref.raw_param, 0x400000b7);
    assert.equal(last.raw_packet_ref.replay_sha256, replay.source_sha256);
    assert.equal(last.raw_packet_ref.raw_payload_sha256, crypto.createHash('sha256')
      .update(payloadFor(defaultRows()[1][9])).digest('hex'));
  }
  assert.equal(result[VISION.capability].tail_gap_total, 1);
  assert.deepEqual(result[VISION.capability].tail_gaps[1], {
    participant_id_candidate: 2,
    last_snapshot_replay_time_ms: 1000,
    last_snapshot_raw_f32_candidate: 10.5,
    last_snapshot_floor_candidate: 10,
    final_tail: 11,
    unobserved_tail_floor_gap: 1,
    unobserved_tail_time_ms: 1000,
  });
  assert.equal(result[EPIC.capability].tail_gap_total, 2);
  assert.equal(result[EPIC.capability].tail_gaps[3].unobserved_tail_floor_gap, 2);
  for (const key of ['vision_event_time_ms', 'damage_event_time_ms', 'source',
    'target', 'location']) {
    assert.equal(Object.hasOwn(result[VISION.capability].events.at(-1), key), false);
    assert.equal(Object.hasOwn(result[EPIC.capability].events.at(-1), key), false);
  }
});

test('missing or invalid one-field tail affects only that selected candidate', () => {
  for (const spec of CASES) {
    assert.equal(spec.assess(fixture()).status, 'PASS');
    const missing = fixture();
    delete missing.tail.stats[0][spec.field];
    const outcomes = decodeHeroStatsSnapshotCandidateSet(missing, CASES.map((row) => row.capability));
    assert.equal(outcomes[spec.capability].status, 'MISSING_INPUT');
    assert.equal(outcomes[CASES.find((row) => row !== spec).capability].status, 'CANDIDATE');
    const invalid = fixture();
    invalid.tail.stats[0][spec.field] = '-1';
    assert.equal(spec.decode(invalid).status, 'UNSUPPORTED');
  }
  const noTail = fixture();
  noTail.tail.stats = null;
  for (const spec of CASES) assert.equal(spec.decode(noTail).status, 'MISSING_INPUT');
});

test('observed decline or floor exceeding its own tail fails closed for each field', () => {
  for (const spec of CASES) {
    const rows = defaultRows();
    rows[0][0][spec.rawKey] = 9.5;
    rows[1][0][spec.rawKey] = 8.5;
    const decreasingReplay = fixture({ rows });
    decreasingReplay.tail.stats[0][spec.field] = '100000';
    const declined = spec.decode(decreasingReplay);
    assert.equal(declined.status, 'DECODE_FAILED');
    assert.match(declined.error, new RegExp(`decreasing observed ${spec.field}`));
    assert.equal(declined.events, null);
    const overrun = fixture();
    overrun.tail.stats[0][spec.field] = '0';
    const bounded = spec.decode(overrun);
    assert.equal(bounded.status, 'DECODE_FAILED');
    assert.match(bounded.error, new RegExp(`exceeds Replay tail ${spec.field}`));
    assert.equal(bounded.events, null);
  }
});

test('wrong build, foreign route, malformed packet, source mutation and incomplete roster fail closed', () => {
  const wrongBuild = fixture({ version: '16.19.820.7194' });
  const foreignStream = fixture({ stream: 1 });
  const foreignShape = replayFromChunks([{ stream: 2, body: Buffer.concat(
    Array.from({ length: 10 }, (_, index) =>
      blockFor(index + 1, 0, Buffer.from([1, 2]))),
  ) }], BUILD);
  const mixed = fixture({ extraBlocks: [blockFor(1, 0, Buffer.from([1, 2]))] });
  const tampered = fixture();
  tampered.buffer[0] = 0;
  const incomplete = fixture({ omitParticipant: 3 });
  for (const spec of CASES) {
    assert.equal(spec.decode(wrongBuild).status, 'UNSUPPORTED');
    assert.equal(spec.decode(foreignStream).status, 'PROFILE_UNAVAILABLE');
    assert.equal(spec.decode(foreignShape).status, 'PROFILE_UNAVAILABLE');
    assert.equal(spec.decode(mixed).status, 'DECODE_FAILED');
    assert.match(spec.decode(tampered).error, /Replay source failed/);
    assert.match(spec.decode(incomplete).error, /lacks one or more hero params/);
  }
});

test('bound shared scan yields both outputs without a second Replay walk', () => {
  const replay = fixture();
  const standalone = Object.fromEntries(CASES.map((spec) => [spec.capability, spec.decode(replay)]));
  const { heroStatsScan } = analyzeReplayWithHeroStats(replay, { strict: true });
  Object.defineProperty(replay, 'chunks', { get() {
    throw new Error('precollected decode must not rescan Replay chunks');
  } });
  const combined = decodeHeroStatsSnapshotCandidateSet(replay,
    CASES.map((spec) => spec.capability), heroStatsScan);
  assert.deepEqual(combined, standalone);
});

test('selected API and capability query expose independent candidate results and tail dependencies', () => {
  const { decodeSemanticReplay, getHeroVisionScoreSnapshotCandidates,
    getHeroEpicMonsterDamageSnapshotCandidates } = require('../src/semantic_api');
  const { capabilityQuery } = require('../src/cli');
  const replay = fixture();
  const selected = CASES.map((spec) => spec.capability);
  const decoded = decodeSemanticReplay(replay, { capabilities: selected });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.deepEqual(Object.keys(decoded.events), CASES.map((spec) => `${spec.capability}_candidates`));
  for (const spec of CASES) {
    assert.equal(decoded.capability_results[spec.capability].event_count, 20);
    const row = capabilityQuery(replay).capabilities.find((entry) => entry.capability === spec.capability);
    assert.equal(row.output, `${spec.capability}_candidates`);
    assert.equal(row.runtime_image_requirement, 'NOT_REQUIRED');
    assert.deepEqual(row.required_inputs.map((input) => input.name),
      ['replay', 'replay_tail_statsJson', `replay_tail_${spec.field}`]);
  }
  assert.equal(getHeroVisionScoreSnapshotCandidates(decoded).at(-1)
    .vision_score_floor_candidate, 50);
  assert.equal(getHeroEpicMonsterDamageSnapshotCandidates(decoded).at(-1)
    .epic_monster_damage_floor_candidate, 1000);
  assert.equal(decoded.events.damage_events, undefined);
  delete replay.tail.stats[0].VISION_SCORE;
  const query = capabilityQuery(replay).capabilities;
  assert.deepEqual(query.find((entry) => entry.capability === VISION.capability).missing_inputs,
    ['replay_tail_VISION_SCORE']);
  assert.deepEqual(query.find((entry) => entry.capability === EPIC.capability).missing_inputs, []);
});

test('selected CLI writes both candidate JSONL outputs with Replay provenance', async (t) => {
  const { main } = require('../src/cli');
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-vision-epic-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailStats(fixture(), input);
  assert.equal(await main(['decode', input, '--events', CASES.map((spec) => spec.capability).join(','),
    '--out-dir', output]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  const replayDir = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDir, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.capability_results[VISION.capability].tail_gap_total, 1);
  assert.equal(semantic.capability_results[EPIC.capability].tail_gap_total, 2);
  for (const spec of CASES) {
    const rows = fs.readFileSync(path.join(replayDir, `${spec.capability}_candidates.jsonl`), 'utf8')
      .trim().split(/\r?\n/).map((line) => JSON.parse(line));
    assert.equal(rows.length, 20);
    assert.equal(rows.at(-1)[spec.floorKey], spec === VISION ? 50 : 1000);
    assert.equal(rows.at(-1).raw_packet_ref.replay_sha256,
      crypto.createHash('sha256').update(fs.readFileSync(input)).digest('hex'));
  }
});
