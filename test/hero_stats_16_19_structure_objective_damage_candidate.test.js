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
  HERO_STRUCTURE_OBJECTIVE_DAMAGE_SNAPSHOT_CANDIDATE_PROFILE,
  analyzeReplayWithHeroStats,
  assessHeroStructureObjectiveDamageSnapshotTail,
  decodeHeroStatsByte,
  decodeHeroStatsSnapshotCandidateSet,
  decodeHeroStructureObjectiveDamagePayload,
  decodeHeroStructureObjectiveDamageSnapshotCandidates,
} = require('../src/decoders/rofl_16_19_hero_stats_candidate');
const { decodeSemanticReplay, getHeroStructureObjectiveDamageSnapshotCandidates } =
  require('../src/semantic_api');
const { capabilityQuery, main } = require('../src/cli');

const BUILD = '16.19.820.7193';
const CAPABILITY = 'hero_structure_objective_damage_snapshot';
const IMAGE_SHA = '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d';
const ENCODE_BYTE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  ENCODE_BYTE[decodeHeroStatsByte(encoded)] = encoded;
}
assert.ok(ENCODE_BYTE.every((value) => value !== null));

function payloadFor({ structure = 0, mirror = structure, objective = 0 } = {}) {
  const blob = Buffer.alloc(1260);
  blob.writeFloatLE(structure, 0x210);
  blob.writeFloatLE(mirror, 0x214);
  blob.writeFloatLE(objective, 0x218);
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
  return [Array.from({ length: 10 }, () => ({ structure: 0, objective: 0 })),
    Array.from({ length: 10 }, (_, index) => ({
      structure: (index + 1) * 100 + 0.5,
      objective: (index + 1) * 120 + 0.75,
    }))];
}

function fixture({ rows = defaultRows(), version = BUILD, stream = 2,
  omitParticipant = null, extraBlocks = [] } = {}) {
  const body = Buffer.concat([
    ...[0, 1000].flatMap((timeMs, timeIndex) => rows[timeIndex].flatMap((value, index) =>
      omitParticipant === index + 1 && timeIndex === 0 ? []
        : [blockFor(index + 1, timeMs, payloadFor(value))])),
    ...extraBlocks,
  ]);
  const replay = replayFromChunks([{ stream, body }], version);
  replay.tail.stats = rows.at(-1).map((value, index) => ({
    TOTAL_DAMAGE_DEALT_TO_BUILDINGS:
      String(Math.floor(value.structure) + (index === 1 ? 1 : 0)),
    TOTAL_DAMAGE_DEALT_TO_OBJECTIVES:
      String(Math.floor(value.objective) + (index === 3 ? 2 : 0)),
    NUM_DEATHS: '0',
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

test('exact HN candidate reads three direct f32 offsets and keeps floors derived', () => {
  const profile = HERO_STRUCTURE_OBJECTIVE_DAMAGE_SNAPSHOT_CANDIDATE_PROFILE;
  assert.ok(HERO_STATS_SNAPSHOT_CAPABILITIES.includes(CAPABILITY));
  assert.equal(profile.capability, CAPABILITY);
  assert.equal(profile.status, 'CANDIDATE');
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.replay_block_packet_id, 0x0276);
  assert.deepEqual(profile.stream_tags, [2, 3]);
  assert.equal(profile.structure_damage_f32le_offset_candidate, 0x210);
  assert.equal(profile.structure_damage_mirror_f32le_offset_candidate, 0x214);
  assert.equal(profile.objective_damage_f32le_offset_candidate, 0x218);
  assert.equal(profile.evidence_runtime_image_sha256, IMAGE_SHA);
  assert.match(profile.evidence_scope, /one HN Replay/);
  assert.match(profile.known_limits.join(' '), /cannot identify turret damage/);
  assert.match(profile.known_limits.join(' '), /floor equals floor\(0x210 \+ 0x21c\)/);
  assert.deepEqual(decodeHeroStructureObjectiveDamagePayload(payloadFor({
    structure: 17.75, objective: 1200.5,
  })), {
    status: 'PASS',
    structure_damage_raw_f32_candidate: 17.75,
    structure_damage_floor_candidate: 17,
    structure_damage_mirror_raw_f32_candidate: 17.75,
    structure_damage_mirror_floor_candidate: 17,
    objective_damage_raw_f32_candidate: 1200.5,
    objective_damage_floor_candidate: 1200,
  });
  for (const field of ['structure', 'mirror', 'objective']) {
    for (const value of [-1, Infinity, NaN, 2 ** 53]) {
      assert.equal(decodeHeroStructureObjectiveDamagePayload(payloadFor({
        structure: 10, mirror: 10, objective: 20, [field]: value,
      })).status, 'DECODE_FAILED', `${field}: ${value}`);
    }
  }
  const mismatch = decodeHeroStructureObjectiveDamagePayload(payloadFor({
    structure: 10.5, mirror: 10.25, objective: 20.5,
  }));
  assert.equal(mismatch.status, 'DECODE_FAILED');
  assert.match(mismatch.error, /0x210 and 0x214 differ/);
  const malformed = payloadFor({ structure: 17.75, objective: 1200.5 });
  malformed[0] = 0x1d;
  assert.equal(decodeHeroStructureObjectiveDamagePayload(malformed).status, 'DECODE_FAILED');
  assert.equal(decodeHeroStructureObjectiveDamagePayload(malformed.subarray(1)).status,
    'DECODE_FAILED');
});

test('one combined keyframe record retains provenance and separate BUILDINGS/OBJECTIVES gaps', () => {
  const replay = fixture();
  const outcome = decodeHeroStructureObjectiveDamageSnapshotCandidates(replay);
  assert.equal(outcome.status, 'CANDIDATE');
  assert.equal(outcome.event_count, 20);
  assert.equal(outcome.input_count, 20);
  assert.equal(outcome.keyframe_timestamp_count, 2);
  assert.equal(outcome.observed_participant_count, 10);
  assert.equal(outcome.evidence_runtime_image_sha256, IMAGE_SHA);
  assert.deepEqual(outcome.tail_gap_totals, {
    TOTAL_DAMAGE_DEALT_TO_BUILDINGS: 1,
    TOTAL_DAMAGE_DEALT_TO_OBJECTIVES: 2,
  });
  assert.equal(outcome.tail_gaps[1].field_gaps.TOTAL_DAMAGE_DEALT_TO_BUILDINGS
    .unobserved_tail_floor_gap, 1);
  assert.equal(outcome.tail_gaps[3].field_gaps.TOTAL_DAMAGE_DEALT_TO_OBJECTIVES
    .unobserved_tail_floor_gap, 2);
  assert.equal(outcome.tail_gaps[9].unobserved_tail_time_ms, 1000);
  const last = outcome.events.at(-1);
  assert.equal(last.event_type, 'HERO_STRUCTURE_OBJECTIVE_DAMAGE_SNAPSHOT_CANDIDATE');
  assert.equal(last.observation_kind, 'KEYFRAME_SNAPSHOT');
  assert.equal(last.confidence, 'CANDIDATE');
  assert.equal(last.participant_id_candidate, 10);
  assert.equal(last.structure_damage_raw_f32_candidate, 1000.5);
  assert.equal(last.structure_damage_floor_candidate, 1000);
  assert.equal(last.structure_damage_mirror_raw_f32_candidate, 1000.5);
  assert.equal(last.structure_damage_mirror_floor_candidate, 1000);
  assert.equal(last.objective_damage_raw_f32_candidate, 1200.75);
  assert.equal(last.objective_damage_floor_candidate, 1200);
  assert.equal(last.field_confidence.structure_damage_floor_candidate,
    'DERIVED_FROM_CANDIDATE');
  assert.equal(last.field_confidence.objective_damage_raw_f32_candidate,
    'CANDIDATE_ONE_REPLAY_TAIL_CORRELATION');
  assert.equal(last.raw_packet_ref.packet_id, 0x0276);
  assert.equal(last.raw_packet_ref.raw_param, 0x400000b7);
  assert.equal(last.raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(last.raw_packet_ref.raw_payload_sha256,
    crypto.createHash('sha256').update(payloadFor(defaultRows()[1][9])).digest('hex'));
  for (const key of ['damage_event_time_ms', 'target_network_id', 'turret_entity_id',
    'objective_entity_id']) assert.equal(Object.hasOwn(last, key), false);
});

test('either missing or invalid Replay tail suppresses only this candidate', () => {
  assert.equal(assessHeroStructureObjectiveDamageSnapshotTail(fixture()).status, 'PASS');
  for (const field of ['TOTAL_DAMAGE_DEALT_TO_BUILDINGS',
    'TOTAL_DAMAGE_DEALT_TO_OBJECTIVES']) {
    const replay = fixture();
    delete replay.tail.stats[0][field];
    const outcomes = decodeHeroStatsSnapshotCandidateSet(replay,
      [CAPABILITY, 'hero_deaths_snapshot']);
    assert.equal(outcomes[CAPABILITY].status, 'MISSING_INPUT');
    assert.equal(outcomes[CAPABILITY].events, null);
    assert.equal(outcomes.hero_deaths_snapshot.status, 'CANDIDATE');
    replay.tail.stats[0][field] = '-1';
    assert.equal(decodeHeroStructureObjectiveDamageSnapshotCandidates(replay).status,
      'UNSUPPORTED');
  }
  const noTail = fixture();
  noTail.tail.stats = null;
  assert.equal(decodeHeroStructureObjectiveDamageSnapshotCandidates(noTail).status,
    'MISSING_INPUT');
});

test('mirror divergence, declines, and field-specific tail overruns fail closed', () => {
  const mismatch = fixture({ rows: [defaultRows()[0], defaultRows()[1].map((value, index) =>
    index === 0 ? { ...value, mirror: value.structure + 1 } : value)] });
  assert.equal(decodeHeroStructureObjectiveDamageSnapshotCandidates(mismatch).status,
    'DECODE_FAILED');
  for (const [key, field] of [['structure', 'TOTAL_DAMAGE_DEALT_TO_BUILDINGS'],
    ['objective', 'TOTAL_DAMAGE_DEALT_TO_OBJECTIVES']]) {
    const rows = defaultRows();
    rows[0][0][key] = 9.5;
    rows[1][0][key] = 8.5;
    const decreasing = fixture({ rows });
    decreasing.tail.stats[0][field] = '100000';
    const declined = decodeHeroStructureObjectiveDamageSnapshotCandidates(decreasing);
    assert.equal(declined.status, 'DECODE_FAILED');
    assert.match(declined.error, new RegExp(`decreasing observed ${field}`));
    assert.equal(declined.events, null);
    const overrun = fixture();
    overrun.tail.stats[0][field] = '0';
    const bounded = decodeHeroStructureObjectiveDamageSnapshotCandidates(overrun);
    assert.equal(bounded.status, 'DECODE_FAILED');
    assert.match(bounded.error, new RegExp(`exceeds Replay tail ${field}`));
    assert.equal(bounded.events, null);
  }
});

test('wrong build, foreign route, malformed packet, source mutation and incomplete roster fail closed', () => {
  const wrongBuild = fixture({ version: '16.19.820.7194' });
  const foreignStream = fixture({ stream: 1 });
  const malformed = fixture({ extraBlocks: [blockFor(1, 0, Buffer.from([1, 2]))] });
  const tampered = fixture();
  tampered.buffer[0] = 0;
  const incomplete = fixture({ omitParticipant: 3 });
  assert.equal(decodeHeroStructureObjectiveDamageSnapshotCandidates(wrongBuild).status,
    'UNSUPPORTED');
  assert.equal(decodeHeroStructureObjectiveDamageSnapshotCandidates(foreignStream).status,
    'PROFILE_UNAVAILABLE');
  assert.equal(decodeHeroStructureObjectiveDamageSnapshotCandidates(malformed).status,
    'DECODE_FAILED');
  assert.match(decodeHeroStructureObjectiveDamageSnapshotCandidates(tampered).error,
    /Replay source failed/);
  assert.match(decodeHeroStructureObjectiveDamageSnapshotCandidates(incomplete).error,
    /lacks one or more hero params/);
});

test('precollected HeroStats scan produces the same candidate without a second Replay walk', () => {
  const replay = fixture();
  const standalone = decodeHeroStructureObjectiveDamageSnapshotCandidates(replay);
  const { heroStatsScan } = analyzeReplayWithHeroStats(replay, { strict: true });
  Object.defineProperty(replay, 'chunks', { get() {
    throw new Error('precollected decode must not rescan Replay chunks');
  } });
  const combined = decodeHeroStatsSnapshotCandidateSet(replay, [CAPABILITY], heroStatsScan);
  assert.deepEqual(combined[CAPABILITY], standalone);
});

test('selected API and capability query expose two tail dependencies and raw provenance', () => {
  const replay = fixture();
  const decoded = decodeSemanticReplay(replay, {
    capabilities: [CAPABILITY, 'hero_deaths_snapshot'],
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].event_count, 20);
  assert.equal(getHeroStructureObjectiveDamageSnapshotCandidates(decoded).at(-1)
    .objective_damage_floor_candidate, 1200);
  assert.equal(decoded.events.damage_events, undefined);
  const query = capabilityQuery(replay).capabilities;
  const capability = query.find((row) => row.capability === CAPABILITY);
  assert.equal(capability.output, `${CAPABILITY}_candidates`);
  assert.equal(capability.runtime_image_requirement, 'NOT_REQUIRED');
  assert.deepEqual(capability.required_inputs.map((input) => input.name), [
    'replay', 'replay_tail_statsJson',
    'replay_tail_TOTAL_DAMAGE_DEALT_TO_BUILDINGS',
    'replay_tail_TOTAL_DAMAGE_DEALT_TO_OBJECTIVES',
  ]);
  delete replay.tail.stats[0].TOTAL_DAMAGE_DEALT_TO_OBJECTIVES;
  const missing = capabilityQuery(replay).capabilities;
  assert.deepEqual(missing.find((row) => row.capability === CAPABILITY).missing_inputs,
    ['replay_tail_TOTAL_DAMAGE_DEALT_TO_OBJECTIVES']);
  assert.deepEqual(missing.find((row) => row.capability === 'hero_deaths_snapshot')
    .missing_inputs, []);
});

test('selected CLI writes structure/objective candidate JSONL with Replay provenance', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-structure-objective-cli-'));
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
  assert.deepEqual(semantic.capability_results[CAPABILITY].tail_gap_totals, {
    TOTAL_DAMAGE_DEALT_TO_BUILDINGS: 1,
    TOTAL_DAMAGE_DEALT_TO_OBJECTIVES: 2,
  });
  const rows = fs.readFileSync(path.join(replayDir, `${CAPABILITY}_candidates.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(rows.length, 20);
  assert.equal(rows.at(-1).structure_damage_floor_candidate, 1000);
  assert.equal(rows.at(-1).objective_damage_floor_candidate, 1200);
  assert.equal(rows.at(-1).confidence, 'CANDIDATE');
  assert.equal(rows.at(-1).raw_packet_ref.replay_sha256,
    crypto.createHash('sha256').update(fs.readFileSync(input)).digest('hex'));
});
