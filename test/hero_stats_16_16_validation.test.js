'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');

const {
  EXPECTED_BLOB_LENGTH,
  EXPECTED_PACKET_COUNT,
  HERO_STATS_16_16_BUILD,
  createHeroStatsScoreboardValidation,
  decodeHeroStatsCandidateFields,
  fieldComparison,
  matchPacketRowsToDetails,
  participantIdFromHeroStatsParam,
} = require('../src/validation/hero_stats_16_16');
const {
  DEFAULT_PATHS,
  assertSafeExplicitPath,
  loadExactValidationInput,
  parseArgs,
} = require('../scripts/validate_hero_stats_16_16');

let exactInput;
let exactReport;

function getExactInput() {
  if (!exactInput) exactInput = loadExactValidationInput({ ...DEFAULT_PATHS, windowMs: 1 });
  return exactInput;
}

function getExactReport() {
  if (!exactReport) {
    exactReport = createHeroStatsScoreboardValidation(getExactInput(), { windowMs: 1 });
  }
  return exactReport;
}

test('HeroStats raw param maps only participant low bytes 0xae..0xb7', () => {
  assert.equal(participantIdFromHeroStatsParam(0x400000ae), 1);
  assert.equal(participantIdFromHeroStatsParam(0x400001b2), 5);
  assert.equal(participantIdFromHeroStatsParam(0x400000b7), 10);
  assert.equal(participantIdFromHeroStatsParam(0x400000ad), null);
  assert.equal(participantIdFromHeroStatsParam(0x400000b8), null);
});

test('HeroStats candidate field decoder reads only the four named f32 offsets', () => {
  const blob = Buffer.alloc(EXPECTED_BLOB_LENGTH);
  blob.writeFloatLE(1234.75, 40);
  blob.writeFloatLE(5678.5, 56);
  blob.writeFloatLE(91, 60);
  blob.writeFloatLE(37.25, 64);
  assert.deepEqual(decodeHeroStatsCandidateFields(blob.toString('hex')), {
    lane_minions_killed: 91,
    xp: 1234.75,
    total_gold: 5678.5,
    jungle_minions_killed: 37.25,
  });
  assert.throws(() => decodeHeroStatsCandidateFields('00'), /1476 bytes/);
});

test('field comparison retains raw residuals and distinguishes exact/floor/round', () => {
  assert.deepEqual(fieldComparison(10.75, 10), {
    raw_value: 10.75,
    details_value: 10,
    residual: 0.75,
    exact_match: false,
    floor_value: 10,
    floor_match: true,
    trunc_value: 10,
    trunc_match: true,
    round_value: 11,
    round_match: false,
    ceil_value: 11,
    ceil_match: false,
  });
});

test('packet-to-DETAILS matching is exact replay/entity, +/-1ms, and one-to-one', () => {
  const replaySha256 = 'a'.repeat(64);
  const packet = {
    row_index: 0,
    game_id: 'g',
    replay_sha256: replaySha256,
    replay_build: HERO_STATS_16_16_BUILD,
    timestamp_ms: 1001,
    participant_id: 1,
    raw_param: 0x400000ae,
    raw_param_hex: '0x400000ae',
    chunk_index: 1,
    decompressed_block_offset: 2,
    occurrence_index: 0,
    payload_length: 1479,
    raw_payload_sha256: 'b'.repeat(64),
    candidate_fields: {
      lane_minions_killed: 2,
      xp: 3.75,
      total_gold: 500.5,
      jungle_minions_killed: 1.25,
    },
  };
  const details = {
    row_index: 0,
    game_id: 'g',
    replay_sha256: replaySha256,
    replay_build: HERO_STATS_16_16_BUILD,
    details_sha256: 'c'.repeat(64),
    frame_index: 0,
    timestamp_ms: 1000,
    participant_id: 1,
    source_json_paths: {},
    fields: {
      lane_minions_killed: 2,
      xp: 3,
      total_gold: 500,
      jungle_minions_killed: 1,
    },
    identity: `${replaySha256}:1000:1`,
  };
  const one = matchPacketRowsToDetails([packet], [details], 1);
  assert.equal(one.matches.length, 1);
  assert.equal(one.matches[0].timestamp_delta_ms, 1);
  assert.equal(one.matches[0].fields.xp.floor_match, true);

  const reused = matchPacketRowsToDetails([packet, { ...packet, row_index: 1 }], [details], 1);
  assert.equal(reused.matches.length, 1);
  assert.equal(reused.reused_details.length, 1);

  const outside = matchPacketRowsToDetails([{ ...packet, timestamp_ms: 1002 }], [details], 1);
  assert.equal(outside.unmatched_packets.length, 1);
});

test('CLI defaults are strict and protected holdout paths are rejected before reads', () => {
  const parsed = parseArgs([]);
  assert.equal(parsed.windowMs, 1);
  assert.match(parsed.output, /hero_stats_scoreboard_validation_16_16\.json$/);
  assert.throws(() => parseArgs(['--window-ms', '2']), /must remain exactly 1/);
  assert.throws(
    () => assertSafeExplicitPath('C:\\forbidden\\Jungle Objective Holdout\\sample.json'),
    /Holdout path is forbidden/,
  );
});

test('exact safe P0 corpus passes all strict HeroStats scoreboard gates', () => {
  const report = getExactReport();
  assert.equal(report.status, 'PASS');
  assert.equal(report.exact_build, HERO_STATS_16_16_BUILD);
  assert.equal(report.decoded_packet_count, EXPECTED_PACKET_COUNT);
  assert.equal(report.matched_count, EXPECTED_PACKET_COUNT);
  assert.equal(report.unmatched_packet_count, 0);
  assert.equal(report.ambiguous_packet_count, 0);
  assert.equal(report.reused_details_count, 0);
  assert.equal(report.unmatched_details_count, 40);
  assert.deepEqual(report.timestamp_delta_ms, {
    min: 0,
    max: 1,
    absolute_max: 1,
    counts: { 0: 620, 1: 770, '-1': 0 },
  });

  assert.equal(report.fields.lane_minions_killed.evidence_status, 'VERIFIED_DIRECT');
  assert.equal(report.fields.lane_minions_killed.aggregate.exact.match_count, 1390);
  assert.equal(report.fields.xp.evidence_status,
    'VERIFIED_DIRECT_RAW_PLUS_VERIFIED_DERIVED_INTEGER');
  assert.equal(report.fields.xp.aggregate.transforms.floor.match_count, 1390);
  assert.equal(report.fields.total_gold.evidence_status, 'CANDIDATE');
  assert.deepEqual(report.fields.total_gold.aggregate.transforms.floor, {
    match_count: 1389,
    mismatch_count: 1,
    match_rate: 1389 / 1390,
  });
  const [goldAnomaly] = report.fields.total_gold.aggregate.floor_mismatch_evidence;
  assert.equal(goldAnomaly.game_id, '11191336852');
  assert.equal(goldAnomaly.participant_id, 4);
  assert.equal(goldAnomaly.packet_timestamp_ms, 2220711);
  assert.equal(goldAnomaly.comparison.raw_value, 20593.97265625);
  assert.equal(goldAnomaly.comparison.details_value, 20591);
  assert.equal(report.fields.total_gold.promotion.allowed, false);

  assert.equal(report.fields.jungle_minions_killed.evidence_status, 'CANDIDATE');
  assert.equal(report.fields.jungle_minions_killed.aggregate.transforms.floor.match_count, 1375);
  assert.equal(report.fields.jungle_minions_killed.aggregate.transforms.floor.mismatch_count, 15);
  assert.equal(report.fields.jungle_minions_killed.promotion.allowed, false);
  assert.deepEqual(report.protected_holdout, {
    enumerated: false,
    read: false,
    hashed: false,
    decoded: false,
    tested: false,
    consumed: false,
  });
});

test('strict corpus validator fails closed if a decoded packet is not fully consumed', () => {
  const input = getExactInput();
  const decodedRows = [...input.decodedRows];
  decodedRows[0] = { ...decodedRows[0], fully_consumed: false };
  assert.throws(
    () => createHeroStatsScoreboardValidation({ ...input, decodedRows }, { windowMs: 1 }),
    /not fully consumed/,
  );
});

test('published validation artifact retains the strict promotion boundary', () => {
  const artifact = JSON.parse(fs.readFileSync(DEFAULT_PATHS.output, 'utf8'));
  const report = getExactReport();
  assert.equal(artifact.status, report.status);
  assert.deepEqual(artifact.gates, report.gates);
  assert.deepEqual(artifact.timestamp_delta_ms, report.timestamp_delta_ms);
  assert.deepEqual(artifact.fields.lane_minions_killed.aggregate,
    report.fields.lane_minions_killed.aggregate);
  assert.deepEqual(artifact.fields.xp.aggregate, report.fields.xp.aggregate);
  assert.deepEqual(artifact.fields.total_gold.aggregate, report.fields.total_gold.aggregate);
  assert.deepEqual(artifact.fields.jungle_minions_killed.aggregate,
    report.fields.jungle_minions_killed.aggregate);
  assert.match(artifact.fields.total_gold.promotion.reason, /no correction, fallback/);
});
