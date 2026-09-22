'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  analyzeRoute0474,
  canonicalHeroEntity,
  participantFromRawParam,
} = require('../src/route_0474_champion_specific_audit');
const { parseArgs } = require('../scripts/audit_route_0474_champion_specific');

function event(replay, participantId, champion, time, rawParam, payload = '605f') {
  return {
    replay_version: '16.16.805.0442',
    replay_sha256: replay,
    replay_label: replay,
    replay_time_ms: time,
    occurrence_index: time,
    packet_id: 0x0474,
    raw_param: rawParam,
    chunk_stream: 'game_chunk',
    payload_length: payload.length / 2,
    raw_payload_hex: payload,
    champion,
    participant_id: participantId,
  };
}

test('raw low byte maps participants while preserving upper-byte variants', () => {
  assert.equal(participantFromRawParam(0x400000b2), 5);
  assert.equal(participantFromRawParam(0x40000cb2), 5);
  assert.equal(canonicalHeroEntity(5), 0x400000b2);
  assert.equal(participantFromRawParam(0), null);
});

test('dominant constant champion-specific behavior rejects general volatile Hero state', () => {
  const events = [];
  for (let index = 0; index < 98; index += 1) {
    events.push(event('a', 5, 'Zilean', index * 20,
      index < 90 ? 0x400000b2 : 0x400001b2));
  }
  events.push(event('b', 2, 'Lucian', 100, 0x400000af, '465f6c'));
  events.push(event('c', 4, 'Ahri', 200, 0x400000b1, '865f6c'));
  const replays = ['a', 'b', 'c', 'd'].map((replay) => ({
    replay_sha256: replay,
    replay_label: replay,
    roster: Array.from({ length: 10 }, (_, index) => ({ participant_id: index + 1 })),
  }));
  const report = analyzeRoute0474(events, 100, replays);
  assert.equal(report.validations.all_pass, true);
  assert.equal(report.dominant_behavior.champion, 'Zilean');
  assert.equal(report.route_decisions[0].decision, 'REPURPOSE');
  assert.equal(report.route_decisions[0].semantic_claim, null);
  assert.ok(report.negative_evidence.rejected_hypotheses.includes('GENERAL_CURRENT_HP'));
});

test('CLI is exact-build, explicit-replay, and Holdout fail-closed', () => {
  assert.throws(() => parseArgs([]), /explicit --replay/);
  assert.throws(() => parseArgs(['--build', '16.15.801.3452', '--replay', 'a.rofl']), /exact build/);
  assert.throws(() => parseArgs(['--replay', 'Jungle_Objective_Holdout/a.rofl']), /forbidden/);
  assert.equal(parseArgs(['--replay', 'a.rofl']).build, '16.16.805.0442');
});
