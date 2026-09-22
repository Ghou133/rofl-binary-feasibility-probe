'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  CURRENT_STAGE_CODES,
  analyzeReplay,
  analyzeRoute0064,
  payloadParts,
} = require('../src/route_0064_support_quest_audit');
const { parseArgs } = require('../scripts/audit_route_0064_support_quest');

const NONUTILITY_CODES = [
  'f0f83186f908', 'f0f831860d08', 'f0f831860408', 'f0f83186bf08',
  null, 'f0f831869e08', 'f0f831863d08', 'f0f83186a908', 'f0f83186be08', null,
];

function supportSuffix(participantId, stage) {
  return `${CURRENT_STAGE_CODES[stage]}${participantId === 5 ? '8a08' : '4408'}`;
}

function syntheticRecord(label = 'r') {
  const roster = Array.from({ length: 10 }, (_, index) => ({
    participant_id: index + 1,
    champion: `C${index + 1}`,
    team_position: [5, 10].includes(index + 1) ? 'UTILITY' : 'TOP',
  }));
  const events = [];
  const times = [1000, 1500, 2000, 2500, 3000, 3500];
  for (const [groupIndex, time] of times.entries()) {
    const stage = groupIndex < 2 ? 0 : groupIndex < 4 ? 1 : 2;
    for (let slot = 0; slot < 10; slot += 1) {
      const participantId = slot + 1;
      const suffix = [5, 10].includes(participantId)
        ? supportSuffix(participantId, stage) : NONUTILITY_CODES[slot];
      events.push({
        replay_version: '16.16.805.0442',
        replay_sha256: label,
        replay_label: label,
        replay_time_ms: time,
        occurrence_index: events.length,
        packet_id: 0x0064,
        raw_param: 0,
        chunk_stream: 'game_chunk',
        payload_length: 7,
        raw_payload_hex: `${(groupIndex + slot).toString(16).padStart(2, '0')}${suffix}`,
      });
    }
  }
  return {
    game_id: label,
    replay_sha256: label,
    replay_label: label,
    roster,
    events,
    item_events: [5, 10].flatMap((participantId) => [
      {
        type: 'ITEM_DESTROYED', timestamp_ms: 1950, participant_id: participantId,
        item_id: 3865, source_json_path: `$3865:${participantId}`,
      },
      {
        type: 'ITEM_DESTROYED', timestamp_ms: 2950, participant_id: participantId,
        item_id: 3867, source_json_path: `$3867:${participantId}`,
      },
      {
        type: 'ITEM_DESTROYED', timestamp_ms: 2700, participant_id: participantId,
        item_id: 3866, source_json_path: `$3866:${participantId}`,
      },
    ]),
  };
}

test('seven-byte payload is split without assigning byte zero semantics', () => {
  assert.deepEqual(payloadParts('7ff09dfa318a08'), {
    raw_payload_hex: '7ff09dfa318a08',
    volatile_prefix_hex: '7f',
    stable_suffix_hex: 'f09dfa318a08',
    stage_family_code_hex: 'f09dfa31',
    participant_slot_code_hex: '8a08',
  });
  assert.throws(() => payloadParts('f09dfa318a08'), /seven bytes/);
});

test('canonical ten-row snapshots isolate three-stage utility series and stable controls', () => {
  const report = analyzeReplay(syntheticRecord());
  assert.equal(report.validations.all_pass, true);
  assert.deepEqual(report.utility_participant_ids, [5, 10]);
  assert.equal(report.slot_series.find((row) => row.participant_id === 5).transitions.length, 3);
  assert.equal(report.slot_series.find((row) => row.participant_id === 4).transitions.length, 1);
});

test('DETAILS item-destruction anchors yield a bounded research promotion', () => {
  const p0 = syntheticRecord('p0');
  const latest = syntheticRecord('latest');
  const report = analyzeRoute0064({
    latestRecords: [latest],
    p0Records: [p0],
    legacyRecords: [],
    expectedLatestCount: latest.events.length,
  });
  assert.equal(report.details_ground_truth_alignment.matched_alignment_count, 4);
  assert.equal(report.details_ground_truth_alignment.unmatched_transition_count, 0);
  assert.equal(report.route_decisions[0].decision, 'PROMOTE');
  assert.equal(report.route_decisions[0].promotion_scope,
    'RESEARCH_ONLY_CANONICAL_TEN_ROW_GROUPS_AND_UTILITY_SLOTS');
  assert.match(report.negative_evidence.residual_unknowns.join(' '), /Three-byte/);
});

test('CLI is explicit, exact-build, and Holdout fail-closed', () => {
  assert.throws(() => parseArgs([]), /explicit --latest-replay/);
  assert.throws(() => parseArgs(['--build', '16.15.801.3452', '--latest-replay', 'a.rofl']),
    /exact build/);
  assert.throws(() => parseArgs(['--latest-replay', 'Jungle Objective Holdout/a.rofl']),
    /forbidden/);
  assert.equal(parseArgs(['--latest-replay', 'a.rofl']).build, '16.16.805.0442');
});
