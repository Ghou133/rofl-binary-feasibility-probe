'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { analyzeRoute02d4 } = require('../src/route_02d4_auxiliary_batch_audit');
const { parseArgs } = require('../scripts/audit_route_02d4_auxiliary_batch');

function syntheticRecord() {
  const routeEvents = [];
  const timeContext = new Map();
  let occurrence = 0;
  for (let groupIndex = 0; groupIndex < 3600; groupIndex += 1) {
    const timestamp = groupIndex * 100;
    const size = groupIndex === 10 ? 120 : groupIndex % 3 === 0 ? 3 : 1;
    const context = { '0x02d4': size, '0x00f6': 1 };
    if (groupIndex % 3 !== 0) context['0x017f'] = 1;
    timeContext.set(timestamp, context);
    for (let index = 0; index < size; index += 1) {
      const payload = index % 2 === 0 ? '280102' : '2f010203';
      routeEvents.push({
        replay_version: '16.16.805.0442', replay_sha256: 'a', replay_label: 'a',
        replay_time_ms: timestamp, occurrence_index: occurrence++, packet_id: 0x02d4,
        raw_param: index === 0 && groupIndex % 20 === 0 ? 0x400000ae : 0,
        chunk_stream: 'game_chunk', payload_length: payload.length / 2,
        raw_payload_hex: payload, previous_packet_hex: '0x017f', next_packet_hex: '0x00f6',
        previous_same_timestamp_hex: '0x017f', next_same_timestamp_hex: '0x00f6',
      });
    }
  }
  return { replay_label: 'a', replay_sha256: 'a', route_events: routeEvents, time_context: timeContext };
}

test('exact batch structure and counterexamples repurpose a damage-correlated raw route', () => {
  const record = syntheticRecord();
  const sampled = {
    sample_count: 100,
    sample_policy_warning: 'sample only',
    entity_identifier_mining: { raw_param: { participant_low_byte_rate: 0.02 } },
    damage_neighborhood: { raw_param_matches_either_within_10ms_rate: 0.03 },
  };
  const report = analyzeRoute02d4([record], record.route_events.length, sampled);
  assert.equal(report.validations.all_pass, true, JSON.stringify(report.validations));
  assert.equal(report.route_decisions[0].decision, 'REPURPOSE');
  assert.equal(report.route_decisions[0].semantic_claim, null);
  assert.ok(report.negative_evidence.rejected_hypotheses.includes('DAMAGE_EVENT'));
  assert.equal(report.counts.maximum_group_size, 120);
});

test('CLI is exact-build, explicit, and Holdout fail-closed', () => {
  assert.throws(() => parseArgs([]), /explicit --replay/);
  assert.throws(() => parseArgs(['--build', '16.15.801.3452', '--replay', 'a.rofl']), /exact build/);
  assert.throws(() => parseArgs(['--replay', 'Jungle_Objective_Holdout/a.rofl']), /forbidden/);
  assert.equal(parseArgs(['--replay', 'a.rofl']).build, '16.16.805.0442');
});
