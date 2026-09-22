'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  DEATH_16_16_BUILD,
  createDeathRouteAnchorValidation,
  participantIdFromDeathParam,
} = require('../src/validation/death_16_16');

function anchor(timestampMs, participantId) {
  return {
    anchor_id: `g:${timestampMs}:${participantId}:p0`,
    game_id: 'g',
    replay_sha256: 'a'.repeat(64),
    replay_build: DEATH_16_16_BUILD,
    timestamp_ms: timestampMs + 1000,
    participant_id: participantId,
    champion: 'Champion',
    frame_boundary_evidence: {
      associated_death_event_timestamp_ms: timestampMs,
      associated_death_event_json_path: '$.json.frames[1].events[2]',
    },
  };
}

function route(timestampMs, rawParam) {
  return {
    replay_sha256: 'a'.repeat(64),
    replay_build: DEATH_16_16_BUILD,
    timestamp_ms: timestampMs,
    packet_id: 0x0112,
    raw_param: rawParam,
    payload_length: 37,
    stream_tag: 1,
  };
}

test('death raw param participant mapping retains upper-byte variants', () => {
  assert.equal(participantIdFromDeathParam(0x400000ae), 1);
  assert.equal(participantIdFromDeathParam(0x400001b2), 5);
  assert.equal(participantIdFromDeathParam(0x400000b7), 10);
  assert.equal(participantIdFromDeathParam(0x400000ad), null);
});

test('death route validation requires exact one-to-one time and participant evidence', () => {
  const report = createDeathRouteAnchorValidation({
    anchorRows: [anchor(100, 1), anchor(200, 5)],
    routeRows: [route(101, 0x400000ae), route(200, 0x400001b2)],
  });
  assert.equal(report.status, 'PASS');
  assert.equal(report.matched_count, 2);
  assert.equal(report.timestamp_absolute_delta_ms.max, 1);
  assert.equal(report.matches[1].participant_mapping.upper_bytes_semantics, 'UNKNOWN_RETAINED_RAW');
});

test('death route validation fails closed on an unmatched or extra packet', () => {
  const report = createDeathRouteAnchorValidation({
    anchorRows: [anchor(100, 1)],
    routeRows: [route(100, 0x400000af)],
  });
  assert.equal(report.status, 'FAIL');
  assert.equal(report.unmatched_anchor_count, 1);
  assert.equal(report.unmatched_route_packet_count, 1);
});
