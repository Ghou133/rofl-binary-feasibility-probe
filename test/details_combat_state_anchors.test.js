'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');

const {
  ANCHOR_TYPE,
  REQUIRED_KEY_GAME_IDS,
  TARGET_REPLAY_BUILD,
  TARGET_SUMMARY_BUILD,
  assertRequiredKeySamples,
  extractDetailsCombatStateAnchors,
  healthTransition,
  unwrapSgpDocument,
} = require('../src/details_combat_state_anchors');
const {
  parseArgs,
  parseSampleSpec,
} = require('../scripts/build_details_combat_state_anchors');

function wrapper(infoType, gameId, json) {
  return {
    json,
    metadata: {
      data_version: '2',
      info_type: infoType,
      match_id: `HN1_${gameId}`,
      participants: ['one', 'two'],
      private: false,
      product: 'lol',
      tags: ['ranked', 'q_420'],
      timestamp: '123456',
    },
  };
}

function participantFrame(participantId, level, health, healthMax, armor, magicResist) {
  return {
    participantId,
    level,
    championStats: {
      health,
      healthMax,
      armor,
      magicResist,
    },
  };
}

function fixtureDocuments(overrides = {}) {
  const gameId = overrides.gameId ?? '42';
  const summary = wrapper('summary', gameId, {
    gameId: Number(gameId),
    gameVersion: overrides.summaryBuild ?? TARGET_SUMMARY_BUILD,
    platformId: 'HN1',
    participants: [
      { participantId: 1, championName: 'Ahri', teamId: 100 },
      { participantId: 2, championName: 'Garen', teamId: 200 },
    ],
  });
  const details = wrapper('details', gameId, {
    gameId: Number(gameId),
    participants: [
      { participantId: 1, puuid: 'one' },
      { participantId: 2, puuid: 'two' },
    ],
    frames: [
      {
        timestamp: 0,
        participantFrames: {
          1: participantFrame(1, 1, 100, 100, 30, 30),
          2: participantFrame(2, 1, 120, 120, 35, 32),
        },
        events: [],
      },
      {
        timestamp: 60000,
        participantFrames: {
          1: participantFrame(1, 1, 0, 100, 30, 30),
          2: participantFrame(2, 1, 110, 120, 35, 32),
        },
        events: [{
          type: 'CHAMPION_KILL',
          timestamp: 50000,
          killerId: 2,
          victimId: 1,
          victimDamageReceived: [{
            participantId: 2,
            name: 'Garen',
            physicalDamage: 100,
            magicDamage: 0,
            trueDamage: 0,
          }],
        }],
      },
      {
        timestamp: 120000,
        participantFrames: {
          1: participantFrame(1, 1, 80, 100, 30, 30),
          2: participantFrame(2, 1, 120, 120, 35, 32),
        },
        events: [],
      },
    ],
  });
  return { gameId, details, summary };
}

function extractFixture(overrides = {}) {
  const documents = fixtureDocuments(overrides);
  return extractDetailsCombatStateAnchors({
    gameId: documents.gameId,
    replayBuild: overrides.replayBuild ?? TARGET_REPLAY_BUILD,
    replaySha256: 'a'.repeat(64),
    replayPath: path.resolve('fixture.rofl'),
    replayByteSize: 100,
    detailsDocument: documents.details,
    detailsPath: path.resolve('details.json'),
    detailsSha256: 'b'.repeat(64),
    detailsByteSize: 200,
    summaryDocument: documents.summary,
    summaryPath: path.resolve('summary.json'),
    summarySha256: 'c'.repeat(64),
    summaryByteSize: 300,
  });
}

test('DETAILS participantFrames become deterministic minute-frame x participant P0 anchors', () => {
  const result = extractFixture();
  assert.equal(result.records.length, 6);
  assert.equal(result.provenance.frame_count, 3);
  assert.equal(result.provenance.participant_count, 2);
  assert.equal(result.provenance.zero_health_anchor_count, 1);
  assert.deepEqual(result.provenance.participant_mapping.map((row) => [row.participant_id, row.champion]), [
    [1, 'Ahri'],
    [2, 'Garen'],
  ]);

  const first = result.records[0];
  assert.equal(first.anchor_type, ANCHOR_TYPE);
  assert.equal(first.game_id, '42');
  assert.equal(first.replay_sha256, 'a'.repeat(64));
  assert.deepEqual(
    [first.participant_id, first.champion, first.current_hp, first.max_hp, first.armor, first.magic_resist],
    [1, 'Ahri', 100, 100, 30, 30],
  );
  assert.equal(first.source.champion_stats_json_path,
    '$.json.frames[0].participantFrames["1"].championStats');
  assert.deepEqual(first.source.field_keys, {
    current_hp: 'health',
    max_hp: 'healthMax',
    armor: 'armor',
    magic_resist: 'magicResist',
  });
});

test('zero-health and positive-health transitions retain death and bounded respawn evidence', () => {
  const result = extractFixture();
  const zero = result.records.find((row) => row.participant_id === 1 && row.timestamp_ms === 60000);
  assert.equal(zero.health_state, 'ZERO_HEALTH');
  assert.equal(zero.frame_boundary_evidence.health_transition, 'POSITIVE_TO_ZERO');
  assert.equal(zero.frame_boundary_evidence.associated_death_event_timestamp_ms, 50000);
  assert.equal(zero.frame_boundary_evidence.associated_death_event_json_path,
    '$.json.frames[1].events[0]');

  const positive = result.records.find((row) => row.participant_id === 1 && row.timestamp_ms === 120000);
  assert.equal(positive.frame_boundary_evidence.health_transition, 'ZERO_TO_POSITIVE');
  assert.equal(positive.frame_boundary_evidence.respawn_lower_bound_timestamp_ms, 60000);
  assert.equal(positive.frame_boundary_evidence.respawn_upper_bound_timestamp_ms, 120000);
  assert.equal(positive.frame_boundary_evidence.exact_respawn_timestamp_available, false);
  assert.equal(healthTransition(0, 0), 'ZERO_TO_ZERO');
});

test('extraction fails closed on non-exact builds and non-wrapper documents', () => {
  assert.throws(() => extractFixture({ replayBuild: '16.15.801.3452' }), /not exact target/);
  assert.throws(() => extractFixture({ summaryBuild: '16.16.805.441' }), /not exact target/);
  assert.throws(() => unwrapSgpDocument({ gameId: 42 }, 'DETAILS', 'details'), /top-level \{json, metadata\}/);
});

test('key sample gate requires all four explicitly named replay ids', () => {
  assert.doesNotThrow(() => assertRequiredKeySamples(REQUIRED_KEY_GAME_IDS));
  assert.throws(() => assertRequiredKeySamples(REQUIRED_KEY_GAME_IDS.slice(1)), /required key samples are missing/);
});

test('builder CLI accepts only explicit four-part sample specifications', () => {
  const replay = path.resolve('one.rofl');
  const details = path.resolve('one-details.json');
  const summary = path.resolve('one-summary.json');
  const parsedSample = parseSampleSpec(`42|${replay}|${details}|${summary}`);
  assert.deepEqual(parsedSample, {
    gameId: '42',
    replayPath: replay,
    detailsPath: details,
    summaryPath: summary,
  });
  assert.throws(() => parseSampleSpec('42|only-two'), /requires GAME_ID/);
  const cli = parseArgs(['--sample', `42|${replay}|${details}|${summary}`]);
  assert.equal(cli.samples.length, 1);
  assert.match(cli.jsonlPath, /details_p0_ground_truth\.jsonl$/);
  assert.match(cli.manifestPath, /details_p0_manifest\.json$/);
});
