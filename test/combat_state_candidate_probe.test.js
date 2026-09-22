'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  TARGET_BUILD,
  classifyRouteCandidate,
  finalizeRouteAccumulator,
  isChampionNetworkId,
  newRouteAccumulator,
  observePacket,
  scanRuntimeNameBuffer,
  scanRuntimeImage,
} = require('../src/combat_state_candidate_probe');

test('combat-state probe classifies only structural candidates and never names a semantic field', () => {
  const accumulator = newRouteAccumulator(TARGET_BUILD, 0x7ffe);
  for (let champion = 0; champion < 10; champion += 1) {
    observePacket(accumulator, {
      chunk_stream: 'keyframe',
      chunk_index: 10,
      replay_key: 'replay-a',
      replay_time_ms: 60000,
      payload_length: 80,
      raw_param: 0x400000ae + champion,
      payload: Buffer.from([champion]),
    });
  }
  const row = finalizeRouteAccumulator(accumulator, 1);
  assert.equal(row.currently_decoded_as_status, 'UNREGISTERED_EXACT_BUILD_RAW_ONLY');
  assert.equal(row.structural_candidate_class, 'HERO_BOUND_KEYFRAME_SNAPSHOT_CANDIDATE');
  assert.equal(row.evidence_grade, 'CANDIDATE');
  assert.match(row.semantic_warning, /do not identify HP/);
  assert.equal(Object.hasOwn(row, 'current_hp'), false);
  assert.equal(Object.hasOwn(row, 'armor'), false);
});

test('registered exact-build routes are excluded from unknown structural classification', () => {
  const knownDamage = {
    currently_decoded_as_status: 'REGISTERED_EXACT_BUILD_ROUTE',
    count: 100,
    stream_counts: { game_chunk: 100 },
    payload_size_distribution: [{ payload_length: 17, count: 100 }],
    param_evidence: { champion_range_observations: 100, distinct_champion_network_ids: 10 },
    replay_count: 1,
    probe_replay_count: 1,
  };
  assert.equal(classifyRouteCandidate(knownDamage), null);
});

test('runtime class-name occurrences remain name-only candidate evidence', () => {
  const image = Buffer.from('xPKT_S2C_HeroStats_syPKT_S2C_HeroStats_sz', 'ascii');
  const rows = scanRuntimeNameBuffer(image, ['PKT_S2C_HeroStats_s', 'PKT_CombatStateChanged_s']);
  const heroStats = rows.find((row) => row.name === 'PKT_S2C_HeroStats_s');
  const combatState = rows.find((row) => row.name === 'PKT_CombatStateChanged_s');
  assert.equal(heroStats.occurrence_count, 2);
  assert.equal(heroStats.evidence_grade, 'CANDIDATE');
  assert.match(heroStats.semantic_status, /NO_PACKET_ROUTE_OR_FIELD_MAPPING/);
  assert.equal(combatState.occurrence_count, 0);
  assert.equal(combatState.evidence_grade, 'UNVERIFIED');
});

test('runtime image evidence fails closed when the exact-build SHA does not match', () => {
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-combat-image-'));
  try {
    const imagePath = path.join(temporaryDirectory, 'image.bin');
    fs.writeFileSync(imagePath, 'wrong-image');
    assert.throws(() => scanRuntimeImage(imagePath, {
      expectedBuild: TARGET_BUILD,
      expectedSha256: '0'.repeat(64),
    }), /does not match/);
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
});

test('champion network-id range is exact and bounded', () => {
  assert.equal(isChampionNetworkId(0x400000ae), true);
  assert.equal(isChampionNetworkId(0x400000b7), true);
  assert.equal(isChampionNetworkId(0x400000ad), false);
  assert.equal(isChampionNetworkId(0x400000b8), false);
});
