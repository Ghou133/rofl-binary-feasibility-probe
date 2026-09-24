'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { parseReplayBuffer } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const heroStats = require('../src/decoders/rofl_16_19_hero_stats_candidate');
const {
  HERO_STATS_SNAPSHOT_CAPABILITIES,
  analyzeReplayWithHeroStats,
  decodeHeroStatsByte,
  decodeHeroStatsSnapshotCandidateSet,
} = heroStats;

const BUILD = '16.19.820.7193';
const SELECTED = ['hero_minions_killed_snapshot', 'hero_deaths_snapshot'];
const ENCODE_BYTE = Array(256).fill(null);
for (let encoded = 0; encoded < 256; encoded += 1) {
  ENCODE_BYTE[decodeHeroStatsByte(encoded)] = encoded;
}
assert.ok(ENCODE_BYTE.every((value) => value !== null));

function payloadFor(minions, deaths) {
  const blob = Buffer.alloc(1260);
  blob.writeFloatLE(minions, 0x3c);
  blob.writeUInt32LE(deaths, 0x50);
  const payload = Buffer.alloc(1263);
  payload.set([0x1c, 0xa6, 0xe8], 0);
  for (let index = 0; index < blob.length; index += 1) {
    payload[index + 3] = ENCODE_BYTE[blob[blob.length - 1 - index]];
  }
  return payload;
}

function block(packetId, participantId, timeMs, payload) {
  const header = Buffer.alloc(15);
  header[0] = 0;
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(0x400000ad + participantId, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ foreignShape = false, version = BUILD } = {}) {
  const first = Buffer.concat(Array.from({ length: 10 }, (_, index) =>
    block(0x0276, index + 1, 0,
      foreignShape ? Buffer.from([1, 2]) : payloadFor(0, 0))));
  const second = Buffer.concat([
    ...Array.from({ length: 10 }, (_, index) =>
      block(0x0276, index + 1, 1000,
        foreignShape ? Buffer.from([1, 2]) : payloadFor(index + 1, index))),
    block(0x0300, 1, 1000, Buffer.from([0x77])),
  ]);
  const replay = replayFromChunks([
    { stream: 1, body: block(0x0276, 1, 500, Buffer.from([0x99])) },
    { stream: 2, body: first },
    { stream: 3, body: second },
  ], version);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    MINIONS_KILLED: String(index + 2),
    NUM_DEATHS: String(index + 1),
  }));
  return replay;
}

test('frozen capability list covers the ten shared HeroStats candidates', () => {
  assert.equal(Object.hasOwn(heroStats, 'createHeroStatsScanCollector'), false);
  assert.equal(Object.isFrozen(HERO_STATS_SNAPSHOT_CAPABILITIES), true);
  assert.deepEqual(HERO_STATS_SNAPSHOT_CAPABILITIES, [
    'hero_minions_killed_snapshot', 'hero_jungle_minions_killed_snapshot',
    'hero_experience_snapshot',
    'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot',
    'hero_champion_kills_snapshot', 'hero_deaths_snapshot',
    'hero_assists_snapshot',
    'hero_kill_stats_snapshot',
    'hero_ward_stats_snapshot',
  ]);
});

test('precollected same-Replay rows equal standalone candidate values and provenance', () => {
  const replay = fixture();
  const standalone = decodeHeroStatsSnapshotCandidateSet(replay, SELECTED);
  const { analysis, heroStatsScan: scan } = analyzeReplayWithHeroStats(replay,
    { strict: true });
  assert.equal(analysis.packet_count, 22);
  assert.equal(Object.isFrozen(scan), true);
  assert.equal(scan.status, 'PASS');
  assert.equal(scan.scanned_block_count, 21);
  assert.equal(Object.hasOwn(scan, 'rows'), false);
  Object.defineProperty(replay, 'chunks', { get() {
    throw new Error('precollected decode must not walk Replay chunks again');
  } });
  const reused = decodeHeroStatsSnapshotCandidateSet(replay, SELECTED, scan);
  assert.deepEqual(reused, standalone);
  assert.equal(reused.hero_deaths_snapshot.event_count, 20);
  assert.equal(reused.hero_deaths_snapshot.events[0].raw_packet_ref.replay_sha256,
    replay.source_sha256);
  assert.equal(reused.hero_deaths_snapshot.events.at(-1).raw_packet_ref.chunk_stream,
    'start_keyframe');
});

test('precollected scan rejects a different Replay and forged or copied tokens', () => {
  const replay = fixture();
  const { heroStatsScan: scan } = analyzeReplayWithHeroStats(replay, { strict: true });
  const secondReplay = parseReplayBuffer(Buffer.from(replay.buffer), replay.source_path);
  secondReplay.tail.stats = replay.tail.stats;
  assert.equal(secondReplay.source_sha256, replay.source_sha256);
  assert.notEqual(secondReplay, replay);
  for (const [input, supplied] of [
    [secondReplay, scan],
    [replay, { ...scan }],
    [replay, Object.freeze({ status: 'PASS', scanned_block_count: 21 })],
    [replay, null],
  ]) {
    const result = decodeHeroStatsSnapshotCandidateSet(input, SELECTED, supplied);
    assert.equal(result.hero_minions_killed_snapshot.status, 'DECODE_FAILED');
    assert.equal(result.hero_deaths_snapshot.status, 'DECODE_FAILED');
    assert.equal(result.hero_deaths_snapshot.events, null);
    assert.match(result.hero_deaths_snapshot.error, /different Replay or is unbound/);
  }
  replay.source_sha256 = 'changed';
  assert.equal(decodeHeroStatsSnapshotCandidateSet(replay, SELECTED, scan)
    .hero_deaths_snapshot.status, 'DECODE_FAILED');
});

test('HeroStats scans reject Replay byte and chunk-layout changes before candidate publication', () => {
  const changedBytes = fixture();
  changedBytes.buffer[changedBytes.chunks[1].body_offset + 15 + 10] ^= 0xff;
  const standalone = decodeHeroStatsSnapshotCandidateSet(changedBytes, SELECTED);
  assert.equal(standalone.hero_minions_killed_snapshot.status, 'DECODE_FAILED');
  assert.match(standalone.hero_minions_killed_snapshot.error, /source bytes differ/);
  const collected = analyzeReplayWithHeroStats(changedBytes, { strict: true });
  assert.equal(collected.heroStatsScan.status, 'DECODE_FAILED');
  assert.equal(decodeHeroStatsSnapshotCandidateSet(changedBytes, SELECTED,
    collected.heroStatsScan).hero_deaths_snapshot.status, 'DECODE_FAILED');

  const changedLayout = fixture();
  changedLayout.chunks[1].offset += 1;
  const layout = decodeHeroStatsSnapshotCandidateSet(changedLayout, SELECTED);
  assert.equal(layout.hero_deaths_snapshot.status, 'DECODE_FAILED');
  assert.match(layout.hero_deaths_snapshot.error, /chunk layout differs/);
});

test('foreign KR-like keyframe shape remains unavailable through precollection', () => {
  const replay = fixture({ foreignShape: true });
  const { heroStatsScan: scan } = analyzeReplayWithHeroStats(replay, { strict: true });
  assert.equal(scan.status, 'PROFILE_UNAVAILABLE');
  assert.equal(scan.observed_raw_route_count, 20);
  const reused = decodeHeroStatsSnapshotCandidateSet(replay, SELECTED, scan);
  const standalone = decodeHeroStatsSnapshotCandidateSet(replay, SELECTED);
  assert.deepEqual(reused, standalone);
  assert.equal(reused.hero_deaths_snapshot.event_count, null);
});

test('trusted analyzer wrapper keeps wrong build unsupported', () => {
  const replay = fixture({ version: '16.19.820.7194' });
  const { analysis, heroStatsScan: scan } = analyzeReplayWithHeroStats(replay,
    { strict: true });
  assert.equal(analysis.packet_count, 22);
  assert.equal(scan.status, 'UNSUPPORTED');
  assert.equal(decodeHeroStatsSnapshotCandidateSet(replay, SELECTED, scan)
    .hero_deaths_snapshot.status, 'UNSUPPORTED');
});

test('zero-chunk Replay cannot gain candidates from forged packet rows', () => {
  const replay = replayFromChunks([], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, () => ({
    MINIONS_KILLED: '1', NUM_DEATHS: '1',
  }));
  const { analysis, heroStatsScan: scan } = analyzeReplayWithHeroStats(replay,
    { strict: true });
  assert.equal(analysis.packet_count, 0);
  assert.equal(scan.status, 'PROFILE_UNAVAILABLE');
  assert.equal(decodeHeroStatsSnapshotCandidateSet(replay, SELECTED, scan)
    .hero_deaths_snapshot.status, 'PROFILE_UNAVAILABLE');
  const forged = {
    status: 'PASS', scanned_block_count: 10,
    rows: Array.from({ length: 10 }, (_, index) => ({
      block: {
        packet_id: 0x0276, param: 0x400000ae + index,
        timestamp_ms: 0, payload_length: 1263,
        payload: payloadFor(0, 0), offset: index, payload_offset: index + 15,
      },
      chunk: { index: 0, chunk_id: 1, stream: 'keyframe', offset: 0 },
    })),
  };
  const result = decodeHeroStatsSnapshotCandidateSet(replay, SELECTED, forged);
  assert.equal(result.hero_minions_killed_snapshot.status, 'DECODE_FAILED');
  assert.equal(result.hero_deaths_snapshot.status, 'DECODE_FAILED');
  assert.equal(result.hero_deaths_snapshot.events, null);
  assert.equal(Object.hasOwn(heroStats, 'createHeroStatsScanCollector'), false);
});
