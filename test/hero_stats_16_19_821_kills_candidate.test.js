'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { collect821Routes, rowsFor821Capability } =
  require('../src/decoders/rofl_16_19_821_scan');
const {
  HERO_CHAMPION_KILLS_SNAPSHOT_821_CANDIDATE_PROFILE,
  assessHeroChampionKillsSnapshotTail821,
  decodeHeroChampionKillsSnapshotCandidates821,
  decodeHeroDeathsSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_hero_stats_candidate');

const BUILD = '16.19.821.7343';
const CODES = [
  0x97, 0xcc, 0x55, 0xf1, 0x6f, 0x8d, 0x58, 0x02, 0xb7,
  0xde, 0x3f, 0xb6, 0xbe, 0xbb, 0xc8, 0xea, 0xef, 0xd6,
];

function block(param, timeMs, payload) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(param >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function fixture({
  version = BUILD,
  frames = [Array(10).fill(0), [17, 12, ...Array(8).fill(0)]],
  tails = [17, 16, ...Array(8).fill(0)],
  mutate = null,
  startRoute = false,
} = {}) {
  const chunks = [];
  if (startRoute) {
    const payload = Buffer.alloc(1263, 0x97);
    payload.set([0x67, 0x00, 0xde]);
    chunks.push({ stream: 3, body: block(0x400000ae, 0, payload) });
  }
  for (const [frameIndex, counts] of frames.entries()) {
    const packets = counts.map((count, index) => {
      const item = { param: 0x400000ae + index, timeMs: frameIndex * 1000,
        payload: Buffer.alloc(1263, 0x97) };
      item.payload.set([0x67, 0x00, 0xde]);
      item.payload[434] = CODES[count];
      item.payload[1186] = CODES[count];
      if (mutate) mutate(item, frameIndex, index);
      return block(item.param, item.timeMs, item.payload);
    });
    chunks.push({ stream: 2, body: Buffer.concat(packets) });
  }
  const replay = replayFromChunks(chunks, version);
  replay.tail.stats = tails.map((count) => ({
    CHAMPIONS_KILLED: String(count), NUM_DEATHS: '0',
  }));
  return replay;
}

test('821 fixed finite mirrored-byte codebook emits candidate snapshots and measured tail gaps', () => {
  const replay = fixture();
  const profile = HERO_CHAMPION_KILLS_SNAPSHOT_821_CANDIDATE_PROFILE;
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.evidence_runtime_image_sha256, null);
  assert.equal(profile.raw_champion_kills_byte_index, 1186);
  assert.equal(profile.raw_champion_kills_mirror_byte_index, 434);
  assert.deepEqual(profile.encoded_byte_for_champion_kill_count_candidate, CODES);
  assert.equal(assessHeroChampionKillsSnapshotTail821(replay).status, 'PASS');
  const result = decodeHeroChampionKillsSnapshotCandidates821(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 20);
  assert.equal(result.input_count, 20);
  assert.equal(result.keyframe_count, 2);
  assert.deepEqual(result.observed_max_champion_kills,
    [17, 12, ...Array(8).fill(0)]);
  assert.equal(result.tail_gap_total, 4);
  assert.equal(result.tail_gaps[1].unobserved_tail_gap, 4);
  assert.equal(result.events[10].champion_kills_candidate, 17);
  assert.equal(result.events[10].raw_champion_kills_byte, 0xd6);
  assert.equal(result.events[10].raw_champion_kills_mirror_byte, 0xd6);
  assert.equal(result.events[10].observation_kind, 'KEYFRAME_SNAPSHOT');
  assert.equal(result.events[10].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[10].field_confidence.champion_kills_candidate,
    result.evidence_status);
  assert.equal(result.runtime_image_used, false);
});

test('821 kills tail, source, and exact build failures stay explicit', () => {
  assert.equal(decodeHeroChampionKillsSnapshotCandidates821(
    fixture({ version: '16.19.820.7193' })).status, 'UNSUPPORTED');
  const missing = fixture();
  missing.tail.stats = null;
  assert.equal(decodeHeroChampionKillsSnapshotCandidates821(missing).status,
    'MISSING_INPUT');
  const invalid = fixture();
  invalid.tail.stats[0].CHAMPIONS_KILLED = 'unknown';
  assert.equal(decodeHeroChampionKillsSnapshotCandidates821(invalid).status,
    'UNSUPPORTED');
  const changed = fixture();
  changed.buffer[changed.chunks[0].body_offset + 15 + 1186] ^= 1;
  const result = decodeHeroChampionKillsSnapshotCandidates821(changed);
  assert.equal(result.status, 'DECODE_FAILED');
  assert.match(result.error, /Replay source failed/);
});

test('821 kills rejects unknown code, mirror mismatch, bad param, and foreign start route', () => {
  const cases = [
    [(item) => { item.payload[434] = item.payload[1186] = 0x4d; }, /unknown code/],
    [(item) => { item.payload[434] ^= 1; }, /bytes 1186 and 434 differ/],
    [(item) => { item.param = 0x400000bd; }, /unsupported raw param/],
    [(item) => { item.payload[0] ^= 1; }, /length or prefix/],
  ];
  for (const [change, message] of cases) {
    const replay = fixture({ mutate(item, frame, index) {
      if (frame === 1 && index === 0) change(item);
    } });
    const result = decodeHeroChampionKillsSnapshotCandidates821(replay);
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
    assert.match(result.error, message);
    assert.equal(result.first_unmatched_packet_ref.raw_param,
      change === cases[2][0] ? 0x400000bd : 0x400000ae);
  }
  const startRoute = decodeHeroChampionKillsSnapshotCandidates821(fixture({ startRoute: true }));
  assert.match(startRoute.error, /start_keyframe/);
});

test('821 kills rejects nonzero first count, declines and values above tail', () => {
  const first = decodeHeroChampionKillsSnapshotCandidates821(fixture({
    frames: [Array(10).fill(1)], tails: Array(10).fill(1),
  }));
  assert.match(first.error, /not zero/);
  const decline = decodeHeroChampionKillsSnapshotCandidates821(fixture({
    frames: [Array(10).fill(0), Array(10).fill(2), Array(10).fill(1)],
    tails: Array(10).fill(2),
  }));
  assert.match(decline.error, /decreasing/);
  const above = decodeHeroChampionKillsSnapshotCandidates821(fixture({
    tails: Array(10).fill(0),
  }));
  assert.match(above.error, /exceeds Replay tail CHAMPIONS_KILLED/);
});

test('821 shared scan serves deaths and kills from one selected 0x0089 route', () => {
  const replay = fixture();
  const token = collect821Routes(replay,
    ['hero_deaths_snapshot', 'hero_champion_kills_snapshot']);
  assert.equal(rowsFor821Capability(replay, token, 'hero_deaths_snapshot').rows.length, 20);
  assert.equal(rowsFor821Capability(replay, token, 'hero_champion_kills_snapshot').rows.length, 20);
  const deaths = decodeHeroDeathsSnapshotCandidates821(replay, token);
  const kills = decodeHeroChampionKillsSnapshotCandidates821(replay, token);
  assert.equal(deaths.status, 'CANDIDATE');
  assert.equal(kills.status, 'CANDIDATE');
  assert.equal(kills.event_count, 20);
  const killsOnly = collect821Routes(replay, ['hero_champion_kills_snapshot']);
  assert.match(rowsFor821Capability(replay, killsOnly, 'hero_deaths_snapshot').error,
    /not selected/);
  assert.equal(decodeHeroChampionKillsSnapshotCandidates821(replay, killsOnly).status,
    'CANDIDATE');
});
