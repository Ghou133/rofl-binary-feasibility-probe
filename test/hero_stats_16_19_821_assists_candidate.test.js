'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { collect821Routes, rowsFor821Capability } =
  require('../src/decoders/rofl_16_19_821_scan');
const {
  HERO_ASSISTS_SNAPSHOT_821_CANDIDATE_PROFILE,
  assessHeroAssistsSnapshotTail821,
  decodeHeroAssistsSnapshotCandidates821,
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
  tails = [21, 14, ...Array(8).fill(0)],
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
      item.payload[1178] = CODES[count];
      if (mutate) mutate(item, frameIndex, index);
      return block(item.param, item.timeMs, item.payload);
    });
    chunks.push({ stream: 2, body: Buffer.concat(packets) });
  }
  const replay = replayFromChunks(chunks, version);
  replay.tail.stats = tails.map((count) => ({ ASSISTS: String(count) }));
  return replay;
}

test('821 assists finite raw-byte candidate reports snapshots and an unbounded measured tail gap', () => {
  const profile = HERO_ASSISTS_SNAPSHOT_821_CANDIDATE_PROFILE;
  assert.equal(profile.replay_version, BUILD);
  assert.equal(profile.raw_assists_byte_index, 1178);
  assert.equal(profile.evidence_runtime_image_sha256, null);
  assert.deepEqual(profile.encoded_byte_for_assist_count_candidate, CODES);
  const replay = fixture();
  assert.equal(assessHeroAssistsSnapshotTail821(replay).status, 'PASS');
  const result = decodeHeroAssistsSnapshotCandidates821(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 20);
  assert.equal(result.input_count, 20);
  assert.equal(result.keyframe_count, 2);
  assert.deepEqual(result.observed_max_assists,
    [17, 12, ...Array(8).fill(0)]);
  assert.equal(result.tail_gap_total, 6);
  assert.equal(result.tail_gaps[0].unobserved_tail_gap, 4);
  assert.equal(result.events[10].event_type, 'HERO_ASSISTS_SNAPSHOT_CANDIDATE');
  assert.equal(result.events[10].assists_candidate, 17);
  assert.equal(result.events[10].raw_assists_byte, 0xd6);
  assert.equal(result.events[10].observation_kind, 'KEYFRAME_SNAPSHOT');
  assert.equal(result.events[10].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[10].field_confidence.assists_candidate,
    result.evidence_status);
  assert.equal(result.runtime_image_used, false);
});

test('821 assists rejects wrong build, missing or invalid tail, and source mutation', () => {
  assert.equal(decodeHeroAssistsSnapshotCandidates821(
    fixture({ version: '16.19.820.7193' })).status, 'UNSUPPORTED');
  const missing = fixture();
  missing.tail.stats = null;
  assert.equal(decodeHeroAssistsSnapshotCandidates821(missing).status,
    'MISSING_INPUT');
  const invalid = fixture();
  invalid.tail.stats[0].ASSISTS = 'unknown';
  assert.equal(decodeHeroAssistsSnapshotCandidates821(invalid).status,
    'UNSUPPORTED');
  const changed = fixture();
  changed.buffer[changed.chunks[0].body_offset + 15 + 1178] ^= 1;
  const result = decodeHeroAssistsSnapshotCandidates821(changed);
  assert.equal(result.status, 'DECODE_FAILED');
  assert.match(result.error, /Replay source failed/);
});

test('821 assists fails closed on unknown code, foreign packet shape, and foreign start route', () => {
  const cases = [
    [(item) => { item.payload[1178] = 0x9d; }, /unknown code/],
    [(item) => { item.param = 0x400000bd; }, /unsupported raw param/],
    [(item) => { item.payload[0] ^= 1; }, /length or prefix/],
  ];
  for (const [change, message] of cases) {
    const replay = fixture({ mutate(item, frame, index) {
      if (frame === 1 && index === 0) change(item);
    } });
    const result = decodeHeroAssistsSnapshotCandidates821(replay);
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
    assert.match(result.error, message);
    assert.ok(result.first_unmatched_packet_ref);
  }
  const startRoute = decodeHeroAssistsSnapshotCandidates821(fixture({ startRoute: true }));
  assert.match(startRoute.error, /start_keyframe/);
});

test('821 assists rejects nonzero first count, declines, and values above tail', () => {
  const first = decodeHeroAssistsSnapshotCandidates821(fixture({
    frames: [Array(10).fill(1)], tails: Array(10).fill(1),
  }));
  assert.match(first.error, /not zero/);
  const decline = decodeHeroAssistsSnapshotCandidates821(fixture({
    frames: [Array(10).fill(0), Array(10).fill(2), Array(10).fill(1)],
    tails: Array(10).fill(2),
  }));
  assert.match(decline.error, /decreasing/);
  const above = decodeHeroAssistsSnapshotCandidates821(fixture({
    tails: Array(10).fill(0),
  }));
  assert.match(above.error, /exceeds Replay tail ASSISTS/);
});

test('821 assists shares the selected keyframe route without bypassing scan binding', () => {
  const replay = fixture();
  const token = collect821Routes(replay, ['hero_assists_snapshot']);
  assert.equal(rowsFor821Capability(replay, token, 'hero_assists_snapshot').rows.length, 20);
  assert.equal(decodeHeroAssistsSnapshotCandidates821(replay, token).status,
    'CANDIDATE');
  const other = fixture();
  const foreign = decodeHeroAssistsSnapshotCandidates821(other, token);
  assert.equal(foreign.status, 'DECODE_FAILED');
  assert.match(foreign.error, /different Replay/);
});
