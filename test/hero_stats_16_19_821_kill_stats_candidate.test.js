'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const {
  HERO_KILL_STATS_SNAPSHOT_821_CANDIDATE_PROFILE: PROFILE,
  assessHeroKillStatsTail821,
  decodeHeroKillStatsSnapshotCandidates821,
} = require('../src/decoders/rofl_16_19_821_kill_stats_candidate');

const BUILD = '16.19.821.7343';
const FIELDS = [
  ['LARGEST_KILLING_SPREE', 'largest_killing_spree_candidate', 0x58],
  ['KILLING_SPREES', 'killing_sprees_candidate', 0x5c],
  ['LARGEST_MULTI_KILL', 'largest_multi_kill_candidate', 0x60],
  ['DOUBLE_KILLS', 'double_kills_candidate', 0x64],
  ['TRIPLE_KILLS', 'triple_kills_candidate', 0x68],
  ['QUADRA_KILLS', 'quadra_kills_candidate', 0x6c],
];
const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));

function writeCount(payload, offset, value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  for (let i = 0; i < 4; i += 1) {
    payload[1262 - offset - i] = ENCODE.get(bytes[i]);
  }
}

function packet(participant, values, timeMs, change = null) {
  const payload = Buffer.alloc(1263, ENCODE.get(0));
  payload.set([0x67, 0x00, 0xde]);
  FIELDS.forEach(([, , offset], index) => writeCount(payload, offset, values[index]));
  if (change) change(payload);
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participant, 11);
  return Buffer.concat([header, payload]);
}

function fixture({ version = BUILD, change = null, decrease = false,
  duplicateParticipant = false } = {}) {
  const chunks = Array.from({ length: decrease ? 3 : 2 }, (_, frame) => ({
    stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) => {
      const participant = index + 1;
      let values = [0, 0, 0, 0, 0, 0];
      if (frame === 1 || frame === 2) {
        if (participant === 1) values = [2, 1, 2, 1, 0, 0];
        if (participant === 2) values = [4, 1, 4, 1, 1, 1];
      }
      if (decrease && frame === 2 && participant === 1) values = [1, 1, 2, 1, 0, 0];
      return packet(duplicateParticipant && frame === 1 && participant === 2
        ? 1 : participant, values, frame * 1000,
      change && change.frame === frame && change.participant === participant
        ? change.edit : null);
    })),
  }));
  const replay = replayFromChunks(chunks, version);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) =>
    Object.fromEntries(FIELDS.map(([field], fieldIndex) => [field,
      String(index === 0 ? [3, 2, 2, 1, 0, 0][fieldIndex]
        : index === 1 ? [4, 1, 4, 1, 1, 1][fieldIndex] : 0),
    ])));
  return replay;
}

test('821 kill stats decode six distinct candidate fields and retain source and final gaps', () => {
  const replay = fixture();
  assert.equal(PROFILE.replay_version, BUILD);
  assert.equal(PROFILE.replay_block_packet_id, 0x0089);
  const assessed = assessHeroKillStatsTail821(replay);
  assert.equal(assessed.status, 'PASS');
  assert.deepEqual(assessed.required_fields.map((row) => row.field),
    FIELDS.map(([field]) => field));
  const output = decodeHeroKillStatsSnapshotCandidates821(replay);
  assert.equal(output.status, 'CANDIDATE');
  assert.equal(output.event_count, 20);
  assert.equal(output.keyframe_count, 2);
  assert.equal(output.events[10].participant_id_candidate, 1);
  assert.equal(output.events[11].participant_id_candidate, 2);
  assert.deepEqual(FIELDS.map(([, key]) => output.events[10][key]), [2, 1, 2, 1, 0, 0]);
  assert.deepEqual(FIELDS.map(([, key]) => output.events[11][key]), [4, 1, 4, 1, 1, 1]);
  assert.equal(output.events[10].decoded_field_bytes_hex.LARGEST_KILLING_SPREE, '02000000');
  assert.equal(output.events[10].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(output.events[10].confidence, 'CANDIDATE');
  assert.match(output.events[11].field_confidence.quadra_kills_candidate, /SPARSE/);
  assert.equal(output.tail_gaps[0].field_gaps.LARGEST_KILLING_SPREE.unobserved_tail_gap, 1);
  assert.equal(output.tail_gap_totals.KILLING_SPREES, 1);
  assert.equal(output.tail_gap_totals.TRIPLE_KILLS, 0);
  assert.equal(output.runtime_image_used, false);
  assert.equal(Object.hasOwn(output.events[11], 'penta_kills_candidate'), false);
});

test('821 kill stats fail closed on foreign build and missing or invalid Replay tails', () => {
  assert.equal(decodeHeroKillStatsSnapshotCandidates821(
    fixture({ version: '16.19.820.7193' })).status, 'UNSUPPORTED');
  const missing = fixture();
  delete missing.tail.stats[0].TRIPLE_KILLS;
  const absent = decodeHeroKillStatsSnapshotCandidates821(missing);
  assert.equal(absent.status, 'MISSING_INPUT');
  assert.match(absent.error, /TRIPLE_KILLS/);
  const preflight = assessHeroKillStatsTail821(missing);
  assert.equal(preflight.required_fields.length, 6);
  assert.equal(preflight.required_fields.find((row) => row.field === 'TRIPLE_KILLS')
    .status, 'MISSING_INPUT');
  const invalid = fixture();
  invalid.tail.stats[0].QUADRA_KILLS = '1.5';
  assert.equal(decodeHeroKillStatsSnapshotCandidates821(invalid).status, 'UNSUPPORTED');
});

test('821 kill stats reject out-of-profile values, a decrease and a duplicate participant', () => {
  const above = fixture();
  above.tail.stats[0].DOUBLE_KILLS = '0';
  const aboveResult = decodeHeroKillStatsSnapshotCandidates821(above);
  assert.equal(aboveResult.status, 'DECODE_FAILED');
  assert.match(aboveResult.error, /exceeds Replay tail DOUBLE_KILLS/);
  assert.equal(aboveResult.first_unmatched_packet_ref.packet_id, 0x0089);

  const first = decodeHeroKillStatsSnapshotCandidates821(fixture({
    change: { frame: 0, participant: 1,
      edit(payload) { writeCount(payload, 0x58, 1); } },
  }));
  assert.equal(first.status, 'DECODE_FAILED');
  assert.match(first.error, /first LARGEST_KILLING_SPREE candidate is not zero/);

  const decreasing = decodeHeroKillStatsSnapshotCandidates821(fixture({ decrease: true }));
  assert.equal(decreasing.status, 'DECODE_FAILED');
  assert.match(decreasing.error, /decreasing LARGEST_KILLING_SPREE/);

  const duplicate = decodeHeroKillStatsSnapshotCandidates821(
    fixture({ duplicateParticipant: true }));
  assert.equal(duplicate.status, 'DECODE_FAILED');
  assert.match(duplicate.error, /duplicates participant/);
});

test('821 kill stats reject a mutated Replay source before decoding', () => {
  const replay = fixture();
  replay.buffer[replay.chunks[0].body_offset + 15 + 700] ^= 1;
  const output = decodeHeroKillStatsSnapshotCandidates821(replay);
  assert.equal(output.status, 'DECODE_FAILED');
  assert.match(output.error, /Replay source failed/);
});
