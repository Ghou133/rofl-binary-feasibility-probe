'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  REPLAY_VERSION_821,
  HERO_LEVEL_CANDIDATE_PROFILE_821,
  assessHeroLevelTail821,
  decodeHeroLevelCandidates821,
} = require('../src/decoders/rofl_16_19_821_level_candidate');

function packet(timestampMs, rawParam, payload, packetId = 0x0197) {
  const bytes = Buffer.from(payload);
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timestampMs / 1000, 1);
  header[5] = bytes.length;
  header.writeUInt16LE(packetId, 6);
  header.writeUInt32LE(rawParam >>> 0, 8);
  return Buffer.concat([header, bytes]);
}

function replayWithObservedRoute(options = {}) {
  const rows = [packet(0, 0x400000ae, [0xde])];
  for (let id = 1; id <= 10; id += 1) rows.push(packet(1000, 0x400000ad + id, [0xe5]));
  rows.push(packet(2000, 0x400000ae, [0xe2, 0x75]));
  rows.push(packet(4000, 0x400000ae, options.unknownCode ? [0xfa, 0x4d] : [0xe2, 0x0b]));
  rows.push(packet(2000, 0x400000b1, [0xe1, 0x75]));
  rows.push(packet(3000, 0x400001b1, [0xe4, 0x75]));
  // This distinct family has one real Replay lead; it is deliberately excluded.
  rows.push(packet(3000, 0x400002ae, [0xe7, 0x80]));
  if (options.decreasing) rows.push(packet(5000, 0x400000ae, [0xe2, 0x75]));
  if (options.badShape) rows.push(packet(5000, 0x400000b2, [0xe2, 0x75, 0x80]));
  if (options.badPrefix) rows.push(packet(5000, 0x400000b2, [0xe3, 0x75]));
  const replay = replayFromChunks([{ body: Buffer.concat(rows) }], options.version ?? REPLAY_VERSION_821);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    LEVEL: String(index === 0 ? options.firstTailLevel ?? (options.unknownCode ? 20 : 5)
      : index === 3 ? 3 : 2),
  }));
  return replay;
}

test('821 level tail assessment and profile require the exact build and ten valid levels', () => {
  assert.equal(HERO_LEVEL_CANDIDATE_PROFILE_821.replay_version, REPLAY_VERSION_821);
  assert.equal(HERO_LEVEL_CANDIDATE_PROFILE_821.evidence_runtime_image_sha256, null);
  const replay = replayWithObservedRoute();
  assert.deepEqual(assessHeroLevelTail821(replay), {
    status: 'PASS', levels: [5, 2, 2, 3, 2, 2, 2, 2, 2, 2],
  });
  replay.tail.stats[0].LEVEL = null;
  assert.equal(decodeHeroLevelCandidates821(replay).status, 'MISSING_INPUT');
  replay.tail.stats[0].LEVEL = '-1';
  assert.equal(assessHeroLevelTail821(replay).status, 'UNSUPPORTED');
  replay.tail.stats = [];
  assert.equal(assessHeroLevelTail821(replay).status, 'UNSUPPORTED');
  assert.equal(decodeHeroLevelCandidates821(replayWithObservedRoute({ version: '16.19.820.7193' })).status,
    'UNSUPPORTED');
});

test('821 level route emits observed values, repeats and gaps with exact raw packet provenance', () => {
  const replay = replayWithObservedRoute();
  const result = decodeHeroLevelCandidates821(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 15);
  assert.equal(result.event_count, 15);
  assert.equal(result.repeated_level_observation_count, 1);
  assert.equal(result.level_one_packet_count, 1);
  assert.equal(result.missing_level_update_count, 1);
  assert.deepEqual(result.missing_level_updates[0], [4]);
  assert.equal(result.unclassified_adjacent_prefix_count, 1);
  assert.equal(result.unclassified_adjacent_prefix_refs[0].raw_param, 0x400002ae);
  assert.deepEqual(result.observed_max_levels, result.final_levels);
  assert.equal(result.runtime_image_used, false);
  assert.deepEqual(result.events.filter((event) => event.participant_id_candidate === 1)
    .map((event) => event.level_after_candidate), [1, 2, 3, 5]);
  const repeated = result.events.find((event) => event.observation_kind === 'REPEATED_LEVEL_OBSERVATION');
  assert.equal(repeated.participant_id_candidate, 4);
  assert.equal(repeated.hero_raw_param, 0x400001b1);
  assert.equal(repeated.level_after_candidate, 3);
  assert.ok(result.events.every((event) => event.raw_packet_ref.replay_sha256 === replay.source_sha256
    && event.raw_packet_ref.packet_id === 0x0197
    && event.raw_packet_ref.raw_payload_sha256.length === 64
    && event.confidence === 'CANDIDATE'));
});

test('821 candidate fails closed on uncalibrated code, malformed shape and sequence conflicts', () => {
  const unknown = decodeHeroLevelCandidates821(replayWithObservedRoute({ unknownCode: true }));
  assert.equal(unknown.status, 'DECODE_FAILED');
  assert.equal(unknown.events, null);
  assert.match(unknown.error, /unclassified 821 level payload fa4d/);
  assert.equal(unknown.rejected_packet_ref.raw_payload_hex, 'fa4d');
  for (const options of [
    { badShape: true },
    { badPrefix: true },
    { decreasing: true },
    { firstTailLevel: 4 },
    { firstTailLevel: 6 },
  ]) {
    const result = decodeHeroLevelCandidates821(replayWithObservedRoute(options));
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
  }
});

test('821 level candidate requires its route, strict framing and original Replay bytes', () => {
  const empty = replayFromChunks([{ body: packet(1000, 0x400000ae, [0xe5], 0x0100) }],
    REPLAY_VERSION_821);
  assert.equal(decodeHeroLevelCandidates821(empty).status, 'PROFILE_UNAVAILABLE');
  const wrongParam = replayFromChunks([{ body: packet(1000, 0x500000ae, [0xe5]) }],
    REPLAY_VERSION_821);
  assert.equal(decodeHeroLevelCandidates821(wrongParam).status, 'PROFILE_UNAVAILABLE');
  const malformed = replayFromChunks([{ body: Buffer.from([0x10]) }], REPLAY_VERSION_821);
  assert.match(decodeHeroLevelCandidates821(malformed).error, /Replay framing failed/);
  const changed = replayWithObservedRoute();
  changed.buffer[0] ^= 1;
  assert.match(decodeHeroLevelCandidates821(changed).error, /Replay source integrity failed/);
});
