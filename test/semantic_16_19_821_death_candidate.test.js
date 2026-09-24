'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  REPLAY_VERSION_821,
  HERO_DEATH_CANDIDATE_PROFILE_821,
  assessHeroDeathTail821,
  decodeHeroDeathCandidates821,
} = require('../src/decoders/rofl_16_19_821_7343');

function packet(packetId, timestampMs, rawParam, payloadLength) {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timestampMs / 1000, 1);
  header[5] = payloadLength;
  header.writeUInt16LE(packetId, 6);
  header.writeUInt32LE(rawParam >>> 0, 8);
  return Buffer.concat([header, Buffer.alloc(payloadLength, packetId & 0xff)]);
}

function replayWithRoute(options = {}) {
  const rows = [];
  for (const [index, participantId] of [1, 4].entries()) {
    const timestampMs = index && options.sameTime ? 1000 : 1000 + index * 1000;
    const rawParam = 0x400000ad + participantId;
    if (!(options.missingShort && index)) {
      rows.push(packet(0x03d4, timestampMs, options.badCorroboratingParam && index ? 1 : 0,
        options.badShortLength && index ? 4 : 3));
      if (options.duplicateShort && index) rows.push(packet(0x03d4, timestampMs, 0, 3));
    }
    if (!(options.missingLong && index)) rows.push(packet(0x031b, timestampMs, 0, 12));
    rows.push(packet(0x0259, timestampMs,
      options.badPrimaryParam && index ? 0x400000ac
        : options.badHighPrefix && index ? 0x500000b1 : rawParam,
      options.badPrimaryLength && index ? 4 : 5));
    if (options.duplicatePrimary && index) rows.push(packet(0x0259, timestampMs, rawParam, 5));
    if (!(options.missingPair && index)) {
      rows.push(packet(0x0438, timestampMs,
        options.badPairParam && index ? rawParam + 1 : rawParam, 13));
      if (options.duplicatePair && index) rows.push(packet(0x0438, timestampMs, rawParam, 13));
    }
  }
  if (options.extraPrimary) {
    rows.push(packet(0x0259, 3000, 0x400000b6, 5));
    rows.push(packet(0x0259, 3000, 0x400000b7, 5));
  }
  if (options.extraShort) rows.push(packet(0x03d4, 3000, 0, 3));
  if (options.extraLong) rows.push(packet(0x031b, 3000, 0, 12));
  if (options.extraPair) rows.push(packet(0x0438, 3000, 0x400000b6, 13));
  const replay = replayFromChunks([{ body: Buffer.concat(rows) }],
    options.version ?? REPLAY_VERSION_821);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: String(index === 0 || index === 3 ? 1 : 0),
  }));
  return replay;
}

test('821 death profile and tail preflight are exact and fail closed on missing counts', () => {
  assert.equal(HERO_DEATH_CANDIDATE_PROFILE_821.replay_version, REPLAY_VERSION_821);
  assert.equal(HERO_DEATH_CANDIDATE_PROFILE_821.evidence_runtime_image_sha256, null);
  const replay = replayWithRoute();
  assert.deepEqual(assessHeroDeathTail821(replay), {
    status: 'PASS', counts: [1, 0, 0, 1, 0, 0, 0, 0, 0, 0],
  });
  replay.tail.stats[0].NUM_DEATHS = null;
  assert.equal(assessHeroDeathTail821(replay).status, 'MISSING_INPUT');
  assert.equal(decodeHeroDeathCandidates821(replay).status, 'MISSING_INPUT');
  replay.tail.stats[0].NUM_DEATHS = '-1';
  assert.equal(assessHeroDeathTail821(replay).status, 'UNSUPPORTED');
  replay.tail.stats = [];
  assert.equal(assessHeroDeathTail821(replay).status, 'UNSUPPORTED');
});

test('four 821 routes produce candidate victim/time with original distinct packet refs', () => {
  const replay = replayWithRoute();
  const result = decodeHeroDeathCandidates821(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 2);
  assert.equal(result.input_count, 2);
  assert.equal(result.supporting_packet_count, 8);
  assert.equal(result.matched_core_count, 2);
  assert.equal(result.unmatched_primary_count, 0);
  assert.equal(result.missing_optional_0x03d4_count, 0);
  assert.equal(result.runtime_image_used, false);
  assert.deepEqual(result.observed_death_counts, result.final_death_counts);
  assert.deepEqual(result.events.map((event) => event.victim_participant_id), [1, 4]);
  assert.deepEqual(result.events.map((event) => event.replay_time_ms), [1000, 2000]);
  for (const event of result.events) {
    assert.equal(event.game_version, REPLAY_VERSION_821);
    assert.equal(event.confidence, 'CANDIDATE');
    assert.equal(event.killer_network_id, null);
    assert.equal(event.respawn_timestamp_ms, null);
    assert.equal(event.raw_packet_ref, event.raw_packet_refs[0]);
    assert.deepEqual(event.raw_packet_refs.map((ref) => ref.packet_id),
      [0x0259, 0x0438, 0x031b, 0x03d4]);
    assert.equal(new Set(event.raw_packet_refs.map((ref) =>
      `${ref.chunk_index}/${ref.decompressed_block_offset}`)).size, 4);
    assert.ok(event.raw_packet_refs.every((ref) =>
      ref.replay_sha256 === replay.source_sha256 && ref.raw_payload_sha256.length === 64));
    assert.ok(event.known_limits.some((limit) => limit.includes('runtime')));
  }
});

test('missing optional 0x03d4 and isolated 0x0259 are disclosed without emitted events', () => {
  const replay = replayWithRoute({ missingShort: true, extraPrimary: true });
  const result = decodeHeroDeathCandidates821(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 4);
  assert.equal(result.event_count, 2);
  assert.equal(result.unmatched_primary_count, 2);
  assert.equal(result.unmatched_primary_packet_refs.length, 2);
  assert.deepEqual(result.unmatched_primary_packet_refs.map((ref) => ref.packet_id),
    [0x0259, 0x0259]);
  assert.equal(result.missing_optional_0x03d4_count, 1);
  assert.equal(result.missing_optional_0x03d4_primary_refs.length, 1);
  assert.deepEqual(result.events.map((event) => event.raw_packet_refs.length), [4, 3]);
  assert.equal(result.events[1].optional_0x03d4_status, 'ABSENT_OBSERVED');
  assert.deepEqual(result.events.map((event) => event.victim_participant_id), [1, 4]);
  assert.deepEqual(result.observed_death_counts, result.final_death_counts);
});

test('wrong build and no route stay unavailable without candidate events', () => {
  const wrong = decodeHeroDeathCandidates821(replayWithRoute({ version: '16.19.820.7193' }));
  assert.equal(wrong.status, 'UNSUPPORTED');
  assert.equal(wrong.events, null);
  const empty = replayFromChunks([{ body: packet(0x0123, 1000, 0, 1) }], REPLAY_VERSION_821);
  assert.equal(decodeHeroDeathCandidates821(empty).status, 'PROFILE_UNAVAILABLE');
});

for (const [name, options, error] of [
  ['missing paired route with unmatched long route', { missingPair: true }, /unmatched 0x031b/],
  ['missing long core route', { missingLong: true }, /unmatched required 821 core/],
  ['paired raw param mismatch', { badPairParam: true }, /unmatched required 821 core/],
  ['primary low byte outside participants', { badPrimaryParam: true }, /raw params/],
  ['primary unobserved high prefix', { badHighPrefix: true }, /raw params/],
  ['primary wrong payload length', { badPrimaryLength: true }, /payload lengths/],
  ['optional route wrong payload length', { badShortLength: true }, /payload lengths/],
  ['corroborating nonzero param', { badCorroboratingParam: true }, /raw params/],
  ['ambiguous same millisecond', { sameTime: true }, /duplicate or ambiguous/],
  ['duplicate primary route', { duplicatePrimary: true }, /duplicate or ambiguous/],
  ['duplicate paired route', { duplicatePair: true }, /duplicate or ambiguous/],
  ['duplicate optional route', { duplicateShort: true }, /duplicate or ambiguous/],
  ['unmatched 0x0438 route', { extraPair: true }, /unmatched required 821 core/],
  ['unmatched 0x031b route', { extraLong: true }, /unmatched 0x031b/],
  ['unexpected optional 0x03d4', { extraShort: true }, /unexpected 0x03d4/],
]) {
  test(`821 candidate rejects ${name}`, () => {
    const result = decodeHeroDeathCandidates821(replayWithRoute(options));
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
    assert.match(result.error, error);
  });
}

test('821 candidate rejects tail mismatch and strict framing error', () => {
  const replay = replayWithRoute();
  replay.tail.stats[0].NUM_DEATHS = '2';
  const mismatch = decodeHeroDeathCandidates821(replay);
  assert.equal(mismatch.status, 'DECODE_FAILED');
  assert.match(mismatch.error, /do not match Replay tail/);

  const malformed = replayFromChunks([{ body: Buffer.from([0x10]) }], REPLAY_VERSION_821);
  const framing = decodeHeroDeathCandidates821(malformed);
  assert.equal(framing.status, 'DECODE_FAILED');
  assert.match(framing.error, /Replay framing failed/);

  const changedSource = replayWithRoute();
  changedSource.buffer[0] ^= 1;
  const source = decodeHeroDeathCandidates821(changedSource);
  assert.equal(source.status, 'DECODE_FAILED');
  assert.match(source.error, /Replay source integrity failed/);
});
