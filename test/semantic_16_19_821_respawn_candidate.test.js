'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  HERO_RESPAWN_CANDIDATE_PROFILE_821,
  assessHeroRespawnTail821,
  decodeHeroRespawnCandidates821,
} = require('../src/decoders/rofl_16_19_821_respawn_candidate');
const { RUNTIME_IMAGE_SHA256, decodeHeroReincarnateAlivePayload821 } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';

test('exact 821 ReincarnateAlive wire decodes both observed payload shapes', () => {
  assert.deepEqual(decodeHeroReincarnateAlivePayload821(
    Buffer.from('64b0f17b7bb06e3b7b1e3aaaf9', 'hex')), {
    pair_f32: [394, 461], optional_f32: 614.25, optional_field_present: true,
  });
  assert.deepEqual(decodeHeroReincarnateAlivePayload821(
    Buffer.from('66be2b8b7bbe2b477b', 'hex')), {
    pair_f32: [14340, 14391], optional_f32: 0, optional_field_present: false,
  });
  assert.equal(decodeHeroReincarnateAlivePayload821(Buffer.alloc(10)), null);
});

function packet(packetId, timestampMs, rawParam, payloadLength) {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timestampMs / 1000, 1);
  header[5] = payloadLength;
  header.writeUInt16LE(packetId, 6);
  header.writeUInt32LE(rawParam >>> 0, 8);
  return Buffer.concat([header, Buffer.alloc(payloadLength, packetId & 0xff)]);
}

function replayWithRoutes(options = {}) {
  const rows = [];
  const add = (id, time, param, length) => rows.push({ id, time, param, length });
  const death = (time, participant) => {
    const param = 0x400000ad + participant;
    add(0x03d4, time, 0, 3);
    add(0x031b, time, 0, 12);
    add(0x0259, time, param, 5);
    add(0x0438, time, param, 13);
  };
  const returned = (time, participant, length = 13, which = null) => {
    const param = 0x400000ad + participant;
    if (which === 'bad_length') length = 8;
    if (which !== 'missing_support') {
      add(0x018d, time, which === 'wrong_support_param' ? param + 1 : param, 55);
      if (which === 'duplicate_support') add(0x018d, time, param, 55);
    }
    if (which === 'support_after') {
      rows.pop();
      add(0x0048, time, param, length);
      add(0x018d, time, param, 55);
    } else {
      add(0x0048, time, which === 'bad_param' ? 0x500000ae : param, length);
    }
  };
  death(1000, 1);
  death(2000, 4);
  add(0x018d, 8000, 0x400000b0, 55); // A real route packet that is not a return.
  if (!options.omitFirstReturn) returned(11500, 1, 9,
    options.mutate === 'first' ? options.change : null);
  death(20000, 1);
  returned(options.lateSecondReturn ? 32500 : 31500,
    options.wrongSecondParticipant ? 4 : 1, 13,
    options.mutate === 'second' ? options.change : null);
  // This isolated primary is not a death core and must not steal the return.
  add(0x0259, 34000, 0x400000b1, 5);
  returned(35000, 4, 13,
    options.mutate === 'third' ? options.change : null);
  death(100000, 4); // Final death has no observed 0x0048 before Replay end.
  if (options.adjacentOnly) {
    for (const row of rows) if (row.id === 0x0048) row.id = 0x0047;
  }
  if (options.extraReturn) returned(36000, 4);
  const body = Buffer.concat(rows.map((row) =>
    packet(row.id, row.time, row.param, row.length)));
  const replay = replayFromChunks([{ body }], options.version ?? BUILD);
  replay.tail.metadata.gameLength = 110000;
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: String(index === 0 || index === 3 ? 2 : 0),
    TOTAL_TIME_SPENT_DEAD: String(index === 0 ? 22 : index === 3 ? 33 : 0),
  }));
  return replay;
}

test('821 return route remains exact-build and requires tail dead-time input', () => {
  assert.equal(HERO_RESPAWN_CANDIDATE_PROFILE_821.replay_version, BUILD);
  assert.equal(HERO_RESPAWN_CANDIDATE_PROFILE_821.evidence_runtime_image_sha256,
    RUNTIME_IMAGE_SHA256);
  const replay = replayWithRoutes();
  assert.deepEqual(assessHeroRespawnTail821(replay), {
    status: 'PASS', seconds: [22, 0, 0, 33, 0, 0, 0, 0, 0, 0],
    game_length_ms: 110000,
  });
  replay.tail.stats[0].TOTAL_TIME_SPENT_DEAD = null;
  assert.equal(decodeHeroRespawnCandidates821(replay).status, 'MISSING_INPUT');
  replay.tail.stats[0].TOTAL_TIME_SPENT_DEAD = '-1';
  assert.equal(decodeHeroRespawnCandidates821(replay).status, 'UNSUPPORTED');
  replay.tail.stats[0].TOTAL_TIME_SPENT_DEAD = '22';
  replay.tail.metadata.gameLength = null;
  assert.equal(decodeHeroRespawnCandidates821(replay).status, 'MISSING_INPUT');
  const wrong = decodeHeroRespawnCandidates821(replayWithRoutes({ version: '16.19.820.7193' }));
  assert.equal(wrong.status, 'UNSUPPORTED');
  assert.equal(wrong.events, null);
});

test('821 candidate emits only observed 0x0048 times from matched death cores', () => {
  const replay = replayWithRoutes();
  const result = decodeHeroRespawnCandidates821(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 3);
  assert.equal(result.matched_death_core_count, 4);
  assert.equal(result.co_timed_0x018d_count, 3);
  assert.equal(result.extra_0x018d_count, 1);
  assert.equal(result.extra_0x018d_packet_refs[0].replay_time_ms, 8000);
  assert.equal(result.unpaired_final_death_count, 1);
  assert.equal(result.unpaired_final_deaths[0].participant_id_candidate, 4);
  assert.equal(result.unpaired_final_deaths[0].replay_remaining_ms, 10000);
  assert.equal(result.unpaired_final_deaths[0].raw_packet_refs.length, 4);
  assert.deepEqual(result.final_total_time_spent_dead_seconds,
    result.observed_floor_total_time_spent_dead_seconds);
  assert.deepEqual(result.events.map((event) => event.replay_time_ms),
    [11500, 31500, 35000]);
  assert.deepEqual(result.events.map((event) => event.participant_id_candidate),
    [1, 1, 4]);
  assert.deepEqual(result.events.map((event) =>
    event.matched_death_replay_time_ms_candidate), [1000, 20000, 2000]);
  assert.deepEqual(result.events.map((event) =>
    event.observed_death_to_return_ms_candidate), [10500, 11500, 33000]);
  for (const event of result.events) {
    assert.equal(event.confidence, 'CANDIDATE');
    assert.equal(event.raw_packet_ref, event.raw_packet_refs[0]);
    assert.deepEqual(event.raw_packet_refs.slice(0, 5).map((ref) => ref.packet_id),
      [0x0048, 0x018d, 0x0259, 0x0438, 0x031b]);
    assert.ok(event.raw_packet_refs.every((ref) => ref.replay_sha256 === replay.source_sha256));
    assert.equal(event.timer_seconds_candidate, undefined);
    assert.equal(event.field_confidence.observed_death_to_return_ms_candidate,
      'CANDIDATE_DIFFERENCE_OF_PAIRED_REPLAY_TIMES');
    assert.ok(event.known_limits.some((limit) => limit.includes('runtime')));
  }
});

for (const [name, options, error] of [
  ['a wrong 0x0048 payload length', { mutate: 'first', change: 'bad_length' }, /payload length/],
  ['wrong hero raw-param family', { mutate: 'first', change: 'bad_param' }, /raw-param family/],
  ['missing co-timed support', { mutate: 'first', change: 'missing_support' }, /unique preceding co-timed/],
  ['duplicate co-timed support', { mutate: 'first', change: 'duplicate_support' }, /unique preceding co-timed/],
  ['wrong support raw param', { mutate: 'first', change: 'wrong_support_param' }, /unique preceding co-timed/],
  ['support after candidate route', { mutate: 'first', change: 'support_after' }, /unique preceding co-timed/],
  ['a shifted participant', { wrongSecondParticipant: true }, /unmatched prior death cores/],
  ['a shifted return time', { lateSecondReturn: true }, /TOTAL_TIME_SPENT_DEAD/],
  ['duplicate return for a death', { extraReturn: true }, /unmatched prior death cores/],
  ['two deaths before one return', { omitFirstReturn: true }, /unmatched prior death cores/],
]) {
  test(`821 candidate rejects ${name}`, () => {
    const replay = replayWithRoutes(options);
    const result = decodeHeroRespawnCandidates821(replay);
    assert.equal(result.status, 'DECODE_FAILED');
    assert.equal(result.events, null);
    assert.match(result.error, error);
  });
}

test('adjacent route and malformed, mutated Replay sources do not yield candidates', () => {
  const adjacent = decodeHeroRespawnCandidates821(replayWithRoutes({ adjacentOnly: true }));
  assert.equal(adjacent.status, 'PROFILE_UNAVAILABLE');
  assert.equal(adjacent.events, null);
  const changedSource = replayWithRoutes();
  changedSource.buffer[0] ^= 1;
  const source = decodeHeroRespawnCandidates821(changedSource);
  assert.equal(source.status, 'DECODE_FAILED');
  assert.match(source.error, /Replay source integrity failed/);
  const malformed = replayFromChunks([{ body: Buffer.from([0x10]) }], BUILD);
  malformed.tail.stats = Array.from({ length: 10 }, () =>
    ({ NUM_DEATHS: '0', TOTAL_TIME_SPENT_DEAD: '0' }));
  const framing = decodeHeroRespawnCandidates821(malformed);
  assert.equal(framing.status, 'DECODE_FAILED');
  assert.match(framing.error, /Replay framing failed/);
});
