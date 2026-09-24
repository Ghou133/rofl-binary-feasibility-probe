'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { collect821Routes } = require('../src/decoders/rofl_16_19_821_scan');
const {
  HERO_DEATH_TIMER_CANDIDATE_PROFILE_821,
  decodeHeroDeathTimerPayload821,
  decodeHeroDeathTimerCandidates821,
} = require('../src/decoders/rofl_16_19_821_death_timer_candidate');

const BUILD = '16.19.821.7343';

function packet(packetId, timestampMs, rawParam, payload) {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timestampMs / 1000, 1);
  header[5] = payload.length;
  header.writeUInt16LE(packetId, 6);
  header.writeUInt32LE(rawParam >>> 0, 8);
  return Buffer.concat([header, payload]);
}

function routeReplay(options = {}) {
  const rows = [];
  const deaths = [
    { time: 1000, param: 0x400000ae, timer: Buffer.from('121017d7d7', 'hex') },
    { time: 2000, param: 0x400000b1,
      timer: options.badMatchedTimer ? Buffer.from('1110f7d7d7', 'hex')
        : Buffer.from('1210f7d7d7', 'hex') },
  ];
  for (const { time, param, timer } of deaths) {
    rows.push(packet(0x03d4, time, 0, Buffer.alloc(3)));
    rows.push(packet(0x031b, time, 0, Buffer.alloc(12)));
    rows.push(packet(0x0259, time, param, timer));
    rows.push(packet(0x0438, time, param, Buffer.alloc(13)));
  }
  if (options.isolated) {
    rows.push(packet(0x0259, 3000, 0x400000b6, Buffer.from('121017d7d7', 'hex')));
    rows.push(packet(0x0259, 3000, 0x400000b7, Buffer.from('1210f7d7d7', 'hex')));
  }
  const replay = replayFromChunks([{ body: Buffer.concat(rows) }], options.version ?? BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: String(index === 0 || index === 3 ? 1 : 0),
  }));
  return replay;
}

test('exact 821 five-byte timer payload decodes the observed float seconds', () => {
  assert.equal(HERO_DEATH_TIMER_CANDIDATE_PROFILE_821.replay_version, BUILD);
  assert.match(HERO_DEATH_TIMER_CANDIDATE_PROFILE_821.evidence_runtime_image_sha256,
    /^[0-9a-f]{64}$/);
  assert.deepEqual(decodeHeroDeathTimerPayload821(Buffer.from('121017d7d7', 'hex')), {
    timer_seconds_candidate: 12,
    timer_float_code: 2,
    decoded_float_bytes_hex: '41400000',
    decoded_float_byte_order: 'BE',
  });
  assert.equal(decodeHeroDeathTimerPayload821(Buffer.from('1210f7d7d7', 'hex'))
    .timer_seconds_candidate, 14);
  assert.equal(decodeHeroDeathTimerPayload821(Buffer.from('111017d7d7', 'hex')), null);
  assert.equal(decodeHeroDeathTimerPayload821(Buffer.from('121017d7', 'hex')), null);
  assert.equal(decodeHeroDeathTimerPayload821(Buffer.from('121017d7d700', 'hex')), null);
});

test('timer output binds only matched death cores and retains isolated packet refs', () => {
  const replay = routeReplay({ isolated: true });
  const scan = collect821Routes(replay, ['hero_death_timer']);
  const outcome = decodeHeroDeathTimerCandidates821(replay, scan);
  assert.equal(outcome.status, 'CANDIDATE');
  assert.equal(outcome.input_count, 4);
  assert.equal(outcome.event_count, 2);
  assert.equal(outcome.matched_death_core_count, 2);
  assert.equal(outcome.excluded_isolated_primary_count, 2);
  assert.deepEqual(outcome.events.map((event) => event.timer_seconds_candidate), [12, 14]);
  assert.deepEqual(outcome.events.map((event) => event.victim_participant_id_candidate), [1, 4]);
  assert.deepEqual(outcome.events.map((event) => event.replay_time_ms), [1000, 2000]);
  assert.equal(outcome.runtime_image_used, false);
  assert.equal(outcome.runtime_image_status, 'STATIC_EXACT_821_RUNTIME_TRANSFORM');
  assert.equal(outcome.excluded_isolated_primary_packet_refs.length, 2);
  for (const event of outcome.events) {
    assert.equal(event.confidence, 'CANDIDATE');
    assert.equal(event.respawn_replay_time_ms_candidate, null);
    assert.equal(event.raw_packet_ref, event.raw_packet_refs[0]);
    assert.deepEqual(event.raw_packet_refs.map((ref) => ref.packet_id),
      [0x0259, 0x0438, 0x031b, 0x03d4]);
    assert.ok(event.raw_packet_refs.every((ref) => ref.replay_sha256 === replay.source_sha256));
  }
  assert.deepEqual(decodeHeroDeathTimerCandidates821(replay).events,
    outcome.events);
});

test('timer candidate fails closed for malformed body, foreign build, source, and death tail', () => {
  const malformed = decodeHeroDeathTimerCandidates821(routeReplay({ badMatchedTimer: true }));
  assert.equal(malformed.status, 'DECODE_FAILED');
  assert.match(malformed.error, /runtime f32 shape/);
  assert.equal(malformed.events, null);

  const foreign = decodeHeroDeathTimerCandidates821(routeReplay({ version: '16.19.820.7193' }));
  assert.equal(foreign.status, 'UNSUPPORTED');
  assert.equal(foreign.events, null);

  const missingTail = routeReplay();
  missingTail.tail.stats[0].NUM_DEATHS = null;
  const missing = decodeHeroDeathTimerCandidates821(missingTail);
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.events, null);

  const changedSource = routeReplay();
  changedSource.buffer[0] ^= 1;
  const changed = decodeHeroDeathTimerCandidates821(changedSource);
  assert.equal(changed.status, 'DECODE_FAILED');
  assert.match(changed.error, /Replay source integrity failed/);

  const replayA = routeReplay();
  const replayB = routeReplay();
  const token = collect821Routes(replayA, ['hero_death_timer']);
  const crossSource = decodeHeroDeathTimerCandidates821(replayB, token);
  assert.equal(crossSource.status, 'DECODE_FAILED');
  assert.match(crossSource.error, /different Replay/);
});
