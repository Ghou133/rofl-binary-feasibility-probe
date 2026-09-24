'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { resolveCapability } = require('../src/build_registry');
const {
  decodeSemanticReplay,
  getDeathTimerEvents,
  getHeroDeathCandidates,
  getHeroDeathTimerCandidates,
  getHeroDeaths,
} = require('../src/semantic_api');
const { decodeHeroDeathTimerPayload } = require('../src/decoders/rofl_16_19_820_7193');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';

function packet(packetId, timestampMs, rawParam, payload) {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timestampMs / 1000, 1);
  header[5] = payload.length;
  header.writeUInt16LE(packetId, 6);
  header.writeUInt32LE(rawParam >>> 0, 8);
  return Buffer.concat([header, payload]);
}

function candidateReplay(options = {}) {
  const rows = [];
  const deaths = [
    { time: 1000, participant: 1, timer: Buffer.from('19eeeee606', 'hex') },
    { time: 2000, participant: 4, timer: Buffer.from('1ceeeee706', 'hex') },
  ];
  for (const [index, death] of deaths.entries()) {
    const rawParam = 0x400000ad + death.participant;
    rows.push(packet(0x02d6, death.time, rawParam,
      index === 0 && options.badTimer ? Buffer.from('18eeeee606', 'hex') : death.timer));
    rows.push(packet(0x04d9, death.time,
      index === 0 && options.badPair ? rawParam + 1 : rawParam, Buffer.alloc(37)));
    if (index === 0 && options.duplicateFirstPair) {
      rows.push(packet(0x02d6, death.time, rawParam, death.timer));
      rows.push(packet(0x04d9, death.time, rawParam, Buffer.alloc(37)));
    }
    if (options.includeDeathTriad) rows.push(packet(0x0326, death.time, 0, Buffer.alloc(20)));
  }
  if (!options.omitRespawns) {
    rows.push(packet(0x0357, options.badRespawnTime ? 13100 : 13025,
      0x400000ae, Buffer.alloc(9)));
    rows.push(packet(0x0357, 16032,
      options.lowByteFallback ? 0x400001b1 : 0x400000b1, Buffer.alloc(13)));
  }
  const replay = replayFromChunks([{ body: Buffer.concat(rows) }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: String(index === 0 || index === 3 ? 1 : 0),
  }));
  if (options.badCounts) replay.tail.stats[0].NUM_DEATHS = '2';
  if (options.gameLength !== undefined) replay.tail.metadata.gameLength = options.gameLength;
  return replay;
}

test('exact-runtime float decoding is bounded to the observed 5-byte shape', () => {
  assert.deepEqual(decodeHeroDeathTimerPayload(Buffer.from('19eeeee606', 'hex')), {
    float_code: 1,
    timer_seconds_candidate: 12,
    decoded_float_bytes_hex: '00004041',
  });
  assert.equal(decodeHeroDeathTimerPayload(Buffer.from('18eeeee606', 'hex')), null);
  assert.equal(decodeHeroDeathTimerPayload(Buffer.from('19eeeee6', 'hex')), null);
});

test('HN timer capability runs independently and keeps candidate and raw provenance', () => {
  assert.equal(resolveCapability(BUILD, 'hero_death_timer').status, 'CANDIDATE');
  assert.equal(resolveCapability('16.19.821.7343', 'hero_death_timer').status,
    'UNSUPPORTED_VERSION');
  const replay = candidateReplay({ lowByteFallback: true });
  const decoded = decodeSemanticReplay(replay, { capabilities: ['hero_death_timer'] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  const result = decoded.capability_results.hero_death_timer;
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 2);
  assert.equal(result.respawn_match_count, 2);
  assert.equal(result.exact_param_respawn_match_count, 1);
  assert.equal(result.unique_low_byte_respawn_match_count, 1);
  assert.equal(result.runtime_image_used, false);
  assert.equal(result.evidence_runtime_image_sha256,
    '7e6804aa589a098a44b01e4fdc894fc697776caeea42fc78f780af11ed6df76d');
  const events = getHeroDeathTimerCandidates(decoded);
  assert.equal(events.length, 2);
  assert.deepEqual(events.map((event) => event.timer_seconds_candidate), [12, 14]);
  assert.deepEqual(events.map((event) => event.victim_participant_id_candidate), [1, 4]);
  assert.equal(events[0].raw_packet_ref.packet_id, 0x02d6);
  assert.equal(events[0].raw_packet_refs[1].packet_id, 0x04d9);
  assert.equal(events[0].raw_packet_refs[2].packet_id, 0x0357);
  assert.equal(events[1].respawn_match_kind, 'unique_low_byte');
  assert.equal(events[0].confidence, 'CANDIDATE');
  assert.equal(decoded.events.death_events, undefined);
  assert.equal(decoded.events.death_timer_events, undefined);
  assert.equal(getHeroDeathCandidates(decoded), null);
  assert.deepEqual(getHeroDeaths(decoded), []);
  assert.deepEqual(getDeathTimerEvents(decoded), []);
});

test('HN death and timer candidates coexist through one Replay block scan', () => {
  const decoded = decodeSemanticReplay(candidateReplay({ includeDeathTriad: true }), {
    capabilities: ['hero_death_timer', 'hero_death'],
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.hero_death_timer.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_death.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_death.scanned_block_count,
    decoded.capability_results.hero_death_timer.scanned_block_count);
  assert.equal(decoded.decoded_packet_count, 2);
  assert.equal(getHeroDeathCandidates(decoded).length, 2);
  assert.equal(getHeroDeathTimerCandidates(decoded).length, 2);
});

test('HN timer candidate fails closed on route, payload, totals and respawn evidence', () => {
  for (const [options, expected] of [
    [{ badTimer: true }, /5-byte float shape/],
    [{ badPair: true }, /pairing differs/],
    [{ badCounts: true }, /NUM_DEATHS/],
    [{ badRespawnTime: true }, /eligible death timer matches/],
    [{ omitRespawns: true }, /before Replay end/],
    [{ omitRespawns: true, gameLength: 0 }, /precedes an observed death timer/],
    [{ duplicateFirstPair: true }, /ambiguous death timer pairing/],
  ]) {
    const decoded = decodeSemanticReplay(candidateReplay(options), {
      capabilities: ['hero_death_timer'],
    });
    assert.equal(decoded.status, 'DECODE_FAILED');
    assert.match(decoded.capability_results.hero_death_timer.error, expected);
    assert.equal(decoded.events, null);
    assert.equal(getHeroDeathTimerCandidates(decoded), null);
  }
  const missing = decodeSemanticReplay(candidateReplay({
    omitRespawns: true, gameLength: null,
  }), { capabilities: ['hero_death_timer'] });
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.match(missing.capability_results.hero_death_timer.missing_input, /gameLength/);
});

test('unobserved reincarnations can be terminally censored only after observed deaths', () => {
  const decoded = decodeSemanticReplay(candidateReplay({
    omitRespawns: true, gameLength: 5000,
  }), { capabilities: ['hero_death_timer'] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.hero_death_timer.unobserved_after_replay_end_count, 2);
  assert.equal(getHeroDeathTimerCandidates(decoded).length, 2);
});

test('KR death triad does not select the HN timer profile', () => {
  const rawParam = 0x400000ae;
  const rows = [
    packet(0x0259, 1000, rawParam, Buffer.alloc(5)),
    packet(0x0438, 1000, rawParam, Buffer.alloc(37)),
    packet(0x0396, 1000, rawParam + 0x100, Buffer.alloc(3)),
  ];
  const replay = replayFromChunks([{ body: Buffer.concat(rows) }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index === 0 ? '1' : '0',
  }));
  const decoded = decodeSemanticReplay(replay, { capabilities: ['hero_death_timer'] });
  assert.equal(decoded.status, 'PROFILE_UNAVAILABLE');
  assert.equal(decoded.events, null);
});
