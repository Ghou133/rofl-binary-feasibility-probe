'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  decodeSemanticReplay,
  getHeroDeathTimerCandidates,
  getHeroRespawnCandidates,
  getHeroRespawns,
} = require('../src/semantic_api');
const {
  collectCandidateRoutes,
  decodeHeroDeathTimerCandidates,
  decodeHeroRespawnCandidates,
} = require('../src/decoders/rofl_16_19_820_7193');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const RAW_PARAM = 0x400000ae;

function packet(packetId, timestampMs, rawParam, payload) {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timestampMs / 1000, 1);
  header[5] = payload.length;
  header.writeUInt16LE(packetId, 6);
  header.writeUInt32LE(rawParam >>> 0, 8);
  return Buffer.concat([header, payload]);
}

function hnReplay(options = {}) {
  const rows = [
    packet(0x02d6, 1000, RAW_PARAM, Buffer.from(
      options.badTimer ? '18eeeee606' : '19eeeee606', 'hex')),
    packet(0x04d9, 1000, RAW_PARAM, Buffer.alloc(37)),
  ];
  if (options.observedRespawn !== false) {
    rows.push(packet(0x0357, 13025, RAW_PARAM, Buffer.alloc(9)));
  }
  const replay = replayFromChunks([{ body: Buffer.concat(rows) }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index === 0 ? '1' : '0',
  }));
  if (options.badDeathCount) replay.tail.stats[0].NUM_DEATHS = '2';
  replay.tail.metadata.gameLength = options.gameLength
    ?? (options.observedRespawn === false ? 5000 : 20000);
  return replay;
}

function krReplay() {
  const rows = [
    packet(0x0259, 1000, RAW_PARAM, Buffer.alloc(5)),
    packet(0x0438, 1000, RAW_PARAM, Buffer.alloc(37)),
    packet(0x0396, 1000, RAW_PARAM + 0x100, Buffer.alloc(3)),
  ];
  const replay = replayFromChunks([{ body: Buffer.concat(rows) }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index === 0 ? '1' : '0',
  }));
  return replay;
}

function reverseDeathAndRespawnOrderReplay() {
  const secondRawParam = RAW_PARAM + 1;
  const rows = [
    packet(0x02d6, 1000, RAW_PARAM, Buffer.from('1ceeeee706', 'hex')),
    packet(0x04d9, 1000, RAW_PARAM, Buffer.alloc(37)),
    packet(0x02d6, 2000, secondRawParam, Buffer.from('19eeeee606', 'hex')),
    packet(0x04d9, 2000, secondRawParam, Buffer.alloc(37)),
    packet(0x0357, 14025, secondRawParam, Buffer.alloc(9)),
    packet(0x0357, 15025, RAW_PARAM, Buffer.alloc(9)),
  ];
  const replay = replayFromChunks([{ body: Buffer.concat(rows) }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index < 2 ? '1' : '0',
  }));
  replay.tail.metadata.gameLength = 20000;
  return replay;
}

function writeReplayWithTailStats(replay, outputPath) {
  const original = replay.buffer;
  const metadataLength = original.readUInt32LE(original.length - 4);
  const metadata = Buffer.from(JSON.stringify({
    ...replay.tail.metadata,
    statsJson: JSON.stringify(replay.tail.stats),
  }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  fs.writeFileSync(outputPath, Buffer.concat([
    original.subarray(0, original.length - metadataLength - 4), metadata, trailer,
  ]));
}

test('selected HN respawn projects one observed 0x0357 match with raw provenance', () => {
  const replay = hnReplay();
  const decoded = decodeSemanticReplay(replay, { capabilities: ['hero_respawn'] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  const result = decoded.capability_results.hero_respawn;
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 1);
  assert.equal(result.input_count, 1);
  assert.equal(result.input_packet_id, 0x0357);
  assert.equal(result.runtime_image_used, false);
  assert.deepEqual(Object.keys(decoded.events), ['hero_respawn_candidates']);
  const events = getHeroRespawnCandidates(decoded);
  assert.equal(events.length, 1);
  assert.equal(events[0].replay_time_ms, 13025);
  assert.equal(events[0].participant_id_candidate, 1);
  assert.equal(events[0].respawn_raw_param, RAW_PARAM);
  assert.equal(events[0].death_timer_replay_time_ms_candidate, 1000);
  assert.equal(events[0].timer_seconds_candidate, 12);
  assert.equal(events[0].respawn_timer_residual_ms, 25);
  assert.equal(events[0].respawn_match_kind, 'exact_param');
  assert.equal(events[0].confidence, 'CANDIDATE');
  assert.equal(events[0].raw_packet_ref.packet_id, 0x0357);
  assert.equal(events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.deepEqual(events[0].raw_packet_refs.map((row) => row.packet_id),
    [0x0357, 0x02d6, 0x04d9]);
  assert.equal(decoded.events.respawn_events, undefined);
  assert.deepEqual(getHeroRespawns(decoded), []);
});

test('terminally censored death timer does not invent a respawn candidate', () => {
  const decoded = decodeSemanticReplay(hnReplay({ observedRespawn: false }), {
    capabilities: ['hero_respawn'],
  });
  const result = decoded.capability_results.hero_respawn;
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 0);
  assert.equal(result.unobserved_after_replay_end_count, 1);
  assert.deepEqual(getHeroRespawnCandidates(decoded), []);
  assert.deepEqual(getHeroRespawns(decoded), []);
});

test('KR route absence and timer evidence failure never publish respawn events', () => {
  const kr = decodeSemanticReplay(krReplay(), { capabilities: ['hero_respawn'] });
  assert.equal(kr.status, 'PROFILE_UNAVAILABLE');
  assert.equal(kr.capability_results.hero_respawn.status, 'PROFILE_UNAVAILABLE');
  assert.equal(kr.events, null);
  assert.equal(getHeroRespawnCandidates(kr), null);

  for (const options of [{ badTimer: true }, { badDeathCount: true }]) {
    const failed = decodeSemanticReplay(hnReplay(options), { capabilities: ['hero_respawn'] });
    assert.equal(failed.status, 'DECODE_FAILED');
    assert.equal(failed.capability_results.hero_respawn.status, 'DECODE_FAILED');
    assert.equal(failed.capability_results.hero_respawn.event_count, null);
    assert.equal(failed.events, null);
    assert.equal(getHeroRespawnCandidates(failed), null);
  }

  const missing = hnReplay();
  missing.tail.stats = null;
  const blocked = decodeSemanticReplay(missing, { capabilities: ['hero_respawn'] });
  assert.equal(blocked.status, 'MISSING_INPUT');
  assert.equal(blocked.capability_results.hero_respawn.status, 'MISSING_INPUT');
  assert.equal(blocked.events, null);
});

test('an orphan 0x0357 raw packet stays unclassified without the HN timer route pair', () => {
  const replay = replayFromChunks([{
    body: packet(0x0357, 13025, RAW_PARAM, Buffer.alloc(9)),
  }], BUILD);
  const decoded = decodeSemanticReplay(replay, { capabilities: ['hero_respawn'] });
  const result = decoded.capability_results.hero_respawn;
  assert.equal(decoded.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.event_count, null);
  assert.equal(result.input_count, 1);
  assert.equal(result.raw_unclassified_packet_count, 1);
  assert.match(result.error, /raw 0x0357 packets remain unclassified/);
  assert.equal(decoded.events, null);
  assert.equal(getHeroRespawnCandidates(decoded), null);
});

test('respawn candidates use observed respawn order when deaths have different timers', () => {
  const decoded = decodeSemanticReplay(reverseDeathAndRespawnOrderReplay(), {
    capabilities: ['hero_respawn'],
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  const events = getHeroRespawnCandidates(decoded);
  assert.deepEqual(events.map((row) => row.replay_time_ms), [14025, 15025]);
  assert.deepEqual(events.map((row) => row.participant_id_candidate), [2, 1]);
  assert.deepEqual(events.map((row) => row.death_timer_replay_time_ms_candidate), [2000, 1000]);
});

test('timer and respawn selection share a route scan but keep separate candidate arrays', () => {
  const decoded = decodeSemanticReplay(hnReplay(), {
    capabilities: ['hero_death_timer', 'hero_respawn'],
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results.hero_death_timer.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_respawn.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_death_timer.scanned_block_count,
    decoded.capability_results.hero_respawn.scanned_block_count);
  assert.equal(getHeroDeathTimerCandidates(decoded).length, 1);
  assert.equal(getHeroRespawnCandidates(decoded).length, 1);
  assert.deepEqual(Object.keys(decoded.events).sort(),
    ['hero_death_timer_candidates', 'hero_respawn_candidates']);
});

test('foreign candidate timer outcome cannot be projected into an identical second Replay', () => {
  const replayA = hnReplay();
  const replayB = hnReplay();
  assert.notStrictEqual(replayA, replayB);
  assert.equal(replayA.source_sha256, replayB.source_sha256);
  assert.deepEqual(replayA.buffer, replayB.buffer);
  const timerFromA = decodeHeroDeathTimerCandidates(replayA);
  assert.equal(timerFromA.status, 'CANDIDATE');
  const rejected = decodeHeroRespawnCandidates(replayB, null, timerFromA);
  assert.equal(rejected.status, 'DECODE_FAILED');
  assert.equal(rejected.event_count, null);
  assert.equal(rejected.events, null);
});

test('foreign route scan cannot be reused for an identical second Replay', () => {
  const replayA = hnReplay();
  const replayB = hnReplay();
  assert.notStrictEqual(replayA, replayB);
  assert.equal(replayA.source_sha256, replayB.source_sha256);
  const scanFromA = collectCandidateRoutes(replayA);
  assert.equal(scanFromA.error, null);
  const rejected = decodeHeroRespawnCandidates(replayB, scanFromA);
  assert.equal(rejected.status, 'DECODE_FAILED');
  assert.equal(rejected.event_count, null);
  assert.equal(rejected.events, null);
});

test('selected CLI writes respawn candidate JSONL without confirmed respawn events', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-respawn-candidate-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailStats(hnReplay(), input);
  const code = await require('../src/cli').main([
    'decode', input, '--events', 'hero_respawn', '--out-dir', output,
  ]);
  assert.equal(code, 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  assert.equal(summary.capability_runs[0].capability_results.hero_respawn.status, 'CANDIDATE');
  const replayDirectory = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.runtime_image_used, false);
  assert.equal(semantic.capability_results.hero_respawn.event_count, 1);
  const events = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'events.json'), 'utf8'));
  assert.deepEqual(Object.keys(events), ['hero_respawn_candidates']);
  assert.equal(events.hero_respawn_candidates.length, 1);
  assert.equal(fs.existsSync(path.join(replayDirectory, 'hero_respawn_candidates.jsonl')), true);
});
