'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { resolveBuildProfile, resolveCapability } = require('../src/build_registry');
const { capabilityQuery, parseOne } = require('../src/cli');
const { decodeSemanticReplay, getHeroDeathCandidates, getHeroDeaths } =
  require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.821.7343';

function packet(packetId, rawParam, payloadLength) {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(1, 1);
  header[5] = payloadLength;
  header.writeUInt16LE(packetId, 6);
  header.writeUInt32LE(rawParam >>> 0, 8);
  return Buffer.concat([header, Buffer.alloc(payloadLength)]);
}

function keyframeDeathsPacket(participantId, count, timeMs) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  payload[1182] = count === 0 ? 0x97 : 0xcc;
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participantId, 11);
  return Buffer.concat([header, payload]);
}

function replay() {
  const game = { body: Buffer.concat([
    packet(0x0259, 0x400000ae, 5),
    packet(0x0438, 0x400000ae, 13),
    packet(0x031b, 0, 12),
    packet(0x03d4, 0, 3),
  ]) };
  const snapshots = [0, 1].map((frame) => ({ stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      keyframeDeathsPacket(index + 1, frame && index === 0 ? 1 : 0, frame * 1000))),
  }));
  const input = replayFromChunks([game, ...snapshots], BUILD);
  input.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index === 0 ? '1' : '0',
  }));
  return input;
}

test('821 build exposes only its exact candidate and tail-only preflight', () => {
  const input = replay();
  assert.equal(resolveBuildProfile(input).status, 'SUPPORTED');
  assert.equal(resolveCapability(BUILD, 'hero_death').status, 'CANDIDATE');
  assert.equal(resolveCapability(BUILD, 'hero_deaths_snapshot').status, 'CANDIDATE');
  assert.equal(resolveCapability(BUILD, 'hero_death_timer').status, 'UNAVAILABLE');
  const query = capabilityQuery(input);
  assert.equal(query.profile_release_status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(query.packet_framing_inspected, false);
  assert.equal(query.semantic_decode_performed, false);
  assert.deepEqual(query.capabilities.map((row) => row.capability),
    ['hero_death', 'hero_deaths_snapshot']);
  assert.equal(query.capabilities[0].runtime_image_requirement, 'NOT_REQUIRED');
  assert.equal(query.capabilities[0].output, 'hero_death_candidates');
  assert.deepEqual(query.capabilities[0].missing_inputs, []);
  assert.equal(query.capabilities[1].runtime_image_requirement, 'NOT_REQUIRED');
  assert.equal(query.capabilities[1].output, 'hero_deaths_snapshot_candidates');
  assert.deepEqual(query.capabilities[1].missing_inputs, []);
  input.tail.stats[0].NUM_DEATHS = null;
  for (const row of capabilityQuery(input).capabilities) {
    assert.deepEqual(row.missing_inputs, ['replay_tail_NUM_DEATHS']);
  }
});

test('821 API dispatch emits separate candidate records and no confirmed deaths', () => {
  const input = replay();
  const decoded = decodeSemanticReplay(input, {
    capabilities: ['hero_death'], runtimeImagePath: 'unused-image.bin',
  });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.game_version, BUILD);
  assert.equal(decoded.runtime_image_used, false);
  assert.equal(decoded.capability_results.hero_death.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_death.runtime_image_status,
    'PROVIDED_NOT_USED');
  assert.equal(decoded.events.death_events, undefined);
  assert.deepEqual(getHeroDeaths(decoded), []);
  assert.equal(getHeroDeathCandidates(decoded).length, 1);
  assert.equal(getHeroDeathCandidates(decoded)[0].victim_participant_id, 1);

  const combined = decodeSemanticReplay(input, {
    capabilities: ['hero_death', 'hero_deaths_snapshot'],
  });
  assert.equal(combined.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(combined.capability_results.hero_deaths_snapshot.status, 'CANDIDATE');
  assert.equal(combined.capability_results.hero_deaths_snapshot.event_count, 20);
  assert.equal(combined.events.hero_deaths_snapshot_candidates.length, 20);
  assert.equal(combined.events.hero_deaths_snapshot_candidates[10].deaths_candidate, 1);
  assert.equal(combined.events.death_events, undefined);

  const unavailable = decodeSemanticReplay(input, { capabilities: ['hero_death_timer'] });
  assert.equal(unavailable.status, 'UNSUPPORTED');
  assert.equal(unavailable.events, null);
  assert.equal(unavailable.capability_results.hero_death_timer.status, 'UNSUPPORTED');
});

test('821 CLI dispatch reads a replay file and labels selected output candidate', (t) => {
  const input = replay();
  const original = input.buffer;
  const metadataLength = original.readUInt32LE(original.length - 4);
  const metadata = Buffer.from(JSON.stringify({
    gameLength: 600000,
    statsJson: JSON.stringify(input.tail.stats),
  }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  const bytes = Buffer.concat([
    original.subarray(0, original.length - metadataLength - 4), metadata, trailer,
  ]);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-cli-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'sample.rofl');
  fs.writeFileSync(file, bytes);
  const result = parseOne(file, {
    semantic: true, events: ['hero_death', 'hero_deaths_snapshot'],
    strict: true, timelineLimit: 0,
  });
  assert.equal(result.ok, true);
  assert.equal(result.analysis.decoder.status, 'CANDIDATE');
  assert.equal(result.analysis.packet_count, 24);
  assert.equal(result.analysis.block_errors.length, 0);
  assert.equal(result.analysis.event_counts.hero_death_candidates, 1);
  assert.equal(result.analysis.event_counts.hero_deaths_snapshot_candidates, 20);
  assert.deepEqual(result.analysis.events.death_events, undefined);
});
