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

function replay() {
  const input = replayFromChunks([{ body: Buffer.concat([
    packet(0x0259, 0x400000ae, 5),
    packet(0x0438, 0x400000ae, 13),
    packet(0x031b, 0, 12),
    packet(0x03d4, 0, 3),
  ]) }], BUILD);
  input.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index === 0 ? '1' : '0',
  }));
  return input;
}

test('821 build exposes only its exact candidate and tail-only preflight', () => {
  const input = replay();
  assert.equal(resolveBuildProfile(input).status, 'SUPPORTED');
  assert.equal(resolveCapability(BUILD, 'hero_death').status, 'CANDIDATE');
  assert.equal(resolveCapability(BUILD, 'hero_death_timer').status, 'UNAVAILABLE');
  const query = capabilityQuery(input);
  assert.equal(query.profile_release_status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(query.packet_framing_inspected, false);
  assert.equal(query.semantic_decode_performed, false);
  assert.deepEqual(query.capabilities.map((row) => row.capability), ['hero_death']);
  assert.equal(query.capabilities[0].runtime_image_requirement, 'NOT_REQUIRED');
  assert.equal(query.capabilities[0].output, 'hero_death_candidates');
  assert.deepEqual(query.capabilities[0].missing_inputs, []);
  input.tail.stats[0].NUM_DEATHS = null;
  assert.deepEqual(capabilityQuery(input).capabilities[0].missing_inputs,
    ['replay_tail_NUM_DEATHS']);
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
    semantic: true, events: ['hero_death'], strict: true, timelineLimit: 0,
  });
  assert.equal(result.ok, true);
  assert.equal(result.analysis.decoder.status, 'CANDIDATE');
  assert.equal(result.analysis.packet_count, 4);
  assert.equal(result.analysis.block_errors.length, 0);
  assert.equal(result.analysis.event_counts.hero_death_candidates, 1);
  assert.deepEqual(result.analysis.events.death_events, undefined);
});
