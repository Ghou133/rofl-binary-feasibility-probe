'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  decodeSemanticReplay,
  getHeroMinionsKilledSnapshotCandidates,
} = require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const HERO_PARAM_FIRST = 0x400000ae;
const CANDIDATE = 'hero_minions_killed_snapshot';
const EVENT_KEY = 'hero_minions_killed_snapshot_candidates';

// The exact 16.19 lookup table decodes f6 to 00, 41 to 40, and 3c to a0.
// The keyframe decoder reverses the 1260-byte encoded blob before reading f32LE at 0x3c.
function heroStatsPayload(minionsKilled) {
  const encodedFloat = {
    0: 'f6f6f6f6',
    3: 'f6f64141',
  }[minionsKilled];
  if (!encodedFloat) throw new RangeError('synthetic fixture supports only CS 0 or 3');
  const encodedBlob = Buffer.alloc(1260, 0xf6);
  const floatBytes = Buffer.from(encodedFloat, 'hex');
  for (let index = 0; index < floatBytes.length; index += 1) {
    encodedBlob[1260 - 1 - (0x3c + index)] = floatBytes[index];
  }
  return Buffer.concat([Buffer.from('1ca6e8', 'hex'), encodedBlob]);
}

function keyframePacket(timestampMs, participantId, minionsKilled) {
  const payload = heroStatsPayload(minionsKilled);
  const header = Buffer.alloc(15);
  header[0] = 0x00; // absolute timestamp, u32 payload length, absolute route and param
  header.writeFloatLE(timestampMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0276, 9);
  header.writeUInt32LE(HERO_PARAM_FIRST + participantId - 1, 11);
  return Buffer.concat([header, payload]);
}

function levelPacket() {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(1, 1);
  header[5] = 1;
  header.writeUInt16LE(0x02b3, 6);
  header.writeUInt32LE(HERO_PARAM_FIRST, 8);
  return Buffer.concat([header, Buffer.from('6d', 'hex')]); // observed HN level 2
}

function replayWithKeyframe(options = {}) {
  const chunks = [];
  if (options.levelPacket) chunks.push({ body: levelPacket(), stream: 1 });
  if (options.heroStats !== false) {
    chunks.push({
      body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
        keyframePacket(1000, index + 1, index === 0 ? 3 : 0))),
      stream: 2,
    });
  }
  const replay = replayFromChunks(chunks, BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    MINIONS_KILLED: String(index === 0 ? 5 : 0),
    LEVEL: String(index === 0 ? 2 : 1),
  }));
  replay.tail.metadata.gameLength = 2000;
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

test('selected API returns ten observed HeroStats candidates and no confirmed events', () => {
  const replay = replayWithKeyframe();
  const decoded = decodeSemanticReplay(replay, { capabilities: [CANDIDATE] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.runtime_image_used, false);
  assert.equal(decoded.capability_results[CANDIDATE].status, 'CANDIDATE');
  assert.equal(decoded.capability_results[CANDIDATE].event_count, 10);
  assert.equal(decoded.capability_results[CANDIDATE].keyframe_timestamp_count, 1);
  assert.equal(decoded.capability_results[CANDIDATE].tail_gap_total, 2);
  assert.deepEqual(Object.keys(decoded.events), [EVENT_KEY]);
  const events = getHeroMinionsKilledSnapshotCandidates(decoded);
  assert.equal(events.length, 10);
  assert.deepEqual(events.map((row) => row.minions_killed_candidate), [3, ...Array(9).fill(0)]);
  assert.deepEqual(events.map((row) => row.participant_id_candidate),
    Array.from({ length: 10 }, (_, index) => index + 1));
  assert.ok(events.every((row) => row.confidence === 'CANDIDATE'
    && row.raw_packet_ref.packet_id === 0x0276
    && row.raw_packet_ref.replay_sha256 === replay.source_sha256));
  assert.equal(decoded.events.hero_minions_killed_events, undefined);
  assert.equal(decoded.events.minion_kill_events, undefined);
});

test('CLI capabilities preflights MINIONS_KILLED without decoding packets', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-hero-stats-capabilities-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const replay = replayWithKeyframe();
  writeReplayWithTailStats(replay, input);
  let output = '';
  t.mock.method(process.stdout, 'write', (chunk) => { output += String(chunk); return true; });
  const cli = require('../src/cli');
  assert.equal(await cli.main(['capabilities', input, '--json']), 0);
  const query = JSON.parse(output);
  const row = query.capabilities.find((capability) => capability.capability === CANDIDATE);
  assert.equal(query.packet_framing_inspected, false);
  assert.equal(query.semantic_decode_performed, false);
  assert.equal(row.status, 'CANDIDATE');
  assert.equal(row.output, EVENT_KEY);
  assert.equal(row.runtime_image_requirement, 'NOT_REQUIRED');
  assert.deepEqual(row.missing_inputs, []);
  assert.deepEqual(row.invalid_inputs, []);
  assert.equal(row.required_inputs.find((inputRow) => inputRow.name === 'replay_tail_MINIONS_KILLED').status,
    'PRESENT_UNVALIDATED');
  delete replay.tail.stats[3].MINIONS_KILLED;
  assert.deepEqual(cli.capabilityQuery(replay).capabilities
    .find((capability) => capability.capability === CANDIDATE).missing_inputs,
  ['replay_tail_MINIONS_KILLED']);
  replay.tail.stats[3].MINIONS_KILLED = 'invalid';
  assert.deepEqual(cli.capabilityQuery(replay).capabilities
    .find((capability) => capability.capability === CANDIDATE).invalid_inputs,
  ['replay_tail_MINIONS_KILLED']);
});

test('selected CLI writes candidate JSONL and retains candidate-only status', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-hero-stats-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailStats(replayWithKeyframe(), input);
  assert.equal(await require('../src/cli').main([
    'decode', input, '--events', CANDIDATE, '--out-dir', output,
  ]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  assert.equal(summary.capability_runs[0].capability_results[CANDIDATE].status, 'CANDIDATE');
  const replayDirectory = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.runtime_image_used, false);
  assert.equal(semantic.capability_results[CANDIDATE].event_count, 10);
  const events = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'events.json'), 'utf8'));
  assert.deepEqual(Object.keys(events), [EVENT_KEY]);
  assert.equal(events[EVENT_KEY].length, 10);
  const jsonl = fs.readFileSync(path.join(replayDirectory, `${EVENT_KEY}.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map((line) => JSON.parse(line));
  assert.equal(jsonl.length, 10);
  assert.equal(jsonl[0].minions_killed_candidate, 3);
  assert.equal(jsonl[0].confidence, 'CANDIDATE');
});

test('mixed selection retains level candidate when HeroStats keyframe route is unavailable', () => {
  const replay = replayWithKeyframe({ heroStats: false, levelPacket: true });
  const decoded = decodeSemanticReplay(replay, {
    capabilities: [CANDIDATE, 'hero_level_state'],
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results[CANDIDATE].status, 'PROFILE_UNAVAILABLE');
  assert.equal(decoded.capability_results[CANDIDATE].event_count, null);
  assert.equal(getHeroMinionsKilledSnapshotCandidates(decoded), null);
  assert.equal(decoded.capability_results.hero_level_state.status, 'CANDIDATE');
  assert.deepEqual(Object.keys(decoded.events), ['hero_level_state_candidates']);
  assert.equal(decoded.events.hero_level_state_candidates.length, 1);
  assert.equal(decoded.events.hero_level_state_candidates[0].level_after_candidate, 2);
});
