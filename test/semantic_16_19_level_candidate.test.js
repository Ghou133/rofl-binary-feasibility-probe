'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  decodeHeroLevelPayload,
  decodeHeroLevelStateCandidates,
} = require('../src/decoders/rofl_16_19_820_7193');
const {
  decodeSemanticReplay,
  getHeroLevelStateCandidates,
  getHeroDeaths,
} = require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';
const ROUTE = 0x02b3;
const HERO_PARAM_1 = 0x400000ae;
const HERO_PARAM_2 = 0x400000af;

function packet(packetId, timestampMs, rawParam, payload) {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timestampMs / 1000, 1);
  header[5] = payload.length;
  header.writeUInt16LE(packetId, 6);
  header.writeUInt32LE(rawParam >>> 0, 8);
  return Buffer.concat([header, payload]);
}

function replayWithLevelRows(rows, options = {}) {
  const body = Buffer.concat(rows.map(([timestampMs, rawParam, payload, packetId = ROUTE]) =>
    packet(packetId, timestampMs, rawParam, Buffer.from(payload, 'hex'))));
  const replay = replayFromChunks([{ body }], options.version ?? BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    LEVEL: String(index === 0 ? options.firstFinalLevel ?? 4
      : index === 1 ? options.secondFinalLevel ?? 3 : 1),
  }));
  return replay;
}

function writeReplayWithTailLevels(replay, outputPath) {
  const original = replay.buffer;
  const metadataLength = original.readUInt32LE(original.length - 4);
  const metadata = Buffer.from(JSON.stringify({
    gameLength: 600000,
    statsJson: JSON.stringify(replay.tail.stats),
  }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  fs.writeFileSync(outputPath, Buffer.concat([
    original.subarray(0, original.length - metadataLength - 4), metadata, trailer,
  ]));
}

test('the exact HN payload examples decode to their candidate levels', () => {
  assert.deepEqual(decodeHeroLevelPayload(Buffer.from('6d', 'hex')),
    { level_candidate: 2, code: 5 });
  assert.deepEqual(decodeHeroLevelPayload(Buffer.from('6818', 'hex')),
    { level_candidate: 3, code: 0 });
  assert.deepEqual(decodeHeroLevelPayload(Buffer.from('6a08', 'hex')),
    { level_candidate: 4, code: 2 });
  assert.deepEqual(decodeHeroLevelPayload(Buffer.from('5b', 'hex')),
    { level_candidate: 1, code: 3 });
  assert.equal(decodeHeroLevelPayload(Buffer.alloc(0)), null);
  assert.equal(decodeHeroLevelPayload(Buffer.from('6408', 'hex')), null);
  assert.equal(decodeHeroLevelPayload(Buffer.from('6308', 'hex')), null);
});

test('observed HN levels stay candidate events and sequence gaps remain explicit', () => {
  const replay = replayWithLevelRows([
    [500, HERO_PARAM_1, '5b'],
    [1000, HERO_PARAM_1, '6d'],
    [2000, HERO_PARAM_2, '6818'],
    [3000, HERO_PARAM_1, '6a08'],
  ]);
  const result = decodeHeroLevelStateCandidates(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 4);
  assert.equal(result.input_count, 4);
  assert.equal(result.input_packet_id, ROUTE);
  assert.deepEqual(result.events.map((row) => row.level_after_candidate), [1, 2, 3, 4]);
  assert.deepEqual(result.events.map((row) => row.participant_id_candidate), [1, 1, 2, 1]);
  assert.equal(result.level_one_packet_count, 1);
  assert.equal(result.repeated_level_observation_count, 0);
  assert.deepEqual(result.missing_level_updates[0], [3]);
  assert.deepEqual(result.missing_level_updates[1], [2]);
  assert.equal(result.missing_level_update_count, 2);
  assert.deepEqual(result.observed_max_levels.slice(0, 2), [4, 3]);
  assert.ok(result.events.every((row) => row.confidence === 'CANDIDATE'));
  assert.ok(result.events.every((row) => row.raw_packet_ref.packet_id === ROUTE));
  assert.equal(result.events[0].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.events[0].hero_raw_param, HERO_PARAM_1);
  assert.equal(result.events[0].observation_kind, 'LEVEL_ONE_OBSERVATION');
  assert.equal(result.events[1].observation_kind, 'HIGHER_LEVEL_OBSERVATION');
});

test('the HN level route is bound to the complete 16.19.820.7193 build', () => {
  const wrongBuild = replayWithLevelRows([[1000, HERO_PARAM_1, '6d']], {
    version: '16.19.821.7343',
  });
  const result = decodeHeroLevelStateCandidates(wrongBuild);
  assert.equal(result.status, 'UNSUPPORTED');
  assert.equal(result.event_count, null);
  assert.equal(result.events, null);
  assert.match(result.error, /16\.19\.820\.7193/);
});

test('missing tail participant levels are missing input rather than zero events', () => {
  const replay = replayWithLevelRows([[1000, HERO_PARAM_1, '6d']]);
  replay.tail.stats = null;
  const missingStats = decodeHeroLevelStateCandidates(replay);
  assert.equal(missingStats.status, 'MISSING_INPUT');
  assert.equal(missingStats.event_count, null);
  assert.equal(missingStats.events, null);
  assert.match(missingStats.missing_input, /statsJson/);

  replay.tail.stats = Array.from({ length: 10 }, () => ({ LEVEL: '4' }));
  delete replay.tail.stats[3].LEVEL;
  const missingLevel = decodeHeroLevelStateCandidates(replay);
  assert.equal(missingLevel.status, 'MISSING_INPUT');
  assert.equal(missingLevel.event_count, null);
  assert.match(missingLevel.missing_input, /LEVEL/);
});

test('capability query reports missing or invalid tail LEVEL before packet decoding', () => {
  const replay = replayWithLevelRows([[1000, HERO_PARAM_1, '6d']]);
  const query = () => require('../src/cli').capabilityQuery(replay)
    .capabilities.find((row) => row.capability === 'hero_level_state');
  assert.equal(query().required_inputs.find((row) => row.name === 'replay_tail_LEVEL').status,
    'PRESENT_UNVALIDATED');
  delete replay.tail.stats[3].LEVEL;
  assert.deepEqual(query().missing_inputs, ['replay_tail_LEVEL']);
  assert.equal(query().input_assessment_complete, true);
  replay.tail.stats[3].LEVEL = 'invalid';
  assert.deepEqual(query().invalid_inputs, ['replay_tail_LEVEL']);
  replay.tail.stats = null;
  assert.deepEqual(query().missing_inputs, ['replay_tail_statsJson']);
  assert.equal(query().input_assessment_complete, false);
});

test('two distinct same-level packets remain separate candidate observations', () => {
  const replay = replayWithLevelRows([
    [1000, HERO_PARAM_1, '6ac7'], // level 8
    [2000, HERO_PARAM_1, '6978'], // level 9, selector 1
    [3000, HERO_PARAM_1, '6a78'], // level 9, selector 2
    [4000, HERO_PARAM_1, '6868'], // level 10
  ], { firstFinalLevel: 10 });
  const result = decodeHeroLevelStateCandidates(replay);
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.input_count, 4);
  assert.equal(result.event_count, 4);
  assert.equal(result.repeated_level_observation_count, 1);
  assert.deepEqual(result.events.map((event) => event.level_after_candidate), [8, 9, 9, 10]);
  assert.deepEqual(result.events.map((event) => event.observation_kind), [
    'HIGHER_LEVEL_OBSERVATION', 'HIGHER_LEVEL_OBSERVATION',
    'REPEATED_LEVEL_OBSERVATION', 'HIGHER_LEVEL_OBSERVATION',
  ]);
  assert.deepEqual(result.events.slice(1, 3).map((event) => event.payload_selector_code), [1, 2]);
  assert.notEqual(result.events[1].raw_packet_ref.decompressed_block_offset,
    result.events[2].raw_packet_ref.decompressed_block_offset);
  assert.notEqual(result.events[1].raw_packet_ref.raw_payload_sha256,
    result.events[2].raw_packet_ref.raw_payload_sha256);
  assert.equal(result.events[2].raw_packet_ref.replay_sha256, replay.source_sha256);
  assert.equal(result.observed_max_levels[0], 10);
  assert.equal(result.missing_level_updates[0].includes(9), false);

  const selected = decodeSemanticReplay(replay, { capabilities: ['hero_level_state'] });
  assert.equal(selected.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(selected.capability_results.hero_level_state.repeated_level_observation_count, 1);
  assert.equal(selected.events.hero_level_state_candidates[2].observation_kind,
    'REPEATED_LEVEL_OBSERVATION');
});

test('decreasing, above-tail, and malformed level sequences fail closed', () => {
  const decreasing = decodeHeroLevelStateCandidates(replayWithLevelRows([
    [1000, HERO_PARAM_1, '6a08'], [2000, HERO_PARAM_1, '6818'],
  ]));
  assert.equal(decreasing.status, 'DECODE_FAILED');
  assert.match(decreasing.error, /decreasing/);

  const aboveTail = decodeHeroLevelStateCandidates(replayWithLevelRows([
    [1000, HERO_PARAM_1, '6a08'],
  ], { firstFinalLevel: 3 }));
  assert.equal(aboveTail.status, 'DECODE_FAILED');
  assert.match(aboveTail.error, /exceeds Replay tail LEVEL/);

  const malformed = decodeHeroLevelStateCandidates(replayWithLevelRows([
    [1000, HERO_PARAM_1, '6408'],
  ]));
  assert.equal(malformed.status, 'DECODE_FAILED');
  assert.match(malformed.error, /candidate shape/);
});

test('a KR death route without the HN level route is profile unavailable', () => {
  const replay = replayWithLevelRows([
    [1000, HERO_PARAM_1, '0000000000', 0x0259],
    [1000, HERO_PARAM_1, '0000000000', 0x0438],
    [1000, HERO_PARAM_1, '000000', 0x0396],
  ]);
  const result = decodeHeroLevelStateCandidates(replay);
  assert.equal(result.status, 'PROFILE_UNAVAILABLE');
  assert.equal(result.event_count, null);
  assert.equal(result.events, null);
  assert.match(result.error, /HN 0x02b3/);
});

test('selected exact-build API emits only the level candidate field', () => {
  const replay = replayWithLevelRows([
    [1000, HERO_PARAM_1, '6d'], [2000, HERO_PARAM_1, '6a08'],
  ]);
  const result = decodeSemanticReplay(replay, { capabilities: ['hero_level_state'] });
  assert.equal(result.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(result.capability_results.hero_level_state.status, 'CANDIDATE');
  assert.equal(result.capability_results.hero_level_state.event_count, 2);
  assert.equal(result.capability_results.hero_level_state.runtime_image_used, false);
  assert.equal(result.runtime_image_used, false);
  assert.deepEqual(Object.keys(result.events), ['hero_level_state_candidates']);
  assert.equal(getHeroLevelStateCandidates(result).length, 2);
  assert.deepEqual(getHeroDeaths(result), []);
  assert.equal(result.events.level_transition_events, undefined);

  const partial = decodeSemanticReplay(replay, {
    capabilities: ['hero_level_state', 'hero_path'],
  });
  assert.equal(partial.status, 'PARTIAL');
  assert.equal(partial.capability_results.hero_level_state.status, 'CANDIDATE');
  assert.equal(partial.capability_results.hero_path.status, 'UNSUPPORTED');
  assert.equal(partial.events.hero_level_state_candidates.length, 2);
});

test('selected CLI writes level candidates with a candidate-only semantic status', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-level-candidate-cli-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic-16.19.rofl');
  const output = path.join(root, 'output');
  writeReplayWithTailLevels(replayWithLevelRows([
    [1000, HERO_PARAM_1, '6d'], [2000, HERO_PARAM_1, '6a08'],
  ]), input);
  const code = await require('../src/cli').main([
    'decode', input, '--events', 'hero_level_state', '--out-dir', output,
  ]);
  assert.equal(code, 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  assert.equal(summary.capability_runs[0].capability_results.hero_level_state.status, 'CANDIDATE');
  const replayDirectory = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'semantic_run.json'), 'utf8'));
  assert.equal(semantic.runtime_image_used, false);
  assert.equal(semantic.capability_results.hero_level_state.status, 'CANDIDATE');
  const events = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'events.json'), 'utf8'));
  assert.deepEqual(Object.keys(events), ['hero_level_state_candidates']);
  assert.equal(events.hero_level_state_candidates.length, 2);
  assert.equal(fs.existsSync(path.join(replayDirectory, 'hero_level_state_candidates.jsonl')), true);
});
