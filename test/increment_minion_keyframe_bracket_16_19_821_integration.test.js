'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayBuffer, parseReplayFile } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const SELECTED = ['increment_minion_kills_packet', 'hero_minions_killed_snapshot'];
const ASSOCIATION = 'increment_minion_keyframe_bracket';
const BRACKET_EVENTS = 'increment_minion_keyframe_bracket_candidates';
const PACKET_EVENTS = 'increment_minion_kills_packet_candidates';
const SNAPSHOT_EVENTS = 'hero_minions_killed_snapshot_candidates';
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');
const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));

function packet(packetId, rawParam, payload, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(packetId, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function snapshotPacket(participant, timeMs, count) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  const bytes = Buffer.alloc(4);
  bytes.writeFloatLE(count);
  for (let index = 0; index < 4; index += 1) {
    payload[1262 - 0x3c - index] = ENCODE.get(bytes[index]);
  }
  return packet(0x0089, 0x400000ad + participant, payload, timeMs);
}

function fixtureBytes() {
  const chunks = [
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      snapshotPacket(index + 1, 1000, 0))) },
    { stream: 1, body: packet(0x03a7, 0x400000ae,
      Buffer.from('380718', 'hex'), 1500) },
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      snapshotPacket(index + 1, 2000, index === 0 ? 1 : 0))) },
  ];
  const original = replayFromChunks(chunks, BUILD).buffer;
  const trailerOffset = original.length - 4;
  const metadataOffset = trailerOffset - original.readUInt32LE(trailerOffset);
  const metadata = Buffer.from(JSON.stringify({
    gameLength: 600000,
    statsJson: JSON.stringify(Array.from({ length: 10 }, (_, index) => ({
      MINIONS_KILLED: index === 0 ? '1' : '0',
    }))),
  }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  return Buffer.concat([original.subarray(0, metadataOffset), metadata, trailer]);
}

test('selected API retains keyframe source rows when 0x03a7 needs the exact image', () => {
  const replay = parseReplayBuffer(fixtureBytes(), 'synthetic-821-minion-bracket.rofl');
  const { decodeSemanticReplay } = require('../src/semantic_api');
  const snapshotOnly = decodeSemanticReplay(replay, {
    capabilities: ['hero_minions_killed_snapshot'],
  });
  assert.equal(snapshotOnly.candidate_associations[ASSOCIATION], undefined);
  const packetOnly = decodeSemanticReplay(replay, {
    capabilities: ['increment_minion_kills_packet'],
  });
  assert.equal(packetOnly.candidate_associations[ASSOCIATION], undefined);

  const decoded = decodeSemanticReplay(replay, { capabilities: SELECTED });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_minions_killed_snapshot.status, 'CANDIDATE');
  assert.equal(decoded.events[SNAPSHOT_EVENTS].length, 20);
  assert.equal(decoded.capability_results.increment_minion_kills_packet.status,
    'MISSING_INPUT');
  assert.equal(decoded.candidate_associations[ASSOCIATION].status, 'MISSING_INPUT');
  assert.equal(decoded.events[PACKET_EVENTS], undefined);
  assert.equal(decoded.events[BRACKET_EVENTS], undefined);
});

test('selected CLI writes missing-image association and independent snapshot JSONL', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-minion-bracket-missing-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const input = path.join(directory, 'synthetic.rofl');
  const output = path.join(directory, 'output');
  fs.writeFileSync(input, fixtureBytes());
  const run = spawnSync(process.execPath, [CLI, 'decode', input,
    '--events', SELECTED.join(','), '--event-jsonl-only', '--out-dir', output], {
    encoding: 'utf8', timeout: 30000,
  });
  assert.equal(run.status, 2, run.stderr || run.stdout);
  const acceptance = JSON.parse(fs.readFileSync(path.join(output,
    'acceptance_summary.json'), 'utf8'));
  assert.equal(acceptance.status, 'PARTIAL');
  const replayDirectory = path.join(output,
    acceptance.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
    'semantic_run.json'), 'utf8'));
  assert.equal(semantic.candidate_associations[ASSOCIATION].status, 'MISSING_INPUT');
  assert.equal(fs.existsSync(path.join(replayDirectory,
    `${BRACKET_EVENTS}.jsonl`)), false);
  const snapshots = fs.readFileSync(path.join(replayDirectory,
    `${SNAPSHOT_EVENTS}.jsonl`), 'utf8').trim().split(/\r?\n/);
  assert.equal(snapshots.length, 20);
});

test('one exact KR replay exposes packet-to-keyframe brackets through API and CLI', (t) => {
  if (!fs.existsSync(REPLAY) || !fs.existsSync(IMAGE)) {
    t.skip('supplied KR 821 replay or matching local runtime image absent');
    return;
  }
  const { decodeSemanticReplay } = require('../src/semantic_api');
  const decoded = decodeSemanticReplay(parseReplayFile(REPLAY), {
    capabilities: SELECTED, runtimeImagePath: IMAGE,
  });
  for (const capability of SELECTED) {
    assert.equal(decoded.capability_results[capability].status, 'CANDIDATE');
  }
  const association = decoded.candidate_associations[ASSOCIATION];
  assert.equal(association.status, 'CANDIDATE', association.error);
  assert.ok(association.event_count > 0);
  assert.equal(association.event_count, decoded.events[BRACKET_EVENTS].length);
  assert.ok(decoded.events[BRACKET_EVENTS].every((row) =>
    row.event_type === 'INCREMENT_MINION_KEYFRAME_BRACKET_CANDIDATE'
      && row.confidence === 'CANDIDATE'
      && row.previous_observation_time_ms < row.replay_time_ms
      && row.replay_time_ms < row.current_observation_time_ms
      && row.semantic_cs_effect_status === 'UNKNOWN'
      && row.raw_packet_ref.packet_id === 0x03a7
      && row.previous_snapshot_raw_packet_ref.packet_id === 0x0089
      && row.current_snapshot_raw_packet_ref.packet_id === 0x0089));

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-minion-bracket-real-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const output = path.join(directory, 'output');
  const run = spawnSync(process.execPath, [CLI, 'decode', REPLAY,
    '--events', SELECTED.join(','), '--runtime-image', IMAGE,
    '--event-jsonl-only', '--out-dir', output], {
    encoding: 'utf8', timeout: 120000,
  });
  assert.equal(run.status, 0, run.stderr || run.stdout);
  const acceptance = JSON.parse(fs.readFileSync(path.join(output,
    'acceptance_summary.json'), 'utf8'));
  const replayDirectory = path.join(output,
    acceptance.replay_artifacts[0].artifact_directory);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
    'semantic_run.json'), 'utf8'));
  const bracketRows = fs.readFileSync(path.join(replayDirectory,
    `${BRACKET_EVENTS}.jsonl`), 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  assert.deepEqual(semantic.candidate_associations[ASSOCIATION], association);
  assert.deepEqual(bracketRows, decoded.events[BRACKET_EVENTS]);
});

test('association failure reports PARTIAL while both decoded source JSONL files survive', async (t) => {
  const packetModule = require('../src/decoders/rofl_16_19_821_increment_minion_kills_packet_candidate');
  const snapshotModule = require('../src/decoders/rofl_16_19_821_float_stats_candidate');
  const bracketModule = require('../src/decoders/rofl_16_19_821_increment_minion_keyframe_bracket_candidate');
  const originalPacket = packetModule.decodeIncrementMinionKillsPacketCandidates821;
  const originalSnapshot = snapshotModule.decodeHeroFloatSnapshotCandidates821;
  const originalBracket = bracketModule.associateIncrementMinionKeyframeBracketCandidates821;
  const semanticPath = require.resolve('../src/semantic_api');
  const cliPath = require.resolve('../src/cli');
  const previousSemanticModule = require.cache[semanticPath];
  const previousCliModule = require.cache[cliPath];
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-minion-bracket-fail-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const input = path.join(directory, 'synthetic.rofl');
  const output = path.join(directory, 'output');
  const packetEvent = { event_type: 'INCREMENT_MINION_KILLS_PACKET_CANDIDATE',
    game_version: BUILD, replay_time_ms: 1500, confidence: 'CANDIDATE' };
  const snapshotEvent = { event_type: 'HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE',
    game_version: BUILD, replay_time_ms: 1000, confidence: 'CANDIDATE' };
  packetModule.decodeIncrementMinionKillsPacketCandidates821 = () => ({
    status: 'CANDIDATE', input_count: 1, event_count: 1,
    input_packet_id: 0x03a7, events: [packetEvent],
    runtime_image_status: 'NOT_REQUIRED', runtime_image_used: false,
  });
  snapshotModule.decodeHeroFloatSnapshotCandidates821 = () => ({
    status: 'CANDIDATE', input_count: 20, event_count: 1,
    input_packet_id: 0x0089, events: [snapshotEvent],
    runtime_image_status: 'NOT_REQUIRED', runtime_image_used: false,
  });
  bracketModule.associateIncrementMinionKeyframeBracketCandidates821 = () => {
    throw new Error('injected bracket association failure');
  };
  delete require.cache[semanticPath];
  delete require.cache[cliPath];
  try {
    const freshApi = require('../src/semantic_api');
    const freshCli = require('../src/cli');
    const replay = parseReplayBuffer(fixtureBytes(), 'synthetic-821-minion-bracket.rofl');
    const decoded = freshApi.decodeSemanticReplay(replay, { capabilities: SELECTED });
    assert.equal(decoded.status, 'PARTIAL');
    assert.deepEqual(decoded.events[PACKET_EVENTS], [packetEvent]);
    assert.deepEqual(decoded.events[SNAPSHOT_EVENTS], [snapshotEvent]);
    assert.equal(decoded.candidate_associations[ASSOCIATION].status, 'DECODE_FAILED');
    assert.match(decoded.candidate_associations[ASSOCIATION].error,
      /injected bracket association failure/);
    assert.equal(decoded.events[BRACKET_EVENTS], undefined);

    fs.writeFileSync(input, fixtureBytes());
    const exitCode = await freshCli.main(['decode', input, '--events', SELECTED.join(','),
      '--event-jsonl-only', '--out-dir', output]);
    assert.equal(exitCode, 2);
    const acceptance = JSON.parse(fs.readFileSync(path.join(output,
      'acceptance_summary.json'), 'utf8'));
    assert.equal(acceptance.status, 'PARTIAL');
    const replayDirectory = path.join(output,
      acceptance.replay_artifacts[0].artifact_directory);
    const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory,
      'semantic_run.json'), 'utf8'));
    assert.equal(semantic.status, 'PARTIAL');
    assert.equal(semantic.candidate_associations[ASSOCIATION].status, 'DECODE_FAILED');
    assert.equal(fs.existsSync(path.join(replayDirectory,
      `${BRACKET_EVENTS}.jsonl`)), false);
    for (const [key, expected] of [[PACKET_EVENTS, packetEvent],
      [SNAPSHOT_EVENTS, snapshotEvent]]) {
      const rows = fs.readFileSync(path.join(replayDirectory, `${key}.jsonl`), 'utf8')
        .trim().split(/\r?\n/).map(JSON.parse);
      assert.deepEqual(rows, [expected]);
    }
  } finally {
    packetModule.decodeIncrementMinionKillsPacketCandidates821 = originalPacket;
    snapshotModule.decodeHeroFloatSnapshotCandidates821 = originalSnapshot;
    bracketModule.associateIncrementMinionKeyframeBracketCandidates821 = originalBracket;
    if (previousSemanticModule) require.cache[semanticPath] = previousSemanticModule;
    else delete require.cache[semanticPath];
    if (previousCliModule) require.cache[cliPath] = previousCliModule;
    else delete require.cache[cliPath];
  }
});
