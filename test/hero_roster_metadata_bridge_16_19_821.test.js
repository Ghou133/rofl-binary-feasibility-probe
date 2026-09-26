'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayBuffer, normalizePlayers } = require('../src/rofl');
const { prepareEventQuery, prepareBatchEventQuery, streamEventQuery,
  streamBatchEventQuery } = require('../src/event_query');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  HERO_ROSTER_METADATA_BRIDGE_821_PROFILE,
  associateHeroRosterMetadataBridge821,
} = require('../src/decoders/rofl_16_19_821_roster_metadata_bridge_candidate');

const BUILD = '16.19.821.7343';
const ROLES = ['TOP', 'JUNGLE', 'MIDDLE', 'BOTTOM', 'UTILITY'];

function players() {
  return Array.from({ length: 10 }, (_, index) => ({
    SKIN: `Champion${index + 1}`,
    TEAM: index < 5 ? '100' : '200',
    INDIVIDUAL_POSITION: ROLES[index % 5],
    CHAMPIONS_KILLED: String(index + 1),
    NUM_DEATHS: String(index + 2),
    ASSISTS: String(index + 3),
    PUUID: `private-puuid-${index}`,
    RIOT_ID_GAME_NAME: `private-name-${index}`,
  }));
}

function replayWithPlayers(stats) {
  const base = replayFromChunks([], BUILD);
  const metadata = Buffer.from(JSON.stringify({
    gameLength: 600000,
    statsJson: JSON.stringify(stats),
  }));
  const length = Buffer.alloc(4);
  length.writeUInt32LE(metadata.length);
  return parseReplayBuffer(Buffer.concat([
    base.buffer.subarray(0, base.tail.metadata_start), metadata, length,
  ]), 'synthetic-roster-bridge.rofl');
}

function sourceOutcomes(replay, counts = players()) {
  const death = counts.map((row) => Number(row.NUM_DEATHS));
  const kills = counts.map((row) => Number(row.CHAMPIONS_KILLED));
  const assists = counts.map((row) => Number(row.ASSISTS));
  const refs = Array.from({ length: 10 }, (_, index) => ({
    replay_sha256: replay.source_sha256,
    chunk_stream: 'keyframe',
    packet_id: 0x0089,
    raw_param: 0x400000ae + index,
    replay_time_ms: 500000,
    chunk_index: 1,
    decompressed_block_offset: index * 1280,
    raw_payload_sha256: crypto.createHash('sha256')
      .update(`hero-${index}`).digest('hex'),
  }));
  const snapshot = (field, values) => ({
    status: 'CANDIDATE', input_count: 10, event_count: 10,
    events: values.map((value, index) => ({
      participant_id_candidate: index + 1,
      hero_raw_param: 0x400000ae + index,
      replay_time_ms: 500000,
      [field]: value,
      raw_packet_ref: refs[index],
    })),
  });
  return {
    hero_death: {
      status: 'CANDIDATE', event_count: death.reduce((sum, n) => sum + n, 0),
      champion_kills_tail_alignment_status: 'CANDIDATE_ALIGNED',
      observed_death_counts: death,
      observed_champion_kills_by_source: kills,
    },
    hero_assist: {
      status: 'CANDIDATE', assist_pair_count: assists.reduce((sum, n) => sum + n, 0),
      observed_assists_by_participant: assists,
    },
    hero_deaths_snapshot: snapshot('deaths_candidate', death),
    hero_champion_kills_snapshot: snapshot('champion_kills_candidate', kills),
    hero_assists_snapshot: snapshot('assists_candidate', assists),
  };
}

test('unique ten-player K/D/A bridge keeps metadata labels direct and network identity candidate', () => {
  const stats = players();
  const replay = replayWithPlayers(stats);
  const result = associateHeroRosterMetadataBridge821(replay,
    sourceOutcomes(replay, stats));
  assert.equal(result.status, 'CANDIDATE');
  assert.equal(result.event_count, 10);
  assert.equal(result.unique_kda_match_count, 10);
  assert.equal(result.events[0].champion_metadata, 'Champion1');
  assert.equal(result.events[0].team_metadata, 'blue');
  assert.equal(result.events[0].role_metadata, 'top');
  assert.equal(result.events[0].per_packet_actor_status, 'UNKNOWN');
  assert.equal(result.events[0].field_confidence.champion_metadata,
    'VERIFIED_FROM_METADATA');
  assert.equal(result.events[0].field_confidence.participant_id_candidate,
    HERO_ROSTER_METADATA_BRIDGE_821_PROFILE.evidence_status);
  assert.equal(result.events[0].raw_packet_ref.raw_param, 0x400000ae);
  assert.equal(result.stats_json_sha256,
    crypto.createHash('sha256').update(replay.tail.metadata.statsJson).digest('hex'));
  const text = JSON.stringify(result.events);
  assert.doesNotMatch(text, /private-puuid|private-name|metadata_player_id|riot_id|puuid/i);
});

test('permuted metadata rows contradict the raw-key alignment and emit no bridge', () => {
  const canonical = players();
  const permuted = [...canonical];
  [permuted[0], permuted[1]] = [permuted[1], permuted[0]];
  const replay = replayWithPlayers(permuted);
  const result = associateHeroRosterMetadataBridge821(replay,
    sourceOutcomes(replay, canonical));
  assert.equal(result.status, 'DECODE_FAILED');
  assert.match(result.error, /contradicts/);
  assert.equal(result.events, null);
});

test('ambiguous K/D/A, missing labels and a missing source remain unavailable', () => {
  const duplicate = players();
  duplicate[1].CHAMPIONS_KILLED = duplicate[0].CHAMPIONS_KILLED;
  duplicate[1].NUM_DEATHS = duplicate[0].NUM_DEATHS;
  duplicate[1].ASSISTS = duplicate[0].ASSISTS;
  const ambiguousReplay = replayWithPlayers(duplicate);
  const ambiguous = associateHeroRosterMetadataBridge821(ambiguousReplay,
    sourceOutcomes(ambiguousReplay, duplicate));
  assert.equal(ambiguous.status, 'PROFILE_UNAVAILABLE');
  assert.match(ambiguous.error, /uniquely/);
  assert.equal(ambiguous.events, null);

  const missing = players();
  delete missing[4].SKIN;
  const missingReplay = replayWithPlayers(missing);
  const noLabel = associateHeroRosterMetadataBridge821(missingReplay,
    sourceOutcomes(missingReplay, missing));
  assert.equal(noLabel.status, 'MISSING_INPUT');
  assert.equal(noLabel.events, null);

  const replay = replayWithPlayers(players());
  const inputs = sourceOutcomes(replay);
  inputs.hero_assist = { status: 'MISSING_INPUT' };
  const noAssists = associateHeroRosterMetadataBridge821(replay, inputs);
  assert.equal(noAssists.status, 'MISSING_INPUT');
  assert.equal(noAssists.events, null);
});

test('raw TEAM and SKIN reject parseInt prefixes and whitespace labels', () => {
  const malformedTeam = players();
  malformedTeam[0].TEAM = '100garbage';
  const replay = replayWithPlayers(malformedTeam);
  const teamResult = associateHeroRosterMetadataBridge821(replay,
    sourceOutcomes(replay, malformedTeam));
  assert.equal(teamResult.status, 'DECODE_FAILED');
  assert.match(teamResult.error, /raw TEAM/);
  assert.equal(teamResult.events, null);

  const blankSkin = players();
  blankSkin[0].SKIN = '   ';
  const blankReplay = replayWithPlayers(blankSkin);
  const skinResult = associateHeroRosterMetadataBridge821(blankReplay,
    sourceOutcomes(blankReplay, blankSkin));
  assert.equal(skinResult.status, 'MISSING_INPUT');
  assert.match(skinResult.error, /raw SKIN/);
  assert.equal(skinResult.events, null);
});

test('altered parsed metadata or mismatched HeroStats references fail closed', () => {
  const replay = replayWithPlayers(players());
  const inputs = sourceOutcomes(replay);
  inputs.hero_assists_snapshot.events[0].raw_packet_ref = {
    ...inputs.hero_assists_snapshot.events[0].raw_packet_ref,
    raw_payload_sha256: '0'.repeat(64),
  };
  const badRef = associateHeroRosterMetadataBridge821(replay, inputs);
  assert.equal(badRef.status, 'DECODE_FAILED');
  assert.equal(badRef.events, null);

  const parsed = replayWithPlayers(players());
  parsed.tail.stats[0].SKIN = 'Injected';
  const changed = associateHeroRosterMetadataBridge821(parsed,
    sourceOutcomes(parsed));
  assert.equal(changed.status, 'DECODE_FAILED');
  assert.match(changed.error, /physical source bytes/);
  assert.equal(changed.events, null);
});

function writeSavedBridgeFixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-bridge-query-'));
  t.after(() => {
    const resolved = path.resolve(root);
    if (!resolved.startsWith(path.resolve(os.tmpdir()) + path.sep)
        || !path.basename(resolved).startsWith('rofl-bridge-query-')) {
      throw new Error('Unsafe test fixture cleanup target');
    }
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  const relative = 'replays/synthetic';
  const directory = path.join(root, 'replays', 'synthetic');
  fs.mkdirSync(directory, { recursive: true });
  const replay = replayWithPlayers(players());
  const result = associateHeroRosterMetadataBridge821(replay,
    sourceOutcomes(replay));
  assert.equal(result.status, 'CANDIDATE');
  const sourcePath = path.join(root, 'absent-original.rofl');
  const rows = result.events.map((row) => ({ ...row,
    raw_packet_ref: { ...row.raw_packet_ref,
      source_path: sourcePath, chunk_id: 1, chunk_file_offset: 1024,
      decompressed_payload_offset:
        row.raw_packet_ref.decompressed_block_offset + 9,
      payload_length: 1263 },
  }));
  const capability = { ...result };
  delete capability.events;
  const semantic = {
    replay_version: BUILD, replay_sha256: replay.source_sha256,
    container_status: 'PASS', status: 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE',
    requested_capabilities: ['hero_roster_metadata_bridge'],
    capability_results: { hero_roster_metadata_bridge: capability },
  };
  const analysis = {
    replay_version: BUILD, replay_sha256: replay.source_sha256,
    patch: '16.19', source_path: sourcePath,
    event_storage: 'JSONL_ONLY',
    event_counts: { hero_roster_metadata_bridge_candidates: 10 },
    event_jsonl_files: { hero_roster_metadata_bridge_candidates:
      'hero_roster_metadata_bridge_candidates.jsonl' },
  };
  const inventory = {
    sha256: replay.source_sha256, replay_version: BUILD,
    metadata: { stats_player_count: 10, players: normalizePlayers(replay) },
  };
  const files = {
    'semantic_run.json': JSON.stringify(semantic),
    'replay_analysis.json': JSON.stringify(analysis),
    'rofl_inventory.json': JSON.stringify(inventory),
    'hero_roster_metadata_bridge_candidates.jsonl':
      `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`,
  };
  const rewrite = () => {
    const hashes = {};
    for (const [name, content] of Object.entries(files)) {
      fs.writeFileSync(path.join(directory, name), content);
      hashes[`${relative}/${name}`] = crypto.createHash('sha256')
        .update(content).digest('hex');
    }
    fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
      command_args: ['decode'],
      replay_inputs: [{ artifact_directory: relative,
        sha256: replay.source_sha256, version: BUILD }],
      output_hashes_excluding_manifest: hashes,
    }));
  };
  rewrite();
  return { root, directory, files, rewrite, replay };
}

test('saved roster query validates manifest-hashed inventory without original ROFL', async (t) => {
  const fixture = writeSavedBridgeFixture(t);
  const event = 'hero_roster_metadata_bridge_candidates';
  const prepared = prepareEventQuery(fixture.directory, event);
  const rows = [];
  const summary = await streamEventQuery(prepared,
    { participant: 1, limit: 1 }, async (line) => rows.push(JSON.parse(line)));
  assert.equal(summary.scanned_count, 10);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.source_provenance_status, 'SAVED_ONLY_UNVERIFIED');
  assert.equal(rows[0].champion_metadata, 'Champion1');
  const batch = prepareBatchEventQuery(fixture.root, event);
  const batchSummary = await streamBatchEventQuery(batch, { participant: 1 },
    async () => {});
  assert.equal(batchSummary.completed_replay_count, 1);
  await assert.rejects(() => streamEventQuery(prepared,
    { verifySource: true }, async () => {}),
  (error) => error.code === 'SOURCE_REPLAY_READ_FAILED');
  const replaced = path.join(fixture.root, 'replaced.rofl');
  const different = replayWithPlayers(players().map((player, index) => ({
    ...player, SKIN: index === 0 ? 'Different' : player.SKIN,
  })));
  fs.writeFileSync(replaced, different.buffer);
  await assert.rejects(() => streamEventQuery(prepared,
    { verifySource: true, sourceReplay: replaced }, async () => {}),
  (error) => error.code === 'SOURCE_REPLAY_IDENTITY_MISMATCH');
});

test('saved query rejects relabeled rows even when manifest hashes are rewritten', async (t) => {
  const fixture = writeSavedBridgeFixture(t);
  const event = 'hero_roster_metadata_bridge_candidates';
  const rows = fixture.files[`${event}.jsonl`].trimEnd().split('\n')
    .map((line) => JSON.parse(line));
  rows[0].champion_metadata = 'Injected';
  fixture.files[`${event}.jsonl`] =
    `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`;
  fixture.rewrite();
  const prepared = prepareEventQuery(fixture.directory, event);
  await assert.rejects(() => streamEventQuery(prepared, {}, async () => {}),
    (error) => error.code === 'INVALID_EVENT_ROW');
});

test('late row tamper after limit 1 produces no CLI stdout', (t) => {
  const fixture = writeSavedBridgeFixture(t);
  const event = 'hero_roster_metadata_bridge_candidates';
  const rows = fixture.files[`${event}.jsonl`].trimEnd().split('\n')
    .map((line) => JSON.parse(line));
  rows[9].champion_metadata = 'Injected';
  fixture.files[`${event}.jsonl`] =
    `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`;
  fixture.rewrite();
  const cli = childProcess.spawnSync(process.execPath, [
    path.join(__dirname, '..', 'src', 'cli.js'),
    'query-events', fixture.directory, '--event', event, '--limit', '1',
  ], { encoding: 'utf8' });
  assert.equal(cli.status, 2);
  assert.equal(cli.stdout, '');
  assert.match(cli.stderr, /INVALID_EVENT_ROW/);
});

test('unavailable bridge metadata cannot be queried as an empty success', (t) => {
  const fixture = writeSavedBridgeFixture(t);
  const semantic = JSON.parse(fixture.files['semantic_run.json']);
  semantic.capability_results.hero_roster_metadata_bridge.status =
    'PROFILE_UNAVAILABLE';
  semantic.capability_results.hero_roster_metadata_bridge.event_count = null;
  fixture.files['semantic_run.json'] = JSON.stringify(semantic);
  fixture.rewrite();
  assert.throws(() => prepareEventQuery(fixture.directory,
    'hero_roster_metadata_bridge_candidates'),
  (error) => error.code === 'CAPABILITY_UNAVAILABLE');
});

test('missing champion in manifest-hashed inventory cannot be queried', (t) => {
  const fixture = writeSavedBridgeFixture(t);
  const inventory = JSON.parse(fixture.files['rofl_inventory.json']);
  inventory.metadata.players[4].champion = null;
  fixture.files['rofl_inventory.json'] = JSON.stringify(inventory);
  fixture.rewrite();
  assert.throws(() => prepareEventQuery(fixture.directory,
    'hero_roster_metadata_bridge_candidates'),
  (error) => error.code === 'CAPABILITY_METADATA_MISMATCH');
});
