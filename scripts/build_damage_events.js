#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { once } = require('node:events');

const {
  DAMAGE_PROFILE,
  damageEventFromDecodedRow,
  participantMetadata,
} = require('../src/decoders/rofl_16_15_801_3452');
const { sha256File } = require('../src/io');
const { parseReplayFile } = require('../src/rofl');

const SCOPES = new Set(['all', 'hero-pair', 'hero-pair-positive']);

function parseArgs(argv) {
  const options = {
    decoded: null,
    replayDir: path.resolve('replay'),
    replayFiles: [],
    output: null,
    manifest: null,
    scope: 'hero-pair-positive',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--decoded') options.decoded = path.resolve(argv[++index]);
    else if (value === '--replay-dir') options.replayDir = path.resolve(argv[++index]);
    else if (value === '--replay') options.replayFiles.push(path.resolve(argv[++index]));
    else if (value === '--output') options.output = path.resolve(argv[++index]);
    else if (value === '--manifest') options.manifest = path.resolve(argv[++index]);
    else if (value === '--scope') options.scope = argv[++index];
    else throw new Error(`unknown argument: ${value}`);
  }
  if (!options.decoded) throw new Error('--decoded is required');
  if (!options.output) throw new Error('--output is required');
  if (!SCOPES.has(options.scope)) throw new Error(`unsupported --scope: ${options.scope}`);
  options.manifest ||= `${options.output}.manifest.json`;
  return options;
}

function loadReplays(directory, replayFiles = []) {
  const bySha256 = new Map();
  const files = replayFiles.length > 0
    ? [...new Set(replayFiles)].sort()
    : fs.readdirSync(directory)
      .filter((item) => item.endsWith('.rofl'))
      .sort()
      .map((name) => path.join(directory, name));
  for (const file of files) {
    const replay = parseReplayFile(file);
    if (replay.header.version !== DAMAGE_PROFILE.replay_version) continue;
    bySha256.set(replay.source_sha256, {
      replay,
      participants: participantMetadata(replay),
    });
  }
  return bySha256;
}

function selected(event, scope) {
  if (scope === 'all') return true;
  const championPair = event.source_entity_type === 'champion'
    && event.target_entity_type === 'champion';
  if (scope === 'hero-pair') return championPair;
  return championPair && event.amount > 0;
}

async function writeLine(stream, row) {
  if (!stream.write(`${JSON.stringify(row)}\n`)) await once(stream, 'drain');
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const replays = loadReplays(options.replayDir, options.replayFiles);
  if (replays.size === 0) throw new Error(`no ${DAMAGE_PROFILE.replay_version} Replay found`);
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  fs.mkdirSync(path.dirname(options.manifest), { recursive: true });
  const destination = fs.createWriteStream(options.output, { encoding: 'utf8' });
  const counts = {
    decoded_rows: 0,
    semantic_rows: 0,
    selected_rows: 0,
    rejected_rows: 0,
    hero_pair_rows: 0,
    hero_pair_positive_rows: 0,
    enemy_hero_pair_positive_rows: 0,
    allied_or_self_hero_pair_positive_rows: 0,
  };
  const perReplay = {};

  const lines = readline.createInterface({
    input: fs.createReadStream(options.decoded),
    crlfDelay: Infinity,
  });
  for await (const line of lines) {
    if (!line.trim()) continue;
    counts.decoded_rows += 1;
    const row = JSON.parse(line);
    const context = replays.get(row.replay_sha256);
    if (!context) throw new Error(`decoded row references an unknown Replay: ${row.replay_sha256}`);
    const event = damageEventFromDecodedRow(context.replay, row, context.participants);
    if (!event) {
      counts.rejected_rows += 1;
      continue;
    }
    counts.semantic_rows += 1;
    const championPair = event.source_entity_type === 'champion'
      && event.target_entity_type === 'champion';
    const positiveChampionPair = championPair && event.amount > 0;
    counts.hero_pair_rows += Number(championPair);
    counts.hero_pair_positive_rows += Number(positiveChampionPair);
    if (positiveChampionPair) {
      const enemy = event.source_team_id !== null
        && event.target_team_id !== null
        && event.source_team_id !== event.target_team_id;
      counts.enemy_hero_pair_positive_rows += Number(enemy);
      counts.allied_or_self_hero_pair_positive_rows += Number(!enemy);
    }
    const replayCounts = perReplay[row.replay_sha256] ||= {
      replay_path: context.replay.source_path,
      replay_sha256: context.replay.source_sha256,
      semantic_rows: 0,
      selected_rows: 0,
    };
    replayCounts.semantic_rows += 1;
    if (selected(event, options.scope)) {
      await writeLine(destination, event);
      counts.selected_rows += 1;
      replayCounts.selected_rows += 1;
    }
  }
  destination.end();
  await once(destination, 'finish');

  const manifest = {
    schema_version: 1,
    status: counts.rejected_rows === 0 && counts.semantic_rows === counts.decoded_rows
      ? 'PASS'
      : 'FAIL',
    operation: 'REPLAY_ONLY_DAMAGE_EVENT_BUILD',
    details_or_oracle_input: false,
    decoder_profile: DAMAGE_PROFILE,
    scope: options.scope,
    decoded_input: options.decoded,
    decoded_input_sha256: await sha256File(options.decoded),
    output: options.output,
    output_sha256: await sha256File(options.output),
    counts,
    replays: Object.values(perReplay),
  };
  fs.writeFileSync(options.manifest, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({ ...manifest, manifest: options.manifest }, null, 2)}\n`);
  if (manifest.status !== 'PASS') process.exitCode = 1;
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { main, parseArgs, selected };
