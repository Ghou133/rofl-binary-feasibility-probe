#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const { once } = require('node:events');

const {
  CAST_SPELL_PROFILE,
  isCastSpellDecodedRow,
  participantIdFromChampionNetworkId,
  participantMetadata,
  spellEventFromDecodedRow,
} = require('../src/decoders/rofl_16_15_801_3452');
const { sha256File } = require('../src/io');
const { parseReplayFile } = require('../src/rofl');
const {
  DEFAULT_SPELL_DICTIONARY,
  annotatePlayerCastGroups,
} = require('../src/semantic_pipeline');

function parseArgs(argv) {
  const options = {
    decoded: null,
    replayDir: path.resolve('replay'),
    replayFiles: [],
    dictionary: DEFAULT_SPELL_DICTIONARY,
    output: null,
    manifest: null,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--decoded') options.decoded = path.resolve(argv[++index]);
    else if (value === '--replay-dir') options.replayDir = path.resolve(argv[++index]);
    else if (value === '--replay') options.replayFiles.push(path.resolve(argv[++index]));
    else if (value === '--dictionary') options.dictionary = path.resolve(argv[++index]);
    else if (value === '--output') options.output = path.resolve(argv[++index]);
    else if (value === '--manifest') options.manifest = path.resolve(argv[++index]);
    else throw new Error(`unknown argument: ${value}`);
  }
  if (!options.decoded) throw new Error('--decoded is required');
  if (!options.output) throw new Error('--output is required');
  options.manifest ||= `${options.output}.manifest.json`;
  return options;
}

function loadReplays(directory, replayFiles = []) {
  const files = replayFiles.length > 0
    ? [...new Set(replayFiles)].sort()
    : fs.readdirSync(directory)
      .filter((item) => item.toLowerCase().endsWith('.rofl'))
      .sort()
      .map((name) => path.join(directory, name));
  const bySha256 = new Map();
  for (const file of files) {
    const replay = parseReplayFile(file);
    if (replay.header.version !== CAST_SPELL_PROFILE.replay_version) continue;
    bySha256.set(replay.source_sha256, {
      replay,
      participants: participantMetadata(replay),
    });
  }
  return bySha256;
}

async function writeLine(stream, row) {
  if (!stream.write(`${JSON.stringify(row)}\n`)) await once(stream, 'drain');
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const dictionarySha256 = await sha256File(options.dictionary);
  if (dictionarySha256 !== CAST_SPELL_PROFILE.spell_dictionary_sha256) {
    throw new Error(`spell dictionary SHA-256 mismatch: ${dictionarySha256}`);
  }
  const dictionary = JSON.parse(fs.readFileSync(options.dictionary, 'utf8'));
  if (dictionary.details_or_oracle_input !== false || dictionary.patch !== '16.15') {
    throw new Error('spell dictionary metadata failed structural verification');
  }
  const replays = loadReplays(options.replayDir, options.replayFiles);
  if (replays.size === 0) {
    throw new Error(`no ${CAST_SPELL_PROFILE.replay_version} Replay found`);
  }

  const counts = {
    decoded_rows: 0,
    structurally_valid_rows: 0,
    semantic_hero_rows: 0,
    non_champion_caster_rows: 0,
    rejected_rows: 0,
    primary_engine_rows: 0,
    primary_player_casts: 0,
    protection_casts: 0,
    resolved_spell_rows: 0,
  };
  const events = [];
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
    const replayCounts = perReplay[row.replay_sha256] ||= {
      replay_path: context.replay.source_path,
      replay_sha256: context.replay.source_sha256,
      decoded_rows: 0,
      semantic_hero_rows: 0,
      non_champion_caster_rows: 0,
      primary_engine_rows: 0,
      primary_player_casts: 0,
      protection_casts: 0,
    };
    replayCounts.decoded_rows += 1;
    if (!isCastSpellDecodedRow(context.replay, row)) {
      counts.rejected_rows += 1;
      continue;
    }
    counts.structurally_valid_rows += 1;
    if (participantIdFromChampionNetworkId(row.decoded_fields.caster_network_id) === null) {
      counts.non_champion_caster_rows += 1;
      replayCounts.non_champion_caster_rows += 1;
      continue;
    }
    const event = spellEventFromDecodedRow(
      context.replay,
      row,
      dictionary,
      context.participants,
    );
    if (!event) {
      counts.rejected_rows += 1;
      continue;
    }
    events.push(event);
    counts.semantic_hero_rows += 1;
    replayCounts.semantic_hero_rows += 1;
  }

  annotatePlayerCastGroups(events);
  fs.mkdirSync(path.dirname(options.output), { recursive: true });
  const destination = fs.createWriteStream(options.output, { encoding: 'utf8' });
  for (const event of events) {
    const replayCounts = perReplay[event.raw_packet_ref.replay_sha256];
    counts.primary_engine_rows += Number(event.is_primary_player_ability);
    counts.primary_player_casts += Number(event.is_player_cast_group_leader);
    counts.protection_casts += Number(event.protection_cast_kind !== null
      && event.is_player_cast_group_leader);
    counts.resolved_spell_rows += Number(event.spell_identifier !== null);
    replayCounts.primary_engine_rows += Number(event.is_primary_player_ability);
    replayCounts.primary_player_casts += Number(event.is_player_cast_group_leader);
    replayCounts.protection_casts += Number(event.protection_cast_kind !== null
      && event.is_player_cast_group_leader);
    await writeLine(destination, event);
  }
  destination.end();
  await once(destination, 'finish');

  const manifest = {
    schema_version: 1,
    status: counts.rejected_rows === 0
      && counts.structurally_valid_rows === counts.decoded_rows
      && counts.semantic_hero_rows + counts.non_champion_caster_rows === counts.decoded_rows
      ? 'PASS'
      : 'FAIL',
    operation: 'REPLAY_ONLY_CAST_SPELL_EVENT_BUILD',
    details_or_oracle_input: false,
    decoder_profile: CAST_SPELL_PROFILE,
    decoded_input: options.decoded,
    decoded_input_sha256: await sha256File(options.decoded),
    spell_dictionary: options.dictionary,
    spell_dictionary_sha256: dictionarySha256,
    output: options.output,
    output_sha256: await sha256File(options.output),
    counts,
    replays: Object.values(perReplay),
  };
  fs.mkdirSync(path.dirname(options.manifest), { recursive: true });
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

module.exports = { loadReplays, main, parseArgs };
