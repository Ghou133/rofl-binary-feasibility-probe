#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const { hashFiles, writeJson } = require('../src/io');
const { parseReplayFile } = require('../src/rofl');
const { DAMAGE_PROFILE } = require('../src/decoders/rofl_16_15_801_3452');

function parseArgs(argv) {
  const options = {
    replay: null,
    details: null,
    output: null,
    artifacts: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--replay') options.replay = path.resolve(argv[++index]);
    else if (value === '--details') options.details = path.resolve(argv[++index]);
    else if (value === '--output') options.output = path.resolve(argv[++index]);
    else if (value === '--artifact') options.artifacts.push(path.resolve(argv[++index]));
    else throw new Error(`unknown argument: ${value}`);
  }
  if (!options.replay) throw new Error('--replay is required');
  if (!options.details) throw new Error('--details is required');
  if (!options.output) throw new Error('--output is required');
  if (options.artifacts.length === 0) throw new Error('at least one --artifact is required');
  return options;
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const repositoryRoot = path.resolve(__dirname, '..');
  const replay = parseReplayFile(options.replay);
  if (replay.header.version !== DAMAGE_PROFILE.replay_version) {
    throw new Error(`holdout Replay has unsupported version ${replay.header.version}`);
  }
  const sourceFiles = [
    path.join(repositoryRoot, 'src', 'decoders', 'rofl_16_15_801_3452.js'),
    path.join(repositoryRoot, 'scripts', 'emulate_exact_packet_decoder.py'),
    path.join(repositoryRoot, 'scripts', 'emulate_selected_packet_decoder.py'),
    path.join(repositoryRoot, 'scripts', 'build_damage_events.js'),
    path.join(repositoryRoot, 'scripts', 'validate_damage_events.js'),
    path.join(repositoryRoot, 'scripts', 'validate_runtime_decoder.py'),
  ];
  const manifest = {
    schema_version: 1,
    freeze_status: 'FROZEN_BEFORE_SEMANTIC_HOLDOUT_ORACLE',
    generated_at: new Date().toISOString(),
    holdout_replay: {
      path: replay.source_path,
      sha256: replay.source_sha256,
      version: replay.header.version,
    },
    holdout_details: {
      path: options.details,
      file_hash_only_at_freeze: true,
      hash: (await hashFiles([options.details]))[options.details],
    },
    prefreeze_oracle_access_disclosure: {
      semantic_fields_read: false,
      structural_metadata_read: true,
      observed_only: [
        'match_id=HN1_11177593199',
        'frames.length=27',
        'participants.length=10',
      ],
      not_observed: [
        'participant champions or teams',
        'death timestamps or victims',
        'victimDamageReceived source or amount fields',
        'spell or position fields',
      ],
      impact: 'No observed structural value can alter packet decoding, entity mapping, or amount recovery rules.',
    },
    frozen_damage_rules: {
      decoder_profile: DAMAGE_PROFILE,
      champion_network_id_range: '0x400000ae..0x400000b7',
      participant_mapping: 'participant_id = low_byte(network_id) - 0xad',
      research_event_scope: 'source and target both mapped champions; amount > 0',
      amount_transform: 'none; preserve direct client float',
      details_input_to_decoder: false,
    },
    source_hashes: await hashFiles(sourceFiles),
    frozen_artifact_hashes: await hashFiles(options.artifacts),
  };
  writeJson(options.output, manifest);
  process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { main, parseArgs };
