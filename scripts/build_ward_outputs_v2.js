'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { parseReplayFile } = require('../src/rofl');
const {
  buildWardOutputs,
  writeWardOutputs,
} = require('../src/ward_pipeline_v2');

function readJsonl(filePath) {
  return fs.readFileSync(filePath, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function main(argv = process.argv.slice(2)) {
  const replayPath = argv[0];
  const outputDir = argv[1] || path.join(process.cwd(), 'ward-v2-output');
  const spellEventsPath = argv[2] || null;
  const wardSpawnEventsPath = argv[3] || null;
  const wardLifecyclesPath = argv[4] || null;
  if (!replayPath) {
    throw new Error(
      'usage: node scripts/build_ward_outputs_v2.js <replay.rofl> [output-dir] [spell-events.jsonl] [ward-spawn-events.jsonl] [ward-lifecycles.jsonl]',
    );
  }
  if (!fs.existsSync(replayPath)) throw new Error(`replay does not exist: ${replayPath}`);
  if (spellEventsPath && !fs.existsSync(spellEventsPath)) {
    throw new Error(`spell events file does not exist: ${spellEventsPath}`);
  }
  if (wardSpawnEventsPath && !fs.existsSync(wardSpawnEventsPath)) {
    throw new Error(`ward spawn events file does not exist: ${wardSpawnEventsPath}`);
  }
  if (wardLifecyclesPath && !fs.existsSync(wardLifecyclesPath)) {
    throw new Error(`ward lifecycle file does not exist: ${wardLifecyclesPath}`);
  }
  const replay = parseReplayFile(path.resolve(replayPath));
  const options = {
    ...(spellEventsPath ? { spell_events: readJsonl(spellEventsPath) } : {}),
    ...(wardSpawnEventsPath ? {
      ward_spawn_events: readJsonl(wardSpawnEventsPath),
      ward_spawn_input_sha256: sha256File(wardSpawnEventsPath),
    } : {}),
    ...(wardLifecyclesPath ? {
      ward_lifecycles: readJsonl(wardLifecyclesPath),
      ward_lifecycle_input_sha256: sha256File(wardLifecyclesPath),
    } : {}),
  };
  const outputs = buildWardOutputs(replay, options);
  const paths = writeWardOutputs(outputDir, outputs);
  process.stdout.write(`${JSON.stringify({
    schema_version: outputs.schema_version,
    status: outputs.status,
    candidate_count: outputs.ward_cast_candidates.length,
    event_count: outputs.ward_events.length,
    lifecycle_count: outputs.ward_lifecycles.length,
    spawn_match_count: outputs.ward_cast_spawn_matches.length,
    heatmap_input_count: outputs.ward_heatmap_input.length,
    ...paths,
    semantic_input: spellEventsPath ? path.resolve(spellEventsPath) : null,
    ward_spawn_input: wardSpawnEventsPath ? path.resolve(wardSpawnEventsPath) : null,
    ward_lifecycle_input: wardLifecyclesPath ? path.resolve(wardLifecyclesPath) : null,
  }, null, 2)}\n`);
  return outputs;
}

if (require.main === module) main();

module.exports = { main };
