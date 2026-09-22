#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const { writeCsv, writeJson } = require('../src/io');

function parseArgs(argv) {
  const options = { events: null, anchors: null, outputDir: null };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--events') options.events = path.resolve(argv[++index]);
    else if (value === '--anchors') options.anchors = path.resolve(argv[++index]);
    else if (value === '--output-dir') options.outputDir = path.resolve(argv[++index]);
    else throw new Error(`unknown argument: ${value}`);
  }
  if (!options.events) throw new Error('--events is required');
  if (!options.anchors) throw new Error('--anchors is required');
  if (!options.outputDir) throw new Error('--output-dir is required');
  return options;
}

async function loadEvents(filePath) {
  const byReplay = new Map();
  const lines = readline.createInterface({
    input: fs.createReadStream(filePath),
    crlfDelay: Infinity,
  });
  for await (const line of lines) {
    if (!line.trim()) continue;
    const event = JSON.parse(line);
    const replaySha256 = event.raw_packet_ref?.replay_sha256;
    if (!replaySha256) throw new Error('death event has no Replay SHA-256 provenance');
    const events = byReplay.get(replaySha256) || [];
    events.push(event);
    byReplay.set(replaySha256, events);
  }
  for (const events of byReplay.values()) {
    events.sort((left, right) => left.replay_time_ms - right.replay_time_ms);
  }
  return byReplay;
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const anchorBundle = JSON.parse(fs.readFileSync(options.anchors, 'utf8'));
  const eventsByReplay = await loadEvents(options.events);
  const rows = [];
  const perReplay = [];
  let falsePositives = 0;
  let falseNegatives = 0;

  for (const replay of anchorBundle.replays) {
    const events = eventsByReplay.get(replay.replay_sha256) || [];
    const anchors = [...(replay.deaths || [])].sort((left, right) => left.timestamp_ms - right.timestamp_ms);
    falsePositives += Math.max(0, events.length - anchors.length);
    falseNegatives += Math.max(0, anchors.length - events.length);
    const compared = Math.min(events.length, anchors.length);
    let matched = 0;
    for (let index = 0; index < compared; index += 1) {
      const event = events[index];
      const anchor = anchors[index];
      const deltaMs = event.replay_time_ms - anchor.timestamp_ms;
      const participantMatch = event.victim_participant_id === anchor.victim_participant_id;
      const timeMatch = deltaMs >= 0 && deltaMs <= 1;
      const verdict = participantMatch && timeMatch ? 'MATCH' : 'MISMATCH';
      matched += Number(verdict === 'MATCH');
      rows.push({
        validation_id: `${replay.game_id}:death:${index + 1}`,
        game_id: replay.game_id,
        replay_sha256: replay.replay_sha256,
        replay_event_index: index,
        anchor_id: anchor.anchor_id,
        replay_time_ms: event.replay_time_ms,
        anchor_time_ms: anchor.timestamp_ms,
        delta_ms: deltaMs,
        replay_victim_participant_id: event.victim_participant_id,
        anchor_victim_participant_id: anchor.victim_participant_id,
        victim_champion: event.victim_champion,
        victim_network_id: event.victim_network_id,
        participant_match: participantMatch,
        time_match_1ms: timeMatch,
        verdict,
        raw_packet_ref: event.raw_packet_ref,
      });
    }
    perReplay.push({
      game_id: replay.game_id,
      replay_sha256: replay.replay_sha256,
      replay_event_count: events.length,
      anchor_count: anchors.length,
      matched_count: matched,
      false_positive_count: Math.max(0, events.length - anchors.length),
      false_negative_count: Math.max(0, anchors.length - events.length),
      status: matched === anchors.length && events.length === anchors.length ? 'PASS' : 'FAIL',
    });
  }

  const matchedCount = rows.filter((row) => row.verdict === 'MATCH').length;
  const status = falsePositives === 0
    && falseNegatives === 0
    && matchedCount === anchorBundle.death_count ? 'PASS' : 'FAIL';
  const summary = {
    schema_version: 1,
    status,
    confidence: status === 'PASS' ? 'VERIFIED_DIRECT' : 'UNVERIFIED',
    replay_count: anchorBundle.replay_count,
    replay_event_count: rows.length + falsePositives,
    anchor_count: anchorBundle.death_count,
    matched_count: matchedCount,
    false_positive_count: falsePositives,
    false_negative_count: falseNegatives,
    minimum_delta_ms: rows.length ? Math.min(...rows.map((row) => row.delta_ms)) : null,
    maximum_delta_ms: rows.length ? Math.max(...rows.map((row) => row.delta_ms)) : null,
    per_replay: perReplay,
  };
  fs.mkdirSync(options.outputDir, { recursive: true });
  writeJson(path.join(options.outputDir, 'death_validation_summary.json'), summary);
  writeCsv(path.join(options.outputDir, 'death_validation_all.csv'), rows, [
    'validation_id',
    'game_id',
    'replay_sha256',
    'replay_event_index',
    'anchor_id',
    'replay_time_ms',
    'anchor_time_ms',
    'delta_ms',
    'replay_victim_participant_id',
    'anchor_victim_participant_id',
    'victim_champion',
    'victim_network_id',
    'participant_match',
    'time_match_1ms',
    'verdict',
    'raw_packet_ref',
  ]);
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  if (status !== 'PASS') process.exitCode = 1;
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { loadEvents, main, parseArgs };
