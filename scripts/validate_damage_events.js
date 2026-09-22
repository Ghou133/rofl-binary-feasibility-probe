#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const { writeCsv, writeJson } = require('../src/io');

const WINDOWS_SECONDS = Object.freeze([2, 5, 10, 15, 20, 30]);
const PRIMARY_WINDOW_SECONDS = 15;

function parseArgs(argv) {
  const options = {
    events: null,
    eventManifest: null,
    anchors: null,
    decodeSummary: null,
    runtimeValidation: null,
    outputDir: null,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--events') options.events = path.resolve(argv[++index]);
    else if (value === '--event-manifest') options.eventManifest = path.resolve(argv[++index]);
    else if (value === '--anchors') options.anchors = path.resolve(argv[++index]);
    else if (value === '--decode-summary') options.decodeSummary = path.resolve(argv[++index]);
    else if (value === '--runtime-validation') options.runtimeValidation = path.resolve(argv[++index]);
    else if (value === '--output-dir') options.outputDir = path.resolve(argv[++index]);
    else throw new Error(`unknown argument: ${value}`);
  }
  for (const [name, value] of Object.entries(options)) {
    if (!value) throw new Error(`--${name.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)} is required`);
  }
  return options;
}

async function loadEvents(filePath) {
  const byReplaySha256 = new Map();
  const lines = readline.createInterface({
    input: fs.createReadStream(filePath),
    crlfDelay: Infinity,
  });
  for await (const line of lines) {
    if (!line.trim()) continue;
    const event = JSON.parse(line);
    const replaySha256 = event.raw_packet_ref?.replay_sha256;
    if (!replaySha256) throw new Error('damage event has no Replay SHA-256 provenance');
    const events = byReplaySha256.get(replaySha256) || [];
    events.push(event);
    byReplaySha256.set(replaySha256, events);
  }
  for (const events of byReplaySha256.values()) {
    events.sort((left, right) => left.replay_time_ms - right.replay_time_ms);
  }
  return byReplaySha256;
}

function oracleDamageBySource(death) {
  const result = new Map();
  for (const row of death.damage_received || []) {
    const source = row.source_participant_id;
    const amount = row.total_damage;
    if (!Number.isInteger(source) || source < 1 || source > 10 || !(amount > 0)) continue;
    result.set(source, (result.get(source) || 0) + amount);
  }
  return result;
}

function pearson(left, right) {
  if (left.length !== right.length || left.length < 2) return null;
  const leftMean = left.reduce((sum, value) => sum + value, 0) / left.length;
  const rightMean = right.reduce((sum, value) => sum + value, 0) / right.length;
  let numerator = 0;
  let leftSquares = 0;
  let rightSquares = 0;
  for (let index = 0; index < left.length; index += 1) {
    const leftDelta = left[index] - leftMean;
    const rightDelta = right[index] - rightMean;
    numerator += leftDelta * rightDelta;
    leftSquares += leftDelta * leftDelta;
    rightSquares += rightDelta * rightDelta;
  }
  const denominator = Math.sqrt(leftSquares * rightSquares);
  return denominator === 0 ? null : numerator / denominator;
}

function emptyMetrics() {
  return {
    oracle_source_rows: 0,
    oracle_total: 0,
    replay_floor_total: 0,
    exact_amount_rows: 0,
    within_1_rows: 0,
    within_2_rows: 0,
    within_5_percent_rows: 0,
    within_10_percent_rows: 0,
    source_true_positive: 0,
    source_false_positive: 0,
    source_false_negative: 0,
    oracle_values: [],
    replay_values: [],
  };
}

function finalizeMetrics(metrics) {
  const sourcePrecisionDenominator = metrics.source_true_positive + metrics.source_false_positive;
  const sourceRecallDenominator = metrics.source_true_positive + metrics.source_false_negative;
  const result = {
    ...metrics,
    replay_to_oracle_total_ratio: metrics.oracle_total === 0
      ? null
      : metrics.replay_floor_total / metrics.oracle_total,
    amount_pearson: pearson(metrics.oracle_values, metrics.replay_values),
    source_precision: sourcePrecisionDenominator === 0
      ? null
      : metrics.source_true_positive / sourcePrecisionDenominator,
    source_recall: sourceRecallDenominator === 0
      ? null
      : metrics.source_true_positive / sourceRecallDenominator,
  };
  delete result.oracle_values;
  delete result.replay_values;
  return result;
}

function updateMetricCounts(metrics, oracleSources, replayBySource) {
  const replaySources = new Set(replayBySource.keys());
  for (const source of replaySources) {
    if (oracleSources.has(source)) metrics.source_true_positive += 1;
    else metrics.source_false_positive += 1;
  }
  for (const source of oracleSources.keys()) {
    if (!replaySources.has(source)) metrics.source_false_negative += 1;
  }
}

function validationRow(gameId, death, sourceParticipantId, oracleAmount, events, seconds) {
  const selected = events.filter((event) => event.target_participant_id === death.victim_participant_id
    && event.source_participant_id === sourceParticipantId
    && event.replay_time_ms >= death.timestamp_ms - seconds * 1000
    && event.replay_time_ms <= death.timestamp_ms + 1);
  const replayAmount = selected.reduce((sum, event) => sum + event.amount, 0);
  const replayFloorAmount = selected.reduce((sum, event) => sum + Math.floor(event.amount), 0);
  const absoluteDelta = Math.abs(replayFloorAmount - oracleAmount);
  return {
    validation_id: `${gameId}:${death.anchor_id}:source:${sourceParticipantId}:window:${seconds}s`,
    game_id: gameId,
    anchor_id: death.anchor_id,
    death_time_ms: death.timestamp_ms,
    victim_participant_id: death.victim_participant_id,
    victim_champion: death.victim_champion,
    source_participant_id: sourceParticipantId,
    window_seconds: seconds,
    hit_count: selected.length,
    first_hit_time_ms: selected[0]?.replay_time_ms ?? null,
    last_hit_time_ms: selected.at(-1)?.replay_time_ms ?? null,
    oracle_amount: oracleAmount,
    replay_amount: replayAmount,
    replay_floor_per_hit_amount: replayFloorAmount,
    absolute_delta: absoluteDelta,
    relative_delta: oracleAmount === 0 ? null : absoluteDelta / oracleAmount,
    exact_amount_match: absoluteDelta === 0,
    within_1: absoluteDelta <= 1,
    within_2: absoluteDelta <= 2,
    within_5_percent: absoluteDelta <= Math.max(2, oracleAmount * 0.05),
    within_10_percent: absoluteDelta <= Math.max(5, oracleAmount * 0.10),
    amount_comparison_note: 'Details integer totals are compared with the sum of floor(Replay hit amount).',
  };
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const eventManifest = JSON.parse(fs.readFileSync(options.eventManifest, 'utf8'));
  const anchors = JSON.parse(fs.readFileSync(options.anchors, 'utf8'));
  const decodeSummary = JSON.parse(fs.readFileSync(options.decodeSummary, 'utf8'));
  const runtimeValidation = JSON.parse(fs.readFileSync(options.runtimeValidation, 'utf8'));
  const eventsByReplay = await loadEvents(options.events);
  const validationRows = [];
  const metricsByWindow = new Map(WINDOWS_SECONDS.map((seconds) => [seconds, emptyMetrics()]));
  const perReplayPrimary = {};
  const sourceParticipants = new Set();
  const targetParticipants = new Set();

  for (const replay of anchors.replays) {
    const events = eventsByReplay.get(replay.replay_sha256) || [];
    for (const event of events) {
      sourceParticipants.add(`${replay.game_id}:${event.source_participant_id}`);
      targetParticipants.add(`${replay.game_id}:${event.target_participant_id}`);
    }
    const primaryMetrics = emptyMetrics();
    for (const death of replay.deaths || []) {
      const oracleSources = oracleDamageBySource(death);
      for (const seconds of WINDOWS_SECONDS) {
        const windowMetrics = metricsByWindow.get(seconds);
        const replayBySource = new Map();
        for (const event of events) {
          if (event.target_participant_id !== death.victim_participant_id
              || event.replay_time_ms < death.timestamp_ms - seconds * 1000
              || event.replay_time_ms > death.timestamp_ms + 1) continue;
          replayBySource.set(event.source_participant_id,
            (replayBySource.get(event.source_participant_id) || 0) + Math.floor(event.amount));
        }
        updateMetricCounts(windowMetrics, oracleSources, replayBySource);
        if (seconds === PRIMARY_WINDOW_SECONDS) {
          updateMetricCounts(primaryMetrics, oracleSources, replayBySource);
        }
        for (const [sourceParticipantId, oracleAmount] of oracleSources) {
          const row = validationRow(
            replay.game_id,
            death,
            sourceParticipantId,
            oracleAmount,
            events,
            seconds,
          );
          validationRows.push(row);
          for (const metrics of [windowMetrics, ...(seconds === PRIMARY_WINDOW_SECONDS ? [primaryMetrics] : [])]) {
            metrics.oracle_source_rows += 1;
            metrics.oracle_total += oracleAmount;
            metrics.replay_floor_total += row.replay_floor_per_hit_amount;
            metrics.exact_amount_rows += Number(row.exact_amount_match);
            metrics.within_1_rows += Number(row.within_1);
            metrics.within_2_rows += Number(row.within_2);
            metrics.within_5_percent_rows += Number(row.within_5_percent);
            metrics.within_10_percent_rows += Number(row.within_10_percent);
            metrics.oracle_values.push(oracleAmount);
            metrics.replay_values.push(row.replay_floor_per_hit_amount);
          }
        }
      }
    }
    perReplayPrimary[replay.game_id] = finalizeMetrics(primaryMetrics);
  }

  const windowMetrics = Object.fromEntries(
    [...metricsByWindow].map(([seconds, metrics]) => [seconds, finalizeMetrics(metrics)]),
  );
  const primary = windowMetrics[PRIMARY_WINDOW_SECONDS];
  const structuralPass = eventManifest.status === 'PASS'
    && decodeSummary.event_count === decodeSummary.successful_full_consume_count
    && decodeSummary.event_count === eventManifest.counts.semantic_rows
    && runtimeValidation.status === 'PASS'
    && runtimeValidation.image_sha256 === decodeSummary.image_sha256
    && runtimeValidation.all_fields_match_count === runtimeValidation.compared_count;
  const mappingPass = eventManifest.counts.hero_pair_positive_rows >= 1000
    && eventManifest.counts.allied_or_self_hero_pair_positive_rows === 0
    && sourceParticipants.size >= anchors.replay_count * 10
    && targetParticipants.size >= anchors.replay_count * 10;
  const oraclePass = primary.amount_pearson >= 0.95
    && primary.source_precision >= 0.98
    && primary.source_recall >= 0.85
    && primary.replay_to_oracle_total_ratio >= 0.90
    && primary.replay_to_oracle_total_ratio <= 1.05;
  const status = structuralPass && mappingPass && oraclePass ? 'PASS' : 'FAIL';
  const summary = {
    schema_version: 1,
    status,
    capability: 'UnitApplyDamage timestamp + source + target + amount',
    confidence: status === 'PASS' ? 'VERIFIED_DIRECT' : 'UNVERIFIED',
    decoder_is_oracle_independent: eventManifest.details_or_oracle_input === false,
    replay_count: anchors.replay_count,
    patch: anchors.target_replay_version,
    decoded_packet_count: decodeSummary.event_count,
    fully_consumed_packet_count: decodeSummary.successful_full_consume_count,
    semantic_damage_event_count: eventManifest.counts.semantic_rows,
    positive_hero_vs_hero_event_count: eventManifest.counts.hero_pair_positive_rows,
    enemy_hero_vs_hero_event_count: eventManifest.counts.enemy_hero_pair_positive_rows,
    allied_or_self_hero_vs_hero_event_count: eventManifest.counts.allied_or_self_hero_pair_positive_rows,
    runtime_validation: {
      status: runtimeValidation.status,
      compared_count: runtimeValidation.compared_count,
      all_fields_match_count: runtimeValidation.all_fields_match_count,
      timestamp_match_count: runtimeValidation.timestamp_match_count,
      maximum_timestamp_delta_ms: runtimeValidation.max_timestamp_delta_ms,
    },
    entity_mapping: {
      status: mappingPass ? 'PASS' : 'FAIL',
      unique_replay_participant_sources: sourceParticipants.size,
      unique_replay_participant_targets: targetParticipants.size,
      rule: 'participant_id = low_byte(network_id) - 0xad for exact range 0x400000ae..0x400000b7',
      non_champion_ids_promoted_to_champion: 0,
    },
    oracle_validation: {
      oracle_role: 'VALIDATION_ONLY',
      primary_window_seconds: PRIMARY_WINDOW_SECONDS,
      primary_metrics: primary,
      window_sensitivity: windowMetrics,
      per_replay_primary_metrics: perReplayPrimary,
    },
    gates: {
      structural_pass: structuralPass,
      entity_mapping_pass: mappingPass,
      development_oracle_pass: oraclePass,
    },
  };

  fs.mkdirSync(options.outputDir, { recursive: true });
  writeJson(path.join(options.outputDir, 'damage_validation_summary.json'), summary);
  writeCsv(path.join(options.outputDir, 'damage_validation_all.csv'), validationRows, [
    'validation_id',
    'game_id',
    'anchor_id',
    'death_time_ms',
    'victim_participant_id',
    'victim_champion',
    'source_participant_id',
    'window_seconds',
    'hit_count',
    'first_hit_time_ms',
    'last_hit_time_ms',
    'oracle_amount',
    'replay_amount',
    'replay_floor_per_hit_amount',
    'absolute_delta',
    'relative_delta',
    'exact_amount_match',
    'within_1',
    'within_2',
    'within_5_percent',
    'within_10_percent',
    'amount_comparison_note',
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

module.exports = {
  WINDOWS_SECONDS,
  PRIMARY_WINDOW_SECONDS,
  finalizeMetrics,
  main,
  oracleDamageBySource,
  parseArgs,
  pearson,
  validationRow,
};
