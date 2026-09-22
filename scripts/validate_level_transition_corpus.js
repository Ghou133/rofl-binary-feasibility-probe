#!/usr/bin/env node

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { parseReplayFile } = require('../src/rofl');
const {
  DEFAULT_DECODER_IMAGE,
  runLevelTransitionDecoder,
} = require('../src/semantic_pipeline');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_FIXTURE = path.join(ROOT, 'test', 'fixtures', 'level-transition-evidence-v1.json');
const DEFAULT_OUTPUT = path.join(
  ROOT,
  'artifacts',
  'rofl_upstream_capability_sync_v1',
  'level_transition_corpus_validation.json',
);

function parseArgs(argv) {
  const options = {
    fixture: DEFAULT_FIXTURE,
    decoderImage: DEFAULT_DECODER_IMAGE,
    output: DEFAULT_OUTPUT,
    python: process.env.ROFL_ANALYZER_PYTHON || 'python',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    const value = argv[index + 1];
    if (token === '--fixture') options.fixture = value;
    else if (token === '--source-root') options.sourceRoot = value;
    else if (token === '--config') options.config = value;
    else if (token === '--decoder-image') options.decoderImage = value;
    else if (token === '--output') options.output = value;
    else if (token === '--python') options.python = value;
    else if (token === '--help') options.help = true;
    else throw new Error(`unknown argument: ${token}`);
    if (token !== '--help') index += 1;
  }
  return options;
}

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function detailsLevelAnchors(filePath, maxTimeMs) {
  const envelope = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const frames = envelope?.json?.frames;
  if (!Array.isArray(frames)) throw new Error(`${filePath} has no json.frames`);
  const anchors = [];
  for (const frame of frames) {
    for (const event of frame.events || []) {
      const timestampMs = Number(event.timestamp);
      const participantId = Number(event.participantId);
      const level = Number(event.level);
      if (event.type !== 'LEVEL_UP'
          || !Number.isInteger(participantId)
          || participantId < 1
          || participantId > 10
          || !Number.isInteger(level)
          || level < 2
          || !Number.isInteger(timestampMs)
          || timestampMs < 0
          || timestampMs > maxTimeMs) continue;
      anchors.push({ participant_id: participantId, timestamp_ms: timestampMs, level });
    }
  }
  return anchors;
}

function increment(object, key) {
  object[key] = (object[key] || 0) + 1;
}

function eventIdentity(event) {
  return [
    event.raw_packet_ref.replay_sha256,
    event.raw_packet_ref.occurrence_index,
  ].join(':');
}

function assertExpected(actual, expected) {
  assert.equal(actual.replay_count, expected.replay_count);
  assert.equal(actual.decoded_packet_count, expected.decoded_packet_count);
  assert.equal(actual.deserialize_success_count, expected.deserialize_success_count);
  assert.equal(actual.fully_consumed_count, expected.fully_consumed_count);
  assert.equal(actual.details_level_event_count, expected.details_level_event_count);
  assert.equal(actual.matched_packet_count, expected.matched_packet_count);
  assert.equal(actual.missing_event_count, expected.missing_event_count);
  assert.equal(actual.hero_param_packet_count, expected.hero_param_packet_count);
  assert.equal(
    actual.unmatched_hero_param_packet_count,
    expected.unmatched_hero_param_packet_count,
  );
  assert.equal(
    actual.timestamp_zero_initialization_count,
    expected.timestamp_zero_initialization_count,
  );
  assert.deepEqual(actual.timestamp_delta_ms_counts, expected.timestamp_delta_ms_counts);
  assert.equal(actual.participant_sequence_count, expected.participant_sequence_count);
  assert.equal(
    actual.monotonic_participant_sequence_count,
    expected.monotonic_participant_sequence_count,
  );
  assert.deepEqual(actual.matched_level_counts, expected.matched_level_counts);
  assert.deepEqual(actual.field_10_to_level_after, expected.field_10_to_level_after);
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write([
      'Usage: node scripts/validate_level_transition_corpus.js [options]',
      '  --source-root <lol-inference-lab root>',
      '  --config <behavior_semantic_probe_v1.json>',
      '  --decoder-image <16.15.801.3452 runtime image>',
      '  --output <validation.json>',
      '  --python <python executable>',
      '',
    ].join('\n'));
    return;
  }

  const fixturePath = path.resolve(options.fixture);
  const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  const sourceRoot = path.resolve(options.sourceRoot || path.join(ROOT, fixture.source_repository));
  const configPath = path.resolve(
    options.config || path.join(sourceRoot, 'config', 'behavior_semantic_probe_v1.json'),
  );
  const decoderImage = path.resolve(options.decoderImage);
  const expectedByGame = new Map(fixture.corpus.map((game) => [game.game_id, game]));

  const sourceArtifacts = fixture.source_artifacts.map((artifact) => {
    const artifactPath = path.resolve(sourceRoot, artifact.path);
    const actualSha256 = sha256File(artifactPath);
    assert.equal(actualSha256, artifact.sha256, `source artifact changed: ${artifactPath}`);
    return {
      path: artifactPath,
      expected_sha256: artifact.sha256,
      actual_sha256: actualSha256,
      status: 'PASS',
    };
  });
  const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  assert.equal(config.target_replay_version, fixture.target_replay_version);
  assert.equal(config.games.length, fixture.expected.replay_count);
  assert.equal(sha256File(decoderImage), fixture.runtime_image_sha256);

  const corpus = [];
  const matches = [];
  const missing = [];
  const unmatchedHeroEvents = [];
  const fieldLevels = new Map();
  const sequences = new Map();
  const timestampDeltaCounts = {};
  const matchedLevelCounts = {};
  let decodedPacketCount = 0;
  let deserializeSuccessCount = 0;
  let fullyConsumedCount = 0;
  let heroParamPacketCount = 0;

  for (const game of config.games) {
    const expected = expectedByGame.get(String(game.game_id));
    assert.ok(expected, `game ${game.game_id} is not pinned in ${fixturePath}`);
    const replayPath = path.resolve(game.replay_path);
    const detailsPath = path.resolve(game.details_path);
    const replaySha256 = sha256File(replayPath);
    const detailsSha256 = sha256File(detailsPath);
    assert.equal(replaySha256, expected.replay_sha256, `Replay changed: ${replayPath}`);
    assert.equal(detailsSha256, expected.details_sha256, `DETAILS changed: ${detailsPath}`);

    const replay = parseReplayFile(replayPath);
    assert.equal(replay.header.version, fixture.target_replay_version);
    assert.equal(replay.source_sha256, replaySha256);
    const decoded = runLevelTransitionDecoder(replay, {
      decoderImage,
      python: options.python,
      decoderTimeoutMs: 180000,
      maxTimeMs: config.max_time_ms,
    });
    decodedPacketCount += decoded.summary.event_count;
    deserializeSuccessCount += decoded.summary.deserialize_success_count;
    fullyConsumedCount += decoded.summary.fully_consumed_count;
    heroParamPacketCount += decoded.events.length;

    const anchors = detailsLevelAnchors(detailsPath, config.max_time_ms);
    const used = new Set();
    for (const anchor of anchors) {
      const candidates = decoded.events.filter((event) => (
        event.participant_id === anchor.participant_id
        && Math.abs(event.timestamp_ms - anchor.timestamp_ms) <= 1
      ));
      if (candidates.length !== 1) {
        missing.push({ game_id: String(game.game_id), ...anchor, candidate_count: candidates.length });
        continue;
      }
      const event = candidates[0];
      assert.equal(event.entity_network_id, (0x400000ad + anchor.participant_id) >>> 0);
      assert.equal(event.transition_evidence, 'VERIFIED_DIRECT');
      assert.equal(event.level_mapping_evidence, 'VERIFIED_DERIVED');
      assert.equal(event.level_after, anchor.level);
      used.add(eventIdentity(event));
      const deltaMs = event.timestamp_ms - anchor.timestamp_ms;
      increment(timestampDeltaCounts, deltaMs);
      increment(matchedLevelCounts, anchor.level);
      let levels = fieldLevels.get(event.raw_field_10);
      if (!levels) {
        levels = new Set();
        fieldLevels.set(event.raw_field_10, levels);
      }
      levels.add(anchor.level);
      const sequenceKey = `${game.game_id}:${anchor.participant_id}`;
      let sequence = sequences.get(sequenceKey);
      if (!sequence) {
        sequence = [];
        sequences.set(sequenceKey, sequence);
      }
      sequence.push({ event, anchor });
      matches.push({
        game_id: String(game.game_id),
        participant_id: anchor.participant_id,
        level_after: anchor.level,
        packet_timestamp_ms: event.timestamp_ms,
        details_timestamp_ms: anchor.timestamp_ms,
        delta_ms: deltaMs,
        raw_field_10: event.raw_field_10,
        raw_field_11: event.raw_field_11,
        raw_packet_ref: event.raw_packet_ref,
      });
    }
    unmatchedHeroEvents.push(...decoded.events
      .filter((event) => !used.has(eventIdentity(event)))
      .map((event) => ({
        game_id: String(game.game_id),
        timestamp_ms: event.timestamp_ms,
        participant_id: event.participant_id,
        raw_field_10: event.raw_field_10,
        raw_field_11: event.raw_field_11,
        is_initialization: event.is_initialization,
        raw_packet_ref: event.raw_packet_ref,
      })));
    corpus.push({
      game_id: String(game.game_id),
      replay_path: replayPath,
      replay_sha256: replaySha256,
      details_path: detailsPath,
      details_sha256: detailsSha256,
      replay_version: replay.header.version,
      decoded_packet_count: decoded.summary.event_count,
      hero_transition_packet_count: decoded.events.length,
      details_level_event_count: anchors.length,
    });
    process.stdout.write(`validated ${game.game_id}: ${decoded.summary.event_count} packets, ${anchors.length} anchors\n`);
  }

  let monotonicSequenceCount = 0;
  for (const sequence of sequences.values()) {
    sequence.sort((left, right) => left.event.timestamp_ms - right.event.timestamp_ms);
    const monotonic = sequence.every((item, index) => index === 0
      || (item.anchor.level > sequence[index - 1].anchor.level
        && item.event.timestamp_ms > sequence[index - 1].event.timestamp_ms));
    if (monotonic) monotonicSequenceCount += 1;
  }
  const fieldMapping = Object.fromEntries(
    [...fieldLevels.entries()]
      .sort(([left], [right]) => left - right)
      .map(([field, levels]) => {
        assert.equal(levels.size, 1, `ambiguous field_10 mapping for ${field}`);
        return [field, [...levels][0]];
      }),
  );
  const actual = {
    replay_count: corpus.length,
    decoded_packet_count: decodedPacketCount,
    deserialize_success_count: deserializeSuccessCount,
    fully_consumed_count: fullyConsumedCount,
    details_level_event_count: matches.length + missing.length,
    matched_packet_count: matches.length,
    missing_event_count: missing.length,
    hero_param_packet_count: heroParamPacketCount,
    unmatched_hero_param_packet_count: unmatchedHeroEvents.length,
    timestamp_zero_initialization_count: unmatchedHeroEvents.filter(
      (event) => event.timestamp_ms === 0 && event.is_initialization === true,
    ).length,
    timestamp_delta_ms_counts: timestampDeltaCounts,
    participant_sequence_count: sequences.size,
    monotonic_participant_sequence_count: monotonicSequenceCount,
    matched_level_counts: matchedLevelCounts,
    field_10_to_level_after: fieldMapping,
  };
  assertExpected(actual, fixture.expected);
  assert.ok(unmatchedHeroEvents.every(
    (event) => event.timestamp_ms === 0 && event.is_initialization === true,
  ));

  const output = {
    schema_version: 'ROFL_LEVEL_TRANSITION_CORPUS_VALIDATION_V1',
    status: 'PASS',
    generated_at_utc: new Date().toISOString(),
    validator_path: __filename,
    validator_sha256: sha256File(__filename),
    fixture_path: fixturePath,
    fixture_sha256: sha256File(fixturePath),
    config_path: configPath,
    config_sha256: sha256File(configPath),
    decoder_image_path: decoderImage,
    decoder_image_sha256: sha256File(decoderImage),
    oracle_role: 'MATCH_DETAILS_VALIDATION_ONLY_REPLAY_IS_FACT_SOURCE',
    source_artifacts: sourceArtifacts,
    corpus,
    result: actual,
    unmatched_hero_param_packets: unmatchedHeroEvents,
    matched_anchor_sample: matches.slice(0, 24),
  };
  const outputPath = path.resolve(options.output);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(output, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({ status: output.status, output: outputPath, result: actual }, null, 2)}\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = {
  detailsLevelAnchors,
  main,
  parseArgs,
};
