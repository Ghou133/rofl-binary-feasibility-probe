'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const { decodeHeroLevelCandidates821 } =
  require('../src/decoders/rofl_16_19_821_level_candidate');
const { decodeHeroFloatSnapshotCandidates821 } =
  require('../src/decoders/rofl_16_19_821_float_stats_candidate');
const { associateLevelExperienceKeyframeBracketCandidates821 } =
  require('../src/decoders/rofl_16_19_821_level_experience_keyframe_bracket_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const BUILD = '16.19.821.7343';
const EVENT = 'level_experience_keyframe_bracket_candidates';
const CAPABILITY = 'level_experience_keyframe_bracket';
const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));

function levelPacket(timeMs, participant, payload) {
  const body = Buffer.from(payload);
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timeMs / 1000, 1);
  header[5] = body.length;
  header.writeUInt16LE(0x0197, 6);
  header.writeUInt32LE(0x400000ad + participant, 8);
  return Buffer.concat([header, body]);
}

function experiencePacket(timeMs, participant, value) {
  const payload = Buffer.alloc(1263, 0x97);
  payload.set([0x67, 0x00, 0xde]);
  const bytes = Buffer.alloc(4);
  bytes.writeFloatLE(value);
  for (let index = 0; index < 4; index += 1) {
    payload[1262 - 0x28 - index] = ENCODE.get(bytes[index]);
  }
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0089, 9);
  header.writeUInt32LE(0x400000ad + participant, 11);
  return Buffer.concat([header, payload]);
}

function makeReplay({ boundary = false } = {}) {
  const levels = Array.from({ length: 10 }, (_, index) =>
    levelPacket(boundary ? 60_000 : 30_000, index + 1, [0xe5]));
  if (!boundary) levels.push(levelPacket(35_000, 1, [0xe2, 0x75]));
  const replay = replayFromChunks([
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      experiencePacket(0, index + 1, 0))) },
    { stream: 1, body: Buffer.concat(levels) },
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      experiencePacket(60_000, index + 1, index === 0 ? 100.5 : 0))) },
  ], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    LEVEL: String(index === 0 && !boundary ? 3 : 2),
    EXP: String(index === 0 ? 101 : 0),
  }));
  return replay;
}

function writeArtifact(t, { boundary = false } = {}) {
  const replay = makeReplay({ boundary });
  const level = decodeHeroLevelCandidates821(replay);
  const experience = decodeHeroFloatSnapshotCandidates821(replay,
    'hero_experience_snapshot');
  assert.equal(level.status, 'CANDIDATE', level.error);
  assert.equal(experience.status, 'CANDIDATE', experience.error);
  const bracket = associateLevelExperienceKeyframeBracketCandidates821(replay, {
    levelOutcome: level, experienceSnapshotOutcome: experience,
  });
  assert.equal(bracket.status, 'CANDIDATE', bracket.error);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-level-exp-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directory = path.join(root, 'replays', 'synthetic');
  fs.mkdirSync(directory, { recursive: true });
  const { events: levelEvents, ...levelSummary } = level;
  const { events: experienceEvents, ...experienceSummary } = experience;
  const { events: bracketEvents, ...bracketSummary } = bracket;
  const semantic = {
    replay_version: BUILD, replay_sha256: replay.source_sha256,
    container_status: 'PASS', status: 'CANDIDATE', api_status: 'CANDIDATE',
    requested_capabilities: ['hero_level_state', 'hero_experience_snapshot'],
    capability_results: {
      hero_level_state: levelSummary,
      hero_experience_snapshot: experienceSummary,
    },
    candidate_associations: { [CAPABILITY]: bracketSummary },
  };
  const eventRows = {
    hero_level_state_candidates: levelEvents,
    hero_experience_snapshot_candidates: experienceEvents,
    [EVENT]: bracketEvents,
  };
  const analysis = {
    patch: '16.19', replay_version: BUILD,
    replay_sha256: replay.source_sha256, source_path: replay.source_path ?? null,
    event_storage: 'JSONL_ONLY', events: null,
    event_counts: Object.fromEntries(Object.entries(eventRows)
      .map(([key, rows]) => [key, rows.length])),
    event_jsonl_files: Object.fromEntries(Object.keys(eventRows)
      .map((key) => [key, `${key}.jsonl`])),
    semantic,
  };
  fs.writeFileSync(path.join(directory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(directory, 'replay_analysis.json'), JSON.stringify(analysis));
  for (const [key, rows] of Object.entries(eventRows)) {
    fs.writeFileSync(path.join(directory, `${key}.jsonl`),
      rows.map((row) => JSON.stringify(row)).join('\n') + (rows.length ? '\n' : ''));
  }
  return { root, directory, eventRows };
}

function query(directory, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', EVENT, ...args],
    { encoding: 'utf8' });
}

function editJson(filename, edit) {
  const document = JSON.parse(fs.readFileSync(filename, 'utf8'));
  edit(document);
  fs.writeFileSync(filename, JSON.stringify(document));
}

function editJsonl(filename, edit) {
  const rows = fs.readFileSync(filename, 'utf8').trimEnd().split('\n').map(JSON.parse);
  edit(rows);
  fs.writeFileSync(filename, `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`);
}

test('query-events filters sampled level/EXP brackets and preserves original JSONL', (t) => {
  const { directory, eventRows } = writeArtifact(t);
  assert.equal(eventRows[EVENT].length, 11);
  const selected = query(directory, '--level-after', '3');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(eventRows[EVENT][10])}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 11);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.level_after_checked_count, 11);
  assert.equal(summary.level_after_unavailable_count, 0);
  assert.equal(summary.filters.level_after, 3);
  assert.equal(summary.rows_unmodified, true);

  const absent = query(directory, '--level-after', '20');
  assert.equal(absent.status, 0, absent.stderr);
  assert.equal(absent.stdout, '');
  assert.equal(JSON.parse(absent.stderr).matched_count, 0);
  assert.equal(JSON.parse(absent.stderr).level_after_checked_count, 11);
});

test('query-events reports a valid empty bracket as checked zero, not unavailable', (t) => {
  const { directory } = writeArtifact(t, { boundary: true });
  const result = query(directory, '--level-after', '2');
  assert.equal(result.status, 0, result.stderr);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, 0);
  assert.equal(summary.matched_count, 0);
  assert.equal(summary.level_after_checked_count, 0);
  assert.equal(summary.level_after_unavailable_count, 0);
});

test('query-events validates later bracket rows and source refs after limit', (t) => {
  for (const change of [
    (row) => { row.level_after_candidate = 20; },
    (row) => { row.previous_experience_raw_packet_ref.packet_id = 0; },
    (row) => { row.experience_endpoint_delta_f32_candidate = 999; },
    (row) => { row.previous_experience_raw_payload_field_bytes_hex = 'ffffffff'; },
    (row) => { row.raw_packet_refs.reverse(); },
  ]) {
    const { root, directory } = writeArtifact(t);
    const output = path.join(root, 'selected.jsonl');
    editJsonl(path.join(directory, `${EVENT}.jsonl`), (rows) => change(rows[10]));
    const result = query(directory, '--level-after', '2', '--limit', '1',
      '--output', output);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
  for (const [source, change] of [
    ['hero_level_state_candidates',
      (rows) => { rows[0].raw_packet_ref.raw_payload_hex = '00'; }],
    ['hero_experience_snapshot_candidates',
      (rows) => { rows[10].raw_payload_field_bytes_hex = '00000000'; }],
  ]) {
    const { directory } = writeArtifact(t);
    editJsonl(path.join(directory, `${source}.jsonl`), change);
    const result = query(directory, '--level-after', '2', '--limit', '1');
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
  }
});

test('query-events rejects changed bracket profile, foreign build/event and bounds', (t) => {
  const { directory } = writeArtifact(t);
  for (const value of ['0', '21', '-1', '1.5', '1e2', '+1']) {
    const result = query(directory, '--level-after', value);
    assert.equal(result.status, 1, `${value}: ${result.stderr}`);
  }
  const foreignEvent = spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event',
      'hero_level_state_candidates', '--level-after', '2'],
    { encoding: 'utf8' });
  assert.equal(foreignEvent.status, 1);
  assert.match(foreignEvent.stderr, /--level-after requires/);

  const bracketMeta = path.join(directory, 'semantic_run.json');
  editJson(bracketMeta, (semantic) => {
    semantic.candidate_associations[CAPABILITY].profile_id = 'foreign';
  });
  const wrongProfile = query(directory, '--level-after', '2');
  assert.equal(wrongProfile.status, 2, wrongProfile.stderr);
  assert.equal(JSON.parse(wrongProfile.stderr).code, 'ASSOCIATION_METADATA_MISMATCH');

  const foreign = writeArtifact(t);
  for (const file of ['semantic_run.json', 'replay_analysis.json']) {
    editJson(path.join(foreign.directory, file), (document) => {
      document.replay_version = '16.19.820.7193';
    });
  }
  const wrongBuild = query(foreign.directory, '--level-after', '2');
  assert.equal(wrongBuild.status, 2, wrongBuild.stderr);
  assert.equal(JSON.parse(wrongBuild.stderr).code, 'UNSUPPORTED_EVENT_BUILD');
});

test('query-events keeps missing level/EXP association unavailable', (t) => {
  const { directory } = writeArtifact(t);
  editJson(path.join(directory, 'semantic_run.json'), (semantic) => {
    semantic.candidate_associations[CAPABILITY] = {
      status: 'PROFILE_UNAVAILABLE', event_count: null,
    };
  });
  const result = query(directory, '--level-after', '2');
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stderr).code, 'ASSOCIATION_UNAVAILABLE');
});
