'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { prepareEventQuery, streamEventQuery } = require('../src/event_query');

const CLI = path.resolve(__dirname, '../src/cli.js');
const BUILD = '16.19.821.7343';
const EVENT = 'hero_death_episode_candidates';
const SELECTED = 'hero_death,hero_assist,hero_death_timer,hero_respawn';
const VICTIM_RAW = 0x400000ae;
const TIMER = Buffer.from('121017d7d7', 'hex');
const RETURN = Buffer.from('64b0f17b7bb06e3b7b1e3aaaf9', 'hex');

function packet(id, rawParam, payload, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function deathCore(timeMs, assisted = false) {
  const heroDie = Buffer.alloc(37, 0x43);
  heroDie.set(Buffer.from('3678', 'hex'), heroDie.length - 2);
  const assist = [];
  if (assisted) {
    const first = Buffer.alloc(44, 0xa5);
    const second = Buffer.from(first);
    first[0] = second[0] = 0xf0;
    Buffer.from('35b94b3d', 'hex').copy(first, 1);
    Buffer.from('350b4bb3', 'hex').copy(second, 1);
    first[43] = 0x14;
    second[43] = 0xd4;
    assist.push(packet(0x040a, 0x400000b0, first, timeMs));
    assist.push(packet(0x040a, 0x400000b0, second, timeMs));
  }
  return [
    packet(0x03d4, 0, Buffer.alloc(3, 0xd4), timeMs),
    packet(0x031b, 0, Buffer.alloc(12, 0x31), timeMs),
    ...assist,
    packet(0x0259, VICTIM_RAW, TIMER, timeMs),
    packet(0x0438, VICTIM_RAW, heroDie, timeMs),
  ];
}

function replayBytes({ includeDeadTime = true, gameLength = 600000 } = {}) {
  const body = Buffer.concat([
    ...deathCore(1000, true),
    packet(0x018d, VICTIM_RAW, Buffer.alloc(55, 0x18), 10000),
    packet(0x0048, VICTIM_RAW, RETURN, 10000),
    ...deathCore(20000),
  ]);
  const replay = replayFromChunks([{ stream: 1, body }], BUILD);
  const stats = Array.from({ length: 10 }, (_, index) => ({
    NUM_DEATHS: index === 0 ? '2' : '0',
    CHAMPIONS_KILLED: index === 5 ? '2' : '0',
    ASSISTS: index === 2 ? '1' : '0',
    ...(includeDeadTime ? { TOTAL_TIME_SPENT_DEAD: index === 0 ? '9' : '0' } : {}),
  }));
  const trailerOffset = replay.buffer.length - 4;
  const metadataOffset = trailerOffset - replay.buffer.readUInt32LE(trailerOffset);
  const metadata = Buffer.from(JSON.stringify({
    gameLength, statsJson: JSON.stringify(stats),
  }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  return Buffer.concat([replay.buffer.subarray(0, metadataOffset), metadata, trailer]);
}

function cli(...args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8', cwd: path.dirname(CLI),
  });
}

function fixture(t, { batch = false, partial = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-episode-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'input');
  const output = path.join(root, 'output');
  fs.mkdirSync(input);
  const first = path.join(input, 'first.rofl');
  fs.writeFileSync(first, replayBytes());
  if (batch) fs.writeFileSync(path.join(input, 'second.rofl'),
    replayBytes({ includeDeadTime: !partial, gameLength: 600001 }));
  const decoded = cli(batch ? 'batch' : 'decode', batch ? input : first,
    '--events', SELECTED, '--event-jsonl-only', '--out-dir', output);
  assert.equal(decoded.status, partial ? 2 : 0,
    `decode exit ${decoded.status}: ${decoded.stderr}\n${decoded.stdout}`);
  const firstDirectory = path.join(output, 'replays', 'first');
  const eventPath = path.join(firstDirectory, `${EVENT}.jsonl`);
  const lines = fs.readFileSync(eventPath, 'utf8').trim().split(/\r?\n/);
  assert.equal(lines.length, 2);
  return { root, input, output, sourcePath: first, firstDirectory, eventPath, lines,
    semanticPath: path.join(firstDirectory, 'semantic_run.json'),
    analysisPath: path.join(firstDirectory, 'replay_analysis.json') };
}

function query(target, ...args) {
  return cli('query-events', target, '--event', EVENT, ...args);
}

function rewriteJson(filename, edit) {
  const value = JSON.parse(fs.readFileSync(filename, 'utf8'));
  edit(value);
  fs.writeFileSync(filename, JSON.stringify(value));
}

test('query-events filters joined 821 episodes and emits original JSONL rows', (t) => {
  const value = fixture(t);
  const first = JSON.parse(value.lines[0]);
  const second = JSON.parse(value.lines[1]);
  assert.equal(first.return_observation_status, 'OBSERVED_RETURN');
  assert.equal(second.return_observation_status, 'UNOBSERVED_BEFORE_REPLAY_END');

  const joined = query(value.firstDirectory,
    '--participant', '1', '--killer-participant', '6',
    '--assisting-participant', '3', '--from-ms', '1000', '--to-ms', '1000',
    '--raw-param', '0x400000b0');
  assert.equal(joined.status, 0, joined.stderr);
  assert.equal(joined.stdout, `${value.lines[0]}\n`);
  const summary = JSON.parse(joined.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.rows_unmodified, true);
  assert.equal(summary.assisting_participant_unavailable_count, 0);

  const terminal = query(value.firstDirectory, '--from-ms', '20000', '--to-ms',
    '20000', '--raw-param', '0x400000ae');
  assert.equal(terminal.status, 0, terminal.stderr);
  assert.equal(terminal.stdout, `${value.lines[1]}\n`);
  assert.equal(JSON.parse(terminal.stderr).matched_count, 1);

  const emptyAssist = query(value.firstDirectory, '--assisting-participant', '4');
  assert.equal(emptyAssist.status, 0, emptyAssist.stderr);
  assert.equal(emptyAssist.stdout, '');
  assert.equal(JSON.parse(emptyAssist.stderr).assisting_participant_unavailable_count, 0);
  assert.equal(fs.readFileSync(value.eventPath, 'utf8'), `${value.lines.join('\n')}\n`);
});

test('query-events rejects missing or corrupted episode association, dependencies, and refs', (t) => {
  const value = fixture(t);
  const originalSemantic = fs.readFileSync(value.semanticPath, 'utf8');
  const originalAnalysis = fs.readFileSync(value.analysisPath, 'utf8');
  const originalRows = fs.readFileSync(value.eventPath, 'utf8');
  const restore = () => {
    fs.writeFileSync(value.semanticPath, originalSemantic);
    fs.writeFileSync(value.analysisPath, originalAnalysis);
    fs.writeFileSync(value.eventPath, originalRows);
  };
  const runBad = (expectedCode) => {
    const destination = path.join(value.root, 'must-not-exist.jsonl');
    const result = query(value.firstDirectory, '--output', destination);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, expectedCode);
    assert.equal(fs.existsSync(destination), false);
    restore();
  };

  for (const filename of [value.semanticPath, value.analysisPath]) {
    rewriteJson(filename, (document) => {
      const association = filename === value.semanticPath
        ? document.candidate_associations.hero_death_episode
        : document.semantic.candidate_associations.hero_death_episode;
      association.profile_id = 'stale-profile';
    });
  }
  runBad('ASSOCIATION_METADATA_MISMATCH');

  for (const filename of [value.semanticPath, value.analysisPath]) {
    rewriteJson(filename, (document) => {
      const association = filename === value.semanticPath
        ? document.candidate_associations.hero_death_episode
        : document.semantic.candidate_associations.hero_death_episode;
      association.observed_return_count = 2;
      association.terminal_unobserved_count = 0;
    });
  }
  runBad('ASSOCIATION_METADATA_MISMATCH');

  for (const filename of [value.semanticPath, value.analysisPath]) {
    rewriteJson(filename, (document) => {
      const association = filename === value.semanticPath
        ? document.candidate_associations.hero_death_episode
        : document.semantic.candidate_associations.hero_death_episode;
      association.verified_raw_packet_count += 1;
    });
  }
  runBad('EVENT_COUNT_MISMATCH');

  for (const filename of [value.semanticPath, value.analysisPath]) {
    rewriteJson(filename, (document) => {
      const result = filename === value.semanticPath
        ? document.capability_results.hero_death_timer
        : document.semantic.capability_results.hero_death_timer;
      result.status = 'MISSING_INPUT';
      result.event_count = null;
    });
  }
  runBad('CAPABILITY_UNAVAILABLE');

  const rows = originalRows.trim().split(/\r?\n/).map(JSON.parse);
  rows[0].death_primary_raw_packet_ref.raw_payload_sha256 = 'f'.repeat(64);
  fs.writeFileSync(value.eventPath, `${rows.map(JSON.stringify).join('\n')}\n`);
  runBad('INVALID_EVENT_ROW');

  const missingReturn = originalRows.trim().split(/\r?\n/).map(JSON.parse);
  delete missingReturn[0].return_raw_packet_ref;
  fs.writeFileSync(value.eventPath, `${missingReturn.map(JSON.stringify).join('\n')}\n`);
  runBad('INVALID_EVENT_ROW');

  const inventedTime = originalRows.trim().split(/\r?\n/).map(JSON.parse);
  inventedTime[0].observed_death_to_return_ms_candidate =
    inventedTime[0].timer_seconds_candidate * 1000;
  fs.writeFileSync(value.eventPath, `${inventedTime.map(JSON.stringify).join('\n')}\n`);
  runBad('INVALID_EVENT_ROW');
});

test('query-events reports a batch with one missing-source episode as PARTIAL', (t) => {
  const value = fixture(t, { batch: true, partial: true });
  const result = query(value.output, '--participant', '1', '--limit', '1');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${value.lines[0]}\n`);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.replay_count, 2);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.replay_results[1].code, 'ASSOCIATION_UNAVAILABLE');
});

test('episode source verification checks all rows and supports a relocated original Replay', (t) => {
  const value = fixture(t);
  const moved = path.join(value.root, 'relocated.rofl');
  fs.renameSync(value.sourcePath, moved);
  const verified = query(value.firstDirectory, '--verify-source',
    '--source-replay', moved, '--participant', '1', '--limit', '1');
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(verified.stdout, `${value.lines[0]}\n`);
  const summary = JSON.parse(verified.stderr);
  assert.equal(summary.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(JSON.parse(verified.stdout).semantic_status,
    'CANDIDATE_821_DEATH_ASSIST_TIMER_RETURN_ASSOCIATION');
});

test('late forged episode timer fails source verification before any callback or CLI output', async (t) => {
  const value = fixture(t);
  const rows = value.lines.map(JSON.parse);
  rows[1].timer_seconds_candidate += 1;
  fs.writeFileSync(value.eventPath, `${rows.map(JSON.stringify).join('\n')}\n`);
  const savedOnly = query(value.firstDirectory, '--limit', '1');
  assert.equal(savedOnly.status, 0, savedOnly.stderr);
  assert.equal(JSON.parse(savedOnly.stderr).source_provenance_status, 'SAVED_ONLY_UNVERIFIED');
  const emitted = [];
  await assert.rejects(streamEventQuery(prepareEventQuery(value.firstDirectory, EVENT),
    { verifySource: true, limit: 1 }, async (line) => emitted.push(line)),
  (error) => error.code === 'SOURCE_PROVENANCE_MISMATCH'
    && error.details.line_number === 2);
  assert.deepEqual(emitted, []);
  const output = path.join(value.root, 'forged-output.jsonl');
  const verified = query(value.firstDirectory, '--verify-source', '--limit', '1', '--output', output);
  assert.equal(verified.status, 2);
  assert.equal(verified.stdout, '');
  assert.match(verified.stderr, /SOURCE_PROVENANCE_MISMATCH/);
  assert.equal(fs.existsSync(output), false);
});

test('episode source identity and dependency metadata cannot be replaced by saved attestations', (t) => {
  const value = fixture(t);
  const different = path.join(value.root, 'different.rofl');
  fs.writeFileSync(different, replayBytes({ includeDeadTime: false }));
  const wrong = query(value.firstDirectory, '--verify-source', '--source-replay', different);
  assert.equal(wrong.status, 2);
  assert.equal(wrong.stdout, '');
  assert.match(wrong.stderr, /SOURCE_REPLAY_IDENTITY_MISMATCH/);
  for (const filename of [value.semanticPath, value.analysisPath]) {
    rewriteJson(filename, (document) => {
      const results = filename === value.semanticPath
        ? document.capability_results : document.semantic.capability_results;
      results.hero_death_timer.input_count += 1;
    });
  }
  const forged = query(value.firstDirectory, '--verify-source', '--limit', '1');
  assert.equal(forged.status, 2);
  assert.equal(forged.stdout, '');
  assert.match(forged.stderr, /SOURCE_PROVENANCE_MISMATCH/);
});

test('batch episode source verification stays PARTIAL for a missing dependency', (t) => {
  const value = fixture(t, { batch: true, partial: true });
  const verified = query(value.output, '--verify-source', '--limit', '1');
  assert.equal(verified.status, 0, verified.stderr);
  const summary = JSON.parse(verified.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.source_provenance_status, 'PARTIAL_SOURCE_REPLAY_VERIFIED');
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.scanned_count, 2);
});

test('batch verification rejects a late episode forgery even when its manifest is rewritten', (t) => {
  const value = fixture(t, { batch: true });
  const second = path.join(value.output, 'replays', 'second', `${EVENT}.jsonl`);
  const rows = fs.readFileSync(second, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  rows[1].timer_seconds_candidate += 1;
  fs.writeFileSync(second, `${rows.map(JSON.stringify).join('\n')}\n`);
  rewriteJson(path.join(value.output, 'manifest.json'), (manifest) => {
    manifest.output_hashes_excluding_manifest[`replays/second/${EVENT}.jsonl`] =
      crypto.createHash('sha256').update(fs.readFileSync(second)).digest('hex');
  });
  const savedOnly = query(value.output, '--limit', '1');
  assert.equal(savedOnly.status, 0, savedOnly.stderr);
  const verified = query(value.output, '--verify-source', '--limit', '1');
  assert.equal(verified.status, 2);
  assert.equal(verified.stdout, '');
  assert.match(verified.stderr, /SOURCE_PROVENANCE_MISMATCH/);
});

test('unused image metadata remains operational while static episode fields are verified', (t) => {
  const value = fixture(t);
  for (const filename of [value.semanticPath, value.analysisPath]) {
    rewriteJson(filename, (document) => {
      const results = filename === value.semanticPath
        ? document.capability_results : document.semantic.capability_results;
      for (const name of ['hero_death_timer', 'hero_respawn']) {
        results[name].runtime_image_status = 'PROVIDED_NOT_USED';
      }
    });
  }
  const verified = query(value.firstDirectory, '--verify-source', '--limit', '1');
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(JSON.parse(verified.stderr).source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
  assert.equal(JSON.parse(verified.stdout).confidence, 'CANDIDATE');
  for (const filename of [value.semanticPath, value.analysisPath]) {
    rewriteJson(filename, (document) => {
      const results = filename === value.semanticPath
        ? document.capability_results : document.semantic.capability_results;
      results.hero_death_timer.runtime_image_used = true;
    });
  }
  const falselyUsed = query(value.firstDirectory, '--verify-source');
  assert.equal(falselyUsed.status, 2);
  assert.equal(falselyUsed.stdout, '');
  assert.match(falselyUsed.stderr, /ASSOCIATION_METADATA_MISMATCH/);
});

test('a saved native assist claim cannot bypass the exact runtime image requirement', (t) => {
  const value = fixture(t);
  for (const filename of [value.semanticPath, value.analysisPath]) {
    rewriteJson(filename, (document) => {
      const results = filename === value.semanticPath
        ? document.capability_results : document.semantic.capability_results;
      results.hero_assist.native_child_identity_status = 'MATCHED_USED';
      results.hero_assist.runtime_image_status = 'MATCHED_USED';
      results.hero_assist.runtime_image_used = true;
      results.hero_assist.runtime_image_sha256 =
        results.hero_assist.evidence_runtime_image_sha256;
    });
  }
  const rows = value.lines.map(JSON.parse);
  rows.forEach((row) => { row.native_child_identity_status = 'MATCHED_USED'; });
  fs.writeFileSync(value.eventPath, `${rows.map(JSON.stringify).join('\n')}\n`);
  const missing = query(value.firstDirectory, '--verify-source');
  assert.equal(missing.status, 2);
  assert.equal(missing.stdout, '');
  assert.match(missing.stderr, /MISSING_SOURCE_RUNTIME_IMAGE/);
  const wrongImage = path.join(value.root, 'wrong-runtime.bin');
  fs.writeFileSync(wrongImage, Buffer.alloc(32));
  const wrong = query(value.firstDirectory, '--verify-source', '--runtime-image', wrongImage);
  assert.equal(wrong.status, 2);
  assert.equal(wrong.stdout, '');
  assert.match(wrong.stderr, /SOURCE_PROVENANCE_MISMATCH/);
});

test('individual exact-821 death, assist, timer and return streams support complete source verification', (t) => {
  const value = fixture(t);
  for (const [eventKey, expectedCount] of [
    ['hero_death_candidates', 2], ['hero_assist_candidates', 2],
    ['hero_death_timer_candidates', 2], ['hero_respawn_candidates', 1],
  ]) {
    const verified = cli('query-events', value.firstDirectory, '--event', eventKey,
      '--verify-source', '--limit', '1');
    assert.equal(verified.status, 0, verified.stderr);
    const summary = JSON.parse(verified.stderr);
    assert.equal(summary.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
    assert.equal(summary.scanned_count, expectedCount);
    assert.equal(summary.emitted_count, 1);
    const original = fs.readFileSync(path.join(value.firstDirectory, `${eventKey}.jsonl`), 'utf8')
      .split('\n')[0];
    assert.equal(verified.stdout, `${original}\n`);
  }
});

test('individual timer source verification catches late semantic field forgery after output limit', (t) => {
  const value = fixture(t);
  const eventKey = 'hero_death_timer_candidates';
  const filename = path.join(value.firstDirectory, `${eventKey}.jsonl`);
  const rows = fs.readFileSync(filename, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  rows[1].timer_seconds_candidate += 1;
  fs.writeFileSync(filename, `${rows.map(JSON.stringify).join('\n')}\n`);
  const savedOnly = cli('query-events', value.firstDirectory, '--event', eventKey, '--limit', '1');
  assert.equal(savedOnly.status, 0, savedOnly.stderr);
  const verified = cli('query-events', value.firstDirectory, '--event', eventKey,
    '--verify-source', '--limit', '1');
  assert.equal(verified.status, 2);
  assert.equal(verified.stdout, '');
  assert.match(verified.stderr, /SOURCE_PROVENANCE_MISMATCH/);
});
