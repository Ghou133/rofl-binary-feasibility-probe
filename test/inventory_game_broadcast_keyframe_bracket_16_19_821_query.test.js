'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.821.7343';
const EVENT = 'inventory_game_broadcast_keyframe_bracket_candidates';
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');

function command(...args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: path.dirname(CLI), encoding: 'utf8', timeout: 120000,
  });
}

function replayArtifact(output) {
  const acceptance = JSON.parse(fs.readFileSync(path.join(output,
    'acceptance_summary.json'), 'utf8'));
  return path.join(output, acceptance.replay_artifacts[0].artifact_directory);
}

function syntheticReplay() {
  const packet = (param, timeMs) => {
    const payload = Buffer.alloc(79);
    payload[0] = 0x1e;
    const header = Buffer.alloc(15);
    header.writeFloatLE(timeMs / 1000, 1);
    header.writeUInt32LE(payload.length, 5);
    header.writeUInt16LE(0x0357, 9);
    header.writeUInt32LE(param, 11);
    return Buffer.concat([header, payload]);
  };
  return replayFromChunks([1000, 2000].map((timeMs) => ({
    stream: 2,
    body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      packet(0x400000ae + index, timeMs))),
  })), BUILD);
}

test('query-events retains missing exact-image bracket as unavailable', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-game-bracket-query-missing-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'sample.rofl');
  const output = path.join(root, 'output');
  fs.writeFileSync(input, syntheticReplay().buffer);
  const decoded = command('decode', input, '--events', 'hero_inventory_broadcast_packet',
    '--event-jsonl-only', '--out-dir', output);
  assert.equal(decoded.status, 2, decoded.stderr || decoded.stdout);
  const queried = command('query-events', replayArtifact(output), '--event', EVENT);
  assert.equal(queried.status, 2, queried.stderr);
  assert.equal(JSON.parse(queried.stderr).code, 'ASSOCIATION_UNAVAILABLE');
});

test('query-events validates real bracket sources and preserves exact JSONL rows', (t) => {
  if (!fs.existsSync(REPLAY) || !fs.existsSync(IMAGE)) {
    t.skip('supplied KR 821 Replay or matching local runtime image absent');
    return;
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-game-bracket-query-real-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const output = path.join(root, 'output');
  const decoded = command('decode', REPLAY, '--events', 'hero_inventory_broadcast_packet',
    '--runtime-image', IMAGE, '--event-jsonl-only', '--out-dir', output);
  assert.equal(decoded.status, 0, decoded.stderr || decoded.stdout);
  const artifact = replayArtifact(output);
  const eventPath = path.join(artifact, EVENT + '.jsonl');
  const original = fs.readFileSync(eventPath, 'utf8');
  const lines = original.trim().split(/\r?\n/);
  const rows = lines.map(JSON.parse);
  assert.ok(rows.length > 0);
  const participant = rows[0].participant_id_candidate;
  const param = rows[0].hero_raw_param;
  const selected = command('query-events', artifact, '--event', EVENT,
    '--participant', String(participant), '--raw-param', String(param),
    '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, lines[0] + '\n');
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, rows.length);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.matched_count, rows.filter((row) =>
    row.participant_id_candidate === participant && row.hero_raw_param === param).length);
  assert.equal(summary.rows_unmodified, true);

  rows[0].record_comparisons_candidate[0].game_item_id_candidate += 1;
  fs.writeFileSync(eventPath, rows.map(JSON.stringify).join('\n') + '\n');
  const invalidOutput = path.join(root, 'must-not-exist.jsonl');
  const tampered = command('query-events', artifact, '--event', EVENT,
    '--output', invalidOutput);
  assert.equal(tampered.status, 2, tampered.stderr);
  assert.equal(JSON.parse(tampered.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(fs.existsSync(invalidOutput), false);
  fs.writeFileSync(eventPath, original);

  const sourcePath = path.join(artifact, 'hero_inventory_broadcast_packet_candidates.jsonl');
  const sourceOriginal = fs.readFileSync(sourcePath, 'utf8');
  const sourceRows = sourceOriginal.trim().split(/\r?\n/).map(JSON.parse);
  const ref = JSON.parse(lines[0]).game_raw_packet_ref;
  const sourceRow = sourceRows.find((row) =>
    row.raw_packet_ref.chunk_index === ref.chunk_index
    && row.raw_packet_ref.decompressed_block_offset === ref.decompressed_block_offset);
  assert.ok(sourceRow);
  sourceRow.packet_slot_snapshot_candidate[sourceRow.records_candidate[0].slot_candidate]
    .item_id_candidate += 1;
  fs.writeFileSync(sourcePath, sourceRows.map(JSON.stringify).join('\n') + '\n');
  const sourceTampered = command('query-events', artifact, '--event', EVENT);
  assert.equal(sourceTampered.status, 2, sourceTampered.stderr);
  assert.equal(JSON.parse(sourceTampered.stderr).code, 'INVALID_EVENT_ROW');
});
