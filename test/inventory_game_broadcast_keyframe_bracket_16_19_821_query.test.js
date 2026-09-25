'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { streamEventQuery } = require('../src/event_query');

const BUILD = '16.19.821.7343';
const EVENT = 'inventory_game_broadcast_keyframe_bracket_candidates';
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const IMAGE = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'kr_821_runtime_capture', 'LeagueOfLegends_16.19.821.7343.memory.bin');
const REPLAY = path.resolve(__dirname, '..', '..', 'kr-rofl-batch-collector',
  'data', 'KR', '16.19', 'builds', BUILD, 'rofl', 'KR_8392938200.rofl');
const BATCH = path.resolve(__dirname, '..', 'artifacts', '16_19_development',
  'inventory_game_broadcast_bracket_batch_11_821');
const LABELS = ['SAME_AS_BOTH_ENDPOINTS', 'DIFFERS_FROM_EQUAL_ENDPOINTS',
  'SAME_AS_PREVIOUS_ENDPOINT', 'SAME_AS_NEXT_ENDPOINT',
  'DIFFERS_FROM_BOTH_ENDPOINTS'];

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

test('comparison label filter rejects unsupported events, builds and spellings', async () => {
  const invalidLabel = command('query-events', 'unused', '--event', EVENT,
    '--comparison-to-endpoints', 'differs_from_equal_endpoints');
  assert.equal(invalidLabel.status, 1);
  assert.match(invalidLabel.stderr, /five exact uppercase bracket comparison labels/);
  const otherEvent = command('query-events', 'unused', '--event',
    'hero_inventory_broadcast_packet_candidates',
    '--comparison-to-endpoints', LABELS[0]);
  assert.equal(otherEvent.status, 1);
  assert.match(otherEvent.stderr, /requires inventory_game_broadcast_keyframe_bracket_candidates/);
  const emit = async () => assert.fail('unsupported filter must reject before reading rows');
  await assert.rejects(() => streamEventQuery({ eventKey: EVENT,
    replayVersion: '16.19.820.7193', capabilityStatus: 'CANDIDATE' },
  { comparisonToEndpoints: LABELS[0] }, emit),
  (error) => error.code === 'UNSUPPORTED_FILTER');
  await assert.rejects(() => streamEventQuery({ eventKey: EVENT,
    replayVersion: BUILD, capabilityStatus: 'CANDIDATE' },
  { comparisonToEndpoints: 'same_as_both_endpoints' }, emit),
  (error) => error.code === 'INVALID_FILTER');
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

  const matches = (row, label, slot = null, itemId = null) =>
    row.record_comparisons_candidate.some((record) =>
      record.comparison_to_endpoints === label
      && (slot === null || record.slot_candidate === slot)
      && (itemId === null || record.game_item_id_candidate === itemId));
  for (const label of LABELS) {
    const expected = lines.filter((_line, index) => matches(rows[index], label));
    const filtered = command('query-events', artifact, '--event', EVENT,
      '--comparison-to-endpoints', label);
    assert.equal(filtered.status, 0, filtered.stderr);
    assert.equal(filtered.stdout, expected.map((line) => `${line}\n`).join(''));
    const result = JSON.parse(filtered.stderr);
    assert.equal(result.scanned_count, rows.length);
    assert.equal(result.matched_count, expected.length);
    assert.equal(result.filters.comparison_to_endpoints, label);
    assert.equal(result.rows_unmodified, true);
  }
  const label = 'DIFFERS_FROM_EQUAL_ENDPOINTS';
  const first = rows.find((row) => matches(row, label));
  assert.ok(first);
  const hit = first.record_comparisons_candidate.find((record) =>
    record.comparison_to_endpoints === label);
  const miss = first.record_comparisons_candidate.find((record) =>
    record.comparison_to_endpoints !== label
    && record.game_item_id_candidate !== hit.game_item_id_candidate);
  assert.ok(miss);
  const itemAndSlot = command('query-events', artifact, '--event', EVENT,
    '--slot', String(hit.slot_candidate), '--item-id', String(hit.game_item_id_candidate));
  assert.equal(itemAndSlot.status, 0, itemAndSlot.stderr);
  assert.equal(itemAndSlot.stdout, lines.filter((_line, index) =>
    rows[index].record_comparisons_candidate.some((record) =>
      record.slot_candidate === hit.slot_candidate
      && record.game_item_id_candidate === hit.game_item_id_candidate))
    .map((line) => `${line}\n`).join(''));
  for (const [filterArgs, predicate] of [
    [['--slot', String(hit.slot_candidate), '--item-id', String(hit.game_item_id_candidate)],
      (row) => matches(row, label, hit.slot_candidate, hit.game_item_id_candidate)],
    [['--slot', String(miss.slot_candidate), '--item-id', String(miss.game_item_id_candidate)],
      (row) => matches(row, label, miss.slot_candidate, miss.game_item_id_candidate)],
    [['--slot', String(hit.slot_candidate), '--item-id', String(miss.game_item_id_candidate)],
      (row) => matches(row, label, hit.slot_candidate, miss.game_item_id_candidate)],
    [['--slot', String(miss.slot_candidate), '--item-id', String(hit.game_item_id_candidate)],
      (row) => matches(row, label, miss.slot_candidate, hit.game_item_id_candidate)],
    [['--item-id', '0'], (row) => matches(row, label, null, 0)],
    [['--slot', '9'], (row) => matches(row, label, 9)],
  ]) {
    const filtered = command('query-events', artifact, '--event', EVENT,
      '--comparison-to-endpoints', label, ...filterArgs);
    assert.equal(filtered.status, 0, filtered.stderr);
    const expected = lines.filter((_line, index) => predicate(rows[index]));
    assert.equal(filtered.stdout, expected.map((line) => `${line}\n`).join(''));
    assert.equal(JSON.parse(filtered.stderr).matched_count, expected.length);
  }
  assert.equal(matches(first, label, miss.slot_candidate, miss.game_item_id_candidate),
    false, 'a different explicit record cannot supply the slot or game item key');
  const limited = command('query-events', artifact, '--event', EVENT,
    '--comparison-to-endpoints', label, '--limit', '1');
  assert.equal(limited.status, 0, limited.stderr);
  assert.equal(limited.stdout, lines.find((_line, index) => matches(rows[index], label)) + '\n');
  assert.equal(JSON.parse(limited.stderr).matched_count,
    rows.filter((row) => matches(row, label)).length);

  rows[0].record_comparisons_candidate[0].game_item_id_candidate += 1;
  fs.writeFileSync(eventPath, rows.map(JSON.stringify).join('\n') + '\n');
  const invalidOutput = path.join(root, 'must-not-exist.jsonl');
  const tampered = command('query-events', artifact, '--event', EVENT,
    '--comparison-to-endpoints', label, '--limit', '1', '--output', invalidOutput);
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
  const sourceTampered = command('query-events', artifact, '--event', EVENT,
    '--comparison-to-endpoints', label, '--limit', '1');
  assert.equal(sourceTampered.status, 2, sourceTampered.stderr);
  assert.equal(JSON.parse(sourceTampered.stderr).code, 'INVALID_EVENT_ROW');
});

test('saved 11-Replay batch comparison query returns original lines and row counts', (t) => {
  if (!fs.existsSync(path.join(BATCH, 'manifest.json'))) {
    t.skip('saved 11-Replay exact-821 bracket batch absent');
    return;
  }
  const filtered = command('query-events', BATCH, '--event', EVENT,
    '--comparison-to-endpoints', 'DIFFERS_FROM_EQUAL_ENDPOINTS');
  assert.equal(filtered.status, 0, filtered.stderr);
  const summary = JSON.parse(filtered.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.completed_replay_count, 11);
  assert.equal(summary.scanned_count, 55);
  assert.equal(summary.matched_count, 25);
  assert.equal(summary.emitted_count, 25);
  assert.equal(summary.rows_unmodified, true);
  assert.equal(crypto.createHash('sha256').update(filtered.stdout).digest('hex'),
    '97bb23d56a2d8b603571e22b33c9f2febc97d91c517df1328445ad1a043cc198');
  const limited = command('query-events', BATCH, '--event', EVENT,
    '--comparison-to-endpoints', 'DIFFERS_FROM_EQUAL_ENDPOINTS', '--limit', '1');
  assert.equal(limited.status, 0, limited.stderr);
  assert.equal(limited.stdout, filtered.stdout.split('\n')[0] + '\n');
  const limitedSummary = JSON.parse(limited.stderr);
  assert.equal(limitedSummary.scanned_count, 55);
  assert.equal(limitedSummary.matched_count, 25);
  assert.equal(limitedSummary.emitted_count, 1);
  assert.equal(limitedSummary.completed_replay_count, 11);
});
