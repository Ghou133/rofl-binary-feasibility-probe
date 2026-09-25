'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const { walkBlocks } = require('../src/rofl');
const { HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821: BROADCAST_PROFILE } =
  require('../src/decoders/rofl_16_19_821_inventory_broadcast_packet_candidate');
const { deriveInventoryKeyframeIntervalDifferenceCandidates821: derive } =
  require('../src/decoders/rofl_16_19_821_inventory_keyframe_interval_difference_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const BUILD = '16.19.821.7343';
const CAPABILITY = 'hero_inventory_broadcast_packet';
const SOURCE_EVENT = 'hero_inventory_broadcast_packet_candidates';
const ASSOCIATION = 'inventory_keyframe_interval_difference';
const EVENT = 'inventory_keyframe_interval_difference_candidates';
const IMAGE_SHA256 = BROADCAST_PROFILE.evidence_runtime_image_sha256;
const SLOT_BYTES = ['c1', '15', '9f', '2e', 'f6', '6b', 'db', '68', '46', 'd4'];

function packet(param, timeMs, size = 79, fill = 0x1e) {
  const payload = Buffer.alloc(size, fill);
  payload[0] = 0x1e;
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x0357, 9);
  header.writeUInt32LE(param >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function slotValues(frame, participant) {
  const values = Array(10).fill(0);
  if (participant === 1 && frame >= 1) {
    if (frame === 2) values[0] = 1001;
    values[6] = frame === 1 ? 3340 : 0;
    values[7] = 2001;
  }
  if (participant === 2) {
    values[6] = frame === 0 ? 3340 : 0;
    if (frame === 2) values[7] = 1001;
  }
  return values;
}

function rowFromBlock(replay, block, chunk) {
  const isKeyframe = chunk.stream === 'keyframe';
  const participant = (block.param >>> 0) - 0x400000ad;
  const values = isKeyframe ? slotValues(chunk.index > 1 ? chunk.index - 1 : 0,
    participant) : Array(10).fill(0);
  const slots = isKeyframe ? [...Array(10).keys()] : [0, 1, 2, 3, 4, 5];
  const records = slots.map((slot, index) => ({
    record_index: index, slot_candidate: slot, item_id_candidate: values[slot],
    emulated_object_slot_byte_hex: SLOT_BYTES[slot],
    emulated_object_item_id_bytes_hex: values[slot] === 3340 ? '0eb8eaea'
      : values[slot] === 2001 ? 'aad8eaea'
        : values[slot] === 1001 ? 'f248eaea' : 'eaeaeaea',
  }));
  const snapshot = Array.from({ length: 10 }, (_, slot) => ({
    slot_candidate: slot,
    item_id_candidate: slots.includes(slot) ? values[slot] : null,
    value_basis: slots.includes(slot)
      ? 'DECODED_PACKET_RECORD' : 'CALLBACK_RESET_WITH_NO_PACKET_RECORD',
  }));
  const rawRef = {
    source_path: replay.source_path ?? null, replay_sha256: replay.source_sha256,
    chunk_index: chunk.index, chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream, chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id, replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length, raw_param: block.param >>> 0,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
  return {
    event_type: 'HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: BROADCAST_PROFILE.id,
    replay_sha256: replay.source_sha256, replay_time_ms: block.timestamp_ms,
    hero_raw_param: block.param >>> 0, participant_id_candidate: participant,
    packet_stream: chunk.stream,
    snapshot_application: 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS',
    record_count: records.length, records_candidate: records,
    packet_slot_snapshot_candidate: snapshot,
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS',
    raw_packet_ref: rawRef,
  };
}

function sourceOutcomes(seed = 0) {
  const chunks = [
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      packet(0x400000ae + index, 0, 79, seed + index))) },
    { stream: 1, body: packet(0x400000ae, 45000, 76, seed + 99) },
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      packet(0x400000ae + index, 60000, 79, seed + index + 1))) },
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      packet(0x400000ae + index, 120000, 79, seed + index + 2))) },
  ];
  const replay = replayFromChunks(chunks, BUILD);
  const events = [];
  walkBlocks(replay, (block, chunk) => events.push(rowFromBlock(replay, block, chunk)),
    { strict: true });
  const inventoryBroadcastOutcome = {
    status: 'CANDIDATE', profile_id: BROADCAST_PROFILE.id,
    evidence_runtime_image_sha256: IMAGE_SHA256,
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS',
    runtime_image_sha256: IMAGE_SHA256, runtime_image_used: true,
    runtime_image_status: 'MATCHED_USED', input_packet_id: 0x0357,
    input_count: events.length, event_count: events.length,
    decoded_record_count: events.reduce((sum, row) => sum + row.record_count, 0),
    events,
  };
  const association = derive(replay, { inventoryBroadcastOutcome });
  assert.equal(association.status, 'CANDIDATE', association.error);
  assert.equal(association.input_count, 31);
  assert.equal(association.keyframe_count, 3);
  assert.equal(association.event_count, 4);
  assert.equal(association.changed_slot_count, 6);
  assert.equal(association.excluded_game_broadcast_count, 1);
  return { replay, inventoryBroadcastOutcome, association };
}

function reversalOutcomes(seed = 0, kind = 'positive') {
  const source = sourceOutcomes(seed);
  const bytes = new Map([[0, 'eaeaeaea'], [1001, 'f248eaea'],
    [2001, 'aad8eaea'], [3340, '0eb8eaea']]);
  const setSlot = (row, slot, item) => {
    row.records_candidate[slot].item_id_candidate = item;
    row.records_candidate[slot].emulated_object_item_id_bytes_hex = bytes.get(item);
    row.packet_slot_snapshot_candidate[slot].item_id_candidate = item;
  };
  const frames = source.inventoryBroadcastOutcome.events.filter((row) =>
    row.packet_stream === 'keyframe' && row.participant_id_candidate === 1
      && [0, 60000].includes(row.replay_time_ms));
  assert.equal(frames.length, 2);
  for (const row of frames) {
    setSlot(row, 6, 3340);
    setSlot(row, 7, 0);
    if (kind === 'zero') {
      setSlot(row, 2, row.replay_time_ms === 0 ? 0 : 2001);
      setSlot(row, 4, row.replay_time_ms === 0 ? 2001 : 0);
    } else {
      setSlot(row, 2, row.replay_time_ms === 0 ? 1001 : 2001);
      setSlot(row, 4, row.replay_time_ms === 0 ? 2001 : 1001);
    }
    if (kind === 'duplicate') setSlot(row, 5, 1001);
    if (kind === 'extra' && row.replay_time_ms === 60000) setSlot(row, 0, 1001);
  }
  source.association = derive(source.replay,
    { inventoryBroadcastOutcome: source.inventoryBroadcastOutcome });
  assert.equal(source.association.status, 'CANDIDATE', source.association.error);
  return source;
}

function withoutEvents(outcome) {
  const copy = structuredClone(outcome);
  delete copy.events;
  return copy;
}

function writeReplayArtifact(root, name, source, { imageMissing = false } = {}) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const capability = imageMissing
    ? { ...withoutEvents(source.inventoryBroadcastOutcome),
      status: 'MISSING_INPUT', event_count: null, runtime_image_used: false,
      runtime_image_status: 'MISSING', missing_input: 'runtime_image' }
    : withoutEvents(source.inventoryBroadcastOutcome);
  const association = imageMissing
    ? { profile_id: source.association.profile_id, status: 'MISSING_INPUT',
      event_count: null, error: 'exact runtime image is missing' }
    : withoutEvents(source.association);
  const semantic = {
    replay_version: BUILD, replay_sha256: source.replay.source_sha256,
    container_status: 'PASS', status: imageMissing ? 'PARTIAL' : 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE',
    requested_capabilities: [CAPABILITY],
    capability_results: { [CAPABILITY]: capability },
    candidate_associations: { [ASSOCIATION]: association },
  };
  const rows = imageMissing ? {} : {
    [SOURCE_EVENT]: source.inventoryBroadcastOutcome.events,
    [EVENT]: source.association.events,
  };
  const eventCounts = Object.fromEntries(Object.entries(rows).map(([key, value]) =>
    [key, value.length]));
  const analysis = {
    source_path: source.replay.source_path,
    patch: '16.19', replay_version: BUILD, replay_sha256: source.replay.source_sha256,
    event_counts: eventCounts, event_storage: 'JSONL_ONLY',
    event_jsonl_files: Object.fromEntries(Object.keys(rows).map((key) =>
      [key, `${key}.jsonl`])),
    events: null,
    semantic: {
      status: semantic.status, requested_capabilities: semantic.requested_capabilities,
      capability_results: { [CAPABILITY]: capability },
      candidate_associations: { [ASSOCIATION]: association },
    },
  };
  fs.writeFileSync(path.join(directory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(directory, 'replay_analysis.json'), JSON.stringify(analysis));
  for (const [key, value] of Object.entries(rows)) {
    fs.writeFileSync(path.join(directory, `${key}.jsonl`),
      `${value.map(JSON.stringify).join('\n')}\n`);
  }
  return { name, directory, sha: source.replay.source_sha256,
    lines: (rows[EVENT] ?? []).map(JSON.stringify),
    semanticPath: path.join(directory, 'semantic_run.json'),
    analysisPath: path.join(directory, 'replay_analysis.json'),
    sourceEventPath: path.join(directory, `${SOURCE_EVENT}.jsonl`),
    eventPath: path.join(directory, `${EVENT}.jsonl`) };
}

function fixture(t, { batch = false, partial = false, reversalKind = null } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-inventory-diff-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const first = writeReplayArtifact(root, 'first', reversalKind
    ? reversalOutcomes(1, reversalKind) : sourceOutcomes(1));
  let second = null;
  if (batch) {
    second = writeReplayArtifact(root, 'second', reversalKind
      ? reversalOutcomes(2, reversalKind) : sourceOutcomes(2),
      { imageMissing: partial });
    const replayInputs = [first, second].map((entry) => ({
      sha256: entry.sha, version: BUILD,
      artifact_directory: `replays/${entry.name}`,
    }));
    const hashes = {};
    for (const entry of replayInputs) {
      for (const name of fs.readdirSync(path.join(root, entry.artifact_directory))) {
        const relative = `${entry.artifact_directory}/${name}`;
        hashes[relative] = crypto.createHash('sha256')
          .update(fs.readFileSync(path.join(root, relative))).digest('hex');
      }
    }
    fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
      command_args: ['batch', 'synthetic-input'], replay_inputs: replayInputs,
      output_hashes_excluding_manifest: hashes,
    }));
  }
  return { root, first, second };
}

function query(target, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', target, '--event', EVENT, ...args],
    { encoding: 'utf8', cwd: path.dirname(CLI) });
}

function rewriteJson(filename, edit) {
  const value = JSON.parse(fs.readFileSync(filename, 'utf8'));
  edit(value);
  fs.writeFileSync(filename, JSON.stringify(value));
}

test('query-events filters sampled inventory differences with same-slot current item', (t) => {
  const { first } = fixture(t);
  const firstRow = JSON.parse(first.lines[0]);
  assert.deepEqual(firstRow.changed_slots_candidate, [
    { slot_candidate: 6, previous_item_id_candidate: 0,
      current_item_id_candidate: 3340 },
    { slot_candidate: 7, previous_item_id_candidate: 0,
      current_item_id_candidate: 2001 },
  ]);
  const selected = query(first.directory, '--participant', '1',
    '--from-ms', '60000', '--to-ms', '60000', '--raw-param', '0x400000ae',
    '--slot', '6', '--item-id', '3340');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${first.lines[0]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, 4);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.rows_unmodified, true);
  const falseCrossRecord = query(first.directory, '--participant', '1',
    '--to-ms', '60000', '--slot', '6', '--item-id', '2001');
  assert.equal(falseCrossRecord.status, 0, falseCrossRecord.stderr);
  assert.equal(falseCrossRecord.stdout, '');
  assert.equal(JSON.parse(falseCrossRecord.stderr).matched_count, 0);
  const zero = query(first.directory, '--participant', '1',
    '--from-ms', '120000', '--slot', '6', '--item-id', '0');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${first.lines[2]}\n`);
  // This same row also has slot 0 changing to 1001. A zero in changed slot 6
  // cannot satisfy a request for zero in changed slot 0.
  const zeroWrongSlot = query(first.directory, '--participant', '1',
    '--from-ms', '120000', '--slot', '0', '--item-id', '0');
  assert.equal(zeroWrongSlot.status, 0, zeroWrongSlot.stderr);
  assert.equal(zeroWrongSlot.stdout, '');
  assert.equal(JSON.parse(zeroWrongSlot.stderr).matched_count, 0);
  assert.equal(fs.readFileSync(first.eventPath, 'utf8'), `${first.lines.join('\n')}\n`);
});

test('previous item ID matches the same changed slot as current ID and slot', (t) => {
  const { first } = fixture(t);
  const originalJsonl = fs.readFileSync(first.eventPath, 'utf8');
  const firstChange = query(first.directory, '--participant', '1',
    '--to-ms', '60000', '--slot', '6',
    '--previous-item-id', '0', '--item-id', '3340');
  assert.equal(firstChange.status, 0, firstChange.stderr);
  assert.equal(firstChange.stdout, `${first.lines[0]}\n`);
  const filters = JSON.parse(firstChange.stderr).filters;
  assert.equal(filters.participant_id, 1);
  assert.equal(filters.to_ms, 60000);
  assert.equal(filters.slot, 6);
  assert.equal(filters.item_id, 3340);
  assert.equal(filters.previous_item_id, 0);

  const changedToZero = query(first.directory, '--participant', '1',
    '--from-ms', '120000', '--slot', '6',
    '--previous-item-id', '0xD0C', '--item-id', '0');
  assert.equal(changedToZero.status, 0, changedToZero.stderr);
  assert.equal(changedToZero.stdout, `${first.lines[2]}\n`);
  assert.equal(JSON.parse(changedToZero.stderr).rows_unmodified, true);

  // In this row, slot 6 previously holds 3340 while slot 0 currently holds
  // 1001. A row-level conjunction would incorrectly match them.
  const falseCrossRecord = query(first.directory, '--participant', '1',
    '--from-ms', '120000', '--previous-item-id', '3340', '--item-id', '1001');
  assert.equal(falseCrossRecord.status, 0, falseCrossRecord.stderr);
  assert.equal(falseCrossRecord.stdout, '');
  assert.equal(JSON.parse(falseCrossRecord.stderr).matched_count, 0);

  const falseCrossSlot = query(first.directory, '--participant', '1',
    '--to-ms', '60000', '--slot', '6',
    '--previous-item-id', '0', '--item-id', '2001');
  assert.equal(falseCrossSlot.status, 0, falseCrossSlot.stderr);
  assert.equal(falseCrossSlot.stdout, '');
  assert.equal(JSON.parse(falseCrossSlot.stderr).matched_count, 0);

  const falseTwoZeros = query(first.directory, '--participant', '1',
    '--from-ms', '120000', '--previous-item-id', '0', '--item-id', '0');
  assert.equal(falseTwoZeros.status, 0, falseTwoZeros.stderr);
  assert.equal(falseTwoZeros.stdout, '');
  assert.equal(JSON.parse(falseTwoZeros.stderr).matched_count, 0);
  assert.equal(fs.readFileSync(first.eventPath, 'utf8'), originalJsonl);
});

test('previous item ID rejects other event streams and malformed uint32 values', (t) => {
  const { first } = fixture(t);
  const otherEvent = spawnSync(process.execPath,
    [CLI, 'query-events', first.directory, '--event', SOURCE_EVENT,
      '--previous-item-id', '0'],
    { encoding: 'utf8', cwd: path.dirname(CLI) });
  assert.equal(otherEvent.status, 1);
  assert.match(otherEvent.stderr, /--previous-item-id/);
  for (const invalid of ['-1', '4294967296', '0x100000000', 'not-a-number']) {
    const rejected = query(first.directory, '--previous-item-id', invalid);
    assert.equal(rejected.status, 1, rejected.stderr);
    assert.match(rejected.stderr, /--previous-item-id.*uint32/);
    assert.equal(rejected.stdout, '');
  }
});

test('batch previous item ID emits original JSONL rows in manifest order', (t) => {
  const { root, first, second } = fixture(t, { batch: true });
  const originalFirst = fs.readFileSync(first.eventPath, 'utf8');
  const originalSecond = fs.readFileSync(second.eventPath, 'utf8');
  const selected = query(root, '--participant', '1', '--previous-item-id', '3340',
    '--item-id', '0', '--slot', '6');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${first.lines[2]}\n${second.lines[2]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.replay_count, 2);
  assert.equal(summary.scanned_count, 8);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 2);
  assert.equal(summary.rows_unmodified, true);
  assert.equal(fs.readFileSync(first.eventPath, 'utf8'), originalFirst);
  assert.equal(fs.readFileSync(second.eventPath, 'utf8'), originalSecond);
});

test('latest-per-participant chooses last matching observed difference per Replay', (t) => {
  const { first } = fixture(t);
  const latest = query(first.directory, '--latest-per-participant', '--to-ms', '120000');
  assert.equal(latest.status, 0, latest.stderr);
  assert.deepEqual(latest.stdout.trimEnd().split('\n'),
    [first.lines[2], first.lines[3]]);
  const summary = JSON.parse(latest.stderr);
  assert.equal(summary.scanned_count, 4);
  assert.equal(summary.matched_count, 4);
  assert.equal(summary.selected_count, 2);
  assert.equal(summary.emitted_count, 2);
  assert.equal(summary.rows_unmodified, true);
  const filtered = query(first.directory, '--latest-per-participant',
    '--slot', '6', '--item-id', '3340');
  assert.equal(filtered.status, 0, filtered.stderr);
  assert.equal(filtered.stdout, `${first.lines[0]}\n`);
  assert.equal(JSON.parse(filtered.stderr).selected_count, 1);
});

test('query-events rejects interval metadata, roster and dependency corruption', (t) => {
  const { root, first } = fixture(t);
  const originalSemantic = fs.readFileSync(first.semanticPath, 'utf8');
  const originalAnalysis = fs.readFileSync(first.analysisPath, 'utf8');
  const restore = () => {
    fs.writeFileSync(first.semanticPath, originalSemantic);
    fs.writeFileSync(first.analysisPath, originalAnalysis);
  };
  const reject = (code) => {
    const output = path.join(root, 'must-not-exist.jsonl');
    const result = query(first.directory, '--output', output);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, code);
    assert.equal(fs.existsSync(output), false);
    restore();
  };
  for (const file of [first.semanticPath, first.analysisPath]) {
    rewriteJson(file, (document) => {
      const association = file === first.semanticPath
        ? document.candidate_associations[ASSOCIATION]
        : document.semantic.candidate_associations[ASSOCIATION];
      association.profile_id = 'wrong-profile';
    });
  }
  reject('ASSOCIATION_METADATA_MISMATCH');

  for (const file of [first.semanticPath, first.analysisPath]) {
    rewriteJson(file, (document) => {
      const association = file === first.semanticPath
        ? document.candidate_associations[ASSOCIATION]
        : document.semantic.candidate_associations[ASSOCIATION];
      association.evidence_runtime_image_sha256 = 'f'.repeat(64);
    });
  }
  reject('ASSOCIATION_METADATA_MISMATCH');

  for (const file of [first.semanticPath, first.analysisPath]) {
    rewriteJson(file, (document) => {
      const association = file === first.semanticPath
        ? document.candidate_associations[ASSOCIATION]
        : document.semantic.candidate_associations[ASSOCIATION];
      association.broadcast_keyframe_packet_count = 29;
    });
  }
  reject('ASSOCIATION_METADATA_MISMATCH');

  for (const file of [first.semanticPath, first.analysisPath]) {
    rewriteJson(file, (document) => {
      const source = file === first.semanticPath
        ? document.capability_results[CAPABILITY]
        : document.semantic.capability_results[CAPABILITY];
      source.status = 'MISSING_INPUT';
      source.event_count = null;
    });
  }
  reject('CAPABILITY_UNAVAILABLE');
});

test('query-events rejects contradictory interval slot and raw packet evidence', (t) => {
  const { root, first } = fixture(t);
  const originalRows = fs.readFileSync(first.eventPath, 'utf8');
  const mutateAndReject = (edit, expectedCode = 'INVALID_EVENT_ROW') => {
    const rows = originalRows.trim().split(/\r?\n/).map(JSON.parse);
    edit(rows);
    fs.writeFileSync(first.eventPath, `${rows.map(JSON.stringify).join('\n')}\n`);
    const output = path.join(root, 'must-not-exist.jsonl');
    const result = query(first.directory, '--output', output);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, expectedCode);
    assert.equal(fs.existsSync(output), false);
    fs.writeFileSync(first.eventPath, originalRows);
  };
  mutateAndReject((rows) => {
    rows[0].previous_raw_packet_ref.raw_payload_sha256 = 'f'.repeat(64);
  });
  mutateAndReject((rows) => {
    rows[0].current_raw_packet_ref.raw_param = 0x400000af;
  });
  mutateAndReject((rows) => {
    rows[0].changed_slots_candidate[0].current_item_id_candidate = 0;
  });
  mutateAndReject((rows) => {
    rows[0].current_observation_time_ms = 0;
  });
  mutateAndReject((rows) => {
    rows[0].changed_slots_candidate.reverse();
  });
  mutateAndReject((rows) => {
    rows.pop();
  }, 'EVENT_COUNT_MISMATCH');
});

test('batch query stays PARTIAL when one Replay lacks exact image evidence', (t) => {
  const { root, first } = fixture(t, { batch: true, partial: true });
  const selected = query(root, '--participant', '1', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${first.lines[0]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.replay_count, 2);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.scanned_count, 4);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.replay_results[1].code, 'ASSOCIATION_UNAVAILABLE');
});

test('endpoint reversed pair uses complete unique nonzero endpoints and original rows', (t) => {
  const { first } = fixture(t, { reversalKind: 'positive' });
  const original = fs.readFileSync(first.eventPath, 'utf8');
  const expected = first.lines.find((line) => {
    const row = JSON.parse(line);
    return row.participant_id_candidate === 1
      && row.previous_observation_time_ms === 0;
  });
  assert.ok(expected);
  const selected = query(first.directory, '--endpoint-reversed-pair');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${expected}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.endpoint_reversed_pair_inspected_count, first.lines.length);
  assert.equal(summary.endpoint_reversed_pair_unavailable_count, 0);
  assert.equal(summary.filters.endpoint_reversed_pair, true);
  assert.equal(summary.rows_unmodified, true);
  const sameSlot = query(first.directory, '--endpoint-reversed-pair',
    '--slot', '2', '--previous-item-id', '1001', '--item-id', '2001');
  assert.equal(sameSlot.status, 0, sameSlot.stderr);
  assert.equal(sameSlot.stdout, `${expected}\n`);
  const crossSlot = query(first.directory, '--endpoint-reversed-pair',
    '--previous-item-id', '1001', '--item-id', '1001');
  assert.equal(crossSlot.status, 0, crossSlot.stderr);
  assert.equal(crossSlot.stdout, '');
  assert.equal(JSON.parse(crossSlot.stderr).matched_count, 0);
  assert.equal(fs.readFileSync(first.eventPath, 'utf8'), original);
});

test('endpoint reversed pair rejects zero moves, extra changes and full-roster duplicates', (t) => {
  for (const kind of ['zero', 'extra', 'duplicate']) {
    const { first } = fixture(t, { reversalKind: kind });
    const selected = query(first.directory, '--endpoint-reversed-pair');
    assert.equal(selected.status, 0, `${kind}: ${selected.stderr}`);
    assert.equal(selected.stdout, '', kind);
    const summary = JSON.parse(selected.stderr);
    assert.equal(summary.matched_count, 0, kind);
    assert.equal(summary.endpoint_reversed_pair_inspected_count,
      first.lines.length, kind);
  }
});

test('endpoint reversed pair rejects wrong stream/build and corrupted Broadcast source', (t) => {
  const { first } = fixture(t, { reversalKind: 'positive' });
  const wrongEvent = spawnSync(process.execPath,
    [CLI, 'query-events', first.directory, '--event', SOURCE_EVENT,
      '--endpoint-reversed-pair'],
    { encoding: 'utf8', cwd: path.dirname(CLI) });
  assert.equal(wrongEvent.status, 1);
  assert.match(wrongEvent.stderr, /--endpoint-reversed-pair/);
  const sourceJsonl = fs.readFileSync(first.sourceEventPath, 'utf8');
  const rows = sourceJsonl.trim().split(/\r?\n/).map(JSON.parse);
  const firstKeyframe = rows.find((row) => row.packet_stream === 'keyframe');
  firstKeyframe.packet_slot_snapshot_candidate[2].item_id_candidate = 1234;
  fs.writeFileSync(first.sourceEventPath, `${rows.map(JSON.stringify).join('\n')}\n`);
  const output = path.join(path.dirname(first.directory), 'must-not-exist.jsonl');
  const corrupted = query(first.directory, '--endpoint-reversed-pair',
    '--output', output);
  assert.equal(corrupted.status, 2, corrupted.stderr);
  assert.equal(JSON.parse(corrupted.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(fs.existsSync(output), false);
  fs.writeFileSync(first.sourceEventPath, sourceJsonl);
  for (const file of [first.semanticPath, first.analysisPath]) {
    rewriteJson(file, (document) => {
      document.replay_version = '16.19.820.7193';
    });
  }
  const wrongBuild = query(first.directory, '--endpoint-reversed-pair');
  assert.equal(wrongBuild.status, 2, wrongBuild.stderr);
  assert.equal(JSON.parse(wrongBuild.stderr).code, 'UNSUPPORTED_EVENT_BUILD');
});

test('batch endpoint reversed pair counts inspected and unavailable Replays', (t) => {
  const { root, first } = fixture(t,
    { batch: true, partial: true, reversalKind: 'positive' });
  const selected = query(root, '--endpoint-reversed-pair', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout.trimEnd().split('\n').length, 1);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.endpoint_reversed_pair_inspected_count, first.lines.length);
  assert.equal(summary.endpoint_reversed_pair_unavailable_replay_count, 1);
  assert.equal(summary.replay_results[1].query_status, 'UNAVAILABLE');
  fs.appendFileSync(first.sourceEventPath, '\n');
  const tampered = query(root, '--endpoint-reversed-pair');
  assert.equal(tampered.status, 2, tampered.stderr);
  assert.equal(JSON.parse(tampered.stderr).code, 'ARTIFACT_HASH_MISMATCH');
});
