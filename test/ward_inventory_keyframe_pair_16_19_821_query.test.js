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
const { HERO_WARD_STATS_SNAPSHOT_821_CANDIDATE_PROFILE: WARD_PROFILE } =
  require('../src/decoders/rofl_16_19_821_aux_counts_candidate');
const { HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE_PROFILE_821: BROADCAST_PROFILE } =
  require('../src/decoders/rofl_16_19_821_inventory_broadcast_packet_candidate');
const { RUNTIME_IMAGE_SHA256, LOOKUP_TABLE_SHA256 } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');
const { associateWardInventoryKeyframePairCandidates821: associate } =
  require('../src/decoders/rofl_16_19_821_ward_inventory_keyframe_pair_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const BUILD = '16.19.821.7343';
const EVENT = 'ward_inventory_keyframe_pair_candidates';
const ASSOCIATION = 'ward_inventory_keyframe_pair';
const WARD_EVENT = 'hero_ward_stats_snapshot_candidates';
const BROADCAST_EVENT = 'hero_inventory_broadcast_packet_candidates';

function packet(id, param, body, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(body.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param >>> 0, 11);
  return Buffer.concat([header, body]);
}

function wardPayload() {
  const body = Buffer.alloc(1263, 0x97);
  Buffer.from('6700de', 'hex').copy(body);
  return body;
}

function broadcastPayload(seed) {
  const body = Buffer.alloc(79, seed);
  body[0] = 0x1e;
  return body;
}

function packetRef(replay, block, chunk) {
  return {
    source_path: replay.source_path ?? null,
    replay_sha256: replay.source_sha256,
    chunk_index: chunk.index, chunk_id: chunk.chunk_id,
    chunk_stream: chunk.stream, chunk_file_offset: chunk.offset,
    decompressed_block_offset: block.offset,
    decompressed_payload_offset: block.payload_offset,
    packet_id: block.packet_id,
    replay_time_ms: block.timestamp_ms,
    payload_length: block.payload_length,
    raw_param: block.param >>> 0,
    raw_payload_sha256: crypto.createHash('sha256').update(block.payload).digest('hex'),
  };
}

function inventoryRecords(frame, participant, stream) {
  const count = stream === 'keyframe' ? 10 : 6;
  const slotBytes = ['c1', '15', '9f', '2e', 'f6', '6b', 'db', '68', '46', 'd4'];
  return Array.from({ length: count }, (_, slot) => {
    let item = 0;
    if (slot === 6) {
      item = frame === 0 && participant === 1 ? 3340
        : frame === 1 && participant === 2 ? 3340 : 1001;
    }
    if (frame === 1 && participant === 1 && slot === 0) item = 3340;
    return {
      record_index: slot, slot_candidate: slot, item_id_candidate: item,
      emulated_object_slot_byte_hex: slotBytes[slot],
      emulated_object_item_id_bytes_hex: item === 3340 ? '0eb8eaea'
        : item === 1001 ? 'f248eaea' : 'eaeaeaea',
    };
  });
}

function slotSnapshot(records) {
  const values = new Map(records.map((row) => [row.slot_candidate, row.item_id_candidate]));
  return Array.from({ length: 10 }, (_, slot) => ({
    slot_candidate: slot,
    item_id_candidate: values.get(slot) ?? null,
    value_basis: values.has(slot) ? 'DECODED_PACKET_RECORD'
      : 'CALLBACK_RESET_WITH_NO_PACKET_RECORD',
  }));
}

function sourceOutcomes(seed = 0) {
  const chunks = [0, 1].map((frame) => {
    const body = [];
    for (let participant = 1; participant <= 10; participant += 1) {
      const param = 0x400000ad + participant;
      body.push(packet(0x0357, param, broadcastPayload(seed + frame + participant),
        (frame + 1) * 1000));
      body.push(packet(0x0089, param, wardPayload(), (frame + 1) * 1000));
    }
    return { stream: 2, body: Buffer.concat(body) };
  });
  // It shares time and raw param with the first keyframe, but is not a pair.
  chunks.push({ stream: 1, body: packet(0x0357, 0x400000ae,
    broadcastPayload(seed + 99), 1000) });
  const replay = replayFromChunks(chunks, BUILD);
  const wardEvents = [];
  const broadcastEvents = [];
  walkBlocks(replay, (block, chunk) => {
    const rawRef = packetRef(replay, block, chunk);
    const participant = (block.param >>> 0) - 0x400000ad;
    if (block.packet_id === 0x0089) {
      wardEvents.push({
        event_type: 'HERO_WARD_STATS_SNAPSHOT_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: WARD_PROFILE.id,
        replay_sha256: replay.source_sha256,
        replay_time_ms: block.timestamp_ms, hero_raw_param: block.param >>> 0,
        participant_id_candidate: participant,
        ward_placed_detector_candidate: 0, ward_killed_candidate: 0,
        ward_placed_candidate: 0,
        raw_ward_placed_detector_byte: 0x97,
        raw_ward_killed_byte: 0x97, raw_ward_placed_byte: 0x97,
        observation_kind: 'KEYFRAME_SNAPSHOT', confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_821_RUNTIME_KEYFRAME_BYTE_AND_REPLAY_TAIL',
        field_confidence: {}, raw_packet_ref: rawRef,
      });
    } else {
      const frame = chunk.stream === 'keyframe' ? chunk.index : 0;
      const records = inventoryRecords(frame, participant, chunk.stream);
      broadcastEvents.push({
        event_type: 'HERO_INVENTORY_BROADCAST_PACKET_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: BROADCAST_PROFILE.id,
        replay_sha256: replay.source_sha256,
        replay_time_ms: block.timestamp_ms, hero_raw_param: block.param >>> 0,
        participant_id_candidate: participant, packet_stream: chunk.stream,
        snapshot_application: 'RESET_SLOTS_0_TO_9_THEN_APPLY_RECORDS',
        record_count: records.length, records_candidate: records,
        packet_slot_snapshot_candidate: slotSnapshot(records),
        confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS',
        field_confidence: {}, raw_packet_ref: rawRef,
      });
    }
  }, { strict: true });
  const wardStatsOutcome = {
    status: 'CANDIDATE', profile_id: WARD_PROFILE.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    runtime_image_used: false,
    runtime_image_status: 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED',
    evidence_status: 'CANDIDATE_821_RUNTIME_KEYFRAME_BYTE_AND_REPLAY_TAIL',
    input_packet_id: 0x0089, input_count: 20, event_count: 20,
    observed_participant_count: 10, events: wardEvents,
  };
  const inventoryBroadcastOutcome = {
    status: 'CANDIDATE', profile_id: BROADCAST_PROFILE.id,
    evidence_runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_image_sha256: RUNTIME_IMAGE_SHA256,
    runtime_image_used: true, runtime_image_status: 'MATCHED_USED',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_BROADCAST_PACKET_FIELDS',
    input_packet_id: 0x0357, input_count: 21, event_count: 21,
    decoded_record_count: 206, events: broadcastEvents,
  };
  const result = associate(replay, { wardStatsOutcome, inventoryBroadcastOutcome });
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.event_count, 20);
  assert.equal(result.excluded_game_broadcast_count, 1);
  return { replay, wardStatsOutcome, inventoryBroadcastOutcome, association: result };
}

function withoutEvents(result) {
  const copy = structuredClone(result);
  delete copy.events;
  return copy;
}

function writeReplayArtifact(root, name, source, { imageMissing = false } = {}) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const association = imageMissing
    ? { profile_id: source.association.profile_id,
      status: 'MISSING_INPUT', event_count: null, events: null,
      error: 'exact runtime image missing' }
    : withoutEvents(source.association);
  const wardResult = withoutEvents(source.wardStatsOutcome);
  wardResult.runtime_image_status = 'PROVIDED_NOT_USED';
  const broadcastResult = imageMissing
    ? { ...withoutEvents(source.inventoryBroadcastOutcome),
      status: 'MISSING_INPUT', event_count: null, runtime_image_used: false,
      runtime_image_status: 'MISSING', missing_input: 'runtime_image' }
    : withoutEvents(source.inventoryBroadcastOutcome);
  const capabilityResults = {
    hero_ward_stats_snapshot: wardResult,
    hero_inventory_broadcast_packet: broadcastResult,
  };
  const semantic = {
    replay_version: BUILD, replay_sha256: source.replay.source_sha256,
    container_status: 'PASS', status: imageMissing ? 'PARTIAL' : 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE',
    requested_capabilities: ['hero_ward_stats_snapshot', 'hero_inventory_broadcast_packet'],
    capability_results: capabilityResults,
    candidate_associations: { [ASSOCIATION]: association },
  };
  const rows = imageMissing ? {} : {
    [WARD_EVENT]: source.wardStatsOutcome.events,
    [BROADCAST_EVENT]: source.inventoryBroadcastOutcome.events,
    [EVENT]: source.association.events,
  };
  if (imageMissing) rows[WARD_EVENT] = source.wardStatsOutcome.events;
  const eventCounts = Object.fromEntries(Object.entries(rows).map(([key, value]) =>
    [key, value.length]));
  const analysis = {
    patch: '16.19', replay_version: BUILD, replay_sha256: source.replay.source_sha256,
    event_counts: eventCounts, event_storage: 'JSONL_ONLY',
    event_jsonl_files: Object.fromEntries(Object.keys(rows).map((key) =>
      [key, `${key}.jsonl`])),
    events: null,
    semantic: {
      status: semantic.status, requested_capabilities: semantic.requested_capabilities,
      capability_results: capabilityResults,
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
    eventPath: path.join(directory, `${EVENT}.jsonl`) };
}

function fixture(t, { batch = false, partial = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-ward-inventory-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const first = writeReplayArtifact(root, 'first', sourceOutcomes(1));
  let second = null;
  if (batch) {
    second = writeReplayArtifact(root, 'second', sourceOutcomes(2),
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
  const document = JSON.parse(fs.readFileSync(filename, 'utf8'));
  edit(document);
  fs.writeFileSync(filename, JSON.stringify(document));
}

test('query-events filters paired ward/inventory observations without changing JSONL', (t) => {
  const { first } = fixture(t);
  const selected = query(first.directory, '--participant', '1',
    '--from-ms', '1000', '--to-ms', '1000', '--raw-param', '0x400000ae',
    '--item-id', '3340', '--slot', '6');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${first.lines[0]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.scanned_count, 20);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.rows_unmodified, true);

  // p1's later row has item 3340 in slot 0 and item 1001 in slot 6.
  const sameRecord = query(first.directory, '--participant', '1',
    '--from-ms', '2000', '--item-id', '3340', '--slot', '6');
  assert.equal(sameRecord.status, 0, sameRecord.stderr);
  assert.equal(sameRecord.stdout, '');
  assert.equal(JSON.parse(sameRecord.stderr).matched_count, 0);

  const zero = query(first.directory, '--participant', '2',
    '--from-ms', '1000', '--to-ms', '1000', '--item-id', '0', '--slot', '0');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${first.lines[1]}\n`);
  assert.equal(fs.readFileSync(first.eventPath, 'utf8'), `${first.lines.join('\n')}\n`);
});

test('latest-per-participant chooses the last matching row from each Replay', (t) => {
  const { first } = fixture(t);
  const latest = query(first.directory, '--latest-per-participant', '--to-ms', '2000');
  assert.equal(latest.status, 0, latest.stderr);
  assert.deepEqual(latest.stdout.trimEnd().split('\n'), first.lines.slice(10));
  const summary = JSON.parse(latest.stderr);
  assert.equal(summary.scanned_count, 20);
  assert.equal(summary.matched_count, 20);
  assert.equal(summary.selected_count, 10);
  assert.equal(summary.emitted_count, 10);
  assert.equal(summary.rows_unmodified, true);

  const matching = query(first.directory, '--latest-per-participant',
    '--item-id', '3340', '--slot', '6');
  assert.equal(matching.status, 0, matching.stderr);
  assert.deepEqual(matching.stdout.trimEnd().split('\n'),
    [first.lines[0], first.lines[11]]);
  assert.equal(JSON.parse(matching.stderr).selected_count, 2);
});

test('query-events fails closed on association, dependency, and raw-ref corruption', (t) => {
  const { root, first } = fixture(t);
  const originalSemantic = fs.readFileSync(first.semanticPath, 'utf8');
  const originalAnalysis = fs.readFileSync(first.analysisPath, 'utf8');
  const originalRows = fs.readFileSync(first.eventPath, 'utf8');
  const restore = () => {
    fs.writeFileSync(first.semanticPath, originalSemantic);
    fs.writeFileSync(first.analysisPath, originalAnalysis);
    fs.writeFileSync(first.eventPath, originalRows);
  };
  const reject = (expectedCode) => {
    const output = path.join(root, 'must-not-exist.jsonl');
    const result = query(first.directory, '--output', output);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, expectedCode);
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
      const dependency = file === first.semanticPath
        ? document.capability_results.hero_inventory_broadcast_packet
        : document.semantic.capability_results.hero_inventory_broadcast_packet;
      dependency.status = 'MISSING_INPUT';
      dependency.event_count = null;
    });
  }
  reject('CAPABILITY_UNAVAILABLE');

  const altered = originalRows.trim().split(/\r?\n/).map(JSON.parse);
  altered[0].ward_stats_raw_packet_ref.raw_payload_sha256 = 'f'.repeat(64);
  fs.writeFileSync(first.eventPath, `${altered.map(JSON.stringify).join('\n')}\n`);
  reject('INVALID_EVENT_ROW');

  const conflicting = originalRows.trim().split(/\r?\n/).map(JSON.parse);
  conflicting[0].inventory_records_candidate[6].item_id_candidate = 9999;
  fs.writeFileSync(first.eventPath, `${conflicting.map(JSON.stringify).join('\n')}\n`);
  reject('INVALID_EVENT_ROW');
});

test('batch query remains partial when one association has no runtime image', (t) => {
  const { root, first } = fixture(t, { batch: true, partial: true });
  const result = query(root, '--participant', '1', '--limit', '1');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${first.lines[0]}\n`);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.replay_count, 2);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.scanned_count, 20);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.replay_results[1].code, 'ASSOCIATION_UNAVAILABLE');
});
