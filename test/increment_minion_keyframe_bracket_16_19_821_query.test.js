'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { prepareEventQuery, streamEventQuery, prepareBatchEventQuery,
  streamBatchEventQuery } = require('../src/event_query');
const { INCREMENT_MINION_KEYFRAME_BRACKET_821_PROFILE: BRACKET } =
  require('../src/decoders/rofl_16_19_821_increment_minion_keyframe_bracket_candidate');
const { INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821: PACKET } =
  require('../src/decoders/rofl_16_19_821_increment_minion_kills_packet_candidate');
const { PROFILES } = require('../src/decoders/rofl_16_19_821_float_stats_candidate');
const { LOOKUP_TABLE_SHA256 } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');

const BUILD = '16.19.821.7343';
const EVENT = 'increment_minion_keyframe_bracket_candidates';
const PACKET_EVENT = 'increment_minion_kills_packet_candidates';
const SNAPSHOT_EVENT = 'hero_minions_killed_snapshot_candidates';
const SNAPSHOT = PROFILES.hero_minions_killed_snapshot;
const SHA = 'a'.repeat(64);

function hash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function ref(replaySha, chunk, stream, time, offset, packetId, param, length,
  payloadHash = hash(`${chunk}/${offset}/${param}`)) {
  return { source_path: null, replay_sha256: replaySha, chunk_index: chunk,
    chunk_id: chunk + 1, chunk_stream: stream, chunk_file_offset: chunk * 1000,
    decompressed_block_offset: offset, decompressed_payload_offset: offset + 15,
    packet_id: packetId, replay_time_ms: time, payload_length: length,
    raw_param: param, raw_payload_sha256: payloadHash };
}

function savedArtifact(directory, replaySha = SHA, missingImage = false) {
  fs.mkdirSync(directory, { recursive: true });
  const packetPayload = '3e8b18';
  const packetRefs = [ref(replaySha, 1, 'game_chunk', 1000, 0, 0x03a7,
    0x400000ae, 3, hash(Buffer.from(packetPayload, 'hex'))),
  ref(replaySha, 1, 'game_chunk', 1500, 20, 0x03a7, 0x400000ae, 3,
    hash(Buffer.from(packetPayload, 'hex')))];
  const packetRows = packetRefs.map((packetRef) => ({
    event_type: 'INCREMENT_MINION_KILLS_PACKET_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: PACKET.id,
    replay_sha256: replaySha, replay_time_ms: packetRef.replay_time_ms,
    raw_param: 0x400000ae, raw_payload_hex: packetPayload, raw_selector_byte: 0x3e,
    native_object_lookup_key_bytes_hex: '8bd7d7e7',
    callback_lookup_key_candidate: 0x400000ae,
    callback_lookup_key_matches_raw_param: true,
    conditional_counter_write_status: 'UNKNOWN',
    semantic_cs_effect_status: 'UNKNOWN', confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_LOOKUP_KEY',
    raw_packet_ref: packetRef,
  }));
  const snapshots = [];
  for (const [chunk, time] of [[0, 1000], [2, 2000]]) {
    for (let participant = 1; participant <= 10; participant += 1) {
      const rawParam = 0x400000ad + participant;
      const value = chunk === 0 && participant === 1 ? 1 : 0;
      snapshots.push({
        event_type: 'HERO_MINIONS_KILLED_SNAPSHOT_CANDIDATE',
        game_version: BUILD, patch: '16.19', build_profile: SNAPSHOT.id,
        replay_sha256: replaySha, replay_time_ms: time,
        hero_raw_param: rawParam, participant_id_candidate: participant,
        raw_payload_field_bytes_hex: value === 1 ? 'e8a79797' : '97979797',
        minions_killed_raw_f32_candidate: value,
        minions_killed_floor_candidate: value,
        decreased_since_previous_snapshot: chunk === 2 && participant === 1,
        observation_kind: 'KEYFRAME_SNAPSHOT', confidence: 'CANDIDATE',
        semantic_status: 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL',
        raw_packet_ref: ref(replaySha, chunk, 'keyframe', time,
          (participant - 1) * 1278, 0x0089, rawParam, 1263),
      });
    }
  }
  const previousRef = snapshots[0].raw_packet_ref;
  const currentRef = snapshots[10].raw_packet_ref;
  const bracketRow = {
    event_type: 'INCREMENT_MINION_KEYFRAME_BRACKET_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: BRACKET.id,
    replay_sha256: replaySha, replay_time_ms: 1500, raw_param: 0x400000ae,
    callback_lookup_key_candidate: 0x400000ae, participant_id_candidate: 1,
    previous_observation_time_ms: 1000, current_observation_time_ms: 2000,
    observation_interval_ms: 1000, packet_offset_from_previous_ms: 500,
    packet_offset_to_current_ms: 500,
    previous_snapshot_minions_killed_candidate: 1,
    current_snapshot_minions_killed_candidate: 0,
    observed_endpoint_delta_candidate: -1,
    observation_kind: 'SAME_KEY_STRICT_ADJACENT_KEYFRAME_BRACKET',
    live_lookup_status: 'UNKNOWN', semantic_cs_effect_status: 'UNKNOWN',
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_821_PACKET_KEY_AND_ADJACENT_MINIONS_KEYFRAME_BRACKET',
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      callback_lookup_key_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
      participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
      previous_snapshot_minions_killed_candidate:
        'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL',
      current_snapshot_minions_killed_candidate:
        'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL',
      observed_endpoint_delta_candidate: 'DERIVED_FROM_CANDIDATE_ENDPOINTS',
    },
    raw_packet_ref: packetRefs[1],
    increment_minion_kills_raw_packet_ref: packetRefs[1],
    previous_snapshot_raw_packet_ref: previousRef,
    current_snapshot_raw_packet_ref: currentRef,
    raw_packet_refs: [packetRefs[1], previousRef, currentRef],
  };
  const packetResult = missingImage ? { status: 'MISSING_INPUT',
    missing_input: 'exact runtime image' } : {
    profile_id: PACKET.id, input_packet_id: 0x03a7,
    evidence_runtime_image_sha256: PACKET.evidence_runtime_image_sha256,
    evidence_callback_transform_sha256: PACKET.evidence_callback_transform_sha256,
    status: 'CANDIDATE', evidence_status: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_LOOKUP_KEY',
    known_limits: [...PACKET.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      raw_payload_hex: 'VERIFIED_DIRECT', raw_selector_byte: 'VERIFIED_DIRECT',
      native_object_lookup_key_bytes_hex: 'CANDIDATE_EXACT_RUNTIME_FIELD',
      callback_lookup_key_candidate: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_TRANSFORM',
    },
    input_count: 2, event_count: 2, scanned_block_count: 22,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: PACKET.evidence_runtime_image_sha256,
  };
  const snapshotResult = {
    profile_id: SNAPSHOT.id, input_packet_id: 0x0089,
    evidence_runtime_image_sha256: BRACKET.evidence_runtime_image_sha256,
    lookup_table_sha256: LOOKUP_TABLE_SHA256,
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL',
    input_count: 20, event_count: 20, keyframe_count: 2,
    observed_participant_count: 10, descent_count: 1,
    runtime_image_used: false,
    runtime_image_status: 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED',
  };
  const association = missingImage ? { status: 'MISSING_INPUT',
    missing_input: 'increment_minion_kills_packet' } : {
    profile_id: BRACKET.id,
    evidence_runtime_image_sha256: BRACKET.evidence_runtime_image_sha256,
    depends_on: [...BRACKET.depends_on], known_limits: [...BRACKET.known_limits],
    status: 'CANDIDATE',
    evidence_status: bracketRow.semantic_status, replay_sha256: replaySha,
    packet_count: 2, snapshot_count: 20, keyframe_count: 2,
    observed_interval_count: 10, bracketed_packet_count: 1,
    distinct_bracket_count: 1, unbracketed_packet_count: 1,
    unbracketed_packets: [{ replay_time_ms: 1000, raw_param: 0x400000ae,
      reason: 'ON_KEYFRAME_BOUNDARY', raw_packet_ref: packetRefs[0] }],
    verified_raw_packet_count: 22, event_count: 1,
  };
  const capability_results = {
    increment_minion_kills_packet: packetResult,
    hero_minions_killed_snapshot: snapshotResult,
  };
  const candidate_associations = { increment_minion_keyframe_bracket: association };
  const semantic = {
    replay_version: BUILD, replay_sha256: replaySha, container_status: 'PASS',
    status: missingImage ? 'PARTIAL' : 'PASS',
    requested_capabilities: [...BRACKET.depends_on], capability_results,
    candidate_associations,
  };
  const event_counts = { [SNAPSHOT_EVENT]: 20 };
  const event_jsonl_files = { [SNAPSHOT_EVENT]: `${SNAPSHOT_EVENT}.jsonl` };
  if (!missingImage) {
    event_counts[PACKET_EVENT] = 2;
    event_counts[EVENT] = 1;
    event_jsonl_files[PACKET_EVENT] = `${PACKET_EVENT}.jsonl`;
    event_jsonl_files[EVENT] = `${EVENT}.jsonl`;
  }
  const analysis = {
    source_path: null, replay_sha256: replaySha, replay_version: BUILD,
    patch: '16.19', event_storage: 'JSONL_ONLY', event_counts, event_jsonl_files,
    semantic: { capability_results, candidate_associations },
  };
  fs.writeFileSync(path.join(directory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(directory, 'replay_analysis.json'), JSON.stringify(analysis));
  const writeRows = (key, rows) => fs.writeFileSync(path.join(directory,
    `${key}.jsonl`), rows.map((row) => `${JSON.stringify(row)}\n`).join(''));
  writeRows(SNAPSHOT_EVENT, snapshots);
  if (!missingImage) {
    writeRows(PACKET_EVENT, packetRows);
    writeRows(EVENT, [bracketRow]);
  }
  return { bracketRow };
}

async function collect(prepared, options = {}) {
  const lines = [];
  const summary = await streamEventQuery(prepared, options,
    async (line) => lines.push(line));
  return { lines, summary };
}

test('saved exact-821 bracket query preserves raw line and negative endpoint evidence', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-minion-query-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const { bracketRow } = savedArtifact(directory);
  const prepared = prepareEventQuery(directory, EVENT);
  const selected = await collect(prepared, {
    fromMs: 1400, toMs: 1600, participant: 1, rawParam: 0x400000ae,
  });
  assert.equal(selected.summary.query_status, 'COMPLETE');
  assert.equal(selected.summary.scanned_count, 1);
  assert.equal(selected.summary.matched_count, 1);
  assert.deepEqual(selected.lines, [`${JSON.stringify(bracketRow)}\n`]);
  assert.equal(bracketRow.observed_endpoint_delta_candidate, -1);
  assert.equal((await collect(prepared, { participant: 2 })).summary.matched_count, 0);
  assert.equal((await collect(prepared, { rawParam: 0x400000af })).summary.matched_count, 0);
});

test('saved bracket query rejects changed endpoint value and excluded packet metadata', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-minion-corrupt-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  savedArtifact(directory);
  const filename = path.join(directory, `${EVENT}.jsonl`);
  const row = JSON.parse(fs.readFileSync(filename, 'utf8'));
  row.observed_endpoint_delta_candidate = 1;
  fs.writeFileSync(filename, `${JSON.stringify(row)}\n`);
  await assert.rejects(collect(prepareEventQuery(directory, EVENT)),
    { code: 'INVALID_EVENT_ROW' });
  savedArtifact(directory);
  const semanticFile = path.join(directory, 'semantic_run.json');
  const semantic = JSON.parse(fs.readFileSync(semanticFile, 'utf8'));
  semantic.candidate_associations.increment_minion_keyframe_bracket
    .unbracketed_packet_count = 0;
  fs.writeFileSync(semanticFile, JSON.stringify(semantic));
  assert.throws(() => prepareEventQuery(directory, EVENT),
    { code: 'ASSOCIATION_METADATA_MISMATCH' });
  savedArtifact(directory);
  const snapshotFile = path.join(directory, `${SNAPSHOT_EVENT}.jsonl`);
  const snapshots = fs.readFileSync(snapshotFile, 'utf8').trim().split('\n')
    .map(JSON.parse);
  snapshots[0].minions_killed_raw_f32_candidate = 2;
  fs.writeFileSync(snapshotFile,
    snapshots.map((snapshot) => `${JSON.stringify(snapshot)}\n`).join(''));
  await assert.rejects(collect(prepareEventQuery(directory, EVENT)),
    { code: 'INVALID_EVENT_ROW' });
});

test('batch bracket query reports missing-image Replay as partial', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-minion-batch-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const available = path.join(directory, 'replays', 'available');
  const missing = path.join(directory, 'replays', 'missing');
  savedArtifact(available);
  savedArtifact(missing, 'b'.repeat(64), true);
  const hashes = {};
  for (const name of ['available', 'missing']) {
    const replayDir = path.join(directory, 'replays', name);
    for (const file of fs.readdirSync(replayDir)) {
      hashes[`replays/${name}/${file}`] = hash(fs.readFileSync(path.join(replayDir, file)));
    }
  }
  fs.writeFileSync(path.join(directory, 'manifest.json'), JSON.stringify({
    command_args: ['batch'], replay_inputs: [
      { artifact_directory: 'replays/available', sha256: SHA, version: BUILD },
      { artifact_directory: 'replays/missing', sha256: 'b'.repeat(64), version: BUILD },
    ], output_hashes_excluding_manifest: hashes,
  }));
  const lines = [];
  const summary = await streamBatchEventQuery(prepareBatchEventQuery(directory, EVENT),
    {}, async (line) => lines.push(line));
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.scanned_count, 1);
  assert.equal(lines.length, 1);
  assert.equal(summary.replay_results[1].query_status, 'UNAVAILABLE');
});
