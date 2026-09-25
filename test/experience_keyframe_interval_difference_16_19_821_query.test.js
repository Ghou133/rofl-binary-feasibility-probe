'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { prepareEventQuery, streamEventQuery, prepareBatchEventQuery,
  streamBatchEventQuery } = require('../src/event_query');
const { EXPERIENCE_KEYFRAME_INTERVAL_DIFFERENCE_821_PROFILE: INTERVAL } =
  require('../src/decoders/rofl_16_19_821_experience_keyframe_interval_difference_candidate');
const { PROFILES } = require('../src/decoders/rofl_16_19_821_float_stats_candidate');
const { decodeRuntimeCountByte } =
  require('../src/decoders/rofl_16_19_821_runtime_bytes');

const SNAPSHOT = PROFILES.hero_experience_snapshot;
const BUILD = '16.19.821.7343';
const EVENT = 'experience_keyframe_interval_difference_candidates';
const SOURCE_EVENT = 'hero_experience_snapshot_candidates';
const ASSOCIATION = 'experience_keyframe_interval_difference';
const SOURCE_STATUS = 'CANDIDATE_821_RUNTIME_BYTE_KEYFRAME_F32_AND_REPLAY_TAIL';
const INTERVAL_STATUS = 'CANDIDATE_821_ADJACENT_KEYFRAME_EXPERIENCE_ENDPOINT_DIFFERENCE';

function hash(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

const encodeByte = Array.from({ length: 256 }, (_, value) => value);
function fieldHex(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeFloatLE(value);
  return Buffer.from([...bytes].reverse().map((byte) =>
    encodeByte.find((encoded) => decodeRuntimeCountByte(encoded) === byte))).toString('hex');
}

function ref(replaySha, chunk, time, participant) {
  const rawParam = 0x400000ad + participant;
  const offset = (participant - 1) * 1278;
  return {
    source_path: null, replay_sha256: replaySha,
    chunk_index: chunk, chunk_id: chunk + 1, chunk_stream: 'keyframe',
    chunk_file_offset: chunk * 10000,
    decompressed_block_offset: offset,
    decompressed_payload_offset: offset + 15,
    packet_id: 0x0089, replay_time_ms: time, payload_length: 1263,
    raw_param: rawParam, raw_payload_sha256: hash(`${replaySha}/${chunk}/${participant}`),
  };
}

function snapshotRow(replaySha, chunk, time, participant, value) {
  const rawRef = ref(replaySha, chunk, time, participant);
  return {
    event_type: 'HERO_EXPERIENCE_SNAPSHOT_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: SNAPSHOT.id,
    replay_sha256: replaySha, replay_time_ms: time,
    hero_raw_param: rawRef.raw_param, participant_id_candidate: participant,
    raw_payload_field_bytes_hex: fieldHex(value),
    experience_raw_f32_candidate: value,
    experience_floor_candidate: Math.floor(value),
    decreased_since_previous_snapshot: false,
    observation_kind: 'KEYFRAME_SNAPSHOT', confidence: 'CANDIDATE',
    semantic_status: SOURCE_STATUS,
    field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', hero_raw_param: 'VERIFIED_DIRECT',
      participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
      raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
      experience_raw_f32_candidate: SOURCE_STATUS,
      experience_floor_candidate: SOURCE_STATUS,
      decreased_since_previous_snapshot: SOURCE_STATUS,
    },
    raw_packet_ref: rawRef, known_limits: [...SNAPSHOT.known_limits],
  };
}

function intervalRow(previous, current) {
  const delta = current.experience_raw_f32_candidate
    - previous.experience_raw_f32_candidate;
  return {
    event_type: 'EXPERIENCE_KEYFRAME_INTERVAL_DIFFERENCE_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: INTERVAL.id,
    replay_sha256: current.replay_sha256,
    replay_time_ms: current.replay_time_ms,
    previous_observation_time_ms: previous.replay_time_ms,
    current_observation_time_ms: current.replay_time_ms,
    observation_interval_ms: current.replay_time_ms - previous.replay_time_ms,
    previous_keyframe_chunk_index: previous.raw_packet_ref.chunk_index,
    current_keyframe_chunk_index: current.raw_packet_ref.chunk_index,
    hero_raw_param: current.hero_raw_param,
    participant_id_candidate: current.participant_id_candidate,
    previous_experience_raw_f32_candidate: previous.experience_raw_f32_candidate,
    current_experience_raw_f32_candidate: current.experience_raw_f32_candidate,
    previous_experience_floor_candidate: previous.experience_floor_candidate,
    current_experience_floor_candidate: current.experience_floor_candidate,
    experience_endpoint_delta_f32_candidate: delta,
    experience_endpoint_delta_floor_candidate:
      current.experience_floor_candidate - previous.experience_floor_candidate,
    previous_raw_payload_field_bytes_hex: previous.raw_payload_field_bytes_hex,
    current_raw_payload_field_bytes_hex: current.raw_payload_field_bytes_hex,
    observation_kind: 'ADJACENT_KEYFRAME_SAMPLED_ENDPOINTS',
    observation_scope: 'KEYFRAME_ENDPOINT_DIFFERENCE_ONLY',
    change_time_status: 'UNRESOLVED_WITHIN_INTERVAL',
    confidence: 'CANDIDATE', semantic_status: INTERVAL_STATUS,
    field_confidence: {
      previous_observation_time_ms: 'VERIFIED_DIRECT',
      current_observation_time_ms: 'VERIFIED_DIRECT',
      participant_id_candidate: 'CANDIDATE_KR_821_RAW_PARAM_TAIL_ALIGNMENT',
      previous_raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
      current_raw_payload_field_bytes_hex: 'VERIFIED_DIRECT',
      previous_experience_raw_f32_candidate: SOURCE_STATUS,
      current_experience_raw_f32_candidate: SOURCE_STATUS,
      experience_endpoint_delta_f32_candidate: INTERVAL_STATUS,
      experience_endpoint_delta_floor_candidate: INTERVAL_STATUS,
    },
    raw_packet_ref: current.raw_packet_ref,
    previous_raw_packet_ref: previous.raw_packet_ref,
    current_raw_packet_ref: current.raw_packet_ref,
    raw_packet_refs: [previous.raw_packet_ref, current.raw_packet_ref],
    known_limits: [...INTERVAL.known_limits],
  };
}

function saveArtifact(directory, replaySha, { unavailable = false,
  unchanged = false } = {}) {
  fs.mkdirSync(directory, { recursive: true });
  const frames = [0, 60000, 120000].map((time, index) =>
    Array.from({ length: 10 }, (_, participantIndex) => {
      const participant = participantIndex + 1;
      const value = unchanged ? 0 : participant === 1 ? [0, 1.5, 3.5][index]
        : participant === 2 ? [0, 0, 2][index] : 0;
      return snapshotRow(replaySha, index * 2, time, participant, value);
    }));
  const snapshots = frames.flat();
  const events = [];
  for (let frame = 1; frame < frames.length; frame += 1) {
    for (let participant = 0; participant < 10; participant += 1) {
      const before = frames[frame - 1][participant];
      const after = frames[frame][participant];
      if (after.experience_raw_f32_candidate > before.experience_raw_f32_candidate) {
        events.push(intervalRow(before, after));
      }
    }
  }
  const snapshotResult = {
    profile_id: SNAPSHOT.id, input_packet_id: 0x0089,
    evidence_runtime_image_sha256: SNAPSHOT.evidence_runtime_image_sha256,
    lookup_table_sha256: SNAPSHOT.lookup_table_sha256,
    known_limits: [...SNAPSHOT.known_limits], status: 'CANDIDATE',
    evidence_status: SOURCE_STATUS, input_count: snapshots.length,
    event_count: snapshots.length, keyframe_count: frames.length,
    observed_participant_count: 10, descent_count: 0,
    runtime_image_used: false,
    runtime_image_status: 'STATIC_821_RUNTIME_TRANSFORM_EMBEDDED',
  };
  const intervalResult = unavailable ? {
    profile_id: INTERVAL.id, status: 'MISSING_INPUT', event_count: null,
    error: 'source association unavailable',
  } : {
    profile_id: INTERVAL.id,
    evidence_runtime_image_sha256: INTERVAL.evidence_runtime_image_sha256,
    lookup_table_sha256: INTERVAL.lookup_table_sha256,
    depends_on: [...INTERVAL.depends_on], known_limits: [...INTERVAL.known_limits],
    status: 'CANDIDATE', evidence_status: INTERVAL_STATUS,
    replay_sha256: replaySha, input_count: snapshots.length,
    keyframe_count: frames.length, observed_interval_count: 20,
    changed_interval_count: events.length,
    unchanged_interval_count: 20 - events.length,
    verified_raw_packet_count: snapshots.length, event_count: events.length,
  };
  const capability_results = { hero_experience_snapshot: snapshotResult };
  const candidate_associations = { [ASSOCIATION]: intervalResult };
  const semantic = {
    replay_version: BUILD, replay_sha256: replaySha,
    container_status: 'PASS', status: unavailable ? 'PARTIAL' : 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE',
    requested_capabilities: ['hero_experience_snapshot'],
    capability_results, candidate_associations,
  };
  const rows = { [SOURCE_EVENT]: snapshots };
  if (!unavailable) rows[EVENT] = events;
  const event_counts = Object.fromEntries(Object.entries(rows).map(([key, value]) =>
    [key, value.length]));
  const event_jsonl_files = Object.fromEntries(Object.keys(rows).map((key) =>
    [key, `${key}.jsonl`]));
  const analysis = {
    source_path: null, replay_version: BUILD, replay_sha256: replaySha,
    patch: '16.19', event_storage: 'JSONL_ONLY', event_counts,
    event_jsonl_files, events: null,
    semantic: { capability_results, candidate_associations },
  };
  fs.writeFileSync(path.join(directory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(directory, 'replay_analysis.json'), JSON.stringify(analysis));
  for (const [key, value] of Object.entries(rows)) {
    fs.writeFileSync(path.join(directory, `${key}.jsonl`),
      value.map((row) => `${JSON.stringify(row)}\n`).join(''));
  }
  return { directory, replaySha, events, snapshots };
}

function batch(t, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-exp-interval-batch-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const first = saveArtifact(path.join(directory, 'replays', 'first'), 'a'.repeat(64));
  const second = saveArtifact(path.join(directory, 'replays', 'second'), 'b'.repeat(64),
    { unavailable: options.unavailable });
  const replay_inputs = [first, second].map((entry, index) => ({
    artifact_directory: `replays/${index === 0 ? 'first' : 'second'}`,
    sha256: entry.replaySha, version: BUILD,
  }));
  const output_hashes_excluding_manifest = {};
  for (const entry of replay_inputs) {
    for (const name of fs.readdirSync(path.join(directory, entry.artifact_directory))) {
      const relative = `${entry.artifact_directory}/${name}`;
      output_hashes_excluding_manifest[relative] =
        hash(fs.readFileSync(path.join(directory, relative)));
    }
  }
  fs.writeFileSync(path.join(directory, 'manifest.json'), JSON.stringify({
    command_args: ['batch', 'synthetic-input'], replay_inputs,
    output_hashes_excluding_manifest,
  }));
  return { directory, first, second };
}

async function collect(prepared, options = {}) {
  const lines = [];
  const summary = await streamEventQuery(prepared, options,
    async (line) => lines.push(line));
  return { lines, summary };
}

test('experience interval query filters sampled endpoints and preserves raw JSONL lines', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-exp-interval-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const artifact = saveArtifact(directory, 'a'.repeat(64));
  const prepared = prepareEventQuery(directory, EVENT);
  const all = await collect(prepared);
  assert.equal(all.summary.query_status, 'COMPLETE');
  assert.equal(all.summary.scanned_count, 3);
  assert.equal(all.summary.matched_count, 3);
  assert.deepEqual(all.lines, artifact.events.map((row) => `${JSON.stringify(row)}\n`));
  const bounded = await collect(prepared, { fromMs: 60000, toMs: 60000,
    participant: 1, limit: 1 });
  assert.equal(bounded.summary.scanned_count, 3);
  assert.equal(bounded.summary.matched_count, 1);
  assert.deepEqual(bounded.lines, [`${JSON.stringify(artifact.events[0])}\n`]);
  const latest = await collect(prepared, { participant: 1,
    latestPerParticipant: true, toMs: 120000 });
  assert.equal(latest.summary.selected_count, 1);
  assert.deepEqual(latest.lines, [`${JSON.stringify(artifact.events[1])}\n`]);
  assert.equal((await collect(prepared, { participant: 3 })).summary.matched_count, 0);
});

test('experience interval query accepts an unchanged-only sampled source', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-exp-unchanged-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  saveArtifact(directory, 'a'.repeat(64), { unchanged: true });
  const result = await collect(prepareEventQuery(directory, EVENT),
    { latestPerParticipant: true });
  assert.equal(result.summary.scanned_count, 0);
  assert.equal(result.summary.matched_count, 0);
  assert.deepEqual(result.lines, []);
});

test('experience interval query rejects corrupted row, source bytes and metadata', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-exp-invalid-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  saveArtifact(directory, 'a'.repeat(64));
  const eventPath = path.join(directory, `${EVENT}.jsonl`);
  let rows = fs.readFileSync(eventPath, 'utf8').trim().split('\n').map(JSON.parse);
  rows[0].experience_endpoint_delta_f32_candidate = 9;
  fs.writeFileSync(eventPath, rows.map((row) => `${JSON.stringify(row)}\n`).join(''));
  await assert.rejects(collect(prepareEventQuery(directory, EVENT)),
    { code: 'INVALID_EVENT_ROW' });

  saveArtifact(directory, 'a'.repeat(64));
  const sourcePath = path.join(directory, `${SOURCE_EVENT}.jsonl`);
  rows = fs.readFileSync(sourcePath, 'utf8').trim().split('\n').map(JSON.parse);
  rows[10].raw_payload_field_bytes_hex = '00000000';
  fs.writeFileSync(sourcePath, rows.map((row) => `${JSON.stringify(row)}\n`).join(''));
  await assert.rejects(collect(prepareEventQuery(directory, EVENT)),
    { code: 'INVALID_EVENT_ROW' });

  saveArtifact(directory, 'a'.repeat(64));
  const semanticPath = path.join(directory, 'semantic_run.json');
  const semantic = JSON.parse(fs.readFileSync(semanticPath, 'utf8'));
  semantic.candidate_associations[ASSOCIATION].unchanged_interval_count = 18;
  fs.writeFileSync(semanticPath, JSON.stringify(semantic));
  assert.throws(() => prepareEventQuery(directory, EVENT),
    { code: 'ASSOCIATION_METADATA_MISMATCH' });
});

test('batch experience interval query reports unavailable Replay and checks source hash', async (t) => {
  const saved = batch(t, { unavailable: true });
  const prepared = prepareBatchEventQuery(saved.directory, EVENT);
  const lines = [];
  const summary = await streamBatchEventQuery(prepared,
    { latestPerParticipant: true, limit: 1 }, async (line) => lines.push(line));
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.completed_replay_count, 1);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.selected_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(lines.length, 1);
  assert.equal(summary.replay_results[1].code, 'ASSOCIATION_UNAVAILABLE');
  fs.appendFileSync(path.join(saved.first.directory, `${SOURCE_EVENT}.jsonl`), '\n');
  assert.throws(() => prepareBatchEventQuery(saved.directory, EVENT),
    { code: 'ARTIFACT_HASH_MISMATCH' });
});
