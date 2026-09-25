'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { FACE_DIRECTION_KEYFRAME_ROSTER_PAIR_821_PROFILE: PROFILE } =
  require('../src/decoders/rofl_16_19_821_face_direction_keyframe_roster_pair_candidate');
const { transformFaceDirectionVectorBytes821 } =
  require('../src/decoders/rofl_16_19_821_face_direction_packet_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const CAPABILITY = 'face_direction_keyframe_roster_pair';
const EVENT = 'face_direction_keyframe_roster_pair_candidates';
const REPLAY_SHA = 'a'.repeat(64);
const FACE_HEX = '83230dd6f1f241e5e7dfdb8785';
const FACE_SHA = crypto.createHash('sha256')
  .update(Buffer.from(FACE_HEX, 'hex')).digest('hex');

function ref(packetId, rawParam, offset, length, hash) {
  return { source_path: null, replay_sha256: REPLAY_SHA,
    chunk_index: 0, chunk_id: 1, chunk_stream: 'keyframe',
    chunk_file_offset: 100, decompressed_block_offset: offset,
    decompressed_payload_offset: offset + 15,
    packet_id: packetId, replay_time_ms: 1000,
    payload_length: length, raw_param: rawParam,
    raw_payload_sha256: hash };
}

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-face-roster-query-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const vectorBytes = transformFaceDirectionVectorBytes821(Buffer.from(FACE_HEX, 'hex'));
  const vector = { x: vectorBytes.readFloatLE(0), y: vectorBytes.readFloatLE(4),
    z: vectorBytes.readFloatLE(8) };
  const rows = Array.from({ length: 10 }, (_, index) => {
    const rawParam = 0x400000ae + index;
    const statsRef = ref(0x0089, rawParam, index * 1278, 1263, 'b'.repeat(64));
    const faceRef = ref(0x038e, rawParam, 10 * 1278 + index * 28, 13, FACE_SHA);
    return {
      event_type: 'FACE_DIRECTION_KEYFRAME_ROSTER_PAIR_CANDIDATE',
      game_version: PROFILE.replay_version, patch: '16.19',
      build_profile: PROFILE.id, replay_sha256: REPLAY_SHA,
      replay_time_ms: 1000, keyframe_chunk_index: 0,
      hero_raw_param: rawParam, hero_stats_participant_id_candidate: index + 1,
      face_raw_payload_hex: FACE_HEX, face_raw_selector_byte: 0x83,
      packet_vector_xyz_f32_candidate: vector,
      pair_basis: 'SAME_KEYFRAME_CHUNK_TIME_FULL_RAW_PARAM_STATS_BEFORE_FACE',
      actor_assignment_status: 'UNKNOWN',
      semantic_direction_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE', semantic_status: PROFILE.evidence_status,
      hero_stats_raw_packet_ref: statsRef, face_direction_raw_packet_ref: faceRef,
      raw_packet_refs: [statsRef, faceRef],
    };
  });
  const capabilityResult = {
    status: 'CANDIDATE', profile_id: PROFILE.id,
    evidence_status: PROFILE.evidence_status,
    replay_sha256: REPLAY_SHA,
    evidence_runtime_image_sha256: PROFILE.evidence_runtime_image_sha256,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: PROFILE.evidence_runtime_image_sha256,
    depends_on: [...PROFILE.depends_on], known_limits: [...PROFILE.known_limits],
    dependency_statuses: { face_direction_packet: 'CANDIDATE',
      hero_minions_killed_snapshot: 'CANDIDATE' },
    face_packet_count: 10, snapshot_count: 10, keyframe_count: 1,
    paired_packet_count: 10, excluded_game_packet_count: 0,
    excluded_noncanonical_keyframe_packet_count: 0,
    first_excluded_face_packet_refs: { game: null, noncanonical_keyframe: null },
    verified_raw_packet_count: 20, input_count: 20, event_count: 10,
  };
  const semantic = {
    replay_version: PROFILE.replay_version, replay_sha256: REPLAY_SHA,
    container_status: 'PASS', status: 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE',
    requested_capabilities: [CAPABILITY],
    capability_results: { [CAPABILITY]: capabilityResult },
  };
  const analysis = {
    source_path: null, replay_version: PROFILE.replay_version, patch: '16.19',
    replay_sha256: REPLAY_SHA, event_counts: { [EVENT]: 10 },
    event_storage: 'JSONL_ONLY', event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` },
    events: null, semantic: { status: 'CANDIDATE',
      requested_capabilities: [CAPABILITY],
      capability_results: { [CAPABILITY]: capabilityResult } },
  };
  const semanticPath = path.join(directory, 'semantic_run.json');
  const analysisPath = path.join(directory, 'replay_analysis.json');
  const eventPath = path.join(directory, `${EVENT}.jsonl`);
  fs.writeFileSync(semanticPath, JSON.stringify(semantic));
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  fs.writeFileSync(eventPath, `${rows.map(JSON.stringify).join('\n')}\n`);
  return { directory, rows, semanticPath, analysisPath, eventPath };
}

function query(directory, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', EVENT, ...args],
    { encoding: 'utf8', cwd: path.dirname(CLI) });
}

function changeJson(filename, edit) {
  const value = JSON.parse(fs.readFileSync(filename, 'utf8'));
  edit(value);
  fs.writeFileSync(filename, JSON.stringify(value));
}

function changeRow(filename, edit) {
  const rows = fs.readFileSync(filename, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  edit(rows[0]);
  fs.writeFileSync(filename, `${rows.map(JSON.stringify).join('\n')}\n`);
}

test('query-events filters roster participant candidate and preserves original pair JSONL', (t) => {
  const source = fixture(t);
  const selected = query(source.directory, '--participant', '4',
    '--raw-param', '0x400000b1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(source.rows[3])}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 10);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.rows_unmodified, true);
  assert.equal(fs.readFileSync(source.eventPath, 'utf8'),
    `${source.rows.map(JSON.stringify).join('\n')}\n`);
  assert.equal(query(source.directory, '--participant', '4',
    '--raw-param', '0x400000b2').stdout, '');
});

test('query-events rejects changed profile or image identity', (t) => {
  const source = fixture(t);
  changeJson(source.semanticPath, (semantic) => {
    semantic.capability_results[CAPABILITY].runtime_image_sha256 = '0'.repeat(64);
  });
  const result = query(source.directory, '--participant', '1');
  assert.equal(result.status, 2);
  assert.equal(JSON.parse(result.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
});

test('query-events rejects false roster, wrong key, reversed refs, claimed actor and vector drift',
  (t) => {
    const edits = [
      (row) => { row.hero_stats_participant_id_candidate = 2; },
      (row) => { row.face_direction_raw_packet_ref.raw_param += 0x200;
        row.raw_packet_refs[1].raw_param += 0x200; },
      (row) => { row.raw_packet_refs.reverse(); },
      (row) => { row.actor_assignment_status = 'KNOWN'; },
      (row) => { row.packet_vector_xyz_f32_candidate.x = 0; },
    ];
    for (const edit of edits) {
      const source = fixture(t);
      changeRow(source.eventPath, edit);
      const result = query(source.directory, '--participant', '1');
      assert.equal(result.status, 2, result.stderr);
      assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
    }
  });
