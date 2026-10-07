'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { FORCE_CREATE_MISSILE_PACKET_CANDIDATE_PROFILE_821: forceProfile } =
  require('../src/decoders/rofl_16_19_821_force_create_missile_packet_candidate');
const { CHANGE_MISSILE_TARGET_PACKET_CANDIDATE_PROFILE_821: changeProfile } =
  require('../src/decoders/rofl_16_19_821_change_missile_target_packet_candidate');
const { recomputeSavedMissileKeyCooccurrence821 } =
  require('../src/decoders/rofl_16_19_821_missile_key_cooccurrence_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const BUILD = '16.19.821.7343';
const FORCE = 'force_create_missile_packet_candidates';
const CHANGE = 'change_missile_target_packet_candidates';
const PAIR = 'missile_key_cooccurrence_candidates';
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');

function sourceRow(kind, index, replaySha, sourcePath) {
  const force = kind === 'force';
  const profile = force ? forceProfile : changeProfile;
  const payloadHex = force ? ['f0abcd', 'f1123456'][index]
    : ['9656981069287b66ec2cad7569', '916fcb'][index];
  const protectedHex = force ? ['90cdc94a', 'cf4ac94a'][index]
    : ['c9c9c9c9', '6fc9c94a'][index];
  const key = force ? [0x40000263, 0x40004003][index]
    : [0, 0x400000b2][index];
  const rawParam = force ? 0x400000b5
    : [0x40000263, 0x40000264][index];
  const replayTime = 1000 + index * 200 + (force ? 0 : 100);
  const chunkIndex = index * 2 + (force ? 0 : 1);
  return {
    event_type: force ? 'FORCE_CREATE_MISSILE_PACKET_CANDIDATE'
      : 'CHANGE_MISSILE_TARGET_PACKET_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: profile.id,
    replay_sha256: replaySha, replay_time_ms: replayTime, raw_param: rawParam,
    packet_name_candidate: profile.packet_name,
    native_protected_comparison_bytes_hex: protectedHex,
    native_callback_comparison_key_u32: key,
    native_callback_witness_status: 'SYNTHETIC_RECEIVER_PRE_COMPARE',
    ...(force ? { live_receiver_lookup_status: 'UNKNOWN' }
      : { live_receiver_comparison_status: 'UNKNOWN' }),
    source_actor_status: 'UNKNOWN', owner_status: 'UNKNOWN',
    missile_identity_status: 'UNKNOWN', target_status: 'UNKNOWN',
    ...(force ? { creation_effect_status: 'UNKNOWN' }
      : { target_change_effect_status: 'UNKNOWN' }),
    causality_status: 'UNKNOWN', confidence: 'CANDIDATE',
    semantic_status: profile.evidence_status,
    raw_packet_ref: {
      source_path: sourcePath, replay_sha256: replaySha,
      chunk_index: chunkIndex, chunk_id: chunkIndex + 1,
      chunk_stream: 'game_chunk', chunk_file_offset: 100 + chunkIndex,
      decompressed_block_offset: 20, decompressed_payload_offset: 29,
      packet_id: profile.replay_block_packet_id, replay_time_ms: replayTime,
      payload_length: payloadHex.length / 2, raw_param: rawParam,
      raw_payload_hex: payloadHex,
      raw_payload_sha256: sha(Buffer.from(payloadHex, 'hex')),
    },
  };
}

function sourceResult(profile, rows, scanned = 4) {
  const input = crypto.createHash('sha256');
  const output = crypto.createHash('sha256');
  for (const row of rows) {
    const payload = Buffer.from(row.raw_packet_ref.raw_payload_hex, 'hex');
    const header = Buffer.alloc(8);
    header.writeUInt32LE(row.raw_param, 0);
    header.writeUInt32LE(payload.length, 4);
    input.update(header).update(payload);
    const key = Buffer.alloc(4);
    key.writeUInt32LE(row.native_callback_comparison_key_u32);
    output.update(Buffer.from(row.native_protected_comparison_bytes_hex, 'hex'))
      .update(key);
  }
  return {
    profile_id: profile.id, input_packet_id: profile.replay_block_packet_id,
    evidence_status: profile.evidence_status,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    status: 'CANDIDATE', input_count: rows.length, event_count: rows.length,
    scanned_block_count: scanned, known_limits: [...profile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      native_callback_comparison_key_u32:
        'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
    },
    native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: rows.length, native_batch_count: 1,
    native_input_sha256: input.digest('hex'),
    native_output_sha256: output.digest('hex'),
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
  };
}

function writeReplay(root, name, replaySha, unavailable = false) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const sourcePath = `${name}.rofl`;
  const forceRows = [0, 1].map((index) =>
    sourceRow('force', index, replaySha, sourcePath));
  const changeRows = unavailable ? [] : [0, 1].map((index) =>
    sourceRow('change', index, replaySha, sourcePath));
  const forceResult = sourceResult(forceProfile, forceRows);
  const changeResult = unavailable ? {
    profile_id: changeProfile.id,
    input_packet_id: changeProfile.replay_block_packet_id,
    evidence_status: changeProfile.evidence_status,
    evidence_runtime_image_sha256: changeProfile.evidence_runtime_image_sha256,
    status: 'PROFILE_UNAVAILABLE', input_count: 0, event_count: null,
    runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    error: 'KR 0x040c packet route is absent', scanned_block_count: 4,
  } : sourceResult(changeProfile, changeRows);
  const computed = recomputeSavedMissileKeyCooccurrence821({
    header: { version: BUILD }, source_sha256: replaySha,
  }, {
    forceCreateMissilePacketOutcome: { ...forceResult, events: forceRows },
    changeMissileTargetPacketOutcome: unavailable ? changeResult
      : { ...changeResult, events: changeRows },
  });
  const { events: pairRows, ...pairResult } = computed;
  assert.equal(computed.status, unavailable ? 'PROFILE_UNAVAILABLE' : 'CANDIDATE');
  if (!unavailable) {
    assert.equal(pairRows.length, 2);
    assert.equal(pairResult.unique_preceding_equal_key_count, 1);
    assert.equal(pairResult.no_preceding_equal_key_count, 1);
  }
  const results = {
    force_create_missile_packet: forceResult,
    change_missile_target_packet: changeResult,
    missile_key_cooccurrence: pairResult,
  };
  const requested = Object.keys(results);
  const semantic = {
    replay_version: BUILD, replay_sha256: replaySha,
    container_status: 'PASS', status: unavailable ? 'PARTIAL' : 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE', requested_capabilities: requested,
    capability_results: results,
  };
  const eventRows = { [FORCE]: forceRows,
    ...(!unavailable ? { [CHANGE]: changeRows, [PAIR]: pairRows } : {}) };
  const analysis = {
    patch: '16.19', replay_version: BUILD, replay_sha256: replaySha,
    source_path: sourcePath, event_storage: 'JSONL_ONLY', events: null,
    event_counts: Object.fromEntries(Object.entries(eventRows)
      .map(([key, rows]) => [key, rows.length])),
    event_jsonl_files: Object.fromEntries(Object.keys(eventRows)
      .map((key) => [key, `${key}.jsonl`])),
    semantic: { status: semantic.status, requested_capabilities: requested,
      capability_results: results },
  };
  fs.writeFileSync(path.join(directory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(directory, 'replay_analysis.json'), JSON.stringify(analysis));
  for (const [key, rows] of Object.entries(eventRows)) {
    fs.writeFileSync(path.join(directory, `${key}.jsonl`),
      `${rows.map(JSON.stringify).join('\n')}\n`);
  }
  return { directory, eventRows, semantic, analysis };
}

function writeManifest(root) {
  const replays = [
    ['candidate', 'a'.repeat(64)], ['route-absent', 'b'.repeat(64)],
  ];
  const outputHashes = {};
  for (const [name] of replays) {
    const directory = path.join(root, 'replays', name);
    for (const file of fs.readdirSync(directory)) {
      const relative = `replays/${name}/${file}`;
      outputHashes[relative] = sha(fs.readFileSync(path.join(directory, file)));
    }
  }
  const manifest = {
    command_args: ['batch'], replay_inputs: replays.map(([name, hash]) => ({
      artifact_directory: `replays/${name}`, version: BUILD, sha256: hash,
    })),
    output_hashes_excluding_manifest: outputHashes,
  };
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify(manifest));
  return manifest;
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-missile-pair-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const candidate = writeReplay(root, 'candidate', 'a'.repeat(64));
  const unavailable = writeReplay(root, 'route-absent', 'b'.repeat(64), true);
  const manifest = writeManifest(root);
  return { root, candidate, unavailable, manifest };
}

function query(directory, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', PAIR, ...args],
    { encoding: 'utf8' });
}

function errorCode(run) {
  assert.equal(run.status, 2, run.stderr);
  assert.equal(run.stdout, '');
  return JSON.parse(run.stderr).code;
}

test('saved full-u32 query retains unmatched rows and explicit unavailable Replay', (t) => {
  const f = fixture(t);
  const selected = query(f.candidate.directory, '--opaque-u32',
    '0x40000263', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout,
    `${JSON.stringify(f.candidate.eventRows[PAIR][0])}\n`);
  assert.equal(JSON.parse(selected.stderr).scanned_count, 2);
  assert.equal(errorCode(query(f.candidate.directory,
    '--participant', '1')), 'UNSUPPORTED_FILTER');
  const batch = query(f.root, '--limit', '1');
  assert.equal(batch.status, 0, batch.stderr);
  const summary = JSON.parse(batch.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.replay_results[1].capability_status, 'PROFILE_UNAVAILABLE');
});

test('late forged pair row fails after limit even with refreshed manifest hash', (t) => {
  const f = fixture(t);
  const file = path.join(f.candidate.directory, `${PAIR}.jsonl`);
  const rows = structuredClone(f.candidate.eventRows[PAIR]);
  rows[1].association_status = 'CANDIDATE_PRECEDING_FULL_U32_KEY_EQUALITY';
  fs.writeFileSync(file, `${rows.map(JSON.stringify).join('\n')}\n`);
  f.manifest.output_hashes_excluding_manifest[`replays/candidate/${PAIR}.jsonl`]
    = sha(fs.readFileSync(file));
  fs.writeFileSync(path.join(f.root, 'manifest.json'), JSON.stringify(f.manifest));
  assert.equal(errorCode(query(f.candidate.directory, '--limit', '1')),
    'INVALID_EVENT_ROW');
});

test('late forged native source fails after limit even with refreshed manifest hash', (t) => {
  const f = fixture(t);
  const file = path.join(f.candidate.directory, `${FORCE}.jsonl`);
  const rows = structuredClone(f.candidate.eventRows[FORCE]);
  rows[1].native_protected_comparison_bytes_hex = '90cdc94a';
  rows[1].native_callback_comparison_key_u32 = 0x40000263;
  fs.writeFileSync(file, `${rows.map(JSON.stringify).join('\n')}\n`);
  f.manifest.output_hashes_excluding_manifest[`replays/candidate/${FORCE}.jsonl`]
    = sha(fs.readFileSync(file));
  fs.writeFileSync(path.join(f.root, 'manifest.json'), JSON.stringify(f.manifest));
  assert.equal(errorCode(query(f.candidate.directory, '--limit', '1')),
    'EVENT_COUNT_MISMATCH');
});

test('manifest forgery and missing physical image both fail closed', (t) => {
  const f = fixture(t);
  assert.equal(errorCode(query(f.candidate.directory,
    '--verify-source', '--limit', '1')), 'MISSING_RUNTIME_IMAGE');
  f.manifest.output_hashes_excluding_manifest[`replays/candidate/${CHANGE}.jsonl`]
    = '0'.repeat(64);
  fs.writeFileSync(path.join(f.root, 'manifest.json'), JSON.stringify(f.manifest));
  assert.equal(errorCode(query(f.root, '--limit', '1')),
    'ARTIFACT_HASH_MISMATCH');
});

test('unavailable route status cannot be rewritten as zero candidate rows', (t) => {
  const f = fixture(t);
  const file = path.join(f.unavailable.directory, 'semantic_run.json');
  const semantic = structuredClone(f.unavailable.semantic);
  semantic.capability_results.missile_key_cooccurrence.status = 'CANDIDATE';
  fs.writeFileSync(file, JSON.stringify(semantic));
  f.manifest.output_hashes_excluding_manifest[
    'replays/route-absent/semantic_run.json'] = sha(fs.readFileSync(file));
  fs.writeFileSync(path.join(f.root, 'manifest.json'), JSON.stringify(f.manifest));
  assert.equal(errorCode(query(f.root, '--limit', '1')),
    'CAPABILITY_METADATA_MISMATCH');
});

test('pair status cannot be promoted to PASS in saved metadata', (t) => {
  const f = fixture(t);
  const semanticFile = path.join(f.candidate.directory, 'semantic_run.json');
  const analysisFile = path.join(f.candidate.directory, 'replay_analysis.json');
  const semantic = structuredClone(f.candidate.semantic);
  const analysis = structuredClone(f.candidate.analysis);
  semantic.capability_results.missile_key_cooccurrence.status = 'PASS';
  analysis.semantic.capability_results.missile_key_cooccurrence.status = 'PASS';
  fs.writeFileSync(semanticFile, JSON.stringify(semantic));
  fs.writeFileSync(analysisFile, JSON.stringify(analysis));
  f.manifest.output_hashes_excluding_manifest[
    'replays/candidate/semantic_run.json'] = sha(fs.readFileSync(semanticFile));
  f.manifest.output_hashes_excluding_manifest[
    'replays/candidate/replay_analysis.json'] = sha(fs.readFileSync(analysisFile));
  fs.writeFileSync(path.join(f.root, 'manifest.json'), JSON.stringify(f.manifest));
  assert.equal(errorCode(query(f.root, '--limit', '1')),
    'CAPABILITY_METADATA_MISMATCH');
});
