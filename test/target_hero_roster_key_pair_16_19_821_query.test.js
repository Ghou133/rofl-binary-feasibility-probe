'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { TARGET_HERO_PACKET_CANDIDATE_PROFILE_821: targetProfile } =
  require('../src/decoders/rofl_16_19_821_target_hero_packet_candidate');
const { HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: rosterProfile } =
  require('../src/decoders/rofl_16_19_821_roster_metadata_bridge_candidate');
const { TARGET_HERO_ROSTER_KEY_PAIR_821_PROFILE: pairProfile } =
  require('../src/decoders/rofl_16_19_821_target_hero_roster_key_pair_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const REPLAY_SHA = 'a'.repeat(64);
const SOURCE_PATH = 'synthetic.rofl';
const TARGET_EVENT = 'target_hero_packet_candidates';
const ROSTER_EVENT = 'hero_roster_metadata_bridge_candidates';
const PAIR_EVENT = 'target_hero_roster_key_pair_candidates';
const ROLES = ['top', 'jungle', 'mid', 'adc', 'support'];
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

function rosterRows() {
  return Array.from({ length: 10 }, (_, index) => {
    const hero = 0x400000ae + index;
    const teamId = index < 5 ? 100 : 200;
    const time = 5000;
    return {
      event_type: 'HERO_ROSTER_METADATA_BRIDGE_CANDIDATE',
      game_version: pairProfile.replay_version, patch: '16.19',
      build_profile: rosterProfile.id, replay_sha256: REPLAY_SHA,
      replay_time_ms: time, hero_raw_param: hero,
      participant_id_candidate: index + 1, metadata_index_candidate: index,
      champion_metadata: `Champion${index + 1}`, team_id_metadata: teamId,
      team_metadata: teamId === 100 ? 'blue' : 'red',
      role_metadata: ROLES[index % 5],
      observed_deaths_candidate: index + 2,
      observed_source_kills_candidate: index + 1,
      observed_assists_candidate: index + 3,
      metadata_kills: index + 1, metadata_deaths: index + 2,
      metadata_assists: index + 3,
      metadata_sha256: 'b'.repeat(64), stats_json_sha256: 'c'.repeat(64),
      observation_kind: 'LATEST_KEYFRAME_ROSTER_AND_REPLAY_METADATA_JOIN',
      confidence: 'CANDIDATE', semantic_status: rosterProfile.evidence_status,
      roster_to_metadata_status: rosterProfile.evidence_status,
      per_packet_actor_status: 'UNKNOWN',
      field_confidence: {
        hero_raw_param: 'VERIFIED_DIRECT',
        champion_metadata: 'VERIFIED_FROM_METADATA',
        team_metadata: 'VERIFIED_FROM_METADATA',
        role_metadata: 'VERIFIED_FROM_METADATA',
        participant_id_candidate: rosterProfile.evidence_status,
        metadata_index_candidate: rosterProfile.evidence_status,
        per_packet_actor_status: 'UNKNOWN',
      },
      raw_packet_ref: {
        source_path: SOURCE_PATH, replay_sha256: REPLAY_SHA,
        chunk_index: index + 10, chunk_id: index + 11,
        chunk_stream: 'keyframe', chunk_file_offset: 1000 + index,
        decompressed_block_offset: index * 1280,
        decompressed_payload_offset: index * 1280 + 9,
        packet_id: 0x0089, replay_time_ms: time, payload_length: 1263,
        raw_param: hero, raw_payload_sha256: sha256(`hero-${index}`),
      },
      known_limits: [...rosterProfile.known_limits],
    };
  });
}

function targetRows() {
  return [0, 1, 2].map((index) => {
    const zero = index === 0;
    const hex = zero ? '33' : '37c68e';
    const time = 1000 + index;
    const rawParam = 0x400000b5;
    return {
      event_type: 'TARGET_HERO_PACKET_CANDIDATE',
      game_version: pairProfile.replay_version, patch: '16.19',
      build_profile: targetProfile.id, replay_sha256: REPLAY_SHA,
      replay_time_ms: time, raw_param: rawParam,
      packet_name_candidate: targetProfile.packet_name,
      native_protected_lookup_bytes_hex: zero ? '35353535' : 'c63535f3',
      native_callback_lookup_key_u32: zero ? 0 : 0x400000b0,
      native_receiver_call_status: 'NOT_EXECUTED',
      source_actor_status: 'UNKNOWN', target_object_status: 'UNKNOWN',
      target_state_status: 'UNKNOWN', semantic_effect_status: 'UNKNOWN',
      confidence: 'CANDIDATE', semantic_status: targetProfile.evidence_status,
      raw_packet_ref: {
        source_path: SOURCE_PATH, replay_sha256: REPLAY_SHA,
        chunk_index: index, chunk_id: index + 1,
        chunk_stream: 'game_chunk', chunk_file_offset: 100 + index,
        decompressed_block_offset: 20 + index * 30,
        decompressed_payload_offset: 29 + index * 30,
        packet_id: 0x0265, replay_time_ms: time,
        payload_length: hex.length / 2, raw_param: rawParam,
        raw_payload_hex: hex, raw_payload_sha256: sha256(Buffer.from(hex, 'hex')),
      },
    };
  });
}

function targetDigests(rows) {
  const input = crypto.createHash('sha256');
  const output = crypto.createHash('sha256');
  for (const row of rows) {
    const payload = Buffer.from(row.raw_packet_ref.raw_payload_hex, 'hex');
    const header = Buffer.alloc(8);
    header.writeUInt32LE(row.raw_param, 0);
    header.writeUInt32LE(payload.length, 4);
    input.update(header).update(payload);
    const key = Buffer.alloc(4);
    key.writeUInt32LE(row.native_callback_lookup_key_u32);
    output.update(Buffer.from(row.native_protected_lookup_bytes_hex, 'hex'))
      .update(key);
  }
  return [input.digest('hex'), output.digest('hex')];
}

function pairRows(target, roster) {
  const selected = roster[2];
  return target.slice(1).map((row) => ({
    event_type: 'TARGET_HERO_ROSTER_KEY_PAIR_CANDIDATE',
    game_version: pairProfile.replay_version, patch: '16.19',
    build_profile: pairProfile.id, replay_sha256: REPLAY_SHA,
    replay_time_ms: row.replay_time_ms, target_hero_raw_param: row.raw_param,
    native_protected_lookup_bytes_hex: row.native_protected_lookup_bytes_hex,
    native_callback_lookup_key_u32: row.native_callback_lookup_key_u32,
    hero_raw_param: selected.hero_raw_param,
    participant_id_candidate: selected.participant_id_candidate,
    metadata_index_candidate: selected.metadata_index_candidate,
    champion_metadata: selected.champion_metadata,
    team_id_metadata: selected.team_id_metadata,
    team_metadata: selected.team_metadata,
    role_metadata: selected.role_metadata,
    metadata_sha256: selected.metadata_sha256,
    stats_json_sha256: selected.stats_json_sha256,
    association_status: 'CANDIDATE_FULL_U32_ROSTER_KEY_EQUALITY',
    roster_to_metadata_status: rosterProfile.evidence_status,
    native_receiver_call_status: 'NOT_EXECUTED',
    source_actor_status: 'UNKNOWN', target_object_status: 'UNKNOWN',
    target_state_status: 'UNKNOWN', live_lookup_status: 'UNKNOWN',
    semantic_effect_status: 'UNKNOWN', confidence: 'CANDIDATE',
    semantic_status: pairProfile.evidence_status,
    field_confidence: {
      native_callback_lookup_key_u32: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
      hero_raw_param: 'CANDIDATE_FULL_U32_ROSTER_KEY_EQUALITY',
      champion_metadata: 'VERIFIED_FROM_METADATA',
      team_metadata: 'VERIFIED_FROM_METADATA',
      role_metadata: 'VERIFIED_FROM_METADATA',
      participant_id_candidate: 'CANDIDATE_FULL_U32_ROSTER_KEY_EQUALITY',
      source_actor_status: 'UNKNOWN', target_object_status: 'UNKNOWN',
    },
    raw_packet_ref: row.raw_packet_ref,
    roster_keyframe_packet_ref: selected.raw_packet_ref,
    known_limits: [...pairProfile.known_limits],
  }));
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-target-roster-query-'));
  t.after(() => {
    const resolved = path.resolve(root);
    if (!resolved.startsWith(path.resolve(os.tmpdir()) + path.sep)
        || !path.basename(resolved).startsWith('rofl-target-roster-query-')) {
      throw new Error('Unsafe synthetic fixture cleanup target');
    }
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  const relative = 'replays/sample';
  const dir = path.join(root, 'replays', 'sample');
  fs.mkdirSync(dir, { recursive: true });
  const roster = rosterRows();
  const target = targetRows();
  const pair = pairRows(target, roster);
  const [nativeInput, nativeOutput] = targetDigests(target);
  const targetResult = {
    profile_id: targetProfile.id, input_packet_id: 0x0265,
    evidence_status: targetProfile.evidence_status,
    evidence_runtime_image_sha256: targetProfile.evidence_runtime_image_sha256,
    status: 'CANDIDATE', input_count: 3, event_count: 3,
    scanned_block_count: 3, known_limits: [...targetProfile.known_limits],
    event_field_confidence: {
      replay_time_ms: 'VERIFIED_DIRECT', raw_param: 'VERIFIED_DIRECT',
      native_callback_lookup_key_u32: 'CANDIDATE_EXACT_RUNTIME_CALLBACK_WITNESS',
    },
    native_witness_status: 'FULLY_CONSUMED_ALL', native_full_success_count: 3,
    native_batch_count: 1, native_input_sha256: nativeInput,
    native_output_sha256: nativeOutput, runtime_image_status: 'MATCHED_USED',
    runtime_image_used: true,
    runtime_image_sha256: targetProfile.evidence_runtime_image_sha256,
  };
  const rosterResult = {
    profile_id: rosterProfile.id, evidence_status: rosterProfile.evidence_status,
    input_packet_id: 0x0089, status: 'CANDIDATE', input_count: 10,
    event_count: 10, metadata_player_count: 10, unique_kda_match_count: 10,
    runtime_image_used: false, runtime_image_status: 'NOT_REQUIRED',
    known_limits: [...rosterProfile.known_limits],
    metadata_sha256: 'b'.repeat(64), stats_json_sha256: 'c'.repeat(64),
    dependency_statuses: Object.fromEntries(rosterProfile.depends_on.map((name) =>
      [name, 'CANDIDATE'])),
    observed_hero_death_count: 65, observed_assist_pair_count: 75,
  };
  const pairResult = {
    profile_id: pairProfile.id, input_packet_id: 0x0265,
    evidence_status: pairProfile.evidence_status,
    evidence_runtime_image_sha256: pairProfile.evidence_runtime_image_sha256,
    dependency_statuses: { target_hero_packet: 'CANDIDATE',
      hero_roster_metadata_bridge: 'CANDIDATE' },
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    known_limits: [...pairProfile.known_limits], status: 'CANDIDATE',
    input_count: 3, event_count: 2, zero_lookup_key_count: 1,
    nonzero_lookup_key_count: 2, matched_nonzero_count: 2,
    unexpected_nonzero_count: 0, native_witness_status: 'FULLY_CONSUMED_ALL',
    native_full_success_count: 3,
    runtime_image_sha256: pairProfile.evidence_runtime_image_sha256,
    metadata_sha256: 'b'.repeat(64), stats_json_sha256: 'c'.repeat(64),
    target_hero_native_input_sha256: nativeInput,
    target_hero_native_output_sha256: nativeOutput,
  };
  const capabilityResults = { target_hero_packet: targetResult,
    hero_roster_metadata_bridge: rosterResult,
    target_hero_roster_key_pair: pairResult };
  const requested = Object.keys(capabilityResults);
  const semantic = {
    replay_version: pairProfile.replay_version, replay_sha256: REPLAY_SHA,
    container_status: 'PASS', status: 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE', requested_capabilities: requested,
    capability_results: capabilityResults,
  };
  const analysis = {
    patch: '16.19', replay_version: pairProfile.replay_version,
    replay_sha256: REPLAY_SHA, source_path: SOURCE_PATH,
    event_storage: 'JSONL_ONLY', events: null,
    event_counts: { [TARGET_EVENT]: target.length,
      [ROSTER_EVENT]: roster.length, [PAIR_EVENT]: pair.length },
    event_jsonl_files: { [TARGET_EVENT]: `${TARGET_EVENT}.jsonl`,
      [ROSTER_EVENT]: `${ROSTER_EVENT}.jsonl`,
      [PAIR_EVENT]: `${PAIR_EVENT}.jsonl` },
    semantic: { status: 'CANDIDATE', requested_capabilities: requested,
      capability_results: capabilityResults },
  };
  const players = roster.map((row) => ({
    metadata_index: row.metadata_index_candidate,
    champion: row.champion_metadata, team_id: row.team_id_metadata,
    team: row.team_metadata, role: row.role_metadata,
    role_status: 'VERIFIED_FROM_METADATA',
    aggregate_stats: { kills: row.metadata_kills,
      deaths: row.metadata_deaths, assists: row.metadata_assists },
  }));
  const inventory = { sha256: REPLAY_SHA,
    replay_version: pairProfile.replay_version,
    metadata: { stats_player_count: 10, players } };
  const files = {
    'semantic_run.json': JSON.stringify(semantic),
    'replay_analysis.json': JSON.stringify(analysis),
    'rofl_inventory.json': JSON.stringify(inventory),
    [`${TARGET_EVENT}.jsonl`]: `${target.map(JSON.stringify).join('\n')}\n`,
    [`${ROSTER_EVENT}.jsonl`]: `${roster.map(JSON.stringify).join('\n')}\n`,
    [`${PAIR_EVENT}.jsonl`]: `${pair.map(JSON.stringify).join('\n')}\n`,
  };
  const rewrite = () => {
    const hashes = {};
    for (const [filename, content] of Object.entries(files)) {
      fs.writeFileSync(path.join(dir, filename), content);
      hashes[`${relative}/${filename}`] = sha256(content);
    }
    fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
      command_args: ['decode'],
      replay_inputs: [{ artifact_directory: relative,
        sha256: REPLAY_SHA, version: pairProfile.replay_version }],
      output_hashes_excluding_manifest: hashes,
    }));
  };
  rewrite();
  return { root, dir, pair, target, files, rewrite };
}

function query(directory, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', PAIR_EVENT, ...args],
    { encoding: 'utf8' });
}

test('saved TargetHero roster query checks complete source streams before output', (t) => {
  const f = fixture(t);
  const selected = query(f.root, '--opaque-u32', String(0x400000b0), '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(f.pair[0])}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.source_provenance_status, 'SAVED_ONLY_UNVERIFIED');
  const participant = query(f.root, '--participant', '3');
  assert.equal(participant.status, 2, participant.stderr);
  assert.equal(JSON.parse(participant.stderr).code, 'UNSUPPORTED_FILTER');
});

test('late pair forgery fails after limit even with a rewritten manifest', (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.pair);
  forged[1].champion_metadata = 'ForgedChampion';
  f.files[`${PAIR_EVENT}.jsonl`] = `${forged.map(JSON.stringify).join('\n')}\n`;
  f.rewrite();
  const result = query(f.root, '--limit', '1');
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(result.stdout, '');
});

test('late native source forgery fails after limit even with a rewritten manifest', (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.target);
  forged[2].native_protected_lookup_bytes_hex = '35353535';
  forged[2].native_callback_lookup_key_u32 = 0;
  f.files[`${TARGET_EVENT}.jsonl`] = `${forged.map(JSON.stringify).join('\n')}\n`;
  f.rewrite();
  const result = query(f.root, '--limit', '1');
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stderr).code, 'EVENT_COUNT_MISMATCH');
  assert.equal(result.stdout, '');
});
