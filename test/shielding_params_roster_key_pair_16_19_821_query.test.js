'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { walkBlocks } = require('../src/rofl');
const { prepareEventQuery, streamEventQuery } = require('../src/event_query');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { SHIELDING_PARAMS_PACKET_PAIR_821_PROFILE: shieldProfile } =
  require('../src/decoders/rofl_16_19_821_shielding_params_packet_pair_candidate');
const { HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: rosterProfile } =
  require('../src/decoders/rofl_16_19_821_roster_metadata_bridge_candidate');
const { SHIELDING_PARAMS_ROSTER_KEY_PAIR_821_PROFILE: pairProfile,
  associateShieldingParamsRosterKeys821 } =
  require('../src/decoders/rofl_16_19_821_shielding_params_roster_key_pair_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const BUILD = '16.19.821.7343';
const FIRST_KEY = 0x400000ae;
const SHIELD_EVENT = 'shielding_params_packet_pair_candidates';
const ROSTER_EVENT = 'hero_roster_metadata_bridge_candidates';
const PAIR_EVENT = 'shielding_params_roster_key_pair_candidates';
const ROLES = ['top', 'jungle', 'mid', 'adc', 'support'];
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');

function packet(id, param, payload, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function syntheticRows() {
  const replay = replayFromChunks([
    { stream: 1, body: Buffer.concat([
      packet(0x040a, FIRST_KEY + 1, Buffer.alloc(29, 1), 1000),
      packet(0x040a, FIRST_KEY + 2, Buffer.alloc(29, 2), 1000),
      packet(0x040a, FIRST_KEY + 3, Buffer.alloc(29, 3), 1100),
      packet(0x040a, 0x40003b78, Buffer.alloc(29, 4), 1100),
    ]) },
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      packet(0x0089, FIRST_KEY + index, Buffer.alloc(1263, index), 2000))) },
  ], BUILD);
  const shieldRefs = [];
  const rosterRefs = [];
  const walked = walkBlocks(replay, (block, chunk) => {
    const ref = {
      source_path: replay.source_path ?? null,
      replay_sha256: replay.source_sha256,
      chunk_index: chunk.index, chunk_id: chunk.chunk_id,
      chunk_stream: chunk.stream, chunk_file_offset: chunk.offset,
      decompressed_block_offset: block.offset,
      decompressed_payload_offset: block.payload_offset,
      packet_id: block.packet_id, replay_time_ms: block.timestamp_ms,
      payload_length: block.payload_length, raw_param: block.param >>> 0,
      raw_payload_sha256: sha(block.payload),
    };
    if (block.packet_id === 0x040a) shieldRefs.push(ref);
    else rosterRefs.push(ref);
  }, { strict: true });
  assert.equal(walked.errors.length, 0);
  const metadataSha = sha('metadata');
  const statsSha = sha('stats');
  const roster = rosterRefs.map((ref, index) => {
    const teamId = index < 5 ? 100 : 200;
    return {
      event_type: 'HERO_ROSTER_METADATA_BRIDGE_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: rosterProfile.id,
      replay_sha256: replay.source_sha256, replay_time_ms: ref.replay_time_ms,
      hero_raw_param: FIRST_KEY + index, participant_id_candidate: index + 1,
      metadata_index_candidate: index,
      champion_metadata: `Champion${index + 1}`,
      team_id_metadata: teamId, team_metadata: teamId === 100 ? 'blue' : 'red',
      role_metadata: ROLES[index % 5],
      observed_deaths_candidate: index + 2,
      observed_source_kills_candidate: index + 1,
      observed_assists_candidate: index + 3,
      metadata_kills: index + 1, metadata_deaths: index + 2,
      metadata_assists: index + 3,
      metadata_sha256: metadataSha, stats_json_sha256: statsSha,
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
      raw_packet_ref: ref,
      known_limits: [...rosterProfile.known_limits],
    };
  });
  const shield = [
    { a: FIRST_KEY + 1, b: FIRST_KEY + 2, refs: shieldRefs.slice(0, 2) },
    { a: FIRST_KEY + 3, b: 0x40003b78, refs: shieldRefs.slice(2, 4) },
  ].map((item, index) => ({
    event_type: 'SHIELDING_PARAMS_PACKET_PAIR_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: shieldProfile.id,
    replay_sha256: replay.source_sha256,
    replay_time_ms: item.refs[0].replay_time_ms,
    child_event_ids: [0x00f0, 0x00ef],
    event_u32_0x08: item.a, event_u32_0x0c: item.b,
    event_raw_f32_0x10: index ? -12.5 : 25.5,
    event_blob_sha256: sha(`pair-${index}`),
    raw_event_id_hex_by_child: {
      on_grant_shield_0x00f0: '0x492b',
      on_receive_shield_0x00ef: '0x4951',
    },
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_SHIELDING_PARAMS_PAIR',
    raw_packet_refs: item.refs,
  }));
  const shieldResult = {
    profile_id: shieldProfile.id, input_packet_id: 0x040a,
    input_packet_scope: 'child_00ef_00f0_length_29',
    child_event_ids: [0x00f0, 0x00ef],
    evidence_runtime_image_sha256: shieldProfile.evidence_runtime_image_sha256,
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_SHIELDING_PARAMS_PAIR',
    known_limits: [...shieldProfile.known_limits],
    input_count: 4, event_count: 2, scanned_block_count: 14,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: shieldProfile.evidence_runtime_image_sha256,
  };
  const rosterResult = {
    profile_id: rosterProfile.id, evidence_status: rosterProfile.evidence_status,
    input_packet_id: 0x0089, status: 'CANDIDATE', input_count: 10,
    event_count: 10, metadata_player_count: 10, unique_kda_match_count: 10,
    runtime_image_used: false, runtime_image_status: 'NOT_REQUIRED',
    known_limits: [...rosterProfile.known_limits],
    metadata_sha256: metadataSha, stats_json_sha256: statsSha,
    dependency_statuses: Object.fromEntries(rosterProfile.depends_on.map(
      (name) => [name, 'CANDIDATE'])),
    observed_hero_death_count: 65, observed_assist_pair_count: 75,
  };
  const outcome = associateShieldingParamsRosterKeys821(replay, {
    shieldingParamsPacketPairOutcome: { ...shieldResult, events: shield },
    heroRosterMetadataBridgeOutcome: { ...rosterResult, events: roster },
  });
  assert.equal(outcome.status, 'CANDIDATE', outcome.error);
  const { events: pair, ...pairResult } = outcome;
  return { replay, shield, roster, pair, shieldResult, rosterResult,
    pairResult };
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-shield-query-'));
  t.after(() => {
    const resolved = path.resolve(root);
    if (!resolved.startsWith(path.resolve(os.tmpdir()) + path.sep)
        || !path.basename(resolved).startsWith('rofl-shield-query-')) {
      throw new Error('Unsafe synthetic fixture cleanup target');
    }
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  const sample = syntheticRows();
  const relative = 'replays/sample';
  const directory = path.join(root, 'replays', 'sample');
  fs.mkdirSync(directory, { recursive: true });
  const results = {
    shielding_params_packet_pair: sample.shieldResult,
    hero_roster_metadata_bridge: sample.rosterResult,
    shielding_params_roster_key_pair: sample.pairResult,
  };
  const requested = Object.keys(results);
  const semantic = {
    replay_version: BUILD, replay_sha256: sample.replay.source_sha256,
    container_status: 'PASS', status: 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE',
    requested_capabilities: requested, capability_results: results,
  };
  const analysis = {
    patch: '16.19', replay_version: BUILD,
    replay_sha256: sample.replay.source_sha256,
    source_path: sample.replay.source_path,
    event_storage: 'JSONL_ONLY', events: null,
    event_counts: { [SHIELD_EVENT]: 2, [ROSTER_EVENT]: 10,
      [PAIR_EVENT]: 2 },
    event_jsonl_files: {
      [SHIELD_EVENT]: `${SHIELD_EVENT}.jsonl`,
      [ROSTER_EVENT]: `${ROSTER_EVENT}.jsonl`,
      [PAIR_EVENT]: `${PAIR_EVENT}.jsonl`,
    },
    semantic: { status: 'CANDIDATE', requested_capabilities: requested,
      capability_results: results },
  };
  const players = sample.roster.map((row) => ({
    metadata_index: row.metadata_index_candidate,
    champion: row.champion_metadata, team_id: row.team_id_metadata,
    team: row.team_metadata, role: row.role_metadata,
    role_status: 'VERIFIED_FROM_METADATA',
    aggregate_stats: { kills: row.metadata_kills, deaths: row.metadata_deaths,
      assists: row.metadata_assists },
  }));
  const inventory = { sha256: sample.replay.source_sha256,
    replay_version: BUILD,
    metadata: { stats_player_count: 10, players } };
  const files = {
    'semantic_run.json': JSON.stringify(semantic),
    'replay_analysis.json': JSON.stringify(analysis),
    'rofl_inventory.json': JSON.stringify(inventory),
    [`${SHIELD_EVENT}.jsonl`]: `${sample.shield.map(JSON.stringify).join('\n')}\n`,
    [`${ROSTER_EVENT}.jsonl`]: `${sample.roster.map(JSON.stringify).join('\n')}\n`,
    [`${PAIR_EVENT}.jsonl`]: `${sample.pair.map(JSON.stringify).join('\n')}\n`,
  };
  const rewrite = () => {
    const hashes = {};
    for (const [filename, content] of Object.entries(files)) {
      fs.writeFileSync(path.join(directory, filename), content);
      hashes[`${relative}/${filename}`] = sha(content);
    }
    fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
      command_args: ['decode'],
      replay_inputs: [{ artifact_directory: relative,
        sha256: sample.replay.source_sha256, version: BUILD }],
      output_hashes_excluding_manifest: hashes,
    }));
  };
  rewrite();
  return { root, directory, files, rewrite, ...sample };
}

function query(directory, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', PAIR_EVENT, ...args],
    { encoding: 'utf8' });
}

test('saved ShieldingParams pair query keeps both keys and the unmatched field', (t) => {
  const f = fixture(t);
  const selected = query(f.root, '--opaque-u32', String(FIRST_KEY + 2),
    '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(f.pair[0])}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.source_provenance_status, 'SAVED_ONLY_UNVERIFIED');
  assert.equal(f.pair[1].roster_match_0x0c.status, 'NOT_IN_TEN_KEY_ROSTER');
  assert.equal(f.pair[1].roster_match_0x0c.participant_id_candidate, null);
  const participant = query(f.root, '--participant', '2');
  assert.equal(participant.status, 2);
  assert.equal(JSON.parse(participant.stderr).code, 'UNSUPPORTED_FILTER');
});

test('saved query API exposes the same role-neutral candidate rows', async (t) => {
  const f = fixture(t);
  const selected = [];
  const prepared = prepareEventQuery(f.directory, PAIR_EVENT);
  const summary = await streamEventQuery(prepared,
    { opaqueU32: FIRST_KEY + 3, limit: 1 },
    async (line) => selected.push(JSON.parse(line)));
  assert.deepEqual(selected, [f.pair[1]]);
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.source_provenance_status, 'SAVED_ONLY_UNVERIFIED');
  assert.equal(selected[0].roster_match_0x0c.status, 'NOT_IN_TEN_KEY_ROSTER');
});

test('late pair forgery fails after limit without partial output', (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.pair);
  forged[1].roster_match_0x0c.participant_id_candidate = 10;
  f.files[`${PAIR_EVENT}.jsonl`] = `${forged.map(JSON.stringify).join('\n')}\n`;
  f.rewrite();
  const result = query(f.root, '--limit', '1');
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(result.stdout, '');
});

test('late source forgery fails after limit with rewritten manifest', (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.shield);
  forged[1].event_u32_0x0c = FIRST_KEY + 4;
  f.files[`${SHIELD_EVENT}.jsonl`] = `${forged.map(JSON.stringify).join('\n')}\n`;
  f.rewrite();
  const result = query(f.root, '--limit', '1');
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stderr).code, 'EVENT_COUNT_MISMATCH');
  assert.equal(result.stdout, '');
});

test('source verification requires the explicit pinned runtime image', (t) => {
  const f = fixture(t);
  const result = query(f.root, '--verify-source', '--limit', '1');
  assert.equal(result.status, 2);
  assert.equal(JSON.parse(result.stderr).code, 'MISSING_RUNTIME_IMAGE');
  assert.equal(result.stdout, '');
});
