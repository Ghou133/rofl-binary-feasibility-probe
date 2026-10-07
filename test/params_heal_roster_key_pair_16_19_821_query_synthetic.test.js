'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { walkBlocks } = require('../src/rofl');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { PARAMS_HEAL_PACKET_CANDIDATE_PROFILE_821: healProfile } =
  require('../src/decoders/rofl_16_19_821_params_heal_packet_candidate');
const { HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: rosterProfile } =
  require('../src/decoders/rofl_16_19_821_roster_metadata_bridge_candidate');
const { associateParamsHealRosterKeys821: associate } =
  require('../src/decoders/rofl_16_19_821_params_heal_roster_key_pair_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const BUILD = '16.19.821.7343';
const HEAL = 'params_heal_packet_candidates';
const ROSTER = 'hero_roster_metadata_bridge_candidates';
const PAIR = 'params_heal_roster_key_pair_candidates';
const FIRST_KEY = 0x400000ae;
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

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-heal-pair-saved-'));
  t.after(() => {
    const resolved = path.resolve(root);
    if (!resolved.startsWith(path.resolve(os.tmpdir()) + path.sep)
        || !path.basename(resolved).startsWith('rofl-heal-pair-saved-')) {
      throw new Error('Unsafe synthetic query cleanup target');
    }
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  const replay = replayFromChunks([
    { stream: 1, body: Buffer.concat(Array.from({ length: 4 }, (_, index) =>
      packet(0x040a, FIRST_KEY + index, Buffer.alloc(60, index + 1),
        1000 + index * 100))) },
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      packet(0x0089, FIRST_KEY + index, Buffer.alloc(1263, index),
        2000))) },
  ], BUILD);
  const refs = { heal: [], roster: [] };
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
    refs[block.packet_id === 0x040a ? 'heal' : 'roster'].push(ref);
  }, { strict: true });
  assert.equal(walked.errors.length, 0);
  const metadataSha = sha('metadata');
  const statsSha = sha('stats');
  const roster = refs.roster.map((ref, index) => {
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
      raw_packet_ref: ref, known_limits: [...rosterProfile.known_limits],
    };
  });
  const keys = [
    [FIRST_KEY + 1, FIRST_KEY + 2],
    [FIRST_KEY + 3, 0x40003b78],
    [0x40003b79, FIRST_KEY + 4],
    [FIRST_KEY + 0x101, 0],
  ];
  const heal = refs.heal.map((ref, index) => ({
    event_type: 'PARAMS_HEAL_PACKET_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: healProfile.id,
    replay_sha256: replay.source_sha256, replay_time_ms: ref.replay_time_ms,
    raw_param: ref.raw_param, event_id: 0x004b,
    reported_amount_candidate: 10 + index,
    event_entity_u32_0x04: keys[index][0],
    event_entity_u32_0x14: keys[index][1],
    raw_event_id_hex: '0x4958', event_blob_sha256: sha(`heal-${index}`),
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_EXACT_RUNTIME_PARAMS_HEAL_REPORT',
    raw_packet_ref: ref,
  }));
  const healResult = {
    profile_id: healProfile.id, input_packet_id: 0x040a,
    child_event_id: 0x004b,
    evidence_runtime_image_sha256: healProfile.evidence_runtime_image_sha256,
    status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_PARAMS_HEAL_REPORT',
    known_limits: [...healProfile.known_limits],
    input_count: 4, event_count: 4, runtime_image_status: 'MATCHED_USED',
    runtime_image_used: true,
    runtime_image_sha256: healProfile.evidence_runtime_image_sha256,
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
  const pairOutcome = associate(replay, {
    paramsHealPacketOutcome: { ...healResult, events: heal },
    heroRosterMetadataBridgeOutcome: { ...rosterResult, events: roster },
  });
  assert.equal(pairOutcome.status, 'CANDIDATE', pairOutcome.error);
  const { events: pair, ...pairResult } = pairOutcome;
  const relative = 'replays/sample';
  const directory = path.join(root, 'replays', 'sample');
  fs.mkdirSync(directory, { recursive: true });
  const results = {
    params_heal_packet: healResult,
    hero_roster_metadata_bridge: rosterResult,
    params_heal_roster_key_pair: pairResult,
  };
  const requested = Object.keys(results);
  const semantic = {
    replay_version: BUILD, replay_sha256: replay.source_sha256,
    container_status: 'PASS', status: 'CANDIDATE',
    requested_capabilities: requested, capability_results: results,
  };
  const analysis = {
    patch: '16.19', replay_version: BUILD,
    replay_sha256: replay.source_sha256,
    source_path: replay.source_path ?? null,
    event_storage: 'JSONL_ONLY', events: null,
    event_counts: { [HEAL]: 4, [ROSTER]: 10, [PAIR]: 4 },
    event_jsonl_files: {
      [HEAL]: `${HEAL}.jsonl`,
      [ROSTER]: `${ROSTER}.jsonl`,
      [PAIR]: `${PAIR}.jsonl`,
    },
    semantic: { status: 'CANDIDATE', requested_capabilities: requested,
      capability_results: results },
  };
  const players = roster.map((row) => ({
    metadata_index: row.metadata_index_candidate,
    champion: row.champion_metadata, team_id: row.team_id_metadata,
    team: row.team_metadata, role: row.role_metadata,
    role_status: 'VERIFIED_FROM_METADATA',
    aggregate_stats: { kills: row.metadata_kills, deaths: row.metadata_deaths,
      assists: row.metadata_assists },
  }));
  const files = {
    'semantic_run.json': JSON.stringify(semantic),
    'replay_analysis.json': JSON.stringify(analysis),
    'rofl_inventory.json': JSON.stringify({
      sha256: replay.source_sha256, replay_version: BUILD,
      metadata: { stats_player_count: 10, players },
    }),
    [`${HEAL}.jsonl`]: `${heal.map(JSON.stringify).join('\n')}\n`,
    [`${ROSTER}.jsonl`]: `${roster.map(JSON.stringify).join('\n')}\n`,
    [`${PAIR}.jsonl`]: `${pair.map(JSON.stringify).join('\n')}\n`,
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
        sha256: replay.source_sha256, version: BUILD }],
      output_hashes_excluding_manifest: hashes,
    }));
  };
  rewrite();
  return { root, directory, heal, roster, pair, files, rewrite };
}

function query(directory, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', PAIR, ...args],
    { encoding: 'utf8' });
}

test('saved ParamsHeal pair query retains both anonymous keys and all negatives', (t) => {
  const f = fixture(t);
  const result = query(f.root, '--opaque-u32', String(FIRST_KEY + 4),
    '--limit', '1');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${JSON.stringify(f.pair[2])}\n`);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.scanned_count, 4);
  assert.equal(summary.matched_count, 1);
  assert.equal(f.pair[2].roster_match_0x04.status, 'NOT_IN_TEN_KEY_ROSTER');
  assert.equal(f.pair[3].roster_match_0x14.status, 'NOT_IN_TEN_KEY_ROSTER');
  const participant = query(f.root, '--participant', '5');
  assert.equal(participant.status, 2);
  assert.equal(JSON.parse(participant.stderr).code, 'UNSUPPORTED_FILTER');
});

test('late pair and source forgeries fail even with limit one', (t) => {
  const f = fixture(t);
  const pair = structuredClone(f.pair);
  pair[3].roster_match_0x14.participant_id_candidate = 5;
  f.files[`${PAIR}.jsonl`] = `${pair.map(JSON.stringify).join('\n')}\n`;
  f.rewrite();
  const forgedPair = query(f.root, '--limit', '1');
  assert.equal(forgedPair.status, 2, forgedPair.stderr);
  assert.equal(JSON.parse(forgedPair.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(forgedPair.stdout, '');
  f.files[`${PAIR}.jsonl`] = `${f.pair.map(JSON.stringify).join('\n')}\n`;
  const heal = structuredClone(f.heal);
  heal[3].reported_amount_candidate += 1;
  f.files[`${HEAL}.jsonl`] = `${heal.map(JSON.stringify).join('\n')}\n`;
  f.rewrite();
  const forgedSource = query(f.root, '--limit', '1');
  assert.equal(forgedSource.status, 2, forgedSource.stderr);
  assert.equal(JSON.parse(forgedSource.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(forgedSource.stdout, '');
});
