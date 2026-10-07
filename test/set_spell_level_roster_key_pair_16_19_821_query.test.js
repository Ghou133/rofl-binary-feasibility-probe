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
const { SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_821: packetProfile,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V1_821: packetV1Profile,
  SET_SPELL_LEVEL_PACKET_CANDIDATE_FIELD_CONFIDENCE_V2_821: packetConfidence,
  decodeSetSpellLevelU32At10FromRaw821,
  decodeSetSpellLevelU32At14FromRaw821 } =
  require('../src/decoders/rofl_16_19_821_set_spell_level_packet_candidate');
const { HERO_ROSTER_METADATA_BRIDGE_821_PROFILE: rosterProfile } =
  require('../src/decoders/rofl_16_19_821_roster_metadata_bridge_candidate');
const { associateSetSpellLevelRosterKeyPair821: associate } =
  require('../src/decoders/rofl_16_19_821_set_spell_level_roster_key_pair_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const BUILD = '16.19.821.7343';
const FIRST_KEY = 0x400000ae;
const PACKET_EVENT = 'set_spell_level_packet_candidates';
const ROSTER_EVENT = 'hero_roster_metadata_bridge_candidates';
const PAIR_EVENT = 'set_spell_level_roster_key_pair_candidates';
const ROLES = ['top', 'jungle', 'mid', 'adc', 'support'];
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');

function block(id, param, payload, timeMs) {
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(param, 11);
  return Buffer.concat([header, payload]);
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-set-spell-pair-query-'));
  t.after(() => {
    const resolved = path.resolve(root);
    if (!resolved.startsWith(path.resolve(os.tmpdir()) + path.sep)
        || !path.basename(resolved).startsWith('rofl-set-spell-pair-query-')) {
      throw new Error('Unsafe synthetic fixture cleanup target');
    }
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  const inputs = [
    [FIRST_KEY + 4, '33', '7bbbbbbb', '72f1f1f1'],
    [FIRST_KEY + 4 + 0x100, '35', 'bbbbbbbb', '32f1f1f1'],
    [FIRST_KEY + 2, '37c6', 'bbbbbbbb', '32f1f1f1'],
  ];
  const replay = replayFromChunks([
    { stream: 1, body: Buffer.concat(inputs.map(([param, payload], index) =>
      block(0x025d, param, Buffer.from(payload, 'hex'), 1000 + index * 100))) },
    { stream: 2, body: Buffer.concat(Array.from({ length: 10 }, (_, index) =>
      block(0x0089, FIRST_KEY + index, Buffer.alloc(1263, index), 2000))) },
  ], BUILD);
  const packetRefs = [];
  const rosterRefs = [];
  const walked = walkBlocks(replay, (packet, chunk) => {
    const ref = {
      source_path: replay.source_path ?? null,
      replay_sha256: replay.source_sha256,
      chunk_index: chunk.index, chunk_id: chunk.chunk_id,
      chunk_stream: chunk.stream, chunk_file_offset: chunk.offset,
      decompressed_block_offset: packet.offset,
      decompressed_payload_offset: packet.payload_offset,
      packet_id: packet.packet_id, replay_time_ms: packet.timestamp_ms,
      payload_length: packet.payload_length, raw_param: packet.param >>> 0,
      raw_payload_sha256: sha(packet.payload),
    };
    if (packet.packet_id === 0x025d) packetRefs.push(ref);
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
      hero_raw_param: FIRST_KEY + index,
      participant_id_candidate: index + 1, metadata_index_candidate: index,
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
  const packetRows = packetRefs.map((ref, index) => {
    const raw10 = inputs[index][2];
    const raw14 = inputs[index][3];
    const value10 = decodeSetSpellLevelU32At10FromRaw821(raw10);
    const value14 = decodeSetSpellLevelU32At14FromRaw821(raw14);
    return {
      event_type: 'SET_SPELL_LEVEL_PACKET_CANDIDATE',
      game_version: BUILD, patch: '16.19', build_profile: packetProfile.id,
      replay_sha256: replay.source_sha256, replay_time_ms: ref.replay_time_ms,
      raw_param: ref.raw_param,
      opaque_u32_0x10: value10, opaque_u32_0x14: value14,
      raw_object_u32_0x10_hex: raw10, raw_object_u32_0x14_hex: raw14,
      native_receiver_slot_candidate: value10 <= 63 ? value10 : 0,
      native_receiver_selection_source: value10 <= 63 ? 'INDEXED' : 'FALLBACK_0',
      native_clamped_scalar_candidate: Math.min(value14, 6),
      native_positive_flag_written: value14 > 0,
      confidence: 'CANDIDATE',
      semantic_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
      raw_packet_ref: ref,
    };
  });
  const packetResult = {
    profile_id: packetProfile.id, status: 'CANDIDATE',
    evidence_status: 'CANDIDATE_EXACT_RUNTIME_PACKET_FIELDS',
    input_packet_id: 0x025d, input_count: 3, event_count: 3,
    evidence_runtime_image_sha256: packetProfile.evidence_runtime_image_sha256,
    evidence_callback_table_sha256: packetProfile.evidence_callback_table_sha256,
    evidence_callback_rva: packetProfile.evidence_callback_rva,
    evidence_receiver_write_rva: packetProfile.evidence_receiver_write_rva,
    evidence_callback_witness_mode: packetProfile.evidence_callback_witness_mode,
    evidence_callback_region_sha256: packetProfile.evidence_callback_region_sha256,
    evidence_receiver_write_region_sha256:
      packetProfile.evidence_receiver_write_region_sha256,
    scanned_block_count: walked.block_count,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: packetProfile.evidence_runtime_image_sha256,
    known_limits: [...packetProfile.known_limits],
    event_field_confidence: packetConfidence,
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
  const outcome = associate(replay, {
    setSpellLevelPacketOutcome: { ...packetResult, events: packetRows },
    heroRosterMetadataBridgeOutcome: { ...rosterResult, events: roster },
  });
  assert.equal(outcome.status, 'CANDIDATE', outcome.error);
  const { events: pairRows, ...pairResult } = outcome;
  assert.equal(pairRows.length, 2);
  const results = {
    set_spell_level_packet: packetResult,
    hero_roster_metadata_bridge: rosterResult,
    set_spell_level_roster_key_pair: pairResult,
  };
  const requested = Object.keys(results);
  const relative = 'replays/sample';
  const directory = path.join(root, 'replays', 'sample');
  fs.mkdirSync(directory, { recursive: true });
  const semantic = {
    replay_version: BUILD, replay_sha256: replay.source_sha256,
    container_status: 'PASS', status: 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE',
    requested_capabilities: requested, capability_results: results,
  };
  const analysis = {
    patch: '16.19', replay_version: BUILD,
    replay_sha256: replay.source_sha256, source_path: replay.source_path,
    event_storage: 'JSONL_ONLY', events: null,
    event_counts: { [PACKET_EVENT]: 3, [ROSTER_EVENT]: 10,
      [PAIR_EVENT]: 2 },
    event_jsonl_files: {
      [PACKET_EVENT]: `${PACKET_EVENT}.jsonl`,
      [ROSTER_EVENT]: `${ROSTER_EVENT}.jsonl`,
      [PAIR_EVENT]: `${PAIR_EVENT}.jsonl`,
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
  const inventory = { sha256: replay.source_sha256,
    replay_version: BUILD,
    metadata: { stats_player_count: 10, players } };
  const files = {
    'semantic_run.json': JSON.stringify(semantic),
    'replay_analysis.json': JSON.stringify(analysis),
    'rofl_inventory.json': JSON.stringify(inventory),
    [`${PACKET_EVENT}.jsonl`]: `${packetRows.map(JSON.stringify).join('\n')}\n`,
    [`${ROSTER_EVENT}.jsonl`]: `${roster.map(JSON.stringify).join('\n')}\n`,
    [`${PAIR_EVENT}.jsonl`]: `${pairRows.map(JSON.stringify).join('\n')}\n`,
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
  return { root, directory, files, rewrite, packetRows, roster,
    pairRows, results };
}

function query(root, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', root, '--event', PAIR_EVENT, ...args],
    { encoding: 'utf8' });
}

test('saved pair query filters the full header key and rejects participant role', (t) => {
  const f = fixture(t);
  const selected = query(f.root, '--opaque-u32', String(FIRST_KEY + 4),
    '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${JSON.stringify(f.pairRows[0])}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.source_provenance_status, 'SAVED_ONLY_UNVERIFIED');
  const rejected = query(f.root, '--participant', '5');
  assert.equal(rejected.status, 2);
  assert.equal(JSON.parse(rejected.stderr).code, 'UNSUPPORTED_FILTER');
});

test('saved query API returns role-neutral row after full source check', async (t) => {
  const f = fixture(t);
  const rows = [];
  const prepared = prepareEventQuery(f.directory, PAIR_EVENT);
  const summary = await streamEventQuery(prepared,
    { opaqueU32: FIRST_KEY + 2, limit: 1 },
    async (line) => rows.push(JSON.parse(line)));
  assert.deepEqual(rows, [f.pairRows[1]]);
  assert.equal(summary.scanned_count, 2);
  assert.equal(rows[0].packet_actor_status, 'UNKNOWN');
});

test('late pair forgery fails after limit without partial output', (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.pairRows);
  forged[1].participant_id_candidate = 10;
  f.files[`${PAIR_EVENT}.jsonl`] = `${forged.map(JSON.stringify).join('\n')}\n`;
  f.rewrite();
  const result = query(f.root, '--limit', '1');
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(result.stdout, '');
});

test('excluded and matched late V2 source forgeries fail after limit', (t) => {
  const f = fixture(t);
  for (const index of [1, 2]) {
    const forged = structuredClone(f.packetRows);
    forged[index].opaque_u32_0x14 = 6;
    f.files[`${PACKET_EVENT}.jsonl`] = `${forged.map(JSON.stringify).join('\n')}\n`;
    f.rewrite();
    const result = query(f.root, '--limit', '1');
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(result.stdout, '');
  }
});

test('last roster source row remains required after limit', (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.roster);
  forged[9].champion_metadata = 'Forged';
  f.files[`${ROSTER_EVENT}.jsonl`] = `${forged.map(JSON.stringify).join('\n')}\n`;
  f.rewrite();
  const result = query(f.root, '--limit', '1');
  assert.equal(result.status, 2, result.stderr);
  assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(result.stdout, '');
});

test('V1 source and physical verification without image fail closed', (t) => {
  const f = fixture(t);
  const missingImage = query(f.root, '--verify-source', '--limit', '1');
  assert.equal(missingImage.status, 2);
  assert.equal(JSON.parse(missingImage.stderr).code, 'MISSING_RUNTIME_IMAGE');
  const semantic = JSON.parse(f.files['semantic_run.json']);
  const analysis = JSON.parse(f.files['replay_analysis.json']);
  semantic.capability_results.set_spell_level_packet.profile_id = packetV1Profile.id;
  analysis.semantic.capability_results.set_spell_level_packet.profile_id = packetV1Profile.id;
  f.files['semantic_run.json'] = JSON.stringify(semantic);
  f.files['replay_analysis.json'] = JSON.stringify(analysis);
  f.rewrite();
  const v1 = query(f.root);
  assert.equal(v1.status, 2);
  assert.equal(JSON.parse(v1.stderr).code, 'SPELL_LEVEL_CALLBACK_UNAVAILABLE');
});
