'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { OBJECTIVE_BOUNTY_TURRET_PAIR_821_PROFILE: PROFILE } =
  require('../src/decoders/rofl_16_19_821_objective_bounty_turret_pair_candidate');
const { OBJECTIVE_BOUNTY_CLAIMED_PACKET_821_PROFILE: CLAIM } =
  require('../src/decoders/rofl_16_19_821_objective_bounty_claimed_packet_candidate');
const { TURRET_PLATE_EVENT_PACKET_821_PROFILE: PLATE } =
  require('../src/decoders/rofl_16_19_821_turret_plate_event_packet_candidate');
const { TURRET_DIE_EVENT_PACKET_821_PROFILE: DIE } =
  require('../src/decoders/rofl_16_19_821_turret_die_event_packet_candidate');
const { prepareEventQuery, streamEventQuery } = require('../src/event_query');

const EVENT = 'objective_bounty_turret_pair_candidates';
const BUILD = '16.19.821.7343';
const SHA = 'a'.repeat(64);
const CLI = path.resolve(__dirname, '..', 'src', 'cli.js');
const REAL_BATCH = path.resolve(__dirname, '..', 'artifacts',
  '16_19_development', 'objective_bounty_turret_pair_cli_batch_11_821');

function command(...args) {
  return spawnSync(process.execPath, [CLI, 'query-events', ...args], {
    encoding: 'utf8', timeout: 120000,
  });
}

function ref(offset, length, param, time = 100) {
  return {
    source_path: 'synthetic.rofl', replay_sha256: SHA,
    chunk_index: 1, chunk_id: 2, chunk_stream: 'game_chunk',
    chunk_file_offset: 8, decompressed_block_offset: offset,
    decompressed_payload_offset: offset + 6, packet_id: 0x040a,
    replay_time_ms: time, payload_length: length, raw_param: param,
    raw_payload_sha256: 'b'.repeat(64),
  };
}

function triple(word = 0x40000088, offsets = [32, 64, 96]) {
  const [plate, die, claim] = [ref(offsets[0], 17, 0x400000ae),
    ref(offsets[1], 116, 0x400000af), ref(offsets[2], 17, 0x400000b0)];
  return {
    event_type: 'OBJECTIVE_BOUNTY_TURRET_PACKET_TRIPLE_CANDIDATE',
    game_version: BUILD, patch: '16.19', build_profile: PROFILE.id,
    replay_sha256: SHA, replay_time_ms: 100, raw_param: claim.raw_param,
    plate_child_event_id: 0x0107, turret_die_child_event_id: 0x003b,
    claim_child_event_id: 0x0113,
    plate_raw_param: plate.raw_param,
    turret_die_raw_param: die.raw_param,
    claim_raw_param: claim.raw_param,
    plate_event_u32_0x04: word,
    turret_die_blob_u32_0x0c: word,
    claim_blob_u32_0x04: word,
    raw_packet_ref: claim,
    plate_raw_packet_ref: plate,
    turret_die_raw_packet_ref: die,
    claim_raw_packet_ref: claim,
    raw_packet_refs: [plate, die, claim],
    confidence: 'CANDIDATE',
    semantic_status: 'CANDIDATE_821_ON_EVENT_PLATE_DIE_CLAIM_PACKET_TRIPLE',
  };
}

function writeJson(filename, value) {
  fs.writeFileSync(filename, JSON.stringify(value));
}

function fixture(t, rows = [triple()]) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-claim-pair-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const artifact = path.join(root, 'replay');
  fs.mkdirSync(artifact);
  const image = PROFILE.evidence_runtime_image_sha256;
  const dependency = (profile, eventCount) => ({
    status: 'CANDIDATE', profile_id: profile.id,
    evidence_runtime_image_sha256: image,
    runtime_image_sha256: image,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    input_packet_id: 0x040a, child_event_id: profile.child_event_id,
    event_count: eventCount,
    input_count: eventCount,
    target_packet_count: eventCount,
  });
  const claim = dependency(CLAIM, rows.length);
  claim.input_count += 1;
  const plate = dependency(PLATE, rows.length);
  plate.input_count += 1;
  const die = dependency(DIE, rows.length);
  const association = {
    status: 'CANDIDATE', profile_id: PROFILE.id,
    evidence_runtime_image_sha256: image,
    evidence_status: 'CANDIDATE_821_ON_EVENT_PLATE_DIE_CLAIM_PACKET_TRIPLE',
    replay_sha256: SHA, depends_on: [...PROFILE.depends_on],
    known_limits: [...PROFILE.known_limits],
    event_count: rows.length, triple_count: rows.length,
    claim_packet_count: rows.length,
    turret_plate_count: rows.length, turret_die_count: rows.length,
    unmatched_claim_count: 0, nonunique_claim_count: 0,
    unmatched_claims: [],
  };
  const semantic = {
    replay_version: BUILD, replay_sha256: SHA, container_status: 'PASS',
    status: 'CANDIDATE', requested_capabilities: [...PROFILE.depends_on],
    capability_results: {
      objective_bounty_claimed_packet: claim,
      turret_plate_event_packet: plate,
      turret_die_event_packet: die,
    },
    candidate_associations: { [PROFILE.capability]: association },
  };
  const analysis = {
    patch: '16.19', replay_version: BUILD, replay_sha256: SHA,
    source_path: 'synthetic.rofl',
    event_counts: {
      [EVENT]: rows.length,
      objective_bounty_claimed_packet_candidates: rows.length,
      turret_plate_event_packet_candidates: rows.length,
      turret_die_event_packet_candidates: rows.length,
    },
    event_storage: 'JSONL_ONLY', events: null,
    event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` },
  };
  writeJson(path.join(artifact, 'semantic_run.json'), semantic);
  writeJson(path.join(artifact, 'replay_analysis.json'), analysis);
  const lines = rows.map(JSON.stringify);
  fs.writeFileSync(path.join(artifact, `${EVENT}.jsonl`), `${lines.join('\n')}\n`);
  return { root, artifact, semantic, rows, lines };
}

test('query emits original exact-821 triple rows and filters anonymous equality word', async (t) => {
  const sample = fixture(t);
  const selected = command(sample.artifact, '--event', EVENT,
    '--opaque-u32', '0x40000088', '--from-ms', '100', '--to-ms', '100');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${sample.lines[0]}\n`);
  assert.equal(JSON.parse(selected.stderr).rows_unmodified, true);
  const prepared = prepareEventQuery(sample.artifact, EVENT);
  const output = [];
  const summary = await streamEventQuery(prepared, { opaqueU32: 0x40000088 },
    async (line) => output.push(line));
  assert.deepEqual(output, [`${sample.lines[0]}\n`]);
  assert.equal(summary.emitted_count, 1);
});

test('query fails closed on changed dependencies and tampered triple fields', (t) => {
  for (const mutate of [
    (sample) => { sample.semantic.candidate_associations[PROFILE.capability]
      .unmatched_claim_count = 1; },
    (sample) => { sample.semantic.capability_results.turret_plate_event_packet
      .runtime_image_sha256 = 'f'.repeat(64); },
    (sample) => { sample.semantic.capability_results.objective_bounty_claimed_packet
      .status = 'PROFILE_UNAVAILABLE'; },
  ]) {
    const sample = fixture(t);
    mutate(sample);
    writeJson(path.join(sample.artifact, 'semantic_run.json'), sample.semantic);
    const rejected = command(sample.artifact, '--event', EVENT);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.ok(['ASSOCIATION_METADATA_MISMATCH', 'CAPABILITY_UNAVAILABLE']
      .includes(JSON.parse(rejected.stderr).code));
  }
  for (const mutate of [
    (row) => { row.claim_blob_u32_0x04 += 1; },
    (row) => { row.turret_die_raw_packet_ref.payload_length = 17; },
    (row) => { row.plate_raw_packet_ref.decompressed_block_offset = 1000; },
    (row) => { row.claim_raw_packet_ref.source_path = 'foreign.rofl'; },
  ]) {
    const rows = [triple(), triple(0x40000089, [132, 164, 196])];
    mutate(rows[1]);
    const sample = fixture(t, rows);
    const output = path.join(sample.root, 'must-not-exist.jsonl');
    const rejected = command(sample.artifact, '--event', EVENT,
      '--limit', '1', '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('real 11-Replay triple query retains unmatched claim and target-free outcomes', (t) => {
  if (!fs.existsSync(path.join(REAL_BATCH, 'manifest.json'))) {
    t.skip('saved exact-821 triple batch absent');
    return;
  }
  const queried = command(REAL_BATCH, '--event', EVENT, '--opaque-u32', '0x40010b5a');
  assert.equal(queried.status, 0, queried.stderr);
  const summary = JSON.parse(queried.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.completed_replay_count, 7);
  assert.equal(summary.unavailable_replay_count, 4);
  assert.equal(summary.scanned_count, 10);
  assert.equal(summary.matched_count, 0);
  assert.equal(queried.stdout, '');
});
