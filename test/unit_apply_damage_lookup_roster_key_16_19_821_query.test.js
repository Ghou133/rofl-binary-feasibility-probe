'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { promoteSavedAssociationV4 } =
  require('./helpers/damage_association_v4_saved');

const { UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V1_821: profile,
  UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_PROFILE_V2_821: v2Profile,
  UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_821_PROFILE: currentProfile } =
  require('../src/decoders/rofl_16_19_821_unit_apply_damage_lookup_roster_key_candidate');
const { UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821: rawPairProfile,
  UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V2_821: v2RawPairProfile,
  UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE: currentRawPairProfile } =
  require('../src/decoders/rofl_16_19_821_unit_apply_damage_roster_key_candidate');
const { UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: damageProfile,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821: damageProfileV3Id,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821: damageProfileV4Id,
  decodeUnitApplyDamageLookupKeyFromRaw821 } =
  require('../src/decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');
const { PROFILES } =
  require('../src/decoders/rofl_16_19_821_float_stats_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'unit_apply_damage_lookup_roster_key_candidates';
const CAPABILITY = 'unit_apply_damage_lookup_roster_key_pair';
const SOURCE_PATH = 'synthetic.rofl';
const PACKET = '71875e460b083dbaef3ba6ec39b975';
const ENCODED = new Map([
  [0x400000ae, '37494929'],
  [0x400000af, '8b494929'],
]);

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function rosterRef(key, replaySha) {
  const participant = key - 0x400000ae + 1;
  return {
    source_path: SOURCE_PATH, replay_sha256: replaySha,
    chunk_index: 1, chunk_id: 1, chunk_stream: 'keyframe',
    chunk_file_offset: 100, decompressed_block_offset: 100 + participant * 1300,
    decompressed_payload_offset: 112 + participant * 1300,
    packet_id: 0x0089, replay_time_ms: 0, payload_length: 1263,
    raw_param: key,
    raw_payload_sha256: sha256(Buffer.alloc(1263, participant)),
  };
}

function row(index, key, rawParam, replaySha = 'a'.repeat(64)) {
  const encoded = ENCODED.get(key);
  assert.equal(decodeUnitApplyDamageLookupKeyFromRaw821(encoded, 0x24), key);
  const payload = Buffer.from(PACKET, 'hex');
  const time = 1000 + index;
  const damageRef = {
    source_path: SOURCE_PATH, replay_sha256: replaySha,
    chunk_index: 2, chunk_id: 2, chunk_stream: 'game_chunk',
    chunk_file_offset: 200, decompressed_block_offset: 1000 + index * 100,
    decompressed_payload_offset: 1006 + index * 100,
    packet_id: 0x005f, replay_time_ms: time, payload_length: payload.length,
    raw_param: rawParam, raw_payload_hex: PACKET,
    raw_payload_sha256: sha256(payload),
  };
  const statsRef = rosterRef(key, replaySha);
  const relation = rawParam === key ? 'EQUAL'
    : rawParam - key === 0x100 ? 'RAW_PARAM_IS_LOOKUP_PLUS_0X100' : 'OTHER';
  return {
    event_type: 'UNIT_APPLY_DAMAGE_LOOKUP_ROSTER_KEY_CANDIDATE',
    game_version: profile.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: replaySha,
    replay_time_ms: time, raw_param: rawParam,
    native_callback_lookup_key_u32_0x24_candidate: key,
    native_callback_lookup_key_0x24_encoded_bytes_hex: encoded,
    native_callback_lookup_key_0x24_raw_param_relation: relation,
    hero_raw_param: key,
    hero_stats_participant_id_candidate: key - 0x400000ae + 1,
    pair_basis:
      'NATIVE_CALLBACK_LOOKUP_KEY_0X24_EXACT_FULL_KEY_IN_CANONICAL_HEROSTATS_ROSTER',
    lookup_resolution_status: 'UNKNOWN', actor_assignment_status: 'UNKNOWN',
    source_target_role_status: 'UNKNOWN', semantic_effect_status: 'UNKNOWN',
    confidence: 'CANDIDATE', semantic_status: profile.evidence_status,
    unit_apply_damage_raw_packet_ref: damageRef,
    hero_stats_roster_raw_packet_ref: statsRef,
    raw_packet_refs: [structuredClone(damageRef), structuredClone(statsRef)],
  };
}

function defaultRows(replaySha = 'a'.repeat(64)) {
  return [
    row(0, 0x400000ae, 0x400000ae, replaySha),
    row(1, 0x400000ae, 0x400001ae, replaySha),
    row(2, 0x400000af, 0x40004007, replaySha),
  ];
}

function writeReplay(root, name, rows, {
  replaySha = 'a'.repeat(64), replayVersion = profile.replay_version,
  status = 'CANDIDATE', withDependencies = true,
} = {}) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const equal = rows.filter((entry) =>
    entry.native_callback_lookup_key_0x24_raw_param_relation === 'EQUAL').length;
  const alias = rows.filter((entry) =>
    entry.native_callback_lookup_key_0x24_raw_param_relation
      === 'RAW_PARAM_IS_LOOKUP_PLUS_0X100').length;
  const result = {
    profile_id: profile.id, depends_on: [...profile.depends_on],
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    evidence_lookup_key_0x24_table_sha256:
      profile.evidence_lookup_key_0x24_table_sha256,
    known_limits: [...profile.known_limits], status,
    evidence_status: profile.evidence_status, replay_sha256: replaySha,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
    dependency_statuses: {
      unit_apply_damage_packet: 'CANDIDATE',
      hero_minions_killed_snapshot: 'CANDIDATE',
      unit_apply_damage_roster_key_pair: 'CANDIDATE',
    },
    damage_packet_count: rows.length, snapshot_count: 10, keyframe_count: 1,
    canonical_roster_key_count: 10,
    matched_lookup_key_packet_count: rows.length,
    matched_alias_0x100_packet_count: alias,
    matched_equal_packet_count: equal,
    matched_other_relation_packet_count: rows.length - alias - equal,
    unmatched_packet_count: 0, unmatched_alias_0x100_packet_count: 0,
    first_unmatched_packet_refs: { alias_0x100: null, other: null },
    verified_raw_packet_count: rows.length + 10,
    input_count: rows.length + 10, event_count: rows.length,
  };
  const dependencies = withDependencies ? {
    unit_apply_damage_packet: {
      status: 'CANDIDATE', profile_id: damageProfileV3Id,
      evidence_status: damageProfile.evidence_status,
      input_count: rows.length, event_count: rows.length,
      native_witness_status: 'FULLY_CONSUMED_ALL',
      native_full_success_count: rows.length,
      native_callback_lookup_full_write_count: rows.length,
      native_input_sha256: 'c'.repeat(64),
      evidence_lookup_key_0x24_table_sha256:
        profile.evidence_lookup_key_0x24_table_sha256,
      evidence_lookup_key_0x2c_table_sha256:
        damageProfile.evidence_lookup_key_0x2c_table_sha256,
      runtime_image_status: 'MATCHED_USED',
      runtime_image_used: true,
      runtime_image_sha256: profile.evidence_runtime_image_sha256,
    },
    hero_minions_killed_snapshot: {
      status: 'CANDIDATE',
      profile_id: PROFILES.hero_minions_killed_snapshot.id,
      input_count: 10, event_count: 10, keyframe_count: 1,
      observed_participant_count: 10,
    },
    unit_apply_damage_roster_key_pair: {
      status: 'CANDIDATE', profile_id: rawPairProfile.id,
      evidence_status: rawPairProfile.evidence_status,
      damage_packet_count: rows.length, snapshot_count: 10,
      keyframe_count: 1, verified_raw_packet_count: rows.length + 10,
      input_count: rows.length + 10,
      event_count: rows.filter((entry) => entry.raw_param >= 0x400000ae
        && entry.raw_param <= 0x400000b7).length,
      excluded_alias_0x100_packet_count: alias,
    },
  } : {};
  const semantic = {
    replay_version: replayVersion, replay_sha256: replaySha,
    container_status: 'PASS', status: 'EXPERIMENTAL_CANDIDATE',
    api_status: 'CANDIDATE', requested_capabilities: [CAPABILITY],
    capability_results: { [CAPABILITY]: result, ...dependencies },
  };
  const analysis = {
    patch: '16.19', replay_version: replayVersion, replay_sha256: replaySha,
    source_path: SOURCE_PATH, event_storage: 'JSONL_ONLY',
    event_counts: { [EVENT]: rows.length },
    event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` }, events: null,
    semantic: { capability_results: structuredClone(semantic.capability_results) },
  };
  fs.writeFileSync(path.join(directory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(directory, 'replay_analysis.json'), JSON.stringify(analysis));
  const lines = rows.map((entry) => JSON.stringify(entry));
  fs.writeFileSync(path.join(directory, `${EVENT}.jsonl`),
    lines.length ? `${lines.join('\n')}\n` : '');
  return { directory, lines, replaySha, replayVersion };
}

function fixture(t, rows = defaultRows(), options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-lookup-roster-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, ...writeReplay(root, 'single', rows, options) };
}

function query(directory, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', EVENT, ...args],
    { encoding: 'utf8' });
}

function mutateResult(directory, mutate) {
  for (const basename of ['semantic_run.json', 'replay_analysis.json']) {
    const filename = path.join(directory, basename);
    const doc = JSON.parse(fs.readFileSync(filename, 'utf8'));
    mutate(basename === 'semantic_run.json'
      ? doc.capability_results[CAPABILITY]
      : doc.semantic.capability_results[CAPABILITY]);
    fs.writeFileSync(filename, JSON.stringify(doc));
  }
}

function promoteFixtureToV5(directory) {
  for (const basename of ['semantic_run.json', 'replay_analysis.json']) {
    const filename = path.join(directory, basename);
    const doc = JSON.parse(fs.readFileSync(filename, 'utf8'));
    const caps = basename === 'semantic_run.json'
      ? doc.capability_results : doc.semantic.capability_results;
    const count = caps[CAPABILITY].damage_packet_count;
    const f32Proof = {
      evidence_callback_f32_0x18_table_sha256:
        damageProfile.evidence_callback_f32_0x18_table_sha256,
      native_callback_f32_0x18_full_write_count: count,
      native_callback_f32_0x18_source_counts: {
        RAW_READER: 0, CONSTANT_0: count,
      },
    };
    caps[CAPABILITY].profile_id = currentProfile.id;
    caps[CAPABILITY].known_limits = [...currentProfile.known_limits];
    Object.assign(caps[CAPABILITY], structuredClone(f32Proof));
    const damage = caps.unit_apply_damage_packet;
    damage.profile_id = damageProfile.id;
    damage.evidence_callback_u32_0x10_table_sha256 =
      damageProfile.evidence_callback_u32_0x10_table_sha256;
    damage.native_callback_u32_0x10_full_write_count = count;
    damage.native_callback_u32_0x10_source_counts = {
      RAW_READER: 0, CONSTANT_0: count,
    };
    Object.assign(damage, structuredClone(f32Proof));
    const rawPair = caps.unit_apply_damage_roster_key_pair;
    rawPair.profile_id = currentRawPairProfile.id;
    Object.assign(rawPair, structuredClone(f32Proof));
    fs.writeFileSync(filename, JSON.stringify(doc));
  }
  const events = path.join(directory, `${EVENT}.jsonl`);
  fs.writeFileSync(events, fs.readFileSync(events, 'utf8').trimEnd()
    .split('\n').map((line) => {
      const entry = JSON.parse(line);
      entry.build_profile = currentProfile.id;
      entry.header_selector_bits_6_8 = 5;
      entry.native_callback_f32_0x18_candidate = 0;
      entry.native_callback_f32_0x18_encoded_bytes_hex = '3e3e3e3e';
      entry.native_callback_f32_0x18_source = 'CONSTANT_0';
      entry.native_callback_f32_0x18_raw_offset = null;
      entry.native_callback_f32_0x18_raw_bytes_hex = null;
      return JSON.stringify(entry);
    }).join('\n') + '\n');
}

function writeManifest(root, entries) {
  const hashes = {};
  for (const entry of entries) {
    for (const basename of ['semantic_run.json', 'replay_analysis.json',
      `${EVENT}.jsonl`]) {
      hashes[`replays/${path.basename(entry.directory)}/${basename}`] =
        sha256(fs.readFileSync(path.join(entry.directory, basename)));
    }
  }
  fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
    command_args: ['batch'],
    replay_inputs: entries.map((entry) => ({
      artifact_directory: `replays/${path.basename(entry.directory)}`,
      sha256: entry.replaySha, version: entry.replayVersion,
    })),
    output_hashes_excluding_manifest: hashes,
  }));
}

test('saved 821 lookup roster query preserves alias and other relation rows', (t) => {
  const { directory, lines } = fixture(t);
  const alias = query(directory, '--raw-param', '0x400001ae');
  assert.equal(alias.status, 0, alias.stderr);
  assert.equal(alias.stdout, `${lines[1]}\n`);
  const summary = JSON.parse(alias.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.capability, CAPABILITY);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.rows_unmodified, true);
  const rosterKey = query(directory, '--raw-param', '0x400000ae', '--limit', '1');
  assert.equal(rosterKey.status, 0, rosterKey.stderr);
  assert.equal(JSON.parse(rosterKey.stderr).matched_count, 1);
  const actorLike = query(directory, '--participant', '1');
  assert.equal(actorLike.status, 2, actorLike.stderr);
  assert.equal(JSON.parse(actorLike.stderr).code, 'PARTICIPANT_UNAVAILABLE');
  const onlyLookupOutput = fixture(t, defaultRows(),
    { withDependencies: false });
  assert.equal(query(onlyLookupOutput.directory,
    '--raw-param', '0x400001ae').status, 0);
});

test('saved lookup roster metadata rejects exact-build, v3 and count changes', (t) => {
  const changes = [
    (result) => { result.profile_id = 'foreign'; },
    (result) => { result.evidence_lookup_key_0x24_table_sha256 = '0'.repeat(64); },
    (result) => { result.runtime_image_used = false; },
    (result) => { result.depends_on = []; },
    (result) => { result.dependency_statuses.unit_apply_damage_packet = 'PASS'; },
    (result) => { result.damage_packet_count += 1; },
    (result) => { result.snapshot_count -= 1; },
    (result) => { result.matched_alias_0x100_packet_count = 2; },
    (result) => { result.unmatched_alias_0x100_packet_count = 1; },
    (result) => { result.first_unmatched_packet_refs.alias_0x100 = {}; },
    (result) => { result.verified_raw_packet_count -= 1; },
    (result) => { result.known_limits = []; },
    (result) => { result.damage_amount = 100; },
  ];
  for (const change of changes) {
    const { directory } = fixture(t);
    mutateResult(directory, change);
    const rejected = query(directory, '--raw-param', '0x400001ae');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code,
      'CAPABILITY_METADATA_MISMATCH');
  }
  const foreign = fixture(t, defaultRows(),
    { replayVersion: '16.19.820.7193' });
  const unsupported = query(foreign.directory, '--raw-param', '0x400001ae');
  assert.equal(unsupported.status, 2);
  assert.equal(JSON.parse(unsupported.stderr).code, 'UNSUPPORTED_EVENT_BUILD');
  const wrongDependency = fixture(t);
  const filename = path.join(wrongDependency.directory, 'semantic_run.json');
  const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
  semantic.capability_results.unit_apply_damage_packet.profile_id = 'v2';
  fs.writeFileSync(filename, JSON.stringify(semantic));
  const rejected = query(wrongDependency.directory, '--raw-param', '0x400001ae');
  assert.equal(rejected.status, 2);
  assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
});

test('saved lookup roster query validates every row after the output limit', (t) => {
  const changes = [
    (entry) => { entry.native_callback_lookup_key_0x24_encoded_bytes_hex = '00000000'; },
    (entry) => { entry.native_callback_lookup_key_0x24_raw_param_relation = 'EQUAL'; },
    (entry) => { entry.hero_raw_param += 1; },
    (entry) => { entry.hero_stats_participant_id_candidate = 10; },
    (entry) => { entry.lookup_resolution_status = 'RESOLVED'; },
    (entry) => { entry.actor_assignment_status = 'CONFIRMED'; },
    (entry) => { entry.source_target_role_status = 'SOURCE'; },
    (entry) => { entry.semantic_effect_status = 'CONFIRMED'; },
    (entry) => { entry.pair_basis = 'LOW_BYTE_MATCH'; },
    (entry) => { entry.unit_apply_damage_raw_packet_ref.raw_param += 1; },
    (entry) => { entry.unit_apply_damage_raw_packet_ref.raw_payload_hex = '00'; },
    (entry) => { entry.hero_stats_roster_raw_packet_ref.packet_id = 0x005f; },
    (entry) => { entry.raw_packet_refs.reverse(); },
    (entry) => { entry.damage_amount = 100; },
  ];
  for (const [changeIndex, change] of changes.entries()) {
    const rows = defaultRows();
    change(rows[2]);
    const { root, directory } = fixture(t, rows);
    const output = path.join(root, 'selected.jsonl');
    const rejected = query(directory, '--raw-param', '0x400000ae',
      '--limit', '1', '--output', output);
    assert.equal(rejected.status, 2,
      `corruption ${changeIndex}: ${rejected.stderr}`);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
  const reversed = fixture(t, defaultRows().reverse());
  const wrongOrder = query(reversed.directory, '--raw-param', '0x400000ae');
  assert.equal(wrongOrder.status, 2);
  assert.equal(JSON.parse(wrongOrder.stderr).code, 'INVALID_EVENT_ROW');
});

test('batch lookup roster query validates later Replay after global output limit', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-lookup-roster-batch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const aSha = 'a'.repeat(64);
  const bSha = 'b'.repeat(64);
  const first = writeReplay(root, 'first', [row(0, 0x400000ae, 0x400000ae, aSha)],
    { replaySha: aSha });
  const second = writeReplay(root, 'second', [
    row(0, 0x400000ae, 0x400000ae, bSha),
    row(1, 0x400000ae, 0x400001ae, bSha),
  ], { replaySha: bSha });
  writeManifest(root, [first, second]);
  const selected = query(root, '--raw-param', '0x400000ae', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${first.lines[0]}\n`);
  assert.equal(JSON.parse(selected.stderr).scanned_count, 3);
  const damaged = JSON.parse(second.lines[1]);
  damaged.lookup_resolution_status = 'RESOLVED';
  fs.writeFileSync(path.join(second.directory, `${EVENT}.jsonl`),
    `${second.lines[0]}\n${JSON.stringify(damaged)}\n`);
  writeManifest(root, [first, second]);
  const output = path.join(root, 'selected.jsonl');
  const rejected = query(root, '--raw-param', '0x400000ae', '--limit', '1',
    '--output', output);
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(fs.existsSync(output), false);
});

test('saved v2 lookup roster association accepts v4 damage and v2 raw pair', (t) => {
  const { directory } = fixture(t);
  for (const basename of ['semantic_run.json', 'replay_analysis.json']) {
    const filename = path.join(directory, basename);
    const doc = JSON.parse(fs.readFileSync(filename, 'utf8'));
    const caps = basename === 'semantic_run.json'
      ? doc.capability_results : doc.semantic.capability_results;
    caps[CAPABILITY].profile_id = v2Profile.id;
    caps[CAPABILITY].known_limits = [...v2Profile.known_limits];
    caps.unit_apply_damage_roster_key_pair.profile_id = v2RawPairProfile.id;
    const damage = caps.unit_apply_damage_packet;
    damage.profile_id = damageProfileV4Id;
    damage.evidence_callback_u32_0x10_table_sha256 =
      damageProfile.evidence_callback_u32_0x10_table_sha256;
    damage.native_callback_u32_0x10_full_write_count = damage.event_count;
    damage.native_callback_u32_0x10_source_counts = {
      RAW_READER: 0, CONSTANT_0: damage.event_count,
    };
    fs.writeFileSync(filename, JSON.stringify(doc));
  }
  const events = path.join(directory, `${EVENT}.jsonl`);
  fs.writeFileSync(events, fs.readFileSync(events, 'utf8').trimEnd()
    .split('\n').map((line) => {
      const entry = JSON.parse(line);
      entry.build_profile = v2Profile.id;
      return JSON.stringify(entry);
    }).join('\n') + '\n');
  const selected = query(directory, '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(JSON.parse(selected.stderr).scanned_count, defaultRows().length);
});

test('saved v3 lookup roster association validates +0x18 rows after limit', (t) => {
  const { directory } = fixture(t);
  promoteFixtureToV5(directory);
  const selected = query(directory, '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(JSON.parse(selected.stderr).scanned_count, defaultRows().length);
  const events = path.join(directory, `${EVENT}.jsonl`);
  const lines = fs.readFileSync(events, 'utf8').trimEnd().split('\n');
  const last = JSON.parse(lines.at(-1));
  last.native_callback_f32_0x18_candidate = 1;
  lines[lines.length - 1] = JSON.stringify(last);
  fs.writeFileSync(events, lines.join('\n') + '\n');
  const rejected = query(directory, '--limit', '1');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
});

test('saved v3 lookup roster association rejects forged +0x18 totals', (t) => {
  const { directory } = fixture(t);
  promoteFixtureToV5(directory);
  mutateResult(directory, (result) => {
    result.native_callback_f32_0x18_full_write_count -= 1;
  });
  const rejected = query(directory, '--limit', '1');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code,
    'CAPABILITY_METADATA_MISMATCH');
});

test('saved v4 lookup roster validates raw +0x1c row after limit', (t) => {
  const { directory } = fixture(t);
  promoteFixtureToV5(directory);
  promoteSavedAssociationV4(directory, EVENT, { rawRowIndex: 1 });
  const selected = query(directory, '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(JSON.parse(selected.stderr).scanned_count, defaultRows().length);
  const events = path.join(directory, `${EVENT}.jsonl`);
  const lines = fs.readFileSync(events, 'utf8').trimEnd().split('\n');
  const later = JSON.parse(lines[1]);
  later.native_callback_u32_0x1c_raw_offset = 8;
  lines[1] = JSON.stringify(later);
  fs.writeFileSync(events, `${lines.join('\n')}\n`);
  const rejected = query(directory, '--limit', '1');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
});
