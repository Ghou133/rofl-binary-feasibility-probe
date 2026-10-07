'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V1_821: profile,
  UNIT_APPLY_DAMAGE_ROSTER_KEY_PROFILE_V2_821: v2Profile,
  UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE: currentProfile } =
  require('../src/decoders/rofl_16_19_821_unit_apply_damage_roster_key_candidate');
const { UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: currentDamageProfile,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V3_ID_821: damageProfileV3Id,
  UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_V4_ID_821: damageProfileV4Id,
  decodeUnitApplyDamageCallbackF32FromRaw821,
  decodeUnitApplyDamageCallbackF32At18FromEncoded821 } =
  require('../src/decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');
const { PROFILES } =
  require('../src/decoders/rofl_16_19_821_float_stats_candidate');
const { promoteSavedAssociationV4 } =
  require('./helpers/damage_association_v4_saved');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'unit_apply_damage_roster_key_candidates';
const CAPABILITY = 'unit_apply_damage_roster_key_pair';
const SHA = 'a'.repeat(64);
const SOURCE_PATH = 'synthetic.rofl';
const PACKET = '71875e460b083dbaef3ba6ec39b975';
const RAW_F32_18_PACKET = '3706a54411d863b80b68bb01d1ca1e9bde73ec6b75';

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function statsRef(key) {
  const participant = key - 0x400000ae + 1;
  return {
    source_path: SOURCE_PATH, replay_sha256: SHA,
    chunk_index: 1, chunk_id: 1, chunk_stream: 'keyframe',
    chunk_file_offset: 100, decompressed_block_offset: 100 + participant * 1300,
    decompressed_payload_offset: 112 + participant * 1300,
    packet_id: 0x0089, replay_time_ms: 0, payload_length: 1263,
    raw_param: key,
    raw_payload_sha256: sha256(Buffer.alloc(1263, participant)),
  };
}

function row(index, key = 0x400000ae) {
  const payload = Buffer.from(PACKET, 'hex');
  const time = 1000 + index;
  const damageRef = {
    source_path: SOURCE_PATH, replay_sha256: SHA,
    chunk_index: 2, chunk_id: 2, chunk_stream: 'game_chunk',
    chunk_file_offset: 200, decompressed_block_offset: 1000 + index * 100,
    decompressed_payload_offset: 1006 + index * 100,
    packet_id: 0x005f, replay_time_ms: time, payload_length: payload.length,
    raw_param: key, raw_payload_hex: PACKET,
    raw_payload_sha256: sha256(payload),
  };
  const rosterRef = statsRef(key);
  return {
    event_type: 'UNIT_APPLY_DAMAGE_ROSTER_KEY_CANDIDATE',
    game_version: profile.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: SHA,
    replay_time_ms: time, raw_param: key,
    hero_stats_participant_id_candidate: key - 0x400000ae + 1,
    native_callback_f32_0x20_candidate:
      decodeUnitApplyDamageCallbackF32FromRaw821(PACKET.slice(10, 18)),
    native_callback_f32_0x20_source: 'RAW_READER',
    pair_basis: 'EXACT_FULL_RAW_PARAM_IN_CANONICAL_HEROSTATS_ROSTER',
    actor_assignment_status: 'UNKNOWN', source_target_role_status: 'UNKNOWN',
    semantic_effect_status: 'UNKNOWN', confidence: 'CANDIDATE',
    semantic_status: profile.evidence_status,
    unit_apply_damage_raw_packet_ref: damageRef,
    hero_stats_roster_raw_packet_ref: rosterRef,
    raw_packet_refs: [structuredClone(damageRef), structuredClone(rosterRef)],
  };
}

function writeReplay(root, rows, {
  replayVersion = profile.replay_version, status = 'CANDIDATE',
  withDependencies = true,
} = {}) {
  const directory = path.join(root, 'replay');
  fs.mkdirSync(directory);
  const result = {
    profile_id: profile.id, depends_on: [...profile.depends_on],
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    known_limits: [...profile.known_limits], status,
    evidence_status: profile.evidence_status, replay_sha256: SHA,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
    dependency_statuses: {
      unit_apply_damage_packet: 'CANDIDATE',
      hero_minions_killed_snapshot: 'CANDIDATE',
    },
    damage_packet_count: rows.length, snapshot_count: 10, keyframe_count: 1,
    canonical_roster_key_count: 10,
    matched_full_key_packet_count: rows.length, unmatched_packet_count: 0,
    excluded_alias_0x100_packet_count: 0,
    first_excluded_packet_refs: { alias_0x100: null, unmatched_other: null },
    verified_raw_packet_count: rows.length + 10,
    input_count: rows.length + 10, event_count: rows.length,
  };
  const dependencies = withDependencies ? {
    unit_apply_damage_packet: {
      status: 'CANDIDATE', profile_id: damageProfileV3Id,
      event_count: rows.length, runtime_image_status: 'MATCHED_USED',
      runtime_image_sha256: profile.evidence_runtime_image_sha256,
      native_witness_status: 'FULLY_CONSUMED_ALL',
    },
    hero_minions_killed_snapshot: {
      status: 'CANDIDATE',
      profile_id: PROFILES.hero_minions_killed_snapshot.id,
      event_count: 10, keyframe_count: 1,
    },
  } : {};
  const semantic = {
    replay_version: replayVersion, replay_sha256: SHA,
    container_status: 'PASS', status: 'EXPERIMENTAL_CANDIDATE',
    api_status: 'CANDIDATE', requested_capabilities: [CAPABILITY],
    capability_results: { [CAPABILITY]: result, ...dependencies },
  };
  const analysis = {
    patch: '16.19', replay_version: replayVersion, replay_sha256: SHA,
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
  return { directory, lines };
}

function fixture(t, rows = [row(0), row(1, 0x400000af)], options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-damage-roster-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return { root, ...writeReplay(root, rows, options) };
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
        currentDamageProfile.evidence_callback_f32_0x18_table_sha256,
      native_callback_f32_0x18_full_write_count: count,
      native_callback_f32_0x18_source_counts: {
        RAW_READER: 0, CONSTANT_0: count,
      },
    };
    caps[CAPABILITY].profile_id = currentProfile.id;
    caps[CAPABILITY].known_limits = [...currentProfile.known_limits];
    Object.assign(caps[CAPABILITY], structuredClone(f32Proof));
    const damage = caps.unit_apply_damage_packet;
    damage.profile_id = currentDamageProfile.id;
    damage.evidence_callback_u32_0x10_table_sha256 =
      currentDamageProfile.evidence_callback_u32_0x10_table_sha256;
    damage.native_callback_u32_0x10_full_write_count = count;
    damage.native_callback_u32_0x10_source_counts = {
      RAW_READER: 0, CONSTANT_0: count,
    };
    Object.assign(damage, structuredClone(f32Proof));
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

test('saved exact 821 roster key pairs retain original rows under raw-param filtering', (t) => {
  const rows = [row(0), row(1, 0x400000af), row(2)];
  const { directory, lines } = fixture(t, rows);
  const selected = query(directory, '--raw-param', '0x400000ae', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${lines[0]}\n`);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.capability, CAPABILITY);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.rows_unmodified, true);
  const withoutSavedDependencies = fixture(t, [row(0)],
    { withDependencies: false });
  assert.equal(query(withoutSavedDependencies.directory,
    '--raw-param', '0x400000ae').status, 0);
});

test('saved roster key pair metadata rejects profile, dependency and count changes', (t) => {
  const changes = [
    (result) => { result.profile_id = 'foreign'; },
    (result) => { result.runtime_image_sha256 = '0'.repeat(64); },
    (result) => { result.depends_on = []; },
    (result) => { result.dependency_statuses.unit_apply_damage_packet = 'PASS'; },
    (result) => { result.damage_packet_count += 1; },
    (result) => { result.snapshot_count -= 1; },
    (result) => { result.matched_full_key_packet_count -= 1; },
    (result) => { result.excluded_alias_0x100_packet_count += 1; },
    (result) => { result.verified_raw_packet_count -= 1; },
    (result) => { result.first_excluded_packet_refs.alias_0x100 = {}; },
    (result) => { result.known_limits = []; },
    (result) => { result.effective_damage = 100; },
  ];
  for (const change of changes) {
    const { directory } = fixture(t);
    mutateResult(directory, change);
    const rejected = query(directory, '--raw-param', '0x400000ae');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code,
      'CAPABILITY_METADATA_MISMATCH');
  }
  const foreign = fixture(t, [row(0)],
    { replayVersion: '16.19.820.7193' });
  const unsupported = query(foreign.directory, '--raw-param', '0x400000ae');
  assert.equal(unsupported.status, 2);
  assert.equal(JSON.parse(unsupported.stderr).code, 'UNSUPPORTED_EVENT_BUILD');

  const changedSource = fixture(t);
  const filename = path.join(changedSource.directory, 'semantic_run.json');
  const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
  semantic.capability_results.unit_apply_damage_packet.event_count += 1;
  fs.writeFileSync(filename, JSON.stringify(semantic));
  const sourceMismatch = query(changedSource.directory,
    '--raw-param', '0x400000ae');
  assert.equal(sourceMismatch.status, 2);
  assert.equal(JSON.parse(sourceMismatch.stderr).code,
    'CAPABILITY_METADATA_MISMATCH');
});

test('saved v1 association rejects v4-only metadata on its v3 damage source', (t) => {
  const { directory } = fixture(t);
  for (const basename of ['semantic_run.json', 'replay_analysis.json']) {
    const filename = path.join(directory, basename);
    const doc = JSON.parse(fs.readFileSync(filename, 'utf8'));
    const capabilities = basename === 'semantic_run.json'
      ? doc.capability_results : doc.semantic.capability_results;
    capabilities.unit_apply_damage_packet.evidence_callback_u32_0x10_table_sha256 =
      currentDamageProfile.evidence_callback_u32_0x10_table_sha256;
    fs.writeFileSync(filename, JSON.stringify(doc));
  }
  const rejected = query(directory, '--raw-param', '0x400000ae');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
});

test('saved v2 association accepts exact v4 damage provenance', (t) => {
  const { directory } = fixture(t);
  for (const basename of ['semantic_run.json', 'replay_analysis.json']) {
    const filename = path.join(directory, basename);
    const doc = JSON.parse(fs.readFileSync(filename, 'utf8'));
    const capabilities = basename === 'semantic_run.json'
      ? doc.capability_results : doc.semantic.capability_results;
    const result = capabilities[CAPABILITY];
    result.profile_id = v2Profile.id;
    result.known_limits = [...v2Profile.known_limits];
    const damage = capabilities.unit_apply_damage_packet;
    damage.profile_id = damageProfileV4Id;
    damage.evidence_callback_u32_0x10_table_sha256 =
      currentDamageProfile.evidence_callback_u32_0x10_table_sha256;
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
  const selected = query(directory, '--raw-param', '0x400000ae', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  const summary = JSON.parse(selected.stderr);
  assert.equal(summary.scanned_count, 2);
  assert.equal(summary.emitted_count, 1);
});

test('saved v3 roster association validates +0x18 rows after limit', (t) => {
  const { directory } = fixture(t, [row(0), row(1, 0x400000af), row(2)]);
  promoteFixtureToV5(directory);
  const selected = query(directory, '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(JSON.parse(selected.stderr).scanned_count, 3);
  const events = path.join(directory, `${EVENT}.jsonl`);
  const lines = fs.readFileSync(events, 'utf8').trimEnd().split('\n');
  const last = JSON.parse(lines.at(-1));
  last.native_callback_f32_0x18_source = 'RAW_READER';
  lines[lines.length - 1] = JSON.stringify(last);
  fs.writeFileSync(events, lines.join('\n') + '\n');
  const rejected = query(directory, '--limit', '1');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
});

test('saved v3 roster association rejects forged +0x18 totals', (t) => {
  const { directory } = fixture(t);
  promoteFixtureToV5(directory);
  mutateResult(directory, (result) => {
    result.native_callback_f32_0x18_source_counts.CONSTANT_0 += 1;
  });
  const rejected = query(directory, '--limit', '1');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code,
    'CAPABILITY_METADATA_MISMATCH');
});

test('saved v3 roster association verifies raw +0x18 bytes after limit', (t) => {
  const { directory } = fixture(t);
  promoteFixtureToV5(directory);
  const events = path.join(directory, `${EVENT}.jsonl`);
  const lines = fs.readFileSync(events, 'utf8').trimEnd().split('\n');
  const later = JSON.parse(lines[1]);
  const payload = Buffer.from(RAW_F32_18_PACKET, 'hex');
  const ref = later.unit_apply_damage_raw_packet_ref;
  ref.raw_payload_hex = RAW_F32_18_PACKET;
  ref.raw_payload_sha256 = sha256(payload);
  ref.payload_length = payload.length;
  later.raw_packet_refs[0] = structuredClone(ref);
  later.native_callback_f32_0x20_candidate =
    decodeUnitApplyDamageCallbackF32FromRaw821(
      payload.subarray(13, 17).toString('hex'));
  later.header_selector_bits_6_8 = 0;
  later.native_callback_f32_0x18_source = 'RAW_READER';
  later.native_callback_f32_0x18_raw_offset = 9;
  later.native_callback_f32_0x18_raw_bytes_hex =
    payload.subarray(9, 13).toString('hex');
  later.native_callback_f32_0x18_encoded_bytes_hex =
    Buffer.from(payload.subarray(9, 13)).reverse().toString('hex');
  later.native_callback_f32_0x18_candidate =
    decodeUnitApplyDamageCallbackF32At18FromEncoded821(
      later.native_callback_f32_0x18_encoded_bytes_hex);
  lines[1] = JSON.stringify(later);
  fs.writeFileSync(events, lines.join('\n') + '\n');
  for (const basename of ['semantic_run.json', 'replay_analysis.json']) {
    const filename = path.join(directory, basename);
    const doc = JSON.parse(fs.readFileSync(filename, 'utf8'));
    const caps = basename === 'semantic_run.json'
      ? doc.capability_results : doc.semantic.capability_results;
    for (const capability of [CAPABILITY, 'unit_apply_damage_packet']) {
      caps[capability].native_callback_f32_0x18_source_counts = {
        RAW_READER: 1, CONSTANT_0: 1,
      };
    }
    fs.writeFileSync(filename, JSON.stringify(doc));
  }
  const selected = query(directory, '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(JSON.parse(selected.stderr).scanned_count, 2);

  later.native_callback_f32_0x18_raw_bytes_hex = '00000000';
  lines[1] = JSON.stringify(later);
  fs.writeFileSync(events, lines.join('\n') + '\n');
  const rejected = query(directory, '--limit', '1');
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
});

test('saved roster key pair checks every row and source order after output limit', (t) => {
  const changes = [
    (entry) => { entry.hero_stats_participant_id_candidate = 10; },
    (entry) => { entry.actor_assignment_status = 'CONFIRMED'; },
    (entry) => { entry.source_target_role_status = 'SOURCE'; },
    (entry) => { entry.semantic_effect_status = 'CONFIRMED'; },
    (entry) => { entry.pair_basis = 'LOW_BYTE_MATCH'; },
    (entry) => { entry.unit_apply_damage_raw_packet_ref.raw_param += 0x100; },
    (entry) => { entry.unit_apply_damage_raw_packet_ref.raw_payload_hex = '00'; },
    (entry) => { entry.hero_stats_roster_raw_packet_ref.packet_id = 0x005f; },
    (entry) => { entry.hero_stats_roster_raw_packet_ref.chunk_stream = 'game_chunk'; },
    (entry) => { entry.raw_packet_refs.reverse(); },
    (entry) => { entry.native_callback_f32_0x20_source = 'CONSTANT_2'; },
    (entry) => { entry.effective_damage = 100; },
  ];
  for (const change of changes) {
    const damaged = row(1, 0x400000af);
    change(damaged);
    const { root, directory } = fixture(t, [row(0), damaged]);
    const output = path.join(root, 'selected.jsonl');
    const rejected = query(directory, '--raw-param', '0x400000ae',
      '--limit', '1', '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
  const reordered = fixture(t, [row(1, 0x400000af), row(0)]);
  const wrongOrder = query(reordered.directory, '--raw-param', '0x400000ae');
  assert.equal(wrongOrder.status, 2, wrongOrder.stderr);
  assert.equal(JSON.parse(wrongOrder.stderr).code, 'INVALID_EVENT_ROW');
});

test('saved v4 roster query validates raw +0x1c span after output limit', (t) => {
  const make = () => {
    const saved = fixture(t, [row(0), row(1, 0x400000af), row(2)]);
    promoteFixtureToV5(saved.directory);
    promoteSavedAssociationV4(saved.directory, EVENT, { rawRowIndex: 1 });
    return saved;
  };
  const valid = make();
  const selected = query(valid.directory, '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(JSON.parse(selected.stderr).scanned_count, 3);
  for (const mutate of [
    (entry) => { entry.header_selector_bits_12_14 = 6; },
    (entry) => { entry.native_callback_u32_0x1c_candidate += 1; },
    (entry) => { entry.native_callback_u32_0x1c_encoded_bytes_hex = '00000000'; },
    (entry) => { entry.native_callback_u32_0x1c_source = 'CONSTANT_0'; },
    (entry) => { entry.native_callback_u32_0x1c_raw_call_rva = '0xf4a742'; },
    (entry) => { entry.native_callback_u32_0x1c_raw_offset = 8; },
    (entry) => { entry.native_callback_u32_0x1c_raw_bytes_hex = '00f100'; },
  ]) {
    const saved = make();
    const file = path.join(saved.directory, `${EVENT}.jsonl`);
    const rows = fs.readFileSync(file, 'utf8').trimEnd().split('\n')
      .map((line) => JSON.parse(line));
    mutate(rows[1]);
    fs.writeFileSync(file, `${rows.map((entry) => JSON.stringify(entry)).join('\n')}\n`);
    const rejected = query(saved.directory, '--limit', '1');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
  }
  for (const mutate of [
    (result) => { result.evidence_callback_u32_0x1c_table_sha256 = '0'.repeat(64); },
    (result) => { result.native_callback_u32_0x1c_full_write_count -= 1; },
    (result) => { result.native_callback_u32_0x1c_source_counts.RAW_READER += 1; },
  ]) {
    const saved = make();
    mutateResult(saved.directory, mutate);
    const rejected = query(saved.directory, '--limit', '1');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code,
      'CAPABILITY_METADATA_MISMATCH');
  }
});
