'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_821_PROFILE: profile } =
  require('../src/decoders/rofl_16_19_821_hero_death_damage_lookup_key_cooccurrence_candidate');
const { HERO_DEATH_CANDIDATE_PROFILE_821: deathProfile } =
  require('../src/decoders/rofl_16_19_821_7343');
const { UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: damageProfile,
  decodeUnitApplyDamageLookupKeyFromRaw821: decodeKey } =
  require('../src/decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');
const { UNIT_APPLY_DAMAGE_ROSTER_KEY_821_PROFILE: rawPairProfile } =
  require('../src/decoders/rofl_16_19_821_unit_apply_damage_roster_key_candidate');
const { PROFILES } =
  require('../src/decoders/rofl_16_19_821_float_stats_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'hero_death_damage_lookup_key_cooccurrence_candidates';
const CAPABILITY = 'hero_death_damage_lookup_key_cooccurrence';
const SOURCE_PATH = 'synthetic.rofl';
const PACKET = '71875e460b083dbaef3ba6ec39b975';
const encodedCache = new Map();

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

// Find fixture bytes through the pinned transform, without copying its table.
function encodeKey(key, offset) {
  const cacheId = `${key}/${offset}`;
  if (encodedCache.has(cacheId)) return encodedCache.get(cacheId);
  const encoded = Buffer.alloc(4);
  for (let index = 0; index < 4; index += 1) {
    const wanted = (key >>> (8 * index)) & 0xff;
    let found = false;
    for (let candidate = 0; candidate < 256; candidate += 1) {
      const probe = Buffer.alloc(4);
      probe[index] = candidate;
      const decoded = decodeKey(probe.toString('hex'), offset);
      if (decoded !== null && ((decoded >>> (8 * index)) & 0xff) === wanted) {
        encoded[index] = candidate;
        found = true;
        break;
      }
    }
    assert.equal(found, true);
  }
  const hex = encoded.toString('hex');
  assert.equal(decodeKey(hex, offset), key);
  encodedCache.set(cacheId, hex);
  return hex;
}

function deathRef(index, role, packetId, payloadLength, blockOffset,
  rawParam, replaySha) {
  return {
    role, source_path: SOURCE_PATH, replay_sha256: replaySha,
    chunk_index: index + 2, chunk_id: index + 2,
    chunk_stream: 'game_chunk', chunk_file_offset: 200 + index * 100,
    decompressed_block_offset: blockOffset,
    decompressed_payload_offset: blockOffset + 6,
    packet_id: packetId, replay_time_ms: 1000 + index * 1000,
    payload_length: payloadLength, raw_param: rawParam,
    raw_payload_sha256: sha256(`${index}/${role}`),
  };
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

function damagePacket(index, ordinal, key24, key2c, rawParam,
  blockOffset, primaryOffset, dieSource, replaySha) {
  const payload = Buffer.from(PACKET, 'hex');
  const damageRef = {
    source_path: SOURCE_PATH, replay_sha256: replaySha,
    chunk_index: index + 2, chunk_id: index + 2,
    chunk_stream: 'game_chunk', chunk_file_offset: 200 + index * 100,
    decompressed_block_offset: blockOffset,
    decompressed_payload_offset: blockOffset + 6,
    packet_id: 0x005f, replay_time_ms: 1000 + index * 1000,
    payload_length: payload.length, raw_param: rawParam,
    raw_payload_hex: PACKET, raw_payload_sha256: sha256(payload),
  };
  assert.notEqual(blockOffset, primaryOffset);
  return {
    raw_param: rawParam,
    native_callback_lookup_key_u32_0x24_candidate: key24,
    native_callback_lookup_key_0x24_encoded_bytes_hex: encodeKey(key24, 0x24),
    native_callback_lookup_key_u32_0x2c_candidate: key2c,
    native_callback_lookup_key_0x2c_encoded_bytes_hex: encodeKey(key2c, 0x2c),
    native_callback_lookup_key_0x24_raw_param_relation:
      rawParam === key24 ? 'EQUAL'
        : rawParam - key24 === 0x100
          ? 'RAW_PARAM_IS_LOOKUP_PLUS_0X100' : 'OTHER',
    die_source_key2c_equal: dieSource === null ? null : key2c === dieSource,
    relative_to_death_primary:
      blockOffset < primaryOffset ? 'BEFORE_PRIMARY' : 'AFTER_PRIMARY',
    unit_apply_damage_raw_packet_ref: damageRef,
  };
}

function anchor(index, victim, dieSource, packetSpecs,
  replaySha = 'a'.repeat(64), optional = false) {
  const victimKey = 0x400000ad + victim;
  const victimRawParam = victimKey + (index === 0 ? 0x100 : 0);
  const deathRefs = [
    deathRef(index, 'candidate_primary', 0x0259, 5,
      1000, victimRawParam, replaySha),
    deathRef(index, 'candidate_paired', 0x0438, 37,
      1010, victimRawParam, replaySha),
    deathRef(index, 'corroborating_core_co_timed', 0x031b, 178,
      900, 0, replaySha),
    ...(optional ? [deathRef(index,
      'optional_corroborating_co_timed', 0x03d4, 3,
      850, 0, replaySha)] : []),
  ];
  const packets = packetSpecs.map(([key2c, rawParam, blockOffset], ordinal) =>
    damagePacket(index, ordinal, victimKey, key2c, rawParam,
      blockOffset, 1000, dieSource, replaySha));
  const before = packets.filter((packet) =>
    packet.relative_to_death_primary === 'BEFORE_PRIMARY').length;
  const dieSourceMatches = packets.filter((packet) =>
    packet.die_source_key2c_equal === true).length;
  const statsRef = rosterRef(victimKey, replaySha);
  return {
    event_type: 'HERO_DEATH_DAMAGE_LOOKUP_KEY_COOCCURRENCE_CANDIDATE',
    game_version: profile.replay_version, patch: '16.19',
    build_profile: profile.id, replay_sha256: replaySha,
    replay_time_ms: 1000 + index * 1000,
    victim_participant_id_candidate: victim,
    victim_raw_param: victimRawParam,
    victim_lookup_roster_key_u32_candidate: victimKey,
    die_source_network_id_candidate: dieSource,
    same_time_victim_key24_packet_candidate_count: packets.length,
    same_time_victim_key24_packet_before_primary_count: before,
    same_time_victim_key24_packet_after_primary_count: packets.length - before,
    same_time_die_source_key2c_packet_candidate_count:
      dieSource === null ? null : dieSourceMatches,
    die_source_key2c_match_status: dieSource === null ? 'DIE_SOURCE_UNAVAILABLE'
      : dieSourceMatches > 0 ? 'HAS_SAME_TIME_MATCH' : 'NO_SAME_TIME_MATCH',
    same_time_victim_key24_packet_candidates: packets,
    pair_basis: 'SAME_CHUNK_SAME_MILLISECOND_EXACT_CANONICAL_VICTIM_KEY24',
    lookup_resolution_status: 'UNKNOWN', actor_assignment_status: 'UNKNOWN',
    source_target_role_status: 'UNKNOWN', semantic_effect_status: 'UNKNOWN',
    confidence: 'CANDIDATE', semantic_status: profile.evidence_status,
    hero_death_raw_packet_ref: structuredClone(deathRefs[0]),
    hero_death_die_source_raw_packet_ref: structuredClone(deathRefs[1]),
    hero_death_raw_packet_refs: deathRefs,
    hero_stats_roster_raw_packet_ref: statsRef,
    raw_packet_refs: [
      ...structuredClone(deathRefs), structuredClone(statsRef),
      ...packets.map((packet) =>
        structuredClone(packet.unit_apply_damage_raw_packet_ref)),
    ],
  };
}

function defaultRows(replaySha = 'a'.repeat(64)) {
  return [
    anchor(0, 1, 0x400000af, [
      [0x400000af, 0x400001ae, 950],
      [0x400000b0, 0x40004007, 1020],
    ], replaySha, true),
    anchor(1, 2, 0x400000ae, [], replaySha),
    anchor(2, 3, null, [
      [0x400000ae, 0x40004009, 1020],
    ], replaySha),
  ];
}

function writeReplay(root, name, rows, {
  replaySha = 'a'.repeat(64), replayVersion = profile.replay_version,
  damageCount = rows.reduce((sum, row) =>
    sum + row.same_time_victim_key24_packet_candidate_count, 0) + 1,
} = {}) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const matchedPacketCount = rows.reduce((sum, row) =>
    sum + row.same_time_victim_key24_packet_candidate_count, 0);
  const withPackets = rows.filter((row) =>
    row.same_time_victim_key24_packet_candidate_count > 0).length;
  const withDieSourceMatch = rows.filter((row) =>
    row.die_source_key2c_match_status === 'HAS_SAME_TIME_MATCH').length;
  const withoutDieSourceMatch = rows.filter((row) =>
    row.die_source_key2c_match_status === 'NO_SAME_TIME_MATCH').length;
  const result = {
    profile_id: profile.id, depends_on: [...profile.depends_on],
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    evidence_lookup_key_0x24_table_sha256:
      profile.evidence_lookup_key_0x24_table_sha256,
    evidence_lookup_key_0x2c_table_sha256:
      profile.evidence_lookup_key_0x2c_table_sha256,
    known_limits: [...profile.known_limits], status: 'CANDIDATE',
    evidence_status: profile.evidence_status, replay_sha256: replaySha,
    runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
    dependency_statuses: {
      hero_death: 'CANDIDATE', unit_apply_damage_packet: 'CANDIDATE',
      hero_minions_killed_snapshot: 'CANDIDATE',
      unit_apply_damage_roster_key_pair: 'CANDIDATE',
    },
    death_anchor_count: rows.length, damage_packet_count: damageCount,
    snapshot_count: 10, canonical_roster_key_count: 10,
    verified_raw_damage_roster_packet_count: damageCount + 10,
    verified_hero_death_route_packet_count:
      rows.reduce((sum, row) => sum + row.hero_death_raw_packet_refs.length, 0),
    matched_victim_key24_packet_count: matchedPacketCount,
    death_anchor_with_victim_key24_packet_count: withPackets,
    death_anchor_without_victim_key24_packet_count: rows.length - withPackets,
    multiple_victim_key24_packet_anchor_count: rows.filter((row) =>
      row.same_time_victim_key24_packet_candidate_count > 1).length,
    max_victim_key24_packet_count_per_anchor: Math.max(0, ...rows.map((row) =>
      row.same_time_victim_key24_packet_candidate_count)),
    matched_die_source_key2c_packet_count: rows.reduce((sum, row) =>
      sum + (row.same_time_die_source_key2c_packet_candidate_count ?? 0), 0),
    death_anchor_with_die_source_key2c_match_count: withDieSourceMatch,
    death_anchor_without_die_source_key2c_match_count: withoutDieSourceMatch,
    death_anchor_die_source_unavailable_count:
      rows.length - withDieSourceMatch - withoutDieSourceMatch,
    input_count: rows.length + damageCount, event_count: rows.length,
  };
  const dependencies = {
    hero_death: {
      status: 'CANDIDATE', profile_id: deathProfile.id,
      evidence_status: 'CANDIDATE_821_REPLAY_TAIL_ROUTE_FINGERPRINT',
      evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
      source_id_lookup_table_sha256:
        deathProfile.source_id_lookup_table_sha256,
      event_count: rows.length, matched_core_count: rows.length,
      matched_core_supporting_packet_count:
        result.verified_hero_death_route_packet_count,
    },
    unit_apply_damage_packet: {
      status: 'CANDIDATE', profile_id: damageProfile.id,
      evidence_status: damageProfile.evidence_status,
      input_count: damageCount, event_count: damageCount,
      native_witness_status: 'FULLY_CONSUMED_ALL',
      native_full_success_count: damageCount,
      native_callback_lookup_full_write_count: damageCount,
      native_input_sha256: 'c'.repeat(64),
      evidence_lookup_key_0x24_table_sha256:
        profile.evidence_lookup_key_0x24_table_sha256,
      evidence_lookup_key_0x2c_table_sha256:
        profile.evidence_lookup_key_0x2c_table_sha256,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
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
      damage_packet_count: damageCount, snapshot_count: 10,
      canonical_roster_key_count: 10,
      verified_raw_packet_count: damageCount + 10,
      input_count: damageCount + 10,
      runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
      runtime_image_sha256: profile.evidence_runtime_image_sha256,
    },
  };
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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-death-damage-query-'));
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
    const document = JSON.parse(fs.readFileSync(filename, 'utf8'));
    mutate(basename === 'semantic_run.json'
      ? document.capability_results[CAPABILITY]
      : document.semantic.capability_results[CAPABILITY]);
    fs.writeFileSync(filename, JSON.stringify(document));
  }
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

test('saved death/damage lookup query keeps zero and multiple anchors with exact filters', (t) => {
  const { directory, lines } = fixture(t);
  const victim = query(directory, '--participant', '1');
  assert.equal(victim.status, 0, victim.stderr);
  assert.equal(victim.stdout, `${lines[0]}\n`);
  assert.equal(JSON.parse(victim.stderr).matched_count, 1);
  const zero = query(directory, '--participant', '2');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${lines[1]}\n`);
  const damage = query(directory, '--raw-param', '0x400001ae');
  assert.equal(damage.status, 0, damage.stderr);
  assert.equal(damage.stdout, `${lines[0]}\n`);
  const summary = JSON.parse(damage.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.rows_unmodified, true);
  const deathParamOnly = query(directory, '--raw-param', '0x400000af');
  assert.equal(deathParamOnly.status, 0, deathParamOnly.stderr);
  assert.equal(deathParamOnly.stdout, '');
  const time = query(directory, '--from-ms', '3000', '--to-ms', '3000');
  assert.equal(time.status, 0, time.stderr);
  assert.equal(time.stdout, `${lines[2]}\n`);
});

test('saved death/damage lookup query filters all three validated +0x2c match statuses', (t) => {
  const { directory, lines } = fixture(t);
  for (const [value, index] of [
    ['has', 0], ['none', 1], ['unavailable', 2],
  ]) {
    const selected = query(directory, '--die-source-key2c-match', value,
      '--limit', '1');
    assert.equal(selected.status, 0, selected.stderr);
    assert.equal(selected.stdout, `${lines[index]}\n`);
    const summary = JSON.parse(selected.stderr);
    assert.equal(summary.scanned_count, 3);
    assert.equal(summary.matched_count, 1);
    assert.equal(summary.emitted_count, 1);
    assert.equal(summary.filters.die_source_key2c_match, value);
    assert.equal(summary.rows_unmodified, true);
  }
  const combined = query(directory, '--die-source-key2c-match', 'has',
    '--participant', '2');
  assert.equal(combined.status, 0, combined.stderr);
  assert.equal(combined.stdout, '');
  assert.equal(JSON.parse(combined.stderr).matched_count, 0);
});

test('death/damage +0x2c match filter rejects invalid value or event', (t) => {
  const { directory } = fixture(t);
  const invalid = query(directory, '--die-source-key2c-match', 'HAS');
  assert.equal(invalid.status, 1);
  assert.match(invalid.stderr, /requires has, none or unavailable/);
  const wrongEvent = spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--event', 'hero_death_candidates',
      '--die-source-key2c-match', 'none'], { encoding: 'utf8' });
  assert.equal(wrongEvent.status, 1);
  assert.match(wrongEvent.stderr,
    /requires hero_death_damage_lookup_key_cooccurrence_candidates/);
});

test('death/damage +0x2c match query validates nonmatching rows after limit', (t) => {
  const rows = defaultRows();
  rows[2].lookup_resolution_status = 'RESOLVED';
  const { root, directory } = fixture(t, rows);
  const output = path.join(root, 'selected.jsonl');
  const rejected = query(directory, '--die-source-key2c-match', 'none',
    '--limit', '1', '--output', output);
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(fs.existsSync(output), false);
});

test('saved death/damage lookup metadata rejects build, image and count changes', (t) => {
  const changes = [
    (result) => { result.profile_id = 'foreign'; },
    (result) => { result.evidence_lookup_key_0x2c_table_sha256 = '0'.repeat(64); },
    (result) => { result.runtime_image_used = false; },
    (result) => { result.depends_on = []; },
    (result) => { result.dependency_statuses.hero_death = 'PASS'; },
    (result) => { result.death_anchor_count += 1; },
    (result) => { result.damage_packet_count -= 1; },
    (result) => { result.death_anchor_without_victim_key24_packet_count += 1; },
    (result) => { result.death_anchor_die_source_unavailable_count += 1; },
    (result) => { result.verified_hero_death_route_packet_count -= 1; },
    (result) => { result.known_limits = []; },
    (result) => { result.confirmed_fatal_packet_count = 1; },
  ];
  for (const change of changes) {
    const { directory } = fixture(t);
    mutateResult(directory, change);
    const rejected = query(directory, '--participant', '1');
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code,
      'CAPABILITY_METADATA_MISMATCH');
  }
  const foreign = fixture(t, defaultRows(),
    { replayVersion: '16.19.820.7193' });
  const unsupported = query(foreign.directory, '--participant', '1');
  assert.equal(unsupported.status, 2);
  assert.equal(JSON.parse(unsupported.stderr).code, 'UNSUPPORTED_EVENT_BUILD');
  const wrongDependency = fixture(t);
  const filename = path.join(wrongDependency.directory, 'semantic_run.json');
  const semantic = JSON.parse(fs.readFileSync(filename, 'utf8'));
  semantic.capability_results.unit_apply_damage_packet.profile_id = 'v2';
  fs.writeFileSync(filename, JSON.stringify(semantic));
  const rejected = query(wrongDependency.directory, '--participant', '1');
  assert.equal(rejected.status, 2);
  assert.equal(JSON.parse(rejected.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
});

test('saved death/damage lookup validates nested packets and later anchors after limit', (t) => {
  const changes = [
    (entry) => { entry.victim_lookup_roster_key_u32_candidate += 1; },
    (entry) => { entry.pair_basis = 'FATAL_DAMAGE_PACKET'; },
    (entry) => { entry.die_source_key2c_match_status = 'HAS_SAME_TIME_MATCH'; },
    (entry) => { entry.hero_death_raw_packet_refs[0].role = 'actor'; },
    (entry) => { entry.hero_stats_roster_raw_packet_ref.raw_param += 1; },
    (entry) => { entry.lookup_resolution_status = 'RESOLVED'; },
    (entry) => { entry.actor_assignment_status = 'CONFIRMED'; },
    (entry) => { entry.raw_packet_refs.reverse(); },
    (entry) => { entry.actual_damage = 100; },
  ];
  for (const [index, change] of changes.entries()) {
    const rows = defaultRows();
    change(rows[2]);
    const { root, directory } = fixture(t, rows);
    const output = path.join(root, 'selected.jsonl');
    const rejected = query(directory, '--participant', '1',
      '--limit', '1', '--output', output);
    assert.equal(rejected.status, 2, `change ${index}: ${rejected.stderr}`);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
  const nestedChanges = [
    (packet) => { packet.native_callback_lookup_key_0x24_encoded_bytes_hex = '00000000'; },
    (packet) => { packet.native_callback_lookup_key_0x2c_encoded_bytes_hex = '00000000'; },
    (packet) => { packet.die_source_key2c_equal = true; },
    (packet) => { packet.relative_to_death_primary = 'BEFORE_PRIMARY'; },
    (packet) => { packet.unit_apply_damage_raw_packet_ref.raw_payload_hex = '00'; },
    (packet) => { packet.unit_apply_damage_raw_packet_ref.chunk_index += 1; },
    (packet) => { packet.confirmed_killer = 1; },
  ];
  for (const [index, change] of nestedChanges.entries()) {
    const rows = defaultRows();
    change(rows[2].same_time_victim_key24_packet_candidates[0]);
    const { root, directory } = fixture(t, rows);
    const rejected = query(directory, '--participant', '1',
      '--limit', '1', '--output', path.join(root, 'selected.jsonl'));
    assert.equal(rejected.status, 2, `nested change ${index}: ${rejected.stderr}`);
    assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
  }
  const rows = defaultRows();
  rows[2].same_time_victim_key24_packet_candidate_count = 2;
  const wrongCount = fixture(t, rows);
  const rejected = query(wrongCount.directory, '--limit', '1');
  assert.equal(rejected.status, 2);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
});

test('batch death/damage query validates later Replay after global output limit', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-death-damage-batch-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const aSha = 'a'.repeat(64);
  const bSha = 'b'.repeat(64);
  const first = writeReplay(root, 'first', [
    anchor(0, 1, 0x400000af, [[0x400000af, 0x400001ae, 950]], aSha, true),
  ], { replaySha: aSha });
  const second = writeReplay(root, 'second', [
    anchor(0, 1, 0x400000af, [[0x400000af, 0x400001ae, 950]], bSha, true),
    anchor(1, 2, 0x400000ae, [], bSha),
  ], { replaySha: bSha });
  writeManifest(root, [first, second]);
  const selected = query(root, '--participant', '1', '--limit', '1');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${first.lines[0]}\n`);
  assert.equal(JSON.parse(selected.stderr).scanned_count, 3);
  const noMatch = query(root, '--die-source-key2c-match', 'none',
    '--limit', '1');
  assert.equal(noMatch.status, 0, noMatch.stderr);
  assert.equal(noMatch.stdout, `${second.lines[1]}\n`);
  assert.equal(JSON.parse(noMatch.stderr).scanned_count, 3);
  const corrupted = JSON.parse(second.lines[1]);
  corrupted.lookup_resolution_status = 'RESOLVED';
  fs.writeFileSync(path.join(second.directory, `${EVENT}.jsonl`),
    `${second.lines[0]}\n${JSON.stringify(corrupted)}\n`);
  writeManifest(root, [first, second]);
  const output = path.join(root, 'selected.jsonl');
  const rejected = query(root, '--participant', '1', '--limit', '1',
    '--output', output);
  assert.equal(rejected.status, 2, rejected.stderr);
  assert.equal(JSON.parse(rejected.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(fs.existsSync(output), false);
});
