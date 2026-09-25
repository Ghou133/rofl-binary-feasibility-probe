'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { CHAMPION_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_champion_die_hero_death_pair_candidate');
const { CHAMPION_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_champion_kill_die_hero_death_pair_candidate');
const { CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_champion_multiple_kill_die_hero_death_pair_candidate');
const { ON_SHUTDOWN_DIE_HERO_DEATH_PAIR_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_on_shutdown_die_hero_death_pair_candidate');
const { CHAMPION_DIE_EVENT_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_champion_die_event_packet_candidate');
const { CHAMPION_KILL_EVENT_PACKET_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_champion_kill_event_packet_candidate');
const { CHAMPION_MULTIPLE_KILL_EVENT_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_champion_multiple_kill_event_packet_candidate');
const { ON_SHUTDOWN_EVENT_PACKET_821_PROFILE } =
  require('../src/decoders/rofl_16_19_821_on_shutdown_event_packet_candidate');
const { HERO_DEATH_CANDIDATE_PROFILE_821 } =
  require('../src/decoders/rofl_16_19_821_7343');

const CLI = path.resolve(__dirname, '../src/cli.js');
const SHA = 'a'.repeat(64);
const VERSION = '16.19.820.7193';
const EVENT = 'hero_level_state_candidates';
const CAPABILITY = 'hero_level_state';
const INVENTORY_EVENT = 'hero_inventory_packet_candidates';
const BROADCAST_EVENT = 'hero_inventory_broadcast_packet_candidates';
const SET_ITEM_EVENT = 'hero_inventory_set_item_packet_candidates';
const HEAL_PACKET_EVENT = 'params_heal_packet_candidates';
const SHIELD_PAIR_EVENT = 'shielding_params_packet_pair_candidates';
const STEALTH_PACKET_EVENT = 'stealth_event_packet_candidates';
const CAST_SPELL_ANS_EVENT = 'cast_spell_ans_packet_candidates';
const CHAMPION_DIE_EVENT = 'champion_die_event_packet_candidates';
const CHAMPION_KILL_EVENT = 'champion_kill_event_packet_candidates';
const CHAMPION_MULTIPLE_KILL_EVENT = 'champion_multiple_kill_event_packet_candidates';
const SHUTDOWN_PACKET_EVENT = 'on_shutdown_event_packet_candidates';
const DIE_PAIR_EVENT = 'champion_die_hero_death_pair_candidates';
const KILL_GROUP_EVENT = 'champion_kill_die_hero_death_pair_candidates';
const MULTI_GROUP_EVENT = 'champion_multiple_kill_die_hero_death_pair_candidates';
const SHUTDOWN_GROUP_EVENT = 'on_shutdown_die_hero_death_pair_candidates';
const ASSOCIATION_EVENTS = [DIE_PAIR_EVENT, KILL_GROUP_EVENT, MULTI_GROUP_EVENT,
  SHUTDOWN_GROUP_EVENT];

function rewriteJson(filename, edit) {
  const value = JSON.parse(fs.readFileSync(filename, 'utf8'));
  edit(value);
  fs.writeFileSync(filename, JSON.stringify(value));
}

function associationArtifact(t, eventKey) {
  const killGroup = eventKey === KILL_GROUP_EVENT;
  const multiGroup = eventKey === MULTI_GROUP_EVENT;
  const shutdownGroup = eventKey === SHUTDOWN_GROUP_EVENT;
  const grouped = killGroup || multiGroup || shutdownGroup;
  const profile = killGroup ? CHAMPION_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE
    : multiGroup ? CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PAIR_821_PROFILE
      : shutdownGroup ? ON_SHUTDOWN_DIE_HERO_DEATH_PAIR_821_PROFILE
        : CHAMPION_DIE_HERO_DEATH_PAIR_821_PROFILE;
  const evidenceStatus = killGroup
    ? 'CANDIDATE_821_ON_CHAMPION_KILL_DIE_HERO_DIE_PACKET_GROUP'
    : multiGroup ? 'CANDIDATE_821_ON_CHAMPION_MULTIPLE_KILL_DIE_HERO_DIE_PACKET_GROUP'
      : shutdownGroup ? 'CANDIDATE_821_ON_SHUTDOWN_DIE_HERO_DIE_PACKET_GROUP'
        : 'CANDIDATE_821_ON_CHAMPION_DIE_HERO_DIE_PACKET_PAIR';
  const time = 100;
  const dieRaw = 0x400000ae;
  const source = 0x400000af;
  const heroRaw = 0x400000ae;
  const ref = (offset, rawParam) => ({
    source_path: 'synthetic.rofl', replay_sha256: SHA,
    chunk_index: 1, chunk_id: 2, chunk_stream: 'game_chunk', chunk_file_offset: 8,
    decompressed_block_offset: offset, decompressed_payload_offset: offset + 6,
    packet_id: 1034, replay_time_ms: time, payload_length: 12,
    raw_param: rawParam, raw_payload_sha256: 'b'.repeat(64),
  });
  const dieRef = ref(10, dieRaw);
  const longRef = ref(20, 0);
  const groupRef = ref(25, source);
  const heroRefs = [ref(30, heroRaw), ref(40, heroRaw), longRef];
  const common = {
    game_version: '16.19.821.7343', patch: '16.19', build_profile: profile.id,
    replay_sha256: SHA, replay_time_ms: time, confidence: 'CANDIDATE',
    semantic_status: evidenceStatus,
    on_champion_die_raw_param: dieRaw, on_champion_die_event_u32_0x04: source,
    hero_death_victim_raw_param: heroRaw,
    hero_death_die_source_network_id_candidate: source,
    on_champion_die_raw_packet_ref: dieRef,
    hero_death_raw_packet_refs: heroRefs,
  };
  const row = grouped ? {
    ...common, event_type: multiGroup
      ? 'CHAMPION_MULTIPLE_KILL_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE'
      : shutdownGroup ? 'ON_SHUTDOWN_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE'
        : 'CHAMPION_KILL_DIE_HERO_DEATH_PACKET_GROUP_CANDIDATE',
    ...(multiGroup ? {
      on_champion_multiple_kill_raw_param: source,
      on_champion_multiple_kill_event_u32_0x04: heroRaw,
      on_champion_multiple_kill_event_u32_0x08: source,
      on_champion_multiple_kill_event_u32_0x0c: 1,
      on_champion_multiple_kill_event_u32_list_0x10: [source],
      multi_0x04_xor_hero_raw_delta: 0,
      multi_0x04_exact_hero_raw_equal: true,
      on_champion_multiple_kill_raw_packet_ref: groupRef,
    } : shutdownGroup ? {
      on_shutdown_raw_param: source,
      on_shutdown_event_u32_0x04: heroRaw,
      on_shutdown_event_u32_0x58: 17,
      on_shutdown_event_u32_0x5c: 19,
      shutdown_0x04_xor_hero_raw_delta: 0,
      shutdown_0x04_exact_hero_raw_equal: true,
      on_shutdown_raw_packet_ref: groupRef,
    } : {
      on_champion_kill_raw_param: source,
      on_champion_kill_event_u32_0x04: heroRaw,
      kill_0x04_xor_hero_raw_delta: 0,
      kill_0x04_exact_hero_raw_equal: true,
      on_champion_kill_raw_packet_ref: groupRef,
    }),
    raw_packet_ref: groupRef,
    raw_packet_refs: [dieRef, longRef, groupRef, ...heroRefs.slice(0, 2)],
  } : {
    ...common, event_type: 'CHAMPION_DIE_HERO_DEATH_PACKET_PAIR_CANDIDATE',
    raw_param_xor_delta: 0, raw_param_exact_equal: true,
    raw_packet_ref: dieRef, raw_packet_refs: [dieRef, ...heroRefs],
  };
  const fixture = artifact(t, [row], true, eventKey);
  const association = {
    profile_id: profile.id,
    evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
    depends_on: [...profile.depends_on], known_limits: [...profile.known_limits],
    status: 'CANDIDATE', evidence_status: evidenceStatus, replay_sha256: SHA,
    on_champion_die_count: 1, hero_death_count: 1, pair_count: 1, event_count: 1,
    ...(grouped ? {
      ...(multiGroup ? {
        on_champion_multiple_kill_count: 1,
        unmatched_on_champion_multiple_kill_count: 0,
        exact_multi_0x04_hero_raw_equal_count: 1,
        multi_0x04_xor_hero_raw_delta_counts: { '0x00000000': 1 },
      } : shutdownGroup ? {
        on_shutdown_count: 1,
        unmatched_on_shutdown_count: 0,
        exact_shutdown_0x04_hero_raw_equal_count: 1,
        shutdown_0x04_xor_hero_raw_delta_counts: { '0x00000000': 1 },
      } : {
        on_champion_kill_count: 1,
        unmatched_on_champion_kill_count: 0,
        exact_kill_0x04_hero_raw_equal_count: 1,
        kill_0x04_xor_hero_raw_delta_counts: { '0x00000000': 1 },
      }),
      unpaired_on_champion_die_count: 0, unpaired_hero_death_count: 0,
    } : {
      exact_raw_param_equal_count: 1,
      raw_param_xor_delta_counts: { '0x00000000': 1 },
    }),
  };
  const profiles = {
    hero_death: HERO_DEATH_CANDIDATE_PROFILE_821,
    champion_die_event_packet: CHAMPION_DIE_EVENT_PACKET_821_PROFILE,
    champion_kill_event_packet: CHAMPION_KILL_EVENT_PACKET_CANDIDATE_PROFILE_821,
    champion_multiple_kill_event_packet: CHAMPION_MULTIPLE_KILL_EVENT_PACKET_821_PROFILE,
    on_shutdown_event_packet: ON_SHUTDOWN_EVENT_PACKET_821_PROFILE,
  };
  const semanticPath = path.join(fixture.replayDirectory, 'semantic_run.json');
  const analysisPath = path.join(fixture.replayDirectory, 'replay_analysis.json');
  rewriteJson(semanticPath, (semantic) => {
    semantic.requested_capabilities = [...profile.depends_on];
    semantic.capability_results = Object.fromEntries(profile.depends_on.map((dependency) =>
      [dependency, { status: 'CANDIDATE', profile_id: profiles[dependency].id,
        event_count: 1,
        evidence_runtime_image_sha256: profile.evidence_runtime_image_sha256,
        ...(dependency === 'hero_death' ? {} : {
          runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
          runtime_image_sha256: profile.evidence_runtime_image_sha256,
        }) }]));
    semantic.candidate_associations = { [profile.capability]: association };
    if (grouped) semantic.candidate_associations.champion_die_hero_death_pair = {
      status: 'CANDIDATE', profile_id: CHAMPION_DIE_HERO_DEATH_PAIR_821_PROFILE.id,
      replay_sha256: SHA, event_count: 1,
    };
  });
  rewriteJson(analysisPath, (analysis) => {
    for (const dependency of profile.depends_on) {
      analysis.event_counts[`${dependency}_candidates`] = 1;
    }
    if (grouped) analysis.event_counts.champion_die_hero_death_pair_candidates = 1;
    analysis.semantic = {
      candidate_associations: { [profile.capability]: association },
    };
  });
  return { ...fixture, row, association, semanticPath, analysisPath,
    eventPath: path.join(fixture.replayDirectory, `${eventKey}.jsonl`) };
}

function artifact(t, rows = [
  { replay_sha256: SHA, replay_time_ms: 0, participant_id_candidate: 1,
    confidence: 'CANDIDATE', field_confidence: { level: 'CANDIDATE' } },
  { replay_sha256: SHA, replay_time_ms: 1000, participant_id_candidate: null,
    confidence: 'CANDIDATE', raw_packet_ref: { replay_sha256: SHA } },
  { replay_sha256: SHA, replay_time_ms: 2000, participant_id_candidate: 1,
    confidence: 'CANDIDATE', raw_packet_ref: { replay_sha256: SHA } },
  { replay_sha256: SHA, replay_time_ms: 2000, participant_id_candidate: 2,
    confidence: 'CANDIDATE', raw_packet_ref: { replay_sha256: SHA } },
], compact = true, eventKey = EVENT) {
  const capability = eventKey.slice(0, -'_candidates'.length);
  const replayVersion = [INVENTORY_EVENT, BROADCAST_EVENT, SET_ITEM_EVENT,
    HEAL_PACKET_EVENT, SHIELD_PAIR_EVENT, STEALTH_PACKET_EVENT, CAST_SPELL_ANS_EVENT,
    CHAMPION_DIE_EVENT, CHAMPION_KILL_EVENT,
    CHAMPION_MULTIPLE_KILL_EVENT, SHUTDOWN_PACKET_EVENT, ...ASSOCIATION_EVENTS].includes(eventKey)
    ? '16.19.821.7343' : VERSION;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-event-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const replayDirectory = path.join(root, 'replays', 'synthetic');
  fs.mkdirSync(replayDirectory, { recursive: true });
  const semantic = {
    replay_version: replayVersion, replay_sha256: SHA, container_status: 'PASS',
    status: 'PARTIAL', api_status: 'PARTIAL',
    requested_capabilities: [capability, 'hero_path'],
    capability_results: {
      [capability]: { status: 'CANDIDATE', input_count: rows.length,
        event_count: rows.length, evidence_status: 'CANDIDATE_SYNTHETIC' },
      hero_path: { status: 'MISSING_INPUT', input_count: null, event_count: null,
        missing_input: 'exact runtime image' },
    },
  };
  const analysis = {
    patch: '16.19', replay_version: replayVersion, replay_sha256: SHA,
    event_counts: { [eventKey]: rows.length },
    ...(compact ? { event_storage: 'JSONL_ONLY',
      event_jsonl_files: { [eventKey]: `${eventKey}.jsonl` }, events: null }
      : { events: { [eventKey]: rows } }),
  };
  fs.writeFileSync(path.join(replayDirectory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(replayDirectory, 'replay_analysis.json'), JSON.stringify(analysis));
  const lines = rows.map((row) => JSON.stringify(row));
  fs.writeFileSync(path.join(replayDirectory, `${eventKey}.jsonl`),
    lines.length ? `${lines.join('\n')}\n` : '');
  return { root, replayDirectory, semantic, analysis, lines };
}

function run(...args) {
  return spawnSync(process.execPath, [CLI, 'query-events', ...args],
    { encoding: 'utf8', cwd: path.dirname(CLI) });
}

test('query-events filters exact 821 pair and group association rows without modifying JSONL', (t) => {
  for (const eventKey of ASSOCIATION_EVENTS) {
    const fixture = associationArtifact(t, eventKey);
    const selected = run(fixture.replayDirectory, '--event', eventKey,
      '--from-ms', '100', '--to-ms', '100', '--raw-param', '0x400000af',
      '--opaque-u32', '0x400000ae');
    assert.equal(selected.status, 0, selected.stderr);
    assert.equal(selected.stdout, eventKey !== DIE_PAIR_EVENT
      ? `${fixture.lines[0]}\n` : '');
    const summary = JSON.parse(selected.stderr);
    assert.equal(summary.capability_status, 'CANDIDATE');
    assert.equal(summary.declared_event_count, 1);
    assert.equal(summary.scanned_count, 1);
    assert.equal(summary.filters.opaque_u32, 0x400000ae);
    assert.equal(summary.opaque_u32_unavailable_count, 0);
    const rawParam = run(fixture.replayDirectory, '--event', eventKey,
      '--raw-param', eventKey === DIE_PAIR_EVENT ? '0x400000ae' : '0x400000af');
    assert.equal(rawParam.status, 0, rawParam.stderr);
    assert.equal(rawParam.stdout, `${fixture.lines[0]}\n`);
    const dieChild = run(fixture.replayDirectory, '--event', eventKey,
      '--opaque-u32', '0x400000af');
    assert.equal(dieChild.status, 0, dieChild.stderr);
    assert.equal(dieChild.stdout, `${fixture.lines[0]}\n`);
    assert.equal(fs.readFileSync(fixture.eventPath, 'utf8'), `${fixture.lines[0]}\n`);
  }
});

test('query-events rejects wrong-build or unavailable 821 association without treating it as zero', (t) => {
  const wrongBuild = associationArtifact(t, DIE_PAIR_EVENT);
  rewriteJson(wrongBuild.semanticPath, (semantic) => {
    semantic.replay_version = VERSION;
  });
  rewriteJson(wrongBuild.analysisPath, (analysis) => {
    analysis.replay_version = VERSION;
  });
  const oldBuild = run(wrongBuild.replayDirectory, '--event', DIE_PAIR_EVENT);
  assert.equal(oldBuild.status, 2);
  assert.equal(JSON.parse(oldBuild.stderr).code, 'UNSUPPORTED_EVENT_BUILD');

  const absent = associationArtifact(t, DIE_PAIR_EVENT);
  rewriteJson(absent.semanticPath, (semantic) => {
    delete semantic.candidate_associations.champion_die_hero_death_pair;
  });
  const unavailable = run(absent.replayDirectory, '--event', DIE_PAIR_EVENT);
  assert.equal(unavailable.status, 2);
  assert.equal(JSON.parse(unavailable.stderr).code, 'ASSOCIATION_UNAVAILABLE');

  const failedAssociation = associationArtifact(t, DIE_PAIR_EVENT);
  rewriteJson(failedAssociation.semanticPath, (semantic) => {
    semantic.candidate_associations.champion_die_hero_death_pair.status = 'MISSING_INPUT';
    semantic.candidate_associations.champion_die_hero_death_pair.event_count = null;
  });
  const absentRows = run(failedAssociation.replayDirectory, '--event', DIE_PAIR_EVENT);
  assert.equal(absentRows.status, 2);
  assert.equal(JSON.parse(absentRows.stderr).code, 'ASSOCIATION_UNAVAILABLE');

  const missing = associationArtifact(t, KILL_GROUP_EVENT);
  rewriteJson(missing.semanticPath, (semantic) => {
    semantic.capability_results.champion_kill_event_packet.status = 'MISSING_INPUT';
    semantic.capability_results.champion_kill_event_packet.event_count = null;
  });
  const failedDependency = run(missing.replayDirectory, '--event', KILL_GROUP_EVENT);
  assert.equal(failedDependency.status, 2);
  assert.equal(JSON.parse(failedDependency.stderr).code, 'CAPABILITY_UNAVAILABLE');

  const notRequested = associationArtifact(t, MULTI_GROUP_EVENT);
  rewriteJson(notRequested.semanticPath, (semantic) => {
    semantic.requested_capabilities = ['champion_die_event_packet',
      'champion_multiple_kill_event_packet'];
  });
  const absentDependency = run(notRequested.replayDirectory, '--event', MULTI_GROUP_EVENT);
  assert.equal(absentDependency.status, 2);
  assert.equal(JSON.parse(absentDependency.stderr).code, 'CAPABILITY_NOT_REQUESTED');
});

test('query-events rejects association profile, count and row identity corruption with output cleanup', (t) => {
  for (const eventKey of ASSOCIATION_EVENTS) {
    const profile = associationArtifact(t, eventKey);
    rewriteJson(profile.semanticPath, (semantic) => {
      semantic.candidate_associations[eventKey.slice(0, -'_candidates'.length)].profile_id =
        'stale-profile';
    });
    const stale = run(profile.replayDirectory, '--event', eventKey);
    assert.equal(stale.status, 2);
    assert.equal(JSON.parse(stale.stderr).code, 'ASSOCIATION_METADATA_MISMATCH');

    const count = associationArtifact(t, eventKey);
    rewriteJson(count.analysisPath, (analysis) => {
      analysis.event_counts[eventKey] = 2;
    });
    const countResult = run(count.replayDirectory, '--event', eventKey);
    assert.equal(countResult.status, 2);
    assert.equal(JSON.parse(countResult.stderr).code, 'EVENT_COUNT_MISMATCH');

    const corrupt = associationArtifact(t, eventKey);
    const output = path.join(corrupt.root, 'invalid-association.jsonl');
    const row = structuredClone(corrupt.row);
    row.on_champion_die_raw_packet_ref.replay_sha256 = 'b'.repeat(64);
    fs.writeFileSync(corrupt.eventPath, `${JSON.stringify(row)}\n`);
    const invalid = run(corrupt.replayDirectory, '--event', eventKey,
      '--output', output);
    assert.equal(invalid.status, 2);
    assert.equal(JSON.parse(invalid.stderr).code, 'ARTIFACT_IDENTITY_MISMATCH');
    assert.equal(fs.existsSync(output), false);
  }
});

test('query-events rejects missing 821 association child fields instead of returning zero matches', (t) => {
  for (const eventKey of ASSOCIATION_EVENTS) {
    const fixture = associationArtifact(t, eventKey);
    const row = structuredClone(fixture.row);
    delete row.on_champion_die_event_u32_0x04;
    if (eventKey === KILL_GROUP_EVENT) delete row.on_champion_kill_event_u32_0x04;
    if (eventKey === MULTI_GROUP_EVENT) {
      delete row.on_champion_multiple_kill_event_u32_0x04;
    }
    if (eventKey === SHUTDOWN_GROUP_EVENT) delete row.on_shutdown_event_u32_0x04;
    fs.writeFileSync(fixture.eventPath, `${JSON.stringify(row)}\n`);
    const output = path.join(fixture.root, 'missing-child-field.jsonl');
    const result = run(fixture.replayDirectory, '--event', eventKey,
      '--opaque-u32', '0', '--output', output);
    assert.equal(result.status, 2);
    assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('query-events streams filtered unmodified JSONL and reports full counts and original status', (t) => {
  const fixture = artifact(t);
  const output = path.join(fixture.root, 'selected.jsonl');
  const result = run(fixture.replayDirectory, '--event', EVENT,
    '--from-ms', '0', '--to-ms', '2000', '--participant', '1', '--limit', '1',
    '--output', output);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  const summary = JSON.parse(result.stdout);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.capability_status, 'CANDIDATE');
  assert.equal(summary.semantic_run_status, 'PARTIAL');
  assert.equal(summary.replay_sha256, SHA);
  assert.equal(summary.declared_event_count, 4);
  assert.equal(summary.scanned_count, 4);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.participant_unavailable_count, 1);
  assert.deepEqual(summary.filters,
    { from_ms: 0, to_ms: 2000, participant_id: 1, limit: 1 });
  assert.equal(fs.readFileSync(output, 'utf8'), `${fixture.lines[0]}\n`);
  assert.equal(fs.readFileSync(path.join(fixture.replayDirectory, `${EVENT}.jsonl`), 'utf8'),
    `${fixture.lines.join('\n')}\n`);
});

test('query-events keeps stdout as JSONL and puts its query summary on stderr', (t) => {
  const fixture = artifact(t);
  const result = run(fixture.replayDirectory, '--event', EVENT, '--from-ms=1000',
    '--to-ms=2000', '--participant=2');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${fixture.lines[3]}\n`);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.output, '-');
});

test('query-events filters recorded raw packet parameters without resolving participants', (t) => {
  const rows = [
    { replay_sha256: SHA, replay_time_ms: 10, confidence: 'CANDIDATE',
      raw_param: 0x400000ae, raw_packet_ref: { replay_sha256: SHA, raw_param: 0x400000ae } },
    { replay_sha256: SHA, replay_time_ms: 20, confidence: 'CANDIDATE',
      raw_packet_refs: [{ replay_sha256: SHA, raw_param: 0x400000af }] },
    { replay_sha256: SHA, replay_time_ms: 30, confidence: 'CANDIDATE' },
  ];
  const fixture = artifact(t, rows);
  const result = run(fixture.replayDirectory, '--event', EVENT,
    '--raw-param', '0x400000af', '--limit', '1');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${fixture.lines[1]}\n`);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.raw_param_unavailable_count, 1);
  assert.equal(summary.filters.raw_param, 0x400000af);
  assert.equal(summary.filters.participant_id, null);

  const decimal = run(fixture.replayDirectory, '--event', EVENT,
    '--raw-param', String(0x400000ae));
  assert.equal(decimal.status, 0, decimal.stderr);
  assert.equal(decimal.stdout, `${fixture.lines[0]}\n`);
});

test('query-events distinguishes absent raw parameters from zero matches', (t) => {
  const fixture = artifact(t);
  const output = path.join(fixture.root, 'missing-raw-param.jsonl');
  const unavailable = run(fixture.replayDirectory, '--event', EVENT,
    '--raw-param', '0', '--output', output);
  assert.equal(unavailable.status, 2);
  assert.equal(JSON.parse(unavailable.stderr).code, 'RAW_PARAM_UNAVAILABLE');
  assert.equal(fs.existsSync(output), false);

  const rows = [{ replay_sha256: SHA, replay_time_ms: 10,
    raw_param: 0, raw_packet_ref: { replay_sha256: SHA, raw_param: 0 } }];
  const withParam = artifact(t, rows);
  const zeroMatch = run(withParam.replayDirectory, '--event', EVENT,
    '--raw-param', '1');
  assert.equal(zeroMatch.status, 0, zeroMatch.stderr);
  assert.equal(zeroMatch.stdout, '');
  assert.equal(JSON.parse(zeroMatch.stderr).matched_count, 0);
});

test('query-events filters only current inventory packet records by decimal or hex item ID', (t) => {
  const rows = [
    { replay_sha256: SHA, replay_time_ms: 10, participant_id_candidate: 1,
      record_count: 2, records_candidate: [
        { slot_candidate: 0, item_id_candidate: 1001 },
        { slot_candidate: 6, item_id_candidate: 3340 },
      ], packet_slot_snapshot_candidate: [{ slot_candidate: 0, item_id_candidate: 1001 }] },
    { replay_sha256: SHA, replay_time_ms: 20, participant_id_candidate: 1,
      record_count: 1, records_candidate: [{ slot_candidate: 0, item_id_candidate: 2031 }],
      packet_slot_snapshot_candidate: [{ slot_candidate: 6, item_id_candidate: 3340 }] },
    { replay_sha256: SHA, replay_time_ms: 30, participant_id_candidate: 2,
      record_count: 0, records_candidate: [],
      packet_slot_snapshot_candidate: [{ slot_candidate: 6, item_id_candidate: 3340 }] },
  ];
  const fixture = artifact(t, rows, true, INVENTORY_EVENT);
  const output = path.join(fixture.root, 'item-3340.jsonl');
  const hex = run(fixture.replayDirectory, '--event', INVENTORY_EVENT,
    '--item-id', '0xd0c', '--output', output);
  assert.equal(hex.status, 0, hex.stderr);
  assert.equal(hex.stderr, '');
  const summary = JSON.parse(hex.stdout);
  assert.equal(summary.query_status, 'COMPLETE');
  assert.equal(summary.capability_status, 'CANDIDATE');
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 1);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.item_id_unavailable_count, 0);
  assert.equal(summary.filters.item_id, 3340);
  assert.equal(fs.readFileSync(output, 'utf8'), `${fixture.lines[0]}\n`);
  assert.equal(fs.readFileSync(path.join(fixture.replayDirectory, `${INVENTORY_EVENT}.jsonl`), 'utf8'),
    `${fixture.lines.join('\n')}\n`);

  const decimal = run(fixture.replayDirectory, '--event', INVENTORY_EVENT,
    '--item-id=2031', '--participant', '1');
  assert.equal(decimal.status, 0, decimal.stderr);
  assert.equal(decimal.stdout, `${fixture.lines[1]}\n`);
  assert.equal(JSON.parse(decimal.stderr).matched_count, 1);

  const zero = run(fixture.replayDirectory, '--event', INVENTORY_EVENT, '--item-id', '0');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(JSON.parse(zero.stderr).matched_count, 0);
});

test('query-events distinguishes unavailable inventory item fields from a confirmed zero match', (t) => {
  const missing = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10, record_count: 1 },
    { replay_sha256: SHA, replay_time_ms: 20, record_count: 1,
      records_candidate: [{ slot_candidate: 0 }] },
  ], true, INVENTORY_EVENT);
  const output = path.join(missing.root, 'unavailable.jsonl');
  const unavailable = run(missing.replayDirectory, '--event', INVENTORY_EVENT,
    '--item-id', '1001', '--output', output);
  assert.equal(unavailable.status, 2);
  const error = JSON.parse(unavailable.stderr);
  assert.equal(error.code, 'ITEM_ID_UNAVAILABLE');
  assert.equal(error.item_id_unavailable_count, 2);
  assert.equal(fs.existsSync(output), false);

  const known = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10, record_count: 1,
      records_candidate: [{ slot_candidate: 0, item_id_candidate: 1001 }] },
    { replay_sha256: SHA, replay_time_ms: 20, record_count: 1,
      records_candidate: [{ slot_candidate: 0 }] },
  ], true, INVENTORY_EVENT);
  const zero = run(known.replayDirectory, '--event', INVENTORY_EVENT, '--item-id', '2001');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, '');
  const summary = JSON.parse(zero.stderr);
  assert.equal(summary.matched_count, 0);
  assert.equal(summary.item_id_unavailable_count, 1);

  const empty = artifact(t, [{ replay_sha256: SHA, replay_time_ms: 10,
    record_count: 0, records_candidate: [] }], true, INVENTORY_EVENT);
  const emptyResult = run(empty.replayDirectory, '--event', INVENTORY_EVENT, '--item-id', '1001');
  assert.equal(emptyResult.status, 0, emptyResult.stderr);
  assert.equal(JSON.parse(emptyResult.stderr).item_id_unavailable_count, 0);
});

test('query-events preserves decoded zero item values in 821 Broadcast records', (t) => {
  const rows = [
    { replay_sha256: SHA, replay_time_ms: 10, record_count: 2,
      records_candidate: [
        { slot_candidate: 0, item_id_candidate: 0 },
        { slot_candidate: 1, item_id_candidate: 3340 },
      ], packet_slot_snapshot_candidate: [
        { slot_candidate: 0, item_id_candidate: 0 },
        { slot_candidate: 2, item_id_candidate: null },
      ] },
    { replay_sha256: SHA, replay_time_ms: 20, record_count: 1,
      records_candidate: [{ slot_candidate: 0, item_id_candidate: 2031 }] },
  ];
  const fixture = artifact(t, rows, true, BROADCAST_EVENT);
  const zero = run(fixture.replayDirectory, '--event', BROADCAST_EVENT,
    '--item-id', '0');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${fixture.lines[0]}\n`);
  assert.equal(JSON.parse(zero.stderr).matched_count, 1);
  const item = run(fixture.replayDirectory, '--event', BROADCAST_EVENT,
    '--item-id', '0xd0c');
  assert.equal(item.status, 0, item.stderr);
  assert.equal(item.stdout, `${fixture.lines[0]}\n`);
});

test('query-events filters the decoded scalar item key in 821 SetItem packets', (t) => {
  const rows = [
    { replay_sha256: SHA, replay_time_ms: 10, slot_candidate: 8,
      item_id_candidate: 1200 },
    { replay_sha256: SHA, replay_time_ms: 20, slot_candidate: 8,
      item_id_candidate: 1202 },
  ];
  const fixture = artifact(t, rows, true, SET_ITEM_EVENT);
  const selected = run(fixture.replayDirectory, '--event', SET_ITEM_EVENT,
    '--item-id', '0x4b2');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${fixture.lines[1]}\n`);
  assert.equal(JSON.parse(selected.stderr).matched_count, 1);

  const missing = artifact(t, [{ replay_sha256: SHA, replay_time_ms: 10,
    slot_candidate: 8, item_id_candidate: null }], true, SET_ITEM_EVENT);
  const unavailable = run(missing.replayDirectory, '--event', SET_ITEM_EVENT,
    '--item-id', '1200');
  assert.equal(unavailable.status, 2);
  assert.equal(JSON.parse(unavailable.stderr).code, 'ITEM_ID_UNAVAILABLE');
});

test('query-events filters observed packet slots including zero, without using snapshots', (t) => {
  for (const eventKey of [INVENTORY_EVENT, BROADCAST_EVENT]) {
    const rows = [
      { replay_sha256: SHA, replay_time_ms: 10, record_count: 2,
        records_candidate: [
          { slot_candidate: 0, item_id_candidate: 1001 },
          { slot_candidate: 6, item_id_candidate: 3340 },
        ] },
      { replay_sha256: SHA, replay_time_ms: 20, record_count: 1,
        records_candidate: [{ slot_candidate: 6, item_id_candidate: 2031 }],
        packet_slot_snapshot_candidate: [{ slot_candidate: 0, item_id_candidate: 1001 }] },
      { replay_sha256: SHA, replay_time_ms: 30, record_count: 0,
        records_candidate: [] },
    ];
    const fixture = artifact(t, rows, true, eventKey);
    const selected = run(fixture.replayDirectory, '--event', eventKey, '--slot', '0');
    assert.equal(selected.status, 0, selected.stderr);
    assert.equal(selected.stdout, `${fixture.lines[0]}\n`);
    const summary = JSON.parse(selected.stderr);
    assert.equal(summary.scanned_count, 3);
    assert.equal(summary.matched_count, 1);
    assert.equal(summary.slot_unavailable_count, 0);
    assert.equal(summary.filters.slot, 0);
  }
});

test('query-events combines item and slot on the same inventory record', (t) => {
  const rows = [
    { replay_sha256: SHA, replay_time_ms: 10, record_count: 2,
      records_candidate: [
        { slot_candidate: 0, item_id_candidate: 1001 },
        { slot_candidate: 6, item_id_candidate: 3340 },
      ] },
    { replay_sha256: SHA, replay_time_ms: 20, record_count: 1,
      records_candidate: [{ slot_candidate: 0, item_id_candidate: 3340 }] },
  ];
  const fixture = artifact(t, rows, true, INVENTORY_EVENT);
  const selected = run(fixture.replayDirectory, '--event', INVENTORY_EVENT,
    '--slot', '0', '--item-id', '3340');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${fixture.lines[1]}\n`);
  assert.equal(JSON.parse(selected.stderr).matched_count, 1);

  const setItem = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10, slot_candidate: 8,
      item_id_candidate: 1200 },
    { replay_sha256: SHA, replay_time_ms: 20, slot_candidate: 8,
      item_id_candidate: 1202 },
  ], true, SET_ITEM_EVENT);
  const setItemMatch = run(setItem.replayDirectory, '--event', SET_ITEM_EVENT,
    '--slot', '8', '--item-id', '1202');
  assert.equal(setItemMatch.status, 0, setItemMatch.stderr);
  assert.equal(setItemMatch.stdout, `${setItem.lines[1]}\n`);
  const noMatch = run(setItem.replayDirectory, '--event', SET_ITEM_EVENT,
    '--slot', '0');
  assert.equal(noMatch.status, 0, noMatch.stderr);
  assert.equal(JSON.parse(noMatch.stderr).matched_count, 0);
});

test('query-events distinguishes unavailable slots from zero matches and rejects corrupt slots', (t) => {
  for (const eventKey of [INVENTORY_EVENT, BROADCAST_EVENT, SET_ITEM_EVENT]) {
    const missingRows = eventKey === SET_ITEM_EVENT
      ? [{ replay_sha256: SHA, replay_time_ms: 10, item_id_candidate: 1200 }]
      : [{ replay_sha256: SHA, replay_time_ms: 10, record_count: 1,
        records_candidate: [{ item_id_candidate: 1200 }] }];
    const missing = artifact(t, missingRows, true, eventKey);
    const unavailable = run(missing.replayDirectory, '--event', eventKey, '--slot', '0');
    assert.equal(unavailable.status, 2, unavailable.stderr);
    assert.equal(JSON.parse(unavailable.stderr).code, 'SLOT_UNAVAILABLE');

    const knownRows = eventKey === SET_ITEM_EVENT
      ? [{ replay_sha256: SHA, replay_time_ms: 10, slot_candidate: 8,
        item_id_candidate: 1200 }, ...missingRows]
      : [{ replay_sha256: SHA, replay_time_ms: 10, record_count: 1,
        records_candidate: [{ slot_candidate: 8, item_id_candidate: 1200 }] },
      ...missingRows];
    const known = artifact(t, knownRows, true, eventKey);
    const zero = run(known.replayDirectory, '--event', eventKey, '--slot', '0');
    assert.equal(zero.status, 0, zero.stderr);
    assert.equal(zero.stdout, '');
    assert.equal(JSON.parse(zero.stderr).slot_unavailable_count, 1);

    for (const invalidSlot of [-1, 10, 1.5, '0']) {
      const badRows = eventKey === SET_ITEM_EVENT
        ? [{ replay_sha256: SHA, replay_time_ms: 10, slot_candidate: 8 },
          { replay_sha256: SHA, replay_time_ms: 20, slot_candidate: invalidSlot }]
        : [{ replay_sha256: SHA, replay_time_ms: 10, record_count: 1,
          records_candidate: [{ slot_candidate: 8 }] },
        { replay_sha256: SHA, replay_time_ms: 20, record_count: 1,
          records_candidate: [{ slot_candidate: invalidSlot }] }];
      const bad = artifact(t, badRows, true, eventKey);
      const output = path.join(bad.root, 'invalid-slot.jsonl');
      const result = run(bad.replayDirectory, '--event', eventKey,
        '--slot', '8', '--output', output);
      assert.equal(result.status, 2, result.stderr);
      assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
      assert.equal(fs.existsSync(output), false);
    }
  }
});

test('query-events limits slot filter to exact 821 inventory streams and 0..9', (t) => {
  const unsupported = artifact(t);
  const wrongEvent = run(unsupported.replayDirectory, '--event', EVENT, '--slot', '0');
  assert.equal(wrongEvent.status, 1);
  assert.match(wrongEvent.stderr, /--slot requires an 821 inventory packet event/);
  const fixture = artifact(t, [], true, INVENTORY_EVENT);
  for (const value of ['-1', '10', '1.5', '0x8', '01']) {
    const result = run(fixture.replayDirectory, '--event', INVENTORY_EVENT,
      '--slot', value);
    assert.equal(result.status, 1, value);
  }
  const empty = run(fixture.replayDirectory, '--event', INVENTORY_EVENT,
    '--slot', '0');
  assert.equal(empty.status, 0, empty.stderr);
  assert.equal(JSON.parse(empty.stderr).scanned_count, 0);

  const oldBuild = artifact(t, [{ replay_sha256: SHA, replay_time_ms: 10,
    record_count: 1, records_candidate: [{ slot_candidate: 0 }] }], true,
  INVENTORY_EVENT);
  rewriteJson(path.join(oldBuild.replayDirectory, 'semantic_run.json'),
    (semantic) => { semantic.replay_version = VERSION; });
  rewriteJson(path.join(oldBuild.replayDirectory, 'replay_analysis.json'),
    (analysis) => { analysis.replay_version = VERSION; });
  const wrongBuild = run(oldBuild.replayDirectory, '--event', INVENTORY_EVENT,
    '--slot', '0');
  assert.equal(wrongBuild.status, 2, wrongBuild.stderr);
  assert.equal(JSON.parse(wrongBuild.stderr).code, 'UNSUPPORTED_FILTER');
});

test('query-events filters either anonymous 821 heal or shield u32 without inferring a role', (t) => {
  const healRows = [
    { replay_sha256: SHA, replay_time_ms: 10, raw_param: 7,
      event_entity_u32_0x04: 0x400000ae, event_entity_u32_0x14: 0x400000af },
    { replay_sha256: SHA, replay_time_ms: 20, raw_param: 0x400000af,
      event_entity_u32_0x04: 0, event_entity_u32_0x14: 0x400000b0 },
  ];
  const heal = artifact(t, healRows, true, HEAL_PACKET_EVENT);
  const selectedHeal = run(heal.replayDirectory, '--event', HEAL_PACKET_EVENT,
    '--opaque-u32', '0x400000af');
  assert.equal(selectedHeal.status, 0, selectedHeal.stderr);
  assert.equal(selectedHeal.stdout, `${heal.lines[0]}\n`);
  assert.equal(JSON.parse(selectedHeal.stderr).matched_count, 1);
  const zero = run(heal.replayDirectory, '--event', HEAL_PACKET_EVENT,
    '--opaque-u32', '0');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${heal.lines[1]}\n`);

  const shieldRows = [
    { replay_sha256: SHA, replay_time_ms: 30,
      event_u32_0x08: 0x400000b4, event_u32_0x0c: 0x400000b5,
      raw_packet_refs: [{ replay_sha256: SHA, raw_param: 1 },
        { replay_sha256: SHA, raw_param: 2 }] },
    { replay_sha256: SHA, replay_time_ms: 40,
      event_u32_0x08: 0x400000b6, event_u32_0x0c: 0x400000b7 },
  ];
  const shield = artifact(t, shieldRows, true, SHIELD_PAIR_EVENT);
  const selectedShield = run(shield.replayDirectory, '--event', SHIELD_PAIR_EVENT,
    '--opaque-u32', String(0x400000b5));
  assert.equal(selectedShield.status, 0, selectedShield.stderr);
  assert.equal(selectedShield.stdout, `${shield.lines[0]}\n`);
  assert.equal(JSON.parse(selectedShield.stderr).filters.opaque_u32, 0x400000b5);
});

test('query-events filters only decoded CastSpellAns signed i32, including both bounds and zero', (t) => {
  const values = [-0x80000000, -1, 0, 0x7fffffff];
  const rows = values.map((value, index) => ({
    replay_sha256: SHA, replay_time_ms: index + 1, raw_param: 0x400000ae,
    opaque_i32_0x14c: value, confidence: 'CANDIDATE',
  }));
  rows.push({ replay_sha256: SHA, replay_time_ms: 5, raw_param: 0x400000ae,
    confidence: 'CANDIDATE' });
  const fixture = artifact(t, rows, true, CAST_SPELL_ANS_EVENT);
  for (const [index, value] of values.entries()) {
    const result = run(fixture.replayDirectory, '--event', CAST_SPELL_ANS_EVENT,
      `--opaque-i32=${value}`);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, `${fixture.lines[index]}\n`);
    const summary = JSON.parse(result.stderr);
    assert.equal(summary.capability_status, 'CANDIDATE');
    assert.equal(summary.scanned_count, rows.length);
    assert.equal(summary.matched_count, 1);
    assert.equal(summary.opaque_i32_unavailable_count, 1);
    assert.equal(summary.filters.opaque_i32, value);
    assert.equal(summary.rows_unmodified, true);
  }
  const noMatch = run(fixture.replayDirectory, '--event', CAST_SPELL_ANS_EVENT,
    '--opaque-i32', '17');
  assert.equal(noMatch.status, 0, noMatch.stderr);
  assert.equal(noMatch.stdout, '');
  assert.equal(JSON.parse(noMatch.stderr).matched_count, 0);
  assert.equal(JSON.parse(noMatch.stderr).opaque_i32_unavailable_count, 1);
});

test('query-events reports wholly missing CastSpellAns i32 and rejects malformed present fields', (t) => {
  const missing = artifact(t, [{ replay_sha256: SHA, replay_time_ms: 1 }],
    true, CAST_SPELL_ANS_EVENT);
  const missingOutput = path.join(missing.root, 'missing-cast-i32.jsonl');
  const unavailable = run(missing.replayDirectory, '--event', CAST_SPELL_ANS_EVENT,
    '--opaque-i32', '0', '--output', missingOutput);
  assert.equal(unavailable.status, 2, unavailable.stderr);
  assert.equal(JSON.parse(unavailable.stderr).code, 'OPAQUE_I32_UNAVAILABLE');
  assert.equal(JSON.parse(unavailable.stderr).opaque_i32_unavailable_count, 1);
  assert.equal(fs.existsSync(missingOutput), false);

  for (const value of [null, '0', 1.5, -0x80000001, 0x80000000]) {
    const fixture = artifact(t, [
      { replay_sha256: SHA, replay_time_ms: 1, opaque_i32_0x14c: 0 },
      { replay_sha256: SHA, replay_time_ms: 2, opaque_i32_0x14c: value },
    ], true, CAST_SPELL_ANS_EVENT);
    const output = path.join(fixture.root, 'invalid-cast-i32.jsonl');
    const result = run(fixture.replayDirectory, '--event', CAST_SPELL_ANS_EVENT,
      '--opaque-i32', '0', '--to-ms', '1', '--output', output);
    assert.equal(result.status, 2, `${value}: ${result.stderr}`);
    assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('query-events limits CastSpellAns i32 filter to exact 821 event and signed decimal range', (t) => {
  const wrongEvent = artifact(t);
  const unsupported = run(wrongEvent.replayDirectory, '--event', EVENT,
    '--opaque-i32', '0');
  assert.equal(unsupported.status, 1, unsupported.stderr);
  assert.match(unsupported.stderr, /--opaque-i32 requires an 821 cast_spell_ans_packet_candidates event/);

  const oldBuild = artifact(t, [{ replay_sha256: SHA, replay_time_ms: 1,
    opaque_i32_0x14c: 0 }], true, CAST_SPELL_ANS_EVENT);
  rewriteJson(path.join(oldBuild.replayDirectory, 'semantic_run.json'),
    (semantic) => { semantic.replay_version = VERSION; });
  rewriteJson(path.join(oldBuild.replayDirectory, 'replay_analysis.json'),
    (analysis) => { analysis.replay_version = VERSION; });
  const wrongBuild = run(oldBuild.replayDirectory, '--event', CAST_SPELL_ANS_EVENT,
    '--opaque-i32', '0');
  assert.equal(wrongBuild.status, 2, wrongBuild.stderr);
  assert.equal(JSON.parse(wrongBuild.stderr).code, 'UNSUPPORTED_FILTER');

  for (const value of ['-2147483649', '2147483648', '0x1', '-0', '1.0', '1e2', '+1']) {
    const invalid = run(oldBuild.replayDirectory, '--event', CAST_SPELL_ANS_EVENT,
      '--opaque-i32', value);
    assert.equal(invalid.status, 1, `${value}: ${invalid.stderr}`);
    assert.equal(invalid.stdout, '');
  }
});

test('query-events filters exact 821 stealth child u32 without substituting Replay raw_param', (t) => {
  const rows = [
    { replay_sha256: SHA, replay_time_ms: 10,
      child_event_id: 0x0101, registered_event_name: 'OnEnterStealth',
      raw_param: 0x400000ae, event_u32_0x04: 0x400000ae,
      raw_packet_ref: { replay_sha256: SHA, raw_param: 0x400000ae } },
    { replay_sha256: SHA, replay_time_ms: 20,
      child_event_id: 0x0102, registered_event_name: 'OnExitStealth',
      raw_param: 0x400001ae, event_u32_0x04: 0x400000ae,
      raw_packet_ref: { replay_sha256: SHA, raw_param: 0x400001ae } },
    { replay_sha256: SHA, replay_time_ms: 30,
      child_event_id: 0x0101, registered_event_name: 'OnEnterStealth',
      raw_param: 0x400002ae, event_u32_0x04: 0 },
    { replay_sha256: SHA, replay_time_ms: 40,
      child_event_id: 0x0102, raw_param: 0x400003ae },
  ];
  const fixture = artifact(t, rows, true, STEALTH_PACKET_EVENT);
  const selected = run(fixture.replayDirectory, '--event', STEALTH_PACKET_EVENT,
    '--opaque-u32', '0x400000ae');
  assert.equal(selected.status, 0, selected.stderr);
  assert.equal(selected.stdout, `${fixture.lines[0]}\n${fixture.lines[1]}\n`);
  assert.equal(JSON.parse(selected.stderr).matched_count, 2);

  const rawOnly = run(fixture.replayDirectory, '--event', STEALTH_PACKET_EVENT,
    '--opaque-u32', '0x400001ae');
  assert.equal(rawOnly.status, 0, rawOnly.stderr);
  assert.equal(rawOnly.stdout, '');
  assert.equal(JSON.parse(rawOnly.stderr).matched_count, 0);
  assert.equal(JSON.parse(rawOnly.stderr).opaque_u32_unavailable_count, 1);

  const zero = run(fixture.replayDirectory, '--event', STEALTH_PACKET_EVENT,
    '--opaque-u32', '0');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${fixture.lines[2]}\n`);
});

test('query-events keeps missing 821 stealth u32 unavailable and enforces exact build and capability', (t) => {
  const missing = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10,
      raw_param: 0x400000ae,
      raw_packet_ref: { replay_sha256: SHA, raw_param: 0x400000ae } },
  ], true, STEALTH_PACKET_EVENT);
  const output = path.join(missing.root, 'missing-stealth-u32.jsonl');
  const unavailable = run(missing.replayDirectory, '--event', STEALTH_PACKET_EVENT,
    '--opaque-u32', '0x400000ae', '--output', output);
  assert.equal(unavailable.status, 2);
  assert.equal(JSON.parse(unavailable.stderr).code, 'OPAQUE_U32_UNAVAILABLE');
  assert.equal(fs.existsSync(output), false);

  const wrongBuild = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10, event_u32_0x04: 0 },
  ], true, STEALTH_PACKET_EVENT);
  for (const name of ['semantic_run.json', 'replay_analysis.json']) {
    const filename = path.join(wrongBuild.replayDirectory, name);
    const document = JSON.parse(fs.readFileSync(filename, 'utf8'));
    document.replay_version = VERSION;
    fs.writeFileSync(filename, JSON.stringify(document));
  }
  const rejected = run(wrongBuild.replayDirectory, '--event', STEALTH_PACKET_EVENT,
    '--opaque-u32', '0');
  assert.equal(rejected.status, 2);
  assert.equal(JSON.parse(rejected.stderr).code, 'UNSUPPORTED_FILTER');

  const unavailableCapability = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10, event_u32_0x04: 0 },
  ], true, STEALTH_PACKET_EVENT);
  const semanticPath = path.join(unavailableCapability.replayDirectory, 'semantic_run.json');
  const semantic = JSON.parse(fs.readFileSync(semanticPath, 'utf8'));
  semantic.capability_results.stealth_event_packet.status = 'MISSING_INPUT';
  semantic.capability_results.stealth_event_packet.event_count = null;
  fs.writeFileSync(semanticPath, JSON.stringify(semantic));
  const notDecoded = run(unavailableCapability.replayDirectory, '--event', STEALTH_PACKET_EVENT,
    '--opaque-u32', '0');
  assert.equal(notDecoded.status, 2);
  assert.equal(JSON.parse(notDecoded.stderr).code, 'CAPABILITY_UNAVAILABLE');
});

test('query-events filters exact 821 stealth child IDs while preserving rows and full counts', (t) => {
  const rows = [
    { replay_sha256: SHA, replay_time_ms: 10, raw_param: 0x0102, child_event_id: 0x0101,
      registered_event_name: 'OnEnterStealth', event_u32_0x04: 4 },
    { replay_sha256: SHA, replay_time_ms: 20, raw_param: 0x0101, child_event_id: 0x0102,
      registered_event_name: 'OnExitStealth', event_u32_0x04: 5 },
    { replay_sha256: SHA, replay_time_ms: 30, child_event_id: 0x0101,
      registered_event_name: 'OnEnterStealth', event_u32_0x04: 6 },
    { replay_sha256: SHA, replay_time_ms: 40, child_event_id: null },
  ];
  const fixture = artifact(t, rows, true, STEALTH_PACKET_EVENT);
  const enter = run(fixture.replayDirectory, '--event', STEALTH_PACKET_EVENT,
    '--child-event-id', '257', '--limit', '1');
  assert.equal(enter.status, 0, enter.stderr);
  assert.equal(enter.stdout, `${fixture.lines[0]}\n`);
  const summary = JSON.parse(enter.stderr);
  assert.equal(summary.scanned_count, 4);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.child_event_id_unavailable_count, 1);
  assert.equal(summary.filters.child_event_id, 0x0101);
  assert.equal(summary.rows_unmodified, true);
  const exit = run(fixture.replayDirectory, '--event', STEALTH_PACKET_EVENT,
    '--child-event-id=0x0102', '--opaque-u32', '5');
  assert.equal(exit.status, 0, exit.stderr);
  assert.equal(exit.stdout, `${fixture.lines[1]}\n`);
  assert.equal(JSON.parse(exit.stderr).matched_count, 1);
});

test('query-events distinguishes missing stealth child ID from explicit zero', (t) => {
  const missing = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10, raw_param: 0x400000ae },
    { replay_sha256: SHA, replay_time_ms: 20, child_event_id: null },
  ], true, STEALTH_PACKET_EVENT);
  const output = path.join(missing.root, 'missing-child-id.jsonl');
  const unavailable = run(missing.replayDirectory, '--event', STEALTH_PACKET_EVENT,
    '--child-event-id', '0x0101', '--output', output);
  assert.equal(unavailable.status, 2);
  assert.equal(JSON.parse(unavailable.stderr).code, 'CHILD_EVENT_ID_UNAVAILABLE');
  assert.equal(fs.existsSync(output), false);

  const zero = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10, child_event_id: 0 },
  ], true, STEALTH_PACKET_EVENT);
  const invalid = run(zero.replayDirectory, '--event', STEALTH_PACKET_EVENT,
    '--child-event-id', '0x0101');
  assert.equal(invalid.status, 2);
  assert.equal(JSON.parse(invalid.stderr).code, 'INVALID_EVENT_ROW');
});

test('query-events rejects unsupported stealth child IDs, streams, and builds before row scan', (t) => {
  const absentDirectory = path.join(os.tmpdir(), 'rofl-child-id-unopened-artifact');
  for (const value of ['0', '0x0103', '0xffffffff', '-1', '4294967296', '0xgg']) {
    const rejected = run(absentDirectory, '--event', STEALTH_PACKET_EVENT,
      '--child-event-id', value);
    assert.equal(rejected.status, 1, `${value}: ${rejected.stderr}`);
    assert.match(rejected.stderr, /--child-event-id/, value);
    assert.doesNotMatch(rejected.stderr, /MISSING_METADATA/, value);
  }
  const otherStream = run(absentDirectory, '--event', HEAL_PACKET_EVENT,
    '--child-event-id', '0x0101');
  assert.equal(otherStream.status, 1);
  assert.match(otherStream.stderr, /--child-event-id requires/);

  const wrongBuild = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10, child_event_id: 0x0101 },
  ], true, STEALTH_PACKET_EVENT);
  for (const name of ['semantic_run.json', 'replay_analysis.json']) {
    const filename = path.join(wrongBuild.replayDirectory, name);
    const document = JSON.parse(fs.readFileSync(filename, 'utf8'));
    document.replay_version = VERSION;
    fs.writeFileSync(filename, JSON.stringify(document));
  }
  const wrongVersion = run(wrongBuild.replayDirectory, '--event', STEALTH_PACKET_EVENT,
    '--child-event-id', '0x0101');
  assert.equal(wrongVersion.status, 2);
  assert.equal(JSON.parse(wrongVersion.stderr).code, 'UNSUPPORTED_FILTER');
});

test('query-events filters OnChampionDie child u32 without using its different raw param', (t) => {
  const rows = [
    { replay_sha256: SHA, replay_time_ms: 10, raw_param: 0x400000ae,
      event_u32_0x04: 0x400000af,
      raw_packet_ref: { replay_sha256: SHA, raw_param: 0x400000ae } },
    { replay_sha256: SHA, replay_time_ms: 20, raw_param: 0x400000af,
      event_u32_0x04: 0 },
    { replay_sha256: SHA, replay_time_ms: 30, raw_param: 0x400000b0 },
  ];
  const fixture = artifact(t, rows, true, CHAMPION_DIE_EVENT);
  const decoded = run(fixture.replayDirectory, '--event', CHAMPION_DIE_EVENT,
    '--opaque-u32', '0x400000af');
  assert.equal(decoded.status, 0, decoded.stderr);
  assert.equal(decoded.stdout, `${fixture.lines[0]}\n`);
  assert.equal(JSON.parse(decoded.stderr).opaque_u32_unavailable_count, 1);
  const rawOnly = run(fixture.replayDirectory, '--event', CHAMPION_DIE_EVENT,
    '--opaque-u32', '0x400000ae');
  assert.equal(rawOnly.status, 0, rawOnly.stderr);
  assert.equal(rawOnly.stdout, '');
  assert.equal(JSON.parse(rawOnly.stderr).matched_count, 0);
  const zero = run(fixture.replayDirectory, '--event', CHAMPION_DIE_EVENT,
    '--opaque-u32', '0');
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, `${fixture.lines[1]}\n`);

  const missing = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10, raw_param: 0x400000af },
  ], true, CHAMPION_DIE_EVENT);
  const unavailable = run(missing.replayDirectory, '--event', CHAMPION_DIE_EVENT,
    '--opaque-u32', '0x400000af');
  assert.equal(unavailable.status, 2);
  assert.equal(JSON.parse(unavailable.stderr).code, 'OPAQUE_U32_UNAVAILABLE');

  const wrongBuild = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10, event_u32_0x04: 0 },
  ], true, CHAMPION_DIE_EVENT);
  for (const name of ['semantic_run.json', 'replay_analysis.json']) {
    const filename = path.join(wrongBuild.replayDirectory, name);
    const document = JSON.parse(fs.readFileSync(filename, 'utf8'));
    document.replay_version = VERSION;
    fs.writeFileSync(filename, JSON.stringify(document));
  }
  const rejected = run(wrongBuild.replayDirectory, '--event', CHAMPION_DIE_EVENT,
    '--opaque-u32', '0');
  assert.equal(rejected.status, 2);
  assert.equal(JSON.parse(rejected.stderr).code, 'UNSUPPORTED_FILTER');
});

test('query-events matches only OnChampionKill decoded u32 fields and rejects invalid rows', (t) => {
  const rows = [
    { replay_sha256: SHA, replay_time_ms: 10, raw_param: 0x400000aa,
      event_u32_0x04: 0x400000ab, event_u32_0x58: 0xffffffff,
      event_u32_0x5c: 0 },
    { replay_sha256: SHA, replay_time_ms: 20, raw_param: 8,
      event_u32_0x04: 5, event_u32_0x58: 6, event_u32_0x5c: 7 },
    { replay_sha256: SHA, replay_time_ms: 30, raw_param: 10,
      event_u32_0x04: null, event_u32_0x58: null, event_u32_0x5c: 9 },
    { replay_sha256: SHA, replay_time_ms: 40, raw_param: 9 },
  ];
  const fixture = artifact(t, rows, true, CHAMPION_KILL_EVENT);
  for (const [value, expectedLine] of [
    ['0x400000ab', 0], ['0xffffffff', 0], ['0', 0], ['6', 1], ['9', 2],
  ]) {
    const selected = run(fixture.replayDirectory, '--event', CHAMPION_KILL_EVENT,
      '--opaque-u32', value);
    assert.equal(selected.status, 0, `${value}: ${selected.stderr}`);
    assert.equal(selected.stdout, `${fixture.lines[expectedLine]}\n`, value);
  }
  const rawOnly = run(fixture.replayDirectory, '--event', CHAMPION_KILL_EVENT,
    '--opaque-u32', '0x400000aa');
  assert.equal(rawOnly.status, 0, rawOnly.stderr);
  assert.equal(rawOnly.stdout, '');
  assert.equal(JSON.parse(rawOnly.stderr).opaque_u32_unavailable_count, 2);

  const invalid = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10,
      event_u32_0x04: 1, event_u32_0x58: 2, event_u32_0x5c: 3 },
    { replay_sha256: SHA, replay_time_ms: 20,
      event_u32_0x04: 1, event_u32_0x58: -1, event_u32_0x5c: 0 },
  ], true, CHAMPION_KILL_EVENT);
  const output = path.join(invalid.root, 'invalid-kill-u32.jsonl');
  const failed = run(invalid.replayDirectory, '--event', CHAMPION_KILL_EVENT,
    '--opaque-u32', '1', '--output', output);
  assert.equal(failed.status, 2);
  assert.equal(JSON.parse(failed.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(fs.existsSync(output), false);

  const semanticPath = path.join(fixture.replayDirectory, 'semantic_run.json');
  const semantic = JSON.parse(fs.readFileSync(semanticPath, 'utf8'));
  semantic.capability_results.champion_kill_event_packet.status = 'MISSING_INPUT';
  semantic.capability_results.champion_kill_event_packet.event_count = null;
  fs.writeFileSync(semanticPath, JSON.stringify(semantic));
  const unavailable = run(fixture.replayDirectory, '--event', CHAMPION_KILL_EVENT,
    '--opaque-u32', '0');
  assert.equal(unavailable.status, 2);
  assert.equal(JSON.parse(unavailable.stderr).code, 'CAPABILITY_UNAVAILABLE');
});

test('query-events filters anonymous OnShutdown child fields without using outer raw param', (t) => {
  const rows = [
    { replay_sha256: SHA, replay_time_ms: 10, raw_param: 0x400000b0,
      event_u32_0x04: 0x400000b4, event_u32_0x58: 63, event_u32_0x5c: 0 },
    { replay_sha256: SHA, replay_time_ms: 20, raw_param: 0x400000b1,
      event_u32_0x04: 0x400000b5, event_u32_0x58: 64,
      event_u32_0x5c: 0xffffffff },
  ];
  const fixture = artifact(t, rows, true, SHUTDOWN_PACKET_EVENT);
  for (const [value, selectedIndex] of [
    ['0x400000b4', 0], ['63', 0], ['0', 0], ['0xffffffff', 1],
  ]) {
    const selected = run(fixture.replayDirectory, '--event', SHUTDOWN_PACKET_EVENT,
      '--opaque-u32', value);
    assert.equal(selected.status, 0, `${value}: ${selected.stderr}`);
    assert.equal(selected.stdout, `${fixture.lines[selectedIndex]}\n`);
    assert.equal(JSON.parse(selected.stderr).capability_status, 'CANDIDATE');
  }
  const rawOnly = run(fixture.replayDirectory, '--event', SHUTDOWN_PACKET_EVENT,
    '--opaque-u32', '0x400000b0');
  assert.equal(rawOnly.status, 0, rawOnly.stderr);
  assert.equal(rawOnly.stdout, '');
  assert.equal(JSON.parse(rawOnly.stderr).matched_count, 0);
});

test('query-events filters only OnChampionMultipleKill decoded scalar u32 fields', (t) => {
  const rows = [
    { replay_sha256: SHA, replay_time_ms: 10, raw_param: 0x400000aa,
      event_u32_0x04: 0x400000ab, event_u32_0x08: 0, event_u32_0x0c: 2,
      event_u32_list_0x10: [0x400000aa, 0x400000ae] },
    { replay_sha256: SHA, replay_time_ms: 20, raw_param: 0x400000ab,
      event_u32_0x04: 5, event_u32_0x08: 6, event_u32_0x0c: 1,
      event_u32_list_0x10: [9] },
    { replay_sha256: SHA, replay_time_ms: 30, raw_param: 9,
      event_u32_0x04: null, event_u32_0x08: null,
      event_u32_0x0c: null, event_u32_list_0x10: [9] },
  ];
  const fixture = artifact(t, rows, true, CHAMPION_MULTIPLE_KILL_EVENT);
  for (const [value, expectedLine] of [
    ['0x400000ab', 0], ['0', 0], ['2', 0], ['5', 1], ['6', 1],
  ]) {
    const selected = run(fixture.replayDirectory, '--event', CHAMPION_MULTIPLE_KILL_EVENT,
      '--opaque-u32', value);
    assert.equal(selected.status, 0, `${value}: ${selected.stderr}`);
    assert.equal(selected.stdout, `${fixture.lines[expectedLine]}\n`, value);
    assert.equal(JSON.parse(selected.stderr).opaque_u32_unavailable_count, 1);
  }
  for (const value of ['0x400000aa', '9']) {
    const excluded = run(fixture.replayDirectory, '--event', CHAMPION_MULTIPLE_KILL_EVENT,
      '--opaque-u32', value);
    assert.equal(excluded.status, 0, `${value}: ${excluded.stderr}`);
    assert.equal(excluded.stdout, '', `raw param or +0x10 list matched ${value}`);
    assert.equal(JSON.parse(excluded.stderr).matched_count, 0);
  }
});

test('query-events keeps missing multikill scalar u32 unavailable and rejects corruption and old build', (t) => {
  const missing = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10, raw_param: 5,
      event_u32_list_0x10: [0] },
    { replay_sha256: SHA, replay_time_ms: 20,
      event_u32_0x04: null, event_u32_0x08: null,
      event_u32_0x0c: null, event_u32_list_0x10: [5] },
  ], true, CHAMPION_MULTIPLE_KILL_EVENT);
  const output = path.join(missing.root, 'missing-multikill-u32.jsonl');
  const unavailable = run(missing.replayDirectory, '--event', CHAMPION_MULTIPLE_KILL_EVENT,
    '--opaque-u32', '0', '--output', output);
  assert.equal(unavailable.status, 2);
  assert.equal(JSON.parse(unavailable.stderr).code, 'OPAQUE_U32_UNAVAILABLE');
  assert.equal(fs.existsSync(output), false);

  const invalid = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10,
      event_u32_0x04: 5, event_u32_0x08: 0, event_u32_0x0c: 2 },
    { replay_sha256: SHA, replay_time_ms: 20,
      event_u32_0x04: 6, event_u32_0x08: -1, event_u32_0x0c: 2 },
  ], true, CHAMPION_MULTIPLE_KILL_EVENT);
  const invalidOutput = path.join(invalid.root, 'invalid-multikill-u32.jsonl');
  const failed = run(invalid.replayDirectory, '--event', CHAMPION_MULTIPLE_KILL_EVENT,
    '--opaque-u32', '5', '--output', invalidOutput);
  assert.equal(failed.status, 2);
  assert.equal(JSON.parse(failed.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(fs.existsSync(invalidOutput), false);

  const wrongBuild = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10,
      event_u32_0x04: 5, event_u32_0x08: 0, event_u32_0x0c: 1 },
  ], true, CHAMPION_MULTIPLE_KILL_EVENT);
  for (const name of ['semantic_run.json', 'replay_analysis.json']) {
    const filename = path.join(wrongBuild.replayDirectory, name);
    const document = JSON.parse(fs.readFileSync(filename, 'utf8'));
    document.replay_version = VERSION;
    fs.writeFileSync(filename, JSON.stringify(document));
  }
  const oldBuild = run(wrongBuild.replayDirectory, '--event', CHAMPION_MULTIPLE_KILL_EVENT,
    '--opaque-u32', '0');
  assert.equal(oldBuild.status, 2);
  assert.equal(JSON.parse(oldBuild.stderr).code, 'UNSUPPORTED_FILTER');
});

test('query-events distinguishes missing anonymous u32 fields from zero matches', (t) => {
  const missing = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10 },
    { replay_sha256: SHA, replay_time_ms: 20,
      event_entity_u32_0x04: null, event_entity_u32_0x14: null },
  ], true, HEAL_PACKET_EVENT);
  const output = path.join(missing.root, 'missing-u32.jsonl');
  const unavailable = run(missing.replayDirectory, '--event', HEAL_PACKET_EVENT,
    '--opaque-u32', '1', '--output', output);
  assert.equal(unavailable.status, 2);
  assert.equal(JSON.parse(unavailable.stderr).code, 'OPAQUE_U32_UNAVAILABLE');
  assert.equal(fs.existsSync(output), false);

  const partial = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10,
      event_entity_u32_0x04: 5, event_entity_u32_0x14: null },
    { replay_sha256: SHA, replay_time_ms: 20,
      event_entity_u32_0x04: 7, event_entity_u32_0x14: 8 },
  ], true, HEAL_PACKET_EVENT);
  const noMatch = run(partial.replayDirectory, '--event', HEAL_PACKET_EVENT,
    '--opaque-u32', '9');
  assert.equal(noMatch.status, 0, noMatch.stderr);
  assert.equal(noMatch.stdout, '');
  const summary = JSON.parse(noMatch.stderr);
  assert.equal(summary.matched_count, 0);
  assert.equal(summary.opaque_u32_unavailable_count, 1);
});

test('query-events rejects opaque-u32 on other streams and invalid anonymous fields', (t) => {
  const unsupported = artifact(t);
  const wrongEvent = run(unsupported.replayDirectory, '--event', EVENT,
    '--opaque-u32', '1');
  assert.equal(wrongEvent.status, 1);
  assert.match(wrongEvent.stderr, /--opaque-u32 requires an 821 ParamsHeal/);
  const corrupt = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 10,
      event_entity_u32_0x04: 1, event_entity_u32_0x14: 2 },
    { replay_sha256: SHA, replay_time_ms: 20,
      event_entity_u32_0x04: -1, event_entity_u32_0x14: 3 },
  ], true, HEAL_PACKET_EVENT);
  const output = path.join(corrupt.root, 'invalid-u32.jsonl');
  const result = run(corrupt.replayDirectory, '--event', HEAL_PACKET_EVENT,
    '--opaque-u32', '1', '--output', output);
  assert.equal(result.status, 2);
  assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(fs.existsSync(output), false);
});

test('query-events rejects item ID filters on other streams and corrupt inventory records', (t) => {
  const unsupported = artifact(t);
  const wrongEvent = run(unsupported.replayDirectory, '--event', EVENT, '--item-id', '1001');
  assert.equal(wrongEvent.status, 1);
  assert.match(wrongEvent.stderr, /--item-id requires an 821 inventory packet event/);

  for (const bad of [-1, 0, 4294967296, '1001']) {
    const fixture = artifact(t, [
      { replay_sha256: SHA, replay_time_ms: 10, record_count: 1,
        records_candidate: [{ slot_candidate: 0, item_id_candidate: 1001 }] },
      { replay_sha256: SHA, replay_time_ms: 20, record_count: 1,
        records_candidate: [{ slot_candidate: 0, item_id_candidate: bad }] },
    ], true, INVENTORY_EVENT);
    const output = path.join(fixture.root, 'invalid-item.jsonl');
    const result = run(fixture.replayDirectory, '--event', INVENTORY_EVENT,
      '--item-id', '1001', '--output', output);
    assert.equal(result.status, 2, result.stderr);
    assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(output), false);
  }
});

test('query-events rejects invalid recorded raw parameters and removes partial output', (t) => {
  const fixture = artifact(t, [
    { replay_sha256: SHA, replay_time_ms: 1, raw_param: 7 },
    { replay_sha256: SHA, replay_time_ms: 2, raw_param: -1 },
  ]);
  const output = path.join(fixture.root, 'invalid-raw-param.jsonl');
  const result = run(fixture.replayDirectory, '--event', EVENT,
    '--raw-param', '7', '--output', output);
  assert.equal(result.status, 2);
  assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
  assert.equal(fs.existsSync(output), false);
});

test('query-events reads default 16.19 artifacts with embedded arrays and existing JSONL', (t) => {
  const fixture = artifact(t, undefined, false);
  const result = run(fixture.replayDirectory, '--event', EVENT,
    '--participant', '1', '--from-ms', '2000');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${fixture.lines[2]}\n`);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.event_storage, 'EMBEDDED_AND_JSONL');
  assert.equal(summary.scanned_count, 4);
  assert.equal(summary.capability_status, 'CANDIDATE');
});

test('query-events reports missing capability without inventing zero events', (t) => {
  const fixture = artifact(t);
  const result = run(fixture.replayDirectory, '--event', 'hero_path_candidates');
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '');
  const error = JSON.parse(result.stderr);
  assert.equal(error.code, 'CAPABILITY_UNAVAILABLE');
  assert.equal(error.capability_status, 'MISSING_INPUT');
  assert.equal(error.missing_input, 'exact runtime image');
});

test('query-events rejects unsafe keys, mismatched identity, count corruption, and output replacement', (t) => {
  const fixture = artifact(t);
  const unsafe = run(fixture.replayDirectory, '--event', '../semantic_run');
  assert.equal(unsafe.status, 2);
  assert.equal(JSON.parse(unsafe.stderr).code, 'INVALID_EVENT_KEY');

  const alias = run(fixture.replayDirectory, '--event', EVENT,
    '--output', path.join(fixture.replayDirectory, `${EVENT}.jsonl`));
  assert.equal(alias.status, 2);
  assert.equal(JSON.parse(alias.stderr).code, 'UNSAFE_OUTPUT');

  const analysisPath = path.join(fixture.replayDirectory, 'replay_analysis.json');
  const analysis = JSON.parse(fs.readFileSync(analysisPath));
  analysis.replay_sha256 = 'b'.repeat(64);
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  const mismatch = run(fixture.replayDirectory, '--event', EVENT);
  assert.equal(mismatch.status, 2);
  assert.equal(JSON.parse(mismatch.stderr).code, 'ARTIFACT_IDENTITY_MISMATCH');

  analysis.replay_sha256 = SHA;
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  fs.appendFileSync(path.join(fixture.replayDirectory, `${EVENT}.jsonl`), `${fixture.lines[0]}\n`);
  const badOutput = path.join(fixture.root, 'bad-output.jsonl');
  const corrupted = run(fixture.replayDirectory, '--event', EVENT, '--output', badOutput);
  assert.equal(corrupted.status, 2);
  assert.equal(JSON.parse(corrupted.stderr).code, 'EVENT_COUNT_MISMATCH');
  assert.equal(fs.existsSync(badOutput), false);
});

test('query-events distinguishes zero candidates from an unresolved participant filter', (t) => {
  const fixture = artifact(t, []);
  const zero = run(fixture.replayDirectory, '--event', EVENT);
  assert.equal(zero.status, 0, zero.stderr);
  assert.equal(zero.stdout, '');
  const summary = JSON.parse(zero.stderr);
  assert.equal(summary.scanned_count, 0);
  assert.equal(summary.capability_status, 'CANDIDATE');

  const row = { replay_sha256: SHA, replay_time_ms: 10, confidence: 'CANDIDATE' };
  const analysisPath = path.join(fixture.replayDirectory, 'replay_analysis.json');
  const semanticPath = path.join(fixture.replayDirectory, 'semantic_run.json');
  const analysis = JSON.parse(fs.readFileSync(analysisPath));
  const semantic = JSON.parse(fs.readFileSync(semanticPath));
  analysis.event_counts[EVENT] = 1;
  semantic.capability_results[CAPABILITY].event_count = 1;
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  fs.writeFileSync(semanticPath, JSON.stringify(semantic));
  fs.writeFileSync(path.join(fixture.replayDirectory, `${EVENT}.jsonl`), `${JSON.stringify(row)}\n`);
  const unknown = run(fixture.replayDirectory, '--event', EVENT, '--participant', '1');
  assert.equal(unknown.status, 2);
  assert.equal(JSON.parse(unknown.stderr).code, 'PARTICIPANT_UNAVAILABLE');
});

test('query-events rejects malformed numeric filters before scanning', (t) => {
  const fixture = artifact(t);
  for (const args of [
    ['--from-ms', '-1'], ['--to-ms', '2.5'], ['--participant', '11'],
    ['--participant', '0'], ['--limit', '0'], ['--from-ms', '2', '--to-ms', '1'],
    ['--raw-param', '-1'], ['--raw-param', '0x100000000'],
    ['--raw-param', '4294967296'], ['--raw-param', '0xgg'],
    ['--item-id', '-1'], ['--item-id', '0x100000000'],
    ['--item-id', '4294967296'], ['--item-id', '0xgg'],
    ['--opaque-u32', '-1'], ['--opaque-u32', '0x100000000'],
    ['--opaque-u32', '4294967296'], ['--opaque-u32', '0xgg'],
  ]) {
    const result = run(fixture.replayDirectory, '--event', EVENT, ...args);
    assert.equal(result.status, 1, args.join(' '));
    assert.equal(result.stdout, '');
  }
});

test('query-events refuses metadata path traversal and invalid timestamp or participant rows', (t) => {
  const fixture = artifact(t);
  const analysisPath = path.join(fixture.replayDirectory, 'replay_analysis.json');
  const eventPath = path.join(fixture.replayDirectory, `${EVENT}.jsonl`);
  const analysis = JSON.parse(fs.readFileSync(analysisPath));
  analysis.event_jsonl_files[EVENT] = '../outside.jsonl';
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  const unsafe = run(fixture.replayDirectory, '--event', EVENT);
  assert.equal(unsafe.status, 2);
  assert.equal(JSON.parse(unsafe.stderr).code, 'UNSAFE_ARTIFACT');

  analysis.event_jsonl_files[EVENT] = `${EVENT}.jsonl`;
  fs.writeFileSync(analysisPath, JSON.stringify(analysis));
  const original = fs.readFileSync(eventPath, 'utf8');
  for (const corrupt of [
    { replay_sha256: SHA, replay_time_ms: -1, participant_id_candidate: 1 },
    { replay_sha256: SHA, replay_time_ms: 1, participant_id_candidate: 11 },
    { replay_time_ms: 1, participant_id_candidate: 1 },
    { replay_sha256: SHA, replay_time_ms: 1, participant_id_candidate: 1,
      raw_packet_ref: {} },
    { replay_sha256: SHA, replay_time_ms: 1, participant_id_candidate: 1,
      raw_packet_refs: [{ replay_sha256: 'b'.repeat(64) }] },
  ]) {
    fs.writeFileSync(eventPath, `${JSON.stringify(corrupt)}\n${fixture.lines.slice(1).join('\n')}\n`);
    const result = run(fixture.replayDirectory, '--event', EVENT,
      '--output', path.join(fixture.root, 'rejected.jsonl'));
    assert.equal(result.status, 2);
    assert.equal(fs.existsSync(path.join(fixture.root, 'rejected.jsonl')), false);
    assert.ok(['INVALID_EVENT_ROW', 'ARTIFACT_IDENTITY_MISMATCH']
      .includes(JSON.parse(result.stderr).code));
  }
  fs.writeFileSync(eventPath, original);
});
