'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  normalizeActionLog,
  processControlledReplayCalibration,
} = require('../src/controlled_replay_calibration');
const { parseArguments } = require('../scripts/process_controlled_replay_calibration');

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'controlled-replay-intake-'));
  const replayPath = path.join(directory, 'controlled.rofl');
  fs.writeFileSync(replayPath, 'exact replay bytes');
  const replaySha = crypto.createHash('sha256').update('exact replay bytes').digest('hex');
  const replay = {
    source_path: replayPath,
    source_sha256: replaySha,
    header: { version: '16.16.805.0442' },
    tail: {
      metadata: { gameLength: 300000 },
      stats_parse_error: null,
      stats: [{ SKIN: 'Kayn', TEAM: '100', INDIVIDUAL_POSITION: 'JUNGLE' }],
    },
  };
  const actions = [
    ['00:21', 'TAKE_ISOLATED_DAMAGE_THEN_NATURAL_REGEN', null],
    ['00:45', 'HEAL', null], ['01:00', 'SHIELD_THEN_TAKE_ISOLATED_DAMAGE', null],
    ['01:20', 'DEATH', null], ['01:29', 'RESPAWN', null], ['01:50', 'LEVEL_UP', null],
    ['02:10', 'BUY_HP_ITEM', 'Ruby Crystal'], ['02:20', 'UNDO_HP_ITEM', 'Ruby Crystal'],
    ['02:40', 'BUY_HP_ITEM', 'Ruby Crystal'], ['02:50', 'SELL_HP_ITEM', 'Ruby Crystal'],
    ['03:20', 'BUY_ARMOR_ITEM', 'Cloth Armor'], ['03:30', 'UNDO_ARMOR_ITEM', 'Cloth Armor'],
    ['03:45', 'BUY_ARMOR_ITEM', 'Cloth Armor'], ['04:00', 'SELL_ARMOR_ITEM', 'Cloth Armor'],
    ['04:15', 'BUY_MAGIC_RESIST_ITEM', 'Null-Magic Mantle'],
    ['04:25', 'UNDO_MAGIC_RESIST_ITEM', 'Null-Magic Mantle'],
    ['04:40', 'BUY_MAGIC_RESIST_ITEM', 'Null-Magic Mantle'],
    ['04:50', 'SELL_MAGIC_RESIST_ITEM', 'Null-Magic Mantle'],
  ].map(([time, action, item_name]) => ({ time, action, ...(item_name ? { item_name } : {}) }));
  return { directory, replayPath, replaySha, replay, actions };
}

function dependencies(data, overrides = {}) {
  const audited = (fields, audit = {}) => ({
    replay_sha256: data.replaySha,
    exact_build: '16.16.805.0442',
    semantic_status: 'VERIFIED_DIRECT',
    confidence: 'VERIFIED_DIRECT',
    decoder_profile: 'fixture-direct-typed-v1',
    raw_payload_sha256: 'a'.repeat(64),
    ...fields,
    ...audit,
  });
  return {
    parseReplayFile: () => data.replay,
    decodeSemanticReplay: () => ({
      status: 'FULL_SEMANTIC', game_version: '16.16.805.0442',
      profile: { game_version: '16.16.805.0442' }, decoded_packet_count: 3,
      events: {
        damage_events: [
          audited({ event_type: 'DamageEvent', timestamp_ms: 21600, target_participant_id: 1, target_network_id: 0x400000ae }, {
            semantic_status: 'UNKNOWN', confidence: 'CANDIDATE',
          }),
          audited({ event_type: 'DamageEvent', timestamp_ms: 21601, target_participant_id: 1, target_network_id: 0x400000ae }, {
            exact_build: undefined,
          }),
          audited({ event_type: 'DamageEvent', timestamp_ms: 21667, target_participant_id: 1, target_network_id: 0x400000ae }),
          audited({ event_type: 'DamageEvent', timestamp_ms: 61785, target_participant_id: 1, target_network_id: 0x400000ae }),
        ],
        heal_events: [audited({ event_type: 'HEAL_REPORTED', replay_time_ms: 45212, subject_entity_id: 0x400000ae })],
        shield_events: [audited({ event_type: 'SHIELD_APPLICATION', replay_time_ms: 61184, subject_entity_id: 0x400000ae })],
        death_events: [audited({ event_type: 'DeathEvent', timestamp_ms: 79218, victim_participant_id: 1 })],
        respawn_events: [audited({ event_type: 'HERO_REINCARNATE_ALIVE', replay_time_ms: 89237, participant_id: 1, subject_network_id: 0x400000ae })],
        reincarnate_alive_events: [audited({ event_type: 'HERO_REINCARNATE_ALIVE', replay_time_ms: 89237, participant_id: 1, subject_network_id: 0x400000ae })],
        level_transition_events: [audited({ event_type: 'level_transition', timestamp_ms: 110380, participant_id: 1, entity_network_id: 0x400000ae }, {
          semantic_status: 'SEMANTIC_VERIFIED_DERIVED_BUILD_BOUND', confidence: 'VERIFIED_DERIVED',
        })],
        item_events: [],
      },
    }),
    ...overrides,
  };
}

function spec(data) {
  return {
    replay: { path: data.replayPath, expected_sha256: data.replaySha,
      exact_build: '16.16.805.0442', champion: 'Kayn' },
    action_log: data.actions,
    output_directory: path.join(data.directory, 'artifacts'),
  };
}

test('explicit Kayn Replay intake emits deterministic hashed artifacts without treating controls as scalar truth', () => {
  const data = fixture();
  try {
    const first = processControlledReplayCalibration(spec(data), dependencies(data));
    const second = processControlledReplayCalibration(spec(data), dependencies(data));
    assert.equal(first.run_id, second.run_id);
    assert.equal(first.action_anchor_count, 18);
    assert.equal(first.request_fulfillment_status, 'FULFILLED');
    assert.equal(first.p0_promotion_status, 'BLOCKED_NO_INDEPENDENT_SCALAR_GROUND_TRUTH');
    const manifest = JSON.parse(fs.readFileSync(first.artifact_manifest, 'utf8'));
    assert.equal(manifest.artifacts.length, 6);
    for (const artifact of manifest.artifacts) {
      const artifactPath = path.join(first.output_directory, artifact.path);
      assert.equal(crypto.createHash('sha256').update(fs.readFileSync(artifactPath)).digest('hex'), artifact.sha256);
      assert.ok(artifact.byte_size > 0);
    }
    const anchors = JSON.parse(fs.readFileSync(path.join(first.output_directory, 'action_anchors.json'), 'utf8'));
    assert.equal(anchors.anchors.every((row) => row.causal_control_only && !row.scalar_ground_truth), true);
    const decode = JSON.parse(fs.readFileSync(path.join(first.output_directory, 'decode_summary.json'), 'utf8'));
    assert.equal(decode.conservation.event_group_sum, 10);
    assert.equal(decode.conservation.event_group_accounting_pass, true);
    const alignment = JSON.parse(fs.readFileSync(path.join(first.output_directory, 'action_semantic_alignment.json'), 'utf8'));
    assert.equal(alignment.alignment_count, 18);
    assert.equal(alignment.action_anchor_count_conserved, true);
    assert.equal(alignment.matched_direct_typed_step_count, 5);
    assert.equal(alignment.alignments[0].steps[0].alignment_status, 'MATCHED_DIRECT_TYPED_EVENT');
    assert.equal(alignment.alignments[0].steps[0].event_audit.semantic_status, 'VERIFIED_DIRECT');
    assert.equal(alignment.alignments[0].steps[0].event_audit.raw_payload_sha256, 'a'.repeat(64));
    assert.equal(alignment.alignments[0].steps[1].alignment_status, 'UNRESOLVED_NO_DIRECT_TYPED_EVENT');
    assert.equal(alignment.alignments[2].steps[0].alignment_status, 'UNRESOLVED_NO_UNIQUE_CANONICAL_EVENT');
    assert.equal(alignment.alignments[2].steps[1].alignment_status, 'UNRESOLVED_NO_UNIQUE_CANONICAL_EVENT');
    assert.equal(alignment.alignments.slice(6).every((row) => row.steps[0].alignment_status === 'UNRESOLVED_NO_CANONICAL_ITEM_EVENT'), true);
    assert.equal(alignment.alignments.every((row) => row.causal_support_only && !row.scalar_ground_truth
      && row.automatic_promotion === 'FORBIDDEN'), true);
  } finally {
    fs.rmSync(data.directory, { recursive: true, force: true });
  }
});

test('run identity includes validated window and request id and permits a decoded fixture injection', () => {
  const data = fixture();
  try {
    const baseSpec = { ...spec(data), machine_case_window_ms: 2500, request_id: 'REQUEST-A' };
    const decoded = dependencies(data).decodeSemanticReplay();
    const first = processControlledReplayCalibration(baseSpec, dependencies(data, {
      decodeSemanticReplay: () => { throw new Error('fixture injection was not used'); },
      decoded,
    }));
    const repeat = processControlledReplayCalibration(baseSpec, dependencies(data, { decoded }));
    const changedWindow = processControlledReplayCalibration({ ...baseSpec, machine_case_window_ms: 2501 }, dependencies(data, { decoded }));
    const changedRequest = processControlledReplayCalibration({ ...baseSpec, request_id: 'REQUEST-B' }, dependencies(data, { decoded }));
    assert.equal(first.run_id, repeat.run_id);
    assert.notEqual(first.run_id, changedWindow.run_id);
    assert.notEqual(first.run_id, changedRequest.run_id);
    const alignment = JSON.parse(fs.readFileSync(
      path.join(first.output_directory, 'action_semantic_alignment.json'), 'utf8',
    ));
    assert.equal(alignment.matched_direct_typed_step_count, 7);
    assert.equal(alignment.replay_sha256, data.replaySha);
    assert.equal(alignment.exact_build, '16.16.805.0442');
    assert.equal(alignment.alignments[4].steps[0].event_group, 'respawn_events');
    assert.equal(alignment.alignments[2].composite_sequence_order_conserved, true);
    assert.deepEqual(
      alignment.alignments[2].steps.map((step) => step.event_timestamp_ms),
      [61184, 61785],
    );
    const wrongReplayScope = structuredClone(decoded);
    wrongReplayScope.events.heal_events[0].replay_sha256 = 'b'.repeat(64);
    const wrongScope = processControlledReplayCalibration(
      { ...baseSpec, request_id: 'REQUEST-WRONG-SCOPE' }, dependencies(data, { decoded: wrongReplayScope }),
    );
    const wrongScopeAlignment = JSON.parse(fs.readFileSync(
      path.join(wrongScope.output_directory, 'action_semantic_alignment.json'), 'utf8',
    ));
    assert.equal(wrongScopeAlignment.matched_direct_typed_step_count, 6);
    assert.equal(wrongScopeAlignment.alignments[1].steps[0].alignment_status, 'UNRESOLVED_NO_UNIQUE_CANONICAL_EVENT');
    assert.throws(
      () => processControlledReplayCalibration(
        { ...baseSpec, machine_case_window_ms: 0 }, dependencies(data, { decoded }),
      ),
      /machine_case_window_ms/,
    );
  } finally {
    fs.rmSync(data.directory, { recursive: true, force: true });
  }
});

test('fails closed on absent bindings, unknown/out-of-order/out-of-bounds actions, champion mismatch, fallback, and protected references', () => {
  const data = fixture();
  try {
    assert.throws(() => processControlledReplayCalibration({ ...spec(data), replay: { ...spec(data).replay, expected_sha256: undefined } }, dependencies(data)), /expected_sha256/);
    assert.throws(() => processControlledReplayCalibration({ ...spec(data), replay: { ...spec(data).replay, exact_build: '16.16' } }, dependencies(data)), /N.N.N.N/);
    assert.throws(() => normalizeActionLog([{ time: '00:01', action: 'GUESS_HP' }], 10000), /unknown/);
    assert.throws(() => normalizeActionLog([{ time: '00:02', action: 'HEAL' }, { time: '00:01', action: 'DEATH' }], 10000), /out of order/);
    assert.throws(() => normalizeActionLog([{ time: '00:11', action: 'HEAL' }], 10000), /outside Replay duration/);
    assert.throws(() => processControlledReplayCalibration({ ...spec(data), replay: { ...spec(data).replay, champion: 'Ahri' } }, dependencies(data)), /champion metadata/);
    assert.throws(() => processControlledReplayCalibration(spec(data), dependencies(data, {
      decodeSemanticReplay: () => ({ status: 'FALLBACK', game_version: '16.16.805.0442', profile: { game_version: '16.16.805.0442' } }),
    })), /failed closed/);
    assert.throws(() => processControlledReplayCalibration({ ...spec(data), output_directory: path.join(data.directory, 'protected-holdout') }, dependencies(data)), /protected Holdout/);
  } finally {
    fs.rmSync(data.directory, { recursive: true, force: true });
  }
});

test('detects replay mutation across decode and refuses to record evidence', () => {
  const data = fixture();
  try {
    let calls = 0;
    assert.throws(() => processControlledReplayCalibration(spec(data), dependencies(data, {
      sha256File: () => (++calls === 1 ? data.replaySha : 'f'.repeat(64)),
    })), /changed during processing/);
    assert.equal(fs.existsSync(path.join(data.directory, 'artifacts')), false);
  } finally {
    fs.rmSync(data.directory, { recursive: true, force: true });
  }
});

test('CLI requires one explicit safe spec path and never performs directory discovery', () => {
  assert.deepEqual(parseArguments(['--spec', 'controlled.json']), {
    spec_path: path.resolve('controlled.json'),
  });
  assert.throws(() => parseArguments([]), /exactly --spec/);
  assert.throws(() => parseArguments(['--spec', 'protected-holdout.json']), /protected Holdout/);
});
