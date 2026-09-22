'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const decoder = require('../src/decoders/gameplay_route_tail_16_16');
const audit = require('../scripts/audit_gameplay_route_tail');

const ROOT = path.resolve(__dirname, '..');
const IMAGE = fs.readFileSync(path.join(
  ROOT,
  'artifacts',
  'new_build_rofl_compatibility_gate_v1',
  'runtime',
  'league_16.16.805.0442.memory.bin',
));
const ROUTES = ['0x00b8', '0x00e4', '0x01ab', '0x01b5', '0x0298', '0x03d4'];
const EXPECTED_EVENTS = {
  '0x00b8': 'ABILITY_COOLDOWN_BROADCAST',
  '0x00e4': 'INSTANT_STOP_ATTACK',
  '0x01ab': 'FACE_DIRECTION_VECTOR',
  '0x01b5': 'BASIC_ATTACK_POSITION_MINION',
  '0x0298': 'WALL_TRACKING_CACHE_SNAPSHOT',
  '0x03d4': 'MISSILE_MOVEMENT_COMPLETE',
};

function sha256(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function firstBalancedRow(route) {
  const filePath = path.join(
    ROOT,
    'artifacts',
    'full_semantic_deep_recovery_v2',
    'gameplay_route_tail',
    'emulation',
    `route_${route.slice(2)}_balanced_decoded.jsonl`,
  );
  const firstLine = fs.readFileSync(filePath, 'utf8').split(/\r?\n/, 1)[0];
  return JSON.parse(firstLine);
}

function replayFor(row, values = {}) {
  return {
    source_sha256: row.replay_sha256,
    source_path: 'explicit-safe-balanced-fixture.rofl',
    header: { version: row.replay_version },
    ...values,
  };
}

function assertCommonScope(event, row, profile) {
  assert.equal(event.event_type, profile.event_type);
  assert.equal(event.semantic_type, 'ResearchEvent');
  assert.equal(event.patch, '16.16');
  assert.equal(event.build_profile, profile.id);
  assert.equal(event.exact_build, decoder.EXACT_BUILD);
  assert.equal(event.game_version, decoder.EXACT_BUILD);
  assert.equal(event.replay_sha256, row.replay_sha256);
  assert.equal(event.replay_time_ms, row.replay_time_ms);
  assert.equal(event.subject_network_id, row.raw_param >>> 0);
  assert.equal(event.decoder_runtime_image_sha256, decoder.RUNTIME_IMAGE_SHA256);
  assert.equal(event.decoder_profile_sha256, profile.runtime_decoder_profile_sha256);
  assert.equal(event.raw_packet_ref.payload_sha256, row.raw_payload_sha256);
  assert.equal(event.raw_packet_ref.packet_id, profile.packet_id);
  assert.equal(event.semantic_status, 'VERIFIED_DIRECT_BOUNDED_RESEARCH_EVENT');
  assert.equal(event.confidence, 'VERIFIED_DIRECT');
  assert.ok(event.known_limits.length > 0);
}

test('six machine profiles pin exact runtime/profile/validation hashes and sample counts', () => {
  assert.deepEqual(Object.keys(decoder.GAMEPLAY_ROUTE_TAIL_PROFILES), ROUTES);
  assert.deepEqual(decoder.ROUTE_IDS, [0x00b8, 0x00e4, 0x01ab, 0x01b5, 0x0298, 0x03d4]);
  assert.equal(sha256(path.join(ROOT, decoder.VALIDATION_ARTIFACT)),
    decoder.VALIDATION_ARTIFACT_SHA256);
  for (const route of ROUTES) {
    const profile = decoder.GAMEPLAY_ROUTE_TAIL_PROFILES[route];
    assert.equal(profile.replay_version, decoder.EXACT_BUILD);
    assert.equal(profile.runtime_image_sha256, decoder.RUNTIME_IMAGE_SHA256);
    assert.equal(sha256(path.join(ROOT, profile.runtime_decoder_profile)),
      profile.runtime_decoder_profile_sha256);
    assert.equal(profile.validation_artifact_sha256,
      decoder.VALIDATION_ARTIFACT_SHA256);
    assert.equal(profile.sample_count.replay_count, 4);
    assert.ok(profile.sample_count.full_corpus_event_count > 0);
    assert.equal(profile.sample_count.stratified_native_event_count,
      profile.sample_count.exact_full_consume_count);
    assert.ok(profile.publishable_fields.includes('subject_network_id=raw_param'));
  }
});

test('one real balanced row for every route produces the bounded public research event', () => {
  for (const route of ROUTES) {
    const row = firstBalancedRow(route);
    const profile = decoder.GAMEPLAY_ROUTE_TAIL_PROFILES[route];
    const event = decoder.gameplayRouteTailEventFromDecodedRow(
      replayFor(row), row, IMAGE,
    );
    assertCommonScope(event, row, profile);
    assert.equal(event.event_type, EXPECTED_EVENTS[route]);
    assert.equal(decoder.isGameplayRouteTailDecodedRow(replayFor(row), row, IMAGE), true);
  }
});

test('synthetic exact-scope rows preserve the same six protected-object inverses', () => {
  for (const route of ROUTES) {
    const real = firstBalancedRow(route);
    const synthetic = {
      ...real,
      replay_path: 'synthetic-safe-fixture.rofl',
      replay_sha256: 'f'.repeat(64),
      replay_time_ms: 123456,
    };
    const event = decoder.gameplayRouteTailEventFromDecodedRow(
      replayFor(synthetic), synthetic, IMAGE,
    );
    assertCommonScope(event, synthetic, decoder.GAMEPLAY_ROUTE_TAIL_PROFILES[route]);
    assert.equal(event.event_type, EXPECTED_EVENTS[route]);
  }
});

test('route-specific public fields remain bounded to the machine decisions', () => {
  const events = Object.fromEntries(ROUTES.map((route) => {
    const row = firstBalancedRow(route);
    return [route, decoder.gameplayRouteTailEventFromDecodedRow(replayFor(row), row, IMAGE)];
  }));

  assert.deepEqual({
    spell_slot_key_1c_u8: events['0x00b8'].spell_slot_key_1c_u8,
    numeric_10_f32: events['0x00b8'].numeric_10_f32,
    numeric_18_f32: events['0x00b8'].numeric_18_f32,
    numeric_20_f32: events['0x00b8'].numeric_20_f32,
    numeric_24_f32: events['0x00b8'].numeric_24_f32,
    flag_14_u8: events['0x00b8'].flag_14_u8,
  }, {
    spell_slot_key_1c_u8: 1,
    numeric_10_f32: 0,
    numeric_18_f32: 0,
    numeric_20_f32: 0,
    numeric_24_f32: 0,
    flag_14_u8: 0,
  });
  assert.equal(events['0x00b8'].field_confidence.numeric_10_f32,
    'UNKNOWN_ROLE_VALUE_VERIFIED_DIRECT');

  assert.equal(events['0x00e4'].attack_sequence_14_u32, 1);
  assert.equal(events['0x00e4'].target_network_id_candidate_1c_u32, 0);
  assert.equal(events['0x00e4'].field_confidence.target_network_id_candidate_1c_u32,
    'CANDIDATE');
  assert.equal(events['0x00e4'].amount, undefined);

  assert.deepEqual([
    events['0x01ab'].direction_x_f32,
    events['0x01ab'].direction_y_f32,
    events['0x01ab'].direction_z_f32,
  ], [0, 0, 1]);
  assert.equal(events['0x01ab'].scalar_20_f32, undefined);
  assert.equal(events['0x01ab'].protocol_fields.scalar_role_status,
    'UNKNOWN_RETAINED_DECODED');

  assert.equal(events['0x01b5'].target_network_id_u32, 0x40000278);
  assert.equal(events['0x01b5'].position_x_f32, 12464.4541015625);
  assert.equal(events['0x01b5'].position_z_f32, 2253.905029296875);
  assert.equal(events['0x01b5'].damage_amount, undefined);

  assert.equal(events['0x0298'].cache_selector_10_u16, 2);
  assert.equal(events['0x0298'].coordinate_x_18_f32, 0);
  assert.equal(events['0x0298'].coordinate_z_1c_f32, 0);
  assert.equal(events['0x0298'].map_truth, undefined);

  assert.equal(events['0x03d4'].movement_complete_count_u8, 1);
  assert.equal(events['0x03d4'].subject_entity_type, undefined);
});

test('wrong build, Replay SHA, runtime, profile, opcode, and consumption fail closed', () => {
  const row = firstBalancedRow('0x00e4');
  const replay = replayFor(row);
  const cases = [
    [replayFor(row, { header: { version: '16.15.801.3452' } }), row, IMAGE,
      /only supports exact build/],
    [replay, { ...row, replay_version: '16.15.801.3452' }, IMAGE,
      /only supports exact build/],
    [replay, { ...row, replay_sha256: 'b'.repeat(64) }, IMAGE,
      /Replay SHA mismatch/],
    [replay, { ...row, decoder_runtime_image_sha256: 'b'.repeat(64) }, IMAGE,
      /runtime image SHA mismatch/],
    [replay, { ...row, decoder_profile_sha256: 'b'.repeat(64) }, IMAGE,
      /runtime profile mismatch/],
    [replay, { ...row, decoder_profile: 'wrong-profile' }, IMAGE,
      /runtime profile mismatch/],
    [replay, { ...row, decoded_opcode: 0x00b8 }, IMAGE,
      /opcode attestation failed/],
    [replay, { ...row, fully_consumed: false }, IMAGE,
      /full-consume row/],
  ];
  for (const [candidateReplay, candidateRow, image, pattern] of cases) {
    assert.throws(() => decoder.gameplayRouteTailEventFromDecodedRow(
      candidateReplay, candidateRow, image,
    ), pattern);
    assert.equal(decoder.isGameplayRouteTailDecodedRow(
      candidateReplay, candidateRow, image,
    ), false);
  }
  assert.throws(() => decoder.gameplayRouteTailEventFromDecodedRow(
    replay, row, Buffer.alloc(IMAGE.length),
  ), /runtime image SHA mismatch/);
});

test('protected Holdout paths fail before any public event is produced', () => {
  const row = firstBalancedRow('0x01ab');
  assert.throws(() => decoder.gameplayRouteTailEventFromDecodedRow(
    replayFor(row, { source_path: 'Jungle Objective Holdout/forbidden.rofl' }),
    row,
    IMAGE,
  ), /protected Holdout path is forbidden/);
  assert.throws(() => decoder.gameplayRouteTailEventFromDecodedRow(
    replayFor(row),
    { ...row, replay_path: 'JUNGLE OBJECTIVE HOLDOUT/forbidden.rofl' },
    IMAGE,
  ), /protected Holdout path is forbidden/);
});

test('the saturation audit re-exports the parser-owned object decoder and bit helpers', () => {
  assert.equal(audit.decodeRouteObject, decoder.decodeRouteObject);
  assert.equal(audit.rotateLeft8, decoder.rotateLeft8);
  assert.equal(audit.rotateRight8, decoder.rotateRight8);
  assert.equal(audit.swapAdjacentBits, decoder.swapAdjacentBits);
});
