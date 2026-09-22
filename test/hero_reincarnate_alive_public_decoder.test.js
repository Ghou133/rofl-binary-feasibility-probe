'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {
  HERO_REINCARNATE_ALIVE_PROFILE,
  heroReincarnateAliveEventFromDecodedRow,
} = require('../src/decoders/hero_reincarnate_alive_16_16');
const {
  canonicalHeroReincarnateAliveEvent,
  validateCanonicalRecord,
} = require('../src/semantic_api');

const ROOT = path.resolve(__dirname, '..');
const ROW_PATH = path.join(
  ROOT,
  'artifacts/full_semantic_deep_recovery_v2/hero_respawn/packet_0265_p0_decoded.jsonl',
);

function firstRow() {
  return JSON.parse(fs.readFileSync(ROW_PATH, 'utf8').split(/\r?\n/).find(Boolean));
}

test('public 0x0265 adapter emits exact reincarnate-alive event with bounded fields', () => {
  const row = firstRow();
  const replay = {
    header: { version: '16.16.805.0442' },
    source_sha256: row.replay_sha256,
    source_path: row.replay_path,
  };
  const event = heroReincarnateAliveEventFromDecodedRow(replay, row);
  assert.equal(event.event_type, 'HERO_REINCARNATE_ALIVE');
  assert.equal(event.lifecycle_operation, 'REINCARNATE_ALIVE');
  assert.equal(event.respawn_timestamp_ms, row.replay_time_ms);
  assert.equal(event.participant_id, 4);
  assert.deepEqual(event.position, { x: 394, y: 0, z: 461 });
  assert.equal(event.reincarnate_scalar, 373.79998779296875);
  assert.match(event.reincarnate_scalar_role, /UNKNOWN/);
  assert.equal(event.raw_packet_ref.payload_sha256, row.raw_payload_sha256);
});

test('public 0x0265 profile pins exact runtime and semantic evidence', () => {
  assert.equal(HERO_REINCARNATE_ALIVE_PROFILE.enabled, true);
  assert.equal(HERO_REINCARNATE_ALIVE_PROFILE.packet_id, 0x0265);
  assert.equal(HERO_REINCARNATE_ALIVE_PROFILE.sample_count.exact_full_consume_count, 282);
  assert.equal(
    HERO_REINCARNATE_ALIVE_PROFILE.field_evidence.reincarnate_scalar,
    'VERIFIED_DIRECT_VALUE_UNKNOWN_RESOURCE_LIKE_ROLE',
  );
});

test('public 0x0265 event maps to canonical EntityLifecycle without route leakage', () => {
  const row = firstRow();
  const raw = heroReincarnateAliveEventFromDecodedRow({
    header: { version: '16.16.805.0442' },
    source_sha256: row.replay_sha256,
    source_path: row.replay_path,
  }, row);
  const canonical = canonicalHeroReincarnateAliveEvent(raw);
  assert.equal(canonical.semantic_type, 'EntityLifecycle');
  assert.equal(canonical.fields.lifecycle_operation, 'REINCARNATE_ALIVE');
  assert.equal(canonical.fields.respawn_timestamp_ms, row.replay_time_ms);
  assert.deepEqual(canonical.fields.position, { x: 394, y: 0, z: 461 });
  assert.equal(Object.hasOwn(canonical, 'packet_id'), false);
  assert.ok(validateCanonicalRecord(canonical));
});

test('public 0x0265 adapter fails closed on build, SHA, and Holdout path', () => {
  const row = firstRow();
  assert.throws(() => heroReincarnateAliveEventFromDecodedRow({
    header: { version: '16.15.801.3452' },
    source_sha256: row.replay_sha256,
    source_path: row.replay_path,
  }, row), /exact build/);
  assert.throws(() => heroReincarnateAliveEventFromDecodedRow({
    header: { version: '16.16.805.0442' },
    source_sha256: '0'.repeat(64),
    source_path: row.replay_path,
  }, row), /SHA mismatch/);
  assert.throws(() => heroReincarnateAliveEventFromDecodedRow({
    header: { version: '16.16.805.0442' },
    source_sha256: row.replay_sha256,
    source_path: 'C:/Jungle Objective Holdout/forbidden.rofl',
  }, row), /Holdout path/);
});
