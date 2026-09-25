'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

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
const CHAMPION_DIE_EVENT = 'champion_die_event_packet_candidates';
const CHAMPION_KILL_EVENT = 'champion_kill_event_packet_candidates';

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
    HEAL_PACKET_EVENT, SHIELD_PAIR_EVENT, STEALTH_PACKET_EVENT,
    CHAMPION_DIE_EVENT, CHAMPION_KILL_EVENT].includes(eventKey)
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
