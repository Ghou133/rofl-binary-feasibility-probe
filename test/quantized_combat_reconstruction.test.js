'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  PROJECTIONS, controlledDamageAudit, decodeShieldCallbackObject, decreaseInterval, derivabilityAudit,
  displayInterval, intervalContains,
  validateShieldMigrationScan,
} = require('../src/quantized_combat_reconstruction');
const {
  shieldAbsorbedFromFullyConsumedRow,
} = require('../src/decoders/shield_absorbed_16_16');

const ROOT = path.resolve(__dirname, '..');

test('HUD projections produce explicit half-open internal intervals', () => {
  assert.deepEqual(displayInterval(41, 'FLOOR'), { lower: 41, upper: 42, lower_closed: true, upper_closed: false });
  assert.deepEqual(displayInterval(41, 'ROUND_NEAREST'), { lower: 40.5, upper: 41.5, lower_closed: true, upper_closed: false });
  assert.deepEqual(displayInterval(41, 'TRUNCATE_TOWARD_ZERO'), { lower: 41, upper: 42, lower_closed: true, upper_closed: false });
  const damage = decreaseInterval(655, 602, 'FLOOR');
  assert.equal(intervalContains(damage, 53.23854064941406), true);
  assert.equal(intervalContains(damage, 54), false);
  assert.equal(intervalContains(damage, 52), false);
  assert.equal(intervalContains(damage, 52 + 1e-9), true);
  assert.equal(intervalContains(damage, 54 - 1e-9), true);
  assert.equal(intervalContains(displayInterval(41, 'FLOOR'), 41), true);
  assert.equal(intervalContains(displayInterval(41, 'FLOOR'), 42), false);
  assert.equal(intervalContains(displayInterval(-41, 'TRUNCATE_TOWARD_ZERO'), -42), false);
  assert.equal(intervalContains(displayInterval(-41, 'TRUNCATE_TOWARD_ZERO'), -41), true);
});

test('three controlled Damage rows pass interval arithmetic without integer equality', () => {
  const file = path.join(ROOT, 'artifacts', 'controlled_calibration_replays', 'HN1-11212942693', 'p0_anchor_scan', '0x017f_decoded.jsonl');
  const rows = fs.readFileSync(file, 'utf8').trim().split(/\r?\n/).map(JSON.parse);
  const audit = controlledDamageAudit(rows);
  assert.equal(audit.length, 3);
  assert.ok(audit.every((row) => row.compatible_projection_count === PROJECTIONS.length));
  assert.equal(audit.find((row) => row.timestamp_ms === 61785).field_2c, 100);
  assert.notEqual(audit[0].field_24, audit[0].hud_integer_difference_for_reference_only);
  const tampered = rows.map((row, index) => index === 0 ? { ...row, replay_sha256: '0'.repeat(64) } : row);
  assert.throws(() => controlledDamageAudit(tampered), /pinned replay\/build\/runtime\/profile identity/);
});

test('all 79 governed capabilities are classified without status mutation', () => {
  const audit = derivabilityAudit();
  assert.equal(audit.capability_count, 79);
  assert.equal(Object.values(audit.classification_counts).reduce((sum, count) => sum + count, 0), 79);
  assert.ok(audit.rows.every((row) => row.public_manifest_changed === false));
  assert.equal(audit.rows.find((row) => row.semantic_capability === 'ARMOR').derivability_classification, 'DERIVABLE_IF_INPUT_X');
  assert.equal(audit.rows.find((row) => row.semantic_capability === 'HERO_PATH').derivability_classification, 'DERIVABLE_NOW');
});

test('16.16 shield callback inverse recovers known target-total amount and duplicate target', () => {
  const image = fs.readFileSync(path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1',
    'runtime', 'league_16.16.805.0442.memory.bin'));
  const decoded = decodeShieldCallbackObject(
    'e809b14101000000e101e6e6b20000407981ece65050505033404019290e0e12',
    image.subarray(0x01a27950, 0x01a27a50));
  assert.equal(decoded.shield_absorbed_amount, 20.230152130126953);
  assert.equal(decoded.field_14_plain_u32, 0);
  assert.equal(decoded.target_network_id_from_field_18, 0x400000b2);
  assert.equal(decoded.target_network_id_from_field_1c, 0x400000b2);
});

test('16.16 shield canonical consumer fails closed on identity and lookup-table tampering', () => {
  const dir = path.join(ROOT, '.omo', 'evidence', 'quant_combat_closure');
  const row = JSON.parse(fs.readFileSync(path.join(dir, 'packet_01e1_neutral_decoded.jsonl'), 'utf8').split(/\r?\n/)[0]);
  const image = fs.readFileSync(path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1',
    'runtime', 'league_16.16.805.0442.memory.bin'));
  const table = image.subarray(0x01a27950, 0x01a27a50);
  assert.equal(shieldAbsorbedFromFullyConsumedRow(row, table)?.semantic, 'SHIELD_ABSORBED');
  for (const mutation of [
    { replay_version: '16.15.801.3452' }, { decoder_profile: 'wrong' },
    { decoder_runtime_image_sha256: '0'.repeat(64) }, { raw_param: null },
    { replay_sha256: null }, { replay_time_ms: 1.5 }, { raw_payload_sha256: '0'.repeat(64) },
    { fully_consumed: false },
  ]) assert.equal(shieldAbsorbedFromFullyConsumedRow({ ...row, ...mutation }, table), null);
  const tamperedTable = Buffer.from(table); tamperedTable[0] ^= 1;
  assert.throws(() => shieldAbsorbedFromFullyConsumedRow(row, tamperedTable), /lookup table SHA/);
});

test('generated combat closure evidence is nonempty and fail-closed', () => {
  const dir = path.join(ROOT, '.omo', 'evidence', 'quant_combat_closure');
  const report = JSON.parse(fs.readFileSync(path.join(dir, 'quantized_combat_reconstruction_report.json'), 'utf8'));
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'artifact_manifest.json'), 'utf8'));
  assert.equal(report.exact_build, '16.16.805.0442');
  assert.equal(report.damage_stage_promotion_audit.promotion_decision, 'NO_PUBLIC_PROMOTION');
  assert.equal(report.damage_stage_promotion_audit.candidate_stage,
    'HUD_QUANTIZED_HP_DECREASE_COMPATIBLE_COMPONENT_HYPOTHESIS');
  assert.equal(report.hud_projection.hypothesis_set_not_exhaustive, true);
  assert.equal(report.corpus_search.latest_four.row_count, 266332);
  assert.equal(report.corpus_search.latest_four.exact_full_consume_count, 266332);
  assert.equal(report.corpus_search.paired_details.lethal_context_component_count, 4);
  assert.equal(report.corpus_search.paired_details.lethal_context_components[0].classification,
    'LETHAL_CONTEXT_COMPONENT_NOT_ISOLATED_LETHAL_HP_DELTA');
  assert.equal(report.mitigation.status, 'EXTERNAL_INPUT_REQUIRED');
  assert.equal(report.shield_route_migration_audit.governed_corpus_scan.total_block_count, 55552224);
  assert.equal(report.shield_route_migration_audit.governed_corpus_scan.migrated_static_route_0x01e1_count, 12);
  assert.equal(report.shield_route_migration_audit.direct_16_16_absorption_recovery.event_count, 12);
  assert.equal(report.shield_route_migration_audit.direct_16_16_absorption_recovery.target_fields_agree_count, 12);
  assert.equal(report.heal_shield.shield.absorbed_status_16_16,
    'DIRECT_RECOVERED_0x01e1_TARGET_TOTAL_12_ROWS');
  assert.equal(report.public_capability_changes[0].semantic, 'SHIELD_ABSORBED');
  assert.equal(report.shield_route_migration_audit.migration_oracle.status,
    'AUTO_VERIFIED_WITH_ROUTE_MOVE');
  assert.ok(Object.values(report.protected_holdout).every((value) => value === false));
  assert.equal(manifest.artifacts.length, 10);
  assert.ok(manifest.artifacts.every((item) => item.bytes > 0 && /^[0-9a-f]{64}$/.test(item.sha256)));
});

test('shield migration cache accepts only the canonical file and complete corpus identities', () => {
  const dir = path.join(ROOT, '.omo', 'evidence', 'quant_combat_closure');
  const cache = path.join(dir, 'shield_route_migration_scan.json');
  const inventory = path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1',
    'new_build_replay_inventory.csv');
  const scan = JSON.parse(fs.readFileSync(cache, 'utf8'));
  assert.equal(validateShieldMigrationScan(scan, { inventoryCsv: inventory, cachedScanPath: cache }), scan);
  for (const mutation of [
    { total_block_count: scan.total_block_count - 1 },
    { migrated_static_route_0x01e1_count: 11 },
    { replays: scan.replays.map((row, index) => index ? row : { ...row, sha256: '0'.repeat(64) }) },
    { migrated_static_route_0x01e1_rows: scan.migrated_static_route_0x01e1_rows.slice(1) },
  ]) assert.throws(() => validateShieldMigrationScan({ ...scan, ...mutation }, { inventoryCsv: inventory }),
    /invalid cached shield-route migration scan/);
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-shield-cache-tamper-'));
  try {
    const tamperedCache = path.join(temp, 'scan.json');
    fs.writeFileSync(tamperedCache, `${JSON.stringify({ ...scan, parser_error_count: 1 }, null, 2)}\n`);
    assert.throws(() => validateShieldMigrationScan(scan,
      { inventoryCsv: inventory, cachedScanPath: tamperedCache }), /invalid cached shield-route migration scan/);
    const tamperedInventory = path.join(temp, 'inventory.csv');
    fs.writeFileSync(tamperedInventory, fs.readFileSync(inventory));
    assert.throws(() => validateShieldMigrationScan(scan,
      { inventoryCsv: tamperedInventory }), /invalid cached shield-route migration scan/);
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
});

test('fresh canonical runs are deterministic and validate pinned identities', () => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-quant-combat-'));
  const first = path.join(tempRoot, 'first');
  const second = path.join(tempRoot, 'second');
  const shieldScan = path.join(ROOT, '.omo', 'evidence', 'quant_combat_closure', 'shield_route_migration_scan.json');
  try {
    for (const output of [first, second]) childProcess.execFileSync(process.execPath, [
      path.join(ROOT, 'scripts', 'run_quantized_combat_reconstruction.js'), '--output-dir', output,
      '--reuse-shield-scan', shieldScan,
    ], { cwd: ROOT, stdio: 'pipe' });
    const firstReport = JSON.parse(fs.readFileSync(path.join(first, 'quantized_combat_reconstruction_report.json'), 'utf8'));
    const secondReport = JSON.parse(fs.readFileSync(path.join(second, 'quantized_combat_reconstruction_report.json'), 'utf8'));
    assert.deepEqual(firstReport, secondReport);
    assert.equal(firstReport.controlled_replay_sha256,
      '1fb1321e802103ce8e20e670b981b8b59d43a1fbbdc911f79ba249257ed672ff');
    assert.equal(firstReport.corpus_search.latest_four.identity.runtime_image_sha256,
      '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55');
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
});
