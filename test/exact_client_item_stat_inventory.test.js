'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  EXACT_BUILD,
  PRESENTATION_STATUS,
  buildExactClientItemStatInventory,
  sha256File,
  writeExactClientItemStatInventoryArtifacts,
} = require('../src/exact_client_item_stat_inventory');

function writeFixture(directory, name, value) {
  fs.mkdirSync(directory, { recursive: true });
  const file = path.join(directory, name);
  const text = `${JSON.stringify(value)}\n`;
  fs.writeFileSync(file, text, 'utf8');
  return { file, sha256: crypto.createHash('sha256').update(text).digest('hex') };
}

function exactBinding() {
  return { exact_build: EXACT_BUILD, status: 'VERIFIED_EXACT_BUILD_IDENTITY', source: 'LOCAL_EXACT_CLIENT_ASSET' };
}

function sampleItems() {
  return [
    {
      id: 3135, name: 'Void Staff',
      description: '<mainText><stats><attention> 95</attention> Ability Power<br><attention> 40%</attention> Magic Penetration<br><attention> 25</attention> Move Speed</stats><br><br><passive>Void</passive> This effect changes while a condition is met.</mainText>',
    },
    {
      id: 3075, name: 'Thornmail',
      description: '<mainText><stats><attention> 350</attention> Health<br><attention> 75</attention> Armor<br><attention> 100%</attention> Base Health Regen</stats><br><br><passive>Thorns</passive> Reflects damage.</mainText>',
    },
    { id: 9999, name: 'No Stats', description: '<mainText>Presentation body only.</mainText>' },
  ];
}

test('strictly inventories literal stats display fields and retains non-stat presentation separately', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-client-item-inventory-'));
  try {
    const fixture = writeFixture(directory, 'items.json', sampleItems());
    const inventory = buildExactClientItemStatInventory({
      itemsPath: fixture.file, expectedSha256: fixture.sha256, exactBuildBinding: exactBinding(),
    });
    assert.equal(inventory.status, PRESENTATION_STATUS);
    assert.equal(inventory.mechanics_consumer_eligible, false);
    assert.equal(inventory.items.length, 3);
    const thornmail = inventory.items.find((row) => row.id === 3075);
    assert.deepEqual(thornmail.recognized_displayed_fields.map(({ field, value, display_unit }) => ({ field, value, display_unit })), [
      { field: 'health', value: 350, display_unit: 'flat' },
      { field: 'armor', value: 75, display_unit: 'flat' },
      { field: 'health_regen_percent', value: 100, display_unit: 'percent' },
    ]);
    const voidStaff = inventory.items.find((row) => row.id === 3135);
    assert.deepEqual(voidStaff.recognized_displayed_fields.map((field) => field.field),
      ['ability_power', 'magic_penetration_percent']);
    assert.deepEqual(voidStaff.unparsed_stats_text, ['25 Move Speed']);
    assert.deepEqual(voidStaff.passive_labels_raw, ['Void']);
    assert.match(voidStaff.conditional_or_passive_body_raw, /condition is met/u);
    assert.equal(voidStaff.mechanics_consumer_eligible, false);
    assert.equal(inventory.summary.recognized_field_counts.magic_penetration_percent, 1);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('build and hash gates fail closed before item normalization', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-client-item-gates-'));
  try {
    const fixture = writeFixture(directory, 'items.json', sampleItems());
    assert.throws(() => buildExactClientItemStatInventory({
      itemsPath: fixture.file, expectedSha256: fixture.sha256,
      exactBuildBinding: { ...exactBinding(), exact_build: '16.16.805.0443' },
    }), /exact build binding mismatch/u);
    assert.throws(() => buildExactClientItemStatInventory({
      itemsPath: fixture.file, expectedSha256: '0'.repeat(64), exactBuildBinding: exactBinding(),
    }), /hash mismatch/u);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('direct and realpath-resolved Holdout inputs are rejected before reads', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-client-item-holdout-'));
  try {
    const holdout = path.join(directory, 'fixture-Holdout');
    const alias = path.join(directory, 'safe-alias');
    const fixture = writeFixture(holdout, 'items.json', sampleItems());
    const originalRead = fs.readFileSync;
    let read = false;
    fs.readFileSync = function guarded(file, ...args) {
      if (String(file).includes('Holdout') || String(file).includes('safe-alias')) read = true;
      return originalRead.call(this, file, ...args);
    };
    try {
      assert.throws(() => buildExactClientItemStatInventory({
        itemsPath: fixture.file, expectedSha256: fixture.sha256, exactBuildBinding: exactBinding(),
      }), /restricted Holdout path/u);
      fs.symlinkSync(holdout, alias, 'junction');
      assert.throws(() => buildExactClientItemStatInventory({
        itemsPath: path.join(alias, 'items.json'), expectedSha256: fixture.sha256, exactBuildBinding: exactBinding(),
      }), /restricted Holdout path/u);
    } finally { fs.readFileSync = originalRead; }
    assert.equal(read, false);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('artifact writing is deterministic and closes the inventory hash', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'exact-client-item-artifacts-'));
  try {
    const fixture = writeFixture(directory, 'items.json', sampleItems());
    const options = { itemsPath: fixture.file, expectedSha256: fixture.sha256, exactBuildBinding: exactBinding() };
    const first = writeExactClientItemStatInventoryArtifacts({ ...options, outputDir: path.join(directory, 'a') });
    const second = writeExactClientItemStatInventoryArtifacts({ ...options, outputDir: path.join(directory, 'b') });
    assert.deepEqual(first.inventory, second.inventory);
    assert.deepEqual(first.closure, second.closure);
    assert.equal(sha256File(first.paths.inventory), first.artifacts[0].sha256);
    assert.equal(first.closure.mechanics_consumer_eligible, false);
    assert.equal(fs.existsSync(first.paths.closure), true);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
