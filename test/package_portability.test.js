'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const manifestPath = path.join(root, 'package_manifest.json');

test('handoff configuration excludes private and non-portable data', () => {
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.equal(packageJson.scripts['package:handoff'],
    'python -B scripts/package_handoff.py --with-evidence');
  assert.equal(packageJson.scripts['package:source'],
    'python -B scripts/package_handoff.py');
  assert.equal(packageJson.scripts['verify:source'],
    'python -B scripts/package_handoff.py --validate dist/rofl-analyzer-source.zip');
  assert.equal(packageJson.scripts['verify:handoff'],
    'python -B scripts/package_handoff.py --validate dist/rofl-analyzer-ai-handoff.zip');
  const builder = fs.readFileSync(path.join(root, 'scripts', 'package_handoff.py'), 'utf8');
  for (const marker of ['replay/', 'research-v3/output/', '.rofl', '.duckdb', '.memory.bin']) {
    assert.ok(builder.includes(marker), `builder must explicitly exclude ${marker}`);
  }
});

test('an extracted handoff verifies every closed-manifest payload', (t) => {
  if (!fs.existsSync(manifestPath)) {
    t.skip('No extracted package_manifest.json; archive integrity is checked by the packaging suite.');
    return;
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assert.ok(['SOURCE_ONLY', 'SOURCE_AND_BOUNDED_EVIDENCE'].includes(manifest.verification_mode));
  assert.equal(manifest.closed_payload, true);
  assert.equal(manifest.raw_redecode_performed, false);
  assert.ok(Array.isArray(manifest.deliberately_excluded));
  const entries = Object.entries(manifest.files ?? {});
  assert.equal(entries.length, manifest.file_count);
  for (const [relative, expected] of entries) {
    assert.equal(path.isAbsolute(relative), false);
    assert.equal(relative.split(/[\\/]/).includes('..'), false);
    const file = path.join(root, relative);
    assert.equal(fs.statSync(file).size, expected.size, relative);
    const actual = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    assert.equal(actual, expected.sha256, relative);
  }
});
