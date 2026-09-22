'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const ROOT = path.resolve(__dirname, '..');
const SCRIPT = path.join(ROOT, 'scripts', 'trace_route_0064_runtime_residual.py');

test('route 0x0064 exact codec self-test closes 24 dynamic and 18 observed constant tag pairs', () => {
  const result = spawnSync('python', [SCRIPT, '--self-test'], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.deepEqual(report, {
    status: 'PASS',
    dynamic_tag_pair_space: 24,
    observed_three_byte_constant_tag_pair_space: 18,
    holdout_guard: 'PASS',
  });
});
