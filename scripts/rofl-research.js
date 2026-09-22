#!/usr/bin/env node

const path = require('node:path');
const { spawnSync } = require('node:child_process');

const projectRoot = path.resolve(__dirname, '..');
const cli = path.join(projectRoot, 'research-v3', 'cli.py');
const python = process.env.ROFL_RESEARCH_PYTHON || process.env.PYTHON || 'python';
const result = spawnSync(python, [cli, ...process.argv.slice(2)], {
  cwd: projectRoot,
  stdio: 'inherit',
  windowsHide: true,
});

if (result.error) {
  process.stderr.write(`${result.error.stack || result.error.message}\n`);
  process.exitCode = 1;
} else {
  process.exitCode = result.status ?? 1;
}
