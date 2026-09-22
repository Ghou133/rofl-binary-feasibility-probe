#!/usr/bin/env node
'use strict';

const path = require('node:path');
const { runHudRuntimeStateBridge } = require('../src/hud_runtime_state_bridge');

const rootDir = path.resolve(__dirname, '..');
let outputDir = path.join(rootDir, '.omo', 'evidence', 'quant_runtime_bridge');
for (let index = 2; index < process.argv.length; index += 1) {
  if (process.argv[index] === '--output-dir') outputDir = path.resolve(process.argv[++index]);
  else throw new Error(`unknown argument: ${process.argv[index]}`);
}

try {
  const { paths } = runHudRuntimeStateBridge({ rootDir, outputDir });
  process.stdout.write(`${JSON.stringify(paths)}\n`);
} catch (error) {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
}
