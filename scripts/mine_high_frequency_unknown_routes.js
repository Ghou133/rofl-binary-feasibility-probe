#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const { mineUnknownRoutes } = require('../src/unknown_route_deep_miner');

function valueAfter(argv, index, option) {
  if (index + 1 >= argv.length || argv[index + 1].startsWith('--')) throw new Error(`${option} requires a value`);
  return argv[index + 1];
}

function parseArgs(argv) {
  const options = {
    root: process.cwd(),
    samplePath: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/high_frequency_unknown_samples.jsonl',
    damageAnchorPath: 'artifacts/hero_combat_state_v2/emulation/packet_017f_latest_four_decoded.jsonl',
    observedRegistryPath: 'artifacts/full_semantic_baseline_v1/observed_route_registry.json',
    outputPath: 'artifacts/full_semantic_deep_recovery_v2/unknown_mining/high_frequency_unknown_deep_mining.json',
    maxScanBytes: 64,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--root') options.root = valueAfter(argv, index++, option);
    else if (option === '--samples') options.samplePath = valueAfter(argv, index++, option);
    else if (option === '--damage-anchors') options.damageAnchorPath = valueAfter(argv, index++, option);
    else if (option === '--observed-registry') options.observedRegistryPath = valueAfter(argv, index++, option);
    else if (option === '--output') options.outputPath = valueAfter(argv, index++, option);
    else if (option === '--max-scan-bytes') options.maxScanBytes = Number(valueAfter(argv, index++, option));
    else throw new Error(`unknown option: ${option}`);
  }
  return options;
}

function rejectHoldout(filePath) {
  const resolved = path.resolve(filePath);
  if (resolved.toLowerCase().includes('holdout')) throw new Error(`protected Holdout path is forbidden: ${resolved}`);
  return resolved;
}

async function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const root = path.resolve(options.root);
  const samplePath = rejectHoldout(path.resolve(root, options.samplePath));
  const damageAnchorPath = rejectHoldout(path.resolve(root, options.damageAnchorPath));
  const observedRegistryPath = rejectHoldout(path.resolve(root, options.observedRegistryPath));
  const outputPath = rejectHoldout(path.resolve(root, options.outputPath));
  const observedRegistry = JSON.parse(fs.readFileSync(observedRegistryPath, 'utf8'));
  if (observedRegistry.exact_build !== '16.16.805.0442') throw new Error('observed registry exact-build mismatch');
  const report = await mineUnknownRoutes({
    samplePath,
    damageAnchorPath,
    observedRegistry,
    maxScanBytes: options.maxScanBytes,
  });
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  const text = `${JSON.stringify(report, null, 2)}\n`;
  fs.writeFileSync(outputPath, text, 'utf8');
  const summary = {
    output: outputPath,
    sha256: crypto.createHash('sha256').update(text).digest('hex'),
    route_count: report.route_count,
    sampled_packet_count: report.sampled_packet_count,
    decisions: report.routes.map((row) => ({
      packet_discriminator: row.packet_discriminator,
      sample_count: row.sample_count,
      decision: row.research_decision.decision,
      hypothesis: row.research_decision.hypothesis,
      damage_within_10ms_rate: row.damage_neighborhood.within_10ms_rate,
    })),
  };
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { main, parseArgs, rejectHoldout };
