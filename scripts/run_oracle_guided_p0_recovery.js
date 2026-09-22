#!/usr/bin/env node

const path = require('node:path');
const { runOracleGuidedP0Recovery } = require('../src/oracle_guided_p0_recovery');

function parseArgs(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === '--replay') options.replayPath = value;
    else if (flag === '--oracle') options.oraclePath = value;
    else if (flag === '--anchor-dir') options.anchorDir = value;
    else if (flag === '--output-dir') options.outputDir = value;
    else if (flag === '--window-ms') options.windowMs = Number(value);
    else if (flag === '--top-n') options.topN = Number(value);
    else throw new Error(`unknown argument: ${flag}`);
    index += 1;
  }
  return options;
}

function main() {
  const result = runOracleGuidedP0Recovery(parseArgs(process.argv.slice(2)));
  const summary = {
    status: 'PASS',
    report_path: path.resolve(result.reportPath),
    markdown_path: path.resolve(result.markdownPath),
    exact_build: result.report.exact_build,
    replay_sha256: result.report.replay_sha256,
    oracle_records: result.report.oracle.record_count,
    transitions: result.report.oracle.completed_transition_count,
    routes: result.report.scan.route_count,
    blocks: result.report.scan.parsed_block_count,
    level_up_status: result.report.oracle.level_up_status,
    p0_funnels: Object.fromEntries(Object.entries(result.report.p0).map(([semantic, value]) => [semantic, value.funnel])),
  };
  process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

if (require.main === module) main();

module.exports = { parseArgs, main };
