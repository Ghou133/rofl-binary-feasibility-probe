#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const {
  buildPacketCoverageInventory,
  recordsFromReplayFile,
  sha256File,
} = require('../src/packet_coverage_inventory');

function parseArgs(argv) {
  const options = {
    output: path.resolve('artifacts', 'semantic_coverage_v1', 'packet_coverage_inventory.json'),
    replayFiles: [],
    recordFiles: [],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === '--output') options.output = path.resolve(argv[++index]);
    else if (value === '--replay') options.replayFiles.push(path.resolve(argv[++index]));
    else if (value === '--records') options.recordFiles.push(path.resolve(argv[++index]));
    else if (value === '--help' || value === '-h') options.help = true;
    else if (value.startsWith('-')) throw new Error(`unknown option: ${value}`);
    else if (value.toLowerCase().endsWith('.rofl')) options.replayFiles.push(path.resolve(value));
    else options.recordFiles.push(path.resolve(value));
  }
  if (!options.help && options.replayFiles.length + options.recordFiles.length === 0) {
    throw new Error('supply at least one .rofl input or --records exported packet file');
  }
  return options;
}

function usage() {
  return [
    'Usage: node scripts/build_packet_coverage_inventory.js [--output FILE] [--replay FILE.rofl] [--records FILE.jsonl|FILE.json] ...',
    'Bare .rofl paths are Replay inputs; all other bare paths are exported packet records.',
  ].join('\n');
}

function readRecordFile(filePath) {
  const text = fs.readFileSync(filePath, 'utf8').trim();
  if (!text) return [];
  if (filePath.toLowerCase().endsWith('.jsonl')) {
    return text.split(/\r?\n/).map((line) => JSON.parse(line));
  }
  const parsed = JSON.parse(text);
  if (Array.isArray(parsed)) return parsed;
  if (Array.isArray(parsed.records)) return parsed.records;
  if (Array.isArray(parsed.packet_records)) return parsed.packet_records;
  throw new Error(`${filePath} must contain an array, records array, packet_records array, or JSONL rows`);
}

function main(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return null;
  }
  const rawRecords = options.recordFiles.sort().flatMap((filePath) => {
    const recordSourceSha256 = sha256File(filePath);
    return readRecordFile(filePath).map((record) => ({
      ...record,
      source_path: record.source_path ?? filePath,
      record_source_sha256: recordSourceSha256,
    }));
  });
  const replayRawRecords = options.replayFiles.sort().flatMap((filePath) => recordsFromReplayFile(filePath));
  const inventory = buildPacketCoverageInventory([...rawRecords, ...replayRawRecords]);
  const output = path.resolve(options.output);
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(inventory, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify({
    output,
    input_record_count: inventory.input_record_count,
    builds: inventory.builds,
    packet_type_count: inventory.packets.length,
  }, null, 2)}\n`);
  return inventory;
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { main, parseArgs, readRecordFile, usage };
