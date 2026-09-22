'use strict';

const fs = require('node:fs');
const path = require('node:path');

const { GenericEntityRegistry, writeEntityRegistry } = require('../src/generic_entity_registry');

function usage() {
  return 'Usage: node scripts/build_entity_registry.js --input <json|jsonl> [--input <...>] --output <registry.json> [--lifecycle] [--limit <n>]';
}

function parseArguments(argv) {
  const result = { inputs: [], lifecycle: false, limit: Infinity };
  const requiredValue = (flag, index) => {
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${flag} requires a value`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--input') result.inputs.push(requiredValue(arg, index++));
    else if (arg === '--output') result.output = requiredValue(arg, index++);
    else if (arg === '--lifecycle') result.lifecycle = true;
    else if (arg === '--limit') result.limit = Number(requiredValue(arg, index++));
    else throw new Error(`${usage()}\nUnknown argument: ${arg}`);
  }
  if (result.inputs.length === 0 || !result.output) throw new Error(usage());
  if (!Number.isSafeInteger(result.limit) || result.limit < 0) throw new Error('--limit must be a non-negative integer');
  return result;
}

function recordsFromDocument(document) {
  if (Array.isArray(document)) return document;
  if (document && typeof document === 'object' && document.events && typeof document.events === 'object') {
    return Object.values(document.events).flatMap((value) => Array.isArray(value) ? value : []);
  }
  return [document];
}

function readRecords(inputPath) {
  const text = fs.readFileSync(inputPath, 'utf8').trim();
  if (!text) return [];
  if (path.extname(inputPath).toLowerCase() === '.jsonl') {
    return text.split(/\r?\n/).map((line, index) => {
      try { return JSON.parse(line); } catch (error) { throw new Error(`${inputPath}:${index + 1}: ${error.message}`); }
    });
  }
  return recordsFromDocument(JSON.parse(text));
}

function buildEntityRegistry(inputPaths, options = {}) {
  const registry = new GenericEntityRegistry(options);
  let remaining = options.limit ?? Infinity;
  for (const inputPath of inputPaths) {
    if (remaining <= 0) break;
    for (const record of readRecords(inputPath)) {
      if (remaining <= 0) break;
      if (options.lifecycle) registry.ingestLifecycle(record);
      else registry.ingest(record);
      remaining -= 1;
    }
  }
  return registry;
}

function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  const registry = buildEntityRegistry(options.inputs, options);
  const output = writeEntityRegistry(options.output, registry);
  process.stdout.write(`${JSON.stringify({ output, entity_count: registry.entities.size, event_count: registry.events.length })}\n`);
  return output;
}

if (require.main === module) main();

module.exports = { buildEntityRegistry, parseArguments, readRecords };
