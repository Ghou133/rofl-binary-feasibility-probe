#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const EXACT_BUILD = '16.16.805.0442';
const ROUTES = new Set([0x01ab, 0x00e4, 0x03d4, 0x0298, 0x00b8, 0x01b5]);

function rejectHoldout(value) {
  const resolved = path.resolve(value);
  if (resolved.toLowerCase().includes('holdout')) {
    throw new Error(`protected Holdout path is forbidden: ${resolved}`);
  }
  return resolved;
}

function scoreRow(row) {
  return crypto.createHash('sha256').update([
    row.replay_sha256,
    row.packet_id,
    row.payload_length,
    row.replay_time_ms,
    row.occurrence_index,
    row.raw_payload_sha256,
  ].join(':')).digest('hex');
}

function insertBounded(rows, candidate, limit) {
  rows.push(candidate);
  rows.sort((left, right) => left.score.localeCompare(right.score));
  if (rows.length > limit) rows.pop();
}

async function selectRows(inputPath, perGroupLimit = 32) {
  if (!Number.isInteger(perGroupLimit) || perGroupLimit < 1 || perGroupLimit > 256) {
    throw new TypeError('perGroupLimit must be an integer from 1 through 256');
  }
  const source = rejectHoldout(inputPath);
  const groups = new Map();
  const reader = readline.createInterface({ input: fs.createReadStream(source), crlfDelay: Infinity });
  for await (const line of reader) {
    if (!line.trim()) continue;
    const row = JSON.parse(line);
    if (!ROUTES.has(Number(row.packet_id))) continue;
    if (row.replay_version !== EXACT_BUILD) throw new Error(`unexpected build ${row.replay_version}`);
    const key = `${row.packet_id}:${row.replay_sha256}:${row.payload_length}`;
    if (!groups.has(key)) groups.set(key, []);
    insertBounded(groups.get(key), { score: scoreRow(row), row }, perGroupLimit);
  }
  return [...groups.values()].flatMap((group) => group.map((entry) => entry.row))
    .sort((left, right) => Number(left.packet_id) - Number(right.packet_id)
      || left.replay_sha256.localeCompare(right.replay_sha256)
      || Number(left.payload_length) - Number(right.payload_length)
      || Number(left.replay_time_ms) - Number(right.replay_time_ms)
      || Number(left.occurrence_index) - Number(right.occurrence_index));
}

async function main(argv = process.argv.slice(2)) {
  const [input, output, limitText = '32'] = argv;
  if (!input || !output) throw new Error('usage: select_gameplay_route_tail_emulation_rows.js INPUT OUTPUT [PER_GROUP_LIMIT]');
  const target = rejectHoldout(output);
  const rows = await selectRows(input, Number(limitText));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const text = rows.map((row) => JSON.stringify(row)).join('\n') + '\n';
  fs.writeFileSync(target, text, 'utf8');
  process.stdout.write(`${JSON.stringify({ output: target, row_count: rows.length, sha256: crypto.createHash('sha256').update(text).digest('hex') }, null, 2)}\n`);
}

if (require.main === module) main().catch((error) => {
  process.stderr.write(`${error.stack ?? error.message}\n`);
  process.exitCode = 1;
});

module.exports = { EXACT_BUILD, ROUTES, insertBounded, rejectHoldout, scoreRow, selectRows };
