'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Readable } = require('node:stream');
const test = require('node:test');

const { outputHashes, writeJsonl } = require('../src/io');

function work(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-jsonl-'));
  t.after(() => {
    for (const name of fs.readdirSync(directory)) {
      fs.rmSync(path.join(directory, name), { force: true });
    }
    fs.rmdirSync(directory);
  });
  return directory;
}

test('JSONL output preserves empty, Unicode, escaping and blank row bytes', (t) => {
  const file = path.join(work(t), 'events.jsonl');
  writeJsonl(file, []);
  assert.equal(fs.statSync(file).size, 0);

  const rows = [
    { ascii: 'one' },
    { unicode: '汉字😀', escaped: 'line\n"quote"' },
    null,
    undefined,
  ];
  rows.length = 6;
  rows[5] = ['x', 1];
  writeJsonl(file, rows);
  const expected = [
    '{"ascii":"one"}',
    '{"unicode":"汉字😀","escaped":"line\\n\\"quote\\""}',
    'null', '', '', '["x",1]', '',
  ].join('\n');
  assert.deepEqual(fs.readFileSync(file), Buffer.from(expected, 'utf8'));

  writeJsonl(file, []);
  assert.equal(fs.statSync(file).size, 0);
  assert.deepEqual(fs.readdirSync(path.dirname(file)), ['events.jsonl']);
});

test('large JSONL output uses bounded writes and preserves its SHA-256', (t) => {
  const file = path.join(work(t), 'large.jsonl');
  const row = { raw: 'x'.repeat(2048), marker: '字😀' };
  const rows = Array(12_000).fill(row);
  rows.push({ raw: 'β'.repeat(1_100_000) });
  const expectedHash = crypto.createHash('sha256');
  let expectedSize = 0;
  for (const value of rows) {
    const line = `${JSON.stringify(value)}\n`;
    expectedHash.update(line, 'utf8');
    expectedSize += Buffer.byteLength(line, 'utf8');
  }

  const requestedWrites = [];
  const originalWriteSync = fs.writeSync;
  fs.writeSync = function instrumentWrite(...args) {
    if (Buffer.isBuffer(args[1])) requestedWrites.push(args[3] ?? args[1].length);
    return Reflect.apply(originalWriteSync, this, args);
  };
  try {
    writeJsonl(file, rows);
  } finally {
    fs.writeSync = originalWriteSync;
  }

  assert.ok(requestedWrites.length > 2);
  assert.ok(requestedWrites.every((size) => size > 0 && size <= 1024 * 1024));
  assert.equal(fs.statSync(file).size, expectedSize);
  assert.equal(crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),
    expectedHash.digest('hex'));
});

test('serialization failure preserves the prior JSONL and removes the temp file', (t) => {
  const directory = work(t);
  const file = path.join(directory, 'events.jsonl');
  fs.writeFileSync(file, 'prior\n', 'utf8');
  const circular = {};
  circular.self = circular;
  assert.throws(() => writeJsonl(file, [{ first: true }, circular]),
    /circular/i);
  assert.equal(fs.readFileSync(file, 'utf8'), 'prior\n');
  assert.deepEqual(fs.readdirSync(directory), ['events.jsonl']);
});

test('output hashes preserve sorted bytes with at most eight open streams', async (t) => {
  const directory = work(t);
  const expected = {};
  for (let index = 0; index < 20; index += 1) {
    const name = `candidate-${String(index).padStart(2, '0')}.jsonl`;
    const bytes = Buffer.from(`${index}:候选:${'x'.repeat(index * 17)}\n`, 'utf8');
    fs.writeFileSync(path.join(directory, name), bytes);
    expected[name] = crypto.createHash('sha256').update(bytes).digest('hex');
  }
  fs.writeFileSync(path.join(directory, 'manifest.json'), 'excluded\n');

  let open = 0;
  let peakOpen = 0;
  const originalCreateReadStream = fs.createReadStream;
  fs.createReadStream = function instrumentReadStream(...args) {
    const stream = Reflect.apply(originalCreateReadStream, this, args);
    open += 1;
    peakOpen = Math.max(peakOpen, open);
    stream.once('close', () => { open -= 1; });
    return stream;
  };
  let actual;
  try {
    actual = await outputHashes(directory, { exclude: ['manifest.json'] });
  } finally {
    fs.createReadStream = originalCreateReadStream;
  }

  assert.deepEqual(actual, expected);
  assert.deepEqual(Object.keys(actual), Object.keys(expected));
  assert.equal(open, 0);
  assert.equal(peakOpen, 8);
});

test('output hash failure drains active streams before rejecting', async (t) => {
  const directory = work(t);
  const names = Array.from({ length: 16 }, (_, index) =>
    `candidate-${String(index).padStart(2, '0')}.jsonl`);
  for (const name of names) fs.writeFileSync(path.join(directory, name), name);
  const failure = new Error('controlled hash read failure');
  const started = [];
  const pending = [];
  let open = 0;
  const originalCreateReadStream = fs.createReadStream;
  fs.createReadStream = function delayedReadStream(filePath) {
    const name = path.basename(filePath);
    const stream = new Readable({ read() {} });
    started.push(name);
    open += 1;
    stream.once('close', () => { open -= 1; });
    if (name === names[0]) {
      stream.once('close', () => setImmediate(() => {
        for (const item of pending) {
          item.stream.push(Buffer.from(item.name));
          item.stream.push(null);
        }
      }));
      process.nextTick(() => stream.destroy(failure));
    } else pending.push({ name, stream });
    return stream;
  };
  try {
    await assert.rejects(outputHashes(directory), (error) => error === failure);
    assert.equal(open, 0);
    assert.deepEqual(started, names.slice(0, 8));
  } finally {
    fs.createReadStream = originalCreateReadStream;
  }
});
