'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const cli = require('../src/cli');
const { packet, replayFromChunks } = require('./helpers/synthetic_replay');

const REPOSITORY = path.resolve(__dirname, '..');

function work(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-batch-jobs-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function replay(root, directory, name = 'same.rofl', version = '16.19.821.7343') {
  const parent = path.join(root, directory);
  fs.mkdirSync(parent, { recursive: true });
  const file = path.join(parent, name);
  fs.writeFileSync(file, replayFromChunks([{
    body: Buffer.concat([packet(1), packet(2), packet(3)]), compressed: true,
  }], version).buffer);
  return file;
}

function command(args) {
  const run = spawnSync(process.execPath, ['src/cli.js', ...args], {
    cwd: REPOSITORY, encoding: 'utf8', timeout: 30_000,
    maxBuffer: 2 * 1024 * 1024, windowsHide: true,
  });
  assert.equal(run.error, undefined, run.error?.message);
  return run;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

test('--jobs is bounded to exact-build JSONL batch use', (t) => {
  const root = work(t);
  const exact = replay(root, 'exact');
  const older = replay(root, 'older', 'old.rofl', '16.19.820.7193');
  const args = ['batch', exact, '--events', 'hero_death', '--event-jsonl-only'];
  assert.equal(cli.parseArgs([...args, '--jobs', '1']).options.jobs, 1);
  assert.equal(cli.parseArgs([...args, '--jobs=2']).options.jobs, 2);
  assert.throws(() => cli.parseArgs([...args, '--jobs', '3']), /--jobs must be 1 or 2/);
  assert.throws(() => cli.parseArgs(['decode', exact, '--events', 'hero_death',
    '--event-jsonl-only', '--jobs', '2']), /--jobs requires batch/);
  assert.throws(() => cli.parseArgs(['batch', exact, '--events', 'hero_death',
    '--jobs', '2']), /--jobs requires batch/);
  const gated = cli.parseOneExact821Batch(older, cli.parseArgs(args).options);
  assert.equal(gated.ok, false);
  assert.equal(gated.error.code, 'UNSUPPORTED_OUTPUT_MODE');
});

test('two-worker exact-821 batch preserves ordered Replay identities and JSONL bytes', (t) => {
  const root = work(t);
  const second = replay(root, 'zeta', 'z.rofl');
  const first = replay(root, 'alpha', 'a.rofl');
  const args = ['batch', second, first, '--events', 'hero_death', '--event-jsonl-only'];
  const serialRoot = path.join(root, 'serial');
  const parallelRoot = path.join(root, 'parallel');
  const serial = command([...args, '--jobs', '1', '--out-dir', serialRoot]);
  const parallel = command([...args, '--jobs', '2', '--out-dir', parallelRoot]);
  assert.equal(parallel.status, serial.status, parallel.stderr);
  const serialManifest = readJson(path.join(serialRoot, 'manifest.json'));
  const parallelManifest = readJson(path.join(parallelRoot, 'manifest.json'));
  const serialSummary = readJson(path.join(serialRoot, 'acceptance_summary.json'));
  const parallelSummary = readJson(path.join(parallelRoot, 'acceptance_summary.json'));
  const sourceOrder = [first, second];
  assert.deepEqual(parallelManifest.replay_inputs.map((row) => row.path), sourceOrder);
  assert.deepEqual(parallelManifest.replay_inputs.map((row) => row.sha256),
    serialManifest.replay_inputs.map((row) => row.sha256));
  assert.deepEqual(parallelManifest.replay_inputs.map((row) => row.decoder_status),
    serialManifest.replay_inputs.map((row) => row.decoder_status));
  assert.equal(parallelSummary.status, serialSummary.status);
  assert.deepEqual(parallelSummary.capability_runs.map((row) => row.source_path), sourceOrder);
  for (let index = 0; index < 2; index += 1) {
    const relative = parallelManifest.replay_inputs[index].artifact_directory;
    const parallelReplay = path.join(parallelRoot, relative);
    const serialReplay = path.join(serialRoot,
      serialManifest.replay_inputs[index].artifact_directory);
    assert.deepEqual(readJson(path.join(parallelReplay, 'semantic_run.json')),
      readJson(path.join(serialReplay, 'semantic_run.json')));
    assert.equal(readJson(path.join(parallelReplay, 'replay_analysis.json')).events, null);
    assert.equal(fs.existsSync(path.join(parallelReplay, 'events.json')), false);
    const serialJsonl = fs.readdirSync(serialReplay).filter((name) => name.endsWith('.jsonl'));
    assert.deepEqual(fs.readdirSync(parallelReplay).filter((name) => name.endsWith('.jsonl')),
      serialJsonl);
    for (const name of serialJsonl) {
      assert.deepEqual(fs.readFileSync(path.join(parallelReplay, name)),
        fs.readFileSync(path.join(serialReplay, name)));
    }
  }
});

test('one corrupt Replay remains a per-Replay failure in a two-worker batch', (t) => {
  const root = work(t);
  const valid = replay(root, 'valid', 'valid.rofl');
  const corrupt = path.join(root, 'corrupt.rofl');
  fs.writeFileSync(corrupt, 'not a ROFL replay');
  const output = path.join(root, 'output');
  const run = command(['batch', valid, corrupt, '--events', 'hero_death',
    '--event-jsonl-only', '--jobs', '2', '--out-dir', output]);
  assert.equal(run.status, 2, run.stderr);
  const summary = readJson(path.join(output, 'acceptance_summary.json'));
  const manifest = readJson(path.join(output, 'manifest.json'));
  assert.equal(summary.status, 'VALIDATION_FAILED');
  assert.equal(summary.replay_file_count, 1);
  assert.equal(summary.errors.length, 1);
  assert.equal(summary.errors[0].source_path, corrupt);
  assert.equal(manifest.replay_inputs.length, 1);
  assert.equal(manifest.replay_inputs[0].path, valid);
});

test('workers retain distinct directories for equal Replay basenames', (t) => {
  const root = work(t);
  const first = replay(root, 'first');
  const second = replay(root, 'second');
  const output = path.join(root, 'output');
  command(['batch', first, second, '--events', 'hero_death',
    '--event-jsonl-only', '--jobs', '2', '--out-dir', output]);
  const manifest = readJson(path.join(output, 'manifest.json'));
  const names = manifest.replay_inputs.map((row) => row.artifact_directory);
  assert.equal(new Set(names).size, 2);
  assert.ok(names.every((name) => /^replays\/same-[a-f0-9]{12}$/.test(name)));
  assert.ok(names.every((name) => fs.existsSync(path.join(output, name, 'semantic_run.json'))));
});

test('missing input and worker crash stay failed; partial worker files are retained', async (t) => {
  const root = work(t);
  const options = { ...cli.parseArgs(['batch', 'unused.rofl', '--events', 'hero_death',
    '--event-jsonl-only', '--jobs', '2']).options, semantic: true };
  const missing = path.join(root, 'missing.rofl');
  const missingResults = await cli.runBatchWorkers([missing], options, path.join(root, 'missing-out'));
  assert.equal(missingResults[0].ok, false);
  assert.equal(missingResults[0].source_path, missing);

  const crashScript = path.join(root, 'crash-worker.js');
  fs.writeFileSync(crashScript, `const fs=require('node:fs');
const path=require('node:path');
const {workerData}=require('node:worker_threads');
const dir=path.join(workerData.rootDir,'replays',workerData.replayDirName);
fs.mkdirSync(dir,{recursive:true});
fs.writeFileSync(path.join(dir,'partial.txt'),'worker stopped');
process.exit(37);\n`);
  const input = replay(root, 'valid');
  const failedRoot = path.join(root, 'crash-out');
  const crashed = await cli.runBatchWorkers([input], options, failedRoot, 2, crashScript);
  assert.equal(crashed[0].ok, false);
  assert.equal(crashed[0].error.code, 'WORKER_FAILED');
  assert.equal(crashed[0].error.details.worker_exit_code, 37);
  const preserved = path.join(failedRoot,
    crashed[0].error.details.partial_artifact_directory);
  assert.equal(fs.readFileSync(path.join(preserved, 'partial.txt'), 'utf8'), 'worker stopped');
  assert.equal(fs.existsSync(path.join(failedRoot, 'replays', 'same')), false);
});
