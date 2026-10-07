'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'params_heal_packet_candidates';
const REPLAY = process.env.ROFL_821_REPLAY;
const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;
const hasInputs = [REPLAY, IMAGE].every((filename) =>
  typeof filename === 'string' && fs.existsSync(filename));

function cli(...args) {
  return spawnSync(process.execPath, [CLI, ...args],
    { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
}

function query(directory, ...args) {
  return cli('query-events', directory, '--event', EVENT, ...args);
}

test('exact-821 ParamsHeal saved query re-decodes every native row before limit',
  { skip: hasInputs ? false : 'ROFL_821_REPLAY and ROFL_821_RUNTIME_IMAGE are unavailable' },
  (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-params-heal-source-'));
    t.after(() => {
      const resolved = path.resolve(root);
      assert.ok(resolved.startsWith(path.resolve(os.tmpdir()) + path.sep));
      assert.ok(path.basename(resolved).startsWith('rofl-params-heal-source-'));
      fs.rmSync(resolved, { recursive: true, force: true });
    });
    const artifact = path.join(root, 'artifact');
    const decoded = cli('decode', REPLAY, '--events', 'params_heal_packet',
      '--runtime-image', IMAGE, '--event-jsonl-only', '--out-dir', artifact);
    assert.equal(decoded.status, 0, decoded.stderr || decoded.stdout);
    const manifestPath = path.join(artifact, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const entry = manifest.replay_inputs[0];
    assert.equal(entry.version, '16.19.821.7343');
    const replayDir = path.join(artifact, entry.artifact_directory);
    const eventPath = path.join(replayDir, `${EVENT}.jsonl`);
    const rows = fs.readFileSync(eventPath, 'utf8').trimEnd().split('\n');
    assert.ok(rows.length > 1);

    const missingImage = query(artifact, '--verify-source', '--limit', '1');
    assert.equal(missingImage.status, 2);
    assert.equal(JSON.parse(missingImage.stderr).code, 'MISSING_RUNTIME_IMAGE');
    assert.equal(missingImage.stdout, '');

    const wrongImagePath = path.join(root, 'wrong-image.bin');
    fs.writeFileSync(wrongImagePath, Buffer.alloc(64));
    const wrongImage = query(artifact, '--verify-source', '--runtime-image',
      wrongImagePath, '--limit', '1');
    assert.equal(wrongImage.status, 2);
    assert.equal(JSON.parse(wrongImage.stderr).code, 'SOURCE_PROVENANCE_MISMATCH');
    assert.equal(wrongImage.stdout, '');

    const relocated = path.join(root, 'same-replay.rofl');
    fs.copyFileSync(REPLAY, relocated);
    const physical = query(replayDir, '--verify-source', '--runtime-image', IMAGE,
      '--source-replay', relocated, '--limit', '1');
    assert.equal(physical.status, 0, physical.stderr);
    assert.equal(physical.stdout.trim().split('\n').length, 1);
    const summary = JSON.parse(physical.stderr);
    assert.equal(summary.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
    assert.equal(summary.scanned_count, rows.length);
    assert.equal(summary.emitted_count, 1);

    const opaqueKey = JSON.parse(rows[0]).event_entity_u32_0x04;
    const filtered = query(artifact, '--verify-source', '--runtime-image', IMAGE,
      '--opaque-u32', String(opaqueKey), '--limit', '1');
    assert.equal(filtered.status, 0, filtered.stderr);
    const filteredSummary = JSON.parse(filtered.stderr);
    assert.equal(filteredSummary.source_provenance_status,
      'SOURCE_REPLAY_VERIFIED');
    assert.equal(filteredSummary.scanned_count, rows.length);
    assert.ok(filteredSummary.matched_count > 0);
    assert.equal(filteredSummary.emitted_count, 1);

    const late = JSON.parse(rows.at(-1));
    late.reported_amount_candidate += 1;
    rows[rows.length - 1] = JSON.stringify(late);
    const forged = `${rows.join('\n')}\n`;
    fs.writeFileSync(eventPath, forged);
    manifest.output_hashes_excluding_manifest[
      `${entry.artifact_directory}/${EVENT}.jsonl`] =
      crypto.createHash('sha256').update(forged).digest('hex');
    fs.writeFileSync(manifestPath, JSON.stringify(manifest));
    const output = path.join(root, 'forged-query.jsonl');
    const rejected = query(artifact, '--verify-source', '--runtime-image', IMAGE,
      '--limit', '1', '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'SOURCE_PROVENANCE_MISMATCH');
    assert.equal(rejected.stdout, '');
    assert.equal(fs.existsSync(output), false);
  });
