'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const CLI = path.join(__dirname, '..', 'src', 'cli.js');
const SAMPLE_DIR = process.env.ROFL_821_REPLAY_DIR;
const SAMPLE = SAMPLE_DIR && fs.existsSync(SAMPLE_DIR)
  ? fs.readdirSync(SAMPLE_DIR).filter((name) => name.endsWith('.rofl'))
    .sort().map((name) => path.join(SAMPLE_DIR, name))[0]
  : null;

function cli(...args) {
  return spawnSync(process.execPath, [CLI, ...args],
    { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
}

function query(directory, eventKey, ...args) {
  return cli('query-events', directory, '--event', eventKey, ...args);
}

test('exact-821 healing snapshot source queries check late rows and relocated input',
  { skip: SAMPLE ? false : 'ROFL_821_REPLAY_DIR with an exact-821 ROFL is unavailable' },
  (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-heal-source-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const decoded = cli('decode', SAMPLE, '--out-dir', root, '--events',
      'hero_total_heal_snapshot,hero_total_units_healed_snapshot',
      '--event-jsonl-only');
    assert.equal(decoded.status, 0, decoded.stderr || decoded.stdout);
    const manifestPath = path.join(root, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const entry = manifest.replay_inputs[0];
    assert.equal(entry.version, '16.19.821.7343');
    const replayDir = path.join(root, entry.artifact_directory);
    const analysis = JSON.parse(fs.readFileSync(
      path.join(replayDir, 'replay_analysis.json'), 'utf8'));
    const relocated = path.join(root, 'same-replay.rofl');
    fs.copyFileSync(SAMPLE, relocated);

    for (const eventKey of ['hero_total_heal_snapshot_candidates',
      'hero_total_units_healed_snapshot_candidates']) {
      const result = query(replayDir, eventKey, '--source-replay', relocated,
        '--verify-source', '--limit', '1');
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stdout.trim().split('\n').length, 1);
      const summary = JSON.parse(result.stderr);
      assert.equal(summary.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
      assert.equal(summary.scanned_count, analysis.event_counts[eventKey]);
      assert.equal(summary.emitted_count, 1);
    }

    const eventKey = 'hero_total_heal_snapshot_candidates';
    const eventPath = path.join(replayDir, `${eventKey}.jsonl`);
    const rows = fs.readFileSync(eventPath, 'utf8').trimEnd().split('\n');
    const late = JSON.parse(rows.at(-1));
    late.total_heal_candidate += 1;
    rows[rows.length - 1] = JSON.stringify(late);
    const forged = `${rows.join('\n')}\n`;
    fs.writeFileSync(eventPath, forged);
    manifest.output_hashes_excluding_manifest[
      `${entry.artifact_directory}/${eventKey}.jsonl`] =
      crypto.createHash('sha256').update(forged).digest('hex');
    fs.writeFileSync(manifestPath, JSON.stringify(manifest));
    const output = path.join(root, 'forged-query.jsonl');
    const rejected = query(root, eventKey, '--verify-source', '--limit', '1',
      '--output', output);
    assert.equal(rejected.status, 2, rejected.stderr);
    assert.equal(JSON.parse(rejected.stderr).code, 'SOURCE_PROVENANCE_MISMATCH');
    assert.equal(rejected.stdout, '');
    assert.equal(fs.existsSync(output), false);
  });
