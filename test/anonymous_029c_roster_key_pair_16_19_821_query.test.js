'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'anonymous_029c_roster_key_pair_candidates';
const SOURCE_EVENT = 'anonymous_029c_packet_candidates';
const REPLAY = process.env.ROFL_821_REPLAY;
const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE;
const available = REPLAY && IMAGE && fs.existsSync(REPLAY) && fs.existsSync(IMAGE);
const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

function cli(...args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
    timeout: 120_000,
  });
}

function updateManifest(root, relative, event, content) {
  const manifestPath = path.join(root, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  manifest.output_hashes_excluding_manifest[`${relative}/${event}.jsonl`] =
    sha256(content);
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));
}

test('real exact-821 saved 0x029c roster query checks full source and late rows',
  { skip: !available ? 'exact 821 replay and runtime image unavailable' : false },
  (t) => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-029c-roster-query-'));
    t.after(() => {
      const resolved = path.resolve(root);
      if (!resolved.startsWith(path.resolve(os.tmpdir()) + path.sep)
          || !path.basename(resolved).startsWith('rofl-029c-roster-query-')) {
        throw new Error('Unsafe 0x029c query test cleanup target');
      }
      fs.rmSync(resolved, { recursive: true, force: true });
    });
    const decoded = cli('decode', REPLAY,
      '--events', 'anonymous_029c_roster_key_pair',
      '--runtime-image', IMAGE, '--event-jsonl-only', '--out-dir', root);
    assert.equal(decoded.status, 0, decoded.stderr);
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json')));
    const relative = manifest.replay_inputs[0].artifact_directory;
    const dir = path.join(root, ...relative.split('/'));
    const semantic = JSON.parse(fs.readFileSync(path.join(dir, 'semantic_run.json')));
    const result = semantic.capability_results.anonymous_029c_roster_key_pair;
    assert.equal(result.status, 'CANDIDATE', result.error);
    assert.equal(result.input_count,
      result.zero_header_count + result.nonroster_nonzero_header_count
        + result.matched_full_u32_header_count);
    assert.ok(result.matched_full_u32_header_count > 0);
    assert.ok(result.plus_0x100_alias_excluded_count > 0);
    const pairPath = path.join(dir, `${EVENT}.jsonl`);
    const pairOriginal = fs.readFileSync(pairPath, 'utf8');
    const pairLines = pairOriginal.trimEnd().split('\n');
    const firstPair = JSON.parse(pairLines[0]);
    assert.equal(firstPair.raw_param, firstPair.hero_raw_param);
    assert.notEqual(firstPair.anonymous_u32_candidate, firstPair.hero_raw_param);
    const verifiedOutput = path.join(root, 'verified.jsonl');
    const verified = cli('query-events', root, '--event', EVENT,
      '--opaque-u32', String(firstPair.raw_param), '--limit', '1',
      '--verify-source', '--output', verifiedOutput);
    assert.equal(verified.status, 0, verified.stderr);
    const verifiedSummary = JSON.parse(verified.stdout);
    assert.equal(verifiedSummary.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
    assert.equal(verifiedSummary.scanned_count, result.event_count);
    assert.equal(verifiedSummary.emitted_count, 1);
    assert.equal(fs.readFileSync(verifiedOutput, 'utf8'), `${pairLines[0]}\n`);
    const participant = cli('query-events', root, '--event', EVENT,
      '--participant', String(firstPair.participant_id_candidate), '--limit', '1');
    assert.notEqual(participant.status, 0);
    assert.equal(JSON.parse(participant.stderr).code, 'UNSUPPORTED_FILTER');

    const forgedPair = pairLines.map((line) => JSON.parse(line));
    forgedPair.at(-1).champion_metadata = 'ForgedChampion';
    const forgedPairText = `${forgedPair.map(JSON.stringify).join('\n')}\n`;
    fs.writeFileSync(pairPath, forgedPairText);
    updateManifest(root, relative, EVENT, forgedPairText);
    const latePairOutput = path.join(root, 'late-pair.jsonl');
    const latePair = cli('query-events', root, '--event', EVENT,
      '--limit', '1', '--output', latePairOutput);
    assert.notEqual(latePair.status, 0);
    assert.equal(JSON.parse(latePair.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(latePairOutput), false);

    fs.writeFileSync(pairPath, pairOriginal);
    updateManifest(root, relative, EVENT, pairOriginal);
    const sourcePath = path.join(dir, `${SOURCE_EVENT}.jsonl`);
    const sourceLines = fs.readFileSync(sourcePath, 'utf8').trimEnd().split('\n');
    const forgedSource = JSON.parse(sourceLines.at(-1));
    forgedSource.anonymous_u32_candidate ^= 1;
    sourceLines[sourceLines.length - 1] = JSON.stringify(forgedSource);
    const forgedSourceText = `${sourceLines.join('\n')}\n`;
    fs.writeFileSync(sourcePath, forgedSourceText);
    updateManifest(root, relative, SOURCE_EVENT, forgedSourceText);
    const lateSourceOutput = path.join(root, 'late-source.jsonl');
    const lateSource = cli('query-events', root, '--event', EVENT,
      '--limit', '1', '--output', lateSourceOutput);
    assert.notEqual(lateSource.status, 0);
    assert.equal(JSON.parse(lateSource.stderr).code, 'INVALID_EVENT_ROW');
    assert.equal(fs.existsSync(lateSourceOutput), false);
  });
