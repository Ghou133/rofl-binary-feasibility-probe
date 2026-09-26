'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { prepareEventQuery, streamEventQuery } = require('../src/event_query');

const CLI = path.resolve(__dirname, '../src/cli.js');
const EVENT = 'params_heal_roster_key_pair_candidates';
const HEAL = 'params_heal_packet_candidates';
const ROSTER = 'hero_roster_metadata_bridge_candidates';
const IMAGE = process.env.ROFL_821_RUNTIME_IMAGE ?? null;
const REPLAY_DIR = process.env.ROFL_821_REPLAY_DIR ?? null;
const FIRST = REPLAY_DIR && path.join(REPLAY_DIR, 'KR_8392938200.rofl');
const SECOND = REPLAY_DIR && path.join(REPLAY_DIR, 'KR_8393872512.rofl');

function cli(...args) {
  return spawnSync(process.execPath, [CLI, ...args],
    { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
}

function query(root, ...args) {
  return cli('query-events', root, '--event', EVENT, ...args);
}

function summary(result) {
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  return JSON.parse(result.stderr);
}

function rewriteJsonl(root, replay, event, change) {
  const relative = `replays/${replay}/${event}.jsonl`;
  const filename = path.join(root, 'replays', replay, `${event}.jsonl`);
  const rows = fs.readFileSync(filename, 'utf8').trimEnd().split('\n')
    .map((line) => JSON.parse(line));
  change(rows[rows.length - 1]);
  fs.writeFileSync(filename, `${rows.map(JSON.stringify).join('\n')}\n`);
  const manifestPath = path.join(root, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  manifest.output_hashes_excluding_manifest[relative] = crypto
    .createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));
}

function rewriteMetadata(root, replay, change) {
  const manifestPath = path.join(root, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  for (const filename of ['semantic_run.json', 'replay_analysis.json']) {
    const relative = `replays/${replay}/${filename}`;
    const full = path.join(root, 'replays', replay, filename);
    const doc = JSON.parse(fs.readFileSync(full, 'utf8'));
    const result = filename === 'semantic_run.json'
      ? doc.capability_results.params_heal_roster_key_pair
      : doc.semantic.capability_results.params_heal_roster_key_pair;
    change(result);
    fs.writeFileSync(full, JSON.stringify(doc));
    manifest.output_hashes_excluding_manifest[relative] = crypto
      .createHash('sha256').update(fs.readFileSync(full)).digest('hex');
  }
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));
}

test('saved ParamsHeal pair query verifies two real exact-build streams and late forgeries', {
  skip: !IMAGE || !fs.existsSync(IMAGE) || !FIRST || !SECOND
    || !fs.existsSync(FIRST) || !fs.existsSync(SECOND),
}, async (t) => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-heal-pair-query-'));
  t.after(() => {
    const resolved = path.resolve(temp);
    if (!resolved.startsWith(path.resolve(os.tmpdir()) + path.sep)
        || !path.basename(resolved).startsWith('rofl-heal-pair-query-')) {
      throw new Error('Unsafe ParamsHeal query fixture cleanup target');
    }
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  const baseline = path.join(temp, 'baseline');
  const decoded = cli('batch', FIRST, SECOND, '--events',
    'params_heal_roster_key_pair', '--runtime-image', IMAGE,
    '--event-jsonl-only', '--strict', '--timeline-limit', '1',
    '--out-dir', baseline);
  assert.equal(decoded.status, 0, decoded.stderr || decoded.error?.message);
  const single = path.join(baseline, 'replays', 'KR_8392938200');
  const second = 'KR_8393872512';
  const saved = summary(query(single, '--limit', '1'));
  assert.equal(saved.declared_event_count, 6059);
  assert.equal(saved.scanned_count, 6059);
  assert.equal(saved.emitted_count, 1);
  assert.equal(saved.source_provenance_status, 'SAVED_ONLY_UNVERIFIED');
  const verified = summary(query(single, '--verify-source',
    '--runtime-image', IMAGE, '--limit', '1'));
  assert.equal(verified.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
  assert.equal(verified.scanned_count, 6059);
  const batch = summary(query(baseline, '--verify-source',
    '--runtime-image', IMAGE, '--limit', '1'));
  assert.equal(batch.replay_count, 2);
  assert.equal(batch.scanned_count, 12356);
  assert.equal(batch.emitted_count, 1);
  assert.equal(batch.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
  assert.deepEqual(batch.replay_results.map((row) => row.scanned_count),
    [6059, 6297]);

  const pairRows = fs.readFileSync(path.join(single, `${EVENT}.jsonl`),
    'utf8').trimEnd().split('\n').map((line) => JSON.parse(line));
  const selected = summary(query(single, '--opaque-u32', '0x400000af',
    '--limit', '1'));
  assert.ok(selected.matched_count > 0);
  const filtered = query(single, '--opaque-u32', '0x400000af', '--limit', '1');
  const firstRow = JSON.parse(filtered.stdout.trim());
  assert.ok(firstRow.event_entity_u32_0x04 === 0x400000af
    || firstRow.event_entity_u32_0x14 === 0x400000af);
  assert.equal(firstRow.field_role_status, 'UNKNOWN');
  assert.equal(firstRow.effective_heal_status, 'UNKNOWN');
  const participant = query(single, '--participant', '1');
  assert.equal(participant.status, 2);
  assert.equal(JSON.parse(participant.stderr).code, 'UNSUPPORTED_FILTER');
  assert.equal(participant.stdout, '');
  const missingImage = query(single, '--verify-source', '--limit', '1');
  assert.equal(missingImage.status, 2);
  assert.equal(JSON.parse(missingImage.stderr).code, 'MISSING_RUNTIME_IMAGE');
  assert.equal(missingImage.stdout, '');

  const copiedReplay = path.join(temp, 'same-bytes.rofl');
  fs.copyFileSync(FIRST, copiedReplay);
  const override = summary(query(single, '--verify-source',
    '--runtime-image', IMAGE, '--source-replay', copiedReplay, '--limit', '1'));
  assert.equal(override.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
  const apiRows = [];
  const apiSummary = await streamEventQuery(prepareEventQuery(single, EVENT),
    { opaqueU32: 0x400000af, limit: 1, verifySource: true,
      runtimeImage: IMAGE, sourceReplay: copiedReplay },
    async (line) => apiRows.push(JSON.parse(line)));
  assert.equal(apiSummary.scanned_count, 6059);
  assert.deepEqual(apiRows, [firstRow]);
  assert.ok(pairRows.some((row) => row.roster_match_0x04.status
    === 'NOT_IN_TEN_KEY_ROSTER'));
  assert.ok(pairRows.some((row) => row.roster_match_0x14.status
    === 'NOT_IN_TEN_KEY_ROSTER'));

  for (const [event, change] of [
    [EVENT, (row) => { row.effective_heal_status = 'EFFECTIVE'; }],
    [HEAL, (row) => { row.reported_amount_candidate += 1; }],
    [ROSTER, (row) => { row.champion_metadata = 'ForgedChampion'; }],
  ]) {
    const forged = path.join(temp, `forged-${event}`);
    fs.cpSync(baseline, forged, { recursive: true });
    rewriteJsonl(forged, second, event, change);
    const result = query(forged, '--limit', '1');
    assert.equal(result.status, 2, `${event}: ${result.stderr}`);
    assert.equal(result.stdout, '', event);
    assert.ok(['INVALID_EVENT_ROW', 'EVENT_COUNT_MISMATCH']
      .includes(JSON.parse(result.stderr).code), result.stderr);
  }
  const forgedCounts = path.join(temp, 'forged-negative-counts');
  fs.cpSync(baseline, forgedCounts, { recursive: true });
  rewriteMetadata(forgedCounts, second, (result) => {
    result.both_matched_count += 1;
    result.both_nonroster_count -= 1;
    result.matched_0x04_count += 1;
    result.unmatched_0x04_count -= 1;
    result.matched_0x14_count += 1;
    result.unmatched_0x14_count -= 1;
  });
  const wrongCounts = query(forgedCounts, '--limit', '1');
  assert.equal(wrongCounts.status, 2, wrongCounts.stderr);
  assert.equal(JSON.parse(wrongCounts.stderr).code, 'EVENT_COUNT_MISMATCH');
  assert.equal(wrongCounts.stdout, '');

  const staleHash = path.join(temp, 'forged-stale-hash');
  fs.cpSync(baseline, staleHash, { recursive: true });
  const stalePath = path.join(staleHash, 'replays', second, `${HEAL}.jsonl`);
  fs.appendFileSync(stalePath, '\n');
  const hashResult = query(staleHash, '--limit', '1');
  assert.equal(hashResult.status, 2, hashResult.stderr);
  assert.equal(JSON.parse(hashResult.stderr).code, 'ARTIFACT_HASH_MISMATCH');
  assert.equal(hashResult.stdout, '');
});
