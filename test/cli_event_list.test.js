'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const CLI = path.resolve(__dirname, '../src/cli.js');
const VERSION = '16.19.821.7343';
const EVENT = 'hero_level_state_candidates';
const CAPABILITY = 'hero_level_state';
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);

function sha256(filename) {
  return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
}

function writeJson(filename, value) {
  fs.writeFileSync(filename, JSON.stringify(value));
}

function rewriteJson(filename, edit) {
  const value = JSON.parse(fs.readFileSync(filename, 'utf8'));
  edit(value);
  writeJson(filename, value);
}

function replayArtifact(root, name, sha, status, count = null) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  writeJson(path.join(directory, 'semantic_run.json'), {
    replay_version: VERSION, replay_sha256: sha, container_status: 'PASS',
    status, requested_capabilities: [CAPABILITY],
    capability_results: { [CAPABILITY]: { status, event_count: count } },
  });
  const saved = status === 'CANDIDATE';
  writeJson(path.join(directory, 'replay_analysis.json'), {
    patch: '16.19', replay_version: VERSION, replay_sha256: sha,
    event_storage: 'JSONL_ONLY', events: null,
    event_counts: saved ? { [EVENT]: count } : {},
    event_jsonl_files: saved ? { [EVENT]: `${EVENT}.jsonl` } : {},
  });
  if (saved) fs.writeFileSync(path.join(directory, `${EVENT}.jsonl`), '');
  return directory;
}

function batchArtifact(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-event-list-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const first = replayArtifact(root, 'first', SHA_A, 'CANDIDATE', 0);
  const second = replayArtifact(root, 'second', SHA_B, 'PROFILE_UNAVAILABLE');
  const hashes = {};
  for (const [name, directory] of [['first', first], ['second', second]]) {
    for (const basename of ['semantic_run.json', 'replay_analysis.json',
      ...(name === 'first' ? [`${EVENT}.jsonl`] : [])]) {
      hashes[`replays/${name}/${basename}`] = sha256(path.join(directory, basename));
    }
  }
  const manifestPath = path.join(root, 'manifest.json');
  writeJson(manifestPath, {
    command_args: ['batch', 'synthetic-input'],
    replay_inputs: [
      { artifact_directory: 'replays/first', sha256: SHA_A, version: VERSION },
      { artifact_directory: 'replays/second', sha256: SHA_B, version: VERSION },
    ],
    output_hashes_excluding_manifest: hashes,
  });
  return { root, first, second, manifestPath };
}

function run(directory, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', directory, '--list-events', ...args],
    { encoding: 'utf8' });
}

test('list-events reports saved zero rows from one exact-build Replay without scanning rows', (t) => {
  const fixture = batchArtifact(t);
  const result = run(fixture.first);
  assert.equal(result.status, 0, result.stderr);
  const catalog = JSON.parse(result.stdout);
  assert.equal(catalog.mode, 'LIST_EVENTS');
  assert.equal(catalog.validation_scope, 'METADATA_AND_FILE_PRESENCE');
  assert.equal(catalog.event_rows_scanned, false);
  assert.deepEqual(catalog.event_keys, [EVENT]);
  assert.equal(catalog.replay_results[0].replay_version, VERSION);
  assert.deepEqual(catalog.replay_results[0].events, [{
    event_key: EVENT, status: 'SAVED', declared_event_count: 0,
    capability_status: 'CANDIDATE',
  }]);
});

test('list-events reports an entirely unavailable Replay without inventing zero rows', (t) => {
  const fixture = batchArtifact(t);
  const result = run(fixture.second);
  assert.equal(result.status, 0, result.stderr);
  const catalog = JSON.parse(result.stdout);
  assert.deepEqual(catalog.event_keys, []);
  assert.deepEqual(catalog.replay_results[0].events, []);
  assert.deepEqual(catalog.replay_results[0].unavailable_capabilities, [
    { capability: CAPABILITY, capability_status: 'PROFILE_UNAVAILABLE' },
  ]);
});

test('list-events distinguishes saved zero from an unavailable Replay in a batch', (t) => {
  const fixture = batchArtifact(t);
  const result = run(fixture.root);
  assert.equal(result.status, 0, result.stderr);
  const catalog = JSON.parse(result.stdout);
  assert.equal(catalog.validation_scope, 'METADATA_AND_SELECTED_MANIFEST_HASHES');
  assert.equal(catalog.replay_count, 2);
  assert.deepEqual(catalog.event_keys, [EVENT]);
  assert.equal(catalog.replay_results[0].events[0].declared_event_count, 0);
  assert.equal(catalog.replay_results[1].events[0].status, 'UNAVAILABLE');
  assert.equal(catalog.replay_results[1].events[0].declared_event_count, null);
  assert.equal(catalog.replay_results[1].events[0].code, 'CAPABILITY_UNAVAILABLE');
  assert.deepEqual(catalog.replay_results[1].unavailable_capabilities, [
    { capability: CAPABILITY, capability_status: 'PROFILE_UNAVAILABLE' },
  ]);
});

test('list-events distinguishes an unrequested batch event from saved zero', (t) => {
  const fixture = batchArtifact(t);
  rewriteJson(path.join(fixture.second, 'semantic_run.json'), (semantic) => {
    semantic.requested_capabilities = [];
    semantic.capability_results = {};
  });
  rewriteJson(fixture.manifestPath, (manifest) => {
    manifest.output_hashes_excluding_manifest['replays/second/semantic_run.json']
      = sha256(path.join(fixture.second, 'semantic_run.json'));
  });
  const result = run(fixture.root);
  assert.equal(result.status, 0, result.stderr);
  const catalog = JSON.parse(result.stdout);
  assert.equal(catalog.replay_results[0].events[0].declared_event_count, 0);
  assert.equal(catalog.replay_results[1].events[0].status, 'NOT_REQUESTED');
  assert.equal(catalog.replay_results[1].events[0].declared_event_count, null);
  assert.deepEqual(catalog.replay_results[1].unavailable_capabilities, []);
});

test('list-events rejects altered manifest hashes and Replay identity', (t) => {
  const fixture = batchArtifact(t);
  rewriteJson(fixture.manifestPath, (manifest) => {
    manifest.output_hashes_excluding_manifest[`replays/first/${EVENT}.jsonl`] = '0'.repeat(64);
  });
  const badHash = run(fixture.root);
  assert.equal(badHash.status, 2);
  assert.equal(JSON.parse(badHash.stderr).code, 'ARTIFACT_HASH_MISMATCH');
  assert.equal(badHash.stdout, '');

  rewriteJson(fixture.manifestPath, (manifest) => {
    manifest.output_hashes_excluding_manifest[`replays/first/${EVENT}.jsonl`]
      = sha256(path.join(fixture.first, `${EVENT}.jsonl`));
  });
  rewriteJson(path.join(fixture.second, 'replay_analysis.json'), (analysis) => {
    analysis.replay_sha256 = SHA_A;
  });
  rewriteJson(fixture.manifestPath, (manifest) => {
    manifest.output_hashes_excluding_manifest['replays/second/replay_analysis.json']
      = sha256(path.join(fixture.second, 'replay_analysis.json'));
  });
  const badIdentity = run(fixture.root);
  assert.equal(badIdentity.status, 2);
  assert.equal(JSON.parse(badIdentity.stderr).code, 'ARTIFACT_IDENTITY_MISMATCH');
  assert.equal(badIdentity.stdout, '');
});

test('list-events rejects query filters instead of ignoring them', (t) => {
  const fixture = batchArtifact(t);
  const result = run(fixture.first, '--limit', '1');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /--list-events cannot be combined/);
});
