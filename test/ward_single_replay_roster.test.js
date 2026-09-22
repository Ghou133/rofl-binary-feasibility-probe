'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { participantMetadataForReplay } = require('../src/semantic_api');

const REPOSITORY_ROOT = path.resolve(__dirname, '..');
const PYTHON = process.env.PYTHON || 'python';
const WARD_DECODER = path.join(REPOSITORY_ROOT, 'scripts', 'decode_ward_spawn_16_16.py');
const PYTHON_LOAD_PARTICIPANTS = [
  'import importlib.util, json, pathlib, sys',
  'spec = importlib.util.spec_from_file_location("ward_decoder", sys.argv[1])',
  'module = importlib.util.module_from_spec(spec)',
  'spec.loader.exec_module(module)',
  'metadata_path = pathlib.Path(sys.argv[2])',
  'manifest = json.loads(sys.argv[3])',
  'scope = sys.argv[4]',
  'owner_map, replays = module.load_participants(metadata_path, manifest, scope)',
  'print(json.dumps({"owner_keys": sorted(owner_map), "labels": sorted(replays)}))',
].join('\n');

function singleParticipantReplay() {
  return {
    source_path: path.join('fixtures', 'HN1-11212942693.rofl'),
    source_sha256: '1'.repeat(64),
    header: { version: '16.16.805.0442' },
    tail: { stats: [{ TEAM: 100, SKIN: 'Kayn', WARD_PLACED: 0 }] },
  };
}

function loadParticipants(metadataPath, scope) {
  return childProcess.spawnSync(PYTHON, [
    '-B', '-c', PYTHON_LOAD_PARTICIPANTS, WARD_DECODER, metadataPath,
    JSON.stringify({
      replay_count: 1,
      replay_shas: { 'HN1-11212942693': '1'.repeat(64) },
    }),
    scope,
  ], {
    cwd: REPOSITORY_ROOT,
    encoding: 'utf8',
  });
}

test('single-Replay Ward roster accepts a validated partial tail without fabricating mappings', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ward-single-roster-'));
  const metadataPath = path.join(directory, 'participants.json');
  const metadata = participantMetadataForReplay(
    singleParticipantReplay(), metadataPath, 'SINGLE_REPLAY_DECODE',
  );

  assert.equal(metadata.validation_scope, 'SINGLE_REPLAY_DECODE');
  assert.deepEqual(metadata.replays[0].roster, {
    expected_participant_count: 10,
    available_participant_count: 1,
    completeness: 'PARTIAL',
    present_participant_ids: [1],
    missing_participant_ids: [2, 3, 4, 5, 6, 7, 8, 9, 10],
    missing_owner_mappings_fabricated: false,
  });

  const result = loadParticipants(metadataPath, 'SINGLE_REPLAY_DECODE');
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    owner_keys: [['HN1-11212942693', 0x400000ae]],
    labels: ['HN1-11212942693'],
  });
});

test('corpus release retains a strict ten-row roster requirement', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ward-corpus-roster-'));
  const metadataPath = path.join(directory, 'participants.json');
  const metadata = participantMetadataForReplay(
    singleParticipantReplay(), metadataPath, 'SINGLE_REPLAY_DECODE',
  );
  delete metadata.validation_scope;
  fs.writeFileSync(metadataPath, `${JSON.stringify(metadata)}\n`);

  const result = loadParticipants(metadataPath, 'CORPUS_RELEASE_GATE');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /must contain ten rows/);
});

test('single-Replay roster rejects duplicate participant identities instead of overwriting maps', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ward-duplicate-roster-'));
  const metadataPath = path.join(directory, 'participants.json');
  const metadata = participantMetadataForReplay(
    singleParticipantReplay(), metadataPath, 'SINGLE_REPLAY_DECODE',
  );
  metadata.replays[0].participants.push({
    ...metadata.replays[0].participants[0],
    team_id: 200,
  });
  fs.writeFileSync(metadataPath, `${JSON.stringify(metadata)}\n`);

  const result = loadParticipants(metadataPath, 'SINGLE_REPLAY_DECODE');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /duplicate participant ID/);
});
