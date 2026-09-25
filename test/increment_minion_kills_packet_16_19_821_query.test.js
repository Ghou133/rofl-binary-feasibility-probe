'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { replayFromChunks } = require('./helpers/synthetic_replay');
const {
  INCREMENT_MINION_KILLS_PACKET_CANDIDATE_PROFILE_821: PROFILE,
  decodeIncrementMinionKillsPacketCandidates821: decode,
} = require('../src/decoders/rofl_16_19_821_increment_minion_kills_packet_candidate');

const CLI = path.resolve(__dirname, '../src/cli.js');
const BUILD = '16.19.821.7343';
const CAPABILITY = 'increment_minion_kills_packet';
const EVENT = 'increment_minion_kills_packet_candidates';
const LOOKUP_BYTES = new Map([
  [0x400000ae, '8bd7d7e7'],
  [0x400000af, 'cbd7d7e7'],
]);

function packet(id, payloadHex, rawParam, timeMs) {
  const payload = Buffer.from(payloadHex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(id, 9);
  header.writeUInt32LE(rawParam >>> 0, 11);
  return Buffer.concat([header, payload]);
}

function replay(extraControl = false) {
  const packets = [
    packet(0x03a7, '380718', 0x400000ae, 1000),
    packet(0x02d9, '070718', 0x400000ae, 1500),
    packet(0x03a7, '390718', 0x400000af, 2000),
    packet(0x03a7, '3a2618', 0x400000ae, 3000),
  ];
  if (extraControl) packets.push(packet(0x02d9, '070718', 0x400000af, 4000));
  return replayFromChunks([{ stream: 1, body: Buffer.concat(packets) }], BUILD);
}

function nativeResult(request) {
  return {
    status: 'PASS',
    runtime_image_sha256: PROFILE.evidence_runtime_image_sha256,
    callback_transform_sha256: PROFILE.evidence_callback_transform_sha256,
    results: request.packets.map((row, index) => ({
      status: 'DECODED', input_index: index,
      raw_param: row.raw_param,
      raw_payload_sha256: crypto.createHash('sha256')
        .update(Buffer.from(row.payload_hex, 'hex')).digest('hex'),
      deserialize_return_al: 1, bytes_consumed: row.payload_hex.length / 2,
      native_packet_id: 0x03a7, native_raw_param: row.raw_param,
      native_object_lookup_key_bytes_hex: LOOKUP_BYTES.get(row.raw_param),
      callback_lookup_key_candidate: row.raw_param,
    })),
  };
}

function decodedSource(t, directory, { imageMissing = false, extraControl = false } = {}) {
  const input = replay(extraControl);
  let outcome;
  if (imageMissing) {
    outcome = decode(input);
    assert.equal(outcome.status, 'MISSING_INPUT');
  } else {
    const image = path.join(directory, `synthetic-image-${extraControl}.bin`);
    fs.writeFileSync(image, Buffer.from([1, 2, 3]));
    const invoke = t.mock.method(childProcess, 'spawnSync', (_python, _args, options) => ({
      status: 0, stderr: '', stdout: JSON.stringify(nativeResult(JSON.parse(options.input))),
    }));
    try {
      outcome = decode(input, { runtimeImagePath: image });
    } finally {
      invoke.mock.restore();
    }
    assert.equal(outcome.status, 'CANDIDATE', outcome.error);
    assert.equal(outcome.event_count, 3);
  }
  return { replay: input, outcome };
}

function withoutEvents(outcome) {
  const copy = structuredClone(outcome);
  delete copy.events;
  return copy;
}

function writeReplayArtifact(root, name, source) {
  const directory = path.join(root, 'replays', name);
  fs.mkdirSync(directory, { recursive: true });
  const result = withoutEvents(source.outcome);
  const semantic = {
    replay_version: BUILD, replay_sha256: source.replay.source_sha256,
    container_status: 'PASS', status: source.outcome.status,
    api_status: source.outcome.status === 'CANDIDATE'
      ? 'EXPERIMENTAL_CANDIDATE' : 'PARTIAL',
    requested_capabilities: [CAPABILITY],
    capability_results: { [CAPABILITY]: result },
  };
  const rows = source.outcome.events ?? [];
  const eventCounts = rows.length ? { [EVENT]: rows.length } : {};
  const analysis = {
    source_path: source.replay.source_path,
    patch: '16.19', replay_version: BUILD, replay_sha256: source.replay.source_sha256,
    event_counts: eventCounts, event_storage: 'JSONL_ONLY',
    event_jsonl_files: rows.length ? { [EVENT]: `${EVENT}.jsonl` } : {},
    events: null, semantic: {
      status: semantic.status, requested_capabilities: [CAPABILITY],
      capability_results: { [CAPABILITY]: result },
    },
  };
  fs.writeFileSync(path.join(directory, 'semantic_run.json'), JSON.stringify(semantic));
  fs.writeFileSync(path.join(directory, 'replay_analysis.json'), JSON.stringify(analysis));
  if (rows.length) fs.writeFileSync(path.join(directory, `${EVENT}.jsonl`),
    `${rows.map(JSON.stringify).join('\n')}\n`);
  return {
    name, directory, sha: source.replay.source_sha256,
    lines: rows.map(JSON.stringify),
    semanticPath: path.join(directory, 'semantic_run.json'),
    analysisPath: path.join(directory, 'replay_analysis.json'),
    eventPath: path.join(directory, `${EVENT}.jsonl`),
  };
}

function fixture(t, { batch = false, partial = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-821-minion-query-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const first = writeReplayArtifact(root, 'first', decodedSource(t, root));
  let second = null;
  if (batch) {
    second = writeReplayArtifact(root, 'second', decodedSource(t, root,
      { imageMissing: partial, extraControl: true }));
    const replayInputs = [first, second].map((entry) => ({
      sha256: entry.sha, version: BUILD,
      artifact_directory: `replays/${entry.name}`,
    }));
    const hashes = {};
    for (const entry of replayInputs) {
      for (const name of fs.readdirSync(path.join(root, entry.artifact_directory))) {
        const relative = `${entry.artifact_directory}/${name}`;
        hashes[relative] = crypto.createHash('sha256')
          .update(fs.readFileSync(path.join(root, relative))).digest('hex');
      }
    }
    fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
      command_args: ['batch', 'synthetic-input'], replay_inputs: replayInputs,
      output_hashes_excluding_manifest: hashes,
    }));
  }
  return { root, first, second };
}

function query(target, ...args) {
  return spawnSync(process.execPath,
    [CLI, 'query-events', target, '--event', EVENT, ...args],
    { encoding: 'utf8', cwd: path.dirname(CLI) });
}

function rewriteJson(filename, edit) {
  const document = JSON.parse(fs.readFileSync(filename, 'utf8'));
  edit(document);
  fs.writeFileSync(filename, JSON.stringify(document));
}

test('query-events filters exact 821 IncrementMinionKills time and raw param, preserving JSONL',
  (t) => {
    const { first } = fixture(t);
    const selected = query(first.directory, '--from-ms', '2000', '--to-ms', '3000',
      '--raw-param', '0x400000ae');
    assert.equal(selected.status, 0, selected.stderr);
    assert.equal(selected.stdout, `${first.lines[2]}\n`);
    const summary = JSON.parse(selected.stderr);
    assert.equal(summary.query_status, 'COMPLETE');
    assert.equal(summary.scanned_count, 3);
    assert.equal(summary.matched_count, 1);
    assert.equal(summary.emitted_count, 1);
    assert.equal(summary.rows_unmodified, true);
    assert.equal(fs.readFileSync(first.eventPath, 'utf8'),
      `${first.lines.join('\n')}\n`);
    const row = JSON.parse(first.lines[2]);
    assert.equal(row.callback_lookup_key_candidate, 0x400000ae);
    assert.equal(row.semantic_cs_effect_status, 'UNKNOWN');
    assert.equal('participant_id_candidate' in row, false);
    const unresolved = query(first.directory, '--participant', '1');
    assert.equal(unresolved.status, 2);
    assert.equal(JSON.parse(unresolved.stderr).code, 'PARTICIPANT_UNAVAILABLE');
    const latest = query(first.directory, '--latest-per-participant');
    assert.equal(latest.status, 2);
    assert.equal(JSON.parse(latest.stderr).code, 'UNSUPPORTED_FILTER');
  });

test('query-events rejects mismatched IncrementMinionKills profile, image and transform',
  (t) => {
    const { root, first } = fixture(t);
    const originalSemantic = fs.readFileSync(first.semanticPath, 'utf8');
    const originalAnalysis = fs.readFileSync(first.analysisPath, 'utf8');
    const restore = () => {
      fs.writeFileSync(first.semanticPath, originalSemantic);
      fs.writeFileSync(first.analysisPath, originalAnalysis);
    };
    const reject = () => {
      const output = path.join(root, 'must-not-exist.jsonl');
      const result = query(first.directory, '--output', output);
      assert.equal(result.status, 2, result.stderr);
      assert.equal(JSON.parse(result.stderr).code, 'CAPABILITY_METADATA_MISMATCH');
      assert.equal(fs.existsSync(output), false);
      restore();
    };
    for (const [field, value] of [
      ['profile_id', 'wrong-profile'],
      ['runtime_image_sha256', 'f'.repeat(64)],
      ['evidence_callback_transform_sha256', 'f'.repeat(64)],
    ]) {
      for (const file of [first.semanticPath, first.analysisPath]) {
        rewriteJson(file, (document) => {
          const outcome = file === first.semanticPath
            ? document.capability_results[CAPABILITY]
            : document.semantic.capability_results[CAPABILITY];
          outcome[field] = value;
        });
      }
      reject();
    }
    rewriteJson(first.analysisPath, (document) => {
      document.semantic.capability_results[CAPABILITY].input_count += 1;
    });
    reject();
  });

test('query-events rejects altered IncrementMinionKills refs, payload and callback key',
  (t) => {
    const { root, first } = fixture(t);
    const originalRows = fs.readFileSync(first.eventPath, 'utf8');
    const mutateAndReject = (edit) => {
      const rows = originalRows.trim().split(/\r?\n/).map(JSON.parse);
      edit(rows[0]);
      fs.writeFileSync(first.eventPath, `${rows.map(JSON.stringify).join('\n')}\n`);
      const output = path.join(root, 'must-not-exist.jsonl');
      const result = query(first.directory, '--output', output);
      assert.equal(result.status, 2, result.stderr);
      assert.equal(JSON.parse(result.stderr).code, 'INVALID_EVENT_ROW');
      assert.equal(fs.existsSync(output), false);
      fs.writeFileSync(first.eventPath, originalRows);
    };
    mutateAndReject((row) => { row.raw_packet_ref.raw_payload_sha256 = 'f'.repeat(64); });
    mutateAndReject((row) => { row.raw_payload_hex = '3a2719'; });
    mutateAndReject((row) => { row.raw_selector_byte = 0x3a; });
    mutateAndReject((row) => { row.native_object_lookup_key_bytes_hex = 'cbd7d7e7'; });
    mutateAndReject((row) => { row.callback_lookup_key_candidate = 0x400000af; });
    mutateAndReject((row) => { row.semantic_cs_effect_status = 'PROVEN'; });
    mutateAndReject((row) => { row.participant_id_candidate = 1; });
    mutateAndReject((row) => { row.cs_delta = 1; });
  });

test('batch query remains PARTIAL when a Replay lacks the exact runtime image', (t) => {
  const { root, first } = fixture(t, { batch: true, partial: true });
  const result = query(root, '--raw-param', '0x400000ae', '--limit', '1');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, `${first.lines[0]}\n`);
  const summary = JSON.parse(result.stderr);
  assert.equal(summary.query_status, 'PARTIAL');
  assert.equal(summary.replay_count, 2);
  assert.equal(summary.unavailable_replay_count, 1);
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 2);
  assert.equal(summary.emitted_count, 1);
  assert.equal(summary.replay_results[1].code, 'CAPABILITY_UNAVAILABLE');
});
