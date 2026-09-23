'use strict';

// CLI seam tests: real CLI/container/analysis/report code, deliberately substituted
// semantic and Ward/Path dependencies. These are not exact-build decoder tests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const test = require('node:test');
const { packet, replayFromChunks } = require('./helpers/synthetic_replay');

function loadCli(decode) {
  const filename = path.resolve(__dirname, '../src/cli.js');
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.paths = Module._nodeModulePaths(path.dirname(filename));
  const nativeRequire = Module.createRequire(filename);
  const substitutes = {
    './semantic_pipeline': {
      DEFAULT_DECODER_IMAGE: 'synthetic-external-image.bin',
      decodeSemanticReplay: decode || (() => { throw new Error('semantic decoder must not run'); }),
    },
    './ward_pipeline_v2': { buildWardOutputs() { throw new Error('Ward is outside this unit test'); } },
    './path_pipeline_v2': {},
    './provenance_v2': {},
    './ward_analysis_v2': {},
    './integrity': {},
    './io': {},
  };
  loaded.require = (name) => Object.hasOwn(substitutes, name) ? substitutes[name] : nativeRequire(name);
  loaded._compile(fs.readFileSync(filename, 'utf8'), filename);
  return loaded.exports;
}

function fixture(t, version = '16.15.801.3452') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-cli-unit-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'synthetic.rofl');
  fs.writeFileSync(input, replayFromChunks([{
    body: Buffer.concat([packet(1), packet(2), packet(3)]), compressed: true,
  }], version).buffer);
  return input;
}

test('the legacy sampling option remains parseable without changing prefix output', (t) => {
  const cli = loadCli();
  const input = fixture(t);
  const parsed = cli.parseArgs(['inspect', input, '--timeline-limit', '2', '--sample-stride', '1']);
  const result = cli.parseOne(input, { ...parsed.options, semantic: false });
  assert.equal(result.ok, true);
  assert.equal(result.analysis.packet_count, 3);
  assert.deepEqual(result.analysis.packet_timeline_sample.map((row) => row.packet_id), [1, 2]);
  assert.equal(result.analysis.semantic, undefined);
});

test('a decoder-unavailable result gets a scoped CLI note, not a fallback or success', (t) => {
  let calls = 0;
  const cli = loadCli((replay) => {
    calls += 1;
    assert.equal(replay.header.version, '16.16.805.0442');
    return { status: 'UNSUPPORTED_REPLAY_VERSION', profile: null, events: null,
      adc_deaths: [], capabilities: null, decoded_packet_count: 0, note: 'synthetic unsupported result' };
  });
  const input = fixture(t, '16.16.805.0442');
  const parsed = cli.parseArgs(['analyze', input]);
  const result = cli.parseOne(input, parsed.options);
  assert.equal(result.ok, true);
  assert.equal(calls, 1);
  assert.equal(result.analysis.decoder.status, 'UNSUPPORTED_REPLAY_VERSION');
  assert.match(result.analysis.decoder.note, /16\.15\.801\.3452/);
  assert.match(result.analysis.decoder.note, /16\.16/);
  assert.equal(result.analysis.decoded_packet_count, 0);
});

test('help explains the Node minimum, CLI version scope and external runtime image', async (t) => {
  let output = '';
  t.mock.method(process.stdout, 'write', (chunk) => { output += String(chunk); return true; });
  const cli = loadCli();
  assert.equal(await cli.main(['--help']), 0);
  assert.match(output, /22\.15\.0/);
  assert.match(output, /16\.15\.801\.3452/);
  assert.match(output, /16\.16/);
  assert.match(output, /not bundled/);
  assert.match(output, /deprecated/i);
});
