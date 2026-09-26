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

function loadCli(decode, decodeExact) {
  const filename = path.resolve(__dirname, '../src/cli.js');
  const loaded = new Module(filename, module);
  loaded.filename = filename;
  loaded.paths = Module._nodeModulePaths(path.dirname(filename));
  const nativeRequire = Module.createRequire(filename);
  const substitutes = {
    './semantic_pipeline': {
      DEFAULT_DECODER_IMAGE: 'synthetic-external-image.bin',
      DEFAULT_SPELL_DICTIONARY: 'synthetic-spell-dictionary.json',
      decodeSemanticReplay: decode || (() => { throw new Error('semantic decoder must not run'); }),
    },
    './semantic_api': {
      DEFAULT_16_16_RUNTIME_IMAGE: 'synthetic-16-16-image.bin',
      decodeSemanticReplay: decodeExact || (() => { throw new Error('exact-build decoder must not run'); }),
    },
    './ward_pipeline_v2': { buildWardOutputs() { throw new Error('Ward is outside this unit test'); } },
    './path_pipeline_v2': {},
    './provenance_v2': {},
    './ward_analysis_v2': {},
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
  assert.match(output, /capabilities <file\.rofl>/);
  assert.match(output, /batch <file\.rofl\|directory>/);
});

test('text capability query displays invalid tail fields separately from missing inputs', async (t) => {
  let output = '';
  t.mock.method(process.stdout, 'write', (chunk) => { output += String(chunk); return true; });
  const cli = loadCli();
  const input = fixture(t, '16.19.820.7193');
  assert.equal(await cli.main(['capabilities', input]), 0);
  assert.match(output, /hero_level_state: CANDIDATE; missing inputs: none detected; invalid inputs: replay_tail_LEVEL/);
});

test('capabilities reports only the 16.19 candidate without packet decoding or a runtime image', async (t) => {
  let output = '';
  t.mock.method(process.stdout, 'write', (chunk) => { output += String(chunk); return true; });
  const cli = loadCli();
  const input = fixture(t, '16.19.820.7193');
  // A structurally valid chunk with invalid packet framing must remain unread.
  fs.writeFileSync(input, replayFromChunks([{
    body: Buffer.from([0]),
  }], '16.19.820.7193').buffer);
  const fakeRuntime = path.join(path.dirname(input), 'not-used-runtime.bin');
  assert.equal(await cli.main(['capabilities', input, '--json', '--runtime-image', fakeRuntime]), 0);
  const result = JSON.parse(output);
  assert.equal(result.game_version, '16.19.820.7193');
  assert.equal(result.status, 'PROFILE_RESOLVED');
  assert.equal(result.profile_release_status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(result.packet_framing_inspected, false);
  assert.equal(result.semantic_decode_performed, false);
  assert.equal(result.runtime_image_used, false);
  assert.equal(result.runtime_image_requested, fakeRuntime);
  assert.equal(result.input_assessment_scope, 'CONTAINER_TAIL_FIELD_PREFLIGHT');
  assert.deepEqual(result.capabilities.map((row) => row.capability),
    require('../src/build_registry').BUILD_PROFILES['16.19.820.7193'].candidate_capabilities);
  const heroDeath = result.capabilities.find((row) => row.capability === 'hero_death');
  assert.equal(heroDeath.status, 'CANDIDATE');
  assert.equal(heroDeath.published, false);
  assert.equal(heroDeath.output, 'hero_death_candidates');
  assert.deepEqual(heroDeath.missing_inputs, []);
  assert.equal(heroDeath.runtime_image_requirement, 'NOT_REQUIRED');
  assert.deepEqual(heroDeath.required_inputs.map((row) => row.name),
    ['replay', 'replay_tail_statsJson', 'replay_tail_NUM_DEATHS']);
  assert.ok(heroDeath.validation_pending.includes('matching 16.19 route fingerprint'));
  const timer = result.capabilities.find((row) => row.capability === 'hero_death_timer');
  assert.equal(timer.output, 'hero_death_timer_candidates');
  assert.equal(timer.runtime_image_requirement, 'NOT_REQUIRED');
  assert.equal(timer.conditional_inputs[0].name, 'replay_tail_gameLength');
  assert.equal(fs.existsSync(fakeRuntime), false);
});

test('inventory MapView capability preflight requires an explicit image but no tail stats', (t) => {
  const cli = loadCli();
  // This body is not valid packet framing; capabilities must leave it unread.
  const replay = replayFromChunks([{ body: Buffer.from([0]) }], '16.19.820.7193');
  replay.tail.stats = null;
  delete replay.tail.metadata.statsJson;
  const rowFor = (query) => query.capabilities.find((item) =>
    item.capability === 'hero_inventory_mapview');

  const absent = cli.capabilityQuery(replay);
  const missing = rowFor(absent);
  const missingSetItem = absent.capabilities.find((item) =>
    item.capability === 'hero_inventory_set_item');
  assert.equal(absent.packet_framing_inspected, false);
  assert.equal(absent.semantic_decode_performed, false);
  assert.equal(missing.status, 'CANDIDATE');
  assert.equal(missing.published, false);
  assert.equal(missing.output, 'hero_inventory_mapview_candidates');
  assert.equal(missing.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.deepEqual(missing.required_inputs.map((input) => input.name),
    ['replay', 'exact_runtime_image']);
  assert.deepEqual(missing.missing_inputs, ['exact_runtime_image']);
  assert.equal(missingSetItem.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.equal(missingSetItem.output, 'hero_inventory_set_item_candidates');
  assert.deepEqual(missingSetItem.required_inputs.map((input) => input.name),
    ['replay', 'exact_runtime_image']);
  assert.deepEqual(missingSetItem.missing_inputs, ['exact_runtime_image']);
  assert.ok(missing.validation_pending.includes('exact runtime image SHA-256 and decoder execution'));
  assert.deepEqual(absent.capabilities.find((item) => item.capability === 'hero_death').missing_inputs,
    ['replay_tail_statsJson']);

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-mapview-preflight-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const image = path.join(root, 'unverified-image.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  const present = cli.capabilityQuery(replay, { runtimeImage: image });
  const available = rowFor(present);
  const availableSetItem = present.capabilities.find((item) =>
    item.capability === 'hero_inventory_set_item');
  assert.equal(available.required_inputs[1].status, 'PRESENT_UNVERIFIED');
  assert.equal(availableSetItem.required_inputs[1].status, 'PRESENT_UNVERIFIED');
  assert.deepEqual(available.missing_inputs, []);
  assert.deepEqual(available.invalid_inputs, []);
  assert.equal(present.runtime_image_used, false);
  assert.equal(present.packet_framing_inspected, false);
  assert.equal(present.semantic_decode_performed, false);
});

test('821 UnitApplyDamage preflight reports a missing Python and Unicorn runtime', () => {
  const cli = loadCli();
  // A malformed packet body must remain unread by the dependency preflight.
  const replay = replayFromChunks([{ body: Buffer.from([0]) }], '16.19.821.7343');
  const unavailablePython = path.join(os.tmpdir(), 'rofl-821-python-does-not-exist');
  const result = cli.capabilityQuery(replay, { python: unavailablePython });
  const damage = result.capabilities.find((row) =>
    row.capability === 'unit_apply_damage_packet');
  assert.equal(result.packet_framing_inspected, false);
  assert.equal(result.semantic_decode_performed, false);
  assert.equal(damage.status, 'CANDIDATE');
  assert.equal(damage.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.deepEqual(damage.required_inputs.map((input) => input.name),
    ['replay', 'exact_runtime_image', 'python_unicorn']);
  assert.deepEqual(damage.missing_inputs,
    ['exact_runtime_image', 'python_unicorn']);
  assert.equal(damage.required_inputs[2].command, unavailablePython);
  assert.equal(damage.required_inputs[2].status, 'MISSING');
});

test('821 ShowHealthBar preflight reports runtime dependencies without opening packet framing', () => {
  const cli = loadCli();
  const replay = replayFromChunks([{ body: Buffer.from([0]) }], '16.19.821.7343');
  const unavailablePython = path.join(os.tmpdir(), 'rofl-821-python-does-not-exist');
  const result = cli.capabilityQuery(replay, { python: unavailablePython });
  const bar = result.capabilities.find((row) =>
    row.capability === 'show_health_bar_packet');
  assert.equal(result.packet_framing_inspected, false);
  assert.equal(result.semantic_decode_performed, false);
  assert.equal(bar.status, 'CANDIDATE');
  assert.equal(bar.output, 'show_health_bar_packet_candidates');
  assert.equal(bar.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.deepEqual(bar.required_inputs.map((input) => input.name),
    ['replay', 'exact_runtime_image', 'python_unicorn']);
  assert.deepEqual(bar.missing_inputs, ['exact_runtime_image', 'python_unicorn']);
  assert.equal(bar.required_inputs[2].status, 'MISSING');
});

test('821 damage roster-key pair preflight names both native and roster dependencies', () => {
  const cli = loadCli();
  const replay = replayFromChunks([{ body: Buffer.from([0]) }], '16.19.821.7343');
  const unavailablePython = path.join(os.tmpdir(), 'rofl-821-python-does-not-exist');
  const result = cli.capabilityQuery(replay, { python: unavailablePython });
  const pair = result.capabilities.find((row) =>
    row.capability === 'unit_apply_damage_roster_key_pair');
  assert.equal(result.packet_framing_inspected, false);
  assert.equal(result.semantic_decode_performed, false);
  assert.equal(pair.status, 'CANDIDATE');
  assert.equal(pair.output, 'unit_apply_damage_roster_key_candidates');
  assert.equal(pair.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.ok(pair.required_inputs.some((input) => input.name === 'exact_runtime_image'));
  assert.ok(pair.required_inputs.some((input) => input.name === 'python_unicorn'));
  assert.ok(pair.required_inputs.some((input) => input.name === 'replay_tail_MINIONS_KILLED'));
  assert.ok(pair.missing_inputs.includes('exact_runtime_image'));
  assert.ok(pair.missing_inputs.includes('python_unicorn'));
  assert.ok(pair.validation_pending.some((pending) => pending.includes('ten-hero')));
});

test('821 native damage lookup-roster pair preflight reports its exact inputs', () => {
  const cli = loadCli();
  const replay = replayFromChunks([{ body: Buffer.from([0]) }], '16.19.821.7343');
  const unavailablePython = path.join(os.tmpdir(), 'rofl-821-python-does-not-exist');
  const result = cli.capabilityQuery(replay, { python: unavailablePython });
  const pair = result.capabilities.find((row) =>
    row.capability === 'unit_apply_damage_lookup_roster_key_pair');
  assert.equal(result.packet_framing_inspected, false);
  assert.equal(result.semantic_decode_performed, false);
  assert.equal(pair.status, 'CANDIDATE');
  assert.equal(pair.output, 'unit_apply_damage_lookup_roster_key_candidates');
  assert.equal(pair.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.ok(pair.required_inputs.some((input) => input.name === 'exact_runtime_image'));
  assert.ok(pair.required_inputs.some((input) => input.name === 'python_unicorn'));
  assert.ok(pair.required_inputs.some((input) => input.name === 'replay_tail_MINIONS_KILLED'));
  assert.ok(pair.missing_inputs.includes('exact_runtime_image'));
  assert.ok(pair.missing_inputs.includes('python_unicorn'));
  assert.ok(pair.validation_pending.some((pending) => pending.includes('+0x24')));
});

test('821 second native damage lookup-roster pair preflight reports its exact inputs', () => {
  const cli = loadCli();
  const replay = replayFromChunks([{ body: Buffer.from([0]) }], '16.19.821.7343');
  const unavailablePython = path.join(os.tmpdir(), 'rofl-821-python-does-not-exist');
  const result = cli.capabilityQuery(replay, { python: unavailablePython });
  const pair = result.capabilities.find((row) =>
    row.capability === 'unit_apply_damage_lookup2c_roster_key_pair');
  assert.equal(result.packet_framing_inspected, false);
  assert.equal(result.semantic_decode_performed, false);
  assert.equal(pair.status, 'CANDIDATE');
  assert.equal(pair.output, 'unit_apply_damage_lookup2c_roster_key_candidates');
  assert.equal(pair.runtime_image_requirement, 'EXACT_IMAGE_REQUIRED');
  assert.ok(pair.required_inputs.some((input) => input.name === 'exact_runtime_image'));
  assert.ok(pair.required_inputs.some((input) => input.name === 'python_unicorn'));
  assert.ok(pair.required_inputs.some((input) => input.name === 'replay_tail_MINIONS_KILLED'));
  assert.ok(pair.missing_inputs.includes('exact_runtime_image'));
  assert.ok(pair.missing_inputs.includes('python_unicorn'));
  assert.ok(pair.validation_pending.some((pending) => pending.includes('+0x2c')));
});

test('capabilities exposes missing Replay tail stats without treating it as zero events', (t) => {
  const cli = loadCli();
  const input = fixture(t, '16.19.820.7193');
  const original = fs.readFileSync(input);
  const metadataLength = original.readUInt32LE(original.length - 4);
  const metadata = Buffer.from(JSON.stringify({ gameLength: 600000 }));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  fs.writeFileSync(input, Buffer.concat([
    original.subarray(0, original.length - metadataLength - 4), metadata, trailer,
  ]));
  const result = cli.capabilityQuery(require('../src/rofl').parseReplayFile(input));
  const heroDeath = result.capabilities.find((row) => row.capability === 'hero_death');
  assert.deepEqual(heroDeath.missing_inputs, ['replay_tail_statsJson']);
  assert.equal(heroDeath.required_inputs.find((row) => row.name === 'replay_tail_statsJson').status,
    'MISSING');
  assert.equal(heroDeath.status, 'CANDIDATE');
  assert.equal(result.semantic_decode_performed, false);
});

test('capabilities distinguishes a released exact-build profile and rejects unknown full builds', async (t) => {
  const cli = loadCli();
  const supported = fixture(t, '16.16.805.0442');
  const older = cli.capabilityQuery(require('../src/rofl').parseReplayFile(supported));
  const death = older.capabilities.find((row) => row.capability === 'hero_death');
  assert.equal(older.profile_release_status, 'SUPPORTED_VERIFIED_DEEP_SEMANTICS_PARTIAL');
  assert.equal(death.status, 'RELEASED_VERIFIED');
  assert.equal(death.published, true);
  assert.equal(death.entrypoint, 'EXACT_BUILD_API_ONLY');
  assert.equal(death.missing_inputs, null);
  assert.equal(death.runtime_image_requirement, 'NOT_ASSESSED_PER_CAPABILITY');
  assert.deepEqual(older.entrypoint_input_precheck.missing_inputs, ['exact_runtime_image']);

  let output = '';
  t.mock.method(process.stdout, 'write', (chunk) => { output += String(chunk); return true; });
  const unsupported = fixture(t, '16.19.9999.9999');
  assert.equal(await cli.main(['capabilities', unsupported, '--json']), 2);
  const unknown = JSON.parse(output);
  assert.equal(unknown.status, 'UNSUPPORTED_VERSION');
  assert.deepEqual(unknown.capabilities, []);
});

test('16.19 inspect reports container-only success without invoking a decoder', async (t) => {
  const cli = loadCli();
  const input = fixture(t, '16.19.820.7193');
  const output = path.join(path.dirname(input), 'inspect-output');
  const code = await cli.main(['inspect', input, '--out-dir', output]);
  assert.equal(code, 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CONTAINER_INSPECTED');
  assert.equal(summary.decoder_summaries[0].status, 'CONTAINER_INSPECTED');
  assert.equal(summary.replay_versions[0], '16.19.820.7193');
});

test('16.19 candidate decode preserves experimental events and exact capability status', async (t) => {
  let calls = 0;
  const requestedImage = path.join(os.tmpdir(), 'unused-16-19-image.bin');
  const cli = loadCli(null, (replay, options) => {
    calls += 1;
    assert.equal(replay.header.version, '16.19.820.7193');
    assert.deepEqual(options.capabilities, ['hero_death']);
    assert.equal(options.runtimeImagePath, requestedImage);
    return {
      status: 'EXPERIMENTAL_CANDIDATE',
      profile: { game_version: replay.header.version },
      events: { hero_death_candidates: [{ victim_participant: 1, timestamp_ms: 3000 }] },
      capability_results: {
        hero_death: { status: 'CANDIDATE', input_count: 1, event_count: 1,
          runtime_image_status: 'PROVIDED_NOT_USED' },
      },
    };
  });
  const input = fixture(t, '16.19.820.7193');
  const output = path.join(path.dirname(input), 'decode-output');
  const code = await cli.main(['decode', input, '--events', 'hero_death',
    '--runtime-image', requestedImage, '--out-dir', output]);
  assert.equal(code, 0);
  assert.equal(calls, 1);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'CANDIDATE');
  assert.equal(summary.capability_runs[0].capability_results.hero_death.status, 'CANDIDATE');
  assert.equal(summary.death_event_count, null);
  assert.equal(summary.adc_death_count, null);
  const replayDir = path.join(output, 'replays', fs.readdirSync(path.join(output, 'replays'))[0]);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDir, 'semantic_run.json'), 'utf8'));
  const events = JSON.parse(fs.readFileSync(path.join(replayDir, 'events.json'), 'utf8'));
  assert.equal(semantic.api_status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(semantic.container_status, 'PASS');
  assert.equal(semantic.runtime_image_requested, requestedImage);
  assert.equal(semantic.runtime_image_used, false);
  const manifest = JSON.parse(fs.readFileSync(path.join(output, 'manifest.json'), 'utf8'));
  assert.deepEqual(manifest.dependencies.external_runtime_dependencies, []);
  assert.deepEqual(manifest.dependencies.requested_runtime_images, [requestedImage]);
  assert.deepEqual(Object.keys(events), ['hero_death_candidates']);
  assert.equal(events.hero_death_candidates.length, 1);
  assert.equal(fs.existsSync(path.join(replayDir, 'adc_deaths.jsonl')), false);
  assert.match(fs.readFileSync(path.join(output, 'ACCEPTANCE_REPORT.md'), 'utf8'),
    /CANDIDATE marks experimental output/);
});

test('16.19 event JSONL only mode preserves rows and status without duplicate event arrays', async (t) => {
  const rows = Array.from({ length: 12 }, (_, index) => ({
    timestamp_ms: index * 1000,
    confidence: 'CANDIDATE',
    raw_packet_ref: { packet_id: 0x03ed, payload_sha256: 'a'.repeat(64) },
  }));
  const cli = loadCli(null, () => ({
    status: 'EXPERIMENTAL_CANDIDATE',
    events: { npc_buff_add_packet_candidates: rows },
    capability_results: {
      npc_buff_add_packet: { status: 'CANDIDATE', input_count: rows.length,
        event_count: rows.length },
    },
  }));
  const input = fixture(t, '16.19.820.7193');
  const root = path.dirname(input);
  const full = path.join(root, 'full');
  const compact = path.join(root, 'compact');
  const args = ['decode', input, '--events', 'npc_buff_add_packet'];
  assert.equal(await cli.main([...args, '--out-dir', full]), 0);
  assert.equal(await cli.main([...args, '--event-jsonl-only', '--out-dir', compact]), 0);

  const fullSummary = JSON.parse(fs.readFileSync(path.join(full, 'acceptance_summary.json')));
  const compactSummary = JSON.parse(fs.readFileSync(path.join(compact, 'acceptance_summary.json')));
  assert.equal(fullSummary.status, compactSummary.status);
  assert.deepEqual(fullSummary.capability_runs[0].capability_results,
    compactSummary.capability_runs[0].capability_results);
  const fullReplay = path.join(full, fullSummary.replay_artifacts[0].artifact_directory);
  const compactReplay = path.join(compact, compactSummary.replay_artifacts[0].artifact_directory);
  const name = 'npc_buff_add_packet_candidates';
  const fullAnalysis = JSON.parse(fs.readFileSync(path.join(fullReplay, 'replay_analysis.json')));
  const compactAnalysis = JSON.parse(fs.readFileSync(path.join(compactReplay, 'replay_analysis.json')));
  assert.deepEqual(fullAnalysis.events[name], rows);
  assert.equal(Object.hasOwn(fullAnalysis, 'event_storage'), false);
  assert.equal(compactAnalysis.events, null);
  assert.equal(compactAnalysis.event_storage, 'JSONL_ONLY');
  assert.deepEqual(compactAnalysis.event_jsonl_files, { [name]: `${name}.jsonl` });
  assert.deepEqual(compactAnalysis.event_counts, { [name]: rows.length });
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(fullReplay, 'events.json'))),
    { [name]: rows });
  assert.equal(fs.existsSync(path.join(compactReplay, 'events.json')), false);
  assert.equal(fs.readFileSync(path.join(fullReplay, `${name}.jsonl`), 'utf8'),
    fs.readFileSync(path.join(compactReplay, `${name}.jsonl`), 'utf8'));
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(fullReplay, 'semantic_run.json'))),
    JSON.parse(fs.readFileSync(path.join(compactReplay, 'semantic_run.json'))));
  const compactManifest = JSON.parse(fs.readFileSync(path.join(compact, 'manifest.json')));
  const relative = compactSummary.replay_artifacts[0].artifact_directory;
  assert.equal(compactManifest.replay_inputs[0].event_storage, 'JSONL_ONLY');
  assert.equal(Object.hasOwn(compactManifest.output_hashes_excluding_manifest,
    `${relative}/events.json`), false);
  assert.match(compactManifest.output_hashes_excluding_manifest[`${relative}/${name}.jsonl`],
    /^[a-f0-9]{64}$/);
  const reviewer = JSON.parse(fs.readFileSync(path.join(compact, 'reviewer_manifest.json')));
  assert.match(reviewer.replay_command, / --event-jsonl-only /);
});

test('event JSONL only mode rejects invalid scope and preserves missing-input evidence', async (t) => {
  const cli = loadCli(null, () => ({
    status: 'BLOCKED',
    events: null,
    capability_results: {
      hero_path: { status: 'MISSING_INPUT', input_count: null, event_count: null,
        missing_input: 'exact runtime image' },
    },
  }));
  const input = fixture(t, '16.19.820.7193');
  assert.throws(() => cli.parseArgs(['inspect', input, '--events', 'hero_path',
    '--event-jsonl-only']), /requires decode or batch/);
  assert.throws(() => cli.parseArgs(['decode', input, '--event-jsonl-only']),
    /requires decode or batch with --events/);

  const output = path.join(path.dirname(input), 'missing-compact');
  assert.equal(await cli.main(['decode', input, '--events', 'hero_path',
    '--event-jsonl-only', '--out-dir', output]), 2);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json')));
  assert.equal(summary.status, 'MISSING_INPUT');
  assert.equal(summary.capability_runs[0].capability_results.hero_path.event_count, null);
  const replayDir = path.join(output, summary.replay_artifacts[0].artifact_directory);
  const analysis = JSON.parse(fs.readFileSync(path.join(replayDir, 'replay_analysis.json')));
  assert.equal(analysis.events, null);
  assert.deepEqual(analysis.event_counts, {});
  assert.deepEqual(analysis.event_jsonl_files, {});
  assert.equal(fs.existsSync(path.join(replayDir, 'events.json')), false);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDir, 'semantic_run.json')));
  assert.equal(semantic.capability_results.hero_path.status, 'MISSING_INPUT');
  assert.equal(semantic.capability_results.hero_path.event_count, null);

  const legacy = fixture(t, '16.15.801.3452');
  const legacyOutput = path.join(path.dirname(legacy), 'legacy-compact');
  assert.equal(await cli.main(['decode', legacy, '--events', 'hero_path',
    '--event-jsonl-only', '--out-dir', legacyOutput]), 2);
  const legacySummary = JSON.parse(fs.readFileSync(
    path.join(legacyOutput, 'acceptance_summary.json')));
  assert.equal(legacySummary.status, 'UNSUPPORTED_OUTPUT_MODE');
  assert.equal(legacySummary.errors[0].code, 'UNSUPPORTED_OUTPUT_MODE');
});

test('16.19 zero-event PASS remains distinct from missing input and partial failure', (t) => {
  const input = fixture(t, '16.19.820.7193');
  const passed = loadCli(null, () => ({
    status: 'PASS',
    events: { hero_path_events: [] },
    capability_results: {
      hero_path: { status: 'PASS', input_count: 0, event_count: 0 },
    },
  })).parseOne(input, {
    ...loadCli().parseArgs(['decode', input, '--events', 'hero_path']).options,
    semantic: true,
  });
  assert.equal(passed.ok, true);
  assert.equal(passed.analysis.decoder.status, 'PASS');
  assert.equal(passed.analysis.semantic.capability_results.hero_path.event_count, 0);
  assert.deepEqual(passed.analysis.events.hero_path_events, []);

  const partial = loadCli(null, () => ({
    status: 'PARTIAL',
    events: { hero_death_candidates: [{ victim_participant: 1 }] },
    capability_results: {
      hero_death: { status: 'CANDIDATE', input_count: 1, event_count: 1 },
      hero_path: { status: 'MISSING_INPUT', input_count: null, event_count: null,
        missing_input: 'exact runtime image' },
    },
  })).parseOne(input, {
    ...loadCli().parseArgs(['decode', input, '--events', 'hero_death,hero_path']).options,
    semantic: true,
  });
  assert.equal(partial.analysis.decoder.status, 'PARTIAL');
  assert.equal(partial.analysis.events.hero_death_candidates.length, 1);
  assert.equal(partial.analysis.semantic.capability_results.hero_path.status, 'MISSING_INPUT');
  assert.equal(partial.analysis.events.death_events, undefined);
});

test('821 UnitApplyDamage V6 CLI switch forwards an explicit decode option', (t) => {
  const input = fixture(t, '16.19.821.7343');
  const seen = [];
  const cli = loadCli(null, (_replay, options) => {
    seen.push(options.damagePacketProfile);
    return { status: 'CANDIDATE',
      events: { unit_apply_damage_packet_candidates: [] },
      capability_results: { unit_apply_damage_packet: {
        status: 'CANDIDATE', input_count: 0, event_count: 0,
      } } };
  });
  const selected = cli.parseArgs(['decode', input, '--events',
    'unit_apply_damage_packet', '--damage-packet-v6']);
  assert.equal(selected.options.damagePacketV6, true);
  assert.equal(cli.parseOne(input, { ...selected.options, semantic: true }).ok, true);
  const ordinary = cli.parseArgs(['decode', input, '--events',
    'unit_apply_damage_packet']);
  assert.equal(cli.parseOne(input, { ...ordinary.options, semantic: true }).ok, true);
  assert.deepEqual(seen, ['v6', undefined]);
  assert.equal(cli.parseArgs(['batch', input, '--events',
    'hero_death_damage_lookup_key_cooccurrence', '--damage-packet-v6'])
    .options.damagePacketV6, true);
  assert.throws(() => cli.parseArgs(['decode', input, '--damage-packet-v6']),
    /--damage-packet-v6 requires/);
  assert.throws(() => cli.parseArgs(['decode', input, '--events',
    'hero_path', '--damage-packet-v6']), /--damage-packet-v6 requires/);
  assert.throws(() => cli.parseArgs(['query-events', input, '--event',
    'unit_apply_damage_packet_candidates', '--damage-packet-v6']),
  /--damage-packet-v6 requires/);
});

test('821 CastSpellAns V5 CLI switch forwards an explicit decode option', (t) => {
  const input = fixture(t, '16.19.821.7343');
  const seen = [];
  const cli = loadCli(null, (_replay, options) => {
    seen.push(options.castPacketProfile);
    return { status: 'CANDIDATE',
      events: { cast_spell_ans_packet_candidates: [] },
      capability_results: { cast_spell_ans_packet: {
        status: 'CANDIDATE', input_count: 0, event_count: 0,
      } } };
  });
  const selected = cli.parseArgs(['decode', input, '--events',
    'cast_spell_ans_packet', '--cast-packet-v5']);
  assert.equal(selected.options.castPacketV5, true);
  assert.equal(cli.parseOne(input, { ...selected.options, semantic: true }).ok, true);
  const ordinary = cli.parseArgs(['decode', input, '--events',
    'cast_spell_ans_packet']);
  assert.equal(cli.parseOne(input, { ...ordinary.options, semantic: true }).ok, true);
  assert.deepEqual(seen, ['v5', undefined]);
  assert.equal(cli.parseArgs(['batch', input, '--events',
    'cast_spell_ans_packet', '--cast-packet-v5']).options.castPacketV5, true);
  assert.throws(() => cli.parseArgs(['decode', input, '--cast-packet-v5']),
    /--cast-packet-v5 requires/);
  assert.throws(() => cli.parseArgs(['decode', input, '--events',
    'hero_path', '--cast-packet-v5']), /--cast-packet-v5 requires/);
  assert.throws(() => cli.parseArgs(['query-events', input, '--event',
    'cast_spell_ans_packet_candidates', '--cast-packet-v5']),
  /--cast-packet-v5 requires/);
});

test('16.19 decode requires an explicit capability and reports missing input as failure', async (t) => {
  const cli = loadCli(null, () => ({
    status: 'BLOCKED',
    events: null,
    capability_results: {
      hero_path: { status: 'MISSING_INPUT', event_count: null, input_count: null,
        missing_input: 'exact runtime image' },
    },
  }));
  const input = fixture(t, '16.19.820.7193');
  const noSelection = cli.parseOne(input, { ...cli.parseArgs(['decode', input]).options, semantic: true });
  assert.equal(noSelection.analysis.decoder.status, 'MISSING_CAPABILITY_SELECTION');
  const output = path.join(path.dirname(input), 'missing-output');
  const code = await cli.main(['decode', input, '--events', 'hero_path', '--out-dir', output]);
  assert.equal(code, 2);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'MISSING_INPUT');
  assert.equal(summary.capability_runs[0].capability_results.hero_path.status, 'MISSING_INPUT');
  assert.match(fs.readFileSync(path.join(output, 'ACCEPTANCE_REPORT.md'), 'utf8'),
    /missing input: exact runtime image/);
});

test('16.19 profile-unavailable replay is not reported as zero candidate events', async (t) => {
  const cli = loadCli(null, () => ({
    status: 'PROFILE_UNAVAILABLE',
    events: null,
    capability_results: {
      hero_death: { status: 'PROFILE_UNAVAILABLE', input_count: null,
        event_count: null, error: 'No bounded route profile matches this Replay.' },
    },
  }));
  const input = fixture(t, '16.19.820.7193');
  const output = path.join(path.dirname(input), 'profile-unavailable');
  const code = await cli.main(['decode', input, '--events', 'hero_death', '--out-dir', output]);
  assert.equal(code, 2);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'PROFILE_UNAVAILABLE');
  assert.equal(summary.capability_runs[0].capability_results.hero_death.event_count, null);
  const replayDir = path.join(output, 'replays', fs.readdirSync(path.join(output, 'replays'))[0]);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(replayDir, 'events.json'), 'utf8')), {});
});

test('mixed-build semantic batch fails on an unsupported replay while inspect stays container-only', async (t) => {
  const cli = loadCli(() => ({
    status: 'UNSUPPORTED_REPLAY_VERSION', profile: null, events: null,
    adc_deaths: [], capabilities: null, decoded_packet_count: 0,
  }), () => ({
    status: 'EXPERIMENTAL_CANDIDATE',
    events: { hero_death_candidates: [{ victim_participant: 1 }] },
    capability_results: {
      hero_death: { status: 'CANDIDATE', input_count: 1, event_count: 1 },
    },
  }));
  const current = fixture(t, '16.19.820.7193');
  const legacy = fixture(t, '16.16.805.0442');
  const namedLegacy = path.join(path.dirname(legacy), 'unsupported.rofl');
  fs.renameSync(legacy, namedLegacy);
  const output = path.join(path.dirname(current), 'batch-output');
  const code = await cli.main(['batch', current, namedLegacy,
    '--events', 'hero_death', '--out-dir', output]);
  assert.equal(code, 2);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'PARTIAL');
  assert.deepEqual(summary.decoder_summaries.map((row) => row.status).sort(),
    ['CANDIDATE', 'UNSUPPORTED_REPLAY_VERSION']);

  const inspectOutput = path.join(path.dirname(current), 'mixed-inspect-output');
  const inspectCode = await cli.main(['inspect', current, namedLegacy, '--out-dir', inspectOutput]);
  assert.equal(inspectCode, 0);
  const inspectSummary = JSON.parse(fs.readFileSync(
    path.join(inspectOutput, 'acceptance_summary.json'), 'utf8'));
  assert.equal(inspectSummary.status, 'CONTAINER_INSPECTED');
});

test('a rerun into a populated output directory keeps the first artifacts and writes a fresh sibling', async (t) => {
  let decodeCount = 0;
  const cli = loadCli(null, () => {
    decodeCount += 1;
    return decodeCount === 1 ? {
      status: 'EXPERIMENTAL_CANDIDATE',
      events: { hero_death_candidates: [{ victim_participant: 1 }] },
      capability_results: {
        hero_death: { status: 'CANDIDATE', input_count: 1, event_count: 1 },
      },
    } : {
      status: 'PROFILE_UNAVAILABLE', events: null,
      capability_results: {
        hero_death: { status: 'PROFILE_UNAVAILABLE', input_count: null,
          event_count: null },
      },
    };
  });
  const input = fixture(t, '16.19.820.7193');
  const requested = path.join(path.dirname(input), 'results');
  const argv = ['decode', input, '--events', 'hero_death', '--out-dir', requested];
  assert.equal(await cli.main(argv), 0);
  const firstSummary = JSON.parse(fs.readFileSync(
    path.join(requested, 'acceptance_summary.json'), 'utf8'));
  const firstEventFile = path.join(requested, firstSummary.replay_artifacts[0].artifact_directory,
    'hero_death_candidates.jsonl');
  const firstEventBytes = fs.readFileSync(firstEventFile, 'utf8');

  assert.equal(await cli.main(argv), 2);
  const siblings = fs.readdirSync(path.dirname(requested))
    .filter((name) => name.startsWith('results-run-'));
  assert.equal(siblings.length, 1);
  const actual = path.join(path.dirname(requested), siblings[0]);
  const secondSummary = JSON.parse(fs.readFileSync(
    path.join(actual, 'acceptance_summary.json'), 'utf8'));
  const secondManifest = JSON.parse(fs.readFileSync(path.join(actual, 'manifest.json'), 'utf8'));
  assert.equal(secondSummary.output_root, actual);
  assert.equal(secondManifest.output_root, actual);
  assert.equal(fs.readFileSync(firstEventFile, 'utf8'), firstEventBytes);
  assert.equal(fs.existsSync(path.join(actual, secondSummary.replay_artifacts[0].artifact_directory,
    'hero_death_candidates.jsonl')), false);
});

test('populated gitignored output roots keep reruns inside the ignored directory', (t) => {
  const cli = loadCli();
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-ignored-output-unit-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const ignorePatterns = new Set(fs.readFileSync(
    path.resolve(__dirname, '../.gitignore'), 'utf8').split(/\r?\n/));
  for (const name of ['artifacts', 'work', 'dist', 'evidence']) {
    assert.equal(ignorePatterns.has(`${name}/`), true);
    const requested = path.join(root, name);
    fs.mkdirSync(requested);
    const sentinel = path.join(requested, 'earlier-result.jsonl');
    fs.writeFileSync(sentinel, '{"prior":true}\n');
    const actual = cli.reserveOutputDirectory(requested, root);
    assert.equal(path.dirname(actual), requested);
    assert.match(path.basename(actual), /^run-[0-9A-Za-z]+-/);
    assert.equal(fs.readFileSync(sentinel, 'utf8'), '{"prior":true}\n');
  }
});

test('same-basename Replays get distinct stable artifact directories in one batch', async (t) => {
  const cli = loadCli(null, () => ({
    status: 'EXPERIMENTAL_CANDIDATE',
    events: { hero_death_candidates: [{ victim_participant: 1 }] },
    capability_results: {
      hero_death: { status: 'CANDIDATE', input_count: 1, event_count: 1 },
    },
  }));
  const first = fixture(t, '16.19.820.7193');
  const second = fixture(t, '16.19.820.7193');
  const output = path.join(path.dirname(first), 'collision-output');
  assert.equal(await cli.main(['batch', first, second, '--events', 'hero_death',
    '--out-dir', output]), 0);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  const manifest = JSON.parse(fs.readFileSync(path.join(output, 'manifest.json'), 'utf8'));
  const directories = summary.replay_artifacts.map((row) => row.artifact_directory);
  assert.equal(new Set(directories).size, 2);
  assert.ok(directories.every((directory) => /^replays\/synthetic-[a-f0-9]{12}$/.test(directory)));
  assert.deepEqual(manifest.replay_inputs.map((row) => row.artifact_directory), directories);
  for (const directory of directories) {
    assert.equal(fs.existsSync(path.join(output, directory, 'hero_death_candidates.jsonl')), true);
  }
});

test('unregistered full 16.19 build is unsupported before capability selection', async (t) => {
  const cli = loadCli();
  const input = fixture(t, '16.19.9999.9999');
  const output = path.join(path.dirname(input), 'unregistered-output');
  assert.equal(await cli.main(['decode', input, '--out-dir', output]), 2);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'UNSUPPORTED_VERSION');
  assert.equal(summary.capability_runs[0].status, 'UNSUPPORTED_VERSION');
});

test('non-strict inspect exits unsuccessfully when packet framing is damaged', async (t) => {
  const cli = loadCli();
  const input = fixture(t, '16.19.820.7193');
  fs.writeFileSync(input, replayFromChunks([{
    body: Buffer.concat([packet(1), Buffer.from([0])]),
  }], '16.19.820.7193').buffer);
  const output = path.join(path.dirname(input), 'damaged-inspect-output');
  assert.equal(await cli.main(['inspect', input, '--out-dir', output]), 2);
  const summary = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json'), 'utf8'));
  assert.equal(summary.status, 'VALIDATION_FAILED');
  assert.equal(summary.real_replay_validation.block_framing_errors, 1);
});
