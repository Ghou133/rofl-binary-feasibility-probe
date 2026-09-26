'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { parseReplayFile } = require('../src/rofl');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { EventQueryError, prepareEventQuery, prepareBatchEventQuery,
  streamEventQuery, streamBatchEventQuery } = require('../src/event_query');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { SET_SPELL_LEVEL_PACKET_CANDIDATE_PROFILE_V2_821: profile,
  decodeSetSpellLevelU32At10FromRaw821: decodeAt10,
  decodeSetSpellLevelU32At14FromRaw821: decodeAt14 } =
  require('../src/decoders/rofl_16_19_821_set_spell_level_packet_candidate');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'set_spell_level_packet';
const EVENT = 'set_spell_level_packet_candidates';
const sha = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

function packet(payloadHex, rawParam, timeMs) {
  const payload = Buffer.from(payloadHex, 'hex');
  const header = Buffer.alloc(15);
  header.writeFloatLE(timeMs / 1000, 1);
  header.writeUInt32LE(payload.length, 5);
  header.writeUInt16LE(0x025d, 9);
  header.writeUInt32LE(rawParam, 11);
  return Buffer.concat([header, payload]);
}

function nativeResponse(request, v2) {
  const rawAt10 = ['bbbbbbbb', '7bbbbbbb', 'bbbbbbbb'];
  const rawAt14 = ['32f1f1f1', '72f1f1f1', '32f1f1f1'];
  return {
    status: 'PASS',
    runtime_image_sha256: profile.evidence_runtime_image_sha256,
    callback_table_sha256: profile.evidence_callback_table_sha256,
    ...(v2 ? {
      callback_rva: profile.evidence_callback_rva,
      receiver_write_rva: profile.evidence_receiver_write_rva,
      callback_region_sha256: profile.evidence_callback_region_sha256,
      receiver_write_region_sha256: profile.evidence_receiver_write_region_sha256,
      callback_witness_mode: profile.evidence_callback_witness_mode,
    } : {}),
    results: request.packets.map((input, index) => {
      const opaqueIndex = decodeAt10(rawAt10[index]);
      const opaqueScalar = decodeAt14(rawAt14[index]);
      return {
        status: 'DECODED', input_index: index,
        raw_param: input.raw_param,
        raw_payload_sha256: sha(Buffer.from(input.payload_hex, 'hex')),
        deserialize_return_al: 1, bytes_consumed: input.payload_hex.length / 2,
        native_packet_id: 0x025d, native_raw_param: input.raw_param,
        raw_u32_0x10_hex: rawAt10[index], opaque_u32_0x10: opaqueIndex,
        raw_u32_0x14_hex: rawAt14[index], opaque_u32_0x14: opaqueScalar,
        ...(v2 ? {
          native_receiver_slot_candidate: opaqueIndex,
          native_receiver_selection_source: 'INDEXED',
          native_clamped_scalar_candidate: opaqueScalar,
          native_positive_flag_written: true,
        } : {}),
      };
    }),
  };
}

function fixture(t, packetProfile = 'v2') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-spell-source-query-'));
  t.after(() => {
    const resolved = path.resolve(root);
    if (!resolved.startsWith(path.resolve(os.tmpdir()) + path.sep)
        || !path.basename(resolved).startsWith('rofl-spell-source-query-')) {
      throw new Error('Unsafe synthetic fixture cleanup target');
    }
    fs.rmSync(resolved, { recursive: true, force: true });
  });
  const image = path.join(root, 'runtime.bin');
  fs.writeFileSync(image, Buffer.from([1, 2, 3]));
  const source = path.join(root, 'original.rofl');
  const generated = replayFromChunks([{
    stream: 1, body: Buffer.concat([
      packet('fa', 0x400000b4, 1000),
      packet('c37b', 0x400000b5, 1100),
      packet('4a', 0x400000b6, 1200),
    ]),
  }], BUILD);
  fs.writeFileSync(source, generated.buffer);
  const replay = parseReplayFile(source);
  const native = t.mock.method(childProcess, 'spawnSync', (_python, args, options) => {
    const v2 = args.includes('--callback-witness-v2');
    const response = nativeResponse(JSON.parse(options.input), v2);
    return { status: 0, stderr: '', stdout: JSON.stringify(response) };
  });
  const decoded = decodeSemanticReplay(replay, {
    capabilities: [CAPABILITY], runtimeImagePath: image,
    setSpellLevelProfile: packetProfile,
  });
  const result = decoded.capability_results[CAPABILITY];
  assert.equal(result.status, 'CANDIDATE', result.error);
  const rows = decoded.events[EVENT];
  assert.equal(rows.length, 3);
  const directory = path.join(root, 'replays', 'sample');
  fs.mkdirSync(directory, { recursive: true });
  const semantic = {
    replay_version: BUILD, replay_sha256: replay.source_sha256,
    container_status: 'PASS', status: 'CANDIDATE',
    api_status: 'EXPERIMENTAL_CANDIDATE',
    requested_capabilities: [CAPABILITY],
    capability_results: { [CAPABILITY]: result },
  };
  const analysis = {
    patch: '16.19', replay_version: BUILD, replay_sha256: replay.source_sha256,
    source_path: source, event_storage: 'JSONL_ONLY', events: null,
    event_counts: { [EVENT]: rows.length },
    event_jsonl_files: { [EVENT]: `${EVENT}.jsonl` },
    semantic: { status: 'CANDIDATE', requested_capabilities: [CAPABILITY],
      capability_results: { [CAPABILITY]: result } },
  };
  const files = {
    'semantic_run.json': JSON.stringify(semantic),
    'replay_analysis.json': JSON.stringify(analysis),
    [`${EVENT}.jsonl`]: `${rows.map(JSON.stringify).join('\n')}\n`,
  };
  const rewrite = () => {
    const hashes = {};
    for (const [filename, content] of Object.entries(files)) {
      fs.writeFileSync(path.join(directory, filename), content);
      hashes[`replays/sample/${filename}`] = sha(content);
    }
    fs.writeFileSync(path.join(root, 'manifest.json'), JSON.stringify({
      command_args: ['decode'],
      replay_inputs: [{ artifact_directory: 'replays/sample',
        sha256: replay.source_sha256, version: BUILD }],
      output_hashes_excluding_manifest: hashes,
    }));
  };
  rewrite();
  return { root, directory, image, source, rows, files, rewrite, native };
}

test('V2 standalone source check re-decodes every row before limit and accepts same-byte relocation', async (t) => {
  const f = fixture(t);
  const prepared = prepareEventQuery(f.directory, EVENT);
  const selected = [];
  const summary = await streamEventQuery(prepared,
    { verifySource: true, runtimeImage: f.image, limit: 1 },
    async (line) => selected.push(JSON.parse(line)));
  assert.deepEqual(selected, [f.rows[0]]);
  assert.equal(summary.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.matched_count, 3);
  assert.equal(summary.spell_level_callback_checked_count, 3);
  const relocated = path.join(f.root, 'relocated.rofl');
  fs.copyFileSync(f.source, relocated);
  const moved = await streamEventQuery(prepared,
    { verifySource: true, runtimeImage: f.image,
      sourceReplay: relocated, limit: 1 }, async () => {});
  assert.equal(moved.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
  assert.equal(f.native.mock.callCount(), 3);
});

test('V2 standalone batch source check verifies all rows under a global limit', async (t) => {
  const f = fixture(t);
  const prepared = prepareBatchEventQuery(f.root, EVENT);
  const output = [];
  const summary = await streamBatchEventQuery(prepared,
    { verifySource: true, runtimeImage: f.image, limit: 1 },
    async (line) => output.push(JSON.parse(line)));
  assert.deepEqual(output, [f.rows[0]]);
  assert.equal(summary.source_provenance_status, 'SOURCE_REPLAY_VERIFIED');
  assert.equal(summary.scanned_count, 3);
  assert.equal(summary.emitted_count, 1);
});

test('V2 standalone source check rejects late saved-row forgery after limit', async (t) => {
  const f = fixture(t);
  const forged = structuredClone(f.rows);
  forged[2].replay_time_ms += 100;
  forged[2].raw_packet_ref.replay_time_ms += 100;
  f.files[`${EVENT}.jsonl`] = `${forged.map(JSON.stringify).join('\n')}\n`;
  f.rewrite();
  const prepared = prepareEventQuery(f.directory, EVENT);
  await assert.rejects(streamEventQuery(prepared,
    { verifySource: true, runtimeImage: f.image, limit: 1 }, async () => {}),
  { code: 'SOURCE_PROVENANCE_MISMATCH', details: { line_number: 3 } });
});

test('V2 standalone source check rejects forged metadata and different ROFL identity', async (t) => {
  const f = fixture(t);
  const semantic = JSON.parse(f.files['semantic_run.json']);
  const analysis = JSON.parse(f.files['replay_analysis.json']);
  semantic.capability_results[CAPABILITY].scanned_block_count += 1;
  analysis.semantic.capability_results[CAPABILITY].scanned_block_count += 1;
  f.files['semantic_run.json'] = JSON.stringify(semantic);
  f.files['replay_analysis.json'] = JSON.stringify(analysis);
  f.rewrite();
  const prepared = prepareEventQuery(f.directory, EVENT);
  await assert.rejects(streamEventQuery(prepared,
    { verifySource: true, runtimeImage: f.image, limit: 1 }, async () => {}),
  { code: 'SOURCE_PROVENANCE_MISMATCH' });
  const unrelated = path.join(f.root, 'unrelated.rofl');
  fs.writeFileSync(unrelated, Buffer.concat([fs.readFileSync(f.source), Buffer.from([0])]));
  await assert.rejects(streamEventQuery(prepared,
    { verifySource: true, runtimeImage: f.image,
      sourceReplay: unrelated, limit: 1 }, async () => {}),
  (error) => error instanceof EventQueryError
    && ['SOURCE_REPLAY_INVALID', 'SOURCE_REPLAY_IDENTITY_MISMATCH'].includes(error.code));
});

test('V2 standalone source check requires an explicit runtime image', async (t) => {
  const f = fixture(t);
  const prepared = prepareEventQuery(f.directory, EVENT);
  await assert.rejects(streamEventQuery(prepared,
    { verifySource: true, limit: 1 }, async () => {}),
  { code: 'MISSING_RUNTIME_IMAGE' });
});

test('V1 saved query remains available without source verification', async (t) => {
  const f = fixture(t, 'v1');
  const prepared = prepareEventQuery(f.directory, EVENT);
  const unverified = await streamEventQuery(prepared, {}, async () => {});
  assert.equal(unverified.source_provenance_status, 'SAVED_ONLY_UNVERIFIED');
  await assert.rejects(streamEventQuery(prepared,
    { verifySource: true, runtimeImage: f.image }, async () => {}),
  { code: 'UNSUPPORTED_SOURCE_VERIFICATION' });
});
