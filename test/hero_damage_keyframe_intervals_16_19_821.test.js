'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { replayFromChunks } = require('./helpers/synthetic_replay');
const { parseReplayBuffer } = require('../src/rofl');
const { decodeSemanticReplay } = require('../src/semantic_api');
const { resolveBuildProfile } = require('../src/build_registry');
const { decodeRuntimeCountByte } = require('../src/decoders/rofl_16_19_821_runtime_bytes');
const { decodeHeroDamageKeyframeIntervalsCandidates821: decode } =
  require('../src/decoders/rofl_16_19_821_damage_keyframe_intervals_candidate');
const { compareDamagePacketKeyframeWindows821: compare } =
  require('../src/decoders/rofl_16_19_821_damage_window_reconciliation_candidate');
const { UNIT_APPLY_DAMAGE_PACKET_CANDIDATE_PROFILE_821: DAMAGE_PROFILE } =
  require('../src/decoders/rofl_16_19_821_unit_apply_damage_packet_candidate');

const BUILD = '16.19.821.7343';
const CAPABILITY = 'hero_damage_keyframe_intervals';
const EVENTS = 'hero_damage_keyframe_interval_candidates';
const OFFSETS = [0x1e0, 0x1d0, 0x1f0, 0x200];
const FIELDS = ['TOTAL_DAMAGE_DEALT_TO_CHAMPIONS', 'TOTAL_DAMAGE_DEALT',
  'TOTAL_DAMAGE_TAKEN', 'TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS'];
const ENCODE = new Map(Array.from({ length: 256 }, (_, raw) =>
  [decodeRuntimeCountByte(raw), raw]));

function fixture({ times = [0, 60_000, 120_000],
  values = [[0, 0, 0, 0], [0.9, 10.5, 15.25, 7.5], [1.1, 10.5, 20.5, 9.25]],
  version = BUILD, missingTail = false, participants = 10 } = {}) {
  const chunks = times.map((time, frame) => ({
    stream: 2,
    body: Buffer.concat(Array.from({ length: participants }, (_, index) => {
      const payload = Buffer.alloc(1263, 0x97);
      payload.set([0x67, 0x00, 0xde]);
      OFFSETS.forEach((offset, field) => {
        const bytes = Buffer.alloc(4);
        bytes.writeFloatLE(index === 0 ? values[frame][field] : 0);
        for (let i = 0; i < 4; i += 1) payload[1262 - offset - i] = ENCODE.get(bytes[i]);
      });
      const header = Buffer.alloc(15);
      header.writeFloatLE(time / 1000, 1);
      header.writeUInt32LE(payload.length, 5);
      header.writeUInt16LE(0x0089, 9);
      header.writeUInt32LE(0x400000ae + index, 11);
      return Buffer.concat([header, payload]);
    })),
  }));
  const container = replayFromChunks(chunks, version).buffer;
  const stats = Array.from({ length: 10 }, (_, index) => Object.fromEntries(
    FIELDS.map((field, column) => [field, String(index === 0
      ? Math.ceil(values.at(-1)[column]) + 5 : 0)])));
  if (missingTail) delete stats[0].TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS;
  const metadata = Buffer.from(JSON.stringify({ gameLength: 180_000,
    statsJson: JSON.stringify(stats) }));
  const oldMetadataLength = container.readUInt32LE(container.length - 4);
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32LE(metadata.length);
  return parseReplayBuffer(Buffer.concat([
    container.subarray(0, container.length - oldMetadataLength - 4), metadata, trailer,
  ]), 'synthetic-damage-interval.rofl');
}

test('sampled damage intervals retain four counter differences, zero rows and endpoint provenance', () => {
  const replay = fixture();
  const result = decode(replay);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.input_count, 30);
  assert.equal(result.keyframe_count, 3);
  assert.equal(result.event_count, 20);
  assert.equal(result.changed_interval_count, 2);
  assert.equal(result.unchanged_interval_count, 18);
  assert.equal(result.tail_gaps.length, 40);
  const first = result.events[0];
  const second = result.events[10];
  assert.equal(first.participant_id_candidate, 1);
  assert.equal(first.previous_observation_time_ms, 0);
  assert.equal(first.current_observation_time_ms, 60_000);
  assert.equal(first.interval_duration_ms, 60_000);
  assert.equal(first.counters.TOTAL_DAMAGE_DEALT.endpoint_delta_f32_candidate, 10.5);
  assert.equal(second.counters.TOTAL_DAMAGE_DEALT.endpoint_delta_f32_candidate, 0);
  assert.equal(second.counters.TOTAL_DAMAGE_TAKEN.endpoint_delta_f32_candidate, 5.25);
  const fraction = second.counters.TOTAL_DAMAGE_DEALT_TO_CHAMPIONS;
  assert.ok(Math.abs(fraction.endpoint_delta_f32_candidate - 0.2) < 0.000001);
  assert.equal(fraction.endpoint_floor_difference_candidate, 1);
  assert.equal(Math.floor(fraction.endpoint_delta_f32_candidate), 0);
  assert.deepEqual(first.raw_packet_refs,
    [first.previous_raw_packet_ref, first.current_raw_packet_ref]);
  assert.equal(first.previous_raw_packet_ref.chunk_index, 0);
  assert.equal(first.current_raw_packet_ref.chunk_index, 1);
  assert.equal(first.observation_scope, 'KEYFRAME_ENDPOINT_DIFFERENCE_ONLY');
  assert.equal(first.change_time_status, 'UNRESOLVED_WITHIN_INTERVAL');
  assert.equal(result.events[1].any_counter_changed, false);
  assert.equal(result.events[1].counters.TOTAL_DAMAGE_TAKEN.endpoint_delta_f32_candidate, 0);
  assert.equal('attacker' in first, false);
  assert.equal('damage_time_ms' in first, false);
  assert.equal('effective_damage' in first, false);
  assert.equal(result.events.at(-1).current_observation_time_ms, 120_000);
});

test('interval differences telescope to the final sampled value rather than filling tail gaps', () => {
  const result = decode(fixture());
  for (const field of FIELDS) {
    const rows = result.events.filter((row) => row.participant_id_candidate === 1);
    const sum = rows.reduce((total, row) => total
      + row.counters[field].endpoint_delta_f32_candidate, 0);
    assert.equal(sum, rows.at(-1).counters[field].current_raw_f32_candidate);
    const gap = result.tail_gaps.find((row) => row.participant_id_candidate === 1
      && row.replay_tail_field === field);
    assert.ok(gap.unobserved_tail_gap > 0);
    assert.ok(gap.final_replay_tail > sum);
  }
});

test('one keyframe exposes a checked empty interval set; missing input is never zero intervals', () => {
  const one = decode(fixture({ times: [0], values: [[0, 0, 0, 0]] }));
  assert.equal(one.status, 'CANDIDATE', one.error);
  assert.equal(one.event_count, 0);
  assert.deepEqual(one.events, []);
  const missing = decode(fixture({ missingTail: true }));
  assert.equal(missing.status, 'MISSING_INPUT');
  assert.equal(missing.event_count, null);
  assert.equal(missing.events, null);
  assert.match(missing.error, /TOTAL_DAMAGE_TAKEN_FROM_CHAMPIONS/);
});

test('exact-build gating, original source and complete rosters remain required', () => {
  assert.equal(decode(fixture({ version: '16.19.820.7193' })).status, 'UNSUPPORTED');
  const mutated = fixture();
  mutated.buffer[0] ^= 1;
  assert.equal(decode(mutated).status, 'DECODE_FAILED');
  const incomplete = decode(fixture({ participants: 9 }));
  assert.notEqual(incomplete.status, 'CANDIDATE');
  assert.equal(incomplete.events, null);
});

test('nonincreasing time and decreasing/invalid counters cannot create plausible windows', () => {
  assert.equal(decode(fixture({ times: [0, 60_000, 60_000] })).status, 'INCONSISTENT');
  const decreased = decode(fixture({ values: [[0, 0, 0, 0],
    [5, 10, 15, 7], [4, 10, 20, 9]] }));
  assert.equal(decreased.status, 'DECODE_FAILED');
  assert.equal(decreased.events, null);
});

test('selected exact-build API exposes intervals without selecting native or hidden snapshot output', () => {
  const replay = fixture();
  const { profile } = resolveBuildProfile(BUILD);
  assert.ok(profile.candidate_capabilities.includes(CAPABILITY));
  const decoded = decodeSemanticReplay(replay, { capabilities: [CAPABILITY] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(decoded.capability_results[CAPABILITY].event_count, 20);
  assert.deepEqual(decoded.events[EVENTS], decode(replay).events);
  assert.deepEqual(Object.keys(decoded.capability_results), [CAPABILITY]);
  assert.equal(decoded.capability_results[CAPABILITY].runtime_image_used, false);
  assert.equal(decoded.decoded_packet_count, 30);
});

test('portable CLI preflight and JSONL-only decode run the selected interval capability', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'rofl-damage-interval-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const replayFile = path.join(directory, 'example.rofl');
  fs.writeFileSync(replayFile, fixture().buffer);
  const cli = path.resolve(__dirname, '../src/cli.js');
  const preflight = spawnSync(process.execPath,
    [cli, 'capabilities', replayFile, '--events', CAPABILITY, '--json'], { encoding: 'utf8' });
  assert.equal(preflight.status, 0, preflight.stderr || preflight.stdout);
  const doc = JSON.parse(preflight.stdout);
  assert.deepEqual(doc.requested_capabilities, [CAPABILITY]);
  assert.equal(doc.capabilities.length, 1);
  assert.equal(doc.capabilities[0].capability, CAPABILITY);
  assert.equal(doc.capabilities[0].runtime_image_requirement, 'NOT_REQUIRED');
  assert.equal(doc.capabilities[0].output, EVENTS);
  const output = path.join(directory, 'out');
  const run = spawnSync(process.execPath, [cli, 'decode', replayFile, '--events', CAPABILITY,
    '--event-jsonl-only', '--out-dir', output], { encoding: 'utf8', timeout: 30000 });
  assert.equal(run.status, 0, run.stderr || run.stdout);
  const acceptance = JSON.parse(fs.readFileSync(path.join(output, 'acceptance_summary.json')));
  const replayDirectory = path.join(output, acceptance.replay_artifacts[0].artifact_directory);
  const rows = fs.readFileSync(path.join(replayDirectory, `${EVENTS}.jsonl`), 'utf8')
    .trim().split(/\r?\n/).map(JSON.parse);
  assert.equal(rows.length, 20);
  assert.equal(rows[0].counters.TOTAL_DAMAGE_DEALT.endpoint_delta_f32_candidate, 10.5);
  const semantic = JSON.parse(fs.readFileSync(path.join(replayDirectory, 'semantic_run.json')));
  assert.equal(semantic.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.equal(semantic.capability_results[CAPABILITY].event_count, 20);
});

test('window calculator separates native keys, strict boundaries and rotated-key controls', () => {
  // Calculator fixtures test grouping only; they are not native-runtime evidence.
  const replay = fixture();
  const intervals = decode(replay);
  const nativePacket = (time, key24, key2c, value) => ({ game_version: BUILD,
    replay_sha256: replay.source_sha256, replay_time_ms: time,
    native_callback_lookup_key_u32_0x24_candidate: key24,
    native_callback_lookup_key_u32_0x2c_candidate: key2c,
    native_callback_f32_0x20_candidate: value,
    raw_packet_ref: { packet_id: 0x005f, replay_time_ms: time } });
  const packets = [
    nativePacket(1000, 0x400000ae, 0x400000af, 10),
    nativePacket(2000, 0x400000ae, 0x400000af, 5.25),
    nativePacket(60_000, 0x400000ae, 0x400000af, 100),
    nativePacket(180_000, 0x400000ae, 0x400000af, 1000),
    nativePacket(3000, 42, 99, 2000),
  ];
  const native = { status: 'CANDIDATE', profile_id: DAMAGE_PROFILE.id,
    runtime_image_used: true, runtime_image_status: 'MATCHED_USED',
    runtime_image_sha256: DAMAGE_PROFILE.evidence_runtime_image_sha256,
    event_count: packets.length, native_full_success_count: packets.length,
    native_callback_f32_available_count: packets.length,
    native_callback_lookup_full_write_count: packets.length, events: packets };
  const result = compare(replay, native, intervals);
  assert.equal(result.status, 'CANDIDATE', result.error);
  assert.equal(result.event_count, 20);
  assert.equal(result.exact_endpoint_time_packets_excluded, 1);
  assert.equal(result.packets_outside_sampled_windows, 1);
  const first = result.events[0];
  assert.equal(first.comparisons.lookup_0x24.packet_count, 2);
  assert.equal(first.comparisons.lookup_0x24.summed_callback_f32_0x20_candidate, 15.25);
  assert.equal(first.comparisons.lookup_0x2c.packet_count, 0);
  assert.equal(first.comparisons.lookup_0x2c.rotated_key_control.packet_count, 2);
  assert.equal(first.comparisons.lookup_0x24.counter_differences.TOTAL_DAMAGE_TAKEN
    .anonymous_sum_minus_counter_delta, 0);
  assert.equal(first.semantic_effect_status, 'UNKNOWN');
  assert.equal(first.comparisons.lookup_0x24.key_role_status, 'UNKNOWN');
  assert.equal(result.positive_counter_comparisons['lookup_0x24/TOTAL_DAMAGE_TAKEN']
    .absolute_error_at_most_0_1, 1);
  native.runtime_image_used = false;
  assert.equal(compare(replay, native, intervals).status, 'INCONSISTENT');
});

test('missing native image retains usable damage windows and marks packet comparisons unavailable', () => {
  const result = decodeSemanticReplay(fixture(), {
    capabilities: [CAPABILITY, 'unit_apply_damage_packet'],
  });
  assert.equal(result.status, 'PARTIAL');
  assert.equal(result.capability_results[CAPABILITY].status, 'CANDIDATE');
  assert.equal(result.events[EVENTS].length, 20);
  assert.equal(result.candidate_associations.hero_damage_packet_keyframe_windows.status, 'UNAVAILABLE');
  assert.equal(result.events.hero_damage_packet_keyframe_window_candidates, undefined);
});
