'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const { resolveBuildProfile, resolveCapability } = require('../src/build_registry');
const {
  decodeSemanticReplay,
  getHeroDeathCandidates,
  getHeroDeaths,
} = require('../src/semantic_api');
const { replayFromChunks } = require('./helpers/synthetic_replay');

const BUILD = '16.19.820.7193';

function packet(packetId, timestampMs, rawParam, payloadLength) {
  const header = Buffer.alloc(12);
  header[0] = 0x10;
  header.writeFloatLE(timestampMs / 1000, 1);
  header[5] = payloadLength;
  header.writeUInt16LE(packetId, 6);
  header.writeUInt32LE(rawParam >>> 0, 8);
  return Buffer.concat([header, Buffer.alloc(payloadLength, packetId & 0xff)]);
}

function replayWithTriad(kind, options = {}) {
  const routes = kind === 'HN'
    ? { first: 0x02d6, second: 0x04d9, third: 0x0326, thirdLength: 20 }
    : { first: 0x0259, second: 0x0438, third: 0x0396, thirdLength: 3 };
  const rows = [];
  for (const [timestampMs, participantId] of [
    [1000, 1], [options.duplicateTimestamp ? 1000 : 2000, 4],
  ]) {
    const rawParam = 0x400000ad + participantId;
    rows.push(packet(routes.first, timestampMs, rawParam, 5));
    rows.push(packet(routes.second, timestampMs, rawParam, 37));
    rows.push(packet(routes.third, timestampMs,
      kind === 'HN' ? 0 : (rawParam + 0x100), routes.thirdLength));
  }
  if (options.removeLastCorroboration) rows.pop();
  const replay = replayFromChunks([{ body: Buffer.concat(rows) }], BUILD);
  replay.tail.stats = Array.from({ length: 10 }, (_, index) => ({
    SKIN: `Champion${index + 1}`,
    TEAM: index < 5 ? '100' : '200',
    NUM_DEATHS: String(index === 0 || index === 3 ? 1 : 0),
  }));
  return replay;
}

test('16.19 build and candidate capability are exact-build bound', () => {
  assert.equal(resolveBuildProfile(BUILD).profile.release_status, 'EXPERIMENTAL_CANDIDATE');
  assert.equal(resolveCapability(BUILD, 'hero_death').status, 'CANDIDATE');
  assert.equal(resolveCapability(BUILD, 'hero_path').status, 'UNAVAILABLE');
  assert.equal(resolveBuildProfile('16.19.821.7343').status, 'SUPPORTED');
  assert.equal(resolveCapability('16.19.821.7343', 'hero_death').status, 'CANDIDATE');
  assert.equal(resolveBuildProfile('16.19.822.0000').status, 'UNSUPPORTED_VERSION');
});

for (const kind of ['HN', 'KR']) {
  test(`${kind} death triad stays in experimental output with packet provenance`, () => {
    const replay = replayWithTriad(kind);
    const decoded = decodeSemanticReplay(replay, {
      capabilities: ['hero_death'], runtimeImagePath: 'not-used.bin',
    });
    assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
    assert.equal(decoded.game_version, BUILD);
    assert.equal(decoded.capability_results.hero_death.status, 'CANDIDATE');
    assert.equal(decoded.capability_results.hero_death.event_count, 2);
    assert.equal(decoded.capability_results.hero_death.runtime_image_used, false);
    assert.equal(decoded.capability_results.hero_death.runtime_image_status, 'PROVIDED_NOT_USED');
    assert.equal(decoded.runtime_image_used, false);
    assert.equal(decoded.events.death_events, undefined);
    assert.deepEqual(getHeroDeaths(decoded), []);
    const candidates = getHeroDeathCandidates(decoded);
    assert.equal(candidates.length, 2);
    assert.equal(candidates[0].victim_participant_id, 1);
    assert.equal(candidates[1].victim_participant_id, 4);
    assert.equal(candidates[0].victim_network_id, null);
    assert.equal(candidates[0].killer_network_id, null);
    assert.equal(candidates[0].confidence, 'CANDIDATE');
    assert.equal(candidates[0].raw_packet_refs.length, 3);
    assert.equal(candidates[0].raw_packet_refs[0].replay_sha256, replay.source_sha256);
    if (kind === 'HN') {
      assert.equal(candidates[0].raw_packet_ref.packet_id, 0x04d9);
      assert.equal(candidates[0].raw_packet_ref.role, 'hero_die');
      assert.equal(candidates[0].raw_packet_refs[1].role, 'death_timer_update');
    }
    assert.match(candidates[0].build_profile, new RegExp(`-${kind.toLowerCase()}-`));
  });
}

test('unknown 16.19 route set has no selected experimental profile', () => {
  const replay = replayFromChunks([{ body: packet(0x0123, 1000, 0, 1) }], BUILD);
  const decoded = decodeSemanticReplay(replay, { capabilities: ['hero_death'] });
  assert.equal(decoded.status, 'PROFILE_UNAVAILABLE');
  assert.equal(decoded.capability_results.hero_death.status, 'PROFILE_UNAVAILABLE');
  assert.equal(decoded.capability_results.hero_death.event_count, null);
  assert.equal(decoded.events, null);
  assert.equal(getHeroDeathCandidates(decoded), null);
});

test('a matched route triad fails closed on missing evidence or death-count mismatch', () => {
  const missing = decodeSemanticReplay(replayWithTriad('HN', {
    removeLastCorroboration: true,
  }), { capabilities: ['hero_death'] });
  assert.equal(missing.status, 'DECODE_FAILED');
  assert.equal(missing.events, null);
  assert.match(missing.capability_results.hero_death.error, /triad counts differ/);

  const replay = replayWithTriad('KR');
  replay.tail.stats[0].NUM_DEATHS = '2';
  const mismatch = decodeSemanticReplay(replay, { capabilities: ['hero_death'] });
  assert.equal(mismatch.status, 'DECODE_FAILED');
  assert.equal(mismatch.events, null);
  assert.match(mismatch.capability_results.hero_death.error, /do not match/);

  replay.tail.stats[0].NUM_DEATHS = null;
  const absent = decodeSemanticReplay(replay, { capabilities: ['hero_death'] });
  assert.equal(absent.status, 'MISSING_INPUT');
  assert.equal(absent.events, null);
  assert.match(absent.capability_results.hero_death.missing_input, /NUM_DEATHS/);
});

test('HN param-zero corroboration is grouped for same-millisecond deaths', () => {
  const decoded = decodeSemanticReplay(replayWithTriad('HN', {
    duplicateTimestamp: true,
  }), { capabilities: ['hero_death'] });
  assert.equal(decoded.status, 'EXPERIMENTAL_CANDIDATE');
  const candidates = getHeroDeathCandidates(decoded);
  assert.equal(candidates.length, 2);
  for (const event of candidates) {
    assert.equal(event.corroboration_assignment, 'TIMESTAMP_GROUP_UNRESOLVED');
    assert.equal(event.corroborating_packet_group_size, 2);
    assert.equal(event.raw_packet_refs.length, 4);
    assert.deepEqual(event.raw_packet_refs.slice(2).map((ref) => ref.packet_id),
      [0x0326, 0x0326]);
    assert.ok(event.raw_packet_refs.slice(2).every((ref) =>
      ref.role === 'corroborating_timestamp_group'));
  }
  assert.deepEqual(candidates[0].raw_packet_refs.slice(2),
    candidates[1].raw_packet_refs.slice(2));
});

test('partial requests retain a successful candidate and state unsupported capability', () => {
  const decoded = decodeSemanticReplay(replayWithTriad('HN'), {
    capabilities: ['hero_death', 'hero_path'],
  });
  assert.equal(decoded.status, 'PARTIAL');
  assert.equal(decoded.capability_results.hero_death.status, 'CANDIDATE');
  assert.equal(decoded.capability_results.hero_path.status, 'UNSUPPORTED');
  assert.equal(decoded.events.hero_death_candidates.length, 2);
});
