'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  analyzeWardEvents,
  derivePerspective,
  filterWardRows,
  normalizeWardFilters,
  parseWardText,
  readWardInput,
  writeWardAnalysis,
} = require('../src/ward_analysis_v2');

function rows() {
  return [
    {
      event_type: 'ward_cast',
      timestamp_ms: 5_000,
      owner_participant: 1,
      owner_champion: 'Lulu',
      owner_team: 100,
      ward_type: 'YELLOW_TRINKET',
      cast_target_x: 10,
      cast_target_y: 20,
      cast_target_z: 30,
      oracle_team: 200,
      timeline_oracle_match: { timestamp: 123 },
    },
    {
      event_type: 'ward_cast',
      timestamp_ms: 65_000,
      owner_participant: 6,
      owner_champion: 'Ahri',
      team: 200,
      ward_type: 'CONTROL_WARD',
      cast_target_x: 40,
      cast_target_y: 50,
      cast_target_z: 60,
    },
    {
      event_type: 'ward_cast',
      replay_time_ms: 125_000,
      caster_participant_id: 2,
      caster_champion: 'Jinx',
      caster_team_id: 100,
      ward_candidate_type: 'BLUE_TRINKET',
      cast_target_x: 70,
      cast_target_y: 80,
      cast_target_z: 90,
    },
  ];
}

const roster = [
  { metadata_index: 0, champion: 'Lulu', team_id: 100, role: 'support' },
  { metadata_index: 1, champion: 'Jinx', team_id: 100, role: 'adc' },
  { metadata_index: 5, champion: 'Ahri', team_id: 200, role: 'mid' },
];

test('Ward analysis preserves raw teams/coordinates and derives explicit perspective', () => {
  const input = rows();
  const output = filterWardRows(input, { viewerTeam: 100, players: roster });
  assert.equal(output.length, 3);
  assert.equal(output[0].owner_team, 100);
  assert.equal(output[0].raw_team, 100);
  assert.equal(output[0].perspective, 'ally');
  assert.equal(output[1].team, 200);
  assert.equal(output[1].raw_team, 200);
  assert.equal(output[1].perspective, 'enemy');
  assert.deepEqual(
    [output[0].cast_target_x, output[0].cast_target_y, output[0].cast_target_z],
    [10, 20, 30],
  );
  assert.equal(Object.hasOwn(output[0], 'oracle_team'), false);
  assert.equal(Object.hasOwn(output[0], 'timeline_oracle_match'), false);
  assert.equal(input[0].oracle_team, 200, 'pure selector must not mutate input');
});

test('Team, ally/enemy, side, champion, role, ward type, and ms filters compose', () => {
  const input = rows();
  assert.equal(filterWardRows(input, { team: 100 }).length, 2);
  assert.equal(filterWardRows(input, { team: 'ally', viewerTeam: 100 }).length, 2);
  assert.equal(filterWardRows(input, { team: 'enemy', viewerTeam: 100 }).length, 1);
  assert.equal(filterWardRows(input, { viewer_team: 100, perspective: 'enemy' }).length, 1);
  assert.equal(filterWardRows(input, { viewer_team: 100, side: 'ally' }).length, 2);
  assert.equal(filterWardRows(input, { champion: 'ahri' }).length, 1);
  assert.equal(filterWardRows(input, { role: 'support', players: roster }).length, 1);
  assert.equal(filterWardRows(input, { ward_type: 'control_ward' }).length, 1);
  assert.equal(filterWardRows(input, { minMs: 5_000, maxMs: 65_000 }).length, 2);
});

test('Minute bounds use inclusive minute buckets', () => {
  const output = filterWardRows(rows(), { minMinute: 1, maxMinute: 1 });
  assert.equal(output.length, 1);
  assert.equal(output[0].timestamp_ms, 65_000);
});

test('Ally/enemy filtering requires an explicit viewer or ally team', () => {
  assert.throws(
    () => normalizeWardFilters({ perspective: 'enemy' }),
    (error) => error.code === 'WARD_PERSPECTIVE_TEAM_REQUIRED',
  );
  assert.throws(
    () => normalizeWardFilters({ team: 'enemy' }),
    (error) => error.code === 'WARD_PERSPECTIVE_TEAM_REQUIRED',
  );
  assert.equal(derivePerspective(200, { viewerTeam: 100 }), 'enemy');
  assert.equal(derivePerspective(100, { ally_team: 100 }), 'ally');
  assert.equal(derivePerspective(100, {}), 'unknown');
});

test('JSON and JSONL helpers select replay rows without oracle input', () => {
  const document = JSON.stringify({
    metadata: { players: roster },
    ward_events: rows(),
    timeline_oracle_matches: [{ should_not_be_read: true }],
  });
  assert.equal(parseWardText(document).length, 3);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ward-analysis-v2-'));
  const input = path.join(dir, 'rows.jsonl');
  fs.writeFileSync(input, rows().map((row) => JSON.stringify(row)).join('\n') + '\n');
  assert.equal(readWardInput(input).length, 3);
  const analysis = analyzeWardEvents(rows(), { viewerTeam: 100, players: roster, perspective: 'enemy' });
  const out = path.join(dir, 'filtered.jsonl');
  writeWardAnalysis(out, analysis);
  const written = fs.readFileSync(out, 'utf8').trim().split(/\r?\n/).filter(Boolean).map(JSON.parse);
  assert.equal(written.length, 1);
  assert.equal(written[0].perspective, 'enemy');
});
