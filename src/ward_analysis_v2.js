'use strict';

/**
 * Pure, replay-only filtering and perspective helpers for the additive Ward
 * V2 surface.
 *
 * This module deliberately does not import Match Details, timeline oracle, or
 * any validation artifact.  Rows are copied before enrichment/filtering and
 * source coordinate/team fields are never renamed or rewritten.
 */

const fs = require('node:fs');
const path = require('node:path');

const WARD_ANALYSIS_SCHEMA_VERSION = 2;
const WARD_ANALYSIS_VERSION = 'ward-analysis-v2';
const VALID_TEAMS = Object.freeze([100, 200]);
const TEAM_SIDE = Object.freeze({ 100: 'blue', 200: 'red' });
const OTHER_TEAM = Object.freeze({ 100: 200, 200: 100 });

const ORACLE_KEY_RE = /(?:^|_)(?:oracle|match_details|details|ground_truth|groundtruth|expected|truth)(?:_|$)/i;
const ORACLE_CONTAINER_KEYS = new Set([
  'oracle',
  'oracle_rows',
  'oracle_matches',
  'timeline_oracle_matches',
  'match_details',
  'details',
  'ground_truth',
  'expected',
]);

const TEAM_KEYS = Object.freeze([
  'raw_team',
  'owner_team',
  'caster_team',
  'source_team',
  'team',
  'team_id',
  'owner_team_id',
  'caster_team_id',
  'source_team_id',
  'teamId',
  'ownerTeam',
  'casterTeam',
]);
const PARTICIPANT_KEYS = Object.freeze([
  'owner_participant',
  'caster_participant_id',
  'source_participant_id',
  'participant',
  'participant_id',
  'participantId',
]);
const NETWORK_KEYS = Object.freeze([
  'owner_entity',
  'caster_network_id',
  'source_network_id',
  'network_id',
  'owner_network_id',
  'caster_entity',
]);
const CHAMPION_KEYS = Object.freeze([
  'owner_champion',
  'caster_champion',
  'source_champion',
  'champion',
  'champion_name',
  'casterChampion',
]);
const ROLE_KEYS = Object.freeze([
  'owner_role',
  'caster_role',
  'source_role',
  'participant_role',
  'role',
  'role_name',
]);
const SIDE_KEYS = Object.freeze(['side', 'team_side', 'raw_side']);
const WARD_TYPE_KEYS = Object.freeze([
  'ward_type',
  'ward_candidate_type',
  'type',
  'wardType',
]);
const TIME_MS_KEYS = Object.freeze([
  'timestamp_ms',
  'replay_time_ms',
  'time_ms',
  'timestamp',
  'cast_timestamp_ms',
  'spawn_timestamp_ms',
  'despawn_time_ms',
]);
const TIME_SECONDS_KEYS = Object.freeze([
  'replay_time_seconds',
  'time_seconds',
  'timestamp_seconds',
]);

function hasOwn(value, key) {
  return value !== null && typeof value === 'object'
    && Object.prototype.hasOwnProperty.call(value, key);
}

function cloneValue(value) {
  if (typeof structuredClone === 'function') {
    try { return structuredClone(value); } catch { /* fall through */ }
  }
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) return value.map(cloneValue);
  if (value && typeof value === 'object') {
    const result = {};
    for (const [key, item] of Object.entries(value)) result[key] = cloneValue(item);
    return result;
  }
  return value;
}

function finiteNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(number) ? number : null;
}

function canonicalTeam(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'number') {
    return value === 100 || value === 200 ? value : null;
  }
  const text = String(value).trim().toLowerCase();
  if (text === 'blue' || text === 'team_blue' || text === 'team1' || text === 'team_1') return 100;
  if (text === 'red' || text === 'team_red' || text === 'team2' || text === 'team_2') return 200;
  const number = Number(text);
  return number === 100 || number === 200 ? number : null;
}

function normalizeTeam(value, label = 'team') {
  const team = canonicalTeam(value);
  if (team === null) {
    throw new RangeError(`${label} must be team 100 or 200`);
  }
  return team;
}

function firstPresent(row, keys) {
  if (!row || typeof row !== 'object') return { key: null, value: null };
  for (const key of keys) {
    if (!hasOwn(row, key)) continue;
    const value = row[key];
    if (value !== null && value !== undefined && value !== '') return { key, value };
  }
  return { key: null, value: null };
}

function rawTeamFromRow(row) {
  return firstPresent(row, TEAM_KEYS).value;
}

function rowTeam(row) {
  return canonicalTeam(rawTeamFromRow(row));
}

function rowParticipantId(row) {
  const value = firstPresent(row, PARTICIPANT_KEYS).value;
  const number = finiteNumber(value);
  return Number.isInteger(number) && number >= 1 && number <= 10 ? number : null;
}

function rowNetworkId(row) {
  const value = firstPresent(row, NETWORK_KEYS).value;
  const number = finiteNumber(value);
  return Number.isInteger(number) ? number : null;
}

function rowChampion(row) {
  return firstPresent(row, CHAMPION_KEYS).value;
}

function rowRole(row) {
  return firstPresent(row, ROLE_KEYS).value;
}

function rowWardType(row) {
  return firstPresent(row, WARD_TYPE_KEYS).value;
}

function normalizeToken(value) {
  return String(value ?? '').trim().toLowerCase();
}

function normalizeChampion(value) {
  const text = normalizeToken(value);
  return text ? text : null;
}

function normalizeRole(value) {
  const text = normalizeToken(value).replace(/[\s-]+/g, '_');
  if (!text) return null;
  if (text === 'top' || text === 'top_lane') return 'top';
  if (text === 'jungle' || text === 'jg' || text === 'jungler') return 'jungle';
  if (text === 'mid' || text === 'middle' || text === 'middle_lane') return 'mid';
  if (text === 'adc' || text === 'bot' || text === 'bottom' || text === 'bottom_lane' || text === 'marksman') return 'adc';
  if (text === 'support' || text === 'supp' || text === 'utility' || text === 'utility_lane') return 'support';
  return text;
}

function normalizePerspective(value) {
  const text = normalizeToken(value);
  if (!text) return null;
  if (['ally', 'allies', 'allied', 'friendly', 'friend', 'self', 'own', 'ours'].includes(text)) return 'ally';
  if (['enemy', 'enemies', 'opponent', 'opponents', 'hostile', 'foe', 'foes', 'theirs'].includes(text)) return 'enemy';
  if (['unknown', 'unavailable', 'neutral', 'none', 'null'].includes(text)) return 'unknown';
  if (['all', 'any', '*'].includes(text)) return 'all';
  return text;
}

function normalizeSide(value) {
  const text = normalizeToken(value).replace(/[\s-]+/g, '_');
  if (!text) return null;
  if (['blue', 'team_blue', 'team1', 'team_1', '100'].includes(text)) return 'blue';
  if (['red', 'team_red', 'team2', 'team_2', '200'].includes(text)) return 'red';
  if (['ally', 'allied', 'friendly', 'self'].includes(text)) return 'ally';
  if (['enemy', 'opponent', 'hostile'].includes(text)) return 'enemy';
  if (['unknown', 'unavailable', 'neutral', 'none', 'null'].includes(text)) return 'unknown';
  return text;
}

function teamSide(team) {
  return TEAM_SIDE[team] ?? null;
}

function derivePerspective(teamOrRow, context = {}) {
  const team = typeof teamOrRow === 'object' && teamOrRow !== null
    ? rowTeam(teamOrRow)
    : canonicalTeam(teamOrRow);
  const allyTeam = canonicalTeam(context.allyTeam ?? context.ally_team ?? context.viewerTeam ?? context.viewer_team);
  if (team === null || allyTeam === null) return 'unknown';
  return team === allyTeam ? 'ally' : 'enemy';
}

function perspectiveForTeam(teamOrRow, context = {}) {
  return derivePerspective(teamOrRow, context);
}

function parseList(value) {
  if (value === null || value === undefined || value === '') return null;
  if (value instanceof Set) return [...value];
  if (Array.isArray(value)) return value.flatMap((item) => parseList(item) ?? []);
  if (typeof value === 'string') {
    const text = value.trim();
    if (!text) return null;
    // A comma-separated CLI value is convenient; champion names themselves do
    // not contain commas in the replay schemas.
    return text.split(',').map((item) => item.trim()).filter(Boolean);
  }
  return [value];
}

function normalizeFilterValues(value, normalizer = (item) => item) {
  const list = parseList(value);
  if (!list) return null;
  const normalized = list.map(normalizer).filter((item) => item !== null && item !== undefined && item !== '');
  if (normalized.length === 0 || normalized.some((item) => item === 'all' || item === '*')) return null;
  return [...new Set(normalized)];
}

function parseTeamFilter(value, label = 'team') {
  const list = parseList(value);
  if (!list) return null;
  return [...new Set(list.map((item) => normalizeTeam(item, label)))];
}

function firstDefined(...values) {
  return values.find((value) => value !== undefined && value !== null);
}

function parseTimeRange(value, unit = 'ms') {
  if (value === null || value === undefined || value === '') return [null, null];
  if (Array.isArray(value)) return [finiteNumber(value[0]), finiteNumber(value[1])];
  if (typeof value === 'object') {
    const low = firstDefined(value.min, value.from, value.start, value.lower);
    const high = firstDefined(value.max, value.to, value.end, value.upper);
    return [finiteNumber(low), finiteNumber(high)];
  }
  const text = String(value).trim();
  if (!text) return [null, null];
  const pieces = text.split(/\.\.|:|,/).map((part) => part.trim());
  if (pieces.length === 1) return [finiteNumber(pieces[0]), null];
  return [finiteNumber(pieces[0]), finiteNumber(pieces[1])];
}

function normalizeWardFilters(options = {}) {
  const source = options.filters && typeof options.filters === 'object'
    ? { ...options, ...options.filters }
    : options && typeof options === 'object' ? options : {};
  let viewerTeam = null;
  let allyTeam = null;
  const viewerRaw = firstDefined(source.viewerTeam, source.viewer_team, source.viewer?.team, source.viewer);
  const allyRaw = firstDefined(source.allyTeam, source.ally_team, source.ally?.team, source.ally);
  if (viewerRaw !== undefined && viewerRaw !== null && viewerRaw !== '') viewerTeam = normalizeTeam(viewerRaw, 'viewer team');
  if (allyRaw !== undefined && allyRaw !== null && allyRaw !== '') allyTeam = normalizeTeam(allyRaw, 'ally team');
  if (allyTeam === null && viewerTeam !== null) allyTeam = viewerTeam;

  const perspectiveRaw = firstDefined(
    source.perspective,
    source.relation,
    source.visibility,
    source.teamPerspective,
    source.team_perspective,
  );
  let perspective = normalizeFilterValues(perspectiveRaw, normalizePerspective);
  if (source.ally === true || source.allied === true) perspective = ['ally'];
  if (source.enemy === true || source.enemies === true) perspective = ['enemy'];
  if (perspective?.some((value) => value !== 'ally' && value !== 'enemy' && value !== 'unknown')) {
    throw new RangeError('perspective must be ally, enemy, or unknown');
  }
  if (perspective && perspective.some((value) => value === 'ally' || value === 'enemy') && allyTeam === null) {
    const error = new Error('viewer/ally team is required for ally/enemy perspective filtering');
    error.code = 'WARD_PERSPECTIVE_TEAM_REQUIRED';
    throw error;
  }

  const sideRaw = firstDefined(source.side, source.sides, source.teamSide, source.team_side);
  const side = normalizeFilterValues(sideRaw, normalizeSide);
  if (side?.some((value) => !['blue', 'red', 'ally', 'enemy', 'unknown'].includes(value))) {
    throw new RangeError('side must be blue, red, ally, enemy, or unknown');
  }
  if (side && side.some((value) => value === 'ally' || value === 'enemy') && allyTeam === null) {
    const error = new Error('viewer/ally team is required for ally/enemy side filtering');
    error.code = 'WARD_PERSPECTIVE_TEAM_REQUIRED';
    throw error;
  }

  // `--team 100|200` is an absolute team filter.  For ergonomic parity with
  // the research spec, `--team ally|enemy` is accepted as a perspective
  // alias, but it still requires an explicit viewer/ally team and never
  // rewrites the source row's numeric team.
  const teamRaw = firstDefined(source.team, source.teams, source.teamId, source.team_id);
  const teamItems = parseList(teamRaw);
  const absoluteTeamItems = [];
  const relativeTeamPerspectives = [];
  for (const item of teamItems ?? []) {
    const relative = normalizePerspective(item);
    if (relative === 'ally' || relative === 'enemy') relativeTeamPerspectives.push(relative);
    else absoluteTeamItems.push(item);
  }
  if (relativeTeamPerspectives.length > 0) {
    perspective = [...new Set([...(perspective ?? []), ...relativeTeamPerspectives])];
  }
  const team = absoluteTeamItems.length > 0
    ? [...new Set(absoluteTeamItems.map((item) => normalizeTeam(item, 'team')))]
    : null;
  if (perspective && perspective.some((value) => value === 'ally' || value === 'enemy') && allyTeam === null) {
    const error = new Error('viewer/ally team is required for ally/enemy perspective filtering');
    error.code = 'WARD_PERSPECTIVE_TEAM_REQUIRED';
    throw error;
  }
  const champion = normalizeFilterValues(
    firstDefined(source.champion, source.champions, source.casterChampion, source.caster_champion),
    normalizeChampion,
  );
  const role = normalizeFilterValues(
    firstDefined(source.role, source.roles),
    normalizeRole,
  );
  const wardType = normalizeFilterValues(
    firstDefined(source.wardType, source.ward_type, source.wardTypes, source.ward_types, source.type),
    (item) => normalizeToken(item).toUpperCase(),
  );

  let [minMs, maxMs] = parseTimeRange(firstDefined(source.timeMs, source.time_ms, source.ms), 'ms');
  minMs = firstDefined(source.minMs, source.fromMs, source.startMs, source.min_time_ms, minMs);
  maxMs = firstDefined(source.maxMs, source.toMs, source.endMs, source.max_time_ms, maxMs);
  let [minMinute, maxMinute] = parseTimeRange(firstDefined(source.minutes, source.minuteRange, source.timeMinutes), 'minutes');
  minMinute = firstDefined(source.minMinute, source.fromMinute, source.startMinute, source.min_minute, minMinute);
  maxMinute = firstDefined(source.maxMinute, source.toMinute, source.endMinute, source.max_minute, maxMinute);
  minMs = finiteNumber(minMs);
  maxMs = finiteNumber(maxMs);
  minMinute = finiteNumber(minMinute);
  maxMinute = finiteNumber(maxMinute);
  if (minMs !== null && maxMs !== null && minMs > maxMs) throw new RangeError('minimum time must not exceed maximum time');
  if (minMinute !== null && maxMinute !== null && minMinute > maxMinute) throw new RangeError('minimum minute must not exceed maximum minute');
  if ([minMs, maxMs, minMinute, maxMinute].some((value) => value !== null && value < 0)) {
    throw new RangeError('time bounds must be non-negative');
  }

  return Object.freeze({
    team,
    perspective,
    side,
    champion,
    role,
    ward_type: wardType,
    wardType,
    min_ms: minMs,
    max_ms: maxMs,
    minMs,
    maxMs,
    min_minute: minMinute,
    max_minute: maxMinute,
    minMinute,
    maxMinute,
    viewer_team: viewerTeam,
    ally_team: allyTeam,
    viewerTeam,
    allyTeam,
    players: source.players ?? source.roster ?? source.metadata?.players ?? null,
    include_unavailable: Boolean(source.includeUnavailable ?? source.include_unavailable),
  });
}

function rosterEntries(players) {
  if (!Array.isArray(players)) return [];
  return players.map((player, index) => {
    const participantId = finiteNumber(firstDefined(
      player.participant_id,
      player.participantId,
      player.metadata_index === undefined ? undefined : Number(player.metadata_index) + 1,
      player.index === undefined ? undefined : Number(player.index) + 1,
    ));
    const networkId = finiteNumber(firstDefined(
      player.network_id,
      player.networkId,
      player.champion_network_id,
      player.championNetworkId,
    ));
    return {
      ...player,
      _index: index,
      _participant_id: Number.isInteger(participantId) ? participantId : null,
      _network_id: Number.isInteger(networkId) ? networkId : null,
      _team: canonicalTeam(firstDefined(player.team_id, player.teamId, player.team, player.side)),
      _champion: firstDefined(player.champion, player.caster_champion, player.name),
      _role: normalizeRole(firstDefined(player.role, player.position, player.lane)),
    };
  });
}

function findRosterPlayer(row, players) {
  const entries = rosterEntries(players);
  if (entries.length === 0) return null;
  const participant = rowParticipantId(row);
  if (participant !== null) {
    const found = entries.find((entry) => entry._participant_id === participant);
    if (found) return found;
  }
  const network = rowNetworkId(row);
  if (network !== null) {
    const found = entries.find((entry) => entry._network_id === network);
    if (found) return found;
  }
  const champion = normalizeChampion(rowChampion(row));
  const team = rowTeam(row);
  if (champion !== null) {
    const found = entries.find((entry) => normalizeChampion(entry._champion) === champion
      && (team === null || entry._team === team));
    if (found) return found;
  }
  return null;
}

function rowTimestampMs(row) {
  if (!row || typeof row !== 'object') return null;
  for (const key of TIME_MS_KEYS) {
    const value = finiteNumber(row[key]);
    if (value !== null) return value;
  }
  for (const key of TIME_SECONDS_KEYS) {
    const value = finiteNumber(row[key]);
    if (value !== null) return value * 1000;
  }
  // Existing ward heatmap rows expose `minute` alongside timestamp.  A minute
  // is only a fallback because it intentionally has lower precision.
  const minute = finiteNumber(row.minute);
  return minute === null ? null : minute * 60000;
}

function rowMinute(row, timestampMs = rowTimestampMs(row)) {
  const explicit = finiteNumber(row?.minute);
  if (explicit !== null) return explicit;
  return timestampMs === null ? null : Math.floor(timestampMs / 60000);
}

function annotateWardRow(row, options = {}) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) {
    throw new TypeError('ward rows must be objects');
  }
  const filters = options._normalizedFilters || normalizeWardFilters(options);
  const clean = stripOracleFields(row);
  const rosterPlayer = findRosterPlayer(clean, filters.players);
  const rawTeam = rawTeamFromRow(clean);
  const sourceTeam = canonicalTeam(rawTeam);
  const derivedTeam = sourceTeam ?? rosterPlayer?._team ?? null;
  const rawChampion = rowChampion(clean);
  const derivedChampion = rawChampion ?? rosterPlayer?._champion ?? null;
  const rawRole = rowRole(clean);
  const derivedRole = normalizeRole(rawRole) ?? rosterPlayer?._role ?? null;
  const rawSide = firstPresent(clean, SIDE_KEYS).value;
  const derivedSide = normalizeSide(rawSide) === 'ally' || normalizeSide(rawSide) === 'enemy'
    ? normalizeSide(rawSide)
    : teamSide(derivedTeam);
  const rawPerspective = hasOwn(clean, 'perspective') ? clean.perspective : null;
  const derivedPerspective = derivedTeam === null
    ? 'unknown'
    : derivePerspective(derivedTeam, filters);
  const timestampMs = rowTimestampMs(clean);

  const output = cloneValue(clean);
  // These fields are additive.  Existing source fields (including `team`,
  // `owner_team`, coordinates, and an input perspective) remain untouched.
  if (!hasOwn(output, 'raw_team')) output.raw_team = rawTeam;
  if (!hasOwn(output, 'canonical_team')) output.canonical_team = derivedTeam;
  // `ward_events` commonly stores the owner as `owner_team`; expose a
  // canonical numeric `team` alias additively so downstream research code can
  // use one stable column while the original owner/source fields remain
  // untouched.
  if (!hasOwn(output, 'team')) output.team = derivedTeam;
  if (!hasOwn(output, 'raw_perspective')) output.raw_perspective = rawPerspective;
  if (filters.viewerTeam !== null && !hasOwn(output, 'viewer_team')) output.viewer_team = filters.viewerTeam;
  if (filters.allyTeam !== null && !hasOwn(output, 'ally_team')) output.ally_team = filters.allyTeam;
  if (!hasOwn(output, 'perspective_team')) {
    output.perspective_team = filters.viewerTeam ?? filters.allyTeam ?? null;
  }
  if (!hasOwn(output, 'derived_perspective_team')) {
    output.derived_perspective_team = filters.viewerTeam ?? filters.allyTeam ?? null;
  }
  if (!hasOwn(output, 'perspective_participant')) {
    output.perspective_participant = options.perspectiveParticipant
      ?? options.perspective_participant
      ?? null;
  }
  if (!hasOwn(output, 'derived_perspective_participant')) {
    output.derived_perspective_participant = options.perspectiveParticipant
      ?? options.perspective_participant
      ?? null;
  }
  // Preserve a source perspective field verbatim.  Explicit viewer/ally
  // context is represented by additive derived fields below.
  if (!hasOwn(output, 'perspective')) {
    output.perspective = derivedPerspective;
  }
  if (!hasOwn(output, 'derived_perspective')) output.derived_perspective = derivedPerspective;
  if (!hasOwn(output, 'perspective_status')) {
    output.perspective_status = derivedPerspective === 'unknown' ? 'UNAVAILABLE' : 'VERIFIED_DERIVED';
  }
  if (!hasOwn(output, 'side')) output.side = derivedSide;
  if (!hasOwn(output, 'derived_side')) output.derived_side = derivedSide;
  if (!hasOwn(output, 'role') && derivedRole !== null) output.role = derivedRole;
  if (!hasOwn(output, 'derived_role')) output.derived_role = derivedRole;
  if (!hasOwn(output, 'champion') && derivedChampion !== null) output.champion = derivedChampion;
  if (!hasOwn(output, 'derived_champion')) output.derived_champion = derivedChampion;
  if (!hasOwn(output, 'timestamp_ms') && timestampMs !== null) output.timestamp_ms = timestampMs;
  if (!hasOwn(output, 'minute') && timestampMs !== null) output.minute = Math.floor(timestampMs / 60000);
  return output;
}

function stripOracleFields(value) {
  if (Array.isArray(value)) return value.map(stripOracleFields);
  if (!value || typeof value !== 'object' || Buffer.isBuffer(value)) return cloneValue(value);
  const output = {};
  for (const [key, item] of Object.entries(value)) {
    const lower = key.toLowerCase();
    if (ORACLE_CONTAINER_KEYS.has(lower) || ORACLE_KEY_RE.test(lower)) continue;
    output[key] = stripOracleFields(item);
  }
  return output;
}

function valueSetMatches(value, accepted, normalizer = normalizeToken) {
  if (accepted === null || accepted === undefined) return true;
  const normalized = normalizer(value);
  if (normalized === null || normalized === undefined || normalized === '') return accepted.includes('unknown');
  return accepted.includes(normalized);
}

function matchesTime(row, filters) {
  const timestampMs = rowTimestampMs(row);
  if (filters.minMs !== null && (timestampMs === null || timestampMs < filters.minMs)) return false;
  if (filters.maxMs !== null && (timestampMs === null || timestampMs > filters.maxMs)) return false;
  if (filters.minMinute !== null || filters.maxMinute !== null) {
    if (timestampMs === null) return false;
    const lower = filters.minMinute === null ? null : filters.minMinute * 60000;
    // Minute bounds are inclusive buckets: max minute 2 includes [2:00, 3:00).
    const upper = filters.maxMinute === null ? null : (filters.maxMinute + 1) * 60000;
    if (lower !== null && timestampMs < lower) return false;
    if (upper !== null && timestampMs >= upper) return false;
  }
  return true;
}

function matchesWardRow(row, filtersOrOptions = {}) {
  const filters = filtersOrOptions._normalizedFilters
    ? filtersOrOptions._normalizedFilters
    : normalizeWardFilters(filtersOrOptions);
  const team = rowTeam(row) ?? canonicalTeam(row.canonical_team) ?? null;
  if (filters.team !== null && (team === null || !filters.team.includes(team))) return false;
  const perspective = normalizePerspective(
    (filters.viewerTeam !== null || filters.allyTeam !== null)
      ? derivePerspective(team, filters)
      : (row.derived_perspective ?? row.perspective),
  ) ?? 'unknown';
  const side = normalizeSide(row.derived_side ?? row.side) ?? teamSide(team) ?? 'unknown';
  if (filters.perspective !== null && !valueSetMatches(perspective, filters.perspective, normalizePerspective)) return false;
  if (filters.side !== null) {
    const sideMatches = filters.side.some((wanted) => (
      wanted === 'ally' || wanted === 'enemy' ? wanted === perspective : wanted === side
    ));
    if (!sideMatches) return false;
  }
  const champion = normalizeChampion(firstPresent(row, CHAMPION_KEYS).value ?? row.derived_champion);
  if (filters.champion !== null && !valueSetMatches(champion, filters.champion, normalizeChampion)) return false;
  const role = normalizeRole(firstPresent(row, ROLE_KEYS).value ?? row.derived_role);
  if (filters.role !== null && !valueSetMatches(role, filters.role, normalizeRole)) return false;
  const wardType = normalizeToken(firstPresent(row, WARD_TYPE_KEYS).value).toUpperCase();
  if (filters.wardType !== null && !valueSetMatches(wardType, filters.wardType, (item) => normalizeToken(item).toUpperCase())) return false;
  return matchesTime(row, filters);
}

function filterWardRows(input, options = {}) {
  const rows = extractWardRows(input, options);
  const filters = normalizeWardFilters(options);
  return rows
    .map((row) => annotateWardRow(row, { ...options, _normalizedFilters: filters }))
    .filter((row) => matchesWardRow(row, filters));
}

function filterWardEvents(input, options = {}) {
  return filterWardRows(input, options);
}

function selectWardRows(input, options = {}) {
  return filterWardRows(input, options);
}

function extractWardRows(input, options = {}) {
  if (Array.isArray(input)) return input.filter((row) => row && typeof row === 'object');
  if (input === null || input === undefined) return [];
  if (typeof input === 'string') return parseWardText(input, options.sourceName || '<text>');
  if (typeof input !== 'object') throw new TypeError('ward input must be an array, object, JSON text, or JSONL text');
  const requested = options.collection || options.collectionKey;
  const keys = requested ? [requested] : [
    'ward_events',
    'wardEvents',
    'rows',
    'events',
    'ward_cast_candidates',
    'wardCastCandidates',
    'ward_heatmap_input',
    'wardHeatmapInput',
    'data',
  ];
  for (const key of keys) {
    if (!hasOwn(input, key)) continue;
    const value = input[key];
    if (Array.isArray(value)) return value.filter((row) => row && typeof row === 'object');
    if (value && typeof value === 'object') {
      const nested = extractWardRows(value, options);
      if (nested.length > 0) return nested;
    }
  }
  // A single Ward row is also a valid input document.
  if (looksLikeWardRow(input)) return [input];
  return [];
}

function looksLikeWardRow(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return ['ward_type', 'ward_candidate_type', 'owner_team', 'caster_team', 'cast_target_x', 'timestamp_ms', 'event_type']
    .some((key) => hasOwn(value, key));
}

function parseWardText(text, sourceName = '<text>') {
  const raw = String(text ?? '').replace(/^\uFEFF/, '').trim();
  if (!raw) return [];
  try {
    return extractWardRows(JSON.parse(raw), { sourceName });
  } catch (jsonError) {
    const rows = [];
    const errors = [];
    for (const [index, line] of raw.split(/\r?\n/).entries()) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) rows.push(...parsed);
        else if (parsed && typeof parsed === 'object') rows.push(parsed);
      } catch (error) {
        errors.push(`line ${index + 1}: ${error.message}`);
      }
    }
    if (errors.length > 0) {
      const error = new Error(`could not parse Ward JSON/JSONL input ${sourceName}: ${errors[0]}`);
      error.code = 'WARD_INPUT_INVALID_JSON';
      error.cause = jsonError;
      throw error;
    }
    return rows.filter((row) => row && typeof row === 'object');
  }
}

function readWardInput(inputPath, options = {}) {
  if (inputPath === '-' || inputPath === null || inputPath === undefined) {
    return parseWardText(fs.readFileSync(0, 'utf8'), '<stdin>');
  }
  const resolved = path.resolve(String(inputPath));
  const text = fs.readFileSync(resolved, 'utf8');
  return parseWardText(text, resolved);
}

function wardDocumentContext(document) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) return {};
  const metadata = document.metadata ?? document.replay?.metadata ?? null;
  const players = document.players
    ?? document.roster
    ?? metadata?.players
    ?? document.replay?.players
    ?? null;
  return { players };
}

function parseWardDocument(input, options = {}) {
  const document = typeof input === 'string'
    ? (() => {
      const raw = String(input).replace(/^\uFEFF/, '').trim();
      try { return JSON.parse(raw); } catch { return null; }
    })()
    : input;
  return {
    rows: extractWardRows(input, options),
    ...wardDocumentContext(document),
    document,
  };
}

function readWardDocument(inputPath, options = {}) {
  if (inputPath === '-' || inputPath === null || inputPath === undefined) {
    const raw = fs.readFileSync(0, 'utf8');
    return parseWardDocument(raw, { ...options, sourceName: '<stdin>' });
  }
  const resolved = path.resolve(String(inputPath));
  const raw = fs.readFileSync(resolved, 'utf8');
  return parseWardDocument(raw, { ...options, sourceName: resolved });
}

function countBy(rows, getter) {
  const counts = {};
  for (const row of rows) {
    const value = getter(row);
    const key = value === null || value === undefined || value === '' ? 'unknown' : String(value);
    counts[key] = (counts[key] || 0) + 1;
  }
  return counts;
}

function serializableFilters(filters) {
  return {
    team: filters.team,
    perspective: filters.perspective,
    side: filters.side,
    champion: filters.champion,
    role: filters.role,
    ward_type: filters.wardType,
    min_ms: filters.minMs,
    max_ms: filters.maxMs,
    min_minute: filters.minMinute,
    max_minute: filters.maxMinute,
    viewer_team: filters.viewerTeam,
    ally_team: filters.allyTeam,
  };
}

function analyzeWardEvents(input, options = {}) {
  const sourceRows = extractWardRows(input, options);
  const filters = normalizeWardFilters(options);
  const rows = sourceRows
    .map((row) => annotateWardRow(row, { ...options, _normalizedFilters: filters }))
    .filter((row) => matchesWardRow(row, filters));
  return {
    schema_version: WARD_ANALYSIS_SCHEMA_VERSION,
    analysis: WARD_ANALYSIS_VERSION,
    status: 'REPLAY_ROWS_FILTERED',
    input_row_count: sourceRows.length,
    row_count: rows.length,
    rows,
    ward_events: rows,
    filters: serializableFilters(filters),
    perspective: {
      viewer_team: filters.viewerTeam,
      ally_team: filters.allyTeam,
      policy: 'ally/enemy is derived only from the explicit viewer/ally team; no team inference from oracle data',
    },
    counts: {
      by_team: countBy(rows, (row) => row.canonical_team),
      by_perspective: countBy(rows, (row) => row.perspective),
      by_side: countBy(rows, (row) => row.derived_side),
      by_champion: countBy(rows, (row) => row.champion ?? row.derived_champion),
      by_role: countBy(rows, (row) => row.role ?? row.derived_role),
      by_ward_type: countBy(rows, (row) => row.ward_type ?? row.ward_candidate_type),
    },
    provenance: {
      fact_source: 'ROFL_REPLAY_PACKET_BYTES_OR_REPLAY_DERIVED_ROWS',
      oracle_policy: 'NOT_USED',
      coordinate_policy: 'RAW_COORDINATE_FIELDS_PRESERVED_NO_RENAMING',
      team_policy: 'RAW_TEAM_FIELDS_PRESERVED; canonical_team and perspective are additive',
    },
  };
}

function buildWardAnalysis(input, options = {}) {
  return analyzeWardEvents(input, options);
}

function csvCell(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') value = JSON.stringify(value);
  const text = String(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeWardAnalysis(outputPath, analysisOrRows, options = {}) {
  if (!outputPath) throw new TypeError('output path is required');
  const analysis = Array.isArray(analysisOrRows)
    ? analyzeWardEvents(analysisOrRows, options)
    : analysisOrRows && typeof analysisOrRows === 'object' && Array.isArray(analysisOrRows.rows)
      ? analysisOrRows
      : analyzeWardEvents(analysisOrRows, options);
  const outputTextFormat = String(options.format || (String(outputPath) === '-' ? 'jsonl' : path.extname(String(outputPath)).slice(1)) || 'jsonl').toLowerCase();
  if (String(outputPath) === '-') {
    return formatWardOutput(outputTextFormat, analysis, options);
  }
  const resolved = path.resolve(String(outputPath));
  const directory = path.dirname(resolved);
  fs.mkdirSync(directory, { recursive: true });
  const text = formatWardOutput(outputTextFormat, analysis, options);
  fs.writeFileSync(resolved, text, 'utf8');
  return resolved;
}

function formatWardOutput(format, analysis, options = {}) {
  if (format === 'json' || format === 'json5') {
    return `${JSON.stringify(options.rowsOnly ? analysis.rows : analysis, null, 2)}\n`;
  }
  if (format === 'csv') {
    const rows = analysis.rows || [];
    const columns = options.columns || unionColumns(rows);
    return `${columns.map(csvCell).join(',')}\n${rows.map((row) => columns.map((column) => csvCell(row[column])).join(',')).join('\n')}${rows.length ? '\n' : ''}`;
  }
  // JSONL is intentionally rows-only: it composes with the existing V2
  // datasets and keeps the analysis envelope separate from event facts.
  const rows = analysis.rows || [];
  return rows.length ? `${rows.map((row) => JSON.stringify(row)).join('\n')}\n` : '';
}

function unionColumns(rows) {
  const columns = [];
  const seen = new Set();
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      if (!seen.has(key)) { seen.add(key); columns.push(key); }
    }
  }
  return columns;
}

function writeWardRows(outputPath, rows, options = {}) {
  return writeWardAnalysis(outputPath, Array.isArray(rows) ? analyzeWardEvents(rows, options) : rows, options);
}

module.exports = {
  WARD_ANALYSIS_SCHEMA_VERSION,
  WARD_ANALYSIS_VERSION,
  VALID_TEAMS,
  TEAM_SIDE,
  OTHER_TEAM,
  canonicalTeam,
  normalizeTeam,
  normalizeRole,
  normalizePerspective,
  normalizeSide,
  teamSide,
  derivePerspective,
  perspectiveForTeam,
  normalizeWardFilters,
  rowTimestampMs,
  rowMinute,
  annotateWardRow,
  enrichWardRow: annotateWardRow,
  matchesWardRow,
  extractWardRows,
  parseWardText,
  readWardInput,
  parseWardDocument,
  readWardDocument,
  filterWardRows,
  filterWardEvents,
  selectWardRows,
  analyzeWardEvents,
  buildWardAnalysis,
  writeWardAnalysis,
  writeWardRows,
  stripOracleFields,
};
