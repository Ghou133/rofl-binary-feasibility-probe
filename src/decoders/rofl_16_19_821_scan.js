'use strict';

const { analyzeReplay } = require('../analysis');
const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');

const BUILD = '16.19.821.7343';
const CAPABILITIES = new Set([
  'hero_death', 'hero_death_timer', 'hero_deaths_snapshot', 'hero_champion_kills_snapshot',
  'hero_assists_snapshot', 'hero_missions_minions_killed_snapshot',
  'hero_ward_stats_snapshot', 'hero_missions_cannon_minions_killed_snapshot',
  'hero_experience_snapshot', 'hero_vision_score_snapshot',
  'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot',
  'hero_level_state', 'hero_respawn',
]);
const DEATH_ROUTES = new Set([0x0259, 0x0438, 0x031b, 0x03d4]);
const RESPAWN_ROUTES = new Set([0x0048, 0x018d]);
const SCAN_SOURCE = new WeakMap();

function copyRow(block, chunk) {
  // A framed block's payload points into a decompressed chunk. Retain only
  // selected packet bytes, independent of later mutation of that chunk.
  return {
    block: {
      offset: block.offset,
      payload_offset: block.payload_offset,
      payload_length: block.payload_length,
      payload: Buffer.from(block.payload),
      timestamp_ms: block.timestamp_ms,
      packet_id: block.packet_id,
      param: block.param,
    },
    chunk: {
      index: chunk.index,
      chunk_id: chunk.chunk_id,
      stream: chunk.stream,
      stream_tag: chunk.stream_tag,
      offset: chunk.offset,
    },
  };
}

function create821ScanCollector(replay, selectedCapabilities) {
  if (replay?.header?.version !== BUILD) {
    throw new RangeError(`821 route scan requires exact build ${BUILD}`);
  }
  const selected = new Set(selectedCapabilities);
  if (selected.size === 0 || [...selected].some((name) => !CAPABILITIES.has(name))) {
    throw new RangeError('821 route scan requires one or more supported capabilities');
  }
  const heroStatsRows = [];
  const rows = {
    hero_death: [],
    hero_death_timer: [],
    hero_respawn: [],
    hero_deaths_snapshot: heroStatsRows,
    hero_champion_kills_snapshot: heroStatsRows,
    hero_assists_snapshot: heroStatsRows,
    hero_missions_minions_killed_snapshot: heroStatsRows,
    hero_ward_stats_snapshot: heroStatsRows,
    hero_missions_cannon_minions_killed_snapshot: heroStatsRows,
    hero_experience_snapshot: heroStatsRows,
    hero_vision_score_snapshot: heroStatsRows,
    hero_gold_earned_snapshot: heroStatsRows,
    hero_gold_spent_snapshot: heroStatsRows,
    hero_level_state: [],
  };
  const selectsHeroStats = selected.has('hero_deaths_snapshot')
    || selected.has('hero_champion_kills_snapshot')
    || selected.has('hero_assists_snapshot')
    || selected.has('hero_missions_minions_killed_snapshot')
    || selected.has('hero_ward_stats_snapshot')
    || selected.has('hero_missions_cannon_minions_killed_snapshot')
    || selected.has('hero_experience_snapshot')
    || selected.has('hero_vision_score_snapshot')
    || selected.has('hero_gold_earned_snapshot')
    || selected.has('hero_gold_spent_snapshot');
  // A return candidate is only meaningful after validating its death cores.
  // Keep those route packets in the same walk even for respawn-only requests.
  const selectsDeathRoutes = selected.has('hero_death') || selected.has('hero_death_timer')
    || selected.has('hero_respawn');
  let blockCount = 0;
  let keyframeBlockCount = 0;
  let finished = false;
  return Object.freeze({
    observe(block, chunk) {
      if (finished) throw new Error('821 route scan collector is already finished');
      blockCount += 1;
      if (chunk.stream_tag === 2 || chunk.stream_tag === 3) keyframeBlockCount += 1;
      if (selectsDeathRoutes && chunk.stream_tag === 1
          && DEATH_ROUTES.has(block.packet_id)) {
        const row = copyRow(block, chunk);
        rows.hero_death.push(row);
        rows.hero_death_timer.push(row);
      }
      if (selected.has('hero_respawn') && chunk.stream_tag === 1
          && RESPAWN_ROUTES.has(block.packet_id)) {
        rows.hero_respawn.push(copyRow(block, chunk));
      }
      if (selectsHeroStats && (chunk.stream_tag === 2 || chunk.stream_tag === 3)
          && block.packet_id === 0x0089) {
        heroStatsRows.push(copyRow(block, chunk));
      }
      if (selected.has('hero_level_state') && chunk.stream_tag === 1
          && block.packet_id === 0x0197) {
        rows.hero_level_state.push(copyRow(block, chunk));
      }
    },
    finish(expectedBlockCount) {
      if (finished) throw new Error('821 route scan collector is already finished');
      if (expectedBlockCount !== undefined && expectedBlockCount !== blockCount) {
        throw new RangeError('821 analyzer block count differs from observed framing');
      }
      finished = true;
      const sourceError = replaySourceError(replay);
      const token = Object.freeze({
        status: sourceError ? 'DECODE_FAILED' : 'COLLECTED',
        scanned_block_count: blockCount,
        error: sourceError ? `Replay source integrity failed: ${sourceError}` : null,
      });
      SCAN_SOURCE.set(token, {
        replay, source_sha256: replay.source_sha256,
        source_path: replay.source_path ?? null,
        version: replay.header.version,
        file_size: replay.file_size,
        selected, rows, blockCount, keyframeBlockCount,
        error: token.error,
      });
      return token;
    },
  });
}

function collect821Routes(replay, selectedCapabilities) {
  const collector = create821ScanCollector(replay, selectedCapabilities);
  const walked = walkBlocks(replay, collector.observe, { strict: true });
  return collector.finish(walked.block_count);
}

function analyzeReplayWith821Routes(replay, options, selectedCapabilities) {
  const collector = create821ScanCollector(replay, selectedCapabilities);
  const analysis = analyzeReplay(replay, {
    ...options, includeStreams: [1, 2, 3], onBlock: collector.observe,
  });
  return {
    analysis,
    candidate821Scan: analysis.block_errors.length === 0
      ? collector.finish(analysis.packet_count) : null,
  };
}

function rowsFor821Capability(replay, token, capability) {
  const bound = token && typeof token === 'object' ? SCAN_SOURCE.get(token) : null;
  if (!bound || bound.replay !== replay
      || bound.source_sha256 !== replay.source_sha256
      || bound.source_path !== (replay.source_path ?? null)
      || bound.version !== replay.header?.version
      || bound.file_size !== replay.file_size) {
    return { error: '821 route scan belongs to a different Replay or is not source-bound' };
  }
  const sourceError = replaySourceError(replay);
  if (sourceError) return { error: `Replay source integrity failed: ${sourceError}` };
  if (bound.error) return { error: bound.error };
  const selected = bound.selected.has(capability)
    || (capability === 'hero_death'
      && (bound.selected.has('hero_respawn') || bound.selected.has('hero_death_timer')));
  if (!selected) {
    return { error: `${capability} was not selected by this 821 route scan` };
  }
  return {
    rows: bound.rows[capability].map((row) => copyRow(row.block, row.chunk)),
    scanned_block_count: capability === 'hero_deaths_snapshot'
      || capability === 'hero_champion_kills_snapshot'
      || capability === 'hero_assists_snapshot'
      || capability === 'hero_missions_minions_killed_snapshot'
      || capability === 'hero_ward_stats_snapshot'
      || capability === 'hero_missions_cannon_minions_killed_snapshot'
      || capability === 'hero_experience_snapshot'
      || capability === 'hero_vision_score_snapshot'
      || capability === 'hero_gold_earned_snapshot'
      || capability === 'hero_gold_spent_snapshot'
      ? bound.keyframeBlockCount : bound.blockCount,
  };
}

module.exports = {
  analyzeReplayWith821Routes,
  collect821Routes,
  create821ScanCollector,
  rowsFor821Capability,
};
