'use strict';

const { analyzeReplay } = require('../analysis');
const { walkBlocks } = require('../rofl');
const { replaySourceError } = require('./replay_source_integrity');

const BUILD = '16.19.821.7343';
const CAPABILITIES = new Set([
  'hero_death', 'hero_death_timer', 'hero_deaths_snapshot', 'hero_champion_kills_snapshot',
  'hero_assists_snapshot', 'hero_missions_minions_killed_snapshot',
  'hero_ward_stats_snapshot', 'hero_missions_cannon_minions_killed_snapshot',
  'hero_minions_killed_snapshot', 'hero_jungle_minions_killed_snapshot',
  'hero_kill_stats_snapshot',
  'hero_experience_snapshot', 'hero_vision_score_snapshot',
  'hero_gold_earned_snapshot', 'hero_gold_spent_snapshot',
  'hero_damage_totals_snapshot', 'hero_damage_taken_from_champions_snapshot',
  'hero_damage_self_mitigated_snapshot',
  'hero_structure_objective_damage_snapshot',
  'hero_longest_living_time_snapshot', 'hero_total_time_spent_dead_snapshot',
  'hero_total_heal_snapshot', 'hero_total_units_healed_snapshot',
  'hero_epic_monster_damage_snapshot', 'hero_crowd_control_time_snapshot',
  'hero_level_state', 'hero_respawn', 'hero_assist', 'hero_inventory_packet',
  'hero_inventory_broadcast_packet', 'hero_inventory_set_item_packet',
  'params_heal_packet',
  'shielding_params_packet_pair',
  'stealth_event_packet',
  'champion_die_event_packet',
  'champion_kill_event_packet',
  'champion_multiple_kill_event_packet',
  'champion_double_kill_event_packet',
  'champion_triple_quadra_event_packet',
  'on_shutdown_event_packet',
  'resurrect_event_packet',
  'turret_plate_event_packet',
  'cast_spell_ans_packet', 'npc_buff_remove_packet', 'npc_buff_add_packet',
  'direct_input_movement_turn_packet',
  'set_movement_driver_packet',
]);
const DEATH_ROUTES = new Set([0x0259, 0x0438, 0x031b, 0x03d4]);
const RESPAWN_ROUTES = new Set([0x0048, 0x018d]);
const MAX_BUFF_REMOVE_PACKET_ROWS = 50_000;
const MAX_BUFF_ADD_PACKET_ROWS = 50_000;
const MAX_BROADCAST_PACKET_ROWS = 512;
const MAX_SET_ITEM_PACKET_ROWS = 256;
const MAX_PARAMS_HEAL_PACKET_ROWS = 20_000;
const MAX_SHIELDING_PARAMS_PACKET_ROWS = 10_000;
const MAX_STEALTH_EVENT_PACKET_ROWS = 5_000;
const MAX_CHAMPION_DIE_EVENT_PACKET_ROWS = 10_000;
const MAX_CHAMPION_KILL_EVENT_PACKET_ROWS = 2_000;
const MAX_CHAMPION_MULTIPLE_KILL_EVENT_PACKET_ROWS = 10_000;
const MAX_CHAMPION_DOUBLE_KILL_EVENT_PACKET_ROWS = 2_000;
const MAX_CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_ROWS = 2_000;
const MAX_ON_SHUTDOWN_EVENT_PACKET_ROWS = 2_000;
const MAX_RESURRECT_EVENT_PACKET_ROWS = 2_000;
const MAX_TURRET_PLATE_EVENT_PACKET_ROWS = 10_000;
const MAX_DIRECT_INPUT_TURN_PACKET_ROWS = 20_000;
const MAX_SET_MOVEMENT_DRIVER_PACKET_ROWS = 20_000;
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
    hero_assist: [],
    hero_inventory_packet: [],
    hero_inventory_broadcast_packet: [],
    hero_inventory_set_item_packet: [],
    params_heal_packet: [],
    shielding_params_packet_pair: [],
    stealth_event_packet: [],
    champion_die_event_packet: [],
    champion_kill_event_packet: [],
    champion_multiple_kill_event_packet: [],
    champion_double_kill_event_packet: [],
    champion_triple_quadra_event_packet: [],
    on_shutdown_event_packet: [],
    resurrect_event_packet: [],
    turret_plate_event_packet: [],
    cast_spell_ans_packet: [],
    npc_buff_remove_packet: [],
    npc_buff_add_packet: [],
    direct_input_movement_turn_packet: [],
    set_movement_driver_packet: [],
    hero_deaths_snapshot: heroStatsRows,
    hero_champion_kills_snapshot: heroStatsRows,
    hero_assists_snapshot: heroStatsRows,
    hero_missions_minions_killed_snapshot: heroStatsRows,
    hero_ward_stats_snapshot: heroStatsRows,
    hero_missions_cannon_minions_killed_snapshot: heroStatsRows,
    hero_minions_killed_snapshot: heroStatsRows,
    hero_jungle_minions_killed_snapshot: heroStatsRows,
    hero_kill_stats_snapshot: heroStatsRows,
    hero_experience_snapshot: heroStatsRows,
    hero_vision_score_snapshot: heroStatsRows,
    hero_gold_earned_snapshot: heroStatsRows,
    hero_gold_spent_snapshot: heroStatsRows,
    hero_damage_totals_snapshot: heroStatsRows,
    hero_damage_taken_from_champions_snapshot: heroStatsRows,
    hero_damage_self_mitigated_snapshot: heroStatsRows,
    hero_structure_objective_damage_snapshot: heroStatsRows,
    hero_longest_living_time_snapshot: heroStatsRows,
    hero_total_time_spent_dead_snapshot: heroStatsRows,
    hero_total_heal_snapshot: heroStatsRows,
    hero_total_units_healed_snapshot: heroStatsRows,
    hero_epic_monster_damage_snapshot: heroStatsRows,
    hero_crowd_control_time_snapshot: heroStatsRows,
    hero_level_state: [],
  };
  const selectsHeroStats = selected.has('hero_deaths_snapshot')
    || selected.has('hero_champion_kills_snapshot')
    || selected.has('hero_assists_snapshot')
    || selected.has('hero_missions_minions_killed_snapshot')
    || selected.has('hero_ward_stats_snapshot')
    || selected.has('hero_missions_cannon_minions_killed_snapshot')
    || selected.has('hero_minions_killed_snapshot')
    || selected.has('hero_jungle_minions_killed_snapshot')
    || selected.has('hero_kill_stats_snapshot')
    || selected.has('hero_experience_snapshot')
    || selected.has('hero_vision_score_snapshot')
    || selected.has('hero_gold_earned_snapshot')
    || selected.has('hero_gold_spent_snapshot')
    || selected.has('hero_damage_totals_snapshot')
    || selected.has('hero_damage_taken_from_champions_snapshot')
    || selected.has('hero_damage_self_mitigated_snapshot')
    || selected.has('hero_structure_objective_damage_snapshot')
    || selected.has('hero_longest_living_time_snapshot')
    || selected.has('hero_total_time_spent_dead_snapshot')
    || selected.has('hero_total_heal_snapshot')
    || selected.has('hero_total_units_healed_snapshot')
    || selected.has('hero_epic_monster_damage_snapshot')
    || selected.has('hero_crowd_control_time_snapshot');
  // A return candidate is only meaningful after validating its death cores.
  // Keep those route packets in the same walk even for respawn-only requests.
  const selectsDeathRoutes = selected.has('hero_death') || selected.has('hero_death_timer')
    || selected.has('hero_respawn') || selected.has('hero_assist');
  let blockCount = 0;
  let keyframeBlockCount = 0;
  let buffRemovePacketCount = 0;
  let buffAddPacketCount = 0;
  let broadcastPacketCount = 0;
  let setItemPacketCount = 0;
  let paramsHealPacketCount = 0;
  let shieldingParamsPacketCount = 0;
  let stealthEventPacketCount = 0;
  let championDieEventPacketCount = 0;
  let championKillEventPacketCount = 0;
  let championMultipleKillEventPacketCount = 0;
  let championDoubleKillEventPacketCount = 0;
  let championTripleQuadraEventPacketCount = 0;
  let onShutdownEventPacketCount = 0;
  let resurrectEventPacketCount = 0;
  let turretPlateEventPacketCount = 0;
  let directInputTurnPacketCount = 0;
  let setMovementDriverPacketCount = 0;
  let finished = false;
  // Capability selection is fixed for this walk. Cache the packet-route
  // decisions instead of probing the Set for every framed block.
  const selectsRespawn = selected.has('hero_respawn');
  const selectsAssist = selected.has('hero_assist');
  const selectsParamsHeal = selected.has('params_heal_packet');
  const selectsShieldingParams = selected.has('shielding_params_packet_pair');
  const selectsStealthEvent = selected.has('stealth_event_packet');
  const selectsChampionDieEvent = selected.has('champion_die_event_packet');
  const selectsChampionKillEvent = selected.has('champion_kill_event_packet');
  const selectsChampionMultipleKillEvent = selected.has('champion_multiple_kill_event_packet');
  const selectsChampionDoubleKillEvent = selected.has('champion_double_kill_event_packet');
  const selectsChampionTripleQuadraEvent = selected.has('champion_triple_quadra_event_packet');
  const selectsOnShutdownEvent = selected.has('on_shutdown_event_packet');
  const selectsResurrectEvent = selected.has('resurrect_event_packet');
  const selectsTurretPlateEvent = selected.has('turret_plate_event_packet');
  const selectsInventoryPacket = selected.has('hero_inventory_packet');
  const selectsInventoryBroadcast = selected.has('hero_inventory_broadcast_packet');
  const selectsInventorySetItem = selected.has('hero_inventory_set_item_packet');
  const selectsCastSpellAns = selected.has('cast_spell_ans_packet');
  const selectsBuffRemove = selected.has('npc_buff_remove_packet');
  const selectsBuffAdd = selected.has('npc_buff_add_packet');
  const selectsDirectInputTurn = selected.has('direct_input_movement_turn_packet');
  const selectsSetMovementDriver = selected.has('set_movement_driver_packet');
  const selectsHeroLevelState = selected.has('hero_level_state');
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
      if (selectsRespawn && chunk.stream_tag === 1
          && RESPAWN_ROUTES.has(block.packet_id)) {
        rows.hero_respawn.push(copyRow(block, chunk));
      }
      if (selectsAssist && chunk.stream_tag === 1
          && block.packet_id === 0x040a && block.payload_length === 44) {
        rows.hero_assist.push(copyRow(block, chunk));
      }
      if (selectsParamsHeal
          && block.packet_id === 0x040a && block.payload_length === 60) {
        paramsHealPacketCount += 1;
        if (rows.params_heal_packet.length < MAX_PARAMS_HEAL_PACKET_ROWS) {
          rows.params_heal_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsShieldingParams
          && block.packet_id === 0x040a && block.payload_length === 29) {
        shieldingParamsPacketCount += 1;
        if (rows.shielding_params_packet_pair.length < MAX_SHIELDING_PARAMS_PACKET_ROWS) {
          rows.shielding_params_packet_pair.push(copyRow(block, chunk));
        }
      }
      if (selectsStealthEvent
          && block.packet_id === 0x040a && block.payload_length === 17) {
        stealthEventPacketCount += 1;
        if (rows.stealth_event_packet.length < MAX_STEALTH_EVENT_PACKET_ROWS) {
          rows.stealth_event_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsChampionDieEvent
          && block.packet_id === 0x040a && block.payload_length === 116) {
        championDieEventPacketCount += 1;
        if (rows.champion_die_event_packet.length < MAX_CHAMPION_DIE_EVENT_PACKET_ROWS) {
          rows.champion_die_event_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsChampionKillEvent
          && block.packet_id === 0x040a && block.payload_length === 104) {
        championKillEventPacketCount += 1;
        if (rows.champion_kill_event_packet.length < MAX_CHAMPION_KILL_EVENT_PACKET_ROWS) {
          rows.champion_kill_event_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsChampionMultipleKillEvent
          && block.packet_id === 0x040a && block.payload_length === 88) {
        championMultipleKillEventPacketCount += 1;
        if (rows.champion_multiple_kill_event_packet.length
            < MAX_CHAMPION_MULTIPLE_KILL_EVENT_PACKET_ROWS) {
          rows.champion_multiple_kill_event_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsChampionDoubleKillEvent
          && block.packet_id === 0x040a && block.payload_length === 104) {
        championDoubleKillEventPacketCount += 1;
        if (rows.champion_double_kill_event_packet.length
            < MAX_CHAMPION_DOUBLE_KILL_EVENT_PACKET_ROWS) {
          rows.champion_double_kill_event_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsChampionTripleQuadraEvent
          && block.packet_id === 0x040a && block.payload_length === 104) {
        championTripleQuadraEventPacketCount += 1;
        if (rows.champion_triple_quadra_event_packet.length
            < MAX_CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_ROWS) {
          rows.champion_triple_quadra_event_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsOnShutdownEvent
          && block.packet_id === 0x040a && block.payload_length === 105) {
        onShutdownEventPacketCount += 1;
        if (rows.on_shutdown_event_packet.length < MAX_ON_SHUTDOWN_EVENT_PACKET_ROWS) {
          rows.on_shutdown_event_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsResurrectEvent
          && block.packet_id === 0x040a && block.payload_length === 20) {
        resurrectEventPacketCount += 1;
        if (rows.resurrect_event_packet.length < MAX_RESURRECT_EVENT_PACKET_ROWS) {
          rows.resurrect_event_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsTurretPlateEvent
          && block.packet_id === 0x040a && block.payload_length === 17) {
        turretPlateEventPacketCount += 1;
        if (rows.turret_plate_event_packet.length < MAX_TURRET_PLATE_EVENT_PACKET_ROWS) {
          rows.turret_plate_event_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsInventoryPacket && chunk.stream_tag === 1
          && block.packet_id === 0x018d) {
        rows.hero_inventory_packet.push(copyRow(block, chunk));
      }
      if (selectsInventoryBroadcast
          && block.packet_id === 0x0357) {
        broadcastPacketCount += 1;
        if (rows.hero_inventory_broadcast_packet.length < MAX_BROADCAST_PACKET_ROWS) {
          rows.hero_inventory_broadcast_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsInventorySetItem
          && block.packet_id === 0x002d) {
        setItemPacketCount += 1;
        if (rows.hero_inventory_set_item_packet.length < MAX_SET_ITEM_PACKET_ROWS) {
          rows.hero_inventory_set_item_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsCastSpellAns && block.packet_id === 0x01da) {
        rows.cast_spell_ans_packet.push(copyRow(block, chunk));
      }
      if (selectsBuffRemove && block.packet_id === 0x047c) {
        buffRemovePacketCount += 1;
        if (rows.npc_buff_remove_packet.length < MAX_BUFF_REMOVE_PACKET_ROWS) {
          rows.npc_buff_remove_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsBuffAdd && block.packet_id === 0x00ae) {
        buffAddPacketCount += 1;
        if (rows.npc_buff_add_packet.length < MAX_BUFF_ADD_PACKET_ROWS) {
          rows.npc_buff_add_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsDirectInputTurn && block.packet_id === 0x00ba) {
        directInputTurnPacketCount += 1;
        if (rows.direct_input_movement_turn_packet.length < MAX_DIRECT_INPUT_TURN_PACKET_ROWS) {
          rows.direct_input_movement_turn_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsSetMovementDriver && block.packet_id === 0x0335) {
        setMovementDriverPacketCount += 1;
        if (rows.set_movement_driver_packet.length < MAX_SET_MOVEMENT_DRIVER_PACKET_ROWS) {
          rows.set_movement_driver_packet.push(copyRow(block, chunk));
        }
      }
      if (selectsHeroStats && (chunk.stream_tag === 2 || chunk.stream_tag === 3)
          && block.packet_id === 0x0089) {
        heroStatsRows.push(copyRow(block, chunk));
      }
      if (selectsHeroLevelState && chunk.stream_tag === 1
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
        buffRemovePacketCount, buffAddPacketCount, broadcastPacketCount,
        setItemPacketCount,
        paramsHealPacketCount,
        shieldingParamsPacketCount,
        stealthEventPacketCount,
        championDieEventPacketCount,
        championKillEventPacketCount,
        championMultipleKillEventPacketCount,
        championDoubleKillEventPacketCount,
        championTripleQuadraEventPacketCount,
        onShutdownEventPacketCount,
        resurrectEventPacketCount,
        turretPlateEventPacketCount,
        directInputTurnPacketCount,
        setMovementDriverPacketCount,
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
      && (bound.selected.has('hero_respawn') || bound.selected.has('hero_death_timer')
        || bound.selected.has('hero_assist')));
  if (!selected) {
    return { error: `${capability} was not selected by this 821 route scan` };
  }
  if (capability === 'hero_inventory_broadcast_packet'
      && bound.broadcastPacketCount > MAX_BROADCAST_PACKET_ROWS) {
    return {
      observed_packet_count: bound.broadcastPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'hero_inventory_set_item_packet'
      && bound.setItemPacketCount > MAX_SET_ITEM_PACKET_ROWS) {
    return {
      observed_packet_count: bound.setItemPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'params_heal_packet'
      && bound.paramsHealPacketCount > MAX_PARAMS_HEAL_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.paramsHealPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'shielding_params_packet_pair'
      && bound.shieldingParamsPacketCount > MAX_SHIELDING_PARAMS_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.shieldingParamsPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'stealth_event_packet'
      && bound.stealthEventPacketCount > MAX_STEALTH_EVENT_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.stealthEventPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'champion_die_event_packet'
      && bound.championDieEventPacketCount > MAX_CHAMPION_DIE_EVENT_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.championDieEventPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'champion_kill_event_packet'
      && bound.championKillEventPacketCount > MAX_CHAMPION_KILL_EVENT_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.championKillEventPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'champion_multiple_kill_event_packet'
      && bound.championMultipleKillEventPacketCount
        > MAX_CHAMPION_MULTIPLE_KILL_EVENT_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.championMultipleKillEventPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'champion_double_kill_event_packet'
      && bound.championDoubleKillEventPacketCount
        > MAX_CHAMPION_DOUBLE_KILL_EVENT_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.championDoubleKillEventPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'champion_triple_quadra_event_packet'
      && bound.championTripleQuadraEventPacketCount
        > MAX_CHAMPION_TRIPLE_QUADRA_EVENT_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.championTripleQuadraEventPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'on_shutdown_event_packet'
      && bound.onShutdownEventPacketCount > MAX_ON_SHUTDOWN_EVENT_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.onShutdownEventPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'resurrect_event_packet'
      && bound.resurrectEventPacketCount > MAX_RESURRECT_EVENT_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.resurrectEventPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'turret_plate_event_packet'
      && bound.turretPlateEventPacketCount > MAX_TURRET_PLATE_EVENT_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.turretPlateEventPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'npc_buff_remove_packet'
      && bound.buffRemovePacketCount > MAX_BUFF_REMOVE_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.buffRemovePacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'npc_buff_add_packet'
      && bound.buffAddPacketCount > MAX_BUFF_ADD_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.buffAddPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'direct_input_movement_turn_packet'
      && bound.directInputTurnPacketCount > MAX_DIRECT_INPUT_TURN_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.directInputTurnPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  if (capability === 'set_movement_driver_packet'
      && bound.setMovementDriverPacketCount > MAX_SET_MOVEMENT_DRIVER_PACKET_ROWS) {
    return {
      observed_packet_count_minimum: bound.setMovementDriverPacketCount,
      scanned_block_count: bound.blockCount,
    };
  }
  return {
    rows: bound.rows[capability].map((row) => copyRow(row.block, row.chunk)),
    scanned_block_count: capability === 'hero_deaths_snapshot'
      || capability === 'hero_champion_kills_snapshot'
      || capability === 'hero_assists_snapshot'
      || capability === 'hero_missions_minions_killed_snapshot'
      || capability === 'hero_ward_stats_snapshot'
      || capability === 'hero_missions_cannon_minions_killed_snapshot'
      || capability === 'hero_minions_killed_snapshot'
      || capability === 'hero_jungle_minions_killed_snapshot'
      || capability === 'hero_kill_stats_snapshot'
      || capability === 'hero_experience_snapshot'
      || capability === 'hero_vision_score_snapshot'
      || capability === 'hero_gold_earned_snapshot'
      || capability === 'hero_gold_spent_snapshot'
      || capability === 'hero_damage_totals_snapshot'
      || capability === 'hero_damage_taken_from_champions_snapshot'
      || capability === 'hero_damage_self_mitigated_snapshot'
      || capability === 'hero_structure_objective_damage_snapshot'
      || capability === 'hero_longest_living_time_snapshot'
      || capability === 'hero_total_time_spent_dead_snapshot'
      || capability === 'hero_total_heal_snapshot'
      || capability === 'hero_total_units_healed_snapshot'
      || capability === 'hero_epic_monster_damage_snapshot'
      || capability === 'hero_crowd_control_time_snapshot'
      ? bound.keyframeBlockCount : bound.blockCount,
  };
}

module.exports = {
  analyzeReplayWith821Routes,
  collect821Routes,
  create821ScanCollector,
  rowsFor821Capability,
};
