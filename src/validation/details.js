function detailsPayload(value) {
  const payload = value?.json ?? value;
  return typeof payload === 'string' ? JSON.parse(payload) : payload;
}

function participantMap(details) {
  const participants = new Map();
  for (const item of details.participants || []) {
    const participantId = Number(item.participantId ?? item.participant_id);
    if (!Number.isInteger(participantId)) continue;
    participants.set(participantId, {
      participant_id: participantId,
      champion: item.championName ?? item.champion ?? null,
      team_id: item.teamId ?? item.team_id ?? null,
    });
  }
  return participants;
}

function damageRows(values) {
  return (values || []).map((item) => ({
    source_participant_id: Number.isInteger(item.participantId) ? item.participantId : null,
    source_name: item.name ?? null,
    spell_name: item.spellName ?? null,
    spell_slot: Number.isFinite(item.spellSlot) ? item.spellSlot : null,
    basic: typeof item.basic === 'boolean' ? item.basic : null,
    source_type: item.type ?? null,
    physical_damage: Number(item.physicalDamage) || 0,
    magic_damage: Number(item.magicDamage) || 0,
    true_damage: Number(item.trueDamage) || 0,
    total_damage: (Number(item.physicalDamage) || 0)
      + (Number(item.magicDamage) || 0)
      + (Number(item.trueDamage) || 0),
  }));
}

function replayParticipants(replay, detailsParticipants) {
  const result = [];
  const stats = Array.isArray(replay.tail?.stats) ? replay.tail.stats : [];
  for (let index = 0; index < stats.length; index += 1) {
    const participantId = index + 1;
    const teamId = Number(stats[index]?.TEAM);
    const oracle = detailsParticipants.get(participantId) || {};
    result.push({
      participant_id: participantId,
      champion: stats[index]?.SKIN ?? oracle.champion ?? null,
      team_id: Number.isFinite(teamId) ? teamId : oracle.team_id ?? null,
      source: 'ROFL_METADATA_STATS_JSON',
    });
  }
  return result;
}

function extractDetailsAnchors(gameId, replay, input) {
  const details = detailsPayload(input);
  if (String(details.gameId) !== String(gameId)) {
    throw new Error(`Details gameId ${details.gameId} does not match ${gameId}`);
  }
  const detailsParticipants = participantMap(details);
  const participants = replayParticipants(replay, detailsParticipants);
  const byParticipant = new Map(participants.map((item) => [item.participant_id, item]));
  const deaths = [];
  for (const frame of details.frames || []) {
    for (const event of frame.events || []) {
      if (event.type !== 'CHAMPION_KILL' || !Number.isFinite(Number(event.timestamp))) continue;
      deaths.push({
        anchor_id: `${gameId}:death:${deaths.length + 1}`,
        event_type: 'CHAMPION_KILL',
        timestamp_ms: Math.round(Number(event.timestamp)),
        killer_participant_id: Number.isInteger(event.killerId) ? event.killerId : null,
        killer_champion: byParticipant.get(event.killerId)?.champion ?? null,
        victim_participant_id: Number.isInteger(event.victimId) ? event.victimId : null,
        victim_champion: byParticipant.get(event.victimId)?.champion ?? null,
        position: event.position && Number.isFinite(event.position.x) && Number.isFinite(event.position.y)
          ? { x: event.position.x, y: event.position.y }
          : null,
        damage_received: damageRows(event.victimDamageReceived),
        oracle: 'LCU_SGP_MATCH_DETAILS',
        oracle_role: 'VALIDATION_ONLY',
        replay_is_fact_source: true,
      });
    }
  }
  deaths.sort((left, right) => left.timestamp_ms - right.timestamp_ms);
  return {
    game_id: String(gameId),
    replay_path: replay.source_path,
    replay_sha256: replay.source_sha256,
    replay_version: replay.header.version,
    participant_count: participants.length,
    participants,
    death_count: deaths.length,
    deaths,
  };
}

module.exports = {
  damageRows,
  detailsPayload,
  extractDetailsAnchors,
  participantMap,
  replayParticipants,
};
