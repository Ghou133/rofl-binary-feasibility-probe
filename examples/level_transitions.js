#!/usr/bin/env node

const path = require('node:path');

const { normalizePlayers, parseReplayFile } = require('../src/rofl');
const {
  queryLevelTransitions,
  runLevelTransitionDecoder,
} = require('../src/semantic_pipeline');

const replayPath = process.argv[2];
const requestedTeam = process.argv[3] ? Number(process.argv[3]) : null;
if (!replayPath) {
  process.stderr.write('Usage: node examples/level_transitions.js <replay.rofl> [team-id]\n');
  process.exitCode = 2;
} else {
  const replay = parseReplayFile(path.resolve(replayPath));
  const jungler = normalizePlayers(replay)
    .find((player) => player.role === 'jungle'
      && (requestedTeam === null || player.team_id === requestedTeam));
  if (!jungler) throw new Error('Replay metadata has no matching jungle participant');
  const participantId = jungler.metadata_index + 1;
  const decoded = runLevelTransitionDecoder(replay);
  const transitions = queryLevelTransitions(decoded.events, {
    participantId,
    levels: [2, 3, 4],
  });
  for (const event of transitions) {
    process.stdout.write([
      `participant=${event.participant_id}`,
      `champion=${event.champion}`,
      `level=${event.level_after}`,
      `timestamp_ms=${event.timestamp_ms}`,
      `transition_evidence=${event.transition_evidence}`,
      `level_mapping_evidence=${event.level_mapping_evidence}`,
    ].join('\t') + '\n');
  }
}
