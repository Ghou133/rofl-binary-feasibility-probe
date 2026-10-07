'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { parentPort, workerData } = require('node:worker_threads');
const { parseOneExact821Batch, writePerReplayArtifacts } = require('./cli');

const { filePath, options, rootDir, replayDirName } = workerData;
try {
  const result = parseOneExact821Batch(filePath, options);
  if (!result.ok) {
    parentPort.postMessage(result);
  } else {
    result.analysis.artifact_directory = path.posix.join('replays', replayDirName);
    writePerReplayArtifacts(result.analysis, rootDir, replayDirName, options);
    // This is the saved JSONL-only analysis: event arrays never cross worker IPC.
    const saved = JSON.parse(fs.readFileSync(path.join(rootDir,
      result.analysis.artifact_directory, 'replay_analysis.json'), 'utf8'));
    if (saved.events !== null || saved.event_storage !== 'JSONL_ONLY') {
      throw new Error('Worker did not save JSONL-only Replay analysis');
    }
    parentPort.postMessage({ ok: true, analysis: saved });
  }
} catch (error) {
  parentPort.postMessage({
    ok: false,
    source_path: path.resolve(filePath),
    error: {
      code: 'WORKER_FAILED',
      message: error.message || String(error),
      details: null,
      name: error.name || 'Error',
    },
  });
}
