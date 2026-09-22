const path = require('node:path');

const DEFAULT_UPSTREAM_PATHS = Object.freeze(
  (process.env.ROFL_UPSTREAM_PATHS || '')
    .split(path.delimiter)
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => path.resolve(value)),
);

function compareHashSnapshots(before, after) {
  const paths = new Set([...Object.keys(before || {}), ...Object.keys(after || {})]);
  const changes = [];
  for (const filePath of [...paths].sort()) {
    const left = before?.[filePath] || { exists: false, sha256: null, size: null };
    const right = after?.[filePath] || { exists: false, sha256: null, size: null };
    if (left.exists !== right.exists || left.sha256 !== right.sha256 || left.size !== right.size) {
      changes.push({ path: filePath, before: left, after: right });
    }
  }
  return {
    unchanged: changes.length === 0,
    changes,
  };
}

module.exports = {
  DEFAULT_UPSTREAM_PATHS,
  compareHashSnapshots,
};
