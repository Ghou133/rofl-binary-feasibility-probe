const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

function ensureDir(directory) {
  fs.mkdirSync(directory, { recursive: true });
}

function writeJson(filePath, value) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function writeJsonl(filePath, rows) {
  ensureDir(path.dirname(filePath));
  const text = rows.length === 0 ? '' : `${rows.map((row) => JSON.stringify(row)).join('\n')}\n`;
  fs.writeFileSync(filePath, text, 'utf8');
}

function csvCell(value) {
  if (value === null || value === undefined) return '';
  if (Array.isArray(value)) value = value.join('|');
  if (typeof value === 'object') value = JSON.stringify(value);
  const text = String(value);
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function writeCsv(filePath, rows, columns = null) {
  ensureDir(path.dirname(filePath));
  if (!columns) {
    columns = rows.length > 0 ? Object.keys(rows[0]) : [];
  }
  const lines = [columns.map(csvCell).join(',')];
  for (const row of rows) {
    lines.push(columns.map((column) => csvCell(row[column])).join(','));
  }
  fs.writeFileSync(filePath, `${lines.join('\n')}\n`, 'utf8');
}

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  const stream = fs.createReadStream(filePath);
  return new Promise((resolve, reject) => {
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

async function hashFiles(paths) {
  const result = {};
  for (const filePath of paths) {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
      result[resolved] = { exists: false, size: null, sha256: null };
      continue;
    }
    const stat = fs.statSync(resolved);
    result[resolved] = {
      exists: true,
      size: stat.size,
      sha256: await sha256File(resolved),
    };
  }
  return result;
}

function safeStem(filePath) {
  return path.basename(filePath, path.extname(filePath)).replace(/[^A-Za-z0-9._-]+/g, '_');
}

function outputHashes(directory, options = {}) {
  const excluded = (options.exclude || []).map((filePath) => filePath.replaceAll(path.sep, '/').replace(/\/$/, ''));
  const isExcluded = (relative) => excluded.some((entry) => relative === entry || relative.startsWith(`${entry}/`));
  const files = [];
  function visit(current) {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) visit(full);
      else {
        const relative = path.relative(directory, full).replaceAll(path.sep, '/');
        if (!isExcluded(relative)) files.push(full);
      }
    }
  }
  if (fs.existsSync(directory)) visit(directory);
  return Promise.all(files.sort().map(async (filePath) => [
    path.relative(directory, filePath).replaceAll(path.sep, '/'),
    await sha256File(filePath),
  ])).then((entries) => Object.fromEntries(entries));
}

module.exports = {
  ensureDir,
  writeJson,
  writeJsonl,
  writeCsv,
  sha256File,
  hashFiles,
  safeStem,
  outputHashes,
};
