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
  // Keep serialization bounded even when a selected Replay capability emits
  // hundreds of megabytes of candidate rows. Publish only a complete file.
  const maxChunkBytes = 1024 * 1024;
  const temporary = path.join(path.dirname(filePath),
    `.rofl-jsonl-${process.pid}-${crypto.randomBytes(8).toString('hex')}.tmp`);
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, 'wx');
    let parts = [];
    let partBytes = 0;
    const writeBytes = (bytes) => {
      let offset = 0;
      while (offset < bytes.length) {
        const written = fs.writeSync(descriptor, bytes, offset,
          Math.min(maxChunkBytes, bytes.length - offset));
        if (written <= 0) throw new Error('JSONL output write made no progress');
        offset += written;
      }
    };
    const flush = () => {
      if (partBytes === 0) return;
      writeBytes(Buffer.from(parts.join(''), 'utf8'));
      parts = [];
      partBytes = 0;
    };
    for (const row of rows) {
      // Array.join used to turn sparse/undefined entries into blank lines.
      const line = `${JSON.stringify(row) ?? ''}\n`;
      const lineBytes = Buffer.byteLength(line, 'utf8');
      if (lineBytes > maxChunkBytes) {
        flush();
        writeBytes(Buffer.from(line, 'utf8'));
      } else {
        if (partBytes + lineBytes > maxChunkBytes) flush();
        parts.push(line);
        partBytes += lineBytes;
      }
    }
    flush();
    fs.closeSync(descriptor);
    descriptor = undefined;
    fs.renameSync(temporary, filePath);
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch { /* Preserve the first error. */ }
    }
    try { fs.rmSync(temporary, { force: true }); } catch { /* Preserve the first error. */ }
    throw error;
  }
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
  const stem = path.basename(filePath, path.extname(filePath))
    .replace(/[^A-Za-z0-9._-]+/g, '_');
  return /^\.*$/.test(stem) ? 'replay' : stem;
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
