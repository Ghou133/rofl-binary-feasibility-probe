'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');

const release = require('../../PUBLIC_RELEASE_SOURCE_HASHES.json');

function assertFrozenOrPublicSourceHash(entry, filePath, fileSha) {
  const publicVersion = release.files[entry.path];
  if (publicVersion) {
    // The original research artifact stays frozen. Public path hygiene has a
    // separate, pinned source identity and must not overwrite that artifact.
    assert.equal(entry.byte_length, publicVersion.original_bytes, `${entry.path}: frozen size`);
    assert.equal(entry.sha256, publicVersion.original_sha256, `${entry.path}: frozen hash`);
    assert.equal(fs.statSync(filePath).size, publicVersion.public_bytes, `${entry.path}: public size`);
    assert.equal(fileSha(filePath), publicVersion.public_sha256, `${entry.path}: public hash`);
    return;
  }
  assert.equal(fs.statSync(filePath).size, entry.byte_length, entry.path);
  assert.equal(fileSha(filePath), entry.sha256, entry.path);
}

module.exports = { assertFrozenOrPublicSourceHash };
