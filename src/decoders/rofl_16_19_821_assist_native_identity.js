'use strict';

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const IMAGE_SHA256 = '35b49575122a8b063d5db6b37373f59740aa25b4be28d0affcb12f93be0cd325';
const REPLAY_VERSION = '16.19.821.7343';
const MAX_IMAGE_BYTES = 64 * 1024 * 1024;
const MAX_PACKETS = 2_000;
const MAX_REQUEST_BYTES = 1_000_000;

function packetHash(payload) {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function validU32(value) {
  return Number.isInteger(value) && value >= 0 && value <= 0xffffffff;
}

function validateAssistNativeChildren821(rows, { runtimeImagePath, pythonExecutable } = {}) {
  const fail = (status, error, extra = {}) => ({
    status, error, runtime_image_status: 'NOT_CHECKED', runtime_image_used: false,
    results: null, ...extra,
  });
  if (!Array.isArray(rows) || rows.length > MAX_PACKETS) {
    return fail('UNSUPPORTED', `assist native input exceeds ${MAX_PACKETS} packets`, {
      observed_packet_count_minimum: rows?.length ?? null,
    });
  }
  if (typeof runtimeImagePath !== 'string' || !runtimeImagePath.trim()) {
    return fail('MISSING_INPUT', 'exact 16.19.821.7343 mapped runtime image is required', {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
    });
  }
  const imagePath = path.resolve(runtimeImagePath);
  try {
    const stat = fs.statSync(imagePath);
    if (!stat.isFile() || stat.size > MAX_IMAGE_BYTES) {
      return fail('MISSING_INPUT', 'runtime image is not a bounded file', {
        missing_input: 'runtime_image', runtime_image_status: 'MISSING',
      });
    }
  } catch (error) {
    return fail('MISSING_INPUT', `runtime image cannot be read: ${error.message}`, {
      missing_input: 'runtime_image', runtime_image_status: 'MISSING',
    });
  }
  for (const row of rows) {
    if (row?.chunk?.stream_tag !== 1 || row?.block?.packet_id !== 0x040a
        || row.block.payload_length !== 44 || !Buffer.isBuffer(row.block.payload)
        || row.block.payload.length !== 44 || !validU32(row.block.param)
        || row.block.param === 0) {
      return fail('DECODE_FAILED', 'assist native row differs from exact 821 game-stream 44-byte scope');
    }
  }
  const request = JSON.stringify({
    replay_version: REPLAY_VERSION,
    packets: rows.map(({ block, chunk }) => ({
      packet_id: block.packet_id, stream_tag: chunk.stream_tag,
      raw_param: block.param >>> 0, payload_hex: block.payload.toString('hex'),
    })),
  });
  if (Buffer.byteLength(request) > MAX_REQUEST_BYTES) {
    return fail('UNSUPPORTED', 'assist native request exceeds bounded input size');
  }
  const python = pythonExecutable || process.env.PYTHON || 'python';
  const script = path.resolve(__dirname, '..', '..', 'scripts',
    'decode_assist_child_packet_16_19_821.py');
  const run = childProcess.spawnSync(python, ['-B', script, '--image', imagePath], {
    input: request, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, timeout: 60_000,
  });
  if (run.error || run.status !== 0) {
    const detail = String(run.error?.message || run.stderr || run.stdout
      || `Python exited ${run.status}`).trim().slice(0, 1500);
    const missingPython = run.error?.code === 'ENOENT'
      || /ModuleNotFoundError: No module named ['"]unicorn['"]|requires the installed unicorn dependency/.test(detail);
    const wrongImage = /runtime image SHA-256 mismatch/i.test(detail);
    return fail(missingPython ? 'MISSING_INPUT' : 'DECODE_FAILED',
      `exact runtime assist child decoder failed: ${detail}`, {
        ...(missingPython ? { missing_input: 'python_unicorn' } : {}),
        runtime_image_status: wrongImage ? 'HASH_MISMATCH'
          : missingPython ? 'NOT_CHECKED' : 'EXECUTION_FAILED',
      });
  }
  let decoded;
  try {
    decoded = JSON.parse(run.stdout);
  } catch (error) {
    return fail('DECODE_FAILED', `assist native output is not JSON: ${error.message}`, {
      runtime_image_status: 'EXECUTION_FAILED',
    });
  }
  if (decoded?.status !== 'PASS' || decoded.runtime_image_sha256 !== IMAGE_SHA256
      || !Array.isArray(decoded.results) || decoded.results.length !== rows.length) {
    return fail('DECODE_FAILED', 'assist native output identity or packet count differs', {
      runtime_image_status: 'EXECUTION_FAILED',
    });
  }
  let firstCount = 0;
  let secondCount = 0;
  for (let index = 0; index < rows.length; index += 1) {
    const { block } = rows[index];
    const result = decoded.results[index];
    const rawParam = block.param >>> 0;
    if (result?.status !== 'DECODED' || result.input_index !== index
        || result.raw_param !== rawParam
        || result.raw_payload_sha256 !== packetHash(block.payload)
        || result.deserialize_return_al !== 1 || result.bytes_consumed !== 44
        || result.native_packet_id !== 0x040a || result.native_raw_param !== rawParam
        || ![0x0056, 0x0057].includes(result.event_id)
        || result.raw_event_id_hex !== (result.event_id === 0x0056
          ? '0x4914' : '0x49d4')
        || result.event_blob_length !== 36
        || !/^[0-9a-f]{64}$/.test(result.event_blob_sha256)
        || !validU32(result.event_u32_0x04)
        || (result.event_id === 0x0057 && !validU32(result.event_u32_0x20))
        || (result.event_id === 0x0056 && result.event_u32_0x20 != null)) {
      return fail('DECODE_FAILED', `assist native packet ${index} did not match exact child identity`, {
        runtime_image_status: 'MATCHED_USED', runtime_image_used: true,
        runtime_image_sha256: IMAGE_SHA256,
        first_failed_packet_index: index, runtime_packet_result: result ?? null,
      });
    }
    if (result.event_id === 0x0056) firstCount += 1;
    else secondCount += 1;
  }
  return { status: 'PASS', runtime_image_status: 'MATCHED_USED',
    runtime_image_used: true, runtime_image_sha256: IMAGE_SHA256,
    native_child_first_count: firstCount, native_child_second_count: secondCount,
    results: decoded.results };
}

module.exports = { validateAssistNativeChildren821 };
