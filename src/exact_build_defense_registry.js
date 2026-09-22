'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const EXACT_BUILD = '16.16.805.0442';
const EXACT_IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const IMAGE_BASE = 0x140000000;
const STATUS = 'VERIFIED_EXACT_IMAGE_FIELD_REGISTRY_OFFSETS';
const HOLDOUT_ACCESS = Object.freeze({
  read: false,
  enumerate: false,
  hash: false,
  decode: false,
  test: false,
  consume: false
});
const PERMITTED_FIELD_NAMES = new Set([
  'mArmor',
  'mSpellBlock',
  'mBonusArmor',
  'mBonusSpellBlock',
  'mFlatBaseArmorMod',
  'mFlatBaseSpellBlockMod',
  'mFlatArmorPenetration',
  'mPercentArmorPenetration',
  'mPercentBonusArmorPenetration',
  'mPercentCritBonusArmorPenetration',
  'mPercentCritTotalArmorPenetration',
  'mFlatMagicPenetration',
  'mPercentMagicPenetration',
  'mPercentBonusMagicPenetration',
  'mPhysicalLethality',
  'mMagicLethality'
]);

function isHoldoutPath(location) {
  return String(location || '').split(/[\\/]+/u).some(function (segment) {
    return /holdout/i.test(segment);
  });
}

function nearestExistingAncestor(location) {
  let candidate = path.resolve(location);
  while (!fs.existsSync(candidate)) {
    const parent = path.dirname(candidate);
    if (parent === candidate) return null;
    candidate = parent;
  }
  return candidate;
}

function assertNoHoldoutPath(location, label) {
  if (!location || typeof location !== 'string') {
    throw new Error((label || 'path') + ' is required');
  }
  const declared = path.resolve(location);
  if (isHoldoutPath(declared)) {
    throw new Error((label || 'path') + ' must not reference Holdout');
  }
  const ancestor = nearestExistingAncestor(declared);
  if (ancestor) {
    const physicalAncestor = fs.realpathSync(ancestor);
    if (isHoldoutPath(physicalAncestor)) {
      throw new Error((label || 'path') + ' resolves through Holdout');
    }
  }
  if (fs.existsSync(declared)) {
    const physical = fs.realpathSync(declared);
    if (isHoldoutPath(physical)) {
      throw new Error((label || 'path') + ' resolves to Holdout');
    }
  }
  return declared;
}

function readSafeFile(location, label) {
  const declared = assertNoHoldoutPath(location, label);
  if (!fs.existsSync(declared)) throw new Error((label || 'file') + ' does not exist');
  const physical = fs.realpathSync(declared);
  if (isHoldoutPath(physical)) throw new Error((label || 'file') + ' resolves to Holdout');
  return { declared: declared, physical: physical, bytes: fs.readFileSync(physical) };
}

function parseJsonSafe(location, label) {
  const input = readSafeFile(location, label);
  try {
    input.value = JSON.parse(input.bytes.toString('utf8'));
    return input;
  } catch (error) {
    throw new Error((label || 'JSON') + ' is invalid: ' + error.message);
  }
}

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function defaultPaths(rootDir) {
  const root = rootDir || path.resolve(__dirname, '..');
  return {
    runtimeImagePath: path.join(root, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime', 'league_16.16.805.0442.memory.bin'),
    identifierXrefsPath: path.join(root, '.omo', 'evidence', 'dynamic_defense_v1', 'runtime_defense_identifier_xrefs.json'),
    registrationBlockPath: path.join(root, '.omo', 'evidence', 'dynamic_defense_v1', 'runtime_defense_registration_block.json')
  };
}

function assertEvidenceHeader(document, runtimeDeclared, label) {
  if (!document || document.schema_version !== 1 || document.image_base !== IMAGE_BASE) {
    throw new Error(label + ' has an unsupported evidence header');
  }
  if (!document.image_path || path.resolve(document.image_path) !== runtimeDeclared) {
    throw new Error(label + ' is not bound to the supplied runtime image path');
  }
}

function readCString(image, rva) {
  if (!Number.isInteger(rva) || rva < 0 || rva >= image.length) {
    throw new Error('C string RVA is outside the runtime image: ' + rva);
  }
  const end = image.indexOf(0, rva);
  if (end < 0) throw new Error('C string at RVA ' + rva + ' is unterminated');
  const value = image.subarray(rva, end).toString('ascii');
  if (!/^[\x20-\x7e]+$/.test(value)) {
    throw new Error('C string at RVA ' + rva + ' is not printable ASCII');
  }
  return value;
}

function instructionBytes(image, rva, size) {
  if (!Number.isInteger(rva) || !Number.isInteger(size) || size < 5 || rva < 0 || rva + size > image.length) {
    throw new Error('instruction range is invalid at RVA ' + rva);
  }
  return image.subarray(rva, rva + size).toString('hex');
}

function instructionTargetFromRip(image, rva, size) {
  const bytes = Buffer.from(instructionBytes(image, rva, size), 'hex');
  const displacement = bytes.readInt32LE(bytes.length - 4);
  return rva + size + displacement;
}

function flattenInstructions(registration) {
  if (!Array.isArray(registration.disassembly)) {
    throw new Error('registration block evidence has no disassembly');
  }
  const byRva = new Map();
  for (const block of registration.disassembly) {
    if (!block || !Array.isArray(block.instructions)) continue;
    for (const instruction of block.instructions) {
      if (!instruction || !Number.isInteger(instruction.rva)) continue;
      const existing = byRva.get(instruction.rva);
      if (existing && (existing.bytes !== instruction.bytes || existing.mnemonic !== instruction.mnemonic || existing.operands !== instruction.operands)) {
        throw new Error('ambiguous registration instruction evidence at RVA ' + instruction.rva);
      }
      byRva.set(instruction.rva, instruction);
    }
  }
  return Array.from(byRva.values()).sort(function (left, right) { return left.rva - right.rva; });
}

function parseStructOffset(instruction) {
  if (!instruction || instruction.mnemonic !== 'lea' || typeof instruction.operands !== 'string') return null;
  const match = /^rcx, \[(rdi|rdx) \+ 0x([0-9a-f]+)\]$/i.exec(instruction.operands);
  return match ? Number.parseInt(match[2], 16) : null;
}

function directCallTarget(image, instruction) {
  if (!instruction || instruction.mnemonic !== 'call' || !/^e8/i.test(instruction.bytes || '')) return null;
  const size = Math.floor(instruction.bytes.length / 2);
  if (size !== 5) return null;
  const displacement = image.readInt32LE(instruction.rva + 1);
  return IMAGE_BASE + instruction.rva + size + displacement;
}

function findRegistrationPair(image, instructions, ripInstruction) {
  const ripIndex = instructions.findIndex(function (instruction) { return instruction.rva === ripInstruction.rva; });
  if (ripIndex < 0) throw new Error('RIP xref is absent from registration disassembly at RVA ' + ripInstruction.rva);
  const offsets = [];
  for (let index = ripIndex - 1; index >= 0; index -= 1) {
    const candidate = instructions[index];
    if (ripInstruction.rva - candidate.rva > 48) break;
    const offset = parseStructOffset(candidate);
    if (offset !== null) offsets.push({ instruction: candidate, offset: offset });
  }
  if (offsets.length !== 1) {
    throw new Error('registration block must contain exactly one struct offset before RIP xref at RVA ' + ripInstruction.rva);
  }
  const calls = [];
  for (let index = ripIndex + 1; index < instructions.length; index += 1) {
    const candidate = instructions[index];
    if (candidate.rva - ripInstruction.rva > 32) break;
    const target = directCallTarget(image, candidate);
    if (target !== null) calls.push({ instruction: candidate, target: target });
  }
  if (calls.length !== 1) {
    throw new Error('registration block must contain exactly one direct call after RIP xref at RVA ' + ripInstruction.rva);
  }
  return {
    structOffset: offsets[0].offset,
    offsetInstruction: offsets[0].instruction,
    callInstruction: calls[0].instruction,
    callTarget: calls[0].target
  };
}

function buildExactBuildDefenseFieldRegistry(options) {
  const config = Object.assign(defaultPaths(), options || {});
  const runtime = readSafeFile(config.runtimeImagePath, 'runtime image');
  const expectedHash = config.expectedImageSha256 || EXACT_IMAGE_SHA256;
  const actualHash = sha256(runtime.bytes);
  if (actualHash !== expectedHash) {
    throw new Error('runtime image SHA-256 mismatch');
  }
  if (expectedHash !== EXACT_IMAGE_SHA256) {
    throw new Error('expected image hash is not the registered exact-build hash');
  }

  const xrefs = parseJsonSafe(config.identifierXrefsPath, 'identifier xrefs');
  const registration = parseJsonSafe(config.registrationBlockPath, 'registration block');
  assertEvidenceHeader(xrefs.value, runtime.declared, 'identifier xrefs');
  assertEvidenceHeader(registration.value, runtime.declared, 'registration block');
  if (!xrefs.value.semantic_xrefs || typeof xrefs.value.semantic_xrefs !== 'object') {
    throw new Error('identifier xrefs have no semantic xrefs');
  }

  const instructions = flattenInstructions(registration.value);
  const instructionByRva = new Map(instructions.map(function (instruction) { return [instruction.rva, instruction]; }));
  const byField = new Map();

  for (const targetText of Object.keys(xrefs.value.semantic_xrefs).sort(function (left, right) { return Number(left) - Number(right); })) {
    const targetRva = Number(targetText);
    const fieldName = readCString(runtime.bytes, targetRva);
    if (!PERMITTED_FIELD_NAMES.has(fieldName)) continue;
    const references = xrefs.value.semantic_xrefs[targetText];
    if (!Array.isArray(references) || references.length === 0) throw new Error('identifier has no references for ' + fieldName);
    for (const reference of references) {
      if (!reference || reference.kind !== 'rip_relative_memory' || reference.mnemonic !== 'lea' || !/\brip\b/i.test(reference.operands || '')) {
        throw new Error('identifier RIP xref metadata is invalid for ' + fieldName);
      }
      const actualBytes = instructionBytes(runtime.bytes, reference.source_rva, reference.instruction_size);
      const source = instructionByRva.get(reference.source_rva);
      if (source && (source.mnemonic !== reference.mnemonic || source.operands !== reference.operands || source.bytes !== actualBytes)) {
        throw new Error('identifier instruction bytes do not match registration evidence for ' + fieldName);
      }
      if (instructionTargetFromRip(runtime.bytes, reference.source_rva, reference.instruction_size) !== targetRva) {
        throw new Error('RIP target does not resolve to registered C string for ' + fieldName);
      }
      if (!source) continue;
      const pair = findRegistrationPair(runtime.bytes, instructions, source);
      const record = {
        structOffset: pair.structOffset,
        targetRva: targetRva,
        cString: fieldName,
        ripXref: {
          source_rva: reference.source_rva,
          instruction_size: reference.instruction_size,
          instruction_bytes: source.bytes,
          target_rva: targetRva
        },
        block: {
          offset_instruction_rva: pair.offsetInstruction.rva,
          offset_instruction_bytes: pair.offsetInstruction.bytes,
          direct_call_rva: pair.callInstruction.rva,
          direct_call_bytes: pair.callInstruction.bytes,
          direct_call_target_va: '0x' + pair.callTarget.toString(16)
        }
      };
      if (!byField.has(fieldName)) byField.set(fieldName, []);
      byField.get(fieldName).push(record);
    }
  }

  const rows = [];
  for (const fieldName of Array.from(byField.keys()).sort()) {
    const occurrences = byField.get(fieldName);
    const offsets = new Set(occurrences.map(function (occurrence) { return occurrence.structOffset; }));
    if (offsets.size !== 1) throw new Error('ambiguous struct offset registrations for ' + fieldName);
    const uniqueOccurrences = [];
    const seen = new Set();
    for (const occurrence of occurrences) {
      const key = occurrence.ripXref.source_rva + ':' + occurrence.structOffset;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueOccurrences.push(occurrence);
      }
    }
    rows.push({
      field_name: fieldName,
      struct_offset: occurrences[0].structOffset,
      struct_offset_hex: '0x' + occurrences[0].structOffset.toString(16),
      status: STATUS,
      provenance: {
        exact_image_sha256: actualHash,
        identifier_c_string_rva: occurrences[0].targetRva,
        registration_occurrence_count: uniqueOccurrences.length,
        occurrences: uniqueOccurrences
      }
    });
  }
  if (rows.length === 0) throw new Error('no permitted defense registry field registrations were verified');

  return {
    schema_version: 1,
    artifact_type: 'VERIFIED_EXACT_IMAGE_FIELD_REGISTRY_OFFSETS',
    status: STATUS,
    exact_build: EXACT_BUILD,
    runtime_image: {
      declared_path: runtime.declared,
      sha256: actualHash,
      image_base: '0x' + IMAGE_BASE.toString(16)
    },
    field_registry_offsets: rows,
    consumer_permission: {
      registry_identity: 'PERMITTED',
      struct_offsets: 'PERMITTED',
      selector_mapping_0x0412: 'NOT_PUBLISHED',
      operation_semantics: 'NOT_PUBLISHED',
      stacking_or_order: 'NOT_PUBLISHED',
      gameplay_formula: 'NOT_PUBLISHED'
    },
    protected_holdout_access: HOLDOUT_ACCESS
  };
}

function writeExactBuildDefenseFieldRegistry(outputPath, options) {
  const output = assertNoHoldoutPath(outputPath, 'registry output');
  const parent = path.dirname(output);
  assertNoHoldoutPath(parent, 'registry output directory');
  if (!fs.existsSync(parent)) fs.mkdirSync(parent, { recursive: true });
  const physicalParent = fs.realpathSync(parent);
  if (isHoldoutPath(physicalParent)) throw new Error('registry output directory resolves through Holdout');
  const registry = buildExactBuildDefenseFieldRegistry(options);
  fs.writeFileSync(output, JSON.stringify(registry, null, 2) + '\n');
  return registry;
}

module.exports = {
  EXACT_BUILD: EXACT_BUILD,
  EXACT_IMAGE_SHA256: EXACT_IMAGE_SHA256,
  STATUS: STATUS,
  HOLDOUT_ACCESS: HOLDOUT_ACCESS,
  PERMITTED_FIELD_NAMES: PERMITTED_FIELD_NAMES,
  assertNoHoldoutPath: assertNoHoldoutPath,
  buildExactBuildDefenseFieldRegistry: buildExactBuildDefenseFieldRegistry,
  defaultPaths: defaultPaths,
  writeExactBuildDefenseFieldRegistry: writeExactBuildDefenseFieldRegistry
};
