'use strict';

const childProcess = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const EXACT_BUILD = '16.16.805.0442';
const EXACT_IMAGE_SHA256 = '0cebc4b940b69e48c79f58f627bd0103cd28b219f74d8a1678df007808de7e55';
const TRUSTED_INSPECTOR_SHA256 = '073fb4e0989a28edd0f71b029e28b8fb24872dc4aa31eae3437732512a054616';
const ROUTE_BINDING_ARTIFACT_SHA256 = '16b5f52db7371861873d0627a8e51917f19e3f281127a1eb95f7a36917f350e0';
const DAMAGE_PROFILE_SHA256 = '694e3de5b04c7a1e61d42646524dd37587f82ef9b83b5788bda69090feb87d0a';
const SHIELD_FINGERPRINT_SHA256 = '42cf7a064f9fb01ca174bb7345ec3cbc5a57cb97d8060c28e9515f93291d2b5f';
const REINCARNATE_AUDIT_SHA256 = 'e3801ae6e3946dfff7c11c7ed13637e02ef9eb8094caa3242543eb2d5f4f59d3';
const FORBIDDEN_PATH = /(?:jungle[^\\/]*objective[^\\/]*holdout|holdout)/i;

const TARGETS = Object.freeze([
  { name: 'damage_receive_callback', rva: 0x002a7fa0, size: 0x500 },
  { name: 'damage_float_text_consumer', rva: 0x0026d260, size: 0x500 },
  { name: 'on_event_callback', rva: 0x0049b050, size: 0x500 },
  { name: 'death_receive_callback', rva: 0x002a0130, size: 0x500 },
  { name: 'death_consumer', rva: 0x00243db0, size: 0x500 },
  { name: 'reincarnate_receive_callback', rva: 0x0032ce00, size: 0x500 },
  { name: 'reincarnate_consumer', rva: 0x0027b660, size: 0x500 },
  { name: 'shield_damage_receive_callback', rva: 0x002a77b0, size: 0x500 },
]);

const ANCHORS = Object.freeze([
  ['damage_field_24_load', 0x002a80aa, '8b4e24', 'mov', 'ecx, dword ptr [rsi + 0x24]'],
  ['damage_amount_decoded', 0x002a80cd, 'f30f10742458', 'movss', 'xmm6, dword ptr [rsp + 0x58]'],
  ['damage_float_text_amount', 0x002a81c8, 'f30f11742438', 'movss', 'dword ptr [rsp + 0x38], xmm6'],
  ['damage_float_text_call', 0x002a81da, 'e88150fcff', 'call', '0x14026d260'],
  ['damage_raw_amount_reload', 0x002a81ef, '8b4624', 'mov', 'eax, dword ptr [rsi + 0x24]'],
  ['damage_raw_amount_argument', 0x002a820d, 'f30f104c2468', 'movss', 'xmm1, dword ptr [rsp + 0x68]'],
  ['damage_target_virtual_slot', 0x002a81e8, '488bb820070000', 'mov', 'rdi, qword ptr [rax + 0x720]'],
  ['damage_target_virtual_call', 0x002a8216, 'ffd7', 'call', 'rdi'],
  ['on_event_parameter_blob', 0x0049b0db, '488b4318', 'mov', 'rax, qword ptr [rbx + 0x18]'],
  ['on_event_event_id', 0x0049b0e4, '0fb74328', 'movzx', 'eax, word ptr [rbx + 0x28]'],
  ['on_event_dispatch', 0x0049b138, 'e8b3ddffff', 'call', '0x140498ef0'],
  ['death_wrapper_call', 0x002a0134, 'e8773cfaff', 'call', '0x140243db0'],
  ['death_virtual_slot', 0x002440e5, '488b90c0070000', 'mov', 'rdx, qword ptr [rax + 0x7c0]'],
  ['death_packet_scalar', 0x0024410f, 'f30f104def', 'movss', 'xmm1, dword ptr [rbp - 0x11]'],
  ['death_virtual_call', 0x00244117, 'ffd2', 'call', 'rdx'],
  ['reincarnate_consumer_call', 0x0032cee8, 'e873e7f4ff', 'call', '0x14027b660'],
  ['reincarnate_virtual_slot', 0x0027b721, '488b03', 'mov', 'rax, qword ptr [rbx]'],
  ['reincarnate_virtual_call', 0x0027b73a, 'ff90500b0000', 'call', 'qword ptr [rax + 0xb50]'],
  ['shield_amount_field', 0x002a7934, '8b4310', 'mov', 'eax, dword ptr [rbx + 0x10]'],
  ['shield_amount_argument', 0x002a7985, 'f30f11442420', 'movss', 'dword ptr [rsp + 0x20], xmm0'],
  ['shield_dispatch_call', 0x002a798b, 'e8b0ec9000', 'call', '0x140bb6640'],
]);

const ROUTE_BINDINGS = Object.freeze([
  { route: '0x017f', name: 'PKT_UnitApplyDamage_s', callback_rva: 0x002a7fa0, object_size: 52 },
  { route: '0x0371', name: 'PKT_OnEvent_s', callback_rva: 0x0049b050, object_size: 48 },
  { route: '0x0112', name: 'PKT_NPC_Hero_Die_s', callback_rva: 0x002a0130, object_size: 92 },
  { route: '0x0265', name: 'PKT_HeroReincarnateAlive_s', callback_rva: null, object_size: 28 },
  { route: '0x01e1', name: 'PKT_UnitApplyShieldDamage_s', callback_rva: 0x002a77b0, object_size: 32 },
]);

const CHAIN_SPECS = Object.freeze([
  {
    id: 'damage_field_24_decode_to_xmm6', function_rva: 0x002a7fa0,
    start_rva: 0x002a80aa, end_rva: 0x002a80cd,
    required_rvas: [0x002a80aa, 0x002a80b2, 0x002a80b6, 0x002a80b9, 0x002a80be,
      0x002a80c0, 0x002a80c3, 0x002a80c8, 0x002a80cb, 0x002a80cd],
    source: 'callback_object_saved_rsi_plus_0x24', sink: 'xmm6',
  },
  {
    id: 'damage_field_24_reload_to_target_virtual_call', function_rva: 0x002a7fa0,
    start_rva: 0x002a81df, end_rva: 0x002a8216,
    required_rvas: [0x002a81df, 0x002a81e3, 0x002a81e8, 0x002a81ef, 0x002a81f2,
      0x002a81f6, 0x002a81f9, 0x002a81fe, 0x002a8200, 0x002a8203, 0x002a8208,
      0x002a820b, 0x002a820d, 0x002a8213, 0x002a8216],
    source: 'callback_object_saved_rsi_plus_0x24', sink: 'target_virtual_slot_0x720_xmm1',
  },
  {
    id: 'damage_current_xmm6_to_direct_call', function_rva: 0x002a7fa0,
    start_rva: 0x002a81b3, end_rva: 0x002a81da,
    required_rvas: [0x002a81b3, 0x002a81b6, 0x002a81ba, 0x002a81bd, 0x002a81c1,
      0x002a81c4, 0x002a81c8, 0x002a81ce, 0x002a81d2, 0x002a81d6, 0x002a81da],
    source: 'current_xmm6_value_after_control_flow_merge', sink: 'direct_call_0x0026d260_stack_plus_0x38',
  },
  {
    id: 'on_event_parameter_and_event_id_to_dispatch', function_rva: 0x0049b050,
    start_rva: 0x0049b0cd, end_rva: 0x0049b138,
    required_rvas: [0x0049b0cd, 0x0049b0d0, 0x0049b0d6, 0x0049b0db, 0x0049b0df,
      0x0049b0e4, 0x0049b0e8, 0x0049b121, 0x0049b126, 0x0049b12b, 0x0049b130,
      0x0049b133, 0x0049b138],
    source: 'callback_object_plus_0x18_qword_and_plus_0x28_u16', sink: 'direct_dispatch_0x00498ef0',
  },
  {
    id: 'death_field_10_decode_to_virtual_call', function_rva: 0x00243db0,
    start_rva: 0x002440de, end_rva: 0x00244117,
    required_rvas: [0x002440de, 0x002440e2, 0x002440e5, 0x002440ec, 0x002440f0,
      0x002440f3, 0x002440f6, 0x002440f8, 0x002440fa, 0x002440fd, 0x002440ff,
      0x00244101, 0x00244103, 0x00244106, 0x0024410a, 0x0024410d, 0x0024410f,
      0x00244114, 0x00244117],
    source: 'death_callback_object_saved_r13_plus_0x10', sink: 'owner_virtual_slot_0x7c0_xmm1',
  },
  {
    id: 'reincarnate_field_18_decode_to_consumer', function_rva: 0x0032ce00,
    start_rva: 0x0032ce04, end_rva: 0x0032cee8,
    required_rvas: [0x0032ce04, 0x0032ce0c, 0x0032ce20, 0x0032ce45, 0x0032ce48,
      0x0032ce4b, 0x0032ce4e, 0x0032cece, 0x0032cee8],
    source: 'callback_object_plus_0x18', sink: 'direct_consumer_0x0027b660_xmm2',
  },
  {
    id: 'reincarnate_consumer_xmm2_to_virtual_call', function_rva: 0x0027b660,
    start_rva: 0x0027b66d, end_rva: 0x0027b73a,
    required_rvas: [0x0027b66d, 0x0027b679, 0x0027b721, 0x0027b724, 0x0027b729,
      0x0027b72c, 0x0027b734, 0x0027b737, 0x0027b73a],
    source: 'consumer_input_xmm2_preserved_in_xmm6', sink: 'owner_virtual_slot_0xb50_xmm2',
  },
  {
    id: 'shield_field_10_decode_to_direct_dispatch', function_rva: 0x002a77b0,
    start_rva: 0x002a7934, end_rva: 0x002a798b,
    required_rvas: [0x002a7934, 0x002a793b, 0x002a7940, 0x002a794f, 0x002a7951,
      0x002a7954, 0x002a7958, 0x002a795b, 0x002a7966, 0x002a7985, 0x002a798b],
    source: 'callback_object_saved_rbx_plus_0x10', sink: 'direct_dispatch_0x00bb6640_stack_plus_0x20',
  },
]);

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function assertSafePath(candidate, { mustExist = true } = {}) {
  if (typeof candidate !== 'string' || candidate.length === 0) throw new Error('path required');
  const resolved = path.resolve(candidate);
  if (FORBIDDEN_PATH.test(resolved)) throw new Error('protected Holdout path is forbidden');
  if (!mustExist) {
    const parent = fs.realpathSync.native(path.dirname(resolved));
    if (FORBIDDEN_PATH.test(parent)) throw new Error('protected Holdout realpath is forbidden');
    return resolved;
  }
  const real = fs.realpathSync.native(resolved);
  if (FORBIDDEN_PATH.test(real)) throw new Error('protected Holdout realpath is forbidden');
  return real;
}

function rvaHex(value) {
  return `0x${value.toString(16).padStart(8, '0')}`;
}

function runInspector(imagePath, inspectorScript) {
  const args = [assertSafePath(inspectorScript), '--image', imagePath, '--size', '0x500'];
  for (const target of TARGETS) args.push('--rva', rvaHex(target.rva));
  const stdout = childProcess.execFileSync('python', args, {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, windowsHide: true,
  });
  return JSON.parse(stdout);
}

function flattenInstructions(inspector) {
  const byRva = new Map();
  for (const window of inspector.disassembly || []) {
    for (const instruction of window.instructions || []) {
      if (!byRva.has(instruction.rva)) byRva.set(instruction.rva, instruction);
    }
  }
  return byRva;
}

function verifyAnchors(instructions) {
  return ANCHORS.map(([name, rva, bytes, mnemonic, operands]) => {
    const actual = instructions.get(rva);
    if (!actual) throw new Error(`${name}: instruction ${rvaHex(rva)} absent`);
    if (actual.bytes !== bytes || actual.mnemonic !== mnemonic || actual.operands !== operands) {
      throw new Error(`${name}: exact instruction mismatch at ${rvaHex(rva)}`);
    }
    return { name, rva: rvaHex(rva), bytes, mnemonic, operands };
  });
}

function verifyRawInstructionBytes(image, instructions) {
  let verified = 0;
  for (const instruction of instructions.values()) {
    const expected = Buffer.from(instruction.bytes, 'hex');
    if (expected.length === 0 || image.subarray(instruction.rva, instruction.rva + expected.length)
      .compare(expected) !== 0) {
      throw new Error(`inspector/raw-image byte mismatch at ${rvaHex(instruction.rva)}`);
    }
    verified += 1;
  }
  return verified;
}

function linearFunctionEnvelope(instructions, entryRva) {
  const ordered = [...instructions.values()].filter((row) => row.rva >= entryRva)
    .sort((a, b) => a.rva - b.rva);
  const body = [];
  for (const instruction of ordered) {
    if (body.length && instruction.rva !== body.at(-1).rva
      + Buffer.from(body.at(-1).bytes, 'hex').length) break;
    body.push(instruction);
    if (instruction.mnemonic === 'ret') break;
  }
  if (!body.length || body[0].rva !== entryRva || body.at(-1).mnemonic !== 'ret') {
    throw new Error(`function boundary not closed at ${rvaHex(entryRva)}`);
  }
  return {
    entry_rva: rvaHex(entryRva), return_rva: rvaHex(body.at(-1).rva),
    instruction_count: body.length,
    direct_calls: body.filter((row) => row.mnemonic === 'call' && /^0x[0-9a-f]+$/.test(row.operands))
      .map((row) => ({ rva: rvaHex(row.rva), bytes: row.bytes, target: row.operands })),
    indirect_calls: body.filter((row) => row.mnemonic === 'call' && !/^0x[0-9a-f]+$/.test(row.operands))
      .map((row) => ({ rva: rvaHex(row.rva), bytes: row.bytes, target_expression: row.operands })),
  };
}

function deriveChains(instructions) {
  return CHAIN_SPECS.map((spec) => {
    const boundary = linearFunctionEnvelope(instructions, spec.function_rva);
    const ordered = [...instructions.values()]
      .filter((row) => row.rva >= spec.start_rva && row.rva <= spec.end_rva)
      .sort((a, b) => a.rva - b.rva);
    if (!ordered.length || ordered[0].rva !== spec.start_rva || ordered.at(-1).rva !== spec.end_rva) {
      throw new Error(`${spec.id}: incomplete instruction interval`);
    }
    for (let index = 1; index < ordered.length; index += 1) {
      const previous = ordered[index - 1];
      if (ordered[index].rva !== previous.rva + Buffer.from(previous.bytes, 'hex').length) {
        throw new Error(`${spec.id}: non-contiguous instruction interval`);
      }
    }
    const present = new Set(ordered.map((row) => row.rva));
    for (const required of spec.required_rvas) {
      if (!present.has(required)) throw new Error(`${spec.id}: required step ${rvaHex(required)} absent`);
    }
    const branches = ordered.filter((row) => /^(?:j[a-z]+|call)$/.test(row.mnemonic)).map((row) => ({
      rva: rvaHex(row.rva), mnemonic: row.mnemonic, target_expression: row.operands,
    }));
    return {
      id: spec.id, linear_function_envelope: boundary, source: spec.source, sink: spec.sink,
      start_rva: rvaHex(spec.start_rva), end_rva: rvaHex(spec.end_rva),
      contiguous_instruction_count: ordered.length,
      required_steps: spec.required_rvas.map(rvaHex),
      branches_and_calls: branches,
      instructions: ordered.map((row) => ({
        rva: rvaHex(row.rva), bytes: row.bytes, mnemonic: row.mnemonic, operands: row.operands,
      })),
      interval_sha256: sha256(Buffer.concat(ordered.map((row) => Buffer.from(row.bytes, 'hex')))),
      validation: 'CONTIGUOUS_RAW_BYTES_MATCHED_REQUIRED_RVA_ANCHORS_WITHIN_LINEAR_ENTRY_RET_ENVELOPE',
    };
  });
}

function allObjects(value, output = []) {
  if (!value || typeof value !== 'object') return output;
  if (!Array.isArray(value)) output.push(value);
  for (const child of Object.values(value)) allObjects(child, output);
  return output;
}

function verifyRouteBindings(bindingDocument) {
  const objects = allObjects(bindingDocument);
  return ROUTE_BINDINGS.map((expected) => {
    const matches = objects.filter((row) => row.name === expected.name
      && row.registration_id_hex === expected.route
      && row.callback_receive_target_rva === expected.callback_rva
      && row.factory_packet?.object_size === expected.object_size);
    if (matches.length !== 1) throw new Error(`${expected.route}: exact route binding count ${matches.length}`);
    const row = matches[0];
    return {
      route: expected.route, runtime_type_name: expected.name,
      callback_rva: expected.callback_rva === null ? null : rvaHex(expected.callback_rva),
      callback_owner_type: row.callback_owner_type,
      object_size: expected.object_size,
      deserializer_rva: row.factory_packet.deserializer_rva_hex,
      registration_path_kind: row.registration_path_kind,
      status: 'VERIFIED_FROM_SHA_BOUND_EXACT_BUILD_REGISTRATION_ARTIFACT',
    };
  });
}

function targetSlices(image) {
  return TARGETS.map((target) => {
    const bytes = image.subarray(target.rva, target.rva + target.size);
    if (bytes.length !== target.size) throw new Error(`${target.name}: slice outside image`);
    return {
      name: target.name, rva: rvaHex(target.rva), size: target.size,
      sha256: sha256(bytes),
    };
  });
}

function probeExactCombatDataflow(options = {}) {
  const rootDir = assertSafePath(options.rootDir || path.resolve(__dirname, '..'));
  const imagePath = assertSafePath(options.imagePath || path.join(rootDir, 'artifacts',
    'new_build_rofl_compatibility_gate_v1', 'runtime', 'league_16.16.805.0442.memory.bin'));
  const inspectorScript = assertSafePath(options.inspectorScript
    || path.join(rootDir, 'scripts', 'inspect_runtime_image.py'));
  const routeBindingArtifact = assertSafePath(options.routeBindingArtifact
    || path.join(rootDir, 'artifacts', 'hero_combat_state_v2', 'runtime',
      'hero_combat_state_runtime_trace_16_16.json'));
  const damageProfileArtifact = assertSafePath(options.damageProfileArtifact
    || path.join(rootDir, 'artifacts', 'hero_combat_state_v2', 'emulation', 'profiles',
      'packet_017f.json'));
  const shieldFingerprintArtifact = assertSafePath(options.shieldFingerprintArtifact
    || path.join(rootDir, '.omo', 'evidence', 'quant_combat_closure',
      'shield_absorbed_semantic_fingerprint.json'));
  const reincarnateAuditArtifact = assertSafePath(options.reincarnateAuditArtifact
    || path.join(rootDir, 'artifacts', 'full_semantic_deep_recovery_v2', 'hero_respawn',
      'hero_reincarnate_alive_audit_16_16.json'));
  const image = fs.readFileSync(imagePath);
  const imageHash = sha256(image);
  if (imageHash !== EXACT_IMAGE_SHA256) throw new Error('exact runtime image SHA mismatch');
  const inspectorBuffer = fs.readFileSync(inspectorScript);
  if (sha256(inspectorBuffer) !== TRUSTED_INSPECTOR_SHA256) {
    throw new Error('trusted inspector implementation SHA mismatch');
  }
  const bindingBuffer = fs.readFileSync(routeBindingArtifact);
  if (sha256(bindingBuffer) !== ROUTE_BINDING_ARTIFACT_SHA256) {
    throw new Error('route binding artifact SHA mismatch');
  }
  const bindingDocument = JSON.parse(bindingBuffer.toString('utf8'));
  if (bindingDocument.build !== EXACT_BUILD || bindingDocument.image?.sha256 !== EXACT_IMAGE_SHA256
    || bindingDocument.image?.size !== image.length) {
    throw new Error('route binding artifact exact-build/image identity mismatch');
  }
  const routeBindings = verifyRouteBindings(bindingDocument);
  const damageProfileBuffer = fs.readFileSync(damageProfileArtifact);
  if (sha256(damageProfileBuffer) !== DAMAGE_PROFILE_SHA256) {
    throw new Error('damage profile artifact SHA mismatch');
  }
  const damageProfile = JSON.parse(damageProfileBuffer.toString('utf8'));
  if (damageProfile.profile?.client_opcode !== '0x017f'
    || damageProfile.profile?.fields?.find((row) => row.name === 'field_24_f32')?.offset !== 36
    || damageProfile.verified_semantic_fields?.field_24_f32 !== 'recorded_amount_stage_unknown') {
    throw new Error('damage field_24 profile binding mismatch');
  }
  const shieldFingerprintBuffer = fs.readFileSync(shieldFingerprintArtifact);
  if (sha256(shieldFingerprintBuffer) !== SHIELD_FINGERPRINT_SHA256) {
    throw new Error('shield semantic fingerprint SHA mismatch');
  }
  const shieldFingerprint = JSON.parse(shieldFingerprintBuffer.toString('utf8'));
  const shieldBinding = shieldFingerprint.build_bindings?.find((row) => row.exact_build === EXACT_BUILD);
  if (shieldFingerprint.semantic_name !== 'SHIELD_ABSORBED'
    || shieldBinding?.binding?.route !== '0x01e1'
    || shieldBinding?.binding?.callback_rva !== '0x002a77b0') {
    throw new Error('shield semantic fingerprint binding mismatch');
  }
  const reincarnateAuditBuffer = fs.readFileSync(reincarnateAuditArtifact);
  if (sha256(reincarnateAuditBuffer) !== REINCARNATE_AUDIT_SHA256) {
    throw new Error('reincarnate audit artifact SHA mismatch');
  }
  const reincarnateAudit = JSON.parse(reincarnateAuditBuffer.toString('utf8'));
  if (reincarnateAudit.exact_build !== EXACT_BUILD
    || reincarnateAudit.native_decode?.route !== '0x0265'
    || reincarnateAudit.static_runtime_chain?.callback_receive_target_rva !== '0x0032ce00'
    || reincarnateAudit.static_runtime_chain?.object_size !== 28) {
    throw new Error('reincarnate callback audit binding mismatch');
  }
  const reincarnateRoute = routeBindings.find((row) => row.route === '0x0265');
  reincarnateRoute.callback_rva = '0x0032ce00';
  reincarnateRoute.callback_binding_status = 'VERIFIED_FROM_SEPARATELY_SHA_BOUND_EXACT_BUILD_AUDIT';
  const inspected = runInspector(imagePath, inspectorScript);
  if (inspected.image_base !== 0x140000000) throw new Error('unexpected image base');
  const instructions = flattenInstructions(inspected);
  const independentlyVerifiedInstructionCount = verifyRawInstructionBytes(image, instructions);
  const selectedInstructions = verifyAnchors(instructions);
  const machineDerivedChains = deriveChains(instructions);

  return {
    schema: 'ROFL_EXACT_COMBAT_DATAFLOW_PROBE_V1',
    schema_version: 1,
    exact_build: EXACT_BUILD,
    status: 'EVIDENCE_EXHAUSTED',
    architecture_gate: 'PASS',
    image: {
      path: path.relative(rootDir, imagePath).replaceAll('\\', '/'),
      bytes: image.length,
      sha256: imageHash,
      image_base: '0x140000000',
    },
    trusted_inputs: {
      inspector: {
        path: path.relative(rootDir, inspectorScript).replaceAll('\\', '/'),
        bytes: inspectorBuffer.length, sha256: sha256(inspectorBuffer),
      },
      exact_build_route_registration_artifact: {
        path: path.relative(rootDir, routeBindingArtifact).replaceAll('\\', '/'),
        bytes: bindingBuffer.length, sha256: sha256(bindingBuffer),
      },
      damage_field_profile: {
        path: path.relative(rootDir, damageProfileArtifact).replaceAll('\\', '/'),
        bytes: damageProfileBuffer.length, sha256: sha256(damageProfileBuffer),
      },
      shield_absorbed_fingerprint: {
        path: path.relative(rootDir, shieldFingerprintArtifact).replaceAll('\\', '/'),
        bytes: shieldFingerprintBuffer.length, sha256: sha256(shieldFingerprintBuffer),
      },
      reincarnate_callback_audit: {
        path: path.relative(rootDir, reincarnateAuditArtifact).replaceAll('\\', '/'),
        bytes: reincarnateAuditBuffer.length, sha256: sha256(reincarnateAuditBuffer),
      },
    },
    bounded_scope: {
      method: 'STATIC_EXACT_IMAGE_X86_64_PINNED_CONTIGUOUS_INSTRUCTION_INTERVALS',
      target_slices: targetSlices(image),
      string_proximity_used_as_semantic_evidence: false,
      process_started_or_attached: false,
      hooking_or_injection: false,
      anti_cheat_bypass: false,
      protected_holdout_accessed_enumerated_hashed_or_consumed: false,
      inspector_emitted_instruction_count_independently_matched_to_raw_image:
        independentlyVerifiedInstructionCount,
    },
    route_bindings: routeBindings,
    field_bindings: {
      DAMAGE_RECORDED_AMOUNT_STAGE_UNKNOWN: {
        route: '0x017f', callback_object_offset: '0x24', type: 'f32',
        profile_status: 'SHA_BOUND_UPSTREAM_PROFILE', profile_sha256: DAMAGE_PROFILE_SHA256,
      },
      GENERIC_ON_EVENT_PARAMETER: {
        route: '0x0371', callback_object_offset: '0x18', type: 'opaque_qword',
        semantic_limit: 'The static generic callback does not itself identify event id 0x004b as heal.',
      },
      SHIELD_ABSORBED: {
        route: '0x01e1', callback_object_offset: '0x10', type: 'f32',
        profile_status: 'SHA_BOUND_UPSTREAM_SEMANTIC_FINGERPRINT_PLUS_EXACT_CALLBACK_CHAIN',
        profile_sha256: SHIELD_FINGERPRINT_SHA256,
      },
      DEATH_PACKET_FIELD_10: {
        route: '0x0112', callback_object_offset: '0x10', type: 'protected_f32', semantic: 'UNKNOWN',
      },
      REINCARNATE_PACKET_FIELD_18: {
        route: '0x0265', callback_object_offset: '0x18', type: 'protected_f32', semantic: 'UNKNOWN',
      },
    },
    exact_instruction_anchors: selectedInstructions,
    machine_derived_contiguous_instruction_intervals: machineDerivedChains,
    traces: {
      damage_0x017f_field_24: {
        route_binding: '0x017f/PKT_UnitApplyDamage_s/callback 0x002a7fa0',
        field_binding: 'SHA-bound field_24_f32 profile: recorded amount, stage unknown',
        machine_interval_ids: [
          'damage_field_24_decode_to_xmm6',
          'damage_field_24_reload_to_target_virtual_call',
          'damage_current_xmm6_to_direct_call',
        ],
        scope_limit: 'The direct-call chain starts from current xmm6 after a control-flow merge; an intervening optional addss at 0x002a811d..0x002a8121 prevents claiming that this argument always equals field_24 alone.',
        missing_edge: 'No resolved instruction path from virtual slot +0x720 to mitigation, shield debit, health subtraction, absolute health storage, or HUD projection.',
      },
      generic_on_event_0x0371: {
        route_binding: '0x0371/PKT_OnEvent_s/callback 0x0049b050',
        field_binding: 'object +0x18 opaque qword and +0x28 protected u16 event id',
        machine_interval_ids: ['on_event_parameter_and_event_id_to_dispatch'],
        scope_limit: 'This callback chain is generic event dispatch. This probe does not statically bind a particular invocation to heal event id 0x004b.',
        missing_edge: 'No clamp against current/max health, effective delta, overheal branch, or health writer is present in the bounded callback path.',
      },
      death_and_reincarnate: {
        route_bindings: ['0x0112/PKT_NPC_Hero_Die_s', '0x0265/PKT_HeroReincarnateAlive_s'],
        machine_interval_ids: [
          'death_field_10_decode_to_virtual_call',
          'reincarnate_field_18_decode_to_consumer',
          'reincarnate_consumer_xmm2_to_virtual_call',
        ],
        semantic_limit: 'Both packet scalar semantics remain UNKNOWN; only their exact object offsets and call arguments are claimed.',
        missing_edge: 'The death (+0x7c0) and reincarnate (+0xb50) virtual targets differ and neither body nor a shared absolute-health accessor/writer is resolved.',
      },
      shield_0x01e1_absorbed: {
        route_binding: '0x01e1/PKT_UnitApplyShieldDamage_s/callback 0x002a77b0',
        field_binding: 'SHA-bound SHIELD_ABSORBED fingerprint plus callback object +0x10 f32 chain',
        machine_interval_ids: ['shield_field_10_decode_to_direct_dispatch'],
        missing_edge: 'No shield instance identifier, layer key, remaining-balance read/write, expiry, replacement, or removal edge is carried by the verified amount path.',
      },
    },
    promotion_decisions: {
      DAMAGE_STAGE: {
        decision: 'NO_PUBLIC_PROMOTION', status: 'EVIDENCE_EXHAUSTED',
        reason: 'field_24 reaches an unresolved target virtual method; a separate post-merge current-xmm6 interval reaches direct call 0x0026d260 but is not proven to equal field_24 alone. Neither call target is resolved as a health/mitigation/shield writer, so no unique stage is identified.',
      },
      CURRENT_HP: {
        decision: 'NO_PUBLIC_PROMOTION', status: 'EVIDENCE_EXHAUSTED',
        reason: 'No absolute health anchor or shared death/reincarnate health accessor/writer was resolved.',
      },
      HEAL_EFFECTIVE: {
        decision: 'NO_PUBLIC_PROMOTION', status: 'EVIDENCE_EXHAUSTED',
        reason: 'The generic 0x0371 callback interval reaches direct call 0x00498ef0 but has no verified health clamp or applied delta; it does not statically identify a heal invocation.',
      },
      OVERHEAL: {
        decision: 'NO_PUBLIC_PROMOTION', status: 'EVIDENCE_EXHAUSTED',
        reason: 'Reported amount cannot be split without verified pre-health, max-health, clamp, and effective delta.',
      },
      SHIELD_REMAINING: {
        decision: 'NO_PUBLIC_PROMOTION', status: 'EVIDENCE_EXHAUSTED',
        reason: 'The absorbed-amount interval reaches direct call 0x00bb6640 but has no verified remaining-balance lifecycle edge.',
      },
      SHIELD_INSTANCE: {
        decision: 'NO_PUBLIC_PROMOTION', status: 'EVIDENCE_EXHAUSTED',
        reason: 'The verified callback fields do not establish source or instance identity.',
      },
    },
    external_input_required: [
      'Resolved concrete implementation for the damage target virtual slot +0x720, bound to the exact AIHeroClient vtable/class.',
      'Exact-build absolute current-health read/write anchor (or governed pre/post-health observations without intervening events).',
      'Exact shield instance lifecycle records linking grant, absorb, replacement/removal, and remaining balance.',
    ],
  };
}

module.exports = {
  ANCHORS,
  EXACT_BUILD,
  EXACT_IMAGE_SHA256,
  TARGETS,
  assertSafePath,
  probeExactCombatDataflow,
};
