#!/usr/bin/env node
'use strict';

const path = require('node:path');
const { runQuantizedCombatReconstruction } = require('../src/quantized_combat_reconstruction');

const ROOT = path.resolve(__dirname, '..');
let outputDir = path.join(ROOT, '.omo', 'evidence', 'quant_combat_closure');
let shieldMigrationScanPath = null;
for (let index = 2; index < process.argv.length; index += 1) {
  if (process.argv[index] === '--output-dir') outputDir = path.resolve(process.argv[++index]);
  else if (process.argv[index] === '--reuse-shield-scan') shieldMigrationScanPath = path.resolve(process.argv[++index]);
  else throw new Error(`unknown argument: ${process.argv[index]}`);
}

runQuantizedCombatReconstruction({
  outputDir,
  shieldMigrationScanPath,
  inputs: {
    controlledDamage: path.join(ROOT, 'artifacts', 'controlled_calibration_replays', 'HN1-11212942693', 'p0_anchor_scan', '0x017f_decoded.jsonl'),
    latestDamage: path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'emulation', 'packet_017f_latest_four_decoded.jsonl'),
    damageValidation: path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'damage', 'damage_16_16_anchor_validation.json'),
    deathValidation: path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'death', 'death_16_16_route_anchor_validation.json'),
    deepReport: path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'buff_spell', 'buff_spell_damage_deep_analysis_latest_four.json'),
    shieldSamples: path.join(ROOT, 'artifacts', 'protection_v4_publication', 'shield_absorption_samples.json'),
    runtimeTrace: path.join(ROOT, 'artifacts', 'hero_combat_state_v2', 'runtime', 'hero_combat_state_runtime_trace_16_16.json'),
    runtimeImage: path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'runtime', 'league_16.16.805.0442.memory.bin'),
    legacyProtectionContract: path.join(ROOT, 'artifacts', 'protection_v4_probe', 'protection_v4_field_contract.json'),
    legacyShieldReplayManifest: path.join(ROOT, 'artifacts', 'protection_v4_probe', 'packet_0017_all14.jsonl.manifest.json'),
    shieldCallbackDisassembly: path.join(ROOT, '.omo', 'evidence', 'quant_combat_closure', 'runtime_01e1_callback_disassembly.json'),
    replayInventoryCsv: path.join(ROOT, 'artifacts', 'new_build_rofl_compatibility_gate_v1', 'new_build_replay_inventory.csv'),
    onEventLatest: path.join(ROOT, 'artifacts', 'full_semantic_deep_recovery_v2', 'buff_spell', 'packet_0371_selected_decoded_latest_four.jsonl'),
  },
}).then(({ paths }) => process.stdout.write(`${JSON.stringify(paths)}\n`)).catch((error) => {
  process.stderr.write(`${error.stack || error.message}\n`);
  process.exitCode = 1;
});
