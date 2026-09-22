'use strict';

const path = require('node:path');
const { importCompletedManualGroundTruth } = require('../src/manual_ground_truth_import');
const { assertNoProtectedReference } = require('../src/controlled_calibration');

function usage() {
  return 'Usage: node scripts/import_completed_manual_ground_truth.js --filled-text <file> --operator-template <file> --canonical-tasks <file> --output-directory <directory> [--hold-case CASE_ID:REASON] [--hold-cases-json <file>]';
}

function parseArguments(argv) {
  const mapping = {
    '--filled-text': 'filled_text_path',
    '--operator-template': 'operator_template_path',
    '--canonical-tasks': 'canonical_tasks_path',
    '--output-directory': 'output_directory',
    '--hold-cases-json': 'hold_cases_json',
  };
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const option = argv[index];
    if (option === '--hold-case') {
      if (index + 1 >= argv.length || argv[index + 1].startsWith('--')) throw new Error(usage());
      (result.hold_cases ??= []).push(argv[index + 1]);
      index += 1;
      continue;
    }
    if (!Object.hasOwn(mapping, option) || index + 1 >= argv.length || argv[index + 1].startsWith('--')) {
      throw new Error(usage());
    }
    const key = mapping[option];
    if (Object.hasOwn(result, key)) throw new Error(`duplicate option ${option}\n${usage()}`);
    result[key] = argv[index + 1];
    index += 1;
  }
  for (const required of ['filled_text_path', 'operator_template_path', 'canonical_tasks_path', 'output_directory']) {
    if (!Object.hasOwn(result, required)) throw new Error(usage());
  }
  if (result.hold_cases_json) {
    const source = path.resolve(result.hold_cases_json);
    assertNoProtectedReference(source, 'hold_cases_json');
    const parsed = JSON.parse(require('node:fs').readFileSync(source, 'utf8'));
    const fromJson = Array.isArray(parsed) ? parsed : Object.entries(parsed).map(([case_id, reason]) => ({ case_id, reason }));
    result.hold_cases = [...(result.hold_cases ?? []), ...fromJson];
    delete result.hold_cases_json;
  }
  return result;
}

try {
  const argumentsObject = parseArguments(process.argv.slice(2));
  const result = importCompletedManualGroundTruth({
    ...argumentsObject,
    filled_text_path: path.resolve(argumentsObject.filled_text_path),
    operator_template_path: path.resolve(argumentsObject.operator_template_path),
    canonical_tasks_path: path.resolve(argumentsObject.canonical_tasks_path),
    output_directory: path.resolve(argumentsObject.output_directory),
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
