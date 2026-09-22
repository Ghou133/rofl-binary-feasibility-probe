'use strict';

const semanticFingerprint = require('./semantic_fingerprint');
const controlledCalibration = require('./controlled_calibration');
const semanticFingerprintMatcher = require('./semantic_fingerprint_matcher');
const semanticMigrationOracle = require('./semantic_migration_oracle');
const semanticRegressionOracle = require('./semantic_regression_oracle');
const controlledGroundTruthStage = require('./controlled_ground_truth_stage');

module.exports = Object.freeze({
  semanticFingerprint,
  controlledCalibration,
  semanticFingerprintMatcher,
  semanticMigrationOracle,
  semanticRegressionOracle,
  controlledGroundTruthStage,
});
