# AI / developer handoff

Protocol research remains `SOURCE_FROZEN_DURING_MIGRATION`; the semantic baseline
is 2026-08-21. Authorized maintenance does not promote fields, delete evidence,
reopen research, or create a second active implementation.

## Start here

Read [README](README.md), [public maintenance](docs/PUBLIC_DEVELOPMENT.md),
[AGENTS](AGENTS.md), then only the relevant source/tests. Ownership and state are
in [PROJECT_CHARTER](PROJECT_CHARTER.md) and `project_contract.json`.

The legacy CLI calls `src/semantic_pipeline.js` and supports semantic analysis of
**16.15.801.3452 only**. The library's separate `src/semantic_api.js` contains
16.16 exact-build surfaces; the CLI does not automatically dispatch to them.
Do not remove version checks or feed one build into another decoder.

Container fixes belong in `src/rofl.js`; raw analysis in `src/analysis.js`; command
orchestration in `src/cli.js`; execution-scoped reports in `src/cli_report.js`;
packaging in `scripts/package_handoff.py`. Preserve research-v3/v4 and existing
Node/Python test directories. A filename containing an old stage is not proof
that its code is unused.

## Evidence rules

Preserve exact versions, source SHA, packet offsets, payload hashes and field
confidence. Direct, derived, partial, candidate and unavailable are different.
Decoder failure, a missing input, an unsupported build and a valid zero-event
result must remain distinct. `UNAVAILABLE` stays null, not zero.

Match Details is validation-only. Ward cast targets are not spawn coordinates.
Reported healing is not effective healing or overheal. Target-total shield
absorption is not source/instance attribution. MaxHP/Armor/MR remain unpublished
when governed inputs are missing. Do not promote fields merely to make tests pass.

Do not read, enumerate, hash, decode, test or consume the protected Jungle
Objective Holdout. Do not overwrite original evidence, negative results or
historical source hashes. Use a separate output directory for reruns.

## Verify without overstating

`npm test` runs the public suite; `npm run test:maintenance` isolates maintenance
regressions. `npm run test:all` and CLI `validate` retain the full Node suite.
V3/V4 and entity/item Python suites have separate commands and input requirements.
`package:source` needs public source; `package:handoff` explicitly requires the
bounded-evidence inputs. Neither package is a raw re-decoding capsule.

Report commands actually executed, pass/fail/skip counts, missing private inputs,
untested platforms and remaining capabilities separately. Never count a missing
fixture as an ordinary pass or label old attestations as a fresh reproduction.

Historical field notes and results remain in
[VALIDATION_STATUS](VALIDATION_STATUS.md), the capability/version matrices and
[the archived handoff](docs/history/AI_HANDOFF-20260923.md). That archive is not a
current task list or current command guide.
