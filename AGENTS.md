# Project instructions

The parser owns replay protocol semantics only. Do not add map truth, behavior
inference, offline corpus collection, live acquisition/cache/state or UI. Consumers
use published interfaces; do not copy decoder logic across ownership boundaries.

## Current state and ordinary maintenance

Protocol development is `SOURCE_FROZEN_DURING_MIGRATION`; the semantic baseline is
2026-08-21. This is not a second active protocol implementation. Read
`PROJECT_CHARTER.md`, `project_contract.json`, `docs/PUBLIC_DEVELOPMENT.md`, then
only the source and tests needed for the current task.

Documentation, packaging, parser safety and fixes within the existing contract
can be reviewed using this repository alone. No private sibling directory or
historical architecture gate is a prerequisite to ordinary maintenance. Existing
user authorization does not need a second approval.

Run focused tests. Report actual passes, failures, skips, missing inputs and
untested platforms separately. `npm test` is the public suite; `npm run test:all`
and CLI `validate` retain the full Node suite, including private-input tests.
Never hide a failed check or turn a missing fixture into an ordinary pass.

## Evidence and boundary changes

Preserve exact-build gates, published interfaces, original provenance, failed and
negative evidence, frozen/incomplete states and explicit user suspensions.
Unavailable is not zero. Maintenance does not authorize new semantic fields,
research-asset deletion, holdout access, or product work.

Cross-project architecture, ownership, a published capability, or a research
asset's status still requires the maintainer's V2 governance context and a recorded
`ARCHITECTURE_GATE = PASS`. The private integration and required documents are
listed in `docs/PUBLIC_DEVELOPMENT.md`. If absent, stop that boundary change, not
independent maintenance already within scope. Never fabricate gate results, run
V1 governance, or treat archived decisions as current tasks.
