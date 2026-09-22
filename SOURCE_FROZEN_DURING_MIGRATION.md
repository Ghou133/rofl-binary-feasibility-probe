# Source Frozen During Migration

Status: `SOURCE_FROZEN_DURING_MIGRATION`  
Effective date: `2026-08-21`  
Migration target: `../lol-inference-lab/replay/` (sibling workspace, not included here)

The latest active stage, `ROFL_DYNAMIC_DEFENSE_EFFECTIVE_DAMAGE_AND_SEMANTIC_ACQUISITION_V1`,
has stopped cleanly with:

```text
status = EVIDENCE_EXHAUSTED
stop_condition = C_EVIDENCE_EXHAUSTED
```

Its final artifact manifest and Semantic Acquisition Router manifest are present
and hash-bound. No new active development belongs in this source tree during
migration. The tree remains readable and preserved for byte/hash comparison,
regression, provenance, and rollback. It will be marked `ARCHIVED_SOURCE_PROJECT`
only after the new repository conserves capabilities, tests, profiles, ground
truth, artifacts, data references, and protected/frozen boundaries.

The protected Jungle Objective Holdout is not an inventory or migration input.
