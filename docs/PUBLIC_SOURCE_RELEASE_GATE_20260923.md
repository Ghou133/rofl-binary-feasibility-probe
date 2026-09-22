# Public source release architecture gate — 2026-09-23

`PROJECT_CONTEXT_LOADED = YES`

## Decision scope

The user authorized publishing this project's source to GitHub. This gate covers a public source snapshot, its GPL-3.0-only license, release documentation, and narrowly scoped path cleanup. It does not promote any protocol field, capability, evidence grade, project stage, consumer permission, or feature pack.

## Authority and ownership

- V2 `SYSTEM_NORTH_STAR.md`, `SYSTEM_PROJECT_MAP.md`, `SYSTEM_DECISION_LOG.md` (especially D-002, D-006, D-009, D-010 and D-013), `CAPABILITY_REGISTRY.md`, and `EVIDENCE_SOURCE_REGISTRY.md` remain canonical. The local `PROJECT_CHARTER.md` and `project_contract.json` define the parser boundary.
- This repository remains `SOURCE_FROZEN_DURING_MIGRATION`. `lol-inference-lab/replay/` is the active long-term implementation target. A public GitHub repository is a historical source and documentation snapshot, not a second active protocol authority.
- The parser owns container/packet decoding, exact-build protocol semantics, evidence grades and published parser interfaces. Map knowledge, behavior inference, data acquisition, runtime state and UI remain with their assigned owners.

## Publication boundary

- Publish original source, tests, project documentation and small path-free historical summaries. Do not publish `.rofl` files, client/runtime images, DuckDB/Parquet, full packet/Match Details corpora, player identifiers, local review state, or the protected Jungle Objective Holdout.
- Keep `evidence/exact_build_route_attestations/` local: its attestation contains raw payload bytes. Preserve its original files and hashes locally; describe the resulting clean-clone test limitation. No evidence is relabeled as reproduced after omission.
- Remove local absolute user paths from the public source and replace them with explicit inputs or hash-bound replay identities. Preserve the original local file bytes and hashes before editing. This is publication hygiene within the existing contract, not active semantic development.
- License only the repository's original code and documentation under GPL-3.0-only. The license does not grant rights over Riot/Tencent or other third-party data, binaries, trademarks or materials.

## Acceptance and failure policy

- Before pushing, inspect the exact staged file list and scan it for paths, credentials, player payloads and disallowed binary/data classes. Run focused tests and portable tests; report any tests requiring excluded evidence as unexecuted on a clean clone.
- Preserve all local raw, frozen, failed, negative and historical assets. A failed publication check blocks the push until corrected, without changing existing capability statuses.
- The public README must distinguish implemented, partial, candidate, unavailable, historical evidence and current rerun results. It must explain architecture, route ownership, roadmap and the source migration freeze.

## Result

The scoped public source release is consistent with the V2 ownership and preservation rules. No protected or non-owned asset is authorized for publication.

`ARCHITECTURE_GATE = PASS`
