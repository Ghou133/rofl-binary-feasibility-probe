# Project instructions

The parser owns replay protocol semantics only. It must not claim or implement map truth, behavior inference, offline corpus collection, Akari runtime acquisition/cache/state, or UI. Consumers must use published interfaces; do not copy decoder logic across boundaries.

## V2 Governance

V2 at `..\LOL_RESEARCH_SYSTEM_GOVERNANCE_V2` is the source of truth. Never execute V1 or treat archived decisions as a current task.

- For ordinary explanation, documentation, or a local fix within the existing contract, read the relevant local files and verify the affected behavior directly. Do not load the full governance history or create a gate record for every task.
- Before changing architecture, ownership, a cross-project interface, a published capability, or an asset's status, read local `PROJECT_CHARTER.md` and `project_contract.json`, then the relevant parts of `SYSTEM_NORTH_STAR.md`, `SYSTEM_PROJECT_MAP.md`, `SYSTEM_DECISION_LOG.md`, `CAPABILITY_REGISTRY.md`, and `EVIDENCE_SOURCE_REGISTRY.md` under the shared V2 directory. Read only the local evidence needed for that change.
- For those boundary changes, record the actual decision using the shared `ARCHITECTURE_GATE_TEMPLATE.md`; proceed with the affected change only on `ARCHITECTURE_GATE = PASS`. A fail blocks that change, not independent work already within the contract. Existing user authorization does not need a second approval.
- Preserve provenance, original evidence, frozen/incomplete state, published contracts, and explicit user suspensions. Instruction cleanup does not itself authorize research-asset deletion or product work.
