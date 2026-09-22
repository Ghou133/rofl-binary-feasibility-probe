# Why this stage exists

Stage: `ROFL_CONTROLLED_GROUND_TRUTH_AND_SEMANTIC_FINGERPRINT_V1`  
Owner: `ROFL_PARSER`  
Exact build at stage start: `16.16.805.0442`

The previous deep-recovery stage ended at `SEMANTIC_RECOVERY_SATURATED`: all
currently safe, local, high-value hypotheses were executed, but important field
identities such as current/max HP, armor, and magic resistance still lack an
independent semantic oracle. Repeating byte scans cannot resolve those identities.

This stage therefore adds a durable Parser-owned evidence layer that keeps
semantic truth independent from build-specific routes. Controlled or supplied
ground truth is imported with exact Replay/build/time/entity provenance, aligned
against build-specific structural candidates, and converted into versioned
semantic fingerprints, negative controls, invariants, exceptions, and regression
oracles. Future builds attempt automatic structural and semantic migration first;
manual validation is allowed only when machine evidence cannot select one passing
candidate.

This is protocol-semantic validation, not downstream behavioral calibration. The
Parser does not acquire Replays, own map truth, infer player behavior, implement
gameplay profiles, or provide Akari runtime/UI. Supplied Replay fixtures and labels
remain evidence inputs; only independently verified exact-build protocol fields may
be published by the Parser capability manifest and semantic API.

The protected Jungle Objective Holdout is outside this stage and must not be read,
enumerated, hashed, decoded, tested, or consumed.
