# Public acceptance: source portability

The public regression suite and the release source package are separate checks.
Passing `npm test` does not establish that the source package is publishable.

The workflow now runs `python -B scripts/check_public_sources.py` before the long
suite. This reports every offending source file using the unchanged release
packager's allow-list and forbidden-content rules. It does not skip tests or
exclude offending test files from the archive. The final build and archive
verification still run after the tests.

Private KR 16.19.821.7343 corpus locations must not be absolute personal paths in
committed test code. Set `ROFL_KR_821_REPLAY_DIR` to the directory containing the
existing local `.rofl` files. Without this variable, repaired declarations use
`../kr-rofl-batch-collector/data/KR/16.19/builds/16.19.821.7343/rofl` relative to the
repository root. The exact-build checks, counts, assertions, runtime-image
requirements and existing missing-input skips are unchanged. No replays or
runtime images are added to the public package.

Run before pushing:

```sh
python -B scripts/check_public_sources.py
npm test
npm run package:source
npm run verify:source
```

Consecutive development pushes each trigger acceptance. A failure notice is a
new run's result, not necessarily a new underlying bug. Fix the first failing
stage and re-run all release checks; do not suppress failure exits or remove
privacy checks to make the badge green.
