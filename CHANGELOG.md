# Changelog

## Unreleased

## 0.2.0

- **Breaking for custom reviewer harnesses:** replace model-generated source excerpts and line numbers with deterministic request-scoped diff anchors. Resolve coordinates and excerpts against pinned Git blobs, and keep paths with unknown, cross-file, or unavailable source anchors unsettled. Existing saved finding coordinates remain readable.
- Distinguish offline review request size from harness-reported token counters and show the counters in the default review output.
- Show the saved head, per-file coverage, and run reasons when listing saved findings in text mode.
- Show OMP-reported upstream HTTP error statuses without saving raw provider diagnostics; keep process timeouts distinct.
- Include per-file coverage and run reasons in saved findings JSON.
- Document the version-specific `--no-tools` isolation observations for OMP 19.1.1 and 19.2.1, including the latter's explicit extension and hook restriction. Revkit remains trusted-local, not a sandbox.
- Record default-on owner-private local review metrics with an opt-out, selectable ignored repository store, per-attempt and deduplicated explicit PR counts, bounded retention, and offline inspection/deletion.
- Keep local review accounting independent of review verdicts, with bounded lock waits, cleanup of abandoned staging files, and explicit unknown usage rather than estimated costs.

## 0.1.1

- First release through crates.io Trusted Publishing. No CLI or dependency changes since `0.1.0`.

## 0.1.0

- Add `init`, `doctor`, and an offline `plan` for pinned Git ranges and single commits. Show trusted-base rules, scope, planned checks, and single-unit admission without running a reviewer or checks.
- Add explicit trusted-local OMP review with typed per-file coverage, exact anchors, opt-in head checks, and distinct incomplete and unavailable outcomes.
- Add versioned JSON and SARIF reports plus local finding and effective-rule lookup.
- Preserve trusted rules and risk tiers across renames, withhold ambiguous protected moves, and verify base anchors against removed lines. Report unavailable-check reasons and how to open a saved run when updating `latest` fails.
