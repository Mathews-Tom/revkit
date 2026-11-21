# revkit execution prompts

Execution is not authorized by this file. See [the development plan](DEVELOPMENT_PLAN.md) for the product contract, release gates and operating rules. Only S0 is dependency-ready. Render the next prompt only after its prerequisites merge or evidence lands; outcome or acceptance changes require owner approval.

### S0 — Harness capability spike (unshipped)

```text
/goal Deliver S0 (Harness capability spike) from .docs/DEVELOPMENT_PLAN.md §3 as one reviewed, evidence-only PR after owner execution authorization.

PROJECT: revkit is a Rust pre-push review CLI with anchored findings, explicit coverage, proof-driven repair and model-free CI verification of exact-head receipts.
GOAL: Identify a confined, working first subscription runtime/channel for 0.1, or record an actionable NO-GO.
CONTEXT: No delivery predecessor. Test only disposable synthetic Git fixtures with inert canaries. Get explicit auth/terms, provider/data and bounded usage approval per live lane. Record missing input without probing that lane. Separate help, offline fixture and actual-auth evidence. Attachment is per run; fallback needs independently confined filtered context and a typed final message.
PRESERVE: No persistent settings or checkout changes. Deny ambient configuration, unauthorized tools, reads, writes and egress. Preserve only reviewed sanitized evidence; no raw transcripts or secrets in Git.
NON-GOALS: No Rust CLI, adapter implementation, comparison-tool probe, replay, real code, artifact publication or release. Do not infer support across versions, platforms or channels.

DONE WHEN:
- Done when an operator can read a versioned matrix covering omp, Claude Code, Codex and agy and see an attach, fallback or refusal decision for each, with version/platform/auth/channel, evidence class and explicit unavailable or uncertified reasons where applicable.
- Done when an operator can reproduce authorized cases with sanitized fixtures or exact safe steps and see typed success with per-file settlement and a validated anchor, plus explicit failure for omitted verdict, forbidden access and bounded no-progress/timeout cleanup, with observed model/usage or explicit unknowns.
- Done when an operator can read a first-runtime GO naming one tested version/platform/subscription/channel that passed every required case under actual approved authentication, or a NO-GO naming missing evidence and the smallest safe next decision. Offline-only, unrun or failed cases cannot yield GO.

VERIFICATION: S0 creates its own checks. Run `python3 spike/check_matrix.py --self-test` (exit 0 when valid GO and NO-GO validate and invalid GO examples are rejected) and `python3 spike/check_matrix.py spike/capabilities.v1.json` (exit 0 for a consistent report, not certification). Follow the recorded authorized case commands and §3 expected results, including bad-anchor correction, missing verdict, boundary canaries and teardown. Stop each lane at pass, evidenced failure or unavailable prerequisite within authorized limits. Missing required observation is a non-pass, not a simulated result.
Require an observed denied attempt at the real boundary with a reachable inert canary. A refusal by the model is not containment evidence. Observe supervised teardown of descendants.
PR SHAPE: One evidence-only PR; no published product. Use one substantive review and normal authorized shipping gates. Escalate after three unsuccessful fix rounds; never solicit external reviewers.
FINAL REPORT: Decision per harness, evidence class, check outputs, first-runtime GO/NO-GO, review/landing state and PR URL. Separate unverified capacities from passes.
NEXT STEPS:
1. Current milestone: land only with authority and verified checks; otherwise report exact gate.
2. Release: none for S0.
3. Next milestone: after merged evidence and GO, render R01 from the approved plan; on NO-GO keep R01 unready and record the owner decision needed.
```
