# S0 harness evidence

[`capabilities.v1.json`](capabilities.v1.json) records **NO-GO** for the first subscription runtime. The owner authorized offline work and evidence publication and named all four harnesses, but did not supply a complete live-lane approval for any of them. No harness was invoked, including for version or help. A `refusal` here is an operator decision not to run a lane, not a harness failure or a model refusing a request. The `null` values mark fields not recorded for these unrun lanes; the workstation's platform is not a tested runtime platform. No model or usage was observed.

## Reproduce the recorded checks

Run from the repository root with Python 3.10 or later and no third-party dependencies:

```sh
python3 spike/check_matrix.py --self-test
python3 spike/check_matrix.py spike/capabilities.v1.json
```

Both commands must exit 0. The first exercises the decision rules using in-memory records, including fictitious complete GO records. It is not an offline harness run. The second validates consistency of the checked-in report, not the truth of its observations or runtime certification. There are no authorized live case commands or boundary observations to reproduce in this report.

## Evidence required to change the decision

Approve **one exact tuple** first: binary/version, OS/architecture, subscription auth method and terms, provider/endpoints, synthetic data scope and hard request, attempt, wall-time, output and usage limits. Record the approval basis without recording credentials or account identifiers. Stop if authentication requires ambient config or a persistent settings edit, the transport cannot be confined to the approved endpoints, or the supervisor cannot prove descendant cleanup.

Use a disposable Git fixture with at least two assigned files and a pinned comparison side. Use only rights-cleared inert contents, a unique known anchor, and separate inert denial canaries. Start with per-invocation least-privilege attachment where authorized. Before considering fallback, record a non-pass for `per_run_attachment` and explain why it cannot be certified. Use `not-observed` with evidence class `none` if a missing prerequisite prevented any probe; describe that prerequisite instead of inventing invocation steps. Verify fallback independently: filter out denied inputs, enforce a read-only projection, and validate a typed final message without ambient tools. Do not infer confinement from a successful attachment or schema-shaped output.

For each attempted case, record the non-secret exact setup/invocation or fixture steps under `reproduction`, and the bounded, redacted result and its source under `observation`. Record `help`, `offline-fixture`, and `actual-auth` separately; `none` denotes no harness evidence. An omitted case is unrun. A case whose required observation was missing is not a pass. To count as `actual-auth`, containment and cleanup observations must use the same authorized channel and confinement as the authenticated lane; a standalone sandbox or stub result does not qualify.

| Case ID | Observation required for a pass |
| --- | --- |
| `per_run_attachment` | A gateway is attached for this invocation only. Record how the allowed tool is selected and confirm no persisted attachment. |
| `filtered_typed_fallback` | Independently confined, read-only projection contains only allowed inputs; the final typed message is parsed and validated. |
| `pinned_input` | The lane reads the allowed pinned input; record the comparison side and object identity and verify the bytes read. |
| `typed_settlement` | Validate the typed result, explicit successful completion, exactly one terminal verdict per assigned file, and a valid anchor against the pinned bytes. |
| `bad_anchor_correction` | Record the rejected anchor and bounded correction; independently validate the corrected anchor against the pinned bytes. |
| `missing_verdict` | A bare finish or omitted required verdict produces explicit incomplete coverage, never success. |
| `ambient_config_denied`, `ambient_tool_denied` | Record attempted config/tool loading reaching the enforcing boundary, denial, and no load or discovery of the ambient canary. |
| `read_denied`, `write_denied`, `egress_denied` | Verify each inert canary is reachable to the operator. Observe each prohibited attempt reach the actual boundary and be denied. Confirm no disclosure, write, or delivery; silence or model refusal is not evidence. |
| `settings_unchanged` | Compare persistent settings before and after; verify no change and remove disposable state. |
| `no_progress_cleanup`, `timeout_cleanup` | Exercise no-progress and wall-time watchdogs against the supervised process with observed descendants. Record each trigger, incomplete result, and verified absence of survivors. Record the enforced attempt/output bounds and whether any limit was exceeded. |

For an actual-auth lane, record both `model` and `usage` as observations with sources, or as explicit unknowns with reasons. Stop at pass, evidenced failure or unavailable prerequisite within approved limits. Review sanitized results before Git publication; exclude raw transcripts, secrets, private paths and real code.

The smallest next decision is owner approval of one complete live lane and confirmation that its confinement is feasible. Keep R01 unready until landed evidence supports GO, or the owner approves a revised plan.
