# S0 trusted-local review evidence — v1

**Decision: GO for trusted-local review.** Codex `0.171.0`, omp `19.1.0`, and agy `1.5.13` qualified on macOS `27.2.1` arm64 for the specific channels in this record. Each qualified lane settled both assigned files in a fresh positive run, found the seeded defect with a verified anchor, and produced a valid one-file response in a separate live control that the unchanged validator rejected as `missing verdict`. The historical confined-runtime NO-GO in [PR #2](https://github.com/Mathews-Tom/revkit/pull/2) is unchanged. This GO does not establish confinement, safe unattended review of untrusted changes, or support for another tuple.

| Harness | Trusted-local evidence |
| --- | --- |
| Codex `0.171.0` | Qualified for the tested trusted-local tuple. Actual subscription evidence for exact-head review and live omission rejection. |
| omp `19.1.0` | Qualified with the existing OpenAI Codex subscription profile, `openai-codex/gpt-6.1-sol`, and fresh `--print --mode json --no-session` runs. Direct Claude subscription OAuth through omp was not run. |
| Claude Code `2.1.330` | Not qualified. The tested native headless invocation reported `Not logged in`; no completed review. |
| agy `1.5.13` | Qualified with the existing personal Google sign-in, `gemini-3.8-flash-medium`, and fresh `--print --mode plan --output-format stream-json --json-schema` runs. |

## Codex observations

| Case | Evidence class | Result |
| --- | --- | --- |
| Fresh exact-head review | Actual subscription | New `thread.started`, `turn.completed`, exit `0` in `7.86 s`. Typed `complete: true`; exactly one verdict per assigned file. `delivery.py` finding at head line 3, exact excerpt `        return "live"`; `display.py` clean. Verified against `git show HEAD:delivery.py`, not just the model's text fields. |
| Destination policy | Actual subscription | Accepted `13`, `12`, and `11` tunnels across the three live runs. The broker rejected eight requests on each run before forwarding: unclassified on the first run, non-allowlisted CONNECT authorities on the two controls. No upstream errors. Tunnel counts are not model requests. |
| Omitted required verdict | Actual subscription and offline control | The constrained fresh session completed and exited `0` in `7.80 s`, with `complete: true` and one valid clean row for `display.py`. The unchanged validator still expected both paths and rejected the run as `missing verdict` for `delivery.py`. An earlier unconstrained control exited `0` but failed as `invalid verdict` before coverage checking; only the constrained result satisfies this case. |
| Wrong anchor; all-clean control | Offline controls | Same validator rejected line `99` and classified a two-verdict, finding-free result as clean. |
| No progress; wall deadline | Offline controls | The same process-group monitor triggered each deadline separately, observed a child in the owned group, and observed both parent and child gone after teardown. |
| Approved versus denied socket | Offline control | The observer reached two local ports. The probe profile reached only its allowlisted port; the other returned `EPERM` and the listener received nothing. |

Codex `turn.completed` reported `13,375` input / `134` output tokens on the positive run, `13,363` / `84` on the unconstrained control, and `13,370` / `73` on the constrained control, with `0` cached input tokens each. Exact model, provider request count and subscription quota consumed are unknown. The approved limits were five invocations, 15 minutes total, three minutes per invocation, 90 seconds without meaningful progress, 1 MiB aggregate output, included allowance only and no paid overage. The three runs captured `1,225`, `1,023`, and `981` bytes. For each, the synthetic worktree remained clean at the same head with unchanged file bytes, the original sign-in file's metadata was unchanged, the owned process was gone, and the disposable root was removed. No transcripts or credentials were retained.

## Redacted reproduction

1. Use a disposable Git repository. Commit the base file contents below, then the head changes. Set author and committer to `S0 Fixture <fixture@example.invalid>`, dates to `2025-01-01T00:00:00Z`, and commit messages to `synthetic base` and `synthetic head` respectively. The observed SHA-1 pins were base `fba1a559158f145c076dec4742e7f46fc31b22d8` and head `f629c4039bd4561a0b3d2944e5d8321f590f792d`.
2. Get the two-file projection from `git diff --no-ext-diff --unified=3 "$BASE" "$HEAD" -- delivery.py display.py`. Supply the requirements and this patch, not the expected verdicts. Requirements: preview must return `"dry-run"`; non-preview must return `"live"`; a `Status: ` prefix is allowed if the label is preserved. Ask for one verdict per file and a verbatim head line with its indentation for each finding. Clean verdicts use line `0` and an empty excerpt. Do not ask the harness to edit files or run tools.
   From the revkit checkout, set `REVKIT_ROOT="$PWD"` and generate the schema in an operator-owned scratch directory: `SCHEMA="$SCRATCH/review.schema.json"; python3 "$REVKIT_ROOT/spike/reproduce_trusted_local.py" schema > "$SCHEMA"`.
3. Use the pinned macOS arm64 binary (SHA-256 `fc8d77cf7585aded2b9bc487dad29c4ee2f066123e4e76dd3b17653a8322ce42`). Launch `codex exec --ephemeral --ignore-user-config --ignore-rules --skip-git-repo-check --sandbox read-only --json --output-schema "$SCHEMA"` as a new session, never `resume`. Pass `-c` overrides for file-backed auth, forced ChatGPT login, no approvals, disabled web search, and disabled shell, image, freeform patch and multi-agent features. Use a disposable `HOME` and `CODEX_HOME` with a read-only reference to the existing CLI sign-in file; do not export API keys. Use normal OS services. For this lane, keep writes to the disposable root (fixture and schema read-only) and direct sockets denied except a supervisor-owned loopback proxy. The proxy accepts only exact `CONNECT chatgpt.com:443` and opens only that destination. Enforce the stated deadline/output budgets externally; do not run against another provider or widen egress on failure.
4. For the Codex negative control, rerun the schema command with `schema --codex-omission`, start another fresh session, and request only the clean `display.py` row. For the other harnesses use the ordinary schema. Extract only the final assistant JSON object into `$SCRATCH/result.json`, not the entire event stream. For Codex NDJSON use `jq -er -s '[.[] | select(.type == "item.completed" and .item.type == "agent_message") | .item.text] | last' "$SCRATCH/events.ndjson" > "$SCRATCH/result.json"` after confirming exit `0` and `turn.completed`. Independently run `python3 "$REVKIT_ROOT/spike/reproduce_trusted_local.py" validate --repo "$FIXTURE" --head "$HEAD" < "$SCRATCH/result.json"`, where `FIXTURE` is the disposable Git checkout and `HEAD` the pinned head SHA. The validator obtains each assigned file through `git show` on that commit and checks completion, verdict coverage, and exact finding anchors. Expect `finding` (exit `2`) for the positive run and `missing verdict` (exit `3`) for the one-row control. Set the positive finding's line to `99` and expect `invalid anchor` (exit `3`). Keep fixtures and results out of provider use until authorized.

Base `delivery.py` (head changes line 3 from `"dry-run"` to `"live"`):

```python
def delivery_mode(is_preview: bool) -> str:
    if is_preview:
        return "dry-run"
    return "live"
```

Base `display.py` (head changes line 2 to `    return f"Status: {label}"`):

```python
def render_status(label: str) -> str:
    return label
```

## Initial parallel qualification attempts

All three launches used the same fixture, base/head pins, external validator and process-group monitor. Each used a new process with no resume, a filtered synthetic diff, and only the approved provider's HTTPS destinations. Limits per lane: five invocations including preflight, 15 minutes total, three minutes per invocation, 90 seconds without progress, 1 MiB capture and included subscription allowance only. No API-key or pay-as-you-go fallback. Blocked proxy destinations were not forwarded; host tunnel counts do not measure inference requests.

| Lane and channel | Positive case | Live omission control | Smallest next check |
| --- | --- | --- | --- |
| omp `19.1.0`, `openai-codex/gpt-5.5`, `--mode json` | Exit `1` in `1.77 s`; no approved upstream tunnel or terminal review. Model and usage unobserved. The retained diagnostic classification does not identify the startup cause. | Not dispatched after positive failure. | Capture the first fatal headless startup diagnostic with upstream blocked, using the existing omp OAuth profile. |
| Claude Code `2.1.330`, native `claude.ai` sign-in, `--output-format stream-json` | Offline `auth status` returned `loggedIn: false` and `authMethod: none` for the launch profile. The live launch initialized `claude-sonnet-5-5`, opened one approved `api.anthropic.com` tunnel, then reported authentication required. Exit `1` in `0.41 s`, zero reported tokens and no settled verdicts. | Not dispatched after positive failure. | Verify `claude auth status` reports a signed-in `claude.ai` subscription under the same headless settings before sending the fixture again. |
| agy `1.5.13`, personal Google sign-in, `--output-format stream-json` | Fresh session on `gemini-3.8-flash-medium` completed in `23.81 s`, exit `0`. `delivery.py` had the seeded finding at exact head line 3 and `display.py` was clean. The same validator rejected an offline variant with the anchor changed to line 99. Reported 13,501 input and 1,370 output tokens, including 1,256 thinking tokens. | Fresh session exited `3` in `10.21 s` with no successful terminal result or typed verdict; zero reported tokens. It did not reach the validator's `missing verdict` branch. The redacted diagnostics do not establish the cause. | Capture the exact redacted terminal error for the omission control. Keep the same external validator; do not count a CLI error as missing-verdict rejection. |

Launch details: omp used `--print --mode json --offline --no-session --no-tools --no-extensions --no-skills --no-rules --no-context-files` with an explicit `openai-codex` model and the JSON schema in the prompt. Claude Code used `--print --output-format stream-json --verbose --no-session-persistence --strict-mcp-config --setting-sources '' --tools '' --permission-mode plan --model sonnet --json-schema`, with hooks disabled and `forceLoginMethod` set to `claudeai`. Antigravity used `--print --output-format stream-json --mode plan --disable-slash-commands --model gemini-3.8-flash-medium --json-schema`, with the CLI's strict tool permission setting. Its init event still advertised 60 tools, so this is not evidence of tool isolation. The two Antigravity cases each opened seven allowed HTTPS tunnels to Google OAuth, userinfo and inference services; other requests were blocked. All launched parent processes were gone on return, the fixture remained clean at the pinned head with unchanged bytes, the checked settings files were unchanged, and all three scratch roots were removed. The separate offline watchdog control established descendant cleanup for the two deadline paths.

Binary SHA-256 pins on macOS `27.2.1` arm64: omp `dca5643669ed5e553f707bd065499babd0fe3030696bbb24c9da09c798af5abb`; Claude Code `f7c5093b9dd6560d08af28bc27b123fb55091deae3180ac39df199522da86815`; agy `3f669d53b6a9807b161c327bf6ce33cdd24ecbf3026edcbb7347c004d1a2d9f2`.

The requested additional omp lane using direct Claude subscription OAuth was not dispatched. The inspected omp provider uses its own Anthropic transport rather than delegating authentication to the unmodified Claude Code binary. [Anthropic's credential terms](https://code.claude.com/docs/en/legal-and-compliance#authentication-and-credential-use) authorize native Claude Code sign-in and restrict third-party handling of Claude subscription credentials. No credential export, API-key fallback or alternate billing was attempted.

### Follow-up diagnostics

| Lane | Observed | Next qualification step |
| --- | --- | --- |
| omp `19.1.0` | With the existing profile, explicit `openai-codex/gpt-5.5`, and egress blocked, startup exited `1`: `SQLITE_READONLY`, `attempt to write a readonly database` for the existing OMP `agent.db`. No provider connection or login action. | Use the normal writable harness state while keeping the synthetic fixture read-only. Keep the explicit model and existing sign-in. |
| Claude Code `2.1.330` | With the same headless settings and egress blocked, native `claude auth status` returned `loggedIn: false`, `authMethod: none`, `apiProvider: firstParty`; exit `1`. This describes the tested profile, not the operator's other sessions. | Use the operator's configured native profile directly; report a launch failure if it cannot start a review. This spike diagnostic is not a revkit preflight. |
| agy `1.5.13` | The fresh omission run exited `3`, terminal `ERROR`, zero reported tokens, and no verdict. Google returned `INVALID_ARGUMENT` (`400`): `enum[0]: cannot be empty` for the schema fields `complete`, `line` and `excerpt`. Their singleton enum values were `true`, `0` and `""`. No missing-verdict validation occurred. | Use the working field types without those singleton enums. Request the one clean row explicitly; verify the row and reject incomplete coverage with the same external validator. |

All three parent processes exited, scratch roots were removed, and checked settings were unchanged. Antigravity's fixture remained unchanged at the pinned head. These diagnostics did not qualify a new lane.

### Direct configured-harness rerun

The three positive cases started in parallel using the pinned binaries and existing native profiles, without login, auth-status preflight, credential import, or automatic model fallback. Normal harness state was writable, checked settings and the fixture were protected, and only the approved destination allowlists could be reached via the proxy. Each command received the same synthetic projection pinned above; no author session was resumed. The existing offline anchor and watchdog controls apply to the unchanged validator and supervisor.

| Lane | Positive exact-head review | Live missing-verdict control |
| --- | --- | --- |
| omp `19.1.0` / `openai-codex/gpt-6.1-sol` | Exit `0` in `17.34 s`. Terminal `agent_end`; typed finding at `delivery.py:3`, clean `display.py`, and the line-99 offline variant rejected. Reported 67,029 input and 82 output tokens. | Separate fresh process exited `0` in `21.11 s`. Terminal `agent_end`; only clean `display.py` returned. Same validator rejected `missing verdict` for `delivery.py`. Reported 67,013 input and 68 output tokens. |
| Claude Code `2.1.330` / `sonnet` | Native initialization advertised `claude-sonnet-5-5`, but exit `1` in `0.50 s` with `Not logged in · Please run /login`. No model response, zero reported tokens, and no verdicts. | Not dispatched after positive failure. No login was attempted. |
| agy `1.5.13` / `gemini-3.8-flash-medium` | Exit `0` in `26.81 s`, terminal `SUCCESS` in a fresh session. Typed finding at `delivery.py:3`, clean `display.py`, and the line-99 offline variant rejected. Reported 13,498 input and 1,821 output tokens. | Separate fresh session exited `0` in `27.55 s`, terminal `SUCCESS`. Only clean `display.py` returned. Same validator rejected `missing verdict` for `delivery.py`. Reported 13,503 input and 721 output tokens. |

The first omp invocation exited before reaching OpenAI; a zero-egress diagnostic resolved it to `Model "openai-codex/gpt-5.5" not found`, not sign-in. The subsequent attempt explicitly selected the configured Codex task model, `openai-codex/gpt-6.1-sol`. It produced a valid positive result, but the initial stream observer treated `yielded: true` as nonterminal. The corrected observer uses `isTerminal` to distinguish pauses from the final event; both qualified runs emitted `isTerminal: true, yielded: true`. Their JSON output was validated externally. In agy, both runs used the working typed schema without the failing singleton enums. The negative prompt explicitly requested one clean row; the external assignment still required both files.

Both qualified channels observed zero tool calls. agy advertised tools at startup, so that observation does not establish tool isolation. Each omp qualification case opened two approved `chatgpt.com` tunnels; each agy case opened six approved Google tunnels and blocked other requests before forwarding. Tunnel counts are not request or quota counts. All test parents were gone, the checked settings and pinned fixture remained unchanged, and scratch directories were removed. This record contains only synthetic code; no credentials or raw transcripts are included.
