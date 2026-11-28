# revkit

Rust CLI for pre-push review of committed changes. The initial supported target is Apple Silicon macOS.

## Quickstart

Install the published 0.1.1 crate with Git and a current stable Rust toolchain, or build from a source checkout with `cargo install --locked --path /path/to/revkit`. Review requires an already-configured `omp`; `plan` does not require `omp` or make a model call.

```sh
cargo install --locked revkit --version '=0.1.1'
revkit --version
revkit init
revkit doctor
```

Run the commands in the repository being reviewed. Commit the generated `.revkit/` setup on the trusted base, then run:

```sh
revkit doctor --base main
revkit plan --base main --requirements 'Preview mode must not send.'
revkit review --base main --trusted-local --requirements 'Preview mode must not send.'
revkit findings --format sarif
revkit rules explain path/to/file.rs
```

`--base` pins the named ref for policy and compares its merge base with `HEAD` or `--head`. `--commit` compares the named commit to its first parent, or to the empty tree for a true root. Review uses committed objects, not dirty or staged files. Use commit IDs to run the same comparison after refs move.

Git object reads are local-only. If a partial clone lacks a required object, fetch it explicitly before running Revkit.

## Trust and scope

`--trusted-local` is for trusted checkouts only. This is **not a sandbox**. Revkit starts one fresh OMP session using your existing configuration and passes `--no-tools`. Revkit rejects a result if it observes a tool attempt, but this does not prevent tool execution or side effects.

OMP tool isolation depends on the installed version. OMP 19.1.1 started configured MCP connectors and could advertise tools despite `--no-tools`. With OMP 19.2.1, offline tests using the Opus review route and synthetic connector configurations observed zero advertised tools and no native or project MCP connector startup under Revkit's existing launch flags. OMP 19.2.1 also rejects combining `--no-tools` with explicit extensions or hooks. Keep the flag enabled; do not weaken isolation to load instrumentation. These observations are version-specific, not a general confinement guarantee or qualification of every connector, provider, or profile.

Set `--harness /path/to/omp` or `--model provider/model` to select explicitly. Revkit does not sign in, check billing, or try another model. Review sends the filtered patch, effective rules, and supplied requirements; only supply and review material you authorize that harness and model to receive. A local timeout is not a provider usage cap.

Use `[scope] deny`, `exclude`, `generated`, and `include` arrays of repository-relative globs in `.revkit/config.toml`. Include overrides generated exclusions, not deny or explicit exclusion. `.revkit/policy.toml` can supply additional `deny` globs. Common secret paths are withheld. Symlinks, gitlinks, binary and unsupported files are not reviewed. Deletions supply context, not file verdicts. Plans that exceed the single-unit limits are not partially dispatched.

Both sides of a detected rename contribute scope, rules, and tier. If Git cannot pair a protected deletion with a destination, unmatched additions are withheld and exact-head checks are refused.

Define Markdown rules in `.revkit/rules/` using `---` frontmatter with a unique `id`, optional `lens`, and optional `paths` and `replaces` string lists. Revkit also applies the trusted `## Code Review Rules` section of `AGENTS.md` and applicable built-in rules. A matching rule suppresses only the matching rules it names directly in `replaces`.

Optional `[checks]` entries map names to shell commands. `plan` shows their identities without running them. Add `--run-checks` to authorize trusted-base commands to execute **head code** in disposable copies of exact committed files. The check tree has no Git metadata and no inherited credentials in its command environment. Snapshots with protected files, links, unsupported entries, or paths that alias on the scratch filesystem are refused rather than run on altered inputs. The check deadline includes snapshot preparation. This is not confinement; authorize checks only for trusted code.

## Results

`plan` measures the bytes in Revkit’s review request before OMP adds its own context. This is not a model token budget. With released Revkit 0.1.1, select `--format json` on the review command itself to inspect the returned `usage` object. The unreleased source build also displays reported counters in the default text review output. Keep the reported field names (including `cacheRead` and `cacheWrite` when present); do not sum an existing `totalTokens` counter with its components. Missing counters are unknown, not zero. These counters do not establish billed usage or subscription quota consumption, and comparing different changes does not isolate harness overhead.

Use `--format json` for versioned structured output, or `--format sarif` with `review` or `findings`. Saved reports are local to the worktree's Git directory. `findings [ID]` and `rules explain PATH` read the latest report or `--run ID` without a reviewer. Base-side anchors must point to removed lines and are not exported as current-head inline locations. Unanchored leads remain local.

The unreleased reviewer protocol annotates selectable diff lines with request-scoped identifiers such as `a12`. Each returned finding supplies `anchor_id`, `severity`, and `note`; Revkit resolves its path, revision, blob, line, and excerpt from pinned source. Added and context lines resolve on the head; removed lines resolve on the base. Deleted-file context has no selectable identifiers. Unknown or cross-file identifiers leave the assigned path unsettled, not clean. An anchored finding is not proof of the underlying defect. Custom reviewer harnesses must use this new response contract; saved report coordinates remain unchanged (`claimed_line` is null for new findings).

Build from the current source checkout to see the saved head, per-file coverage, and reasons alongside anchored findings in `revkit findings --run ID`. JSON output includes the saved `coverage` map and `reasons` array, even when filtering by finding ID. The published 0.1.0 and 0.1.1 builds omit coverage and reasons from this lookup. A successful lookup does not mean the saved review completed; check its status. The lookup does not run the model or checks.

The unreleased build reports a numeric upstream HTTP error status when OMP supplies one on the failed assistant response. It does not copy OMP's raw error message. A process deadline is reported as a timeout, not an inferred provider error.

| Exit | Meaning |
|---|---|
| `0` | Passed within the reported scope or successful lookup; P3 findings are advisory |
| `1` | Invalid request/configuration or local error |
| `2` | Blocking findings on a completed review |
| `3` | Incomplete execution or coverage; inspect the report for any verified partial findings |
| `5` | A configured check was missing, failed, or not authorized |
| `6` | Reviewer unavailable |

Reports show all applicable reasons. Incomplete or unavailable review takes precedence over check and finding exit codes; failing checks take precedence over findings. Tests use a scripted reviewer and need no provider account.

## Local metrics (unreleased)

Source builds record review attempts locally by default in `~/.revkit/metrics/`. No metrics are uploaded. Use `revkit metrics show --format json` to inspect counts and `revkit metrics clear` to remove the records and PR attribution key. Records use owner-only files, retain at most 1,000 attempts, and expire after 90 days on the next recorded attempt. Expired attempts are excluded from inspection.

To select a repository-local store, first ignore `/.revkit/metrics/` in Git, then pass `--metrics-store repository` to `review` and `--store repository` to `metrics show` or `metrics clear`. Revkit refuses tracked or non-ignored repository stores. Each review writes to at most one store.

Disable collection per review with `--no-metrics`, or persist the opt-out in `~/.revkit/settings.toml` or `<repo>/.revkit/settings.toml`:

```toml
[metrics]
enabled = false
```

Either opt-out wins. Pass `--pr-id forge.example/org/repository#123` only when the PR identity is known; repeated attempts are counted separately but attributed PRs are deduplicated within the chosen store using a private keyed digest. Without an explicit ID, the attempt remains unattributed. No branch inference or forge request is made. `--harness-version` records an operator-known version without launching another executable. Raw paths, review inputs, findings, and PR identities are not collected. Local metrics failures warn separately and never cause a model retry or change the review verdict.

Counters retain original harness field names and reported-attempt denominators; absent usage/cost is unknown, not zero. Aggregate sums exceeding the JSON unsigned 64-bit integer range are exact decimal strings. Anchored counts represent comments, not adjudicated bugs. Do not compare model quality or cost across unmatched changes from these records.

Maintainers: see [release instructions](https://github.com/Mathews-Tom/revkit/blob/main/docs/releasing.md).

- [Apache-2.0 license](LICENSE)
