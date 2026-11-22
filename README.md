# revkit

Rust CLI for pre-push review of committed changes. The initial supported target is Apple Silicon macOS.

## Quickstart

Install the published 0.1.0 crate with Git and a current stable Rust toolchain, or build from a source checkout with `cargo install --locked --path /path/to/revkit`. Review requires an already-configured `omp`; `plan` does not require `omp` or make a model call.

```sh
cargo install --locked revkit --version 0.1.0
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

`--trusted-local` is for trusted checkouts only. This is **not a sandbox**. Revkit starts one fresh tool-disabled OMP session using your existing configuration. Set `--harness /path/to/omp` or `--model provider/model` to select explicitly. Revkit does not sign in, check billing, or try another model. Review sends the filtered patch, effective rules, and supplied requirements; only supply and review material you authorize that harness and model to receive. A local timeout is not a provider usage cap.

Use `[scope] deny`, `exclude`, `generated`, and `include` arrays of repository-relative globs in `.revkit/config.toml`. Include overrides generated exclusions, not deny or explicit exclusion. `.revkit/policy.toml` can supply additional `deny` globs. Common secret paths are withheld. Symlinks, gitlinks, binary and unsupported files are not reviewed. Deletions supply context, not file verdicts. Plans that exceed the single-unit limits are not partially dispatched.

Both sides of a detected rename contribute scope, rules, and tier. If Git cannot pair a protected deletion with a destination, unmatched additions are withheld and exact-head checks are refused.

Define Markdown rules in `.revkit/rules/` using `---` frontmatter with a unique `id`, optional `lens`, and optional `paths` and `replaces` string lists. Revkit also applies the trusted `## Code Review Rules` section of `AGENTS.md` and applicable built-in rules. A matching rule suppresses only the matching rules it names directly in `replaces`.

Optional `[checks]` entries map names to shell commands. `plan` shows their identities without running them. Add `--run-checks` to authorize trusted-base commands to execute **head code** in disposable copies of exact committed files. The check tree has no Git metadata and no inherited credentials in its command environment. Snapshots with protected files, links, unsupported entries, or paths that alias on the scratch filesystem are refused rather than run on altered inputs. The check deadline includes snapshot preparation. This is not confinement; authorize checks only for trusted code.

## Results

Use `--format json` for versioned structured output, or `--format sarif` with `review` or `findings`. Saved reports are local to the worktree's Git directory. `findings [ID]` and `rules explain PATH` read the latest report or `--run ID` without a reviewer. Base-side anchors must point to removed lines and are not exported as current-head inline locations. Unanchored leads remain local.

| Exit | Meaning |
|---|---|
| `0` | Passed within the reported scope or successful lookup; P3 findings are advisory |
| `1` | Invalid request/configuration or local error |
| `2` | Blocking findings on a completed review |
| `3` | Incomplete execution or coverage; inspect the report for any verified partial findings |
| `5` | A configured check was missing, failed, or not authorized |
| `6` | Reviewer unavailable |

Reports show all applicable reasons. Incomplete or unavailable review takes precedence over check and finding exit codes; failing checks take precedence over findings. Tests use a scripted reviewer and need no provider account.

Maintainers: see [release instructions](https://github.com/Mathews-Tom/revkit/blob/main/docs/releasing.md).

- [Apache-2.0 license](LICENSE)
