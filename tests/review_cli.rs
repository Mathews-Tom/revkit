#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

fn isolated_command(program: &str) -> Command {
    let mut command = Command::new(program);
    for (key, _) in std::env::vars_os() {
        if key.as_encoded_bytes().starts_with(b"GIT_") {
            command.env_remove(key);
        }
    }
    command
}

struct Repo(tempfile::TempDir);

impl Repo {
    fn new() -> Self {
        let repo = Self(tempfile::tempdir().unwrap());
        repo.git(&["init", "-q", "-b", "main"]);
        repo
    }

    fn root(&self) -> &Path {
        self.0.path()
    }

    fn git(&self, args: &[&str]) -> String {
        let output = isolated_command("git")
            .args(args)
            .current_dir(self.root())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?}: {:?}", output);
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn write(&self, path: &str, contents: &str) {
        let path = self.root().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn checkpoint(&self, message: &str) -> String {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-qm", message]);
        self.git(&["rev-parse", "HEAD"])
    }

    fn cli(&self, code: i32, args: &[&str]) -> Value {
        let output = isolated_command(env!("CARGO_BIN_EXE_revkit"))
            .args(args)
            .current_dir(self.root())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{args:?}: {}: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn runner(&self, name: &str, script: &str) -> PathBuf {
        let path = format!(".git/{name}");
        self.write(&path, &format!("#!/bin/sh\n{script}\n"));
        let path = self.root().join(path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn stub(&self, completion: Value, terminal: bool) -> PathBuf {
        let messages = json!({"type":"message_end", "message":{
            "role":"assistant", "stopReason":"stop", "model":"scripted-model",
            "usage":{"input":420,"output":25}, "content":[{"type":"text", "text":completion.to_string()}]}});
        self.runner(
            "offline-reviewer",
            &format!(
                r#"
case " $* " in
  *' --no-session '*' --no-tools '*' --model fixture/model '*) ;;
  *) exit 61 ;;
esac
[ ! -e .git ] || exit 62
cat <<'EVENTS'
{messages}
{{"type":"agent_end","isTerminal":{terminal},"yielded":true}}
EVENTS
"#
            ),
        )
    }

    fn review(&self, code: i32, stub: &Path, extra: &[&str]) -> Value {
        let mut args = vec![
            "review",
            "--base",
            "main",
            "--trusted-local",
            "--harness",
            stub.to_str().unwrap(),
            "--model",
            "fixture/model",
            "--format",
            "json",
        ];
        args.extend(extra);
        self.cli(code, &args)
    }
}

fn clean(path: &str) -> Value {
    json!({"path":path,"verdict":"clean","findings":[]})
}
fn finding(path: &str, side: &str, line: usize, excerpt: &str) -> Value {
    json!({"path":path,"verdict":"finding","findings":[{"severity":"P2","side":side,"line":line,"excerpt":excerpt,"note":"Preview uses the live delivery mode."}]})
}
fn verdicts(rows: &[Value]) -> Value {
    json!({"complete":true,"verdicts":rows})
}

#[test]
fn setup_plan_and_rule_provenance_use_only_pinned_git_inputs() {
    let repo = Repo::new();
    let init = repo.cli(0, &["init", "--format", "json"]);
    assert_eq!(
        init["files"],
        json!([
            {"path":".revkit/config.toml","status":"created"},
            {"path":".revkit/policy.toml","status":"created"}
        ])
    );
    assert!(repo.root().join(".revkit/config.toml").is_file());
    assert!(repo.root().join(".revkit/policy.toml").is_file());
    repo.write(
        ".revkit/config.toml",
        "version=1\n[scope]\nexclude=['skip.txt']\n[checks]\nsyntax='exit 1'\n",
    );
    repo.cli(0, &["init", "--format", "json"]);
    assert!(
        fs::read_to_string(repo.root().join(".revkit/config.toml"))
            .unwrap()
            .contains("exit 1")
    );
    repo.write("delivery.py", "def delivery():\n    return 'dry-run'\n");
    repo.write("obsolete.txt", "Deleted context.\n");
    repo.write(
        ".revkit/rules/delivery.md",
        "---\nid: delivery\npaths: ['**/*.py']\n---\nPreview must not send.\n",
    );
    let merge_base = repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("delivery.py", "def delivery():\n    return 'live'\n");
    repo.write(
        ".revkit/rules/delivery.md",
        "---\nid: head-only\n---\nDo not review.\n",
    );
    repo.write(".env", "fixture-secret\n");
    repo.write("skip.txt", "excluded\n");
    repo.write("binary.dat", "a\0b");
    symlink(".env", repo.root().join("link")).unwrap();
    fs::remove_file(repo.root().join("obsolete.txt")).unwrap();
    let head = repo.checkpoint("change");
    repo.git(&["checkout", "-q", "main"]);
    repo.write(
        ".revkit/rules/delivery.md",
        "---\nid: delivery\npaths: ['**/*.py']\n---\nPreview must return dry-run.\n",
    );
    let trusted = repo.checkpoint("base policy update");
    repo.git(&["checkout", "-q", "change"]);
    repo.write("delivery.py", "unstaged bytes\n");
    let plan = repo.cli(0, &["plan", "--base", "main", "--format", "json"]);
    assert_eq!(plan["comparison"]["base"], merge_base);
    assert_eq!(plan["trusted_base"], trusted);
    assert_eq!(plan["comparison"]["head"], head);
    assert_eq!(plan["admission"]["status"], "admitted");
    assert_eq!(plan["checks"][0]["name"], "syntax");
    let rules = plan["rules"].as_array().unwrap();
    assert!(rules.iter().any(|rule| rule["id"] == "delivery"
        && rule["body"].as_str().unwrap().contains("return dry-run")));
    assert!(!rules.iter().any(|rule| rule["id"] == "head-only"));
    for (reason, path) in [
        ("binary", "binary.dat"),
        ("unsupported_object", "link"),
        ("deleted", "obsolete.txt"),
        ("exclude", "skip.txt"),
    ] {
        assert!(
            plan["files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|file| file["scope"]["reason"] == reason && file["path"] == path)
        );
    }
    assert!(
        plan["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["scope"]["reason"] == "secret_path" && file["path"].is_null())
    );
    assert!(!repo.root().join(".git/revkit").exists());
    let root = repo.cli(0, &["plan", "--commit", &merge_base, "--format", "json"]);
    assert_eq!(root["admission"]["status"], "admitted");
    assert!(root["comparison"]["base"].is_null());
    let stub = repo.runner("doctor-runner", "exit 61");
    let doctor = repo.cli(
        0,
        &[
            "doctor",
            "--harness",
            stub.to_str().unwrap(),
            "--base",
            "main",
            "--format",
            "json",
        ],
    );
    assert_eq!(doctor["ready"], true);
    assert_eq!(doctor["profile_checked"], false);
}

#[test]
fn review_distinguishes_typed_completion_and_preserves_verified_findings() {
    let repo = Repo::new();
    repo.write("delivery.py", "def delivery():\n    return 'dry-run'\n");
    repo.write("display.py", "return label\n");
    let base = repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("delivery.py", "def delivery():\n    return 'live'\n");
    repo.write("display.py", "return 'Status: ' + label\n");
    let head = repo.checkpoint("change");
    repo.write("delivery.py", "false dirty anchor\n");
    let anchor = finding("delivery.py", "head", 2, "    return 'live'");
    let unknown = repo.root().join("missing-executable");
    assert_eq!(
        repo.cli(
            1,
            &[
                "review",
                "--base",
                "main",
                "--harness",
                unknown.to_str().unwrap(),
                "--format",
                "json"
            ]
        )["kind"],
        "error"
    );
    assert!(!repo.root().join(".git/revkit").exists());
    assert_eq!(repo.review(6, &unknown, &[])["status"], "unavailable");
    assert_eq!(
        repo.review(
            0,
            &repo.stub(verdicts(&[clean("delivery.py"), clean("display.py")]), true),
            &[]
        )["status"],
        "clean"
    );
    let missing = repo.review(
        3,
        &repo.stub(verdicts(std::slice::from_ref(&anchor)), true),
        &[],
    );
    assert_eq!(missing["coverage"]["display.py"], "unsettled");
    assert_eq!(missing["coverage"]["delivery.py"], "settled_with_findings");
    assert_eq!(missing["findings"][0]["line"], 2);
    let invalid = repo.review(
        3,
        &repo.stub(
            verdicts(&[
                finding("delivery.py", "head", 1, "false dirty anchor"),
                clean("display.py"),
            ]),
            true,
        ),
        &[],
    );
    assert_eq!(invalid["leads"][0]["reason"], "invalid_anchor");
    assert_eq!(invalid["findings"], json!([]));
    assert_eq!(invalid["coverage"]["display.py"], "settled_no_findings");
    let nonterminal = repo.review(
        3,
        &repo.stub(verdicts(&[anchor.clone(), clean("display.py")]), false),
        &[],
    );
    assert_eq!(nonterminal["coverage"]["delivery.py"], "unsettled");
    assert_eq!(nonterminal["findings"][0]["commit"], head);
    let positive = repo.review(
        2,
        &repo.stub(
            verdicts(&[
                finding("delivery.py", "head", 99, "    return 'live'"),
                finding("display.py", "base", 1, "return label"),
            ]),
            true,
        ),
        &[],
    );
    assert_eq!(positive["status"], "findings");
    assert_eq!(positive["comparison"]["head"], head);
    assert_eq!(positive["findings"][0]["line"], 2);
    assert_eq!(positive["findings"][0]["claimed_line"], 99);
    assert_eq!(positive["findings"][0]["id"], missing["findings"][0]["id"]);
    assert_eq!(positive["findings"][1]["commit"], base);
    let id = positive["findings"][0]["id"].as_str().unwrap();
    let by_id = repo.cli(
        0,
        &[
            "findings",
            id,
            "--run",
            positive["run_id"].as_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(by_id["findings"][0]["id"], id);
    let sarif = repo.cli(0, &["findings", "--format", "sarif"]);
    assert_eq!(
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        2
    );
    assert!(sarif["runs"][0]["results"][1]["locations"].is_null());
    let rules = repo.cli(0, &["rules", "explain", "delivery.py", "--format", "json"]);
    assert_eq!(rules["run_id"], positive["run_id"]);
    assert_eq!(rules["trusted_base"], base);
}

#[test]
fn checks_require_opt_in_and_each_reads_the_pinned_snapshot() {
    let repo = Repo::new();
    repo.write(".revkit/config.toml", "version=1\n[checks]\na='grep -qx pinned file.txt && echo mutated > file.txt'\nb='grep -qx pinned file.txt'\nc='exit 7'\n");
    repo.write("file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "pinned\n");
    repo.write(".revkit/config.toml", "[checks]\nlater='exit 123'\n");
    repo.checkpoint("change");
    repo.write("file.txt", "dirty\n");
    let stub = repo.stub(
        verdicts(&[clean("file.txt"), clean(".revkit/config.toml")]),
        true,
    );
    let skipped = repo.review(5, &stub, &[]);
    assert_eq!(skipped["checks"][0]["status"], "not_authorized");
    let checked = repo.review(5, &stub, &["--run-checks"]);
    let checks = checked["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 3);
    assert_eq!(checks[0]["status"], "passed");
    assert_eq!(checks[1]["status"], "passed");
    assert_eq!(checks[2]["status"], "failed");
    assert_eq!(checks[2]["exit_code"], 7);
    assert_eq!(
        fs::read_to_string(repo.root().join("file.txt")).unwrap(),
        "dirty\n"
    );
}

#[test]
fn timeout_remains_incomplete_with_a_descendant_holding_output_open() {
    let repo = Repo::new();
    repo.write("file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "after\n");
    repo.checkpoint("head");
    let stub = repo.runner("timed-reviewer", "sleep 30 &\nwait");
    let start = std::time::Instant::now();
    let report = repo.review(3, &stub, &["--timeout-seconds", "1"]);
    assert!(start.elapsed() < std::time::Duration::from_secs(15));
    assert_eq!(report["status"], "incomplete");
    assert!(
        report["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason.as_str().unwrap().contains("timeout"))
    );
}

#[test]
fn reviewer_receives_only_assigned_blobs_and_allowed_context() {
    let repo = Repo::new();
    repo.write("settings", "allowed context\n");
    repo.write(".env", "synthetic rename canary\n");
    repo.write("target.txt", "old\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    fs::remove_file(repo.root().join("settings")).unwrap();
    repo.write("settings/.env", "synthetic descendant canary\n");
    fs::rename(repo.root().join(".env"), repo.root().join("example.txt")).unwrap();
    repo.write("target.txt", "changed\n");
    repo.checkpoint("head");
    let body = verdicts(&[clean("target.txt")]);
    let wire = json!({
        "type":"message_end","message":{"role":"assistant","stopReason":"stop",
        "content":[{"type":"text","text":body.to_string()}]}
    });
    let runner = repo.runner("scope-reviewer", &format!(r#"
case "$*" in *'synthetic rename canary'*|*'synthetic descendant canary'*|*'example.txt'*|*'settings/.env'*) exit 71;; esac
case "$*" in *'allowed context'*'changed'*) :;; *) exit 72;; esac
cat <<'EVENTS'
{wire}
{{"type":"agent_end","isTerminal":true}}
EVENTS
"#));
    let report = repo.review(0, &runner, &[]);
    assert_eq!(
        report["coverage"],
        json!({"target.txt":"settled_no_findings"})
    );
    assert!(
        report["exclusions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["change"] == "renamed"
                && file["path"].is_null()
                && file["scope"]["reason"] == "secret_path")
    );
}

#[test]
fn operator_interrupt_stops_the_active_reviewer() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let repo = Repo::new();
    repo.write("file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "after\n");
    repo.checkpoint("head");
    let marker = repo.root().join(".git/ready");
    let runner = repo.runner(
        "waiting-reviewer",
        "echo $$ > \"$FIXTURE_MARKER\"\nsleep 30 &\nwait",
    );
    let mut child = isolated_command(env!("CARGO_BIN_EXE_revkit"))
        .current_dir(repo.root())
        .env("FIXTURE_MARKER", &marker)
        .args([
            "review",
            "--base",
            "main",
            "--trusted-local",
            "--harness",
            runner.to_str().unwrap(),
            "--format",
            "json",
            "--timeout-seconds",
            "10",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let reviewer_pid = loop {
        if let Ok(text) = fs::read_to_string(&marker)
            && let Ok(pid) = text.trim().parse::<libc::pid_t>()
        {
            break pid;
        }
        if start.elapsed() > Duration::from_secs(5) || child.try_wait().unwrap().is_some() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("scripted reviewer did not start");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // Signal only our owned CLI; its supervisor must reap the separate reviewer.
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert_ne!(unsafe { libc::kill(reviewer_pid, 0) }, 0);
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["reasons"].as_array().unwrap().iter().any(|reason| {
        reason
            .as_str()
            .is_some_and(|reason| reason.contains("operator interrupt"))
    }));
}

#[test]
fn review_harness_uses_the_same_relative_path_lookup_as_doctor() {
    let repo = Repo::new();
    repo.write("file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "after\n");
    repo.checkpoint("head");
    repo.stub(verdicts(&[clean("file.txt")]), true);
    let run = |args: &[&str]| {
        let output = isolated_command(env!("CARGO_BIN_EXE_revkit"))
            .current_dir(repo.root())
            .env("PATH", ".git:/usr/bin:/bin")
            .args(args)
            .args([
                "--harness",
                "offline-reviewer",
                "--model",
                "fixture/model",
                "--format",
                "json",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        serde_json::from_slice::<Value>(&output.stdout).unwrap()
    };
    assert_eq!(run(&["doctor"])["ready"], true);
    assert_eq!(
        run(&["review", "--base", "main", "--trusted-local"])["status"],
        "clean"
    );
}

#[test]
fn rename_preserves_source_and_destination_policy() {
    let repo = Repo::new();
    repo.write(
        ".revkit/config.toml",
        "version=1\n[tiers]\nhigh=['sensitive/**']\nlow=['docs/**']\n[checks]\ninspect='true'\n",
    );
    repo.write(
        ".revkit/rules/source.md",
        "---\nid: source-rule\npaths: ['sensitive/**']\n---\nPreserve the source invariant.\n",
    );
    repo.write(
        ".revkit/rules/dest.md",
        "---\nid: dest-rule\npaths: ['docs/**']\n---\nPreserve the destination invariant.\n",
    );
    repo.write("sensitive/file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    fs::create_dir(repo.root().join("docs")).unwrap();
    fs::rename(
        repo.root().join("sensitive/file.txt"),
        repo.root().join("docs/file.txt"),
    )
    .unwrap();
    repo.checkpoint("rename");
    let plan = repo.cli(0, &["plan", "--base", "main", "--format", "json"]);
    assert_eq!(plan["tier"], "high");
    assert_eq!(plan["admission"]["status"], "admitted");
    assert_eq!(
        plan["effective_rules"]["docs/file.txt"],
        json!(["dest-rule", "source-rule"])
    );
}

#[test]
fn anchors_accept_long_changed_lines_but_reject_unchanged_base_context() {
    let repo = Repo::new();
    repo.write("file.txt", "unchanged\nremoved\ntrailing\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    let long_line = "x".repeat(4_097);
    repo.write("file.txt", &format!("unchanged\n{long_line}\ntrailing\n"));
    repo.checkpoint("head");

    let mut combined = finding("file.txt", "head", 2, &long_line);
    let entries = combined["findings"].as_array_mut().unwrap();
    entries.push(finding("file.txt", "base", 2, "removed")["findings"][0].clone());
    let report = repo.review(2, &repo.stub(verdicts(&[combined]), true), &[]);
    assert_eq!(report["findings"].as_array().unwrap().len(), 2);
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["excerpt"] == long_line)
    );
    let invalid = finding("file.txt", "base", 1, "unchanged");
    let report = repo.review(3, &repo.stub(verdicts(&[invalid]), true), &[]);
    assert_eq!(report["findings"], json!([]));
    assert_eq!(report["leads"][0]["reason"], "invalid_anchor");
    assert_eq!(report["coverage"]["file.txt"], "unsettled");
}

#[test]
fn duplicate_findings_keep_the_strongest_severity() {
    let repo = Repo::new();
    repo.write("file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "after\n");
    repo.checkpoint("head");

    let mut advisory = finding("file.txt", "head", 1, "after");
    advisory["findings"][0]["severity"] = json!("P3");
    let report = repo.review(0, &repo.stub(verdicts(&[advisory.clone()]), true), &[]);
    let id = &report["findings"][0]["id"];
    let mut blocking = advisory["findings"][0].clone();
    blocking["severity"] = json!("P1");
    advisory["findings"].as_array_mut().unwrap().push(blocking);
    for _ in 0..2 {
        let report = repo.review(2, &repo.stub(verdicts(&[advisory.clone()]), true), &[]);
        assert_eq!(report["findings"].as_array().unwrap().len(), 1);
        assert_eq!(&report["findings"][0]["id"], id);
        assert_eq!(report["findings"][0]["severity"], "P1");
        advisory["findings"].as_array_mut().unwrap().reverse();
    }
}

#[test]
fn saved_review_can_be_recovered_when_latest_cannot_be_replaced() {
    let repo = Repo::new();
    repo.write("file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "after\n");
    repo.checkpoint("head");
    fs::create_dir_all(repo.root().join(".git/revkit/latest")).unwrap();
    let report = repo.review(
        1,
        &repo.stub(verdicts(&[finding("file.txt", "head", 1, "after")]), true),
        &[],
    );
    let message = report["error"]["message"].as_str().unwrap();
    let id = message
        .split_whitespace()
        .nth(2)
        .unwrap()
        .trim_end_matches(';');
    assert!(message.contains(&format!("revkit findings --run {id}")));
    let saved = repo.cli(0, &["findings", "--run", id, "--format", "json"]);
    assert_eq!(saved["findings"][0]["excerpt"], "after");
}

#[test]
fn ambiguous_protected_moves_are_withheld_from_review_and_checks() {
    let repo = Repo::new();
    repo.write(
        ".revkit/config.toml",
        "version=1\n[checks]\ninspect='exit 99'\n",
    );
    repo.write(".env", "synthetic original line\n");
    repo.write("known.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    fs::remove_file(repo.root().join(".env")).unwrap();
    repo.write("new.txt", "substantially rewritten synthetic content\n");
    repo.write("known.txt", "after\n");
    repo.checkpoint("head");
    let plan = repo.cli(0, &["plan", "--base", "main", "--format", "json"]);
    assert_eq!(plan["unit"], json!(["known.txt"]));
    assert!(plan["files"].as_array().unwrap().iter().any(|file| {
        file["scope"]["reason"] == "ambiguous_protected_rename" && file["new_blob"].is_null()
    }));
    let stub = repo.stub(verdicts(&[clean("known.txt")]), true);
    let sarif = repo.cli(
        5,
        &[
            "review",
            "--base",
            "main",
            "--trusted-local",
            "--run-checks",
            "--harness",
            stub.to_str().unwrap(),
            "--model",
            "fixture/model",
            "--format",
            "sarif",
        ],
    );
    assert!(
        sarif["runs"][0]["properties"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| {
                item.as_str().is_some_and(|reason| {
                    reason.contains("Check inspect: unavailable") && reason.contains("ambiguous")
                })
            })
    );
}

#[test]
fn inherited_git_location_and_diff_options_cannot_override_a_plan() {
    let other = Repo::new();
    other.write("wrong.txt", "other checkout\n");
    other.checkpoint("other");
    let repo = Repo::new();
    let context = format!(
        "{}\n",
        "unchanged context line with over forty bytes\n".repeat(1_400)
    );
    repo.write("right.txt", &format!("{context}before\n"));
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("right.txt", &format!("{context}after\n"));
    let head = repo.checkpoint("head");
    let output = isolated_command(env!("CARGO_BIN_EXE_revkit"))
        .current_dir(repo.root())
        .env("GIT_DIR", other.root().join(".git"))
        .env("GIT_WORK_TREE", other.root())
        .env("GIT_DIFF_OPTS", "--unified=1500")
        .args(["plan", "--base", "main", "--format", "json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["comparison"]["head"], head);
    assert_eq!(plan["unit"], json!(["right.txt"]));
    assert_eq!(plan["admission"]["status"], "admitted");
}
