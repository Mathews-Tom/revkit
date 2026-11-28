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
        serde_json::from_slice(&self.cli_stdout(code, args)).unwrap()
    }

    fn cli_stdout(&self, code: i32, args: &[&str]) -> Vec<u8> {
        let output = isolated_command(env!("CARGO_BIN_EXE_revkit"))
            .args(args)
            .current_dir(self.root())
            .env("HOME", self.root().join(".git"))
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(code),
            "{args:?}: {}: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
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
            "provider":"fixture-observed",
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
fn finding(path: &str, anchor_id: &str) -> Value {
    json!({"path":path,"verdict":"finding","findings":[{"severity":"P2","anchor_id":anchor_id,"note":"Preview uses the live delivery mode."}]})
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
fn text_output_distinguishes_request_size_from_harness_usage() {
    let repo = Repo::new();
    repo.write("display.py", "label = 'old'\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("display.py", "label = 'new'\n");
    repo.checkpoint("change");

    let plan = String::from_utf8(repo.cli_stdout(0, &["plan", "--base", "main"])).unwrap();
    assert!(plan.contains("bytes, 2 changed lines (before harness context; not a token budget)"));

    let stub = repo.stub(verdicts(&[clean("display.py")]), true);
    let missing = repo.root().join("missing-reviewer");
    for (harness, exit, tokens) in [
        (stub, 0, "input=420 output=25"),
        (missing, 6, "not reported"),
    ] {
        let report = repo.cli_stdout(
            exit,
            &[
                "review",
                "--base",
                "main",
                "--trusted-local",
                "--harness",
                harness.to_str().unwrap(),
                "--model",
                "fixture/model",
            ],
        );
        let report = String::from_utf8(report).unwrap();
        assert!(
            report.lines().any(|line| line.ends_with(tokens)),
            "{report}"
        );
    }
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
    let anchor = finding("delivery.py", "a3");
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
            verdicts(&[finding("delivery.py", "a999"), clean("display.py")]),
            true,
        ),
        &[],
    );
    assert_eq!(invalid["leads"][0]["reason"], "unknown_anchor_id");
    assert_eq!(invalid["findings"], json!([]));
    assert_eq!(invalid["coverage"]["display.py"], "settled_no_findings");
    let cross_file = repo.review(
        3,
        &repo.stub(
            verdicts(&[finding("delivery.py", "a5"), clean("display.py")]),
            true,
        ),
        &[],
    );
    assert_eq!(cross_file["leads"][0]["reason"], "anchor_path_mismatch");
    assert_eq!(cross_file["coverage"]["delivery.py"], "unsettled");
    assert_eq!(cross_file["findings"], json!([]));
    let nonterminal = repo.review(
        3,
        &repo.stub(verdicts(&[anchor.clone(), clean("display.py")]), false),
        &[],
    );
    assert_eq!(nonterminal["coverage"]["delivery.py"], "unsettled");
    assert_eq!(nonterminal["findings"][0]["commit"], head);
    let positive = repo.review(
        2,
        &repo.stub(verdicts(&[anchor, finding("display.py", "a4")]), true),
        &[],
    );
    assert_eq!(positive["status"], "findings");
    assert_eq!(positive["comparison"]["head"], head);
    assert_eq!(positive["findings"][0]["line"], 2);
    assert_eq!(positive["findings"][0]["excerpt"], "    return 'live'");
    assert!(positive["findings"][0]["claimed_line"].is_null());
    assert_eq!(positive["findings"][0]["id"], missing["findings"][0]["id"]);
    assert_eq!(positive["findings"][1]["commit"], base);
    let saved = repo.cli_stdout(
        0,
        &["findings", "--run", missing["run_id"].as_str().unwrap()],
    );
    let saved = String::from_utf8(saved).unwrap();
    assert!(saved.contains(&format!("Head: {head}\n")), "{saved}");
    assert!(saved.contains("\"display.py\": unsettled"), "{saved}");
    assert!(
        saved.contains("\"delivery.py\": settled_with_findings"),
        "{saved}"
    );
    assert!(saved.contains("Missing verdict:"), "{saved}");
    assert!(
        saved.contains(missing["findings"][0]["id"].as_str().unwrap()),
        "{saved}"
    );

    let saved_json = repo.cli(
        0,
        &[
            "findings",
            "--run",
            missing["run_id"].as_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert_eq!(saved_json["status"], "incomplete");
    assert_eq!(saved_json["coverage"], missing["coverage"]);
    assert_eq!(saved_json["reasons"], missing["reasons"]);
    assert_eq!(saved_json["findings"], missing["findings"]);

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
fn reviewer_reports_http_status_without_disclosing_error_text() {
    let repo = Repo::new();
    repo.write("file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "after\n");
    repo.checkpoint("head");
    let error = json!({"type":"message_end","message":{
        "role":"assistant","stopReason":"error","content":[],
        "errorStatus":429,"errorMessage":"private upstream details"
    }});
    let completion = json!({"type":"message_end","message":{
        "role":"assistant","stopReason":"stop",
        "content":[{"type":"text","text":verdicts(&[clean("file.txt")]).to_string()}]
    }});
    let terminal = json!({"type":"agent_end","isTerminal":true});
    let stub = repo.runner(
        "rate-limited-reviewer",
        &format!("cat <<'EVENTS'\n{error}\n{terminal}\nEVENTS\nexit 1"),
    );
    let report = repo.review(3, &stub, &[]);
    assert_eq!(report["status"], "incomplete");
    assert_eq!(report["coverage"]["file.txt"], "unsettled");
    assert_eq!(
        report["reasons"],
        json!([
            "OMP reported an upstream error (HTTP 429).",
            "No final reviewer verdict"
        ])
    );
    assert!(!report.to_string().contains("private upstream details"));

    let stub = repo.runner(
        "recovered-reviewer",
        &format!("cat <<'EVENTS'\n{error}\n{completion}\n{terminal}\nEVENTS"),
    );
    let report = repo.review(0, &stub, &[]);
    assert_eq!(report["status"], "clean");
    assert_eq!(report["coverage"]["file.txt"], "settled_no_findings");
    assert_eq!(report["reasons"], json!([]));
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
        .env("HOME", repo.root().join(".git"))
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
            .env("HOME", repo.root().join(".git"))
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
fn anchors_resolve_long_lines_and_distinguish_removed_from_context() {
    let repo = Repo::new();
    repo.git(&["config", "diff.suppressBlankEmpty", "true"]);
    repo.write("file.txt", "leading\n\nunchanged\nremoved\ntrailing\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    let long_line = "x".repeat(4_097);
    repo.write(
        "file.txt",
        &format!("leading\n\nunchanged\n{long_line}\ntrailing\n"),
    );
    repo.checkpoint("head");

    let mut combined = finding("file.txt", "a5");
    let entries = combined["findings"].as_array_mut().unwrap();
    entries.push(finding("file.txt", "a4")["findings"][0].clone());
    let report = repo.review(2, &repo.stub(verdicts(&[combined]), true), &[]);
    assert_eq!(report["findings"].as_array().unwrap().len(), 2);
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["excerpt"] == long_line)
    );
    let context = finding("file.txt", "a3");
    let report = repo.review(2, &repo.stub(verdicts(&[context]), true), &[]);
    assert_eq!(report["findings"][0]["side"], "head");
    assert_eq!(report["findings"][0]["line"], 3);
    assert_eq!(report["findings"][0]["excerpt"], "unchanged");
}

#[test]
fn annotated_anchors_are_deterministic_and_bound_to_visible_pinned_lines() {
    let repo = Repo::new();
    repo.write("a-deleted.txt", "deleted context\n");
    repo.write("b.txt", "repeat\r\nold\r\nrepeat\r\nend");
    repo.write(
        "d-old.txt",
        &format!(
            "{}\n",
            (1..=24)
                .map(|n| format!("stable line {n}"))
                .collect::<Vec<_>>()
                .join("\n")
        ),
    );
    let base = repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    fs::remove_file(repo.root().join("a-deleted.txt")).unwrap();
    repo.write("b.txt", "repeat\r\nnew\r\nrepeat\r\nend!");
    repo.write("c.txt", "a1 + literal source\n");
    repo.git(&["mv", "d-old.txt", "d-new.txt"]);
    let renamed = fs::read_to_string(repo.root().join("d-new.txt")).unwrap();
    repo.write(
        "d-new.txt",
        &renamed
            .replace("stable line 2\n", "changed first\n")
            .replace("stable line 23\n", "changed last\n"),
    );
    let head = repo.checkpoint("head");
    let capture = repo.root().join(".git/captured-prompt");
    let stub = repo.stub(
        verdicts(&[clean("b.txt"), clean("c.txt"), clean("d-new.txt")]),
        true,
    );
    let runner = repo.runner(
        "capture-reviewer",
        &format!(
            "for prompt do :; done\nprintf '%s' \"$prompt\" > '{}'\nexec '{}' \"$@\"",
            capture.display(),
            stub.display()
        ),
    );
    repo.review(0, &runner, &[]);
    let first = fs::read_to_string(&capture).unwrap();
    repo.review(0, &runner, &[]);
    assert_eq!(first, fs::read_to_string(&capture).unwrap());
    let projection: Value = serde_json::from_str(first.lines().last().unwrap()).unwrap();
    let patches = projection["patches"].as_array().unwrap();
    let patch = |path: &str| {
        patches.iter().find(|row| row["path"] == path).unwrap()["patch"]
            .as_str()
            .unwrap()
    };
    assert!(!patch("a-deleted.txt").contains("a1 "));
    let b = patch("b.txt");
    assert!(b.contains("a1  repeat\r\n"));
    assert!(b.contains("a2 -old\r\n"));
    assert!(b.contains("a3 +new\r\n"));
    assert!(b.contains("a4  repeat\r\n"));
    assert!(b.contains("a5 -end\n\\ No newline at end of file\n"));
    assert!(b.contains("a6 +end!\n\\ No newline at end of file\n"));
    assert!(patch("c.txt").contains("a7 +a1 + literal source\n"));
    let anchor = |path: &str, source: &str| {
        patch(path)
            .lines()
            .find_map(|row| {
                let (id, text) = row.split_once(' ')?;
                (id.starts_with('a') && text == source).then_some(id)
            })
            .unwrap()
    };
    let mut b_findings = finding("b.txt", "a1");
    b_findings["findings"]
        .as_array_mut()
        .unwrap()
        .extend(["a4", "a5", "a6"].map(|id| finding("b.txt", id)["findings"][0].clone()));
    let mut d_findings = finding("d-new.txt", anchor("d-new.txt", "-stable line 23"));
    d_findings["findings"]
        .as_array_mut()
        .unwrap()
        .push(finding("d-new.txt", anchor("d-new.txt", "+changed last"))["findings"][0].clone());
    let report = repo.review(
        2,
        &repo.stub(
            verdicts(&[b_findings, finding("c.txt", "a7"), d_findings]),
            true,
        ),
        &[],
    );
    let rows = report["findings"].as_array().unwrap();
    assert_eq!(rows.len(), 7);
    for (path, side, commit, line, excerpt) in [
        ("b.txt", "head", &head, 1, "repeat"),
        ("b.txt", "head", &head, 3, "repeat"),
        ("b.txt", "base", &base, 4, "end"),
        ("b.txt", "head", &head, 4, "end!"),
        ("c.txt", "head", &head, 1, "a1 + literal source"),
        ("d-old.txt", "base", &base, 23, "stable line 23"),
        ("d-new.txt", "head", &head, 23, "changed last"),
    ] {
        assert!(
            rows.iter().any(|row| {
                row["path"] == path
                    && row["side"] == side
                    && row["commit"] == commit.as_str()
                    && row["line"] == line
                    && row["excerpt"] == excerpt
            }),
            "{path}:{line} {side}: {rows:?}"
        );
    }
}

#[test]
fn admission_counts_anchor_prefixes_in_prompt_budget() {
    let repo = Repo::new();
    repo.write("base.txt", "base\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("large.txt", &format!("{}\n", "x".repeat(31)).repeat(1300));
    repo.checkpoint("head");
    let plan = repo.cli(0, &["plan", "--base", "main", "--format", "json"]);
    assert_eq!(plan["admission"]["status"], "over_limit");
    assert_eq!(plan["admission"]["reasons"], json!(["prompt_byte_limit"]));
    let harness = repo.runner("must-not-run", "exit 99");
    let report = repo.review(3, &harness, &[]);
    assert_eq!(report["coverage"]["large.txt"], "unsettled");
    assert_eq!(report["reasons"], json!(["prompt_byte_limit"]));
}

#[test]
fn duplicate_findings_keep_the_strongest_severity() {
    let repo = Repo::new();
    repo.write("file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "after\n");
    repo.checkpoint("head");

    let mut advisory = finding("file.txt", "a2");
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
        &repo.stub(verdicts(&[finding("file.txt", "a2")]), true),
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

#[test]
fn metrics_count_attempts_and_deduplicate_only_explicit_prs() {
    let repo = Repo::new();
    repo.write("file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "after\n");
    repo.checkpoint("head");
    let stub = repo.stub(verdicts(&[clean("file.txt")]), true);
    let unavailable = repo.root().join(".git/unavailable");
    let identity = "forge.invalid/private/example#42";
    let args = ["--pr-id", identity, "--harness-version", "fixture-v1"];
    repo.review(0, &stub, &args);
    repo.review(0, &stub, &args);
    repo.review(6, &unavailable, &[]);
    let summary = repo.cli(0, &["metrics", "show", "--format", "json"]);
    assert_eq!(summary["attempts"], 3);
    assert_eq!(summary["distinct_attributed_prs"], 1);
    assert_eq!(summary["unattributed_attempts"], 1);
    assert_eq!(summary["outcomes"]["unavailable"], 1);
    assert_eq!(summary["coverage"]["settled_paths"], 2);
    assert_eq!(summary["usage"]["input"]["reported_sum"], 840);
    assert_eq!(summary["usage"]["input"]["unknown_attempts"], 1);
    assert!(summary["reported_cost"].is_null());
    let dir = repo.root().join(".git/.revkit/metrics");
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let mut pr_digests = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let file = entry.unwrap().path();
        assert_eq!(
            fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        if file.extension().is_some_and(|ext| ext == "json") {
            let text = fs::read_to_string(file).unwrap();
            assert!(!text.contains(identity));
            assert!(!text.contains("file.txt"));
            let row: Value = serde_json::from_str(&text).unwrap();
            if let Some(digest) = row["pr_digest"].as_str() {
                pr_digests.push(digest.to_owned());
                assert_eq!(row["observed_provider"], "fixture-observed");
                assert_eq!(row["harness_version"], "fixture-v1");
                assert_eq!(row["selected_model"], "fixture/model");
            }
        }
    }
    assert_eq!(pr_digests.len(), 2);
    assert_eq!(pr_digests[0], pr_digests[1]);
    fs::write(dir.join("unrelated"), "keep").unwrap();
    let cleared = repo.cli(0, &["metrics", "clear", "--format", "json"]);
    assert_eq!(cleared["removed_attempts"], 3);
    assert_eq!(
        repo.cli(0, &["metrics", "show", "--format", "json"])["attempts"],
        0
    );
    assert!(!dir.join("pr-key").exists());
    assert!(dir.join("unrelated").exists());
}

#[test]
fn metrics_opt_out_and_repository_store_are_isolated() {
    let repo = Repo::new();
    repo.write("file.txt", "before\n");
    repo.write(".gitignore", "/.revkit/metrics/\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "after\n");
    repo.checkpoint("head");
    let stub = repo.stub(verdicts(&[clean("file.txt")]), true);
    let global = repo.root().join(".git/.revkit/metrics");
    let local = repo.root().join(".revkit/metrics");
    repo.review(0, &stub, &["--no-metrics"]);
    assert!(!global.exists());
    repo.cli_stdout(
        1,
        &[
            "review",
            "--base",
            "main",
            "--trusted-local",
            "--pr-id",
            "",
            "--harness",
            stub.to_str().unwrap(),
            "--model",
            "fixture/model",
            "--format",
            "json",
        ],
    );
    assert!(!global.exists());
    repo.write(".git/.revkit/settings.toml", "[metrics]\nenabled = false\n");
    repo.write(".revkit/settings.toml", "[metrics]\nenabled = true\n");
    repo.review(0, &stub, &["--metrics-store", "repository"]);
    assert!(!local.exists());
    repo.write(".git/.revkit/settings.toml", "[metrics]\nenabled = true\n");
    repo.write(".revkit/settings.toml", "[metrics]\nenabled = false\n");
    repo.review(0, &stub, &[]);
    assert!(!global.exists());
    repo.write(".revkit/settings.toml", "[metrics]\nenabled = true\n");
    let settings_dir = repo.root().join(".revkit");
    fs::set_permissions(&settings_dir, fs::Permissions::from_mode(0o775)).unwrap();
    repo.review(0, &stub, &[]);
    assert_eq!(
        repo.cli(0, &["metrics", "show", "--format", "json"])["attempts"],
        1
    );
    repo.cli(0, &["metrics", "clear", "--format", "json"]);
    fs::remove_dir_all(&global).unwrap();
    fs::set_permissions(&settings_dir, fs::Permissions::from_mode(0o755)).unwrap();
    repo.review(0, &stub, &["--metrics-store", "repository"]);
    assert_eq!(
        repo.cli(
            0,
            &[
                "metrics",
                "show",
                "--store",
                "repository",
                "--format",
                "json"
            ]
        )["attempts"],
        1
    );
    assert!(!global.exists());
    repo.git(&["add", "-f", ".revkit/metrics/lock"]);
    repo.review(0, &stub, &["--metrics-store", "repository"]);
    repo.cli(
        1,
        &[
            "metrics",
            "show",
            "--store",
            "repository",
            "--format",
            "json",
        ],
    );
    assert!(!global.exists());
}

#[test]
fn metrics_refuse_symlink_and_do_not_change_verdict() {
    let repo = Repo::new();
    repo.write("file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "after\n");
    repo.checkpoint("head");
    let stub = repo.stub(verdicts(&[clean("file.txt")]), true);
    let outside = tempfile::tempdir().unwrap();
    let parent = repo.root().join(".git/.revkit");
    fs::create_dir(&parent).unwrap();
    symlink(outside.path(), parent.join("metrics")).unwrap();
    let output = isolated_command(env!("CARGO_BIN_EXE_revkit"))
        .current_dir(repo.root())
        .env("HOME", repo.root().join(".git"))
        .args([
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
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("local metrics not recorded"));
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    repo.cli(1, &["metrics", "clear", "--format", "json"]);
    assert!(parent.join("metrics").is_symlink());
}

#[test]
fn metrics_retention_excludes_expired_and_bounds_new_attempts() {
    let repo = Repo::new();
    repo.write("file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "after\n");
    repo.checkpoint("head");
    let stub = repo.stub(verdicts(&[clean("file.txt")]), true);
    repo.review(0, &stub, &[]);
    let dir = repo.root().join(".git/.revkit/metrics");
    let original = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .unwrap();
    let mut old: Value = serde_json::from_slice(&fs::read(&original).unwrap()).unwrap();
    let today = old["utc_day"].as_u64().unwrap();
    old["utc_day"] = json!(today - 90);
    fs::write(&original, serde_json::to_vec(&old).unwrap()).unwrap();
    assert_eq!(
        repo.cli(0, &["metrics", "show", "--format", "json"])["attempts"],
        0
    );
    repo.review(0, &stub, &[]);
    assert!(!original.exists());
    let fresh = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .unwrap();
    for index in 0..999 {
        fs::copy(&fresh, dir.join(format!("attempt-{index:016}.json"))).unwrap();
    }
    repo.review(0, &stub, &[]);
    assert_eq!(
        repo.cli(0, &["metrics", "show", "--format", "json"])["attempts"],
        1000
    );
}

#[test]
fn metrics_preserve_large_reported_sums_without_panicking() {
    let repo = Repo::new();
    repo.write("file.txt", "before\n");
    repo.checkpoint("base");
    repo.git(&["checkout", "-qb", "change"]);
    repo.write("file.txt", "after\n");
    repo.checkpoint("head");
    let events = json!({"type":"message_end","message":{"role":"assistant","stopReason":"stop","usage":{"input":u64::MAX},"content":[{"type":"text","text":verdicts(&[clean("file.txt")]).to_string()}]}});
    let stub = repo.runner(
        "huge-usage",
        &format!(
            "cat <<'EVENTS'\n{events}\n{{\"type\":\"agent_end\",\"isTerminal\":true}}\nEVENTS"
        ),
    );
    repo.review(0, &stub, &[]);
    repo.review(0, &stub, &[]);
    let summary = repo.cli(0, &["metrics", "show", "--format", "json"]);
    assert_eq!(
        summary["usage"]["input"]["reported_sum"],
        (2 * u128::from(u64::MAX)).to_string()
    );
}
