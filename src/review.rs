use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Value, json};

use crate::harness::{self, Execution, Status};
use crate::plan::{Anchor, MAX_FINDINGS_PER_FILE, Plan, Prepared, Side, digest};
use crate::policy::Rule;
use crate::snapshot::{Comparison, Git, Selection};
use crate::{Result, SCHEMA_VERSION};

const MAX_LOCAL_REPORT: usize = 4 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
pub(crate) struct Report {
    kind: String,
    schema_version: u8,
    pub(crate) run_id: String,
    pub(crate) trust_mode: String,
    pub(crate) comparison: Comparison,
    pub(crate) trusted_base: Option<String>,
    pub(crate) status: RunStatus,
    pub(crate) reasons: Vec<String>,
    pub(crate) coverage: BTreeMap<String, String>,
    pub(crate) findings: Vec<Finding>,
    pub(crate) leads: Vec<Lead>,
    pub(crate) checks: Vec<Check>,
    pub(crate) effective_rules: BTreeMap<String, Vec<String>>,
    pub(crate) rules: Vec<Rule>,
    pub(crate) exclusions: Value,
    pub(crate) model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) provider: Option<String>,
    #[serde(skip)]
    pub(crate) no_changes: bool,
    pub(crate) usage: Option<Value>,
    elapsed_ms: u128,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RunStatus {
    Clean,
    Findings,
    Incomplete,
    Unavailable,
    ChecksOnly,
}

impl RunStatus {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Findings => "findings",
            Self::Incomplete => "incomplete",
            Self::Unavailable => "unavailable",
            Self::ChecksOnly => "checks_only",
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Finding {
    pub(crate) id: String,
    pub(crate) path: String,
    pub(crate) side: Side,
    pub(crate) commit: String,
    pub(crate) blob: String,
    pub(crate) line: usize,
    pub(crate) claimed_line: Option<usize>,
    pub(crate) severity: Severity,
    pub(crate) excerpt: String,
    pub(crate) note: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Lead {
    pub(crate) path: String,
    pub(crate) note: String,
    pub(crate) reason: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Check {
    pub(crate) name: String,
    pub(crate) command_sha256: String,
    pub(crate) status: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout_sha256: Option<String>,
    pub(crate) stderr_sha256: Option<String>,
    pub(crate) elapsed_ms: Option<u128>,
    pub(crate) reason: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum Severity {
    P0,
    P1,
    P2,
    P3,
}

impl Severity {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::P0 => "P0",
            Self::P1 => "P1",
            Self::P2 => "P2",
            Self::P3 => "P3",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    complete: bool,
    verdicts: Vec<Box<RawValue>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Verdict {
    path: String,
    verdict: Decision,
    findings: Vec<Box<RawValue>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    Clean,
    Finding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    anchor_id: String,
    severity: Severity,
    note: String,
}

impl Report {
    pub(crate) fn exit_code(&self) -> u8 {
        match self.status {
            RunStatus::Unavailable => 6,
            RunStatus::Incomplete => 3,
            _ if self.checks.iter().any(|check| check.status != "passed") => 5,
            RunStatus::Findings
                if self
                    .findings
                    .iter()
                    .any(|finding| finding.severity != Severity::P3) =>
            {
                2
            }
            _ => 0,
        }
    }

    pub(crate) fn sarif(&self, only: Option<&str>) -> Value {
        let results: Vec<_> = self.findings.iter().filter(|finding| only.is_none_or(|id| id == finding.id))
            .map(|finding| {
                let level = match finding.severity {
                    Severity::P0 | Severity::P1 => "error",
                    Severity::P2 => "warning",
                    Severity::P3 => "note",
                };
                // Base anchors are not inline locations at the current head.
                let mut result = json!({
                    "ruleId": finding.severity.name(), "level": level, "message": {"text": finding.note},
                    "partialFingerprints": {"revkitFinding/v1": finding.id},
                    "properties": {"side": finding.side, "commit": finding.commit},
                });
                if finding.side == Side::Head {
                    result["locations"] = json!([{"physicalLocation": {
                        "artifactLocation": {"uri": uri(&finding.path)},
                        "region": {"startLine": finding.line}
                    }}]);
                } else {
                    result["properties"]["basePath"] = json!(finding.path);
                    result["properties"]["baseLine"] = json!(finding.line);
                }
                result
            }).collect();
        json!({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
            "tool": {"driver": {"name": "revkit", "version": env!("CARGO_PKG_VERSION")}},
            "invocations": [{"executionSuccessful": !matches!(self.status, RunStatus::Incomplete | RunStatus::Unavailable),
                "exitCode": self.exit_code()}],
            "properties": {"runId": self.run_id, "head": self.comparison.head, "status": self.status, "reasons": self.reasons},
            "results": results
        }]})
    }
}

pub(crate) fn run(
    git: &Git,
    prepared: Prepared,
    executable: &Path,
    model: Option<&str>,
    timeout: Duration,
    run_checks: bool,
) -> Result<Report> {
    let start = std::time::Instant::now();
    let Prepared {
        plan,
        policy,
        prompt,
        anchors,
    } = prepared;
    let checks = if run_checks {
        checks(git, &plan, &policy)
    } else {
        plan.checks
            .iter()
            .map(|check| pending_check(check, "not_authorized"))
            .collect()
    };
    let mut coverage: BTreeMap<_, _> = plan
        .unit
        .iter()
        .map(|path| (path.clone(), "unsettled".to_owned()))
        .collect();
    let mut reasons: Vec<String> = plan
        .admission
        .reasons
        .iter()
        .map(|reason| (*reason).to_owned())
        .collect();
    let mut findings = Vec::new();
    let mut leads = Vec::new();
    let mut observed_model = None;
    let mut observed_provider = None;
    let mut usage = None;
    let status = match (plan.admission.status, prompt) {
        ("no_changes", _) => RunStatus::Clean,
        ("checks_only", _) => {
            coverage
                .values_mut()
                .for_each(|status| *status = "model_skipped:tier_low".to_owned());
            RunStatus::ChecksOnly
        }
        ("admitted", Some(prompt)) => {
            let execution = harness::run(executable, model, &prompt, timeout);
            let validation = validate(git, &plan, &anchors, &execution)?;
            coverage = validation.coverage;
            findings = validation.findings;
            leads = validation.leads;
            reasons.extend(validation.reasons);
            observed_model = execution.model;
            observed_provider = execution.provider;
            usage = execution.usage;
            if execution.status == Status::Unavailable {
                RunStatus::Unavailable
            } else if execution.status != Status::Complete || !reasons.is_empty() {
                RunStatus::Incomplete
            } else if findings.is_empty() {
                RunStatus::Clean
            } else {
                RunStatus::Findings
            }
        }
        ("over_limit", _) => RunStatus::Incomplete,
        ("no_model_targets", _) => {
            reasons.push("No changed file is eligible for model review".to_owned());
            RunStatus::Incomplete
        }
        _ => return Err("Inconsistent review admission".into()),
    };
    for check in &checks {
        if check.status != "passed" {
            let suffix = check
                .reason
                .as_deref()
                .map_or(String::new(), |reason| format!(" ({reason})"));
            reasons.push(format!("Check {}: {}{suffix}", check.name, check.status));
        }
    }
    let exclusions = serde_json::to_value(
        plan.files
            .iter()
            .filter(|file| !matches!(file.scope, crate::snapshot::Selection::Selected))
            .collect::<Vec<_>>(),
    )?;
    Ok(Report {
        kind: "review".to_owned(),
        schema_version: SCHEMA_VERSION,
        run_id: String::new(),
        trust_mode: "trusted_local".to_owned(),
        comparison: plan.comparison,
        trusted_base: plan.trusted_base,
        status,
        reasons,
        coverage,
        findings,
        leads,
        checks,
        effective_rules: plan.effective_rules,
        rules: plan.rules,
        exclusions,
        model: observed_model,
        provider: observed_provider,
        no_changes: plan.admission.status == "no_changes",
        usage,
        elapsed_ms: start.elapsed().as_millis(),
    })
}

struct Validation {
    coverage: BTreeMap<String, String>,
    reasons: Vec<String>,
    findings: Vec<Finding>,
    leads: Vec<Lead>,
}

fn validate(
    git: &Git,
    plan: &Plan,
    anchors: &[Anchor],
    execution: &Execution,
) -> Result<Validation> {
    let mut result = Validation {
        coverage: plan
            .unit
            .iter()
            .map(|path| (path.clone(), "unsettled".to_owned()))
            .collect(),
        reasons: execution.reason.iter().cloned().collect(),
        findings: Vec::new(),
        leads: Vec::new(),
    };
    let Some(text) = &execution.final_text else {
        result.reasons.push("No final reviewer verdict".to_owned());
        return Ok(result);
    };
    let Ok(final_verdict) = serde_json::from_str::<Completion>(text) else {
        result
            .reasons
            .push("Invalid typed review completion".to_owned());
        return Ok(result);
    };
    let completed = final_verdict.complete && execution.status == Status::Complete;
    if !final_verdict.complete {
        result
            .reasons
            .push("Reviewer did not declare completion".to_owned());
    }
    let mut by_path = BTreeMap::<String, Vec<Verdict>>::new();
    let mut invalid = BTreeSet::new();
    for row in final_verdict.verdicts {
        if let Ok(verdict) = serde_json::from_str::<Verdict>(row.get()) {
            if result.coverage.contains_key(&verdict.path) {
                by_path
                    .entry(verdict.path.clone())
                    .or_default()
                    .push(verdict);
            } else {
                result
                    .reasons
                    .push("Verdict for an unassigned path".to_owned());
            }
        } else if let Some(path) = serde_json::from_str::<Value>(row.get())
            .ok()
            .and_then(|row| {
                row.get("path")
                    .and_then(Value::as_str)
                    .filter(|path| result.coverage.contains_key(*path))
                    .map(str::to_owned)
            })
        {
            invalid.insert(path);
        } else {
            result
                .reasons
                .push("Invalid or unassigned verdict row".to_owned());
        }
    }
    let mut by_id = BTreeMap::<String, usize>::new();
    for (file_index, file) in plan.files.iter().enumerate() {
        let Some(path) = file
            .path
            .as_deref()
            .filter(|path| result.coverage.contains_key(*path))
        else {
            continue;
        };
        let rows = by_path.remove(path).unwrap_or_default();
        let mut bad = invalid.contains(path);
        if rows.is_empty() && !bad {
            result.reasons.push(format!("Missing verdict: {path:?}"));
            continue;
        }
        if rows.len() > 1 {
            result.reasons.push(format!("Duplicate verdict: {path:?}"));
            bad = true;
        }
        let mut saw_finding = false;
        let mut blobs: [Option<String>; 2] = [None, None];
        for row in rows.into_iter().take(2) {
            if matches!(row.verdict, Decision::Clean) {
                bad |= !row.findings.is_empty();
                continue;
            }
            saw_finding = true;
            bad |= row.findings.is_empty() || row.findings.len() > MAX_FINDINGS_PER_FILE;
            for value in row.findings.into_iter().take(MAX_FINDINGS_PER_FILE) {
                let Ok(candidate) = serde_json::from_str::<Candidate>(value.get()) else {
                    bad = true;
                    continue;
                };
                if candidate.note.trim().is_empty() || candidate.note.len() > 2_048 {
                    bad = true;
                    continue;
                }
                let anchor = candidate
                    .anchor_id
                    .strip_prefix('a')
                    .filter(|index| {
                        !index.starts_with('0') && index.bytes().all(|b| b.is_ascii_digit())
                    })
                    .and_then(|index| index.parse::<usize>().ok())
                    .and_then(|index| index.checked_sub(1))
                    .and_then(|index| anchors.get(index));
                let reason = match anchor {
                    None => Some("unknown_anchor_id"),
                    Some(anchor) if anchor.file_index != file_index => Some("anchor_path_mismatch"),
                    Some(_) => None,
                };
                if let Some(reason) = reason {
                    result.leads.push(Lead {
                        path: path.to_owned(),
                        note: candidate.note,
                        reason: reason.to_owned(),
                    });
                    bad = true;
                    continue;
                }
                let anchor = anchor.expect("validated anchor");
                let (commit, blob, index, anchor_path) = match anchor.side {
                    Side::Head => (Some(&plan.comparison.head), file.new_blob.as_ref(), 0, path),
                    Side::Base => (
                        plan.comparison.base.as_ref(),
                        file.old_blob.as_ref(),
                        1,
                        file.old_path.as_deref().unwrap_or(path),
                    ),
                };
                let commit = commit.ok_or("Anchor has no pinned commit")?;
                let blob = blob.ok_or("Anchor has no pinned blob")?;
                if blobs[index].is_none() {
                    blobs[index] = Some(git.blob_text(blob)?);
                }
                let excerpt = blobs[index]
                    .as_deref()
                    .expect("loaded blob")
                    .lines()
                    .nth(anchor.line - 1)
                    .ok_or("Anchor line is outside pinned blob")?;
                let id = digest(&serde_json::to_vec(&(
                    anchor_path,
                    anchor.side,
                    commit,
                    anchor.line,
                    excerpt,
                    &candidate.note,
                ))?);
                if let Some(&index) = by_id.get(&id) {
                    let finding = &mut result.findings[index];
                    finding.severity = finding.severity.min(candidate.severity);
                } else {
                    by_id.insert(id.clone(), result.findings.len());
                    result.findings.push(Finding {
                        id,
                        path: anchor_path.to_owned(),
                        side: anchor.side,
                        commit: commit.clone(),
                        blob: blob.clone(),
                        line: anchor.line,
                        claimed_line: None,
                        severity: candidate.severity,
                        excerpt: excerpt.to_owned(),
                        note: candidate.note,
                    });
                }
            }
        }
        if bad {
            result
                .reasons
                .push(format!("Invalid verdict or anchor: {path:?}"));
        } else if completed {
            result.coverage.insert(
                path.to_owned(),
                if saw_finding {
                    "settled_with_findings"
                } else {
                    "settled_no_findings"
                }
                .to_owned(),
            );
        }
    }
    result.reasons.sort_unstable();
    result.reasons.dedup();
    result.findings.sort_unstable_by(|a, b| {
        (a.severity, &a.path, a.line, &a.id).cmp(&(b.severity, &b.path, b.line, &b.id))
    });
    Ok(result)
}

fn pending_check(plan: &crate::plan::CheckPlan, status: &str) -> Check {
    Check {
        name: plan.name.clone(),
        command_sha256: plan.command_sha256.clone(),
        status: status.to_owned(),
        exit_code: None,
        stdout_sha256: None,
        stderr_sha256: None,
        elapsed_ms: None,
        reason: None,
    }
}

fn checks(git: &Git, plan: &Plan, policy: &crate::policy::Policy) -> Vec<Check> {
    use std::process::Command;
    use std::time::Instant;

    let deadline = Instant::now() + Duration::from_secs(45);
    plan.checks
        .iter()
        .map(|planned| {
            let mut check = pending_check(planned, "unavailable");
            let attempt = || -> Result<_> {
                if harness::interrupted() {
                    return Err("Check cancelled by operator interrupt".into());
                }
                if plan
                    .files
                    .iter()
                    .any(|file| (file.change == "renamed" && file.path.is_none()) || matches!(
                        file.scope, Selection::Excluded { reason: "ambiguous_protected_rename" }
                    ))
                {
                    return Err(
                        "Exact check snapshot contains a protected, ambiguous, or unsupported rename".into(),
                    );
                }
                if Instant::now() >= deadline {
                    return Err("Check stage deadline reached".into());
                }
                let scratch = tempfile::tempdir()?;
                let tree = scratch.path().join("tree");
                fs::create_dir(&tree)?;
                #[cfg(unix)]
                git.materialize_checks(&plan.comparison.head, &tree, policy, deadline)?;
                #[cfg(not(unix))]
                return Err("Exact check snapshots are unsupported on this platform".into());
                let home = scratch.path().join("home");
                fs::create_dir(&home)?;
                let command = &policy.checks[&planned.name];
                let limit = deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(15));
                if limit.is_zero() {
                    return Err("Check stage deadline reached".into());
                }
                let mut process = Command::new("/bin/sh");
                process
                    .args(["-c", command])
                    .env_clear()
                    .env("PATH", "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin")
                    .env("HOME", &home)
                    .env("TMPDIR", scratch.path())
                    .env("LC_ALL", "C")
                    .current_dir(tree);
                Ok(harness::bounded(&mut process, limit)?)
            };
            let checked_at = Instant::now();
            match attempt() {
                Ok(output) => {
                    check.exit_code = output.status.code();
                    check.stdout_sha256 = Some(digest(&output.stdout));
                    check.stderr_sha256 = Some(digest(&output.stderr));
                    check.status = if output.status.success() {
                        "passed"
                    } else if output.status.code() == Some(127) {
                        "missing"
                    } else {
                        "failed"
                    }
                    .to_owned();
                }
                Err(err) => check.reason = Some(err.to_string()),
            }
            check.elapsed_ms = Some(checked_at.elapsed().as_millis());
            check
        })
        .collect()
}

pub(crate) fn save(git: &Git, report: &mut Report) -> Result<()> {
    let dir = git.git_dir()?.join("revkit");
    match fs::symlink_metadata(&dir) {
        Ok(meta) if !meta.is_dir() => {
            return Err("Local revkit state path is not a directory".into());
        }
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            match builder.create(&dir) {
                Ok(()) => {}
                Err(err)
                    if err.kind() == std::io::ErrorKind::AlreadyExists
                        && fs::symlink_metadata(&dir)?.is_dir() => {}
                Err(err) => return Err(err.into()),
            }
        }
        Err(err) => return Err(err.into()),
    }
    let mut file = tempfile::Builder::new()
        .prefix("run-")
        .rand_bytes(16)
        .tempfile_in(&dir)?;
    let id = file
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Invalid local review ID")?;
    report.run_id = id.to_owned();
    let encoded = serde_json::to_vec(report)?;
    if encoded.len() > MAX_LOCAL_REPORT {
        return Err("Review report exceeds the local record limit".into());
    }
    file.write_all(&encoded)?;
    let target = dir.join(format!("{}.json", report.run_id));
    file.persist_noclobber(target)?;
    let update_latest = || -> std::io::Result<()> {
        let mut latest = tempfile::NamedTempFile::new_in(&dir)?;
        latest.write_all(report.run_id.as_bytes())?;
        latest
            .persist(dir.join("latest"))
            .map_err(|err| err.error)?;
        Ok(())
    };
    update_latest().map_err(|err| {
        format!(
            "Saved review {}; could not update latest: {err}. Recover with `revkit findings --run {}`.",
            report.run_id, report.run_id
        ).into()
    })
}

pub(crate) fn load(git: &Git, run_id: Option<&str>) -> Result<Report> {
    let dir = git.git_dir()?.join("revkit");
    if !fs::symlink_metadata(&dir).is_ok_and(|meta| meta.is_dir()) {
        return Err("No local revkit report found".into());
    }
    let latest;
    let id = if let Some(id) = run_id {
        id
    } else {
        latest = String::from_utf8(read_local(&dir.join("latest"), 64)?)?;
        &latest
    };
    if !id.strip_prefix("run-").is_some_and(|suffix| {
        suffix.len() == 16 && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
    }) {
        return Err("Invalid local review ID".into());
    }
    let report: Report = serde_json::from_slice(&read_local(
        &dir.join(format!("{id}.json")),
        MAX_LOCAL_REPORT,
    )?)?;
    if report.kind != "review" || report.schema_version != SCHEMA_VERSION || report.run_id != id {
        return Err("Unsupported or mismatched local review record".into());
    }
    Ok(report)
}

fn read_local(path: &Path, limit: usize) -> Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err("Local review record is not a regular file".into());
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("Local review record exceeds the byte limit".into());
    }
    Ok(bytes)
}

fn uri(path: &str) -> String {
    use std::fmt::Write as _;
    let mut uri = String::new();
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            uri.push(char::from(b));
        } else {
            write!(uri, "%{b:02X}").expect("write to string");
        }
    }
    uri
}
