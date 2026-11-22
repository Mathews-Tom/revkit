mod harness;
mod plan;
mod policy;
mod review;
mod snapshot;

use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use serde_json::json;

use plan::Plan;
use review::Report;
use snapshot::{Comparison, Git, Selection};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Copy, Default, ValueEnum)]
enum Format {
    #[default]
    Text,
    Json,
    Sarif,
}

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, global = true, value_enum, default_value = "text")]
    format: Format,
    #[arg(long, global = true, value_name = "DIR")]
    repo: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Args)]
struct Target {
    #[arg(long, required_unless_present = "commit", conflicts_with = "commit")]
    base: Option<String>,
    #[arg(long, requires = "base")]
    head: Option<String>,
    #[arg(long)]
    commit: Option<String>,
    /// Additional operator requirements; supply the same value to plan and review.
    #[arg(long, default_value = "")]
    requirements: String,
}

impl Target {
    fn pin(&self, git: &Git) -> Result<Comparison> {
        if let Some(commit) = &self.commit {
            git.single(commit)
        } else {
            git.range(
                self.base.as_deref().ok_or("select --base or --commit")?,
                self.head.as_deref().unwrap_or("HEAD"),
            )
        }
    }
}

#[derive(Args)]
struct Runtime {
    /// Operator-selected, already-configured omp executable.
    #[arg(long, default_value = "omp", value_name = "OMP")]
    harness: PathBuf,
    /// Model selector passed unchanged to the configured harness.
    #[arg(long)]
    model: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Write initial configuration without overwriting existing files.
    Init,
    /// Check local Git, base policy, and reviewer executable availability. No sign-in or model calls.
    Doctor {
        #[command(flatten)]
        runtime: Runtime,
        #[arg(long)]
        base: Option<String>,
    },
    /// Preview a committed Git comparison without a reviewer or checks.
    Plan {
        #[command(flatten)]
        target: Target,
    },
    /// Review committed inputs in one fresh configured harness session.
    Review {
        #[command(flatten)]
        target: Target,
        #[command(flatten)]
        runtime: Runtime,
        /// Required for trusted checkouts; this mode is not a confinement boundary.
        #[arg(long, required = true)]
        trusted_local: bool,
        /// Also run trusted-base check commands on disposable exact-head files.
        #[arg(long, requires = "trusted_local")]
        run_checks: bool,
        #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=180))]
        timeout_seconds: u64,
    },
    /// Read anchored findings from a saved local review.
    Findings {
        id: Option<String>,
        #[arg(long)]
        run: Option<String>,
    },
    /// Inspect rules from a saved local review.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
}

#[derive(Subcommand)]
enum RulesCommand {
    /// Explain the effective trusted rules for an assigned path.
    Explain {
        path: String,
        #[arg(long)]
        run: Option<String>,
    },
}

fn run(mut cli: Cli, out: &mut impl Write) -> Result<u8> {
    if matches!(cli.format, Format::Sarif)
        && !matches!(
            cli.command,
            Command::Review { .. } | Command::Findings { .. }
        )
    {
        return Err("SARIF is available for review and findings only".into());
    }
    if let Command::Review { runtime, .. } | Command::Doctor { runtime, .. } = &mut cli.command {
        if runtime.harness.is_relative() && runtime.harness.components().count() > 1 {
            runtime.harness = env::current_dir()?.join(&runtime.harness);
        }
        if runtime
            .model
            .as_ref()
            .is_some_and(|model| model.is_empty() || model.starts_with('-'))
        {
            return Err("Use a nonempty model selector that does not start with '-'".into());
        }
    }
    if let Some(repo) = cli.repo {
        env::set_current_dir(repo)?;
    }
    let git = Git::current()?;
    let format = cli.format;
    match cli.command {
        Command::Init => init(&git, format, out)?,
        Command::Doctor { runtime, base } => {
            return doctor(&git, &runtime, base.as_deref(), format, out);
        }
        Command::Plan { target } => {
            let prepared = plan::prepare(&git, target.pin(&git)?, &target.requirements)?;
            emit(out, format, &prepared.plan, |out| {
                text_plan(out, &prepared.plan)
            })?;
        }
        Command::Review {
            target,
            runtime,
            trusted_local,
            run_checks,
            timeout_seconds,
        } => {
            if !trusted_local {
                return Err("Review requires --trusted-local".into());
            }
            harness::install_interrupts()?;
            let prepared = plan::prepare(&git, target.pin(&git)?, &target.requirements)?;
            let mut report = review::run(
                &git,
                prepared,
                &runtime.harness,
                runtime.model.as_deref(),
                Duration::from_secs(timeout_seconds),
                run_checks,
            )?;
            review::save(&git, &mut report)?;
            show_report(out, format, &report)?;
            return Ok(report.exit_code());
        }
        Command::Findings { id, run } => {
            let report = review::load(&git, run.as_deref())?;
            let findings: Vec<_> = report
                .findings
                .iter()
                .filter(|f| id.as_ref().is_none_or(|id| *id == f.id))
                .collect();
            if findings.is_empty() && id.is_some() {
                return Err("No anchored finding with that ID in this review".into());
            }
            if matches!(format, Format::Sarif) {
                write_json(out, &report.sarif(id.as_deref()))?;
            } else {
                emit(
                    out,
                    format,
                    &json!({"kind": "findings", "schema_version": SCHEMA_VERSION, "run_id": report.run_id,
                    "head": report.comparison.head, "status": report.status, "findings": findings}),
                    |out| {
                        writeln!(out, "Review {} ({})", report.run_id, report.status.name())?;
                        if findings.is_empty() {
                            writeln!(out, "No anchored findings.")?;
                        }
                        for finding in findings {
                            text_finding(out, finding)?;
                        }
                        Ok(())
                    },
                )?;
            }
        }
        Command::Rules {
            command: RulesCommand::Explain { path, run },
        } => {
            let report = review::load(&git, run.as_deref())?;
            let path = git.relative_path(&path)?;
            let rule_ids = report
                .effective_rules
                .get(&path)
                .ok_or("Path was not assigned in this review")?;
            let rules: Vec<_> = rule_ids
                .iter()
                .map(|id| {
                    report
                        .rules
                        .iter()
                        .find(|rule| rule.id == *id)
                        .ok_or("Local report is missing an effective rule")
                })
                .collect::<std::result::Result<_, _>>()?;
            emit(
                out,
                format,
                &json!({"kind": "rules", "schema_version": SCHEMA_VERSION, "run_id": report.run_id,
                "trusted_base": report.trusted_base, "path": path, "rules": rules}),
                |out| {
                    writeln!(out, "Rules for {path:?} in {}", report.run_id)?;
                    for rule in rules {
                        writeln!(
                            out,
                            "{} ({:?}, {} bytes)\n{}",
                            rule.id,
                            rule.source,
                            rule.body.len(),
                            rule.body
                        )?;
                    }
                    Ok(())
                },
            )?;
        }
    }
    Ok(0)
}

fn init(git: &Git, format: Format, out: &mut impl Write) -> Result<()> {
    let dir = git.root().join(".revkit");
    match fs::create_dir(&dir) {
        Ok(()) => {}
        Err(err)
            if err.kind() == io::ErrorKind::AlreadyExists
                && fs::symlink_metadata(&dir)?.is_dir() => {}
        Err(err) => return Err(err.into()),
    }
    let mut paths = Vec::new();
    for (path, contents) in [
        (policy::CONFIG_PATH, policy::DEFAULT_CONFIG),
        (
            ".revkit/policy.toml",
            "# Denied paths are never supplied to reviewers or checks.\ndeny = []\n",
        ),
    ] {
        let file = git.root().join(path);
        let status = match fs::symlink_metadata(&file) {
            Ok(meta) if meta.is_file() => "existing",
            Ok(_) => return Err(format!("Refusing to use non-regular setup path {path}").into()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let mut draft = tempfile::NamedTempFile::new_in(&dir)?;
                draft.write_all(contents.as_bytes())?;
                draft.persist_noclobber(file)?;
                "created"
            }
            Err(err) => return Err(err.into()),
        };
        paths.push((path, status));
    }
    emit(
        out,
        format,
        &json!({"kind": "init", "schema_version": SCHEMA_VERSION,
        "files": paths.iter().map(|(path, status)| json!({"path": path,"status": status})).collect::<Vec<_>>(),
        "next": "Commit the setup on the trusted base before reviewing against it"}),
        |out| {
            for (path, status) in paths {
                writeln!(out, "{status}: {path}")?;
            }
            writeln!(
                out,
                "Commit setup on the trusted base before reviewing against it."
            )
        },
    )
}

fn doctor(
    git: &Git,
    runtime: &Runtime,
    base: Option<&str>,
    format: Format,
    out: &mut impl Write,
) -> Result<u8> {
    let pinned = base.map(|rev| git.resolve_commit(rev)).transpose()?;
    let policy = plan::policy_at(git, pinned.as_deref())?;
    let executable = available_executable(&runtime.harness);
    let ready = cfg!(unix) && executable.is_some();
    emit(
        out,
        format,
        &json!({"kind": "doctor", "schema_version": SCHEMA_VERSION, "ready": ready,
        "git_root": git.root(), "trusted_base": pinned, "check_names": policy.checks.keys().collect::<Vec<_>>(),
        "trust_mode": "trusted_local", "confinement": false, "harness": "omp", "executable": executable,
        "requested_model": runtime.model, "profile_checked": false}),
        |out| {
            writeln!(out, "Git worktree: {:?}", git.root())?;
            writeln!(
                out,
                "Trusted policy: {}; {} configured checks",
                pinned
                    .as_deref()
                    .unwrap_or("built-in defaults (pass --base to validate repository policy)"),
                policy.checks.len()
            )?;
            if ready {
                writeln!(out, "Configured OMP executable: {executable:?}")?;
            } else {
                writeln!(
                    out,
                    "Reviewer unavailable: an executable OMP and Unix process supervision are required."
                )?;
            }
            writeln!(
                out,
                "Trusted-local only; no confinement. No sign-in or model checks performed."
            )
        },
    )?;
    Ok(if ready { 0 } else { 6 })
}

fn available_executable(executable: &Path) -> Option<PathBuf> {
    fn runnable(path: &Path) -> bool {
        fs::metadata(path).is_ok_and(|meta| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                meta.is_file() && meta.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                meta.is_file()
            }
        })
    }
    if executable.is_absolute() || executable.components().count() != 1 {
        return runnable(executable).then(|| executable.to_owned());
    }
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(executable))
        .find(|path| runnable(path))
}

fn text_plan(out: &mut dyn Write, plan: &Plan) -> io::Result<()> {
    writeln!(
        out,
        "Comparison: {}..{}",
        plan.comparison.base.as_deref().unwrap_or("(empty tree)"),
        plan.comparison.head
    )?;
    writeln!(
        out,
        "Trusted policy: {}",
        plan.trusted_base.as_deref().unwrap_or("built-in defaults")
    )?;
    writeln!(
        out,
        "Tier: {}; unit: {} selected; admission: {}",
        plan.tier,
        plan.unit.len(),
        plan.admission.status
    )?;
    for reason in &plan.admission.reasons {
        writeln!(out, "  {reason}")?;
    }
    writeln!(
        out,
        "Prompt estimate: {:?} bytes; changed lines: {:?}",
        plan.admission.prompt_bytes, plan.admission.changed_lines
    )?;
    writeln!(
        out,
        "Effective rules: {} ({} bytes)",
        plan.rules.len(),
        plan.rule_bytes
    )?;
    for rule in &plan.rules {
        writeln!(out, "  {} from {:?}", rule.id, rule.source)?;
    }
    for file in &plan.files {
        if let Some(path) = &file.path {
            write!(out, "{path:?}")?;
        } else if let Some(hex) = &file.path_bytes_hex {
            write!(out, "<path bytes: {hex}>")?;
        } else {
            write!(out, "<withheld path>")?;
        }
        match file.scope {
            Selection::Selected => {
                write!(out, "\tselected")?;
                if let Some(ids) = file
                    .path
                    .as_ref()
                    .and_then(|path| plan.effective_rules.get(path))
                    && !ids.is_empty()
                {
                    write!(out, " ({})", ids.join(", "))?;
                }
                writeln!(out)?;
            }
            Selection::Excluded { reason } => writeln!(out, "\texcluded: {reason}")?,
            Selection::ContextOnly { reason } => writeln!(out, "\tcontext only: {reason}")?,
        }
    }
    for check in &plan.checks {
        writeln!(out, "Planned check: {} (requires --run-checks)", check.name)?;
    }
    Ok(())
}

fn show_report(out: &mut impl Write, format: Format, report: &Report) -> Result<()> {
    if matches!(format, Format::Sarif) {
        return write_json(out, &report.sarif(None));
    }
    emit(out, format, report, |out| {
        writeln!(
            out,
            "Review {}: {} (exit {})",
            report.run_id,
            report.status.name(),
            report.exit_code()
        )?;
        writeln!(
            out,
            "Trust: trusted-local; no confinement. Head: {}",
            report.comparison.head
        )?;
        for (path, status) in &report.coverage {
            writeln!(out, "  {path:?}: {status}")?;
        }
        for reason in &report.reasons {
            writeln!(out, "  {reason:?}")?;
        }
        for check in &report.checks {
            writeln!(out, "Check {}: {}", check.name, check.status)?;
        }
        for finding in &report.findings {
            text_finding(out, finding)?;
        }
        for lead in &report.leads {
            writeln!(out, "Unanchored lead {:?}: {:?}", lead.path, lead.note)?;
        }
        if let Some(entries) = report.exclusions.as_array() {
            for entry in entries {
                let path = entry["path"]
                    .as_str()
                    .or_else(|| entry["path_bytes_hex"].as_str())
                    .unwrap_or("<withheld path>");
                let reason = entry["scope"]["reason"].as_str().unwrap_or("unspecified");
                writeln!(out, "  Not assigned {path:?}: {reason}")?;
            }
        }
        Ok(())
    })
}

fn text_finding(out: &mut dyn Write, finding: &review::Finding) -> io::Result<()> {
    writeln!(
        out,
        "{} {:?}:{} ({}) {} {:?}",
        finding.severity.name(),
        finding.path,
        finding.line,
        finding.side.name(),
        finding.id,
        finding.note
    )
}

fn emit(
    out: &mut impl Write,
    format: Format,
    value: &impl Serialize,
    text: impl FnOnce(&mut dyn Write) -> io::Result<()>,
) -> Result<()> {
    match format {
        Format::Text => Ok(text(out)?),
        Format::Json => write_json(out, value),
        Format::Sarif => Err("Unsupported output format".into()),
    }
}

fn write_json(out: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *out, value)?;
    writeln!(out)?;
    Ok(())
}

fn error(out: &mut impl Write, format: Format, code: &str, message: &str) -> ExitCode {
    match format {
        Format::Text => eprintln!("{message}"),
        _ => {
            if write_json(
                out,
                &json!({"kind": "error", "schema_version": SCHEMA_VERSION,
                "error": {"code": code, "message": message}}),
            )
            .is_err()
            {
                eprintln!("Cannot write result");
            }
        }
    }
    ExitCode::FAILURE
}

fn requested_format(args: &[OsString]) -> Format {
    let mut args = args.iter().skip(1);
    while let Some(arg) = args.next().and_then(|arg| arg.to_str()) {
        let value = match arg {
            "--" => break,
            "--format" => args.next().and_then(|arg| arg.to_str()),
            arg => arg.strip_prefix("--format="),
        };
        match value {
            Some("json") => return Format::Json,
            Some("sarif") => return Format::Sarif,
            _ => {}
        }
    }
    Format::Text
}

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().collect();
    let requested = requested_format(&args);
    let mut out = io::stdout().lock();
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) if err.exit_code() == 0 => {
            if matches!(requested, Format::Json) {
                return match write_json(
                    &mut out,
                    &json!({"kind": "help", "schema_version": SCHEMA_VERSION, "text": err.to_string()}),
                ) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(_) => ExitCode::FAILURE,
                };
            }
            err.exit();
        }
        Err(err) => return error(&mut out, requested, "invalid_arguments", &err.to_string()),
    };
    let format = cli.format;
    match run(cli, &mut out) {
        Ok(code) => ExitCode::from(code),
        Err(err) => error(&mut out, format, "request_failed", &err.to_string()),
    }
}
