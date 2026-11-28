//! Local review-attempt accounting. No network, credentials or raw review material.
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::Result;
use crate::review::Report;
use crate::snapshot::Git;

const MAX_ROWS: usize = 1_000;
const RETENTION_DAYS: u64 = 90;
const MAX_RECORD_BYTES: u64 = 16 * 1024;
const REPO_STORE: &str = ".revkit/metrics";

#[derive(Clone, Copy, Default, ValueEnum)]
pub(crate) enum Location {
    #[default]
    Global,
    Repository,
}

#[derive(Args)]
pub(crate) struct Options {
    /// Disable local metrics for this review.
    #[arg(long)]
    pub(crate) no_metrics: bool,
    /// Select the single local metrics store.
    #[arg(long, value_enum, default_value = "global")]
    pub(crate) metrics_store: Location,
    /// Explicitly known, fully qualified PR identity (stored only as a keyed digest).
    #[arg(long, value_parser = parse_pr_id)]
    pub(crate) pr_id: Option<String>,
    /// Operator-known harness version; no extra executable invocation is made.
    #[arg(long)]
    pub(crate) harness_version: Option<String>,
}

fn parse_pr_id(identity: &str) -> std::result::Result<String, &'static str> {
    if identity.trim().is_empty() || identity.len() > 1024 || identity.chars().any(char::is_control)
    {
        return Err(
            "PR identity must be nonempty, at most 1024 bytes and contain no control characters",
        );
    }
    Ok(identity.to_owned())
}

#[derive(Default, Deserialize)]
struct Settings {
    metrics: Option<MetricsSettings>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricsSettings {
    enabled: Option<bool>,
}

fn global_home() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err("HOME must be an absolute path for local metrics".into());
    }
    Ok(home.join(".revkit"))
}

fn from_settings(dir: &Path) -> Result<bool> {
    // Settings can only opt out; reading them doesn't require write ownership.
    check_parent(dir, false)?;
    let path = dir.join("settings.toml");
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_file() => {
            let mut text = String::new();
            nofollow(&path)?
                .take(MAX_RECORD_BYTES + 1)
                .read_to_string(&mut text)?;
            if text.len() as u64 > MAX_RECORD_BYTES {
                return Err("Metrics settings exceeds local input limit".into());
            }
            let settings: Settings = toml::from_str(&text)?;
            Ok(settings.metrics.and_then(|m| m.enabled) != Some(false))
        }
        Ok(_) => Err("Metrics settings must be a regular file".into()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(err) => Err(err.into()),
    }
}

fn directory(location: Location, git: Option<&Git>) -> Result<PathBuf> {
    match location {
        Location::Global => Ok(global_home()?.join("metrics")),
        Location::Repository => {
            let git = git.ok_or("Repository metrics require a Git worktree")?;
            git.require_ignored_untracked(REPO_STORE)?;
            Ok(git.root().join(REPO_STORE))
        }
    }
}

fn day() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 86_400)
}

fn label(value: Option<&str>) -> Option<String> {
    value
        .filter(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
        .map(str::to_owned)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    schema_version: u8,
    utc_day: u64,
    adapter: String,
    adapter_version: String,
    harness: Option<String>,
    harness_version: Option<String>,
    selected_provider: Option<String>,
    selected_model: Option<String>,
    observed_provider: Option<String>,
    observed_model: Option<String>,
    outcome: String,
    exit_code: u8,
    assigned_paths: Option<usize>,
    settled_paths: Option<usize>,
    elapsed_ms: u128,
    anchored_by_severity: Option<[usize; 4]>,
    usage: Option<BTreeMap<String, u64>>,
    // OMP counters are not an invoice; no price or billed-cost data is inferred.
    reported_cost: Option<Value>,
    estimated_cost: Option<Value>,
    pr_digest: Option<String>,
}

fn attempt(
    options: &Options,
    exit_code: u8,
    selected_model: Option<&str>,
    report: Option<&Report>,
    elapsed_ms: u128,
) -> Result<Attempt> {
    let selected_model = label(selected_model);
    let selected_provider = selected_model
        .as_deref()
        .and_then(|s| s.split_once('/'))
        .and_then(|(provider, _)| label(Some(provider)));
    let severity = report.map(|report| {
        let mut counts = [0; 4];
        for finding in &report.findings {
            counts[finding.severity as usize] += 1;
        }
        counts
    });
    let usage = report
        .and_then(|r| r.usage.as_ref())
        .and_then(Value::as_object)
        .map(|fields| {
            fields
                .iter()
                .filter_map(|(name, n)| n.as_u64().map(|n| (name.clone(), n)))
                .collect::<BTreeMap<_, _>>()
        })
        .filter(|fields| !fields.is_empty());
    Ok(Attempt {
        schema_version: 1,
        utc_day: day()?,
        adapter: "omp".into(),
        adapter_version: env!("CARGO_PKG_VERSION").into(),
        harness: Some("omp".into()),
        harness_version: label(options.harness_version.as_deref()),
        selected_provider,
        selected_model,
        observed_provider: report.and_then(|r| label(r.provider.as_deref())),
        observed_model: report.and_then(|r| label(r.model.as_deref())),
        outcome: report
            .map_or("local_error", |r| {
                if r.no_changes {
                    "no_changes"
                } else {
                    r.status.name()
                }
            })
            .into(),
        exit_code,
        assigned_paths: report.map(|r| r.coverage.len()),
        settled_paths: report.map(|r| {
            r.coverage
                .values()
                .filter(|s| matches!(s.as_str(), "settled_with_findings" | "settled_no_findings"))
                .count()
        }),
        elapsed_ms,
        anchored_by_severity: severity,
        usage,
        reported_cost: None,
        estimated_cost: None,
        pr_digest: None,
    })
}

pub(crate) fn record(
    git: &Git,
    options: &Options,
    model: Option<&str>,
    report: Option<&Report>,
    elapsed_ms: u128,
    exit_code: u8,
) -> Result<()> {
    if options.no_metrics
        || !from_settings(&global_home()?)?
        || !from_settings(&git.root().join(".revkit"))?
    {
        return Ok(());
    }
    let mut attempt = attempt(options, exit_code, model, report, elapsed_ms)?;
    let dir = directory(options.metrics_store, Some(git))?;
    let store = Store::open(dir, true)?.ok_or("Metrics store was not created")?;
    if let Some(identity) = &options.pr_id {
        attempt.pr_digest = Some(keyed_digest(&store.key()?, identity.as_bytes()));
    }
    let mut records = store.entries()?;
    records.sort_unstable_by(|a, b| (a.1.utc_day, &a.0).cmp(&(b.1.utc_day, &b.0)));
    let retained_start = records
        .partition_point(|(_, a)| a.utc_day.saturating_add(RETENTION_DAYS) <= attempt.utc_day);
    let remove = retained_start.max(records.len().saturating_sub(MAX_ROWS - 1));
    for (path, _) in records.into_iter().take(remove) {
        fs::remove_file(path)?;
    }
    let mut file = tempfile::Builder::new()
        .prefix("attempt-")
        .rand_bytes(16)
        .tempfile_in(&store.dir)?;
    let name = file
        .path()
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Invalid metrics record name")?;
    let target = store.dir.join(format!("{name}.json"));
    serde_json::to_writer(&mut file, &attempt)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(target)?;
    Ok(())
}

fn keyed_digest(key: &[u8; 32], message: &[u8]) -> String {
    // HMAC-SHA256 with a store-local 256-bit random key and a domain tag.
    let mut inner = [0x36; 64];
    let mut outer = [0x5c; 64];
    for (i, byte) in key.iter().enumerate() {
        inner[i] ^= byte;
        outer[i] ^= byte;
    }
    let mut hash = Sha256::new();
    hash.update(inner);
    hash.update(b"revkit-pr-v1\0");
    hash.update(message);
    let mut mac = Sha256::new();
    mac.update(outer);
    mac.update(hash.finalize());
    format!("{:x}", mac.finalize())
}

fn owner_private(meta: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no memory or input requirements.
        meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        false
    }
}

fn check_parent(dir: &Path, for_write: bool) -> Result<bool> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                // SAFETY: geteuid has no arguments or memory requirements.
                if for_write
                    && (meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0)
                {
                    return Err("Metrics parent must be owner-controlled".into());
                }
            }
            Ok(true)
        }
        Ok(_) => Err("Refusing a non-directory or symlink metrics parent".into()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn create_directory(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    match builder.create(dir) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists && check_parent(dir, true)? => {
            Ok(())
        }
        Err(err) => Err(err.into()),
    }
}

fn nofollow(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    opts.open(path)
}

fn private_file(path: &Path) -> Result<fs::File> {
    let file = nofollow(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || !owner_private(&meta) {
        return Err("Metrics file must be regular and owner-only".into());
    }
    Ok(file)
}

struct Store {
    dir: PathBuf,
    _lock: fs::File,
}

impl Store {
    fn open(dir: PathBuf, create: bool) -> Result<Option<Self>> {
        let parent = dir.parent().ok_or("Metrics path has no parent")?;
        if !check_parent(parent, true)? {
            if !create {
                return Ok(None);
            }
            create_directory(parent)?;
        }
        if !check_parent(&dir, true)? {
            if !create {
                return Ok(None);
            }
            create_directory(&dir)?;
        }
        if !owner_private(&fs::symlink_metadata(&dir)?) {
            return Err("Metrics directory must be owner-only".into());
        }
        let mut opts = fs::OpenOptions::new();
        opts.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let lock = opts.open(dir.join("lock"))?;
        let metadata = lock.metadata()?;
        if !metadata.is_file() || !owner_private(&metadata) {
            return Err("Metrics lock must be a regular owner-only file".into());
        }
        lock.lock()?;
        Ok(Some(Self { dir, _lock: lock }))
    }

    fn key(&self) -> Result<[u8; 32]> {
        let path = self.dir.join("pr-key");
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let mut file = private_file(&path)?;
                let mut key = [0; 32];
                file.read_exact(&mut key)?;
                if file.read(&mut [0])? != 0 {
                    return Err("Invalid metrics PR key".into());
                }
                Ok(key)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let mut key = [0; 32];
                fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
                let mut temp = tempfile::NamedTempFile::new_in(&self.dir)?;
                temp.write_all(&key)?;
                temp.as_file().sync_all()?;
                temp.persist_noclobber(path)?;
                Ok(key)
            }
            Err(err) => Err(err.into()),
        }
    }

    fn record_paths(&self) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            if entry.file_name().to_str().is_some_and(|name| {
                name.strip_prefix("attempt-")
                    .and_then(|name| name.strip_suffix(".json"))
                    .is_some_and(|id| {
                        id.len() == 16 && id.bytes().all(|b| b.is_ascii_alphanumeric())
                    })
            }) {
                // Never follow or remove a foreign file or symlink from this directory.
                private_file(&entry.path())?;
                paths.push(entry.path());
            }
        }
        Ok(paths)
    }

    fn entries(&self) -> Result<Vec<(PathBuf, Attempt)>> {
        self.record_paths()?
            .into_iter()
            .map(|path| {
                let file = private_file(&path)?;
                let mut data = Vec::new();
                file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut data)?;
                if data.len() as u64 > MAX_RECORD_BYTES {
                    return Err("Metrics record exceeds local limit".into());
                }
                let attempt: Attempt = serde_json::from_slice(&data)?;
                if attempt.schema_version != 1 {
                    return Err("Unknown metrics record schema".into());
                }
                Ok((path, attempt))
            })
            .collect()
    }
}

// JSON numeric values in the current serializer cannot hold counters above u64.
// Preserve such sums exactly as decimal strings rather than panic or truncate.
fn json_counter(value: u128) -> Value {
    u64::try_from(value).map_or_else(|_| Value::String(value.to_string()), Value::from)
}

pub(crate) fn show(location: Location, git: Option<&Git>) -> Result<Value> {
    let store = Store::open(directory(location, git)?, false)?;
    let records = if let Some(store) = store {
        store.entries()?
    } else {
        Vec::new()
    };
    let today = day()?;
    let records: Vec<_> = records
        .into_iter()
        .filter(|(_, a)| a.utc_day.saturating_add(RETENTION_DAYS) > today)
        .map(|(_, a)| a)
        .collect();
    let mut pr_ids = BTreeSet::new();
    let mut outcomes = BTreeMap::<String, usize>::new();
    let mut usage = BTreeMap::<String, (u128, usize)>::new();
    let mut unattributed = 0;
    let mut known_coverage = 0;
    let mut assigned = 0;
    let mut settled = 0;
    let mut severity = [0; 4];
    let mut elapsed_ms = 0u128;
    for row in &records {
        if let Some(id) = &row.pr_digest {
            pr_ids.insert(id);
        } else {
            unattributed += 1;
        }
        *outcomes.entry(row.outcome.clone()).or_default() += 1;
        elapsed_ms = elapsed_ms.saturating_add(row.elapsed_ms);
        if let (Some(a), Some(s)) = (row.assigned_paths, row.settled_paths) {
            known_coverage += 1;
            assigned += a;
            settled += s;
        }
        if let Some(counts) = row.anchored_by_severity {
            for (total, count) in severity.iter_mut().zip(counts) {
                *total += count;
            }
        }
        if let Some(fields) = &row.usage {
            for (key, count) in fields {
                let (sum, reported) = usage.entry(key.clone()).or_default();
                *sum += u128::from(*count);
                *reported += 1;
            }
        }
    }
    let usage = usage.into_iter().map(|(key, (sum, reported))| (key, json!({"reported_sum":json_counter(sum),"reported_attempts":reported,"unknown_attempts":records.len()-reported}))).collect::<BTreeMap<_,_>>();
    Ok(json!({
        "kind": "metrics",
        "schema_version": 1,
        "attempts": records.len(),
        "distinct_attributed_prs": pr_ids.len(),
        "unattributed_attempts": unattributed,
        "outcomes": outcomes,
        "wall_ms_sum": json_counter(elapsed_ms),
        "coverage": {
            "assigned_paths": assigned, "settled_paths": settled,
            "known_attempts": known_coverage, "unknown_attempts": records.len() - known_coverage
        },
        "anchored_by_severity": {"P0": severity[0], "P1": severity[1], "P2": severity[2], "P3": severity[3]},
        "usage": usage,
        "reported_cost": null,
        "estimated_cost": null,
        "retention_days": RETENTION_DAYS,
        "max_records": MAX_ROWS
    }))
}

pub(crate) fn clear(location: Location, git: Option<&Git>) -> Result<Value> {
    let Some(store) = Store::open(directory(location, git)?, false)? else {
        return Ok(json!({"kind":"metrics_clear","schema_version":1,"removed_attempts":0}));
    };
    let records = store.record_paths()?;
    for path in &records {
        fs::remove_file(path)?;
    }
    let key = store.dir.join("pr-key");
    match fs::symlink_metadata(&key) {
        Ok(_) => {
            private_file(&key)?;
            fs::remove_file(key)?;
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    Ok(json!({"kind":"metrics_clear","schema_version":1,"removed_attempts":records.len()}))
}
