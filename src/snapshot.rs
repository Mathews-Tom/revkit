use std::error::Error;
use std::fmt::Write;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::str;

use serde::{Deserialize, Serialize};

type Result<T, E = Box<dyn Error>> = std::result::Result<T, E>;

// Local preview ceiling. It also bounds the amount read to classify a blob.
const MAX_BLOB_BYTES: u64 = 1_048_576;
const MAX_CLASSIFICATION_BYTES: u64 = 64 * MAX_BLOB_BYTES;

#[derive(Deserialize, Serialize)]
pub(crate) struct Comparison {
    pub(crate) requested_base: Option<String>,
    pub(crate) base: Option<String>,
    pub(crate) head: String,
}

#[derive(Serialize)]
pub(crate) struct File {
    pub(crate) path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) old_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) path_bytes_hex: Option<String>,
    pub(crate) change: &'static str,
    pub(crate) scope: Selection,
    pub(crate) old_mode: String,
    pub(crate) new_mode: String,
    pub(crate) old_blob: Option<String>,
    pub(crate) new_blob: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum Selection {
    Selected,
    Excluded { reason: &'static str },
    ContextOnly { reason: &'static str },
}

pub(crate) struct Git {
    cwd: PathBuf,
    prefix: String,
}

impl Git {
    pub(crate) fn current() -> Result<Self> {
        let mut git = Self {
            cwd: std::env::current_dir()?,
            prefix: String::new(),
        };
        if git.text(&["rev-parse", "--is-inside-work-tree"])? != "true\n" {
            return Err("Run revkit in a Git worktree".into());
        }
        git.prefix = git.text(&["rev-parse", "--show-prefix"])?;
        let root = git.text(&["rev-parse", "--show-toplevel"])?;
        git.cwd = PathBuf::from(root.strip_suffix('\n').ok_or("Missing Git root")?);
        Ok(git)
    }

    fn bytes(&self, args: &[&str]) -> Result<Vec<u8>> {
        self.limited(args, 4 * MAX_BLOB_BYTES)
    }

    fn limited(&self, args: &[&str], limit: u64) -> Result<Vec<u8>> {
        let mut child = Command::new("git")
            .args([
                "--no-replace-objects",
                "--no-lazy-fetch",
                "--no-optional-locks",
                "--literal-pathspecs",
            ])
            .args(args)
            .current_dir(&self.cwd)
            .env("GIT_ATTR_NOSYSTEM", "1")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut bytes = Vec::new();
        let read = child
            .stdout
            .take()
            .expect("piped stdout")
            .take(limit + 1)
            .read_to_end(&mut bytes);
        if read.is_err() || bytes.len() as u64 > limit {
            let _ = child.kill();
        }
        let status = child.wait()?;
        read?;
        if bytes.len() as u64 > limit {
            return Err(format!("git {} output exceeds the local input limit", args[0]).into());
        }
        if !status.success() {
            return Err(format!("git {} failed ({status})", args[0]).into());
        }
        Ok(bytes)
    }

    fn text(&self, args: &[&str]) -> Result<String> {
        Ok(String::from_utf8(self.bytes(args)?)?)
    }

    fn commit(&self, rev: &str) -> Result<String> {
        if rev.is_empty() {
            return Err("An empty revision is not a commit selector".into());
        }
        let object = format!("{rev}^{{commit}}");
        let oid = self.text(&["rev-parse", "--verify", "--end-of-options", &object])?;
        let oid = oid.trim_end();
        if !valid_oid(oid) {
            return Err("Git returned an invalid commit ID".into());
        }
        Ok(oid.to_owned())
    }

    pub(crate) fn resolve_commit(&self, rev: &str) -> Result<String> {
        self.commit(rev)
    }

    pub(crate) fn range(&self, base: &str, head: &str) -> Result<Comparison> {
        let requested_base = self.commit(base)?;
        let head = self.commit(head)?;
        if requested_base != head
            && self.text(&["rev-parse", "--is-shallow-repository"])? == "true\n"
        {
            return Err(
                "Cannot resolve a range reliably in a shallow checkout; fetch full history".into(),
            );
        }
        let bases = self.text(&["merge-base", "--all", &requested_base, &head])?;
        let mut bases = bases.lines();
        let merge_base = bases
            .next()
            .filter(|s| valid_oid(s))
            .ok_or("No valid merge base")?;
        if bases.next().is_some() {
            return Err("Multiple merge bases; use --commit for an unambiguous comparison".into());
        }
        Ok(Comparison {
            base: Some(merge_base.to_owned()),
            requested_base: Some(requested_base),
            head,
        })
    }

    pub(crate) fn single(&self, head: &str) -> Result<Comparison> {
        let head = self.commit(head)?;
        // rev-list hides parents at a shallow boundary; the commit header does not.
        let raw = self.bytes(&["cat-file", "commit", &head])?;
        let parent = raw
            .split(|&byte| byte == b'\n')
            .take_while(|line| !line.is_empty())
            .find_map(|line| line.strip_prefix(b"parent "));
        let base = if let Some(parent) = parent {
            let parent = str::from_utf8(parent)?;
            if !valid_oid(parent) {
                return Err("The first parent ID is invalid".into());
            }
            Some(self.commit(parent).map_err(|err| {
                format!("First parent unavailable; fetch required Git history: {err}")
            })?)
        } else {
            None
        };
        Ok(Comparison {
            requested_base: None,
            base,
            head,
        })
    }

    pub(crate) fn files(
        &self,
        comparison: &Comparison,
        policy: &crate::policy::Policy,
    ) -> Result<Vec<File>> {
        let mut args = vec![
            "diff-tree",
            "-r",
            "--root",
            "--raw",
            "-z",
            "--no-commit-id",
            "--find-renames",
            "-l256",
            "--no-abbrev",
            "--ignore-submodules=none",
        ];
        if let Some(base) = &comparison.base {
            args.push(base);
        }
        args.extend([&comparison.head, "--"]);
        let raw = self.bytes(&args)?;
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        let raw = raw.strip_suffix(b"\0").ok_or("Unterminated Git diff")?;
        if raw.split(|&b| b == 0).count() > 512 {
            return Err("Comparison exceeds the path inventory limit".into());
        }
        let mut records = raw.split(|&b| b == 0);
        let mut files = Vec::new();
        let mut remaining = MAX_CLASSIFICATION_BYTES;
        while let Some(header) = records.next() {
            let delta = Delta::parse(str::from_utf8(header)?)?;
            let first = next_path(&mut records)?;
            let (old, path) = if delta.change == "renamed" {
                (Some(first), next_path(&mut records)?)
            } else {
                (None, first)
            };
            let old_path = old.map(str::from_utf8).transpose();
            let (path, path_bytes_hex, scope) = match (str::from_utf8(path), old_path) {
                (Ok(path), Ok(old)) => {
                    let sides = [Some(path), old];
                    if sides.iter().flatten().any(|path| secret_path(path)) {
                        (None, None, excluded("secret_path"))
                    } else if sides.iter().flatten().any(|path| policy.protected(path)) {
                        (None, None, excluded("denied_path"))
                    } else if let Some(reason) = old.and_then(|old| policy.scope(old)) {
                        (Some(path.to_owned()), None, excluded(reason))
                    } else {
                        (
                            Some(path.to_owned()),
                            None,
                            self.scope(&delta, path, policy, &mut remaining)?,
                        )
                    }
                }
                _ if old.is_some() => (None, None, excluded("unsupported_path_encoding")),
                _ => {
                    let display = String::from_utf8_lossy(path);
                    if secret_path(&display) || policy.protected(&display) {
                        (None, None, excluded("denied_path"))
                    } else {
                        let mut hex = String::with_capacity(path.len() * 2);
                        for byte in path {
                            write!(hex, "{byte:02x}")?;
                        }
                        (None, Some(hex), excluded("unsupported_path_encoding"))
                    }
                }
            };
            let disclosable = !matches!(scope, Selection::Excluded { .. });
            files.push(File {
                path,
                old_path: if disclosable {
                    old_path?.map(str::to_owned)
                } else {
                    None
                },
                path_bytes_hex,
                change: delta.change,
                scope,
                old_mode: delta.sides[0].0.to_owned(),
                new_mode: delta.sides[1].0.to_owned(),
                old_blob: if disclosable { delta.blob(0) } else { None },
                new_blob: if disclosable { delta.blob(1) } else { None },
            });
        }
        Ok(files)
    }

    fn scope(
        &self,
        delta: &Delta<'_>,
        path: &str,
        policy: &crate::policy::Policy,
        remaining: &mut u64,
    ) -> Result<Selection> {
        if !safe_path(path) {
            return Ok(excluded("unsupported_path"));
        }
        if let Some(reason) = policy.scope(path) {
            return Ok(excluded(reason));
        }
        // Check both modes before reading either object. A type change must not
        // disclose the old symlink target or enter a gitlink's repository.
        if delta
            .sides
            .iter()
            .any(|(mode, _)| !matches!(*mode, "000000" | "100644" | "100755"))
        {
            return Ok(excluded("unsupported_object"));
        }
        let mut previous = None;
        for (mode, oid) in delta.sides {
            if mode == "000000" || previous == Some(oid) {
                continue;
            }
            previous = Some(oid);
            let size: u64 = self.text(&["cat-file", "-s", oid])?.trim_end().parse()?;
            if size > MAX_BLOB_BYTES {
                return Ok(excluded("too_large"));
            }
            if size > *remaining {
                return Ok(excluded("classification_limit"));
            }
            *remaining -= size;
            let bytes = self.limited(&["cat-file", "blob", oid], size)?;
            if bytes.contains(&0) {
                return Ok(excluded("binary"));
            }
            if str::from_utf8(&bytes).is_err() {
                return Ok(excluded("unsupported_encoding"));
            }
        }
        if delta.change == "deleted" {
            return Ok(Selection::ContextOnly { reason: "deleted" });
        }
        Ok(Selection::Selected)
    }

    pub(crate) fn root(&self) -> &Path {
        &self.cwd
    }

    pub(crate) fn git_dir(&self) -> Result<PathBuf> {
        let path = self.text(&["rev-parse", "--absolute-git-dir"])?;
        Ok(PathBuf::from(
            path.strip_suffix('\n').ok_or("Missing Git directory")?,
        ))
    }

    pub(crate) fn relative_path(&self, path: &str) -> Result<String> {
        let prefix = self.prefix.strip_suffix('\n').ok_or("Missing Git prefix")?;
        if !safe_path(path) {
            return Err("Use a repository-relative file path without '..'".into());
        }
        Ok(format!("{prefix}{path}"))
    }

    pub(crate) fn patch(&self, file: &File) -> Result<String> {
        // Diff the pinned blobs, never pathspecs: even a literal pathspec
        // matches descendants when a file turns into a directory.
        match (&file.old_blob, &file.new_blob) {
            (Some(old), Some(new)) if old != new => {
                let patch = self.bytes(&[
                    "-c",
                    "diff.algorithm=myers",
                    "diff",
                    "--no-color",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-indent-heuristic",
                    "--text",
                    "--unified=3",
                    old,
                    new,
                    "--",
                ])?;
                Ok(String::from_utf8(patch)?)
            }
            (Some(oid), None) => self.whole_file_patch(oid, false),
            (None, Some(oid)) => self.whole_file_patch(oid, true),
            _ => Ok(String::new()),
        }
    }

    fn whole_file_patch(&self, oid: &str, added: bool) -> Result<String> {
        let source = self.blob_text(oid)?;
        let lines = source.split_inclusive('\n');
        let count = lines.clone().count();
        if count == 0 {
            return Ok(String::new());
        }
        let mut patch = String::with_capacity(source.len() + count + 64);
        let prefix = if added {
            writeln!(patch, "@@ -0,0 +1,{count} @@")?;
            '+'
        } else {
            writeln!(patch, "@@ -1,{count} +0,0 @@")?;
            '-'
        };
        for line in lines {
            patch.push(prefix);
            patch.push_str(line);
        }
        if !source.ends_with('\n') {
            patch.push_str("\n\\ No newline at end of file\n");
        }
        Ok(patch)
    }

    pub(crate) fn blob_text(&self, oid: &str) -> Result<String> {
        if !valid_oid(oid) {
            return Err("Invalid blob ID".into());
        }
        Ok(String::from_utf8(
            self.limited(&["cat-file", "blob", oid], MAX_BLOB_BYTES)?,
        )?)
    }

    fn tree(&self, commit: &str, path: Option<&str>) -> Result<Vec<TreeEntry>> {
        if !valid_oid(commit) {
            return Err("Invalid tree commit".into());
        }
        let mut args = vec!["ls-tree", "-r", "-z", "--full-tree", commit, "--"];
        args.extend(path);
        let bytes = self.bytes(&args)?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        bytes
            .strip_suffix(b"\0")
            .ok_or("Unterminated Git tree")?
            .split(|b| *b == 0)
            .map(TreeEntry::parse)
            .collect()
    }

    pub(crate) fn policy_text(&self, commit: &str, path: &str) -> Result<Option<String>> {
        let entries = self.tree(commit, Some(path))?;
        let Some(entry) = entries.iter().find(|entry| entry.path == path.as_bytes()) else {
            if !entries.is_empty() {
                return Err(format!("Trusted policy path {path} must be a regular file").into());
            }
            return Ok(None);
        };
        Ok(Some(self.small_policy_blob(entry)?))
    }

    pub(crate) fn policy_rules(&self, commit: &str) -> Result<Vec<(String, String)>> {
        let files = self.tree(commit, Some(".revkit/rules"))?;
        if files.len() > 64 {
            return Err("Trusted rule tree exceeds the file limit".into());
        }
        let mut total = 0;
        let mut rules = Vec::new();
        for entry in files {
            let path = str::from_utf8(&entry.path)?;
            if path == ".revkit/rules" {
                return Err(".revkit/rules must be a tree, not a file or link".into());
            }
            if !path.ends_with(".md") {
                continue;
            }
            let body = self.small_policy_blob(&entry)?;
            total += body.len();
            if total > 32 * 1024 {
                return Err("Trusted rule tree exceeds the byte limit".into());
            }
            rules.push((path.to_owned(), body));
        }
        Ok(rules)
    }

    fn small_policy_blob(&self, entry: &TreeEntry) -> Result<String> {
        if !entry.regular() {
            return Err("Trusted rule or policy source is not a regular blob".into());
        }
        let text = String::from_utf8(self.limited(&["cat-file", "blob", &entry.oid], 32 * 1024)?)?;
        if text.contains('\0') {
            return Err("Trusted policy source is not text".into());
        }
        Ok(text)
    }

    #[cfg(unix)]
    pub(crate) fn materialize_checks(
        &self,
        head: &str,
        root: &Path,
        policy: &crate::policy::Policy,
    ) -> Result<()> {
        use std::fs::{self, OpenOptions};
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;

        const MAX_TREE: u64 = 32 * 1024 * 1024;
        let entries = self.tree(head, None)?;
        if entries.len() > 2_000 {
            return Err("Exact check snapshot exceeds the file limit".into());
        }
        let mut remaining = MAX_TREE;
        for entry in entries {
            let path = str::from_utf8(&entry.path)?;
            if !entry.regular() || !safe_path(path) || secret_path(path) || policy.protected(path) {
                return Err(
                    "Exact check snapshot contains a protected or unsupported entry".into(),
                );
            }
            let bytes = self.limited(&["cat-file", "blob", &entry.oid], remaining)?;
            remaining -= bytes.len() as u64;
            let path = root.join(path);
            fs::create_dir_all(path.parent().ok_or("Missing check snapshot parent")?)?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(if entry.mode == "100755" { 0o755 } else { 0o644 })
                .open(path)?
                .write_all(&bytes)?;
        }
        Ok(())
    }
}

struct Delta<'a> {
    sides: [(&'a str, &'a str); 2],
    change: &'static str,
}

impl<'a> Delta<'a> {
    fn parse(header: &'a str) -> Result<Self> {
        let header = header
            .strip_prefix(':')
            .ok_or("Invalid raw Git diff header")?;
        let mut fields = header.split_ascii_whitespace();
        let (Some(old_mode), Some(new_mode), Some(old), Some(new), Some(status), None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err("Incomplete raw Git diff header".into());
        };
        if !valid_oid(old) || !valid_oid(new) {
            return Err("Invalid Git diff object ID".into());
        }
        let change = match status {
            "A" => "added",
            "M" => "modified",
            "D" => "deleted",
            "T" => "type_changed",
            rename
                if rename
                    .strip_prefix('R')
                    .is_some_and(|score| score.parse::<u8>().is_ok_and(|score| score <= 100)) =>
            {
                "renamed"
            }
            _ => return Err(format!("Unsupported Git diff status {status:?}").into()),
        };
        Ok(Self {
            sides: [(old_mode, old), (new_mode, new)],
            change,
        })
    }
}

fn next_path<'a>(records: &mut impl Iterator<Item = &'a [u8]>) -> Result<&'a [u8]> {
    records
        .next()
        .filter(|path| !path.is_empty())
        .ok_or_else(|| "Missing Git diff path".into())
}

impl Delta<'_> {
    fn blob(&self, side: usize) -> Option<String> {
        let (mode, oid) = self.sides[side];
        (mode != "000000").then(|| oid.to_owned())
    }
}

struct TreeEntry {
    mode: String,
    kind: String,
    oid: String,
    path: Vec<u8>,
}

impl TreeEntry {
    fn parse(record: &[u8]) -> Result<Self> {
        let offset = record
            .iter()
            .position(|b| *b == b'\t')
            .ok_or("Invalid Git tree record")?;
        let (header, path) = record.split_at(offset);
        let mut fields = str::from_utf8(header)?.split_ascii_whitespace();
        match (fields.next(), fields.next(), fields.next(), fields.next()) {
            (Some(mode), Some(kind), Some(oid), None) if valid_oid(oid) => Ok(Self {
                mode: mode.to_owned(),
                kind: kind.to_owned(),
                oid: oid.to_owned(),
                path: path[1..].to_vec(),
            }),
            _ => Err("Invalid Git tree record header".into()),
        }
    }

    fn regular(&self) -> bool {
        self.kind == "blob" && matches!(self.mode.as_str(), "100644" | "100755")
    }
}

fn safe_path(path: &str) -> bool {
    path.split('/').all(|part| {
        !part.eq_ignore_ascii_case(".git")
            && matches!(
                Path::new(part).components().next(),
                Some(Component::Normal(_))
            )
            && !part.contains(['\\', ':'])
    })
}

fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn excluded(reason: &'static str) -> Selection {
    Selection::Excluded { reason }
}

fn secret_path(path: &str) -> bool {
    path.split('/').any(|component| {
        let name = component.as_bytes();
        [
            ".env",
            ".netrc",
            ".npmrc",
            ".pypirc",
            "credentials.json",
            "id_rsa",
            "id_ed25519",
        ]
        .iter()
        .any(|entry| name.eq_ignore_ascii_case(entry.as_bytes()))
            || name
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b".env."))
            || name.last_chunk::<4>().is_some_and(|suffix| {
                [b".pem", b".key", b".pfx", b".p12"]
                    .iter()
                    .any(|entry| suffix.eq_ignore_ascii_case(*entry))
            })
    })
}
