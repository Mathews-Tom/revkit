//! Policy is parsed exclusively from caller-pinned text; this module performs no I/O.
//!
//! Config: `version = 1`, `[scope]` string arrays `deny`, `exclude`, `include`,
//! `generated`; `[tiers]` string arrays `high`, `low`; `[checks]` string values.
//! Generated patterns extend the defaults. Include overrides generated patterns only.
//! Policy accepts `deny = [...]`, `[deny] paths = [...]`, or `[scope] deny = [...]`.
//!
//! Rule frontmatter is a deliberately constrained YAML subset, not general YAML:
//! `id` and optional `lens` are plain or quoted single-line strings; `paths` and
//! `replaces` accept a string, an inline list, or an indented `- string` list.
//! Double-quoted strings and inline arrays use JSON string escaping; single quotes
//! use YAML doubled-quote escaping. No aliases, tags, multiline scalars, comments,
//! nested mappings, or unknown keys are accepted. Missing paths means `**`.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::io;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

pub(crate) const CONFIG_PATH: &str = ".revkit/config.toml";
pub(crate) const DEFAULT_CONFIG: &str = r#"version = 1

[scope]
deny = []
exclude = []
include = []
generated = []

[tiers]
high = []
low = []

# Commands run only with review --trusted-local --run-checks.
[checks]
"#;

const MAX_BYTES: usize = 32 * 1024;
const MAX_RULES: usize = 64;
const MAX_PATTERNS: usize = 256;
const DENIED: &[&str] = &[
    ".git/**",
    "**/.git/**",
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/.netrc",
    "**/.npmrc",
    "**/credentials",
    "**/credentials.json",
    "**/id_rsa*",
    "**/id_ed25519*",
];
const GENERATED: &[&str] = &[
    "**/Cargo.lock",
    "**/package-lock.json",
    "**/npm-shrinkwrap.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/bun.lock",
    "**/bun.lockb",
    "**/poetry.lock",
    "**/uv.lock",
    "**/Pipfile.lock",
    "**/Gemfile.lock",
    "**/composer.lock",
    "**/go.sum",
    "**/vendor/**",
    "**/node_modules/**",
    "**/target/**",
    "**/build/**",
    "**/dist/**",
    "**/.next/**",
    "**/__pycache__/**",
    "**/*.min.js",
    "**/*.min.css",
    "**/*.map",
];
const HIGH: &[&str] = &[
    "**/auth/**",
    "**/security/**",
    "**/migrations/**",
    ".github/workflows/**",
];
const LOW: &[&str] = &["**/*.md", "**/*.txt", "**/LICENSE*", "**/NOTICE*"];

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    version: Option<u32>,
    scope: Scope,
    tiers: Tiers,
    checks: BTreeMap<String, String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Scope {
    deny: Vec<String>,
    exclude: Vec<String>,
    include: Vec<String>,
    generated: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Tiers {
    high: Vec<String>,
    low: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PolicyFile {
    version: Option<u32>,
    deny: Option<Deny>,
    scope: DenyScope,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Deny {
    Paths(Vec<String>),
    Table(DenyScope),
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DenyScope {
    #[serde(alias = "paths")]
    deny: Vec<String>,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct Rule {
    pub(crate) id: String,
    pub(crate) source: String,
    pub(crate) body: String,
}

struct ScopedRule {
    rule: Rule,
    paths: GlobSet,
    replaces: Vec<String>,
    // Resolved once at load time, including transitive replacement targets.
    supersedes: BTreeSet<usize>,
}

pub(crate) struct Policy {
    deny: GlobSet,
    exclude: GlobSet,
    include: GlobSet,
    generated: GlobSet,
    high: GlobSet,
    low: GlobSet,
    rules: Vec<ScopedRule>,
    pub(crate) checks: BTreeMap<String, String>,
}

type Result<T, E = Box<dyn Error>> = std::result::Result<T, E>;

impl Policy {
    pub(crate) fn load(
        config: Option<&str>,
        policy: Option<&str>,
        rules: Vec<(String, String)>,
        agents: Option<&str>,
    ) -> Result<Self> {
        if rules.len() > MAX_RULES {
            return Err(invalid("at most 64 rule sources are allowed"));
        }
        let mut total = 0usize;
        for text in config
            .into_iter()
            .chain(policy)
            .chain(agents)
            .chain(rules.iter().map(|(_, text)| text.as_str()))
        {
            if text.len() > MAX_BYTES {
                return Err(invalid("each policy source must be at most 32 KiB"));
            }
            total = total
                .checked_add(text.len())
                .ok_or_else(|| invalid("policy size overflow"))?;
        }
        if total > MAX_BYTES {
            return Err(invalid("combined policy sources must be at most 32 KiB"));
        }
        let config: Config = config.map(toml::from_str).transpose()?.unwrap_or_default();
        check_version(config.version)?;
        let policy: PolicyFile = policy.map(toml::from_str).transpose()?.unwrap_or_default();
        check_version(policy.version)?;
        let mut denied = owned(DENIED);
        denied.extend(config.scope.deny);
        denied.extend(policy.scope.deny);
        match policy.deny {
            Some(Deny::Paths(paths)) => denied.extend(paths),
            Some(Deny::Table(table)) => denied.extend(table.deny),
            None => {}
        }
        let mut generated = owned(GENERATED);
        generated.extend(config.scope.generated);
        let mut high = owned(HIGH);
        high.extend(config.tiers.high);
        let mut low = owned(LOW);
        low.extend(config.tiers.low);
        for (name, command) in &config.checks {
            if name.trim().is_empty()
                || command.trim().is_empty()
                || name.chars().any(char::is_control)
                || command.contains('\0')
            {
                return Err(invalid(
                    "check names and preview commands must be nonempty text",
                ));
            }
        }
        let mut parsed = builtins()?;
        let mut sources = BTreeSet::new();
        for (source, text) in rules {
            if !valid_path(&source)
                || !source.starts_with(".revkit/rules/")
                || !source.ends_with(".md")
                || source[".revkit/rules/".len()..].contains('/')
            {
                return Err(invalid("rule sources must be .revkit/rules/*.md paths"));
            }
            if !sources.insert(source.clone()) {
                return Err(invalid("duplicate rule source"));
            }
            parsed.push(parse_rule(source, &text)?);
        }
        if let Some(body) = agents.and_then(manual_rules) {
            parsed.push(scoped_rule(
                "agents.code_review".into(),
                "AGENTS.md".into(),
                body.into(),
                vec!["**".into()],
                Vec::new(),
            )?);
        }
        if parsed.len() > MAX_RULES {
            return Err(invalid(
                "at most 64 rules including built-in and AGENTS rules are allowed",
            ));
        }
        resolve_replacements(&mut parsed)?;
        Ok(Self {
            deny: compile(&denied)?,
            exclude: compile(&config.scope.exclude)?,
            include: compile(&config.scope.include)?,
            generated: compile(&generated)?,
            high: compile(&high)?,
            low: compile(&low)?,
            rules: parsed,
            checks: config.checks,
        })
    }

    /// Returns an exclusion reason before any blob is read. Includes cannot
    /// bypass deny patterns, explicit excludes, or repository-path validation.
    pub(crate) fn scope(&self, path: &str) -> Option<&'static str> {
        if !valid_path(path) {
            Some("invalid_path")
        } else if self.deny.is_match(path) {
            Some("deny")
        } else if self.exclude.is_match(path) {
            Some("exclude")
        } else if self.generated.is_match(path) && !self.include.is_match(path) {
            Some("generated")
        } else {
            None
        }
    }

    /// Whether a path must never be materialized for review or local checks.
    /// Unlike scope, generated files and explicit relevance excludes are allowed.
    pub(crate) fn protected(&self, path: &str) -> bool {
        !valid_path(path) || self.deny.is_match(path)
    }

    pub(crate) fn tier(&self, path: &str) -> &'static str {
        if self.high.is_match(path) {
            "high"
        } else if !self.checks.is_empty() && self.low.is_match(path) {
            "checks_only"
        } else {
            "standard"
        }
    }

    pub(crate) fn rules_for<'a>(&'a self, path: &str) -> Vec<&'a Rule> {
        if self.scope(path).is_some() {
            return Vec::new();
        }
        let matching: Vec<usize> = self
            .rules
            .iter()
            .enumerate()
            .filter_map(|(index, rule)| rule.paths.is_match(path).then_some(index))
            .collect();
        matching
            .iter()
            .filter_map(|&index| {
                (!matching
                    .iter()
                    .any(|&other| self.rules[other].supersedes.contains(&index)))
                .then_some(&self.rules[index].rule)
            })
            .collect()
    }
}

fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, message.into()).into()
}

fn check_version(version: Option<u32>) -> Result<()> {
    if version.is_some_and(|version| version != 1) {
        return Err(invalid("unsupported policy version (expected 1)"));
    }
    Ok(())
}

fn owned(patterns: &[&str]) -> Vec<String> {
    patterns.iter().map(|pattern| (*pattern).into()).collect()
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn compile(patterns: &[String]) -> Result<GlobSet> {
    if patterns.len() > MAX_PATTERNS {
        return Err(invalid("at most 256 patterns per selector are allowed"));
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        if pattern.is_empty()
            || pattern.starts_with('/')
            || pattern.contains('\\')
            || pattern.chars().any(char::is_control)
            || pattern
                .split('/')
                .any(|part| part == "." || part == ".." || part.is_empty())
        {
            return Err(invalid(format!(
                "invalid repository-relative glob: {pattern:?}"
            )));
        }
        let mut root = pattern.as_str();
        loop {
            builder.add(GlobBuilder::new(root).literal_separator(true).build()?);
            // Make zero-directory matching explicit, including at repository root.
            match root.strip_prefix("**/") {
                Some(rest) => root = rest,
                None => break,
            }
        }
    }
    Ok(builder.build()?)
}

fn scoped_rule(
    id: String,
    source: String,
    body: String,
    paths: Vec<String>,
    replaces: Vec<String>,
) -> Result<ScopedRule> {
    if !valid_id(&id) || replaces.iter().any(|id| !valid_id(id)) {
        return Err(invalid(
            "rule IDs must use ASCII letters, digits, '.', '_', or '-'",
        ));
    }
    if body.trim().is_empty() || paths.is_empty() {
        return Err(invalid(
            "rules require a nonempty body and at least one path pattern",
        ));
    }
    let unique: BTreeSet<&String> = replaces.iter().collect();
    if unique.len() != replaces.len() {
        return Err(invalid("duplicate replacement target"));
    }
    Ok(ScopedRule {
        rule: Rule { id, source, body },
        paths: compile(&paths)?,
        replaces,
        supersedes: BTreeSet::new(),
    })
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn builtins() -> Result<Vec<ScopedRule>> {
    [
        ("builtin.rust", "**/*.rs", "Review changed Rust for correctness: error propagation, ownership and lifetimes, panics on external input, and unsafe-code invariants. Report only concrete defects supported by the changed code."),
        ("builtin.python", "**/*.py", "Review changed Python for correctness: exception handling, mutable defaults, resource cleanup, and boundary conditions. Report only concrete defects supported by the changed code."),
        ("builtin.javascript", "**/*.{js,jsx,ts,tsx,mjs,cjs}", "Review changed JavaScript or TypeScript for correctness: asynchronous error handling, nullability, resource cleanup, and state consistency. Report only concrete defects supported by the changed code."),
    ].into_iter().map(|(id, path, body)| scoped_rule(
        id.into(), "builtin".into(), body.into(), vec![path.into()], Vec::new(),
    )).collect()
}

fn parse_rule(source: String, text: &str) -> Result<ScopedRule> {
    let mut lines = text.split_inclusive('\n');
    if lines.next().map(|line| line.trim_end_matches(['\r', '\n'])) != Some("---") {
        return Err(invalid(format!("{source}: missing YAML frontmatter")));
    }
    let mut offset = text.find('\n').map_or(text.len(), |index| index + 1);
    let mut header = Vec::new();
    let mut closed = false;
    for line in lines {
        offset += line.len();
        if line.trim_end_matches(['\r', '\n']) == "---" {
            closed = true;
            break;
        }
        header.push(line.trim_end_matches(['\r', '\n']));
    }
    if !closed {
        return Err(invalid(format!("{source}: unterminated frontmatter")));
    }
    let mut values: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut pending: Option<&str> = None;
    for line in header {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            let key = pending.ok_or_else(|| invalid("unexpected frontmatter indentation"))?;
            if line.starts_with('\t') {
                return Err(invalid("frontmatter list indentation must use spaces"));
            }
            let item = line
                .trim_start()
                .strip_prefix("- ")
                .ok_or_else(|| invalid("expected an indented '- string' list item"))?;
            values
                .get_mut(key)
                .ok_or_else(|| invalid("missing list field"))?
                .push(scalar(item)?);
            continue;
        }
        pending = None;
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("expected frontmatter key: value"))?;
        if !matches!(key, "id" | "paths" | "lens" | "replaces") || values.contains_key(key) {
            return Err(invalid(format!(
                "unknown or duplicate frontmatter key: {key}"
            )));
        }
        let value = value.trim();
        let is_list = matches!(key, "paths" | "replaces");
        let parsed = if value.is_empty() && is_list {
            pending = Some(key);
            Vec::new()
        } else if is_list && value.starts_with('[') {
            inline_list(value)?
        } else {
            vec![scalar(value)?]
        };
        values.insert(key, parsed);
    }
    let id = values
        .remove("id")
        .and_then(|mut values| values.pop())
        .ok_or_else(|| invalid("rule frontmatter requires id"))?;
    let paths = values.remove("paths").unwrap_or_else(|| vec!["**".into()]);
    let replaces = values.remove("replaces").unwrap_or_default();
    let mut body = text[offset..].trim().to_owned();
    if body.is_empty() {
        return Err(invalid("rule body must not be empty"));
    }
    if let Some(mut lens) = values.remove("lens") {
        let lens = lens.pop().ok_or_else(|| invalid("lens must be a string"))?;
        body = format!("Review lens: {lens}\n\n{body}");
    }
    scoped_rule(id, source, body, paths, replaces)
}

fn scalar(value: &str) -> Result<String> {
    let value = value.trim();
    let result = if value.starts_with('"') {
        serde_json::from_str::<String>(value)?
    } else if value.starts_with('\'') {
        if value.len() < 2 || !value.ends_with('\'') {
            return Err(invalid("unterminated single-quoted frontmatter string"));
        }
        let inner = &value[1..value.len() - 1];
        let mut decoded = String::new();
        let mut chars = inner.chars();
        while let Some(character) = chars.next() {
            if character == '\'' && chars.next() != Some('\'') {
                return Err(invalid(
                    "single quotes must be doubled inside a quoted string",
                ));
            }
            decoded.push(character);
        }
        decoded
    } else {
        if value.starts_with([
            '[', ']', '{', '}', '&', '*', '!', '|', '>', '@', '`', '#', '-', '?', ':',
        ]) || value.contains(" #")
            || value.contains(": ")
            || matches!(value, "null" | "~" | "true" | "false")
        {
            return Err(invalid(
                "unsupported YAML syntax; quote strings or use JSON arrays",
            ));
        }
        value.into()
    };
    if result.is_empty() || result.chars().any(char::is_control) {
        return Err(invalid(
            "frontmatter strings must be nonempty single-line text",
        ));
    }
    Ok(result)
}

fn inline_list(value: &str) -> Result<Vec<String>> {
    if !value.ends_with(']') {
        return Err(invalid("unterminated inline frontmatter list"));
    }
    let inner = &value[1..value.len() - 1];
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    let mut start = 0;
    let mut quote = None;
    let mut escaped = false;
    let mut chars = inner.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        match quote {
            Some('"') => {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    quote = None;
                }
            }
            Some('\'') if character == '\'' => {
                if chars.peek().is_some_and(|(_, next)| *next == '\'') {
                    chars.next();
                } else {
                    quote = None;
                }
            }
            Some(_) => {}
            None if character == '"' || character == '\'' => quote = Some(character),
            None if character == ',' => {
                result.push(scalar(&inner[start..index])?);
                start = index + 1;
            }
            None => {}
        }
    }
    if quote.is_some() {
        return Err(invalid("unterminated inline-list string"));
    }
    result.push(scalar(&inner[start..])?);
    Ok(result)
}

fn resolve_replacements(rules: &mut [ScopedRule]) -> Result<()> {
    let mut ids = BTreeMap::new();
    for (index, rule) in rules.iter().enumerate() {
        if ids.insert(rule.rule.id.as_str(), index).is_some() {
            return Err(invalid(format!("duplicate rule ID: {}", rule.rule.id)));
        }
    }
    let mut edges = vec![Vec::new(); rules.len()];
    let mut replaced_by = BTreeMap::new();
    for (index, rule) in rules.iter().enumerate() {
        for target in &rule.replaces {
            let target_index = *ids
                .get(target.as_str())
                .ok_or_else(|| invalid(format!("dangling replacement target: {target}")))?;
            if replaced_by.insert(target_index, index).is_some() {
                return Err(invalid(format!(
                    "ambiguous replacement chain for: {target}"
                )));
            }
            edges[index].push(target_index);
        }
    }
    let mut resolved = Vec::with_capacity(rules.len());
    for index in 0..rules.len() {
        let mut seen = BTreeSet::new();
        let mut pending = edges[index].clone();
        while let Some(target) = pending.pop() {
            if target == index {
                return Err(invalid("cyclic rule replacement chain"));
            }
            if seen.insert(target) {
                pending.extend(edges[target].iter().copied());
            }
        }
        resolved.push(seen);
    }
    for (rule, supersedes) in rules.iter_mut().zip(resolved) {
        rule.supersedes = supersedes;
    }
    Ok(())
}

fn manual_rules(agents: &str) -> Option<&str> {
    let mut offset = 0;
    let mut start = None;
    let mut fence: Option<(u8, usize)> = None;
    for line in agents.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let content = trimmed.trim_start_matches(' ');
        let indent = trimmed.len() - content.len();
        if indent <= 3 {
            let marker = content.as_bytes().first().copied();
            if matches!(marker, Some(b'`' | b'~')) {
                let marker = marker.unwrap_or_default();
                let count = content.bytes().take_while(|byte| *byte == marker).count();
                if let Some((open, minimum)) = fence {
                    if marker == open && count >= minimum && content[count..].trim().is_empty() {
                        fence = None;
                    }
                } else if count >= 3 {
                    fence = Some((marker, count));
                }
            } else if fence.is_none() {
                let heading = content.trim_end();
                if start.is_none() && heading == "## Code Review Rules" {
                    start = Some(offset + line.len());
                } else if let Some(start) = start
                    && (heading.starts_with("# ") || heading.starts_with("## "))
                {
                    let body = agents[start..offset].trim();
                    return (!body.is_empty()).then_some(body);
                }
            }
        }
        offset += line.len();
    }
    start.and_then(|start| {
        let body = agents[start..].trim();
        (!body.is_empty()).then_some(body)
    })
}
