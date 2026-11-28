use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Complete,
    Incomplete,
    Unavailable,
}

#[derive(Debug)]
pub(crate) struct Execution {
    pub(crate) status: Status,
    pub(crate) final_text: Option<String>,
    pub(crate) model: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) usage: Option<serde_json::Value>,
    pub(crate) reason: Option<String>,
}

impl Execution {
    fn unavailable(reason: &str) -> Self {
        Self {
            status: Status::Unavailable,
            final_text: None,
            model: None,
            provider: None,
            usage: None,
            reason: Some(reason.to_owned()),
        }
    }
}

pub(crate) fn run(
    executable: &Path,
    model: Option<&str>,
    prompt: &str,
    timeout: Duration,
) -> Execution {
    #[cfg(unix)]
    {
        unix::run(executable, model, prompt, timeout)
    }
    #[cfg(not(unix))]
    {
        let _ = (executable, model, prompt, timeout);
        Execution::unavailable("OMP process-group supervision is unavailable on this platform.")
    }
}

pub(crate) fn available_executable(executable: &Path) -> Option<PathBuf> {
    fn runnable(path: &Path) -> bool {
        std::fs::metadata(path).is_ok_and(|meta| {
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
    let cwd = std::env::current_dir().ok()?;
    if executable.is_absolute() || executable.as_os_str().as_encoded_bytes().contains(&b'/') {
        let path = cwd.join(executable);
        return runnable(&path).then_some(path);
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| cwd.join(dir).join(executable))
        .find(|path| runnable(path))
}

pub(crate) fn bounded(
    command: &mut std::process::Command,
    timeout: Duration,
) -> Result<std::process::Output, &'static str> {
    bounded_with_cap(command, timeout, 1024 * 1024)
}

pub(crate) fn bounded_with_cap(
    command: &mut std::process::Command,
    timeout: Duration,
    max_bytes: usize,
) -> Result<std::process::Output, &'static str> {
    #[cfg(unix)]
    {
        unix::bounded(command, timeout, max_bytes)
    }
    #[cfg(not(unix))]
    {
        let _ = (command, timeout, max_bytes);
        Err("Process-group supervision is unavailable on this platform.")
    }
}

pub(crate) fn install_interrupts() -> std::io::Result<()> {
    #[cfg(unix)]
    unix::install_interrupts()?;
    Ok(())
}

pub(crate) fn interrupted() -> bool {
    #[cfg(unix)]
    return unix::interrupted();
    #[cfg(not(unix))]
    false
}

#[derive(Default)]
struct Transcript {
    final_text: Option<String>,
    model: Option<String>,
    provider: Option<String>,
    usage: Option<serde_json::Value>,
    stopped: bool,
    provider_error_status: Option<u64>,
    terminal: bool,
    tools: bool,
    malformed: bool,
}

impl Transcript {
    fn parse(bytes: &[u8]) -> Self {
        let mut transcript = Self::default();
        // Parse complete records independently, so a truncated final record does not
        // discard useful assistant text from an earlier record.
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let Ok(event) = serde_json::from_slice::<serde_json::Value>(line) else {
                transcript.malformed = true;
                transcript.terminal = false;
                continue;
            };
            let Some(kind) = event.get("type").and_then(serde_json::Value::as_str) else {
                transcript.malformed = true;
                transcript.terminal = false;
                continue;
            };
            // These explicit advisor-only notifications cannot resume primary work.
            // Confirmed in OMP's AgentSessionEvent and RPC wire event definitions.
            if matches!(kind, "advisor_yielded" | "advisor_cost_changed") {
                continue;
            }
            // Primary and unknown events invalidate earlier completion until a
            // subsequent terminal agent_end proves the primary run finished.
            transcript.terminal = false;
            match kind {
                "message_end" | "turn_end" => {
                    let message = event.get("message").unwrap_or(&event);
                    if message.get("role").and_then(serde_json::Value::as_str) == Some("assistant")
                    {
                        transcript.assistant(message, true);
                    }
                    if event.get("toolResults").is_some_and(nonempty) {
                        transcript.tools = true;
                    }
                }
                "agent_end" => {
                    transcript.terminal = event.get("isTerminal")
                        != Some(&serde_json::Value::Bool(false))
                        && !event.get("awaitingAsyncWork").is_some_and(nonempty);
                    if let Some(messages) =
                        event.get("messages").and_then(serde_json::Value::as_array)
                    {
                        transcript.tools |= messages.iter().any(has_tool_call);
                        // A final snapshot can salvage text, but cannot replace
                        // the required assistant message_end/turn_end evidence.
                        if transcript.final_text.is_none()
                            && let Some(message) = messages.iter().rev().find(|message| {
                                message.get("role").and_then(serde_json::Value::as_str)
                                    == Some("assistant")
                            })
                        {
                            transcript.assistant(message, false);
                        }
                    }
                }
                "tool_execution_start" | "tool_execution_update" | "tool_execution_end" => {
                    transcript.tools = true;
                }
                _ => {}
            }
        }
        transcript
    }

    fn assistant(&mut self, message: &serde_json::Value, ended: bool) {
        if let Some(model) = message.get("model").and_then(serde_json::Value::as_str)
            && !model.is_empty()
        {
            self.model = Some(model.to_owned());
        }
        if let Some(provider) = message.get("provider").and_then(serde_json::Value::as_str)
            && !provider.is_empty()
        {
            self.provider = Some(provider.to_owned());
        }
        if let Some(usage) = message.get("usage").and_then(serde_json::Value::as_object) {
            let mut tokens = serde_json::Map::new();
            for key in [
                "input",
                "output",
                "cacheRead",
                "cacheWrite",
                "totalTokens",
                "inputTokens",
                "outputTokens",
                "cacheReadTokens",
                "cacheWriteTokens",
                "input_tokens",
                "output_tokens",
                "total_tokens",
                "prompt_tokens",
                "completion_tokens",
                "cache_read_input_tokens",
                "cache_creation_input_tokens",
                "reasoning",
                "reasoningTokens",
                "reasoning_tokens",
            ] {
                if let Some(value) = usage.get(key)
                    && value.is_number()
                {
                    tokens.insert(key.to_owned(), value.clone());
                }
            }
            self.usage = (!tokens.is_empty()).then_some(serde_json::Value::Object(tokens));
        }
        let mut text = String::new();
        let tool_call = has_tool_call(message);
        if let Some(content) = message.get("content").and_then(serde_json::Value::as_array) {
            for block in content {
                if block.get("type").and_then(serde_json::Value::as_str) == Some("text")
                    && let Some(part) = block.get("text").and_then(serde_json::Value::as_str)
                {
                    text.push_str(part);
                }
            }
        }
        self.tools |= tool_call;
        let usable = !text.trim().is_empty();
        if ended {
            let stop_reason = message
                .get("stopReason")
                .and_then(serde_json::Value::as_str);
            self.stopped = usable && !tool_call && stop_reason == Some("stop");
            self.provider_error_status = if stop_reason == Some("error") {
                message
                    .get("errorStatus")
                    .and_then(serde_json::Value::as_u64)
                    .filter(|status| (400..600).contains(status))
            } else {
                None
            };
        }
        if usable {
            self.final_text = Some(text);
        }
    }

    fn finish(self, success: bool, failure: Option<&str>) -> Execution {
        let reason = if let Some(failure) = failure {
            Some(failure.to_owned())
        } else if !self.malformed
            && !self.tools
            && let Some(status) = self.provider_error_status
        {
            Some(format!("OMP reported an upstream error (HTTP {status})."))
        } else {
            let reason = if !success {
                Some("OMP exited unsuccessfully.")
            } else if self.malformed {
                Some("OMP returned an invalid event stream.")
            } else if self.tools {
                Some("OMP attempted tool use.")
            } else if !self.stopped {
                Some("OMP did not finish an assistant text response with stopReason stop.")
            } else if !self.terminal {
                Some("OMP did not finish with a terminal agent_end event.")
            } else {
                None
            };
            reason.map(str::to_owned)
        };
        Execution {
            status: if reason.is_none() {
                Status::Complete
            } else {
                Status::Incomplete
            },
            final_text: self.final_text,
            model: self.model,
            provider: self.provider,
            usage: self.usage,
            reason,
        }
    }
}

fn has_tool_call(message: &serde_json::Value) -> bool {
    message.get("tool_calls").is_some_and(nonempty)
        || message
            .get("content")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|content| {
                content.iter().any(|block| {
                    matches!(
                        block.get("type").and_then(serde_json::Value::as_str),
                        Some("toolCall" | "tool_call" | "tool_use")
                    )
                })
            })
}

fn nonempty(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Array(value) => !value.is_empty(),
        serde_json::Value::Object(value) => !value.is_empty(),
        serde_json::Value::String(value) => !value.is_empty(),
        serde_json::Value::Number(value) => value.as_u64() != Some(0),
    }
}

#[cfg(unix)]
mod unix {
    use super::{Execution, Transcript};
    use std::io::{self, Read};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Command, ExitStatus, Output, Stdio};
    use std::time::{Duration, Instant};

    const OUTPUT_CAP: usize = 1024 * 1024;

    pub(super) fn run(
        executable: &Path,
        model: Option<&str>,
        prompt: &str,
        timeout: Duration,
    ) -> Execution {
        let Some(executable) = super::available_executable(executable) else {
            return Execution::unavailable("Could not resolve the OMP executable path.");
        };
        let Ok(scratch) = tempfile::tempdir() else {
            return Execution::unavailable("Could not create an isolated OMP working directory.");
        };
        let mut command = Command::new(executable);
        command.args([
            "--print",
            "--mode",
            "json",
            "--no-session",
            "--no-extensions",
            "--no-tools",
            "--no-skills",
            "--no-rules",
            "--no-context-files",
            "--no-title",
            "--no-lsp",
            "--offline",
        ]);
        if let Some(model) = model {
            command.arg("--model").arg(model);
        }
        command
            .arg("--")
            .arg(prompt)
            .current_dir(scratch.path())
            .env("PWD", scratch.path());
        match supervise(&mut command, timeout, OUTPUT_CAP) {
            Ok(capture) => Transcript::parse(&capture.stdout).finish(
                capture.status.is_some_and(|status| status.success()),
                capture.failure,
            ),
            Err(reason) => Execution::unavailable(reason),
        }
    }

    pub(super) fn bounded(
        command: &mut Command,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<Output, &'static str> {
        let capture = supervise(command, timeout, max_bytes)?;
        if let Some(reason) = capture.failure {
            return Err(reason);
        }
        Ok(Output {
            status: capture
                .status
                .ok_or("Could not observe the process status.")?,
            stdout: capture.stdout,
            stderr: capture.stderr,
        })
    }

    struct Capture {
        status: Option<ExitStatus>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        failure: Option<&'static str>,
    }

    static INTERRUPTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    extern "C" fn interrupt(_: libc::c_int) {
        INTERRUPTED.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub(super) fn interrupted() -> bool {
        INTERRUPTED.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub(super) fn install_interrupts() -> io::Result<()> {
        // The handler only sets a lock-free flag. Cleanup happens in the owner thread.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = interrupt as *const () as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
                if libc::sigaction(signal, &action, std::ptr::null_mut()) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }

    fn supervise(
        command: &mut Command,
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<Capture, &'static str> {
        if interrupted() {
            return Ok(Capture {
                status: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                failure: Some("Process cancelled by operator interrupt."),
            });
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let start = Instant::now();
        let mut child = command
            .spawn()
            .map_err(|_| "Could not start the process.")?;
        let (Some(mut stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take())
        else {
            terminate(&mut child);
            return Err("Could not capture process output.");
        };
        if nonblocking(stdout.as_raw_fd()).is_err() || nonblocking(stderr.as_raw_fd()).is_err() {
            terminate(&mut child);
            return Err("Could not supervise process output safely.");
        }
        let mut bytes = Vec::new();
        let mut diagnostics = Vec::new();
        let mut total = 0;
        let mut stdout_open = true;
        let mut stderr_open = true;
        let mut exited = None;
        let mut failure = None;
        loop {
            if interrupted() {
                failure = Some("Process cancelled by operator interrupt.");
                break;
            }
            if start.elapsed() >= timeout {
                failure = Some("Process exceeded its execution timeout.");
                break;
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    exited = Some(status);
                    // Kill descendants even when the leader exited normally.
                    // Never wait for EOF: a descendant could retain either pipe.
                    kill_group(&child);
                }
                Ok(None) => {}
                Err(_) => {
                    failure = Some("Could not observe the process status.");
                    break;
                }
            }
            if stdout_open {
                match drain(&mut stdout, Some(&mut bytes), &mut total, max_bytes) {
                    Ok(open) => stdout_open = open,
                    Err(reason) => {
                        failure = Some(reason);
                        break;
                    }
                }
            }
            if stderr_open {
                match drain(&mut stderr, Some(&mut diagnostics), &mut total, max_bytes) {
                    Ok(open) => stderr_open = open,
                    Err(reason) => {
                        failure = Some(reason);
                        break;
                    }
                }
            }
            if exited.is_some() {
                break;
            }
            let remaining = timeout.saturating_sub(start.elapsed());
            let delay = remaining.as_millis().min(20) as libc::c_int;
            let mut fds = [
                libc::pollfd {
                    fd: if stdout_open { stdout.as_raw_fd() } else { -1 },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if stderr_open { stderr.as_raw_fd() } else { -1 },
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            // The only descriptors passed to poll are our owned, nonblocking pipes.
            let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, delay) };
            if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                failure = Some("Could not supervise process output safely.");
                break;
            }
        }
        if failure.is_some() {
            terminate(&mut child);
            // Preserve immediately available text without ever blocking on an
            // inherited descriptor. A full output budget must not grow further.
            if total < max_bytes {
                let _ = drain(&mut stdout, Some(&mut bytes), &mut total, max_bytes);
            }
        }
        Ok(Capture {
            status: exited,
            stdout: bytes,
            stderr: diagnostics,
            failure,
        })
    }

    fn nonblocking(fd: RawFd) -> io::Result<()> {
        // fcntl borrows a live owned pipe and preserves its existing flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn drain(
        reader: &mut impl Read,
        mut capture: Option<&mut Vec<u8>>,
        total: &mut usize,
        max_bytes: usize,
    ) -> Result<bool, &'static str> {
        let mut buffer = [0_u8; 8192];
        loop {
            // Read one extra byte to distinguish exactly-at-cap output from overflow.
            let limit = buffer
                .len()
                .min(max_bytes.saturating_sub(*total).saturating_add(1));
            match reader.read(&mut buffer[..limit]) {
                Ok(0) => return Ok(false),
                Ok(count) => {
                    let kept = count.min(max_bytes.saturating_sub(*total));
                    if let Some(capture) = capture.as_deref_mut() {
                        capture.extend_from_slice(&buffer[..kept]);
                    }
                    *total += kept;
                    if count > kept {
                        return Err("Process exceeded the combined output limit.");
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(true),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("Could not read process output."),
            }
        }
    }

    fn kill_group(child: &Child) {
        if let Ok(pid) = libc::pid_t::try_from(child.id()) {
            // The child created its own process group before exec. Negative pid
            // targets that group, including descendants with inherited pipes.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }

    fn terminate(child: &mut Child) {
        kill_group(child);
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::{Status, Transcript};

    const COMPLETE: &str = concat!(
        "{\"type\":\"message_end\",\"message\":{\"role\":\"assistant\",",
        "\"content\":[{\"type\":\"text\",\"text\":\"done\"}],\"stopReason\":\"stop\"}}\n",
        "{\"type\":\"agent_end\"}\n",
    );

    #[test]
    fn advisor_tail_preserves_primary_completion() {
        let events = format!(
            "{COMPLETE}{{\"type\":\"advisor_cost_changed\"}}\n{{\"type\":\"advisor_yielded\"}}\n"
        );
        assert_eq!(
            Transcript::parse(events.as_bytes())
                .finish(true, None)
                .status,
            Status::Complete
        );
    }

    #[test]
    fn primary_and_unknown_tails_require_another_terminal_event() {
        for kind in [
            "agent_start",
            "message_start",
            "agent_pause",
            "advisor_unknown",
            "unknown",
        ] {
            let events =
                format!("{COMPLETE}{{\"type\":\"{kind}\"}}\n{{\"type\":\"advisor_yielded\"}}\n");
            assert_eq!(
                Transcript::parse(events.as_bytes())
                    .finish(true, None)
                    .status,
                Status::Incomplete
            );
            let events = format!("{events}{{\"type\":\"agent_end\"}}\n");
            assert_eq!(
                Transcript::parse(events.as_bytes())
                    .finish(true, None)
                    .status,
                Status::Complete
            );
        }
    }

    #[test]
    fn advisor_tail_does_not_complete_a_yielded_primary() {
        let events = format!(
            "{COMPLETE}{{\"type\":\"agent_end\",\"isTerminal\":false}}\n\
             {{\"type\":\"advisor_cost_changed\"}}\n{{\"type\":\"advisor_yielded\"}}\n"
        );
        assert_eq!(
            Transcript::parse(events.as_bytes())
                .finish(true, None)
                .status,
            Status::Incomplete
        );
    }
}
