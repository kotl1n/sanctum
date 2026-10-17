//! Original shell data exists only in this process, never in tool arguments.
use crate::{
    Error, MAX_BODY, Result, json,
    protocol::Session,
    redaction::{Policy, Redactor},
    vault::Vault,
};
use serde_json::json as value;
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub fn decode(encoded: &str) -> Result<String> {
    if encoded.len() > MAX_BODY * 2 || !encoded.len().is_multiple_of(2) || !encoded.is_ascii() {
        return Err(Error("invalid_command_encoding"));
    }
    let bytes = (0..encoded.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&encoded[i..i + 2], 16)
                .map_err(|_| Error("invalid_command_encoding"))
        })
        .collect::<Result<Vec<_>>>()?;
    String::from_utf8(bytes).map_err(|_| Error("utf8_required"))
}
pub fn run(vault: &Vault, session: &str, policy: Policy, encoded: &str) -> Result<i32> {
    run_with_options(vault, session, policy, encoded, None, false, None)
}
pub fn run_with_options(
    vault: &Vault,
    session: &str,
    policy: Policy,
    encoded: &str,
    shell: Option<&str>,
    login: bool,
    cwd_hex: Option<&str>,
) -> Result<i32> {
    if !vault.exists(session)? {
        return Err(Error("protected_session_required"));
    }
    let command = decode(encoded)?;
    let restored = Zeroizing::new(vault.transact(session, policy.clone(), |engine| {
        let session = Session::new(Redactor::from_snapshot(policy.clone(), &engine.snapshot())?);
        let input = value!({"cmd":command}).to_string();
        let arguments = json::parse(session.arguments(&input, "shell")?.as_bytes())?;
        Ok(arguments["cmd"]
            .as_str()
            .ok_or(Error("command_required"))?
            .to_owned())
    })?);
    let shell = shell
        .map(str::to_owned)
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/bash".into());
    if !std::path::Path::new(&shell).is_absolute() {
        return Err(Error("absolute_shell_path_required"));
    }
    let mut command = Command::new(shell);
    command
        .args([if login { "-lc" } else { "-c" }, &restored])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(encoded) = cwd_hex {
        let cwd = decode(encoded)?;
        let cwd = vault.transact(session, policy.clone(), |engine| {
            let session =
                Session::new(Redactor::from_snapshot(policy.clone(), &engine.snapshot())?);
            let args = json::parse(
                session
                    .arguments(&value!({"workdir":cwd}).to_string(), "local_file")?
                    .as_bytes(),
            )?;
            Ok(args["workdir"]
                .as_str()
                .ok_or(Error("invalid_workdir"))?
                .to_owned())
        })?;
        command.current_dir(cwd);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|_| Error("local_command_start_failed"))?;
    let group = child.id();
    let stop = |child: &mut std::process::Child| {
        #[cfg(unix)]
        {
            // SAFETY: group is the id of the private process group created
            // immediately above for this subprocess, never a caller's pid.
            unsafe {
                libc::kill(-(group as libc::pid_t), libc::SIGKILL);
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    };
    let stdout = child
        .stdout
        .take()
        .ok_or(Error("local_command_pipe_failed"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(Error("local_command_pipe_failed"))?;
    fn capture(reader: impl Read) -> Result<Zeroizing<Vec<u8>>> {
        let mut bytes = Zeroizing::new(Vec::new());
        reader
            .take((MAX_BODY + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("local_output_read_failed"))?;
        if bytes.len() > MAX_BODY {
            return Err(Error("local_output_size_limit"));
        }
        Ok(bytes)
    }
    let (send, receive) = std::sync::mpsc::channel();
    let errors = send.clone();
    std::thread::spawn(move || {
        let _ = send.send((false, capture(stdout)));
    });
    std::thread::spawn(move || {
        let _ = errors.send((true, capture(stderr)));
    });
    let until = Instant::now() + Duration::from_secs(120);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                stop(&mut child);
                return Err(Error("local_command_timeout"));
            }
        }
    };
    let mut stdout = None;
    let mut stderr = None;
    for _ in 0..2 {
        let remaining = until.saturating_duration_since(Instant::now());
        let (is_error, result) = match receive.recv_timeout(remaining) {
            Ok(result) => result,
            Err(_) => {
                stop(&mut child);
                return Err(Error("local_capture_timeout"));
            }
        };
        let output = match result {
            Ok(output) => output,
            Err(error) => {
                stop(&mut child);
                return Err(error);
            }
        };
        if is_error {
            stderr = Some(output);
        } else {
            stdout = Some(output);
        }
    }
    let stdout = stdout.ok_or(Error("local_capture_failed"))?;
    let stderr = stderr.ok_or(Error("local_capture_failed"))?;
    let stdout = std::str::from_utf8(&stdout).map_err(|_| Error("binary_tool_output_disabled"))?;
    let stderr = std::str::from_utf8(&stderr).map_err(|_| Error("binary_tool_output_disabled"))?;
    let safe = vault.mask(session, policy, &value!({"stdout":stdout,"stderr":stderr}))?;
    std::io::stdout()
        .write_all(
            safe["stdout"]
                .as_str()
                .ok_or(Error("invalid_output"))?
                .as_bytes(),
        )
        .map_err(|_| Error("output_write_failed"))?;
    std::io::stderr()
        .write_all(
            safe["stderr"]
                .as_str()
                .ok_or(Error("invalid_output"))?
                .as_bytes(),
        )
        .map_err(|_| Error("output_write_failed"))?;
    Ok(status.code().unwrap_or(1))
}
