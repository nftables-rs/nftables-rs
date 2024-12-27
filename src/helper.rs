use std::string::FromUtf8Error;
use std::{
    ffi::{OsStr, OsString},
    io::{self, Write},
    process::{Command, Stdio},
};

use thiserror::Error;

use crate::schema::Nftables;

const NFT_EXECUTABLE: &str = "nft"; // search in PATH

/// Use the default `nft` executable.
pub const DEFAULT_NFT: Option<&str> = None;

/// Do not use additional arguments to the `nft` executable.
pub const DEFAULT_ARGS: Option<&[&str]> = None;

#[derive(Error, Debug)]
pub enum NftablesError {
    #[error("unable to execute {program:?}: {inner}")]
    NftExecution { program: OsString, inner: io::Error },
    #[error("{program:?}'s output contained invalid utf8: {inner}")]
    NftOutputEncoding {
        program: OsString,
        inner: FromUtf8Error,
    },
    #[error("got invalid json: {0}")]
    NftInvalidJson(serde_json::Error),
    #[error("{program:?} did not return successfully while {hint}")]
    NftFailed {
        program: OsString,
        hint: String,
        stdout: String,
        stderr: String,
    },
}

pub fn get_current_ruleset() -> Result<Nftables<'static>, NftablesError> {
    get_current_ruleset_with_args(DEFAULT_NFT, DEFAULT_ARGS)
}

pub fn get_current_ruleset_with_args<P: AsRef<OsStr>, A: AsRef<OsStr>>(
    program: Option<P>,
    args: Option<&[A]>,
) -> Result<Nftables<'static>, NftablesError> {
    let output = get_current_ruleset_raw(program, args)?;
    serde_json::from_str(&output).map_err(NftablesError::NftInvalidJson)
}

pub fn get_current_ruleset_raw<P: AsRef<OsStr>, A: AsRef<OsStr>>(
    program: Option<P>,
    args: Option<&[A]>,
) -> Result<String, NftablesError> {
    let mut nft_cmd = get_command(program);
    let nft_cmd = nft_cmd.arg("-j");
    let nft_cmd = match args {
        Some(args) => nft_cmd.args(args),
        None => nft_cmd.args(["list", "ruleset"]),
    };
    let process_result = nft_cmd.output();
    let process_result = process_result.map_err(|e| NftablesError::NftExecution {
        inner: e,
        program: nft_cmd.get_program().to_os_string(),
    })?;

    let stdout = read_output(nft_cmd, process_result.stdout)?;

    if !process_result.status.success() {
        let stderr = read_output(nft_cmd, process_result.stderr)?;

        return Err(NftablesError::NftFailed {
            program: nft_cmd.get_program().to_os_string(),
            hint: "getting the current ruleset".to_string(),
            stdout,
            stderr,
        });
    }
    Ok(stdout)
}

pub fn apply_ruleset(nftables: &Nftables) -> Result<(), NftablesError> {
    apply_ruleset_with_args(nftables, DEFAULT_NFT, DEFAULT_ARGS)
}

pub fn apply_ruleset_with_args<P: AsRef<OsStr>, A: AsRef<OsStr>>(
    nftables: &Nftables,
    program: Option<P>,
    args: Option<&[A]>,
) -> Result<(), NftablesError> {
    let nftables = serde_json::to_string(nftables).expect("failed to serialize Nftables struct");
    apply_ruleset_raw(&nftables, program, args)
}

pub fn apply_ruleset_raw<P: AsRef<OsStr>, A: AsRef<OsStr>>(
    payload: &str,
    program: Option<P>,
    args: Option<&[A]>,
) -> Result<(), NftablesError> {
    let mut nft_cmd = get_command(program);
    let default_args = ["-j", "-f", "-"];
    let process = nft_cmd
        .args(args.into_iter().flatten())
        .args(default_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn();
    let mut process = process.map_err(|e| NftablesError::NftExecution {
        program: nft_cmd.get_program().to_os_string(),
        inner: e,
    })?;

    let mut stdin = process.stdin.take().unwrap();
    stdin
        .write_all(payload.as_bytes())
        .map_err(|e| NftablesError::NftExecution {
            program: nft_cmd.get_program().to_os_string(),
            inner: e,
        })?;
    drop(stdin);

    let result = process.wait_with_output();
    match result {
        Ok(output) if output.status.success() => Ok(()),
        Ok(process_result) => {
            let stdout = read_output(&nft_cmd, process_result.stdout)?;
            let stderr = read_output(&nft_cmd, process_result.stderr)?;

            Err(NftablesError::NftFailed {
                program: nft_cmd.get_program().to_os_string(),
                hint: "applying ruleset".to_string(),
                stdout,
                stderr,
            })
        }
        Err(e) => Err(NftablesError::NftExecution {
            program: nft_cmd.get_program().to_os_string(),
            inner: e,
        }),
    }
}

fn get_command<S: AsRef<OsStr>>(program: Option<S>) -> Command {
    match program {
        Some(program) => Command::new(program),
        None => Command::new(NFT_EXECUTABLE),
    }
}

fn read_output(cmd: &Command, bytes: Vec<u8>) -> Result<String, NftablesError> {
    String::from_utf8(bytes).map_err(|e| NftablesError::NftOutputEncoding {
        inner: e,
        program: cmd.get_program().to_os_string(),
    })
}
