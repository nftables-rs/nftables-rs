use std::string::FromUtf8Error;
use std::{
    ffi::{OsStr, OsString},
    io::{self, Write},
    process::{Command, Stdio},
};

use thiserror::Error;

use crate::schema::Nftables;

/// Default `nft` executable.
const NFT_EXECUTABLE: &str = "nft"; // search in PATH

/// Use the default `nft` executable.
pub const DEFAULT_NFT: Option<&str> = None;

/// Do not use additional arguments to the `nft` executable.
pub const DEFAULT_ARGS: Option<&[&str]> = None;

/// Error during `nft` execution.
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

/// Get the rule set that is currently active in the kernel.
///
/// This is done by calling the default `nft` executable with default arguments.
pub fn get_current_ruleset() -> Result<Nftables<'static>, NftablesError> {
    get_current_ruleset_with_args(DEFAULT_NFT, DEFAULT_ARGS)
}

/// Get the current rule set by calling a custom `nft` with custom arguments.
///
/// If `program` is [Some], then this program will be called instead of the
/// default `nft` executable.
/// [DEFAULT_NFT] can be passed to call the default `nft`.
///
/// If `args` is [Some], then these `nft` arguments will be used instead of the
/// default arguments `list` and `ruleset`.
/// [DEFAULT_ARGS] can be passed to use the default arguments.
/// Note that the argument `-j` is always added in front of `args`.
pub fn get_current_ruleset_with_args<P: AsRef<OsStr>, A: AsRef<OsStr>>(
    program: Option<P>,
    args: Option<&[A]>,
) -> Result<Nftables<'static>, NftablesError> {
    let output = get_current_ruleset_raw(program, args)?;
    serde_json::from_str(&output).map_err(NftablesError::NftInvalidJson)
}

/// Get the current raw rule set json by calling a custom `nft` with custom arguments.
///
/// If `program` is [Some], then this program will be called instead of the
/// default `nft` executable.
/// [DEFAULT_NFT] can be passed to call the default `nft`.
///
/// If `args` is [Some], then these `nft` arguments will be used instead of the
/// default arguments `list` and `ruleset`.
/// [DEFAULT_ARGS] can be passed to use the default arguments.
/// Note that the argument `-j` is always added in front of `args`.
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

/// Apply the given rule set to the kernel.
///
/// This is done by calling the default `nft` executable with default arguments.
pub fn apply_ruleset(nftables: &Nftables) -> Result<(), NftablesError> {
    apply_ruleset_with_args(nftables, DEFAULT_NFT, DEFAULT_ARGS)
}

/// Apply the given rule set by calling a custom `nft` with custom arguments.
///
/// If `program` is [Some], then this program will be called instead of the
/// default `nft` executable.
/// [DEFAULT_NFT] can be passed to call the default `nft`.
///
/// If `args` is [Some], then these `nft` arguments will be added in front of the
/// other arguments `-j` and `-f -` that are always required internally.
pub fn apply_ruleset_with_args<P: AsRef<OsStr>, A: AsRef<OsStr>>(
    nftables: &Nftables,
    program: Option<P>,
    args: Option<&[A]>,
) -> Result<(), NftablesError> {
    let nftables = serde_json::to_string(nftables).expect("failed to serialize Nftables struct");
    apply_ruleset_raw(&nftables, program, args)
}

/// Apply the given raw rule set json by calling a custom `nft` with custom arguments.
///
/// If `program` is [Some], then this program will be called instead of the
/// default `nft` executable.
/// [DEFAULT_NFT] can be passed to call the default `nft`.
///
/// If `args` is [Some], then these `nft` arguments will be added in front of the
/// other arguments `-j` and `-f -` that are always required internally.
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
