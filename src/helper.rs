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
pub const DEFAULT_ARGS: &[&str] = &[];

#[cfg(all(feature = "tokio", feature = "async-process"))]
compile_error!("features `tokio` and `async-process` are mutually exclusive");

/// Error during `nft` execution.
#[derive(Error, Debug)]
pub enum NftExecutableError {
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
pub fn get_current_ruleset() -> Result<Nftables<'static>, NftExecutableError> {
    get_current_ruleset_with_args(DEFAULT_NFT, DEFAULT_ARGS)
}

/// Get the current rule set by calling a custom `nft` with custom arguments.
///
/// If `program` is [Some], then this program will be called instead of the
/// default `nft` executable.
/// [DEFAULT_NFT] can be passed to call the default `nft`.
///
/// If `args` is not empty, then these `nft` arguments will be used instead of the
/// default arguments `list` and `ruleset`.
/// [DEFAULT_ARGS] can be passed to use the default arguments.
/// Note that the argument `-j` is always added in front of `args`.
pub fn get_current_ruleset_with_args<'a, P, A, I>(
    program: Option<&P>,
    args: I,
) -> Result<Nftables<'static>, NftExecutableError>
where
    P: AsRef<OsStr> + ?Sized,
    A: AsRef<OsStr> + ?Sized + 'a,
    I: IntoIterator<Item = &'a A> + 'a,
{
    let output = get_current_ruleset_raw(program, args)?;
    serde_json::from_str(&output).map_err(NftExecutableError::NftInvalidJson)
}

/// Get the current raw rule set json by calling a custom `nft` with custom arguments.
///
/// If `program` is [Some], then this program will be called instead of the
/// default `nft` executable.
/// [DEFAULT_NFT] can be passed to call the default `nft`.
///
/// If `args` is not empty, then these `nft` arguments will be used instead of the
/// default arguments `list` and `ruleset`.
/// [DEFAULT_ARGS] can be passed to use the default arguments.
/// Note that the argument `-j` is always added in front of `args`.
pub fn get_current_ruleset_raw<'a, P, A, I>(
    program: Option<&P>,
    args: I,
) -> Result<String, NftExecutableError>
where
    P: AsRef<OsStr> + ?Sized,
    A: AsRef<OsStr> + ?Sized + 'a,
    I: IntoIterator<Item = &'a A> + 'a,
{
    let program = program
        .map(AsRef::as_ref)
        .unwrap_or(NFT_EXECUTABLE.as_ref());
    let mut nft_cmd = Command::new(program);
    let nft_cmd = nft_cmd.arg("-j");
    let mut args = args.into_iter();
    let nft_cmd = match args.next() {
        Some(arg) => nft_cmd.arg(arg).args(args),
        None => nft_cmd.args(["list", "ruleset"]),
    };
    let process_result = nft_cmd.output();
    let process_result = process_result.map_err(|e| NftExecutableError::NftExecution {
        inner: e,
        program: program.into(),
    })?;

    let stdout = read_output(program, process_result.stdout)?;

    if !process_result.status.success() {
        let stderr = read_output(program, process_result.stderr)?;

        return Err(NftExecutableError::NftFailed {
            program: program.into(),
            hint: "getting the current ruleset".to_string(),
            stdout,
            stderr,
        });
    }
    Ok(stdout)
}

/// Get the rule set that is currently active in the kernel asynchronously.
///
/// See the synchronous [`get_current_ruleset`] for more information.
#[cfg(any(feature = "tokio", feature = "async-process"))]
pub async fn get_current_ruleset_async() -> Result<Nftables<'static>, NftExecutableError> {
    get_current_ruleset_with_args_async(DEFAULT_NFT, DEFAULT_ARGS).await
}

/// Get the current rule set asynchronously by calling a custom `nft` with custom arguments.
///
/// See the synchronous [`get_current_ruleset_with_args`] for more information.
#[cfg(any(feature = "tokio", feature = "async-process"))]
pub async fn get_current_ruleset_with_args_async<'a, P, A, I>(
    program: Option<&P>,
    args: I,
) -> Result<Nftables<'static>, NftExecutableError>
where
    P: AsRef<OsStr> + ?Sized,
    A: AsRef<OsStr> + ?Sized + 'a,
    I: IntoIterator<Item = &'a A> + 'a,
{
    let output = get_current_ruleset_raw_async(program, args).await?;
    serde_json::from_str(&output).map_err(NftExecutableError::NftInvalidJson)
}

/// Get the current raw rule set json asynchronously by calling a custom `nft` with custom arguments.
///
/// See the synchronous [`get_current_ruleset_raw`] for more information.
#[cfg(any(feature = "tokio", feature = "async-process"))]
pub async fn get_current_ruleset_raw_async<'a, P, A, I>(
    program: Option<&P>,
    args: I,
) -> Result<String, NftExecutableError>
where
    P: AsRef<OsStr> + ?Sized,
    A: AsRef<OsStr> + ?Sized + 'a,
    I: IntoIterator<Item = &'a A> + 'a,
{
    #[cfg(feature = "async-process")]
    use async_process::Command;
    #[cfg(feature = "tokio")]
    use tokio::process::Command;

    let program = program
        .map(AsRef::as_ref)
        .unwrap_or(NFT_EXECUTABLE.as_ref());
    let mut nft_cmd = Command::new(program);
    let nft_cmd = nft_cmd.arg("-j");
    let mut args = args.into_iter();
    let nft_cmd = match args.next() {
        Some(arg) => nft_cmd.arg(arg).args(args),
        None => nft_cmd.args(["list", "ruleset"]),
    };
    let process_result = nft_cmd.output().await;
    let process_result = process_result.map_err(|e| NftExecutableError::NftExecution {
        inner: e,
        program: program.into(),
    })?;

    let stdout = read_output(program, process_result.stdout)?;

    if !process_result.status.success() {
        let stderr = read_output(program, process_result.stderr)?;

        return Err(NftExecutableError::NftFailed {
            program: program.into(),
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
pub fn apply_ruleset(nftables: &Nftables) -> Result<(), NftExecutableError> {
    apply_ruleset_with_args(nftables, DEFAULT_NFT, DEFAULT_ARGS)
}

/// Apply the given rule set by calling a custom `nft` with custom arguments.
///
/// If `program` is [Some], then this program will be called instead of the
/// default `nft` executable.
/// [DEFAULT_NFT] can be passed to call the default `nft`.
///
/// If `args` is not empty, then these `nft` arguments will be added in front of the
/// other arguments `-j` and `-f -` that are always required internally.
pub fn apply_ruleset_with_args<'a, P, A, I>(
    nftables: &Nftables,
    program: Option<&P>,
    args: I,
) -> Result<(), NftExecutableError>
where
    P: AsRef<OsStr> + ?Sized,
    A: AsRef<OsStr> + ?Sized + 'a,
    I: IntoIterator<Item = &'a A> + 'a,
{
    let nftables = serde_json::to_string(nftables).expect("failed to serialize Nftables struct");
    apply_ruleset_raw(&nftables, program, args)?;
    Ok(())
}

/// Apply the given rule set to the kernel, and returns the processed rule set with
/// extra information.
///
/// This is done by using `nft --echo`. One can get rule handles from the returned
/// objects for future modifications, positional inserts, as well as removal.
pub fn apply_and_return_ruleset(nftables: &Nftables) -> Result<Nftables<'static>, NftExecutableError> {
    apply_and_return_ruleset_with_args(nftables, DEFAULT_NFT, DEFAULT_ARGS)
}

/// Apply the given rule set by calling a custom `nft` with custom arguments, and
/// returns the processed rule set with extra information.
///
/// This is done by using `nft --echo`. One can get rule handles from the returned
/// objects for future modifications, positional inserts, as well as removal.
pub fn apply_and_return_ruleset_with_args<'a, P, A, I>(
    nftables: &Nftables,
    program: Option<&P>,
    args: I,
) -> Result<Nftables<'static>, NftExecutableError>
where
    P: AsRef<OsStr> + ?Sized,
    A: AsRef<OsStr> + ?Sized + 'a,
    I: IntoIterator<Item = &'a A> + 'a,
{
    let nftables = serde_json::to_string(nftables).expect("failed to serialize Nftables struct");
    let args = args
        .into_iter()
        .map(AsRef::as_ref)
        .chain(Some("--echo".as_ref()));
    let output = apply_ruleset_raw(&nftables, program, args)?;
    serde_json::from_str(&output).map_err(NftExecutableError::NftInvalidJson)
}

/// Apply the given raw rule set json by calling a custom `nft` with custom arguments.
///
/// If `program` is [Some], then this program will be called instead of the
/// default `nft` executable.
/// [DEFAULT_NFT] can be passed to call the default `nft`.
///
/// If `args` is not empty, then these `nft` arguments will be added in front of the
/// other arguments `-j` and `-f -` that are always required internally.
///
/// The command's stdout is returned as a [`String`].
pub fn apply_ruleset_raw<'a, P, A, I>(
    payload: &str,
    program: Option<&P>,
    args: I,
) -> Result<String, NftExecutableError>
where
    P: AsRef<OsStr> + ?Sized,
    A: AsRef<OsStr> + ?Sized + 'a,
    I: IntoIterator<Item = &'a A> + 'a,
{
    let program = program
        .map(AsRef::as_ref)
        .unwrap_or(NFT_EXECUTABLE.as_ref());
    let mut nft_cmd = Command::new(program);
    let default_args = ["-j", "-f", "-"];
    let process = nft_cmd
        .args(args)
        .args(default_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn();
    let mut process = process.map_err(|e| NftExecutableError::NftExecution {
        program: program.into(),
        inner: e,
    })?;

    let mut stdin = process.stdin.take().unwrap();
    stdin
        .write_all(payload.as_bytes())
        .map_err(|e| NftExecutableError::NftExecution {
            program: program.into(),
            inner: e,
        })?;
    drop(stdin);

    let result = process.wait_with_output();
    match result {
        Ok(output) if output.status.success() => read_output(program, output.stdout),
        Ok(process_result) => {
            let stdout = read_output(program, process_result.stdout)?;
            let stderr = read_output(program, process_result.stderr)?;

            Err(NftExecutableError::NftFailed {
                program: program.into(),
                hint: "applying ruleset".to_string(),
                stdout,
                stderr,
            })
        }
        Err(e) => Err(NftExecutableError::NftExecution {
            program: program.into(),
            inner: e,
        }),
    }
}

/// Apply the given rule set to the kernel asynchronously.
///
/// See the synchronous [`apply_ruleset`] for more information.
#[cfg(any(feature = "tokio", feature = "async-process"))]
pub async fn apply_ruleset_async(nftables: &Nftables<'_>) -> Result<(), NftExecutableError> {
    apply_ruleset_with_args_async(nftables, DEFAULT_NFT, DEFAULT_ARGS).await
}

/// Apply the given rule set asynchronously by calling a custom `nft` with custom arguments.
///
/// See the synchronous [`apply_ruleset_with_args`] for more information.
#[cfg(any(feature = "tokio", feature = "async-process"))]
pub async fn apply_ruleset_with_args_async<'a, P, A, I>(
    nftables: &Nftables<'_>,
    program: Option<&P>,
    args: I,
) -> Result<(), NftExecutableError>
where
    P: AsRef<OsStr> + ?Sized,
    A: AsRef<OsStr> + ?Sized + 'a,
    I: IntoIterator<Item = &'a A> + 'a,
{
    let nftables = serde_json::to_string(nftables).expect("failed to serialize Nftables struct");
    apply_ruleset_raw_async(&nftables, program, args).await?;
    Ok(())
}

/// Apply the given rule set to the kernel asynchronously, and returns the processed
/// rule set with extra information.
///
/// See the synchronous [`apply_and_return_ruleset`] for more information.
#[cfg(any(feature = "tokio", feature = "async-process"))]
pub async fn apply_and_return_ruleset_async(
    nftables: &Nftables<'_>,
) -> Result<Nftables<'static>, NftExecutableError> {
    apply_and_return_ruleset_with_args_async(nftables, DEFAULT_NFT, DEFAULT_ARGS).await
}

/// Apply the given rule set asynchronously by calling a custom `nft` with custom
/// arguments, and returns the processed rule set with extra information.
///
/// See the synchronous [`apply_and_return_ruleset_with_args`] for more information.
#[cfg(any(feature = "tokio", feature = "async-process"))]
pub async fn apply_and_return_ruleset_with_args_async<'a, P, A, I>(
    nftables: &Nftables<'_>,
    program: Option<&P>,
    args: I,
) -> Result<Nftables<'static>, NftExecutableError>
where
    P: AsRef<OsStr> + ?Sized,
    A: AsRef<OsStr> + ?Sized + 'a,
    I: IntoIterator<Item = &'a A> + 'a,
{
    let nftables = serde_json::to_string(nftables).expect("failed to serialize Nftables struct");
    let args = args
        .into_iter()
        .map(AsRef::as_ref)
        .chain(Some("--echo".as_ref()));
    let output = apply_ruleset_raw_async(&nftables, program, args).await?;
    serde_json::from_str(&output).map_err(NftExecutableError::NftInvalidJson)
}

/// Apply the given raw rule set json asynchronously by calling a custom `nft` with custom arguments.
///
/// See the synchronous [`apply_ruleset_raw`] for more information.
#[cfg(any(feature = "tokio", feature = "async-process"))]
pub async fn apply_ruleset_raw_async<'a, P, A, I>(
    payload: &str,
    program: Option<&P>,
    args: I,
) -> Result<String, NftExecutableError>
where
    P: AsRef<OsStr> + ?Sized,
    A: AsRef<OsStr> + ?Sized + 'a,
    I: IntoIterator<Item = &'a A> + 'a,
{
    #[cfg(feature = "async-process")]
    use async_process::Command;
    #[cfg(feature = "async-process")]
    use futures_lite::io::AsyncWriteExt;
    #[cfg(feature = "tokio")]
    use tokio::io::AsyncWriteExt;
    #[cfg(feature = "tokio")]
    use tokio::process::Command;

    let program = program
        .map(AsRef::as_ref)
        .unwrap_or(NFT_EXECUTABLE.as_ref());
    let mut nft_cmd = Command::new(program);
    let default_args = ["-j", "-f", "-"];
    let process = nft_cmd
        .args(args)
        .args(default_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn();
    let mut process = process.map_err(|e| NftExecutableError::NftExecution {
        program: program.into(),
        inner: e,
    })?;

    let mut stdin = process.stdin.take().unwrap();
    stdin
        .write_all(payload.as_bytes())
        .await
        .map_err(|e| NftExecutableError::NftExecution {
            program: program.into(),
            inner: e,
        })?;
    drop(stdin);

    #[cfg(feature = "tokio")]
    let result = process.wait_with_output().await;
    #[cfg(feature = "async-process")]
    let result = process.output().await;
    match result {
        Ok(output) if output.status.success() => read_output(program, output.stdout),
        Ok(process_result) => {
            let stdout = read_output(program, process_result.stdout)?;
            let stderr = read_output(program, process_result.stderr)?;

            Err(NftExecutableError::NftFailed {
                program: program.into(),
                hint: "applying ruleset".to_string(),
                stdout,
                stderr,
            })
        }
        Err(e) => Err(NftExecutableError::NftExecution {
            program: program.into(),
            inner: e,
        }),
    }
}

fn read_output(program: impl Into<OsString>, bytes: Vec<u8>) -> Result<String, NftExecutableError> {
    String::from_utf8(bytes).map_err(|e| NftExecutableError::NftOutputEncoding {
        inner: e,
        program: program.into(),
    })
}
