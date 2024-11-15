use std::string::FromUtf8Error;
use std::{
    io::{self, Write},
    process::{Command, Stdio},
};

use thiserror::Error;

use crate::schema::Nftables;

const NFT_EXECUTABLE: &str = "nft"; // search in PATH

#[derive(Error, Debug)]
pub enum NftablesError {
    #[error("unable to execute {program}: {inner}")]
    NftExecution { program: String, inner: io::Error },
    #[error("{program}'s output contained invalid utf8: {inner}")]
    NftOutputEncoding {
        program: String,
        inner: FromUtf8Error,
    },
    #[error("got invalid json: {0}")]
    NftInvalidJson(serde_json::Error),
    #[error("{program} did not return successfully while {hint}")]
    NftFailed {
        program: String,
        hint: String,
        stdout: String,
        stderr: String,
    },
}

pub fn get_current_ruleset(
    program: Option<&str>,
    args: Option<&[&str]>,
) -> Result<Nftables, NftablesError> {
    let output = get_current_ruleset_raw(program, args)?;
    serde_json::from_str(&output).map_err(NftablesError::NftInvalidJson)
}

pub fn get_current_ruleset_raw(
    program: Option<&str>,
    args: Option<&[&str]>,
) -> Result<String, NftablesError> {
    let mut nft_cmd = get_command(program);
    let default_args = ["list", "ruleset"];
    let args = match args {
        Some(args) => args,
        None => &default_args,
    };
    let program = nft_cmd.get_program().to_str().unwrap().to_string();
    let process_result =
        nft_cmd
            .arg("-j")
            .args(args)
            .output()
            .map_err(|e| NftablesError::NftExecution {
                inner: e,
                program: program.clone(),
            })?;

    let stdout = read_output(&nft_cmd, process_result.stdout)?;

    if !process_result.status.success() {
        let stderr = read_output(&nft_cmd, process_result.stderr)?;

        return Err(NftablesError::NftFailed {
            program,
            hint: "getting the current ruleset".to_string(),
            stdout,
            stderr,
        });
    }
    Ok(stdout)
}

pub fn apply_ruleset(
    nftables: &Nftables,
    program: Option<&str>,
    args: Option<&[&str]>,
) -> Result<(), NftablesError> {
    let nftables = serde_json::to_string(nftables).expect("failed to serialize Nftables struct");
    apply_ruleset_raw(&nftables, program, args)
}

pub fn apply_ruleset_raw(
    payload: &str,
    program: Option<&str>,
    args: Option<&[&str]>,
) -> Result<(), NftablesError> {
    let mut nft_cmd = get_command(program);
    let default_args = ["-j", "-f", "-"];
    let program = nft_cmd.get_program().to_str().unwrap().to_string();
    let mut process = nft_cmd
        .args(args.into_iter().flatten())
        .args(default_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| NftablesError::NftExecution {
            program: program.clone(),
            inner: e,
        })?;

    let mut stdin = process.stdin.take().unwrap();
    stdin
        .write_all(payload.as_bytes())
        .map_err(|e| NftablesError::NftExecution {
            program: program.clone(),
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
                program,
                hint: "applying ruleset".to_string(),
                stdout,
                stderr,
            })
        }
        Err(e) => Err(NftablesError::NftExecution {
            program: nft_cmd.get_program().to_str().unwrap().to_string(),
            inner: e,
        }),
    }
}

fn get_command(program: Option<&str>) -> Command {
    let nft_executable: &str = program.unwrap_or(NFT_EXECUTABLE);
    Command::new(nft_executable)
}

fn read_output(cmd: &Command, bytes: Vec<u8>) -> Result<String, NftablesError> {
    String::from_utf8(bytes).map_err(|e| NftablesError::NftOutputEncoding {
        inner: e,
        program: cmd.get_program().to_str().unwrap().to_string(),
    })
}
