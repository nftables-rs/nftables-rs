use crate::schema::Nftables;
use schemars::schema_for;
use std::{env::args, fs, io::Read, process::exit};

/// Get command arguments.
///
/// This skips the first argument, because it is the program path itself.
pub fn collect_command_args() -> Vec<String> {
    args().skip(1).collect()
}

/// Dispatch command line arguments to commands.
pub fn handle_args(args: Vec<String>) {
    let mut args = args.into_iter();

    if let Some(command) = &args.next() {
        if command == "schema" {
            generate_json_schema(args.next().unwrap_or("./nftables.schema.json".to_string()));
            return;
        }
        eprintln!("Unknown command: `{command}`. Try again with the schema command to generate a JSON Schema or call with stdin only.");
        exit(1);
    }
    deserialize_stdin();
}

fn generate_json_schema(schema_dst_path: String) {
    let schema = schema_for!(Nftables);

    if let Err(err) = fs::write(
        schema_dst_path.clone(),
        serde_json::to_string_pretty(&schema).expect("Serde should serialize the document"),
    ) {
        eprintln!("Failed to write data to file: {err}");
        exit(1);
    }

    println!("Wrote schema data to: {schema_dst_path}");
}

/// Deserializes nftables JSON from the standard input and prints the result.
///
/// This is the default behavior when the executable is called without any
/// arguments.
fn deserialize_stdin() {
    use std::io;
    let mut buffer = String::new();

    match io::stdin().read_to_string(&mut buffer) {
        Err(error) => panic!("Problem opening the file: {error:?}"),
        Ok(_) => {
            println!("Document: {}", &buffer);

            let deserializer = &mut serde_json::Deserializer::from_str(&buffer);
            let result: Result<Nftables, _> = serde_path_to_error::deserialize(deserializer);

            match result {
                Ok(_) => println!("Result: {result:?}"),
                Err(err) => {
                    panic!("Deserialization error: {err}");
                }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::{env, fs};
    use tempfile::TempDir;

    #[test]
    // Use serial due to altering the value
    // of CWD
    #[serial]
    fn test_handle_args_schema_default_path() {
        let tmp_dir = TempDir::new().expect("Should create a temp dir inside `env::tmp_dir`");
        let path = tmp_dir.path().join("nftables.schema.json");

        // Little hack, to have "control" over the directory
        // in which the default file is created
        let cwd = env::current_dir().expect("Should get current dir");
        let _ = env::set_current_dir(tmp_dir.path());
        handle_args(vec!["schema".to_string()]);
        let _ = env::set_current_dir(cwd);

        assert!(fs::metadata(&path).is_ok());
    }

    #[test]
    fn test_handle_args_schema_custom_path() {
        let tmp_dir = TempDir::new().expect("Should create a temp dir inside `env::tmp_dir`");
        let path = tmp_dir.path().join("test_nftables.schema.json");
        handle_args(vec![
            "schema".to_string(),
            path.to_str().unwrap().to_string(),
        ]);

        assert!(fs::metadata(&path).is_ok());
    }

    #[test]
    fn test_generate_json_schema() {
        let tmp_dir = TempDir::new().expect("Should create a temp dir inside `env::tmp_dir`");
        let path = tmp_dir.path().join("nftables.schema.json");

        generate_json_schema(path.to_str().unwrap().to_string());

        assert!(fs::metadata(&path).is_ok());

        let content = fs::read_to_string(&path).unwrap();
        // Check if generated file contains JSON schema "$schema" field
        assert!(content.contains("$schema"));
        assert_eq!(
            content.to_string(),
            serde_json::to_string_pretty(&schema_for!(Nftables)).expect("")
        )
    }
}
