use std::{fs::File, io::BufReader, path::Path};

use nftables::schema::Nftables;
use serde::de::Error;

fn test_deserialize_json_files(path: &Path) -> datatest_stable::Result<()> {
    println!("Deserializing file: {}", path.display());
    let file = File::open(path).expect("Cannot open file");
    let reader = BufReader::new(file);

    let jd = &mut serde_json::Deserializer::from_reader(reader);
    let result: Result<Nftables, _> = serde_path_to_error::deserialize(jd);

    match result {
        Ok(nf) => {
            println!("Deserialized document: {:?}", nf);
            Ok(())
        }
        Err(err) => Err(serde_json::error::Error::custom(format!(
            "Path: {}. Original error: {}",
            err.path(),
            err
        ))
        .into()),
    }
}

datatest_stable::harness! {
    {test = test_deserialize_json_files, root = "resources/test/json", pattern = r"^.*/*"},
}
