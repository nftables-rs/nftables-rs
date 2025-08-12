use std::{fs::File, io::BufReader};

use nftables::schema::Nftables;

// nft 1.1.4 changed behavior where the flag is printed as single string instead of array
// As such this lib should be able to parse both and return the same result.
// https://bugzilla.netfilter.org/show_bug.cgi?id=1806
#[test]
fn test_parse_fib_flags() {
    let file1 = BufReader::new(
        File::open("resources/test/fixtures/single-fib-flag-1.json").expect("Cannot open file1"),
    );
    let json1: Nftables =
        serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_reader(file1))
            .expect("failed to parse json1");

    let file2 = BufReader::new(
        File::open("resources/test/fixtures/single-fib-flag-2.json").expect("Cannot open file2"),
    );

    let json2: Nftables =
        serde_path_to_error::deserialize(&mut serde_json::Deserializer::from_reader(file2))
            .expect("failed to parse json2");

    assert_eq!(json1, json2, "Both parsed files should be identical")
}
