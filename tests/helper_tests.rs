use std::vec;

use nftables::{
    batch::Batch,
    expr,
    helper::{self, NftablesError},
    schema::{self, Table},
    types,
};
use serial_test::serial;

#[test]
#[ignore]
#[serial]
/// Reads current ruleset from nftables and reads it to `Nftables` Rust struct.
fn test_list_ruleset() {
    flush_ruleset().expect("failed to flush ruleset");
    helper::get_current_ruleset(None, None).unwrap();
}

#[test]
#[ignore]
/// Attempts to read current ruleset from nftables using non-existing nft binary.
fn test_list_ruleset_invalid_program() {
    let result = helper::get_current_ruleset(Some("/dev/null/nft"), None);
    let err =
        result.expect_err("getting the current ruleset should fail with non-existing nft binary");
    assert!(matches!(err, NftablesError::NftExecution { .. }));
}

#[test]
#[ignore]
#[serial]
/// Applies an example ruleset to nftables, lists single map/set through nft args.
fn test_nft_args_list_map_set() {
    flush_ruleset().expect("failed to flush ruleset");
    let ruleset = example_ruleset(false);
    nftables::helper::apply_ruleset(&ruleset, None, None).unwrap();
    // nft should return two list object: metainfo and the set/map
    let applied = helper::get_current_ruleset(
        None,
        Some(&["list", "map", "ip", "test-table-01", "test_map"]),
    )
    .unwrap();
    assert_eq!(2, applied.objects.len());
    let applied = helper::get_current_ruleset(
        None,
        Some(&["list", "set", "ip", "test-table-01", "test_set"]),
    )
    .unwrap();
    assert_eq!(2, applied.objects.len());
}

#[test]
#[ignore]
#[serial]
/// Applies a ruleset to nftables.
fn test_apply_ruleset() {
    flush_ruleset().expect("failed to flush ruleset");
    let ruleset = example_ruleset(true);
    nftables::helper::apply_ruleset(&ruleset, None, None).unwrap();
}

#[test]
#[ignore]
#[serial]
/// Attempts to delete an unknown table, expecting an error.
fn test_remove_unknown_table() {
    flush_ruleset().expect("failed to flush ruleset");
    let mut batch = Batch::new();
    batch.delete(schema::NfListObject::Table(schema::Table {
        family: types::NfFamily::IP6,
        name: "i-do-not-exist".to_string(),
        ..Table::default()
    }));
    let ruleset = batch.to_nftables();

    let result = nftables::helper::apply_ruleset(&ruleset, None, None);
    let err = result.expect_err("Expecting nftables error for unknown table.");
    assert!(matches!(err, NftablesError::NftFailed { .. }));
}

fn example_ruleset(with_undo: bool) -> schema::Nftables {
    let mut batch = Batch::new();
    // create table "test-table-01"
    let table_name = "test-table-01".to_string();
    batch.add(schema::NfListObject::Table(Table {
        name: table_name.clone(),
        family: types::NfFamily::IP,
        ..Table::default()
    }));
    // create named set "test_set"
    let set_name = "test_set".to_string();
    batch.add(schema::NfListObject::Set(schema::Set {
        family: types::NfFamily::IP,
        table: table_name.clone(),
        name: set_name.clone(),
        handle: None,
        set_type: schema::SetTypeValue::Single(schema::SetType::Ipv4Addr),
        policy: None,
        flags: None,
        elem: None,
        timeout: None,
        gc_interval: None,
        size: None,
        comment: None,
    }));
    // create named map "test_map"
    batch.add(schema::NfListObject::Map(schema::Map {
        family: types::NfFamily::IP,
        table: table_name.clone(),
        name: "test_map".to_string(),
        handle: None,
        map: schema::SetTypeValue::Single(schema::SetType::EtherAddr),
        set_type: schema::SetTypeValue::Single(schema::SetType::Ipv4Addr),
        policy: None,
        flags: None,
        elem: None,
        timeout: None,
        gc_interval: None,
        size: None,
        comment: None,
    }));
    // add element to set
    batch.add(schema::NfListObject::Element(schema::Element {
        family: types::NfFamily::IP,
        table: table_name,
        name: set_name,
        elem: vec![
            expr::Expression::String("127.0.0.1".to_string()),
            expr::Expression::String("127.0.0.2".to_string()),
        ],
    }));
    if with_undo {
        batch.delete(schema::NfListObject::Table(schema::Table {
            family: types::NfFamily::IP,
            name: "test-table-01".to_string(),
            ..Table::default()
        }));
    }
    batch.to_nftables()
}

fn get_flush_ruleset() -> schema::Nftables {
    let mut batch = Batch::new();
    batch.add_cmd(schema::NfCmd::Flush(schema::FlushObject::Ruleset(None)));
    batch.to_nftables()
}

fn flush_ruleset() -> Result<(), NftablesError> {
    let ruleset = get_flush_ruleset();
    nftables::helper::apply_ruleset(&ruleset, None, None)
}
