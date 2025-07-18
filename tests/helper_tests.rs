use std::{borrow::Cow, vec};

use nftables::{
    batch::Batch,
    expr,
    helper::{self, NftablesError},
    schema::{self, Chain, Rule, Table},
    stmt, types,
};
use serial_test::serial;

#[test]
#[ignore]
#[serial]
/// Reads current ruleset from nftables and reads it to `Nftables` Rust struct.
fn test_list_ruleset() {
    flush_ruleset().expect("failed to flush ruleset");
    helper::get_current_ruleset().unwrap();
}

#[test]
#[ignore]
/// Attempts to read current ruleset from nftables using non-existing nft binary.
fn test_list_ruleset_invalid_program() {
    let result = helper::get_current_ruleset_with_args(Some("/dev/null/nft"), helper::DEFAULT_ARGS);
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
    nftables::helper::apply_ruleset(&ruleset).unwrap();
    // nft should return two list object: metainfo and the set/map
    let applied = helper::get_current_ruleset_with_args(
        helper::DEFAULT_NFT,
        ["list", "map", "ip", "test-table-01", "test_map"],
    )
    .unwrap();
    assert_eq!(2, applied.objects.len());
    let applied = helper::get_current_ruleset_with_args(
        helper::DEFAULT_NFT,
        ["list", "set", "ip", "test-table-01", "test_set"],
    )
    .unwrap();
    assert_eq!(2, applied.objects.len());
}

#[test]
#[ignore]
#[serial]
/// Test that AnonymousCounter can be applied with [Option::None] values.
fn test_regr_anoncounter_none() {
    flush_ruleset().expect("failed to flush ruleset");
    let mut batch = Batch::new();
    // create table "test-table-02" and chain "test-chain-02".
    let table_name: &'static str = "test-table-02";
    batch.add(schema::NfListObject::Table(Table {
        name: table_name.into(),
        family: types::NfFamily::IP,
        ..Table::default()
    }));
    batch.add(schema::NfListObject::Chain(Chain {
        name: "test-chain-02".into(),
        family: types::NfFamily::IP,
        table: table_name.into(),
        ..Chain::default()
    }));
    // create rule with multiple forms of [nftables::stmt::AnonymousCounter].
    batch.add(schema::NfListObject::Rule(Rule {
        chain: "test-chain-02".into(),
        family: types::NfFamily::IP,
        table: table_name.into(),
        expr: [
            stmt::Statement::Counter(nftables::stmt::Counter::Anonymous(Some(
                nftables::stmt::AnonymousCounter {
                    packets: None,
                    bytes: None,
                },
            ))),
            stmt::Statement::Counter(nftables::stmt::Counter::Anonymous(Some(
                nftables::stmt::AnonymousCounter {
                    packets: Some(0),
                    bytes: Some(0),
                },
            ))),
        ][..]
            .into(),
        ..Rule::default()
    }));
    let ruleset = batch.to_nftables();

    let result = nftables::helper::apply_ruleset(&ruleset);
    assert!(result.is_ok());
}

#[test]
#[ignore]
#[serial]
/// Applies a ruleset to nftables.
fn test_apply_ruleset() {
    flush_ruleset().expect("failed to flush ruleset");
    let ruleset = example_ruleset(true);
    nftables::helper::apply_ruleset(&ruleset).unwrap();
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
        name: "i-do-not-exist".into(),
        ..Table::default()
    }));
    let ruleset = batch.to_nftables();

    let result = nftables::helper::apply_ruleset(&ruleset);
    let err = result.expect_err("Expecting nftables error for unknown table.");
    assert!(matches!(err, NftablesError::NftFailed { .. }));
}

fn example_ruleset(with_undo: bool) -> schema::Nftables<'static> {
    let mut batch = Batch::new();
    // create table "test-table-01"
    let table_name: &'static str = "test-table-01";
    batch.add(schema::NfListObject::Table(Table {
        name: table_name.into(),
        family: types::NfFamily::IP,
        ..Table::default()
    }));
    // create named set "test_set"
    let set_name = "test_set";
    batch.add(schema::NfListObject::Set(Box::new(schema::Set {
        family: types::NfFamily::IP,
        table: table_name.into(),
        name: set_name.into(),
        set_type: schema::SetTypeValue::Single(schema::SetType::Ipv4Addr),
        ..schema::Set::default()
    })));
    // create named map "test_map"
    batch.add(schema::NfListObject::Map(Box::new(schema::Map {
        family: types::NfFamily::IP,
        table: table_name.into(),
        name: "test_map".into(),
        map: schema::SetTypeValue::Single(schema::SetType::EtherAddr),
        set_type: schema::SetTypeValue::Single(schema::SetType::Ipv4Addr),
        ..schema::Map::default()
    })));
    // add element to set
    batch.add(schema::NfListObject::Element(schema::Element {
        family: types::NfFamily::IP,
        table: table_name.into(),
        name: set_name.into(),
        elem: Cow::Owned(vec![
            expr::Expression::String("127.0.0.1".into()),
            expr::Expression::String("127.0.0.2".into()),
        ]),
    }));
    if with_undo {
        batch.delete(schema::NfListObject::Table(schema::Table {
            family: types::NfFamily::IP,
            name: "test-table-01".into(),
            ..Table::default()
        }));
    }
    batch.to_nftables()
}

fn get_flush_ruleset() -> schema::Nftables<'static> {
    let mut batch = Batch::new();
    batch.add_cmd(schema::NfCmd::Flush(schema::FlushObject::Ruleset(None)));
    batch.to_nftables()
}

fn flush_ruleset() -> Result<(), NftablesError> {
    let ruleset = get_flush_ruleset();
    nftables::helper::apply_ruleset(&ruleset)
}
