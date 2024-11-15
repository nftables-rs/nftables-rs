use nftables::{expr::*, schema::*, stmt::*, types::*};
use std::borrow::Cow;

#[test]
fn test_serialize() {
    let _a: Nftables = Nftables {
        objects: Cow::Borrowed(&[
            NfObject::CmdObject(NfCmd::Add(NfListObject::Table(Table {
                family: NfFamily::INet,
                name: Cow::Borrowed("namib"),
                handle: None,
            }))),
            NfObject::CmdObject(NfCmd::Add(NfListObject::Chain(Chain {
                family: NfFamily::INet,
                table: Cow::Borrowed("namib"),
                name: Cow::Borrowed("one_chain"),
                newname: None,
                handle: None,
                _type: Some(NfChainType::Filter),
                hook: Some(NfHook::Forward),
                prio: None,
                dev: None,
                policy: Some(NfChainPolicy::Accept),
            }))),
            NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(Rule {
                family: NfFamily::INet,
                table: Cow::Borrowed("namib"),
                chain: Cow::Borrowed("one_chain"),
                expr: Cow::Borrowed(&[
                    Statement::Match(Match {
                        left: Expression::List(Cow::Borrowed(&[
                            Expression::Number(123),
                            Expression::String(Cow::Borrowed("asd")),
                        ])),
                        right: Expression::Named(NamedExpression::CT(CT {
                            key: Cow::Borrowed("state"),
                            family: None,
                            dir: None,
                        })),
                        op: Operator::EQ,
                    }),
                    Statement::Drop(Some(Drop {})),
                ]),
                handle: None,
                index: None,
                comment: None,
            }))),
        ]),
    };

    let j = serde_json::to_string(&_a).unwrap();
    let result: Nftables = serde_json::from_str(&j).unwrap();
    println!("JSON: {}", j);
    println!("Parsed: {:?}", result);
}
