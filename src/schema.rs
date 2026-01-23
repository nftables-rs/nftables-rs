use schemars::JsonSchema;
use std::{borrow::Cow, collections::HashSet};

use crate::visitor::deserialize_optional_flags;
use crate::{
    expr::Expression, stmt::Statement, types::*, visitor::single_string_to_option_vec,
    DEFAULT_CHAIN, DEFAULT_FAMILY, DEFAULT_TABLE,
};

use serde::{Deserialize, Serialize};

use strum_macros::EnumString;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// In general, any JSON input or output is enclosed in an object with a single property named **nftables**.
///
/// See [libnftables-json global structure](Global Structure).
///
/// (Global Structure): <https://manpages.debian.org/testing/libnftables1/libnftables-json.5.en.html#GLOBAL_STRUCTURE>
pub struct Nftables<'a> {
    /// An array containing [commands](NfCmd) (for input) or [ruleset elements](NfListObject) (for output).
    #[serde(rename = "nftables")]
    pub objects: Cow<'a, [NfObject<'a>]>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
/// A [ruleset element](NfListObject) or [command](NfCmd) in an [nftables document](Nftables).
pub enum NfObject<'a> {
    /// A command.
    CmdObject(NfCmd<'a>),
    /// A ruleset element.
    ListObject(NfListObject<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// A ruleset element in an [nftables document](Nftables).
pub enum NfListObject<'a> {
    /// A table element.
    Table(Table<'a>),
    /// A chain element.
    Chain(Chain<'a>),
    /// A rule element.
    Rule(Rule<'a>),
    /// A set element.
    Set(Box<Set<'a>>),
    /// A map element.
    Map(Box<Map<'a>>),
    /// An element manipulation.
    Element(Element<'a>),
    /// A flow table.
    FlowTable(FlowTable<'a>),
    /// A counter.
    Counter(Counter<'a>),
    /// A quota.
    Quota(Quota<'a>),
    #[serde(rename = "ct helper")]
    /// A conntrack helper (ct helper).
    CTHelper(CTHelper<'a>),
    /// A limit.
    Limit(Limit<'a>),
    #[serde(rename = "metainfo")]
    /// The metainfo object.
    MetainfoObject(MetainfoObject<'a>),
    /// A conntrack timeout (ct timeout).
    CTTimeout(CTTimeout<'a>),
    #[serde(rename = "ct expectation")]
    /// A conntrack expectation (ct expectation).
    CTExpectation(CTExpectation<'a>),
    /// A synproxy object.
    SynProxy(SynProxy<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// A command is an object with a single property whose name identifies the command.
///
/// Its value is a ruleset element - basically identical to output elements,
/// apart from certain properties which may be interpreted differently or are
/// required when output generally omits them.
pub enum NfCmd<'a> {
    /// Add a new ruleset element to the kernel.
    Add(NfListObject<'a>),
    /// Replace a rule.
    ///
    /// In [RULE](Rule), the **handle** property is mandatory and identifies
    /// the rule to be replaced.
    Replace(Rule<'a>),
    /// Identical to [add command](NfCmd::Add), but returns an error if the object already exists.
    Create(NfListObject<'a>), // TODO: ADD_OBJECT is subset of NfListObject
    /// Insert an object.
    ///
    /// This command is identical to [add](NfCmd::Add) for rules, but instead of
    /// appending the rule to the chain by default, it inserts at first position.
    /// If a handle or index property is given, the rule is inserted before the
    /// rule identified by those properties.
    Insert(NfListObject<'a>),
    /// Delete an object from the ruleset.
    ///
    /// Only the minimal number of properties required to uniquely identify an
    /// object is generally needed in the enclosed object.
    /// For most ruleset elements, this is **family** and **table** plus either
    /// **handle** or **name** (except rules since they don’t have a name).
    Delete(NfListObject<'a>), // TODO: ADD_OBJECT is subset of NfListObject
    /// List ruleset elements.
    ///
    /// The plural forms are used to list all objects of that kind,
    /// optionally filtered by family and for some, also table.
    List(NfListObject<'a>),
    /// Reset state in suitable objects, i.e. zero their internal counter.
    Reset(ResetObject<'a>),
    /// Empty contents in given object, e.g. remove all chains from given table
    /// or remove all elements from given set.
    Flush(FlushObject<'a>),
    /// Rename a [chain](Chain).
    ///
    /// The new name is expected in a dedicated property named **newname**.
    Rename(Chain<'a>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Reset state in suitable objects, i.e. zero their internal counter.
pub enum ResetObject<'a> {
    /// A counter to reset.
    Counter(Counter<'a>),
    /// A list of counters to reset.
    Counters(Cow<'a, [Counter<'a>]>),
    /// A quota to reset.
    Quota(Quota<'a>),
    /// A list of quotas to reset.
    Quotas(Cow<'a, [Quota<'a>]>),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Empty contents in given object, e.g. remove all chains from given table or remove all elements from given set.
pub enum FlushObject<'a> {
    /// A table to flush (i.e., remove all chains from table).
    Table(Table<'a>),
    /// A chain to flush (i.e., remove all rules from chain).
    Chain(Chain<'a>),
    /// A set to flush (i.e., remove all elements from set).
    Set(Box<Set<'a>>),
    /// A map to flush (i.e., remove all elements from map).
    Map(Box<Map<'a>>),
    /// A meter to flush.
    Meter(Meter<'a>),
    /// Flush the live ruleset (i.e., remove all elements from live ruleset).
    Ruleset(Option<Ruleset>),
}

// Ruleset Elements

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// This object describes a table.
pub struct Table<'a> {
    /// The table’s [family](NfFamily), e.g. "ip" or "ip6".
    pub family: NfFamily,
    /// The table’s name.
    pub name: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The table’s handle.
    ///
    /// In input, it is used only in [delete command](NfCmd::Delete) as
    /// alternative to **name**.
    pub handle: Option<u32>,
}

/// Default table.
impl Default for Table<'_> {
    fn default() -> Self {
        Table {
            family: DEFAULT_FAMILY,
            name: DEFAULT_TABLE.into(),
            handle: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// This object describes a chain.
pub struct Chain<'a> {
    /// The table’s family.
    pub family: NfFamily,
    /// The table’s name.
    pub table: Cow<'a, str>,
    /// The chain’s name.
    pub name: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// New name of the chain when supplied to the [rename command](NfCmd::Rename).
    pub newname: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The chain’s handle.
    /// In input, it is used only in [delete command](NfCmd::Delete) as alternative to **name**.
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "type")]
    /// The chain’s type.
    /// Required for [base chains](Base chains).
    ///
    /// (Base chains): <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Adding_base_chains>
    pub _type: Option<NfChainType>, // type
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The chain’s hook.
    /// Required for [base chains](Base chains).
    ///
    /// (Base chains): <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Adding_base_chains>
    pub hook: Option<NfHook>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The chain’s priority.
    /// Required for [base chains](Base chains).
    ///
    /// (Base chains): <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Adding_base_chains>
    pub prio: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The chain’s bound interface (if in the netdev family).
    /// Required for [base chains](Base chains).
    ///
    /// (Base chains): <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Adding_base_chains>
    pub dev: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The chain’s [policy](NfChainPolicy).
    /// Required for [base chains](Base chains).
    ///
    /// (Base chains): <https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains#Adding_base_chains>
    pub policy: Option<NfChainPolicy>,
}

/// Default Chain.
impl Default for Chain<'_> {
    fn default() -> Self {
        Chain {
            family: DEFAULT_FAMILY,
            table: DEFAULT_TABLE.into(),
            name: DEFAULT_CHAIN.into(),
            newname: None,
            handle: None,
            _type: None,
            hook: None,
            prio: None,
            dev: None,
            policy: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// This object describes a rule.
///
/// Basic building blocks of rules are statements.
/// Each rule consists of at least one.
pub struct Rule<'a> {
    /// The table’s family.
    pub family: NfFamily,
    /// The table’s name.
    pub table: Cow<'a, str>,
    /// The chain’s name.
    pub chain: Cow<'a, str>,
    #[serde(default)]
    /// An array of statements this rule consists of.
    ///
    /// In input, it is used in [add](NfCmd::Add)/[insert](NfCmd::Insert)/[replace](NfCmd::Replace) commands only.
    pub expr: Cow<'a, [Statement<'a>]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The rule’s handle.
    ///
    /// In [delete](NfCmd::Delete)/[replace](NfCmd::Replace) commands, it serves as an identifier of the rule to delete/replace.
    /// In [add](NfCmd::Add)/[insert](NfCmd::Insert) commands, it serves as an identifier of an existing rule to append/prepend the rule to.
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The rule’s position for [add](NfCmd::Add)/[insert](NfCmd::Insert) commands.
    ///
    /// It is used as an alternative to **handle** then.
    pub index: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional rule comment.
    pub comment: Option<Cow<'a, str>>,
}

/// Default rule with no expressions.
impl Default for Rule<'_> {
    fn default() -> Self {
        Rule {
            family: DEFAULT_FAMILY,
            table: DEFAULT_TABLE.into(),
            chain: DEFAULT_CHAIN.into(),
            expr: [][..].into(),
            handle: None,
            index: None,
            comment: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// Named set that holds expression elements.
pub struct Set<'a> {
    /// The table’s family.
    pub family: NfFamily,
    /// The table’s name.
    pub table: Cow<'a, str>,
    /// The set’s name.
    pub name: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The set’s handle. For input, it is used by the [delete command](NfCmd::Delete) only.
    pub handle: Option<u32>,
    #[serde(rename = "type")]
    /// The set’s datatype.
    ///
    /// The set type might be a string, such as `"ipv4_addr"` or an array consisting of strings (for concatenated types).
    pub set_type: SetTypeValue<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The set’s policy.
    pub policy: Option<SetPolicy>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_flags",
        default
    )]
    /// The set’s flags.
    pub flags: Option<HashSet<SetFlag>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Initial set element(s).
    ///
    /// A single set element might be given as string, integer or boolean value for simple cases. If additional properties are required, a formal elem object may be used.
    /// Multiple elements may be given in an array.
    pub elem: Option<Cow<'a, [Expression<'a>]>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Element timeout in seconds.
    pub timeout: Option<u32>,
    #[serde(rename = "gc-interval", skip_serializing_if = "Option::is_none")]
    /// Garbage collector interval in seconds.
    pub gc_interval: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Maximum number of elements supported.
    pub size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional set comment.
    ///
    /// Set comment attribute requires at least nftables 0.9.7 and kernel 5.10
    pub comment: Option<Cow<'a, str>>,
}

/// Default set `"myset"` with type `ipv4_addr`.
impl Default for Set<'_> {
    fn default() -> Self {
        Set {
            family: DEFAULT_FAMILY,
            table: DEFAULT_TABLE.into(),
            name: "myset".into(),
            handle: None,
            set_type: SetTypeValue::Single(SetType::Ipv4Addr),
            policy: None,
            flags: None,
            elem: None,
            timeout: None,
            gc_interval: None,
            size: None,
            comment: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// Named map that holds expression elements.
/// Maps are a special form of sets in that they translate a unique key to a value.
pub struct Map<'a> {
    /// The table’s family.
    pub family: NfFamily,
    /// The table’s name.
    pub table: Cow<'a, str>,
    /// The map’s name.
    pub name: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The map’s handle. For input, it is used by the [delete command](NfCmd::Delete) only.
    pub handle: Option<u32>,
    #[serde(rename = "type")]
    /// The map set’s datatype.
    ///
    /// The set type might be a string, such as `"ipv4_addr"`` or an array
    /// consisting of strings (for concatenated types).
    pub set_type: SetTypeValue<'a>,
    /// Type of values this set maps to (i.e. this set is a map).
    pub map: SetTypeValue<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The map’s policy.
    pub policy: Option<SetPolicy>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_flags",
        default
    )]
    /// The map’s flags.
    pub flags: Option<HashSet<SetFlag>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Initial map set element(s).
    ///
    /// A single set element might be given as string, integer or boolean value for simple cases. If additional properties are required, a formal elem object may be used.
    /// Multiple elements may be given in an array.
    pub elem: Option<Cow<'a, [Expression<'a>]>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Element timeout in seconds.
    pub timeout: Option<u32>,
    #[serde(rename = "gc-interval", skip_serializing_if = "Option::is_none")]
    /// Garbage collector interval in seconds.
    pub gc_interval: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Maximum number of elements supported.
    pub size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional map comment.
    ///
    /// The map/set comment attribute requires at least nftables 0.9.7 and kernel 5.10
    pub comment: Option<Cow<'a, str>>,
}

/// Default map "mymap" that maps ipv4addrs.
impl Default for Map<'_> {
    fn default() -> Self {
        Map {
            family: DEFAULT_FAMILY,
            table: DEFAULT_TABLE.into(),
            name: "mymap".into(),
            handle: None,
            set_type: SetTypeValue::Single(SetType::Ipv4Addr),
            map: SetTypeValue::Single(SetType::Ipv4Addr),
            policy: None,
            flags: None,
            elem: None,
            timeout: None,
            gc_interval: None,
            size: None,
            comment: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
/// Wrapper for single or concatenated set types.
/// The set type might be a string, such as `"ipv4_addr"` or an array consisting of strings (for concatenated types).
pub enum SetTypeValue<'a> {
    /// Single set type.
    Single(SetType),
    /// Concatenated set types.
    Concatenated(Cow<'a, [SetType]>),
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, EnumString, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
/// Describes a set’s datatype.
pub enum SetType {
    #[serde(rename = "ipv4_addr")]
    #[strum(serialize = "ipv4_addr")]
    /// IPv4 address.
    Ipv4Addr,
    #[serde(rename = "ipv6_addr")]
    #[strum(serialize = "ipv6_addr")]
    /// IPv6 address.
    Ipv6Addr,
    #[serde(rename = "ether_addr")]
    #[strum(serialize = "ether_addr")]
    /// Ethernet address.
    EtherAddr,
    #[serde(rename = "inet_proto")]
    #[strum(serialize = "inet_proto")]
    /// Internet protocol type.
    InetProto,
    #[serde(rename = "inet_service")]
    #[strum(serialize = "inet_service")]
    /// Internet service.
    InetService,
    #[serde(rename = "mark")]
    #[strum(serialize = "mark")]
    /// Mark type.
    Mark,
    #[serde(rename = "ifname")]
    #[strum(serialize = "ifname")]
    /// Network interface name (eth0, eth1..).
    Ifname,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Describes a set’s policy.
pub enum SetPolicy {
    /// Performance policy (default).
    Performance,
    /// Memory policy.
    Memory,
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, EnumString, Hash, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
/// Describes a [set](Set)’s flags.
pub enum SetFlag {
    /// Set content may not change while bound.
    Constant,
    /// Set contains intervals.
    Interval,
    /// Elements can be added with a timeout.
    Timeout,
    // TODO: undocumented upstream
    /// *Undocumented flag.*
    Dynamic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Describes an operator on set.
pub enum SetOp {
    /// Operator for adding elements.
    Add,
    /// Operator for updating elements.
    Update,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// Manipulate element(s) in a named set.
pub struct Element<'a> {
    /// The table’s family.
    pub family: NfFamily,
    /// The table’s name.
    pub table: Cow<'a, str>,
    /// The set’s name.
    pub name: Cow<'a, str>,
    /// A single set element might be given as string, integer or boolean value for simple cases.
    /// If additional properties are required, a formal `elem` object may be used.
    /// Multiple elements may be given in an array.
    pub elem: Cow<'a, [Expression<'a>]>,
}

/// Default manipulation element for [set](Set) "myset".
impl Default for Element<'_> {
    fn default() -> Self {
        Element {
            family: DEFAULT_FAMILY,
            table: DEFAULT_TABLE.into(),
            name: "myset".into(),
            elem: [][..].into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// [Flowtables] allow you to accelerate packet forwarding in software (and in hardware if your NIC supports it)
/// by using a conntrack-based network stack bypass.
///
/// [Flowtables]: https://wiki.nftables.org/wiki-nftables/index.php/Flowtables
pub struct FlowTable<'a> {
    /// The [table](Table)’s family.
    pub family: NfFamily,
    /// The [table](Table)’s name.
    pub table: Cow<'a, str>,
    /// The flow table’s name.
    pub name: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The flow table’s handle. In input, it is used by the [delete command](NfCmd::Delete) only.
    pub handle: Option<u32>,
    /// The flow table’s [hook](NfHook).
    pub hook: Option<NfHook>,
    /// The flow table's *priority* can be a signed integer or *filter* which stands for 0.
    /// Addition and subtraction can be used to set relative priority, e.g., filter + 5 is equal to 5.
    pub prio: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "single_string_to_option_vec"
    )]
    /// The *devices* are specified as iifname(s) of the input interface(s) of the traffic that should be offloaded.
    ///
    /// Devices are required for both traffic directions.
    /// Cow slice of device names, e.g. `vec!["wg0".into(), "wg1".into()].into()`.
    pub dev: Option<Cow<'a, [Cow<'a, str>]>>,
}

/// Default [flowtable](FlowTable) named "myflowtable".
impl Default for FlowTable<'_> {
    fn default() -> Self {
        FlowTable {
            family: DEFAULT_FAMILY,
            table: DEFAULT_TABLE.into(),
            name: "myflowtable".into(),
            handle: None,
            hook: None,
            prio: None,
            dev: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// This object represents a named [counter].
///
/// A counter counts both the total number of packets and the total bytes it has seen since it was last reset.
/// With nftables you need to explicitly specify a counter for each rule you want to count.
///
/// [counter]: https://wiki.nftables.org/wiki-nftables/index.php/Counters
pub struct Counter<'a> {
    /// The [table](Table)’s family.
    pub family: NfFamily,
    /// The [table](Table)’s name.
    pub table: Cow<'a, str>,
    /// The counter’s name.
    pub name: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The counter’s handle. In input, it is used by the [delete command](NfCmd::Delete) only.
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Packet counter value.
    pub packets: Option<u32>,
    /// Byte counter value.
    pub bytes: Option<u32>,
}

/// Default [counter](Counter) named "mycounter".
impl Default for Counter<'_> {
    fn default() -> Self {
        Counter {
            family: DEFAULT_FAMILY,
            table: DEFAULT_TABLE.into(),
            name: "mycounter".into(),
            handle: None,
            packets: None,
            bytes: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// This object represents a named [quota](Quota).
///
/// A quota:
/// * defines a threshold number of bytes;
/// * sets an initial byte count (defaults to 0 bytes if not specified);
/// * counts the total number of bytes, starting from the initial count; and
/// * matches either:
///     * only until the byte count exceeds the threshold, or
///     * only after the byte count is over the threshold.
///
/// (Quota): <https://wiki.nftables.org/wiki-nftables/index.php/Quotas>
pub struct Quota<'a> {
    /// The [table](Table)’s family.
    pub family: NfFamily,
    /// The [table](Table)’s name.
    pub table: Cow<'a, str>,
    /// The quota’s name.
    pub name: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The quota’s handle. In input, it is used by the [delete command](NfCmd::Delete) only.
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Quota threshold.
    pub bytes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Quota used so far.
    pub used: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// If `true`, match if the quota has been exceeded (i.e., "invert" the quota).
    pub inv: Option<bool>,
}

/// Default [quota](Quota) named "myquota".
impl Default for Quota<'_> {
    fn default() -> Self {
        Quota {
            family: DEFAULT_FAMILY,
            table: DEFAULT_TABLE.into(),
            name: "myquota".into(),
            handle: None,
            bytes: None,
            used: None,
            inv: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "ct helper")]
/// Enable the specified [conntrack helper][Conntrack helpers] for this packet.
///
/// [Conntrack helpers]: <https://wiki.nftables.org/wiki-nftables/index.php/Conntrack_helpers>
pub struct CTHelper<'a> {
    /// The [table](Table)’s family.
    pub family: NfFamily,
    /// The [table](Table)’s name.
    pub table: Cow<'a, str>,
    /// The ct helper’s name.
    pub name: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The ct helper’s handle. In input, it is used by the [delete command](NfCmd::Delete) only.
    pub handle: Option<u32>,
    #[serde(rename = "type")]
    /// The ct helper type name, e.g. "ftp" or "tftp".
    pub _type: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The ct helper’s layer 4 protocol.
    pub protocol: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The ct helper’s layer 3 protocol, e.g. "ip" or "ip6".
    pub l3proto: Option<Cow<'a, str>>,
}

/// Default ftp [ct helper](CTHelper) named "mycthelper".
impl Default for CTHelper<'_> {
    fn default() -> Self {
        CTHelper {
            family: DEFAULT_FAMILY,
            table: DEFAULT_TABLE.into(),
            name: "mycthelper".into(),
            handle: None,
            _type: "ftp".into(),
            protocol: None,
            l3proto: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// This object represents a named [limit](Limit).
///
/// A limit uses a [token bucket](Token bucket) filter to match packets:
/// * only until its rate is exceeded; or
/// * only after its rate is exceeded, if defined as an over limit.
///
/// (Limit): <https://wiki.nftables.org/wiki-nftables/index.php/Limits>
/// (Token bucket): <https://en.wikipedia.org/wiki/Token_bucket>
pub struct Limit<'a> {
    /// The [table](Table)’s family.
    pub family: NfFamily,
    /// The [table](Table)’s name.
    pub table: Cow<'a, str>,
    /// The limit’s name.
    pub name: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The limit’s handle. In input, it is used by the [delete command](NfCmd::Delete) only.
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The limit’s rate value.
    pub rate: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Time unit to apply the limit to, e.g. "week", "day", "hour", etc.
    ///
    /// If omitted, defaults to "second".
    pub per: Option<NfTimeUnit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The limit’s burst value. If omitted, defaults to 0.
    pub burst: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [Unit](LimitUnit) of rate and burst values. If omitted, defaults to "packets".
    pub unit: Option<LimitUnit>,
    /// If `true`, match if limit was exceeded. If omitted, defaults to `false`.
    pub inv: Option<bool>,
}

/// Default [limit](Limit) named "mylimit".
impl Default for Limit<'_> {
    fn default() -> Self {
        Limit {
            family: DEFAULT_FAMILY,
            table: DEFAULT_TABLE.into(),
            name: "mylimit".into(),
            handle: None,
            rate: None,
            per: None,
            burst: None,
            unit: None,
            inv: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// A unit used in [limits](Limit).
pub enum LimitUnit {
    /// Limit by number of packets.
    Packets,
    /// Limit by number of bytes.
    Bytes,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Meter<'a> {
    pub name: Cow<'a, str>,
    pub key: Expression<'a>,
    pub stmt: Box<Statement<'a>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// Represents the live ruleset (to be [flushed](NfCmd::Flush)).
pub struct Ruleset {}

/// Default ruleset.
impl Default for Ruleset {
    fn default() -> Self {
        Ruleset {}
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// Library information in output.
///
/// In output, the first object in an nftables array is a special one containing library information.
pub struct MetainfoObject<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The value of version property is equal to the package version as printed by `nft -v`.
    pub version: Option<Cow<'a, str>>,
    /// The value of release_name property is equal to the release name as printed by `nft -v`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_name: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The JSON Schema version.
    ///
    /// If supplied in (libnftables) library input, the parser will verify the
    /// `json_schema_version` value to not exceed the internally hardcoded one
    /// (to make sure the given schema is fully understood).
    /// In future, a lower number than the internal one may activate
    /// compatibility mode to parse outdated and incompatible JSON input.
    pub json_schema_version: Option<u32>,
}

/// Default (empty) [metainfo object](MetainfoObject).
impl Default for MetainfoObject<'_> {
    fn default() -> Self {
        MetainfoObject {
            version: None,
            release_name: None,
            json_schema_version: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// This object represents a named [conntrack timeout][Ct timeout] policy.
///
/// You can use a ct timeout object to specify a connection tracking timeout policy for a particular flow.
///
/// [Ct timeout]: <https://wiki.nftables.org/wiki-nftables/index.php/Ct_timeout>
pub struct CTTimeout<'a> {
    /// The table’s family.
    pub family: NfFamily,
    /// The table’s name.
    pub table: Cow<'a, str>,
    /// The ct timeout object’s name.
    pub name: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The ct timeout object’s handle. In input, it is used by the [delete command](NfCmd::Delete) only.
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The ct timeout object’s [layer 4 protocol](CTHProto).
    pub protocol: Option<CTHProto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The connection state name, e.g. "established", "syn_sent", "close" or "close_wait", for which the timeout value has to be updated.
    pub state: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The updated timeout value for the specified connection state.
    pub value: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The ct timeout object’s layer 3 protocol, e.g. "ip" or "ip6".
    pub l3proto: Option<Cow<'a, str>>,
}

/// Default [ct timeout](CTTimeout) named "mycttimeout"
impl Default for CTTimeout<'_> {
    fn default() -> Self {
        CTTimeout {
            family: DEFAULT_FAMILY,
            table: DEFAULT_TABLE.into(),
            name: "mycttimeout".into(),
            handle: None,
            protocol: None,
            state: None,
            value: None,
            l3proto: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// This object represents a named [conntrack expectation][Ct expectation].
///
/// [Ct expectation]: <https://wiki.nftables.org/wiki-nftables/index.php/Ct_expectation>
pub struct CTExpectation<'a> {
    /// The table’s family.
    pub family: NfFamily,
    /// The table’s name.
    pub table: Cow<'a, str>,
    /// The ct expectation object’s name.
    pub name: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The ct expectation object’s handle. In input, it is used by delete command only.
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The ct expectation object’s layer 3 protocol, e.g. "ip" or "ip6".
    pub l3proto: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The ct expectation object’s layer 4 protocol.
    pub protocol: Option<CTHProto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The destination port of the expected connection.
    pub dport: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The time in millisecond that this expectation will live.
    pub timeout: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The maximum count of expectations to be living in the same time.
    pub size: Option<u32>,
}

/// [SynProxy] intercepts new TCP connections and handles the initial 3-way handshake using
/// syncookies instead of conntrack to establish the connection.
///
/// Named SynProxy requires **nftables 0.9.3 or newer**.
///
/// [SynProxy]: https://wiki.nftables.org/wiki-nftables/index.php/Synproxy
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SynProxy<'a> {
    /// The table’s family.
    pub family: NfFamily,
    /// The table’s name.
    pub table: Cow<'a, str>,
    /// The synproxy's name.
    pub name: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The synproxy's handle. For input, it is used by the [delete command](NfCmd::Delete) only.
    pub handle: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The maximum segment size (must match your backend server).
    pub mss: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The window scale (must match your backend server).
    pub wscale: Option<u8>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_flags",
        default
    )]
    /// The synproxy's [flags](crate::types::SynProxyFlag).
    pub flags: Option<HashSet<SynProxyFlag>>,
}
