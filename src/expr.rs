use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashSet};

use crate::stmt::{Counter, JumpTarget, Statement};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
/// Expressions are the building blocks of (most) [statements](crate::stmt::Statement).
/// In their most basic form, they are just immediate values represented as a
/// JSON string, integer or boolean type.
pub enum Expression<'a> {
    // immediates
    /// A string expression (*immediate expression*).
    /// For string expressions there are two special cases:
    ///   * `@STRING`: The remaining part is taken as [set](crate::schema::Set)
    ///     name to create a set reference.
    ///   * `\*`: Construct a wildcard expression.
    String(Cow<'a, str>),
    /// An integer expression (*immediate expression*).
    Number(u32),
    /// A boolean expression (*immediate expression*).
    Boolean(bool),
    /// List expressions are constructed by plain arrays containing of an arbitrary number of expressions.
    List(Vec<Expression<'a>>),
    /// A [binary operation](BinaryOperation) expression.
    BinaryOperation(Box<BinaryOperation<'a>>),
    /// Construct a range of values.
    ///
    /// The first array item denotes the lower boundary, the second one the upper boundary.
    Range(Box<Range<'a>>),

    /// Wrapper for non-immediate expressions.
    Named(NamedExpression<'a>),
    /// A verdict expression (used in [verdict maps](crate::stmt::VerdictMap)).
    Verdict(Verdict<'a>),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Wrapper for non-immediate [Expressions](Expression).
pub enum NamedExpression<'a> {
    /// Concatenate several expressions.
    Concat(Vec<Expression<'a>>),
    /// This object constructs an anonymous set with [items](SetItem).
    /// For mappings, an array of arrays with exactly two elements is expected.
    Set(Vec<SetItem<'a>>),
    /// Map a key to a value.
    Map(Box<Map<'a>>),
    /// Construct an IPv4 or IPv6 [prefix](Prefix) consisting of address part and prefix length.
    Prefix(Prefix<'a>),

    /// Construct a [payload](Payload) expression, i.e. a reference to a certain part of packet data.
    Payload(Payload<'a>),

    /// Create a reference to a field in an IPv6 extension header.
    Exthdr(Exthdr<'a>),
    #[serde(rename = "tcp option")]
    /// Create a reference to a field of a TCP option header.
    TcpOption(TcpOption<'a>),
    #[serde(rename = "sctp chunk")]
    /// Create a reference to a field of an SCTP chunk.
    SctpChunk(SctpChunk<'a>),
    // TODO: DCCP Option
    /// Create a reference to packet meta data.
    Meta(Meta),
    /// Create a reference to packet routing data.
    RT(RT),
    /// Create a reference to packet conntrack data.
    CT(CT<'a>),
    /// Create a number generator.
    Numgen(Numgen),
    /// Hash packet data (Jenkins Hash).
    JHash(JHash<'a>),
    /// Hash packet data (Symmetric Hash).
    SymHash(SymHash),

    /// Perform kernel Forwarding Information Base lookups.
    Fib(Fib),
    /// Explicitly set element object, in case `timeout`, `expires`, or `comment`
    /// are desired.
    Elem(Elem<'a>),
    /// Construct a reference to a packet’s socket.
    Socket(Socket<'a>),
    /// Perform OS fingerprinting.
    ///
    /// This expression is typically used in the [LHS](crate::stmt::Match::left)
    /// of a [match](crate::stmt::Match) statement.
    Osf(Osf<'a>),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "map")]
/// Map a key to a value.
pub struct Map<'a> {
    /// Map key.
    pub key: Expression<'a>,
    /// Mapping expression consisting of value/target pairs.
    pub data: Expression<'a>,
}

/// Default map expression (`true -> false`).
impl Default for Map<'_> {
    fn default() -> Self {
        Map {
            key: Expression::Boolean(true),
            data: Expression::Boolean(false),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
/// Item in an anonymous set.
pub enum SetItem<'a> {
    /// A set item containing a single expression.
    Element(Expression<'a>),
    /// A set item mapping two expressions.
    Mapping(Expression<'a>, Expression<'a>),
    /// A set item mapping an expression to a statement.
    MappingStatement(Expression<'a>, Statement<'a>),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "prefix")]
/// Construct an IPv4 or IPv6 prefix consisting of address part in
/// [addr](Prefix::addr) and prefix length in [len](Prefix::len).
pub struct Prefix<'a> {
    /// An IPv4 or IPv6 address.
    pub addr: Box<Expression<'a>>,
    /// The prefix length.
    pub len: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "range")]
/// Construct a range of values.
/// The first array item denotes the lower boundary, the second one the upper
/// boundary.
pub struct Range<'a> {
    /// The range boundaries.
    ///
    /// The first array item denotes the lower boundary, the second one the
    /// upper boundary.
    pub range: [Expression<'a>; 2],
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
/// Construct a payload expression, i.e. a reference to a certain part of packet
/// data.
pub enum Payload<'a> {
    /// Allows one to reference a field by name in a named packet header.
    PayloadField(PayloadField<'a>),
    /// Creates a raw payload expression to point at a random number of bits at
    /// a certain offset from a given reference point.
    PayloadRaw(PayloadRaw),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// Creates a raw payload expression to point at a random number
/// ([len](PayloadRaw::len)) of bits at a certain offset
/// ([offset](PayloadRaw::offset)) from a given reference point
/// ([base](PayloadRaw::base)).
pub struct PayloadRaw {
    /// The (protocol layer) reference point.
    pub base: PayloadBase,
    /// Offset from the reference point in bits.
    pub offset: u32,
    /// Number of bits.
    pub len: u32,
}

/// Default raw payload expression (0-length at link layer).
impl Default for PayloadRaw {
    fn default() -> Self {
        PayloadRaw {
            base: PayloadBase::LL,
            offset: 0,
            len: 0,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// Construct a payload expression, i.e. a reference to a certain part of packet
/// data.
///
/// Allows to reference a field by name ([field](PayloadField::field)) in a
/// named packet header ([protocol](PayloadField::protocol)).
pub struct PayloadField<'a> {
    /// A named packet header.
    pub protocol: Cow<'a, str>,
    /// The field name.
    pub field: Cow<'a, str>,
}

/// Default payload field reference (`arp ptype`).
impl Default for PayloadField<'_> {
    fn default() -> Self {
        PayloadField {
            protocol: "arp".into(),
            field: "ptype".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents a protocol layer for [payload](Payload) references.
pub enum PayloadBase {
    /// Link layer, for example the Ethernet header.
    LL,
    /// Network header, for example IPv4 or IPv6.
    NH,
    /// Transport Header, for example TCP.
    ///
    /// *Added in nftables 0.9.2 and Linux kernel 5.3.*
    TH,
    /// Inner Header / Payload, i.e. after the L4 transport level header.
    ///
    /// *Added in Kernel version 6.2.*
    IH,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "exthdr")]
/// Create a reference to a field ([field](Exthdr::field)) in an IPv6 extension
/// header ([name](Exthdr::name)).
///
/// [offset](Exthdr::offset) is used only for `rt0` protocol.
pub struct Exthdr<'a> {
    /// The IPv6 extension header name.
    pub name: Cow<'a, str>,
    /// The field name.
    ///
    /// If the [field][Exthdr::field] property is not given, the expression is
    /// to be used as a header existence check in a [match](crate::stmt::Match)
    /// statement with a [boolean](Expression::Boolean) on the
    /// [right](crate::stmt::Match::right) hand side.
    pub field: Option<Cow<'a, str>>,
    /// The offset length. Used only for `rt0` protocol.
    pub offset: Option<u32>,
}

/// Default [Exthdr] for `frag` extension header.
impl Default for Exthdr<'_> {
    fn default() -> Self {
        Exthdr {
            name: "frag".into(),
            field: None,
            offset: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "tcp option")]
/// Create a reference to a field ([field](TcpOption::field)) of a TCP option
/// header ([name](TcpOption::field)).
pub struct TcpOption<'a> {
    /// The TCP option header name.
    pub name: Cow<'a, str>,
    /// The field name.
    ///
    /// If the field property is not given, the expression is to be used as a
    /// TCP option existence check in a [match](crate::stmt::Match)
    /// statement with a [boolean](Expression::Boolean) on the
    /// [right](crate::stmt::Match::right) hand side.
    pub field: Option<Cow<'a, str>>,
}

/// Default TCP option for `maxseg` option.
impl Default for TcpOption<'_> {
    fn default() -> Self {
        TcpOption {
            name: "maxseg".into(),
            field: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "sctp chunk")]
/// Create a reference to a field ([field](SctpChunk::field)) of an SCTP chunk
/// ((name)[SctpChunk::name]).
pub struct SctpChunk<'a> {
    /// The SCTP chunk name.
    pub name: Cow<'a, str>,
    /// The field name.
    ///
    /// If the field property is not given, the expression is to be used as an
    /// SCTP chunk existence check in a [match](crate::stmt::Match) statement
    /// with a [boolean](Expression::Boolean) on the
    /// [right](crate::stmt::Match::right) hand side.
    pub field: Cow<'a, str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "meta")]
/// Create a reference to packet meta data.
///
/// See [this page](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation)  
/// for more information.
pub struct Meta {
    /// The packet [meta data key](MetaKey).
    pub key: MetaKey,
}

/// Default impl for meta key `l4proto`.
impl Default for Meta {
    fn default() -> Self {
        Meta {
            key: MetaKey::L4proto,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents a `meta` key for packet meta data.
///
/// See [this page](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation)
/// for more information.
pub enum MetaKey {
    // matching by packet info:
    /// Packet type (unicast, broadcast, multicast, other).
    Pkttype,
    /// Packet length in bytes.
    Length,
    /// Packet protocol / EtherType protocol value.
    Protocol,
    /// Netfilter packet protocol family.
    Nfproto,
    /// Layer 4 protocol.
    L4proto,

    // matching by interface:
    /// Input interface index.
    Iif,
    /// Input interface name.
    Iifname,
    /// Input interface type.
    Iiftype,
    /// Input interface kind name.
    Iifkind,
    /// Input interface group.
    Iifgroup,
    /// Output interface index.
    Oif,
    /// Output interface name.
    Oifname,
    /// Output interface type.
    Oiftype,
    /// Output interface kind name.
    Oifkind,
    /// Output interface group.
    Oifgroup,
    /// Input bridge interface name.
    Ibridgename,
    /// Output bridge interface name.
    Obridgename,
    /// Input bridge interface name
    Ibriport,
    /// Output bridge interface name
    Obriport,

    // matching by packet mark, routing class and realm:
    /// Packet mark.
    Mark,
    /// TC packet priority.
    Priority,
    /// Routing realm.
    Rtclassid,

    // matching by socket uid/gid:
    /// UID associated with originating socket.
    Skuid,
    /// GID associated with originating socket.
    Skgid,

    // matching by security selectors:
    /// CPU number processing the packet.
    Cpu,
    /// Socket control group ID.
    Cgroup,
    /// `true` if packet was ipsec encrypted. (*obsolete*)
    Secpath,

    // matching by miscellaneous selectors:
    /// Pseudo-random number.
    Random,
    /// [nftrace debugging] bit.
    ///
    /// [nftract debugging]: <https://wiki.nftables.org/wiki-nftables/index.php/Ruleset_debug/tracing>
    Nftrace,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "rt")]
/// Create a reference to packet routing data.
pub struct RT {
    /// The routing data key.
    pub key: RTKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The protocol family.
    ///
    /// The `family` property is optional and defaults to unspecified.
    pub family: Option<RTFamily>,
}

/// Default impl for [RT] with key [nexthop](RTKey::NextHop).
impl Default for RT {
    fn default() -> Self {
        RT {
            key: RTKey::NextHop,
            family: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents a key to reference to packet routing data.
pub enum RTKey {
    /// Routing realm.
    ClassId,
    /// Routing nexthop.
    NextHop,
    /// TCP maximum segment size of route.
    MTU,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents a protocol family for use by the [rt](RT) expression.
pub enum RTFamily {
    /// IPv4 RT protocol family.
    IP,
    /// IPv6 RT protocol family.
    IP6,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "ct")]
/// Create a reference to packet conntrack data.
pub struct CT<'a> {
    /// The conntrack expression.
    ///
    /// See also: *CONNTRACK EXPRESSIONS* in *ntf(8)*.
    pub key: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The [conntrack protocol family](CTFamily).
    pub family: Option<CTFamily>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Conntrack flow [direction](CTDir).
    ///
    /// Some CT keys do not support a direction.
    /// In this case, `dir` must not be given.
    pub dir: Option<CTDir>,
}

/// Default impl for conntrack with `l3proto` conntrack key.
impl Default for CT<'_> {
    fn default() -> Self {
        CT {
            key: "l3proto".into(),
            family: None,
            dir: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents a protocol family for use by the [ct](CT) expression.
pub enum CTFamily {
    /// IPv4 conntrack protocol family.
    IP,
    /// IPv6 conntrack protocol family.
    IP6,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents a direction for use by the [ct](CT) expression.
pub enum CTDir {
    /// Original direction.
    Original,
    /// Reply direction.
    Reply,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "numgen")]
/// Create a number generator.
pub struct Numgen {
    /// The [number generator mode](NgMode).
    pub mode: NgMode,
    #[serde(rename = "mod")]
    /// Specifies an upper boundary ("modulus") which is not reached by returned
    /// numbers.
    pub ng_mod: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Allows one to increment the returned value by a fixed offset.
    pub offset: Option<u32>,
}

/// Default impl for [numgen](Numgen) with mode [inc](NgMode::Inc) and mod `7`.
impl Default for Numgen {
    fn default() -> Self {
        Numgen {
            mode: NgMode::Inc,
            ng_mod: 7,
            offset: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents a number generator mode.
pub enum NgMode {
    /// The last returned value is simply incremented.
    Inc,
    /// A new random number is returned.
    Random,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "jhash")]
/// Hash packet data (Jenkins Hash).
pub struct JHash<'a> {
    #[serde(rename = "mod")]
    /// Specifies an upper boundary ("modulus") which is not reached by returned numbers.
    pub hash_mod: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Increment the returned value by a fixed offset.
    pub offset: Option<u32>,
    /// Determines the parameters of the packet header to apply the hashing,
    /// concatenations are possible as well.
    pub expr: Box<Expression<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Specify an init value used as seed in the hashing function
    pub seed: Option<u32>,
}

/// Default impl for [jhash](JHash).
impl Default for JHash<'_> {
    fn default() -> Self {
        JHash {
            hash_mod: 7,
            offset: None,
            expr: Box::new(Expression::Named(NamedExpression::Payload(
                Payload::PayloadField(PayloadField {
                    protocol: "ip".into(),
                    field: "saddr".into(),
                }),
            ))),
            seed: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "symhash")]
/// Hash packet data (Symmetric Hash).
pub struct SymHash {
    #[serde(rename = "mod")]
    /// Specifies an upper boundary ("modulus") which is not reached by returned numbers.
    pub hash_mod: u32,
    /// Increment the returned value by a fixed offset.
    pub offset: Option<u32>,
}

/// Default impl for [symhash](SymHash).
impl Default for SymHash {
    fn default() -> Self {
        SymHash {
            hash_mod: 2,
            offset: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "fib")]
/// Perform kernel Forwarding Information Base lookups.
pub struct Fib {
    /// The data to be queried by fib lookup.
    pub result: FibResult,
    /// The tuple of elements ([FibFlags](FibFlag)) that is used as input to the
    /// fib lookup functions.
    pub flags: HashSet<FibFlag>,
}

/// Default impl for [fib](Fib).
impl Default for Fib {
    fn default() -> Self {
        let mut flags = HashSet::with_capacity(1);
        flags.insert(FibFlag::Iif);
        Fib {
            result: FibResult::Oif,
            flags,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents which data is queried by [fib](Fib) lookup.
pub enum FibResult {
    /// Output interface index.
    Oif,
    /// Output interface name.
    Oifname,
    /// Address type.
    Type,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents flags for `fib` lookup.
pub enum FibFlag {
    /// Consider the source address of a packet.
    Saddr,
    /// Consider the destination address of a packet.
    Daddr,
    /// Consider the packet mark.
    Mark,
    /// Consider the packet's input interface.
    Iif,
    /// Consider the packet's output interface.
    Oif,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
/// Represents a binary operation to be used in an `Expression`.
pub enum BinaryOperation<'a> {
    #[serde(rename = "&")]
    /// Binary AND (`&`)
    AND(Expression<'a>, Expression<'a>),

    #[serde(rename = "|")]
    /// Binary OR (`|`)
    OR(Expression<'a>, Expression<'a>),

    #[serde(rename = "^")]
    /// Binary XOR (`^`)
    XOR(Expression<'a>, Expression<'a>),

    #[serde(rename = "<<")]
    /// Left shift (`<<`)
    LSHIFT(Expression<'a>, Expression<'a>),

    #[serde(rename = ">>")]
    /// Right shift (`>>`)
    RSHIFT(Expression<'a>, Expression<'a>),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// A verdict expression (used in [verdict maps](crate::stmt::VerdictMap)).
///
/// There are also verdict [statements](crate::stmt::Statement), such as
/// [accept](crate::stmt::Statement::Accept).
pub enum Verdict<'a> {
    /// Terminate ruleset evaluation and accept the packet.
    ///
    /// The packet can still be dropped later by another hook, for instance
    /// accept in the forward hook still allows one to drop the packet later in
    /// the postrouting hook, or another forward base chain that has a higher
    /// priority number and is evaluated afterwards in the processing pipeline.
    Accept,
    /// Terminate ruleset evaluation and drop the packet.
    ///
    /// The drop occurs instantly, no further chains or hooks are evaluated.
    /// It is not possible to accept the packet in a later chain again, as those
    /// are not evaluated anymore for the packet.
    Drop,
    /// Continue ruleset evaluation with the next rule.
    ///
    /// This is the default behaviour in case a rule issues no verdict.
    Continue,
    /// Return from the current chain and continue evaluation at the next rule
    /// in the last chain.
    ///
    /// If issued in a base chain, it is equivalent to the base chain policy.
    Return,
    /// Continue evaluation at the first rule in chain.
    ///
    /// The current position in the ruleset is pushed to a call stack and
    /// evaluation will continue there when the new chain is entirely evaluated
    /// or a [return](Verdict::Return) verdict is issued. In case an absolute
    /// verdict is issued by a rule in the chain, ruleset evaluation terminates
    /// immediately and the specific action is taken.
    Jump(JumpTarget<'a>),
    /// Similar to jump, but the current position is not pushed to the call
    /// stack.
    ///
    /// That means that after the new chain evaluation will continue at the
    /// last chain instead of the one containing the goto statement.
    Goto(JumpTarget<'a>),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "elem")]
/// Explicitly set element object.
///
/// Element-related commands allow one to change contents of named
/// [sets](crate::schema::Set) and [maps](crate::schema::Map).
pub struct Elem<'a> {
    /// The element value.
    pub val: Box<Expression<'a>>,
    /// Timeout value for [sets](crate::schema::Set)/[maps](crate::schema::Map).
    /// with flag [timeout](crate::schema::SetFlag::Timeout)
    pub timeout: Option<u32>,
    /// The time until given element expires, useful for ruleset replication only.
    pub expires: Option<u32>,
    /// Per element comment field.
    pub comment: Option<Cow<'a, str>>,
    /// Enable a [counter][crate::stmt::Counter] per element.
    ///
    /// Added in nftables version *0.9.5*.
    pub counter: Option<Counter<'a>>,
}

/// Default impl for [Elem].
impl Default for Elem<'_> {
    fn default() -> Self {
        Elem {
            val: Box::new(Expression::String("10.2.3.4".into())),
            timeout: None,
            expires: None,
            comment: None,
            counter: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "socket")]
/// Construct a reference to packet’s socket.
pub struct Socket<'a> {
    /// The socket attribute to match on.
    pub key: Cow<'a, SocketAttr>,
}

/// Default impl for [Socket] with [wildcard](SocketAttr::Wildcard) key.
impl Default for Socket<'_> {
    fn default() -> Self {
        Socket {
            key: Cow::Borrowed(&SocketAttr::Wildcard),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// A [socket][Socket] attribute to match on.
pub enum SocketAttr {
    /// Match on the `IP_TRANSPARENT` socket option in the found socket.
    Transparent,
    /// Match on the socket mark (`SOL_SOCKET`, `SO_MARK`).
    Mark,
    /// Indicates whether the socket is wildcard-bound (e.g. 0.0.0.0 or ::0).
    Wildcard,
    /// The cgroup version 2 for this socket (path from `/sys/fs/cgroup`).
    Cgroupv2,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename = "osf")]
/// Perform OS fingerprinting.
///
/// This expression is typically used in the [LHS](crate::stmt::Match::left) of
/// a [match](crate::stmt::Match) statement.
pub struct Osf<'a> {
    /// Name of the OS signature to match.
    ///
    /// All signatures can be found at `pf.os` file.
    /// Use "unknown" for OS signatures that the expression could not detect.
    pub key: Cow<'a, str>,
    /// Do TTL checks on the packet to determine the operating system.
    pub ttl: OsfTtl,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// TTL check mode for [osf](Osf).
pub enum OsfTtl {
    /// Check if the IP header's TTL is less than the fingerprint one.
    ///
    /// Works for globally-routable addresses.
    Loose,
    /// Do not compare the TTL at all.
    Skip,
}
