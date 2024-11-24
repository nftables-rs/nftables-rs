use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::HashSet};

use crate::stmt::{Counter, JumpTarget, Statement};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
/// Expressions are the building blocks of (most) statements.
/// In their most basic form, they are just immediate values represented as a JSON string, integer or boolean type.
pub enum Expression {
    // immediates
    String(Cow<'static, str>),
    Number(u32),
    Boolean(bool),
    /// List expressions are constructed by plain arrays containing of an arbitrary number of expressions.
    List(Vec<Expression>),
    BinaryOperation(Box<BinaryOperation>),
    Range(Box<Range>),

    Named(NamedExpression),
    Verdict(Verdict),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Wrapper for non-immediate `Expression`s.
pub enum NamedExpression {
    /// Concatenate several expressions.
    Concat(Vec<Expression>),
    /// This object constructs an anonymous set.
    /// For mappings, an array of arrays with exactly two elements is expected.
    Set(Vec<SetItem>),
    Map(Box<Map>),
    Prefix(Prefix),

    Payload(Payload),

    Exthdr(Exthdr),
    #[serde(rename = "tcp option")]
    TcpOption(TcpOption),
    #[serde(rename = "sctp chunk")]
    SctpChunk(SctpChunk),
    Meta(Meta),
    RT(RT),
    CT(CT),
    Numgen(Numgen),
    JHash(JHash),
    SymHash(SymHash),
    Fib(Fib),
    Elem(Elem),
    Socket(Socket),
    Osf(Osf),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "map")]
/// Map a key to a value.
pub struct Map {
    /// Map key.
    pub key: Expression,
    /// Mapping expression consisting of value/target pairs.
    pub data: Expression,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
/// Item in an anonymous set.
pub enum SetItem {
    /// A set item containing a single expression.
    Element(Expression),
    /// A set item mapping two expressions.
    Mapping(Expression, Expression),
    /// A set item mapping an expression to a statement.
    MappingStatement(Expression, Statement),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "prefix")]
/// Construct an IPv4 or IPv6 prefix consisting of address part in `addr` and prefix length in `len`.
pub struct Prefix {
    pub addr: Box<Expression>,
    pub len: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "range")]
/// Construct a range of values.
/// The first array item denotes the lower boundary, the second one the upper boundary.
pub struct Range {
    pub range: [Expression; 2],
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Payload {
    PayloadField(PayloadField),
    PayloadRaw(PayloadRaw),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
/// Construct a payload expression, i.e. a reference to a certain part of packet data.
///
/// Creates a raw payload expression to point at a random number (`len`) of bytes at a certain offset (`offset`) from a given reference point (`base`).
pub struct PayloadRaw {
    pub base: PayloadBase,
    pub offset: u32,
    pub len: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
/// Construct a payload expression, i.e. a reference to a certain part of packet data.
/// Allows to reference a field by name (`field`) in a named packet header (`protocol`).
pub struct PayloadField {
    pub protocol: Cow<'static, str>,
    pub field: Cow<'static, str>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a protocol layer for `payload` references.
pub enum PayloadBase {
    /// Link layer, for example the Ethernet header
    LL,
    /// Network header, for example IPv4 or IPv6
    NH,
    /// Transport Header, for example TCP
    TH,
    /// Inner Header / Payload, i.e. after the L4 transport level header
    IH,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "exthdr")]
/// Create a reference to a field (field) in an IPv6 extension header (name).
/// `offset` is used only for rt0 protocol.
pub struct Exthdr {
    pub name: Cow<'static, str>,
    pub field: Cow<'static, str>,
    pub offset: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "tcp option")]
/// Create a reference to a field (`field`) of a TCP option header (`name`).
pub struct TcpOption {
    pub name: Cow<'static, str>,
    pub field: Cow<'static, str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "sctp chunk")]
/// Create a reference to a field (`field`) of an SCTP chunk (`name`).
pub struct SctpChunk {
    pub name: Cow<'static, str>,
    pub field: Cow<'static, str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "meta")]
/// Create a reference to packet meta data.
pub struct Meta {
    pub key: MetaKey,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a `meta` key for packet meta data.
pub enum MetaKey {
    Length,
    Protocol,
    Priority,
    Random,
    Mark,
    Iif,
    Iifname,
    Iiftype,
    Oif,
    Oifname,
    Oiftype,
    Skuid,
    Skgid,
    Nftrace,
    Rtclassid,
    Ibriport,
    Obriport,
    Ibridgename,
    Obridgename,
    Pkttype,
    Cpu,
    Iifgroup,
    Oifgroup,
    Cgroup,
    Nfproto,
    L4proto,
    Secpath,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "rt")]
/// Create a reference to packet routing data.
pub struct RT {
    pub key: RTKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<RTFamily>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a key to reference to packet routing data.
pub enum RTKey {
    ClassId,
    NextHop,
    MTU,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a protocol family for use by the `ct` expression.
pub enum RTFamily {
    IP,
    IP6,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "ct")]
/// Create a reference to packet conntrack data.
pub struct CT {
    pub key: Cow<'static, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<CTFamily>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<CTDir>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a protocol family for use by the `ct` expression.
pub enum CTFamily {
    IP,
    IP6,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a direction for use by the `ct` expression.
pub enum CTDir {
    Original,
    Reply,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "numgen")]
/// Create a number generator.
pub struct Numgen {
    pub mode: NgMode,
    #[serde(rename = "mod")]
    pub ng_mod: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents a number generator mode.
pub enum NgMode {
    Inc,
    Random,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "jhash")]
/// Hash packet data
pub struct JHash {
    #[serde(rename = "mod")]
    pub hash_mod: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    pub expr: Box<Expression>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u32>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "symhash")]
/// Hash packet data
pub struct SymHash {
    #[serde(rename = "mod")]
    pub hash_mod: u32,
    pub offset: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "fib")]
/// Perform kernel Forwarding Information Base lookups.
pub struct Fib {
    pub result: FibResult,
    pub flags: HashSet<FibFlag>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Represents which data is queried by `fib` lookup.
pub enum FibResult {
    Oif,
    Oifname,
    Type,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Hash)]
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

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
/// Represents a binary operation to be used in an `Expression`.
pub enum BinaryOperation {
    #[serde(rename = "&")]
    /// Binary AND (`&`)
    AND(Expression, Expression),

    #[serde(rename = "|")]
    /// Binary OR (`|`)
    OR(Expression, Expression),

    #[serde(rename = "^")]
    /// Binary XOR (`^`)
    XOR(Expression, Expression),

    #[serde(rename = "<<")]
    /// Left shift (`<<`)
    LSHIFT(Expression, Expression),

    #[serde(rename = ">>")]
    /// Right shift (`>>`)
    RSHIFT(Expression, Expression),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// Verdict expression.
pub enum Verdict {
    Accept,
    Drop,
    Continue,
    Return,
    Jump(JumpTarget),
    Goto(JumpTarget),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "elem")]
/// Explicitly set element object.
pub struct Elem {
    pub val: Box<Expression>,
    pub timeout: Option<u32>,
    pub expires: Option<u32>,
    pub comment: Option<Cow<'static, str>>,
    pub counter: Option<Counter>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "socket")]
/// Construct a reference to packet’s socket.
pub struct Socket {
    pub key: Cow<'static, str>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename = "osf")]
/// Perform OS fingerprinting.
/// This expression is typically used in the LHS of a `match` statement.
pub struct Osf {
    ///  Name of the OS signature to match.
    /// All signatures can be found at pf.os file.
    /// Use "unknown" for OS signatures that the expression could not detect.
    pub key: Cow<'static, str>,
    /// Do TTL checks on the packet to determine the operating system.
    pub ttl: OsfTtl,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// TTL check mode for `osf`.
pub enum OsfTtl {
    /// Check if the IP header's TTL is less than the fingerprint one. Works for globally-routable addresses.
    Loose,
    /// Do not compare the TTL at all.
    Skip,
}
