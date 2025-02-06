use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Families in nftables.
///
/// See <https://wiki.nftables.org/wiki-nftables/index.php/Nftables_families>.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum NfFamily {
    IP,
    IP6,
    INet,
    ARP,
    Bridge,
    NetDev,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents the type of a Chain.
pub enum NfChainType {
    Filter,
    Route,
    NAT,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents the policy of a Chain.
pub enum NfChainPolicy {
    Accept,
    Drop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents a netfilter hook.
///
/// See <https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks>.
pub enum NfHook {
    Ingress,
    Prerouting,
    Forward,
    Input,
    Output,
    Postrouting,
    Egress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Represents a conntrack helper protocol.
pub enum CTHProto {
    TCP,
    UDP,
    DCCP,
    SCTP,
    GRE,
    ICMPv6,
    ICMP,
    Generic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RejectCode {
    #[serde(rename = "admin-prohibited")]
    /// Host administratively prohibited (ICMPX, ICMP, ICMPv6)
    AdminProhibited,
    #[serde(rename = "port-unreachable")]
    /// Destination port unreachable (ICMPX, ICMP, ICMPv6)
    PortUnreach,
    #[serde(rename = "no-route")]
    /// No route to destination (ICMPX, ICMP, ICMPv6)
    NoRoute,
    #[serde(rename = "host-unreachable")]
    /// Destination host unreachable (ICMPX, ICMP, ICMPv6)
    HostUnreach,
    #[serde(rename = "net-unreachable")]
    /// Destination network unreachable (ICMP)
    NetUnreach,
    #[serde(rename = "prot-unreachable")]
    /// Destination protocol unreachable (ICMP)
    ProtUnreach,
    #[serde(rename = "net-prohibited")]
    /// Network administratively prohibited (ICMP)
    NetProhibited,
    #[serde(rename = "host-prohibited")]
    /// Host administratively prohibited (ICMP)
    HostProhibited,
    #[serde(rename = "addr-unreachable")]
    /// Address unreachable (ICMPv6)
    AddrUnreach,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Hash, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// Describes a SynProxy's flags.
pub enum SynProxyFlag {
    /// Pass client timestamp option to backend.
    Timestamp,
    #[serde(rename = "sack-perm")]
    /// Pass client selective acknowledgement option to backend.
    SackPerm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
/// A time unit (used by [limits][crate::schema::Limit]).
pub enum NfTimeUnit {
    /// A second.
    Second,
    /// A minute (60 seconds).
    Minute,
    /// An hour (3600 seconds).
    Hour,
    /// A day (86400 seconds).
    Day,
    /// A week (604800 seconds).
    Week,
}
