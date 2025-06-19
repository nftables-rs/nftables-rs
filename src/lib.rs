//! nftables-rs is a Rust library designed to provide a safe and easy-to-use abstraction over the nftables JSON API, known as libnftables-json.
//!
//! This library is engineered for developers who need to interact with nftables,
//! the Linux kernel's next-generation firewalling tool, directly from Rust applications.
//!
//! By abstracting the underlying JSON API, nftables-rs facilitates the creation, manipulation,
//! and application of firewall rulesets without requiring deep knowledge of nftables' internal workings.

// TODO: add example usage to library doc

/// Contains Batch object to be used to prepare Nftables payloads.
pub mod batch;

/// Contains [expressions](crate::expr::Expression).
/// Expressions are the building blocks of (most) statements.
///
/// See <https://manpages.debian.org/testing/libnftables1/libnftables-json.5.en.html#EXPRESSIONS>.
pub mod expr;

/// Contains the global structure of an Nftables document.
///
/// See <https://manpages.debian.org/testing/libnftables1/libnftables-json.5.en.html#GLOBAL_STRUCTURE>.
pub mod schema;

/// Contains Statements.
/// Statements are the building blocks for rules.
///
/// See <https://manpages.debian.org/testing/libnftables1/libnftables-json.5.en.html#STATEMENTS>.
pub mod stmt;

/// Contains common type definitions referred to in the schema.
pub mod types;

/// Contains methods to communicate with nftables JSON API.
pub mod helper;

/// Contains node visitors for serde.
pub mod visitor;

/// Contains handling and parsing of command line arguments.
pub mod cli;

/// Contains error types.
pub mod error;

// Default values for Default implementations.
const DEFAULT_FAMILY: types::NfFamily = types::NfFamily::INet;
const DEFAULT_TABLE: &str = "filter";
const DEFAULT_CHAIN: &str = "forward";
