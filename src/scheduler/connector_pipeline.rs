//! Connector-first scheduler entrypoints.
//!
//! This module is the public migration surface for connector-native scheduling.
//! During migration it forwards to the existing runtime implementation while
//! exposing connector-oriented names at the scheduler API boundary.

pub use super::remote::{
    scan_remote as scan_connector, ErrorClass as ConnectorErrorClass,
    RemoteBackend as ConnectorSource, RemoteConfig as ConnectorConfig,
    RemoteObject as ConnectorObject, RemoteRunError as ConnectorRunError,
    RemoteRunReport as ConnectorRunReport, RetryPolicy as ConnectorRetryPolicy,
};
