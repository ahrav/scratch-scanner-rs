//! Format-specific helpers used by detection and scanners.
//!
//! # Design Notes
//! - This module re-exports small, bounded parsers tailored for scanning.

pub mod gzip;
pub mod tar;
pub mod zip;

pub use gzip::{is_gzip_magic, GzipStream};
pub use tar::{is_ustar_header, TarCursor, TarInput, TarNext, TarRead};
pub use zip::{is_zip_magic, ZipCursor, ZipEntryMeta, ZipEntryReader, ZipNext, ZipOpen, ZipSource};
