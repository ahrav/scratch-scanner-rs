//! Utility helpers for low-level byte handling and zero checks.

pub mod utils;
pub mod zero;

pub use utils::{
    align_up, as_bytes, as_bytes_unchecked, as_bytes_unchecked_mut, equal_bytes, AlignedBox, Pod,
    Zeroable,
};
