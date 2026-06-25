//! Stack core: re-exports of the canonical `unified-quote` crate.
//!
//! The eat format and quote verifier are now a real git dependency
//! (see Cargo.toml), not a vendored copy. This service therefore verifies
//! with exactly the same code the base layer ships — no drift possible.

pub use unified_quote::tee::kds;
pub use unified_quote::{eat, quote, value_x};

use unified_quote::quote::Platform;

/// Stable lowercase platform name used in receipts and detail strings.
pub fn platform_name(p: Platform) -> &'static str {
    match p {
        Platform::Nitro => "nitro",
        Platform::SevSnp => "snp",
        Platform::Tdx => "tdx",
    }
}
