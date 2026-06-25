//! Stack core: the pieces of `maceip/unified-quote` this service must agree
//! with byte-for-byte. Vendored (not a git dependency) because `unified-quote`
//! keeps its crate in a `v2/` subdirectory with no top-level workspace, which
//! cargo git deps can't target cleanly. Upstream remains the source of truth;
//! these files are faithful copies with only module-path edits.

pub mod eat;
pub mod kds;
pub mod quote;
pub mod value_x;
