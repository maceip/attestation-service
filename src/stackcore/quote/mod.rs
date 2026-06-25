//! Quote model + verifier. VENDORED from `maceip/unified-quote`
//! (`v2/src/quote/`).

pub mod roots;
pub mod verify;

use serde::{Deserialize, Serialize};

/// TEE platform identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Platform {
    Nitro = 1,
    SevSnp = 2,
    Tdx = 3,
}

impl Platform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Platform::Nitro => "nitro",
            Platform::SevSnp => "sev-snp",
            Platform::Tdx => "tdx",
        }
    }
}
