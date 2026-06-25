//! The human- and machine-readable receipt returned by `/v1/attest` and
//! `/v1/verify`. This is a projection of an [`EatToken`] plus the verdict
//! produced by the stack verifier. The raw, wire-compatible token travels in
//! `eat_cbor_b64`; everything else is a decoded convenience view.

use serde::{Deserialize, Serialize};

use crate::stackcore::eat::EatToken;

/// Top-level decision for a receipt or a verification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// A hardware quote was present and verified against a pinned vendor root.
    Verified,
    /// No hardware quote — a software witness receipt. Honest, not trusted.
    Witness,
    /// A hardware quote was present but failed verification.
    Failed,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::Witness => "witness",
            Verdict::Failed => "failed",
        }
    }
}

/// One stage in a build→runtime chain, with its own verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageView {
    /// "stage0" (root / build) or "stage1+" (runtime, chains a previous).
    pub stage: String,
    pub platform: String,
    pub verdict: Verdict,
    pub value_x: String,
    pub value_x_short: String,
    pub source_hash: String,
    pub artifact_hash: String,
    pub tls_spki_hash: String,
    pub iat: u64,
    /// Platform measurements pulled out of the quote during verification
    /// (e.g. MRTD, RTMR0..3 for TDX; MEASUREMENT for SNP; PCR0 for Nitro).
    pub measurements: std::collections::BTreeMap<String, String>,
    pub detail: String,
}

/// The full receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Stable id: short sha256 of the EAT CBOR.
    pub id: String,
    pub verdict: Verdict,
    /// Stages, runtime-first (stage1 then stage0) — the order a verifier walks.
    pub chain: Vec<StageView>,
    /// Whether `value_x` is stable across every stage in the chain.
    pub value_x_stable: bool,
    pub eat_version: u32,
    pub eat_profile: String,
    /// The raw, wire-compatible EAT — base64(CBOR). Feed this to `uq`.
    pub eat_cbor_b64: String,
    pub detail: String,
}

/// Render a [`StageView`] from a decoded token plus its verification outcome.
pub fn stage_view(
    token: &EatToken,
    is_root: bool,
    verdict: Verdict,
    measurements: std::collections::BTreeMap<String, String>,
    detail: String,
) -> StageView {
    let platform = match token.platform {
        1 => "nitro",
        2 => "sev-snp",
        3 => "tdx",
        _ => "software-witness",
    }
    .to_string();

    StageView {
        stage: if is_root { "stage0".into() } else { "stage1+".into() },
        platform,
        verdict,
        value_x: hex::encode(token.value_x),
        value_x_short: hex::encode(&token.value_x[..8]),
        source_hash: hex::encode(token.source_hash),
        artifact_hash: hex::encode(token.artifact_hash),
        tls_spki_hash: hex::encode(token.tls_spki_hash),
        iat: token.iat,
        measurements,
        detail,
    }
}
