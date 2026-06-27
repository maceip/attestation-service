//! Verification engine: decode an EAT, walk its build→runtime chain, and
//! cryptographically verify every stage's hardware quote against the pinned
//! vendor roots. This is the core demo of the lower layers — the same check
//! `uq` runs, exposed as a service.

use std::collections::BTreeMap;

use base64::Engine;
use sha2::{Digest, Sha256};

use crate::receipt::{stage_view, Receipt, StageView, Verdict};
use crate::stackcore::eat::EatToken;
use crate::stackcore::quote::verify::verify_platform_quote;

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Decode an EAT from raw CBOR, or from a base64-encoded CBOR string.
pub fn decode_eat(body: &[u8]) -> Result<EatToken, String> {
    if let Ok(t) = EatToken::from_cbor(body) {
        return Ok(t);
    }
    // Try base64 (trim whitespace/newlines).
    let trimmed: String = std::str::from_utf8(body)
        .map_err(|_| "body is neither CBOR nor UTF-8 base64".to_string())?
        .trim()
        .to_string();
    let raw = b64()
        .decode(trimmed.as_bytes())
        .map_err(|e| format!("not CBOR and not valid base64: {e}"))?;
    EatToken::from_cbor(&raw).map_err(|e| format!("decoded base64 is not a valid EAT: {e}"))
}

fn verify_one(token: &EatToken) -> StageView {
    let is_root = !token.has_previous();

    match token.platform_enum() {
        Some(platform) if !token.platform_quote.is_empty() => {
            let binding = token.binding_bytes();
            match verify_platform_quote(platform, &token.platform_quote, &binding) {
                Ok(meas) => {
                    let mut m = BTreeMap::new();
                    for (k, v) in meas {
                        m.insert(k, hex::encode(v));
                    }
                    stage_view(
                        token,
                        is_root,
                        Verdict::Verified,
                        m,
                        format!(
                            "quote verified against pinned {} vendor root",
                            crate::stackcore::platform_name(platform)
                        ),
                    )
                }
                Err(e) => stage_view(
                    token,
                    is_root,
                    Verdict::Failed,
                    BTreeMap::new(),
                    e.to_string(),
                ),
            }
        }
        _ => stage_view(
            token,
            is_root,
            Verdict::Failed,
            BTreeMap::new(),
            "no hardware quote present — refused (attestation requires a hardware root of trust)"
                .into(),
        ),
    }
}

/// Verify a token and its entire previous-stage chain. Returns a [`Receipt`].
pub fn verify_chain(token: EatToken) -> Receipt {
    // Collect the chain runtime-first.
    let mut chain_tokens: Vec<EatToken> = vec![token.clone()];
    let mut cursor = token.clone();
    loop {
        match cursor.decode_previous() {
            Ok(Some(prev)) => {
                chain_tokens.push(prev.clone());
                cursor = prev;
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }

    let views: Vec<StageView> = chain_tokens.iter().map(verify_one).collect();

    // value_x must be stable across stages: the runtime is the code the
    // builder produced.
    let value_x_stable = chain_tokens
        .windows(2)
        .all(|w| w[0].value_x == w[1].value_x);

    let any_failed = views.iter().any(|v| v.verdict == Verdict::Failed);
    let any_verified = views.iter().any(|v| v.verdict == Verdict::Verified);

    let (verdict, detail) = if !value_x_stable {
        (
            Verdict::Failed,
            "value_x is not stable across the chain — runtime is not the built source".to_string(),
        )
    } else if any_failed {
        (Verdict::Failed, "one or more stages failed verification".to_string())
    } else if any_verified {
        (
            Verdict::Verified,
            format!("{} stage(s) verified against pinned vendor roots", views.len()),
        )
    } else {
        (
            Verdict::Failed,
            "no hardware quote in the chain — refused (attestation requires a hardware root)"
                .to_string(),
        )
    };

    let cbor = token.to_cbor().unwrap_or_default();
    let id = hex::encode(&Sha256::digest(&cbor)[..8]);

    Receipt {
        id,
        verdict,
        chain: views,
        value_x_stable,
        eat_version: token.version,
        eat_profile: token.eat_profile.clone(),
        eat_cbor_b64: b64().encode(&cbor),
        detail,
    }
}
