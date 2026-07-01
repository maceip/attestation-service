//! The `/v1/attest` pipeline: source → identity → (build) → bind → quote →
//! chained EAT → self-verify → receipt.
//!
//! stage0 vs stage1:
//!   - With no `previous`, this issues a **stage0** (build/root) receipt.
//!   - With a `previous` EAT supplied, this issues a **stage1+** (runtime)
//!     receipt that chains the previous stage in via `set_previous`, so the
//!     binding committed into the quote covers `sha256(previous)`. That is the
//!     build→runtime evolution the stack promotes.

use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;

use crate::receipt::Receipt;
use crate::service::state::AppState;
use crate::service::verify::verify_chain;
use crate::stackcore::eat::{
    platform_to_u8, EatToken, DEFAULT_BINDING_SUITE, EAT_PROFILE, EAT_VERSION,
};

#[derive(Default)]
pub struct AttestOptions {
    /// 32-byte freshness nonce (else random).
    pub nonce: Option<[u8; 32]>,
    /// CBOR of a previous-stage EAT to chain onto (makes this stage1+).
    pub previous_cbor: Option<Vec<u8>>,
    /// sha256 of the TLS SPKI to bind (attested-TLS); zero if not applicable.
    pub tls_spki_hash: Option<[u8; 32]>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run the full attest pipeline for a submitted source tarball.
pub fn run_attest(
    state: &AppState,
    source_tar: &[u8],
    opts: AttestOptions,
) -> anyhow::Result<Receipt> {
    // 1. Unpack + identity + (optional) build.
    let dir = crate::service::build::unpack_source(source_tar)?;
    let build = state.builder.build(dir.path())?;

    // 2. Assemble the EAT (pre-quote: platform/quote/measurement empty).
    let mut nonce = [0u8; 32];
    match opts.nonce {
        Some(n) => nonce = n,
        None => rand::thread_rng().fill_bytes(&mut nonce),
    }

    let mut eat = EatToken {
        version: EAT_VERSION,
        eat_profile: EAT_PROFILE.to_string(),
        binding_suite: DEFAULT_BINDING_SUITE,
        value_x: build.value_x,
        platform: 0, // unset until a hardware quote is collected (step 5)
        platform_measurement: Vec::new(),
        platform_quote: Vec::new(),
        tls_spki_hash: opts.tls_spki_hash.unwrap_or([0u8; 32]),
        source_hash: build.source_hash,
        artifact_hash: build.artifact_hash,
        iat: now(),
        eat_nonce: nonce,
        previous_attestation: Vec::new(),
    };

    // 3. Chain a previous stage if provided (stage1+). Must be set BEFORE the
    //    binding is computed so the quote commits to the chain.
    if let Some(prev) = opts.previous_cbor {
        // Validate it is a real EAT before chaining.
        EatToken::from_cbor(&prev)
            .map_err(|e| anyhow::anyhow!("previous attestation is not a valid EAT: {e}"))?;
        eat.set_previous(prev);
    }

    // 4. Bind: report_data = binding(32) || value_x[0..32].
    let binding = eat.binding_bytes();
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&binding);
    report_data[32..].copy_from_slice(&eat.value_x[..32]);

    // 5. Collect a hardware quote. Issuance fails closed: without a configured
    //    hardware quote source the service refuses to issue — it never emits a
    //    software-witness receipt.
    let quote_source = state.quote_source.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "issuance refused: no hardware quote source configured. This service \
             only issues hardware-rooted receipts; set AS_QUOTE_SOURCE."
        )
    })?;
    match quote_source.collect(&report_data)? {
        Some(q) => {
            eat.platform = platform_to_u8(q.platform);
            eat.platform_quote = q.raw_quote;
            eat.platform_measurement = q.measurement;
        }
        None => anyhow::bail!(
            "issuance refused: hardware quote source returned no quote (no TEE present)"
        ),
    }

    // 6. Self-verify and project to a receipt (binding excludes the quote, so
    //    it is unchanged by step 5).
    let receipt = verify_chain(eat);

    if let Ok(mut store) = state.store.lock() {
        store.insert(receipt.id.clone(), receipt.clone());
    }

    Ok(receipt)
}
