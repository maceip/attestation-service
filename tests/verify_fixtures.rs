//! Verifies the bundled real hardware-quote fixtures through the service's
//! own verification engine. This is the demo, asserted in CI: offline
//! cryptographic verification of real Nitro/TDX evidence against pinned roots,
//! plus a stage0→stage1 chain walk.
//!
//! Fixtures were captured from live TEEs (see `examples/fixtures/`), the same
//! vectors `unified-quote`'s hardware regression suite uses. SNP is excluded
//! from the offline assertion because its VCEK chain is fetched from AMD KDS
//! (network); we only assert it decodes.

use attestation_service::receipt::Verdict;
use attestation_service::service::verify::{decode_eat, verify_chain};
use std::fs;

fn load(name: &str) -> Vec<u8> {
    fs::read(format!("examples/fixtures/{name}"))
        .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

#[test]
fn tdx_stage1_chain_verifies() {
    let token = decode_eat(&load("tdx_stage1.cbor")).expect("decode tdx_stage1");
    let r = verify_chain(token);
    assert_eq!(r.verdict, Verdict::Verified, "detail: {}", r.detail);
    assert!(r.value_x_stable, "value_x must be stable across the chain");
    assert_eq!(r.chain.len(), 2, "stage1 should walk back to stage0");
    assert!(r.chain.iter().all(|s| s.verdict == Verdict::Verified));
    // MRTD must be present on a verified TDX stage.
    assert!(r.chain[0].measurements.contains_key("MRTD"));
}

#[test]
fn tdx_stage0_verifies() {
    let token = decode_eat(&load("tdx_stage0.cbor")).expect("decode tdx_stage0");
    let r = verify_chain(token);
    assert_eq!(r.verdict, Verdict::Verified, "detail: {}", r.detail);
}

#[test]
fn nitro_stage0_verifies() {
    let token = decode_eat(&load("nitro_stage0.cbor")).expect("decode nitro_stage0");
    let r = verify_chain(token);
    assert_eq!(r.verdict, Verdict::Verified, "detail: {}", r.detail);
    assert_eq!(r.chain[0].platform, "nitro");
}

#[test]
fn snp_fixture_decodes() {
    // Offline: just confirm it is a well-formed SNP EAT. Full crypto needs KDS.
    let token = decode_eat(&load("snp_stage0.cbor")).expect("decode snp_stage0");
    assert_eq!(token.platform, 2, "snp platform discriminant");
    assert!(!token.platform_quote.is_empty());
}
