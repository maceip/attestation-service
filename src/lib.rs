//! attestation-service: issue and verify hardware-rooted EAT receipts for
//! arbitrary source.
//!
//! The service is the demo surface for the lower layers of the stack:
//!   - it computes the same `value_x` source identity as the in-TEE builder,
//!   - it issues stage0 (build) and stage1 (runtime) EAT receipts that chain,
//!   - it cryptographically verifies real hardware quotes (Nitro / SEV-SNP /
//!     TDX) against pinned vendor roots using the unified-quote crate verifier.
//!
//! It is designed to run as the loopback workload inside `attested-workload`
//! (listen on 127.0.0.1:8080, expose `/v1/*` and `/healthz`), so its own
//! responses are themselves served over attested TLS.

pub mod receipt;
pub mod service;
pub mod stackcore;
