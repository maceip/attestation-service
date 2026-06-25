//! The HTTP attestation service: build identity, issue stage0/stage1 EAT
//! receipts, and verify hardware quotes against pinned vendor roots.

pub mod attest;
pub mod build;
pub mod http;
pub mod quote_source;
pub mod state;
pub mod verify;
