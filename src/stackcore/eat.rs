//! EAT (Entity Attestation Token) — the canonical wire format for a
//! bountynet attestation.
//!
//! VENDORED, byte-for-byte wire-compatible with `maceip/unified-quote`
//! (`v2/src/eat.rs`). The only change from upstream is the module path of
//! the `Platform` import. A receipt produced here decodes and verifies with
//! `runcard check` and the unified-quote verifier, and vice versa.
//!
//! An EAT carries everything a verifier needs to decide whether a remote
//! TEE is trustworthy: the application identity (Value X), the raw
//! platform quote, the platform measurement, the TLS key binding for
//! attested TLS, and enough metadata (iat, nonce, source hash, artifact hash)
//! to link the runtime back to the build-time attestation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::stackcore::quote::Platform;

/// Schema version. Bumped on any breaking change to the binding format
/// or field layout. Verifiers MUST reject tokens with unknown versions.
pub const EAT_VERSION: u32 = 2;

/// Profile identifier, serialized under the standard EAT `eat_profile`
/// claim. Our profile URI namespace.
pub const EAT_PROFILE: &str = "https://bountynet.dev/eat/v2";

/// Errors produced by encoding/decoding an EAT.
#[derive(Debug, thiserror::Error)]
pub enum EatError {
    #[error("CBOR encode failed: {0}")]
    Encode(String),
    #[error("CBOR decode failed: {0}")]
    Decode(String),
    #[error("schema version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u32, got: u32 },
    #[error("profile mismatch: expected {expected}, got {got}")]
    ProfileMismatch { expected: String, got: String },
    #[error("field length invalid: {field} expected {expected} got {got}")]
    LengthMismatch {
        field: &'static str,
        expected: usize,
        got: usize,
    },
}

/// The canonical attestation payload. CBOR-encodes to a map with string
/// field names for debuggability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EatToken {
    /// Schema version. Must equal [`EAT_VERSION`] for today's format.
    pub version: u32,

    /// Profile URI. Must equal [`EAT_PROFILE`].
    pub eat_profile: String,

    /// Application identity — sha384 of the runner source files (Value X).
    #[serde(with = "serde_bytes_48")]
    pub value_x: [u8; 48],

    /// TEE platform discriminant: 1=Nitro, 2=SevSnp, 3=Tdx. 0=software witness.
    pub platform: u8,

    /// Platform measurement extracted from the quote (Nitro PCR0 / SNP
    /// MEASUREMENT / TDX MRTD). Variable length per platform.
    #[serde(with = "serde_bytes")]
    pub platform_measurement: Vec<u8>,

    /// Raw TEE evidence. Opaque leaf: verifiers parse per-platform.
    #[serde(with = "serde_bytes")]
    pub platform_quote: Vec<u8>,

    /// sha256 of the TLS server SPKI (DER-encoded SubjectPublicKeyInfo).
    #[serde(with = "serde_bytes_32")]
    pub tls_spki_hash: [u8; 32],

    /// Source tree hash. sha384. Binds runtime identity back to the exact
    /// source the builder witnessed.
    #[serde(with = "serde_bytes_48")]
    pub source_hash: [u8; 48],

    /// Artifact hash. sha384.
    #[serde(with = "serde_bytes_48")]
    pub artifact_hash: [u8; 48],

    /// Standard CWT/EAT claim: issued-at, unix seconds.
    pub iat: u64,

    /// Standard EAT claim: 32-byte freshness nonce.
    #[serde(with = "serde_bytes_32")]
    pub eat_nonce: [u8; 32],

    /// The previous stage's EAT, CBOR-encoded. Empty for stage 0;
    /// populated for stage 1+ with the complete CBOR bytes of the prior
    /// stage's token. Committed into this stage's binding via `previous_hash()`.
    #[serde(with = "serde_bytes", default, skip_serializing_if = "Vec::is_empty")]
    pub previous_attestation: Vec<u8>,
}

impl EatToken {
    /// Compute the 32-byte binding that goes into the TEE quote's
    /// `report_data[0..32]`. Excludes `platform_quote` and
    /// `platform_measurement` (chicken-and-egg / derivable), and mixes the
    /// previous stage in via the fixed-size `previous_hash()`.
    pub fn binding_bytes(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.version.to_be_bytes());
        h.update((self.eat_profile.len() as u32).to_be_bytes());
        h.update(self.eat_profile.as_bytes());
        h.update(self.value_x);
        h.update([self.platform]);
        h.update(self.tls_spki_hash);
        h.update(self.source_hash);
        h.update(self.artifact_hash);
        h.update(self.iat.to_be_bytes());
        h.update(self.eat_nonce);
        h.update(self.previous_hash());
        h.finalize().into()
    }

    /// Commitment to the previous stage's attestation. Zero hash for a root
    /// (stage 0); otherwise `sha256(previous_attestation)`.
    pub fn previous_hash(&self) -> [u8; 32] {
        if self.previous_attestation.is_empty() {
            [0u8; 32]
        } else {
            Sha256::digest(&self.previous_attestation).into()
        }
    }

    /// Returns `true` if this EAT chains to a previous stage's EAT.
    pub fn has_previous(&self) -> bool {
        !self.previous_attestation.is_empty()
    }

    /// Decode the previous stage's EAT from `previous_attestation`.
    pub fn decode_previous(&self) -> Result<Option<Self>, EatError> {
        if self.previous_attestation.is_empty() {
            return Ok(None);
        }
        Ok(Some(Self::from_cbor(&self.previous_attestation)?))
    }

    /// Chain this EAT to a previous stage. Must be called BEFORE
    /// `binding_bytes()` is computed for quote collection.
    pub fn set_previous(&mut self, previous_cbor: Vec<u8>) {
        self.previous_attestation = previous_cbor;
    }

    /// Encode to CBOR bytes.
    pub fn to_cbor(&self) -> Result<Vec<u8>, EatError> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(self, &mut out).map_err(|e| EatError::Encode(e.to_string()))?;
        Ok(out)
    }

    /// Decode a CBOR byte slice into an EAT token. Validates version and
    /// profile; does NOT verify the embedded platform quote.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, EatError> {
        let token: Self =
            ciborium::de::from_reader(bytes).map_err(|e| EatError::Decode(e.to_string()))?;
        token.validate_shape()?;
        Ok(token)
    }

    fn validate_shape(&self) -> Result<(), EatError> {
        if self.version != EAT_VERSION {
            return Err(EatError::VersionMismatch {
                expected: EAT_VERSION,
                got: self.version,
            });
        }
        if self.eat_profile != EAT_PROFILE {
            return Err(EatError::ProfileMismatch {
                expected: EAT_PROFILE.to_string(),
                got: self.eat_profile.clone(),
            });
        }
        Ok(())
    }

    /// Resolve the platform discriminant to the [`Platform`] enum.
    pub fn platform_enum(&self) -> Option<Platform> {
        match self.platform {
            1 => Some(Platform::Nitro),
            2 => Some(Platform::SevSnp),
            3 => Some(Platform::Tdx),
            _ => None,
        }
    }
}

/// Discriminant encoding for [`Platform`].
pub fn platform_to_u8(p: Platform) -> u8 {
    match p {
        Platform::Nitro => 1,
        Platform::SevSnp => 2,
        Platform::Tdx => 3,
    }
}

/// serde helper: serialize `[u8; 32]` as a CBOR byte string.
mod serde_bytes_32 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(v).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let v = <Vec<u8>>::deserialize(d)?;
        v.as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::invalid_length(v.len(), &"32-byte array"))
    }
    use serde::Serialize as _;
}

/// serde helper: serialize `[u8; 48]` as a CBOR byte string.
mod serde_bytes_48 {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u8; 48], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(v).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 48], D::Error> {
        let v = <Vec<u8>>::deserialize(d)?;
        v.as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::invalid_length(v.len(), &"48-byte array"))
    }
    use serde::Serialize as _;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> EatToken {
        EatToken {
            version: EAT_VERSION,
            eat_profile: EAT_PROFILE.to_string(),
            value_x: [0x11; 48],
            platform: 3,
            platform_measurement: vec![0x22; 48],
            platform_quote: vec![0x33; 256],
            tls_spki_hash: [0x44; 32],
            source_hash: [0x55; 48],
            artifact_hash: [0x66; 48],
            iat: 1_713_312_000,
            eat_nonce: [0x77; 32],
            previous_attestation: Vec::new(),
        }
    }

    #[test]
    fn cbor_roundtrip() {
        let t = sample();
        let bytes = t.to_cbor().unwrap();
        let back = EatToken::from_cbor(&bytes).unwrap();
        assert_eq!(back.value_x, t.value_x);
        assert_eq!(back.platform, t.platform);
    }

    #[test]
    fn binding_excludes_platform_quote_and_measurement() {
        let t1 = sample();
        let mut t2 = t1.clone();
        t2.platform_quote = vec![0xff; 16];
        t2.platform_measurement = vec![0xee; 96];
        assert_eq!(t1.binding_bytes(), t2.binding_bytes());
    }

    #[test]
    fn chain_commits_previous_hash_into_binding() {
        let stage0 = sample();
        let stage0_cbor = stage0.to_cbor().unwrap();
        let mut stage1 = sample();
        let before = stage1.binding_bytes();
        stage1.set_previous(stage0_cbor.clone());
        let after = stage1.binding_bytes();
        assert_ne!(before, after);
        let expected: [u8; 32] = Sha256::digest(&stage0_cbor).into();
        assert_eq!(stage1.previous_hash(), expected);
    }
}
