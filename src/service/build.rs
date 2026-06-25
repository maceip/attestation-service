//! Stage 0 build: take a submitted source tarball, derive its identity
//! (`value_x` / `source_hash`), and produce an `artifact_hash`.
//!
//! Two builders:
//!   - [`WitnessBuilder`] (default): unpacks and hashes; it does NOT execute
//!     untrusted source. `artifact_hash` is a deterministic function of the
//!     source identity. Honest about the fact that no isolated build ran.
//!   - [`CommandBuilder`]: runs a configured build command against the
//!     unpacked tree (intended to run *inside* a TEE, e.g. under
//!     `attested-workload`), then hashes the resulting output directory.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha384};

use crate::stackcore::value_x::compute_tree_hash;

/// Identity + artifact derived from a submitted source tree.
pub struct BuildOutput {
    pub value_x: [u8; 48],
    pub source_hash: [u8; 48],
    pub artifact_hash: [u8; 48],
    pub build_mode: String,
    pub log: String,
}

/// Unpack a (optionally gzip-compressed) tar archive into a fresh temp dir.
pub fn unpack_source(bytes: &[u8]) -> anyhow::Result<tempfile::TempDir> {
    let dir = tempfile::tempdir()?;
    let decompressed: Vec<u8> = if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut gz = flate2::read::GzDecoder::new(bytes);
        let mut out = Vec::new();
        gz.read_to_end(&mut out)?;
        out
    } else {
        bytes.to_vec()
    };

    let mut ar = tar::Archive::new(&decompressed[..]);
    ar.set_preserve_permissions(false);
    // Guard against path traversal: tar crate strips `..` with this off, but
    // be explicit.
    ar.set_overwrite(true);
    ar.unpack(dir.path())?;
    Ok(dir)
}

/// A builder strategy.
pub trait Builder: Send + Sync {
    fn build(&self, source_dir: &Path) -> anyhow::Result<BuildOutput>;
    fn name(&self) -> &'static str;
}

/// Default builder: identity-only, no code execution.
pub struct WitnessBuilder;

impl Builder for WitnessBuilder {
    fn build(&self, source_dir: &Path) -> anyhow::Result<BuildOutput> {
        let value_x = compute_tree_hash(source_dir)?;
        // artifact_hash is a deterministic, domain-separated function of the
        // source identity. In witness mode the "artifact" is the witnessed
        // source itself; the prefix makes it unambiguous that no compiler ran.
        let mut h = Sha384::new();
        h.update(b"attestation-service:artifact:witness:v1");
        h.update(value_x);
        let artifact_hash: [u8; 48] = h.finalize().into();

        Ok(BuildOutput {
            value_x,
            source_hash: value_x,
            artifact_hash,
            build_mode: "witness".into(),
            log: "identity-only: source unpacked and hashed; no isolated build executed".into(),
        })
    }
    fn name(&self) -> &'static str {
        "witness"
    }
}

/// Runs a configured shell command inside the unpacked source dir and hashes
/// the resulting tree as the artifact. Intended for in-TEE use where the
/// command runs under an attested runtime.
pub struct CommandBuilder {
    pub command: String,
}

impl Builder for CommandBuilder {
    fn build(&self, source_dir: &Path) -> anyhow::Result<BuildOutput> {
        let value_x = compute_tree_hash(source_dir)?;

        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&self.command)
            .current_dir(source_dir)
            .output()?;

        let mut log = String::new();
        log.push_str(&String::from_utf8_lossy(&out.stdout));
        log.push_str(&String::from_utf8_lossy(&out.stderr));
        if !out.status.success() {
            anyhow::bail!("build command failed ({}): {}", out.status, log);
        }

        // Hash the post-build tree as the artifact identity.
        let artifact_hash = compute_tree_hash(source_dir)?;

        Ok(BuildOutput {
            value_x,
            source_hash: value_x,
            artifact_hash,
            build_mode: "command".into(),
            log: log.chars().take(4000).collect(),
        })
    }
    fn name(&self) -> &'static str {
        "command"
    }
}
