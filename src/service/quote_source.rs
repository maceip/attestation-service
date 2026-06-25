//! Where a hardware quote comes from.
//!
//! The service itself never fabricates hardware evidence. It either obtains a
//! real quote (when running inside a TEE) or returns nothing and the receipt
//! is honestly marked `witness`.
//!
//! [`CommandQuoteSource`] is the seam to the runtime layer (`attested-workload`
//! / `unified-quote`'s `uq`/`aw` binaries): a configured command is given
//! the 64-byte `report_data` (hex) and must emit the raw quote. This keeps
//! device ioctls in the runtime layer where they belong, while the service
//! orchestrates the build→bind→quote flow.

use crate::stackcore::quote::Platform;

/// A collected hardware quote.
pub struct CollectedQuote {
    pub platform: Platform,
    pub raw_quote: Vec<u8>,
    /// Optional platform measurement if the collector reported it separately.
    pub measurement: Vec<u8>,
}

pub trait QuoteSource: Send + Sync {
    /// Collect a quote that binds `report_data` (64 bytes; the first 32 are
    /// the EAT `binding_bytes()`). Returns `Ok(None)` when no TEE is present.
    fn collect(&self, report_data: &[u8; 64]) -> anyhow::Result<Option<CollectedQuote>>;
    fn name(&self) -> &'static str;
}

/// No TEE: every receipt is a software witness.
pub struct SoftwareWitness;

impl QuoteSource for SoftwareWitness {
    fn collect(&self, _report_data: &[u8; 64]) -> anyhow::Result<Option<CollectedQuote>> {
        Ok(None)
    }
    fn name(&self) -> &'static str {
        "software-witness"
    }
}

/// Invoke an external collector. The command is run with the report_data hex
/// appended as its final argument and must write the raw quote bytes to stdout.
///
/// Example (conceptual): `AS_QUOTE_CMD="uq quote --platform tdx --report-data"`
pub struct CommandQuoteSource {
    pub command: String,
    pub platform: Platform,
}

impl QuoteSource for CommandQuoteSource {
    fn collect(&self, report_data: &[u8; 64]) -> anyhow::Result<Option<CollectedQuote>> {
        let rd_hex = hex::encode(report_data);
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{} {}", self.command, rd_hex))
            .output()?;
        if !out.status.success() {
            anyhow::bail!(
                "quote command failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        if out.stdout.is_empty() {
            anyhow::bail!("quote command produced no output");
        }
        Ok(Some(CollectedQuote {
            platform: self.platform,
            raw_quote: out.stdout,
            measurement: Vec::new(),
        }))
    }
    fn name(&self) -> &'static str {
        "command"
    }
}
