//! Where a hardware quote comes from.
//!
//! The service itself never fabricates hardware evidence and never runs without
//! a hardware quote source: there is no software-witness mode. [`CommandQuoteSource`]
//! is the only implementation and is mandatory (see `AppState::from_env`).
//!
//! [`CommandQuoteSource`] runs the configured runtime collector (`attested-workload`
//! or `unified-quote` binaries). The command receives the 64-byte `report_data`
//! value as hex and must emit the raw quote. Hardware device access stays in
//! the runtime collector; this service builds the receipt, binds it to
//! `report_data`, and attaches the returned quote.

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

/// Invoke an external collector. The command is run with the report_data hex
/// appended as its final argument and must write the raw quote bytes to stdout.
///
/// Example (conceptual): `AS_QUOTE_SOURCE="tdx:uq quote --platform tdx --report-data"`
pub struct CommandQuoteSource {
    pub command: String,
    pub platform: Platform,
}

impl CommandQuoteSource {
    pub fn new(command: String, platform: Platform) -> anyhow::Result<Self> {
        parse_command(&command)?;
        Ok(Self { command, platform })
    }
}

impl QuoteSource for CommandQuoteSource {
    fn collect(&self, report_data: &[u8; 64]) -> anyhow::Result<Option<CollectedQuote>> {
        let rd_hex = hex::encode(report_data);
        let mut argv = parse_command(&self.command)?;
        let prog = argv.remove(0);
        let out = std::process::Command::new(prog)
            .args(argv)
            .arg(rd_hex)
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

fn parse_command(command: &str) -> anyhow::Result<Vec<&str>> {
    let argv = command.split_whitespace().collect::<Vec<_>>();
    if argv.is_empty() {
        anyhow::bail!("quote command must not be empty");
    }
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_quote_source_rejects_empty_command() {
        assert!(CommandQuoteSource::new(" ".into(), Platform::Tdx).is_err());
    }
}
