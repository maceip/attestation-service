//! Shared service state and configuration.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::receipt::Receipt;
use crate::service::build::{Builder, CommandBuilder, WitnessBuilder};
use crate::service::quote_source::{CommandQuoteSource, QuoteSource};
use crate::stackcore::quote::Platform;

#[derive(Clone)]
pub struct AppState {
    pub builder: Arc<dyn Builder>,
    /// The hardware quote source. `None` means this deployment is **verify-only**
    /// and will refuse to issue receipts — there is no software-witness issuance.
    pub quote_source: Option<Arc<dyn QuoteSource>>,
    pub store: Arc<Mutex<HashMap<String, Receipt>>>,
    pub mode: String,
}

impl AppState {
    /// Build state from the environment. **Fails closed**: there is no
    /// software-witness mode and no flag/env to enable one.
    ///
    /// - `AS_QUOTE_SOURCE=<platform>:<command>`: collect real hardware quotes
    ///   through the configured command on `nitro`|`sev-snp`|`tdx`.
    ///   `AS_QUOTE_CMD` + `AS_PLATFORM` is accepted only as deprecated
    ///   compatibility for older deployments and is validated the same way. With
    ///   no quote source the service runs verify-only and refuses issuance.
    /// - `AS_BUILD_CMD`: if set, run this build command in the source tree;
    ///   otherwise the source tree is witnessed as-is (a measurement primitive,
    ///   still bound into the hardware quote).
    pub fn from_env() -> anyhow::Result<Self> {
        let builder: Arc<dyn Builder> = match std::env::var("AS_BUILD_CMD") {
            Ok(cmd) if !cmd.trim().is_empty() => Arc::new(CommandBuilder { command: cmd }),
            _ => Arc::new(WitnessBuilder),
        };

        let quote_source: Option<Arc<dyn QuoteSource>> = quote_source_from_env()?;

        let quote_name = match &quote_source {
            Some(qs) => qs.name(),
            None => "none (verify-only; issuance refused)",
        };
        let mode = format!("build={} quote={}", builder.name(), quote_name);

        Ok(Self {
            builder,
            quote_source,
            store: Arc::new(Mutex::new(HashMap::new())),
            mode,
        })
    }
}

fn quote_source_from_env() -> anyhow::Result<Option<Arc<dyn QuoteSource>>> {
    let source = std::env::var("AS_QUOTE_SOURCE")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let cmd = std::env::var("AS_QUOTE_CMD")
        .ok()
        .filter(|c| !c.trim().is_empty());
    let platform = std::env::var("AS_PLATFORM")
        .ok()
        .filter(|p| !p.trim().is_empty());

    match (source, cmd, platform) {
        (Some(source), None, None) => {
            let (platform, command) = parse_quote_source(&source)?;
            Ok(Some(Arc::new(CommandQuoteSource::new(command, platform)?)))
        }
        (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
            anyhow::bail!("set either AS_QUOTE_SOURCE or AS_QUOTE_CMD + AS_PLATFORM, not both")
        }
        (None, Some(command), Some(platform)) => {
            let platform = parse_platform(&platform, "AS_PLATFORM")?;
            Ok(Some(Arc::new(CommandQuoteSource::new(command, platform)?)))
        }
        (None, Some(_), None) => {
            anyhow::bail!(
                "AS_QUOTE_CMD is set but AS_PLATFORM is missing (expected nitro | sev-snp | tdx)"
            )
        }
        (None, None, Some(_)) => {
            anyhow::bail!("AS_PLATFORM is set but AS_QUOTE_CMD is missing")
        }
        (None, None, None) => Ok(None),
    }
}

fn parse_quote_source(source: &str) -> anyhow::Result<(Platform, String)> {
    let (platform, command) = source
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("AS_QUOTE_SOURCE must be '<platform>:<command>'"))?;
    let platform = parse_platform(platform, "AS_QUOTE_SOURCE platform")?;
    let command = command.trim();
    if command.is_empty() {
        anyhow::bail!("AS_QUOTE_SOURCE command must not be empty");
    }
    Ok((platform, command.to_string()))
}

fn parse_platform(value: &str, name: &str) -> anyhow::Result<Platform> {
    match value.trim().to_lowercase().as_str() {
        "nitro" => Ok(Platform::Nitro),
        "sev-snp" | "snp" => Ok(Platform::SevSnp),
        "tdx" => Ok(Platform::Tdx),
        other => anyhow::bail!("unknown {name} '{other}' (expected nitro | sev-snp | tdx)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_quote_source_accepts_platform_command_pair() {
        let (platform, command) = parse_quote_source("sev-snp:uq azure collect").unwrap();
        assert!(matches!(platform, Platform::SevSnp));
        assert_eq!(command, "uq azure collect");
    }

    #[test]
    fn parse_quote_source_rejects_missing_command() {
        let err = parse_quote_source("tdx:   ").unwrap_err();
        assert!(err.to_string().contains("command must not be empty"));
    }

    #[test]
    fn parse_quote_source_rejects_unknown_platform() {
        let err = parse_quote_source("desktop-tpm:collect").unwrap_err();
        assert!(err.to_string().contains("unknown AS_QUOTE_SOURCE platform"));
    }
}
