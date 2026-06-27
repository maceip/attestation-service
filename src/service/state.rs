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
    /// - `AS_QUOTE_CMD` + `AS_PLATFORM`: collect real hardware quotes via that
    ///   command on the named platform (`nitro`|`sev-snp`|`tdx`). When set, the
    ///   service can issue hardware-rooted receipts. When `AS_QUOTE_CMD` is
    ///   unset the service runs **verify-only** and refuses issuance — it never
    ///   falls back to issuing software-witness receipts. Setting `AS_QUOTE_CMD`
    ///   without a valid `AS_PLATFORM` is a hard error.
    /// - `AS_BUILD_CMD`: if set, run this build command in the source tree;
    ///   otherwise the source tree is witnessed as-is (a measurement primitive,
    ///   still bound into the hardware quote).
    pub fn from_env() -> anyhow::Result<Self> {
        let builder: Arc<dyn Builder> = match std::env::var("AS_BUILD_CMD") {
            Ok(cmd) if !cmd.trim().is_empty() => Arc::new(CommandBuilder { command: cmd }),
            _ => Arc::new(WitnessBuilder),
        };

        let cmd = std::env::var("AS_QUOTE_CMD").ok().filter(|c| !c.trim().is_empty());
        let quote_source: Option<Arc<dyn QuoteSource>> = match cmd {
            Some(cmd) => {
                let plat = std::env::var("AS_PLATFORM")
                    .ok()
                    .filter(|p| !p.trim().is_empty())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "AS_QUOTE_CMD is set but AS_PLATFORM is missing \
                             (expected nitro | sev-snp | tdx)"
                        )
                    })?;
                let platform = match plat.to_lowercase().as_str() {
                    "nitro" => Platform::Nitro,
                    "sev-snp" | "snp" => Platform::SevSnp,
                    "tdx" => Platform::Tdx,
                    other => anyhow::bail!(
                        "unknown AS_PLATFORM '{other}' (expected nitro | sev-snp | tdx)"
                    ),
                };
                Some(Arc::new(CommandQuoteSource { command: cmd, platform }))
            }
            None => None,
        };

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
