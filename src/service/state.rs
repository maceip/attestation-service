//! Shared service state and configuration.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::receipt::Receipt;
use crate::service::build::{Builder, CommandBuilder, WitnessBuilder};
use crate::service::quote_source::{CommandQuoteSource, QuoteSource, SoftwareWitness};
use crate::stackcore::quote::Platform;

#[derive(Clone)]
pub struct AppState {
    pub builder: Arc<dyn Builder>,
    pub quote_source: Arc<dyn QuoteSource>,
    pub store: Arc<Mutex<HashMap<String, Receipt>>>,
    pub mode: String,
}

impl AppState {
    /// Build state from the environment.
    ///
    /// - `AS_BUILD_CMD`: if set, run this build command in the source tree
    ///   (otherwise identity-only witness build).
    /// - `AS_QUOTE_CMD` + `AS_PLATFORM`: if set, collect real hardware quotes
    ///   via that command (otherwise software-witness receipts).
    pub fn from_env() -> Self {
        let builder: Arc<dyn Builder> = match std::env::var("AS_BUILD_CMD") {
            Ok(cmd) if !cmd.trim().is_empty() => Arc::new(CommandBuilder { command: cmd }),
            _ => Arc::new(WitnessBuilder),
        };

        let quote_source: Arc<dyn QuoteSource> = match (
            std::env::var("AS_QUOTE_CMD"),
            std::env::var("AS_PLATFORM"),
        ) {
            (Ok(cmd), Ok(plat)) if !cmd.trim().is_empty() => {
                let platform = match plat.to_lowercase().as_str() {
                    "nitro" => Platform::Nitro,
                    "sev-snp" | "snp" => Platform::SevSnp,
                    "tdx" => Platform::Tdx,
                    other => {
                        eprintln!("[attestation-service] unknown AS_PLATFORM '{other}', falling back to witness");
                        return Self::witness(builder);
                    }
                };
                Arc::new(CommandQuoteSource { command: cmd, platform })
            }
            _ => Arc::new(SoftwareWitness),
        };

        let mode = format!("build={} quote={}", builder.name(), quote_source.name());

        Self {
            builder,
            quote_source,
            store: Arc::new(Mutex::new(HashMap::new())),
            mode,
        }
    }

    fn witness(builder: Arc<dyn Builder>) -> Self {
        let quote_source: Arc<dyn QuoteSource> = Arc::new(SoftwareWitness);
        let mode = format!("build={} quote={}", builder.name(), quote_source.name());
        Self {
            builder,
            quote_source,
            store: Arc::new(Mutex::new(HashMap::new())),
            mode,
        }
    }
}
