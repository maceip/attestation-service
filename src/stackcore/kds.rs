//! AMD Key Distribution Service (KDS) client. VENDORED from
//! `maceip/unified-quote` (`v2/src/tee/kds.rs`).
//!
//! Fetches VCEK certificates and cert chains from AMD's public KDS at
//! https://kdsintf.amd.com. This is the fallback when SNP_GET_EXT_REPORT
//! doesn't include certificates. No authentication required.

const KDS_BASE: &str = "https://kdsintf.amd.com";

/// Fetch the VCEK certificate for a specific chip and TCB version.
pub fn fetch_vcek(
    product: &str,
    chip_id: &[u8],
    bl_spl: u8,
    tee_spl: u8,
    snp_spl: u8,
    ucode_spl: u8,
) -> Result<Vec<u8>, String> {
    let chip_id_hex = hex::encode(chip_id);
    let url = format!(
        "{KDS_BASE}/vcek/v1/{product}/{chip_id_hex}?blSPL={bl_spl}&teeSPL={tee_spl}&snpSPL={snp_spl}&ucodeSPL={ucode_spl}"
    );

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let resp = client
        .get(&url)
        .header("Accept", "application/x-pem-file")
        .send()
        .map_err(|e| format!("KDS request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("KDS returned {}: {}", resp.status(), url));
    }

    let body = resp.bytes().map_err(|e| format!("KDS read body: {e}"))?;

    if body.starts_with(b"-----BEGIN") {
        pem_to_der(&body).ok_or_else(|| "Failed to parse PEM from KDS".into())
    } else {
        Ok(body.to_vec())
    }
}

/// Fetch the ASK + ARK cert chain for a product family. Returns (ASK, ARK).
pub fn fetch_cert_chain(product: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let url = format!("{KDS_BASE}/vcek/v1/{product}/cert_chain");

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| format!("HTTP client: {e}"))?;

    let resp = client
        .get(&url)
        .header("Accept", "application/x-pem-file")
        .send()
        .map_err(|e| format!("KDS cert chain request: {e}"))?;

    if !resp.status().is_success() {
        return Err(format!("KDS cert chain returned {}", resp.status()));
    }

    let body = resp.bytes().map_err(|e| format!("KDS read: {e}"))?;
    let pem_str = String::from_utf8_lossy(&body);

    let certs = parse_pem_certs(&pem_str);
    if certs.len() < 2 {
        return Err(format!("Expected 2 certs (ASK + ARK), got {}", certs.len()));
    }

    Ok((certs[0].clone(), certs[1].clone()))
}

/// Extract SNP report fields needed for KDS URL construction.
pub fn extract_kds_params(report: &[u8]) -> Result<(String, Vec<u8>, u8, u8, u8, u8), String> {
    if report.len() < 0x188 {
        return Err(format!("Report too short: {} bytes", report.len()));
    }

    let version = u32::from_le_bytes(report[0..4].try_into().map_err(|_| "version bytes")?);
    let product = match version {
        2 => "Milan",
        5 => "Genoa",
        _ => return Err(format!("Unknown SNP version {version}")),
    };

    let chip_id = report[0x140..0x180].to_vec();

    let tcb = &report[0x180..0x188];
    let bl_spl = tcb[0];
    let tee_spl = tcb[1];
    let snp_spl = tcb[6];
    let ucode_spl = tcb[7];

    Ok((product.to_string(), chip_id, bl_spl, tee_spl, snp_spl, ucode_spl))
}

fn pem_to_der(pem_bytes: &[u8]) -> Option<Vec<u8>> {
    let pem_str = std::str::from_utf8(pem_bytes).ok()?;
    let certs = parse_pem_certs(pem_str);
    certs.into_iter().next()
}

fn parse_pem_certs(pem_str: &str) -> Vec<Vec<u8>> {
    use base64::Engine;
    let engine = base64::engine::general_purpose::STANDARD;

    let mut certs = Vec::new();
    for block in pem_str.split("-----END CERTIFICATE-----") {
        if let Some(start) = block.find("-----BEGIN CERTIFICATE-----") {
            let b64 = &block[start + 27..];
            let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
            if let Ok(der) = engine.decode(&cleaned) {
                certs.push(der);
            }
        }
    }
    certs
}
