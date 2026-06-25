//! HTTP surface. Routes live under `/v1/*` plus `/healthz` so the service
//! slots directly into `attested-workload`'s loopback app-proxy (which
//! forwards `/v1/*` and `/healthz` from the enclave to `127.0.0.1:8080`).

use std::collections::HashMap;

use axum::{
    body::{to_bytes, Bytes},
    extract::{FromRequest, Multipart, Path, Request, State},
    http::{header::CONTENT_TYPE, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

use crate::service::attest::{run_attest, AttestOptions};
use crate::service::state::AppState;
use crate::service::verify::{decode_eat, verify_chain};

const BODY_LIMIT: usize = 32 * 1024 * 1024;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(landing))
        .route("/healthz", get(healthz))
        .route("/v1/info", get(info))
        .route("/v1/attest", post(attest))
        .route("/v1/verify", post(verify))
        .route("/v1/receipt/{id}", get(receipt))
        .with_state(state)
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

async fn healthz(State(state): State<AppState>) -> Response {
    (StatusCode::OK, Json(json!({ "status": "ok", "mode": state.mode }))).into_response()
}

async fn info(State(state): State<AppState>) -> Response {
    Json(json!({
        "service": "attestation-service",
        "eat_profile": crate::stackcore::eat::EAT_PROFILE,
        "eat_version": crate::stackcore::eat::EAT_VERSION,
        "mode": state.mode,
        "platforms": ["nitro", "sev-snp", "tdx"],
        "endpoints": {
            "POST /v1/attest": "submit a source tarball, receive a stage0/stage1 EAT receipt",
            "POST /v1/verify": "verify an EAT (raw CBOR or base64) against pinned vendor roots",
            "GET /v1/receipt/{id}": "fetch a previously issued receipt",
            "GET /healthz": "liveness"
        }
    }))
    .into_response()
}

fn parse_query(uri_query: Option<&str>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(q) = uri_query {
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                map.insert(k.to_string(), v.to_string());
            }
        }
    }
    map
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let v = hex::decode(s.trim()).ok()?;
    v.as_slice().try_into().ok()
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s.trim().as_bytes())
        .ok()
}

async fn attest(State(state): State<AppState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let query = parse_query(parts.uri.query());

    let mut opts = AttestOptions::default();
    if let Some(n) = query.get("nonce").and_then(|s| hex32(s)) {
        opts.nonce = Some(n);
    }
    if let Some(t) = query.get("tls_spki").and_then(|s| hex32(s)) {
        opts.tls_spki_hash = Some(t);
    }
    if let Some(prev) = parts
        .headers
        .get("x-previous-eat")
        .and_then(|h| h.to_str().ok())
        .and_then(b64_decode)
    {
        opts.previous_cbor = Some(prev);
    }

    let content_type = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    let source_tar: Vec<u8> = if content_type.starts_with("multipart/form-data") {
        let request = Request::from_parts(parts, body);
        let mut mp = match Multipart::from_request(request, &state).await {
            Ok(m) => m,
            Err(e) => return err(StatusCode::BAD_REQUEST, format!("invalid multipart: {e}")),
        };
        let mut tar: Option<Vec<u8>> = None;
        loop {
            match mp.next_field().await {
                Ok(Some(field)) => {
                    let name = field.name().unwrap_or("").to_string();
                    let data = match field.bytes().await {
                        Ok(b) => b.to_vec(),
                        Err(e) => return err(StatusCode::BAD_REQUEST, format!("field read: {e}")),
                    };
                    match name.as_str() {
                        "src" | "source" | "file" => tar = Some(data),
                        "previous" => opts.previous_cbor = Some(data),
                        "nonce" => {
                            if let Some(n) = std::str::from_utf8(&data).ok().and_then(hex32) {
                                opts.nonce = Some(n);
                            }
                        }
                        _ => {}
                    }
                }
                Ok(None) => break,
                Err(e) => return err(StatusCode::BAD_REQUEST, format!("multipart: {e}")),
            }
        }
        match tar {
            Some(t) => t,
            None => return err(StatusCode::BAD_REQUEST, "no `src` file field in multipart form"),
        }
    } else {
        match to_bytes(body, BODY_LIMIT).await {
            Ok(b) => b.to_vec(),
            Err(e) => return err(StatusCode::BAD_REQUEST, format!("read body: {e}")),
        }
    };

    if source_tar.is_empty() {
        return err(StatusCode::BAD_REQUEST, "empty source payload");
    }

    // Build + quote collection may block (process exec, crypto, KDS network).
    let st = state.clone();
    let result =
        tokio::task::spawn_blocking(move || run_attest(&st, &source_tar, opts)).await;

    match result {
        Ok(Ok(receipt)) => (StatusCode::OK, Json(receipt)).into_response(),
        Ok(Err(e)) => err(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("task panicked: {e}")),
    }
}

async fn verify(body: Bytes) -> Response {
    let token = match decode_eat(&body) {
        Ok(t) => t,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    let receipt = tokio::task::spawn_blocking(move || verify_chain(token)).await;
    match receipt {
        Ok(r) => (StatusCode::OK, Json(r)).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("task panicked: {e}")),
    }
}

async fn receipt(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let found = state.store.lock().ok().and_then(|s| s.get(&id).cloned());
    match found {
        Some(r) => (StatusCode::OK, Json(r)).into_response(),
        None => err(StatusCode::NOT_FOUND, format!("no receipt with id {id}")),
    }
}

async fn landing() -> Html<&'static str> {
    Html(LANDING)
}

const LANDING: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>attestation-service</title>
<style>
body{background:#080a09;color:#c6d2c6;font-family:ui-monospace,Menlo,monospace;
max-width:720px;margin:0 auto;padding:42px 22px;line-height:1.6}
h1{font-weight:600;letter-spacing:-.02em}a{color:#5ef08a}
code{color:#ffb454}.dim{color:#6f7e70}
pre{background:#0d100e;border:1px solid #1c241e;border-radius:5px;padding:14px;overflow:auto}
</style></head><body>
<h1>attestation-service</h1>
<p class="dim">verifiable eat receipts for arbitrary source. the quote format and
verifier are <a href="https://github.com/maceip/unified-quote">unified-quote</a>;
the in-tee runtime is <a href="https://github.com/maceip/attested-workload">attested-workload</a>.</p>
<pre># issue a stage0 receipt for some source
curl -s -X POST --data-binary @app.tar.gz http://localhost:8080/v1/attest

# verify any eat (raw cbor or base64) against pinned vendor roots
curl -s -X POST --data-binary @receipt.cbor http://localhost:8080/v1/verify</pre>
<p class="dim">endpoints: <code>POST /v1/attest</code> · <code>POST /v1/verify</code> ·
<code>GET /v1/receipt/{id}</code> · <code>GET /healthz</code></p>
</body></html>"#;
