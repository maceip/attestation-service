# attestation-service

verifiable eat receipts for arbitrary source.

submit a source tarball; an ephemeral **intel tdx** vm shadow-builds it inside
the tee and returns a signed **eat** receipt that binds the build output to a
hardware quote. the build host is not trusted — only the cpu vendor root is.

it is also the demo surface for the lower layers: it issues stage0 (build) and
stage1 (runtime) eat receipts that chain, and it cryptographically verifies real
aws nitro / amd sev-snp / intel tdx quotes against pinned vendor roots — the same
check `runcard` runs. the eat format and verifier are vendored from
[unified-quote](https://github.com/maceip/unified-quote).

## run

```bash
cargo build --release --bin attestation-service
./target/release/attestation-service        # listens on 127.0.0.1:8080
```

## endpoints

- `POST /v1/attest` — submit a source tarball (`--data-binary @app.tar.gz`, or
  multipart `src=@app.tar.gz`); get a stage0 receipt. chain a runtime onto a
  build by passing the previous eat: header `x-previous-eat: <base64 cbor>`.
- `POST /v1/verify` — verify an eat (raw cbor or base64) and its full
  build→runtime chain against the pinned vendor roots.
- `GET /v1/receipt/{id}` · `GET /healthz`.

## demo (no tee required)

```bash
./scripts/demo.sh
```

issues a witness receipt for sample source, then cryptographically verifies the
bundled real tdx (stage0→stage1 chain) and aws nitro quotes against pinned vendor
roots — entirely offline.

## running inside attested-workload

the service binds `127.0.0.1:8080` and serves `/v1/*` + `/healthz`, so it drops
straight into [attested-workload](https://github.com/maceip/attested-workload)'s
loopback app-proxy — its own responses are then served over attested tls. set
`AS_QUOTE_CMD` + `AS_PLATFORM` to collect real hardware quotes; otherwise receipts
are honest software witnesses (never faked). see `deploy/attested-workload.md`.

## the stack

- agent platform — [cvm-agent](https://github.com/maceip/cvm-agent)
- attestation service — **attestation-service** (here)
- quote format — [unified-quote](https://github.com/maceip/unified-quote)
- in-tee runtime — [attested-workload](https://github.com/maceip/attested-workload)

pages: https://maceip.github.io/attestation-service/

<!-- agentic-canon -->
## agentic canon

<table>
<tr>
<td width="200" valign="top"><img src="docs/assets/canon-scroll.png" width="180" alt="agentic canon" /></td>
<td valign="top">

**no proof, no privilege.**

1. **make behavior enforceable.** replace conventions with hardware quotes, attested gates, and runtime checks.
2. **turn failures into evolution.** each failed verification hardens the shared verifier, not just one deployment.
3. **compose through proofs.** every layer declares what it accepts, returns, and can prove.
4. **carry trust forward.** a proof from one stage becomes the ground the next stands on.

</td>
</tr>
</table>
