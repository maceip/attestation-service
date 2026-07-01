# running inside attested-workload

`attestation-service` is designed to run as the loopback workload behind
[attested-workload](https://github.com/maceip/attested-workload). the runtime
collects a hardware quote for the tee it boots in, binds the serving tls spki
into that quote, and reverse-proxies a local http app. this service is that app.

## contract

- binds `127.0.0.1:8080` (override with `AS_BIND`).
- exposes `GET /healthz` for the runtime's readiness probe.
- all attestation endpoints live under `/v1/*`.

when fronted by `attested-workload`, every response — including the eat receipts
this service issues — is delivered over attested tls. a client runs the same
`unified-quote` verification on the transport that this service runs on its
payloads, so trust composes: transport proof ⟶ build/runtime proof.

## quote source

by default the service runs verify-only and refuses issuance. it does not emit
software-witness receipts.

to collect a real quote, point the service at a quote tool for the host tee:

```bash
export AS_QUOTE_SOURCE="tdx:/usr/local/bin/get-quote"
# command writes raw quote bytes to stdout and receives report_data as final argv (hex)
```

the service commits the eat `binding_bytes` (value_x ‖ tls spki hash) into the
quote's `report_data`, so the resulting receipt is bound to both the code and the
serving key. verification then runs against the pinned vendor root for the
configured platform.

## stage chaining

a build host issues a **stage0** receipt over the source. the runtime issues a
**stage1** receipt and links the build by sending the stage0 eat:

```
x-previous-eat: <base64 cbor of the stage0 eat>
```

`/v1/verify` walks the chain and asserts `value_x` is stable from build to runtime.
