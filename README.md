# attestation-service

verifiable eat receipts for arbitrary source.

submit a source tarball; an ephemeral **intel tdx** vm shadow-builds it inside
the tee and returns a signed **eat** receipt that binds the build output to a
hardware quote. the build host is not trusted — only the cpu vendor root is.

## use

```bash
curl -F src=@app.tar.gz https://<service>/attest
# -> { "verdict": "verified", "eat": "...", "mrtd": "..." }
```

the receipt format and verifier are [unified-quote](https://github.com/maceip/unified-quote).

## the stack

- agent platform — [cvm-agent](https://github.com/maceip/cvm-agent)
- attestation service — **attestation-service** (here)
- quote format — [unified-quote](https://github.com/maceip/unified-quote)
- in-tee runtime — [attested-workload](https://github.com/maceip/attested-workload)

pages: https://maceip.github.io/attestation-service/
