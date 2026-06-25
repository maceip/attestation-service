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
