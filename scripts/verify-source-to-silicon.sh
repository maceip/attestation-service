#!/usr/bin/env bash
# verify-source-to-silicon.sh — tie GitHub build provenance to AMD hardware.
#
# Two independent roots must agree on one value_x = sha256(attestation-service):
#   1. GitHub/Sigstore: the artifact was built from this repo (in-TEE runner).
#   2. AMD SEV-SNP: a genuine Azure confidential VM bound that same digest into
#      its vTPM AK quote, chained to the AMD root.
#
# Usage: verify-source-to-silicon.sh [endpoint] [owner/repo]
set -euo pipefail

ENDPOINT="${1:-https://attest.secure.build:8443/}"
REPO="${2:-maceip/attestation-service}"
UQ="${UQ:-uq}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

sha256() { sha256sum "$1" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$1" | awk '{print $1}'; }

# attested-TLS endpoints (https) carry the evidence in the cert; plain http
# endpoints serve a bundle. pick the matching verifier subcommand.
case "$ENDPOINT" in
  https://*) AZ_CHECK="check-tls" ;;
  *)         AZ_CHECK="check" ;;
esac

echo "==> [1/4] hardware attestation (Azure SEV-SNP -> AMD root) + value_x"
HW_OUT="$("$UQ" azure "$AZ_CHECK" "$ENDPOINT" 2>&1)" || { echo "$HW_OUT"; exit 1; }
echo "$HW_OUT" | sed 's/^/    /'
echo "$HW_OUT" | grep -q 'verdict: *verified'    || { echo "FAIL: hardware verdict not verified"; exit 1; }
echo "$HW_OUT" | grep -q 'value_x_bound: *true'  || { echo "FAIL: value_x not bound in hardware quote"; exit 1; }
VALUE_X="$(echo "$HW_OUT" | awk '/value_x: /{print $3; exit}')"

echo "==> [2/4] download the GitHub release artifact"
gh release download azure-tee-build --repo "$REPO" --pattern attestation-service --dir "$WORK" --clobber
ART="$WORK/attestation-service"

echo "==> [3/4] GitHub build provenance (sigstore) for the artifact"
gh attestation verify "$ART" --repo "$REPO"

echo "==> [4/4] tie: provenance subject digest == hardware value_x"
D="$(sha256 "$ART")"
echo "    artifact digest D     = $D"
echo "    hardware value_x      = $VALUE_X"
[ "$D" = "$VALUE_X" ] || { echo "FAIL: D != value_x (provenance and hardware disagree)"; exit 1; }

echo
echo "PASS: source -> silicon"
echo "  GitHub attests artifact $D was built from $REPO (in-TEE self-hosted runner)"
echo "  AMD attests a genuine SEV-SNP TEE is bound to value_x = $D"
