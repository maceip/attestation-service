#!/usr/bin/env bash
# End-to-end demo of attestation-service. No TEE required.
#
#   1. builds the service
#   2. issues a stage0 witness receipt for sample source
#   3. cryptographically verifies bundled real TDX (stage0->stage1) and AWS
#      Nitro quotes against pinned vendor roots — entirely offline.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${PORT:-8080}"
BASE="http://127.0.0.1:${PORT}"

say() { printf '\n\033[1;32m== %s ==\033[0m\n' "$*"; }

say "build"
cargo build --release --bin attestation-service

say "start service on ${BASE}"
AS_BIND="127.0.0.1:${PORT}" ./target/release/attestation-service >/tmp/attestation-service.log 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT
sleep 1.5

pp() { python3 -m json.tool 2>/dev/null || cat; }

say "health"
curl -fsS "${BASE}/healthz" | pp

say "stage0 attest (witness) for sample source"
SRC="$(mktemp -d)"
printf 'def main():\n    print("hello, attested world")\n' > "${SRC}/app.py"
printf '# sample workload\n' > "${SRC}/README.md"
TAR="$(mktemp).tar.gz"
tar -C "${SRC}" -czf "${TAR}" .
curl -fsS -X POST --data-binary @"${TAR}" "${BASE}/v1/attest" | pp

say "verify real TDX stage1 (walks stage0->stage1, pinned Intel root)"
curl -fsS -X POST --data-binary @examples/fixtures/tdx_stage1.cbor "${BASE}/v1/verify" | pp

say "verify real AWS Nitro stage0 (pinned AWS Nitro root)"
curl -fsS -X POST --data-binary @examples/fixtures/nitro_stage0.cbor "${BASE}/v1/verify" | pp

say "done"
