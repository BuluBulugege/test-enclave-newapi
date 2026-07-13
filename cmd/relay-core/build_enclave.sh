#!/usr/bin/env bash
# build_enclave.sh — render + sign the relay-core Gramine manifest and print
# the production MRENCLAVE. Run ON THE SGX SERVER (needs gramine tools + the
# built /root/relay-core binary + a gramine signing key).
set -euo pipefail

ENTRYPOINT="${ENTRYPOINT:-/root/relay-core}"
LISTEN_ADDR="${LISTEN_ADDR:-0.0.0.0:8443}"
DNSNAME="${DNSNAME:-relay-core.local}"
WORKDIR="${WORKDIR:-/root/enclave}"
ARCH_LIBDIR="/lib/x86_64-linux-gnu"

mkdir -p "${WORKDIR}"
cd "${WORKDIR}"

# Host directory backing the encrypted /secrets mount. Gramine stores only
# ciphertext here (sealed with the _sgx_mrenclave key); it must exist empty.
mkdir -p "${WORKDIR}/secrets_enc"

# Signing key (MRSIGNER). Reuse the Phase-0 key if present, else generate.
KEY="${HOME}/.config/gramine/enclave-key.pem"
if [ ! -f "${KEY}" ]; then
  echo "== generating gramine signing key =="
  gramine-sgx-gen-private-key
fi

echo "== render manifest =="
gramine-manifest \
  -Dentrypoint="${ENTRYPOINT}" \
  -Darch_libdir="${ARCH_LIBDIR}" \
  -Dlisten_addr="${LISTEN_ADDR}" \
  -Ddnsname="${DNSNAME}" \
  "${MANIFEST_TEMPLATE:-/root/relay-core-src/cmd/relay-core/relay-core.manifest.template}" \
  relay-core.manifest

echo "== sign (produces relay-core.manifest.sgx + relay-core.sig) =="
gramine-sgx-sign \
  --manifest relay-core.manifest \
  --output relay-core.manifest.sgx \
  --key "${KEY}"

echo "== MRENCLAVE / MRSIGNER =="
gramine-sgx-sigstruct-view relay-core.sig | grep -iE "mr_enclave|mr_signer|debug|isv"
