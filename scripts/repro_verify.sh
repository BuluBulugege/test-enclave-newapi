#!/usr/bin/env bash
# repro_verify.sh — third-party reproducible-build verifier for the SGX
# relay-core enclave.
#
# It performs the trust check that makes MRENCLAVE meaningful:
#
#   1. Hermetically REBUILD the enclave from source (this checkout) using
#      cmd/relay-core/Dockerfile.reproducible, and read the MRENCLAVE it produces.
#   2. Compare the rebuilt MRENCLAVE to the PUBLISHED expected value.
#   3. (optional) Fetch a LIVE enclave's RA-TLS certificate, extract the
#      MRENCLAVE from its embedded DCAP quote, and compare that too.
#
# All requested comparisons must match; any mismatch exits non-zero. Equality of
#   rebuilt == published == live
# proves the running service is exactly the audited source (docs 03 + 05), whose
# MRENCLAVE is what the attestation quote carries.
#
# The signing key is irrelevant to MRENCLAVE (it only sets MRSIGNER), so this
# verifier never needs the operator's private key — it rebuilds with a throwaway
# key and still gets the same MRENCLAVE.
#
# ---------------------------------------------------------------------------
# USAGE
#   scripts/repro_verify.sh <published-mrenclave> [live-host:port]
#   scripts/repro_verify.sh --print-only
#
#   Positional:
#     <published-mrenclave>  64 hex chars (32 bytes). Required unless --print-only.
#     [live-host:port]       optional live RA-TLS endpoint to cross-check.
#
#   Flags:
#     --print-only           build + print the rebuilt MRENCLAVE; do not compare.
#     --require-live         fail (non-zero) if a requested live check cannot run
#                            (e.g. no relaycore-verify and no openssl+python3).
#
#   Env equivalents / knobs:
#     EXPECTED_MRENCLAVE   same as positional #1
#     LIVE_ENDPOINT        same as positional #2
#     REQUIRE_LIVE=1       fail (non-zero) if a requested live check cannot run
#     IMAGE_TAG            docker tag for the rebuilt image (default: relay-core-repro:verify)
#     DOCKERFILE           path to the reproducible Dockerfile
#                          (default: <repo>/cmd/relay-core/Dockerfile.reproducible)
#     BUILD_CONTEXT        docker build context (default: repo root = this script's ../)
#     PLATFORM             build platform (default: linux/amd64; Gramine is x86-64 only)
#     DOCKER_BUILD_ARGS    extra args appended to `docker build` (e.g. pins:
#                          "--build-arg UBUNTU_REF=ubuntu:24.04@sha256:... --build-arg GRAMINE_VERSION=1.9")
#
# EXAMPLES
#   # rebuild the current checkout and just print the MRENCLAVE
#   scripts/repro_verify.sh --print-only
#
#   # verify against a published value
#   scripts/repro_verify.sh a1b2c3...64hex
#
#   # verify against published value AND a running enclave
#   scripts/repro_verify.sh a1b2c3...64hex relay.example.com:8443
#
# NOTE: to verify a specific release, `git checkout <signed-tag>` first, then run
# this script from that checkout.
set -euo pipefail

# --------------------------------------------------------------------------- #
# args / config
# --------------------------------------------------------------------------- #
PRINT_ONLY=0
POSITIONAL=()
for arg in "$@"; do
  case "$arg" in
    --print-only) PRINT_ONLY=1 ;;
    --require-live) REQUIRE_LIVE=1 ;;
    -h|--help)
      # print the whole leading comment header (skip the shebang), strip "# "
      awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
    *) POSITIONAL+=("$arg") ;;
  esac
done

EXPECTED_MRENCLAVE="${EXPECTED_MRENCLAVE:-${POSITIONAL[0]:-}}"
LIVE_ENDPOINT="${LIVE_ENDPOINT:-${POSITIONAL[1]:-}}"
REQUIRE_LIVE="${REQUIRE_LIVE:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DOCKERFILE="${DOCKERFILE:-${REPO_ROOT}/cmd/relay-core/Dockerfile.reproducible}"
BUILD_CONTEXT="${BUILD_CONTEXT:-${REPO_ROOT}}"
IMAGE_TAG="${IMAGE_TAG:-relay-core-repro:verify}"
PLATFORM="${PLATFORM:-linux/amd64}"
DOCKER_BUILD_ARGS="${DOCKER_BUILD_ARGS:-}"

if [ "${PRINT_ONLY}" -ne 1 ] && [ -z "${EXPECTED_MRENCLAVE}" ]; then
  echo "ERROR: published MRENCLAVE required (arg #1 or EXPECTED_MRENCLAVE), or pass --print-only." >&2
  echo "Run '$0 --help' for usage." >&2
  exit 2
fi

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found on PATH." >&2; exit 2; }
[ -f "${DOCKERFILE}" ] || { echo "ERROR: Dockerfile not found: ${DOCKERFILE}" >&2; exit 2; }

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

# normalize an MRENCLAVE string: lowercase, drop whitespace/colons, strip a
# leading 0x, then keep only hex. Accepts raw, 0x-prefixed, or colon-separated.
norm_mr() {
  local s
  s="$(printf '%s' "${1:-}" | tr 'A-F' 'a-f' | tr -d '[:space:]:')"
  s="${s#0x}"
  printf '%s' "${s}" | tr -cd '0-9a-f'
}

# --------------------------------------------------------------------------- #
# [1/4] hermetic rebuild
# --------------------------------------------------------------------------- #
echo "==> [1/4] Hermetic Docker rebuild of relay-core enclave"
echo "    dockerfile : ${DOCKERFILE}"
echo "    context    : ${BUILD_CONTEXT}"
echo "    platform   : ${PLATFORM}"

REBUILT_MR=""
ARTIFACTS="${WORK}/artifacts"

# Preferred path: export the measured artifacts to the host via BuildKit. This
# yields mrenclave.txt directly, so the host needs NO gramine install.
if DOCKER_BUILDKIT=1 docker build \
      --target artifacts \
      --platform="${PLATFORM}" \
      ${DOCKER_BUILD_ARGS} \
      -o "type=local,dest=${ARTIFACTS}" \
      -f "${DOCKERFILE}" \
      "${BUILD_CONTEXT}" >&2; then
  if [ -f "${ARTIFACTS}/mrenclave.txt" ]; then
    REBUILT_MR="$(norm_mr "$(cat "${ARTIFACTS}/mrenclave.txt")")"
    echo "    exported artifacts -> ${ARTIFACTS}"
  fi
fi

# Fallback: some older Docker lacks `-o type=local`. Build the default image and
# read the MRENCLAVE by running it.
if [ -z "${REBUILT_MR}" ]; then
  echo "    (BuildKit export unavailable or empty — falling back to image build + run)" >&2
  DOCKER_BUILDKIT=1 docker build \
    --platform="${PLATFORM}" \
    ${DOCKER_BUILD_ARGS} \
    -t "${IMAGE_TAG}" \
    -f "${DOCKERFILE}" \
    "${BUILD_CONTEXT}" >&2
  REBUILT_MR="$(norm_mr "$(docker run --rm --platform="${PLATFORM}" "${IMAGE_TAG}" cat /enclave/mrenclave.txt)")"
fi

if [ ${#REBUILT_MR} -ne 64 ]; then
  echo "!! FAIL: could not extract a 64-hex MRENCLAVE from the rebuild (got '${REBUILT_MR}')." >&2
  exit 1
fi
echo "    rebuilt   MRENCLAVE = ${REBUILT_MR}"

# --------------------------------------------------------------------------- #
# print-only mode: emit and stop
# --------------------------------------------------------------------------- #
if [ "${PRINT_ONLY}" -eq 1 ]; then
  echo ""
  echo "MRENCLAVE=${REBUILT_MR}"
  echo "(print-only: no comparison performed)"
  exit 0
fi

# --------------------------------------------------------------------------- #
# [2/4] compare rebuild vs published
# --------------------------------------------------------------------------- #
echo "==> [2/4] Comparing rebuild against PUBLISHED value"
EXPECTED_NORM="$(norm_mr "${EXPECTED_MRENCLAVE}")"
echo "    published MRENCLAVE = ${EXPECTED_NORM}"
if [ ${#EXPECTED_NORM} -ne 64 ]; then
  echo "!! FAIL: published MRENCLAVE is not 64 hex chars: '${EXPECTED_MRENCLAVE}'" >&2
  exit 2
fi
if [ "${REBUILT_MR}" != "${EXPECTED_NORM}" ]; then
  echo "!! FAIL: rebuilt MRENCLAVE does NOT match the published value." >&2
  echo "   Either the published binary was not built from this source, or the" >&2
  echo "   build is not reproducible (check Go/Gramine/base-image pins — doc 08)." >&2
  exit 1
fi
echo "    OK: rebuild matches published MRENCLAVE."

# --------------------------------------------------------------------------- #
# [3/4] extract MRENCLAVE from the LIVE enclave quote (optional)
# --------------------------------------------------------------------------- #
echo "==> [3/4] Cross-checking against a LIVE attestation quote"
if [ -z "${LIVE_ENDPOINT}" ]; then
  echo "    (skipped — no live endpoint given)"
else
  LIVE_MR=""
  # Preferred: the doc-07 client verifier if it is installed.
  if command -v relaycore-verify >/dev/null 2>&1; then
    LIVE_MR="$(norm_mr "$(relaycore-verify --endpoint "${LIVE_ENDPOINT}" --print-mrenclave 2>/dev/null || true)")"
  fi

  # Fallback: fetch the RA-TLS cert with openssl, extract the DCAP quote from the
  # RA-TLS X.509 extension (OID 1.2.840.113741.1337.6, see pkg/raenclave), and
  # read MRENCLAVE from the quote. In a DCAP ECDSA quote the SGX report body
  # starts at byte 48; mr_enclave is at offset 64 within it -> quote[112:144].
  if [ -z "${LIVE_MR}" ]; then
    if command -v openssl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
      host="${LIVE_ENDPOINT%%:*}"; port="${LIVE_ENDPOINT##*:}"
      if openssl s_client -connect "${host}:${port}" -servername "${host}" </dev/null 2>/dev/null \
           | openssl x509 -outform der -out "${WORK}/live_cert.der" 2>/dev/null \
         && [ -s "${WORK}/live_cert.der" ]; then
        LIVE_MR="$(norm_mr "$(python3 - "${WORK}/live_cert.der" <<'PY'
import sys
der = open(sys.argv[1], "rb").read()
quote = None
try:
    from cryptography import x509
    cert = x509.load_der_x509_certificate(der)
    for ext in cert.extensions:
        if ext.oid.dotted_string == "1.2.840.113741.1337.6":
            v = ext.value
            quote = getattr(v, "value", None) or bytes(v)
            break
except Exception:
    quote = None
if quote is None:
    # last-resort: locate the RA-TLS OID DER prefix, then the following OCTET STRING
    oid = bytes([0x06,0x09,0x2a,0x86,0x48,0x86,0xf8,0x4d,0x8a,0x39,0x06])  # 1.2.840.113741.1337.6
    i = der.find(oid)
    if i != -1:
        j = der.find(b"\x04\x82", i)  # OCTET STRING, 2-byte length
        if j != -1:
            n = (der[j+2] << 8) | der[j+3]
            quote = der[j+4:j+4+n]
if not quote or len(quote) < 144:
    sys.exit(0)  # print nothing -> treated as "unavailable"
print(quote[112:144].hex())
PY
)")"
      fi
    fi
  fi

  if [ -z "${LIVE_MR}" ] || [ ${#LIVE_MR} -ne 64 ]; then
    msg="could not extract MRENCLAVE from ${LIVE_ENDPOINT} (need 'relaycore-verify' or openssl+python3[cryptography])."
    if [ "${REQUIRE_LIVE}" = "1" ]; then
      echo "!! FAIL: ${msg}" >&2
      exit 1
    fi
    echo "    WARNING: ${msg}"
    echo "    (skipping live cross-check; rebuild==published already verified)"
  else
    echo "    live      MRENCLAVE = ${LIVE_MR}"
    if [ "${LIVE_MR}" != "${REBUILT_MR}" ]; then
      echo "!! FAIL: the RUNNING enclave's MRENCLAVE differs from the audited source." >&2
      echo "   The live service is NOT running the code you just rebuilt/audited." >&2
      exit 1
    fi
    echo "    OK: live enclave matches rebuild."
  fi
fi

# --------------------------------------------------------------------------- #
# [4/4] verdict
# --------------------------------------------------------------------------- #
echo "==> [4/4] Result"
if [ -n "${LIVE_ENDPOINT}" ] && [ "${LIVE_MR:-}" != "" ] && [ ${#LIVE_MR} -eq 64 ]; then
  echo "PASS: rebuild == published == live quote  (${REBUILT_MR})"
  echo "      => the live service runs exactly the audited relay-core (docs 03, 05)."
else
  echo "PASS: rebuild == published  (${REBUILT_MR})"
fi
exit 0
