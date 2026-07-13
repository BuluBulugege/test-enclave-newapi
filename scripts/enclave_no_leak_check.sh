#!/usr/bin/env bash
# enclave_no_leak_check.sh — CI guard for the SGX relay-core "no content at rest"
# property. It fails (non-zero exit) if the enclave binary's package closure
# either (a) imports a forbidden business package that carries disk/log/DB code,
# or (b) references a forbidden content-persistence symbol in its own source.
#
# This turns the manual purity check into an automated invariant. Run in CI on
# every change touching cmd/relay-core or pkg/officialurls or pkg/relaycontrol.
#
# Usage: scripts/enclave_no_leak_check.sh
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="./cmd/relay-core"
MODULE="github.com/QuantumNous/new-api"

# Packages that must NEVER appear in the enclave closure. These carry the four
# audited content-leak sites (disk cache, dify temp file, debug body dumps,
# error-body logging) plus the DB/business layer.
FORBIDDEN_PKGS_RE="/(dto|common|logger|model|service|setting|middleware|controller|relay/helper)($|/)"

# Symbols that write content to non-volatile storage or logs. Even a single
# reference in the enclave closure's source is a red flag.
FORBIDDEN_SYMS=(
  "os.Create"
  "os.OpenFile"
  "os.WriteFile"
  "ioutil.WriteFile"
  "CreateDiskCacheFile"
  "WriteDiskCacheFile"
  "RecordErrorLog"
  "LocalLogPreview"
  "os.CreateTemp"
)

fail=0

echo "== [1/2] package-closure check on ${TARGET} =="
CLOSURE=$(go list -deps "${TARGET}" 2>/dev/null | grep "${MODULE}" || true)
if [ -z "${CLOSURE}" ]; then
  echo "ERROR: could not compute package closure for ${TARGET}" >&2
  exit 2
fi

BAD_PKGS=$(echo "${CLOSURE}" | grep -E "${FORBIDDEN_PKGS_RE}" || true)
if [ -n "${BAD_PKGS}" ]; then
  echo "FAIL: enclave closure contains forbidden package(s):" >&2
  echo "${BAD_PKGS}" | sed 's/^/  - /' >&2
  fail=1
else
  echo "  ok: no forbidden packages in closure"
  echo "  closure (internal):"
  echo "${CLOSURE}" | sed 's/^/    /'
fi

echo "== [2/2] forbidden-symbol scan over closure source =="
# Resolve each closure package to its source dir and grep .go files (excluding
# _test.go). We only scan packages inside this module.
SCAN_DIRS=()
while IFS= read -r pkg; do
  [ -z "${pkg}" ] && continue
  dir=$(go list -f '{{.Dir}}' "${pkg}" 2>/dev/null || true)
  [ -n "${dir}" ] && SCAN_DIRS+=("${dir}")
done <<< "${CLOSURE}"

for sym in "${FORBIDDEN_SYMS[@]}"; do
  for dir in "${SCAN_DIRS[@]}"; do
    # Grep non-test Go files; ignore comment-only lines starting with // for
    # robustness against commented-out leak code.
    hits=$(grep -rnF "${sym}" "${dir}" --include="*.go" 2>/dev/null \
             | grep -v "_test.go" \
             | grep -vE "^\s*[^:]+:[0-9]+:\s*//" || true)

    # EXEMPTION (narrow, audited): pkg/raenclave is the small, hand-audited
    # enclave secret/attestation package. Its ONLY os.WriteFile uses are:
    #   1. writing SHA-512(TLS-pubkey) to /dev/attestation/user_report_data, and
    #   2. sealing an upstream API key into the _sgx_mrenclave-encrypted mount.
    # Neither writes request/response CONTENT — they handle attestation input and
    # a provider secret. We drop os.WriteFile hits ONLY in pkg/raenclave; the
    # relay content path (main/dispatch/relaycontrol) still must have zero writes.
    if [ -n "${hits}" ] && [ "${sym}" = "os.WriteFile" ]; then
      hits=$(echo "${hits}" | grep -v "/pkg/raenclave/" || true)
    fi

    if [ -n "${hits}" ]; then
      echo "FAIL: forbidden symbol '${sym}' referenced in enclave closure:" >&2
      echo "${hits}" | sed 's/^/  /' >&2
      fail=1
    fi
  done
done
[ "${fail}" -eq 0 ] && echo "  ok: no forbidden symbols in closure source"

if [ "${fail}" -ne 0 ]; then
  echo "" >&2
  echo "enclave leak-guard FAILED — the relay-core enclave must not link content-persistence code." >&2
  exit 1
fi
echo ""
echo "enclave leak-guard PASSED"
