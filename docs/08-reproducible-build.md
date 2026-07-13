# 08 — Reproducible Build & MRENCLAVE Pinning for relay-core

> Scope: how to build the `cmd/relay-core` Go binary and its Gramine-SGX 1.9
> enclave so that **any third party can rebuild from the published source at a
> pinned git commit and obtain a bit-identical enclave with the same
> MRENCLAVE**. This closes the "audited source == running code" link: the
> MRENCLAVE inside the DCAP quote (doc 02) is only meaningful if that measurement
> provably corresponds to source that has no content-persistence path (doc 05)
> and enforces official upstream URLs (doc 03). Targets Gramine **v1.9**,
> production **non-debug** enclave.
>
> This document is about the *build*. Doc 02 covers how the running enclave
> proves its MRENCLAVE over RA-TLS; doc 07 covers the client verifier. Here we
> make MRENCLAVE reproducible and publishable.

---

## 0. Why this matters (the trust chain)

The no-log guarantee rests on a chain:

```
published source @ commit X
   │  (reproducible build — THIS DOC)
   ▼
bit-identical relaycore binary + .manifest.sgx
   │  (gramine-sgx-sign)
   ▼
MRENCLAVE = M
   │  (attestation, doc 02)
   ▼
DCAP quote embeds M  →  client pins M  (doc 07)
```

If the build is **not** reproducible, a third party cannot confirm that the
enclave whose MRENCLAVE is `M` was built from the audited source. The operator
could attest an enclave built from *different* source (one that logs prompts)
and the client would have no way to detect it. Reproducibility is therefore not
a nicety — it is the mechanism that makes the source audit (docs 03, 05)
binding on the running binary.

**Non-goal:** we do not need the whole Docker image reproducible, only the two
artifacts that feed MRENCLAVE: the `relaycore` ELF and the rendered
`relaycore.manifest.sgx`.

---

## 1. Toolchain conflict — resolution (READ THIS FIRST)

Verified by reading the repo:

| Source | Declares |
|---|---|
| `go.mod` line 4 | `go 1.25.1` (language/module minimum). No `toolchain` directive present. |
| `Dockerfile` line 23 | `golang:1.26.1-alpine@sha256:2389ebfa...` (the actual compiler used for the main `new-api` binary) |
| `VERSION` file | **empty** in both working tree and `git HEAD` (the `-X Version=$(cat VERSION)` ldflag injects an empty string today) |
| `Dockerfile` line 24, 29 | `CGO_ENABLED=0`, `GOEXPERIMENT=greenteagc` |

So the module *requires* at least Go 1.25.1, but the image *builds with* Go
1.26.1. A `go 1.25.1` directive is a **minimum**, not a pin; toolchain 1.26.1
satisfies it. There is no contradiction in correctness — but for a reproducible
build "at least 1.25.1" is useless, because the exact compiler patch version
changes generated machine code and therefore MRENCLAVE.

### Recommendation: pin Go **1.26.1** for relay-core

1. **Match the Dockerfile (1.26.1).** It is the newest of the two, it already
   satisfies `go 1.25.1`, and it is what the project's real artifact is compiled
   with today — least surprise, no second toolchain to maintain.
2. **Pin it hard, three ways at once**, so no machine silently substitutes a
   different compiler:
   - Base the build image on `golang:1.26.1-alpine` **by digest** (the exact
     `@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039`
     already in the Dockerfile).
   - Add an explicit `toolchain go1.26.1` directive to the relay-core module (or
     a dedicated `go.mod` for `cmd/relay-core` if it is split out) so `go`
     records the intended toolchain in source.
   - Set `GOTOOLCHAIN=local` in the build environment. This **disables Go's
     automatic toolchain download**: if the installed `go` is not 1.26.1 the
     build fails loudly instead of fetching a different version behind your back.
     This is the single most important flag for reproducibility — without it, a
     newer `toolchain` line or `go.mod` bump can cause `go` to download and use a
     compiler you never pinned.
3. **Pin `GOEXPERIMENT` identically.** The Dockerfile sets
   `GOEXPERIMENT=greenteagc`. Experiments change code generation and runtime
   layout, so this **must** be part of the pinned environment for relay-core too
   — either keep `greenteagc` (recommended, to match the audited/known-good
   config) or drop it, but decide once and record it in the release manifest
   (§4). A mismatched `GOEXPERIMENT` silently produces a different binary and a
   different MRENCLAVE.

> If the team prefers to standardize the whole repo on one compiler, bump
> `go.mod`'s directive and the Dockerfile together to `1.26.1` and delete the
> ambiguity. Until then, relay-core pins 1.26.1 as above.

---
## 2. Deterministic Go build for relay-core

### 2.1 The CGO question (relay-core is different from `new-api`)

The main `new-api` build is `CGO_ENABLED=0` — a fully static, pure-Go binary,
which is trivially reproducible. **relay-core is not necessarily so**, because
attestation may need C libraries:

- If relay-core uses **Option A** from doc 02 (dlopen Gramine's
  `libra_tls_attest.so` via cgo) or links `libsgx_dcap_*` directly, it needs
  `CGO_ENABLED=1`. cgo pulls in the host C toolchain (gcc/musl on Alpine, or
  glibc on Debian) and those libraries' versions become part of the binary.
- If relay-core uses **Option B** (pure Go, treating `/dev/attestation/*` as
  plain files — doc 02's recommended path), then `CGO_ENABLED=0` and the build
  is as reproducible as `new-api`.

**Recommendation: prefer Option B (CGO_ENABLED=0) for relay-core.** Doc 02
already recommends it for a smaller TCB; here it also removes the C toolchain and
`libsgx_dcap`/glibc versions from the reproducibility surface. A pure-Go static
binary depends only on (a) the pinned Go toolchain, (b) module sources hashed in
`go.sum`, (c) build flags. All three are pinnable.

If cgo is unavoidable, then determinism additionally requires pinning: the exact
C compiler, the exact `libsgx-dcap-*` package versions, the C library (musl vs
glibc), and `-gcflags`/`-ldflags` that reach the C linker. Every one of those
must be locked in the build image by digest + apt version pin. Treat cgo as the
hard case and document each C dependency version in the release manifest (§4).

### 2.2 Exact build command and environment

```bash
# ---- pinned environment ----
export GOTOOLCHAIN=local          # never auto-download a different compiler
export CGO_ENABLED=0              # Option B; set 1 only if linking DCAP C libs
export GOOS=linux
export GOARCH=amd64               # SGX target is x86-64; pin it, don't inherit host
export GOEXPERIMENT=greenteagc    # MUST match the audited config (see §1.3)
export GOFLAGS='-trimpath -buildvcs=false -mod=readonly'
export SOURCE_DATE_EPOCH=0        # neutralize any timestamp-sensitive step
# make module/proxy resolution deterministic:
export GOPROXY=off                # build from a fully vendored tree (see note)
export GONOSUMCHECK=0

VERSION_STR="$(cat VERSION)"      # empty today; a release should populate it

go build \
  -trimpath \
  -buildvcs=false \
  -mod=readonly \
  -ldflags "-s -w -buildid= -X 'github.com/QuantumNous/new-api/common.Version=${VERSION_STR}'" \
  -o relaycore \
  ./cmd/relay-core
```

Flag-by-flag, why each matters for a byte-identical binary:

| Flag / env | Effect on determinism |
|---|---|
| `-trimpath` | Removes absolute filesystem paths (`/build/...`, `/home/...`) from the compiled binary. Without it the binary embeds the builder's GOPATH/module cache path and differs per machine. **Mandatory.** |
| `-buildvcs=false` | Stops Go from stamping VCS info (commit hash, dirty flag, build time) into the binary. That stamp differs between a clean checkout and a working tree and would change the bytes. **Mandatory.** |
| `-ldflags "-s -w"` | Strips the symbol table (`-s`) and DWARF (`-w`). Smaller, and removes some path/debug noise. Both sides must use the same choice. |
| `-ldflags "-buildid="` | Sets the Go build ID to empty. The build ID is derived from a content hash but is a known source of surprise diffs across environments; forcing it empty removes that variable. (Combined with `-trimpath` the content hash is stable, but pinning it empty is belt-and-suspenders.) |
| `-X ...Version=<fixed>` | Only inject values that are **identical** for everyone rebuilding the same commit. Use the committed `VERSION` file content (or the git tag), never `date`, `hostname`, `git rev-parse` at build time, or a CI build number. A varying `-X` value is the most common self-inflicted reproducibility break. |
| `GOTOOLCHAIN=local` | Fails instead of downloading a different Go — see §1. |
| `CGO_ENABLED=0` | Static, no C toolchain in the surface (Option B). |
| `GOOS/GOARCH` pinned | The output must be `linux/amd64` regardless of who builds it. Never inherit from the host. |
| `GOEXPERIMENT` pinned | Experiments change codegen/runtime; must match. |
| `-mod=readonly` + `go.sum` | Module contents are hash-verified; nobody can substitute a tampered dependency without changing `go.sum` (which is in the audited commit). |
| `GOPROXY=off` + vendoring | See note below. |
| `SOURCE_DATE_EPOCH=0` | Go itself does not embed wall-clock time when `-buildvcs=false` and `-trimpath` are set, but downstream steps (tar, manifest signing, archive creation) may; exporting it makes the whole pipeline timestamp-stable. |

> **Vendor the dependencies.** For a hermetic third-party rebuild, commit a
> `vendor/` directory (`go mod vendor`) and build with `-mod=vendor`
> (`GOFLAGS=-mod=vendor`) and `GOPROXY=off`. This removes the module proxy and
> the network from the reproducibility surface entirely: the exact dependency
> bytes live in the audited commit. If you instead rely on `GOPROXY` + `go.sum`,
> the build is still verifiable (sums are pinned) but now depends on the proxy
> serving identical module zips — an extra external dependency. Vendoring is the
> stronger choice for a security artifact.

---
## 3. MRENCLAVE vs MRSIGNER — what each measures, and what to pin

Two 32-byte SGX measurements land in every quote. Pinning the **wrong** one
breaks the trust chain.

### MRENCLAVE — the enclave identity (PIN THIS)

MRENCLAVE is a SHA-256 built incrementally by the SGX `EINIT`/`EEXTEND` flow
over **everything that defines the enclave's initial state**:

- the enclave code and initialized data pages,
- the **page layout**: which virtual addresses get which pages, their
  permissions (R/W/X), and the order they are added,
- heap, stack, and thread-control-structure pages sized by the manifest
  (`sgx.enclave_size`, `sgx.max_threads`, stack size),
- for Gramine specifically, the measurement folds in the **Gramine loader
  (libos/PAL) pages and the manifest measurement** — i.e. the `SIGSTRUCT` that
  `gramine-sgx-sign` produces covers the manifest and all trusted-file hashes.

So MRENCLAVE = *this exact code + this exact Gramine + this exact manifest +
this exact memory geometry*. Change any of them and MRENCLAVE changes. That is
precisely the property we want: it is a fingerprint of the running software.
**Third parties pin MRENCLAVE.**

### MRSIGNER — the signer identity (do NOT pin as the primary check)

MRSIGNER is `SHA-256` of the **public part of the RSA key** used to sign the
enclave (`gramine-sgx-sign -k enclave-key.pem`). It says "some key signed this
enclave", not "this specific code". Consequences:

- **Rotating the signing key changes MRSIGNER but does NOT change MRENCLAVE.**
  The code measurement is independent of who signed it. So if we re-sign the
  identical enclave with a new key, MRENCLAVE stays `M`; only MRSIGNER changes.
- Conversely, an attacker with *any* valid signing key can produce an enclave
  with the *same* MRSIGNER family but a **different** MRENCLAVE (different code).
  MRSIGNER-only pinning would accept that malicious enclave.

**Therefore the client verifier (doc 07) pins MRENCLAVE as the authoritative
identity.** MRSIGNER (plus `isvprodid`/`isvsvn`) may be checked as a secondary
policy, but MRENCLAVE is the anchor. This also means we are free to rotate the
signing key for operational reasons without invalidating the published
MRENCLAVE — a real benefit, and a reason the published artifact (§4) lists
MRENCLAVE first.

### How the Gramine manifest feeds MRENCLAVE (and why it must be pinned)

`gramine-manifest` renders `relaycore.manifest.template` → `relaycore.manifest`
(TOML), then `gramine-sgx-sign` produces `relaycore.manifest.sgx` +
`relaycore.sig`. The signing step:

1. hashes every file in `sgx.trusted_files` and writes those hashes **into** the
   final manifest,
2. computes MRENCLAVE over the loader + manifest + measured pages,
3. writes the `SIGSTRUCT`.

Because trusted-file hashes and enclave geometry are baked in, the manifest is
**part of the measured input**. Any of the following changes MRENCLAVE:

- `sgx.enclave_size` (e.g. `"2G"` vs `"4G"`) — changes page count/layout,
- `sgx.max_threads` — changes TCS page count,
- `sgx.trusted_files` list or the **content** of any trusted file (the relaycore
  binary hash, the Gramine runtime `.so` hashes),
- `loader.env.*` values baked into the manifest,
- `fs.mounts` entries,
- `sgx.debug` (production `false` vs Phase-0 `true` — different MRENCLAVE; see
  §6 and the Phase-0 note),
- `sgx.isvprodid` / `sgx.isvsvn`.

So the manifest **template must be committed** to the audited commit and
rendered **deterministically**. Watch these nondeterminism traps in the rendered
`.manifest.sgx`:

- **Absolute/host-specific paths.** `gramine-manifest` expands
  `{{ gramine.runtimedir() }}`, `{{ arch_libdir }}`, `{{ gramine.libos }}` to
  paths that depend on where Gramine is installed. If two builders install
  Gramine in different prefixes, the rendered paths — and the trusted-file set —
  differ, and MRENCLAVE differs. **Fix:** build inside the pinned Docker image so
  the Gramine install prefix is identical for everyone (§4).
- **Timestamps / build host values.** Do not template in `hostname`, build
  dates, or `pwd`. Keep the template free of environment-derived values except
  the fixed ones you control.
- **Trusted-file ordering / globs.** Directory globs
  (`file:{{ gramine.runtimedir() }}/`) expand to whatever files exist in that
  dir; a drifting Gramine minor version changes that set. Pin the Gramine
  version (§4, §6) so the glob expands identically.
- **`gramine-manifest` variable injection** (`-Dvar=value`). Any `-D` values
  passed at render time must be identical across builders; record them in the
  release manifest.

Commit the template; publish the exact `gramine-manifest`/`gramine-sgx-sign`
invocation; render inside the pinned image. Then the rendered manifest — and
thus MRENCLAVE — is reproducible.

---
## 4. Hermetic Docker build → bit-identical enclave + printed MRENCLAVE

The build must be **hermetic**: same inputs → same MRENCLAVE, on any host, with
no dependency on the builder's machine state. Everything that touches the
measurement is pinned by digest or apt version.

### 4.1 Dockerfile sketch (`docker/relay-core.reproducible.Dockerfile`)

```dockerfile
# ---- Stage 1: build relaycore (pinned Go, matches §1 resolution) ----
# Pinned BY DIGEST, Go 1.26.1 to match the repo Dockerfile.
FROM golang:1.26.1-alpine@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS gobuild
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    GOOS=linux GOARCH=amd64 \
    GOEXPERIMENT=greenteagc \
    GOFLAGS=-mod=vendor \
    GOPROXY=off \
    SOURCE_DATE_EPOCH=0
WORKDIR /build
COPY . .
# Build ONLY from the vendored tree; no network.
RUN VERSION_STR="$(cat VERSION)" && \
    go build -trimpath -buildvcs=false -mod=vendor \
      -ldflags "-s -w -buildid= -X 'github.com/QuantumNous/new-api/common.Version=${VERSION_STR}'" \
      -o /out/relaycore ./cmd/relay-core

# ---- Stage 2: Gramine sign, pinned Gramine 1.9 ----
# Pin the Gramine base image by digest. gramineproject/gramine ships gramine +
# the SGX tooling; pin the tag to the 1.9 image AND its digest.
FROM gramineproject/gramine:1.9@sha256:<PIN_THE_1.9_IMAGE_DIGEST> AS graminesign
# If installing via apt instead, pin the exact package version:
#   RUN apt-get update && apt-get install -y --no-install-recommends gramine=1.9
# (never an unpinned `gramine`; a 1.9.x point release can shift the loader pages
#  and therefore MRENCLAVE — see §6).
WORKDIR /enclave
COPY --from=gobuild /out/relaycore ./relaycore
COPY docker/relaycore.manifest.template ./relaycore.manifest.template

# Deterministic signing key. For a *reproducible* MRENCLAVE the key is
# IRRELEVANT (it only sets MRSIGNER, §3). Use a build-time throwaway key OR the
# committed public-verifiable key; MRENCLAVE is identical either way.
RUN openssl genrsa -3 -out enclave-key.pem 3072

# Render manifest deterministically. All -D vars are fixed values, no host state.
RUN gramine-manifest \
      -Dlog_level=error \
      -Darch_libdir=/lib/x86_64-linux-gnu \
      -Dentrypoint=/relaycore \
      relaycore.manifest.template \
      relaycore.manifest

# Produce PRODUCTION (non-debug) SIGSTRUCT + signed manifest.
# (sgx.debug=false must be set in the template — see §6.)
RUN gramine-sgx-sign \
      --manifest relaycore.manifest \
      --key enclave-key.pem \
      --output relaycore.manifest.sgx

# Print MRENCLAVE (the authoritative measurement) from the SIGSTRUCT.
RUN gramine-sgx-sigstruct-view relaycore.sig \
      && gramine-sgx-sigstruct-view --verbose relaycore.sig | tee /out-mr.txt

# ---- Stage 3: export just the measured artifacts ----
FROM scratch AS artifacts
COPY --from=graminesign /enclave/relaycore /relaycore
COPY --from=graminesign /enclave/relaycore.manifest.sgx /relaycore.manifest.sgx
COPY --from=graminesign /enclave/relaycore.sig /relaycore.sig
```

`gramine-sgx-sigstruct-view` prints MRENCLAVE (and MRSIGNER, `isv_prod_id`,
`isv_svn`, `debug` flag). That printed MRENCLAVE is the value we publish (§5) and
that the client pins (doc 07). Extract it in the verify script with:

```bash
docker build --target artifacts -o type=local,dest=./artifacts \
  -f docker/relay-core.reproducible.Dockerfile .
# then, from a gramine image:
gramine-sgx-sigstruct-view ./artifacts/relaycore.sig | grep -i mr_enclave
```

### 4.2 Nondeterminism sources this design neutralizes

| Source | Neutralized by |
|---|---|
| Build timestamps | `-buildvcs=false`, `-trimpath`, `SOURCE_DATE_EPOCH=0` |
| Absolute paths in binary | `-trimpath` |
| Absolute paths in manifest | Build inside the pinned image (identical Gramine prefix) + fixed `-D` vars |
| Go compiler drift | `golang:1.26.1-alpine@sha256:...` + `GOTOOLCHAIN=local` |
| Dependency drift | vendored tree + `-mod=vendor` + `GOPROXY=off` + `go.sum` |
| Gramine version drift (loader pages) | Gramine base image pinned by **digest**, or apt `gramine=1.9` exact pin |
| glibc/musl drift (matters only if cgo) | musl fixed by the pinned Alpine Go image; if cgo, pin the runtime image too |
| Enclave geometry | `sgx.enclave_size`, `sgx.max_threads`, stack size all fixed in the committed template |
| File ordering in trusted_files globs | Deterministic once Gramine version is pinned (glob expands over the same fileset) |
| Signing-key variance | Irrelevant to MRENCLAVE by design (§3); only affects MRSIGNER |

Two independent machines running this Docker build from the same commit must
print the same MRENCLAVE. That equality is the thing a third party checks (§5).

---
## 5. Publication artifact — the RELEASE manifest

A release is only trustworthy if the mapping *MRENCLAVE ↔ source commit* is
published **authentically**. The artifact is a signed document (checked into the
repo as `docs/cc-research/releases/relaycore-<version>.md` and attached to a
signed GitHub release) with these fields:

```yaml
# relaycore reproducible-build release record
relaycore_version:   "1.0.0"            # matches VERSION file content
git_commit:          "ca50b9437...full-40-char-sha"
git_tag:             "relaycore-v1.0.0"

# --- the measurement third parties pin ---
mrenclave:           "a1b2c3...64 hex chars (32 bytes)"
mrsigner:            "d4e5f6...64 hex chars"   # informational; rotatable (§3)
isv_prod_id:         0
isv_svn:             1
sgx_debug:           false                    # PRODUCTION (§6)

# --- exact toolchain / environment (§1, §2) ---
go_toolchain:        "go1.26.1"
go_image_digest:     "sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039"
cgo_enabled:         false
goexperiment:        "greenteagc"
goflags:             "-trimpath -buildvcs=false -mod=vendor"
ldflags:             "-s -w -buildid= -X github.com/QuantumNous/new-api/common.Version=1.0.0"

# --- Gramine (§4, §6) ---
gramine_version:     "1.9"
gramine_image_digest: "sha256:<pinned>"
manifest_template_sha256: "sha256 of docker/relaycore.manifest.template @ commit"
rendered_manifest_sgx_sha256: "sha256 of relaycore.manifest.sgx"
enclave_size:        "2G"
max_threads:         64

# --- build reproduction ---
build_command: "docker build --target artifacts -o type=local,dest=./artifacts -f docker/relay-core.reproducible.Dockerfile ."

# --- the trust mapping (the whole point) ---
source_audit:
  no_content_persistence: "verified — see docs/cc-research/05-*.md; relay-core has no prompt/response write path"
  official_urls_enforced:  "verified — see docs/cc-research/03-*.md; upstream base URLs are pinned/allowlisted"
  statement: >
    This MRENCLAVE corresponds to relay-core source at commit <git_commit>,
    which has no content-persistence path (doc 05) and enforces official
    upstream URLs (doc 03). Rebuilding that commit with the toolchain and
    Gramine version above yields this MRENCLAVE.
```

### Publishing authentically

The record is only as trustworthy as its origin proof. Publish so a third party
can confirm *who* asserted the mapping:

1. **Tag the commit** and create a **GitHub release** for `relaycore-v1.0.0`.
2. **Sign the git tag** (`git tag -s`) with a maintainer GPG key whose
   fingerprint is published out-of-band (repo README, website, keyservers). The
   tag signature binds the release to the exact commit.
3. Attach the release record file **and** its detached signature
   (`gpg --detach-sign` or `cosign sign-blob`) so verifiers can check the record
   itself was not altered.
4. Optionally attach the built `relaycore.sig` (the SIGSTRUCT) so verifiers can
   `gramine-sgx-sigstruct-view` it without rebuilding, as a cross-check against
   their own rebuild.
5. If using GitHub's build provenance / attestations
   (`actions/attest-build-provenance`), attach that too — but note it certifies
   *GitHub's* CI ran the build, not reproducibility. The independent rebuild
   (§6) remains the real guarantee.

Do **not** rely on an unsigned release page: the security claim is
"source→MRENCLAVE", and only a signature ties the published MRENCLAVE to an
identity a client can trust.

---
## 6. Third-party verify script

A verifier does three things: (1) rebuild the enclave from the pinned commit,
(2) read the MRENCLAVE out of their own build, (3) confirm it equals both the
**published** value and the MRENCLAVE inside a **live attestation quote** from
the running service (doc 02/07). All three must match.

`scripts/verify-relaycore-mrenclave.sh`:

```bash
#!/usr/bin/env bash
# Reproducible-build verifier for relay-core.
# Rebuilds the enclave from a pinned commit and compares MRENCLAVE against
# (a) the published release record and (b) a live RA-TLS quote.
set -euo pipefail

COMMIT="${1:?usage: verify-relaycore-mrenclave.sh <git-commit> <published-mrenclave> [live-host:port]}"
PUBLISHED_MR="${2:?published MRENCLAVE (64 hex chars) required}"
LIVE_ENDPOINT="${3:-}"          # optional: host:port of the running enclave

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> [1/4] Fetching source @ ${COMMIT}"
git clone --quiet https://github.com/QuantumNous/new-api "$WORK/src"
git -C "$WORK/src" checkout --quiet "$COMMIT"

echo "==> [2/4] Hermetic Docker rebuild"
docker build --no-cache \
  --target artifacts \
  -o "type=local,dest=$WORK/artifacts" \
  -f "$WORK/src/docker/relay-core.reproducible.Dockerfile" \
  "$WORK/src"

echo "==> [3/4] Extracting MRENCLAVE from our rebuild"
# Read the SIGSTRUCT with a pinned gramine image (no host gramine needed).
REBUILT_MR="$(docker run --rm -v "$WORK/artifacts:/a" \
  gramineproject/gramine:1.9@sha256:<PIN_THE_1.9_IMAGE_DIGEST> \
  gramine-sgx-sigstruct-view /a/relaycore.sig \
  | awk -F': *' '/mr_enclave/ {gsub(/[^0-9a-fA-F]/,"",$2); print tolower($2)}')"

echo "    rebuilt   MRENCLAVE = $REBUILT_MR"
echo "    published MRENCLAVE = $(echo "$PUBLISHED_MR" | tr 'A-F' 'a-f')"

if [ "$REBUILT_MR" != "$(echo "$PUBLISHED_MR" | tr 'A-F' 'a-f')" ]; then
  echo "!! FAIL: rebuilt MRENCLAVE does not match published value."
  echo "   The published binary was NOT built from this source, OR the build"
  echo "   is not reproducible (check Go/Gramine pins — see doc 08 §1, §7)."
  exit 1
fi
echo "    OK: rebuild matches published MRENCLAVE."

echo "==> [4/4] Comparing against LIVE attestation quote"
if [ -z "$LIVE_ENDPOINT" ]; then
  echo "    (skipped — no live endpoint given)"
  echo "PASS: source@${COMMIT} reproducibly yields published MRENCLAVE."
  exit 0
fi

# Fetch the RA-TLS cert, extract the DCAP quote, pull MRENCLAVE from it.
# Reuses the client verifier from doc 07 (relaycore-verify is that tool).
LIVE_MR="$(relaycore-verify --endpoint "$LIVE_ENDPOINT" --print-mrenclave)"
echo "    live      MRENCLAVE = $LIVE_MR"

if [ "$LIVE_MR" != "$REBUILT_MR" ]; then
  echo "!! FAIL: the RUNNING enclave's MRENCLAVE differs from the audited source."
  echo "   The live service is NOT running the code you just rebuilt/audited."
  exit 1
fi

echo "PASS: running enclave == published MRENCLAVE == rebuild of source@${COMMIT}."
echo "      => the live service runs exactly the audited relay-core (docs 03,05)."
```

The three-way equality (`rebuilt == published == live-quote`) is the complete
proof: the source you can read (and that docs 03/05 audit) is the source that
produced the published MRENCLAVE, and that MRENCLAVE is what the attestation
quote from the live server carries.

---
## 7. Known hard parts — is Gramine's MRENCLAVE actually reproducible?

Yes, but only if you lock things Gramine does **not** lock for you. Honest list
of the gotchas, and how each is pinned here.

### 7.1 Gramine loader (PAL/libos) pages are part of MRENCLAVE

MRENCLAVE measures the Gramine loader pages, not just relaycore. So the **exact
Gramine build** matters. Two problems:

- A different **1.9.x point release** (or a distro-patched Gramine) ships
  different loader `.so` bytes → different measured pages → different MRENCLAVE,
  even from identical relaycore source. **Lock:** pin the Gramine image by
  digest (not just tag `1.9`), or `apt install gramine=<exact-version>`. Record
  the full version in the release manifest.
- Gramine compiled with different options (e.g. different `direct` vs `sgx` PAL
  build flags, or a self-built Gramine vs the upstream image) differs. **Lock:**
  everyone uses the same upstream `gramineproject/gramine:1.9@sha256:...` image.

### 7.2 Enclave geometry must match exactly

`sgx.enclave_size`, `sgx.max_threads`, and thread stack size directly change the
number and layout of measured pages. A verifier who renders the manifest with
`enclave_size = "4G"` when the release used `"2G"` gets a different MRENCLAVE and
a false mismatch. **Lock:** these live in the committed
`relaycore.manifest.template` at the pinned commit; never pass them as
environment-derived `-D` values.

### 7.3 glibc / libc drift (only if cgo, or if not fully static)

If relaycore is pure-Go static (`CGO_ENABLED=0`, §2.1) this does not apply — the
binary carries no libc. If cgo is used, the C library version becomes measured
content (it is in the binary and/or in trusted `.so`s). **Lock:** pin the build
and runtime images by digest so glibc/musl is fixed. This is the strongest
argument for keeping relaycore pure-Go.

### 7.4 The Phase-0 DEBUG vs production non-debug difference (MUST document)

Phase-0 on the Alibaba Ice Lake box verified a **DEBUG** enclave
(`sgx.debug = true`). Production relay-core must be **non-debug**
(`sgx.debug = false`). This is not cosmetic:

- The `debug` bit is part of the SGX attributes covered by the enclave identity,
  so **the DEBUG enclave and the production enclave have different MRENCLAVEs**.
  You cannot reuse the Phase-0 measurement.
- A debug enclave allows the host to inspect/modify enclave memory (`EDBGRD`/
  `EDBGWR`), which would completely void the no-content-storage guarantee. The
  client verifier (doc 07) **must reject `debug=1`** in the quote's attributes,
  independent of the MRENCLAVE check.
- Therefore: build production with `sgx.debug = false` in the committed
  template, publish that (non-debug) MRENCLAVE, and set `sgx_debug: false` in the
  release record. Re-measure from scratch for production; do not carry the
  Phase-0 number forward.

### 7.5 EDMM and dynamic memory

If `sgx.edmm_enable = true`, some pages are added dynamically at runtime and the
initial MRENCLAVE covers a different page set than a static-heap enclave. Keep
`edmm_enable = false` (as doc 02's manifest does) for a stable, fully-measured
initial layout, unless you have verified identical behavior across builders.
Record the choice.

### 7.6 Signing key is deliberately NOT a reproducibility factor

Restating §3 because it surprises people: the RSA signing key does **not** affect
MRENCLAVE. A verifier rebuilding the enclave can use their **own throwaway key**
and still get the same MRENCLAVE as the official release — they are checking the
code measurement, not the signature. Only MRSIGNER (and the `relaycore.sig`
signature itself) depends on the key. This is why the verify script (§6) never
needs the operator's private key.

### 7.7 Residual risk / what is NOT proven

- Reproducibility proves *code identity*, not *code correctness*. It says the
  running enclave is the audited source; docs 03/05 are what make that source
  trustworthy. Both are required.
- The DCAP quote proves genuine, up-to-date SGX hardware and the MRENCLAVE, but
  TCB-recovery events (microcode/PSW updates) change TCB status, not MRENCLAVE.
  Handle TCB policy in the verifier (doc 07), separate from the reproducibility
  check here.
- If Gramine upstream yanks or re-tags the `1.9` image, the digest pin still
  resolves the exact bytes; keep a mirrored copy of the pinned Gramine image so
  a future rebuild is not blocked by upstream deletion.

### 7.8 Practical pinning checklist

- [ ] `GOTOOLCHAIN=local`, Go image pinned by digest to **1.26.1** (§1)
- [ ] `GOEXPERIMENT=greenteagc` recorded and identical
- [ ] `-trimpath -buildvcs=false -mod=vendor`, `-ldflags "-s -w -buildid= -X ...=<fixed>"`
- [ ] `vendor/` committed; `GOPROXY=off`
- [ ] `CGO_ENABLED=0` (or every C dep version pinned if cgo is unavoidable)
- [ ] Gramine image pinned **by digest**, version = 1.9
- [ ] `relaycore.manifest.template` committed; `enclave_size`, `max_threads`,
      `edmm_enable=false`, `debug=false` fixed in it
- [ ] `gramine-manifest -D…` values are fixed literals, no host state
- [ ] release record signed (GPG/cosign) + tag signed; MRENCLAVE published first
- [ ] verify script confirms `rebuild == published == live quote`

