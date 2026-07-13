# test-enclave-newapi

A confidential-computing **relay core** for [QuantumNous/new-api](https://github.com/QuantumNous/new-api):
the request→response hot path of the AI API gateway, moved into an **Intel SGX
enclave** (via [Gramine](https://gramine.readthedocs.io/)) so that two properties
become **externally verifiable** by a remote client, without trusting the server
operator:

1. **No content at rest** — on the request→response path the server stores **no
   prompt/response content**. Only non-content billing metadata (token counts,
   model, user, cost) may persist.
2. **Official-URL integrity (anti-MITM)** — a channel using a provider's
   official/default base URL provably connects to the **real** upstream
   (e.g. `api.openai.com`), not a host-side interceptor.

> **Attribution.** This is a subset of, and depends on, the
> **new-api** project by **QuantumNous** (`github.com/QuantumNous/new-api`). The
> Go module path is kept as `github.com/QuantumNous/new-api` on purpose so the
> import paths and measurements match upstream. All new-api / QuantumNous
> branding and licensing is preserved.

## Why the guarantees can be *proven*, not just claimed

The enclave is the only component a client trusts. Everything else (the new-api
main body: users, billing, DB, admin, marketplace) is treated as an **untrusted
host** and lives *outside* the enclave.

```
reproducible source (this repo)  ──rebuild──▶  a specific MRENCLAVE
                                                     ↕  must be equal
running enclave's DCAP quote      ──client verifier──▶  MRENCLAVE + Intel-signed + bound to TLS key
```

A client (`cmd/relay-verify`) verifies, **before sending any prompt**, that the
DCAP quote is genuinely Intel-signed, that its `MRENCLAVE` equals a value you
rebuilt yourself from this source, and that the quote is bound to the TLS key of
the connection it is actually talking to. Because the enclave's package closure
contains **no** disk/DB/logging code (see the leak-guard below) and its Gramine
manifest mounts no writable host path, "the running binary cannot persist
content" follows from the measurement.

**This is source, not a pre-built blob** — that is the whole point. You rebuild
it reproducibly (`cmd/relay-core/Dockerfile.reproducible`) and confirm the
`MRENCLAVE` matches what a live enclave attests. A convenience binary, if ever
published, is trusted only via "rebuild → same MRENCLAVE", never on faith.

## Layout

```
cmd/relay-core/          the enclave binary (measured into MRENCLAVE)
  main.go                read request, extract only {model,stream}, route, settle metadata
  dispatch.go            strict-TLS forward to the compiled-in official URL, stream, count tokens
  server.go              RA-TLS listener + /attestation endpoint
  control_client.go      calls the untrusted new-api control plane (loopback HTTP)
  relay-core.manifest.template   Gramine manifest: sgx.debug=false, tmpfs-only FS, encrypted /secrets
  build_enclave.sh       render + sign → print MRENCLAVE
  Dockerfile.reproducible        hermetic build → deterministic MRENCLAVE
pkg/officialurls/        single source of truth for official base URLs (pure, zero deps)
pkg/relaycontrol/        enclave↔host wire contract; PeekRequest never materializes prompt content
pkg/raenclave/           reads /dev/attestation/* to build the RA-TLS cert + seals the upstream key
cmd/relay-verify/        client-side attestation verifier (DCAP chain + MRENCLAVE + channel binding)
scripts/enclave_no_leak_check.sh   CI guard: fails if the enclave closure links DB/log/disk code
docs/                    design docs (01–08), threat model, reproducible-build RELEASE format
docs/integration/        reference: the new-api-side control-plane glue (see "Integrating with new-api")
```

The entire enclave closure is `cmd/relay-core` + `pkg/officialurls` +
`pkg/relaycontrol` + `pkg/raenclave` — about 1,100 lines of readable Go with
**zero third-party module dependencies**.

## Build & verify

```bash
# build the enclave binary (pure Go, no network needed)
go build ./cmd/relay-core

# prove the enclave closure links no content-persistence code
bash scripts/enclave_no_leak_check.sh

# build + sign the enclave on an SGX host with Gramine 1.9, prints MRENCLAVE
bash cmd/relay-core/build_enclave.sh

# client verifier (default build = structural checks; add -tags dcap on a host
# with libsgx_dcap_quoteverify for full signature-chain verification)
go build ./cmd/relay-verify
CGO_ENABLED=1 go build -tags dcap ./cmd/relay-verify   # full DCAP chain verify
./relay-verify -addr <host:8443> -mrenclave <hex> -dcap-verify
```

## Integrating with new-api

The enclave links to new-api through a **single narrow loopback HTTP call** —
`cmd/relay-core/control_client.go` POSTs `{token, model}` to new-api's
`/internal/relaycore/select` and gets back routing metadata + the upstream key.
Only `{token, model}` ever leaves the enclave; **prompt content never reaches
new-api.**

Two minimal changes to upstream new-api enable this (both preserved here for
reference; neither is part of the enclave / MRENCLAVE):

1. `constant/channel.go` — the `ChannelBaseURLs` table is extracted into
   `pkg/officialurls` and aliased (`var ChannelBaseURLs = officialurls.BaseURLs`),
   so the enclave and the host share one source of truth. Behavior unchanged.
2. `main.go` — one line, `StartRelayCoreControlPlane("127.0.0.1:3001")`, starts
   the loopback control plane. Its handler
   (`docs/integration/relaycore_control.go.txt`) reuses new-api's own
   `ValidateUserToken` → `GetRandomSatisfiedChannel` → `GetNextEnabledKey`.

## Limitations

- The client **must actually verify** (a client that skips `-dcap-verify` gets no
  guarantee). SGX has known micro-architectural side-channel research limitations.
- For a canonical reproducible build, the Docker base image must be pinned by
  digest and apt versions frozen (the manifest measures system libs).
- Upstream key custody has two modes: sealed to `MRENCLAVE` (host cannot read it),
  or supplied by new-api's DB over loopback (host-visible). The latter is used
  when you want to use a key already stored in a new-api account.
