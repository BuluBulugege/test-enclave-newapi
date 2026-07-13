# RELEASE — relay-core Enclave MRENCLAVE Publication Record (TEMPLATE)

> Fill one copy of this template per release and publish it authentically
> (§ *Publishing authentically*). It binds a **MRENCLAVE** to an **exact git
> commit** whose relay-core source has been audited, so third parties can pin
> MRENCLAVE and trust that the running enclave is the audited code.
>
> Companion documents:
> - Build design & rationale: `docs/cc-research/08-reproducible-build.md`
> - The reproducible build itself: `cmd/relay-core/Dockerfile.reproducible`
> - The verifier third parties run: `scripts/repro_verify.sh`
> - The runtime attestation story: `docs/cc-research/02-ratls-attestation.md`
> - The client verifier / MRENCLAVE pinning: `docs/cc-research/07-client-verifier.md`

---

## 0. The trust chain (why this record exists)

```
audited source @ commit X
   │  reproducible build  (cmd/relay-core/Dockerfile.reproducible)
   ▼
byte-identical relay-core ELF  +  rendered relay-core.manifest.sgx
   │  gramine-sgx-sign  (ephemeral key — irrelevant to MRENCLAVE)
   ▼
MRENCLAVE = M          ◄── THIS RECORD PUBLISHES M and ties it to commit X
   │  DCAP attestation  (doc 02)
   ▼
live quote embeds M    ◄── client pins M  (doc 07)
```

A verifier confirms the chain end-to-end with:

```
scripts/repro_verify.sh <MRENCLAVE> <live-host:port>
#   rebuild == published == live  →  the running service IS the audited source.
```

MRENCLAVE is a fingerprint of `{relay-core code + Gramine loader + rendered
manifest + enclave geometry}`. It does **not** depend on the signing key, so the
build uses a throwaway key and any rebuilder gets the same M.

---

## 1. Release record

```yaml
# ---- identity ----
relaycore_component:  "relay-core"           # cmd/relay-core SGX enclave
release_version:      "<e.g. 1.0.0>"         # matches the VERSION file at the tag (empty today)
git_commit:           "<full 40-char SHA>"   # e.g. ca50b943736911d80b6c1febd1f0746d7fbbe73b
git_tag:              "<e.g. relay-core-v1.0.0>"   # SIGNED tag (git tag -s)
repo_clone_url:       "<git remote used for this fork>"   # informational; module path is github.com/QuantumNous/new-api

# ---- THE value third parties pin ----
mrenclave:            "<64 hex chars / 32 bytes>"   # authoritative enclave identity — PIN THIS
mrsigner:             "<64 hex chars>"        # informational only; rotatable (see §5). Do NOT pin as primary.
isv_prod_id:          0
isv_svn:              0
sgx_debug:            false                   # PRODUCTION. A debug enclave has a DIFFERENT MRENCLAVE and MUST be rejected by clients.

# ---- Go toolchain / build (Stage 1) ----
go_toolchain:         "go1.26.1"
go_image:             "golang:1.26.1-alpine"
go_image_digest:      "sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039"
cgo_enabled:          false
goexperiment:         "greenteagc"
gotoolchain:          "local"
goproxy:              "off"                   # hermetic: relay-core imports zero external modules
goflags:              "-mod=readonly"
build_flags:          "-trimpath -buildvcs=false"
ldflags:              "-s -w -buildid="       # NO -X: common.Version is not linked into relay-core
relay_core_elf_sha256: "<sha256 of the relay-core ELF>"   # byte-reproducible (see §6)

# ---- Gramine / enclave (Stage 2) ----
gramine_version:      "1.9"                   # set to the FULL exact apt version for a canonical release
ubuntu_base:          "ubuntu:24.04"          # noble
ubuntu_base_digest:   "sha256:<pin at release time>"      # measured base libs — pin by digest (§6)
ca_certificates_ver:  "<apt version at release>"          # /etc/ssl/certs/ca-certificates.crt is measured
enclave_size:         "1G"                    # from the committed template
max_threads:          64                      # from the committed template
edmm_enable:          false                   # Gramine DEFAULT — NOT set in the template; measured as false. Confirm per release (§7).

# ---- rendered manifest -D values (all baked into MRENCLAVE; MUST match on deploy) ----
manifest_entrypoint:  "/app/relay-core"
manifest_arch_libdir: "/lib/x86_64-linux-gnu"
manifest_listen_addr: "0.0.0.0:8443"
manifest_dnsname:     "relay-core.local"

# ---- hashes ----
manifest_template_sha256:      "<sha256 of cmd/relay-core/relay-core.manifest.template @ commit>"
rendered_manifest_sgx_sha256:  "<sha256 of relay-core.manifest.sgx>"   # expected deterministic (§6)
# NOTE: relay-core.sig bytes are NOT reproducible (they embed the signing date +
# the RSA signature). Only the MRENCLAVE *inside* the .sig is stable. Do not pin
# the .sig file hash; extract and compare MRENCLAVE.

# ---- exact reproduction command ----
build_command: >
  DOCKER_BUILDKIT=1 docker build --target artifacts
  -o type=local,dest=./artifacts
  --platform=linux/amd64
  --build-arg UBUNTU_REF=ubuntu:24.04@sha256:<ubuntu_base_digest>
  --build-arg GRAMINE_VERSION=<exact gramine version>
  -f cmd/relay-core/Dockerfile.reproducible .
verify_command: >
  scripts/repro_verify.sh <mrenclave> [<live-host:port>]
```

---

## 2. What is measured into MRENCLAVE (the pin set)

Everything below is folded into MRENCLAVE. Reproducibility requires each item be
identical for every rebuilder. This is the honest, complete surface.

| Measured input | Fixed by | Notes |
|---|---|---|
| relay-core ELF bytes | Go 1.26.1 image **digest** + `GOTOOLCHAIN=local` + `CGO_ENABLED=0` + `GOEXPERIMENT=greenteagc` + `-trimpath -buildvcs=false -ldflags "-s -w -buildid="` | Pure-Go static binary; byte-reproducible (verified: two builds → identical sha256). No external modules, so `GOPROXY=off` is fully hermetic. |
| Gramine loader (libos/PAL) pages + runtime libc glob `{{ gramine.runtimedir() }}/` | `gramine=1.9*` apt pin (set the FULL version for canonical) | A 1.9.x point release can shift loader bytes → different MRENCLAVE. Pin the exact version and record it. |
| `/lib/x86_64-linux-gnu/*` and `/usr/lib/x86_64-linux-gnu/*` (trusted_files globs in the template) | Ubuntu **digest** pin + apt version pins | Largest residual surface. The globs hash whatever is in those dirs at sign time. |
| `/etc/ssl/certs/ca-certificates.crt` | `ca-certificates` apt version | The CA bundle content is measured; pin its version. |
| rendered manifest (`enclave_size=1G`, `max_threads=64`, mounts, `loader.env.*`, `sgx.debug=false`) | committed `cmd/relay-core/relay-core.manifest.template` | Geometry + env are measured; never pass geometry as environment-derived `-D`. `sgx.edmm_enable` is **not** set in the template, so it takes Gramine's default (`false`) — an implicit measured input; confirm per release (§7). |
| the four `-D` render values | fixed literals in `Dockerfile.reproducible` | entrypoint `/app/relay-core`, arch_libdir `/lib/x86_64-linux-gnu`, listen_addr `0.0.0.0:8443`, dnsname `relay-core.local`. |

**NOT measured:** the signing key (only sets MRSIGNER), the encrypted `/secrets`
ciphertext (encrypted mounts are not hashed), and the SIGSTRUCT date.

> **Canonical == deploy.** Because absolute paths and the base/Gramine libs are
> measured, the enclave you **deploy** must be built by this same
> `Dockerfile.reproducible` (same images, same paths, same `-D` values). The
> legacy `cmd/relay-core/build_enclave.sh` path `/root/relay-core` is host
> specific and produces a **different, non-reproducible** MRENCLAVE — do not use
> it for a published/deployed enclave.

---

## 3. Source-audit trust mapping (the whole point)

This MRENCLAVE corresponds to relay-core source at `git_commit`, which has the
three provable properties below. Rebuilding that commit with the toolchain and
Gramine version in §1 yields this MRENCLAVE.

| Property | Source of truth (audit here) | How it is enforced / bound to MRENCLAVE |
|---|---|---|
| **(a) No content-persistence path.** Prompts/responses are never written to disk, DB, or logs. | `cmd/relay-core/{main.go,dispatch.go,server.go}`, `pkg/relaycontrol/wire.go` (metadata-only wire types) | CI guard **`scripts/enclave_no_leak_check.sh`** fails the build if the enclave package closure imports any content-persistence package (`dto/common/logger/model/service/setting/…`) or references write symbols (`os.Create`, `os.WriteFile`, `RecordErrorLog`, …). At runtime the **committed manifest** grants only a **tmpfs `/tmp`** (encrypted EPC, gone at exit) and an encrypted `/secrets`; there is **no writable host mount and no `allowed_files`**, so even a bug cannot spill to host disk. Both the code closure and the tmpfs-only mount set are measured into this MRENCLAVE. |
| **(b) Official upstream URLs enforced (anti-MITM).** An "official" channel is dialed at the compiled-in official host, never a host-supplied override. | `pkg/officialurls/officialurls.go` (the URL table), `cmd/relay-core/main.go` (`officialUpstreamURL`, re-derives officiality in-enclave), `cmd/relay-core/dispatch.go` (`newStrictUpstreamClient`) | The `officialurls` table is **compiled into** the measured binary. The enclave ignores `sel.IsOfficial` from the untrusted host and re-derives it from the table; the upstream HTTP client hard-codes **`InsecureSkipVerify:false`** and **`Proxy:nil`** (no env can weaken TLS or inject a proxy inside the enclave). Any tampering with the table or the client changes the ELF bytes → changes this MRENCLAVE. |
| **(c) Upstream key sealed to MRENCLAVE.** The host can never read the provider API key in plaintext. | `cmd/relay-core/main.go` (seal-on-first-boot + read), `pkg/raenclave/raenclave.go` (`SealKeyFile`), manifest `fs.mounts` | The manifest mounts an **encrypted `/secrets`** with `key_name = "_sgx_mrenclave"`: Gramine derives the wrap key from **this** MRENCLAVE, so only an enclave with this exact measurement can decrypt the key; the host holds only ciphertext. The mount declaration is part of the measured manifest. (The `os.WriteFile` used to seal is the single audited exemption in the leak-guard — it writes a provider secret, never request/response content.) |

---

## 4. Determinism status (what is byte-stable)

- **relay-core ELF** — byte-reproducible. Verified: two independent builds with
  the pinned flags produce an identical SHA-256.
- **rendered `relay-core.manifest.sgx`** — expected byte-reproducible (contains
  the manifest TOML + trusted-file hashes; no key/date material). Record its
  hash as a cross-check.
- **MRENCLAVE (ENCLAVEHASH in the `.sig`)** — reproducible; independent of the
  signing key and of the SIGSTRUCT date. **This is the value to pin/compare.**
- **`relay-core.sig` file bytes** — **NOT** reproducible (embed the signing date
  and the RSA signature). Never compare the `.sig` file hash across builds;
  compare the MRENCLAVE extracted from it.

---

## 5. Publishing authentically

The record is only as trustworthy as its origin proof. Publish so a third party
can confirm *who* asserted the `MRENCLAVE ↔ commit` mapping:

1. **Tag the exact commit** and cut a GitHub release for `git_tag`.
2. **Sign the tag** (`git tag -s <git_tag>`) with a maintainer key whose
   fingerprint is published out-of-band (repo README / website / keyservers).
   The signature binds the release to the exact commit.
3. Attach this filled record **and a detached signature** of it
   (`gpg --detach-sign` or `cosign sign-blob`) so verifiers can confirm the
   record itself was not altered.
4. Optionally attach the built `relay-core.sig` so verifiers can
   `gramine-sgx-sigstruct-view` it as a cross-check without rebuilding.
5. If you also publish CI build provenance (`actions/attest-build-provenance`),
   note that it certifies *CI ran the build*, not reproducibility — the
   independent rebuild in §6 is the real guarantee.

**Pin MRENCLAVE, not MRSIGNER.** MRSIGNER is just `SHA-256(signing public key)`;
any key can sign a *different* (malicious) enclave and share a MRSIGNER family.
The client verifier (doc 07) pins **MRENCLAVE** as the authoritative identity and
independently rejects `sgx_debug = true`. Because MRENCLAVE is key-independent,
the signing key may be rotated for operational reasons without invalidating this
published MRENCLAVE.

---

## 6. How to verify (end users / third parties)

**One command** (rebuild + compare to published, and optionally to a live enclave):

```bash
git clone <repo_clone_url> new-api && cd new-api
git checkout <git_tag>          # verify the signed tag: git tag -v <git_tag>

# rebuild from source and compare to the published MRENCLAVE:
scripts/repro_verify.sh <mrenclave>

# also cross-check a RUNNING enclave's attestation quote:
scripts/repro_verify.sh <mrenclave> relay.example.com:8443
```

The script (`scripts/repro_verify.sh`) will:

1. Build `cmd/relay-core/Dockerfile.reproducible` (`--target artifacts`) and read
   the rebuilt MRENCLAVE — no SGX hardware and no operator key required.
2. Fail non-zero unless `rebuilt == published`.
3. If a live `host:port` is given, fetch its RA-TLS cert, extract the MRENCLAVE
   from the DCAP quote in the cert extension (OID `1.2.840.113741.1337.6`), and
   fail non-zero unless `live == rebuilt`.

**Manual rebuild** (equivalent to step 1):

```bash
DOCKER_BUILDKIT=1 docker build --target artifacts \
  -o type=local,dest=./artifacts \
  --platform=linux/amd64 \
  --build-arg UBUNTU_REF=ubuntu:24.04@sha256:<ubuntu_base_digest> \
  --build-arg GRAMINE_VERSION=<exact gramine version> \
  -f cmd/relay-core/Dockerfile.reproducible .
cat ./artifacts/mrenclave.txt      # must equal the published mrenclave
```

A successful `rebuild == published == live` means: the source you can read (and
that docs 03/05 audit) produced the published MRENCLAVE, and that MRENCLAVE is
exactly what the live server's attestation quote carries. Reproducibility proves
**code identity**; docs 03/05 are what make that code **trustworthy** — both are
required.

---

## 7. Residual risks (disclose honestly in the release)

- **apt drift.** `/lib/x86_64-linux-gnu/*`, the Gramine runtime, and
  `ca-certificates.crt` are measured. Pinning the Ubuntu **digest** and exact apt
  versions fixes them; for a fully deterministic apt install, build against a
  frozen mirror (e.g. `snapshot.ubuntu.com`) and record the snapshot date. An
  unpinned `ubuntu:24.04` tag or floating `gramine=1.9*` can drift over time and
  yield a different MRENCLAVE — pin fully for a canonical release.
- **Gramine image availability.** If upstream re-tags/removes the pinned Gramine
  packages, keep a mirror of the exact `.deb`s so a future rebuild is not blocked.
- **TCB recovery.** Microcode/PSW updates change DCAP TCB status, **not**
  MRENCLAVE. Handle TCB acceptance policy in the client verifier (doc 07),
  separate from this reproducibility check.
- **`sgx.debug` must be false.** Re-measure for production; never carry a debug
  (Phase-0) MRENCLAVE forward. Clients reject `debug=1` independent of MRENCLAVE.
- **`sgx.edmm_enable` is implicit.** The committed template does not set it, so it
  takes Gramine's default (`false`) — a static, fully-measured initial layout,
  which is what we want. But it is a *default-derived* measured input, not an
  explicit pin: if a future Gramine changes the default, the layout (and
  MRENCLAVE) could change. Confirm `edmm=false` in the SIGSTRUCT per release, and
  consider pinning `sgx.edmm_enable = false` explicitly in the template.
