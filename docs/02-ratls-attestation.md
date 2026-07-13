# 02 — RA-TLS + DCAP Attestation for a Go Relay-Core under Gramine-SGX 1.9

> Scope: the minimal Go "relay-core" binary runs inside an SGX enclave via
> Gramine-SGX 1.9. This document specifies how that binary produces a DCAP
> remote-attestation quote, binds it to its TLS key, serves an RA-TLS
> certificate, and how a remote client verifies the enclave **before** sending
> any prompt. Everything here targets Gramine **v1.9** specifically.
>
> Goal it serves (from the CC design): the client obtains cryptographic proof
> that it is talking to the exact pinned enclave measurement (MRENCLAVE) running
> on genuine, up-to-date Intel SGX hardware, and that the TLS session it is
> about to use is bound to that enclave's key. No prompt content leaves the
> client until that proof verifies.

---

## 0. Mental model

RA-TLS folds remote attestation into the TLS handshake. The server's X.509
certificate is **self-signed** and carries, inside a custom extension, an SGX
DCAP **quote**. The quote's 64-byte `report_data` field contains a hash of the
certificate's public key. The verifier, during the TLS handshake, runs a custom
certificate callback that:

1. extracts the quote from the cert extension,
2. verifies the quote's signature chain up to the Intel SGX Root CA (using DCAP
   collateral fetched from a PCCS),
3. checks that `report_data == hash(cert public key)` — this binds the TLS
   session to the attested enclave,
4. checks the enclave identity (MRENCLAVE / MRSIGNER / prod id / svn) against
   pinned expected values,
5. applies a TCB / policy decision.

Because the key is bound into the quote, a man-in-the-middle cannot reuse a
valid quote with a different key: the `report_data` hash would not match.

---

## 1. Gramine attestation pseudo-files (v1.9)

When remote attestation is enabled in the manifest, Gramine populates a virtual
`/dev/attestation/` directory inside the enclave. These are not real files;
they are Gramine-emulated pseudo-files backed by enclave/quoting-enclave logic.
The relay-core reads and writes them like ordinary files.

| Pseudo-file | Mode | Meaning |
|---|---|---|
| `/dev/attestation/attestation_type` | read | Returns the configured type: `none`, `dcap`, or (legacy) `epid`. Use this to assert `dcap` at startup. |
| `/dev/attestation/user_report_data` | read/write | 64 bytes. **Write** your custom `report_data` here (we write `SHA-512(SPKI)` — see below). Reading returns the last-set value. |
| `/dev/attestation/target_info` | read/write | The SGX `sgx_target_info_t` of the Quoting Enclave. For the DCAP quote flow Gramine manages the target internally; you generally do not need to hand-manage it for a self-quote. |
| `/dev/attestation/my_target_info` | read | This enclave's own `sgx_target_info_t` (useful for local attestation scenarios). |
| `/dev/attestation/report` | read/write | Produces a local SGX `sgx_report_t` for the current `user_report_data` (local report). |
| `/dev/attestation/quote` | read | Reading this triggers the DCAP flow: Gramine takes the current `user_report_data`, gets a local report, sends it to the Quoting Enclave (AESM / DCAP QE), and returns the resulting **quote** (`sgx_quote3_t`, i.e. an ECDSA/DCAP quote). |

### Critical ordering (Gramine 1.9 semantics)

`report_data` is **latched** by the last write to `user_report_data`. The quote
returned by reading `/dev/attestation/quote` embeds whatever `report_data` was
in effect at read time. Therefore the sequence is strictly:

1. Generate the TLS keypair and self-signed cert (so the public key exists).
2. Compute `report_data = SHA-512(DER(SubjectPublicKeyInfo))` truncated/padded
   to 64 bytes. SHA-512 conveniently produces exactly 64 bytes, which is why
   Gramine's own RA-TLS uses SHA-512 over the SPKI and fills the full field.
3. Write those 64 bytes to `/dev/attestation/user_report_data`.
4. Read `/dev/attestation/quote` to obtain the DCAP quote bytes.
5. Embed the quote in the certificate extension (or serve it out-of-band).

If you read `quote` before writing `user_report_data`, the quote binds
all-zero report_data and the verifier's public-key-binding check will fail.

### What Gramine's RA-TLS puts in `report_data`

Gramine's reference RA-TLS (`ra_tls_attest.so`) computes:

```
report_data[0..64] = SHA-512( DER-encoded SubjectPublicKeyInfo of the cert )
```

For a pure-Go implementation we mirror this exactly so the same verifier logic
works regardless of which side generated the cert. Use the DER bytes of the
SPKI (Go: `cert.RawSubjectPublicKeyInfo` after parsing, or
`x509.MarshalPKIXPublicKey(pub)`), hash with SHA-512, and write all 64 bytes.

---

## 2. Manifest requirements (Gramine 1.9)

Remote attestation and the `/dev/attestation/` tree are gated by the manifest.
The relevant keys (TOML manifest, `.manifest.template` before
`gramine-manifest` / `gramine-sgx-sign`):

```toml
# --- loader / entrypoint ---
loader.entrypoint.uri = "file:{{ gramine.libos }}"
libos.entrypoint       = "/relaycore"
loader.log_level       = "error"

loader.env.LD_LIBRARY_PATH = "/lib:{{ arch_libdir }}"
# Optional: pass through RA-TLS knobs if you use gramine-ratls (see §3A)
loader.env.RA_TLS_MRENCLAVE = { passthrough = true }   # example passthrough

# --- filesystem mounts ---
fs.mounts = [
  { type = "chroot", uri = "file:{{ gramine.runtimedir() }}", path = "/lib" },
  { type = "chroot", uri = "file:{{ arch_libdir }}", path = "{{ arch_libdir }}" },
  { path = "/relaycore", uri = "file:relaycore" },
]

# --- SGX core ---
sgx.debug            = false            # PRODUCTION: must be false (see §6)
sgx.enclave_size     = "2G"
sgx.max_threads      = 64
sgx.edmm_enable      = false            # keep off unless kernel/driver support verified

# --- THIS is what enables /dev/attestation and DCAP quoting ---
sgx.remote_attestation = "dcap"

# --- trusted files: every file mapped read-only must be measured ---
sgx.trusted_files = [
  "file:{{ gramine.libos }}",
  "file:{{ gramine.runtimedir() }}/",
  "file:{{ arch_libdir }}/",
  "file:relaycore",
  # If using Gramine's ready-made RA-TLS attest lib (§3A):
  "file:{{ gramine.runtimedir() }}/libra_tls_attest.so",
]

# CA/collateral files the app reads at runtime, if any, can be allowed_files,
# but prefer trusted_files for anything security-relevant.
```

Key points, Gramine 1.9-specific:

- `sgx.remote_attestation = "dcap"` is the switch. Without it, `/dev/attestation/`
  is absent or `attestation_type` reports `none`, and reading `quote` fails.
  The string form (`"dcap"`) is the current v1.x syntax; the old boolean
  `sgx.remote_attestation = true` was removed — do not use it on 1.9.
- DCAP quoting in Gramine 1.9 is **in-process via the DCAP quote provider
  library** (`libsgx_dcap_ql` / `libsgx_dcap_quoteprov`) on the host; the
  enclave talks to the host quoting path. No AESM daemon is required for DCAP
  (AESM was the EPID path). Ensure the host has the DCAP QPL and
  `/etc/sgx_default_qcnl.conf` pointing at the PCCS (Phase-0 verified: Alibaba
  PCCS `https://sgx-dcap-server.cn-hongkong.aliyuncs.com/sgx/certification/v4/`).
- Any `.so` you dlopen for RA-TLS (e.g. `libra_tls_attest.so`) must be listed in
  `sgx.trusted_files`, otherwise Gramine refuses to map it.
- `sgx.isvprodid` / `sgx.isvsvn` set the enclave's product id / SVN; these end
  up in the quote and are part of the verifier's identity policy. Set them
  deliberately and pin them on the verifier.

---

## 3. Serving an RA-TLS cert from Go — two options

### Option A — Gramine's ready-made `gramine-ratls` / `libra_tls_attest.so` (via cgo)

Gramine ships an attestation library that generates a complete self-signed
X.509 cert with the quote already embedded. The core C entrypoint is:

```c
int ra_tls_create_key_and_crt_der(uint8_t** der_key, size_t* der_key_size,
                                   uint8_t** der_crt, size_t* der_crt_size);
```

exported from `libra_tls_attest.so`. It internally: generates a keypair,
computes `SHA-512(SPKI)`, writes `/dev/attestation/user_report_data`, reads
`/dev/attestation/quote`, and packs the quote into the cert extension using
Gramine's OID layout. You dlopen it and call via cgo, then hand the DER key +
cert to Go's `crypto/tls`:

```go
/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
typedef int (*ratls_fn)(uint8_t**, size_t*, uint8_t**, size_t*);
static int call_ratls(void* f, uint8_t** k, size_t* ks, uint8_t** c, size_t* cs){
    return ((ratls_fn)f)(k, ks, c, cs);
}
*/
import "C"
// dlopen("libra_tls_attest.so"), dlsym("ra_tls_create_key_and_crt_der"),
// call_ratls(...), then C.GoBytes the DER key+cert, build tls.Certificate.
```

Pros: exact, upstream-maintained OID layout and collateral packing; least chance
of a verifier mismatch. Cons: cgo + a trusted `.so` inside the enclave; ties the
Go binary to Gramine's ABI.

### Option B — pure Go (recommended for the relay-core)

Do the whole thing in Go, treating `/dev/attestation/*` as plain files. This
keeps the enclave binary cgo-free (smaller TCB, static build, easier to
reproduce a pinned MRENCLAVE). Flow:

1. Generate an ECDSA P-384 (or RSA-3072) keypair; build a self-signed cert.
2. `spki := cert.RawSubjectPublicKeyInfo` (DER of SubjectPublicKeyInfo).
3. `rd := sha512.Sum512(spki)` → 64 bytes.
4. Write `rd[:]` to `/dev/attestation/user_report_data`.
5. Read `/dev/attestation/quote` → `quote []byte`.
6. Re-issue the cert with a custom extension carrying the quote, using the
   Gramine OID (below), so a stock Gramine RA-TLS verifier accepts it.

Because Go's `x509.CreateCertificate` lets you inject arbitrary
`ExtraExtensions`, embedding the quote is straightforward. The only subtlety is
that the public key must be fixed before you compute `report_data`; you generate
the key once and reuse it for the final signed cert, so the SPKI (and thus the
hash in the quote) matches the served cert.

### The CORRECT Gramine 1.9 OID(s) and extension layout

Gramine 1.9 embeds attestation evidence using the **TCG DICE "tagged evidence"**
OID:

```
2.23.133.5.4.9     (id-tagged-evidence, TCG DICE)
  → extension value = CBOR-encoded tagged evidence containing the SGX quote
```

For backward compatibility Gramine 1.9 also emits/accepts a **legacy
Gramine-specific OID** whose DER bytes decode to:

```
1.2.840.113741.1337.6
```

> Load-bearing correction (from Phase-0 salvage): the legacy OID is
> **`1.2.840.113741.1337.6`**, NOT the older `1.2.840.113741.1.13.1` that some
> pre-1.x / SGX-SDK-era docs reference. Verify against the exact Gramine v1.9
> source tag (`tools/sgx/ra-tls/ra_tls_attest.c` and the DICE OID constants in
> the ra-tls sources) before pinning the verifier, because the verifier must
> look for the OID that the attester actually writes.

Extension layout notes:

- The DICE tagged-evidence extension value is **CBOR**, not raw quote bytes.
  A pure-Go attester that targets `2.23.133.5.4.9` must CBOR-encode the quote as
  TCG tagged evidence; a verifier reading that OID must CBOR-decode it first.
- The legacy `1.2.840.113741.1337.6` extension historically carried the raw
  quote (`sgx_quote3_t`) bytes directly (no CBOR wrapper). Simpler to produce
  and parse in pure Go.
- Practical recommendation for our controlled client+server: emit **both**
  extensions if you want compatibility with stock Gramine verifiers, but since
  we own the verifier, the simplest robust path is: put the raw quote under the
  legacy OID `1.2.840.113741.1337.6` and have our Go verifier read that OID
  directly. If you also want to interoperate with Gramine's C verifier, add the
  DICE `2.23.133.5.4.9` CBOR extension. Mark neither extension critical (a
  critical unknown extension would break generic TLS stacks that don't know the
  OID; our verifier looks it up explicitly).
- Collateral (PCK cert chain, TCB info, QE identity, CRLs) is **not** required
  to be in the cert. RA-TLS verifiers fetch collateral from the PCCS at verify
  time. Optionally you can also expose collateral out-of-band (see §4) so an
  offline/air-gapped verifier can be fed it.

---

## 4. Minimal Go code sketch (pure-Go, Option B)

This sketches the attester side: read the quote from `/dev/attestation`, build
the RA-TLS cert, start a TLS listener, and expose a plain `/attestation`
endpoint returning the raw quote (+ optional collateral) for out-of-band
verification.

```go
package ratls

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha512"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/asn1"
    "math/big"
    "os"
    "time"
)

// Legacy Gramine RA-TLS OID that carries the raw SGX quote (see §3).
// 1.2.840.113741.1337.6
var oidGramineQuote = asn1.ObjectIdentifier{1, 2, 840, 113741, 1337, 6}

// buildRATLSCert generates a keypair, binds SHA-512(SPKI) into the SGX
// report_data, fetches the DCAP quote, and returns a tls.Certificate whose
// leaf carries the quote in a custom extension.
func buildRATLSCert() (tls.Certificate, []byte, error) {
    key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
    if err != nil {
        return tls.Certificate{}, nil, err
    }

    // 1) DER of SubjectPublicKeyInfo — this is what report_data binds to.
    spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
    if err != nil {
        return tls.Certificate{}, nil, err
    }
    rd := sha512.Sum512(spki) // exactly 64 bytes

    // 2) Latch report_data, then read the quote. Order matters (§1).
    if err := os.WriteFile("/dev/attestation/user_report_data", rd[:], 0); err != nil {
        return tls.Certificate{}, nil, err
    }
    quote, err := os.ReadFile("/dev/attestation/quote")
    if err != nil {
        return tls.Certificate{}, nil, err
    }

    // 3) Self-signed cert carrying the quote as a non-critical extension.
    tmpl := &x509.Certificate{
        SerialNumber: big.NewInt(time.Now().UnixNano()),
        Subject:      pkix.Name{CommonName: "relaycore-ratls"},
        NotBefore:    time.Now().Add(-time.Minute),
        NotAfter:     time.Now().Add(24 * time.Hour), // short-lived; rotate
        KeyUsage:     x509.KeyUsageDigitalSignature,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        ExtraExtensions: []pkix.Extension{
            {Id: oidGramineQuote, Critical: false, Value: quote},
        },
        BasicConstraintsValid: true,
    }
    der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
    if err != nil {
        return tls.Certificate{}, nil, err
    }
    return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, quote, nil
}
```

```go
// Server wiring: TLS listener with the RA-TLS cert + a plain /attestation
// endpoint returning the raw quote for out-of-band verification.
func NewServer(addr string) (*http.Server, error) {
    cert, quote, err := buildRATLSCert()
    if err != nil {
        return nil, err
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/attestation", func(w http.ResponseWriter, r *http.Request) {
        // Raw DCAP quote for clients that fetch collateral themselves.
        w.Header().Set("Content-Type", "application/octet-stream")
        w.Write(quote)
        // Optionally: also serve cached PCK chain / TCB info / QE identity
        // (fetched once from the PCCS) as a JSON bundle under /attestation/collateral
        // so an air-gapped verifier can be handed everything at once.
    })

    return &http.Server{
        Addr:    addr,
        Handler: mux,
        TLSConfig: &tls.Config{
            Certificates: []tls.Certificate{cert},
            MinVersion:   tls.VersionTLS13, // Phase-0 handshake was TLS 1.3
        },
    }, nil
}
```

Notes:

- Startup assertion: read `/dev/attestation/attestation_type` and fail fast if
  it is not `dcap` — this catches a mis-provisioned manifest before serving.
- `os.WriteFile(..., 0)` — the mode is irrelevant for the pseudo-file; the write
  must be exactly 64 bytes for `user_report_data`.
- Rotate the cert/key periodically (short `NotAfter`); each rotation re-runs the
  quote flow so the quote always binds the currently served key.
- The `/attestation` endpoint is served over the same RA-TLS TLS, so a client
  can fetch the quote both from the handshake cert and from the endpoint and
  compare — useful for debugging and for out-of-band re-verification.

---

## 5. Verifier side — how a remote client verifies

The client must verify **before** transmitting any prompt. It performs a TLS
handshake but replaces normal chain validation with an RA-TLS callback.

### 5.1 Verification steps

1. **Extract the quote.** In the TLS handshake, take the leaf cert
   (`tls.ConnectionState().PeerCertificates[0]`). Find the extension by OID
   (`1.2.840.113741.1337.6` for the raw-quote layout, or `2.23.133.5.4.9` and
   CBOR-decode for the DICE layout). The extension value is (or wraps) the
   `sgx_quote3_t` DCAP quote.

2. **Verify the quote signature chain.** Using DCAP verification
   (`libsgx_dcap_quoteverify` via the Go verifier, or Gramine's
   `ra_tls_verify_callback`), validate:
   `quote signature → PCK certificate → Intel SGX Processor/Platform CA →
   Intel SGX Root CA`. The Root CA public key is pinned in the verifier. The
   PCK cert and its chain, TCB info, QE identity, and CRLs (the **collateral**)
   are fetched from the Alibaba PCCS
   (`https://sgx-dcap-server.cn-hongkong.aliyuncs.com/sgx/certification/v4/`)
   configured in `/etc/sgx_default_qcnl.conf`, or supplied out-of-band via the
   `/attestation/collateral` endpoint.

3. **Check public-key binding.** Recompute `SHA-512(DER(SPKI of peer cert))`
   and compare byte-for-byte against the quote's `report_body.report_data`
   (first 64 bytes). This is the step that binds the TLS session to the attested
   enclave and defeats quote-reuse / MITM. If it mismatches, abort.

4. **Check enclave identity (pinned).** Compare against expected pinned values:
   - `MRENCLAVE` == the exact measurement of the production relay-core enclave.
     This is the primary identity anchor. **Must** match the reproducibly-built
     production enclave hash.
   - Optionally `MRSIGNER`, `ISV_PROD_ID`, `ISV_SVN` for signer/version policy.

5. **Check TCB status.** The DCAP verification yields a TCB status
   (`UpToDate`, `ConfigurationNeeded`, `OutOfDate`, `SWHardeningNeeded`,
   `ConfigurationAndSWHardeningNeeded`, `Revoked`, ...). Apply policy (§5.3).

6. **Freshness / nonce.** DCAP quotes are not inherently challenge-response.
   Bind freshness by: (a) the TLS handshake itself using the attested key
   (a replayed quote can't complete the handshake without the private key,
   since report_data pins the pubkey), and (b) optionally a client nonce echoed
   through a fresh cert rotation or an application-level signed challenge over
   the established channel. See §6 for replay caveats.

### 5.2 Using Gramine's own verifier callback

Gramine ships `libra_tls_verify_dcap.so` exporting
`ra_tls_verify_callback_der(...)` and a callback registration
`ra_tls_set_measurement_callback(...)`. The client can call it (cgo) to do steps
1–3 and 5, then supply a measurement callback for step 4 where you compare
MRENCLAVE/MRSIGNER/prodid/svn against pinned values and return 0/non-zero to
accept/reject. This is the least-effort correct verifier; a pure-Go verifier
must replicate the same DCAP logic (feasible via a cgo shim to
`libsgx_dcap_quoteverify`, or a Go DCAP library).

### 5.3 `RA_TLS_ALLOW_*` policy knobs and their security meaning

Gramine's DCAP verifier reads these environment variables (the verifier side):

| Env var | Effect | Security meaning |
|---|---|---|
| `RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE` | Accept quotes from **debug** enclaves (`sgx.debug = true`). | **Insecure.** A debug enclave's memory is inspectable; secrets are not protected. Production must reject debug. |
| `RA_TLS_ALLOW_OUTDATED_TCB_INSECURE` | Accept `OUT_OF_DATE` / `ConfigurationNeeded` TCB. | Accepts platforms missing microcode/TCB updates — potentially vulnerable to known SGX attacks. |
| `RA_TLS_ALLOW_SW_HARDENING_NEEDED` | Accept `SWHardeningNeeded` TCB status. | Platform needs software mitigations (e.g. for LVI-class issues); acceptable only if the enclave build applied them. |
| `RA_TLS_ALLOW_HW_CONFIG_NEEDED` | Accept `ConfigurationNeeded` / hardware-config-needed status. | Platform BIOS/hardware config (e.g. hyperthreading) not in the ideal secure state. |
| `RA_TLS_MRENCLAVE` / `RA_TLS_MRSIGNER` / `RA_TLS_ISV_PROD_ID` / `RA_TLS_ISV_SVN` | Pinned expected identity values (hex). | The core identity policy. Set `MRENCLAVE` to the pinned production measurement. |

**Phase-0 reality on this platform:** the verified `ra-tls-mbedtls` DCAP example
required `RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1` (it was a debug enclave),
`RA_TLS_ALLOW_SW_HARDENING_NEEDED=1`, `RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1`,
and `RA_TLS_ALLOW_HW_CONFIG_NEEDED=1`. That matched the observed result
`quote_verification_result = 0xa008` = `TEE_TCB_STATUS_CONFIG_AND_SW_HARDENING_NEEDED`
(the func result was `0x0`, i.e. structurally valid quote). This combination is
acceptable for Phase-0 bring-up but **must be tightened for production**
(see §6): at minimum drop `ALLOW_DEBUG`, and ideally drop `ALLOW_OUTDATED_TCB`
after patching the platform TCB. `SW_HARDENING` / `HW_CONFIG` may remain
necessary on this specific Ice Lake host; document the residual risk explicitly
rather than silently allowing it.

---

## 6. Risks and mitigations

### 6.1 Quote freshness / replay

- **Risk:** DCAP quotes are not challenge-response by construction. A recorded
  quote could be replayed by a party that also possesses the matching private
  key.
- **Mitigation:** the public-key binding (report_data = hash(SPKI)) means a
  replayed quote is only useful together with the corresponding private key.
  As long as the private key never leaves the enclave (it is generated inside
  and never sealed/exported in plaintext), an attacker replaying the quote
  cannot complete the TLS handshake. Reinforce with short cert lifetimes
  (hours) and periodic re-attestation so a leaked key/quote pair has a small
  window. For strict freshness, layer an application-level signed nonce
  challenge over the established RA-TLS channel.
- **Do not** rely on the quote alone as a bearer token; always couple it to the
  live TLS key exchange.

### 6.2 Debug vs production enclave (MRENCLAVE differs)

- **Risk:** the Phase-0 example was a **debug** enclave (`sgx.debug = true`),
  whose memory is inspectable and whose secrets are unprotected. A debug
  enclave also has a **different MRENCLAVE** than the production
  (`sgx.debug = false`) build, and its quotes carry the DEBUG attribute bit.
- **Mitigation:** production must build with `sgx.debug = false`, pin the
  resulting production `MRENCLAVE` in the verifier, and the verifier must
  **not** set `RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE`. Treat the Phase-0
  MRENCLAVE as throwaway — it will not match production. Establish a
  reproducible build so the production MRENCLAVE can be independently recomputed
  and pinned by third parties (this is what makes the "no-content" claim
  externally verifiable).

### 6.3 Collateral availability (PCCS down)

- **Risk:** DCAP verification needs collateral (PCK chain, TCB info, QE
  identity, CRLs) from a PCCS. If the Alibaba PCCS
  (`sgx-dcap-server.cn-hongkong.aliyuncs.com`) is unreachable, verification
  fails and clients cannot connect.
- **Mitigation:**
  - Cache collateral aggressively on the verifier and honor its validity
    window; collateral changes infrequently (TCB updates, CRL refresh).
  - Serve collateral out-of-band from the server's `/attestation/collateral`
    endpoint (server fetches it once from PCCS and caches), so verifiers can be
    fed a self-contained bundle even when they can't reach the PCCS directly.
  - Optionally run a local/mirrored PCCS for redundancy.
  - Distinguish "collateral fetch failed" (transient, retry) from "collateral
    says revoked/out-of-date" (policy decision) in verifier error handling — do
    not fail-open on fetch errors.

### 6.4 Other residual risks

- **TCB status masking:** allowing `OUTDATED_TCB` / `SW_HARDENING` /
  `HW_CONFIG` weakens guarantees. Each `RA_TLS_ALLOW_*` in production must be a
  documented, justified decision with the residual attack surface stated.
- **OID mismatch:** if the attester writes the DICE `2.23.133.5.4.9` CBOR
  extension but the verifier only looks for the legacy raw-quote OID (or the
  wrong legacy OID `1.2.840.113741.1.13.1`), verification silently fails or,
  worse, the wrong bytes are parsed. Confirm both sides use the identical OID
  and encoding against the exact Gramine 1.9 source before pinning.
- **Report_data hash mismatch:** if the attester hashes something other than the
  exact DER SPKI the verifier recomputes (e.g. hashing the whole cert, or the
  raw EC point instead of the SPKI), the binding check fails. Both sides must
  agree: `SHA-512` over `DER(SubjectPublicKeyInfo)`, full 64 bytes.

---

## 7. Summary checklist

- [ ] Manifest: `sgx.remote_attestation = "dcap"`, `sgx.debug = false` (prod),
      all trusted files listed, isvprodid/isvsvn set.
- [ ] Host: DCAP QPL installed, `/etc/sgx_default_qcnl.conf` → Alibaba PCCS.
- [ ] Attester: generate key → `SHA-512(SPKI)` → write `user_report_data` →
      read `quote` → embed under agreed OID → serve over TLS 1.3.
- [ ] `/attestation` endpoint exposes raw quote (+ cached collateral).
- [ ] Verifier: quote chain → Intel Root CA; report_data == hash(pubkey);
      MRENCLAVE == pinned prod value; TCB policy applied.
- [ ] Production: no `ALLOW_DEBUG`; minimize other `RA_TLS_ALLOW_*`; document
      residuals; reproducible build for independent MRENCLAVE pinning.

> Verification status of this document: the Gramine pseudo-file interface,
> manifest keys, and `RA_TLS_ALLOW_*` semantics reflect Gramine 1.x/1.9 behavior
> and the Phase-0 end-to-end result observed on this platform
> (`func_verify_quote_result=0x0`, `quote_verification_result=0xa008`). The
> exact OID bytes and the CBOR-vs-raw extension layout MUST be re-confirmed
> against the pinned Gramine v1.9 source tag before the verifier is frozen; the
> legacy OID is `1.2.840.113741.1337.6` (NOT `1.2.840.113741.1.13.1`), and the
> current DICE tagged-evidence OID is `2.23.133.5.4.9`.
