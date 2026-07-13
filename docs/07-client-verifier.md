# 07 — Client-Side "One-Click Verify": Proving the Enclave Before You Trust It

> Scope: the **product face** of the attestation proof. Before a user hands the
> gateway a single prompt, they must be able to confirm — from their own side,
> without trusting the gateway — that the endpoint they're talking to is the
> genuine, pinned, no-log SGX enclave described in docs 01/05/06 and served over
> RA-TLS per doc 02.
>
> This document designs two verifier form factors (a web page and a CLI), the
> exact verification flow, **where** verification should run (and why running it
> inside the gateway is disqualified), how the expected MRENCLAVE is published
> and pinned, and the honest UX that states precisely what is and isn't proven.

---

## 0. The one rule everything else hangs on: no self-attestation

The whole point of remote attestation is to remove the gateway from the trust
path. A verifier that asks the gateway "are you genuine?" and trusts the
gateway's answer has proven nothing — a malicious or subverted gateway lies.

So the verifier must satisfy two independent conditions:

1. **The evidence is enclave-bound, not server-bound.** The DCAP quote is signed
   by Intel-rooted keys inside the SGX platform; the gateway process cannot forge
   it. The quote carries `report_data = SHA-512(SPKI)` binding it to the exact
   TLS key presented in the handshake (doc 02 §0). The gateway relaying its own
   quote is fine — it *cannot* alter it.
2. **The trust anchors come from somewhere other than the gateway.** Verdict
   correctness depends on (a) the Intel SGX Root CA public key, (b) DCAP
   collateral (TCBInfo, QEIdentity, CRLs), and (c) the expected MRENCLAVE. If any
   of these are fetched *from the gateway*, the gateway can feed self-consistent
   fakes and the green checkmark is meaningless.

Condition 1 is a property of RA-TLS/DCAP itself. Condition 2 is a property of
**where and how the verifier runs** — and it is the part that is easy to get
wrong. The rest of this doc is largely about honoring condition 2.

### The circular-trust pitfall, stated concretely

The tempting design is: ship a "Verify this gateway" button in the gateway's own
React app (`web/default`). The user clicks it, sees green, feels safe. But the
page's JavaScript was served **by the gateway**. A subverted gateway can:

- serve a verifier bundle that always renders green regardless of the quote;
- substitute its own "expected MRENCLAVE" and "Intel Root CA" constants;
- proxy collateral requests through itself and return doctored TCBInfo/CRLs;
- strip the actual verification code and keep only the UI.

None of that is exotic — it's just editing the static assets it already serves.
So a verifier page *hosted by the gateway* proves nothing on its own. It can
still be **useful** (convenient, good UX, correct for an honest gateway), but its
trust value is conditional and must be spelled out. Two ways to recover trust
for the web form factor:

- **Independent hosting.** Publish the verifier as static assets on a host the
  gateway doesn't control (GitHub Pages, the org's docs domain, IPFS with a
  pinned CID). The user loads the verifier from there and points it at the
  gateway. Now the gateway supplies only the quote (which it can't forge); the
  code, roots, and expected MRENCLAVE come from elsewhere.
- **Independent anchors + integrity pinning even when co-hosted.** If the page
  *is* served by the gateway, it must (a) fetch collateral and the Intel root
  from Intel PCS / a user-chosen PCCS directly, not via the gateway, and (b) let
  the user verify the bundle's integrity out-of-band (Subresource Integrity hash
  or signature published in the signed release note, doc 08). This shrinks but
  does not fully remove the trust-on-first-load problem: the user still had to
  trust the bytes long enough to read the SRI hash. Honest copy must say so.

The CLI form factor sidesteps this entirely: the user installs it from a signed
release, runs it on their own machine, and the gateway never touches the verifier
code. That is why the CLI is the trust baseline and the web page is the
convenience layer. See §3 for the full comparison of where verification runs.


---

## 1. Two form factors

### (a) Web verifier page — the convenience layer

A single-page app whose job is: connect to a gateway URL, obtain the quote,
verify it, render a green/red result with expandable detail. Audience: any user
about to use the gateway, non-experts included.

Non-negotiables (from §0):

- **Ships from an independent origin.** Canonical home is a GitHub Pages / docs
  domain build, not `web/default` served by the gateway. We *may* also embed a
  copy in `web/default` for discoverability, but that embedded copy must display
  a persistent banner: "This page was served by the gateway you're verifying.
  For an independent check, run the CLI or load the verifier from
  &lt;independent-URL&gt;." Never let the co-hosted copy claim unqualified proof.
- **Fetches anchors independently.** Intel Root CA is compiled into the bundle
  (pinned, see §4). Collateral is fetched from Intel PCS
  (`https://api.trustedservices.intel.com/sgx/certification/v4/…`) or a
  user-entered PCCS URL — never proxied through the gateway.
- **Does the crypto locally.** Quote verification runs in-browser via a WASM
  DCAP verifier (§3 option i). The page must not POST the quote to a backend for
  a verdict, or that backend becomes a new trusted party.

Browser reality check: a browser cannot open a raw TLS socket and read the peer
certificate's custom extensions from JS. So the web verifier obtains the quote
via the plain **`GET /attestation`** endpoint (doc 02), which returns the raw
quote + collateral hints as bytes/JSON. It then *separately* must bind that quote
to the actual TLS channel the user will use — see §2.4 for the browser-specific
limitation here (the browser can't see the handshake pubkey, so channel binding
in-browser is weaker than in the CLI, and the copy must admit it).

### (b) CLI / script — the trust baseline for power users & CI

A small static binary (or a `curl | verifier` script) the user runs on their own
machine. Audience: developers, SREs, CI pipelines, the security-conscious.

Why it's the baseline: the user obtains it from a signed release (§4), runs it
locally, and it can do the *strong* form of channel binding — perform the TLS
handshake itself, read the server cert's DICE extension, extract the quote,
verify, and compare `report_data` against the hash of the very key it just
handshook with. Nothing is delegated to the gateway.

Shape:

```
enclave-verify \
  --url https://gateway.example.com \
  --expected-mrenclave <hex, or --mrenclave-file signed-release.json> \
  --pccs https://sgx-dcap-server.cn-hongkong.aliyuncs.com/... \  # or Intel PCS
  --require-tcb-up-to-date \            # fail on OUTDATED_TCB (default on)
  --allow-sw-hardening-needed \         # accept CONFIG_AND_SW_HARDENING_NEEDED (this platform)
  --json                                # machine-readable for CI
# exit 0 = verified, non-zero = failed; --json emits the full detail object of §6
```

In CI it doubles as a gate: pin the expected MRENCLAVE in the repo, run
`enclave-verify --url $GATEWAY --json`, fail the job on non-zero exit. That turns
"is the endpoint still the audited enclave?" into a continuously enforced check
rather than a one-time human glance.


---

## 2. The verification flow (step by step)

Both form factors implement the same logical pipeline. Differences are noted per
step. This mirrors doc 02 §0 but from the *verifier's* side.

### 2.1 Obtain the quote

Two acquisition paths:

- **From the RA-TLS handshake (CLI, strong).** Open a TLS connection to the
  gateway. In the certificate-verification callback, take the server's
  self-signed leaf cert and parse the custom extension carrying the quote.
  Per the salvaged Gramine 1.9 finding, the quote lives under the **TCG DICE
  "tagged evidence" OID `2.23.133.5.4.9`** (CBOR-encoded), with a legacy copy
  under `1.2.840.113741.1337.6`. The verifier must decode the DICE OID: parse the
  extension value as CBOR, pull the evidence structure, and extract the raw
  `sgx_quote3_t` bytes. Do **not** assume the old `1.2.840.113741.1.13.1` OID —
  it is not what this Gramine emits. Align byte-for-byte with doc 02's layout.
- **From `GET /attestation` (web, and CLI fallback).** Fetch the raw quote +
  collateral bundle over plain HTTPS. Simpler, but see 2.4: an out-of-band quote
  is only meaningful if you *also* bind it to the channel you'll actually use.

Freshness input: the verifier SHOULD send a client nonce (query param or header)
that the enclave folds into `report_data` alongside the SPKI hash, OR rely on a
timestamp inside the quote/collateral. See 2.6 for replay handling; the
mechanism has to be decided jointly with doc 02 (the enclave side controls what
goes into the 64-byte `report_data`, and it's already spending all 64 bytes on
`SHA-512(SPKI)` — so a nonce needs a scheme change: e.g. `report_data =
SHA-512(SPKI || nonce)`, which doc 02 must adopt for nonce-based freshness to
work).

### 2.2 Verify the DCAP quote signature chain

This is the cryptographic core. Given the quote and collateral:

1. Parse `sgx_quote3_t`: header, ISV report body (contains MRENCLAVE, MRSIGNER,
   ISV prod id, ISV SVN, report_data, attributes/flags), and the ECDSA-P256
   signature section (quote signature, attestation public key, QE report, QE
   report signature, and the PCK cert chain).
2. Verify the chain **PCK leaf → Intel SGX Processor/Platform CA → Intel SGX
   Root CA**, checking each signature and that the root matches the **pinned
   Intel SGX Root CA** (§4). The PCK chain is usually embedded in the quote; the
   intermediate/root are also cross-checked against collateral.
3. Verify the QE report is signed by the PCK key, and that the attestation key
   hash appears in the QE report data (this ties the quote signature to the
   platform's provisioning key).
4. Verify the quote body signature over the ISV report using the attestation
   key.
5. Check revocation: the PCK and intermediate must not appear in the CRLs from
   collateral.

Never hand-roll this. Use a maintained DCAP verification library (§5). Collateral
= TCBInfo, QEIdentity, PCK CRL, Root CA CRL, all fetched independently (§0).

### 2.3 Check TCB status

From TCBInfo + QEIdentity, compute the platform's TCB level for the PCK cert's
FMSPC/PCESVN/CPUSVN, and the QE's identity level. Map to a status:

- `UpToDate` → good.
- `SWHardeningNeeded` / `ConfigurationAndSWHardeningNeeded` → **the expected
  status on this exact box** (Phase 0 saw `0xa008` CONFIG_AND_SW_HARDENING_NEEDED
  on the 8369B). Treat as *conditional pass*: allowed only when the operator has
  opted in (`--allow-sw-hardening-needed`), and always surfaced in the UI detail
  with an amber note explaining it means a microcode/config mitigation is
  advised but the measurement chain is intact. Do **not** silently hide it.
- `OutOfDate` / `OutOfDateConfigurationNeeded` → fail by default
  (`--require-tcb-up-to-date`); the platform is missing security updates.
- `Revoked` → hard fail, never overridable.

The web verifier's default policy should match the CLI's, and both must show the
raw status string, not just green/red, so the caveat is legible.

### 2.4 Check MRENCLAVE (and MRSIGNER / prod id / SVN)

- `MRENCLAVE` from the report body MUST equal the **published expected value**
  (§4). This is the identity of the exact reproducibly-built, audited, no-log
  enclave. A mismatch means you are NOT talking to the audited code — hard fail,
  no override. This is the single most important check for the product claim.
- `MRSIGNER` + `ISV prod id` SHOULD match the published signer/prod id (defense
  in depth; MRENCLAVE already pins the code, but MRSIGNER pins who signed it).
- `ISV SVN` SHOULD be `>=` the minimum published SVN (lets you roll a security
  fix and require clients pin the new floor).
- **`attributes.flags` DEBUG bit MUST be 0** for a production verdict. A debug
  enclave's memory is inspectable — its confidentiality guarantee is void. Phase
  0's enclave was a debug build (needed `RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1`);
  the real deployment must be a production enclave, which also changes MRENCLAVE.
  If the DEBUG bit is set, the verifier shows a red "DEBUG ENCLAVE — not
  confidential" state and refuses a pass unless an explicit insecure override
  flag is passed (never the default).

### 2.5 Check report_data binds the channel

This is what stops a MITM from replaying a genuine quote in front of its own TLS
key.

- **CLI (strong binding).** The verifier performed the handshake, so it has the
  server's presented TLS public key. Compute `SHA-512(DER(SPKI))` of that key and
  assert it equals the quote's `report_data` (or the SPKI-derived portion if a
  nonce scheme splits the field). Match → the TLS session you're on terminates
  inside the attested enclave. Mismatch → someone is relaying a quote for a key
  they don't hold; fail.
- **Web (weak binding — must be disclosed).** The browser fetched the quote via
  `/attestation` and cannot read the live handshake's server pubkey from JS. So
  the page can only check `report_data` against a key the *gateway told it about*
  — which the gateway controls. This means the in-browser check confirms the
  quote is internally consistent and the enclave is genuine, but it does **not**
  independently prove the specific TLS channel the browser is using terminates in
  that enclave. Honest copy for the web page: "Verified the endpoint runs the
  genuine enclave. Full channel-binding (proving your live connection isn't
  being relayed) requires the CLI verifier." Do not overstate. (A partial
  mitigation: if the browser can obtain the server cert's SPKI — e.g. the
  `/attestation` response echoes the leaf cert and the page compares it to what
  it can observe — it's still gateway-sourced, so it's belt-and-suspenders, not
  independent proof.)

### 2.6 Check freshness / anti-replay

A quote is a signed statement about the platform at generation time; a stale
quote could be replayed. Defenses, strongest first:

- **Nonce (best).** Client sends a random nonce; enclave binds it into
  `report_data` (requires the doc 02 scheme change noted in 2.1). Verifier
  confirms the nonce round-trips. Kills replay outright.
- **Collateral freshness.** TCBInfo/QEIdentity carry `issueDate`/`nextUpdate`;
  reject if `nextUpdate` is in the past. Bounds staleness to the collateral
  refresh window (days), not seconds.
- **Quote/receipt timestamp.** If the enclave emits a fresh quote per connection
  and includes a signed timestamp, reject quotes older than a small window.

For v1 (RA-TLS only, no chain), the pragmatic combination is: fresh quote per
handshake + strong channel binding (CLI) + a nonce once doc 02 supports it. The
web page relies on collateral freshness + per-request quote and must disclose the
weaker guarantee.


---

## 3. Where verification runs — three options compared

The verdict is only as trustworthy as the environment that computes it. Ruled
out up front: **verifying inside the gateway's own server.** That is circular
trust (§0) — the thing under test would be issuing its own passing grade. Never
do this, and never let the web page silently delegate the verdict to a
gateway-side endpoint.

### (i) Pure client-side in-browser via a WASM DCAP verifier

Compile a Rust DCAP quote-verification library to WebAssembly and run the full
signature-chain + TCB + policy check inside the user's browser tab. Collateral
and the Intel root come from Intel PCS / a user PCCS; expected MRENCLAVE is
pinned in the bundle.

- **Trust:** strongest for a *web* experience — no third party sees or decides;
  the user's own browser is the verifier. Combined with independent hosting
  (§1a) it fully satisfies §0 condition 2.
- **Cost:** hardest to build and maintain. You must compile a DCAP verifier
  (e.g. Automata's `dcap-rs` or Phala's `dcap-qvl`) to `wasm32`, wire up
  `fetch()` for collateral, and keep the WASM in sync with library updates.
  Payload is non-trivial (hundreds of KB). CBOR/DICE parsing of the quote must be
  done in JS/WASM too.
- **Residual weakness:** the channel-binding gap of §2.5 (browser can't read the
  live handshake key). Genuine-enclave: yes. This-exact-socket-isn't-relayed: no.

### (ii) A trusted remote attestation verification service (Intel Trust Authority or Alibaba)

Send the quote to Intel Trust Authority (ITA) or Alibaba's remote-attestation
verification API; they return a signed attestation result (often a JWT) that your
verifier checks.

- **Trust:** you no longer trust the gateway — but you now trust the verification
  service and must pin *its* signing key. That's a smaller, reputable trust
  anchor than the gateway, and it's independent of it, so it satisfies §0. Good
  middle ground.
- **Cost:** low to build (call an API, verify a JWT signature). ITA needs an API
  key/subscription; Alibaba's service ties naturally to the cn-hongkong region
  we already use for PCCS collateral.
- **Weaknesses:** privacy (the quote, which contains platform identifiers, goes
  to a third party), availability (their outage blocks verification), and you
  must still pin the expected MRENCLAVE *yourself* — the service verifies the
  quote is genuine and reports the measurement, but *which* MRENCLAVE is "the
  right one" is your policy, not theirs. Also still has the browser
  channel-binding gap if driven from a browser.

### (iii) A small self-hosted CLI the user runs, using `libsgx_dcap_quoteverify`

The user runs a local binary that links Intel's official
`libsgx_dcap_quoteverify` (the SGX DCAP Quote Verification Library, optionally
using the QvE — Quote Verification Enclave — for verifiable verification), or a
maintained Rust equivalent, on their own machine.

- **Trust:** strongest overall. Code from a signed release the user installed,
  Intel's own verification library, runs locally, does strong channel binding
  (§2.5 CLI path). Fully independent of the gateway. This is the reference
  verdict everything else is measured against.
- **Cost:** medium. Distributing a binary that links the SGX DCAP libs across
  platforms is fiddly (the libs are Linux-first; macOS/Windows users lean on the
  Rust pure-software verifiers instead). CI-friendly.
- **Weaknesses:** requires the user to install something; least "one-click." The
  library itself doesn't need SGX hardware to *verify* (verification is
  software), but packaging is heavier.

### Recommendation

Ship **(iii) the CLI as the trust baseline** and **(i) the in-browser WASM
verifier, independently hosted, as the one-click convenience layer**, with
**(ii) offered as an optional cross-check** ("verify this result against Intel
Trust Authority") rather than the primary path.

Rationale: (iii) gives the strongest, self-contained proof for the users who most
need it (developers, CI) and anchors the whole system's credibility. (i) delivers
the "one-click" product promise to everyone else without introducing a new
trusted party, as long as it's hosted off the gateway and its channel-binding
limitation is stated honestly. (ii) is a nice reassurance button and a fallback
when a user can't/won't run WASM, but making it the default would quietly swap
gateway-trust for vendor-trust and add a privacy cost, so it stays optional.
Under no configuration is option "verify on the gateway" offered.


---

## 4. Publishing & pinning the expected MRENCLAVE

MRENCLAVE is the linchpin of §2.4. If an attacker can influence which MRENCLAVE
the verifier treats as "expected," the whole chain collapses. So the expected
value must reach the user **out-of-band, authenticated, and independent of the
gateway.**

- **Source of truth: the reproducible build (doc 08).** The audited enclave is
  built reproducibly; `gramine-sgx-sigstruct-view server.sig` yields MRENCLAVE,
  MRSIGNER, ISV prod id, ISV SVN. Doc 08 must emit these into a machine-readable
  manifest (JSON) as part of the release.
- **Signed release note.** Publish that manifest in a **signed GitHub release**:
  a `expected-enclave.json` (mrenclave, mrsigner, isv_prod_id, min_isv_svn,
  build commit, toolchain pin) plus a detached signature (`cosign`/`minisign`/GPG)
  over it. Users get the public key once, out-of-band (release page, docs domain,
  keybase/well-known), and every subsequent manifest is verified against it. This
  ties directly to doc 08's reproducible-build output so anyone can rebuild and
  confirm the MRENCLAVE independently.
- **How the user gets an authentic copy.**
  - CLI: `enclave-verify` ships with the current expected values baked in *and*
    accepts `--mrenclave-file expected-enclave.json`; the binary itself came from
    a signed release, so the baked-in value is as trustworthy as the binary.
  - Web (independent host): the expected values are compiled into the
    independently-hosted bundle. Since the bundle isn't served by the gateway,
    the gateway can't tamper with them.
  - Web (co-hosted copy in `web/default`): must fetch `expected-enclave.json`
    from the independent release URL and verify its signature in-browser against
    a pinned public key — never trust a gateway-served copy of the expected
    value.
- **Rotation.** When the enclave is rebuilt (fix, dependency bump), MRENCLAVE
  changes. Publish a new signed manifest; bump `min_isv_svn` for security-
  relevant changes so old measurements can be explicitly retired. The verifier
  should be able to accept a small set of currently-valid MRENCLAVEs during a
  rollout window, each still signed.

Reproducibility is what makes this honest: because doc 08's build is
deterministic, a skeptical user can rebuild from the pinned commit+toolchain and
confirm the MRENCLAVE in the signed manifest matches — they don't have to take
the release note's word for it.


---

## 5. Concrete libraries

DCAP quote verification is a security-critical, standards-heavy routine — hand-
rolling it is how you ship a verifier that always says green. Use maintained
implementations:

**Rust (the core; compiles to native + WASM):**

- **`dcap-qvl`** (Phala) — pure-Rust DCAP quote verification, no dependency on
  Intel's C libs, verifies against collateral, `wasm32`-friendly. Strong fit for
  both the CLI and the in-browser WASM verifier (option i).
- **`dcap-rs` / Automata `automata-dcap-*`** — Automata's Rust DCAP verifier
  (used in their on-chain attestation work); pure-Rust, also WASM-targetable.
  Good cross-check / alternative to dcap-qvl.
- These give you a single verification core reusable across form factors: compile
  to a native lib for the CLI and to `wasm32-unknown-unknown` for the browser.

**Intel official (CLI, Linux, reference-grade):**

- **`libsgx_dcap_quoteverify`** (+ `libsgx_dcap_ql`, `libsgx_dcap_default_qpl`) —
  Intel's SGX DCAP Quote Verification Library. Optionally runs the **QvE** (Quote
  Verification Enclave) so the verification itself is attestable. Already present
  on the research box's package set (memory: `libsgx-dcap-*`). Linux-first;
  best for the CLI and CI runners. The QPL fetches collateral from the configured
  PCCS (`/etc/sgx_default_qcnl.conf`, already pointed at the cn-hongkong PCCS).

**Go (if the CLI is written in Go to share code with relay-core):**

- Intel's **`dcap-quote-verify` Go bindings** or cgo wrappers around
  `libsgx_dcap_quoteverify`. Or shell out to a small Rust `dcap-qvl` helper.
  Go has no mature pure-Go DCAP verifier, so either cgo-bind the Intel lib or
  embed the Rust verifier — do not write the chain check in pure Go by hand.

**RA-TLS handshake + DICE OID extraction (CLI strong path):**

- Gramine's **`ra_tls_verify_dcap`** (`libra_tls_verify_dcap.so`) already knows
  how to pull the quote from the cert and verify it, honoring the env-var policy
  knobs Phase 0 used (`RA_TLS_MRENCLAVE`, `RA_TLS_ALLOW_SW_HARDENING_NEEDED`,
  etc.). Reusing it in the CLI gives a Gramine-consistent verifier for free.
- If not using Gramine's lib: parse the leaf cert with a standard X.509 library,
  read the extension at OID **`2.23.133.5.4.9`**, CBOR-decode the DICE tagged
  evidence to recover the `sgx_quote3_t`, then feed it to `dcap-qvl`. Keep this
  parser byte-aligned with doc 02.

**Collateral fetch:** talk to Intel PCS
(`api.trustedservices.intel.com/sgx/certification/v4/`) or a PCCS
(`sgx-dcap-server.cn-hongkong.aliyuncs.com/...`). The verifier fetches this
itself; never accept collateral relayed by the gateway (§0).

**Trusted-service cross-check (option ii):** Intel Trust Authority client SDK
(verify the returned JWT against ITA's published JWKS) or Alibaba's remote-
attestation verify API for the cn-hongkong region.

**Web signature verification (option 4):** `cosign`-verifiable bundles, or
`minisign`/`libsodium` (WASM) to check the signed `expected-enclave.json` in the
browser.


---

## 6. UX: honest result + expandable detail

The product promise is "click, know you're safe." The obligation that comes with
it is to state **exactly** what was and wasn't proven — overclaiming here is worse
than not shipping, because it manufactures false confidence about prompt privacy.

### Top-level result

One unmistakable state, neo-brutalist bold (per the project design language):

- **GREEN — "Verified genuine no-log enclave."** All hard checks passed
  (signature chain to Intel root, MRENCLAVE == expected, non-debug, TCB
  acceptable per policy, channel bound [CLI] / genuine-enclave confirmed [web]).
- **AMBER — "Verified, with caveats."** Hard checks passed but a conditional
  applies: TCB is `CONFIG_AND_SW_HARDENING_NEEDED` (this platform's expected
  case), or web-mode weak channel binding, or a nonce-less freshness path.
  Green-ish but the caveat is named on the face, not buried.
- **RED — "NOT verified — do not send prompts."** Any hard failure (see failure
  states). Loud, blocking, with the specific reason.

### Expandable detail (the `detail` object)

Every field visible on demand, raw values shown, not just booleans:

```jsonc
{
  "result": "verified" | "verified_with_caveats" | "failed",
  "checked_at": "2026-07-13T12:00:00Z",
  "gateway_url": "https://gateway.example.com",
  "enclave": {
    "mrenclave": "hex…",              // measured
    "mrenclave_expected": "hex…",     // pinned (§4)
    "mrenclave_match": true,
    "mrsigner": "hex…",
    "isv_prod_id": 0,
    "isv_svn": 3,
    "debug_enclave": false            // MUST be false for green
  },
  "tcb": {
    "status": "ConfigurationAndSWHardeningNeeded",  // raw string, always shown
    "advisory_ids": ["INTEL-SA-…"],
    "policy": "allowed_by_operator_opt_in"
  },
  "chain": {
    "pck_to_intel_root": "ok",
    "root_ca_pin": "matched_pinned_intel_sgx_root_ca",
    "crl_checked": true,
    "collateral_source": "intel_pcs" | "pccs:cn-hongkong",
    "collateral_next_update": "2026-07-20T00:00:00Z"
  },
  "binding": {
    "report_data_expected": "sha512(SPKI)…",
    "report_data_actual": "…",
    "channel_bound": true,            // CLI: true; web: "not_independently_verified"
    "mode": "tls_handshake" | "attestation_endpoint"
  },
  "freshness": {
    "nonce_echoed": true,             // if scheme supports it
    "quote_age_seconds": 2
  },
  "proves": [ "endpoint runs the exact audited enclave image (MRENCLAVE)",
              "enclave runs on genuine, non-debug Intel SGX hardware",
              "TLS session terminates inside that enclave (CLI mode)" ],
  "does_not_prove": [ "that the audited source actually has no logging — read the audit + doc 06",
                      "anything about upstream providers beyond the enclave",
                      "future behavior — this is a point-in-time check" ]
}
```

The `proves` / `does_not_prove` arrays render as plain-language bullets under the
result. This is the honesty contract: MRENCLAVE proves *which code* runs, and the
"no-log" property is a claim about *that code*, established by the audit +
reproducible build (doc 08) + threat model (doc 06) — attestation proves you're
running the audited artifact, not that the audit was correct. The UI links
"what this does and doesn't prove" straight to **doc 06 (threat model)**.

### Failure states (each with a specific, actionable message)

- **MRENCLAVE mismatch** → RED, non-overridable. "This endpoint is running
  different code than the published audited enclave. Do not send prompts." Show
  both hashes.
- **Debug enclave** → RED. "This enclave is in DEBUG mode; its memory can be
  inspected and confidentiality is not guaranteed." Override only via explicit
  insecure flag (CLI), never in the web UI.
- **Outdated TCB** (`OutOfDate…`) → RED by default. "The platform is missing SGX
  security updates (advisories: …)." Overridable only with
  `--allow-outdated-tcb-insecure` and a prominent warning.
- **TCB revoked** → RED, never overridable.
- **Signature chain / CRL failure** → RED. "Could not verify the quote back to
  Intel's root, or a certificate is revoked."
- **report_data mismatch** → RED. "The attestation is not bound to this
  connection's key — the channel may be relayed/MITM'd."
- **PCCS / collateral unreachable** → distinct **GREY "Cannot verify right now"**
  (not green, not a security failure). "Couldn't fetch Intel/PCCS collateral —
  check network or try a different PCCS. No verdict was reached; do not assume
  safe." Offer a retry and a PCCS/Intel-PCS toggle. Critical: unreachable
  collateral must NEVER degrade to green.
- **Stale quote / replay suspected** → RED or AMBER depending on mechanism.

### Two-tier disclosure

Casual users see the color + one sentence + the `proves`/`does_not_prove`
bullets. Power users expand the full `detail` object (also the CLI `--json`
output verbatim). Same data, two depths.


---

## 7. Verifier API / flow sketch + key UI states

### Enclave-side surface the verifier consumes (aligns with doc 02)

- **RA-TLS handshake** — the leaf cert carries the quote under DICE OID
  `2.23.133.5.4.9`. CLI strong path.
- **`GET /attestation`** — returns `{ quote: base64, tls_spki: base64,
  collateral_hint?: {...}, nonce_echo?: hex, generated_at: iso8601 }`. The quote
  is fresh per request; `tls_spki` lets a client compare (weak, gateway-sourced).
  Optionally accepts `?nonce=<hex>` which the enclave folds into `report_data`
  (needs the doc 02 scheme change from §2.1/2.6).

Note: `/attestation` and `tls_spki` are *conveniences*; the verdict's integrity
never rests on them (§0). Collateral is fetched by the verifier from Intel
PCS/PCCS, not from `collateral_hint`, which is treated as an untrusted hint only.

### Flow (both form factors)

```
        ┌ CLI: TLS handshake ─► read leaf cert ─► parse OID 2.23.133.5.4.9
obtain ─┤                                          (CBOR/DICE) ─► sgx_quote3_t
 quote  └ Web: GET /attestation ─────────────────► sgx_quote3_t (+ tls_spki)
          │
          ▼
   fetch collateral  ◄── Intel PCS / user PCCS   (NEVER via gateway)
   + pinned Intel SGX Root CA (compiled in)
          │
          ▼
   verify chain PCK ─► Intel Root   (dcap-qvl / libsgx_dcap_quoteverify)
   verify QE report + quote sig
   check CRLs
          │
          ▼
   TCB status ─► {UpToDate | SWHardeningNeeded* | OutOfDate | Revoked}
          │
          ▼
   MRENCLAVE == expected (signed manifest, §4)?  MRSIGNER/prodid/SVN?  DEBUG==0?
          │
          ▼
   report_data == SHA-512(SPKI)?   CLI: SPKI from live handshake (STRONG)
                                   Web: SPKI from /attestation   (WEAK, disclosed)
          │
          ▼
   freshness: nonce echoed? collateral nextUpdate valid? quote age ok?
          │
          ▼
   verdict ─► GREEN / AMBER / RED / GREY(cannot-verify)  + detail object (§6)
```

### Key UI states

1. **Idle** — URL input (+ advanced: PCCS override, expected-MRENCLAVE override),
   big "Verify" button.
2. **Verifying** — stepper showing each stage of the flow above ticking through
   (obtain quote → chain → TCB → MRENCLAVE → binding → freshness). Transparency
   here is itself trust-building.
3. **GREEN / verified** — bold pass, `proves` bullets, expandable detail, and (if
   co-hosted) the persistent "served by the gateway — run the CLI for independent
   proof" banner.
4. **AMBER / verified-with-caveats** — pass with the named caveat (TCB hardening,
   weak web binding) front and center.
5. **RED / failed** — blocking, specific reason (§6 failure list), both hashes on
   mismatch, no accidental path to sending prompts.
6. **GREY / cannot-verify** — collateral/PCCS unreachable; retry + PCCS toggle; no
   verdict, explicitly not "safe."
7. **Detail drawer** — the full `detail` JSON (§6), copyable; matches CLI
   `--json`.

### Cross-references

- Quote acquisition, OID `2.23.133.5.4.9` layout, `report_data = SHA-512(SPKI)`,
  handshake ordering → **doc 02**.
- What "no-log" means and the residual trust the `does_not_prove` list points at
  → **doc 06 (threat model)**.
- Reproducible build, `expected-enclave.json`, signed release, MRENCLAVE
  publication → **doc 08**.
- Enclave boundary / content-leak elimination that the audited MRENCLAVE embodies
  → **docs 01 / 05**.

