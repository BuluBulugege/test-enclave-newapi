# 06 — Threat Model & Security Argument

> Scope: this is the whitepaper core. It states the adversary model, the trusted
> computing base (TCB), and a step-by-step argument for the two properties this
> system claims to make **externally provable**:
>
> - **Property 1 (no content storage):** on the request→response path the server
>   persists **no** request/response content (prompts, completions). Non-content
>   metadata (token counts, model name, user id, cost) may persist.
> - **Property 2 (official upstream):** a channel marked as using the
>   official/default base URL provably connects to the real official upstream,
>   not an operator-controlled MITM.
>
> The mechanism is a minimal Go `relay-core` running inside an Intel SGX enclave
> under Gramine-SGX 1.9, reached over RA-TLS with DCAP remote attestation
> (verified end-to-end in Phase 0 on the Alibaba Ice Lake box, region
> `cn-hongkong`, against the Alibaba PCCS). new-api's control plane (users,
> billing, DB, admin) runs **outside** the enclave and sees only non-content
> metadata.
>
> This document is written to survive a skeptical reviewer. A negative claim
> ("we store nothing") cannot be proven by testing alone; it is argued from an
> attested measurement plus a source/build audit, and every step names its
> assumption. Section 5 is deliberately adversarial about what SGX/RA-TLS does
> **not** buy us. Related docs: `01` (relay-core arch), `02` (RA-TLS/DCAP),
> `03` (official-channel backend), `05` (content-leak elimination),
> `07` (client verifier), `08` (reproducible build).

---

## 1. Adversary model

We enumerate five adversaries. For each we state what it **can** do and what it
**cannot** do under our assumptions. The properties must hold against all of
them simultaneously, except where explicitly marked out of scope.

### 1(a). Malicious / curious gateway OPERATOR

This is the primary adversary and the whole reason the system exists. The
operator owns the deployment. They are assumed to have:

- **root on the host** running new-api and the enclave;
- full read/write to the new-api **database, Redis, config, and env** (they can
  set `HTTP_PROXY`, `TLS_INSECURE_SKIP_VERIFY`, per-channel `Proxy`, rewrite a
  channel's base URL, flip `ERROR_LOG_ENABLED`, etc.);
- the ability to **restart, stop, or replace binaries**, including swapping the
  enclave binary for a modified one, or running an entirely different program;
- the ability to read all **host memory** outside the enclave (so all of
  new-api's process memory, including the plaintext metadata it handles);
- the ability to **observe encrypted network traffic** on both legs and its
  sizes/timings, and to tamper with or drop it;
- physical/console access via the cloud provider console.

What the operator **cannot** do, under the SGX assumption (§2): read or modify
enclave memory (EPC) at runtime, extract the enclave's TLS private key, or forge
a DCAP quote for a MRENCLAVE they did not actually load. Crucially, if the
operator swaps the enclave for a modified binary, the **MRENCLAVE changes** and
an honest client's verifier rejects the handshake (§3). The operator can *deny
service* but cannot *silently* break either property — that asymmetry is the
core of the design.

### 1(b). Malicious / curious HOST OS + hypervisor (Alibaba cloud)

Strictly stronger than a root operator on the software side: the OS kernel and
the hypervisor are in the TCB of everything **except** the enclave. This models
a compromised or curious cloud provider. Capabilities: schedule/interrupt the
enclave, observe all non-enclave memory and all I/O, manipulate paging of
enclave pages (encrypted EPC), mount page-fault / controlled-channel attacks,
and observe precise timing. SGX's threat model explicitly targets this
adversary: enclave RAM is encrypted and integrity-protected by the CPU, so the
hypervisor sees only ciphertext. It **cannot** read enclave plaintext or forge
attestation. It **can** contribute to side channels (§5) and can halt the
machine (availability, not confidentiality).

### 1(c). Active + passive NETWORK attacker

Two legs:

- **client ↔ gateway:** a passive attacker sees TLS 1.3 ciphertext plus
  packet sizes and timing. An active attacker can inject, drop, or attempt MITM.
  RA-TLS defeats MITM: the server cert is self-signed and carries a DCAP quote
  whose `report_data` binds `hash(TLS-pubkey)`; a MITM presenting its own key
  produces a `report_data` mismatch and the verifier aborts before any prompt is
  sent (see `02`). The attacker is left with traffic analysis only (§5).
- **gateway ↔ upstream:** the enclave opens a strict TLS 1.3 connection to the
  compiled-in official host with full certificate verification and no proxy. An
  active attacker (or the operator playing MITM here) cannot present a cert
  chaining to the real upstream's CA for the pinned hostname. This is the
  network half of Property 2 (§4).

### 1(d). Malicious UPSTREAM provider

The real OpenAI/Anthropic/etc. endpoint (or whoever controls it) is **not**
trusted for confidentiality of the prompt — by construction it receives the
prompt in order to answer it. That is inherent to being a proxy and is out of
scope for Property 1, which is about **our** server storing nothing, not about
the upstream. We do defend against a *fake* upstream (§4): the operator cannot
repoint an "official" channel at an attacker while keeping the official badge,
because the routing table is inside MRENCLAVE. What the genuine upstream does
with the prompt is the upstream's policy, disclosed to the user by their choice
of model/channel.

### 1(e). Other tenants (co-resident on the same host)

Other VMs/containers on the Alibaba host, or other processes the operator runs.
Capabilities reduce to a subset of 1(b): they may attempt cross-VM/cross-core
microarchitectural side channels (§5) but have no legitimate access to enclave
memory and cannot attest as our enclave. Treated as a contributor to the side
channel surface, not an independent break.

## 2. Trust assumptions and the TCB

The security of both properties reduces to trusting the following. Everything
here is **in** the TCB; everything in §2.2 is deliberately **out**.

### 2.1 Inside the TCB

1. **Intel SGX hardware + microcode.** We assume the CPU correctly enforces
   enclave memory encryption/integrity and produces honest measurements
   (MRENCLAVE), and that the loaded microcode patch level (the platform TCB) is
   as reported. This is the root assumption; §5 lists the microarchitectural
   attacks that erode it and why the platform's `CONFIG_AND_SW_HARDENING_NEEDED`
   status matters.
2. **The DCAP Quoting Enclave (QE) and Provisioning Certification Enclave
   (PCE).** Intel-signed architectural enclaves that turn a local report into a
   remotely verifiable, ECDSA-signed quote. Trusted to sign only genuine reports
   from the local platform. Their identity is itself measured and pinned by the
   DCAP verification library.
3. **The `relay-core` code**, as audited (source review, `05`) and as built
   reproducibly (`08`). The audit establishes there is *no code path* that
   writes prompt/completion content to non-volatile storage or hands it to
   new-api; the reproducible build establishes that the audited source is what
   produced the pinned MRENCLAVE.
4. **The client verifier** (`07`). If the client does not actually verify the
   quote and pin MRENCLAVE, it gets **no** guarantee (§5). The verifier's
   correctness — quote parsing, signature chain check, MRENCLAVE comparison,
   `report_data` binding — is part of the TCB for the party relying on it.
5. **The reproducible-build toolchain** (`08`): pinned Go toolchain, Gramine
   1.9, manifest, and signing flow. A tampered toolchain could produce a benign
   MRENCLAVE from malicious source; hence the build must be deterministic and
   independently reproducible by a third party. (Known open item from Phase 0:
   `go.mod` vs Dockerfile toolchain mismatch — must be pinned to one.)

**Alibaba PCCS — trusted for collateral availability only, not integrity.**
The PCCS (`sgx-dcap-server.cn-hongkong.aliyuncs.com`) caches Intel-signed
collateral: the PCK certificate chain, TCB info, QE identity, and CRLs. It is
**not** trusted to be honest. Argument that a malicious PCCS cannot forge a
valid quote: every piece of collateral is signed by Intel keys that chain to the
**Intel SGX Root CA**, whose public key is pinned in the client verifier — not
fetched from the PCCS. A malicious PCCS can (a) serve stale but still
Intel-signed collateral, (b) refuse to serve (availability), or (c) serve
garbage. It cannot mint a PCK cert or TCB info with a valid Intel signature,
and it cannot produce an ECDSA quote signature that verifies against the
attestation key certified by that chain. The quote itself is signed inside the
QE on genuine hardware. So the worst a malicious PCCS achieves against
confidentiality is **denial of verification** (client refuses to proceed —
fail-closed) or **replay of outdated TCB status** (bounded by the client also
pinning a minimum acceptable TCB / SVN and by CRL checks). It cannot cause an
honest verifier to accept a quote that was never produced by the genuine pinned
enclave.

### 2.2 Explicitly OUTSIDE the TCB

- **new-api** (the whole control plane): user/token DB, billing, admin UI,
  routing metadata store, OAuth, Redis. It handles metadata only and is assumed
  hostile for content confidentiality.
- **The host OS, kernel, and hypervisor** (Alibaba cloud stack).
- **The database and Redis** (SQLite/MySQL/PostgreSQL + cache). They persist
  metadata by design; they must never receive content, and the argument for that
  is enclave-side (§3), not a matter of trusting the DB.
- **The front proxy / load balancer.** It must be a non-decrypting TCP
  passthrough; it is untrusted and must never terminate client TLS (if it did,
  plaintext would exist outside the enclave and Property 1 would be void). This
  is an architectural invariant, not a trusted component.
- **The operator's config and env.** Untrusted; the enclave ignores or overrides
  the content-relevant ones (proxy, insecure-skip-verify) for official channels
  because those settings are inside the measured code path, not read from the
  host.

## 3. Property 1 argument — no content storage

Claim: no request or response **content** reaches non-volatile storage or the
operator. This is a negative/existential claim ("there exists no path that
stores content"), so it is argued as a chain where each link is either
cryptographically enforced or established by audit + reproducible build. A break
in any single link breaks the property, so each link names its assumption.

**The chain:**

1. **RA-TLS handshake ⇒ client obtains a fresh quote.** The client connects and
   the enclave presents a self-signed cert carrying a DCAP quote whose
   `report_data` = `hash(TLS-pubkey)` (`02`). Freshness: the quote is generated
   for this enclave instance's key; combined with TLS 1.3's ephemeral key
   exchange, a captured old quote cannot be replayed against a new session
   because the pinned key would not match the live handshake.
   *Assumption:* TLS 1.3 and the hash binding are sound; the QE signed a genuine
   local report.
2. **Quote signature verifies to the Intel SGX Root CA.** The verifier checks
   the ECDSA quote signature → attestation key → PCK cert chain → Intel Root CA
   (pinned in the client, §2). *Assumption:* Intel's root key is uncompromised;
   the verifier pins it and does not trust the PCCS for integrity.
3. **MRENCLAVE == published value.** The verifier compares the quote's MRENCLAVE
   against the value published for the audited, reproducibly-built relay-core.
   Equality means the running enclave *is* that exact code. *Assumption:* the
   client actually performs this check and pins the right value (§5 — a client
   that skips it gets nothing); MRENCLAVE is second-preimage resistant.
4. **The measured binary has no content-persistence path.** Established by
   source audit (`05`) + reproducible build (`08`): given MRENCLAVE identifies
   this exact source, and the audit shows the source never writes content to
   disk/DB/Redis and never returns content to new-api, the running code cannot
   do so either. Concretely, the audit compiled **out** the four known
   content-leak sites and confirmed no successful prompt/completion is persisted:
   - disk body-cache temp files (`common/body_storage.go`, `service/file_service.go`),
   - dify temp file (`relay/channel/dify/relay-dify.go`),
   - DEBUG body/stream dumps (`relay/helper/stream_scanner.go`,
     `compatible_handler.go`, `relay-openai.go`),
   - upstream-error body capture (`service/error.go`, `model/log.go`,
     gated by `ERROR_LOG_ENABLED`).
   The relay-core→new-api boundary returns **only** numeric billing metadata
   (token counts, model, cost), never bodies. *Assumption:* the audit is
   complete and the build is deterministic — these are the load-bearing human
   steps and the ones a reviewer should attack hardest.
5. **The Gramine manifest mounts no writable host filesystem.** Even if a bug
   attempted a write, the enclave's view of persistent storage is constrained by
   its manifest to `tmpfs` (volatile, in encrypted EPC / enclave memory) with no
   `sgx.trusted_files` or `sgx.allowed_files` mapping a writable host path for
   content. Any content therefore lives only in encrypted enclave RAM for the
   lifetime of the request and is gone on process exit. *Assumption:* the
   manifest is itself part of the measured/pinned build (`08`) so the operator
   cannot add a writable mount without changing MRENCLAVE.

**Conclusion.** If steps 1–3 hold cryptographically and steps 4–5 hold by
audit+build, then content exists only transiently in encrypted enclave memory
that neither the operator nor the host OS/hypervisor can read (§2 SGX
assumption), and never reaches disk, DB, Redis, logs, or new-api. The residual
attack surface against this claim is (i) breaking the SGX confidentiality
assumption via side channels (§5), (ii) a flawed or incomplete audit, or (iii) a
non-reproducible/tampered build — all called out explicitly.

## 4. Property 2 argument — official upstream (anti-MITM)

Claim: a channel the UI marks as "official" provably connects to the real
official upstream, and the operator cannot silently repoint it to a MITM while
keeping the badge.

**The chain:**

1. **The official-URL table is compiled into relay-core.** The set of official
   base URLs (`constant.ChannelBaseURLs` keyed by channel type) is part of the
   enclave source, hence part of MRENCLAVE. For an official channel the enclave
   itself decides the upstream host from this compiled-in table; it does not
   take the URL from operator-controlled config for the "official" decision.
2. **The enclave enforces strict TLS to that host and refuses insecure paths.**
   For an official channel, relay-core opens TLS 1.3 with full certificate
   verification against the pinned official hostname, and **refuses**: per-channel
   `Proxy` (`dto/channel_settings.go`), `TLS_INSECURE_SKIP_VERIFY`
   (`common/init.go`), and env `HTTP(S)_PROXY` (`service/http_client.go`). These
   are exactly the operator levers that could otherwise interpose a MITM; the
   enclave ignores them on the official path. A channel is treated as official
   only when `GetBaseURL() == ChannelBaseURLs[type]` **and** its `Proxy == ""`.
3. **Verifying MRENCLAVE verifies the routing policy.** Because the table and
   the enforcement live in the measured code, a client that has pinned MRENCLAVE
   (§3, steps 1–3) has already verified that this exact routing/enforcement
   policy is what runs. There is no separate trust step: the anti-MITM guarantee
   rides on the same attestation as Property 1.
4. **Operator cannot silently repoint.** To route an "official" channel through
   a MITM the operator must modify relay-core (the table or the enforcement),
   which **changes MRENCLAVE**, which an honest client rejects. Alternatively the
   operator can present the channel as non-official (a custom base URL) — but
   then it is not badged official and the user is not misled. The property is:
   *official badge ⇒ measured routing ⇒ genuine upstream*, or the client refuses.

**Optional strengthening — per-request signed upstream-cert receipt.** The
enclave can hash the upstream server certificate it actually validated for the
request and return a signed receipt (signed by the enclave key already bound to
MRENCLAVE via RA-TLS). A client, or an auditor, can then confirm out-of-band
that the receipt matches the genuine official upstream's certificate/pin. This
converts "trust the measured code routed correctly" into "here is per-request
evidence of which upstream cert was on the wire," closing the gap where a
reviewer worries about upstream-side network tampering that the enclave itself
would already have rejected. Design detail in `07`.

*Assumptions:* the official-URL table is correct and kept current (a stale table
is a correctness bug, caught by audit, not a silent break); the upstream's own
TLS/CA is not compromised (out of scope — that is the upstream's and the public
CA system's problem, not something SGX can fix).

## 5. What SGX / RA-TLS does NOT protect

An honest threat model has to be loud about its limits. None of the following is
hand-waved; each is a real avenue a reviewer will and should press on.

- **Microarchitectural / cache-timing side channels.** SGX confidentiality is
  eroded by the Foreshadow/L1TF, ÆPIC Leak, SGAxe/CacheOut, MDS, and
  controlled-channel (page-fault) class of attacks. These can, under the right
  conditions, leak enclave memory — including a prompt in flight — to a
  privileged local attacker (adversary 1b/1e). This is **directly** adverse to a
  "we cannot see your prompt" claim: SGX makes *storing* and *casually reading*
  content infeasible, but does not make a determined microarchitectural attacker
  on the same silicon impossible. Mitigation is largely microcode/TCB level
  (patched CPUs, up-to-date platform TCB) plus disabling hyperthreading; several
  of these are exactly what the platform TCB status flags track (below). We must
  state plainly: **against a nation-state-grade local side-channel attacker, the
  confidentiality of an in-flight prompt is reduced, not absolute.**
- **Rollback / replay of state.** SGX does not by itself prevent the operator
  from restarting the enclave, feeding it stale sealed state, or replaying old
  requests. Our design keeps no content state to roll back, which limits the
  blast radius, but any metadata or counters the enclave relies on across
  restarts would need monotonic-counter / freshness protection that SGX does not
  provide for free.
- **Availability / DoS.** The operator can stop the enclave, block the port,
  throttle, or pull the machine. This is unpreventable and **by design
  acceptable**: the operator can turn the service off, but cannot make it run
  while silently violating either property. Fail-closed, not fail-open.
- **Traffic analysis.** Even with content encrypted and unstored, the **sizes
  and timing** of requests and responses leak on both network legs (adversary
  1b/1c). Prompt length, completion length, streaming token cadence, and
  request rate are all observable and can reveal a great deal. RA-TLS does
  nothing about this. Padding/batching would be needed to reduce it and is out
  of scope for v1.
- **Metadata leakage (by design).** Property 1 explicitly permits persisting
  token counts, model, user id, and cost. Token counts reveal content **length**;
  model choice and user identity are retained for billing. Anyone reading the
  new-api DB learns who asked how much of which model when — just not *what* was
  asked. This is a deliberate scope boundary, not an accident, and must be
  disclosed to users.
- **DEBUG enclave weakness (Phase-0 caveat).** Phase 0 was verified with a
  **debug** enclave. A debug enclave has a **different MRENCLAVE** than a
  production build and offers weaker guarantees — debug enclaves can be
  inspected by the operator (e.g. `EDBGRD`/`EDBGWR`), so their memory
  confidentiality against a privileged local party is effectively void. The
  Phase-0 client only worked because it set
  `RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1`. **A production deployment MUST run a
  non-debug (production) enclave, and the published MRENCLAVE and client policy
  MUST reject debug enclaves.** A reviewer who sees a debug MRENCLAVE or that
  flag set should treat the confidentiality claim as unproven.
- **`CONFIG_AND_SW_HARDENING_NEEDED` TCB status (Phase-0 caveat).** Phase 0's
  quote verified with `quote_verification_result = 0xa008` =
  `CONFIG_AND_SW_HARDENING_NEEDED`. This is **not** a full "OK": Intel is
  signalling that, given the platform's config and current TCB, additional
  software hardening / configuration is required to be robust against known
  issues (typically the side-channel class above — e.g. hyperthreading enabled,
  or a config that needs mitigation). The Phase-0 client only accepted it
  because it set `RA_TLS_ALLOW_SW_HARDENING_NEEDED=1` (and related
  `ALLOW_OUTDATED_TCB` / `ALLOW_HW_CONFIG_NEEDED`). For a real guarantee the
  client policy should require `UpToDate` (or at minimum consciously document
  which relaxations it accepts and why), and the platform should be hardened
  (latest microcode, HT disabled) to clear this status. Accepting it silently
  would let a reviewer argue the very side channels that threaten the prompt are
  known-unmitigated on this box.
- **Supply chain of the enclave code.** MRENCLAVE only proves "this measurement
  ran"; it says nothing about whether the source behind that measurement is
  trustworthy. The guarantee is only as good as (a) the source audit (`05`) and
  (b) the reproducibility of the build (`08`) that lets a third party confirm the
  published MRENCLAVE really comes from the audited source. A compromised
  dependency, build toolchain, or manifest that still produces the "expected"
  MRENCLAVE would defeat everything. The Phase-0 toolchain mismatch (`go.mod`
  1.25.1 vs Dockerfile 1.26.1) is a concrete reproducibility gap to close.
- **The client MUST actually verify.** Every guarantee above is contingent on
  the client performing full verification *before* sending the prompt:
  signature chain to the pinned Intel root, MRENCLAVE == published, non-debug,
  acceptable TCB, and `report_data == hash(pubkey)`. A client that skips any of
  these — or accepts on TOFU, or ignores a mismatch — gets **no** guarantee at
  all, and no amount of server-side correctness compensates. The verifier (`07`)
  and its default-deny policy are therefore part of the security story, not an
  afterthought.

## 6. Residual-risk table

Legend: **Closed** = cryptographically or architecturally prevented under stated
assumptions; **Reduced** = made hard / detectable but not eliminated;
**Out of scope** = accepted, disclosed, not addressed in v1.

| # | Risk | Who (adversary) | Status | Residual after mitigation |
|---|------|-----------------|--------|---------------------------|
| 1 | Operator reads/stores prompt from disk/DB/Redis/logs | 1a | Closed | Relies on audit (`05`) + reproducible build (`08`) being complete; no content path in measured code, tmpfs-only manifest. |
| 2 | Operator swaps enclave for a logging binary | 1a | Closed | MRENCLAVE changes → honest client rejects. Residual only if client skips verification (#12). |
| 3 | Host OS / hypervisor reads enclave RAM | 1b | Closed | SGX memory encryption; residual is side channels (#8). |
| 4 | MITM on client↔gateway leg | 1c | Closed | `report_data`=hash(pubkey) binding; residual is client not verifying (#12). |
| 5 | Operator repoints "official" channel to MITM upstream | 1a | Closed | Routing table in MRENCLAVE; enclave refuses proxy/insecure. Optional signed cert receipt strengthens. Residual: stale official-URL table (correctness bug, caught by audit). |
| 6 | MITM on gateway↔upstream leg | 1c | Closed | Strict upstream TLS verify inside enclave. Residual: upstream's own CA/TLS compromise (#11). |
| 7 | Forged DCAP quote via malicious Alibaba PCCS | 1a/1b | Closed | Collateral is Intel-signed to a pinned root; PCCS can only deny/stale, not forge. Residual is stale-TCB replay bounded by client SVN pin + CRL (#9). |
| 8 | Microarchitectural side channel leaks in-flight prompt | 1b/1e | Reduced | Real risk. Mitigate: production enclave, latest microcode, HT off, clear TCB status. Against a strong local side-channel attacker, in-flight confidentiality is not absolute. |
| 9 | Rollback / stale-TCB / replay | 1a/1b | Reduced | No content state to roll back; client pins min SVN and checks CRLs. Metadata freshness not fully protected in v1. |
| 10 | Availability / DoS (operator stops or blocks the service) | 1a/1b | Out of scope | Accepted by design — fail-closed. Operator can stop it, cannot silently violate a property while running. |
| 11 | Genuine upstream provider stores/uses the prompt | 1d | Out of scope | Inherent to proxying; disclosed to user via model/channel choice. Not something SGX addresses. |
| 12 | Client does not verify (or verifies weakly / TOFU) | 1c + user | Out of scope (client-side) | No guarantee if skipped. Mitigate: ship a correct default-deny verifier (`07`), publish MRENCLAVE, educate integrators. |
| 13 | Traffic analysis — sizes / timing / rate | 1b/1c | Out of scope | Leaks length and activity. No padding/batching in v1. |
| 14 | Metadata retention (token counts, model, user, cost) | 1a | Out of scope (by design) | Permitted by Property 1 definition. Reveals length + who/when/which, never content. Must be disclosed. |
| 15 | DEBUG enclave / relaxed TCB flags in production | 1a | Reduced → must Close before launch | Phase 0 used a debug enclave + `ALLOW_*` relaxations. Production MUST use non-debug enclave, publish its MRENCLAVE, and set client policy to reject debug and require acceptable TCB. |
| 16 | Supply-chain / non-reproducible build (benign MRENCLAVE from malicious source) | 1a + build | Reduced | Reproducible build (`08`) + third-party rebuild confirms MRENCLAVE↔source. Residual: audit/toolchain trust; pin single Go toolchain (close the 1.25.1/1.26.1 gap). |

### Honesty summary

- **Fully closed (under the SGX + pinned-Intel-root + honest-audit
  assumptions):** operator/host content theft via storage or binary swap, client-
  and upstream-side MITM, official-channel repointing, PCCS quote forgery
  (risks 1–7).
- **Reduced, not eliminated — the sharp edges a reviewer should press:**
  microarchitectural side channels (8), rollback/freshness of metadata (9),
  supply-chain/reproducibility (16), and the Phase-0 debug/TCB caveats (15)
  which are *blocking items* that must be closed before any real "we store
  nothing" claim is made externally.
- **Out of scope by design, and disclosed:** availability (10), what the genuine
  upstream does (11), clients that refuse to verify (12), traffic analysis (13),
  and permitted metadata retention (14).

The strongest true statement this system can make: *given a verified production
enclave with an up-to-date platform TCB and a correctly verifying client, a
malicious operator or cloud host cannot store or read your prompt/completion
content on the request→response path, and cannot silently route an official
channel to a fake upstream — at the cost of a reduced (not zero) exposure to
microarchitectural side channels and the acknowledged leakage of request
size/timing and billing metadata.*

