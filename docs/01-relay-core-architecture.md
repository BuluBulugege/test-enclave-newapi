# 01 — `cmd/relay-core` Enclave Architecture & Boundary

Status: design draft (v1). Scope: the SGX enclave binary
that terminates client TLS, dispatches to upstream AI providers, and its wire
contract with the out-of-enclave new-api control plane.

This document is the entry point for the confidential-computing (CC) layer. It
does NOT change code; it specifies what must be built and refactored.

---

## 0. Goals recap (what must become externally verifiable)

1. **No-content-at-rest.** On the request→response path the enclave stores NO
   prompt/completion CONTENT. Only non-content billing metadata (token counts,
   model, user, cost, latency, request_id) may leave the enclave and persist.
2. **Anti-MITM for official channels.** A channel using the default/official
   base URL provably connects to the real official upstream (pinned identity),
   not a host-side interceptor.

The enclave is the *only* component a remote client trusts. Everything outside
it (new-api main body: users, billing, DB, admin UI) is treated as an untrusted
host from the client's point of view — the RA-TLS attestation covers only the
enclave binary + its measured config.

---

## 1. The central problem: import severance

### 1.1 Verified import graph

`go list -deps ./relay/channel/openai` pulls in the entire business stack. The
internal (module `github.com/QuantumNous/new-api`) dependencies are:

```
constant                         relay/constant
common                           relay/common
setting/config                   setting/*  (billing, model, operation, perf, ratio, system, reasoning)
types                            model                      ← DB layer (GORM)
dto                              service                    ← business logic
logger                           service/chain
pkg/cachex                       service/relayconvert(+internal/*)
pkg/billingexpr                  relay/helper               ← contains disk-cache + body dumps
pkg/perf_metrics                 relay/common_handler
relay/reasonmap                  relay/channel + sibling channels (ai360, lingyiwanwu, openrouter, xinference)
relay/channel/task/taskcommon
```

The load-bearing offenders, in order of severity:

- **`model`** — GORM models and DB access. Imported by `relay/channel/adapter.go:8`
  (the `Adaptor` interface signature itself references `*model.Task` at
  `adapter.go:61,82`). Pulling the interface pulls the DB layer.
- **`service`** — `openai/adaptor.go:29` calls `service.ConvertRequest(...)`
  (`adaptor.go:45,66`) and `service.NewProxyHttpClient` / `service.GetHttpClient`
  (used in the dispatch at `relay/channel/api_request.go` `doRequest`). `service`
  transitively imports `model`, Redis, quota, logging.
- **`logger`** — `openai/adaptor.go:18`; also all over `api_request.go`
  (`logger.LogDebug/LogError`). Logger can write request-correlated lines.
- **`relay/helper`** — request validation + response helpers; also the home of
  SSE/ping and (historically) body-dump/disk-cache helpers.

### 1.2 The four content-leak sites (must be absent from the enclave binary)

Confirmed by grep across `relay/ common/ service/`:

1. **Debug body dumps** — `common.DebugEnabled` gated `os.WriteFile`/print of
   request/response bodies. Live examples:
   `relay/compatible_handler.go:102`, `relay/channel/claude/relay-claude.go:138`,
   `relay/channel/ollama/stream.go:213`, `relay/channel/openai/relay-openai.go:157`,
   `relay/common/override.go:206,262,274`. Commented-but-present in
   `openai/adaptor.go:60-83` (writes `claude_request_*.txt`, `claude_to_openai_request_*.txt`).
2. **Dify temp file** — `relay/channel/dify/relay-dify.go:46`
   `os.CreateTemp("", "dify-upload-*")` writes uploaded content to host disk.
3. **Error-body logging** — upstream error bodies logged verbatim on failure
   paths (`logger.LogError` in `api_request.go` `doRequest`, override.go).
4. **Disk cache / local content log** — `common/str.go:28` (`LocalLogContentLimit`
   truncation implies content is logged) and any response caching under
   `relay/helper`/`common`.

Reusing `relay/channel/openai` as-is drags **all four** into the measured
enclave binary. Even if disabled at runtime (`DEBUG=false`), their *presence in
the binary* undermines the attestation claim ("the thing I measured cannot
write content to disk"). The verifier reasons about the binary, not the flag.

### 1.3 Severance options

**(a) Extract a pure package `relay/pure/<provider>`.**
Move the pure request/response transform + URL building out of
`relay/channel/openai` into a new leaf package that imports only
`dto`, `types`, `constant`, `common` (json/string helpers), and `stdlib`.
No `model`, `service`, `logger`, `relay/helper`.

**(b) Build tags (`//go:build enclave`).**
Compile leak sites (disk-cache, dify temp file, debug dumps, error-body logging)
to no-op stubs under `enclave`. One file `foo.go` (`//go:build !enclave`) with the
real impl, one `foo_enclave.go` (`//go:build enclave`) with a stub.

**(c) Interface injection.**
The adaptor takes `Logger`, `Store`, `HTTPClientFactory` interfaces; relay-core
supplies no-op / in-memory implementations. Requires refactoring adaptors to stop
calling package-level `logger.*` / `service.*` / `model.*` directly.

### 1.4 Recommendation: **(a) as the backbone, (b) as the safety net.**

Rationale:

- Option (a) gives the strongest *verifiable* property: the enclave binary
  literally does not link `model`/`service`/`logger`, so no content-writing code
  path exists to audit. This is the property the client is attesting.
- Option (c) alone is insufficient for verification: the leak code still links
  into the binary, so the attestation reviewer must trust runtime wiring rather
  than the measurement. Good for testability, weak for the trust claim.
- Option (b) is the pragmatic complement: for the few shared helpers we cannot
  fully relocate, an `enclave` build tag guarantees the compiled artifact
  excludes disk/logging code. We additionally add a CI guard that runs
  `go list -deps -tags enclave ./cmd/relay-core` and FAILS if `model`, `service`,
  `logger`, or `os.WriteFile`-bearing packages appear.

So: pure packages carry the logic; build tags fence off anything that must stay
shared; injected no-op interfaces cover the runtime seams (http client, metrics).

### 1.5 Proposed package layout

```
cmd/relay-core/                 NEW enclave binary (main)
  main.go                       RA-TLS listener bootstrap, config, graceful stop
  dispatch.go                   per-request pipeline (convert → select → do → stream → settle)
relay/pure/                     NEW — zero model/service/logger imports
  core/
    adaptor.go                  PureAdaptor interface (see §3.1)
    registry.go                 apiType → PureAdaptor
  openai/
    convert.go                  ConvertOpenAIRequest (ported, no service.ConvertRequest)
    url.go                      GetRequestURL (ported from openai/adaptor.go:105)
    response.go                 usage/parse (no logger, no disk)
  claude/ gemini/ ...           later providers
pkg/raenclave/                  NEW — RA-TLS cert generation + quote embedding
pkg/relaycontrol/               NEW — client of the new-api control-plane (§4)
  wire.go                       shared request/response structs (imported by BOTH sides)
internal/enclavestub/           NEW — //go:build enclave no-op logger/store/cache
```

`pkg/relaycontrol/wire.go` is the single shared type module imported by both the
enclave and new-api, so the wire contract cannot drift.

### 1.6 Files that must be refactored

- `relay/channel/adapter.go:15-32` — the `Adaptor` interface references
  `*model.Task` (`:61,:82` on the `TaskAdaptor`/video interfaces) and `gin.Context`.
  The enclave must NOT depend on this interface. Introduce the smaller
  `PureAdaptor` (§3.1) that uses only `dto`/`types` and a plain `*RequestMeta`
  instead of `*gin.Context`/`*relaycommon.RelayInfo`. Keep the existing `Adaptor`
  for the non-enclave path; have the non-enclave adaptor *wrap* the pure one.
- `relay/channel/openai/adaptor.go`:
  - `GetRequestURL` (`:105`) → port to `relay/pure/openai/url.go`. It reads only
    `info.ChannelType`, `info.ChannelBaseUrl`, `info.RequestURLPath`,
    `info.ApiVersion`, `info.RelayMode` — all pure inputs; drop the `gin`/`model`
    coupling by passing a `RequestMeta`.
  - `ConvertOpenAIRequest` (`:237`) → port to `relay/pure/openai/convert.go`.
    Remove `service.ConvertRequest` usage that lives in `ConvertClaudeRequest`
    (`:66`) / `ConvertGeminiRequest` (`:45`); the cross-format conversion
    (`service/relayconvert`) must itself be audited for `model`/`logger` imports
    and either ported to `relay/pure/convert` or the enclave restricts v1 to
    same-format (OpenAI-in/OpenAI-out) relay.
  - `SetupRequestHeader` (`:183`) — pure (only sets `Authorization: Bearer` from
    `info.ApiKey` + provider quirks). Port as-is.
  - Remove the commented body-dump block `:60-83` in the ported copy (do not
    carry it forward).
- `relay/channel/api_request.go` `doRequest` (near `:477`) — currently uses
  `service.GetHttpClient`/`service.NewProxyHttpClient` and `logger.*`. The enclave
  needs its own `doRequest` in `cmd/relay-core/dispatch.go` that takes an injected
  `*http.Client` and a no-op logger, and does NOT log error bodies.
- `relay/compatible_handler.go:67-207` — the dispatch order
  (`GetAdaptor → Init → ConvertOpenAIRequest → DoRequest → DoResponse`) is the
  template the enclave `dispatch.go` reimplements against `PureAdaptor`, minus the
  pre/post-consume DB calls (those become control-plane RPCs, §4).

---

## 2. Boundary protocol

Two planes:

- **Data plane** (inside enclave): client TLS ↔ enclave ↔ upstream provider.
  Carries prompt/completion CONTENT. Never persisted, never crosses to the host
  in cleartext for storage.
- **Control plane** (host, new-api): channel selection, key vault, quota
  pre-consume, billing settle, logging of METADATA only. Reached from the enclave
  by RPC.

### 2.1 Recommendation: gRPC for enclave↔host control plane; HTTPS pass-through for data plane

- Control plane = **gRPC over a local Unix domain socket / loopback mTLS**.
  Rationale: strongly-typed contract (protobuf), streaming not required, small
  fixed set of calls (SelectChannel, FetchKey, PreConsume, Settle), easy to
  enforce "these are the ONLY things the enclave tells the host." A narrow,
  enumerable RPC surface is itself a security property — the reviewer can list
  every field that ever leaves the enclave and confirm none is content.
- Data plane = the enclave makes an ordinary outbound HTTPS request to the
  upstream, streaming the body straight through (§4.3). No gRPC involved.
- Alternative considered: HTTP+JSON for the control plane. Simpler to eyeball in
  logs, but weaker typing and easier to accidentally widen. gRPC's explicit
  `.proto` is the better artifact for an auditor. If the team prefers one language
  and minimal deps, HTTP+JSON with the shared `pkg/relaycontrol/wire.go` structs
  is an acceptable fallback.

### 2.2 (a) Where TLS terminates

```
client ──TLS(RA-TLS server cert)──▶ [ENCLAVE tls.Listener]
```

- The enclave runs a Go `tls.Listener`. Its leaf certificate is generated
  *inside* the enclave at startup by `pkg/raenclave`: it creates an ephemeral
  keypair, computes the SGX quote over `hash(pubkey)` (report-data binding), and
  embeds the DCAP quote as an X.509 extension (RA-TLS). The private key never
  leaves the enclave and is never sealed to disk.
- The client verifies the quote (against Alibaba cn-hongkong PCCS → Intel root,
  already proven in Phase 0) BEFORE sending any prompt. Only after the enclave
  measurement matches the expected MRENCLAVE/MRSIGNER does the client transmit
  content.
- Consequence: the host cannot MITM the client↔enclave leg — it does not possess
  the enclave key and cannot forge a quote for a different measurement.

### 2.3 (b) Channel selection call (enclave → control plane)

After TLS terminates, the enclave parses just enough of the request to extract
the `model` string and the caller's API token, then calls the control plane. It
does NOT send prompt content.

Request (`SelectChannelRequest`): `model`, `token_hash` (SHA-256 of the bearer
token, not the token itself where possible), `relay_format` (openai/claude/gemini),
`relay_mode`, `is_stream`, `request_id`, coarse size hints for pre-consume
(`estimated_prompt_tokens` computed inside the enclave, optional).

Response (`SelectChannelResponse`): `channel_id`, `channel_type`,
`upstream_base_url`, `upstream_api_key` (see §5.1 for how this is delivered
safely), `is_official` (drives anti-MITM pinning), `model_mapping`
(origin→upstream), `upstream_model_name`, `group`, `ratios` (for the enclave to
report cost, or left to settle), `api_version`, `organization`, `proxy`.

This mirrors what `middleware/distributor.go:504 SetupContextForSelectedChannel`
writes into the gin context today (`ContextKeyChannelBaseUrl` ← `channel.GetBaseURL()`
at `distributor.go:542`, `ContextKeyChannelKey` at `:541`, model mapping at `:526`).
The enclave receives these as an RPC response instead of context keys.

### 2.4 (c) Completion callback — billing metadata ONLY

On completion (success or error, streaming or not) the enclave calls
`Settle(SettleRequest)` with METADATA ONLY:
`request_id`, `user_id`, `token_id`, `channel_id`, `model`, `prompt_tokens`,
`completion_tokens`, `cached_tokens`, `reasoning_tokens`, `quota`/`cost`,
`latency_ms`, `upstream_status_code`, `is_stream`, `finish_reason`,
optional `quota_saturation` marker. **No `messages`, no `content`, no
`choices[].text`, no error body.**

Note: today `model.Log.Content` (`model/log.go:65`) holds a short human-readable
*descriptor string* (e.g. model + duration), not the prompt. In the enclave world
the host builds any such descriptor from metadata it already has; the enclave
never forwards the descriptor derived from content. This must be re-audited so
the host's log-building path (`service/log_info_generate.go`) receives only the
`SettleRequest` fields and nothing content-derived.

---

## 3. Go struct / interface sketches

### 3.1 `PureAdaptor` (in `relay/pure/core/adaptor.go`)

No `gin`, no `model`, no `service`, no `logger`. `RequestMeta` replaces both
`*gin.Context` and `*relaycommon.RelayInfo` for the enclave path.

```go
package core

import (
    "io"
    "github.com/QuantumNous/new-api/dto"
    "github.com/QuantumNous/new-api/types"
)

// RequestMeta is the pure, content-free routing/build context. It is the
// intersection of RelayInfo fields the transform+dispatch logic actually reads
// (see relay/common/relay_info.go:64-105) with NO DB/gin coupling.
type RequestMeta struct {
    RequestID         string
    RelayFormat       types.RelayFormat // openai | claude | gemini | responses
    RelayMode         int
    IsStream          bool
    ChannelType       int
    ChannelBaseURL    string // from SelectChannelResponse.upstream_base_url
    APIVersion        string
    Organization      string
    OriginModelName   string
    UpstreamModelName string // after model mapping
    RequestURLPath    string
    // ApiKey is injected late (see §5.1); kept out of any log/marshal path.
    ApiKey            string
    IsOfficial        bool
}

// PureAdaptor: request-shape conversion + URL/header building + response
// parsing. Pure functions of (meta, request-bytes). Returns bytes/usage; never
// touches disk, DB, or a package-level logger.
type PureAdaptor interface {
    GetRequestURL(m *RequestMeta) (string, error)
    SetupRequestHeader(m *RequestMeta, h http.Header) error
    ConvertOpenAIRequest(m *RequestMeta, req *dto.GeneralOpenAIRequest) (any, error)
    // ParseUsage extracts token counts from a (already-read) response for a
    // non-stream reply, or is fed each SSE frame for streaming. Returns METADATA.
    ParseUsage(m *RequestMeta, respChunk []byte) (*dto.Usage, error)
}
```

### 3.2 Injected seams (in `internal/enclavestub`, `//go:build enclave`)

```go
// Logger: no-op inside the enclave. NEVER formats content.
type Logger interface {
    Metric(requestID string, fields map[string]any) // counts/latency only
}
type noopLogger struct{}
func (noopLogger) Metric(string, map[string]any) {} // discard

// HTTPClientFactory: supplies the outbound client. In-enclave impl pins the
// official upstream identity when meta.IsOfficial (see §5.2).
type HTTPClientFactory interface {
    For(m *core.RequestMeta) (*http.Client, error)
}
```

### 3.3 Control-plane wire types (in `pkg/relaycontrol/wire.go`, shared by both sides)

```go
type SelectChannelRequest struct {
    RequestID             string `json:"request_id"`
    Model                 string `json:"model"`
    TokenHash             string `json:"token_hash"`
    RelayFormat           string `json:"relay_format"`
    RelayMode             int    `json:"relay_mode"`
    IsStream              bool   `json:"is_stream"`
    EstimatedPromptTokens int    `json:"estimated_prompt_tokens,omitempty"`
}

type SelectChannelResponse struct {
    ChannelID         int               `json:"channel_id"`
    ChannelType       int               `json:"channel_type"`
    UpstreamBaseURL   string            `json:"upstream_base_url"`
    UpstreamAPIKey    string            `json:"upstream_api_key"` // §5.1
    IsOfficial        bool              `json:"is_official"`
    UpstreamModelName string            `json:"upstream_model_name"`
    ModelMapping      map[string]string `json:"model_mapping,omitempty"`
    Group             string            `json:"group"`
    APIVersion        string            `json:"api_version,omitempty"`
    Organization      string            `json:"organization,omitempty"`
    Proxy             string            `json:"proxy,omitempty"`
    // Ratios for enclave-side cost calc, OR omitted to settle host-side.
    Ratios            map[string]float64 `json:"ratios,omitempty"`
    UserID            int               `json:"user_id"`
    TokenID           int               `json:"token_id"`
}

// SettleRequest — METADATA ONLY. No content fields exist on this struct by
// construction; that absence is the auditable invariant.
type SettleRequest struct {
    RequestID          string `json:"request_id"`
    UserID             int    `json:"user_id"`
    TokenID            int    `json:"token_id"`
    ChannelID          int    `json:"channel_id"`
    Model              string `json:"model"`
    PromptTokens       int    `json:"prompt_tokens"`
    CompletionTokens   int    `json:"completion_tokens"`
    CachedTokens       int    `json:"cached_tokens,omitempty"`
    ReasoningTokens    int    `json:"reasoning_tokens,omitempty"`
    Quota              int    `json:"quota"`
    LatencyMs          int64  `json:"latency_ms"`
    UpstreamStatusCode int    `json:"upstream_status_code"`
    IsStream           bool   `json:"is_stream"`
    FinishReason       string `json:"finish_reason,omitempty"`
    QuotaSaturation    string `json:"quota_saturation,omitempty"`
}
```

### 3.4 ASCII request sequence

```
CLIENT                 ENCLAVE (cmd/relay-core)              HOST new-api (control plane)        UPSTREAM
  │                          │                                        │                             │
  │  TLS ClientHello         │                                        │                             │
  │─────────────────────────▶│                                        │                             │
  │  RA-TLS cert (quote)      │                                        │                             │
  │◀─────────────────────────│                                        │                             │
  │  [verify MRENCLAVE +      │                                        │                             │
  │   PCCS→Intel root]        │                                        │                             │
  │  POST /v1/chat/... +body  │                                        │                             │
  │═════ CONTENT ════════════▶│  (TLS terminates INSIDE enclave)       │                             │
  │                          │  parse model + token_hash only         │                             │
  │                          │  PreConsume + SelectChannel (gRPC) ────▶│  auth token, pick channel   │
  │                          │                                        │  decrypt upstream key,      │
  │                          │                                        │  quota pre-deduct (DB)      │
  │                          │◀── SelectChannelResponse (key,url,...) ─│                             │
  │                          │  PureAdaptor.ConvertOpenAIRequest       │                             │
  │                          │  GetRequestURL / SetupRequestHeader     │                             │
  │                          │  pin official identity if IsOfficial    │                             │
  │                          │  HTTPS (stream body through) ═══════════════ CONTENT ═══════════════▶│
  │                          │◀════════════ CONTENT (stream) ══════════════════════════════════════│
  │◀═══ stream frames ════════│  (tee: count tokens in-memory,         │                             │
  │      (CONTENT)            │   forward frames to client)            │                             │
  │                          │  Settle(metadata only) ────────────────▶│  finalize quota, write Log  │
  │                          │                                        │  (METADATA only, DB)        │
  │  [conn close]            │                                        │                             │
```

---

## 4. Hard questions

### 4.1 How do upstream provider keys reach the enclave without host-side leak?

The upstream API key lives encrypted in the DB, decrypted today by the host in
`middleware/distributor.go:541` (`ContextKeyChannelKey`). Options:

- **v1 (accept host trust for the key): host decrypts, returns key in
  `SelectChannelResponse` over the loopback mTLS/UDS gRPC channel.** The key is
  visible to the host process, but this is acceptable in v1 because the *client's*
  two verifiable properties are (1) no-content-at-rest and (2) anti-MITM — neither
  requires the upstream key to be host-secret. The key transits an authenticated
  local channel and is held only in enclave memory thereafter (never sealed/logged).
- **v2 (remove host from key custody): seal the key material to the enclave.**
  The channel key is encrypted to the enclave's sealing/MRSIGNER identity; the
  host stores ciphertext it cannot read and hands it to the enclave, which
  unseals inside. This closes the residual host-visibility of upstream keys.
  Deferred — larger key-management change, and orthogonal to the client's v1
  trust claims.

Decision needed from human: is upstream-key host-visibility acceptable for v1?
(Recommended: yes, document it explicitly as out-of-scope for the v1 attestation.)

### 4.2 Who owns retry / load-balancing — new-api re-selects, or the enclave loops?

**Recommendation: new-api owns retry policy; the enclave performs the attempt.**

- The retry/ban/weight logic lives in `service.CacheGetRandomSatisfiedChannel`
  (`middleware/distributor.go:175`) and the retry loop around it — all DB/cache
  backed. Reimplementing it in the enclave would drag `model`/`service` back in,
  defeating §1.
- Flow: on an upstream failure the enclave reports the failure class (status
  code, timeout) to the control plane and calls `SelectChannel` again with an
  `exclude_channel_id` hint; the host picks the next channel and returns new
  routing. The enclave loops on *attempts*, the host decides *which channel* and
  *whether to keep trying*. This keeps the load-balancer stateful part outside
  and the content-bearing part inside.
- Consequence: retries re-send content upstream, but content stays inside the
  enclave the whole time — the request body is buffered in enclave memory (bounded,
  see §4.3) to allow re-dispatch. For streaming where the body is small (the
  prompt) and the response is large, buffering the *request* for retry is cheap;
  once response bytes start flowing, retries stop (standard behavior).

### 4.3 How does streaming pass through without buffering to disk?

- The enclave forwards `resp.Body` frame-by-frame straight to the client
  `tls.Conn` writer — an in-memory `io.Copy`/SSE-scanner pipe, never a temp file.
  This is the enclave analogue of the current SSE path but WITHOUT the ping/log
  helpers that touch disk. The Dify temp-file path (`relay-dify.go:46`) is
  explicitly excluded from the enclave build (§1.2 item 2).
- Token counting for billing happens by *teeing* the stream in memory: as frames
  pass through, `PureAdaptor.ParseUsage` accumulates counts from the usage field
  (or tokenizes locally). Only the running counters survive the request; frame
  bytes are discarded after forwarding.
- Backpressure: bounded in-memory buffers only; a slow client applies backpressure
  to the upstream read. No spill-to-disk. EPC is 3.9GB and RAM 3.4GB (POC), so
  buffers must be strictly bounded and streaming (never "read full body then
  write") — enforced in `dispatch.go`.

### 4.4 How does token auth work when the DB is outside the enclave?

- The enclave does NOT validate the caller's token itself (the token table +
  quota live in the DB, outside). Instead, the *first* control-plane call
  (`PreConsume`/`SelectChannel`) carries the `token_hash`; the host authenticates
  it exactly as `middleware` does today (token lookup, group, quota check) and
  returns either routing or an auth error the enclave relays to the client.
- The bearer token itself: the enclave should send a **hash** where the host can
  match on a stored hash, avoiding the raw secret crossing back to the host. If
  the current schema stores tokens in a form requiring the raw value, v1 may pass
  the raw token over the local authenticated channel (same trust basis as §4.1)
  and migrate to hash-matching later. Decision needed: token storage form.
- Pre-consume (预扣费) stays host-side (it needs the DB and the billing-safety
  invariants in `common/quota_math.go`); the enclave only triggers it and honors
  an "insufficient quota" rejection before contacting upstream.

---

## 5. Anti-MITM for official channels (property 2)

### 5.1 What "official" means

`is_official` is set by the host when the channel uses the default base URL for
its type — i.e. `channel.BaseURL` is empty/unset and `GetBaseURL()`
(`model/channel.go:494`) falls back to `constant.ChannelBaseURLs[channel.Type]`
(the hard-coded official endpoint). The host reports this flag; the *enforcement*
must be inside the enclave, because the host is untrusted for this property.

### 5.2 Enforcement inside the enclave

- For `IsOfficial` channels, the enclave's `HTTPClientFactory.For` uses a TLS
  config that **pins the official upstream** — either a pinned CA set / SPKI pin
  for `api.openai.com` et al., baked into the enclave binary (and therefore
  measured by MRENCLAVE), or at minimum strict hostname + public-CA verification
  against the *constant* official host, ignoring any host-supplied base URL
  override. The host cannot point an "official" channel at a proxy it controls,
  because the enclave ignores host-supplied URLs for official channels and dials
  the compiled-in official host.
- The pin list is part of the enclave measurement, so a verifier confirms "this
  binary can only reach the real official endpoints for official channels."
- Non-official (user-configured) channels use normal verification against their
  configured base URL; the anti-MITM guarantee is scoped to official channels
  only, matching the stated goal.

Decision needed: pin strategy — SPKI pinning (strong, brittle on provider cert
rotation) vs. pinned public-CA + fixed hostname (weaker, robust). Recommend the
latter for v1 with the official hostnames compiled in, revisit SPKI later.

---

## 6. Open questions / risks / decisions for the human

1. **Cross-format conversion in the enclave.** `service.ConvertRequest`
   (used by `openai/adaptor.go:45,66` for Claude/Gemini→OpenAI) lives under
   `service/relayconvert` and its `internal/*` tree. Does it transitively import
   `model`/`logger`? If yes, either port it into `relay/pure/convert` or **scope
   enclave v1 to same-format relay only** (OpenAI-in/OpenAI-out). Recommendation:
   v1 = same-format only; add cross-format after the pure-convert audit. NEEDS
   DECISION.
2. **Upstream key custody (§4.1).** Accept host-visible upstream keys in v1, or
   invest in enclave-sealed keys now? Recommend accept for v1.
3. **Token secret form (§4.4).** Can the host match on `token_hash`, or must the
   raw token cross the local channel? Depends on current token storage — needs a
   schema check.
4. **Pin strategy (§5.2).** SPKI vs pinned-CA+hostname for official channels.
5. **Attestation freshness / session resumption.** Does the client re-verify the
   quote per connection, or cache the measurement for a TTL? Affects latency at
   2 vCPU scale. Recommend per-connection verify for v1 (POC), optimize later.
6. **Metadata-leak audit is ongoing, not one-time.** `SettleRequest` has no
   content fields *by construction*, but every future field addition is a
   potential content-leak. Add a CI check + code-review rule: `pkg/relaycontrol`
   structs may only gain metadata fields. Pair with the §1.4 dep-guard
   (`go list -deps -tags enclave ./cmd/relay-core` must not contain
   `model`/`service`/`logger`).
7. **EPC/RAM pressure (3.9GB EPC, 3.4GB RAM).** Streaming buffers must be
   bounded; concurrent request ceiling must be set so aggregate buffers + Go heap
   stay within EPC. Needs a load target (concurrent streams) to size limits.
8. **Error surfaces.** Upstream error bodies must NOT be logged (leak site §1.2
   item 3) and must NOT be forwarded to `Settle`. The client still needs a useful
   error — forward the upstream error body to the *client* over the trusted TLS
   leg (that is content, allowed to flow to the client) but strip it before any
   host RPC.
9. **`DoResponse` billing coupling.** Today `adaptor.DoResponse`
   (`compatible_handler.go:207`, `openai/adaptor.go:628`) computes usage AND
   drives host-side consume. In the enclave these split: usage parsing stays in
   `PureAdaptor.ParseUsage`; consume becomes the `Settle` RPC. Confirm no usage
   logic secretly depends on `model`/`service` state.

---

## 7. Summary of the recommended path

- Extract `relay/pure/openai` (convert + url + header + usage) with zero
  `model`/`service`/`logger` imports; fence residual shared helpers behind
  `//go:build enclave` no-op stubs; inject http-client/logger seams.
- New `cmd/relay-core` runs an RA-TLS `tls.Listener`, reimplements the
  `compatible_handler` dispatch order against `PureAdaptor`, and talks to the
  host over a narrow gRPC control plane (`SelectChannel`/`PreConsume`/`Settle`)
  whose types live in shared `pkg/relaycontrol/wire.go`.
- Content stays inside the enclave (in-memory streaming, no disk); only
  `SettleRequest` metadata crosses to the host for billing/logging.
- Official channels are pinned to compiled-in official hosts inside the enclave,
  ignoring host-supplied base URLs, giving the anti-MITM guarantee.
- v1 scope reductions to confirm with the human: same-format relay only,
  host-visible upstream keys, per-connection attestation.




