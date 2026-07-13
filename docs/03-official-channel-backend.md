# 03 — Official Channel: Backend Design (PROPOSED, not applied)

Status: design proposal. All Go code below is a **sketch to be reviewed**, not a diff to
apply. File:line citations point at the current `newapi-remake` tree.

## 0. Goal recap

We want a provable property: a channel that uses the **default/official** upstream base URL
provably connects to the **real** official upstream (anti-MITM), enforced inside the SGX
`relay-core` enclave and verifiable via RA-TLS.

The backend's job here is narrow and control-plane only:

1. Decide, deterministically, whether a channel is "official" (`IsOfficial()`).
2. Surface that flag to (a) relay-core over the control-plane channel-select response
   (companion doc `01`), and (b) the admin channel list/detail API for operator visibility.
3. Define the enforcement contract that relay-core applies to official channels. The backend
   does **not** enforce anti-MITM — it only classifies. Enforcement is inside the enclave,
   because only enclave-resident, MRENCLAVE-measured code is trustworthy.

Key design stance: **the "official" bit computed by new-api is advisory / a hint.** relay-core
must **recompute** officiality from its own compiled-in table and its own view of the base URL
+ proxy, and never trust a flag the (untrusted) host process asserts. new-api's `IsOfficial()`
exists for UX (admin UI badge) and for the control plane to route/label, not as the security
boundary. See §3 and §4.

---

## 1. `IsOfficial()` on `model/channel.go`

### 1.1 Semantics

A channel is official iff **all** hold:

- Its type has a **non-empty** official default URL in `constant.ChannelBaseURLs[Type]`
  (`constant/channel.go:63-123`). Empty-default types can never be official (see §5.2).
- The **effective** base URL equals that official default. Because `GetBaseURL()`
  (`model/channel.go:494-503`) already resolves a blank/`nil` `BaseURL` to
  `constant.ChannelBaseURLs[channel.Type]`, "used the default" and "explicitly typed the
  official URL" collapse to the same effective string — both are official. That is the
  behavior we want.
- No transport indirection is configured: `GetSetting().Proxy == ""`
  (`dto/channel_settings.go:16`, resolved via `GetSetting()` at `model/channel.go:971-982`).

### 1.2 Code sketch

```go
// model/channel.go — proposed, near GetBaseURL (l.494) / GetSetting (l.971).

// officialDefaultBaseURL returns the built-in official upstream for this channel's type,
// or "" when the type has no official default (Azure, Custom, VertexAi, Xinference, …).
func (channel *Channel) officialDefaultBaseURL() string {
	t := channel.Type
	if t < 0 || t >= len(constant.ChannelBaseURLs) {
		return ""
	}
	return constant.ChannelBaseURLs[t]
}

// IsOfficial reports whether this channel provably targets its provider's official
// upstream with no operator-configured transport indirection.
//
// NOTE: this is an ADVISORY classification for UI/control-plane labeling. The security
// boundary is inside relay-core (SGX), which recomputes officiality from its own
// MRENCLAVE-baked URL table and refuses to trust this flag. See docs/cc-research/03 §3.
func (channel *Channel) IsOfficial() bool {
	official := channel.officialDefaultBaseURL()
	if official == "" {
		// Types with an empty default (Azure=3, Custom=8, PaLM=11, Xunfei=18,
		// VertexAi=41, Xinference=47, AdvancedCustom=58) can never be "official".
		return false
	}
	if channel.GetBaseURL() != official {
		return false
	}
	if channel.GetSetting().Proxy != "" {
		return false
	}
	return true
}
```

Notes / rationale:

- `GetBaseURL()` normalizes `nil` and `""` to the default, so we compare against the resolved
  effective URL rather than the raw `*BaseURL`. This makes both "left blank" and "typed the
  canonical URL" count as official, and any override (even a trailing-slash or scheme variant)
  count as non-official. relay-core applies the same exact-string rule on its side.
- We deliberately do **not** attempt URL canonicalization (trailing slash, lowercasing host,
  etc.). Exact-match keeps the classifier trivially auditable and matches relay-core's
  compiled-in comparison. If we ever want to accept `https://api.openai.com/` (trailing slash)
  as official, that normalization must be added identically in both places (see §4).
- No new DB column: `IsOfficial()` is a pure method over already-loaded fields.

---

## 2. Surfacing the official flag

Two independent surfaces. Neither adds a DB column — both derive the value at serialization
time to avoid GORM `AutoMigrate` churn and the fork's default-bool pitfalls called out in
`AGENTS.md` ("Avoid GORM boolean default tags…").

### 2.1 Admin channel list/detail API (`controller/channel.go`)

The channel object is serialized directly (`controller/channel.go:404-408` in `GetChannel`,
and the list path around `GetAllChannels`/`SearchChannels`). The `Channel` struct
(`model/channel.go:23-63`) is marshaled as-is via `c.JSON(..., "data": channel)`.

Add a **derived, gorm-ignored** field so it appears in JSON without touching the schema:

```go
// model/channel.go — add to the Channel struct (l.23-63), in the "cache info" area near
// `Keys []string json:"-" gorm:"-"` (l.62). gorm:"-" => never a DB column, no migration.

// IsOfficialChannel is a DERIVED response-only field. It is not persisted; it is populated
// at serialization time from IsOfficial(). Never read it back as a source of truth.
IsOfficialChannel bool `json:"is_official" gorm:"-"`
```

Because a `gorm:"-"` field is not auto-populated, set it explicitly right before serialization.
Two viable placements:

Option A — populate at each controller response site (explicit, local, easy to audit):

```go
// controller/channel.go, GetChannel, before c.JSON (l.401-403 area)
if channel != nil {
	clearChannelInfo(channel)
	channel.IsOfficialChannel = channel.IsOfficial()
}
```

For the list endpoints, loop over the returned slice and set the flag on each element before
`c.JSON`. Do this in `GetAllChannels` / `SearchChannels` (`controller/channel.go:100`, `:268`).

Option B — implement `Channel.MarshalJSON` so the flag is always correct wherever a channel is
marshaled:

```go
// model/channel.go — proposed
func (channel Channel) MarshalJSON() ([]byte, error) {
	type alias Channel // avoid recursion
	return common.Marshal(struct {
		alias
		IsOfficial bool `json:"is_official"`
	}{alias(channel), channel.IsOfficial()})
}
```

Recommendation: **Option A**. `MarshalJSON` on `Channel` is invasive — the struct is marshaled
in many code paths (cache, logs, sync, task payloads), and a custom marshaler would leak the
derived field everywhere and risks recursion / `common.Marshal` (AGENTS.md JSON rule) subtleties.
Explicit population at the two admin response sites keeps the blast radius small and the field
absent from internal serializations. Keep the struct field from §2.1 (with `json:"is_official"`)
either way; with Option A it stays zero-valued until explicitly set.

Frontend can render an "Official / 官方直连" badge from `is_official` in the channel table and
detail drawer. (Frontend work is out of scope for this doc.)

### 2.2 Control-plane channel-select response to relay-core (companion doc `01`)

Doc `01` defines the control-plane message new-api returns when relay-core asks "which channel
handles this request?". Today the live relay path stuffs the base URL into the gin context at
`middleware/distributor.go:542` (`SetContextKey(ContextKeyChannelBaseUrl, channel.GetBaseURL())`)
which surfaces as `relayInfo.ChannelBaseUrl` (`relay/common/relay_info.go:206`). In the SGX
split, that in-process context handoff is replaced by an explicit control-plane DTO.

Proposed addition to that DTO (defined fully in doc `01`):

```go
// The control-plane descriptor new-api hands to relay-core for a selected channel.
type ChannelDispatch struct {
	ChannelId int    `json:"channel_id"`
	Type      int    `json:"type"`
	BaseURL   string `json:"base_url"` // == channel.GetBaseURL()
	Proxy     string `json:"proxy"`    // == channel.GetSetting().Proxy
	// IsOfficial is a HINT for routing/labeling. relay-core recomputes officiality from its
	// MRENCLAVE-baked table using Type/BaseURL/Proxy and does NOT trust this field for
	// enforcement. See §3.
	IsOfficial bool `json:"is_official"`
	// ... key material, model mapping, header/param override, etc. per doc 01.
}
```

Critical: relay-core receives `Type`, `BaseURL`, and `Proxy` **anyway** (it needs them to build
the request), so it can and must derive officiality itself. The transmitted `IsOfficial` is
never the deciding input; it exists so the control plane and enclave agree on labeling and so
mismatches (host says official, enclave computes non-official, or vice versa) are detectable and
can be logged/refused. Treat a disagreement as a hard error inside relay-core.

---

## 3. Enforcement inside relay-core (official channels)

Enforcement lives **only** in the enclave. The host new-api process is untrusted for this
property; anything it asserts (including `IsOfficial`) is a hint. relay-core recomputes
officiality and, when official, applies the following, all measured into MRENCLAVE:

### 3.1 (a) Ignore any DB base_url override — use the compiled-in table

For an official channel, relay-core **ignores** the transmitted `BaseURL` entirely and uses its
own compiled-in official URL for `Type`:

```go
// relay-core (enclave) — sketch
func resolveUpstream(d ChannelDispatch) (string, error) {
	official := officialpkg.BaseURLFor(d.Type) // compiled-in copy, measured into MRENCLAVE
	isOfficial := official != "" &&
		d.BaseURL == official && // same exact-match rule as new-api IsOfficial()
		d.Proxy == ""
	if d.IsOfficial != isOfficial {
		return "", fmt.Errorf("officiality mismatch: host=%v enclave=%v type=%d",
			d.IsOfficial, isOfficial, d.Type)
	}
	if isOfficial {
		// Anti-MITM: never honor a host-supplied base URL for official channels.
		// Use the tamper-proof compiled-in value regardless of d.BaseURL.
		return official, nil
	}
	return d.BaseURL, nil // non-official: host-configured base URL is allowed
}
```

Why this is the anti-MITM core: the enclave binary's official URL table is part of MRENCLAVE.
A relying party who verifies the RA-TLS quote knows exactly which URLs "official" maps to. The
host cannot redirect an official channel to a proxy/interceptor by mutating `base_url` in the
DB, because the enclave discards that value.

### 3.2 (b) Forbid proxy / insecure TLS / env proxy

For official channels the enclave must neutralize every transport-indirection lever that exists
in the current codebase:

- **Per-channel Proxy** (`dto/channel_settings.go:16`, applied in the dispatcher at
  `relay/channel/api_request.go:480`): if `d.Proxy != ""` on a channel that otherwise looks
  official, it is by definition non-official (the `IsOfficial()` rule already rejects it). But
  relay-core must additionally **refuse** to build any proxied transport for an official
  channel — defense in depth in case of a future code path that sets a proxy independently.
- **`TLS_INSECURE_SKIP_VERIFY`** (`common/init.go:89` → `common.InsecureTLSConfig`
  `common/constants.go:119`): this global must have **no effect** inside relay-core for official
  channels. Bake the policy in: official channels always use strict verification; the enclave
  ignores any insecure-skip flag/env for them. Ideally relay-core does not even read that env
  var; if it must exist for non-official channels, gate it so it can never widen to official.
- **Env `HTTP(S)_PROXY`** (`http.ProxyFromEnvironment` at `service/http_client.go:62`): the
  enclave's HTTP client for official channels must set `Proxy: nil` explicitly, never
  `http.ProxyFromEnvironment`, so host-controlled env cannot interpose a proxy.

```go
// relay-core (enclave) — official channels get a locked-down transport.
func officialTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil, // never ProxyFromEnvironment for official channels
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: false, // hard-coded; TLS_INSECURE_SKIP_VERIFY is inert here
			// RootCAs: nil => system CA pool (see 3.3)
		},
	}
}
```

### 3.3 (c) Strict system-CA TLS verification

Official channels verify against the **system CA pool** (`RootCAs: nil` uses the OS trust
store), with `InsecureSkipVerify: false` and SNI/host verification on (Go's default when
`ServerName` is left to the URL host). No custom CA injection is permitted for official
channels — otherwise the host could add a rogue CA and MITM. The set of trusted roots is part
of the enclave's provisioned environment and should itself be pinned/measured where the SGX
image build allows (e.g. bake a curated CA bundle into the image rather than reading a
host-mutable `/etc/ssl`).

### 3.4 (d) SPKI pinning discussion for openai / anthropic / google

Question: should relay-core hard-pin the SPKI (public-key hash) of `api.openai.com`,
`api.anthropic.com`, `generativelanguage.googleapis.com`?

Trade-offs:

- **Hard SPKI pinning** (pin leaf/intermediate public key hashes): strongest anti-MITM, but
  **breaks hard on cert rotation**. These providers rotate certificates frequently and without
  notice; a pinned enclave would start failing all official traffic the moment a key rotates,
  and fixing it requires rebuilding + re-attesting the enclave (new MRENCLAVE). Operationally
  brittle and a self-inflicted outage risk.
- **Pin the CA / issuer** (pin to a known root or intermediate, e.g. the provider's known CA):
  survives leaf rotation as long as the issuer is stable, but CAs also change and cross-signing
  makes "the" CA ambiguous. Medium brittleness.
- **Cert-chain-to-known-CA + strict SNI/host check** (system trust store + hostname
  verification, which is 3.3): survives rotation, relies on the public CA ecosystem. This is
  the same trust model browsers use. Combined with 3.1 (compiled-in host, cannot be redirected)
  and 3.2 (no proxy, no insecure skip), the residual risk is "a public CA mis-issues a cert for
  the official host" — a high bar for an attacker and out of scope for host-level MITM.

**Recommendation:** do **not** hard-pin SPKI. Use strict chain-to-known-CA validation with
SNI/host verification (§3.3) as the baseline. Optionally add **CA-level** pinning as a
configurable, per-provider hardening layer with a documented rotation/rebuild runbook, but keep
it off by default so cert rotation never causes an official-traffic outage. The dominant
anti-MITM guarantee comes from the compiled-in URL table (§3.1) + locked transport (§3.2), not
from pinning. If a future threat model demands pinning, prefer pinning the **CA public key**
over the **leaf SPKI**, and ship the pin set inside MRENCLAVE with an explicit update procedure.

---

## 4. Where the compiled-in official table lives + staying in sync

### 4.1 Single source of truth problem

`constant.ChannelBaseURLs` (`constant/channel.go:63-123`) is the authoritative table today, but
`constant/` may pull in siblings that transitively reach `model`/`service`. relay-core must
import the URL table **without** dragging in `model`/`service` (this is exactly the import
severance discussed in doc `01`). So the table needs to live in a **leaf, pure package** with
zero heavy dependencies.

### 4.2 Recommended: extract a pure leaf package + generate/verify

Create `pkg/officialurls` (pure Go, no imports beyond stdlib) that owns the canonical slice:

```go
// pkg/officialurls/officialurls.go — the single source of truth.
package officialurls

// BaseURLs is indexed by channel type. Empty string == no official default.
var BaseURLs = []string{
	"",                        // 0
	"https://api.openai.com",  // 1
	// ... full copy, kept in type-index order ...
}

func BaseURLFor(channelType int) string {
	if channelType < 0 || channelType >= len(BaseURLs) {
		return ""
	}
	return BaseURLs[channelType]
}
```

Then `constant.ChannelBaseURLs` becomes an alias so existing call sites are untouched:

```go
// constant/channel.go — proposed: re-point to the pure package.
var ChannelBaseURLs = officialurls.BaseURLs
```

- new-api (`GetBaseURL`, `IsOfficial`) reads `constant.ChannelBaseURLs` → same bytes.
- relay-core imports **only** `pkg/officialurls` (leaf, no `model`/`service`), and that slice is
  compiled into the enclave binary → measured into MRENCLAVE.
- One definition, one source of truth, no drift.

Because relay-core is a **separately built binary**, "compiled-in" and "in sync" are guaranteed
by both binaries building from the same `pkg/officialurls` source at the same commit. Add a CI
guard so they can never diverge at build time:

- A `go test` in `pkg/officialurls` (or a codegen check) that asserts the slice length and a few
  golden entries (`BaseURLs[1] == "https://api.openai.com"`, `[14] == "https://api.anthropic.com"`,
  `[24] == "https://generativelanguage.googleapis.com"`), so an accidental reordering/insertion is
  caught. Index-based tables are fragile to insertion; the test locks the critical indices.
- The enclave build and the host build must be pinned to the same commit; the RA-TLS
  MRENCLAVE already encodes which `officialurls` bytes are running, so a relying party can, in
  principle, verify the enclave's table against the published source for that commit.

### 4.3 Why not codegen a frozen copy?

An alternative is generating a `//go:generate`d frozen copy into relay-core. That adds a
divergence window (generated file lags the source) and a second thing to review. The shared-leaf
package (§4.2) is simpler and removes the copy entirely — prefer it. Keep codegen only if doc
`01`'s import severance turns out to force a physical copy (e.g. relay-core lives in a separate
module); in that case, generate `officialurls` into relay-core from the canonical file and gate
CI on `git diff --exit-code` after regeneration.

---

## 5. Edge cases

### 5.1 `ChannelSpecialBases` (model-sync only)

`constant.ChannelSpecialBases` (`constant/channel.go:195-212`) maps sync-plan names
(`glm-coding-plan`, etc.) to Claude/OpenAI base URLs. Audited fact: it is used **only** by
model-sync (`controller/channel_upstream_update.go:293-306`), **not** in the live relay path.
Therefore:

- `IsOfficial()` must **not** consult `ChannelSpecialBases`. A channel whose operator set its
  base URL to, e.g., `https://open.bigmodel.cn/api/anthropic` is **non-official** by our rule
  (it's not `constant.ChannelBaseURLs[Type]`), which is correct — those are coding-plan
  endpoints, not the provider's canonical official upstream, and they must not receive the
  anti-MITM guarantee.
- No relay-core changes are needed for `ChannelSpecialBases`; it never reaches the enclave's
  upstream resolution. Just make sure the shared-leaf extraction (§4.2) does **not** accidentally
  fold `ChannelSpecialBases` into the official table.

### 5.2 Azure / custom empty-default types

Types with `constant.ChannelBaseURLs[Type] == ""` — Azure=3, Custom=8, PaLM=11, Xunfei=18,
VertexAi=41, Xinference=47, AdvancedCustom=58 (and any other empty slot, e.g. 0, 28-30, 32-33,
36) — have no official default. `IsOfficial()` returns `false` immediately for them (§1.2, the
`official == ""` guard). This is correct: there is no single canonical upstream to prove against
(Azure uses per-resource hostnames like `*.openai.azure.com`; VertexAi/Xinference are
deployment-specific). These channels always take the non-official path in relay-core (§3.1
`else` branch) and receive normal — not anti-MITM-hardened — treatment. They can still use the
locked transport if desired, but they cannot be labeled "official".

### 5.3 Cloudflare-gateway special case

`GetFullRequestURL` (`relay/common/relay_utils.go:26-38`) rewrites the request path when the
base URL starts with `https://gateway.ai.cloudflare.com` (stripping `/v1` for OpenAI, etc.).
This is a base-URL-prefix-triggered rewrite. Interaction with officiality:

- A Cloudflare-gateway base URL is **never** equal to any `constant.ChannelBaseURLs[Type]`
  entry (none of them are `gateway.ai.cloudflare.com`), so `IsOfficial()` naturally returns
  `false` for such channels. Good — a Cloudflare AI Gateway is, by definition, an intermediary,
  which is the opposite of the anti-MITM property. It must not be official.
- relay-core must apply the Cloudflare path-rewrite logic **only** on the non-official branch.
  For official channels the base URL is force-set to the compiled-in canonical value (§3.1),
  which never has the Cloudflare prefix, so the rewrite is inert for them by construction. When
  porting `GetFullRequestURL` into relay-core, keep the Cloudflare branch after the official
  resolution so it can only affect host-supplied (non-official) base URLs.

---

## 6. Summary of proposed backend changes (for doc 01 / implementation)

| Change | Location | Kind |
| --- | --- | --- |
| `IsOfficial()` + `officialDefaultBaseURL()` | `model/channel.go` (near l.494/971) | new pure methods |
| `IsOfficialChannel bool` derived field | `model/channel.go` struct (near l.62) | `gorm:"-"`, response-only |
| Populate flag before `c.JSON` | `controller/channel.go` GetChannel l.401-403, list at l.100/268 | explicit set (Option A) |
| Extract `pkg/officialurls` leaf pkg; `ChannelBaseURLs = officialurls.BaseURLs` | new `pkg/officialurls`, `constant/channel.go:63` | refactor, single source of truth |
| CI golden test for critical indices | `pkg/officialurls/*_test.go` | drift guard |
| `IsOfficial` field on `ChannelDispatch` DTO | control-plane DTO (doc 01) | hint only |
| Officiality recompute + upstream lock + locked transport | relay-core (enclave) | enforcement (§3) |

Security boundary reminder: new-api's `IsOfficial()` and the transmitted `is_official` are
**advisory**. The enforced, attestable anti-MITM guarantee is entirely inside relay-core:
compiled-in URL table (MRENCLAVE), forced official upstream, proxy/insecure-TLS refusal, strict
system-CA verification. Everything the untrusted host says is re-derived and cross-checked.
