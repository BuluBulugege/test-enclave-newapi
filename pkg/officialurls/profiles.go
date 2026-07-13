package officialurls

// UpstreamProfile describes HOW relay-core authenticates to a provider's
// OFFICIAL upstream. It is compiled into the enclave and measured by MRENCLAVE,
// so a remote verifier confirms exactly which providers can be reached as
// "official" and how their credential is injected. relay-core stays a faithful
// pass-through: the client sends each provider's NATIVE request format to its
// native path; relay-core enforces the official host, injects the standard
// credential below, forwards the body verbatim, and never stores content.
type UpstreamProfile struct {
	// AuthHeader is the HTTP header that carries the upstream API key.
	AuthHeader string
	// AuthPrefix is prepended to the key in that header (e.g. "Bearer ").
	AuthPrefix string
	// ExtraHeaders are constant headers the provider requires (e.g. Anthropic's
	// version pin). nil is fine.
	ExtraHeaders map[string]string
}

// profiles maps channel type id (see constant.ChannelType*) to the official
// auth profile. Only providers listed here can be served as "official" by the
// enclave — an explicit, auditable allowlist.
var profiles = map[int]UpstreamProfile{
	// OpenAI (1): https://api.openai.com — Bearer
	1: {AuthHeader: "Authorization", AuthPrefix: "Bearer "},

	// OpenRouter (20): https://openrouter.ai/api — Bearer + attribution headers
	20: {AuthHeader: "Authorization", AuthPrefix: "Bearer ", ExtraHeaders: map[string]string{
		"HTTP-Referer": "https://newapi.ai",
		"X-Title":      "new-api",
	}},

	// Anthropic (14): https://api.anthropic.com — x-api-key + version pin.
	// Served via /v1/messages (native Anthropic Messages API).
	14: {AuthHeader: "x-api-key", AuthPrefix: "", ExtraHeaders: map[string]string{
		"anthropic-version": "2023-06-01",
	}},

	// Gemini / Google AI Studio (24), Azure (3), Vertex (41), AWS Bedrock (33)
	// are DEFERRED: they need per-provider URL building (native paths differ from
	// /v1/chat/completions) and/or non-static auth (OAuth2 service-account, SigV4)
	// that the current single-host + static-header profile cannot express. They
	// will be added with a profile redesign (host-suffix validation + a signing
	// hook) and validated with published test vectors before the enclave rebuild.
}

// ProfileFor returns the official auth profile for a channel type. ok=false for
// types that are NOT vetted as official upstreams (the enclave refuses to serve
// them as official).
func ProfileFor(channelType int) (UpstreamProfile, bool) {
	p, ok := profiles[channelType]
	return p, ok
}

// SupportsOfficial reports whether a channel type is a vetted official provider:
// it has both a non-empty official base URL and an auth profile.
func SupportsOfficial(channelType int) bool {
	if !HasOfficial(channelType) {
		return false
	}
	_, ok := profiles[channelType]
	return ok
}
