package officialurls

import "strings"

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
	// PathRewrite, when set, maps the client's incoming request path to the
	// upstream path before it is appended to the official host. Used when a
	// provider's official path differs from the OpenAI-style path the client
	// sends (e.g. Gemini's OpenAI-compatible surface lives under /v1beta/openai).
	// nil means the path is forwarded verbatim.
	PathRewrite func(inPath string) string
}

// geminiOpenAIPathRewrite maps the OpenAI-style path a client sends to Google
// AI Studio's OpenAI-COMPATIBLE surface, which is rooted at /v1beta/openai:
// "/v1/chat/completions" -> "/v1beta/openai/chat/completions". Non-/v1 paths are
// left unchanged (the enclave only serves the OpenAI-style endpoints).
func geminiOpenAIPathRewrite(inPath string) string {
	if strings.HasPrefix(inPath, "/v1/") {
		return "/v1beta/openai/" + strings.TrimPrefix(inPath, "/v1/")
	}
	return inPath
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

	// Gemini / Google AI Studio (24): https://generativelanguage.googleapis.com
	// via its OpenAI-COMPATIBLE surface. The client sends OpenAI-style requests
	// (model in the body) to /v1/chat/completions; the enclave rewrites the path
	// to /v1beta/openai/chat/completions and injects Authorization: Bearer <key>.
	// Exact host (measured), so it is a faithful pass-through like OpenAI.
	24: {AuthHeader: "Authorization", AuthPrefix: "Bearer ", PathRewrite: geminiOpenAIPathRewrite},

	// Azure (3), Vertex (41), AWS Bedrock (33) remain DEFERRED: they route the
	// model in the request PATH (not the body) and/or need non-static auth
	// (Azure per-resource host + api-key; Vertex OAuth2 SA token; AWS SigV4). The
	// pure-stdlib crypto is already implemented + test-vector-validated here
	// (SignSigV4 in sigv4.go, CachedVertexToken in vertexoauth.go) and host-suffix
	// validation is in officialurls.go (IsOfficialHostSuffix), but wiring them into
	// the enclave dispatch needs model-from-path routing + per-provider request/
	// response handling (Bedrock event-stream) and a live-credential check.
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
