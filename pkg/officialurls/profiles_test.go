package officialurls

import "testing"

// TestOfficialProviders pins the base URL + auth style for each vetted official
// provider the enclave supports. These are security policy (which host, how to
// authenticate) and are measured into MRENCLAVE — a drift here is a real change.
func TestOfficialProviders(t *testing.T) {
	cases := []struct {
		name        string
		channelType int
		baseURL     string
		authHeader  string
		authPrefix  string
	}{
		{"OpenAI", 1, "https://api.openai.com", "Authorization", "Bearer "},
		{"OpenRouter", 20, "https://openrouter.ai/api", "Authorization", "Bearer "},
		{"Anthropic", 14, "https://api.anthropic.com", "x-api-key", ""},
		{"Gemini/AIStudio", 24, "https://generativelanguage.googleapis.com", "Authorization", "Bearer "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := For(c.channelType); got != c.baseURL {
				t.Fatalf("base URL = %q, want %q", got, c.baseURL)
			}
			p, ok := ProfileFor(c.channelType)
			if !ok {
				t.Fatalf("no profile for %s (type %d)", c.name, c.channelType)
			}
			if p.AuthHeader != c.authHeader || p.AuthPrefix != c.authPrefix {
				t.Fatalf("auth = %q+%q, want %q+%q", p.AuthPrefix, p.AuthHeader, c.authPrefix, c.authHeader)
			}
			if !SupportsOfficial(c.channelType) {
				t.Fatalf("SupportsOfficial(%d) = false, want true", c.channelType)
			}
		})
	}
}

func TestAnthropicVersionPinned(t *testing.T) {
	p, _ := ProfileFor(14)
	if p.ExtraHeaders["anthropic-version"] == "" {
		t.Fatal("Anthropic profile must pin anthropic-version")
	}
}

func TestUnsupportedTypeNotOfficial(t *testing.T) {
	// A type with an official URL but no vetted auth profile must not be servable
	// as official (e.g. DeepSeek=43 has a base URL but no profile yet).
	if SupportsOfficial(43) {
		t.Fatal("type 43 has no profile; SupportsOfficial should be false")
	}
	// Custom (8) has no official URL at all.
	if SupportsOfficial(8) {
		t.Fatal("custom type 8 must never be official")
	}
}

// TestGeminiOpenAICompatPathRewrite pins Gemini's OpenAI-compatible path rewrite
// (client's /v1/... -> upstream /v1beta/openai/...), which is what lets the
// enclave serve Gemini as a faithful body-model pass-through.
func TestGeminiOpenAICompatPathRewrite(t *testing.T) {
	p, ok := ProfileFor(24)
	if !ok || p.PathRewrite == nil {
		t.Fatal("Gemini profile must define a PathRewrite")
	}
	cases := map[string]string{
		"/v1/chat/completions": "/v1beta/openai/chat/completions",
		"/v1/embeddings":       "/v1beta/openai/embeddings",
		"/v1beta/openai/x":     "/v1beta/openai/x", // already-rewritten / non-/v1 left as-is
	}
	for in, want := range cases {
		if got := p.PathRewrite(in); got != want {
			t.Fatalf("rewrite(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDeferredProviders documents that the per-provider-URL / non-static-auth
// providers Azure(3), AWS Bedrock(33), Vertex(41) are DEFERRED: not yet servable
// as official through the enclave (no auth profile) until model-from-path routing
// + their dispatch land. Adding a profile here is a deliberate MRENCLAVE policy
// change and must come with URL-building + signing support.
func TestDeferredProviders(t *testing.T) {
	for _, ct := range []int{3, 33, 41} {
		if SupportsOfficial(ct) {
			t.Fatalf("type %d is deferred and must not be official yet", ct)
		}
	}
}

// TestIsOfficialHostSuffix locks the anti-MITM host-boundary check for the
// per-resource/per-region providers — lookalike domains MUST be rejected.
func TestIsOfficialHostSuffix(t *testing.T) {
	ok := []struct {
		ct   int
		host string
	}{
		{3, "myres.openai.azure.com"},
		{3, "https://myres.openai.azure.com/openai/deployments/x"},
		{3, "MyRes.OpenAI.Azure.Com:443"},
		{3, "acct.cognitiveservices.azure.com"},
		{33, "bedrock-runtime.us-east-1.amazonaws.com"},
		{41, "us-central1-aiplatform.googleapis.com"},
		{41, "aiplatform.googleapis.com"},
	}
	for _, c := range ok {
		if !IsOfficialHostSuffix(c.ct, c.host) {
			t.Fatalf("IsOfficialHostSuffix(%d,%q) = false, want true", c.ct, c.host)
		}
	}
	bad := []struct {
		ct   int
		host string
	}{
		{3, "evil-openai.azure.com"},                 // no label boundary
		{3, "openai.azure.com.attacker.com"},         // suffix appended
		{3, "openai.azure.com.evil"},                 // trailing label
		{33, "notamazonaws.com"},                     // label boundary
		{41, "aiplatform.googleapis.com.evil.com"},   // appended
		{1, "api.openai.com"},                        // type with no suffix rule
		{3, ""},                                      // empty
	}
	for _, c := range bad {
		if IsOfficialHostSuffix(c.ct, c.host) {
			t.Fatalf("IsOfficialHostSuffix(%d,%q) = true, want false", c.ct, c.host)
		}
	}
}
