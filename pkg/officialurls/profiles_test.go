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

// TestDeferredProviders documents that Gemini/AIStudio (24) and the other
// per-provider-URL / non-static-auth providers (Azure=3, AWS Bedrock=33,
// Vertex=41) are DEFERRED: they are not yet servable as official through the
// enclave and must have no auth profile until the profile redesign lands. A
// profile added here is a deliberate MRENCLAVE policy change and must come with
// its URL-building + signing support.
func TestDeferredProviders(t *testing.T) {
	for _, ct := range []int{24, 3, 33, 41} {
		if SupportsOfficial(ct) {
			t.Fatalf("type %d is deferred and must not be official yet", ct)
		}
	}
	// Gemini's base URL is still known (in the URL table) even though it has no
	// profile yet — that's expected; SupportsOfficial gates on BOTH.
	if For(24) == "" {
		t.Fatal("Gemini base URL should still be present in the URL table")
	}
}
