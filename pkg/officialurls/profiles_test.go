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
		{"Gemini/AIStudio", 24, "https://generativelanguage.googleapis.com", "x-goog-api-key", ""},
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
