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
		// Gemini (24) serves multiple formats via Routes, not a single top-level
		// auth — see TestGeminiNativeAndCompatRoutes. Its base URL is still pinned:
	}
	// Gemini base URL (its auth is per-format, checked separately).
	if got := For(24); got != "https://generativelanguage.googleapis.com" {
		t.Fatalf("Gemini base URL = %q", got)
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
// (client's /v1/... -> upstream /v1beta/openai/...) via its "openai" Route.
func TestGeminiOpenAICompatPathRewrite(t *testing.T) {
	p, ok := ProfileFor(24)
	if !ok {
		t.Fatal("Gemini must have a profile")
	}
	cases := map[string]string{
		"/v1/chat/completions": "/v1beta/openai/chat/completions",
		"/v1/embeddings":       "/v1beta/openai/embeddings",
	}
	for in, want := range cases {
		_, _, _, got, ok := p.ResolveRoute("openai", in)
		if !ok || got != want {
			t.Fatalf("openai route rewrite(%q) = %q (ok=%v), want %q", in, got, ok, want)
		}
	}
}

func TestAWSBedrockOfficialSupport(t *testing.T) {
	if !SupportsOfficial(33) {
		t.Fatal("AWS Bedrock must be admitted by its measured dynamic-host policy")
	}
	if HasOfficial(33) {
		t.Fatal("AWS Bedrock must not have a single fixed base URL; its host is region-derived")
	}
	if !HasOfficialHostRule(33) {
		t.Fatal("AWS Bedrock must have a dynamic official-host rule")
	}
	if _, ok := ProfileFor(33); !ok {
		t.Fatal("AWS Bedrock must have an enclave dispatch profile marker")
	}
}

func TestDatabricksOfficialSupport(t *testing.T) {
	if !SupportsOfficial(59) {
		t.Fatal("Databricks must be admitted by its measured suffix-host policy")
	}
	if HasOfficial(59) {
		t.Fatal("Databricks must not have a single fixed base URL; the host is per-workspace")
	}
	if !HasOfficialHostRule(59) {
		t.Fatal("Databricks must have a dynamic official-host rule")
	}
	p, ok := ProfileFor(59)
	if !ok {
		t.Fatal("Databricks must have an enclave profile")
	}
	if !p.SuffixHost {
		t.Fatal("Databricks profile must be marked SuffixHost (host from control plane, re-validated)")
	}
	// Databricks serves BOTH OpenAI chat and native Anthropic Messages, both Bearer,
	// at different upstream paths — no body transformation.
	ah, ap, _, up, ok := p.ResolveRoute("openai", "/v1/chat/completions")
	if !ok || ah != "Authorization" || ap != "Bearer " || up != "/v1/chat/completions" {
		t.Fatalf("Databricks openai route wrong: ok=%v %q+%q path=%q", ok, ap, ah, up)
	}
	ah, ap, _, up, ok = p.ResolveRoute("claude", "/v1/messages")
	if !ok || ah != "Authorization" || ap != "Bearer " || up != "/anthropic/v1/messages" {
		t.Fatalf("Databricks claude route must map to /anthropic/v1/messages: ok=%v path=%q", ok, up)
	}
	// A format Databricks does not serve is refused.
	if _, _, _, _, ok := p.ResolveRoute("gemini", "/v1beta/models/x:generateContent"); ok {
		t.Fatal("Databricks must not serve the gemini format")
	}
}

// TestGeminiNativeAndCompatRoutes pins Gemini's two formats: the OpenAI-compat
// surface (Bearer, /v1beta/openai/...) and the native generateContent surface
// (x-goog-api-key, verbatim path).
func TestGeminiNativeAndCompatRoutes(t *testing.T) {
	p, ok := ProfileFor(24)
	if !ok {
		t.Fatal("Gemini must have a profile")
	}
	ah, ap, _, up, ok := p.ResolveRoute("openai", "/v1/chat/completions")
	if !ok || ah != "Authorization" || ap != "Bearer " || up != "/v1beta/openai/chat/completions" {
		t.Fatalf("Gemini openai-compat route wrong: ok=%v %q+%q path=%q", ok, ap, ah, up)
	}
	ah, _, _, up, ok = p.ResolveRoute("gemini", "/v1beta/models/gemini-2.0-flash:generateContent")
	if !ok || ah != "x-goog-api-key" || up != "/v1beta/models/gemini-2.0-flash:generateContent" {
		t.Fatalf("Gemini native route must use x-goog-api-key + verbatim path: ok=%v ah=%q path=%q", ok, ah, up)
	}
	if _, _, _, _, ok := p.ResolveRoute("claude", "/v1/messages"); ok {
		t.Fatal("Gemini must not serve the claude format")
	}
}

// TestDeferredProviders documents that Azure(3) and Vertex(41) remain
// unsupported until their per-resource/project metadata + dispatch are wired.
func TestDeferredProviders(t *testing.T) {
	for _, ct := range []int{3, 41} {
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
		{59, "adb-3339848738319975.15.azuredatabricks.net"},
		{59, "https://adb-123.15.azuredatabricks.net/serving-endpoints"},
		{59, "myworkspace.cloud.databricks.com"},
		{59, "ws.gcp.databricks.com"},
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
		{3, "evil-openai.azure.com"},                   // no label boundary
		{3, "openai.azure.com.attacker.com"},           // suffix appended
		{3, "openai.azure.com.evil"},                   // trailing label
		{33, "notamazonaws.com"},                       // label boundary
		{41, "aiplatform.googleapis.com.evil.com"},     // appended
		{1, "api.openai.com"},                          // type with no suffix rule
		{3, ""},                                        // empty
		{59, "azuredatabricks.net.attacker.com"},       // suffix appended
		{59, "evilazuredatabricks.net"},                // no label boundary
		{59, "adb-1.databricks.net.evil.com"},          // appended
	}
	for _, c := range bad {
		if IsOfficialHostSuffix(c.ct, c.host) {
			t.Fatalf("IsOfficialHostSuffix(%d,%q) = true, want false", c.ct, c.host)
		}
	}
}
