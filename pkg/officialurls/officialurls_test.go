package officialurls

import "testing"

// TestGoldenIndices pins well-known channel type ids to their official base URL.
// The table is a positional slice indexed by channel type; an accidental
// insertion or reordering would silently repoint every provider below it. This
// test fails loudly instead. Keep these in sync with constant.ChannelType*.
func TestGoldenIndices(t *testing.T) {
	cases := []struct {
		name        string
		channelType int
		want        string
	}{
		{"OpenAI", 1, "https://api.openai.com"},
		{"Anthropic", 14, "https://api.anthropic.com"},
		{"Gemini", 24, "https://generativelanguage.googleapis.com"},
		{"DeepSeek", 43, "https://api.deepseek.com"},
		{"Xai", 48, "https://api.x.ai"},
		{"Codex", 57, "https://chatgpt.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := For(c.channelType); got != c.want {
				t.Fatalf("BaseURLs[%d] (%s) = %q, want %q", c.channelType, c.name, got, c.want)
			}
		})
	}
}

// TestEmptyDefaultTypes pins the types that have NO official default, so they
// can never be classified as official. If any of these ever gains a URL by an
// index shift, IsOfficialURL could wrongly treat a custom endpoint as official.
func TestEmptyDefaultTypes(t *testing.T) {
	empties := []struct {
		name        string
		channelType int
	}{
		{"Azure", 3},
		{"Custom", 8},
		{"PaLM", 11},
		{"Xunfei", 18},
		{"Aws", 33},
		{"VertexAi", 41},
		{"Xinference", 47},
		{"AdvancedCustom", 58},
	}
	for _, e := range empties {
		t.Run(e.name, func(t *testing.T) {
			if HasOfficial(e.channelType) {
				t.Fatalf("channelType %d (%s) unexpectedly has official URL %q; index shift?",
					e.channelType, e.name, For(e.channelType))
			}
		})
	}
}

func TestIsOfficialURL(t *testing.T) {
	cases := []struct {
		name        string
		channelType int
		resolved    string
		want        bool
	}{
		{"openai blank-resolved-to-default", 1, "https://api.openai.com", true},
		{"openai custom override", 1, "https://my-proxy.example.com", false},
		{"openai empty stays false", 1, "", false},
		{"custom type never official", 8, "https://api.openai.com", false},
		{"out of range", 9999, "https://api.openai.com", false},
		{"negative", -1, "https://api.openai.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsOfficialURL(c.channelType, c.resolved); got != c.want {
				t.Fatalf("IsOfficialURL(%d, %q) = %v, want %v", c.channelType, c.resolved, got, c.want)
			}
		})
	}
}
