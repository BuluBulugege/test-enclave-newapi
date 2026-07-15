package relaycontrol

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPeekRequest(t *testing.T) {
	// A realistic OpenAI body: prompt content lives in messages, which PeekRequest
	// must NOT surface. It only returns model + stream.
	body := []byte(`{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"secret prompt"}]}`)
	model, stream, err := PeekRequest(body)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if model != "gpt-4o-mini" {
		t.Fatalf("model = %q, want gpt-4o-mini", model)
	}
	if !stream {
		t.Fatalf("stream = false, want true")
	}
}

func TestPeekRequestNoModel(t *testing.T) {
	if _, _, err := PeekRequest([]byte(`{"messages":[]}`)); err == nil {
		t.Fatal("expected error for missing model")
	}
	if _, _, err := PeekRequest([]byte(`not json`)); err == nil {
		t.Fatal("expected error for invalid json")
	}
}

func TestSplitModelRegion(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		wantModel  string
		wantRegion string
		wantOK     bool
	}{
		{
			name:       "profile id with region",
			in:         "us.anthropic.claude-sonnet-4-5-20250929-v1:0@us-east-1",
			wantModel:  "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
			wantRegion: "us-east-1",
			wantOK:     true,
		},
		{
			name:       "gov region",
			in:         "anthropic.claude-opus-4-8@us-gov-west-1",
			wantModel:  "anthropic.claude-opus-4-8",
			wantRegion: "us-gov-west-1",
			wantOK:     true,
		},
		{
			name:      "plain model, no suffix",
			in:        "anthropic.claude-opus-4-8",
			wantModel: "anthropic.claude-opus-4-8",
			wantOK:    false,
		},
		{
			name:      "invalid region fails closed, model unchanged",
			in:        "anthropic.claude-opus-4-8@us-east-1.evil.com",
			wantModel: "anthropic.claude-opus-4-8@us-east-1.evil.com",
			wantOK:    false,
		},
		{
			name:      "empty model before @",
			in:        "@us-east-1",
			wantModel: "@us-east-1",
			wantOK:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model, region, ok := SplitModelRegion(tt.in)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantModel, model)
			assert.Equal(t, tt.wantRegion, region)
		})
	}
}

func TestPeekUsage(t *testing.T) {
	body := []byte(`{"id":"x","usage":{"prompt_tokens":12,"completion_tokens":3,"total_tokens":15}}`)
	u, ok := PeekUsage(body)
	if !ok {
		t.Fatal("expected usage present")
	}
	if u.PromptTokens != 12 || u.CompletionTokens != 3 || u.TotalTokens != 15 {
		t.Fatalf("usage = %+v, want 12/3/15", u)
	}
}

func TestPeekUsageAbsent(t *testing.T) {
	if _, ok := PeekUsage([]byte(`{"choices":[{"delta":{"content":"hi"}}]}`)); ok {
		t.Fatal("expected no usage for a content-only frame")
	}
	if _, ok := PeekUsage([]byte(`bad json`)); ok {
		t.Fatal("expected no usage for invalid json")
	}
}

// TestPeekUsageAnthropic covers the Anthropic shapes so Claude /official traffic
// is not billed as free (the counts feed settleOfficialBilling).
func TestPeekUsageAnthropic(t *testing.T) {
	cases := []struct {
		name          string
		body          string
		prompt, compl int
		total         int
	}{
		{"non-stream", `{"type":"message","usage":{"input_tokens":25,"output_tokens":7}}`, 25, 7, 32},
		{"message_start", `{"type":"message_start","message":{"usage":{"input_tokens":25,"output_tokens":1}}}`, 25, 1, 26},
		{"message_delta", `{"type":"message_delta","usage":{"output_tokens":40}}`, 0, 40, 40},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, ok := PeekUsage([]byte(c.body))
			if !ok {
				t.Fatalf("expected usage present for %s", c.name)
			}
			if u.PromptTokens != c.prompt || u.CompletionTokens != c.compl || u.TotalTokens != c.total {
				t.Fatalf("usage = %+v, want %d/%d/%d", u, c.prompt, c.compl, c.total)
			}
		})
	}
}

// TestEnsureStreamUsage verifies the enclave injects stream_options.include_usage
// for OpenAI streams (so usage is emitted + billable) without touching content,
// and leaves non-stream / non-JSON bodies untouched.
func TestResolveModelMapping(t *testing.T) {
	tests := []struct {
		name    string
		model   string
		mapping string
		want    string
		wantErr bool
	}{
		{name: "empty mapping", model: "nova-micro", mapping: "", want: "nova-micro"},
		{name: "direct mapping", model: "nova-micro", mapping: `{"nova-micro":"amazon.nova-micro-v1:0"}`, want: "amazon.nova-micro-v1:0"},
		{name: "chain mapping", model: "public", mapping: `{"public":"internal","internal":"amazon.nova-micro-v1:0"}`, want: "amazon.nova-micro-v1:0"},
		{name: "self mapping", model: "same", mapping: `{"same":"same"}`, want: "same"},
		{name: "cycle", model: "a", mapping: `{"a":"b","b":"a"}`, wantErr: true},
		{name: "invalid json", model: "a", mapping: `{`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveModelMapping(tt.model, tt.mapping)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnsureStreamUsage(t *testing.T) {
	// streaming request gains include_usage, model + messages preserved
	out := EnsureStreamUsage([]byte(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	m, s, err := PeekRequest(out)
	if err != nil || m != "gpt-4o" || !s {
		t.Fatalf("PeekRequest(out) = %q/%v/%v", m, s, err)
	}
	if !strings.Contains(string(out), `"include_usage":true`) {
		t.Fatalf("expected include_usage injected, got %s", out)
	}
	if !strings.Contains(string(out), `"content":"hi"`) {
		t.Fatalf("message content must be preserved, got %s", out)
	}
	// non-stream request is returned unchanged (no stream_options added)
	in := []byte(`{"model":"gpt-4o","messages":[]}`)
	if got := EnsureStreamUsage(in); strings.Contains(string(got), "stream_options") {
		t.Fatalf("non-stream body must not gain stream_options, got %s", got)
	}
	// non-JSON body is returned unchanged
	if got := EnsureStreamUsage([]byte(`not json`)); string(got) != `not json` {
		t.Fatalf("invalid body must pass through unchanged, got %s", got)
	}
}

// SettleRequest must stay metadata-only. This test is a compile-time-ish guard:
// if someone adds a content-bearing field, the reviewer sees it fail intent.
// We assert the JSON tag set to make an accidental content field obvious in diff.
func TestSettleRequestFieldsMetadataOnly(t *testing.T) {
	// A allowlist of permitted json field names. Adding a field forces updating
	// this list, which is the human checkpoint against content leakage.
	allowed := map[string]bool{
		"request_id": true, "user_id": true, "token_id": true, "channel_id": true,
		"model": true, "prompt_tokens": true, "completion_tokens": true,
		"total_tokens": true, "latency_ms": true, "upstream_status_code": true,
		"is_stream": true,
		// Non-token billing metadata (integers / short enum strings — never content).
		"request_kind": true, "image_count": true, "image_size": true, "image_quality": true,
	}
	// Reflect over the struct tags.
	got := settleJSONFields()
	for _, f := range got {
		if !allowed[f] {
			t.Fatalf("SettleRequest has unexpected field %q — is it content-derived? "+
				"metadata-only invariant broken", f)
		}
	}
}

// TestPeekUsageResponsesStreaming pins that the OpenAI Responses API streaming
// usage (nested under response.usage on the response.completed event) is billed.
// Without this the stream would settle at 0 tokens (free).
func TestPeekUsageResponsesStreaming(t *testing.T) {
	frame := []byte(`{"type":"response.completed","response":{"id":"resp_1","usage":{"input_tokens":10,"output_tokens":20,"total_tokens":30}}}`)
	u, ok := PeekUsage(frame)
	require.True(t, ok, "response.completed usage must be recognized")
	assert.Equal(t, 10, u.PromptTokens)
	assert.Equal(t, 20, u.CompletionTokens)
	assert.Equal(t, 30, u.TotalTokens)
}

// TestPeekUsageResponsesNonStream pins the non-streaming Responses shape
// (top-level usage.input_tokens/output_tokens), which reuses the Anthropic
// input/output fallback.
func TestPeekUsageResponsesNonStream(t *testing.T) {
	body := []byte(`{"id":"resp_1","usage":{"input_tokens":7,"output_tokens":13,"total_tokens":20}}`)
	u, ok := PeekUsage(body)
	require.True(t, ok)
	assert.Equal(t, 7, u.PromptTokens)
	assert.Equal(t, 13, u.CompletionTokens)
	assert.Equal(t, 20, u.TotalTokens)
}

// TestPeekUsageGeminiNative pins that Gemini native usageMetadata is billed
// (previously native-Gemini calls settled free — a real under-billing hole),
// INCLUDING the separate, additive thoughtsTokenCount (thinking) and
// toolUsePromptTokenCount blocks that vanilla new-api adds.
func TestPeekUsageGeminiNative(t *testing.T) {
	// Plain response (no thinking / tools).
	body := []byte(`{"candidates":[{"content":{"parts":[{"text":"hi"}]}}],"usageMetadata":{"promptTokenCount":11,"candidatesTokenCount":5,"totalTokenCount":16}}`)
	u, ok := PeekUsage(body)
	require.True(t, ok, "usageMetadata must be recognized")
	assert.Equal(t, 11, u.PromptTokens)
	assert.Equal(t, 5, u.CompletionTokens)
	assert.Equal(t, 16, u.TotalTokens)

	// Thinking model with function-calling: thoughts add to completion, tool-use
	// prompt tokens add to prompt (both separate from the base counts).
	thinking := []byte(`{"usageMetadata":{"promptTokenCount":1000,"toolUsePromptTokenCount":300,"candidatesTokenCount":200,"thoughtsTokenCount":3000,"totalTokenCount":4500}}`)
	tu, tok := PeekUsage(thinking)
	require.True(t, tok)
	assert.Equal(t, 1300, tu.PromptTokens, "prompt = promptTokenCount + toolUsePromptTokenCount")
	assert.Equal(t, 3200, tu.CompletionTokens, "completion = candidatesTokenCount + thoughtsTokenCount")
	assert.Equal(t, 4500, tu.TotalTokens, "total from totalTokenCount")
}

// TestPeekUsageRerankTotalOnly documents that a rerank response carrying only
// usage.total_tokens is surfaced (ok=true, total set); the serveRelay caller is
// responsible for the prompt=total normalization, so here we only assert total.
func TestPeekUsageRerankTotalOnly(t *testing.T) {
	body := []byte(`{"results":[],"usage":{"total_tokens":42}}`)
	u, ok := PeekUsage(body)
	require.True(t, ok)
	assert.Equal(t, 42, u.TotalTokens)
	assert.Equal(t, 0, u.PromptTokens)
}

// TestPeekImageParamsBoundsN is the billing-safety boundary for image count:
// a missing, malformed, negative, or wrapped-huge n can NEVER become a billing
// multiplier above MaxImageN, and a valid n is preserved. size/quality are read
// verbatim; the prompt is never surfaced.
func TestPeekImageParamsBoundsN(t *testing.T) {
	cases := []struct {
		name string
		body string
		n    int
	}{
		{"valid n", `{"model":"dall-e-3","prompt":"secret","n":4,"size":"1024x1024","quality":"hd"}`, 4},
		{"missing n defaults 1", `{"model":"dall-e-3","prompt":"x","size":"512x512"}`, 1},
		{"zero -> 1", `{"model":"dall-e-3","prompt":"x","n":0}`, 1},
		{"negative -> 1", `{"model":"dall-e-3","prompt":"x","n":-5}`, 1},
		{"above max clamped", `{"model":"dall-e-3","prompt":"x","n":9999}`, MaxImageN},
		{"exactly max", `{"model":"dall-e-3","prompt":"x","n":128}`, 128},
		{"wrapped huge uint -> safe default 1", `{"model":"dall-e-3","prompt":"x","n":18446744073686646784}`, 1},
		{"malformed json -> 1", `not json`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			size, quality, n, _ := PeekImageParams([]byte(c.body))
			assert.Equal(t, c.n, n, "n bound")
			// For the well-formed dall-e-3 hd 1024x1024 case, confirm size/quality passthrough.
			if c.name == "valid n" {
				assert.Equal(t, "1024x1024", size)
				assert.Equal(t, "hd", quality)
			}
		})
	}
}

// TestPeekImageParamsStream confirms the stream flag is read (the enclave refuses
// streaming image responses).
func TestPeekImageParamsStream(t *testing.T) {
	_, _, _, stream := PeekImageParams([]byte(`{"model":"gpt-image-1","prompt":"x","stream":true}`))
	assert.True(t, stream)
	_, _, _, stream2 := PeekImageParams([]byte(`{"model":"gpt-image-1","prompt":"x"}`))
	assert.False(t, stream2)
}

// TestPeekImageCount counts returned images and clamps to MaxImageN; a body with
// no data array returns 0 (caller falls back to the bounded request n).
func TestPeekImageCount(t *testing.T) {
	assert.Equal(t, 2, PeekImageCount([]byte(`{"created":1,"data":[{"url":"a"},{"b64_json":"BBBB"}]}`)))
	assert.Equal(t, 0, PeekImageCount([]byte(`{"created":1}`)))
	assert.Equal(t, 0, PeekImageCount([]byte(`not json`)))
	// A pathological upstream returning a huge data array is clamped.
	big := "{\"data\":[" + strings.Repeat(`{},`, 200) + "{}]}"
	assert.Equal(t, MaxImageN, PeekImageCount([]byte(big)))
}
