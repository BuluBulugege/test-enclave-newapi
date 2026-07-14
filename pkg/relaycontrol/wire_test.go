package relaycontrol

import (
	"strings"
	"testing"
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
