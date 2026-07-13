package relaycontrol

import "testing"

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
