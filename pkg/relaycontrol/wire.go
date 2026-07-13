// Package relaycontrol defines the pure wire contract between the SGX relay-core
// enclave and the untrusted new-api control plane, plus the minimal request
// introspection the enclave needs.
//
// PURITY CONTRACT: this package imports ONLY the standard library. It must never
// import dto / common / logger / model / service / setting, because those pull
// disk-cache, logging-to-disk, and DB code into the enclave's measured closure
// and would defeat the "no content at rest" guarantee. A CI leak-guard enforces
// this. Keep every type here metadata-only.
//
// Design note (v1 demo scope): the enclave does OpenAI-in / OpenAI-out relaying
// only, which is essentially a byte pass-through. So instead of reusing the
// heavy relay/channel adaptor (whose dto/types closure drags in common+logger),
// the enclave extracts just the routing-relevant scalar fields from the raw
// request bytes with a tiny local struct. The prompt CONTENT is never parsed
// into a business struct, never logged, never written — it is streamed through.
package relaycontrol

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
)

// SelectChannelRequest is what the enclave sends the control plane to route a
// call. It carries NO prompt content — only the model, a hash of the caller's
// gateway token, and coarse routing metadata.
type SelectChannelRequest struct {
	RequestID   string `json:"request_id"`
	Model       string `json:"model"`
	TokenHash   string `json:"token_hash"`
	// RawToken is the gateway API token (sk-...) the caller presented. It is the
	// gateway's OWN credential (not prompt content), sent to the untrusted control
	// plane over loopback because new-api authenticates by matching the raw key.
	// This is auth metadata, not request/response content — the no-content
	// invariant is unaffected.
	RawToken    string `json:"raw_token,omitempty"`
	RelayFormat string `json:"relay_format"` // v1: always "openai"
	IsStream    bool   `json:"is_stream"`
}

// SelectChannelResponse is the routing decision returned by the control plane.
// UpstreamAPIKey is intentionally omitted in the key-sealed design (decision 2:
// the host never sees the upstream key); the enclave loads the upstream key from
// its own sealed store keyed by ChannelID. If a deployment opts into v1
// host-visible keys, it may populate UpstreamAPIKey instead.
type SelectChannelResponse struct {
	ChannelID         int    `json:"channel_id"`
	ChannelType       int    `json:"channel_type"`
	IsOfficial        bool   `json:"is_official"` // host hint; enclave re-derives authoritatively
	UpstreamModelName string `json:"upstream_model_name"`
	UserID            int    `json:"user_id"`
	TokenID           int    `json:"token_id"`
	// UpstreamAPIKey is empty in the sealed-key design (decision 2). Present only
	// for the optional host-visible-key fallback.
	UpstreamAPIKey string `json:"upstream_api_key,omitempty"`
	// Error, when non-empty, means the host rejected the call (bad token, no
	// quota, unknown model); the enclave relays this to the client and stops.
	Error string `json:"error,omitempty"`
}

// SettleRequest is the completion callback. METADATA ONLY — there are no
// content fields on this struct by construction, and that absence is the
// auditable invariant. Do NOT add any field derived from prompt/response text.
type SettleRequest struct {
	RequestID          string `json:"request_id"`
	UserID             int    `json:"user_id"`
	TokenID            int    `json:"token_id"`
	ChannelID          int    `json:"channel_id"`
	Model              string `json:"model"`
	PromptTokens       int    `json:"prompt_tokens"`
	CompletionTokens   int    `json:"completion_tokens"`
	TotalTokens        int    `json:"total_tokens"`
	LatencyMs          int64  `json:"latency_ms"`
	UpstreamStatusCode int    `json:"upstream_status_code"`
	IsStream           bool   `json:"is_stream"`
}

// requestPeek is the ONLY struct the enclave unmarshals the client body into. It
// deliberately captures just the routing scalars and ignores every content field
// (messages, prompt, input, ...). encoding/json drops unknown fields, so prompt
// content is never materialized into a Go value here.
type requestPeek struct {
	Model  string `json:"model"`
	Stream bool   `json:"stream"`
}

// PeekRequest extracts the model name and stream flag from a raw OpenAI-style
// request body WITHOUT parsing or retaining any prompt content. The full body
// bytes are still forwarded upstream verbatim by the caller; this only reads
// routing scalars.
func PeekRequest(body []byte) (model string, stream bool, err error) {
	var p requestPeek
	if err := json.Unmarshal(body, &p); err != nil {
		return "", false, err
	}
	if p.Model == "" {
		return "", false, errors.New("request has no model field")
	}
	return p.Model, p.Stream, nil
}

// usagePeek captures only the token-count block from an upstream response.
type usagePeek struct {
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// Usage holds the token counts extracted for billing. Metadata only.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

// PeekUsage extracts token counts from a (non-stream) response body or a single
// stream frame that carries a usage block. Returns ok=false if no usage present
// (the caller keeps the last non-empty usage seen across stream frames).
func PeekUsage(chunk []byte) (u Usage, ok bool) {
	var p usagePeek
	if err := json.Unmarshal(chunk, &p); err != nil {
		return Usage{}, false
	}
	if p.Usage.TotalTokens == 0 && p.Usage.PromptTokens == 0 && p.Usage.CompletionTokens == 0 {
		return Usage{}, false
	}
	return Usage{
		PromptTokens:     p.Usage.PromptTokens,
		CompletionTokens: p.Usage.CompletionTokens,
		TotalTokens:      p.Usage.TotalTokens,
	}, true
}

// settleJSONFields returns the json field names declared on SettleRequest. Used
// by the test that enforces the metadata-only invariant: any newly added field
// must be an explicitly-allowed metadata name, never content-derived.
func settleJSONFields() []string {
	t := reflect.TypeOf(SettleRequest{})
	fields := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			name = t.Field(i).Name
		}
		fields = append(fields, name)
	}
	return fields
}
