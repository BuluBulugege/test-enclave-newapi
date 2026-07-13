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
	RequestID string `json:"request_id"`
	Model     string `json:"model"`
	TokenHash string `json:"token_hash"`
	// RawToken is the gateway API token (sk-...) the caller presented. It is the
	// gateway's OWN credential (not prompt content), sent to the untrusted control
	// plane over loopback because new-api authenticates by matching the raw key.
	// This is auth metadata, not request/response content — the no-content
	// invariant is unaffected.
	RawToken string `json:"raw_token,omitempty"`
	// RelayFormat is the request family: "openai" (/v1/chat/completions) or
	// "claude" (/v1/messages). Routing metadata only.
	RelayFormat string `json:"relay_format"`
	// Path is the upstream request path (e.g. /v1/chat/completions, /v1/messages)
	// so the control plane resolves path-scoped channels correctly. Metadata only.
	Path     string `json:"path,omitempty"`
	IsStream bool   `json:"is_stream"`
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

// usagePeek captures only the token-count block from an upstream response. It
// understands BOTH the OpenAI shape (usage.prompt_tokens/completion_tokens) and
// the Anthropic shape (usage.input_tokens/output_tokens, and message.usage.* on
// the message_start stream frame). No content field is ever read.
type usagePeek struct {
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
		InputTokens      int `json:"input_tokens"`
		OutputTokens     int `json:"output_tokens"`
	} `json:"usage"`
	Message struct {
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	} `json:"message"`
}

// Usage holds the token counts extracted for billing. Metadata only.
type Usage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

// PeekUsage extracts token counts from a (non-stream) response body or a single
// stream frame that carries a usage block, for either OpenAI or Anthropic
// shapes (input_tokens->prompt, output_tokens->completion). Returns ok=false if
// no usage present. Anthropic splits input (message_start) and output
// (message_delta) across frames, so a streaming caller must MERGE per field
// across frames rather than replace (see streamThrough).
func PeekUsage(chunk []byte) (u Usage, ok bool) {
	var p usagePeek
	if err := json.Unmarshal(chunk, &p); err != nil {
		return Usage{}, false
	}
	prompt := p.Usage.PromptTokens
	if prompt == 0 {
		prompt = p.Usage.InputTokens
	}
	if prompt == 0 {
		prompt = p.Message.Usage.InputTokens
	}
	completion := p.Usage.CompletionTokens
	if completion == 0 {
		completion = p.Usage.OutputTokens
	}
	if completion == 0 {
		completion = p.Message.Usage.OutputTokens
	}
	total := p.Usage.TotalTokens
	if prompt == 0 && completion == 0 && total == 0 {
		return Usage{}, false
	}
	if total == 0 {
		total = prompt + completion
	}
	return Usage{PromptTokens: prompt, CompletionTokens: completion, TotalTokens: total}, true
}

// EnsureStreamUsage returns body with stream_options.include_usage=true for an
// OpenAI-style STREAMING request, so the upstream emits a final usage frame the
// enclave can bill from (without it, streaming usage is absent and the request
// would settle free). It parses only TOP-LEVEL keys — "messages"/prompt content
// stay opaque json.RawMessage and are never materialized into a value — then
// re-marshals. If body isn't a JSON object or stream isn't true, it is returned
// unchanged. Call ONLY for the OpenAI relay format (Anthropic always reports
// usage and has no stream_options field).
func EnsureStreamUsage(body []byte) []byte {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return body
	}
	var stream bool
	if raw, ok := top["stream"]; ok {
		_ = json.Unmarshal(raw, &stream)
	}
	if !stream {
		return body
	}
	so := map[string]json.RawMessage{}
	if raw, ok := top["stream_options"]; ok {
		_ = json.Unmarshal(raw, &so)
	}
	so["include_usage"] = json.RawMessage("true")
	soBytes, err := json.Marshal(so)
	if err != nil {
		return body
	}
	top["stream_options"] = soBytes
	out, err := json.Marshal(top)
	if err != nil {
		return body
	}
	return out
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
