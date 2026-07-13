// Command relay-core is the minimal AI-request relay that runs inside the SGX
// enclave (via Gramine-SGX). It terminates the client's TLS connection, extracts
// only the routing scalars (model, stream) from the request, asks the untrusted
// control plane which upstream to use, and for OFFICIAL channels dials the
// compiled-in official host over strict TLS — ignoring any host-supplied URL
// override, which is the anti-MITM guarantee. Request/response CONTENT is
// streamed straight through and NEVER written to disk, DB, or logs.
//
// PURITY: this binary's package closure must contain ONLY stdlib +
// pkg/officialurls + pkg/relaycontrol. It must never import dto/common/logger/
// model/service/setting (those carry disk-cache/logging/DB code). The CI
// leak-guard (scripts/enclave_no_leak_check.sh) enforces this.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/QuantumNous/new-api/pkg/officialurls"
	"github.com/QuantumNous/new-api/pkg/relaycontrol"
)

// ControlPlane is the narrow interface relay-core uses to reach the untrusted
// new-api host. In the demo it is a local stub; in production it is a gRPC/UDS
// client. Defined here (consumed here) per "accept interfaces" guidance.
type ControlPlane interface {
	SelectChannel(ctx context.Context, req relaycontrol.SelectChannelRequest) (relaycontrol.SelectChannelResponse, error)
	Settle(ctx context.Context, req relaycontrol.SettleRequest) error
}

// UpstreamKeyStore returns the upstream API key for a channel. In the sealed-key
// design (decision 2) this reads from a Gramine-protected file the host cannot
// decrypt; the host never sees the key. The demo stub reads an env/file the
// enclave owns.
type UpstreamKeyStore interface {
	KeyFor(channelID int) (string, error)
}

// relayHandler carries the per-process dependencies.
type relayHandler struct {
	cp       ControlPlane
	keys     UpstreamKeyStore
	client   *http.Client // strict-TLS client for official upstreams
	nowMilli func() int64
}

// officialUpstreamURL returns the request URL for an OFFICIAL channel, built
// from the compiled-in official host (measured into MRENCLAVE), NOT from any
// host-supplied base URL. This is the core of property (2): the enclave decides
// the destination, the untrusted host cannot repoint it.
func officialUpstreamURL(channelType int, requestPath string) (string, error) {
	base := officialurls.For(channelType)
	if base == "" {
		return "", fmt.Errorf("channel type %d has no official base URL", channelType)
	}
	return base + requestPath, nil
}

// serveRelay handles one client request end-to-end. It never persists content.
func (h *relayHandler) serveRelay(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := r.Header.Get("X-Request-Id")

	// 1. Read the raw client body. Held only in memory (encrypted EPC inside SGX),
	//    forwarded verbatim upstream, never written to disk.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read request body failed")
		return
	}

	// 2. Extract ONLY routing scalars. Prompt content is not parsed into a value.
	model, isStream, err := relaycontrol.PeekRequest(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}

	// 3. Ask the control plane which channel to use (no content sent). The relay
	//    format + path are derived from the request path so the control plane can
	//    resolve path-scoped channels (e.g. Claude /v1/messages) correctly.
	relayFormat := "openai"
	if strings.HasSuffix(r.URL.Path, "/messages") {
		relayFormat = "claude"
	}

	// For OpenAI-family streams, ensure the upstream emits a usage frame so the
	// request can be billed (the enclave has no tokenizer). This modifies only
	// top-level JSON keys; prompt content stays opaque and is never materialized.
	if relayFormat == "openai" && isStream {
		body = relaycontrol.EnsureStreamUsage(body)
	}
	sel, err := h.cp.SelectChannel(ctx, relaycontrol.SelectChannelRequest{
		RequestID:   requestID,
		Model:       model,
		TokenHash:   hashToken(r.Header.Get("Authorization")),
		RawToken:    bearerToken(r.Header.Get("Authorization")),
		RelayFormat: relayFormat,
		Path:        r.URL.Path,
		IsStream:    isStream,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "control plane error")
		return
	}
	if sel.Error != "" {
		writeError(w, http.StatusForbidden, sel.Error)
		return
	}

	// 4. ENFORCE property (2): re-derive officiality inside the enclave. We do NOT
	//    trust sel.IsOfficial blindly. For an official channel we build the URL
	//    from the compiled-in table and use the strict-TLS client.
	profile, ok := officialurls.ProfileFor(sel.ChannelType)
	if !officialurls.HasOfficial(sel.ChannelType) || !ok {
		writeError(w, http.StatusBadRequest,
			"this provider is not a vetted official upstream in the enclave")
		return
	}
	// Some providers serve the OpenAI-style request under a different upstream
	// path (e.g. Gemini's OpenAI-compatible surface at /v1beta/openai). Apply the
	// profile's path rewrite, if any, before building the compiled-in-host URL.
	upstreamPath := r.URL.Path
	if profile.PathRewrite != nil {
		upstreamPath = profile.PathRewrite(upstreamPath)
	}
	upstreamURL, err := officialUpstreamURL(sel.ChannelType, upstreamPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// 5. Resolve the upstream key from the enclave-owned store (host never sees it).
	apiKey := sel.UpstreamAPIKey // fallback path (host-visible key), usually empty
	if apiKey == "" {
		apiKey, err = h.keys.KeyFor(sel.ChannelID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "upstream key unavailable")
			return
		}
	}

	// 6. Dispatch upstream + stream response through, counting usage in memory.
	//    The per-provider profile decides how the upstream credential is injected
	//    (Bearer / x-api-key / x-goog-api-key + any required headers).
	start := h.nowMilli()
	usage, status, err := h.forward(ctx, w, upstreamURL, body, apiKey, isStream, profile)
	latency := h.nowMilli() - start
	if err != nil {
		// Do NOT log the upstream error body (leak site). Relay a generic error.
		if !headersSent(w) {
			writeError(w, http.StatusBadGateway, "upstream request failed")
		}
		return
	}

	// 7. Settle: METADATA ONLY (token counts, no content). The client response is
	//    already delivered, so a settle failure is non-fatal — but it MUST be
	//    visible (a dropped settle = a free request), so log it to stderr.
	if serr := h.cp.Settle(ctx, relaycontrol.SettleRequest{
		RequestID:          requestID,
		UserID:             sel.UserID,
		TokenID:            sel.TokenID,
		ChannelID:          sel.ChannelID,
		Model:              model,
		PromptTokens:       usage.PromptTokens,
		CompletionTokens:   usage.CompletionTokens,
		TotalTokens:        usage.TotalTokens,
		LatencyMs:          latency,
		UpstreamStatusCode: status,
		IsStream:           isStream,
	}); serr != nil {
		fmt.Fprintf(os.Stderr, "[settle] failed request_id=%s: %v\n", requestID, serr)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// Minimal error shape; contains no upstream body.
	fmt.Fprintf(w, `{"error":{"message":%q,"type":"relay_core_error"}}`, msg)
}
