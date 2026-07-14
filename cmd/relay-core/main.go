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

// suffixHostUpstreamURL builds the upstream URL for a SuffixHost provider (e.g.
// Databricks) from the control-plane-supplied base URL. The host is RE-VALIDATED
// against the enclave's compiled-in IsOfficialHostSuffix rule (measured into
// MRENCLAVE), so an untrusted control plane can only pick a workspace WITHIN the
// official host family, never repoint traffic elsewhere. Returns an error if the
// base URL is missing, unparseable, or its host is not in the official family.
func suffixHostUpstreamURL(channelType int, baseURL, requestPath string) (string, error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return "", fmt.Errorf("suffix-host channel type %d has no base URL", channelType)
	}
	if !officialurls.IsOfficialHostSuffix(channelType, baseURL) {
		return "", fmt.Errorf("base URL host is not an official upstream for channel type %d", channelType)
	}
	return strings.TrimRight(baseURL, "/") + requestPath, nil
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
	//    trust sel.IsOfficial blindly. A supported provider has either a fixed
	//    measured URL (OpenAI/OpenRouter/Anthropic/Gemini) or a measured dynamic
	//    host policy (AWS region host).
	profile, ok := officialurls.ProfileFor(sel.ChannelType)
	if !officialurls.SupportsOfficial(sel.ChannelType) || !ok {
		writeError(w, http.StatusBadRequest,
			"this provider is not a vetted official upstream in the enclave")
		return
	}

	// A SuffixHost provider (e.g. Databricks) speaks only the OpenAI-compatible
	// format on a per-workspace host. The enclave is a faithful passthrough — it
	// never transforms request/response bodies (that would touch content, which
	// the no-content design forbids) — so it cannot convert an Anthropic Messages
	// (/v1/messages) request/response for such a provider. Serve these providers
	// ONLY on the OpenAI path and steer /v1/messages clients accordingly; the
	// normal (non-enclave) new-api path does the Claude<->OpenAI conversion.
	if profile.SuffixHost && relayFormat == "claude" {
		writeError(w, http.StatusBadRequest,
			"this provider is served only via /v1/chat/completions on /official; use the OpenAI format")
		return
	}

	// 5. Resolve the upstream key from the enclave-owned store. The current v1
	//    control-plane fallback may supply it from new-api's DB; for AWS this is
	//    AK|SK|region[|sessionToken]. It is never forwarded to the client or logged.
	apiKey := sel.UpstreamAPIKey
	if apiKey == "" {
		apiKey, err = h.keys.KeyFor(sel.ChannelID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "upstream key unavailable")
			return
		}
	}

	// 6. Dispatch upstream + stream response through, counting usage in memory.
	start := h.nowMilli()
	var usage relaycontrol.Usage
	var status int
	if sel.ChannelType == awsBedrockChannelType {
		if isStream {
			writeError(w, http.StatusBadRequest, "AWS Bedrock streaming is not supported by the enclave yet")
			return
		}
		upstreamModel := sel.UpstreamModelName
		if upstreamModel == "" { // backward compatibility with an older control plane
			upstreamModel = model
		}
		usage, status, err = h.forwardAWSBedrock(ctx, w, body, apiKey, upstreamModel, isStream, requestID)
	} else {
		// Some providers serve the OpenAI-style request under a different upstream
		// path (e.g. Gemini's /v1beta/openai). Apply the measured rewrite first.
		upstreamPath := r.URL.Path
		if profile.PathRewrite != nil {
			upstreamPath = profile.PathRewrite(upstreamPath)
		}
		// Suffix-host providers (Databricks) take the workspace host from the
		// control plane, re-validated against the measured host-suffix rule;
		// exact-host providers use the compiled-in official URL.
		var upstreamURL string
		var urlErr error
		if profile.SuffixHost {
			upstreamURL, urlErr = suffixHostUpstreamURL(sel.ChannelType, sel.UpstreamBaseURL, upstreamPath)
		} else {
			upstreamURL, urlErr = officialUpstreamURL(sel.ChannelType, upstreamPath)
		}
		if urlErr != nil {
			writeError(w, http.StatusInternalServerError, urlErr.Error())
			return
		}
		usage, status, err = h.forward(ctx, w, upstreamURL, body, apiKey, isStream, profile)
	}
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
