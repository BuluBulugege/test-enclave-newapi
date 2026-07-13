package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"io"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/pkg/relaycontrol"
)

// newStrictUpstreamClient builds the HTTP client relay-core uses for OFFICIAL
// upstreams. TLS verification is ALWAYS on (InsecureSkipVerify:false, hard-coded
// — no env knob can weaken it inside the enclave), no proxy is honored, and the
// system CA pool validates the chain. Combined with dialing the compiled-in
// official host (see officialUpstreamURL), this gives the anti-MITM property.
func newStrictUpstreamClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// Proxy deliberately nil: ignore HTTP(S)_PROXY env entirely.
			Proxy: nil,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: false, // never weakened in the enclave
			},
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        32,
			DisableCompression:  false,
		},
	}
}

// forward sends the (verbatim) client body to the official upstream and streams
// the response back to the client. Content is copied through memory buffers
// only — never spilled to disk. Token usage is peeked from the response in
// memory for billing. Returns the usage, upstream status code, and any error.
func (h *relayHandler) forward(
	ctx context.Context,
	w http.ResponseWriter,
	upstreamURL string,
	body []byte,
	apiKey string,
	isStream bool,
) (relaycontrol.Usage, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(body))
	if err != nil {
		return relaycontrol.Usage{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if isStream {
		req.Header.Set("Accept", "text/event-stream")
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return relaycontrol.Usage{}, 0, err
	}
	defer resp.Body.Close()

	// Propagate upstream status + content-type to the client.
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)

	if isStream {
		return h.streamThrough(w, resp)
	}
	return h.bufferThrough(w, resp)
}

// bufferThrough handles a non-stream response: read fully into memory, forward
// to client, peek usage. The body is freed when this returns; nothing persists.
func (h *relayHandler) bufferThrough(w http.ResponseWriter, resp *http.Response) (relaycontrol.Usage, int, error) {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return relaycontrol.Usage{}, resp.StatusCode, err
	}
	if _, err := w.Write(data); err != nil {
		return relaycontrol.Usage{}, resp.StatusCode, err
	}
	usage, _ := relaycontrol.PeekUsage(data)
	return usage, resp.StatusCode, nil
}

// streamThrough forwards SSE frames one-by-one to the client and keeps the last
// usage block seen (OpenAI emits usage in the final frame when
// stream_options.include_usage is set). No frame is written to disk; each line
// is forwarded and discarded. Flushes per frame for real-time delivery.
func (h *relayHandler) streamThrough(w http.ResponseWriter, resp *http.Response) (relaycontrol.Usage, int, error) {
	flusher, _ := w.(http.Flusher)
	reader := bufio.NewReaderSize(resp.Body, 64*1024)
	var lastUsage relaycontrol.Usage

	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if _, werr := w.Write(line); werr != nil {
				return lastUsage, resp.StatusCode, werr
			}
			if flusher != nil {
				flusher.Flush()
			}
			// SSE data frames are "data: {json}". Peek usage from the JSON payload.
			if trimmed := bytes.TrimPrefix(bytes.TrimSpace(line), []byte("data:")); len(trimmed) > 0 {
				if u, ok := relaycontrol.PeekUsage(bytes.TrimSpace(trimmed)); ok {
					lastUsage = u
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return lastUsage, resp.StatusCode, err
		}
	}
	return lastUsage, resp.StatusCode, nil
}

// hashToken returns a hex SHA-256 of the bearer token so the enclave can send a
// stable identifier to the host without transmitting the raw secret where a hash
// match suffices. Strips the "Bearer " prefix.
func hashToken(authHeader string) string {
	tok := bearerToken(authHeader)
	if tok == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// bearerToken extracts the raw gateway token from an Authorization header,
// stripping the "Bearer " prefix. new-api authenticates by matching the raw key,
// so the real control-plane client sends this (see control_client.go).
func bearerToken(authHeader string) string {
	return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
}

// headersSent reports whether the response headers were already written (so we
// don't try to write an error status after streaming began). net/http does not
// expose this directly; we track it via a wrapper in the server setup, but for
// the demo the ResponseWriter is checked structurally. Kept minimal.
func headersSent(w http.ResponseWriter) bool {
	if sw, ok := w.(*statusTrackingWriter); ok {
		return sw.wroteHeader
	}
	return false
}
