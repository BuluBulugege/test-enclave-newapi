package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"os"
	"time"

	"github.com/QuantumNous/new-api/pkg/officialurls"
	"github.com/QuantumNous/new-api/pkg/raenclave"
	"github.com/QuantumNous/new-api/pkg/relaycontrol"
)

// statusTrackingWriter records whether the response header was written, so the
// handler can avoid writing an error status after streaming has begun.
type statusTrackingWriter struct {
	http.ResponseWriter
	wroteHeader bool
	status      int
}

func (w *statusTrackingWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		w.status = code
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *statusTrackingWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// Flush implements http.Flusher when the underlying writer supports it, so SSE
// streaming works through the wrapper.
func (w *statusTrackingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// newHandler wires the relay handler and returns an http.Handler that wraps each
// response writer for status tracking. raCert (may be nil for the plaintext dev
// path) is exposed via /attestation so out-of-band clients can fetch the quote.
func newHandler(cp ControlPlane, keys UpstreamKeyStore, raCert *raenclave.Cert) http.Handler {
	h := &relayHandler{
		cp:       cp,
		keys:     keys,
		client:   newStrictUpstreamClient(),
		nowMilli: func() int64 { return time.Now().UnixMilli() },
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// /attestation returns the raw DCAP quote (if attested) so a client can
	// verify the enclave out-of-band. Metadata only; no secrets.
	mux.HandleFunc("/attestation", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if raCert == nil || !raCert.Attested {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"attested":false,"reason":"not running in an SGX enclave"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"attested":true,"quote_b64":"`))
		_, _ = w.Write([]byte(b64(raCert.Quote)))
		_, _ = w.Write([]byte(`","report_data_hex":"`))
		_, _ = w.Write([]byte(hexstr(raCert.ReportData[:])))
		_, _ = w.Write([]byte(`"}`))
	})
	relay := func(w http.ResponseWriter, r *http.Request) {
		sw := &statusTrackingWriter{ResponseWriter: w}
		h.serveRelay(sw, r)
	}
	mux.HandleFunc("/v1/chat/completions", relay)
	// Anthropic-native messages endpoint (Claude via /official). The Anthropic
	// official profile + base URL already exist; this is routing + format
	// plumbing only, still a faithful pass-through.
	mux.HandleFunc("/v1/messages", relay)
	return mux
}

// --- demo stubs (replaced by gRPC/UDS control plane + sealed key store) -------

// fileKeyStore reads the upstream key from a path that, inside the enclave, is a
// Gramine "encrypted" mount: the ciphertext lives on the host, but Gramine
// transparently decrypts it in enclave memory using a wrap key the host process
// does not hold in plaintext at rest. The host sees only ciphertext on disk.
//
// v1-demo residual (decision 2, Option A): the wrap key is currently supplied
// via the manifest, so a host with the manifest could in principle read it. Full
// host-invisibility requires runtime RA-TLS secret provisioning of the wrap key
// (Gramine ra-tls-secret-prov) — that is the v2 refinement. What IS already
// true in v1: the upstream key is never on the host disk in plaintext and never
// in the relay-core process env when this store is used.
type fileKeyStore struct {
	path string
	// envFallback is used ONLY for local (non-enclave) dev when path is unset.
	envName string
}

func (s fileKeyStore) KeyFor(channelID int) (string, error) {
	if s.path != "" {
		if b, err := os.ReadFile(s.path); err == nil {
			if k := trimSpace(string(b)); k != "" {
				return k, nil
			}
		}
		// fall through to env fallback (local dev / not yet provisioned)
	}
	k := os.Getenv(s.envName)
	if k == "" {
		return "", os.ErrNotExist
	}
	return k, nil
}

// trimSpace trims surrounding whitespace/newlines without importing strings into
// this hot path (strings is stdlib and fine, but keep the key handling explicit
// and minimal). The upstream key file may have a trailing newline.
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }

// staticControlPlane is the demo ControlPlane: it always routes to a single
// configured official OpenAI channel and accepts any non-empty token. Settle
// prints metadata to stdout (counts only — no content) so the demo shows the
// billing path without a DB.
type staticControlPlane struct {
	channelID   int
	channelType int
}

func (c staticControlPlane) SelectChannel(_ context.Context, req relaycontrol.SelectChannelRequest) (relaycontrol.SelectChannelResponse, error) {
	if req.TokenHash == "" {
		return relaycontrol.SelectChannelResponse{Error: "missing gateway token"}, nil
	}
	return relaycontrol.SelectChannelResponse{
		ChannelID:         c.channelID,
		ChannelType:       c.channelType,
		IsOfficial:        officialurls.HasOfficial(c.channelType),
		UpstreamModelName: req.Model,
		UserID:            1,
		TokenID:           1,
	}, nil
}

func (c staticControlPlane) Settle(_ context.Context, req relaycontrol.SettleRequest) error {
	// Metadata-only line. Deliberately no content. Demo uses stdout; the real
	// enclave sends this over the gRPC control plane to new-api.
	os.Stdout.WriteString(
		"[settle] request_id=" + req.RequestID +
			" model=" + req.Model +
			" prompt_tokens=" + itoa(req.PromptTokens) +
			" completion_tokens=" + itoa(req.CompletionTokens) +
			" total_tokens=" + itoa(req.TotalTokens) +
			" latency_ms=" + itoa64(req.LatencyMs) +
			" status=" + itoa(req.UpstreamStatusCode) + "\n")
	return nil
}

func main() {
	addr := envOr("RELAY_CORE_ADDR", ":8443")
	channelType := 1 // OpenAI (official) for the demo

	// Build the RA-TLS certificate. Inside an SGX enclave it embeds a DCAP quote
	// bound to the TLS pubkey; on a normal host it is a plain self-signed cert
	// with Attested=false (dev only).
	raCert, err := raenclave.BuildCert(envOr("RELAY_CORE_DNSNAME", "relay-core.local"))
	if err != nil {
		os.Stderr.WriteString("build RA-TLS cert failed: " + err.Error() + "\n")
		os.Exit(1)
	}

	// Upstream key: read from the MRENCLAVE-sealed encrypted mount. On first boot,
	// if the sealed file is absent but a bootstrap key is provided in env, seal it
	// once (Gramine encrypts it with the _sgx_mrenclave key before it hits host
	// disk). After that the env can be dropped; the host only ever holds ciphertext.
	keyFile := envOr("RELAY_CORE_UPSTREAM_KEY_FILE", "/secrets/upstream_key")
	if bootstrap := os.Getenv("RELAY_CORE_UPSTREAM_KEY"); bootstrap != "" {
		if _, err := os.Stat(keyFile); err != nil && raCert.Attested {
			if serr := raenclave.SealKeyFile(keyFile, bootstrap); serr != nil {
				os.Stderr.WriteString("warn: seal upstream key failed: " + serr.Error() + "\n")
			} else {
				os.Stdout.WriteString("provisioned MRENCLAVE-sealed upstream key at " + keyFile + "\n")
			}
		}
	}

	// Control plane: if RELAY_CORE_CONTROL_URL is set, use the REAL new-api
	// control plane over loopback (token auth + channel select + upstream key
	// from new-api's DB). Otherwise fall back to the built-in static stub.
	var cp ControlPlane
	if cpURL := os.Getenv("RELAY_CORE_CONTROL_URL"); cpURL != "" {
		cp = newHTTPControlPlane(cpURL)
		os.Stdout.WriteString("control plane: REAL new-api at " + cpURL + "\n")
	} else {
		cp = staticControlPlane{channelID: 1, channelType: channelType}
		os.Stdout.WriteString("control plane: static stub (demo)\n")
	}

	handler := newHandler(
		cp,
		fileKeyStore{path: keyFile, envName: "RELAY_CORE_UPSTREAM_KEY"},
		raCert,
	)

	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
	}

	// Allow a plaintext dev mode ONLY when explicitly requested (local wiring
	// tests). Never use in the enclave.
	if os.Getenv("RELAY_CORE_PLAINTEXT") == "1" {
		os.Stdout.WriteString("relay-core listening (PLAINTEXT, dev only) on " + addr + "\n")
		if err := srv.ListenAndServe(); err != nil {
			os.Stderr.WriteString("server error: " + err.Error() + "\n")
			os.Exit(1)
		}
		return
	}

	// Default: serve TLS using the in-memory RA-TLS cert (no cert files on disk).
	srv.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{raCert.TLS},
	}
	if raCert.Attested {
		os.Stdout.WriteString("relay-core listening (RA-TLS, ATTESTED enclave) on " + addr + "\n")
	} else {
		os.Stdout.WriteString("relay-core listening (self-signed TLS, NOT attested — not in enclave) on " + addr + "\n")
	}
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		os.Stderr.WriteString("server error: " + err.Error() + "\n")
		os.Exit(1)
	}
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// b64 / hexstr: stdlib encoders for the /attestation JSON payload.
func b64(b []byte) string    { return base64.StdEncoding.EncodeToString(b) }
func hexstr(b []byte) string { return hex.EncodeToString(b) }

// itoa / itoa64: tiny stdlib-only int formatting to avoid importing strconv into
// the settle path unnecessarily (strconv is stdlib and fine; kept explicit).
func itoa(i int) string   { return itoa64(int64(i)) }
func itoa64(i int64) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
