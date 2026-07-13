package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/QuantumNous/new-api/pkg/relaycontrol"
)

// httpControlPlane is the REAL control plane: it talks to new-api over a
// loopback HTTP endpoint (127.0.0.1). new-api authenticates the gateway token,
// selects a channel for the model, and returns the upstream key + routing
// metadata. Only {token, model} leave the enclave here — never prompt content.
//
// This keeps relay-core's package closure pure: it uses only net/http +
// encoding/json + pkg/relaycontrol, so the leak-guard still passes.
type httpControlPlane struct {
	baseURL string
	client  *http.Client
}

func newHTTPControlPlane(baseURL string) *httpControlPlane {
	return &httpControlPlane{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// wire shapes matching new-api's relaycore_control.go handler.
type cpSelectReq struct {
	Token string `json:"token"`
	Model string `json:"model"`
}

type cpSelectResp struct {
	ChannelID   int    `json:"channel_id"`
	ChannelType int    `json:"channel_type"`
	UpstreamKey string `json:"upstream_key"`
	UserID      int    `json:"user_id"`
	TokenID     int    `json:"token_id"`
	IsOfficial  bool   `json:"is_official"`
	Error       string `json:"error,omitempty"`
}

func (h *httpControlPlane) SelectChannel(ctx context.Context, req relaycontrol.SelectChannelRequest) (relaycontrol.SelectChannelResponse, error) {
	payload, err := json.Marshal(cpSelectReq{Token: req.RawToken, Model: req.Model})
	if err != nil {
		return relaycontrol.SelectChannelResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		h.baseURL+"/internal/relaycore/select", bytes.NewReader(payload))
	if err != nil {
		return relaycontrol.SelectChannelResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return relaycontrol.SelectChannelResponse{}, fmt.Errorf("control plane unreachable: %w", err)
	}
	defer resp.Body.Close()

	var out cpSelectResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return relaycontrol.SelectChannelResponse{}, fmt.Errorf("control plane bad response: %w", err)
	}
	if out.Error != "" {
		return relaycontrol.SelectChannelResponse{Error: out.Error}, nil
	}
	return relaycontrol.SelectChannelResponse{
		ChannelID:      out.ChannelID,
		ChannelType:    out.ChannelType,
		IsOfficial:     out.IsOfficial,
		UserID:         out.UserID,
		TokenID:        out.TokenID,
		UpstreamAPIKey: out.UpstreamKey, // key comes from new-api's DB (host-visible path, v1)
	}, nil
}

// Settle logs billing metadata locally for the demo. A production build would
// POST this to a new-api /internal/relaycore/settle endpoint to deduct quota.
func (h *httpControlPlane) Settle(ctx context.Context, req relaycontrol.SettleRequest) error {
	fmt.Printf("[settle] request_id=%s model=%s prompt=%d completion=%d total=%d latency_ms=%d status=%d\n",
		req.RequestID, req.Model, req.PromptTokens, req.CompletionTokens, req.TotalTokens,
		req.LatencyMs, req.UpstreamStatusCode)
	return nil
}
