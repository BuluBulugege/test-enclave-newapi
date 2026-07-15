package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAWSBedrockCredentials(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantRegion  string
		wantSession string
		wantErr     string
	}{
		{name: "permanent", raw: "AKID|SECRET|us-east-1", wantRegion: "us-east-1"},
		{name: "temporary STS", raw: "AKID|SECRET|us-west-2|SESSION", wantRegion: "us-west-2", wantSession: "SESSION"},
		{name: "missing secret", raw: "AKID||us-east-1", wantErr: "empty"},
		{name: "invalid shape", raw: "AKID|SECRET", wantErr: "three or four"},
		{name: "invalid region injection", raw: "AKID|SECRET|us-east-1.evil.com|SESSION", wantErr: "region"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAWSBedrockCredentials(tt.raw)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "AKID", got.AccessKey)
			assert.Equal(t, "SECRET", got.SecretKey)
			assert.Equal(t, tt.wantRegion, got.Region)
			assert.Equal(t, tt.wantSession, got.SessionToken)
		})
	}
}

func TestConvertOpenAIRequestToNova(t *testing.T) {
	body := []byte(`{
		"model":"amazon.nova-micro-v1:0",
		"stream":false,
		"messages":[
			{"role":"system","content":"Be exact."},
			{"role":"user","content":"Reply AWSB_OK"},
			{"role":"assistant","content":[{"type":"text","text":"Earlier"}]}
		],
		"max_tokens":16,
		"temperature":0,
		"top_p":0.9,
		"stop":["END"]
	}`)

	got, err := convertOpenAIRequestToNova(body)
	require.NoError(t, err)

	var out struct {
		SchemaVersion string `json:"schemaVersion"`
		System        []struct {
			Text string `json:"text"`
		} `json:"system"`
		Messages []struct {
			Role    string `json:"role"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
		InferenceConfig struct {
			MaxTokens     *int     `json:"maxTokens"`
			Temperature   *float64 `json:"temperature"`
			TopP          *float64 `json:"topP"`
			StopSequences []string `json:"stopSequences"`
		} `json:"inferenceConfig"`
	}
	require.NoError(t, json.Unmarshal(got, &out))
	assert.Equal(t, "messages-v1", out.SchemaVersion)
	require.Len(t, out.System, 1)
	assert.Equal(t, "Be exact.", out.System[0].Text)
	require.Len(t, out.Messages, 2)
	assert.Equal(t, "user", out.Messages[0].Role)
	assert.Equal(t, "Reply AWSB_OK", out.Messages[0].Content[0].Text)
	assert.Equal(t, "assistant", out.Messages[1].Role)
	assert.Equal(t, "Earlier", out.Messages[1].Content[0].Text)
	require.NotNil(t, out.InferenceConfig.MaxTokens)
	assert.Equal(t, 16, *out.InferenceConfig.MaxTokens)
	require.NotNil(t, out.InferenceConfig.Temperature)
	assert.Equal(t, float64(0), *out.InferenceConfig.Temperature, "explicit zero must be preserved")
	require.NotNil(t, out.InferenceConfig.TopP)
	assert.Equal(t, 0.9, *out.InferenceConfig.TopP)
	assert.Equal(t, []string{"END"}, out.InferenceConfig.StopSequences)

	assert.NotContains(t, string(got), "amazon.nova-micro-v1:0", "model belongs in the Bedrock URL, not the Nova body")
	assert.NotContains(t, string(got), `"stream"`)
}

func TestConvertNovaResponseToOpenAI(t *testing.T) {
	nova := []byte(`{
		"output":{"message":{"role":"assistant","content":[{"text":"AWSB_"},{"text":"OK"}]}},
		"stopReason":"end_turn",
		"usage":{"inputTokens":8,"outputTokens":5,"totalTokens":13}
	}`)

	got, usage, err := convertNovaResponseToOpenAI(nova, "amazon.nova-micro-v1:0", "req-123", 1700000000)
	require.NoError(t, err)
	assert.Equal(t, 8, usage.PromptTokens)
	assert.Equal(t, 5, usage.CompletionTokens)
	assert.Equal(t, 13, usage.TotalTokens)

	var out struct {
		ID      string `json:"id"`
		Object  string `json:"object"`
		Created int64  `json:"created"`
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	require.NoError(t, json.Unmarshal(got, &out))
	assert.Equal(t, "req-123", out.ID)
	assert.Equal(t, "chat.completion", out.Object)
	assert.Equal(t, int64(1700000000), out.Created)
	assert.Equal(t, "amazon.nova-micro-v1:0", out.Model)
	require.Len(t, out.Choices, 1)
	assert.Equal(t, "assistant", out.Choices[0].Message.Role)
	assert.Equal(t, "AWSB_OK", out.Choices[0].Message.Content)
	assert.Equal(t, "stop", out.Choices[0].FinishReason)
}

func TestPrepareAWSBedrockRequestUsesOfficialHostAndSTS(t *testing.T) {
	body := []byte(`{"model":"amazon.nova-micro-v1:0","messages":[{"role":"user","content":"hi"}],"max_tokens":8}`)
	now := time.Date(2026, 7, 14, 1, 2, 3, 0, time.UTC)

	req, err := prepareAWSBedrockRequest(
		context.Background(),
		body,
		"AKID|SECRET|us-east-1|SESSION",
		"amazon.nova-micro-v1:0",
		false,
		now,
	)
	require.NoError(t, err)
	assert.Equal(t, "https", req.URL.Scheme)
	assert.Equal(t, "bedrock-runtime.us-east-1.amazonaws.com", req.URL.Host)
	assert.Equal(t, "/model/amazon.nova-micro-v1:0/invoke", req.URL.EscapedPath())
	assert.Equal(t, "SESSION", req.Header.Get("X-Amz-Security-Token"))
	assert.Equal(t, "20260714T010203Z", req.Header.Get("X-Amz-Date"))
	assert.True(t, strings.HasPrefix(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKID/20260714/us-east-1/bedrock/aws4_request,"))
	assert.Contains(t, req.Header.Get("Authorization"), "x-amz-security-token")
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, "application/json", req.Header.Get("Accept"))
}

func TestPrepareAWSBedrockRequestPerModelRegion(t *testing.T) {
	// The aggregated channel encodes each model's region as an "@<region>" suffix on
	// the upstream model name. The enclave must dispatch to that region's host and
	// SIGN with that region, NOT the credential's own region (us-east-1 here), while
	// the model in the URL path drops the suffix.
	body := []byte(`{"model":"x","messages":[{"role":"user","content":"hi"}],"max_tokens":8}`)
	now := time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)

	req, err := prepareAWSBedrockRequest(
		context.Background(),
		body,
		"AKID|SECRET|us-east-1|SESSION",
		"us.anthropic.claude-sonnet-4-5-20250929-v1:0@us-west-2",
		false,
		now,
	)
	require.NoError(t, err)
	assert.Equal(t, "bedrock-runtime.us-west-2.amazonaws.com", req.URL.Host)
	assert.Equal(t, "/model/us.anthropic.claude-sonnet-4-5-20250929-v1:0/invoke", req.URL.EscapedPath())
	assert.NotContains(t, req.URL.EscapedPath(), "@", "the @region suffix must not leak into the URL path")
	// SigV4 credential scope must use the per-model region, not the credential's.
	assert.Contains(t, req.Header.Get("Authorization"), "/20260715/us-west-2/bedrock/aws4_request,")
}

func TestPrepareAWSBedrockRequestRejectsStream(t *testing.T) {
	_, err := prepareAWSBedrockRequest(
		context.Background(),
		[]byte(`{"model":"amazon.nova-micro-v1:0","stream":true,"messages":[{"role":"user","content":"hi"}]}`),
		"AKID|SECRET|us-east-1|SESSION",
		"amazon.nova-micro-v1:0",
		true,
		time.Now(),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stream")
}

func TestForwardAWSBedrockEndToEnd(t *testing.T) {
	var gotHost, gotPath, gotSession, gotAuthorization string
	var gotNova novaRequest
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		gotPath = r.URL.Path
		gotSession = r.Header.Get("X-Amz-Security-Token")
		gotAuthorization = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotNova))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":{"message":{"role":"assistant","content":[{"text":"AWSB_OK"}]}},"stopReason":"end_turn","usage":{"inputTokens":8,"outputTokens":5,"totalTokens":13}}`))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	transport := upstream.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, upstreamURL.Host)
	}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true} // test server only

	h := &relayHandler{client: &http.Client{Transport: transport}}
	writer := httptest.NewRecorder()
	body := []byte(`{"model":"amazon.nova-micro-v1:0","messages":[{"role":"user","content":"Reply AWSB_OK"}],"max_tokens":16}`)
	usage, status, err := h.forwardAWSBedrock(
		context.Background(), writer, body,
		"AKID|SECRET|us-east-1|SESSION",
		"amazon.nova-micro-v1:0", false, "req-e2e",
	)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, 8, usage.PromptTokens)
	assert.Equal(t, 5, usage.CompletionTokens)
	assert.Equal(t, 13, usage.TotalTokens)
	assert.Equal(t, "bedrock-runtime.us-east-1.amazonaws.com", gotHost)
	assert.Equal(t, "/model/amazon.nova-micro-v1:0/invoke", gotPath)
	assert.Equal(t, "SESSION", gotSession)
	assert.Contains(t, gotAuthorization, "AWS4-HMAC-SHA256")
	assert.Contains(t, gotAuthorization, "x-amz-security-token")
	assert.Equal(t, "messages-v1", gotNova.SchemaVersion)
	require.Len(t, gotNova.Messages, 1)
	assert.Equal(t, "Reply AWSB_OK", gotNova.Messages[0].Content[0].Text)

	var openAI openAIFromNovaResponse
	require.NoError(t, json.Unmarshal(writer.Body.Bytes(), &openAI))
	assert.Equal(t, "req-e2e", openAI.ID)
	assert.Equal(t, "AWSB_OK", openAI.Choices[0].Message.Content)
	assert.Equal(t, 8, openAI.Usage.PromptTokens)
	assert.Equal(t, 5, openAI.Usage.CompletionTokens)
}
