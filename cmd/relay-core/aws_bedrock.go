package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/pkg/officialurls"
	"github.com/QuantumNous/new-api/pkg/relaycontrol"
)

const (
	awsBedrockChannelType = 33
	awsBedrockService     = "bedrock"
)

var awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-\d+$`)

type awsBedrockCredentials struct {
	AccessKey    string
	SecretKey    string
	Region       string
	SessionToken string
}

func parseAWSBedrockCredentials(raw string) (awsBedrockCredentials, error) {
	parts := strings.Split(raw, "|")
	if len(parts) != 3 && len(parts) != 4 {
		return awsBedrockCredentials{}, errors.New("AWS Bedrock credentials must have three or four pipe-separated fields")
	}
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			return awsBedrockCredentials{}, errors.New("AWS Bedrock credentials contain an empty field")
		}
	}
	region := strings.TrimSpace(parts[2])
	if !awsRegionPattern.MatchString(region) {
		return awsBedrockCredentials{}, errors.New("invalid AWS Bedrock region")
	}
	credentials := awsBedrockCredentials{
		AccessKey: strings.TrimSpace(parts[0]),
		SecretKey: strings.TrimSpace(parts[1]),
		Region:    region,
	}
	if len(parts) == 4 {
		credentials.SessionToken = strings.TrimSpace(parts[3])
	}
	return credentials, nil
}

type openAIToNovaRequest struct {
	Model       string                `json:"model"`
	Stream      bool                  `json:"stream"`
	Messages    []openAIToNovaMessage `json:"messages"`
	MaxTokens   *int                  `json:"max_tokens,omitempty"`
	Temperature *float64              `json:"temperature,omitempty"`
	TopP        *float64              `json:"top_p,omitempty"`
	Stop        json.RawMessage       `json:"stop,omitempty"`
}

type openAIToNovaMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

type novaRequest struct {
	SchemaVersion   string               `json:"schemaVersion"`
	System          []novaTextBlock      `json:"system,omitempty"`
	Messages        []novaMessage        `json:"messages"`
	InferenceConfig *novaInferenceConfig `json:"inferenceConfig,omitempty"`
}

type novaMessage struct {
	Role    string          `json:"role"`
	Content []novaTextBlock `json:"content"`
}

type novaTextBlock struct {
	Text string `json:"text"`
}

type novaInferenceConfig struct {
	MaxTokens     *int     `json:"maxTokens,omitempty"`
	Temperature   *float64 `json:"temperature,omitempty"`
	TopP          *float64 `json:"topP,omitempty"`
	StopSequences []string `json:"stopSequences,omitempty"`
}

func convertOpenAIRequestToNova(body []byte) ([]byte, error) {
	var input openAIToNovaRequest
	if err := json.Unmarshal(body, &input); err != nil {
		return nil, fmt.Errorf("decode OpenAI request for Nova: %w", err)
	}
	if len(input.Messages) == 0 {
		return nil, errors.New("Nova request requires at least one message")
	}
	if input.MaxTokens != nil && (*input.MaxTokens < 0 || *input.MaxTokens > relaycontrol.MaxTokensLimit) {
		return nil, errors.New("max_tokens is out of range")
	}

	output := novaRequest{SchemaVersion: "messages-v1"}
	for _, message := range input.Messages {
		text, err := openAIMessageText(message.Content)
		if err != nil {
			return nil, fmt.Errorf("convert %s message for Nova: %w", message.Role, err)
		}
		switch message.Role {
		case "system", "developer":
			output.System = append(output.System, novaTextBlock{Text: text})
		case "user", "assistant":
			output.Messages = append(output.Messages, novaMessage{
				Role:    message.Role,
				Content: []novaTextBlock{{Text: text}},
			})
		default:
			return nil, fmt.Errorf("Nova does not support message role %q", message.Role)
		}
	}
	if len(output.Messages) == 0 {
		return nil, errors.New("Nova request requires a user or assistant message")
	}

	stopSequences, err := parseNovaStop(input.Stop)
	if err != nil {
		return nil, err
	}
	if input.MaxTokens != nil || input.Temperature != nil || input.TopP != nil || len(stopSequences) > 0 {
		output.InferenceConfig = &novaInferenceConfig{
			MaxTokens:     input.MaxTokens,
			Temperature:   input.Temperature,
			TopP:          input.TopP,
			StopSequences: stopSequences,
		}
	}
	converted, err := json.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("encode Nova request: %w", err)
	}
	return converted, nil
}

func openAIMessageText(raw json.RawMessage) (string, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text, nil
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err != nil {
		return "", errors.New("content must be a string or text-part array")
	}
	var builder strings.Builder
	for _, part := range parts {
		if part.Type != "text" || part.Text == "" {
			continue
		}
		builder.WriteString(part.Text)
	}
	if builder.Len() == 0 {
		return "", errors.New("content has no text")
	}
	return builder.String(), nil
}

func parseNovaStop(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if one == "" {
			return nil, nil
		}
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, errors.New("stop must be a string or string array")
	}
	return many, nil
}

type novaResponse struct {
	Output struct {
		Message struct {
			Content []novaTextBlock `json:"content"`
		} `json:"message"`
	} `json:"output"`
	StopReason string `json:"stopReason"`
	Usage      struct {
		InputTokens  int `json:"inputTokens"`
		OutputTokens int `json:"outputTokens"`
		TotalTokens  int `json:"totalTokens"`
	} `json:"usage"`
}

type openAIFromNovaResponse struct {
	ID      string                 `json:"id"`
	Object  string                 `json:"object"`
	Created int64                  `json:"created"`
	Model   string                 `json:"model"`
	Choices []openAIFromNovaChoice `json:"choices"`
	Usage   openAIFromNovaUsage    `json:"usage"`
}

type openAIFromNovaChoice struct {
	Index        int                   `json:"index"`
	Message      openAIFromNovaMessage `json:"message"`
	FinishReason string                `json:"finish_reason"`
}

type openAIFromNovaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIFromNovaUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

func convertNovaResponseToOpenAI(body []byte, model, requestID string, created int64) ([]byte, relaycontrol.Usage, error) {
	var input novaResponse
	if err := json.Unmarshal(body, &input); err != nil {
		return nil, relaycontrol.Usage{}, fmt.Errorf("decode Nova response: %w", err)
	}
	var text strings.Builder
	for _, block := range input.Output.Message.Content {
		text.WriteString(block.Text)
	}
	if requestID == "" {
		requestID = "chatcmpl-bedrock"
	}
	usage := relaycontrol.Usage{
		PromptTokens:     input.Usage.InputTokens,
		CompletionTokens: input.Usage.OutputTokens,
		TotalTokens:      input.Usage.TotalTokens,
	}
	if usage.TotalTokens == 0 {
		usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
	}
	output := openAIFromNovaResponse{
		ID:      requestID,
		Object:  "chat.completion",
		Created: created,
		Model:   model,
		Choices: []openAIFromNovaChoice{{
			Index: 0,
			Message: openAIFromNovaMessage{
				Role:    "assistant",
				Content: text.String(),
			},
			FinishReason: novaFinishReason(input.StopReason),
		}},
		Usage: openAIFromNovaUsage{
			PromptTokens:     usage.PromptTokens,
			CompletionTokens: usage.CompletionTokens,
			TotalTokens:      usage.TotalTokens,
		},
	}
	encoded, err := json.Marshal(output)
	if err != nil {
		return nil, relaycontrol.Usage{}, fmt.Errorf("encode OpenAI response from Nova: %w", err)
	}
	return encoded, usage, nil
}

func novaFinishReason(reason string) string {
	switch reason {
	case "max_tokens", "maxTokens":
		return "length"
	default:
		return "stop"
	}
}

func prepareAWSBedrockRequest(ctx context.Context, body []byte, rawCredentials, model string, isStream bool, now time.Time) (*http.Request, error) {
	if isStream {
		return nil, errors.New("AWS Bedrock streaming is not supported by the enclave yet")
	}
	credentials, err := parseAWSBedrockCredentials(rawCredentials)
	if err != nil {
		return nil, err
	}
	converted, err := convertOpenAIRequestToNova(body)
	if err != nil {
		return nil, err
	}
	host := "bedrock-runtime." + credentials.Region + ".amazonaws.com"
	if !officialurls.IsOfficialHostSuffix(awsBedrockChannelType, host) {
		return nil, errors.New("constructed AWS Bedrock host is not official")
	}
	modelPath := url.PathEscape(model)
	requestURL := "https://" + host + "/model/" + modelPath + "/invoke"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(converted))
	if err != nil {
		return nil, fmt.Errorf("build AWS Bedrock request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if err := officialurls.SignSigV4(req, converted, credentials.AccessKey, credentials.SecretKey, credentials.SessionToken, credentials.Region, awsBedrockService, now.UTC()); err != nil {
		return nil, fmt.Errorf("sign AWS Bedrock request: %w", err)
	}
	return req, nil
}

func (h *relayHandler) forwardAWSBedrock(ctx context.Context, w http.ResponseWriter, body []byte, rawCredentials, model string, isStream bool, requestID string) (relaycontrol.Usage, int, error) {
	req, err := prepareAWSBedrockRequest(ctx, body, rawCredentials, model, isStream, time.Now().UTC())
	if err != nil {
		return relaycontrol.Usage{}, 0, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return relaycontrol.Usage{}, 0, fmt.Errorf("call AWS Bedrock: %w", err)
	}
	defer resp.Body.Close()
	upstreamBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return relaycontrol.Usage{}, resp.StatusCode, fmt.Errorf("read AWS Bedrock response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		// Do not forward or log the upstream body: it may contain request-derived
		// diagnostic data. Return only the status; settlement charges only 2xx.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write([]byte(`{"error":{"message":"AWS Bedrock upstream rejected the request","type":"relay_core_error"}}`))
		return relaycontrol.Usage{}, resp.StatusCode, nil
	}
	converted, usage, err := convertNovaResponseToOpenAI(upstreamBody, model, requestID, time.Now().Unix())
	if err != nil {
		return relaycontrol.Usage{}, resp.StatusCode, err
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	if _, err := w.Write(converted); err != nil {
		return relaycontrol.Usage{}, resp.StatusCode, fmt.Errorf("write AWS Bedrock response: %w", err)
	}
	return usage, resp.StatusCode, nil
}
