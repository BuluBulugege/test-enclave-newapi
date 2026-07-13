package officialurls

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Credentials, region, service, date and host are the fixed inputs of the
// canonical AWS "aws-sig-v4-test-suite" (https://docs.aws.amazon.com/...).
// The expected signatures below are the values AWS publishes in that suite's
// *.authz files, so these are real known-answers, not self-referential output.
const (
	testAccessKey = "AKIDEXAMPLE"
	testSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
)

var testSigningTime = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

func TestSignSigV4(t *testing.T) {
	tests := []struct {
		name         string
		method       string
		url          string
		body         []byte
		headers      map[string]string
		sessionToken string
		region       string
		service      string

		// Known-answer expectations (set for the published AWS vectors).
		wantSignedHeaders string
		wantSignature     string

		// Structural expectations (used when wantSignature == "").
		wantScope             string
		wantSignedHeadersHave []string
	}{
		{
			// aws-sig-v4-test-suite: get-vanilla
			// Canonical request signs only host;x-amz-date; empty body.
			name:              "get-vanilla",
			method:            http.MethodGet,
			url:               "https://example.amazonaws.com",
			body:              nil,
			region:            "us-east-1",
			service:           "service",
			wantSignedHeaders: "host;x-amz-date",
			wantSignature:     "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
		},
		{
			// aws-sig-v4-test-suite: post-x-www-form-urlencoded
			// POST with a body and a caller-set Content-Type that must be signed.
			name:              "post-x-www-form-urlencoded",
			method:            http.MethodPost,
			url:               "https://example.amazonaws.com",
			body:              []byte("Param1=value1"),
			headers:           map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			region:            "us-east-1",
			service:           "service",
			wantSignedHeaders: "content-type;host;x-amz-date",
			wantSignature:     "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a",
		},
		{
			// Realistic Bedrock-style call: JSON body + STS session token. There is
			// no published AWS vector for a session token, so assert structure: the
			// token header is set, it is part of the signed set, and Authorization
			// is well-formed with the correct credential scope.
			name:                  "post-json-with-session-token",
			method:                http.MethodPost,
			url:                   "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-v2/invoke",
			body:                  []byte(`{"prompt":"hello","max_tokens":16}`),
			headers:               map[string]string{"Content-Type": "application/json"},
			sessionToken:          "FQoGZXIvYXdzEExampleSessionTokenABCDEF==",
			region:                "us-east-1",
			service:               "bedrock",
			wantScope:             "20150830/us-east-1/bedrock/aws4_request",
			wantSignedHeadersHave: []string{"host", "x-amz-date", "x-amz-security-token", "content-type"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var bodyReader *bytes.Reader
			if tt.body != nil {
				bodyReader = bytes.NewReader(tt.body)
			} else {
				bodyReader = bytes.NewReader(nil)
			}
			req, err := http.NewRequest(tt.method, tt.url, bodyReader)
			require.NoError(t, err)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			err = SignSigV4(req, tt.body, testAccessKey, testSecretKey, tt.sessionToken, tt.region, tt.service, testSigningTime)
			require.NoError(t, err)

			// Common invariants for every signed request.
			assert.Equal(t, "20150830T123600Z", req.Header.Get("X-Amz-Date"))
			assert.Equal(t, hexSHA256(tt.body), req.Header.Get("X-Amz-Content-Sha256"))

			params := parseAuthzParams(t, req.Header.Get("Authorization"))
			// Signature must always be 64 lowercase hex chars.
			sig := params["Signature"]
			require.Len(t, sig, 64)
			_, decErr := hex.DecodeString(sig)
			require.NoError(t, decErr, "signature must be valid hex")

			if tt.wantSignature != "" {
				// Exact known-answer assertions against the published AWS vector.
				wantScope := "20150830/" + tt.region + "/" + tt.service + "/aws4_request"
				wantAuthz := "AWS4-HMAC-SHA256 " +
					"Credential=" + testAccessKey + "/" + wantScope + ", " +
					"SignedHeaders=" + tt.wantSignedHeaders + ", " +
					"Signature=" + tt.wantSignature
				assert.Equal(t, tt.wantSignature, sig)
				assert.Equal(t, tt.wantSignedHeaders, params["SignedHeaders"])
				assert.Equal(t, testAccessKey+"/"+wantScope, params["Credential"])
				assert.Equal(t, wantAuthz, req.Header.Get("Authorization"))
				return
			}

			// Structural assertions (session-token case).
			assert.Equal(t, testAccessKey+"/"+tt.wantScope, params["Credential"])
			if tt.sessionToken != "" {
				assert.Equal(t, tt.sessionToken, req.Header.Get("X-Amz-Security-Token"))
				assert.Contains(t, params["SignedHeaders"], "x-amz-security-token")
			}
			signed := strings.Split(params["SignedHeaders"], ";")
			for _, want := range tt.wantSignedHeadersHave {
				assert.Contains(t, signed, want)
			}
			// SignedHeaders must be sorted ascending.
			assert.True(t, sort.StringsAreSorted(signed), "SignedHeaders must be sorted: %q", params["SignedHeaders"])
		})
	}
}

func parseAuthzParams(t *testing.T, authz string) map[string]string {
	t.Helper()
	const prefix = "AWS4-HMAC-SHA256 "
	require.True(t, strings.HasPrefix(authz, prefix), "Authorization must start with %q, got %q", prefix, authz)
	params := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(authz, prefix), ", ") {
		kv := strings.SplitN(part, "=", 2)
		require.Len(t, kv, 2, "malformed Authorization component: %q", part)
		params[kv[0]] = kv[1]
	}
	return params
}
