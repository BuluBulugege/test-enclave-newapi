// sigv4.go implements AWS Signature Version 4 (header-based auth) using ONLY the
// Go standard library, so it can be linked into the SGX relay-core enclave
// without dragging in the aws-sdk or any third-party crypto. Like the rest of
// this package it is a pure leaf: it signs Bedrock/other AWS requests in-enclave
// so the untrusted host never sees the long-lived secret key or a pre-signed
// blob it could replay against a different body. The signing math is the SigV4
// spec verbatim (canonical request -> string-to-sign -> HMAC key chain ->
// signature); a known-answer test pins it to the canonical AWS test vectors so a
// subtle regression fails CI instead of silently producing rejected requests.

package officialurls

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	sigV4Algorithm  = "AWS4-HMAC-SHA256"
	amzDateFormat   = "20060102T150405Z" // YYYYMMDDTHHMMSSZ
	shortDateFormat = "20060102"         // YYYYMMDD
	terminator      = "aws4_request"
	upperHex        = "0123456789ABCDEF"
)

// SignSigV4 signs an http.Request for AWS SigV4 (header-based auth) and sets
// Authorization + X-Amz-Date + x-amz-content-sha256 (+ X-Amz-Security-Token when
// sessionToken != ""). body is the exact request body bytes. service e.g.
// "bedrock", region e.g. "us-east-1". nowUTC is the signing time (inject for
// testability; callers pass time.Now().UTC()). Pure stdlib.
//
// The signed-header set is host, x-amz-date, x-amz-security-token (only when a
// session token is supplied) plus any headers already present on req (e.g. a
// caller-set Content-Type). x-amz-content-sha256 is written to the request AFTER
// signing and is deliberately NOT part of the signed set: the payload is already
// bound into the signature through the canonical request's trailing payload-hash
// line, and keeping it out of SignedHeaders keeps the signature bit-for-bit
// identical to the canonical AWS "aws-sig-v4-test-suite" vectors (which sign only
// host;x-amz-date for the vanilla cases).
func SignSigV4(req *http.Request, body []byte, accessKey, secretKey, sessionToken, region, service string, nowUTC time.Time) error {
	if req == nil {
		return fmt.Errorf("sigv4: nil request")
	}
	if req.URL == nil {
		return fmt.Errorf("sigv4: request has nil URL")
	}
	if accessKey == "" || secretKey == "" {
		return fmt.Errorf("sigv4: missing access key or secret key")
	}
	if region == "" || service == "" {
		return fmt.Errorf("sigv4: region and service are required")
	}

	amzDate := nowUTC.Format(amzDateFormat)
	shortDate := nowUTC.Format(shortDateFormat)
	payloadHash := hexSHA256(body)

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	// Set the signing-relevant headers before collecting the signed-header set so
	// what we sign is exactly what goes on the wire.
	req.Header.Set("X-Amz-Date", amzDate)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}

	canonicalHeaders, signedHeaders := canonicalizeHeaders(req.Header, host)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURIPath(req.URL),
		canonicalQueryString(req.URL),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := strings.Join([]string{shortDate, region, service, terminator}, "/")

	stringToSign := strings.Join([]string{
		sigV4Algorithm,
		amzDate,
		credentialScope,
		hexSHA256([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigningKey(secretKey, shortDate, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	authorization := fmt.Sprintf(
		"%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		sigV4Algorithm, accessKey, credentialScope, signedHeaders, signature,
	)

	req.Header.Set("Authorization", authorization)
	// x-amz-content-sha256 is set last: it is sent on the wire but is not part of
	// the signed-header set (see the function doc for why).
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	return nil
}

// canonicalizeHeaders builds the canonical-headers block and the signed-headers
// list from the derived host plus every header currently on req. Header names are
// lowercased, values trimmed (multi-valued headers comma-joined), and both
// outputs are sorted by lowercased name.
func canonicalizeHeaders(h http.Header, host string) (canonical, signed string) {
	values := make(map[string]string, len(h)+1)
	for name, vs := range h {
		trimmed := make([]string, 0, len(vs))
		for _, v := range vs {
			trimmed = append(trimmed, strings.TrimSpace(v))
		}
		values[strings.ToLower(name)] = strings.Join(trimmed, ",")
	}
	// The derived host is authoritative; set it after the loop so a stray Host
	// entry in the header map cannot shadow it.
	values["host"] = strings.TrimSpace(host)

	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(values[n])
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(names, ";")
}

// canonicalURIPath returns the RFC3986-encoded, segment-encoded path. An empty
// path becomes "/". Each segment is encoded once, which is correct for every
// non-S3 service whose paths use unreserved/ASCII characters (Bedrock, etc.);
// S3's single-encoding-without-normalization and the double-encoding rule for
// paths containing reserved characters are out of scope for this signer.
func canonicalURIPath(u *url.URL) string {
	path := u.Path
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, s := range segments {
		segments[i] = awsURIEncode(s, true)
	}
	return strings.Join(segments, "/")
}

// canonicalQueryString returns the sorted, RFC3986-encoded canonical query
// string. Parameters are sorted by encoded key then encoded value.
func canonicalQueryString(u *url.URL) string {
	raw := u.RawQuery
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	pairs := make([]kv, 0)
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		key, val := part, ""
		if eq := strings.IndexByte(part, '='); eq >= 0 {
			key, val = part[:eq], part[eq+1:]
		}
		// Decode any existing percent-encoding, then re-encode with AWS's exact
		// unreserved set so the result is canonical regardless of the caller's
		// original encoding.
		if dk, err := url.QueryUnescape(key); err == nil {
			key = dk
		}
		if dv, err := url.QueryUnescape(val); err == nil {
			val = dv
		}
		pairs = append(pairs, kv{awsURIEncode(key, true), awsURIEncode(val, true)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k == pairs[j].k {
			return pairs[i].v < pairs[j].v
		}
		return pairs[i].k < pairs[j].k
	})
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.k)
		b.WriteByte('=')
		b.WriteString(p.v)
	}
	return b.String()
}

// awsURIEncode percent-encodes s per RFC3986, leaving only the unreserved set
// (A-Z a-z 0-9 - . _ ~) unescaped. When encodeSlash is false, '/' is preserved
// (used for path separators). Encoding is byte-wise so multi-byte UTF-8 is
// percent-encoded correctly.
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&0x0f])
		}
	}
	return b.String()
}

func deriveSigningKey(secretKey, shortDate, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(shortDate))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte(terminator))
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
