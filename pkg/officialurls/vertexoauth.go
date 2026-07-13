package officialurls

// vertexoauth.go implements the Google service-account OAuth2 flow (RFC 7523,
// "JWT bearer" grant) used to mint Vertex AI access tokens — in PURE Go standard
// library.
//
// This file is compiled into the SGX relay-core enclave, which is why it may NOT
// depend on the usual helpers used elsewhere in the tree
// (relay/channel/vertex/service_account.go pulls in golang-jwt, go-redis, and
// the business "service" package). The CI guard scripts/enclave_no_leak_check.sh
// forbids any import outside the standard library here, so we hand-roll the
// RS256 assertion JWT and the token exchange.
//
// NOTE ON encoding/json: the project convention is to funnel JSON through
// common.Marshal/Unmarshal, but the enclave leak-guard forbids importing the
// "common" package (it carries disk/log/DB code). encoding/json is on the
// explicit stdlib allow-list for this package, so we use it directly here.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// googleSAKey is the subset of a Google service-account JSON we need.
type googleSAKey struct {
	ClientEmail string `json:"client_email"`
	PrivateKey  string `json:"private_key"`
	TokenURI    string `json:"token_uri"`
}

const (
	// defaultTokenURI is Google's OAuth2 token endpoint, used when the
	// service-account JSON omits token_uri.
	defaultTokenURI = "https://oauth2.googleapis.com/token"

	// jwtBearerGrant is the RFC 7523 grant type for the SA assertion flow.
	jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// tokenLifetimeSeconds is the assertion lifetime; Google caps this at 3600s.
	tokenLifetimeSeconds = 3600

	// cacheSkewSeconds is subtracted from a cached token's expiry so we re-mint
	// slightly before the real expiry rather than handing out a token that dies
	// mid-flight.
	cacheSkewSeconds = 60
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Iss   string `json:"iss"`
	Scope string `json:"scope"`
	Aud   string `json:"aud"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

// BuildSignedSAJWT builds and RS256-signs the assertion JWT used in the
// service-account OAuth2 flow (RFC 7523). scope e.g.
// "https://www.googleapis.com/auth/cloud-platform". aud is the token URI. iat/exp
// from nowUnix (exp = iat+3600). Pure stdlib (parse PKCS8/PKCS1 PEM via crypto/x509,
// sign with rsa.SignPKCS1v15 + sha256). Returns the compact JWT string.
func BuildSignedSAJWT(sa googleSAKey, scope, aud string, nowUnix int64) (string, error) {
	key, err := parseRSAPrivateKey(sa.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("parse service-account private key: %w", err)
	}

	headerJSON, err := json.Marshal(jwtHeader{Alg: "RS256", Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("marshal jwt header: %w", err)
	}
	claimsJSON, err := json.Marshal(jwtClaims{
		Iss:   sa.ClientEmail,
		Scope: scope,
		Aud:   aud,
		Iat:   nowUnix,
		Exp:   nowUnix + tokenLifetimeSeconds,
	})
	if err != nil {
		return "", fmt.Errorf("marshal jwt claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)

	digest := sha256.Sum256([]byte(signingInput))
	// RS256 == RSASSA-PKCS1-v1_5 over a SHA-256 digest. This is deterministic
	// (v1.5 signatures do not consume randomness), so the same input always
	// yields the same signature — which is what makes a known-answer test viable.
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// parseRSAPrivateKey decodes a PEM-encoded RSA private key, accepting either the
// PKCS#8 ("PRIVATE KEY") form Google emits or the legacy PKCS#1 ("RSA PRIVATE
// KEY") form.
func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	// Service-account JSON already contains real newlines after JSON decoding, but
	// tolerate an escaped "\n" form in case a caller passes the raw string.
	pemStr = strings.ReplaceAll(pemStr, "\\n", "\n")

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("no PEM block found in private key")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is %T, not RSA", key)
		}
		return rsaKey, nil
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("private key is neither valid PKCS#8 nor PKCS#1 RSA")
}

// MintVertexAccessToken parses a service-account JSON, builds+signs the JWT, and
// exchanges it at the token URI for an access token
// (POST application/x-www-form-urlencoded grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<jwt>).
// Uses the provided *http.Client (the enclave's strict-TLS client). Returns the
// access token. Network call is NOT unit-tested; keep it a thin wrapper.
func MintVertexAccessToken(client *http.Client, saJSON []byte, scope string, nowUnix int64) (accessToken string, expiresIn int, err error) {
	var sa googleSAKey
	if err = json.Unmarshal(saJSON, &sa); err != nil {
		return "", 0, fmt.Errorf("parse service-account json: %w", err)
	}
	if sa.ClientEmail == "" || sa.PrivateKey == "" {
		return "", 0, errors.New("service-account json missing client_email or private_key")
	}

	tokenURI := sa.TokenURI
	if tokenURI == "" {
		tokenURI = defaultTokenURI
	}

	assertion, err := BuildSignedSAJWT(sa, scope, tokenURI, nowUnix)
	if err != nil {
		return "", 0, err
	}

	form := url.Values{}
	form.Set("grant_type", jwtBearerGrant)
	form.Set("assertion", assertion)

	req, err := http.NewRequest(http.MethodPost, tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("read token response: %w", err)
	}

	var tr struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err = json.Unmarshal(body, &tr); err != nil {
		return "", 0, fmt.Errorf("decode token response (status %d): %w", resp.StatusCode, err)
	}

	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		if tr.Error != "" {
			return "", 0, fmt.Errorf("token exchange rejected (status %d): %s: %s", resp.StatusCode, tr.Error, tr.ErrorDescription)
		}
		return "", 0, fmt.Errorf("token exchange failed (status %d): no access_token in response", resp.StatusCode)
	}

	return tr.AccessToken, tr.ExpiresIn, nil
}

// tokenCacheEntry is one minted access token plus the wall-clock unix second at
// which it should be considered expired (already adjusted for cacheSkewSeconds).
type tokenCacheEntry struct {
	token     string
	expiresAt int64
}

var (
	tokenCacheMu sync.Mutex
	tokenCache   = map[string]tokenCacheEntry{}
)

// CachedVertexToken returns a valid Vertex access token, minting a fresh one only
// when the cache is empty or the cached token is within cacheSkewSeconds of
// expiry. The cache is keyed by client_email+scope and guarded by a mutex so the
// enclave does not mint a new token on every request.
func CachedVertexToken(client *http.Client, saJSON []byte, scope string, nowUnix int64) (string, error) {
	var sa googleSAKey
	if err := json.Unmarshal(saJSON, &sa); err != nil {
		return "", fmt.Errorf("parse service-account json: %w", err)
	}
	if sa.ClientEmail == "" {
		return "", errors.New("service-account json missing client_email")
	}
	cacheKey := sa.ClientEmail + "\x00" + scope

	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()

	if entry, ok := tokenCache[cacheKey]; ok && nowUnix < entry.expiresAt {
		return entry.token, nil
	}

	token, expiresIn, err := MintVertexAccessToken(client, saJSON, scope, nowUnix)
	if err != nil {
		return "", err
	}

	if expiresIn <= 0 {
		expiresIn = tokenLifetimeSeconds
	}
	expiresAt := nowUnix + int64(expiresIn) - cacheSkewSeconds
	if expiresAt <= nowUnix {
		// Degenerate lifetime; still cache but do not create a stale entry that is
		// already "valid" in the past. Set to nowUnix so the next call re-mints.
		expiresAt = nowUnix
	}
	tokenCache[cacheKey] = tokenCacheEntry{token: token, expiresAt: expiresAt}

	return token, nil
}
