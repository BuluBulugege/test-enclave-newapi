package officialurls

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildSignedSAJWTVertex is a known-answer test for the RFC 7523 assertion
// JWT with NO network. It generates a throwaway RSA-2048 key, signs a JWT, and
// then — using ONLY the JWT string and the corresponding PUBLIC key — proves:
//   - the header/claims decode to the exact expected values (alg/typ, iss/scope/
//     aud, iat==nowUnix, exp==iat+3600), and
//   - the third segment is a real, correct RS256 signature over "header.claims":
//     recomputing SHA-256(signing input) and calling rsa.VerifyPKCS1v15 against
//     the public key succeeds. That verification IS the "known answer": a
//     tampered payload, wrong digest, or bogus signature would fail here.
func TestBuildSignedSAJWTVertex(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	validPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	require.NotEmpty(t, validPEM)

	// A PKCS#1 ("RSA PRIVATE KEY") PEM for the same key, to prove that legacy
	// form is also accepted.
	pkcs1 := x509.MarshalPKCS1PrivateKey(key)
	validPKCS1PEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1}))
	require.NotEmpty(t, validPKCS1PEM)

	const (
		email = "svc@my-project.iam.gserviceaccount.com"
		scope = "https://www.googleapis.com/auth/cloud-platform"
		aud   = "https://oauth2.googleapis.com/token"
		now   = int64(1_700_000_000)
	)

	tests := []struct {
		name    string
		sa      googleSAKey
		wantErr bool
	}{
		{
			name: "valid PKCS8 key round-trips and verifies",
			sa:   googleSAKey{ClientEmail: email, PrivateKey: validPEM, TokenURI: aud},
		},
		{
			name: "valid PKCS1 key round-trips and verifies",
			sa:   googleSAKey{ClientEmail: email, PrivateKey: validPKCS1PEM, TokenURI: aud},
		},
		{
			name:    "malformed PEM returns error",
			sa:      googleSAKey{ClientEmail: email, PrivateKey: "this is not a pem block", TokenURI: aud},
			wantErr: true,
		},
		{
			name:    "empty private key returns error",
			sa:      googleSAKey{ClientEmail: email, PrivateKey: "", TokenURI: aud},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			jwt, err := BuildSignedSAJWT(tc.sa, scope, aud, now)
			if tc.wantErr {
				require.Error(t, err)
				assert.Empty(t, jwt)
				return
			}
			require.NoError(t, err)

			parts := strings.Split(jwt, ".")
			require.Len(t, parts, 3, "compact JWT must have header.claims.signature")

			// --- header ---
			headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
			require.NoError(t, err)
			var hdr struct {
				Alg string `json:"alg"`
				Typ string `json:"typ"`
			}
			require.NoError(t, json.Unmarshal(headerJSON, &hdr))
			assert.Equal(t, "RS256", hdr.Alg)
			assert.Equal(t, "JWT", hdr.Typ)

			// --- claims ---
			claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
			require.NoError(t, err)
			var claims struct {
				Iss   string `json:"iss"`
				Scope string `json:"scope"`
				Aud   string `json:"aud"`
				Iat   int64  `json:"iat"`
				Exp   int64  `json:"exp"`
			}
			require.NoError(t, json.Unmarshal(claimsJSON, &claims))
			assert.Equal(t, email, claims.Iss)
			assert.Equal(t, scope, claims.Scope)
			assert.Equal(t, aud, claims.Aud)
			assert.Equal(t, now, claims.Iat)
			assert.Equal(t, now+3600, claims.Exp, "exp must be iat+3600")

			// --- signature: the real RS256 verification (the "known answer") ---
			signingInput := parts[0] + "." + parts[1]
			digest := sha256.Sum256([]byte(signingInput))
			sig, err := base64.RawURLEncoding.DecodeString(parts[2])
			require.NoError(t, err)
			err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig)
			require.NoError(t, err, "signature must verify under the corresponding RSA public key")

			// Determinism check: RS256 (PKCS#1 v1.5) is deterministic, so signing
			// the same inputs again must produce a byte-identical JWT.
			jwt2, err := BuildSignedSAJWT(tc.sa, scope, aud, now)
			require.NoError(t, err)
			assert.Equal(t, jwt, jwt2)

			// Tamper detection: flipping the claims must break verification.
			tampered := sha256.Sum256([]byte(signingInput + "x"))
			assert.Error(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, tampered[:], sig))
		})
	}
}
