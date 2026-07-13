// Package raenclave builds an RA-TLS certificate for the SGX relay-core enclave
// under Gramine-SGX. It binds the TLS key to a fresh DCAP quote so a remote
// client can verify (before sending any prompt) that it is talking to the
// genuine, measured, no-content-storage enclave.
//
// Mechanism (matches Gramine 1.9, verified in Phase 0):
//   - hash the certificate's SubjectPublicKeyInfo (SPKI) with SHA-512,
//   - write that 64-byte digest to /dev/attestation/user_report_data,
//   - read the DCAP quote back from /dev/attestation/quote,
//   - embed the quote in an X.509 extension so it travels inside the TLS cert.
//
// The client re-derives SHA-512(SPKI) from the presented cert and checks it
// equals the quote's report_data — this binds the attested enclave identity to
// THIS TLS channel (anti-relay). See pkg/... client verifier.
//
// PURITY: stdlib + crypto only. No dto/common/logger/model/service/setting.
//
// Outside a real enclave (e.g. local dev on macOS) the /dev/attestation pseudo-
// files are absent; BuildCert falls back to a plain self-signed cert with NO
// quote extension and Attested=false, so development still works while making
// the missing attestation explicit.
package raenclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"time"
)

// Gramine attestation pseudo-files.
const (
	attnTypePath   = "/dev/attestation/attestation_type"
	reportDataPath = "/dev/attestation/user_report_data"
	quotePath      = "/dev/attestation/quote"
)

// raTLSQuoteOID is the X.509 extension OID under which the raw SGX quote is
// carried. Gramine 1.9 uses the legacy Intel RA-TLS OID 1.2.840.113741.1337.6
// for the raw quote (the newer TCG DICE tagged-evidence OID 2.23.133.5.4.9 wraps
// it in CBOR). We embed the raw quote under the legacy OID; the verifier reads
// this extension. (Confirmed against the Gramine v1.9 source in doc 02.)
var raTLSQuoteOID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1337, 6}

// Cert is the result of BuildCert.
type Cert struct {
	TLS      tls.Certificate
	Attested bool   // true iff a real DCAP quote was embedded
	Quote    []byte // the raw quote (nil when not attested)
	ReportData [64]byte
}

// Available reports whether we appear to be running inside a Gramine SGX enclave
// with DCAP attestation wired (the pseudo-files exist).
func Available() bool {
	if _, err := os.Stat(quotePath); err != nil {
		return false
	}
	if _, err := os.Stat(reportDataPath); err != nil {
		return false
	}
	return true
}

// BuildCert generates an ephemeral EC keypair, builds a self-signed leaf cert,
// and — inside an enclave — binds it to a DCAP quote via report_data. The
// private key never leaves the process and is never written to disk.
func BuildCert(dnsName string) (*Cert, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{dnsName},
	}

	// Marshal SPKI to hash it. We create a throwaway cert first to obtain the
	// DER SPKI, compute report_data, then (if in enclave) fetch the quote and
	// re-issue the cert WITH the quote extension.
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	reportData := sha512.Sum512(spki)

	out := &Cert{ReportData: reportData}

	if Available() {
		quote, qerr := fetchQuote(reportData)
		if qerr != nil {
			return nil, qerr
		}
		out.Quote = quote
		out.Attested = true
		tmpl.ExtraExtensions = []pkix.Extension{{
			Id:    raTLSQuoteOID,
			Value: quote,
		}}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	out.TLS = tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        tmpl,
	}
	return out, nil
}

// SealKeyFile writes an upstream secret (e.g. the provider API key) to a path
// that is a Gramine "encrypted" mount keyed by _sgx_mrenclave. Gramine
// transparently encrypts the bytes with the MRENCLAVE-sealing key before they
// touch the host disk, so the host only ever sees ciphertext and cannot derive
// the key. This is a SECRET-PROVISIONING write, never request/response content —
// the enclave leak-guard exempts os.WriteFile in this package for exactly this
// (audited) reason. Called once at first boot; subsequent boots just read.
func SealKeyFile(path, secret string) error {
	if secret == "" {
		return errors.New("refusing to seal empty secret")
	}
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		return errors.New("seal key file: " + err.Error())
	}
	return nil
}

// fetchQuote writes report_data to the Gramine pseudo-file and reads the quote.
// The write MUST happen before the read (Gramine binds the last-written
// report_data into the produced quote).
func fetchQuote(reportData [64]byte) ([]byte, error) {
	if err := os.WriteFile(reportDataPath, reportData[:], 0); err != nil {
		return nil, errors.New("write user_report_data: " + err.Error())
	}
	quote, err := os.ReadFile(quotePath)
	if err != nil {
		return nil, errors.New("read quote: " + err.Error())
	}
	if len(quote) == 0 {
		return nil, errors.New("empty quote from /dev/attestation/quote")
	}
	return quote, nil
}
