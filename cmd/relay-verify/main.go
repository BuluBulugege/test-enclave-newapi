// Command relay-verify is the client-side attestation verifier for relay-core.
// A user runs it BEFORE trusting the gateway with prompts. It fetches the
// enclave's DCAP quote, checks the enclave measurement (MRENCLAVE) against a
// value the user supplies out-of-band, and confirms the quote is bound to the
// TLS key the gateway is actually presenting (report_data == SHA-512(SPKI)).
//
// TRUST MODEL (critical, see docs/cc-research/07-client-verifier.md): the
// expected MRENCLAVE MUST come from the user (flag/file from a signed release),
// NEVER from the gateway — otherwise a malicious gateway could self-attest. This
// tool treats the gateway as untrusted: it independently extracts the quote from
// the presented TLS certificate and cross-checks the report_data binding.
//
// Full DCAP signature-chain verification (PCK -> Intel SGX Root CA via
// collateral) requires the platform DCAP quote-verification library and is run
// with --dcap-verify on a machine that has libsgx_dcap_quoteverify (e.g. the
// SGX host or any Linux box with the Intel DCAP QVL). Without it, this tool does
// structural + MRENCLAVE + channel-binding checks and clearly says the signature
// chain was NOT cryptographically verified.
package main

import (
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
)

// raTLSQuoteOID mirrors pkg/raenclave: the legacy Intel RA-TLS OID under which
// relay-core embeds the raw SGX quote in its TLS certificate.
var raTLSQuoteOID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1337, 6}

// SGX quote layout offsets (ECDSA quote v3, little-endian fields). We only parse
// the report body fields we need: MRENCLAVE and REPORT_DATA.
//   quote header:            48 bytes
//   report body starts at:   48
//   mr_enclave offset in body: 64 (len 32)
//   report_data offset in body: 320 (len 64)
const (
	quoteHeaderLen     = 48
	mrEnclaveBodyOff   = 64
	mrEnclaveLen       = 32
	reportDataBodyOff  = 320
	reportDataLen      = 64
	minQuoteLen        = quoteHeaderLen + reportDataBodyOff + reportDataLen
)

func main() {
	var (
		addr          = flag.String("addr", "", "relay-core host:port (e.g. 1.2.3.4:8443)")
		expectedMRE   = flag.String("mrenclave", "", "expected MRENCLAVE (hex), obtained out-of-band from a signed release")
		allowUnbound  = flag.Bool("allow-unbound", false, "skip the report_data<->TLS-pubkey binding check (NOT recommended)")
		dcapVerify    = flag.Bool("dcap-verify", false, "cryptographically verify the quote's signature chain to the Intel SGX root (needs a -tags dcap build)")
		allowOutdated = flag.Bool("allow-outdated", false, "accept a verified quote whose platform TCB is out of date (weaker posture)")
	)
	flag.Parse()

	if *addr == "" || *expectedMRE == "" {
		fmt.Fprintln(os.Stderr, "usage: relay-verify -addr host:port -mrenclave <hex>")
		os.Exit(2)
	}
	want, err := hex.DecodeString(*expectedMRE)
	if err != nil || len(want) != mrEnclaveLen {
		fmt.Fprintf(os.Stderr, "invalid -mrenclave: must be %d hex bytes\n", mrEnclaveLen)
		os.Exit(2)
	}

	cert, err := fetchLeafCert(*addr)
	if err != nil {
		fail("could not obtain server certificate: " + err.Error())
	}

	quote, err := extractQuote(cert)
	if err != nil {
		fail("no RA-TLS quote in server certificate: " + err.Error() +
			"\n  -> the gateway is NOT presenting an attested enclave certificate.")
	}

	// Check 0 (the crucial anti-forgery step): verify the quote's signature chain
	// to the Intel SGX Root CA. Without this, a server could present a quote with
	// the right MRENCLAVE bytes but no valid Intel signature and fool the
	// structural checks below. This requires a -tags dcap build.
	dcapChecked := false
	if *dcapVerify {
		if !dcapVerifyAvailable {
			fail("-dcap-verify requested but this binary has no DCAP support.\n" +
				"  rebuild: CGO_ENABLED=1 go build -tags dcap ./cmd/relay-verify (needs libsgx_dcap_quoteverify)")
		}
		result, status, verr := verifyQuoteChain(quote)
		if verr != nil {
			fail("DCAP quote verification could not complete: " + verr.Error() +
				"\n  -> could not establish the quote is genuine; do NOT trust this endpoint.")
		}
		switch classifyQVResult(result) {
		case "fail":
			fail(fmt.Sprintf("DCAP SIGNATURE-CHAIN VERIFICATION FAILED: %s (0x%X)\n"+
				"  -> the quote is not a genuine Intel-signed SGX quote (forged/revoked).", status, result))
		case "outdated":
			if !*allowOutdated {
				fail(fmt.Sprintf("quote verified but platform TCB is OUT OF DATE: %s (0x%X)\n"+
					"  -> pass -allow-outdated to accept this weaker posture, or update the platform.", status, result))
			}
			fmt.Printf("⚠️  DCAP chain verified, TCB out-of-date accepted (-allow-outdated): %s\n", status)
		default: // pass
			fmt.Printf("✅ DCAP signature chain verified to Intel SGX root: %s\n", status)
		}
		dcapChecked = true
	}

	mre, reportData, err := parseQuote(quote)
	if err != nil {
		fail("malformed quote: " + err.Error())
	}

	// Check 1: MRENCLAVE matches the user-supplied expected value.
	if !bytesEqual(mre, want) {
		fail(fmt.Sprintf("MRENCLAVE MISMATCH\n  got:      %s\n  expected: %s\n"+
			"  -> the enclave running is NOT the audited no-log build you pinned.",
			hex.EncodeToString(mre), *expectedMRE))
	}

	// Check 2: report_data binds the quote to THIS TLS channel's public key.
	if !*allowUnbound {
		spki := cert.RawSubjectPublicKeyInfo
		want := sha512.Sum512(spki)
		if !bytesEqual(reportData, want[:]) {
			fail("REPORT_DATA BINDING FAILED\n" +
				"  the quote is not bound to the TLS key the gateway presented\n" +
				"  -> possible relay/MITM: the quote may belong to a different enclave.")
		}
	}

	if dcapChecked {
		fmt.Println("✅ VERIFICATION PASSED (DCAP signature-chain + MRENCLAVE + channel-binding)")
		fmt.Printf("   MRENCLAVE:   %s\n", hex.EncodeToString(mre))
		fmt.Printf("   report_data: %s\n", hex.EncodeToString(reportData)[:32]+"...")
		fmt.Println("   The quote is a genuine Intel-signed SGX quote, its measurement matches")
		fmt.Println("   the pinned no-log build, and it is bound to this TLS channel. Safe to send prompts.")
	} else {
		fmt.Println("⚠️  PARTIAL PASS (structural + MRENCLAVE + channel-binding; signature chain NOT verified)")
		fmt.Printf("   MRENCLAVE:   %s\n", hex.EncodeToString(mre))
		fmt.Printf("   report_data: %s\n", hex.EncodeToString(reportData)[:32]+"...")
		fmt.Println("   WARNING: without -dcap-verify the quote's authenticity was NOT checked — a forged")
		fmt.Println("   quote could pass. Re-run with -dcap-verify (needs a -tags dcap build) before trusting.")
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "❌ VERIFICATION FAILED")
	fmt.Fprintln(os.Stderr, "   "+msg)
	os.Exit(1)
}

// fetchLeafCert performs a TLS handshake (skipping chain verification, since the
// cert is self-signed by design — trust comes from the QUOTE, not a CA) and
// returns the leaf certificate.
func fetchLeafCert(addr string) (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // trust is established via the quote, not PKI
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("server presented no certificate")
	}
	return certs[0], nil
}

// extractQuote pulls the raw quote from the RA-TLS X.509 extension.
func extractQuote(cert *x509.Certificate) ([]byte, error) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(raTLSQuoteOID) {
			if len(ext.Value) == 0 {
				return nil, errors.New("quote extension present but empty")
			}
			return ext.Value, nil
		}
	}
	return nil, errors.New("RA-TLS quote OID not found")
}

// parseQuote extracts MRENCLAVE and REPORT_DATA from an SGX ECDSA quote.
func parseQuote(q []byte) (mrEnclave, reportData []byte, err error) {
	if len(q) < minQuoteLen {
		return nil, nil, fmt.Errorf("quote too short: %d < %d", len(q), minQuoteLen)
	}
	mrOff := quoteHeaderLen + mrEnclaveBodyOff
	rdOff := quoteHeaderLen + reportDataBodyOff
	mrEnclave = q[mrOff : mrOff+mrEnclaveLen]
	reportData = q[rdOff : rdOff+reportDataLen]
	return mrEnclave, reportData, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
