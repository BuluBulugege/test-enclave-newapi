//go:build !dcap

package main

import "errors"

// dcapVerifyAvailable is false in the default (pure-Go, no-cgo) build. The
// structural + MRENCLAVE + channel-binding checks still work; only the
// cryptographic signature-chain verification is unavailable.
const dcapVerifyAvailable = false

// verifyQuoteChain is a no-op stub when built without -tags dcap. Real DCAP
// verification (dcap_cgo.go) needs libsgx_dcap_quoteverify + cgo.
func verifyQuoteChain(quote []byte) (uint32, string, error) {
	return 0, "", errors.New(
		"this relay-verify build has NO DCAP signature-chain support; " +
			"rebuild on a host with libsgx_dcap_quoteverify:  " +
			"CGO_ENABLED=1 go build -tags dcap ./cmd/relay-verify")
}
