package main

// SGX DCAP quote-verification result codes (sgx_ql_qv_result_t). These classify
// the outcome of the signature-chain + TCB verification performed by
// sgx_qv_verify_quote (see dcap_cgo.go). 0x0000 is fully trusted; the 0xA00x
// values are verified-but-with-platform-caveats or hard failures.
const (
	qvOK              = 0x0000 // fully up-to-date, trusted
	qvConfigNeeded    = 0xA001 // verified; platform config advisory
	qvOutOfDate       = 0xA002 // verified; TCB out of date
	qvOutOfDateConfig = 0xA003 // verified; TCB out of date + config
	qvInvalidSig      = 0xA004 // FAIL: signature did not verify
	qvRevoked         = 0xA005 // FAIL: key/cert revoked
	qvUnspecified     = 0xA006 // FAIL: unspecified error
	qvSWHardening     = 0xA007 // verified; SW hardening advisory
	qvConfigSWHard    = 0xA008 // verified; config + SW hardening advisory
)

func qvResultString(r uint32) string {
	switch r {
	case qvOK:
		return "OK (up-to-date, trusted)"
	case qvConfigNeeded:
		return "CONFIG_NEEDED (verified; platform config advisory)"
	case qvOutOfDate:
		return "OUT_OF_DATE (verified; TCB out of date)"
	case qvOutOfDateConfig:
		return "OUT_OF_DATE_CONFIG_NEEDED (verified; TCB out of date + config)"
	case qvInvalidSig:
		return "INVALID_SIGNATURE (FAIL)"
	case qvRevoked:
		return "REVOKED (FAIL)"
	case qvUnspecified:
		return "UNSPECIFIED (FAIL)"
	case qvSWHardening:
		return "SW_HARDENING_NEEDED (verified; SW hardening advisory)"
	case qvConfigSWHard:
		return "CONFIG_AND_SW_HARDENING_NEEDED (verified; config + SW hardening advisory)"
	default:
		return "unknown quote-verification result"
	}
}

// classifyQVResult maps a result code to an acceptance decision.
//   - "pass": the quote's signature chain verified to the Intel SGX root and the
//     TCB is acceptable (OK, or an advisory-only status).
//   - "outdated": verified signature but TCB is out of date — accepted ONLY when
//     the caller passes -allow-outdated (documents a known-weaker posture).
//   - "fail": the quote is not trustworthy (bad signature, revoked, unspecified).
func classifyQVResult(r uint32) string {
	switch r {
	case qvOK, qvConfigNeeded, qvSWHardening, qvConfigSWHard:
		return "pass"
	case qvOutOfDate, qvOutOfDateConfig:
		return "outdated"
	default:
		return "fail"
	}
}
