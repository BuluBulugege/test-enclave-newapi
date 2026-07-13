//go:build dcap

package main

/*
#cgo LDFLAGS: -lsgx_dcap_quoteverify
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sgx_ql_lib_common.h"
#include "sgx_dcap_quoteverify.h"

// rv_verify verifies an SGX ECDSA quote's signature chain (PCK -> Intel SGX Root
// CA) and TCB status. Passing NULL collateral makes the quote-verification
// library fetch the required collateral (TCBInfo, QEIdentity, CRLs) via the
// default QPL, which on this platform points at the Alibaba cn-hongkong PCCS.
// Returns the library call status (0 == SGX_QL_SUCCESS) and writes the
// verification verdict into *qv_result (an sgx_ql_qv_result_t).
static int rv_verify(const uint8_t *quote, uint32_t quote_len,
                     uint32_t *coll_exp_status, uint32_t *qv_result) {
    uint32_t supp_size = 0;
    uint8_t *supp = NULL;
    if (sgx_qv_get_quote_supplemental_data_size(&supp_size) == SGX_QL_SUCCESS && supp_size > 0) {
        supp = (uint8_t*)malloc(supp_size);
        if (!supp) return -1;
        memset(supp, 0, supp_size);
    } else {
        supp_size = 0;
    }

    time_t now = time(NULL);
    sgx_ql_qv_result_t result = SGX_QL_QV_RESULT_UNSPECIFIED;
    quote3_error_t ret = sgx_qv_verify_quote(
        quote, quote_len,
        NULL,                 // collateral: NULL => fetch via default QPL (Alibaba PCCS)
        now,
        coll_exp_status,
        &result,
        NULL,                 // no QvE report (trusting the in-process QVL)
        supp_size, supp);

    if (supp) free(supp);
    *qv_result = (uint32_t)result;
    return (int)ret;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// dcapVerifyAvailable is true: this build links libsgx_dcap_quoteverify.
const dcapVerifyAvailable = true

// verifyQuoteChain cryptographically verifies that the quote is a genuine
// Intel-signed SGX quote (signature chain to the Intel SGX Root CA) and returns
// the TCB verification verdict. A forged quote (e.g. one with the right
// MRENCLAVE bytes but no valid Intel signature) makes this return a non-pass
// result, which is exactly the check the structural parser cannot do.
func verifyQuoteChain(quote []byte) (uint32, string, error) {
	if len(quote) == 0 {
		return 0, "", fmt.Errorf("empty quote")
	}
	var collExp C.uint32_t
	var qvResult C.uint32_t
	ret := C.rv_verify(
		(*C.uint8_t)(unsafe.Pointer(&quote[0])),
		C.uint32_t(len(quote)),
		&collExp,
		&qvResult,
	)
	if int(ret) != 0 {
		return uint32(qvResult), "", fmt.Errorf(
			"sgx_qv_verify_quote returned library error 0x%x (collateral fetch or malformed quote)", int(ret))
	}
	res := uint32(qvResult)
	return res, qvResultString(res), nil
}
