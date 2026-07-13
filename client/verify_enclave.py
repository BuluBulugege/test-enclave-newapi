#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_enclave.py — Client-side verifier for the confidential-computing
relay-core enclave (see README / whitepaper).

WHAT THIS PROVES, AND HOW  (the "verification manual")
======================================================
You are about to send prompts to an AI gateway. Normally you must TRUST the
operator not to read or log them. This tool lets you replace that trust with a
hardware-backed proof, BEFORE you send anything, in three checks:

  Check 1 — Structure & liveness
      Connect to the endpoint and fetch its remote-attestation "quote": a blob
      the Intel SGX CPU produces that describes the exact code running inside
      the enclave.

  Check 2 — Measurement match (MRENCLAVE)
      MRENCLAVE is a cryptographic hash of the exact enclave code + config,
      computed by the CPU (like a Docker image digest, but hardware-enforced).
      We compare it to a value YOU obtained out-of-band (a signed release /
      a reproducible rebuild). If it matches, the running code is byte-for-byte
      the audited, no-content-storage, official-URL-enforcing build.

  Check 3 — Channel binding (anti-relay)
      The quote embeds SHA-512 of the enclave's TLS public key in its
      "report_data" field. We take the TLS certificate the server actually
      presented, hash its public key the same way, and require it to equal the
      quote's report_data. This proves the attested enclave IS the endpoint you
      are talking to — a operator cannot forward someone else's quote.

IMPORTANT HONESTY NOTE
======================
This pure-Python tool does Checks 1–3 (structure + MRENCLAVE pin + channel
binding). It does NOT, by itself, cryptographically verify that the quote was
signed by Intel (the "DCAP signature chain"). That final step — which makes a
forged quote impossible — is done by the DCAP quote-verification library
(Intel libsgx_dcap_quoteverify), e.g. the companion Go tool:

    CGO_ENABLED=1 go build -tags dcap ./cmd/relay-verify
    ./relay-verify -addr <host:port> -mrenclave <hex> -dcap-verify

For full, non-repudiable assurance, run BOTH: this script (readable, no deps for
the core checks) AND the DCAP chain verification. This script clearly labels its
result as PARTIAL unless the chain is also verified.

USAGE
=====
    python3 verify_enclave.py --addr 8.217.148.82:8443 \
        --mrenclave 4aa951d16a0c237605f032cd480095b65be1f485e9f7a959a16f38a80428a445

Only the standard library is required for Checks 1 & 2. Check 3 (channel
binding) additionally uses the `cryptography` package if available
(`pip install cryptography`); without it, Check 3 is skipped with a notice.
"""

import argparse
import base64
import hashlib
import json
import ssl
import sys
import urllib.request

# --- SGX ECDSA quote layout (little-endian). We read two fixed-offset fields. --
QUOTE_HEADER_LEN = 48
MRENCLAVE_OFFSET = QUOTE_HEADER_LEN + 64   # report body starts at 48; mr_enclave at +64
MRENCLAVE_LEN = 32
REPORTDATA_OFFSET = QUOTE_HEADER_LEN + 320  # report_data at +320 in the body
REPORTDATA_LEN = 64

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
RESET = "\033[0m"


def unverified_ctx():
    # We deliberately do NOT verify the TLS chain against a CA: this is an
    # RA-TLS self-signed certificate. Trust is established by the SGX QUOTE, not
    # by PKI. (Same reason `curl -k` is correct here.)
    ctx = ssl._create_unverified_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_attestation(host, port):
    url = f"https://{host}:{port}/attestation"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20, context=unverified_ctx()) as r:
        body = r.read()
    doc = json.loads(body)
    if not doc.get("attested"):
        raise RuntimeError(
            "endpoint reports attested=false: it is NOT running inside an SGX "
            "enclave (reason: %s)" % doc.get("reason", "unknown"))
    quote = base64.b64decode(doc["quote_b64"])
    report_data_hex = doc.get("report_data_hex", "")
    return quote, report_data_hex


def get_peer_cert_der(host, port):
    ctx = unverified_ctx()
    with ssl.create_connection((host, int(port)), timeout=20) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(binary_form=True)


def spki_sha512(cert_der):
    """SHA-512 of the certificate's SubjectPublicKeyInfo (matches how the
    enclave binds its TLS key into the quote). Needs the `cryptography` pkg."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return None
    cert = x509.load_der_x509_certificate(cert_der)
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha512(spki).digest()


def parse_quote(quote):
    if len(quote) < REPORTDATA_OFFSET + REPORTDATA_LEN:
        raise RuntimeError("quote too short (%d bytes); malformed" % len(quote))
    mrenclave = quote[MRENCLAVE_OFFSET:MRENCLAVE_OFFSET + MRENCLAVE_LEN]
    report_data = quote[REPORTDATA_OFFSET:REPORTDATA_OFFSET + REPORTDATA_LEN]
    return mrenclave, report_data


def main():
    ap = argparse.ArgumentParser(description="Verify a relay-core SGX enclave.")
    ap.add_argument("--addr", default="8.217.148.82:8443",
                    help="enclave host:port (default: %(default)s)")
    ap.add_argument("--mrenclave", required=True,
                    help="expected MRENCLAVE (64 hex chars), from a signed "
                         "release or your own reproducible rebuild")
    args = ap.parse_args()

    host, _, port = args.addr.partition(":")
    port = port or "8443"
    want_mre = args.mrenclave.strip().lower()
    if len(want_mre) != 64:
        print(f"{RED}✗ --mrenclave must be 64 hex chars{RESET}")
        sys.exit(2)

    print(f"{BOLD}Verifying enclave at {host}:{port}{RESET}\n")

    # ---- Check 1: fetch quote (structure + liveness) --------------------------
    try:
        quote, report_data_hex = fetch_attestation(host, port)
        mrenclave, report_data = parse_quote(quote)
    except Exception as e:
        print(f"{RED}✗ Check 1 FAILED — could not obtain a valid quote: {e}{RESET}")
        sys.exit(1)
    print(f"{GREEN}✓ Check 1{RESET} quote obtained ({len(quote)} bytes) and parsed")

    # ---- Check 2: MRENCLAVE pin ----------------------------------------------
    got_mre = mrenclave.hex()
    if got_mre != want_mre:
        print(f"{RED}✗ Check 2 FAILED — MRENCLAVE MISMATCH{RESET}")
        print(f"    running : {got_mre}")
        print(f"    expected: {want_mre}")
        print(f"    → the enclave is NOT the audited build you pinned. Do not trust it.")
        sys.exit(1)
    print(f"{GREEN}✓ Check 2{RESET} MRENCLAVE matches the pinned value")
    print(f"    {got_mre}")

    # ---- Check 3: channel binding (report_data == SHA-512(TLS pubkey)) --------
    binding_ok = None
    try:
        cert_der = get_peer_cert_der(host, port)
        want_rd = spki_sha512(cert_der)
    except Exception as e:
        want_rd = None
        print(f"{YELLOW}! Check 3 skipped — could not read TLS cert: {e}{RESET}")

    if want_rd is None:
        print(f"{YELLOW}! Check 3 skipped — install `cryptography` "
              f"(pip install cryptography) to bind the quote to this TLS channel{RESET}")
    else:
        binding_ok = (want_rd == report_data)
        if not binding_ok:
            print(f"{RED}✗ Check 3 FAILED — report_data does not match the TLS key{RESET}")
            print(f"    → possible relay/MITM: this quote may belong to a different enclave.")
            sys.exit(1)
        print(f"{GREEN}✓ Check 3{RESET} quote is bound to THIS TLS channel "
              f"(report_data == SHA-512(server pubkey))")

    # ---- Verdict --------------------------------------------------------------
    print()
    if binding_ok:
        print(f"{GREEN}{BOLD}RESULT: PARTIAL PASS (structure + MRENCLAVE + channel binding){RESET}")
    else:
        print(f"{YELLOW}{BOLD}RESULT: PARTIAL PASS (structure + MRENCLAVE; channel binding not checked){RESET}")
    print(f"{YELLOW}  The quote's Intel signature chain was NOT verified by this script.{RESET}")
    print(f"{YELLOW}  For full assurance also run the DCAP chain check:{RESET}")
    print(f"    ./relay-verify -addr {host}:{port} -mrenclave {want_mre} -dcap-verify")
    print(f"\n  Once BOTH pass, you are provably talking to the genuine, audited,")
    print(f"  no-content-storage enclave — safe to send prompts.")


if __name__ == "__main__":
    main()
