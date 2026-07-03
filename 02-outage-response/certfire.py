#!/usr/bin/env python3
"""
certfire — certificate outage response tool.

Given a broken hostname, names the root cause in plain English and stages
everything needed to push a replacement: a fresh private key, a CSR
pre-filled from the broken certificate's Subject/SANs, and a deployment
checklist.

Usage:
    python3 certfire.py diagnose <host:port>
    python3 certfire.py stage <host:port> --out <dir> [--reuse-key]
    python3 certfire.py verify <host:port> --expect-not-after <YYYY-MM-DD>
"""
import argparse
import os
import socket
import ssl
import sys
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

NETWORK_TIMEOUT = 8


def fetch_certificate(host: str, port: int):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    with socket.create_connection((host, port), timeout=NETWORK_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(True)
            proto = ssock.version()
    return x509.load_der_x509_certificate(der), proto


def diagnose_cert(cert: x509.Certificate, host: str):
    now = datetime.now(timezone.utc)
    if cert.not_valid_after_utc < now:
        days = (now - cert.not_valid_after_utc).days
        return "EXPIRED", f"Expired on:    {cert.not_valid_after_utc.date()}  ({days} days ago)"
    if cert.not_valid_before_utc > now:
        return "NOT YET VALID", f"Not valid until: {cert.not_valid_before_utc.date()}"

    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    bare_host = host.split(":")[0]
    name_ok = bare_host in sans or any(
        san.startswith("*.") and bare_host.endswith(san[1:]) for san in sans
    )
    if not name_ok and sans:
        return "NAME MISMATCH", f"Certificate covers {', '.join(sans)}, not {bare_host}"

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
        return "WEAK KEY", f"RSA key size is only {pub.key_size} bits"

    return "HEALTHY", "No issues detected — certificate is currently valid."


def cmd_diagnose(args):
    host = args.target
    print("[ DIAGNOSIS ]")
    print(f"  Host:          {host}")
    try:
        cert, _proto = fetch_certificate(*split_target(host))
    except Exception as exc:
        print(f"  Verdict:       UNREACHABLE")
        print(f"  Detail:        {exc}")
        return 1

    verdict, detail = diagnose_cert(cert, host)
    print(f"  Verdict:       {verdict}")
    for line in detail.split("\n"):
        key, _, rest = line.partition(":")
        print(f"  {key}:{' ' * max(1, 14 - len(key))}{rest.strip()}")
    print(f"  Issuer:        {cert.issuer.rfc4514_string()}")
    print(f"  Subject:       {cert.subject.rfc4514_string()}")

    print("\n[ STAGE THIS NEXT ]")
    print(f"  python3 certfire.py stage {host} --out ./replacement")
    print("  -> writes replacement/key.pem, replacement/req.csr, replacement/CHECKLIST.md")

    print("\nEstimated time-to-recovery if you have a CA on standby: ~15 minutes.")
    return 0


def split_target(target: str):
    if ":" in target:
        host, port = target.rsplit(":", 1)
        return host, int(port)
    return target, 443


def cmd_stage(args):
    host, port = split_target(args.target)
    try:
        cert, _ = fetch_certificate(host, port)
    except Exception as exc:
        print(f"ERROR: could not retrieve original certificate ({exc})")
        return 1

    os.makedirs(args.out, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = os.path.join(args.out, "key.pem")
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = [host]

    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(cert.subject)
    if sans:
        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    csr = csr_builder.sign(key, hashes.SHA256())
    csr_path = os.path.join(args.out, "req.csr")
    with open(csr_path, "wb") as fh:
        fh.write(csr.public_bytes(serialization.Encoding.PEM))

    checklist_path = os.path.join(args.out, "CHECKLIST.md")
    with open(checklist_path, "w") as fh:
        fh.write(
            f"# Replacement checklist for {host}\n\n"
            f"1. Submit `req.csr` to your CA.\n"
            f"2. Retrieve the signed certificate and full chain.\n"
            f"3. Deploy the new certificate + `key.pem` to the load balancer / server.\n"
            f"4. Verify with: `python3 certfire.py verify {host} --expect-not-after <new-date>`\n"
        )

    print(f"Staged replacement for {host}:")
    print(f"  {key_path}")
    print(f"  {csr_path}")
    print(f"  {checklist_path}")
    return 0


def cmd_verify(args):
    host, port = split_target(args.target)
    try:
        cert, _ = fetch_certificate(host, port)
    except Exception as exc:
        print(f"FAIL  {host}  -- unreachable ({exc})")
        return 1

    expect = datetime.strptime(args.expect_not_after, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    live_not_after = cert.not_valid_after_utc
    if live_not_after.date() >= expect.date():
        print(f"PASS  {host}  not_after={live_not_after.date()}  issuer={cert.issuer.rfc4514_string()}")
        return 0
    print(f"FAIL  {host}  not_after={live_not_after.date()}  -- expected on/after {expect.date()}")
    return 1


def main():
    parser = argparse.ArgumentParser(prog="certfire.py")
    sub = parser.add_subparsers(dest="command", required=True)

    p_diag = sub.add_parser("diagnose")
    p_diag.add_argument("target")
    p_diag.set_defaults(func=cmd_diagnose)

    p_stage = sub.add_parser("stage")
    p_stage.add_argument("target")
    p_stage.add_argument("--out", required=True)
    p_stage.add_argument("--reuse-key", action="store_true")
    p_stage.set_defaults(func=cmd_stage)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("target")
    p_verify.add_argument("--expect-not-after", required=True)
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
