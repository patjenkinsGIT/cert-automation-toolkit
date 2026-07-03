#!/usr/bin/env python3
"""
certrecon — PKI discovery & inventory tool.

Sweeps hosts, retrieves their leaf certificate, checks OCSP/CRL revocation
status, and writes a clean inventory CSV. No agents, no SaaS, no telemetry
leaving the network it runs on.

Usage:
    python3 certrecon.py inspect <host:port> [--check-revocation]
    python3 certrecon.py sweep --targets targets.txt --out inventory.csv [--check-revocation]
    python3 certrecon.py report --inventory inventory.csv --expiring-within <days>
"""
import argparse
import csv
import socket
import ssl
import sys
import urllib.request
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.ocsp import OCSPCertStatus, OCSPRequestBuilder, load_der_ocsp_response

NETWORK_TIMEOUT = 8


def fetch_certificate(host: str, port: int):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT@SECLEVEL=1")
    with socket.create_connection((host, port), timeout=NETWORK_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(True)
            chain_der = []
            try:
                chain_der = [c.public_bytes(ssl.Encoding.DER) for c in ssock.get_verified_chain()]
            except Exception:
                chain_der = []
    cert = x509.load_der_x509_certificate(der)
    chain = [x509.load_der_x509_certificate(c) for c in chain_der] if chain_der else []
    return cert, chain


def key_summary(cert: x509.Certificate) -> str:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA-{pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC-{pub.curve.name}"
    return pub.__class__.__name__


def get_sans(cert: x509.Certificate):
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def get_aia_urls(cert: x509.Certificate):
    ocsp_urls, issuer_urls = [], []
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        for desc in aia.value:
            url = desc.access_location.value
            if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                ocsp_urls.append(url)
            elif desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                issuer_urls.append(url)
    except x509.ExtensionNotFound:
        pass
    return ocsp_urls, issuer_urls


def get_crl_urls(cert: x509.Certificate):
    try:
        cdp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        urls = []
        for dp in cdp.value:
            if dp.full_name:
                for name in dp.full_name:
                    if isinstance(name, x509.UniformResourceIdentifier):
                        urls.append(name.value)
        return urls
    except x509.ExtensionNotFound:
        return []


def fetch_issuer_cert(issuer_urls):
    for url in issuer_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "certrecon/1.0"})
            data = urllib.request.urlopen(req, timeout=NETWORK_TIMEOUT).read()
            try:
                return x509.load_der_x509_certificate(data)
            except ValueError:
                return x509.load_pem_x509_certificate(data)
        except Exception:
            continue
    return None


def check_ocsp(cert: x509.Certificate, issuer: x509.Certificate, ocsp_urls):
    if not issuer or not ocsp_urls:
        return "N/A", None
    try:
        builder = OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1())
        req = builder.build()
        req_der = req.public_bytes(ssl.Encoding.DER) if hasattr(req, "public_bytes") else req.public_bytes()
    except Exception:
        return "N/A", None
    from cryptography.hazmat.primitives.serialization import Encoding as SerEncoding
    req_der = req.public_bytes(SerEncoding.DER)
    for url in ocsp_urls:
        try:
            http_req = urllib.request.Request(
                url,
                data=req_der,
                headers={"Content-Type": "application/ocsp-request", "User-Agent": "certrecon/1.0"},
            )
            resp_der = urllib.request.urlopen(http_req, timeout=NETWORK_TIMEOUT).read()
            resp = load_der_ocsp_response(resp_der)
            if resp.certificate_status == OCSPCertStatus.REVOKED:
                reason = resp.revocation_reason.value if resp.revocation_reason else "unspecified"
                return "REVOKED", reason
            if resp.certificate_status == OCSPCertStatus.GOOD:
                return "GOOD", None
            return "UNKNOWN", None
        except Exception:
            continue
    return "N/A", None


def check_crl(cert: x509.Certificate, crl_urls):
    for url in crl_urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "certrecon/1.0"})
            data = urllib.request.urlopen(req, timeout=NETWORK_TIMEOUT).read()
            try:
                crl = x509.load_der_x509_crl(data)
            except ValueError:
                crl = x509.load_pem_x509_crl(data)
            entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
            if entry is not None:
                return "REVOKED", entry
            return "GOOD", None
        except Exception:
            continue
    return "N/A", None


def cmd_inspect(args):
    target = args.target
    if ":" in target:
        host, port_s = target.rsplit(":", 1)
        port = int(port_s)
    else:
        host, port = target, 443

    print(f"Host: {host}:{port}")
    try:
        cert, chain = fetch_certificate(host, port)
    except Exception as exc:
        print(f"  ERROR: could not retrieve certificate ({exc})")
        print("\n1 host inspected, 0 REVOKED.")
        return 1

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    now = datetime.now(timezone.utc)
    days_left = (not_after - now).days
    sans = get_sans(cert)

    print(f"  Subject:     {subject}")
    print(f"  Issuer:      {issuer}")
    print(f"  Not Before:  {not_before.date()}")
    if days_left >= 0:
        print(f"  Not After:   {not_after.date()}  (in {days_left} days)")
    else:
        print(f"  Not After:   {not_after.date()}  ({-days_left} days ago)")
    print(f"  Key:         {key_summary(cert)}")
    print(f"  SANs:        {', '.join(sans) if sans else '(none)'}")

    revoked_count = 0
    if args.check_revocation:
        ocsp_urls, issuer_urls = get_aia_urls(cert)
        crl_urls = get_crl_urls(cert)

        issuer_cert = chain[0] if chain else fetch_issuer_cert(issuer_urls)
        ocsp_status, ocsp_reason = check_ocsp(cert, issuer_cert, ocsp_urls)
        crl_status, crl_entry = check_crl(cert, crl_urls)

        if ocsp_status == "REVOKED":
            print(f"  OCSP:        REVOKED  (reason: {ocsp_reason})")
        else:
            print(f"  OCSP:        {ocsp_status}")

        if crl_status == "REVOKED":
            print("  CRL:         REVOKED")
        else:
            print(f"  CRL:         {crl_status}")

        if ocsp_status == "REVOKED" or crl_status == "REVOKED":
            revoked_count = 1
            agree = ocsp_status == "REVOKED" and crl_status == "REVOKED"
            basis = "CRL + OCSP agree" if agree else ("CRL" if crl_status == "REVOKED" else "OCSP")
            print(f"  -> Status:   REVOKED ({basis})")
        elif ocsp_status == "GOOD" or crl_status == "GOOD":
            print("  -> Status:   VALID (not revoked)")
        else:
            print("  -> Status:   UNKNOWN (no OCSP/CRL responder reachable)")

    print(f"\n1 host inspected, {revoked_count} REVOKED.")
    return 0


def cmd_sweep(args):
    with open(args.targets) as fh:
        targets = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

    rows = []
    revoked_total = 0
    for target in targets:
        host, port = (target.rsplit(":", 1) + ["443"])[:2] if ":" in target else (target, "443")
        try:
            cert, chain = fetch_certificate(host, int(port))
        except Exception as exc:
            print(f"  {target}: ERROR ({exc})")
            continue
        status = ""
        if args.check_revocation:
            ocsp_urls, issuer_urls = get_aia_urls(cert)
            crl_urls = get_crl_urls(cert)
            issuer_cert = chain[0] if chain else fetch_issuer_cert(issuer_urls)
            ocsp_status, _ = check_ocsp(cert, issuer_cert, ocsp_urls)
            crl_status, _ = check_crl(cert, crl_urls)
            status = "REVOKED" if "REVOKED" in (ocsp_status, crl_status) else "VALID"
            if status == "REVOKED":
                revoked_total += 1
        rows.append({
            "host": host,
            "port": port,
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_after": cert.not_valid_after_utc.date().isoformat(),
            "key": key_summary(cert),
            "sans": ";".join(get_sans(cert)),
            "revocation_status": status,
        })
        print(f"  {target}: OK")

    with open(args.out, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()) if rows else [
            "host", "port", "subject", "issuer", "not_after", "key", "sans", "revocation_status"
        ])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n{len(rows)} hosts inspected, {revoked_total} REVOKED. Inventory written to {args.out}.")
    return 0


def cmd_report(args):
    with open(args.inventory, newline="") as fh:
        reader = csv.DictReader(fh)
        rows = list(reader)
    now = datetime.now(timezone.utc).date()
    expiring = []
    for row in rows:
        try:
            not_after = datetime.fromisoformat(row["not_after"]).date()
        except Exception:
            continue
        if (not_after - now).days <= args.expiring_within:
            expiring.append((row["host"], not_after))
    print(f"{len(expiring)} of {len(rows)} certificates expire within {args.expiring_within} days:")
    for host, not_after in expiring:
        print(f"  {host}  ->  {not_after}")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="certrecon.py")
    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser("inspect")
    p_inspect.add_argument("target")
    p_inspect.add_argument("--check-revocation", action="store_true")
    p_inspect.set_defaults(func=cmd_inspect)

    p_sweep = sub.add_parser("sweep")
    p_sweep.add_argument("--targets", required=True)
    p_sweep.add_argument("--out", required=True)
    p_sweep.add_argument("--check-revocation", action="store_true")
    p_sweep.set_defaults(func=cmd_sweep)

    p_report = sub.add_parser("report")
    p_report.add_argument("--inventory", required=True)
    p_report.add_argument("--expiring-within", type=int, default=47)
    p_report.set_defaults(func=cmd_report)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
