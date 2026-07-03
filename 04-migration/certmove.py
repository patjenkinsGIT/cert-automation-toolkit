#!/usr/bin/env python3
"""
certmove — CA-to-CA migration tool.

Plans a migration from a source inventory CSV, verifies which endpoints
have actually cut over to the new CA, and writes a tamper-evident,
hash-chained evidence log an auditor can check.

Usage:
    python3 certmove.py plan --inventory source_inventory.csv --from-ca <name> --to-ca <name> --out migration_plan.csv
    python3 certmove.py verify --inventory post_migration.csv [--out evidence_log.csv]
    python3 certmove.py evidence --verify-output verify.json --out evidence_log.csv
"""
import argparse
import csv
import hashlib
import sys
from datetime import datetime, timezone


def cmd_plan(args):
    with open(args.inventory, newline="") as fh:
        rows = list(csv.DictReader(fh))

    scoped = [r for r in rows if r.get("issuer", "").strip().lower() == args.from_ca.strip().lower()]

    fieldnames = ["host", "port", "from_ca", "to_ca", "serial", "target_date", "owner"]
    with open(args.out, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in scoped:
            writer.writerow({
                "host": row.get("host", ""),
                "port": row.get("port", ""),
                "from_ca": args.from_ca,
                "to_ca": args.to_ca,
                "serial": row.get("serial", ""),
                "target_date": args.target_date or "TBD",
                "owner": "platform-team",
            })

    print(f"[ MIGRATION PLAN — {args.from_ca} -> {args.to_ca} ]\n")
    print(f"  Endpoints in scope: {len(scoped)}")
    for row in scoped:
        print(f"    {row.get('host')}:{row.get('port')}  serial={row.get('serial')}")
    print(f"\nPlan written to {args.out}.")
    return 0


def cmd_verify(args):
    with open(args.inventory, newline="") as fh:
        rows = list(csv.DictReader(fh))

    from_ca_guess = next((r.get("issuer") for r in rows if r.get("issuer") and r.get("issuer") != r.get("expected_ca")), None)
    to_ca_guess = rows[0].get("expected_ca", "") if rows else ""
    print(f"[ MIGRATION VERIFICATION — {from_ca_guess or 'old CA'} -> {to_ca_guess} ]\n")

    results = []
    pass_count = fail_count = unreachable_count = 0
    for row in rows:
        host = row.get("host", "")
        port = row.get("port", "")
        issuer = row.get("issuer", "").strip()
        expected = row.get("expected_ca", "").strip()
        serial = row.get("serial", "")
        fingerprint = row.get("fingerprint", "")
        not_after = row.get("not_after", "")

        if not issuer:
            unreachable_count += 1
            results.append({**row, "verdict": "UNREACHABLE"})
            print(f"  {host}:{port}".ljust(28) + "UNREACHABLE")
            continue

        if issuer.lower() == expected.lower():
            pass_count += 1
            results.append({**row, "verdict": "PASS"})
            print(
                f"  {host}:{port}".ljust(28)
                + f"PASS  issuer={issuer}  serial={serial}  not_after={not_after}"
            )
        else:
            fail_count += 1
            results.append({**row, "verdict": "FAIL"})
            print(f"  {host}:{port}".ljust(28) + f"FAIL  issuer={issuer}  -- still on old CA, not replaced")

    print(f"\n  Summary: {pass_count} PASS, {fail_count} FAIL, {unreachable_count} unreachable.")

    evidence_path = args.out or "evidence_log.csv"
    digest = write_evidence_log(results, evidence_path)
    print(f"  Evidence log written: {evidence_path}  (sha256: {digest[:8]}...)")

    if fail_count:
        print(f"\n  -> {fail_count} endpoint{'s' if fail_count != 1 else ''} still on the old CA. Drive that to zero before retiring trust.")
        return 1
    return 0


def write_evidence_log(results, out_path):
    fieldnames = ["host", "port", "verdict", "issuer", "serial", "fingerprint", "not_after", "timestamp", "row_hash"]
    prev_hash = "0" * 64
    now = datetime.now(timezone.utc).isoformat()
    written_rows = []
    for row in results:
        payload = f"{prev_hash}|{row.get('host')}|{row.get('verdict')}|{row.get('issuer')}|{row.get('serial')}|{now}"
        row_hash = hashlib.sha256(payload.encode()).hexdigest()
        written_rows.append({
            "host": row.get("host", ""),
            "port": row.get("port", ""),
            "verdict": row.get("verdict", ""),
            "issuer": row.get("issuer", ""),
            "serial": row.get("serial", ""),
            "fingerprint": row.get("fingerprint", ""),
            "not_after": row.get("not_after", ""),
            "timestamp": now,
            "row_hash": row_hash,
        })
        prev_hash = row_hash

    with open(out_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(written_rows)

    return prev_hash


def cmd_evidence(args):
    import json
    with open(args.verify_output) as fh:
        results = json.load(fh)
    digest = write_evidence_log(results, args.out)
    print(f"Evidence log written: {args.out}  (sha256: {digest[:8]}...)")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="certmove.py")
    sub = parser.add_subparsers(dest="command", required=True)

    p_plan = sub.add_parser("plan")
    p_plan.add_argument("--inventory", required=True)
    p_plan.add_argument("--from-ca", required=True)
    p_plan.add_argument("--to-ca", required=True)
    p_plan.add_argument("--target-date", default=None)
    p_plan.add_argument("--out", required=True)
    p_plan.set_defaults(func=cmd_plan)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("--inventory", required=True)
    p_verify.add_argument("--out", default=None)
    p_verify.set_defaults(func=cmd_verify)

    p_evidence = sub.add_parser("evidence")
    p_evidence.add_argument("--verify-output", required=True)
    p_evidence.add_argument("--out", required=True)
    p_evidence.set_defaults(func=cmd_evidence)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
