#!/usr/bin/env python3
"""
massrev — mass revocation response tool.

Takes an inventory CSV (from certrecon), intersects it with the CA that
issued a batch revocation, scores each certificate by exposure, and writes
a prioritized replacement plan. Track progress and read the burndown as you go.

Usage:
    python3 massrev.py plan --inventory inventory.csv --ca <name> --deadline <YYYY-MM-DD> --out plan.csv
    python3 massrev.py mark --plan plan.csv --serial <serial> --status <replaced|in_progress>
    python3 massrev.py status --plan plan.csv
"""
import argparse
import csv
import sys
from datetime import datetime, timezone


def score_priority(exposure: str, environment: str) -> str:
    if exposure == "public" and environment == "production":
        return "P0"
    if environment == "production":
        return "P1"
    return "P2"


def cmd_plan(args):
    with open(args.inventory, newline="") as fh:
        rows = list(csv.DictReader(fh))

    scoped = [r for r in rows if r.get("issuer", "").strip().lower() == args.ca.strip().lower()]
    for row in scoped:
        row["priority"] = score_priority(row.get("exposure", "internal"), row.get("environment", "dev"))
        row.setdefault("status", "not_started")

    priority_order = {"P0": 0, "P1": 1, "P2": 2}
    scoped.sort(key=lambda r: priority_order.get(r["priority"], 3))

    fieldnames = ["host", "port", "issuer", "exposure", "environment", "priority", "status", "serial", "deadline"]
    with open(args.out, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in scoped:
            writer.writerow({
                "host": row.get("host", ""),
                "port": row.get("port", ""),
                "issuer": row.get("issuer", ""),
                "exposure": row.get("exposure", ""),
                "environment": row.get("environment", ""),
                "priority": row["priority"],
                "status": row.get("status", "not_started"),
                "serial": row.get("serial", ""),
                "deadline": args.deadline,
            })

    p0 = sum(1 for r in scoped if r["priority"] == "P0")
    p1 = sum(1 for r in scoped if r["priority"] == "P1")
    p2 = sum(1 for r in scoped if r["priority"] == "P2")
    print(f"[ MASS REVOCATION PLAN — {args.ca} deadline {args.deadline} ]")
    print(f"  Total in scope:  {len(scoped)} certificates")
    print(f"  P0 public-facing prod:  {p0}")
    print(f"  P1 internal prod:       {p1}")
    print(f"  P2 non-prod:            {p2}")
    print(f"\nPlan written to {args.out}. Highest-exposure endpoints first.")
    return 0


def cmd_mark(args):
    with open(args.plan, newline="") as fh:
        rows = list(csv.DictReader(fh))
        fieldnames = fh and list(rows[0].keys()) if rows else []

    found = False
    for row in rows:
        if row.get("serial", "").strip() == args.serial.strip():
            row["status"] = args.status
            found = True

    if not found:
        print(f"No row found with serial {args.serial}")
        return 1

    with open(args.plan, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Marked {args.serial} as {args.status}.")
    return 0


def cmd_status(args):
    with open(args.plan, newline="") as fh:
        rows = list(csv.DictReader(fh))

    if not rows:
        print("Plan is empty.")
        return 1

    total = len(rows)
    replaced = sum(1 for r in rows if r.get("status") == "replaced")
    in_progress = sum(1 for r in rows if r.get("status") == "in_progress")
    not_started = total - replaced - in_progress
    pct = round((replaced / total) * 100) if total else 0

    deadline_str = rows[0].get("deadline", "")
    hours_remaining = None
    if deadline_str:
        try:
            deadline = datetime.strptime(deadline_str, "%Y-%m-%d").replace(
                hour=23, minute=59, tzinfo=timezone.utc
            )
            delta = deadline - datetime.now(timezone.utc)
            hours_remaining = max(0, int(delta.total_seconds() // 3600))
        except ValueError:
            pass

    not_started_rows = [r for r in rows if r.get("status") == "not_started"]
    p0 = sum(1 for r in not_started_rows if r.get("priority") == "P0")
    p1 = sum(1 for r in not_started_rows if r.get("priority") == "P1")
    p2 = sum(1 for r in not_started_rows if r.get("priority") == "P2")

    ca = rows[0].get("issuer", "the affected CA")
    print(f"[ MASS REVOCATION BURNDOWN — {ca} deadline {deadline_str} ]\n")
    print(f"  Total in scope:      {total} certificates")
    print(f"  Replaced:            {replaced} ({pct}%)")
    print(f"  In progress:          {in_progress}")
    print(f"  Not started:         {not_started}")
    if hours_remaining is not None:
        print(f"  Time remaining:      {hours_remaining}h")
    print("\n  Priority breakdown (not started):")
    print(f"    P0 public-facing prod:     {p0}  <-- DO THESE NEXT")
    print(f"    P1 internal prod:          {p1}")
    print(f"    P2 non-prod:              {p2}")

    bar_width = 32
    filled = round((pct / 100) * bar_width)
    bar = "#" * filled + "." * (bar_width - filled)
    print(f"\n  [{bar}]  {pct}%")
    return 0


def main():
    parser = argparse.ArgumentParser(prog="massrev.py")
    sub = parser.add_subparsers(dest="command", required=True)

    p_plan = sub.add_parser("plan")
    p_plan.add_argument("--inventory", required=True)
    p_plan.add_argument("--ca", required=True)
    p_plan.add_argument("--deadline", required=True)
    p_plan.add_argument("--out", required=True)
    p_plan.set_defaults(func=cmd_plan)

    p_mark = sub.add_parser("mark")
    p_mark.add_argument("--plan", required=True)
    p_mark.add_argument("--serial", required=True)
    p_mark.add_argument("--status", required=True, choices=["not_started", "in_progress", "replaced"])
    p_mark.set_defaults(func=cmd_mark)

    p_status = sub.add_parser("status")
    p_status.add_argument("--plan", required=True)
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
