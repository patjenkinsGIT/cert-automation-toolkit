# certfire — Outage Response

## Why this tool exists

When a certificate breaks production, the first 15 minutes decide whether
this is a footnote in a status page or a Sev-1 with an executive readout.

certfire takes a hostname, returns the single root cause in plain English,
and stages everything you need to push a replacement — a fresh private key,
a CSR pre-filled from the broken certificate, and a copy-paste deployment
checklist.

Pair it with the runbook in the GitHub folder. The runbook is the second
artifact your incident commander needs after the cause is named.

## What it does

- **Diagnose** — one screen names the cause: expired, name mismatch, chain
  incomplete, weak key, revoked, or wrong protocol. Each verdict carries a
  one-line remediation pointer.
- **Stage** — generates a 2048-bit RSA key (or P-256, your choice), builds a
  CSR with the original Subject and SANs preserved, and writes a deployment
  checklist file with the exact commands for your platform.
- **Verify** — reconnects, confirms the new certificate is live, and writes a
  PASS/FAIL line to the incident log. This is the artifact you paste into the
  post-incident ticket.

## Common questions

**Why not just renew through the portal?**
Portals work when the outage is calm. They do not work at 2am when the
on-call engineer has never used your CA portal before. certfire is the
muscle memory the on-call engineer does not have yet.

**Does this support ACME?**
The stage command emits a standard CSR that any ACME client can consume.
Hand req.csr to certbot, acme.sh, win-acme, or your in-house wrapper —
whichever your runbook calls for.

**What about the private key from the broken cert?**
You are replacing the certificate, not the key, unless the cause is
compromise. The default flow generates a new key because that is the safer
assumption during an outage; pass --reuse-key if you have a hardware-bound
key you must keep.
