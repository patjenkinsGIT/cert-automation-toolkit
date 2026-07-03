# Certificate Outage Runbook — the first 15 minutes

Use this alongside `certfire.py`. The tool names the cause and stages the fix;
this runbook is what the incident commander runs while that happens.

**Goal:** replacement certificate live in ~15 minutes if a CA is on standby.

---

## T+0 — Declare and diagnose (minutes 0–3)

1. **Declare the incident.** Certificate outages masquerade as app outages —
   naming it early stops three teams from debugging the wrong layer.
2. **Run the diagnosis:**

   ```bash
   python3 certfire.py diagnose <host>:443
   ```

3. **Read the verdict.** One of: `EXPIRED`, `NAME MISMATCH`, `CHAIN INCOMPLETE`,
   `WEAK KEY`, `REVOKED`, `WRONG PROTOCOL`. Paste the full output into the
   incident channel — verbatim, no paraphrasing.
4. **Check blast radius.** If the certificate is a wildcard or multi-SAN, every
   name on it is affected. Grep your inventory:

   ```bash
   grep -i '<domain>' inventory.csv
   ```

## T+3 — Stage the replacement (minutes 3–8)

5. **Stage key + CSR from the broken cert:**

   ```bash
   python3 certfire.py stage <host>:443 --out ./replacement
   ```

   This writes `replacement/key.pem`, `replacement/req.csr`, and
   `replacement/CHECKLIST.md`. The CSR preserves the original Subject and SANs —
   no retyping under pressure.

6. **Submit the CSR** to your CA (portal, ACME, or API). If the verdict was
   `REVOKED`, do **not** reuse the old key — `stage` already generated a fresh
   one; make sure the old key is retired everywhere it was deployed.
7. **While waiting on issuance:** identify every place the old certificate is
   deployed (load balancers, CDN, origin, internal proxies). The checklist file
   has a placeholder table — fill it in now, not after.

## T+8 — Deploy (minutes 8–12)

8. **Install the issued certificate** per `replacement/CHECKLIST.md` for your
   platform. Full chain, not just the leaf — an incomplete chain is how this
   incident happens twice in one day.
9. **Reload, don't restart,** where the platform supports it (nginx, HAProxy,
   Apache all reload gracefully).

## T+12 — Verify and close (minutes 12–15)

10. **Prove the fix:**

    ```bash
    python3 certfire.py verify <host>:443 --expect-not-after <new-expiry>
    ```

    A `PASS` line is your closing artifact — paste it into the incident ticket.
11. **Verify from outside the network too** (a phone off wifi is fine). Split-
    horizon DNS and cached chains lie.
12. **Stand down** and note the timestamps: detected, diagnosed, staged,
    deployed, verified.

---

## Post-incident (same day, 15 minutes, not optional)

- **Why did monitoring miss it?** If the answer is "we don't monitor expiry,"
  the corrective action is a sweep: `certrecon.py sweep` against your estate,
  then alerting on the inventory.
- **Was this cert in the inventory?** If not, discovery has a gap — fix the
  target list.
- **Could ACME have prevented it?** If the cert was manually managed, add it to
  the automation backlog with this incident as the business case.
- **File the artifacts:** diagnosis output, verify PASS line, and timestamps go
  in the ticket. That is what turns a bad Tuesday into an audit asset.

## Escalation triggers

Escalate beyond the on-call if any of these are true:

- The verdict is `REVOKED` and you did not request the revocation — assume key
  compromise until proven otherwise, and involve security.
- The CA cannot issue within the hour and the endpoint is public-facing —
  consider a temporary cert from a secondary CA you have pre-validated.
- The same verdict appears on multiple unrelated hosts — you may be at the
  start of a mass-revocation event. Switch to `../03-mass-revocation/`.
