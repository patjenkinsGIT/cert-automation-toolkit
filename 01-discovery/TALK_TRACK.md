# certrecon — Discovery & Inventory

## Why this tool exists

You cannot automate what you cannot see. Discovery is the spine of every PKI
program — and it is where most programs are weakest.

certrecon is a single-file Python tool that sweeps hosts, pulls each
certificate, checks OCSP and CRL revocation status, and writes a clean
inventory CSV. No agents, no SaaS, no telemetry leaving your network.

Run it once and you have the artifact every other tool in the toolkit needs:
a row per certificate with subject, SANs, issuer, expiry, key algorithm, and
— critically — revocation status. The inventory is the product.

## What it does

- **Inspect a single host** — connects, retrieves the leaf certificate, walks
  the chain, and queries OCSP and CRL. A REVOKED verdict on a production host
  is the strongest single screen in the toolkit — it tells you whether any
  endpoint is serving a certificate the issuing CA no longer trusts.
- **Sweep a target list** — reads a newline-separated list of host:port
  targets and writes one row per certificate. This is the file every other
  tool in the toolkit ingests.
- **Filter the inventory** — surfaces certificates that will need a renewal
  cycle before upcoming shorter-lifetime mandates land.

## Common questions

**Why a script instead of a CLM?**
A CLM costs six figures and takes 9 months to deploy. certrecon runs in five
minutes and produces the same inventory CSV your CLM will eventually ingest.
Buy the CLM when you have proof you need one — not before.

**Will this slow down my network?**
It opens one TLS connection per target with a short timeout and no payload.
Sweep a /24 in seconds. For larger estates, batch by subnet and run from a
host with line-of-sight to the targets.

**Does it handle internal CAs?**
Yes. Pass --ca-bundle to point at your internal trust store. Revocation
checks will use the CDP and AIA URLs published in your certificates — make
sure those are reachable from the scan host.
