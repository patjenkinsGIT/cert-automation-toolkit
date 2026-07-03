# cert-automation-toolkit

Four practitioner-grade PKI automation tools for the certificate scenarios that
actually page you: discovery, outage response, mass revocation, and CA-to-CA
migration.

Open-source, MIT-licensed, single-dependency (`cryptography`), no agents,
no SaaS, no telemetry leaving your network.

## The four tools

| # | Folder | Tool | Question it answers |
|---|--------|------|----------------------|
| 01 | `01-discovery/` | `certrecon.py` | What certificates are out there — and which ones are already revoked? |
| 02 | `02-outage-response/` | `certfire.py` | A certificate just broke production. What is wrong and what do I do next? |
| 03 | `03-mass-revocation/` | `massrev.py` | A CA just revoked thousands of our certificates. How do we prioritize and burn it down? |
| 04 | `04-migration/` | `certmove.py` | We are switching CAs. How do we prove every endpoint actually moved? |

Each folder contains:
- the tool itself (single-file Python script)
- `README.md` — usage reference
- `TALK_TRACK.md` — the narrative behind the tool: why it exists, what it does, common questions
- `sample_output.txt` — a real captured run so you know what to expect
- any fixture data files the tool's demo commands use

## Quick start

```bash
python3 -m venv venv
source venv/bin/activate
pip install cryptography
cd 01-discovery
python3 certrecon.py inspect revoked.badssl.com:443 --check-revocation
```

## They chain together

The discovery inventory (`certrecon`) is the spine. Scan once; the rest run
off it. Outage response (`certfire`) reads it to stage replacements. Mass
revocation (`massrev`) reads it to prioritize a burndown. Migration
(`certmove`) reads it to plan and verify the move.

## License

MIT — see `LICENSE`.

## More

Full write-ups, interactive browser demos, and the design principles behind
this toolkit: https://github.com/patjenkinsGIT/cert-automation-toolkit
