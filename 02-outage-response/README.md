# certfire — Outage Response

A certificate just broke production. What is wrong and what do I do next?

## Usage

```bash
# Diagnose the outage
python3 certfire.py diagnose expired.badssl.com:443

# Stage the replacement
python3 certfire.py stage expired.badssl.com:443 --out ./replacement

# Verify post-deploy
python3 certfire.py verify expired.badssl.com:443 --expect-not-after 2027-03-01
```
