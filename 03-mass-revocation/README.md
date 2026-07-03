# massrev — Mass Revocation Response

A CA just revoked thousands of our certificates. How do we prioritize and burn it down?

## Usage

```bash
# Plan the burndown
python3 massrev.py plan --inventory sample_inventory.csv --ca Entrust --deadline 2026-12-31 --out plan.csv

# Mark progress
python3 massrev.py mark --plan plan.csv --serial 0x4a:7b:... --status replaced

# Read the burndown
python3 massrev.py status --plan plan.csv
```

Fixture: `sample_inventory.csv`, pre-generated `plan.csv`.
