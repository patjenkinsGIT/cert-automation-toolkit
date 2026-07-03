# certrecon — Discovery & Inventory

What certificates are out there — and which ones are already revoked?

## Usage

```bash
# Inspect a single host
python3 certrecon.py inspect revoked.badssl.com:443 --check-revocation

# Sweep a target list
python3 certrecon.py sweep --targets targets.txt --out inventory.csv --check-revocation

# Filter the inventory
python3 certrecon.py report --inventory inventory.csv --expiring-within 47
```

Sample fixture: `sample_inventory.csv` (used by the other three tools' demos).
