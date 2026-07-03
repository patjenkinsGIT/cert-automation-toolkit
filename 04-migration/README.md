# certmove — CA-to-CA Migration

We are switching CAs. How do we prove every endpoint actually moved?

## Usage

```bash
# Plan the migration
python3 certmove.py plan --inventory source_inventory.csv --from-ca Entrust --to-ca Sectigo --out migration_plan.csv

# Verify post-migration
python3 certmove.py verify --inventory post_migration.csv

# Generate the evidence log
python3 certmove.py evidence --verify-output verify.json --out evidence_log.csv
```

Fixtures: `source_inventory.csv`, `post_migration.csv`.
