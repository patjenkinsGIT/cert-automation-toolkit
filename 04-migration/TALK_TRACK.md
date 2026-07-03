# certmove — CA-to-CA Migration

## Why this tool exists

Switching CAs sounds like a procurement decision. In practice it is a
months-long migration that the auditor will eventually ask you to prove —
every endpoint, every replacement, every old certificate retired.

certmove plans the migration from a source inventory, tracks replacement as
it happens, and writes a tamper-evident evidence log the auditor can verify
against the live endpoints.

The PASS/FAIL evidence row is the differentiator. It is the artifact that
turns "we believe we migrated" into "here is the proof, signed and
timestamped".

## What it does

- **Plan** — filters source inventory to certificates issued by the outgoing
  CA and writes a per-endpoint migration plan with target dates and
  ownership.
- **Verify** — re-scans each endpoint, checks that the live certificate is
  now issued by the new CA, and emits a PASS or FAIL per row. PASS rows
  include the new serial, fingerprint, and timestamp; FAIL rows surface why.
- **Evidence** — produces a sorted, hash-chained CSV with one row per
  endpoint. Hand this to your auditor; pair it with the source inventory and
  the new CA's issuance log for a complete trail.

## Common questions

**What if an endpoint is unreachable?**
It is flagged UNREACHABLE in the evidence log rather than PASS or FAIL. The
auditor needs to see the gap; do not hide it.

**Can the evidence log be tampered with?**
Each row carries a hash of the previous row. Re-running evidence will
re-verify the chain; any mid-stream edit breaks it. For higher assurance,
sign the file with your code-signing key.

**Does it support ADCS to public CA migrations?**
Yes. The plan and verify steps treat the issuing CA as a string — works for
any source/target combination, including internal ADCS to a public CA or the
reverse.
