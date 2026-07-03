# massrev — Mass Revocation Response

## Why this tool exists

SSL.com revoked 1.7 million certificates in 24 hours. Let's Encrypt drilled 3
million more. Both events exposed the same gap: most teams cannot respond to
"replace everything from this CA now" within the deadline.

massrev takes your inventory CSV from certrecon, intersects it with the
affected serial list the CA publishes, and produces a prioritized replacement
plan: highest-exposure endpoints first, internal-only ones last, batched
against the deadline.

As you replace certificates, mark them done and the burndown moves. The
status command is the screen you put on the war-room TV.

## What it does

- **Plan** — reads your full inventory, filters to certificates issued by the
  affected CA, scores each by exposure (public-facing > internal, production
  > dev), and writes a prioritized plan.csv with a target replacement window
  per certificate.
- **Mark** — updates the plan with a replacement timestamp. Idempotent —
  re-running on the same serial is safe.
- **Status** — prints the burndown bar, priority breakdown, and hours
  remaining against the deadline. This is the screen the incident commander
  reads to leadership.

## Common questions

**Where does the affected serial list come from?**
The CA publishes it — usually as a CSV or text file on their
incident-response page. Save it as affected_serials.txt and pass --serials
to massrev plan.

**How do you score exposure?**
Public-facing hosts (resolvable on the internet) score higher than internal.
Production scores higher than non-prod. You can override per-row with a
priority column in the inventory CSV.

**Does this work for shorter-lifetime cutovers too?**
Yes. Pass --ca all and a future deadline to model the cutover as a burndown
today. That is the rehearsal exercise we recommend before shorter validity
periods land in production.
