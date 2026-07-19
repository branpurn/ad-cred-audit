# ad-cred-audit-poc

Offline, retroactive Active Directory **custom-dictionary** password audit — discovers accounts
whose current password appears in an operator-supplied dictionary, across the whole directory,
**without authenticating** (no lockouts).

> **Start here:** [`docs/CONOP.md`](docs/CONOP.md) — the concept of operations: goals, trade-space
> rationale, architecture, operational workflow, assurance model, and phased delivery.

## One-paragraph architecture

Work from an **offline IFM snapshot** of `ntds.dit`. A **pluggable extractor** (DSInternals
black-box for the POC; an owned static-file extractor possible later) emits
`{SamAccountName, RID, NTHash, Enabled}` records behind a fixed contract. Everything downstream is
extractor-agnostic: the **candidate hasher** NT-hashes each dictionary word (in-box CNG MD4), the
**matcher** looks them up against the account hashes, and a **fail-closed assurance gate**
(positive canary + count reconcile) makes silent under-reporting impossible before anything is
reported.

## Status

Pre-lab proof-of-concept. Phase A components (contract, matcher, hasher, assurance harness,
reporter) are buildable and unit-testable now with synthetic fixtures; the extractor and end-to-end
run are lab-gated. See CONOP §10–§11.

## Related folders

- `../ad-cred-audit` — upstream DSInternals (source of truth for the extractor).
- `../ad-cred-audit-de-minimis-wip` — trimmed C# dictionary-match cmdlet; reference for the matcher
  logic ported here.
