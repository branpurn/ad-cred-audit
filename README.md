# ad-cred-audit-poc

Offline Active Directory **custom-dictionary** password audit — discovers accounts whose current
password appears in an operator-supplied dictionary, across the whole domain, **without
authenticating** (no lockouts).

> **Start here:** [`docs/EXECUTIVE-SUMMARY.md`](docs/EXECUTIVE-SUMMARY.md).

## One-paragraph architecture

A first-party **PowerShell module** works against an **offline copy** of `ntds.dit`
(replication/IFM snapshot). It reads the database and decrypts each account's NT hash using
**in-box/OEM components only** (no DSInternals), NT-hashes each dictionary word (in-box CNG MD4),
matches them against the account hashes, and reports the hits. A fail-closed **canary** guards
against silent false negatives.

## Principles (fixed unless explicitly changed)

- **OEM-first** — Microsoft parts only: in-box Windows APIs + .NET Framework BCL. No third-party deps.
- **PowerShell** — delivered as a PowerShell module; native calls via `Add-Type` P/Invoke.

## Status

Pre-lab proof-of-concept. The matcher, dictionary hasher, and canary self-test are buildable/testable
now (synthetic fixtures + NT-hash known-answer vectors); the `ntds.dit` reader/decryptor is lab-gated.

## Related folders

- `../ad-cred-audit` — upstream DSInternals; **reference only** for how the extraction works (not a
  dependency).
- `../ad-cred-audit-de-minimis-wip` — trimmed dictionary-match cmdlet; reference for the matcher logic.
