# ad-cred-audit-poc

Offline Active Directory **custom-dictionary** password audit — discovers accounts whose current
password appears in an operator-supplied dictionary, across the whole domain, **without
authenticating** (no lockouts).

> **Start here:** [`docs/EXECUTIVE-SUMMARY.md`](docs/EXECUTIVE-SUMMARY.md).

## One-paragraph architecture

A single self-contained **`.ps1` script** (`Invoke-AdCredDictionaryAudit.ps1`) works against an
**offline copy** of `ntds.dit` (replication/IFM snapshot). It reads the database and decrypts each
account's NT hash using **in-box/OEM components only** (no DSInternals), NT-hashes each dictionary
word (in-box CNG MD4), matches them against the account hashes, and reports the hits. A fail-closed
**canary** guards against silent false negatives.

## Principles (fixed unless explicitly changed)

- **OEM-first** — Microsoft parts only: in-box Windows APIs + .NET Framework BCL. Microsoft prereqs
  (.NET Framework, RSAT ActiveDirectory module) installed out-of-band; no third-party code shipped.
- **Single `.ps1`, not a module** — one file: PowerShell + embedded C# via `Add-Type`. No `.psm1`,
  nothing to `Import-Module`. Built-in `-SelfTest`; no external test framework.

## Usage

```powershell
.\Invoke-AdCredDictionaryAudit.ps1 -SelfTest                       # validate the build (run on Windows)
.\Invoke-AdCredDictionaryAudit.ps1 -FixturePath .\accounts.json ` # offline dev against a JSON fixture
    -Dictionary password -Canary canary
.\Invoke-AdCredDictionaryAudit.ps1 -DatabasePath C:\ifm\ntds.dit ` # real run (lab; extractor is Phase B)
    -BootKey <hex> -DictionaryFile .\weak.txt -Canary svc-canary-pos -ExpectedCount 4210
```

## Status

Pre-lab proof-of-concept. Matcher, hasher, assurance gate, reporter, and `-SelfTest` are built; the
`ntds.dit` reader/decryptor (the `Get-AccountSecret` region) is stubbed and lab-gated.

## Related folders

- `../ad-cred-audit` — upstream DSInternals; **reference only** for how the extraction works (not a
  dependency).
- `../ad-cred-audit-de-minimis-wip` — trimmed dictionary-match cmdlet; reference for the matcher logic.
