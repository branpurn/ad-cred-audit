# AD Password Dictionary Audit

Offline, retroactive Active Directory password auditing: find accounts whose **current** password
appears in a custom dictionary — across the whole domain, **without ever authenticating** (no failed
logons, no account lockouts).

It runs against an **offline copy** of the directory database (`ntds.dit` plus the `SYSTEM` registry
hive — for example an `ntdsutil` IFM snapshot), so it never touches a live domain controller.

Where it fits: environments with large numbers of default passwords — and places where the execution
footprint of one self-contained PowerShell script tends to clear managerial review more readily than
multi-package installs.

## Highlights

- **One script, nothing to install.** The whole tool is a single `.ps1` you drop onto a host and
  run — no modules to import, no build step.
- **Runs on stock Windows.** It uses only components already shipped with the operating system (CNG,
  the ESE database engine, the LSA crypto helpers) and the in-box .NET Framework. No third-party
  libraries.
- **Read-only and lockout-free.** Everything happens against an offline copy; production accounts are
  never authenticated against.
- **Fail-closed by design.** If the tool can't prove its own results are trustworthy, it refuses to
  report a clean bill of health (see [Assurance](#assurance)).

## Requirements

- A Windows host with Windows PowerShell 5.1 or PowerShell 7.
- An offline copy of `ntds.dit` and its matching `SYSTEM` registry hive.
- *Optional:* the Microsoft `ActiveDirectory` (RSAT) module, if you want to pass `-ExpectedCount` for
  the additional account-level cross-check (truncation protection is automatic and needs neither).

## Quick start

```powershell
# 1. On a domain controller (elevated), take a clean offline snapshot of the directory.
#    Writes ntds.dit + the SYSTEM/SECURITY hives under C:\snapshot; the live database is untouched:
ntdsutil "activate instance ntds" "ifm" "create full C:\snapshot" quit quit

# 2. Verify the build on the analysis host (runs built-in known-answer self-tests):
.\Invoke-AdCredDictionaryAudit.ps1 -SelfTest

# 3. Audit the snapshot against a dictionary:
.\Invoke-AdCredDictionaryAudit.ps1 `
    -DatabasePath   'C:\snapshot\Active Directory\ntds.dit' `
    -SystemHivePath 'C:\snapshot\registry\SYSTEM' `
    -DictionaryFile .\weak-passwords.txt `
    -Canary         svc-canary `
    -ExpectedCount  4210
```

> `-Canary` is required and must name a **canary account** whose password is in your dictionary —
> create one first (see [Assurance](#assurance)). Without a valid canary the run fails closed.

The result is a report listing the matched accounts, the number processed, a dictionary fingerprint
(the wordlist is never written to the report), and the assurance verdict.

## How it works

1. Read the offline `ntds.dit` and derive the boot key from the `SYSTEM` hive.
2. Decrypt each account's NT hash in memory (password-encryption-key unwrap, then per-account
   decryption).
3. NT-hash every dictionary entry and match against the account hashes — `O(accounts + dictionary)`.
4. Report the accounts whose password is in the dictionary.

User accounts are audited by default; computer and trust accounts (whose passwords are random) are
skipped unless you pass `-IncludeComputerAccounts`. Disabled accounts are skipped unless you pass
`-IncludeDisabledAccounts`.

## Assurance

A broken extraction fails *silently* — it decrypts to noise, matches nothing, and reports "all
clear." Two guards make that impossible to miss:

- **Canary (fail-closed).** Seed a low-privilege account whose password is in the dictionary. If the
  run doesn't flag it, the run aborts as untrustworthy instead of certifying the results. Create one
  on a DC (elevated, requires the `ActiveDirectory` module) — disabled, so it can never be used to
  authenticate, while the audit still reads its stored hash:

  ```powershell
  New-ADUser -Name svc-canary -SamAccountName svc-canary `
    -AccountPassword (Read-Host -AsSecureString -Prompt 'Canary password (must be a word in your dictionary)') `
    -Enabled $false -PasswordNeverExpires $true -CannotChangePassword $true -AccountNotDelegated $true `
    -Description 'AUTHORIZED audit canary - weak password by design; disabled (no logon); do not remediate or delete'
  ```

  Pass its name to the audit as `-Canary svc-canary`, and make sure its password is one of the words
  in your dictionary. Note: the domain password policy (complexity/length) is still enforced when the
  password is *set*, even for a disabled account — so pick a dictionary word that satisfies it (e.g.
  `Summer2024!`), or stage a temporary fine-grained password policy for the canary's OU.
- **Read-completeness (automatic).** When the database engine reports its record count, the run
  compares it to the rows actually read and fails closed on a short read — no operator input required.
  If the engine does not return a count, it warns (rather than failing) and relies on the canary.
  Optionally supply `-ExpectedCount` for an additional account-level cross-check.

Each stage can also be checked in isolation against a snapshot with the built-in probes:
`-EseProbe`, `-EseDumpAccounts`, `-BootKeyProbe`, `-PekProbe`, and `-HashProbe`.

## Handling

`ntds.dit` contains every account's credentials. Treat the snapshot and any output as highly
sensitive: work on an isolated host, keep artifacts encrypted at rest and in transit, and securely
destroy them when finished. **For authorized auditing only.**

## Status

Proof-of-concept. The matching, assurance, reporting, and hashing logic ship with unit tests
(`-SelfTest`); the offline `ntds.dit` extraction is intended to be validated on a Windows lab domain
controller using the probes above before use.

## Documentation

- [`docs/EXTRACTOR-SPEC.md`](docs/EXTRACTOR-SPEC.md) — internals of the offline `ntds.dit` extraction.

## License

MIT — see [LICENSE](LICENSE).

---

Built by SpaceXAI Grok 4.5
