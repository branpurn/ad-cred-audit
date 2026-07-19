# Executive Summary — Offline AD Custom-Dictionary Password Audit

## What it does

Finds Active Directory accounts whose current password appears in an operator-supplied **custom
dictionary**, across the whole domain, **offline** — no authentication attempts, no lockouts.

## Approach

Work against an **offline copy of the directory** (replication/IFM snapshot of `ntds.dit`), never a
live DC. A first-party PowerShell module:

1. **Reads** the offline `ntds.dit` and **decrypts** each account's NT hash — reimplemented in-house
   from in-box/OEM components.
2. **NT-hashes** every dictionary word (in-box CNG MD4).
3. **Matches** dictionary hashes against account hashes and reports the hits.

## Guiding principles (fixed unless we explicitly agree to change them)

- **OEM-first.** Built from Microsoft parts only — in-box Windows APIs (`esent.dll`, CNG/`advapi32`
  crypto, `ntdsutil`) and the .NET Framework BCL. No third-party dependencies (no DSInternals).
- **PowerShell.** Delivered and operated as a PowerShell module. Native calls go through `Add-Type`
  P/Invoke to in-box DLLs — still PowerShell.

## Why the risk is acceptable

- **Reimplementing the hash extraction is the hard part** — but we run it against a **read-only
  offline copy**, so a bug can't touch production. Blast radius is our copy, nothing more.
- **False negatives** (a weak password silently missed) are the only dangerous error, and a
  **canary account** kills them: seed a no-privs account whose password is in the dictionary; if the
  run doesn't flag it, the run **fails closed** as untrustworthy instead of reporting "all clear."
- **False positives** we don't chase — a broken matcher lights up the whole domain, which is obvious
  on sight. Not worth engineering against.

## Scope

One job: exact dictionary membership against current NT hashes. No duplicate-password test, no
breach-corpus/HIBP, no cracking rules, no online testing.

## Status

Pre-lab proof-of-concept. The matcher, dictionary hasher, and canary self-test are buildable and
testable now (synthetic fixtures + NT-hash known-answer vectors). The `ntds.dit` reader/decryptor is
built and validated in a Windows lab.
