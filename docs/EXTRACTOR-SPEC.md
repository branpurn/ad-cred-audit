# Spec — `Get-AccountSecret` offline `ntds.dit` NT-hash extractor

Fills the one stubbed region in `Invoke-AdCredDictionaryAudit.ps1`. Turns an **offline copy** of
`ntds.dit` + the `SYSTEM` hive into a stream of `AccountSecret` records for the (already-validated)
downstream pipeline. This is the hard, correctness-critical part; every mechanic below is grounded in
the documented `ntds.dit` format as implemented by the open-source [DSInternals](https://github.com/MichaelGrafnetter/DSInternals)
`DataStore` project, used here as a reference for the on-disk structures and crypto.

## 1. Scope

**Produce, per account:** `{ SamAccountName, Rid, NtHashHex, Enabled }`.

**In scope:** the *current* NT hash only. **Out of scope:** LM hash, NT/LM history, supplemental
credentials, Kerberos keys, DPAPI, cleartext/reversible, link table, DNS/BitLocker — none are read.

## 2. Contract

```
Get-AccountSecret -DatabasePath <ntds.dit> -BootKey <hex|-SystemHivePath> [-IncludeDisabledAccounts]
   -> emits [PSCustomObject]{ SamAccountName; Rid:int; NtHashHex:string(32 upper hex); Enabled:bool }
   -> also returns a total processed-account count (for the assurance count-reconcile)
```

BootKey may be supplied directly (hex) or derived from the offline `SYSTEM` hive (§5).

## 3. Pipeline (7 stages)

```
SYSTEM hive ──►(5) BootKey ──►(6) decrypt PEK list ──┐
ntds.dit ──►(4a) ESE open ──►(4b) locate pekList row ┘
                     └──►(4c) iterate account rows ──►(7) per-account: DecryptSecret(PEK) → DES-by-RID → NT hash
```

## 4. ESE / database access  (esent.dll — in-box)

**4a. Open (read-only).** Hand-written P/Invoke to `esent.dll` (we cannot use ManagedEsent — it is a
separate assembly, violating single-file; see §9). Sequence:
`JetSetSystemParameter`(paths, recovery, format) → `JetCreateInstance`/`JetInit` → `JetBeginSession`
→ `JetAttachDatabase` → `JetOpenDatabase` → `JetOpenTable("datatable")`.

> **RISK — dirty shutdown.** An IFM snapshot / VSS copy is usually in *clean* shutdown, but a raw
> file copy may be *dirty* → `JetAttachDatabase` fails (`JET_errDatabaseDirtyShutdown`). Mitigations:
> require the operator to run `esentutl /r <logbase> /d` first, and/or set recovery params. Mirror the
> `JET_param*` set DSInternals requests (`DSInternals.DataStore/NativeMethods.txt`:
> `JET_paramRecovery`, `JET_paramDeleteOldLogs`, `JET_paramEngineFormatVersion`,
> `JET_paramUnicodeIndexDefault`, temp/system/log paths). Fail closed with a clear message on dirty DB.

**4b. Locate the PEK holder.** The encrypted `pekList` lives on the domain NC head object. Pragmatic
approach: scan the datatable for the single row whose `pekList` column is non-null → that blob is the
encrypted PEK. (DSInternals resolves it via the domain-NC DNTag; the scan is a simpler equivalent.)

**4c. Iterate accounts.** `JetMove(JET_MoveFirst..JET_MoveNext)` over the datatable. For each row read
`sAMAccountType`; keep account rows (`SAM_NORMAL_USER_ACCOUNT 0x30000000`; optionally
`SAM_MACHINE_ACCOUNT 0x30000001`, `SAM_TRUST_ACCOUNT 0x30000002`). Rows without `unicodePwd` are
skipped. Retrieve columns with `JetRetrieveColumn`.

### Column resolution (scoping decision)

DSInternals reads the schema dynamically (prefix table + `msDS-IntId`) to resolve *any* attribute. We
only need ~6 **well-known system attributes**, whose `ATTRTYP` IDs are fixed, so the datatable column
names are stable and can be **hardcoded** — avoiding the ~10K-LOC schema/prefix port:

| Attribute | Column | Type char | Use |
|---|---|---|---|
| `unicodePwd` | `ATTk589914` | k (blob) | encrypted NT hash |
| `pekList` | `ATTk590689` | k (blob) | encrypted PEK list |
| `sAMAccountName` | `ATTm590045` | m (unicode) | account name |
| `sAMAccountType` | `ATTj590126` | j (int) | account filter |
| `userAccountControl` | `ATTj589832` | j (int) | Enabled bit |
| `objectSid` | `ATTr589970` | r (SID blob) | RID |

> **RISK — column-name assumption.** These are the standard secretsdump/DSInternals constants and are
> stable for system attributes (system attrs never use `msDS-IntId`). **Verify against the lab DB on
> first run** (dump `JetGetColumnInfo` names). Fallback if fragile: port the minimal schema read
> (`DirectorySchema.GetAttributeTypeFromColumnName`: strip `ATT` + 1 char, parse remaining digits as
> the attribute ID) — small, and avoids the full prefix-table port.

## 5. BootKey from the offline SYSTEM hive  (advapi32 — in-box)

Mirror `DataStore/Cryptography/BootKeyRetriever.cs` exactly (fully portable logic):

- Load the offline hive: `advapi32!RegLoadAppKey` (mounts a hive file into a private key without
  attaching under HKLM), then `RegOpenKeyEx`.
- Control set: read `Select\Current` → `ControlSet{NNN:D3}`; **default to 1** if `Select` is absent
  (common in copied hives).
- For each of `{ JD, Skew1, GBG, Data }` under `ControlSet{NNN}\Control\Lsa\`, read the key's **class
  name** (via `RegQueryInfoKey` — the material is the *class*, not a value), hex→binary, concat → 16B.
- Unscramble with the fixed permutation:
  `KeyPermutation = { 8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7 }` → `decoded[i] = raw[perm[i]]`.

## 6. Decrypt the PEK list  (advapi32 RC4 + BCL MD5/AES)

Mirror `DataStoreSecretDecryptor`:

- **Outer blob:** `Version(4) | Flags(4) | Salt(16) | EncryptedPekList`.
  - `Version W2k` → RC4; `Version W2016` → AES (strip trailing 16B before decrypt).
  - `Flags Encrypted` → decrypt; `Clear` → use as-is (rare).
- **RC4 path:** `rc4Key = MD5^1000(bootKey ‖ salt)` then RC4-decrypt. **(PEK list uses 1000 rounds.)**
- **AES path:** AES-CBC, `IV = salt`, `key = bootKey`.
- **Decrypted PEK list:** `Signature(16) | LastGenerated(8) | CurrentKey(4) | KeyCount(4) | { KeyId(4) | Key(16) }×`.
  - Signature GUID **must** equal `{4881d956-91ec-11d1-905a-00c04fc2d4cf}` — validate (fail closed).
  - Store `Keys[keyId] = 16B key`. Usually one key (index 0); handle multiple (post-rotation).

## 7. Per-account NT-hash decrypt  (two layers)

For each account with a `unicodePwd` blob:

**Layer 1 — DecryptSecret (PEK).** Blob: `AlgId(2) | Flags(2) | PekId(4) | Salt(16) | [AES only: SecretLen(4)] | EncData`.
- `AlgId == DatabaseRC4WithSalt` → `key = MD5^1(Keys[PekId] ‖ salt)`, RC4-decrypt. **(1 round here, vs 1000 for the PEK list.)**
- `AlgId == DatabaseAES` → AES-CBC, `IV = salt`, `key = Keys[PekId]`.
- Yields a 16B value **still** RID-encrypted.

**Layer 2 — DES-by-RID.** `advapi32!RtlDecryptNtOwfPwdWithIndex(partial16B, ref rid, out nt16B)`
(in-box; no DES key-expansion code needed). `rid = objectSid.GetRid()` (last sub-authority).

**Result** → `NtHashHex = uppercase hex(nt16B)`. `Enabled = (userAccountControl & 0x2) == 0`
(`ADS_UF_ACCOUNTDISABLE`), unless `-IncludeDisabledAccounts`.

## 8. Confirmed dependency map (all Tier-1 / OEM)

| Need | In-box entry point |
|---|---|
| ESE read | `esent.dll` `Jet*` (hand P/Invoke) |
| Load offline hive | `advapi32!RegLoadAppKey`, `RegOpenKeyEx`, `RegQueryInfoKey` (class name) |
| RC4 | `advapi32!SystemFunction033` (aka `RtlDecryptData2`) |
| DES-by-RID | `advapi32!RtlDecryptNtOwfPwdWithIndex` |
| MD5 (key derivation) | BCL `System.Security.Cryptography.MD5` |
| AES-CBC (2016+ DBs) | BCL `System.Security.Cryptography.Aes` |
| MD4 (dictionary side) | CNG `bcrypt.dll` — already implemented |

No DSInternals, no ManagedEsent, no third-party crypto. `.NET Framework` (C# compiler for `Add-Type`)
is the only out-of-band OEM prereq.

## 9. Single-file impact

All of the above is **embedded C# compiled at runtime via `Add-Type`** inside the one `.ps1`. The ESE
P/Invoke surface is the bulk of the new code (structs for `JET_*`, column-info, retrieve loops).
Rough size: ESE interop ~400–700 lines C#; bootkey+PEK+secret decrypt ~250–400 lines; row iteration &
shaping ~150 lines. Large, but one file — consistent with the "monster .ps1" constraint.

## 10. Assurance integration (already built downstream)

- **Canary KAT is the end-to-end oracle.** The seeded canary's known password validates the *entire*
  chain (ESE → schema columns → bootkey → PEK → RC4/AES → DES-by-RID). If the canary isn't flagged,
  the run already fails closed. This is why we can own this code with confidence.
- **Count reconcile:** `Get-AccountSecret` returns the processed-account count → compared to
  `-ExpectedCount` (operator supplies from `Get-ADUser`/DB). Guards ESE-cursor truncation.
- **Residual blind spot (documented):** accounts under a *stale* PEK version never rewritten — the
  fresh canary can't exercise that path. Small tail; if critical, diff vs DSInternals on the same
  snapshot.

## 11. Build phasing (each sub-milestone independently lab-testable)

| # | Milestone | Test |
|---|---|---|
| B1 | ESE open + iterate `datatable`, print row count | count ≈ object count |
| B2 | Resolve/verify the 6 columns; read `sAMAccountName`/`objectSid`/`UAC` | names match a real account |
| B3 | BootKey from SYSTEM hive | compare to `Get-BootKey` (DSInternals) on same hive |
| B4 | Decrypt PEK list; validate signature GUID | signature matches; key count sane |
| B5 | Per-account Layer1+Layer2 → NT hash | **canary hash == NThash(known pw)** |
| B6 | Shape to `AccountSecret`; wire into Main; full run | `-SelfTest` + real run green, count reconciles |

**Correctness oracle:** on a lab snapshot, diff extracted `{Sam→NtHashHex}` against
`Get-ADDBAccount` (DSInternals) — used only during development, never shipped.

## 12. Reference map (mirror these DSInternals files at build time)

| Stage | Reference |
|---|---|
| ESE open/iterate/retrieve | `DataStore/DirectoryContext.cs`, `DatastoreObject.cs`, `Extensions/CursorExtensions.cs` |
| Column/const | `Common/Schema/CommonDirectoryAttributes.cs`, `DirectorySchema.GetAttributeTypeFromColumnName` |
| BootKey | `DataStore/Cryptography/BootKeyRetriever.cs` |
| PEK + secret decrypt | `DataStore/Cryptography/DataStoreSecretDecryptor.cs`, `Common/Cryptography/DirectorySecretDecryptor.cs` |
| RID-DES / RC4 P/Invoke | `Common/Interop/NativeMethods.cs` (`RtlDecryptNtOwfPwdWithIndex`, `SystemFunction033`) |
| Account flow | `DataStore/DirectoryAgent.PasswordManagement.cs` (`GetSecretDecryptor`, RID→hash) |

## 13. Open questions

1. **AD LDS support?** BootKey there comes from root+schema `pekList` (different derivation — see
   `BootKeyRetriever.GetBootKey(rootPekList, schemaPekList)`). Assume AD DS only for the POC unless needed.
2. **Machine/trust accounts** — include or user-only? Default user-only (computers have random pw);
   make it a switch.
3. **ESE recovery posture** — require pre-recovered clean DB (simpler, safer) vs. attempt soft
   recovery in-tool (more robust, more risk)? Lean: require clean, fail closed on dirty.
