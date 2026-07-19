# CONOP — Offline AD Custom-Dictionary Password Audit

**Project:** `ad-cred-audit-poc`
**Status:** Concept / pre-lab proof-of-concept
**Classification of handling:** Sensitive — this tool processes domain credential material (see §8)

---

## 1. Purpose & Scope

**Purpose.** Retroactively discover which Active Directory accounts have a password present in
an operator-supplied **custom dictionary**, across the **entire directory population**, **without
authenticating as those accounts** (no lockouts, no production disruption).

**In scope.**
- Offline audit of the *current* NT hash of every account against a custom dictionary.
- A fail-closed self-test that makes silent under-reporting detectable.
- A report of matched accounts suitable for a remediation handoff.

**Explicitly out of scope.**
- Duplicate-password detection, HIBP/breach-corpus checks, and every other DSInternals
  `Test-PasswordQuality` dimension (Kerberoastable, LM hash, cleartext, etc.). This tool does
  *one* thing.
- Online/credential-spray testing (rejected — see §4).
- Password *history*, supplemental credentials, Kerberos keys, LM hashes.
- Cracking beyond exact dictionary membership (no rules/mutations engine in the POC).

---

## 2. Problem Statement

Weak, guessable passwords remain a top initial-access vector. Defenders need to *find* them in
their existing population, but the two obvious approaches each fail:

- **Online testing** (guess each account's password by authenticating) increments `badPwdCount`
  and **locks accounts out** — a self-inflicted DoS on production.
- **Offline hash comparison** requires reading and decrypting directory secrets, for which
  **Windows ships no supported in-box extractor.**

This project resolves that tension by working from an **offline copy** of the directory and doing
**exact dictionary membership** on decrypted NT hashes — retroactive, full-coverage, and
lockout-free.

---

## 3. Operating Environment & Assumptions

- **Target:** on-premises AD DS; Windows Server domain controllers.
- **Directory-format variability:** RC4-with-salt PEK (older) and **AES PEK (2016+)** both exist;
  the extractor must handle whatever epoch the target DB uses (see §7 assurance).
- **Analysis host:** a dedicated, isolated **Windows** host (Windows PowerShell 5.1 / .NET
  Framework) — *not* required to be a DC. Provides in-box CNG (`bcrypt.dll` MD4) for candidate
  hashing.
- **Operator privileges:** authority to create an IFM snapshot on/from a DC (Domain Admin or
  delegated equivalent) and to handle the resulting `ntds.dit` + `SYSTEM` hive.
- **Authorization:** a written, scoped engagement authorization exists before any run (see §8).
- **Lab-first:** all development validates in an isolated lab domain before any production use.

---

## 4. Design Decisions & Rationale (the trade space we walked)

| Decision | Chosen | Why (rejected alternatives) |
|---|---|---|
| Testing model | **Offline, retroactive** | Online spray risks domain-wide lockout/DoS. |
| Coverage | **Full population** | Kerberoast/AS-REP is offline+in-box but only covers the SPN/preauth-disabled *subset*. |
| Extraction substrate | **Static file (IFM snapshot)** | Lower *reimplementation* risk than replication: a static `ntds.dit` is deterministic and re-testable offline with no DC in the loop; replication adds live-DC RPC + NDR-marshalling + auth surface. |
| Extractor ownership | **Pluggable behind a contract; DSInternals black-box first** | A "minimal DSInternals subset" is *not* minimal — measured ~6–10K LOC of ESE + schema + PEK/DES/AES crypto + 3 build deps, and it's the code you least want to own (silent-wrong failure mode). See §5. |
| Assurance | **Positive canary (fail-closed) + count reconcile** | Converts the dangerous *silent false-negative* into a caught failure. Negative control dropped: a global false-positive is self-announcing (whole domain pings hot) and one sample can't catch partial FPs anyway. |

**The impossibility triangle.** `{retroactive, no-crypto, in-box-only}` — pick two. We chose
**retroactive + (mostly) in-box**, accepting a bounded amount of decryption code — minimized by
black-boxing it behind a swappable contract.

---

## 5. System Architecture

**Design spine: the extractor is a replaceable component behind a fixed contract. Everything
downstream is extractor-agnostic and independently testable.**

```
                     ┌──────────────────────────────────────────────┐
   DC ── IFM ──►  ntds.dit + SYSTEM hive  (offline copy; no lockout) │
                     └──────────────────────────────────────────────┘
                                  │
                                  ▼
                    ┌───────────────────────────┐
                    │  EXTRACTOR (pluggable)     │   Contract → AccountSecret records:
                    │  POC: DSInternals          │   { SamAccountName, RID, NTHash(16B),
                    │       Get-ADDBAccount       │     Enabled, IsCanary? }
                    │  Future: owned static-file  │
                    │          extractor          │
                    └───────────────────────────┘
                                  │  (extractor-agnostic from here down)
                                  ▼
   custom dictionary ─► CANDIDATE HASHER ─► MATCHER ─► ASSURANCE GATE ─► REPORT
     (words / file)     in-box CNG MD4        hash→        (§7)          matched
                        (NThash of each       accounts     fail-closed   accounts
                        candidate)            map lookup                 + evidence
```

**Components**

1. **Snapshot** — `ntdsutil "activate instance ntds" ifm "create full <path>"` (in-box) →
   `ntds.dit` + `registry\SYSTEM`.
2. **Extractor (pluggable)** — emits `AccountSecret` records per the contract above.
   - *POC impl:* DSInternals `Get-ADDBAccount -All -DatabasePath … -BootKey …` (opaque, signed,
     maintained). BootKey via `Get-BootKey`.
   - *Future impl:* first-party static-file extractor (ESE read + schema decode + PEK/DES/AES).
     Independently swappable; validated by the same §7 gate.
3. **Candidate hasher** — computes the NT hash (MD4 of UTF-16LE) of each dictionary entry using
   **in-box CNG `bcrypt.dll` MD4** (fallback: `advapi32!SystemFunction007`). No third-party crypto.
4. **Matcher** — builds `hashToAccountMap : NTHash → {accounts}` from the extractor stream, then
   looks up each candidate hash. Reuses the logic already trimmed in
   `ad-cred-audit-de-minimis-wip` (dictionary path). O(accounts + dictionary).
5. **Assurance gate** — §7. Runs *before* results are trusted; fail-closed.
6. **Reporter** — matched accounts (Sam/RID/enabled), run metadata, assurance verdict, dictionary
   fingerprint (hash of the dictionary used, not its contents).

---

## 6. Concept of Operations — operational workflow

Actors: **Operator** (runs the audit), **Approver** (authorizes), **Data Custodian** (governs the
snapshot lifecycle). Each phase has a go/no-go gate.

- **P0 — Authorize & scope.** Approver signs off on scope, window, target domain, and disposal
  plan. *Gate:* no authorization → stop.
- **P1 — Provision positive canary.** Create a no-privs/no-groups control account; set its password
  to a value that IS in the dictionary; allowlist its RID in the reporter. Confirm it exists
  *before* the snapshot. (See §7, §8.)
- **P2 — Offline snapshot.** Operator creates the IFM copy on/from a DC. Read-only w.r.t. the live
  directory. *Gate:* snapshot integrity check (files present, non-zero, canary epoch covered).
- **P3 — Secure transfer.** Move `ntds.dit` + `SYSTEM` to the isolated analysis host over an
  encrypted channel; record chain of custody. Treat as crown-jewel material (§8).
- **P4 — Extract.** Run the configured extractor → `AccountSecret` stream. *Gate:* extractor
  returns without error and record count > 0.
- **P5 — Prepare dictionary.** Load the custom dictionary; compute candidate NT hashes in-box;
  record the dictionary fingerprint.
- **P6 — Match.** Build the map; look up candidates; collect matched accounts.
- **P7 — Assurance gate (fail-closed).** Positive canary MUST be flagged; processed-count MUST
  reconcile with the expected population; (optional) hit-rate sanity warn. *Gate:* any failure →
  **discard results, emit "UNTRUSTWORTHY," do not report a clean bill of health.**
- **P8 — Report.** Emit matched accounts + assurance verdict + run metadata. Canary reported as
  "control passed," not as a finding.
- **P9 — Remediation handoff.** Deliver findings to the identity/IR owner for forced resets /
  investigation.
- **P10 — Disposal.** Securely destroy the snapshot, extracted hashes, and intermediate artifacts
  per the disposal plan; retire/rotate the canary; close chain of custody.

---

## 7. Assurance & Self-Test (the trust model)

The audit fails **silently** if extraction is wrong — it decrypts to garbage, matches nothing, and
reports "all clear." The gate makes that impossible to miss:

- **Positive canary — fail-closed.** A known account whose known password is in the dictionary
  MUST appear in matches. If it doesn't, the pipeline is broken → results are discarded and the run
  is marked UNTRUSTWORTHY. This is the primary guard against silent false negatives.
  - *Known limit:* a freshly-created canary validates the **dominant PEK/etype path** (uniform per
    DB epoch — i.e., most of the population), but **cannot** exercise *stale-encoded* accounts whose
    secret predates a PEK rotation and was never rewritten. That tail remains a small, sampled blind
    spot; document it, don't pretend it's covered.
- **Count reconcile — fail-closed.** Accounts processed must match the expected population
  (DB/`Get-ADUser` count) within tolerance. Guards **enumeration truncation** (e.g., a cursor that
  stops early) — a failure the canary cannot see.
- **Aggregate hit-rate sanity — warn (optional).** If the flagged fraction exceeds an implausible
  share of enabled accounts, warn/fail. Free backstop for the self-evident global-false-positive
  case; replaces the (rejected) negative control.

**Error-direction asymmetry (why the harness is shaped this way):** false negatives are silent and
dangerous → guard hard (canary + reconcile). False positives are loud and self-correcting → a cheap
aggregate warn suffices.

---

## 8. Security, Safety & Handling

- **`ntds.dit` = the entire domain's secrets.** The snapshot and every extracted hash are
  maximum-sensitivity material. Encrypt at rest and in transit; minimize copies; strict chain of
  custody; **secure, verified destruction** at P10.
- **Authorized use only.** No run without written, scoped authorization (P0). This is a defensive
  credential-hygiene tool; treat the snapshot with the same care as the DC itself.
- **Isolated analysis host.** Dedicated, hardened, network-isolated; not a daily-driver workstation.
- **No production write-back, ever.** The tool only reads; remediation (resets) is a separate,
  human-owned step (P9).
- **Audit the auditor.** Log who ran what, when, against which snapshot, with which dictionary
  fingerprint (never log the dictionary contents or any hash).
- **Canary hygiene.** Unique weak password, reused nowhere; deny all logon rights; no SPN; sensitive
  + not-delegated; retire/rotate at P10; documented so responders don't panic.

---

## 9. Roles & Responsibilities

| Role | Responsibility |
|---|---|
| Approver | Authorizes scope/window; owns risk acceptance. |
| Operator | Executes P1–P8; runs the tool; honors fail-closed gates. |
| Data Custodian | Governs snapshot transfer, storage, and destruction (P3, P10). |
| Remediation owner | Acts on findings (P9). |

---

## 10. POC Scope — buildable now vs. lab-gated

**Buildable & unit-testable now (no DC, cross-platform-friendly):**
- The **extractor contract** (`AccountSecret` schema) and the pluggable interface.
- The **matcher** (map build + lookup) — pure logic; ported from the trimmed de-minimis cmdlet.
- The **candidate hasher** *design* with two impls: in-box CNG MD4 (prod) and a portable managed
  MD4 (dev/test), both validated against published **NT-hash known-answer vectors**
  (e.g., `NThash("password") = 8846F7EAEE8FB117AD06BDD830B7586C`).
- The **assurance harness** (canary check + count reconcile + hit-rate warn) against synthetic
  `AccountSecret` fixtures.
- The **reporter** and run-metadata/fingerprint format.
- CLI/module surface (`Test-ADPasswordDictionary`) and parameter design.

**Lab-gated (requires a Windows lab DC):**
- `ntdsutil` IFM snapshot; BootKey retrieval.
- The DSInternals black-box extractor wired to a real `ntds.dit`.
- In-box CNG MD4 execution (needs `bcrypt.dll`).
- Full end-to-end run + canary/reconcile validation on real data across a DB epoch.

**Testing strategy without a lab:** drive the whole downstream pipeline with **synthetic
`AccountSecret` fixtures** (hand-built hash→account records, including a canary record), so matcher +
assurance + reporter are fully exercised offline. The extractor is the only component that must wait
for the lab, and it sits behind the contract precisely so everything else doesn't have to.

---

## 11. Phased Delivery

1. **Phase A (now):** contract + matcher + hasher (portable MD4) + assurance harness + reporter,
   with synthetic fixtures and NT-hash KAT vectors. Fully unit-tested offline.
2. **Phase B (lab):** DSInternals black-box extractor adapter; IFM + BootKey; in-box CNG MD4;
   end-to-end on a lab DC; validate the fail-closed gates on real data.
3. **Phase C (optional, later):** first-party static-file extractor behind the same contract, gated
   by the same assurance harness and diffed against DSInternals on identical snapshots before trust.

---

## 12. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Silent false negatives (garbage decrypt) | Positive canary, fail-closed (§7). |
| Enumeration truncation | Count reconcile, fail-closed (§7). |
| Stale-PEK-encoded accounts missed | Documented sampled blind spot; if critical, diff against DSInternals on same snapshot. |
| Snapshot leakage (crown jewels) | Encryption, isolation, chain of custody, verified destruction (§8). |
| DB-epoch/format drift (AES vs RC4) | Black-box maintained extractor first; assurance gate catches misdecrypt. |
| Owning the extractor balloons scope | Deferred to Phase C behind the contract; not on the POC critical path. |

---

## 13. Open Decision

- **Extractor ownership (Phase C trigger):** ship on the DSInternals black-box indefinitely, or
  invest in a first-party static-file extractor later? *Recommendation:* black-box for POC and
  initial use; only build the owned extractor if a hard "zero-non-OEM-dependency" mandate materializes
  — and if so, gate it behind the same canary/reconcile harness and validate against DSInternals
  before trusting it. **Nothing else in the architecture changes** either way, by design.
