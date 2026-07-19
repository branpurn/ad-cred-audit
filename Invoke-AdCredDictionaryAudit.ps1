#Requires -Version 5.1
<#
.SYNOPSIS
    Offline Active Directory custom-dictionary password audit — SINGLE-FILE tool.

    Flags accounts whose current password appears in a supplied dictionary, using an OFFLINE copy
    of ntds.dit. No authentication, no lockouts. Not a module: one self-contained .ps1.

.DESCRIPTION
    Design constraints (fixed):
      * Delivered as ONE .ps1 file. No module, no dot-sourced components.
      * OEM-first: PowerShell + in-box native APIs (CNG bcrypt.dll for MD4; esent.dll for the
        ntds.dit reader) via Add-Type P/Invoke. Microsoft prerequisites (.NET Framework, the RSAT
        ActiveDirectory module) are installed out-of-band; we ship no third-party code.

    Pipeline: extract -> hash dictionary (in-box CNG MD4) -> match -> fail-closed assurance -> report.

    A canary account (known weak password placed in the dictionary) MUST be flagged, or the run
    FAILS CLOSED as untrustworthy rather than reporting a false "all clear."

.PARAMETER SelfTest
    Run embedded known-answer tests (matcher/assurance logic + in-box CNG NT-hash KAT) and exit.
    No external test framework required.

.EXAMPLE
    .\Invoke-AdCredDictionaryAudit.ps1 -SelfTest

.EXAMPLE
    .\Invoke-AdCredDictionaryAudit.ps1 -DatabasePath C:\ifm\ntds.dit -BootKey <hex> `
        -DictionaryFile .\weak.txt -Canary svc-canary-pos -ExpectedCount 4210

.EXAMPLE
    # Offline development against a JSON fixture (no DC; CNG still used to hash the dictionary):
    .\Invoke-AdCredDictionaryAudit.ps1 -FixturePath .\accounts.json -Dictionary password -Canary canary
#>
[CmdletBinding()]
param(
    [string]$DatabasePath,
    [string]$BootKey,
    [string[]]$Dictionary,
    [string]$DictionaryFile,
    [string]$Canary,                       # required for a real run; validated in Main (not [Mandatory]
                                           # so -SelfTest and dot-sourcing don't trigger a prompt)
    [switch]$IncludeDisabledAccounts,
    [int]$ExpectedCount = -1,
    [string]$FixturePath,                  # dev: load AccountSecret records from JSON instead of extracting
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'

#region Interop — in-box native crypto (OEM Tier-1). NT hash via the CNG MD4 provider in bcrypt.dll.
if (-not ('AdCredAudit.NtHash' -as [type])) {
@'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AdCredAudit
{
    public static class NtHash
    {
        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptHash(IntPtr hAlgorithm, byte[] pbSecret, uint cbSecret, byte[] pbInput, uint cbInput, byte[] pbOutput, uint cbOutput);

        // NT hash = MD4(UTF-16LE(password)), computed with the in-box CNG MD4 provider.
        public static byte[] Compute(string password)
        {
            IntPtr hAlg = IntPtr.Zero;
            int status = BCryptOpenAlgorithmProvider(out hAlg, "MD4", null, 0);
            if (status != 0) throw new Exception(string.Format("BCryptOpenAlgorithmProvider(MD4) failed: 0x{0:X8}", status));
            try
            {
                byte[] input = Encoding.Unicode.GetBytes(password);
                byte[] output = new byte[16];
                status = BCryptHash(hAlg, null, 0, input, (uint)input.Length, output, (uint)output.Length);
                if (status != 0) throw new Exception(string.Format("BCryptHash(MD4) failed: 0x{0:X8}", status));
                return output;
            }
            finally
            {
                if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
            }
        }
    }
}
'@ | Add-Type -Language CSharp
}
#endregion Interop

#region Extract — the pluggable seam. Contract: AccountSecret = { SamAccountName, Rid, NtHashHex, Enabled }.
function Get-AccountSecret {
    # Lab-gated (Phase B): read the offline ntds.dit and decrypt each NT hash using in-box esent.dll
    # + CNG/advapi32 crypto (embedded C# via Add-Type). Stubbed until built & validated in a lab.
    [CmdletBinding()]
    param([string]$DatabasePath, [string]$BootKey, [switch]$IncludeDisabledAccounts)
    throw [System.NotImplementedException]::new(
        "Get-AccountSecret: ntds.dit extraction is lab-gated (Phase B). " +
        "Use -FixturePath for offline development, or implement the esent.dll reader in this region.")
}

function Import-AccountSecretFixture {
    # Dev/test substitute for the extractor. Fixture = JSON array of AccountSecret records.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $raw = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    foreach ($r in $raw) {
        [PSCustomObject]@{
            SamAccountName = [string]$r.SamAccountName
            Rid            = [int]$r.Rid
            NtHashHex      = ([string]$r.NtHashHex).ToUpperInvariant()
            Enabled        = [bool]$r.Enabled
        }
    }
}
#endregion Extract

#region Hash — candidate hashing. Dictionary words -> NT-hash hex via in-box CNG.
function ConvertTo-NtHashHex {
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][AllowEmptyString()][string]$Password)
    process {
        if ($null -eq $Password) { return }
        $bytes = [AdCredAudit.NtHash]::Compute($Password)
        ([System.BitConverter]::ToString($bytes) -replace '-', '').ToUpperInvariant()
    }
}
#endregion Hash

#region Match — build a hash->accounts map, then look up candidate hashes. O(accounts + dictionary).
function Build-NtHashMap {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Account)
    $map = @{}
    foreach ($a in $Account) {
        if ([string]::IsNullOrEmpty($a.NtHashHex)) { continue }
        $key = $a.NtHashHex.ToUpperInvariant()
        if (-not $map.ContainsKey($key)) { $map[$key] = [System.Collections.Generic.List[string]]::new() }
        $map[$key].Add($a.SamAccountName)
    }
    ,$map
}

function Find-DictionaryMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$HashMap,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$CandidateHashHex
    )
    $hits = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $CandidateHashHex) {
        if ([string]::IsNullOrEmpty($c)) { continue }
        $key = $c.ToUpperInvariant()
        if ($HashMap.ContainsKey($key)) { foreach ($sam in $HashMap[$key]) { [void]$hits.Add($sam) } }
    }
    ,$hits
}
#endregion Match

#region Assure — trust gate, runs BEFORE reporting. Fail-closed.
function Test-AuditAssurance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Matched,
        [string]$CanarySamAccountName,
        [int]$ProcessedCount = -1,
        [int]$ExpectedCount  = -1,
        [int]$EnabledCount   = -1,
        [double]$MaxHitRate  = 0.5
    )
    $matchedArr = @($Matched)
    $failures = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()

    # Positive canary — fail-closed (guards silent false negatives).
    if ([string]::IsNullOrWhiteSpace($CanarySamAccountName)) {
        $failures.Add('No canary specified — results cannot be certified (fail-closed).')
    }
    elseif ($matchedArr -notcontains $CanarySamAccountName) {
        $failures.Add("Canary '$CanarySamAccountName' was NOT flagged — extraction/match pipeline is untrustworthy (fail-closed).")
    }

    # Count reconcile — fail-closed when an expected count is supplied (guards enumeration truncation).
    if ($ExpectedCount -ge 0 -and $ProcessedCount -ne $ExpectedCount) {
        $failures.Add("Count reconcile failed: processed $ProcessedCount of $ExpectedCount expected accounts (fail-closed).")
    }

    # Aggregate hit-rate sanity — warn only (false positives are self-evident).
    if ($EnabledCount -gt 0) {
        $findingCount = @($matchedArr | Where-Object { $_ -ne $CanarySamAccountName }).Count
        $rate = $findingCount / $EnabledCount
        if ($rate -gt $MaxHitRate) {
            $warnings.Add(('Hit rate {0:P0} exceeds {1:P0} of enabled accounts — possible global false positive; review.' -f $rate, $MaxHitRate))
        }
    }

    [PSCustomObject]@{
        Passed   = ($failures.Count -eq 0)
        Failures = $failures.ToArray()
        Warnings = $warnings.ToArray()
    }
}
#endregion Assure

#region Report — findings + run metadata. Canary allowlisted out; dictionary fingerprinted, never stored.
function Get-DictionaryFingerprint {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$CandidateHashHex)
    $joined = (($CandidateHashHex | Sort-Object -Unique) -join "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($joined))
        ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function Format-AuditReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Matched,
        [int]$AccountsProcessed,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$CandidateHashHex,
        [string]$Canary,
        [Parameter(Mandatory)][object]$Assurance
    )
    $findings = @(@($Matched) | Where-Object { $_ -ne $Canary } | Sort-Object)
    [PSCustomObject]@{
        GeneratedUtc          = [DateTime]::UtcNow.ToString('o')
        AccountsProcessed     = $AccountsProcessed
        DictionaryEntries     = @($CandidateHashHex | Sort-Object -Unique).Count
        DictionaryFingerprint = Get-DictionaryFingerprint -CandidateHashHex $CandidateHashHex
        Canary                = $Canary
        AssurancePassed       = $Assurance.Passed
        AssuranceWarnings     = $Assurance.Warnings
        MatchCount            = $findings.Count
        MatchedAccounts       = $findings
    }
}
#endregion Report

#region SelfTest — embedded known-answer tests. No external framework.
function Invoke-SelfTest {
    [CmdletBinding()]
    param()
    $results = [System.Collections.Generic.List[object]]::new()
    $assert  = { param($name, $cond) $results.Add([PSCustomObject]@{ Test = $name; Passed = [bool]$cond }) }
    $Pw = '8846F7EAEE8FB117AD06BDD830B7586C'  # NThash("password")

    $accts = @(
        [PSCustomObject]@{ SamAccountName = 'alice';  NtHashHex = $Pw },
        [PSCustomObject]@{ SamAccountName = 'bob';    NtHashHex = 'AABBCCDDEEFF00112233445566778899' },
        [PSCustomObject]@{ SamAccountName = 'canary'; NtHashHex = $Pw }
    )
    $map = Build-NtHashMap -Account $accts
    $m   = Find-DictionaryMatch -HashMap $map -CandidateHashHex @($Pw)
    & $assert 'matcher flags alice'                 (@($m) -contains 'alice')
    & $assert 'matcher flags canary'                (@($m) -contains 'canary')
    & $assert 'matcher skips non-match (bob)'       (-not (@($m) -contains 'bob'))
    & $assert 'matcher is case-insensitive on hex'  ((@(Find-DictionaryMatch -HashMap $map -CandidateHashHex @($Pw.ToLower()))) -contains 'alice')

    $pass = Test-AuditAssurance -Matched $m -CanarySamAccountName 'canary' -ProcessedCount 3 -ExpectedCount 3
    & $assert 'assurance passes when canary present'          ($pass.Passed)
    & $assert 'assurance FAILS when canary absent'            (-not (Test-AuditAssurance -Matched @('alice') -CanarySamAccountName 'canary' -ProcessedCount 3 -ExpectedCount 3).Passed)
    & $assert 'assurance FAILS on count mismatch'             (-not (Test-AuditAssurance -Matched @('canary') -CanarySamAccountName 'canary' -ProcessedCount 2 -ExpectedCount 3).Passed)
    & $assert 'assurance FAILS when no canary specified'      (-not (Test-AuditAssurance -Matched @('alice') -CanarySamAccountName '' -ProcessedCount 3).Passed)

    $rep = Format-AuditReport -Matched $m -AccountsProcessed 3 -CandidateHashHex @($Pw) -Canary 'canary' -Assurance $pass
    & $assert 'report allowlists canary out of findings' ($rep.MatchCount -eq 1 -and @($rep.MatchedAccounts).Count -eq 1 -and @($rep.MatchedAccounts)[0] -eq 'alice')

    # In-box CNG NT-hash known-answer test (Windows / bcrypt.dll only).
    try {
        $kat = ConvertTo-NtHashHex -Password 'password'
        & $assert "CNG NT-hash KAT  NThash('password')=8846F7EA..." ($kat -eq $Pw)
    }
    catch {
        & $assert 'CNG NT-hash KAT (requires Windows/bcrypt.dll)' $false
        Write-Warning "CNG MD4 unavailable on this host: $($_.Exception.Message)"
    }

    foreach ($r in $results) { Write-Host ('  {0}  {1}' -f $(if ($r.Passed) { 'PASS' } else { 'FAIL' }), $r.Test) }
    $failed = @($results | Where-Object { -not $_.Passed }).Count
    if ($failed -gt 0) { throw "SELF-TEST FAILED: $failed of $($results.Count) checks failed." }
    Write-Host ('SELF-TEST PASSED: {0}/{0} checks.' -f $results.Count)
}
#endregion SelfTest

#region Main — orchestration. Guarded so dot-sourcing only defines functions.
if ($MyInvocation.InvocationName -ne '.') {

    if ($SelfTest) { Invoke-SelfTest; return }

    if ([string]::IsNullOrWhiteSpace($Canary)) { throw 'A -Canary account name is required for a trustworthy run (fail-closed).' }

    # 1. Accounts from the offline copy (fixture during development; real extractor in the lab).
    $accounts = if ($FixturePath) {
        Import-AccountSecretFixture -Path $FixturePath
    } elseif ($DatabasePath) {
        Get-AccountSecret -DatabasePath $DatabasePath -BootKey $BootKey -IncludeDisabledAccounts:$IncludeDisabledAccounts
    } else {
        throw 'Provide either -FixturePath (dev) or -DatabasePath (an offline ntds.dit copy).'
    }

    # Tag the canary by name; drop disabled accounts unless asked, but never drop the canary.
    $accounts = @($accounts | ForEach-Object {
        $_ | Add-Member -NotePropertyName IsCanary -NotePropertyValue ([bool]($_.SamAccountName -eq $Canary)) -Force -PassThru
    })
    if (-not $IncludeDisabledAccounts) { $accounts = @($accounts | Where-Object { $_.Enabled -or $_.IsCanary }) }

    # 2. Dictionary -> candidate NT hashes (in-box CNG MD4).
    $words = @()
    if ($Dictionary)     { $words += $Dictionary }
    if ($DictionaryFile) { $words += Get-Content -LiteralPath $DictionaryFile }
    if (-not $words)     { throw 'No dictionary provided (-Dictionary and/or -DictionaryFile).' }
    $candidates = @($words | ConvertTo-NtHashHex)

    # 3. Match.
    $map     = Build-NtHashMap -Account $accounts
    $matched = Find-DictionaryMatch -HashMap $map -CandidateHashHex $candidates

    # 4. Assurance — fail closed BEFORE any findings are emitted.
    $enabledCount = @($accounts | Where-Object { $_.Enabled }).Count
    $assurance = Test-AuditAssurance -Matched $matched -CanarySamAccountName $Canary `
        -ProcessedCount $accounts.Count -ExpectedCount $ExpectedCount -EnabledCount $enabledCount
    if (-not $assurance.Passed) { throw "AUDIT UNTRUSTWORTHY (fail-closed): $($assurance.Failures -join ' | ')" }
    foreach ($w in $assurance.Warnings) { Write-Warning $w }

    # 5. Report.
    Format-AuditReport -Matched $matched -AccountsProcessed $accounts.Count `
        -CandidateHashHex $candidates -Canary $Canary -Assurance $assurance
}
#endregion Main
