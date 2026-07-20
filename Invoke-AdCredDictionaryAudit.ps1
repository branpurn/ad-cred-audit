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
    [switch]$IncludeComputerAccounts,      # include machine/trust accounts (default: user accounts only)
    [int]$ExpectedCount = -1,
    [string]$FixturePath,                  # dev: load AccountSecret records from JSON instead of extracting
    [switch]$SelfTest,
    [switch]$EseProbe,                     # B1 lab probe: open -DatabasePath read-only and print datatable row count
    [switch]$EseDumpAccounts,              # B2 lab probe: dump the first -First account rows
    [int]$First = 20,
    [string]$SystemHivePath,               # offline SYSTEM hive copy (boot key source)
    [switch]$BootKeyProbe,                  # B3 lab probe: derive + print the boot key from -SystemHivePath
    [switch]$PekProbe,                      # B4 lab probe: decrypt + summarize the PEK list
    [switch]$HashProbe                      # B5 lab probe: decrypt + print per-account NT hashes
)

$ErrorActionPreference = 'Stop'

#region Interop — in-box native crypto (OEM Tier-1). NT hash via the CNG MD4 provider in bcrypt.dll.
if (-not ('AdCredAudit.NtHash' -as [type])) {
    $ntHashSource = @'
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
'@
    Add-Type -TypeDefinition $ntHashSource -Language CSharp
}
#endregion Interop

#region ESE Interop — B1: open an offline ntds.dit read-only and iterate the datatable (esent.dll, in-box).
#
#  LAB-VALIDATION CHECKLIST (this block cannot be exercised off-Windows; it only *compiles* here):
#   1. Entry points use ANSI base exports (JetSetSystemParameter, JetCreateInstance, JetBeginSession,
#      JetAttachDatabase, JetOpenDatabase, JetOpenTable). If EntryPointNotFoundException -> switch to the
#      W-suffixed exports + CharSet.Unicode.
#   2. Page size is pinned to 8192 (ntds.dit default). If JET_errPageSizeMismatch (-1213) -> adjust.
#   3. Opens recovery-Off / read-only, expecting a CLEAN shutdown. If JET_errDatabaseDirtyShutdown (-550)
#      -> operator runs `esentutl /r <logbase>` (or supply a clean IFM copy) before auditing.
#   4. System/Temp/Log paths are pointed at %TEMP% so nothing is written into a read-only snapshot dir.
#   5. Handles sized as IntPtr (JET_INSTANCE/SESID/TABLEID) and JET_DBID as uint; validated for 64-bit.
#   6. JetOpenTable grbit = 0 (read intent inherited from the read-only DB); add JET_bitTableReadOnly(0x4) if needed.
#
if (-not ('AdCredAudit.EseReader' -as [type])) {
    $eseSource = @'
using System;
using System.Runtime.InteropServices;

namespace AdCredAudit
{
    public sealed class EseException : Exception
    {
        public int Code;
        public EseException(int code, string context)
            : base(string.Format("ESENT error {0} [{1}] during {2}.", code, EseReader.ErrName(code), context))
        { this.Code = code; }
    }

    public sealed class AccountRow
    {
        public string SamAccountName;
        public int SamAccountType;
        public int UserAccountControl;
        public long Rid;
        public string Sid;
        public bool HasNtHash;
        public bool Enabled;
        public byte[] NtHashBlob;   // raw encrypted unicodePwd blob (decrypted in PS via Secret.DecryptNtHash)
    }

    // B1 scope: open + count datatable rows. MoveFirst/MoveNext are public for the B2+ column-retrieval work.
    public sealed class EseReader : IDisposable
    {
        private IntPtr _instance = IntPtr.Zero;   // JET_INSTANCE  (pointer-sized)
        private IntPtr _sesid    = IntPtr.Zero;   // JET_SESID     (pointer-sized)
        private uint   _dbid     = 0;             // JET_DBID      (32-bit)
        private IntPtr _table    = IntPtr.Zero;   // JET_TABLEID   (pointer-sized)
        private bool _instInited, _sessionOpen, _tableOpen;
        private static int _instanceSeq;
        private static bool _pageSizeSet;   // JET_paramDatabasePageSize is process-global; set it once (M4)

        private const uint JET_bitDbReadOnly            = 0x1;
        private const int  JET_MoveFirst                = unchecked((int)0x80000000);
        private const int  JET_MoveNext                 = 1;
        private const uint JET_paramSystemPath          = 0;
        private const uint JET_paramTempPath            = 1;
        private const uint JET_paramLogFilePath         = 2;
        private const uint JET_paramMaxTemporaryTables  = 60;
        private const uint JET_paramRecovery            = 34;
        private const uint JET_paramDatabasePageSize    = 64;
        private const int  err_Success                  = 0;
        private const int  err_NoCurrentRecord          = -1603;
        private const int  err_DatabaseDirtyShutdown    = -550;
        private const int  err_PageSizeMismatch         = -1213;
        private const int  NtdsPageSize                 = 8192;
        private const uint JET_ColInfo                  = 0;
        private const int  err_ColumnNotFound           = -1004;
        private const int  JET_wrnColumnNull            = 1004;
        private const int  JET_wrnBufferTruncated       = 1006;
        // Well-known ATTRTYP datatable column names (system attributes; IDs are fixed/stable).
        private const string Col_SamAccountName     = "ATTm590045";
        private const string Col_SamAccountType     = "ATTj590126";
        private const string Col_UserAccountControl = "ATTj589832";
        private const string Col_ObjectSid          = "ATTr589970";
        private const string Col_UnicodePwd         = "ATTk589914";
        private const string Col_PekList            = "ATTk590689";

        // Global param (pinstance = NULL): must be set before the instance exists.
        [DllImport("esent.dll", CharSet = CharSet.Ansi, EntryPoint = "JetSetSystemParameter")]
        private static extern int JetSetSystemParameterGlobal(IntPtr pinstance, IntPtr sesid, uint paramid, IntPtr lParam, string szParam);
        // Per-instance param (pinstance = &instance): set after create, before init.
        [DllImport("esent.dll", CharSet = CharSet.Ansi, EntryPoint = "JetSetSystemParameter")]
        private static extern int JetSetSystemParameterInst(ref IntPtr pinstance, IntPtr sesid, uint paramid, IntPtr lParam, string szParam);
        [DllImport("esent.dll", CharSet = CharSet.Ansi)]
        private static extern int JetCreateInstance(out IntPtr instance, string szInstanceName);
        [DllImport("esent.dll")]
        private static extern int JetInit(ref IntPtr instance);
        [DllImport("esent.dll", CharSet = CharSet.Ansi)]
        private static extern int JetBeginSession(IntPtr instance, out IntPtr sesid, string szUserName, string szPassword);
        [DllImport("esent.dll", CharSet = CharSet.Ansi)]
        private static extern int JetAttachDatabase(IntPtr sesid, string szFilename, uint grbit);
        [DllImport("esent.dll", CharSet = CharSet.Ansi)]
        private static extern int JetOpenDatabase(IntPtr sesid, string szFilename, string szConnect, out uint dbid, uint grbit);
        [DllImport("esent.dll", CharSet = CharSet.Ansi)]
        private static extern int JetOpenTable(IntPtr sesid, uint dbid, string szTableName, IntPtr pvParameters, uint cbParameters, uint grbit, out IntPtr tableid);
        [DllImport("esent.dll")]
        private static extern int JetMove(IntPtr sesid, IntPtr tableid, int cRow, uint grbit);
        [DllImport("esent.dll")]
        private static extern int JetCloseTable(IntPtr sesid, IntPtr tableid);
        [DllImport("esent.dll")]
        private static extern int JetEndSession(IntPtr sesid, uint grbit);
        [DllImport("esent.dll")]
        private static extern int JetTerm(IntPtr instance);
        [DllImport("esent.dll", CharSet = CharSet.Ansi)]
        private static extern int JetGetTableColumnInfo(IntPtr sesid, IntPtr tableid, string szColumnName, ref JET_COLUMNDEF pvResult, uint cbMax, uint InfoLevel);
        [DllImport("esent.dll")]
        private static extern int JetRetrieveColumn(IntPtr sesid, IntPtr tableid, uint columnid, byte[] pvData, uint cbData, out uint cbActual, uint grbit, IntPtr pretinfo);

        [StructLayout(LayoutKind.Sequential)]
        private struct JET_COLUMNDEF
        {
            public uint cbStruct; public uint columnid; public uint coltyp;
            public ushort wCountry; public ushort langid; public ushort cp; public ushort wCollate;
            public uint cbMax; public uint grbit;
        }

        // ---- B2 column state (resolved once, lazily) ----
        private bool _columnsResolved;
        private uint _colSam, _colSamType, _colUac, _colSid, _colNtHash, _colPek;
        private bool _hasSam, _hasSamType, _hasUac, _hasSid, _hasNtHash, _hasPek;

        public static string ErrName(int code)
        {
            switch (code)
            {
                case err_NoCurrentRecord:       return "JET_errNoCurrentRecord";
                case err_DatabaseDirtyShutdown: return "JET_errDatabaseDirtyShutdown - recover with 'esentutl /r' or supply a clean copy";
                case err_PageSizeMismatch:      return "JET_errPageSizeMismatch - DB page size != 8192";
                default:                        return "JET_err";
            }
        }

        private static void Check(int err, string context)
        {
            if (err != err_Success) throw new EseException(err, context);
        }

        public EseReader(string dbPath)
        {
            string tempDir = System.IO.Path.GetTempPath();

            // Global page size must be set once per process, BEFORE any instance is JetInit'd.
            // Re-setting it after a prior instance was initialized fails, so guard to set-once (M4).
            if (!_pageSizeSet)
            {
                Check(JetSetSystemParameterGlobal(IntPtr.Zero, IntPtr.Zero, JET_paramDatabasePageSize, (IntPtr)NtdsPageSize, null), "set page size");
                _pageSizeSet = true;
            }

            string instName = "adcredaudit_" + System.Threading.Interlocked.Increment(ref _instanceSeq);
            Check(JetCreateInstance(out _instance, instName), "create instance");

            // Per-instance (after create, before init):
            Check(JetSetSystemParameterInst(ref _instance, IntPtr.Zero, JET_paramRecovery, IntPtr.Zero, "Off"), "disable recovery");
            Check(JetSetSystemParameterInst(ref _instance, IntPtr.Zero, JET_paramMaxTemporaryTables, IntPtr.Zero, null), "no temp tables");
            Check(JetSetSystemParameterInst(ref _instance, IntPtr.Zero, JET_paramSystemPath, IntPtr.Zero, tempDir), "system path");
            Check(JetSetSystemParameterInst(ref _instance, IntPtr.Zero, JET_paramTempPath, IntPtr.Zero, tempDir), "temp path");
            Check(JetSetSystemParameterInst(ref _instance, IntPtr.Zero, JET_paramLogFilePath, IntPtr.Zero, tempDir), "log path");

            Check(JetInit(ref _instance), "init"); _instInited = true;
            Check(JetBeginSession(_instance, out _sesid, null, null), "begin session"); _sessionOpen = true;
            Check(JetAttachDatabase(_sesid, dbPath, JET_bitDbReadOnly), "attach database");
            Check(JetOpenDatabase(_sesid, dbPath, null, out _dbid, JET_bitDbReadOnly), "open database");
        }

        private void OpenDatatable()
        {
            if (_tableOpen) return;
            Check(JetOpenTable(_sesid, _dbid, "datatable", IntPtr.Zero, 0, 0, out _table), "open datatable");
            _tableOpen = true;
        }

        public bool MoveFirst()
        {
            OpenDatatable();
            int err = JetMove(_sesid, _table, JET_MoveFirst, 0);
            if (err == err_NoCurrentRecord) return false;
            Check(err, "move first");
            return true;
        }

        public bool MoveNext()
        {
            int err = JetMove(_sesid, _table, JET_MoveNext, 0);
            if (err == err_NoCurrentRecord) return false;
            Check(err, "move next");
            return true;
        }

        // B1 deliverable: open the datatable and count every row.
        public long CountDatatableRows()
        {
            long count = 0;
            if (MoveFirst()) { do { count++; } while (MoveNext()); }
            return count;
        }

        // ---- B2: column resolution + retrieval + account-row reading ----

        private bool TryGetColumn(string name, out uint columnid)
        {
            JET_COLUMNDEF def = new JET_COLUMNDEF();
            def.cbStruct = (uint)Marshal.SizeOf(typeof(JET_COLUMNDEF));
            int err = JetGetTableColumnInfo(_sesid, _table, name, ref def, def.cbStruct, JET_ColInfo);
            if (err == err_ColumnNotFound) { columnid = 0; return false; }
            Check(err, "column info " + name);
            columnid = def.columnid;
            return true;
        }

        private void ResolveColumns()
        {
            if (_columnsResolved) return;
            OpenDatatable();
            _hasSam     = TryGetColumn(Col_SamAccountName, out _colSam);
            _hasSamType = TryGetColumn(Col_SamAccountType, out _colSamType);
            _hasUac     = TryGetColumn(Col_UserAccountControl, out _colUac);
            _hasSid     = TryGetColumn(Col_ObjectSid, out _colSid);
            _hasNtHash  = TryGetColumn(Col_UnicodePwd, out _colNtHash);
            _hasPek     = TryGetColumn(Col_PekList, out _colPek);
            _columnsResolved = true;
        }

        // Returns the raw column value of the current row, or null when the column is absent/null.
        private byte[] Retrieve(uint columnid)
        {
            uint cb;
            int err = JetRetrieveColumn(_sesid, _table, columnid, null, 0, out cb, 0, IntPtr.Zero);
            if (err == JET_wrnColumnNull || cb == 0) return null;
            if (err != err_Success && err != JET_wrnBufferTruncated) Check(err, "retrieve size");
            byte[] buf = new byte[cb];
            err = JetRetrieveColumn(_sesid, _table, columnid, buf, cb, out cb, 0, IntPtr.Zero);
            if (err == JET_wrnColumnNull) return null;
            if (err != err_Success && err != JET_wrnBufferTruncated) Check(err, "retrieve data");
            return buf;
        }

        // Reads core account fields from the current row; null if the row has no sAMAccountName.
        public AccountRow ReadCurrentAccountRow()
        {
            ResolveColumns();
            if (!_hasSam) return null;
            byte[] nameBytes = Retrieve(_colSam);
            if (nameBytes == null) return null;

            AccountRow row = new AccountRow();
            row.SamAccountName = System.Text.Encoding.Unicode.GetString(nameBytes).TrimEnd('\0');

            byte[] st = _hasSamType ? Retrieve(_colSamType) : null;
            row.SamAccountType = (st != null && st.Length >= 4) ? BitConverter.ToInt32(st, 0) : 0;

            byte[] uac = _hasUac ? Retrieve(_colUac) : null;
            row.UserAccountControl = (uac != null && uac.Length >= 4) ? BitConverter.ToInt32(uac, 0) : 0;
            row.Enabled = (row.UserAccountControl & 0x2) == 0;   // ADS_UF_ACCOUNTDISABLE

            byte[] sid = _hasSid ? Retrieve(_colSid) : null;
            if (sid != null && sid.Length >= 8)
            {
                int n = sid.Length;
                // ntds.dit stores the RID (last 4 bytes) BIG-endian.
                row.Rid = ((long)sid[n - 4] << 24) | ((long)sid[n - 3] << 16) | ((long)sid[n - 2] << 8) | (long)sid[n - 1];
                row.Sid = FormatSid(sid);
            }

            row.NtHashBlob = _hasNtHash ? Retrieve(_colNtHash) : null;
            row.HasNtHash = row.NtHashBlob != null;
            return row;
        }

        // B2 deliverable: dump up to `max` account rows (user/machine/trust) for eyeball validation.
        public System.Collections.Generic.List<AccountRow> DumpAccountRows(int max)
        {
            var list = new System.Collections.Generic.List<AccountRow>();
            if (!MoveFirst()) return list;
            do
            {
                AccountRow row = ReadCurrentAccountRow();
                if (row != null && IsAccountType(row.SamAccountType))
                {
                    list.Add(row);
                    if (max > 0 && list.Count >= max) break;
                }
            } while (MoveNext());
            return list;
        }

        private static bool IsAccountType(int t)
        {
            // SAM_NORMAL_USER_ACCOUNT / SAM_MACHINE_ACCOUNT / SAM_TRUST_ACCOUNT
            return t == 0x30000000 || t == 0x30000001 || t == 0x30000002;
        }

        // B4: the encrypted PEK list sits on the domain NC head — the single row with a non-null pekList.
        public byte[] FindPekListBlob()
        {
            ResolveColumns();
            if (!_hasPek) throw new Exception("pekList column (ATTk590689) not found in datatable.");
            if (!MoveFirst()) return null;
            do
            {
                byte[] blob = Retrieve(_colPek);
                if (blob != null && blob.Length > 24) return blob;
            } while (MoveNext());
            return null;
        }

        private static string FormatSid(byte[] sid)
        {
            byte[] b = (byte[])sid.Clone();
            int n = b.Length;
            // Reverse the big-endian RID back to standard little-endian for display.
            byte t;
            t = b[n - 4]; b[n - 4] = b[n - 1]; b[n - 1] = t;
            t = b[n - 3]; b[n - 3] = b[n - 2]; b[n - 2] = t;
            byte revision = b[0];
            int subCount = b[1];
            long authority = 0;
            for (int i = 0; i < 6; i++) authority = (authority << 8) | b[2 + i];
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            sb.Append("S-").Append(revision).Append('-').Append(authority);
            for (int i = 0; i < subCount && 8 + i * 4 + 4 <= b.Length; i++)
            {
                sb.Append('-').Append(BitConverter.ToUInt32(b, 8 + i * 4));
            }
            return sb.ToString();
        }

        public void Dispose()
        {
            try { if (_tableOpen)   { JetCloseTable(_sesid, _table); _tableOpen = false; } } catch { }
            try { if (_sessionOpen) { JetEndSession(_sesid, 0);      _sessionOpen = false; } } catch { }
            try { if (_instInited)  { JetTerm(_instance);            _instInited = false; } } catch { }
        }
    }
}
'@
    Add-Type -TypeDefinition $eseSource -Language CSharp
}

function Measure-NtdsDatatableRow {
    # B1 lab probe: open an offline ntds.dit read-only and count datatable rows.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DatabasePath)
    $resolved = (Resolve-Path -LiteralPath $DatabasePath).Path
    $reader = [AdCredAudit.EseReader]::new($resolved)
    try { $reader.CountDatatableRows() }
    finally { $reader.Dispose() }
}

function Get-NtdsAccountRow {
    # B2 lab probe: dump the first N account rows (name / RID / SID / type / enabled / has-hash).
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DatabasePath, [int]$First = 20)
    $resolved = (Resolve-Path -LiteralPath $DatabasePath).Path
    $reader = [AdCredAudit.EseReader]::new($resolved)
    try {
        foreach ($r in $reader.DumpAccountRows($First)) {
            [PSCustomObject]@{
                SamAccountName = $r.SamAccountName
                Rid            = $r.Rid
                Sid            = $r.Sid
                Type           = ('0x{0:X8}' -f $r.SamAccountType)
                Enabled        = $r.Enabled
                HasNtHash      = $r.HasNtHash
            }
        }
    }
    finally { $reader.Dispose() }
}
#endregion ESE Interop

#region BootKey Interop — B3: derive the boot key from an offline SYSTEM hive (advapi32, in-box).
#
#  LAB NOTES: uses RegLoadAppKey (no SeRestorePrivilege needed, loads a private copy). The hive file
#  must be WRITABLE (RegLoadAppKey may journal) — copy the snapshot SYSTEM to a writable path first.
#  The boot-key bytes live in the *class* names of the JD/Skew1/GBG/Data keys (read via RegQueryInfoKey).
#  Validate by comparing to DSInternals `Get-BootKey -Path <SYSTEM>` on the same hive.
#
if (-not ('AdCredAudit.BootKey' -as [type])) {
    $bootKeySource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace AdCredAudit
{
    public static class BootKey
    {
        private const uint KEY_READ = 0x20019;
        private static readonly int[] KeyPermutation = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };
        private static readonly string[] BootKeySubKeys = { "JD", "Skew1", "GBG", "Data" };

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegLoadAppKeyW")]
        private static extern int RegLoadAppKey(string lpFile, out IntPtr phkResult, uint samDesired, uint dwOptions, uint Reserved);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegOpenKeyExW")]
        private static extern int RegOpenKeyEx(IntPtr hKey, string lpSubKey, uint ulOptions, uint samDesired, out IntPtr phkResult);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegQueryValueExW")]
        private static extern int RegQueryValueEx(IntPtr hKey, string lpValueName, IntPtr lpReserved, out uint lpType, byte[] lpData, ref uint lpcbData);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RegQueryInfoKeyW")]
        private static extern int RegQueryInfoKey(IntPtr hKey, StringBuilder lpClass, ref uint lpcchClass, IntPtr lpReserved,
            out uint lpcSubKeys, out uint lpcbMaxSubKeyLen, out uint lpcbMaxClassLen, out uint lpcValues,
            out uint lpcbMaxValueNameLen, out uint lpcbMaxValueLen, out uint lpcbSecurityDescriptor, IntPtr lpftLastWriteTime);
        [DllImport("advapi32.dll")]
        private static extern int RegCloseKey(IntPtr hKey);

        public static byte[] GetBootKey(string systemHivePath)
        {
            IntPtr hHive;
            int rc = RegLoadAppKey(systemHivePath, out hHive, KEY_READ, 0, 0);
            if (rc != 0) throw new Exception("RegLoadAppKey failed (" + rc + "). Ensure the path is a writable SYSTEM hive copy, not already loaded.");
            try
            {
                int ccs = GetCurrentControlSet(hHive);
                string lsaPath = string.Format("ControlSet{0:D3}\\Control\\Lsa", ccs);
                IntPtr hLsa;
                rc = RegOpenKeyEx(hHive, lsaPath, 0, KEY_READ, out hLsa);
                if (rc != 0) throw new Exception("Open " + lsaPath + " failed (" + rc + ").");
                try
                {
                    byte[] scrambled = new byte[16];
                    for (int i = 0; i < BootKeySubKeys.Length; i++)
                    {
                        byte[] part = HexToBytes(GetKeyClass(hLsa, BootKeySubKeys[i]));
                        Array.Copy(part, 0, scrambled, i * 4, part.Length);
                    }
                    byte[] bootKey = new byte[16];
                    for (int i = 0; i < 16; i++) bootKey[i] = scrambled[KeyPermutation[i]];
                    return bootKey;
                }
                finally { RegCloseKey(hLsa); }
            }
            finally { RegCloseKey(hHive); }
        }

        private static int GetCurrentControlSet(IntPtr hHive)
        {
            IntPtr hSelect;
            if (RegOpenKeyEx(hHive, "Select", 0, KEY_READ, out hSelect) != 0) return 1;   // absent in some copied hives
            try
            {
                uint type; uint cb = 4; byte[] data = new byte[4];
                if (RegQueryValueEx(hSelect, "Current", IntPtr.Zero, out type, data, ref cb) != 0) return 1;
                return BitConverter.ToInt32(data, 0);
            }
            finally { RegCloseKey(hSelect); }
        }

        private static string GetKeyClass(IntPtr hParent, string subKeyName)
        {
            IntPtr hSub;
            int rc = RegOpenKeyEx(hParent, subKeyName, 0, KEY_READ, out hSub);
            if (rc != 0) throw new Exception("Open Lsa\\" + subKeyName + " failed (" + rc + ").");
            try
            {
                StringBuilder cls = new StringBuilder(256);
                uint cch = (uint)cls.Capacity;
                uint sk, mskl, mcl, vals, mvnl, mvl, sd;
                rc = RegQueryInfoKey(hSub, cls, ref cch, IntPtr.Zero, out sk, out mskl, out mcl, out vals, out mvnl, out mvl, out sd, IntPtr.Zero);
                if (rc != 0) throw new Exception("Query class of " + subKeyName + " failed (" + rc + ").");
                return cls.ToString();
            }
            finally { RegCloseKey(hSub); }
        }

        private static byte[] HexToBytes(string hex)
        {
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }
    }
}
'@
    Add-Type -TypeDefinition $bootKeySource -Language CSharp
}

function Get-NtdsBootKey {
    # B3 lab probe: derive the boot key from an offline SYSTEM hive; returns 32-char lowercase hex.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$SystemHivePath)
    $resolved = (Resolve-Path -LiteralPath $SystemHivePath).Path
    $bytes = [AdCredAudit.BootKey]::GetBootKey($resolved)
    -join ($bytes | ForEach-Object { $_.ToString('x2') })
}
#endregion BootKey Interop

#region Secret Crypto — B4/B5: PEK list + secret decryption (advapi32 RC4 + BCL MD5/AES, in-box).
#
#  LAB NOTES: RC4 is advapi32 SystemFunction032 (== SystemFunction033; RC4 is symmetric — swap if one
#  export is missing). AES path is CBC/PKCS7, IV=salt, key=bootKey/PEK (mirrors DSInternals). A VALID
#  PEK signature GUID after decryption is a strong end-to-end check on the boot key + RC4/AES path.
#
if (-not ('AdCredAudit.Secret' -as [type])) {
    $secretSource = @'
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace AdCredAudit
{
    public sealed class PekList
    {
        public int Version;
        public int Flags;
        public int CurrentKeyIndex;
        public byte[][] Keys;
        public bool SignatureValid;
        public int KeyCount { get { return Keys == null ? 0 : Keys.Length; } }
        public string VersionName { get { return Version == 3 ? "W2016 (AES)" : Version == 2 ? "W2k (RC4)" : ("v" + Version); } }
        public byte[] Key(int index) { return (Keys != null && index >= 0 && index < Keys.Length) ? Keys[index] : null; }
    }

    public static class Secret
    {
        // PEK list signature GUID {4881d956-91ec-11d1-905a-00c04fc2d4cf} in stored byte order.
        private static readonly byte[] PekSignature = new Guid("4881d956-91ec-11d1-905a-00c04fc2d4cf").ToByteArray();

        [StructLayout(LayoutKind.Sequential)]
        private struct USTRING { public int Length; public int MaximumLength; public IntPtr Buffer; }

        // RC4 (symmetric) via the in-box LSA helper.
        [DllImport("advapi32.dll", EntryPoint = "SystemFunction032")]
        private static extern int SystemFunction032(ref USTRING data, ref USTRING key);

        public static byte[] Rc4(byte[] data, byte[] key)
        {
            byte[] result = (byte[])data.Clone();
            GCHandle hData = GCHandle.Alloc(result, GCHandleType.Pinned);
            GCHandle hKey  = GCHandle.Alloc(key, GCHandleType.Pinned);
            try
            {
                USTRING d = new USTRING(); d.Length = result.Length; d.MaximumLength = result.Length; d.Buffer = hData.AddrOfPinnedObject();
                USTRING k = new USTRING(); k.Length = key.Length;    k.MaximumLength = key.Length;    k.Buffer = hKey.AddrOfPinnedObject();
                int st = SystemFunction032(ref d, ref k);
                if (st != 0) throw new Exception(string.Format("SystemFunction032 (RC4) failed: 0x{0:X8}", st));
                return result;
            }
            finally { hData.Free(); hKey.Free(); }
        }

        // MD5(key || salt x rounds) — mirrors DSInternals ComputeMD5.
        public static byte[] ComputeMd5(byte[] key, byte[] salt, int rounds)
        {
            using (MD5 md5 = MD5.Create())
            {
                md5.TransformBlock(key, 0, key.Length, null, 0);
                for (int i = 1; i < rounds; i++) md5.TransformBlock(salt, 0, salt.Length, null, 0);
                md5.TransformFinalBlock(salt, 0, salt.Length);
                return md5.Hash;
            }
        }

        public static byte[] DecryptRc4WithSalt(byte[] data, byte[] salt, byte[] key, int rounds)
        {
            return Rc4(data, ComputeMd5(key, salt, rounds));
        }

        public static byte[] DecryptAesCbc(byte[] data, byte[] iv, byte[] key)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                using (ICryptoTransform dec = aes.CreateDecryptor(key, iv))
                    return dec.TransformFinalBlock(data, 0, data.Length);
            }
        }

        // Version(4)|Flags(4)|Salt(16)|Encrypted... ; W2k=RC4(1000 rounds), W2016=AES(strip trailing 16B).
        public static PekList DecryptPekList(byte[] blob, byte[] bootKey)
        {
            RequireLength(blob, 25, "PEK list blob");   // 24-byte header + at least 1 byte of payload
            int version = BitConverter.ToInt32(blob, 0);
            int flags   = BitConverter.ToInt32(blob, 4);
            byte[] salt = new byte[16]; Array.Copy(blob, 8, salt, 0, 16);
            byte[] enc = new byte[blob.Length - 24]; Array.Copy(blob, 24, enc, 0, enc.Length);

            byte[] cleartext;
            if (flags == 1)
            {
                if (version == 2) cleartext = DecryptRc4WithSalt(enc, salt, bootKey, 1000);
                else if (version == 3)
                {
                    RequireLength(enc, 17, "encrypted PEK list (AES)");   // trailing 16B block + payload
                    byte[] trimmed = new byte[enc.Length - 16]; Array.Copy(enc, 0, trimmed, 0, trimmed.Length);
                    cleartext = DecryptAesCbc(trimmed, salt, bootKey);
                }
                else throw new Exception("Unsupported PEK list version: " + version);
            }
            else cleartext = enc;

            return ParsePekList(cleartext, version, flags);
        }

        // Signature(16)|LastGenerated(8)|CurrentKey(4)|KeyCount(4)|{KeyId(4)|Key(16)}
        private static PekList ParsePekList(byte[] blob, int version, int flags)
        {
            RequireLength(blob, 32, "decrypted PEK list");   // sig(16)+lastGen(8)+currentKey(4)+count(4)
            PekList pek = new PekList(); pek.Version = version; pek.Flags = flags;
            byte[] sig = new byte[16]; Array.Copy(blob, 0, sig, 0, 16);
            pek.SignatureValid = ByteEquals(sig, PekSignature);
            pek.CurrentKeyIndex = BitConverter.ToInt32(blob, 24);
            int numKeys = BitConverter.ToInt32(blob, 28);
            if (numKeys < 0 || numKeys > 1024) throw new Exception("Implausible PEK key count (" + numKeys + ") - wrong boot key or failed decryption.");
            RequireLength(blob, 32 + numKeys * 20, "decrypted PEK list keys");   // {keyId(4)+key(16)} x numKeys
            pek.Keys = new byte[numKeys][];
            int off = 32;
            for (int i = 0; i < numKeys; i++)
            {
                int keyId = BitConverter.ToInt32(blob, off); off += 4;
                byte[] key = new byte[16]; Array.Copy(blob, off, key, 0, 16); off += 16;
                if (keyId >= 0 && keyId < numKeys) pek.Keys[keyId] = key;
            }
            return pek;
        }

        private static bool ByteEquals(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        // M3: guard byte-offset reads so a truncated/corrupt blob yields a clear error, not ArgumentOutOfRange.
        private static void RequireLength(byte[] blob, int min, string what)
        {
            if (blob == null || blob.Length < min)
                throw new Exception(string.Format("Malformed {0}: need >= {1} bytes, got {2}.", what, min, blob == null ? 0 : blob.Length));
        }

        // ---- B5: per-account NT hash (layer 1 = PEK decrypt, layer 2 = DES-by-RID) ----

        [DllImport("advapi32.dll", EntryPoint = "SystemFunction027", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern int SystemFunction027([In] byte[] encrypted, [In] ref int index, [In, Out] byte[] output);

        // Layer 1: strip the PEK layer. AlgId(2)|Flags(2)|PekId(4)|Salt(16)|[AES only: SecretLen(4)]|EncData
        public static byte[] DecryptSecret(byte[] blob, PekList pek)
        {
            RequireLength(blob, 25, "secret blob");   // 24-byte header + at least 1 byte of payload
            int algId = BitConverter.ToUInt16(blob, 0);
            int pekId = BitConverter.ToInt32(blob, 4);
            byte[] salt = new byte[16]; Array.Copy(blob, 8, salt, 0, 16);
            byte[] key = pek.Key(pekId);
            if (key == null) throw new Exception("PEK index " + pekId + " not present in the PEK list.");

            if (algId == 0x11) // DatabaseRC4WithSalt (1 salt-hash round)
            {
                byte[] enc = new byte[blob.Length - 24]; Array.Copy(blob, 24, enc, 0, enc.Length);
                return DecryptRc4WithSalt(enc, salt, key, 1);
            }
            if (algId == 0x13) // DatabaseAES
            {
                RequireLength(blob, 29, "secret blob (AES)");   // 24-byte header + secretLen(4) + payload
                int secretLen = BitConverter.ToInt32(blob, 24);
                byte[] enc = new byte[blob.Length - 28]; Array.Copy(blob, 28, enc, 0, enc.Length);
                byte[] dec = DecryptAesCbc(enc, salt, key);
                if (secretLen >= 0 && secretLen < dec.Length)
                {
                    byte[] trimmed = new byte[secretLen]; Array.Copy(dec, 0, trimmed, 0, secretLen); return trimmed;
                }
                return dec;
            }
            throw new Exception("Unsupported secret encryption type: 0x" + algId.ToString("X"));
        }

        // Layer 2: remove the RID DES layer (in-box advapi32).
        public static byte[] DecryptDesByRid(byte[] encrypted16, int rid)
        {
            byte[] output = new byte[16];
            int st = SystemFunction027(encrypted16, ref rid, output);
            if (st != 0) throw new Exception(string.Format("SystemFunction027 (DES-by-RID) failed: 0x{0:X8}", st));
            return output;
        }

        // Full per-account NT hash: PEK layer then RID-DES layer.
        public static byte[] DecryptNtHash(byte[] unicodePwdBlob, int rid, PekList pek)
        {
            byte[] layer1 = DecryptSecret(unicodePwdBlob, pek);
            if (layer1.Length != 16) throw new Exception("Unexpected NT hash length after PEK decrypt: " + layer1.Length);
            return DecryptDesByRid(layer1, rid);
        }
    }
}
'@
    Add-Type -TypeDefinition $secretSource -Language CSharp
}

function Resolve-AuditBootKey {
    [CmdletBinding()]
    param([string]$BootKey, [string]$SystemHivePath)
    if ($SystemHivePath) {
        return [AdCredAudit.BootKey]::GetBootKey((Resolve-Path -LiteralPath $SystemHivePath).Path)
    }
    if ($BootKey) {
        $hex = ($BootKey -replace '[^0-9A-Fa-f]', '')
        if ($hex.Length -ne 32) { throw "BootKey must be 32 hex chars (16 bytes); got $($hex.Length)." }
        $b = New-Object byte[] 16
        for ($i = 0; $i -lt 16; $i++) { $b[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16) }
        return $b
    }
    throw 'Provide -SystemHivePath (offline SYSTEM hive) or -BootKey (32-hex).'
}

function Get-NtdsPekList {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DatabasePath, [string]$SystemHivePath, [string]$BootKey)
    $bootKeyBytes = Resolve-AuditBootKey -BootKey $BootKey -SystemHivePath $SystemHivePath
    $reader = [AdCredAudit.EseReader]::new((Resolve-Path -LiteralPath $DatabasePath).Path)
    try { $blob = $reader.FindPekListBlob() } finally { $reader.Dispose() }
    if (-not $blob) { throw 'No pekList blob found in the datatable.' }
    [AdCredAudit.Secret]::DecryptPekList($blob, $bootKeyBytes)
}

function Get-NtdsAccountHash {
    # B5: decrypt each account's NT hash (PEK layer + DES-by-RID). One ESE open for PEK + accounts.
    #
    # H2: users-only by default (SAM_NORMAL_USER_ACCOUNT = 0x30000000). Computer passwords are random
    #     and never match a dictionary, and including them makes -ExpectedCount reconcile unintuitive;
    #     -IncludeComputerAccounts adds machine/trust accounts back.
    # H1: a per-account decryption failure is collected (never silently skipped -> that would be a
    #     false negative) and triggers a FAIL-CLOSED abort at the end, with a count + sample, instead
    #     of the whole run dying opaquely on the first oddball account.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$DatabasePath,
        [string]$SystemHivePath,
        [string]$BootKey,
        [int]$First = 0,                       # 0 = all accounts
        [switch]$IncludeDisabledAccounts,
        [switch]$IncludeComputerAccounts
    )
    $bootKeyBytes = Resolve-AuditBootKey -BootKey $BootKey -SystemHivePath $SystemHivePath
    $reader = [AdCredAudit.EseReader]::new((Resolve-Path -LiteralPath $DatabasePath).Path)
    try {
        $blob = $reader.FindPekListBlob()
        if (-not $blob) { throw 'No pekList blob found in the datatable.' }
        $pek = [AdCredAudit.Secret]::DecryptPekList($blob, $bootKeyBytes)
        if (-not $pek.SignatureValid) {
            throw 'PEK signature invalid - boot key or decryption is wrong; refusing to emit hashes (fail-closed).'
        }
        $failures = [System.Collections.Generic.List[string]]::new()
        foreach ($r in $reader.DumpAccountRows($First)) {
            if (-not $r.NtHashBlob) { continue }
            if (-not $IncludeComputerAccounts -and $r.SamAccountType -ne 0x30000000) { continue }
            if (-not $IncludeDisabledAccounts  -and -not $r.Enabled) { continue }
            try {
                $nt = [AdCredAudit.Secret]::DecryptNtHash($r.NtHashBlob, [int]$r.Rid, $pek)
            }
            catch {
                $failures.Add(('{0} (RID {1}): {2}' -f $r.SamAccountName, $r.Rid, $_.Exception.Message))
                continue
            }
            [PSCustomObject]@{
                SamAccountName = $r.SamAccountName
                Rid            = $r.Rid
                Enabled        = $r.Enabled
                NtHashHex      = (-join ($nt | ForEach-Object { $_.ToString('X2') }))
            }
        }
        if ($failures.Count -gt 0) {
            $sample = ($failures | Select-Object -First 5) -join ' | '
            throw ('{0} account(s) failed to decrypt - results incomplete, refusing to certify (fail-closed). First few: {1}' -f $failures.Count, $sample)
        }
    }
    finally { $reader.Dispose() }
}
#endregion Secret Crypto

#region Extract — the pluggable seam. Contract: AccountSecret = { SamAccountName, Rid, NtHashHex, Enabled }.
function Get-AccountSecret {
    # B6: offline ntds.dit extractor. Emits an AccountSecret record for every USER account (enabled
    # and disabled; -IncludeComputerAccounts adds machine/trust). Main applies the enabled/canary
    # filter, same as the fixture path. Per-account decrypt failures fail-closed inside
    # Get-NtdsAccountHash. Heavy lifting lives in the ESE Interop and Secret Crypto regions (B1-B5).
    [CmdletBinding()]
    param([string]$DatabasePath, [string]$BootKey, [string]$SystemHivePath, [switch]$IncludeDisabledAccounts, [switch]$IncludeComputerAccounts)
    Get-NtdsAccountHash -DatabasePath $DatabasePath -SystemHivePath $SystemHivePath -BootKey $BootKey `
        -First 0 -IncludeDisabledAccounts -IncludeComputerAccounts:$IncludeComputerAccounts |
        ForEach-Object {
            [PSCustomObject]@{
                SamAccountName = $_.SamAccountName
                Rid            = [int]$_.Rid
                NtHashHex      = $_.NtHashHex.ToUpperInvariant()
                Enabled        = $_.Enabled
            }
        }
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
    # Emit the matched names as a normal enumeration (sorted, de-duplicated by the SortedSet) so both
    # `$x = Find-DictionaryMatch ...` and inline `@(Find-DictionaryMatch ...)` behave identically.
    $hits
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
    $assert  = { param($name, $cond) $results.Add([PSCustomObject]@{ Test = $name; Passed = [bool]$cond; Skipped = $false }) }
    $skip    = { param($name, $why) $results.Add([PSCustomObject]@{ Test = "$name (skipped: $why)"; Passed = $true; Skipped = $true }) }
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

    # In-box CNG NT-hash known-answer test — native, Windows-only. Skipped (not failed) elsewhere,
    # so the portable logic suite can go fully green on a non-Windows dev host (e.g. macOS pwsh 7).
    $onWindows = (-not (Test-Path Variable:\IsWindows)) -or $IsWindows   # 5.1 has no $IsWindows => Windows
    if ($onWindows) {
        try {
            $kat = ConvertTo-NtHashHex -Password 'password'
            & $assert "CNG NT-hash KAT  NThash('password')=8846F7EA..." ($kat -eq $Pw)
        }
        catch {
            & $assert 'CNG NT-hash KAT (bcrypt.dll call failed)' $false
            Write-Warning "CNG MD4 error: $($_.Exception.Message)"
        }
    }
    else {
        & $skip 'CNG NT-hash KAT' 'non-Windows host, bcrypt.dll unavailable'
    }

    foreach ($r in $results) {
        $tag = if ($r.Skipped) { 'SKIP' } elseif ($r.Passed) { 'PASS' } else { 'FAIL' }
        Write-Host ('  {0}  {1}' -f $tag, $r.Test)
    }
    $failed  = @($results | Where-Object { -not $_.Passed }).Count
    $skipped = @($results | Where-Object { $_.Skipped }).Count
    if ($failed -gt 0) { throw "SELF-TEST FAILED: $failed of $($results.Count) checks failed." }
    Write-Host ('SELF-TEST PASSED: {0} checks ({1} skipped).' -f $results.Count, $skipped)
}
#endregion SelfTest

#region Main — orchestration. Guarded so dot-sourcing only defines functions.
if ($MyInvocation.InvocationName -ne '.') {

    if ($SelfTest) { Invoke-SelfTest; return }

    if ($EseProbe) {
        if ([string]::IsNullOrWhiteSpace($DatabasePath)) { throw '-EseProbe requires -DatabasePath (an offline ntds.dit copy).' }
        $rows = Measure-NtdsDatatableRow -DatabasePath $DatabasePath
        Write-Host ("datatable rows: {0}" -f $rows)
        return
    }

    if ($EseDumpAccounts) {
        if ([string]::IsNullOrWhiteSpace($DatabasePath)) { throw '-EseDumpAccounts requires -DatabasePath (an offline ntds.dit copy).' }
        Get-NtdsAccountRow -DatabasePath $DatabasePath -First $First | Format-Table -AutoSize
        return
    }

    if ($BootKeyProbe) {
        if ([string]::IsNullOrWhiteSpace($SystemHivePath)) { throw '-BootKeyProbe requires -SystemHivePath (an offline SYSTEM hive copy).' }
        Write-Host ("boot key: {0}" -f (Get-NtdsBootKey -SystemHivePath $SystemHivePath))
        return
    }

    if ($PekProbe) {
        if ([string]::IsNullOrWhiteSpace($DatabasePath)) { throw '-PekProbe requires -DatabasePath (and -SystemHivePath or -BootKey).' }
        $pek = Get-NtdsPekList -DatabasePath $DatabasePath -SystemHivePath $SystemHivePath -BootKey $BootKey
        [PSCustomObject]@{
            Version         = $pek.VersionName
            FlagsEncrypted  = ($pek.Flags -eq 1)
            SignatureValid  = $pek.SignatureValid
            KeyCount        = $pek.KeyCount
            CurrentKeyIndex = $pek.CurrentKeyIndex
        } | Format-List
        return
    }

    if ($HashProbe) {
        if ([string]::IsNullOrWhiteSpace($DatabasePath)) { throw '-HashProbe requires -DatabasePath (and -SystemHivePath or -BootKey).' }
        Get-NtdsAccountHash -DatabasePath $DatabasePath -SystemHivePath $SystemHivePath -BootKey $BootKey `
            -First $First -IncludeDisabledAccounts:$IncludeDisabledAccounts `
            -IncludeComputerAccounts:$IncludeComputerAccounts | Format-Table -AutoSize
        return
    }

    if ([string]::IsNullOrWhiteSpace($Canary)) { throw 'A -Canary account name is required for a trustworthy run (fail-closed).' }

    # 1. Accounts from the offline copy (fixture during development; real extractor in the lab).
    $accounts = if ($FixturePath) {
        Import-AccountSecretFixture -Path $FixturePath
    } elseif ($DatabasePath) {
        Get-AccountSecret -DatabasePath $DatabasePath -BootKey $BootKey -SystemHivePath $SystemHivePath `
            -IncludeDisabledAccounts:$IncludeDisabledAccounts -IncludeComputerAccounts:$IncludeComputerAccounts
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
