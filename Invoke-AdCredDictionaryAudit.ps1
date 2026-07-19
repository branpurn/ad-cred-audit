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
    [switch]$SelfTest,
    [switch]$EseProbe,                     # B1 lab probe: open -DatabasePath read-only and print datatable row count
    [switch]$EseDumpAccounts,              # B2 lab probe: dump the first -First account rows
    [int]$First = 20,
    [string]$SystemHivePath,               # offline SYSTEM hive copy (boot key source)
    [switch]$BootKeyProbe                   # B3 lab probe: derive + print the boot key from -SystemHivePath
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
    }

    // B1 scope: open + count datatable rows. MoveFirst/MoveNext are public for the B2+ column-retrieval work.
    public sealed class EseReader : IDisposable
    {
        private IntPtr _instance = IntPtr.Zero;   // JET_INSTANCE  (pointer-sized)
        private IntPtr _sesid    = IntPtr.Zero;   // JET_SESID     (pointer-sized)
        private uint   _dbid     = 0;             // JET_DBID      (32-bit)
        private IntPtr _table    = IntPtr.Zero;   // JET_TABLEID   (pointer-sized)
        private bool _instInited, _sessionOpen, _tableOpen;

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
        private uint _colSam, _colSamType, _colUac, _colSid, _colNtHash;
        private bool _hasSam, _hasSamType, _hasUac, _hasSid, _hasNtHash;

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

            // Global (before instance creation):
            Check(JetSetSystemParameterGlobal(IntPtr.Zero, IntPtr.Zero, JET_paramDatabasePageSize, (IntPtr)NtdsPageSize, null), "set page size");

            Check(JetCreateInstance(out _instance, "adcredaudit"), "create instance");

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

            row.HasNtHash = _hasNtHash && Retrieve(_colNtHash) != null;
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
