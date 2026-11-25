# unblock.ps1 - remove the Mark-of-the-Web (Zone.Identifier ADS).
#
# The browser attaches Zone.Identifier (ZoneId=3) to every download. That single
# NTFS alternate data stream is what makes SmartScreen show "Windows protected
# your PC" and what makes Defender/AMSI treat the file as untrusted. Clearing it
# is the same thing Explorer's "Unblock" checkbox does.
#
# Usage (single file):
#   powershell -File scripts\unblock.ps1 -Path C:\Users\Public\lab\AddinLoader.dll
# Usage (whole extracted folder, recursively):
#   powershell -ExecutionPolicy Bypass -File scripts\unblock.ps1 -Path C:\path\extracted -Recurse
#
# NOTE: Unblock-File only clears the ADS; it does NOT stop Defender from
# deleting the payload on write if a signature/ML rule matches the file itself.
# See docs/README.md for that class of mitigation (garble, code-signing, lab
# exclusion).
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [switch]$Recurse
)

$ErrorActionPreference = "Stop"

$target = Get-Item -LiteralPath (Resolve-Path -LiteralPath $Path).Path
if ($target.PSIsContainer) {
    $files = Get-ChildItem -LiteralPath $target.FullName -File -Recurse:$Recurse
} else {
    $files = @($target)
}

$cleared = 0
$still = 0
foreach ($f in $files) {
    Unblock-File -LiteralPath $f.FullName -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $f.FullName -Stream Zone.Identifier -Force -ErrorAction SilentlyContinue
    if (Get-Item -LiteralPath $f.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue) {
        $still++
    } else {
        $cleared++
    }
}

Write-Host "[+] MOTW cleared on $cleared file(s)"
if ($still -gt 0) {
    Write-Host "[-] Zone.Identifier still present on $still file(s)"
    exit 1
}
