[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA "agy-manager\bin")
)

$ErrorActionPreference = "Stop"
$repo = "QNIX-Dev/eligibility-antigravity-patcher"
$asset = "agy-manager-windows-x64.zip"
$baseUrl = "https://github.com/$repo/releases/latest/download"
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("agy-manager-" + [guid]::NewGuid())

try {
    New-Item -ItemType Directory -Force -Path $temporary | Out-Null
    Invoke-WebRequest -Uri "$baseUrl/$asset" -OutFile (Join-Path $temporary $asset)
    Invoke-WebRequest -Uri "$baseUrl/SHA256SUMS" -OutFile (Join-Path $temporary "SHA256SUMS")
    $expected = ((Get-Content (Join-Path $temporary "SHA256SUMS") | Where-Object { $_ -match "\s$asset$" }) -split '\s+')[0]
    if (-not $expected) { throw "No checksum found for $asset" }
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $temporary $asset)).Hash.ToLowerInvariant()
    if ($actual -ne $expected.ToLowerInvariant()) { throw "Checksum verification failed" }

    Expand-Archive -Force (Join-Path $temporary $asset) $temporary
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Force (Join-Path $temporary "agy-manager.exe") (Join-Path $InstallDir "agy-manager.exe")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (($userPath -split ';') -notcontains $InstallDir) {
        $newPath = if ($userPath) { $userPath.TrimEnd(';') + ";" + $InstallDir } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Host "Added $InstallDir to the user PATH. Open a new terminal."
    }
    Write-Host "Installed: $(Join-Path $InstallDir 'agy-manager.exe')"
}
finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $temporary
}
