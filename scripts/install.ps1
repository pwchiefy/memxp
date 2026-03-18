[CmdletBinding()]
param(
    [string]$Version = "",
    [switch]$VerifyOnly,
    [string]$InstallDir = "$env:LOCALAPPDATA\memxp",
    [switch]$NoBackup,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$repoOwner = "pwchiefy"
$repoName = "memxp"

if ($Help) {
    Write-Host "memxp installer"
    Write-Host ""
    Write-Host "Usage: .\install.ps1 [-Version <tag>] [-VerifyOnly] [-InstallDir <path>] [-NoBackup]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Version       Target version/tag (e.g. v0.2.0). Defaults to latest release."
    Write-Host "  -VerifyOnly    Download release artifacts and verify checksum only."
    Write-Host "  -InstallDir    Destination directory for memxp.exe"
    Write-Host "  -NoBackup      Skip backup/restore copy for existing binary replacement."
    exit 0
}

if (-not $Version) {
    if ($env:MEMXP_VERSION) {
        $Version = $env:MEMXP_VERSION
    } else {
        Write-Host "fetching latest release..."
        $latest = Invoke-RestMethod -Headers @{ Accept = "application/vnd.github+json" } -Uri "https://api.github.com/repos/$repoOwner/$repoName/releases/latest"
        $Version = $latest.tag_name
    }
}

$Version = $Version.TrimStart('v')
$asset = "memxp-windows-x86_64"
$archive = "$asset.zip"

$baseUrl = "https://github.com/$repoOwner/$repoName/releases/download/v$Version"
$checksumsUrl = "$baseUrl/checksums.txt"
$artifactUrl = "$baseUrl/$archive"

$tmp = Join-Path $env:TEMP ("memxp-install-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

try {
    Write-Host "Downloading checksums..."
    $checksumFile = Join-Path $tmp "checksums.txt"
    Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumFile

    $expected = Select-String -Path $checksumFile -Pattern ("\s" + [regex]::Escape($archive) + "$") |
        ForEach-Object { ($_ -split "\s+")[0] }
    if (-not $expected) {
        throw "checksum not found for $archive"
    }

    Write-Host "Downloading memxp v$Version ($archive)..."
    $archiveFile = Join-Path $tmp $archive
    Invoke-WebRequest -Uri $artifactUrl -OutFile $archiveFile

    $hash = (Get-FileHash -Path $archiveFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -ne $expected.ToLowerInvariant()) {
        throw "checksum mismatch: expected $expected, got $hash"
    }

    if ($VerifyOnly) {
        Write-Host "checksum-ok: v$Version/$archive"
        exit 0
    }

    $extractDir = Join-Path $tmp "extract"
    Expand-Archive -Path $archiveFile -DestinationPath $extractDir -Force
    $binary = Join-Path $extractDir "memxp.exe"
    if (-not (Test-Path $binary)) {
        throw "memxp.exe not found in archive"
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $target = Join-Path $InstallDir "memxp.exe"

    if ((Test-Path $target) -and (-not $NoBackup)) {
        $backup = "$target.bak.$((Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss"))"
        Copy-Item $target $backup
        Write-Host "backed up existing binary to $backup"
    }

    Copy-Item -Path $binary -Destination $target -Force

    # Create backward-compat symlink (vaultp2p.exe -> memxp.exe)
    $legacyLink = Join-Path $InstallDir "vaultp2p.exe"
    if (-not (Test-Path $legacyLink)) {
        try { New-Item -ItemType SymbolicLink -Path $legacyLink -Target $target -Force | Out-Null } catch {}
    }

    Write-Host "installed to $target"

    # Install cr-sqlite extension to active config directory
    # Mirror the binary's fallback logic: prefer .memxp, fall back to .vaultp2p
    $newDir = Join-Path $env:USERPROFILE ".memxp"
    $legacyDir = Join-Path $env:USERPROFILE ".vaultp2p"
    if (Test-Path $newDir) {
        $vaultDir = $newDir
    } elseif (Test-Path $legacyDir) {
        $vaultDir = $legacyDir
    } else {
        $vaultDir = $newDir
    }
    New-Item -ItemType Directory -Path $vaultDir -Force | Out-Null
    $crsqliteExt = Join-Path $extractDir "crsqlite.dll"
    if (Test-Path $crsqliteExt) {
        Copy-Item -Path $crsqliteExt -Destination (Join-Path $vaultDir "crsqlite.dll") -Force
        Write-Host "installed cr-sqlite extension to $vaultDir\crsqlite.dll"
    } else {
        Write-Host "warning: crsqlite.dll not found in archive (P2P sync requires it)"
    }
} finally {
    Remove-Item -Recurse -Force $tmp
}
