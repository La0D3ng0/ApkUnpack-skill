param(
    [Parameter(Mandatory = $true)]
    [string]$SdkRoot,
    [string]$JavaHome,
    [switch]$AcceptSdkLicense
)

$ErrorActionPreference = "Stop"
if (-not $AcceptSdkLicense) {
    throw "Review the Android SDK license, then rerun with -AcceptSdkLicense"
}
if ($JavaHome) {
    $env:JAVA_HOME = [System.IO.Path]::GetFullPath($JavaHome)
}

$skillRoot = $PSScriptRoot
$lockPath = Join-Path $skillRoot "build-tools.lock.json"
$lock = Get-Content -Raw -Encoding UTF8 $lockPath | ConvertFrom-Json
$sdkPath = [System.IO.Path]::GetFullPath($SdkRoot)
$downloadRoot = Join-Path $sdkPath ".reverse-skills-downloads"
$commandZip = Join-Path $downloadRoot "commandlinetools-win-15859902_latest.zip"
$commandRoot = Join-Path $sdkPath "cmdline-tools\reverse-skills-15859902"
New-Item -ItemType Directory -Force -Path $downloadRoot | Out-Null

if (-not (Test-Path -LiteralPath $commandZip -PathType Leaf)) {
    Invoke-WebRequest -Uri $lock.command_line_tools_windows.url -OutFile $commandZip
}
$commandHash = (Get-FileHash -LiteralPath $commandZip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($commandHash -ne $lock.command_line_tools_windows.sha256) {
    throw "Command-line tools checksum mismatch: $commandHash"
}
if (-not (Test-Path -LiteralPath $commandRoot)) {
    New-Item -ItemType Directory -Force -Path $commandRoot | Out-Null
    Expand-Archive -LiteralPath $commandZip -DestinationPath $commandRoot
}

$sdkManager = Join-Path $commandRoot "cmdline-tools\bin\sdkmanager.bat"
if (-not (Test-Path -LiteralPath $sdkManager -PathType Leaf)) {
    throw "sdkmanager was not found after extraction: $sdkManager"
}
1..20 | ForEach-Object { "y" } | & $sdkManager --sdk_root=$sdkPath "build-tools;36.0.0"
if ($LASTEXITCODE -ne 0) {
    throw "sdkmanager failed to install build-tools;36.0.0"
}

$buildTools = Join-Path $sdkPath "build-tools\36.0.0"
foreach ($entry in $lock.installed_files.PSObject.Properties) {
    $relative = $entry.Name.Replace("/", [System.IO.Path]::DirectorySeparatorChar)
    $path = Join-Path $buildTools $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing Build Tools file: $($entry.Name)"
    }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $entry.Value) {
        throw "Checksum mismatch for $($entry.Name): $actual"
    }
}

Write-Output "Verified Android Build Tools 36.0.0 at $buildTools"
