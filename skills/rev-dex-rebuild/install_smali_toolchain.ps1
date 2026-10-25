param(
    [string]$MavenCommand = "mvn",
    [string]$OutputDirectory
)

$ErrorActionPreference = "Stop"
$skillRoot = $PSScriptRoot
if (-not $OutputDirectory) {
    $cacheRoot = [Environment]::GetFolderPath("LocalApplicationData")
    $OutputDirectory = Join-Path $cacheRoot "reverse-skills\smali-3.0.9"
}
$outputPath = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

$maven = Get-Command $MavenCommand -ErrorAction Stop
$mavenLocation = Split-Path $maven.Source -Parent
Push-Location $mavenLocation
try {
    & $maven.Source -f (Join-Path $skillRoot "smali-pom.xml") dependency:copy-dependencies `
        "-DoutputDirectory=$outputPath" -DincludeScope=runtime
    if ($LASTEXITCODE -ne 0) {
        throw "Maven failed to resolve the smali toolchain"
    }
} finally {
    Pop-Location
}

$lock = Get-Content -Raw -Encoding UTF8 (Join-Path $skillRoot "smali-toolchain.lock.json") |
    ConvertFrom-Json
foreach ($entry in $lock.files.PSObject.Properties) {
    $path = Join-Path $outputPath $entry.Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing locked dependency: $($entry.Name)"
    }
    $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $entry.Value) {
        throw "Checksum mismatch for $($entry.Name): $actual"
    }
}

Write-Output "Verified smali 3.0.9 toolchain at $outputPath"
