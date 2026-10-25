param(
    [string]$ToolDirectory,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ToolArguments
)

$ErrorActionPreference = "Stop"
if (-not $ToolDirectory) {
    $ToolDirectory = Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "reverse-skills\smali-3.0.9"
}
$lib = [IO.Path]::GetFullPath($ToolDirectory)
if (-not (Test-Path -LiteralPath (Join-Path $lib "smali-3.0.9.jar"))) {
    throw "Run install_smali_toolchain.ps1 first"
}
& java -cp (Join-Path $lib "*") com.android.tools.smali.smali.Main @ToolArguments
exit $LASTEXITCODE
