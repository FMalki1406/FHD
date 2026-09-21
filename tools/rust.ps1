param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $CargoArguments
)

$ErrorActionPreference = 'Stop'
$taskProjectRoot = Split-Path -Parent $PSScriptRoot
$taskCargoHome = Join-Path $taskProjectRoot '.tools\cargo'
$taskRustupHome = Join-Path $taskProjectRoot '.tools\rustup'
$taskCargo = Join-Path $taskCargoHome 'bin\cargo.exe'
if (-not (Test-Path -LiteralPath $taskCargo)) {
    throw 'Project-local Rust is missing. See docs/development.md for setup.'
}
$taskPreviousCargoHome = $env:CARGO_HOME
$taskPreviousRustupHome = $env:RUSTUP_HOME
try {
    $env:CARGO_HOME = $taskCargoHome
    $env:RUSTUP_HOME = $taskRustupHome
    Push-Location -LiteralPath $taskProjectRoot
    try {
        & $taskCargo @CargoArguments
        $taskCargoExit = $LASTEXITCODE
    } finally {
        Pop-Location
    }
} finally {
    $env:CARGO_HOME = $taskPreviousCargoHome
    $env:RUSTUP_HOME = $taskPreviousRustupHome
}
exit $taskCargoExit
