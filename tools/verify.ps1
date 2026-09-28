# Everything a Windows box can check before a push, reporting an exit code per step.
#
# **Why a script rather than a command line.** The last push failed CI at the
# architecture gate, and the local run before it had failed too -- I did not see it,
# because I was reading a filtered log for the lines each step prints on success. A
# filter that matches success signals makes a failure look like silence, and the gate
# prints its findings in a shape that filter did not match. So this reports `name=code`
# for every step, and the summary at the end is the exit codes, not a search for
# reassuring words.
#
# Usage: ./tools/verify.ps1 [-SkipTests]
param([switch] $SkipTests)

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$previousCargoHome = $env:CARGO_HOME
$previousRustupHome = $env:RUSTUP_HOME
$previousPath = $env:PATH
$env:CARGO_HOME = Join-Path $root '.tools\cargo'
$env:RUSTUP_HOME = Join-Path $root '.tools\rustup'
$env:PATH = (Join-Path $env:CARGO_HOME 'bin') + ';' + $env:PATH
$log = Join-Path $env:TEMP ('fhd-verify-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.txt')
$results = [ordered] @{}

function Step {
    param([string] $Name, [scriptblock] $Body)
    ("=== " + $Name) | Out-File $log -Append -Encoding utf8
    & $Body *>> $log
    $script:results[$Name] = $LASTEXITCODE
    $mark = if ($LASTEXITCODE -eq 0) { 'ok  ' } else { 'FAIL' }
    Write-Host ("{0} {1} (exit {2})" -f $mark, $Name, $LASTEXITCODE)
}

Push-Location $root
try {
    Step 'fmt' { cargo fmt --all -- --check }
    Step 'clippy-windows' { cargo clippy --workspace --all-targets -- -D warnings }
    # The crates a Windows box can cross-check: `libsqlite3-sys` needs a C cross
    # compiler, so the daemon and the repository cannot be built for another target
    # here. This is the check that caught a Linux-only test file still calling an old
    # signature, after everything Windows compiles was already green.
    Step 'clippy-linux' {
        cargo clippy -p fhd-app -p fhd-domain -p fhd-storage -p fhd-runtime -p fhd-testkit `
            -p fhd-platform --lib --tests --target x86_64-unknown-linux-gnu -- -D warnings
    }
    Step 'clippy-macos' {
        cargo clippy -p fhd-platform --all-targets --target x86_64-apple-darwin -- -D warnings
    }
    Step 'architecture-gate' { node tools/check-architecture.mjs }
    Step 'architecture-gate-tests' { node tools/check-architecture.test.mjs }
    Step 'coverage-gate-tests' { node tools/check-contract-tests.test.mjs }
    Step 'coverage-gate' { node tools/check-contract-tests.mjs }
    if (-not $SkipTests) {
        Step 'tests' { cargo test --workspace }
    }
} finally {
    Pop-Location
    $env:CARGO_HOME = $previousCargoHome
    $env:RUSTUP_HOME = $previousRustupHome
    $env:PATH = $previousPath
}

Write-Host ''
Write-Host ("full output: " + $log)
$failed = @($results.GetEnumerator() | Where-Object { $_.Value -ne 0 })
if ($failed.Count -gt 0) {
    Write-Host ''
    Write-Host ("FAILED: " + ($failed | ForEach-Object { $_.Key }) -join ', ')
    exit 1
}
$counts = Select-String -Path $log -Pattern 'test result: ok\. (\d+) passed.*?(\d+) ignored' -AllMatches
$passed = 0
$ignored = 0
foreach ($match in $counts.Matches) {
    $passed += [int] $match.Groups[1].Value
    $ignored += [int] $match.Groups[2].Value
}
Write-Host ''
Write-Host ("every step passed. tests: {0} passed, {1} ignored" -f $passed, $ignored)
exit 0
