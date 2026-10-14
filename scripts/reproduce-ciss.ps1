param(
    [ValidateSet('named', 'full')][string]$Mode = 'named',
    [ValidateSet('init', 'baseline', 'hardened', 'summary', 'all')][string]$Phase = 'all',
    [string]$RunId = ('release-' + (Get-Date -Format 'yyyyMMddTHHmmss'))
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($RunId -notmatch '^[a-zA-Z0-9][a-zA-Z0-9-]{0,70}$') { throw 'RunId must contain only letters, digits and hyphens.' }
$repoRoot = Split-Path -Parent $PSScriptRoot
$scratch = Join-Path $repoRoot ".tmp/ciss-$RunId"
$runtimeFile = Join-Path $scratch 'runtime.json'
function Invoke-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Docker command failed (exit $LASTEXITCODE). Preserve the run and retry with a fresh RunId." }
}
function New-FixtureWallet {
    $walletJson = & docker run --rm --entrypoint cast ghcr.io/foundry-rs/foundry:v1.0.0 wallet new --json
    if ($LASTEXITCODE -ne 0) { throw 'Could not generate disposable development wallet.' }
    return ($walletJson | ConvertFrom-Json)[0]
}
Push-Location $repoRoot
$oldVariables = @{}
$names = @('GOVPROV_DEV_DEPLOYER_PRIVATE_KEY', 'GOVPROV_TEMPORAL_ACTOR_PRIVATE_KEY', 'GOVPROV_DEV_ADMIN_ADDRESS', 'GOVPROV_TEMPORAL_RUN_ID', 'GOVPROV_TEMPORAL_CASES_TSV', 'GOVPROV_TEMPORAL_CASES_JSON')
foreach ($name in $names) { $oldVariables[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    if ($Phase -eq 'init' -or $Phase -eq 'all') {
        if (Test-Path -LiteralPath $scratch) { throw 'RunId already exists; choose a fresh one. Existing runs are preserved.' }
        New-Item -ItemType Directory -Path $scratch | Out-Null
        Invoke-Docker @('compose', 'run', '--rm', 'foundry')
        $admin = New-FixtureWallet
        $actor = New-FixtureWallet
        $runtime = @{ admin = $admin; actor = $actor; mode = $Mode; run_id = $RunId }
        [IO.File]::WriteAllText($runtimeFile, ($runtime | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
        foreach ($kind in @('baseline', 'hardened')) {
            $relativeData = "./.tmp/ciss-$RunId/$kind-chain"
            $overrideText = @"
services:
  besu-dev:
    ports: !override []
    volumes: !override
      - ${relativeData}:/var/lib/besu
      - ./chain/besu/dev/qbft-config.json:/etc/besu/qbft-config.json:ro
      - ./chain/besu/dev/start-besu-dev.sh:/etc/besu/start-besu-dev.sh:ro
"@
            [IO.File]::WriteAllText((Join-Path $scratch "$kind.yaml"), $overrideText, [Text.UTF8Encoding]::new($false))
        }
    }
    if (!(Test-Path -LiteralPath $runtimeFile)) { throw 'Initialize this RunId with -Phase init first, or use -Phase all.' }
    $runtime = Get-Content -LiteralPath $runtimeFile -Raw | ConvertFrom-Json
    if ($runtime.mode -ne $Mode) { throw 'Mode differs from the initialized run.' }
    $env:GOVPROV_DEV_DEPLOYER_PRIVATE_KEY = $runtime.admin.private_key
    $env:GOVPROV_TEMPORAL_ACTOR_PRIVATE_KEY = $runtime.actor.private_key
    $env:GOVPROV_DEV_ADMIN_ADDRESS = $runtime.admin.address
    $env:GOVPROV_TEMPORAL_CASES_JSON = ''
    $env:GOVPROV_TEMPORAL_CASES_TSV = ''
    if ($Mode -eq 'full') {
        $env:GOVPROV_TEMPORAL_CASES_JSON = '/workspace/packages/experiments/temporal-ordering/cases.enumerated.k1.json'
        $env:GOVPROV_TEMPORAL_CASES_TSV = '/workspace/packages/experiments/temporal-ordering/cases.enumerated.k1.tsv'
    }
    foreach ($kind in @('baseline', 'hardened')) {
        if ($Phase -ne 'all' -and $Phase -ne $kind) { continue }
        $prefix = @('compose', '--project-directory', $repoRoot, '-p', "govreplay-$RunId-$kind", '-f', 'compose.yaml', '-f', (Join-Path $scratch "$kind.yaml"), '--profile', 'besu-dev')
        $env:GOVPROV_TEMPORAL_RUN_ID = if ($kind -eq 'baseline') { "temporal-$RunId" } else { "hardening-$RunId" }
        Invoke-Docker ($prefix + @('up', '-d', 'besu-dev'))
        try {
            if ($kind -eq 'baseline') {
                Invoke-Docker ($prefix + @('--profile', 'temporal-ordering', 'run', '--rm', '--no-deps', '--entrypoint', 'sh', 'temporal-ordering-besu', './scripts/temporal-ordering-besu-retry.sh'))
                Invoke-Docker ($prefix + @('--profile', 'temporal-ordering', 'run', '--rm', '--no-deps', 'temporal-ordering-report'))
            } else {
                Invoke-Docker ($prefix + @('--profile', 'temporal-hardening', 'run', '--rm', '--no-deps', 'temporal-hardening-besu'))
                Invoke-Docker ($prefix + @('--profile', 'temporal-hardening', 'run', '--rm', '--no-deps', 'temporal-hardening-report'))
            }
        } finally {
            # Stop only this isolated project. Preserve chain data for receipt inspection.
            Invoke-Docker ($prefix + @('stop', 'besu-dev'))
        }
    }
    if ($Phase -eq 'summary' -or $Phase -eq 'all') {
        $mount = "${repoRoot}:/workspace"
        $base = "/workspace/runs/temporal-$RunId/temporal_ordering"
        $hard = "/workspace/runs/hardening-$RunId/temporal_ordering"
        $output = "/workspace/.tmp/ciss-$RunId"
        if ($Mode -eq 'full') {
            Invoke-Docker @('run', '--rm', '-v', $mount, '-w', '/workspace', 'node:24.2.0-alpine', 'node', '--experimental-strip-types', 'packages/experiments/temporal-ordering/src/propertyCheck.ts', $base, $hard, "$output/properties.json")
            Invoke-Docker @('run', '--rm', '-v', $mount, '-w', '/workspace', 'node:24.2.0-alpine', 'node', '--experimental-strip-types', 'packages/experiments/temporal-ordering/src/summarizeEnumeration.ts', 'packages/experiments/temporal-ordering/release/frozen-predictions.json', $base, $hard, $output)
        }
        Invoke-Docker @('run', '--rm', '-v', $mount, '-w', '/workspace', 'node:24.2.0-alpine', 'node', '--experimental-strip-types', 'scripts/check-ciss-release.ts', $base, $hard)
    }
    Write-Host "Completed phase $Phase for $RunId ($Mode). Outputs remain under runs/ and .tmp/; runtime.json contains disposable keys and must stay private."
} finally {
    foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $oldVariables[$name], 'Process') }
    Pop-Location
}
