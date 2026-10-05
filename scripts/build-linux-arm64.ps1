$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$outputDir = Join-Path $repoRoot 'bin/linux-arm64'
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

$goCommand = Get-Command go -ErrorAction Stop
$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
$previousCGOEnabled = $env:CGO_ENABLED

try {
    Push-Location $repoRoot
    $env:GOOS = 'linux'
    $env:GOARCH = 'arm64'
    $env:CGO_ENABLED = '0'

    & $goCommand.Source build -trimpath -o (Join-Path $outputDir 'flow') ./cmd/flow
    if ($LASTEXITCODE -ne 0) {
        throw "Building flow for Linux ARM64 failed with exit code $LASTEXITCODE."
    }

    & $goCommand.Source build -trimpath -o (Join-Path $outputDir 'flownode') ./cmd/flownode
    if ($LASTEXITCODE -ne 0) {
        throw "Building flownode for Linux ARM64 failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
    $env:GOOS = $previousGOOS
    $env:GOARCH = $previousGOARCH
    $env:CGO_ENABLED = $previousCGOEnabled
}

Write-Output "Built Linux ARM64 binaries in $outputDir"
