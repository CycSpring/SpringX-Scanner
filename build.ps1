param(
    [string]$Version = "",
    [switch]$SkipTests,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

if ($Help) {
    Write-Host "SpringX Scanner Build Script"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\build.ps1"
    Write-Host "  .\build.ps1 -Version v0.2.0"
    Write-Host "  .\build.ps1 -SkipTests"
    Write-Host ""
    Write-Host "Output:"
    Write-Host "  dist\springx.exe"
    exit 0
}

$env:GOPROXY = "https://goproxy.cn,direct"
$env:GOMODCACHE = "D:\Temp\go-mod-cache"
$env:GOCACHE = "D:\Temp\go-build-cache"
$env:GOTOOLCHAIN = "auto"

New-Item -ItemType Directory -Force -Path $env:GOMODCACHE | Out-Null
New-Item -ItemType Directory -Force -Path $env:GOCACHE | Out-Null

Write-Host "[BUILD] GOPROXY=$env:GOPROXY"
Write-Host "[BUILD] GOMODCACHE=$env:GOMODCACHE"
Write-Host "[BUILD] GOCACHE=$env:GOCACHE"

if ([string]::IsNullOrWhiteSpace($Version)) {
    $gitTag = ""
    $gitTagOutput = & git describe --tags --exact-match 2>$null
    if ($LASTEXITCODE -eq 0) {
        $gitTag = [string]($gitTagOutput | Select-Object -First 1)
        $gitTag = $gitTag.Trim()
    }

    if (-not [string]::IsNullOrWhiteSpace($gitTag)) {
        $Version = $gitTag
    }
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    $gitCommit = ""
    $gitCommitOutput = & git rev-parse --short HEAD 2>$null
    if ($LASTEXITCODE -eq 0) {
        $gitCommit = [string]($gitCommitOutput | Select-Object -First 1)
        $gitCommit = $gitCommit.Trim()
    }

    if (-not [string]::IsNullOrWhiteSpace($gitCommit)) {
        $Version = "dev-$gitCommit"
    }
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = "dev-unknown"
}

$BuildTime = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"

Write-Host "[BUILD] Version: $Version"
Write-Host "[BUILD] BuildTime: $BuildTime"

if (-not $SkipTests) {
    Write-Host "[BUILD] Running tests..."
    go test ./... -timeout 300s
    if ($LASTEXITCODE -ne 0) {
        Write-Error "[BUILD] Tests failed. Aborting build."
        exit 1
    }
    Write-Host "[BUILD] Tests passed."
} else {
    Write-Host "[BUILD] Skipping tests (-SkipTests)"
}

if (-not (Test-Path "dist")) {
    New-Item -ItemType Directory -Path "dist" | Out-Null
}

$ModulePath = "github.com/CycSpring/SpringX-Scanner/cmd"
$LdFlags = "-X $ModulePath.appVersion=$Version -X $ModulePath.buildTime=$BuildTime"

Write-Host "[BUILD] Building dist\springx.exe..."
go build -ldflags $LdFlags -o dist\springx.exe .
if ($LASTEXITCODE -ne 0) {
    Write-Error "[BUILD] Build failed."
    exit 1
}

Write-Host "[BUILD] Verifying build..."
$versionOutput = & .\dist\springx.exe --version
Write-Host "[BUILD] $versionOutput"

if ($versionOutput -notmatch [regex]::Escape($Version)) {
    Write-Error "[BUILD] Version mismatch in binary. Expected '$Version' in output: $versionOutput"
    exit 1
}

Write-Host "[BUILD] Success! Output: dist\springx.exe"
