param(
    [string]$MsiPath,
    [string]$InstallLog = (Join-Path $PSScriptRoot "..\..\target\wix\install.log")
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($MsiPath)) {
    $manifestPath = Join-Path $PSScriptRoot "..\..\Cargo.toml"
    $versionLine = Select-String -LiteralPath $manifestPath -Pattern '^\s*version\s*=\s*"([^"]+)"\s*$' |
        Select-Object -First 1
    if ($null -eq $versionLine) {
        throw "Could not read package version from $manifestPath."
    }
    $version = $versionLine.Matches[0].Groups[1].Value
    $MsiPath = Join-Path $PSScriptRoot "..\..\target\wix\affix-$version-x86_64.msi"
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This smoke test must run from an elevated PowerShell session."
    }
}

function Test-ServiceExists {
    param([string]$Name)
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    return $null -ne $service
}

function Wait-ServiceAbsent {
    param([string]$Name)
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        if (-not (Test-ServiceExists -Name $Name)) {
            return
        }
        Start-Sleep -Seconds 1
    }
    throw "Service '$Name' still exists after deletion request."
}

function Wait-ServiceRunning {
    param([string]$Name)
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -eq "Running") {
            return
        }
        Start-Sleep -Seconds 1
    }
    throw "Service '$Name' did not reach Running state."
}

function Invoke-Checked {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList
    )

    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) {
        throw "$FilePath exited with code $($process.ExitCode)."
    }
}

Assert-Admin

$resolvedMsi = Resolve-Path -LiteralPath $MsiPath -ErrorAction Stop
$installLogParent = Split-Path -Parent $InstallLog
if ($installLogParent) {
    New-Item -ItemType Directory -Force -Path $installLogParent | Out-Null
}

if (Test-ServiceExists -Name "affix") {
    Stop-Service -Name "affix" -ErrorAction SilentlyContinue
    sc.exe delete affix | Out-Host
    Wait-ServiceAbsent -Name "affix"
}

$legacyBinary = "C:\Windows\affix.exe"
if (Test-Path -LiteralPath $legacyBinary) {
    Remove-Item -LiteralPath $legacyBinary -Force
}

Invoke-Checked -FilePath "msiexec.exe" -ArgumentList @(
    "/i",
    $resolvedMsi.Path,
    "/qn",
    "/l*v",
    $InstallLog
)

Wait-ServiceRunning -Name "affix"

$service = Get-CimInstance -ClassName Win32_Service -Filter "Name='affix'"
if ($service.StartMode -ne "Auto") {
    throw "Service 'affix' is not configured for automatic start."
}
if ($service.StartName -ne "LocalSystem") {
    throw "Service 'affix' is not configured to run as LocalSystem."
}
if ($service.PathName -notlike "*C:\Program Files\Affix\affix.exe*") {
    throw "Service 'affix' binary path is '$($service.PathName)', expected C:\Program Files\Affix\affix.exe."
}
if (-not (Test-Path -LiteralPath "C:\Program Files\Affix\affix.exe")) {
    throw "Installed service binary C:\Program Files\Affix\affix.exe is missing."
}

Write-Host "Quiet MSI install succeeded; affix service is installed and running." -ForegroundColor Green
