<#
Nubrix Zero Trust Assessment Launcher (Customer Entry Point)

MANDATORY FLAGS:
-InvokeSasUrl   (SAS URL to download invoke-zta.ps1 from Azure Blob)
-RunSasUrl      (SAS URL passed through to invoke-zta.ps1 so it can download run-zta.ps1)

OPTIONAL FLAGS:
-Partner
-SkipExecSummary
-SkipSecureScore
-SkipLicenseReview
-KeepZtExport
-OpenOutput

HOW TO RUN:
Step 1 — Download the launcher script (start-zta.ps1)
Open PowerShell (recommended: PowerShell 7, but Windows PowerShell works for the download step)

Run command:
$u = "https://raw.githubusercontent.com/nubrixsecurity/zero-trust-assessment/main/start-zta.ps1"
$p = Join-Path $env:USERPROFILE "Documents\start-zta.ps1"
if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
Invoke-WebRequest -Uri $u -OutFile $p -ErrorAction Stop

Step 2 — Run the assessment
Run the script from Documents (replace the GUIDs with your values):

pwsh -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\Documents\start-zta.ps1" `
  -TenantId "<tenant-guid>" `
  -SubscriptionId "<sub-guid>" `
  -InvokeSasUrl "<sas-url-for-invoke>" `
  -RunSasUrl "<sas-url-for-run>" `
  -Partner `
  -OpenOutput
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$InvokeSasUrl,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$RunSasUrl,

    [switch]$Partner,

    [switch]$SkipExecSummary,
    [switch]$SkipSecureScore,
    [switch]$SkipLicenseReview,
    [switch]$KeepZtExport,
    [switch]$OpenOutput
)

function Write-Err {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "[ERROR] $Message"
}

# Working folder for Nubrix ZTA temp artifacts
$ztaTemp = Join-Path $env:TEMP "nubrix-zta"
New-Item -Path $ztaTemp -ItemType Directory -Force | Out-Null

# Download invoke wrapper into the temp folder (Blob SAS only)
$p = Join-Path $ztaTemp "invoke-zta.ps1"

try {
    Invoke-WebRequest -Uri $InvokeSasUrl -OutFile $p -ErrorAction Stop
} catch {
    $msg = $_.Exception.Message
    if ($msg -match "403" -or $msg -match "AuthenticationFailed" -or $msg -match "Authorization") {
        Write-Err "Failed to download invoke-zta.ps1. The download link may have expired. Please request a refreshed link and try again."
    } else {
        Write-Err "Failed to download invoke-zta.ps1. $msg"
    }
    exit 1
}

# Forward parameters/switches to invoke-zta.ps1
$forward = @(
    "-TenantId", $TenantId,
    "-SubscriptionId", $SubscriptionId
)

# Pass Run SAS URL to invoke layer
if (-not [string]::IsNullOrWhiteSpace($RunSasUrl)) {
    $forward += @("-RunSasUrl", $RunSasUrl)
}

if ($Partner)          { $forward += "-Partner" }
if ($SkipExecSummary)  { $forward += "-SkipExecSummary" }
if ($SkipSecureScore)  { $forward += "-SkipSecureScore" }
if ($SkipLicenseReview){ $forward += "-SkipLicenseReview" }
if ($KeepZtExport)     { $forward += "-KeepZtExport" }
if ($OpenOutput)       { $forward += "-OpenOutput" }

pwsh -NoProfile -ExecutionPolicy Bypass -File $p @forward
