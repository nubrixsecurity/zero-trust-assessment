<#
Nubrix Zero Trust Assessment Launcher (Customer Entry Point)

FLAGS (optional):
-SkipExecSummary
-SkipSecureScore
-SkipLicenseReview
-KeepZtExport
-OpenOutput

Example:
pwsh -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\Documents\start-zta.ps1" -TenantId "<tenant-guid>" -SubscriptionId "<sub-guid>" -OpenOutput
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,

    [switch]$SkipExecSummary,
    [switch]$SkipSecureScore,
    [switch]$SkipLicenseReview,
    [switch]$KeepZtExport,
    [switch]$OpenOutput
)

# Working folder for Nubrix ZTA temp artifacts
$ztaTemp = Join-Path $env:TEMP "nubrix-zta"
New-Item -Path $ztaTemp -ItemType Directory -Force | Out-Null

# Download invoke wrapper into the temp folder
$u = "https://raw.githubusercontent.com/nubrixsecurity/zero-trust-assessment/main/invoke-zta.ps1"
$p = Join-Path $ztaTemp "invoke-zta.ps1"

Invoke-WebRequest -Uri $u -OutFile $p -ErrorAction Stop

# Forward switches to invoke-zta.ps1
$forward = @(
    "-TenantId", $TenantId,
    "-SubscriptionId", $SubscriptionId
)

if ($SkipExecSummary)   { $forward += "-SkipExecSummary" }
if ($SkipSecureScore)   { $forward += "-SkipSecureScore" }
if ($SkipLicenseReview) { $forward += "-SkipLicenseReview" }
if ($KeepZtExport)      { $forward += "-KeepZtExport" }
if ($OpenOutput)        { $forward += "-OpenOutput" }

pwsh -NoProfile -ExecutionPolicy Bypass -File $p @forward
