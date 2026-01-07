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

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$RunSasUrl,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ExecSummarySasUrl,

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

function Download-WithSasErrorHandling {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile,
        [Parameter(Mandatory = $true)][string]$FriendlyName
    )

    $oldPP = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -ErrorAction Stop
        try { Unblock-File -LiteralPath $OutFile -ErrorAction SilentlyContinue } catch {}
        return $true
    } catch {
        $msg = $_.Exception.Message
        if ($msg -match "403" -or $msg -match "AuthenticationFailed" -or $msg -match "Authorization") {
            Write-Err "Failed to download $FriendlyName. The download link may have expired. Please request a refreshed link and try again."
        } else {
            Write-Err "Failed to download $FriendlyName. $msg"
        }
        return $false
    } finally {
        $ProgressPreference = $oldPP
    }
}

$ztaTemp = Join-Path $env:TEMP "nubrix-zta"
New-Item -Path $ztaTemp -ItemType Directory -Force | Out-Null

$invokePath      = Join-Path $ztaTemp "invoke-zta.ps1"
$runPath         = Join-Path $ztaTemp "run-zta.ps1"
$execSummaryPath = Join-Path $ztaTemp "invoke-zta-execsummary.ps1"

if (-not (Download-WithSasErrorHandling -Uri $InvokeSasUrl      -OutFile $invokePath      -FriendlyName "invoke-zta.ps1")) { exit 1 }
if (-not (Download-WithSasErrorHandling -Uri $RunSasUrl         -OutFile $runPath         -FriendlyName "run-zta.ps1"))    { exit 1 }
if (-not (Download-WithSasErrorHandling -Uri $ExecSummarySasUrl -OutFile $execSummaryPath -FriendlyName "invoke-zta-execsummary.ps1")) { exit 1 }

$invokeText = Get-Content -LiteralPath $invokePath -Raw -ErrorAction SilentlyContinue

$invokeHasRunPath         = $false
$invokeHasExecSummaryPath = $false
$invokeHasExecSummarySas  = $false

if (-not [string]::IsNullOrWhiteSpace($invokeText)) {
    $invokeHasRunPath         = $invokeText -match '(?mi)^\s*\[\s*(?:Parameter\([^\)]*\)\s*)?\]\s*\[\s*string\s*\]\s*\$RunPath\b' -or $invokeText -match '(?mi)^\s*\[\s*string\s*\]\s*\$RunPath\b'
    $invokeHasExecSummaryPath = $invokeText -match '(?mi)^\s*\[\s*(?:Parameter\([^\)]*\)\s*)?\]\s*\[\s*string\s*\]\s*\$ExecSummaryPath\b' -or $invokeText -match '(?mi)^\s*\[\s*string\s*\]\s*\$ExecSummaryPath\b'
    $invokeHasExecSummarySas  = $invokeText -match '(?mi)^\s*\[\s*(?:Parameter\([^\)]*\)\s*)?\]\s*\[\s*string\s*\]\s*\$ExecSummarySasUrl\b' -or $invokeText -match '(?mi)^\s*\[\s*string\s*\]\s*\$ExecSummarySasUrl\b'
}

$forward = @(
    "-TenantId", $TenantId,
    "-SubscriptionId", $SubscriptionId,
    "-RunSasUrl", $RunSasUrl
)

if ($invokeHasRunPath) {
    $forward += @("-RunPath", $runPath)
}

if ($invokeHasExecSummarySas) {
    $forward += @("-ExecSummarySasUrl", $ExecSummarySasUrl)
}

if ($invokeHasExecSummaryPath) {
    $forward += @("-ExecSummaryPath", $execSummaryPath)
}

if ($Partner)           { $forward += "-Partner" }
if ($SkipExecSummary)   { $forward += "-SkipExecSummary" }
if ($SkipSecureScore)   { $forward += "-SkipSecureScore" }
if ($SkipLicenseReview) { $forward += "-SkipLicenseReview" }
if ($KeepZtExport)      { $forward += "-KeepZtExport" }
if ($OpenOutput)        { $forward += "-OpenOutput" }

pwsh -NoProfile -ExecutionPolicy Bypass -File $invokePath @forward
