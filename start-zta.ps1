[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    # NEW: single container SAS URL (optional, but preferred going forward)
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ZtaContainerSasUrl,

    # Legacy per-file SAS URLs (now optional; will be derived from ZtaContainerSasUrl if not provided)
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$InvokeSasUrl,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$RunSasUrl,

    [Parameter(Mandatory = $false)]
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

# ---------------------------
# Resolve URLs
# ---------------------------
# Preferred: single container SAS URL, from which we derive the three script URLs.
# Fallback: legacy mode where all three URLs are passed in directly.
if ($ZtaContainerSasUrl) {
    # Expect something like:
    # https://stzta.blob.core.windows.net/zta-scripts?sv=...&sr=c&sp=r&sig=...
    $qIndex = $ZtaContainerSasUrl.IndexOf("?")
    if ($qIndex -lt 0) {
        Write-Err "ZtaContainerSasUrl does not contain a SAS query string ('?'). Please provide a valid container SAS URL."
        exit 1
    }

    # Base URL: https://stzta.blob.core.windows.net/zta-scripts
    $baseUrl = $ZtaContainerSasUrl.Substring(0, $qIndex).TrimEnd("/")

    # SAS part: ?sv=...&se=...&sp=...&sig=...
    $sasPart = $ZtaContainerSasUrl.Substring($qIndex)

    # Derive the three URLs from the container SAS
    $InvokeSasUrl      = "$baseUrl/prod/invoke-zta.ps1$sasPart"
    $RunSasUrl         = "$baseUrl/prod/run-zta.ps1$sasPart"
    $ExecSummarySasUrl = "$baseUrl/prod/invoke-zta-execsummary.ps1$sasPart"
}
else {
    # Legacy mode: validate that the three URLs were provided
    if ([string]::IsNullOrWhiteSpace($InvokeSasUrl) -or
        [string]::IsNullOrWhiteSpace($RunSasUrl)    -or
        [string]::IsNullOrWhiteSpace($ExecSummarySasUrl)) {

        Write-Err "Either ZtaContainerSasUrl must be provided, or all three of InvokeSasUrl, RunSasUrl, and ExecSummarySasUrl must be specified."
        exit 1
    }
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
