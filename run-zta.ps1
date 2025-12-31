#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ""
)

#region Output path
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $runId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
    $OutputPath = Join-Path $env:USERPROFILE "Documents\ZeroTrustAssessment\$runId"
}
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
#endregion Output path

try {
    Write-Host "[INFO] OutputPath: $OutputPath"
    Write-Host "[INFO] Installing ZeroTrustAssessment module (CurrentUser)..."

    Install-Module ZeroTrustAssessment -Scope CurrentUser -AllowClobber -Force

    Write-Host "[INFO] Clearing Az config and setting default subscription for login..."
    Clear-AzConfig -Scope CurrentUser -Force -ErrorAction Ignore | Out-Null
    Update-AzConfig -DefaultSubscriptionForLogin $SubscriptionId -Scope CurrentUser | Out-Null

    Write-Host "[INFO] Connecting to Zero Trust Assessment (TenantId: $TenantId)..."
    Connect-ZtAssessment -TenantId $TenantId

    Write-Host "[INFO] Running assessment..."
    Invoke-ZtAssessment -Path $OutputPath

    Write-Host "[INFO] Completed. Results saved to: $OutputPath"
}
catch {
    Write-Error $_.Exception.Message
    throw
}
