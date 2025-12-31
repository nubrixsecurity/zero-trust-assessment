[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [switch]$UseTimestampedRunFolder,

    [Parameter(Mandatory = $false)]
    [switch]$RequirePowerShell7
)

#region PowerShell version guard
if ($RequirePowerShell7 -and $PSVersionTable.PSVersion.Major -lt 7) {
    Write-Error "This runner requires PowerShell 7+. Current version: $($PSVersionTable.PSVersion). Install PowerShell 7 (pwsh) and re-run."
    exit 1
}
#endregion PowerShell version guard

#region Output path
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $base = Join-Path $env:USERPROFILE "Documents\ZeroTrustAssessment"
    $date = (Get-Date).ToString("yyyy-MM-dd")

    if ($UseTimestampedRunFolder) {
        $time = (Get-Date).ToString("HHmmss")
        $OutputPath = Join-Path $base "$date\run-$time"
    }
    else {
        $OutputPath = Join-Path $base $date
    }
}

New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
Write-Host "[INFO] OutputPath: $OutputPath"
#endregion Output path

try {
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
