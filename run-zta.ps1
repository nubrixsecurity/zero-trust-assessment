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
    [switch]$NoSelfDelete,

    [Parameter(Mandatory = $false)]
    [switch]$UpdateModules,

    [Parameter(Mandatory = $false)]
    [switch]$Partner,

    [Parameter(Mandatory = $false)]
    [int]$PartnerIdDesired = 7023112
)

#region Output path (Documents + date + timestamp)
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $base = Join-Path $env:USERPROFILE "Documents\ZeroTrustAssessment"
    $date = (Get-Date).ToString("yyyy-MM-dd")
    $time = (Get-Date).ToString("HHmmss")
    $OutputPath = Join-Path $base "$date\run-$time"
}

New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
Write-Host "[INFO] PowerShell version: $($PSVersionTable.PSVersion)"
Write-Host "[INFO] OutputPath: $OutputPath"
#endregion Output path

#region Ensure module installed (install only if missing)
function Ensure-ModuleInstalled {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [switch]$Update
    )

    $installed = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1

    if (-not $installed) {
        Write-Host "[INFO] Installing $Name (CurrentUser)..."
        $oldWP = $WarningPreference
        $oldPP = $ProgressPreference
        $WarningPreference = 'SilentlyContinue'
        $ProgressPreference = 'SilentlyContinue'
        try {
            Install-Module $Name -Scope CurrentUser -AllowClobber -Force
        }
        finally {
            $WarningPreference = $oldWP
            $ProgressPreference = $oldPP
        }
        return
    }

    Write-Host "[INFO] $Name already installed (v$($installed.Version))."

    if ($Update) {
        Write-Host "[INFO] Updating $Name (CurrentUser)..."
        $oldWP = $WarningPreference
        $oldPP = $ProgressPreference
        $WarningPreference = 'SilentlyContinue'
        $ProgressPreference = 'SilentlyContinue'
        try {
            Update-Module $Name -Scope CurrentUser -Force -ErrorAction SilentlyContinue
        }
        finally {
            $WarningPreference = $oldWP
            $ProgressPreference = $oldPP
        }
    }
}
#endregion Ensure module installed

#region Partner association (COMPLETELY SILENT)
function Set-ManagementPartnerAssociationSilent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [int]$PartnerIdDesired
    )

    # Save current preferences
    $oldEap = $ErrorActionPreference
    $oldWp  = $WarningPreference
    $oldVp  = $VerbosePreference
    $oldIp  = $InformationPreference
    $oldPp  = $ProgressPreference

    try {
        # Force silent preferences (no warnings, no progress, no verbose/info)
        $ErrorActionPreference = 'SilentlyContinue'
        $WarningPreference     = 'SilentlyContinue'
        $VerbosePreference     = 'SilentlyContinue'
        $InformationPreference = 'SilentlyContinue'
        $ProgressPreference    = 'SilentlyContinue'

        # Install only if missing (quiet)
        if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
            Install-Module Az.Accounts -Scope CurrentUser -Force -AllowClobber -WarningAction SilentlyContinue | Out-Null
        }
        if (-not (Get-Module -ListAvailable -Name Az.ManagementPartner)) {
            Install-Module Az.ManagementPartner -Scope CurrentUser -Force -AllowClobber -WarningAction SilentlyContinue | Out-Null
        }

        # Import (quiet)
        Import-Module Az.Accounts -Force -WarningAction SilentlyContinue | Out-Null
        Import-Module Az.ManagementPartner -Force -WarningAction SilentlyContinue | Out-Null

        # Assume already authenticated; if not, try tenant-scoped login (still quiet)
        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        $ctxTenant = $null
        if ($ctx -and $ctx.Tenant) {
            # Tenant may be string or object with Id
            if ($ctx.Tenant.Id) { $ctxTenant = $ctx.Tenant.Id }
            else { $ctxTenant = [string]$ctx.Tenant }
        }

        if (-not $ctx -or ($ctxTenant -and $ctxTenant -ne $TenantId)) {
            Connect-AzAccount -Tenant $TenantId -ErrorAction SilentlyContinue | Out-Null
        }

        # Get current partner association and set desired
        $mp = Get-AzManagementPartner -ErrorAction SilentlyContinue
        $currentPid = $null
        if ($mp -and $mp.PartnerId) { $currentPid = [int]$mp.PartnerId }

        if (-not $currentPid) {
            New-AzManagementPartner -PartnerId $PartnerIdDesired -ErrorAction SilentlyContinue | Out-Null
        }
        elseif ($currentPid -ne $PartnerIdDesired) {
            Remove-AzManagementPartner -PartnerId $currentPid -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
            New-AzManagementPartner -PartnerId $PartnerIdDesired -ErrorAction SilentlyContinue | Out-Null
        }
        # else: already set correctly, do nothing (silent)
    }
    finally {
        # Restore preferences
        $ErrorActionPreference = $oldEap
        $WarningPreference     = $oldWp
        $VerbosePreference     = $oldVp
        $InformationPreference = $oldIp
        $ProgressPreference    = $oldPp
    }
}
#endregion Partner association

#region Self-delete (best-effort)
function Invoke-SelfDelete {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )

    if ($NoSelfDelete) {
        Write-Host "[INFO] Self-delete disabled (-NoSelfDelete). Script left at: $ScriptPath"
        return
    }

    if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)) {
        return
    }

    try {
        $cmd = "/c ping 127.0.0.1 -n 3 > nul & del /f /q `"$ScriptPath`""
        Start-Process -FilePath "cmd.exe" -ArgumentList $cmd -WindowStyle Hidden | Out-Null
        Write-Host "[INFO] Scheduled self-delete for: $ScriptPath"
    }
    catch {
        # Best-effort cleanup only; don't fail the run if cleanup fails.
        Write-Warning "Unable to schedule self-delete for $ScriptPath. Error: $($_.Exception.Message)"
    }
}
#endregion Self-delete

$scriptPath = $MyInvocation.MyCommand.Path

try {
    Ensure-ModuleInstalled -Name "ZeroTrustAssessment" -Update:$UpdateModules

    Write-Host "[INFO] Clearing Az config and setting default subscription for login..."
    Clear-AzConfig -Scope CurrentUser -Force -ErrorAction Ignore | Out-Null
    Update-AzConfig -DefaultSubscriptionForLogin $SubscriptionId -Scope CurrentUser | Out-Null

    if ($Partner) {
        # Completely silent by design
        Set-ManagementPartnerAssociationSilent -TenantId $TenantId -PartnerIdDesired $PartnerIdDesired
    }

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
finally {
    Invoke-SelfDelete -ScriptPath $scriptPath
}
