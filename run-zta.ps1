<#
    FLAGS:
    -Partner
    -Partner -PartnerIdDesired 1234567
    -LicenseReview
    -SecureScore
#>

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
    [int]$PartnerIdDesired = 7023112,

    [Parameter(Mandatory = $false)]
    [switch]$LicenseReview,

    [Parameter(Mandatory = $false)]
    [string]$LicenseMapUrl = "https://raw.githubusercontent.com/nubrixsecurity/zero-trust-assessment/main/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv",

    [Parameter(Mandatory = $false)]
    [switch]$SecureScore,

    [Parameter(Mandatory = $false)]
    [switch]$OpenOutput
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

#region Partner association (COMPLETELY SILENT; assumes ZTA already authenticated)
function Set-ManagementPartnerAssociationSilent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TenantId,

        [Parameter(Mandatory = $true)]
        [int]$PartnerIdDesired
    )

    $oldEap = $ErrorActionPreference
    $oldWp  = $WarningPreference
    $oldVp  = $VerbosePreference
    $oldIp  = $InformationPreference
    $oldPp  = $ProgressPreference

    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $WarningPreference     = 'SilentlyContinue'
        $VerbosePreference     = 'SilentlyContinue'
        $InformationPreference = 'SilentlyContinue'
        $ProgressPreference    = 'SilentlyContinue'

        if (-not (Get-Module -ListAvailable -Name Az.ManagementPartner)) {
            Install-Module Az.ManagementPartner -Scope CurrentUser -Force -AllowClobber -WarningAction SilentlyContinue | Out-Null
        }

        if (-not (Get-Module -Name Az.ManagementPartner)) {
            Import-Module Az.ManagementPartner -ErrorAction SilentlyContinue | Out-Null
        }

        $ctx = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $ctx) { return }

        $ctxTenant = $null
        if ($ctx.Tenant) {
            if ($ctx.Tenant.Id) { $ctxTenant = $ctx.Tenant.Id }
            else { $ctxTenant = [string]$ctx.Tenant }
        }
        if ($ctxTenant -and $ctxTenant -ne $TenantId) { return }

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
    }
    finally {
        $ErrorActionPreference = $oldEap
        $WarningPreference     = $oldWp
        $VerbosePreference     = $oldVp
        $InformationPreference = $oldIp
        $ProgressPreference    = $oldPp
    }
}
#endregion Partner association

#region License Review (optional, no explicit Graph module imports)
function Invoke-LicenseReview {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$LicenseMapUrl
    )

    if (-not (Get-Module -ListAvailable -Name "Microsoft.Graph.Beta.Users")) {
        Write-Host "[INFO] Installing module: Microsoft.Graph.Beta.Users"
        Install-Module -Name "Microsoft.Graph.Beta.Users" -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
    }

    $requiredPerms = @(
        "User.Read.All",
        "AuditLog.Read.All",
        "Organization.Read.All",
        "Directory.Read.All"
    )

    $ctx = Get-MgContext
    $hasAllPerms = $false

    if ($ctx -and $ctx.Scopes) {
        $missing = @()
        foreach ($perm in $requiredPerms) {
            if ($ctx.Scopes -notcontains $perm) { $missing += $perm }
        }

        if ($missing.Count -eq 0) {
            $hasAllPerms = $true
            Write-Host "[INFO] Microsoft Graph already connected with required permissions."
        }
        else {
            Write-Host "[INFO] Reconnecting to Microsoft Graph to include required permissions..."
        }
    }
    else {
        Write-Host "[INFO] Connecting to Microsoft Graph..."
    }

    if (-not $hasAllPerms) {
        Connect-MgGraph -Scopes $requiredPerms -NoWelcome -ErrorAction Stop | Out-Null
        Write-Host "[INFO] Connected to Microsoft Graph."
    }

    $mapFileName = "Product names and service plan identifiers for licensing.csv"
    $mapPath = Join-Path $OutputPath $mapFileName

    if (-not (Test-Path -LiteralPath $mapPath)) {
        Write-Host "[INFO] Downloading license map CSV..."
        Invoke-WebRequest -Uri $LicenseMapUrl -OutFile $mapPath -ErrorAction Stop
    }

    $productList = Import-Csv -Path $mapPath

    $guidMap = @{}
    foreach ($item in $productList) {
        if ($item.GUID) { $guidMap[$item.GUID] = $item.Product_Display_Name }
    }

    $licenses = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/subscribedSkus" -OutputType PSObject -ErrorAction Stop |
        Select-Object -ExpandProperty value |
        Where-Object { $_.CapabilityStatus -eq 'Enabled' }

    $licenseOverview = foreach ($license in $licenses) {
        $skuId = [string]$license.skuId
        $skuName = [string]$license.skuPartNumber
        $productName = if ($guidMap.ContainsKey($skuId)) { $guidMap[$skuId] } else { $skuName }

        $total  = [int]$license.PrepaidUnits.Enabled
        $used   = [int]$license.ConsumedUnits
        $unused = $total - $used

        [PSCustomObject]@{
            "Product Name" = $productName
            "Total"        = $total
            "Assigned"     = $used
            "Unused"       = $unused
        }
    }

    $licenseFolder = Join-Path $OutputPath "License Review"
    New-Item -Path $licenseFolder -ItemType Directory -Force | Out-Null

    $csvOut = Join-Path $licenseFolder "License_Review.csv"
    $licenseOverview | Export-Csv -Path $csvOut -NoTypeInformation -Encoding UTF8

    Write-Host "[INFO] License review exported: $csvOut"
}
#endregion License Review

#region Secure Score (optional)
function Get-SecureScoreAndChart {
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        [int]$ChartWidth  = 1200,
        [int]$ChartHeight = 600
    )
    # returns: @{ OrgName; Percentage; Current; MaxScore; CreatedDate; ChartPath; FolderPath }

    $OrgName = try {
        (Get-MgOrganization -Property DisplayName | Select-Object -First 1 -ExpandProperty DisplayName)
    } catch {
        "Your Organization"
    }

    $score = Get-MgSecuritySecureScore -Top 1 | Sort-Object CreatedDateTime -Descending | Select-Object -First 1
    if (-not $score) { throw "No Secure Score snapshot returned." }

    $MaxScore    = [int]$score.MaxScore
    $Current     = [double]$score.CurrentScore
    $Percentage  = if ($MaxScore -gt 0) { [math]::Round(($Current / $MaxScore) * 100, 2) } else { 0 }
    $CreatedDate = (Get-Date $score.CreatedDateTime).ToString('MMMM d, yyyy')

    $folderPath = Join-Path $OutputPath "Secure Score"
    New-Item -Path $folderPath -ItemType Directory -Force | Out-Null

    $safeScore = [math]::Round($Current, 0)
    $chartFile = "SecureScore_Trend_{0}.png" -f $safeScore
    $chartPath = Join-Path $folderPath $chartFile

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Windows.Forms.DataVisualization

    $snapshots = Get-MgSecuritySecureScore -All |
        Sort-Object CreatedDateTime |
        Group-Object { ([datetime]$_.CreatedDateTime).Date } |
        ForEach-Object { $_.Group | Sort-Object CreatedDateTime -Descending | Select-Object -First 1 } |
        Sort-Object CreatedDateTime

    $trend = foreach ($s in $snapshots) {
        $pct = if ($s.MaxScore -gt 0) { [math]::Round(($s.CurrentScore / $s.MaxScore) * 100, 2) } else { 0 }
        [pscustomobject]@{ Date=[datetime]$s.CreatedDateTime; Percentage=$pct }
    }

    $chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
    $chart.Width = $ChartWidth
    $chart.Height = $ChartHeight

    $area = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea "Main"
    $area.AxisX.Interval = 1
    $area.AxisX.LabelStyle.Format = "MMM"
    $area.AxisX.MajorGrid.Enabled = $false
    $area.AxisY.Title = "Secure Score (%)"

    $ys = $trend | Select-Object -ExpandProperty Percentage
    $area.AxisY.Minimum = [math]::Max(0,  [math]::Floor((($ys | Measure-Object -Minimum).Minimum) - 2))
    $area.AxisY.Maximum = [math]::Min(100,[math]::Ceiling((($ys | Measure-Object -Maximum).Maximum) + 2))
    $chart.ChartAreas.Add($area)

    $series = New-Object System.Windows.Forms.DataVisualization.Charting.Series "Secure Score"
    $series.ChartType   = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line
    $series.BorderWidth = 3
    $series.MarkerStyle = [System.Windows.Forms.DataVisualization.Charting.MarkerStyle]::Circle
    $series.MarkerSize  = 6
    foreach ($row in $trend) { [void]$series.Points.AddXY($row.Date, $row.Percentage) }
    $chart.Series.Add($series)

    $title = New-Object System.Windows.Forms.DataVisualization.Charting.Title
    $title.Text = ("Secure Score: {0}/{1} ({2}%)" -f [math]::Round($Current,0), $MaxScore, $Percentage)
    $chart.Titles.Add($title)

    $chart.SaveImage($chartPath, "Png")

    return @{
        OrgName     = $OrgName
        Percentage  = $Percentage
        Current     = $Current
        MaxScore    = $MaxScore
        CreatedDate = $CreatedDate
        ChartPath   = $chartPath
        FolderPath  = $folderPath
    }
}

function Invoke-SecureScoreExport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    Write-Host "[INFO] Generating Secure Score chart..."

    $result = Get-SecureScoreAndChart -OutputPath $OutputPath

    $summaryPath = Join-Path $result.FolderPath "SecureScore_Summary.csv"
    [pscustomobject]@{
        OrgName     = $result.OrgName
        Current     = [math]::Round($result.Current, 0)
        MaxScore    = $result.MaxScore
        Percentage  = $result.Percentage
        CreatedDate = $result.CreatedDate
        ChartPath   = $result.ChartPath
    } | Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8

    Write-Host "[INFO] Secure Score exported: $($result.ChartPath)"
    Write-Host "[INFO] Secure Score summary:  $summaryPath"
}
#endregion Secure Score

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

    Write-Host "[INFO] Connecting to Zero Trust Assessment (TenantId: $TenantId)..."
    Connect-ZtAssessment -TenantId $TenantId

    Write-Host "[INFO] Running Zero Trust Assessment..."
    Invoke-ZtAssessment -Path $OutputPath

    if ($Partner) {
        Set-ManagementPartnerAssociationSilent -TenantId $TenantId -PartnerIdDesired $PartnerIdDesired
    }

    if ($LicenseReview) {
        Invoke-LicenseReview -OutputPath $OutputPath -LicenseMapUrl $LicenseMapUrl
    }

    if ($SecureScore) {
        Invoke-SecureScoreExport -OutputPath $OutputPath
    }

    Write-Host "[INFO] Completed. Results saved to: $OutputPath"
}
catch {
    Write-Error $_.Exception.Message
    throw
}
finally {
    Write-Host "[INFO] Disconnecting sessions..."

    Write-Host "[INFO] Disconnecting AzAccount and clearing context..."
    $null = Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue
    $null = Clear-AzContext -Scope Process -ErrorAction SilentlyContinue

    Write-Host "[INFO] Disconnecting Microsoft Graph..."
    $null = Disconnect-MgGraph -ErrorAction SilentlyContinue

    Invoke-SelfDelete -ScriptPath $scriptPath

    Write-Host "[INFO] Cleanup complete."

    Write-Host ""
    Write-Host "Press any key to exit..."
    [void][System.Console]::ReadKey($true)
    exit
}
