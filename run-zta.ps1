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

    if ($Update) {
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

#region License Review (optional, ensures map CSV saved under License Review)
function Invoke-LicenseReview {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [string]$LicenseMapUrl
    )

    if (-not (Get-Module -ListAvailable -Name "Microsoft.Graph.Beta.Users")) {
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
        if ($missing.Count -eq 0) { $hasAllPerms = $true }
    }

    if (-not $hasAllPerms) {
        Connect-MgGraph -Scopes $requiredPerms -NoWelcome -ErrorAction Stop | Out-Null
    }

    $licenseFolder = Join-Path $OutputPath "License Review"
    New-Item -Path $licenseFolder -ItemType Directory -Force | Out-Null

    $mapFileName = "Product names and service plan identifiers for licensing.csv"
    $mapPath = Join-Path $licenseFolder $mapFileName

    if (-not (Test-Path -LiteralPath $mapPath)) {
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

    $csvOut = Join-Path $licenseFolder "License_Review.csv"
    $licenseOverview | Export-Csv -Path $csvOut -NoTypeInformation -Encoding UTF8
}
#endregion License Review

#region Secure Score (optional) - REST-based to avoid Graph module collisions
function Ensure-SecureScoreGraphScopes {
    [CmdletBinding()]
    param()

    $secureScoreScopes = @("SecurityEvents.Read.All", "Organization.Read.All")

    $ctx = Get-MgContext
    $needsConnect = $true

    if ($ctx -and $ctx.Scopes) {
        $missing = @($secureScoreScopes | Where-Object { $ctx.Scopes -notcontains $_ })
        if ($missing.Count -eq 0) { $needsConnect = $false }
    }

    if ($needsConnect) {
        Connect-MgGraph -Scopes $secureScoreScopes -NoWelcome -ErrorAction Stop | Out-Null
    }
}

function Get-SecureScoreAndChart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,

        [int]$ChartWidth  = 1200,
        [int]$ChartHeight = 600
    )
    # returns: @{ OrgName; Percentage; Current; MaxScore; CreatedDate; ChartPath; FolderPath }

    $OrgName = "Your Organization"
    try {
        $uri = "https://graph.microsoft.com/v1.0/organization?`$select=displayName"
        $resp = Invoke-MgGraphRequest -Uri $uri -OutputType PSObject -ErrorAction Stop
        $OrgName = $resp.value | Select-Object -First 1 -ExpandProperty displayName
        if (-not $OrgName) { $OrgName = "Your Organization" }
    } catch {}

    $latestUri = "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1"
    $latestResp = Invoke-MgGraphRequest -Uri $latestUri -OutputType PSObject -ErrorAction Stop
    $latest = $latestResp.value | Sort-Object createdDateTime -Descending | Select-Object -First 1
    if (-not $latest) { throw "No Secure Score snapshot returned." }

    $MaxScore    = [int]$latest.maxScore
    $Current     = [double]$latest.currentScore
    $Percentage  = if ($MaxScore -gt 0) { [math]::Round(($Current / $MaxScore) * 100, 2) } else { 0 }
    $CreatedDate = (Get-Date $latest.createdDateTime).ToString('MMMM d, yyyy')

    $folderPath = Join-Path $OutputPath "Secure Score"
    New-Item -Path $folderPath -ItemType Directory -Force | Out-Null

    $safePct = ($Percentage.ToString("0.00") -replace '\.','_')
    $chartFile = "SecureScore_Trend_{0}pct.png" -f $safePct
    $chartPath = Join-Path $folderPath $chartFile

    $uri = "https://graph.microsoft.com/v1.0/security/secureScores?`$top=500"
    $all = @()
    while ($uri) {
        $r = Invoke-MgGraphRequest -Uri $uri -OutputType PSObject -ErrorAction Stop
        if ($r.value) { $all += @($r.value) }
        $uri = $r.'@odata.nextLink'
    }

    $snapshots = $all |
        Sort-Object createdDateTime |
        Group-Object { ([datetime]$_.createdDateTime).Date } |
        ForEach-Object { $_.Group | Sort-Object createdDateTime -Descending | Select-Object -First 1 } |
        Sort-Object createdDateTime

    $trend = foreach ($s in $snapshots) {
        $pct = if ([double]$s.maxScore -gt 0) { [math]::Round(([double]$s.currentScore / [double]$s.maxScore) * 100, 2) } else { 0 }
        [pscustomobject]@{ Date = [datetime]$s.createdDateTime; Percentage = $pct }
    }

    if (-not $trend -or $trend.Count -lt 2) {
        $trend = @([pscustomobject]@{ Date = (Get-Date); Percentage = $Percentage })
    }

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Windows.Forms.DataVisualization
    Add-Type -AssemblyName System.Drawing

    $chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
    $chart.Width  = $ChartWidth
    $chart.Height = $ChartHeight
    $chart.BackColor = [System.Drawing.Color]::White

    $area = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea "Main"
    $area.BackColor = [System.Drawing.Color]::White

    $area.AxisX.Interval = 1
    $area.AxisX.LabelStyle.Format = "MMM"
    $area.AxisX.MajorGrid.Enabled = $false
    $area.AxisX.LabelStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9)

    $area.AxisY.Title = "Secure Score (%)"
    $area.AxisY.MajorGrid.LineColor = [System.Drawing.Color]::Gainsboro
    $area.AxisY.LabelStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $area.AxisY.TitleFont = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)

    $ys = $trend | Select-Object -ExpandProperty Percentage
    $minY = ($ys | Measure-Object -Minimum).Minimum
    $maxY = ($ys | Measure-Object -Maximum).Maximum
    $area.AxisY.Minimum = [math]::Max(0,  [math]::Floor($minY - 2))
    $area.AxisY.Maximum = [math]::Min(100,[math]::Ceiling($maxY + 2))

    $chart.ChartAreas.Add($area)

    $series = New-Object System.Windows.Forms.DataVisualization.Charting.Series "Secure Score"
    $series.ChartType   = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line
    $series.BorderWidth = 3
    $series.MarkerStyle = [System.Windows.Forms.DataVisualization.Charting.MarkerStyle]::Circle
    $series.MarkerSize  = 6
    foreach ($row in $trend) { [void]$series.Points.AddXY($row.Date, $row.Percentage) }
    $chart.Series.Add($series)

    $title = New-Object System.Windows.Forms.DataVisualization.Charting.Title
    $title.Text = ("Secure Score {0}%" -f $Percentage.ToString("0.00"))
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
    $chart.Titles.Clear()
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

    Ensure-SecureScoreGraphScopes
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
}
#endregion Secure Score

#region ZTA Report -> Actionable CSV + folder structure
function Get-JsonArrayTextFromZtaHtml {
    param([Parameter(Mandatory)][string]$Text)

    $m = [regex]::Match($Text, '"TestId"\s*:\s*"?\d+"?')
    if (-not $m.Success) { throw "Could not find TestId marker in the ZTA HTML report." }

    $idx = $m.Index

    $lb = -1
    for ($i = $idx; $i -ge 0; $i--) {
        if ($Text[$i] -eq '[') {
            $tail = $Text.Substring($i, [Math]::Min(50, $Text.Length - $i))
            if ($tail -match '^\[\s*\{') { $lb = $i; break }
        }
    }
    if ($lb -lt 0) { throw "Could not find the start of the embedded results array in the HTML report." }

    $depth = 0
    $inString = $false
    $esc = $false
    $rb = -1

    for ($j = $lb; $j -lt $Text.Length; $j++) {
        $ch = $Text[$j]

        if ($inString) {
            if ($esc) { $esc = $false; continue }
            if ($ch -eq '\') { $esc = $true; continue }
            if ($ch -eq '"') { $inString = $false; continue }
            continue
        }

        if ($ch -eq '"') { $inString = $true; continue }

        if ($ch -eq '[') { $depth++ }
        elseif ($ch -eq ']') {
            $depth--
            if ($depth -eq 0) { $rb = $j; break }
        }
    }

    if ($rb -lt 0) { throw "Could not find the end of the embedded results array in the HTML report." }

    return $Text.Substring($lb, ($rb - $lb + 1))
}

function Get-ZtaRemediationText {
    param([string]$Desc)

    if ([string]::IsNullOrWhiteSpace($Desc)) { return "" }

    $marker = "**Remediation action**"
    $pos = $Desc.IndexOf($marker)
    if ($pos -lt 0) { return "" }

    return $Desc.Substring($pos + $marker.Length).Trim()
}

function Export-ZtaActionableCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $assessmentFolder = Join-Path $OutputPath "Assessment Report"
    New-Item -Path $assessmentFolder -ItemType Directory -Force | Out-Null

    # Find newest HTML report in root output folder
    $htmlReportPath = Get-ChildItem -Path $OutputPath -Filter "*.html" -File -ErrorAction Stop |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 -ExpandProperty FullName

    if (-not $htmlReportPath) {
        throw "No HTML report found in output folder: $OutputPath"
    }

    $html = Get-Content -Path $htmlReportPath -Raw -Encoding UTF8

    $jsonText = Get-JsonArrayTextFromZtaHtml -Text $html
    $jsonText = $jsonText -replace ',(\s*[}\]])', '$1'  # remove common trailing commas
    $tests = $jsonText | ConvertFrom-Json

    # Build RemediationLinks column (joined URLs)
    $linkRegex = '\[([^\]]+)\]\((https?://[^)]+)\)'
    $linkLookup = @{}

    foreach ($t in $tests) {
        $rem = Get-ZtaRemediationText -Desc ([string]$t.TestDescription)
        if ([string]::IsNullOrWhiteSpace($rem)) { continue }

        $urls = [regex]::Matches($rem, $linkRegex) |
            ForEach-Object { $_.Groups[2].Value } |
            Select-Object -Unique

        if ($urls -and $urls.Count -gt 0) {
            $linkLookup["$($t.TestId)"] = ($urls -join " | ")
        }
    }

    $rows = foreach ($t in $tests) {
        $rem = Get-ZtaRemediationText -Desc ([string]$t.TestDescription)

        [pscustomobject]@{
            TestId                 = $t.TestId
            TestTitle              = $t.TestTitle
            TestStatus             = $t.TestStatus
            TestPillar             = $t.TestPillar
            TestSfiPillar          = $t.TestSfiPillar
            TestCategory           = $t.TestCategory
            TestRisk               = $t.TestRisk
            TestImpact             = $t.TestImpact
            TestMinimumLicense     = $t.TestMinimumLicense
            TestImplementationCost = $t.TestImplementationCost
            RemediationActions     = $rem
            TestResult             = $t.TestResult
            RemediationLinks       = $linkLookup["$($t.TestId)"]
        }
    }

    # Export actionable CSV into Assessment Report folder
    $outCsv = Join-Path $assessmentFolder "ZeroTrustAssessment_Actionable.csv"
    $rows | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

    # Move the HTML report into Assessment Report folder
    try {
        $destHtml = Join-Path $assessmentFolder (Split-Path $htmlReportPath -Leaf)
        if ($htmlReportPath -ne $destHtml) {
            Move-Item -LiteralPath $htmlReportPath -Destination $destHtml -Force -ErrorAction Stop
        }
    } catch {}

    # Move zt-export folder into Assessment Report folder (if present)
    try {
        $ztExportPath = Join-Path $OutputPath "zt-export"
        if (Test-Path -LiteralPath $ztExportPath) {
            $destZtExport = Join-Path $assessmentFolder "zt-export"
            if (Test-Path -LiteralPath $destZtExport) {
                Remove-Item -LiteralPath $destZtExport -Recurse -Force -ErrorAction SilentlyContinue
            }
            Move-Item -LiteralPath $ztExportPath -Destination $destZtExport -Force -ErrorAction Stop
        }
    } catch {}

    return @{
        AssessmentFolder = $assessmentFolder
        ActionableCsv    = $outCsv
        RowCount         = ($rows | Measure-Object).Count
    }
}
#endregion ZTA Report -> Actionable CSV + folder structure

#region Self-delete (best-effort)
function Invoke-SelfDelete {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )

    if ($NoSelfDelete) {
        return
    }

    if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)) {
        return
    }

    try {
        $cmd = "/c ping 127.0.0.1 -n 3 > nul & del /f /q `"$ScriptPath`""
        Start-Process -FilePath "cmd.exe" -ArgumentList $cmd -WindowStyle Hidden | Out-Null
    }
    catch {
        # best-effort
    }
}
#endregion Self-delete

$scriptPath = $MyInvocation.MyCommand.Path

try {
    Ensure-ModuleInstalled -Name "ZeroTrustAssessment" -Update:$UpdateModules

    Clear-AzConfig -Scope CurrentUser -Force -ErrorAction Ignore | Out-Null
    Update-AzConfig -DefaultSubscriptionForLogin $SubscriptionId -Scope CurrentUser | Out-Null

    Write-Host "[INFO] Connecting to Zero Trust Assessment (TenantId: $TenantId)..."
    Connect-ZtAssessment -TenantId $TenantId

    Write-Host "[INFO] Running Zero Trust Assessment..."
    Invoke-ZtAssessment -Path $OutputPath

    # Export actionable CSV and organize assessment artifacts into: Assessment Report\
    try {
        $export = Export-ZtaActionableCsv -OutputPath $OutputPath
    }
    catch {
        Write-Host "[WARN] HTML-to-CSV export/organization failed: $($_.Exception.Message)"
    }

    if ($Partner) {
        Set-ManagementPartnerAssociationSilent -TenantId $TenantId -PartnerIdDesired $PartnerIdDesired
    }

    if ($LicenseReview) {
        Invoke-LicenseReview -OutputPath $OutputPath -LicenseMapUrl $LicenseMapUrl
    }

    if ($SecureScore) {
        try {
            Invoke-SecureScoreExport -OutputPath $OutputPath
        }
        catch {
            Write-Host "[WARN] Secure Score export failed: $($_.Exception.Message)"
        }
    }

    Write-Host "[INFO] Completed. Results saved to: $OutputPath"
}
catch {
    Write-Error $_.Exception.Message
    throw
}
finally {
    # Always attempt to disconnect; keep silent
    #$null = Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue
    #$null = Clear-AzContext -Scope Process -ErrorAction SilentlyContinue
    #$null = Disconnect-MgGraph -ErrorAction SilentlyContinue

    Invoke-SelfDelete -ScriptPath $scriptPath

    # Open run folder; if it fails, do nothing (path is already shown in the final [INFO] line)
    try { Invoke-Item -Path $OutputPath | Out-Null } catch {}

    Write-Host ""
    Write-Host "The Zero Trust Assessment has completed successfully. You may now close this window." -ForegroundColor Green
    [void][System.Console]::ReadKey($true)
    Write-Host ""
}
