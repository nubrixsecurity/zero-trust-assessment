<#
    FLAGS (back-compat kept, but internally we RUN by default unless skipped):
    -Partner
    -Partner -PartnerIdDesired 1234567

    BACK-COMPAT FLAGS (kept, but ignored internally):
    -LicenseReview
    -SecureScore

    NEW FLAGS (preferred):
    -SkipSecureScore
    -SkipLicenseReview

    OPTIONAL:
    -KeepZtExport   (keeps the zt-export folder instead of deleting it)
    -OpenOutput     (opens OutputPath at end)

    ALWAYS (no flag):
    - Create Assessment Report folder
    - Parse HTML report
    - Export Actionable CSV into Assessment Report (with RemediationLinks column)
    - Move HTML report into Assessment Report
    - Secure Score export runs (unless -SkipSecureScore)
    - License Review export runs (unless -SkipLicenseReview)
    - Write ExecutiveSummary.Context.json into Assessment Report (if Actionable CSV exists)

    Notes:
    - Secure Score + License Review are treated as default behaviors now.
    - zt-export folder is deleted by default after parsing (silent).
    - Disconnects are commented out per your request.
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

    # Back-compat (kept, but ignored internally)
    [Parameter(Mandatory = $false)]
    [switch]$LicenseReview,

    [Parameter(Mandatory = $false)]
    [string]$LicenseMapUrl = "https://raw.githubusercontent.com/nubrixsecurity/zero-trust-assessment/main/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv",

    # Back-compat (kept, but ignored internally)
    [Parameter(Mandatory = $false)]
    [switch]$SecureScore,

    # NEW: default behavior is RUN unless skipped
    [Parameter(Mandatory = $false)]
    [switch]$SkipSecureScore,

    [Parameter(Mandatory = $false)]
    [switch]$SkipLicenseReview,

    [Parameter(Mandatory = $false)]
    [switch]$KeepZtExport,

    [Parameter(Mandatory = $false)]
    [switch]$ExecSummary,

    # Optional metadata for reporting/context
    [Parameter(Mandatory = $false)]
    [string]$CustomerName,

    [Parameter(Mandatory = $false)]
    [string]$PreparedBy = "Nubrix Security",

    [Parameter(Mandatory = $false)]
    [switch]$OpenOutput
)

#region Output path (Documents + date + timestamp)
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $base = Join-Path $env:USERPROFILE "Documents\Zero-Trust-Assessment"
    $date = (Get-Date).ToString("yyyy-MM-dd")
    $time = (Get-Date).ToString("HHmmss")
    $OutputPath = Join-Path $base "$date\run-$time"
}
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

# Nubrix temp working folder (safe to delete as a unit)
$script:NubrixTempRoot = Join-Path $env:TEMP "nubrix-zta"
New-Item -Path $script:NubrixTempRoot -ItemType Directory -Force | Out-Null
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

#region License Review (default run unless skipped)
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

    $requiredPerms = @("User.Read.All","AuditLog.Read.All","Organization.Read.All","Directory.Read.All")

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
    $script:LicenseMapPath = $mapPath
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

    return $csvOut
}
#endregion License Review

#region Secure Score (default run unless skipped)
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
    param([Parameter(Mandatory = $true)][string]$OutputPath)

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

    return @{
        ChartPath   = $result.ChartPath
        SummaryPath = $summaryPath
        FolderPath  = $result.FolderPath

        # NEW: pass these through to context.json
        Current     = [math]::Round($result.Current, 0)
        MaxScore    = $result.MaxScore
        Percentage  = $result.Percentage
        CreatedDate = $result.CreatedDate
        OrgName     = $result.OrgName
    }
}
#endregion Secure Score

#region ZTA HTML -> Actionable CSV + move HTML to Assessment Report + delete zt-export by default (silent)
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
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory = $false)][switch]$KeepZtExport
    )

    $assessmentFolder = Join-Path $OutputPath "Assessment Report"
    New-Item -Path $assessmentFolder -ItemType Directory -Force | Out-Null

    $htmlReportPath = Get-ChildItem -Path $OutputPath -Filter "*.html" -File -ErrorAction Stop |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $htmlReportPath) { throw "No HTML report found in output folder: $OutputPath" }

    $html = Get-Content -Path $htmlReportPath -Raw -Encoding UTF8

    $jsonText = Get-JsonArrayTextFromZtaHtml -Text $html
    $jsonText = $jsonText -replace ',(\s*[}\]])', '$1'
    $tests = $jsonText | ConvertFrom-Json

    $linkRegex = '\[([^\]]+)\]\((https?://[^)]+)\)'
    $linkLookup = @{}

    foreach ($t in $tests) {
        $rem = Get-ZtaRemediationText -Desc ([string]$t.TestDescription)
        if ([string]::IsNullOrWhiteSpace($rem)) { continue }

        $urls = [regex]::Matches($rem, $linkRegex) |
            ForEach-Object { $_.Groups[2].Value } |
            Select-Object -Unique

        if ($urls -and $urls.Count -gt 0) { $linkLookup["$($t.TestId)"] = ($urls -join " | ") }
    }

    $rows = foreach ($t in $tests) {
        $rem = Get-ZtaRemediationText -Desc ([string]$t.TestDescription)
        [pscustomobject]@{
            Id                 = $t.TestId
            Title              = $t.TestTitle
            Status             = $t.TestStatus
            Pillar             = $t.TestPillar
            SfiPillar          = $t.TestSfiPillar
            Category           = $t.TestCategory
            Risk               = $t.TestRisk
            Impact             = $t.TestImpact
            MinimumLicense     = $t.TestMinimumLicense
            ImplementationCost = $t.TestImplementationCost
            RemediationActions = $rem
            #Result             = $t.TestResult
            RemediationLinks   = $linkLookup["$($t.TestId)"]
        }
    }

    $outCsv = Join-Path $assessmentFolder "ZeroTrustAssessment_Actionable.csv"
    $rows | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

    # Move HTML into Assessment Report folder
    try {
        $destHtml = Join-Path $assessmentFolder (Split-Path $htmlReportPath -Leaf)
        if ($htmlReportPath -ne $destHtml) {
            Move-Item -LiteralPath $htmlReportPath -Destination $destHtml -Force -ErrorAction Stop
        }
    } catch {}

    # Delete zt-export by default (SILENT; suppress progress output)
    if (-not $KeepZtExport) {
        $oldPP = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try {
            $ztExportPath = Join-Path $OutputPath "zt-export"
            if (Test-Path -LiteralPath $ztExportPath) {
                Remove-Item -LiteralPath $ztExportPath -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
            }
        }
        finally {
            $ProgressPreference = $oldPP
        }
    }

    return @{
        AssessmentFolder = $assessmentFolder
        ActionableCsv    = $outCsv
        Rows             = $rows
        RowCount         = ($rows | Measure-Object).Count
    }
}
#endregion ZTA export

#region Customer Name resolver (Graph org displayName; no module installs)
function Resolve-CustomerName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$CustomerName,
        [Parameter(Mandatory = $false)][string]$TenantId
    )

    # If caller supplied a name, trust it
    if (-not [string]::IsNullOrWhiteSpace($CustomerName)) {
        return $CustomerName.Trim()
    }

    try {
        # Ensure we have a Graph context with org-read scope (best-effort; no installs)
        $ctx = $null
        try { $ctx = Get-MgContext } catch { $ctx = $null }

        $hasOrgScope = $false
        if ($ctx -and $ctx.Scopes) {
            if ($ctx.Scopes -contains "Organization.Read.All" -or $ctx.Scopes -contains "Directory.Read.All") {
                $hasOrgScope = $true
            }
        }

        if (-not $hasOrgScope) {
            # Best-effort connect (won't prompt if already connected in many cases; will prompt if not)
            try { Connect-MgGraph -Scopes @("Organization.Read.All") -NoWelcome -ErrorAction Stop | Out-Null } catch {}
        }

        # Preferred: cmdlet (if available)
        if (Get-Command Get-MgOrganization -ErrorAction SilentlyContinue) {
            $org = Get-MgOrganization -Property DisplayName -ErrorAction Stop | Select-Object -First 1
            if ($org -and -not [string]::IsNullOrWhiteSpace($org.DisplayName)) {
                return $org.DisplayName.Trim()
            }
        }

        # Fallback: raw request (works even if cmdlet isn't present)
        $resp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization?`$select=displayName" -OutputType PSObject -ErrorAction Stop
        $dn = $resp.value | Select-Object -First 1 -ExpandProperty displayName -ErrorAction SilentlyContinue
        if (-not [string]::IsNullOrWhiteSpace($dn)) {
            return $dn.Trim()
        }
    }
    catch {
        # best-effort only
    }

    # Optional fallback: use tenantId if you prefer not-blank
    # if (-not [string]::IsNullOrWhiteSpace($TenantId)) { return $TenantId }

    return ""
}
#endregion Customer Name resolver

#region Exec Summary context writer (writes JSON to Assessment Report)
function Write-ExecSummaryContextFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ContextPath,
        [Parameter(Mandatory)][hashtable]$Context
    )

    $folder = Split-Path $ContextPath -Parent
    if (-not (Test-Path -LiteralPath $folder)) {
        New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    $Context | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ContextPath -Encoding UTF8
    return $ContextPath
}
#endregion Exec Summary context writer

#region Exec Summary runner helpers (download + run)
function Convert-GitHubUrlToRaw {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Url)

    if ($Url -match '^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$') {
        $org    = $Matches[1]
        $repo   = $Matches[2]
        $branch = $Matches[3]
        $path   = $Matches[4]
        return "https://raw.githubusercontent.com/$org/$repo/$branch/$path"
    }
    return $Url
}

function Get-ExecSummaryScriptFromTempOrDownload {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ScriptUrl)

    $fileName = "invoke-zta-execsummary.ps1"
    $tempPath = Join-Path $script:NubrixTempRoot $fileName

    if (Test-Path -LiteralPath $tempPath) { return $tempPath }

    $rawUrl = Convert-GitHubUrlToRaw -Url $ScriptUrl

    $oldPP = $ProgressPreference
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $rawUrl -OutFile $tempPath -ErrorAction Stop
        try { Unblock-File -LiteralPath $tempPath -ErrorAction SilentlyContinue } catch {}
        return $tempPath
    }
    catch {
        Write-Host "[WARN] Failed to download Exec Summary script: $($_.Exception.Message)"
        return $null
    }
    finally {
        $ProgressPreference = $oldPP
    }
}

function Invoke-ExecSummaryScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$ContextPath
    )

    if (-not (Test-Path -LiteralPath $ScriptPath)) {
        Write-Host "[WARN] Exec Summary script not found: $ScriptPath"
        return $false
    }
    if (-not (Test-Path -LiteralPath $ContextPath)) {
        Write-Host "[WARN] Exec Summary context file not found: $ContextPath"
        return $false
    }

    $pwsh = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if (-not $pwsh) {
        Write-Host "[WARN] pwsh not found. Exec Summary requires PowerShell 7."
        return $false
    }

    # Logs: keep ONLY if failure
    $stdoutLog = Join-Path $script:NubrixTempRoot "zta-execsummary-stdout.log"
    $stderrLog = Join-Path $script:NubrixTempRoot "zta-execsummary-stderr.log"

    # Overwrite old logs each run (so failure logs are current)
    foreach ($p in @($stdoutLog, $stderrLog)) {
        try { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue } } catch {}
    }

    # Quote paths (they can contain spaces)
    $quotedScript  = '"' + $ScriptPath  + '"'
    $quotedContext = '"' + $ContextPath + '"'

    $argString = @(
        "-NoProfile"
        "-ExecutionPolicy Bypass"
        "-File $quotedScript"
        "-ContextPath $quotedContext"
    ) -join ' '

    try {
        $p = Start-Process `
            -FilePath $pwsh `
            -ArgumentList $argString `
            -Wait `
            -PassThru `
            -NoNewWindow `
            -RedirectStandardOutput $stdoutLog `
            -RedirectStandardError  $stderrLog

        if ($p.ExitCode -eq 0) {
            # SUCCESS: delete logs (Option A)
            foreach ($item in @($stdoutLog, $stderrLog)) {
                try {
                    if ($item -and (Test-Path -LiteralPath $item)) {
                        Remove-Item -LiteralPath $item -Force -ErrorAction SilentlyContinue
                    }
                } catch {}
            }
            return $true
        }

        # FAILURE: keep logs + show where they are
        Write-Host "[WARN] Exec Summary script exited with code: $($p.ExitCode)"
        Write-Host "[WARN] Stdout log: $stdoutLog"
        Write-Host "[WARN] Stderr log: $stderrLog"
        return $false
    }
    catch {
        # FAILURE: keep logs (if any were created) + show location
        Write-Host "[WARN] Exec Summary failed to launch: $($_.Exception.Message)"
        Write-Host "[WARN] Stdout log: $stdoutLog"
        Write-Host "[WARN] Stderr log: $stderrLog"
        return $false
    }
}
#endregion Exec Summary runner helpers

#region Self-delete (best-effort)
function Invoke-SelfDelete {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$Paths
    )

    if ($NoSelfDelete) { return }

    $targets = @()
    foreach ($p in $Paths) {
        if (-not [string]::IsNullOrWhiteSpace($p)) { $targets += $p }
    }
    if ($targets.Count -eq 0) { return }

    try {
        $psExe = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"

        $cmd = @()
        $cmd += 'Start-Sleep -Seconds 3'
        $cmd += 'foreach ($p in $args) {'
        $cmd += '  if ([string]::IsNullOrWhiteSpace($p)) { continue }'
        $cmd += '  for ($i=0; $i -lt 20; $i++) {'
        $cmd += '    try {'
        $cmd += '      if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop }'
        $cmd += '      break'
        $cmd += '    } catch { Start-Sleep -Milliseconds 500 }'
        $cmd += '  }'
        $cmd += '}'

        $scriptText = ($cmd -join '; ')
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptText))

        $argLine = "/c ping 127.0.0.1 -n 3 > nul & `"$psExe`" -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc --% " +
                   (($targets | ForEach-Object { '"' + $_ + '"' }) -join ' ')

        Start-Process -FilePath "cmd.exe" -ArgumentList $argLine -WindowStyle Hidden | Out-Null
    }
    catch {
        # best-effort
    }
}
#endregion Self-delete

$scriptPath = $MyInvocation.MyCommand.Path

# Tracking outputs for context file
$script:SecureScorePercent        = $null
$script:SecureScorePoints         = $null
$script:SecureScoreMaxScore       = $null
$script:SecureScoreCreatedDate    = $null
$script:SecureScoreChartPath      = $null
$script:SecureScoreSummaryCsvPath = $null
$script:LicenseReviewCsvPath      = $null
$script:ExecSummaryContextPath    = $null
$script:LicenseMapPath            = $null
$script:NubrixTempRoot            = $null


try {
    Ensure-ModuleInstalled -Name "ZeroTrustAssessment" -Update:$UpdateModules

    Clear-AzConfig -Scope CurrentUser -Force -ErrorAction Ignore | Out-Null
    Update-AzConfig -DefaultSubscriptionForLogin $SubscriptionId -Scope CurrentUser | Out-Null

    Write-Host "[INFO] Connecting to Zero Trust Assessment (TenantId: $TenantId)..." -f cyan
    Connect-ZtAssessment -TenantId $TenantId

    #Write-Host "[INFO] Running Zero Trust Assessment..." -f cyan
    Invoke-ZtAssessment -Path $OutputPath

    # ALWAYS: Actionable CSV + move HTML + delete zt-export (default)
    $export = $null
    try {
        $export = Export-ZtaActionableCsv -OutputPath $OutputPath -KeepZtExport:$KeepZtExport
    }
    catch {
        Write-Host "[WARN] Failed to generate Actionable CSV: $($_.Exception.Message)"
    }

   # DEFAULT RUN: Secure Score export (unless skipped)
    if (-not $SkipSecureScore) {
        try {
            $ss = Invoke-SecureScoreExport -OutputPath $OutputPath
    
            # Capture chart path (existing behavior)
            if ($ss -and $ss.ChartPath -and (Test-Path -LiteralPath $ss.ChartPath)) {
                $script:SecureScoreChartPath = $ss.ChartPath
            }
            else {
                # fallback: discover chart by search
                $secureScoreFolder = Join-Path $OutputPath "Secure Score"
                if (Test-Path -LiteralPath $secureScoreFolder) {
                    $script:SecureScoreChartPath = Get-ChildItem -Path $secureScoreFolder -Filter "SecureScore_Trend_*pct.png" -File -ErrorAction SilentlyContinue |
                        Sort-Object LastWriteTime -Descending |
                        Select-Object -First 1 -ExpandProperty FullName
                }
            }
    
            # Capture summary CSV path (existing behavior)
            if ($ss -and $ss.SummaryPath -and (Test-Path -LiteralPath $ss.SummaryPath)) {
                $script:SecureScoreSummaryCsvPath = $ss.SummaryPath
            }
            else {
                $maybe = Join-Path (Join-Path $OutputPath "Secure Score") "SecureScore_Summary.csv"
                if (Test-Path -LiteralPath $maybe) { $script:SecureScoreSummaryCsvPath = $maybe }
            }
    
            # NEW: Capture Secure Score values for exec summary narrative (points/max/percent/date)
            if ($ss) {
                if ($ss.ContainsKey('Percentage'))  { $script:SecureScorePercent      = $ss.Percentage }
                if ($ss.ContainsKey('Current'))     { $script:SecureScorePoints       = $ss.Current }
                if ($ss.ContainsKey('MaxScore'))    { $script:SecureScoreMaxScore     = $ss.MaxScore }
                if ($ss.ContainsKey('CreatedDate')) { $script:SecureScoreCreatedDate  = $ss.CreatedDate }
            }
        }
        catch {
            Write-Host "[WARN] Secure Score export failed: $($_.Exception.Message)"
        }
    }
    # DEFAULT RUN: License Review export (unless skipped)
    if (-not $SkipLicenseReview) {
        try {
            $lr = Invoke-LicenseReview -OutputPath $OutputPath -LicenseMapUrl $LicenseMapUrl
            if ($lr -and (Test-Path -LiteralPath $lr)) {
                $script:LicenseReviewCsvPath = $lr
            } else {
                $maybe = Join-Path (Join-Path $OutputPath "License Review") "License_Review.csv"
                if (Test-Path -LiteralPath $maybe) { $script:LicenseReviewCsvPath = $maybe }
            }
        }
        catch {
            Write-Host "[WARN] License Review export failed: $($_.Exception.Message)"
        }
    }

    # Partner association (optional)
    if ($Partner) {
        Set-ManagementPartnerAssociationSilent -TenantId $TenantId -PartnerIdDesired $PartnerIdDesired
    }

    # ALWAYS: write context file if Actionable CSV exists
    try {
        if ($export -and $export.AssessmentFolder -and $export.ActionableCsv -and (Test-Path -LiteralPath $export.ActionableCsv)) {
    
            $ctxPath = Join-Path $export.AssessmentFolder "ExecutiveSummary.Context.json"
            $script:ExecSummaryContextPath = $ctxPath
    
            # Resolve CustomerName:
            # - Prefer explicit -CustomerName if provided
            # - Otherwise, pull tenant displayName from Graph
            $resolvedCustomerName = $null
    
            if (-not [string]::IsNullOrWhiteSpace($CustomerName)) {
                $resolvedCustomerName = $CustomerName.Trim()
            }
            else {
                try {
                    if (Get-Command Get-MgOrganization -ErrorAction SilentlyContinue) {
                        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
                        if ($org -and -not [string]::IsNullOrWhiteSpace($org.DisplayName)) {
                            $resolvedCustomerName = $org.DisplayName.Trim()
                        }
                    }
                    else {
                        if (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue) {
                            $resp = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization?`$select=displayName" -OutputType PSObject -ErrorAction Stop
                            $dn = $resp.value | Select-Object -First 1 -ExpandProperty displayName
                            if (-not [string]::IsNullOrWhiteSpace($dn)) {
                                $resolvedCustomerName = $dn.Trim()
                            }
                        }
                    }
                }
                catch {
                    $resolvedCustomerName = $null
                }
            }
    
            if ([string]::IsNullOrWhiteSpace($resolvedCustomerName)) {
                $resolvedCustomerName = ""   # keep deterministic JSON
            }
    
            $ctx = @{
                TenantId                  = $TenantId
                SubscriptionId            = $SubscriptionId
    
                # FIX: write the resolved value, not the raw parameter
                CustomerName              = $resolvedCustomerName
    
                PreparedBy                = $PreparedBy
                OutputPath                = $OutputPath
                AssessmentFolder          = $export.AssessmentFolder
                ActionableCsvPath         = $export.ActionableCsv
    
                SecureScoreChartPath      = $script:SecureScoreChartPath
                SecureScoreSummaryCsvPath = $script:SecureScoreSummaryCsvPath
    
                SecureScorePercent        = $script:SecureScorePercent
                SecureScorePoints         = $script:SecureScorePoints
                SecureScoreMaxScore       = $script:SecureScoreMaxScore
                SecureScoreCreatedDate    = $script:SecureScoreCreatedDate
    
                LicenseReviewCsvPath      = $script:LicenseReviewCsvPath
    
                CreatedUtc                = (Get-Date).ToUniversalTime().ToString("o")
            }
    
            $null = Write-ExecSummaryContextFile -ContextPath $ctxPath -Context $ctx
    
            if ($ExecSummary) {
                $execSummaryUrl = "https://github.com/nubrixsecurity/zero-trust-assessment/blob/main/invoke-zta-execsummary.ps1"
                $execScript = Get-ExecSummaryScriptFromTempOrDownload -ScriptUrl $execSummaryUrl
    
                if ($execScript -and (Test-Path -LiteralPath $execScript) -and (Test-Path -LiteralPath $ctxPath)) {
                    $ok = Invoke-ExecSummaryScript -ScriptPath $execScript -ContextPath $ctxPath
                    if (-not $ok) {
                        Write-Host "[WARN] Exec Summary did not complete successfully."
                    }
                }
                else {
                    Write-Host "[WARN] Exec Summary could not run (script or context missing)."
                }
            }
        }
        else {
            Write-Host "[WARN] Context file not written because Actionable CSV was not produced."
        }
    }
    catch {
        Write-Host "[WARN] Failed to write context file / run Exec Summary: $($_.Exception.Message)"
    }

    Write-Host "[INFO] Completed. Results saved to: $OutputPath" -f cyan
}
catch {
    Write-Error $_.Exception.Message
    throw
}
finally {
    #$null = Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue
    #$null = Clear-AzContext -Scope Process -ErrorAction SilentlyContinue
    #$null = Disconnect-MgGraph -ErrorAction SilentlyContinue

    # Self-delete only when NOT using -NoSelfDelete
    if (-not $NoSelfDelete) {
        $deleteTargets = @(
            $scriptPath,
            $script:ExecSummaryContextPath,
            $script:LicenseMapPath,
            $script:NubrixTempRoot
        )

        Invoke-SelfDelete -Paths $deleteTargets
    }

    if ($OpenOutput) {
        try { Invoke-Item -Path $OutputPath | Out-Null } catch {}
    }

    Write-Host ""
    Write-Host "The Zero Trust Assessment has completed successfully. You may now close this window." -ForegroundColor Green

    # ONLY pause when -NoSelfDelete is used (wrapper / interactive runs)
    if ($NoSelfDelete) {
        [void][System.Console]::ReadKey($true)
        Write-Host ""
    }
}
