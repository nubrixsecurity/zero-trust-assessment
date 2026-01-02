<#
    FLAGS:
    -Partner
    -Partner -PartnerIdDesired 1234567
    -LicenseReview
    -SecureScore
    -KeepZtExport   (optional; keeps the zt-export folder instead of deleting it)
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
    [switch]$KeepZtExport,

    # Optional metadata for your branded Word template placeholders (safe to omit)
    [Parameter(Mandatory = $false)]
    [string]$CustomerName,

    [Parameter(Mandatory = $false)]
    [string]$PreparedBy = "Nubrix Security",

    # Optional override; if omitted, the script generates a short executive summary paragraph
    [Parameter(Mandatory = $false)]
    [string]$ExecutiveSummaryText,

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
        try { Install-Module $Name -Scope CurrentUser -AllowClobber -Force } finally {
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
        try { Update-Module $Name -Scope CurrentUser -Force -ErrorAction SilentlyContinue } finally {
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
            if ($ctx.Tenant.Id) { $ctxTenant = $ctx.Tenant.Id } else { $ctxTenant = [string]$ctx.Tenant }
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

#region ZTA Report -> Actionable CSV + folder structure (Assessment Report)
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
        [string]$OutputPath,

        [Parameter(Mandatory = $false)]
        [switch]$KeepZtExport
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

    $outCsv = Join-Path $assessmentFolder "ZeroTrustAssessment_Actionable.csv"
    $rows | Export-Csv -Path $outCsv -NoTypeInformation -Encoding UTF8

    try {
        $destHtml = Join-Path $assessmentFolder (Split-Path $htmlReportPath -Leaf)
        if ($htmlReportPath -ne $destHtml) {
            Move-Item -LiteralPath $htmlReportPath -Destination $destHtml -Force -ErrorAction Stop
        }
    } catch {}

    if (-not $KeepZtExport) {
        try {
            $ztExportPath = Join-Path $OutputPath "zt-export"
            if (Test-Path -LiteralPath $ztExportPath) {
                Remove-Item -LiteralPath $ztExportPath -Recurse -Force -ErrorAction Stop
            }
        } catch {}
    }

    return @{
        AssessmentFolder = $assessmentFolder
        ActionableCsv    = $outCsv
        RowCount         = ($rows | Measure-Object).Count
    }
}
#endregion ZTA Report -> Actionable CSV + folder structure

#region Executive Summary (Word template in script root)
function Get-RiskRank {
    param([string]$Value)
    switch -Regex ($Value) {
        'critical' { return 4 }
        'high'     { return 3 }
        'medium'   { return 2 }
        'low'      { return 1 }
        default    { return 0 }
    }
}

function Find-ExecutiveSummaryTemplate {
    [CmdletBinding()]
    param()

    # User said: template is in root (same folder as run-zta.ps1)
    $root = $PSScriptRoot

    $preferred = Join-Path $root "ZeroTrustAssessment_ExecutiveSummary_Template.docx"
    if (Test-Path -LiteralPath $preferred) { return $preferred }

    $match = Get-ChildItem -Path $root -File -Filter "*.docx" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'executive|summary|zta' } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($match) { return $match.FullName }

    return $null
}

function Replace-DocPlaceholders {
    param(
        [Parameter(Mandatory)]$Doc,
        [Parameter(Mandatory)][hashtable]$Map
    )

    foreach ($k in $Map.Keys) {
        $findText = $k
        $replaceText = [string]$Map[$k]

        # Word Find/Replace (wdReplaceAll = 2)
        $range = $Doc.Content
        $find = $range.Find
        $find.ClearFormatting() | Out-Null
        $find.Replacement.ClearFormatting() | Out-Null
        $null = $find.Execute($findText, $false, $true, $false, $false, $false, $true, 1, $false, $replaceText, 2)
    }
}

function Populate-TopRisksTable {
    param(
        [Parameter(Mandatory)]$Doc,
        [Parameter(Mandatory)]$TopRisks
    )

    # Find the first table that looks like the "Top risks" table by checking header cells.
    $target = $null
    foreach ($t in $Doc.Tables) {
        try {
            $c1 = ($t.Cell(1,1).Range.Text -replace '[\r\a]+','').Trim()
            $c2 = ($t.Cell(1,2).Range.Text -replace '[\r\a]+','').Trim()
            $c3 = ($t.Cell(1,3).Range.Text -replace '[\r\a]+','').Trim()
            if ($c1 -eq 'TestId' -and $c2 -match 'Title' -and $c3 -eq 'Pillar') {
                $target = $t
                break
            }
        } catch {}
    }

    if (-not $target) { return }

    # Ensure header + 10 rows
    $desiredRows = 1 + 10
    while ($target.Rows.Count -lt $desiredRows) { $null = $target.Rows.Add() }
    while ($target.Rows.Count -gt $desiredRows) { $target.Rows.Item($target.Rows.Count).Delete() | Out-Null }

    # Fill rows 2..11
    for ($i = 0; $i -lt 10; $i++) {
        $rowIndex = $i + 2
        $item = $null
        if ($i -lt $TopRisks.Count) { $item = $TopRisks[$i] }

        $vals = @{
            1 = if ($item) { [string]$item.TestId } else { "" }
            2 = if ($item) { [string]$item.TestTitle } else { "" }
            3 = if ($item) { [string]$item.TestPillar } else { "" }
            4 = if ($item) { [string]$item.TestStatus } else { "" }
            5 = if ($item) { ("{0} / {1}" -f $item.TestRisk, $item.TestImpact) } else { "" }
            6 = if ($item) { [string]$item.RemediationLinks } else { "" }
        }

        foreach ($col in $vals.Keys) {
            try {
                $cellRange = $target.Cell($rowIndex, $col).Range
                $cellRange.Text = $vals[$col]
            } catch {}
        }
    }
}

function New-ZtaExecutiveSummaryDoc {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AssessmentFolder,

        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$ActionableCsvPath,

        [Parameter(Mandatory = $false)]
        [string]$CustomerName,

        [Parameter(Mandatory = $false)]
        [string]$PreparedBy = "Nubrix Security",

        [Parameter(Mandatory = $false)]
        [string]$ExecutiveSummaryText
    )

    $templatePath = Find-ExecutiveSummaryTemplate
    if (-not $templatePath) { return } # silent best-effort

    if (-not (Test-Path -LiteralPath $ActionableCsvPath)) { return }

    $rows = Import-Csv -Path $ActionableCsvPath
    if (-not $rows -or $rows.Count -eq 0) { return }

    $runDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $total = $rows.Count

    $fails  = @($rows | Where-Object { $_.TestStatus -match 'fail|at risk|noncompliant|not met' }).Count
    $passes = @($rows | Where-Object { $_.TestStatus -match 'pass|implemented|compliant' }).Count
    $manual = $total - $fails - $passes

    $statusBreakdown = $rows | Group-Object TestStatus | Sort-Object Count -Descending |
        ForEach-Object { "- {0}: {1}" -f (if ([string]::IsNullOrWhiteSpace($_.Name)) { "Unknown" } else { $_.Name }), $_.Count }
    $statusBreakdownText = if ($statusBreakdown) { ($statusBreakdown -join "`r`n") } else { "" }

    $topPillars = $rows | Where-Object { $_.TestStatus -match 'fail|at risk|noncompliant|not met' } |
        Group-Object TestPillar | Sort-Object Count -Descending | Select-Object -First 5 |
        ForEach-Object { "- {0}: {1}" -f (if ([string]::IsNullOrWhiteSpace($_.Name)) { "Unknown" } else { $_.Name }), $_.Count }
    $topPillarsText = if ($topPillars) { ($topPillars -join "`r`n") } else { "" }

    $topRisks = $rows |
        ForEach-Object {
            $_ | Add-Member -NotePropertyName _RiskScore -NotePropertyValue (Get-RiskRank $_.TestRisk) -Force
            $_ | Add-Member -NotePropertyName _ImpactScore -NotePropertyValue (Get-RiskRank $_.TestImpact) -Force
            $_
        } |
        Sort-Object _RiskScore, _ImpactScore -Descending |
        Select-Object -First 10

    if ([string]::IsNullOrWhiteSpace($ExecutiveSummaryText)) {
        $pillarHint = ($topPillars | Select-Object -First 2) -join "; "
        if ([string]::IsNullOrWhiteSpace($pillarHint)) { $pillarHint = "the major Zero Trust pillars" }

        $ExecutiveSummaryText =
            "This Zero Trust Assessment produced $total recommendations. " +
            "A total of $fails items were identified as failed/at risk, and $passes items were identified as passed/implemented. " +
            "The highest concentration of gaps is typically observed across $pillarHint. " +
            "Use the Actionable CSV to assign owners and track remediation, and consider converting the results into a phased roadmap (0–30, 30–90, 90–180 days) to align remediation work to business risk."
    }

    $destDoc = Join-Path $AssessmentFolder "ZeroTrustAssessment_ExecutiveSummary.docx"
    Copy-Item -LiteralPath $templatePath -Destination $destDoc -Force

    $word = $null
    $doc = $null
    try {
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $doc = $word.Documents.Open($destDoc, $false, $false)

        $map = @{
            "{{customer_name}}"                = $(if ([string]::IsNullOrWhiteSpace($CustomerName)) { "{{customer_name}}" } else { $CustomerName })
            "{{prepared_by}}"                  = $(if ([string]::IsNullOrWhiteSpace($PreparedBy))   { "Nubrix Security" } else { $PreparedBy })
            "{{run_date}}"                     = $runDate
            "{{tenant_id}}"                    = $TenantId
            "{{executive_summary_paragraph}}"  = $ExecutiveSummaryText
            "{{total_recommendations}}"        = "$total"
            "{{failed_count}}"                 = "$fails"
            "{{passed_count}}"                 = "$passes"
            "{{manual_or_not_scored_count}}"   = "$manual"
            "{{status_breakdown_bullets}}"     = $statusBreakdownText
            "{{top_pillars_bullets}}"          = $topPillarsText

            # Optional sections (leave tokens if you want to manually fill later)
            "{{roadmap_0_30}}"                 = "{{roadmap_0_30}}"
            "{{roadmap_30_90}}"                = "{{roadmap_30_90}}"
            "{{roadmap_90_180}}"               = "{{roadmap_90_180}}"
            "{{workshop_cta}}"                 = "{{workshop_cta}}"
            "{{scope_assumptions}}"            = "{{scope_assumptions}}"
        }

        Replace-DocPlaceholders -Doc $doc -Map $map
        Populate-TopRisksTable -Doc $doc -TopRisks $topRisks

        $doc.Save()
    }
    catch {
        # silent best-effort (to preserve minimal console output)
    }
    finally {
        try { if ($doc)  { $doc.Close($true) | Out-Null } } catch {}
        try { if ($word) { $word.Quit() | Out-Null } } catch {}
        if ($doc)  { try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($doc)  | Out-Null } catch {} }
        if ($word) { try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) | Out-Null } catch {} }
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
    }
}
#endregion Executive Summary

#region Self-delete (best-effort)
function Invoke-SelfDelete {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )

    if ($NoSelfDelete) { return }
    if ([string]::IsNullOrWhiteSpace($ScriptPath) -or -not (Test-Path -LiteralPath $ScriptPath)) { return }

    try {
        $cmd = "/c ping 127.0.0.1 -n 3 > nul & del /f /q `"$ScriptPath`""
        Start-Process -FilePath "cmd.exe" -ArgumentList $cmd -WindowStyle Hidden | Out-Null
    } catch {}
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
    $export = $null
    try {
        $export = Export-ZtaActionableCsv -OutputPath $OutputPath -KeepZtExport:$KeepZtExport
    } catch {}

    # Generate Executive Summary docx (best-effort, silent)
    try {
        if ($export -and $export.AssessmentFolder -and $export.ActionableCsv) {
            New-ZtaExecutiveSummaryDoc `
                -AssessmentFolder $export.AssessmentFolder `
                -TenantId $TenantId `
                -ActionableCsvPath $export.ActionableCsv `
                -CustomerName $CustomerName `
                -PreparedBy $PreparedBy `
                -ExecutiveSummaryText $ExecutiveSummaryText
        }
    } catch {}

    if ($Partner) {
        Set-ManagementPartnerAssociationSilent -TenantId $TenantId -PartnerIdDesired $PartnerIdDesired
    }

    if ($LicenseReview) {
        Invoke-LicenseReview -OutputPath $OutputPath -LicenseMapUrl $LicenseMapUrl
    }

    if ($SecureScore) {
        try { Invoke-SecureScoreExport -OutputPath $OutputPath } catch {}
    }

    Write-Host "[INFO] Completed. Results saved to: $OutputPath"
}
catch {
    Write-Error $_.Exception.Message
    throw
}
finally {
    #$null = Disconnect-AzAccount -Scope Process -ErrorAction SilentlyContinue
    #$null = Clear-AzContext -Scope Process -ErrorAction SilentlyContinue
    #$null = Disconnect-MgGraph -ErrorAction SilentlyContinue

    Invoke-SelfDelete -ScriptPath $scriptPath

    if ($OpenOutput) {
        try { Invoke-Item -Path $OutputPath | Out-Null } catch {}
    }

    Write-Host ""
    Write-Host "The Zero Trust Assessment has completed successfully. You may now close this window." -ForegroundColor Green
    [void][System.Console]::ReadKey($true)
    Write-Host ""
}
