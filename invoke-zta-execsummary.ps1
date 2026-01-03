<#
    Invoke-ExecSummary.ps1
    Purpose:
      - Reads a context JSON file produced by the main ZTA script
      - Generates ZeroTrustAssessment_ExecutiveSummary.docx in the Assessment Report folder
      - Populates Word Rich Text Content Controls (Tag/Title OR placeholder text) across ALL StoryRanges
      - Inserts Top Risks table via Rich Text Content Control (NO bookmarks)
      - Inserts Secure Score summary text + Secure Score chart image via Rich Text Content Controls (if provided)

    Requires:
      - PowerShell 7+
      - Microsoft Word installed (COM automation)

    Context JSON (expected fields; extra fields are ignored):
      TenantId
      CustomerName (optional)
      PreparedBy  (optional)
      RunDate     (optional)
      OutputPath  (optional)
      AssessmentFolder
      ActionableCsv
      SecureScoreImage (optional; full path to PNG)

    Template requirements (Rich Text Content Controls):
      CustomerName
      PreparedBy
      RunDate
      TenantId
      ExecutiveSummary
      TotalRecommendations
      FailedCount
      PassedCount
      ManualCount
      StatusBreakdown
      TopPillars
      Roadmap_0_30
      Roadmap_30_90
      Roadmap_90_180
      Workshop_CTA

      TopRisksTableSpot   (Rich Text CC for table insertion)

      SecureScore_Summary (Rich Text CC)
      SecureScore_Image   (Rich Text CC)

    Usage:
      pwsh -NoProfile -ExecutionPolicy Bypass -File .\Invoke-ExecSummary.ps1 -ContextPath "C:\...\Assessment Report\ExecSummaryContext.json"

    Optional:
      -TemplatePath "C:\path\ZeroTrustAssessment_ExecutiveSummary_Template.docx"
      -TemplateUrl  "https://github.com/nubrixsecurity/zero-trust-assessment/blob/main/ZeroTrustAssessment_ExecutiveSummary_Template.docx"
      -OutFileName  "ZeroTrustAssessment_ExecutiveSummary.docx"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ContextPath,

    [Parameter(Mandatory = $false)]
    [string]$TemplatePath,

    [Parameter(Mandatory = $false)]
    [string]$TemplateUrl = "https://github.com/nubrixsecurity/zero-trust-assessment/blob/main/ZeroTrustAssessment_ExecutiveSummary_Template.docx",

    [Parameter(Mandatory = $false)]
    [string]$OutFileName = "ZeroTrustAssessment_ExecutiveSummary.docx",

    [Parameter(Mandatory = $false)]
    [string]$CustomerNameOverride,

    [Parameter(Mandatory = $false)]
    [string]$PreparedByOverride
)

#region ===== Helpers: GitHub raw + download =====
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

function Get-ExecutiveSummaryTemplateFromTempOrDownload {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TemplateUrl)

    $fileName = "ZeroTrustAssessment_ExecutiveSummary_Template.docx"
    $tempPath = Join-Path $env:TEMP $fileName

    if (Test-Path -LiteralPath $tempPath) {
        return $tempPath
    }

    $rawUrl = Convert-GitHubUrlToRaw -Url $TemplateUrl

    $oldPP = $ProgressPreference
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $rawUrl -OutFile $tempPath -ErrorAction Stop

        # Prevent Protected View / MOTW prompts from blocking Word COM automation
        try { Unblock-File -LiteralPath $tempPath -ErrorAction SilentlyContinue } catch {}

        return $tempPath
    }
    catch {
        Write-Host "[WARN] Failed to download template: $($_.Exception.Message)"
        return $null
    }
    finally {
        $ProgressPreference = $oldPP
    }
}

function Resolve-TemplatePath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$ProvidedPath,
        [Parameter(Mandatory = $false)][string]$TemplateUrl
    )

    $fileName = "ZeroTrustAssessment_ExecutiveSummary_Template.docx"

    if (-not [string]::IsNullOrWhiteSpace($ProvidedPath) -and (Test-Path -LiteralPath $ProvidedPath)) {
        return (Resolve-Path -LiteralPath $ProvidedPath).Path
    }

    $p1 = Join-Path $PSScriptRoot $fileName
    if (Test-Path -LiteralPath $p1) { return $p1 }

    $p2 = Join-Path (Get-Location).Path $fileName
    if (Test-Path -LiteralPath $p2) { return $p2 }

    $p3 = Join-Path (Join-Path $env:USERPROFILE "Downloads") $fileName
    if (Test-Path -LiteralPath $p3) { return $p3 }

    if (-not [string]::IsNullOrWhiteSpace($TemplateUrl)) {
        $tmp = Get-ExecutiveSummaryTemplateFromTempOrDownload -TemplateUrl $TemplateUrl
        if ($tmp -and (Test-Path -LiteralPath $tmp)) { return $tmp }
    }

    return $null
}
#endregion

#region ===== Helpers: Word / Content Controls =====
function Test-WordComAvailable {
    try {
        $w = New-Object -ComObject Word.Application
        $w.Quit() | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($w) | Out-Null
        return $true
    }
    catch { return $false }
}

# Return ALL content controls, including headers/footers/textboxes (StoryRanges)
function Get-AllContentControls {
    param([Parameter(Mandatory)]$Doc)

    $all = @()
    try { $all += @($Doc.ContentControls) } catch {}

    try {
        $sr = $Doc.StoryRanges
        while ($sr) {
            try {
                if ($sr.ContentControls) { $all += @($sr.ContentControls) }
            } catch {}
            try { $sr = $sr.NextStoryRange } catch { break }
        }
    } catch {}

    return $all
}

function Get-ContentControlByKey {
    param(
        [Parameter(Mandatory)]$Doc,
        [Parameter(Mandatory)][string]$Key
    )

    foreach ($cc in @(Get-AllContentControls -Doc $Doc)) {
        try {
            if ($cc.Tag -eq $Key -or $cc.Title -eq $Key) { return $cc }
        } catch {}
    }
    return $null
}

function Get-ContentControlByPlaceholderText {
    param(
        [Parameter(Mandatory)]$Doc,
        [Parameter(Mandatory)][string]$Key
    )

    foreach ($cc in @(Get-AllContentControls -Doc $Doc)) {
        try {
            $text = $null
            try { $text = $cc.Range.Text } catch { $text = $null }

            if (-not [string]::IsNullOrWhiteSpace($text)) {
                if ($text.Trim() -eq $Key) { return $cc }
            }
        } catch {}
    }

    return $null
}

function Set-RichCCValue {
    param(
        [Parameter(Mandatory)]$Doc,
        [Parameter(Mandatory)][string]$Key,

        # IMPORTANT: allow blanks (CustomerName may be empty)
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text = ""
    )

    $cc = Get-ContentControlByKey -Doc $Doc -Key $Key
    if (-not $cc) { $cc = Get-ContentControlByPlaceholderText -Doc $Doc -Key $Key }
    if (-not $cc) { return $false }

    try {
        $cc.LockContents = $false

        # Clear existing content
        try { $cc.Range.Delete() } catch {}

        # Insert text (blank is allowed)
        $cc.Range.InsertAfter([string]$Text)
        return $true
    }
    catch {
        return $false
    }
}

function Set-ImageInRichCC {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Doc,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$ImagePath
    )

    if ([string]::IsNullOrWhiteSpace($ImagePath) -or -not (Test-Path -LiteralPath $ImagePath)) {
        return $false
    }

    $cc = Get-ContentControlByKey -Doc $Doc -Key $Key
    if (-not $cc) { $cc = Get-ContentControlByPlaceholderText -Doc $Doc -Key $Key }
    if (-not $cc) { return $false }

    try {
        $cc.LockContents = $false
        try { $cc.Range.Delete() } catch {}

        $rng = $cc.Range
        $null = $rng.InlineShapes.AddPicture($ImagePath)
        return $true
    }
    catch {
        return $false
    }
}
#endregion

#region ===== Helpers: Roadmap + CTA text =====
function Get-RoadmapText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Rows,
        [Parameter(Mandatory)][ValidateSet('0_30','30_90','90_180')][string]$Window
    )

    $fail = @($Rows | Where-Object { $_.TestStatus -match 'fail|at risk|noncompliant|not met' })

    $topPillars = @(
        $fail |
        Group-Object TestPillar |
        Sort-Object Count -Descending |
        Select-Object -First 3 |
        ForEach-Object { $_.Name } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    $pText = if ($topPillars.Count -gt 0) { ($topPillars -join ", ") } else { "Identity, Devices, Applications" }

    switch ($Window) {
        '0_30' {
            return @(
                "Focus on quick wins that reduce immediate risk and harden identity and admin controls.",
                "Prioritize failed/at-risk findings in pillars: $pText.",
                "Typical actions: enforce MFA, reduce standing admin roles, validate Conditional Access baselines, close obvious policy gaps, and address critical/high risk items first."
            ) -join "`r`n"
        }
        '30_90' {
            return @(
                "Focus on hardening and standardization across users, devices, and access policies.",
                "Typical actions: expand Conditional Access coverage, require compliant devices where appropriate, tighten legacy authentication controls, standardize device baselines, and improve alerting/visibility."
            ) -join "`r`n"
        }
        '90_180' {
            return @(
                "Focus on governance and operationalization to sustain Zero Trust improvements.",
                "Typical actions: implement access reviews, automate enforcement where possible, mature monitoring/response playbooks, align controls to business units and data sensitivity, and establish a monthly posture review cadence."
            ) -join "`r`n"
        }
    }
}

function Get-WorkshopCtaText {
    return @(
        "Zero Trust Roadmap Workshop (optional):",
        "We’ll review the findings, validate priorities with stakeholders, and produce a phased execution plan.",
        "Deliverables typically include: a 90-day remediation backlog with owners, effort estimates, dependencies, and a clear roadmap aligned to business risk."
    ) -join "`r`n"
}
#endregion

#region ===== Helpers: Top Risks table via Content Control =====
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

function Add-TopRisksTable_IntoContentControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Doc,
        [Parameter(Mandatory)][object[]]$TopRisks,
        [Parameter(Mandatory)][string]$Key
    )

    $cc = Get-ContentControlByKey -Doc $Doc -Key $Key
    if (-not $cc) { $cc = Get-ContentControlByPlaceholderText -Doc $Doc -Key $Key }
    if (-not $cc) { return $false }

    try {
        $cc.LockContents = $false

        # Clear placeholder
        $cc.Range.Text = ""
        $range = $cc.Range
        $range.Collapse(0) # wdCollapseStart

        $rows = 11
        $cols = 6
        $tbl = $Doc.Tables.Add($range, $rows, $cols)
        $tbl.Style = "Table Grid"

        $tbl.Cell(1,1).Range.Text = "TestId"
        $tbl.Cell(1,2).Range.Text = "Title"
        $tbl.Cell(1,3).Range.Text = "Pillar"
        $tbl.Cell(1,4).Range.Text = "Status"
        $tbl.Cell(1,5).Range.Text = "Risk/Impact"
        $tbl.Cell(1,6).Range.Text = "Remediation Links"

        for ($i = 0; $i -lt 10; $i++) {
            $r = $i + 2
            $item = $null
            if ($i -lt $TopRisks.Count) { $item = $TopRisks[$i] }

            $tbl.Cell($r,1).Range.Text = if ($item) { [string]$item.TestId } else { "" }
            $tbl.Cell($r,2).Range.Text = if ($item) { [string]$item.TestTitle } else { "" }
            $tbl.Cell($r,3).Range.Text = if ($item) { [string]$item.TestPillar } else { "" }
            $tbl.Cell($r,4).Range.Text = if ($item) { [string]$item.TestStatus } else { "" }
            $tbl.Cell($r,5).Range.Text = if ($item) { ("{0} / {1}" -f $item.TestRisk, $item.TestImpact) } else { "" }
            $tbl.Cell($r,6).Range.Text = if ($item) { [string]$item.RemediationLinks } else { "" }
        }

        return $true
    }
    catch {
        return $false
    }
}
#endregion

#region ===== Core: Generate Executive Summary =====
function New-ZtaExecutiveSummaryDoc_FromContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Ctx,
        [Parameter(Mandatory)][string]$TemplateFullPath,
        [Parameter(Mandatory)][string]$OutDocPath
    )

    if (-not (Test-Path -LiteralPath $Ctx.ActionableCsv)) { throw "Actionable CSV not found: $($Ctx.ActionableCsv)" }
    if (-not (Test-Path -LiteralPath $TemplateFullPath)) { throw "Template not found: $TemplateFullPath" }

    $rows = Import-Csv -Path $Ctx.ActionableCsv
    if (-not $rows -or $rows.Count -eq 0) { throw "Actionable CSV is empty." }

    # Normalize expected column names (support both your schema + older variants)
    # Expected properties used below:
    # TestStatus, TestPillar, TestRisk, TestImpact, TestId, TestTitle, RemediationLinks
    $norm = foreach ($r in $rows) {
        $status = $r.TestStatus; if (-not $status) { $status = $r.Status }
        $pillar = $r.TestPillar; if (-not $pillar) { $pillar = $r.Pillar }
        $risk   = $r.TestRisk;   if (-not $risk)   { $risk   = $r.Risk }
        $impact = $r.TestImpact; if (-not $impact) { $impact = $r.Impact }
        $id     = $r.TestId;     if (-not $id)     { $id     = $r.Id }
        $title  = $r.TestTitle;  if (-not $title)  { $title  = $r.Title }
        $links  = $r.RemediationLinks

        [pscustomobject]@{
            TestId           = $id
            TestTitle        = $title
            TestStatus       = $status
            TestPillar       = $pillar
            TestRisk         = $risk
            TestImpact       = $impact
            RemediationLinks = $links
        }
    }

    $runDate = if ($Ctx.RunDate) { [string]$Ctx.RunDate } else { (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }
    $tenantId = [string]$Ctx.TenantId

    $customerName = if ($CustomerNameOverride) { $CustomerNameOverride } elseif ($Ctx.CustomerName) { [string]$Ctx.CustomerName } else { "" }
    $preparedBy   = if ($PreparedByOverride)   { $PreparedByOverride }   elseif ($Ctx.PreparedBy)   { [string]$Ctx.PreparedBy }   else { "Nubrix Security" }

    $total   = [int]($norm | Measure-Object).Count
    $fails  = [int](($norm | Where-Object { $_.TestStatus -match 'fail|at risk|noncompliant|not met' } | Measure-Object).Count)
    $passes = [int](($norm | Where-Object { $_.TestStatus -match 'pass|implemented|compliant' } | Measure-Object).Count)
    $manual = [int]($total - $fails - $passes)

    $statusGroups = $norm | Group-Object TestStatus | Sort-Object Count -Descending
    $statusBreakdownText = ($statusGroups | ForEach-Object {
        $name = if ([string]::IsNullOrWhiteSpace($_.Name)) { "Unknown" } else { $_.Name }
        "- ${name}: $($_.Count)"
    }) -join "`r`n"

    $failRows = $norm | Where-Object { $_.TestStatus -match 'fail|at risk|noncompliant|not met' }
    $pillarGroups = $failRows | Group-Object TestPillar | Sort-Object Count -Descending | Select-Object -First 5
    $topPillarsText = ($pillarGroups | ForEach-Object {
        $name = if ([string]::IsNullOrWhiteSpace($_.Name)) { "Unknown" } else { $_.Name }
        "- ${name}: $($_.Count)"
    }) -join "`r`n"

    $topRisks = $norm |
        ForEach-Object {
            $_ | Add-Member -NotePropertyName _RiskScore   -NotePropertyValue (Get-RiskRank $_.TestRisk)   -Force
            $_ | Add-Member -NotePropertyName _ImpactScore -NotePropertyValue (Get-RiskRank $_.TestImpact) -Force
            $_
        } |
        Sort-Object _RiskScore, _ImpactScore -Descending |
        Select-Object -First 10

    $execSummaryText =
        "This Zero Trust Assessment produced $total recommendations. " +
        "A total of $fails items were identified as failed/at risk, and $passes items were identified as passed/implemented. " +
        "Use the Actionable CSV to assign owners and track remediation, and convert the results into a phased roadmap (0–30, 30–90, 90–180 days) aligned to business risk."

    $roadmap0_30   = Get-RoadmapText -Rows $norm -Window '0_30'
    $roadmap30_90  = Get-RoadmapText -Rows $norm -Window '30_90'
    $roadmap90_180 = Get-RoadmapText -Rows $norm -Window '90_180'
    $workshopCta   = Get-WorkshopCtaText

    $secureScoreSummaryText = @(
        "Secure Score Summary:",
        "The Secure Score trend chart is included below.",
        "Recommended next steps: address high-impact gaps first (especially identity and admin protections), and establish a monthly posture review cadence."
    ) -join "`r`n"

    $secureScoreImage = $null

    # Support both keys
    if ($Ctx.SecureScoreChartPath -and (Test-Path -LiteralPath $Ctx.SecureScoreChartPath)) {
        $secureScoreImage = [string]$Ctx.SecureScoreChartPath
    }
    elseif ($Ctx.SecureScoreImage -and (Test-Path -LiteralPath $Ctx.SecureScoreImage)) {
        $secureScoreImage = [string]$Ctx.SecureScoreImage
    }


    if (-not (Test-WordComAvailable)) { throw "Microsoft Word COM automation not available." }

    $word = $null
    $doc  = $null
    try {
        Write-Host "[INFO] Launching Word COM..."
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $word.DisplayAlerts = 0

        Write-Host "[INFO] Opening template: $TemplateFullPath"
        $doc = $word.Documents.Open($TemplateFullPath, $false, $true)

        # Ensure folder exists
        $outDir = Split-Path $OutDocPath -Parent
        if (-not (Test-Path -LiteralPath $outDir)) {
            New-Item -Path $outDir -ItemType Directory -Force | Out-Null
        }

        Write-Host "[INFO] Saving output: $OutDocPath"
        $doc.SaveAs2($OutDocPath) | Out-Null

        Write-Host "[INFO] Re-opening output for edits..."
        $doc.Close($false) | Out-Null
        $doc = $word.Documents.Open($OutDocPath, $false, $false)

        # Populate standard CCs
        $null = Set-RichCCValue -Doc $doc -Key "CustomerName"         -Text $customerName
        $null = Set-RichCCValue -Doc $doc -Key "PreparedBy"           -Text $preparedBy
        $null = Set-RichCCValue -Doc $doc -Key "RunDate"              -Text $runDate
        $null = Set-RichCCValue -Doc $doc -Key "TenantId"             -Text $tenantId

        $null = Set-RichCCValue -Doc $doc -Key "ExecutiveSummary"     -Text $execSummaryText
        $null = Set-RichCCValue -Doc $doc -Key "TotalRecommendations" -Text "$total"
        $null = Set-RichCCValue -Doc $doc -Key "FailedCount"          -Text "$fails"
        $null = Set-RichCCValue -Doc $doc -Key "PassedCount"          -Text "$passes"
        $null = Set-RichCCValue -Doc $doc -Key "ManualCount"          -Text "$manual"
        $null = Set-RichCCValue -Doc $doc -Key "StatusBreakdown"      -Text $statusBreakdownText
        $null = Set-RichCCValue -Doc $doc -Key "TopPillars"           -Text $topPillarsText

        $null = Set-RichCCValue -Doc $doc -Key "Roadmap_0_30"         -Text $roadmap0_30
        $null = Set-RichCCValue -Doc $doc -Key "Roadmap_30_90"        -Text $roadmap30_90
        $null = Set-RichCCValue -Doc $doc -Key "Roadmap_90_180"       -Text $roadmap90_180
        $null = Set-RichCCValue -Doc $doc -Key "Workshop_CTA"         -Text $workshopCta

        # Secure Score (optional insert)
        $null = Set-RichCCValue -Doc $doc -Key "SecureScore_Summary" -Text $secureScoreSummaryText
        if ($secureScoreImage) {
            if (-not (Set-ImageInRichCC -Doc $doc -Key "SecureScore_Image" -ImagePath $secureScoreImage)) {
                Write-Host "[WARN] Secure Score image CC missing or insert failed: SecureScore_Image"
            } else {
                Write-Host "[INFO] Secure Score image inserted: $secureScoreImage"
            }
        } else {
            Write-Host "[WARN] Secure Score image not provided or not found; skipping image insert."
        }

        # Top Risks table via CC
        if (-not (Add-TopRisksTable_IntoContentControl -Doc $doc -TopRisks $topRisks -Key "TopRisksTableSpot")) {
            Write-Host "[WARN] Top Risks table CC missing or insert failed: TopRisksTableSpot"
        } else {
            Write-Host "[INFO] Top Risks table inserted via CC: TopRisksTableSpot"
        }

        $doc.Save() | Out-Null
        return $OutDocPath
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
#endregion

#region ===== Main =====
try {
    $ErrorActionPreference = 'Stop'

    if (-not (Test-Path -LiteralPath $ContextPath)) {
        throw "Context file not found: $ContextPath"
    }

    Write-Host "[INFO] Reading context: $ContextPath"
    $ctxRaw = Get-Content -Path $ContextPath -Raw -Encoding UTF8
    $ctx = $ctxRaw | ConvertFrom-Json

    if (-not $ctx.AssessmentFolder) { throw "Context missing: AssessmentFolder" }

    # Support both keys (new main script uses ActionableCsvPath)
    $actionableCsv = $null
    if ($ctx.ActionableCsvPath) { $actionableCsv = [string]$ctx.ActionableCsvPath }
    elseif ($ctx.ActionableCsv) { $actionableCsv = [string]$ctx.ActionableCsv }
    
    if ([string]::IsNullOrWhiteSpace($actionableCsv)) { throw "Context missing: ActionableCsvPath/ActionableCsv" }
    if (-not (Test-Path -LiteralPath $actionableCsv)) { throw "Actionable CSV not found: $actionableCsv" }
    
    if (-not $ctx.TenantId) { throw "Context missing: TenantId" }
    
    # Normalize into the object your generator expects
    $ctx | Add-Member -NotePropertyName ActionableCsv -NotePropertyValue $actionableCsv -Force

    $assessmentFolder = [string]$ctx.AssessmentFolder
    $outDoc = Join-Path $assessmentFolder $OutFileName

    $resolvedTemplate = Resolve-TemplatePath -ProvidedPath $TemplatePath -TemplateUrl $TemplateUrl
    if (-not $resolvedTemplate) {
        throw "Executive Summary template not found. Expected filename: ZeroTrustAssessment_ExecutiveSummary_Template.docx (or provide -TemplatePath)."
    }

    Write-Host "[INFO] Template resolved to: $resolvedTemplate"
    Write-Host "[INFO] Output DOCX: $outDoc"

    $created = New-ZtaExecutiveSummaryDoc_FromContext -Ctx $ctx -TemplateFullPath $resolvedTemplate -OutDocPath $outDoc
    Write-Host "[DONE] Executive Summary saved to: $created"
}
catch {
    # Rich error output (line number + stack) so parent can show it
    Write-Host "[ERROR] Exec Summary failed."
    Write-Host ("[ERROR] Message: {0}" -f $_.Exception.Message)

    if ($_.Exception.InnerException) {
        Write-Host ("[ERROR] Inner: {0}" -f $_.Exception.InnerException.Message)
    }

    if ($_.InvocationInfo) {
        Write-Host ("[ERROR] At: {0}:{1}" -f $_.InvocationInfo.ScriptName, $_.InvocationInfo.ScriptLineNumber)
        Write-Host ("[ERROR] Line: {0}" -f $_.InvocationInfo.Line)
    }

    Write-Host "[ERROR] Stack:"
    Write-Host $_.ScriptStackTrace

    exit 1
}
#endregion
