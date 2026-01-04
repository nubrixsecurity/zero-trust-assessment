[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId
)

function Get-PwshPath {
    try { return (Get-Command pwsh -ErrorAction Stop).Source } catch { return $null }
}

# Ensure PowerShell 7 exists (best-effort install via winget)
$pwsh = Get-PwshPath
if (-not $pwsh) {
    Write-Host "[WARN] PowerShell 7 (pwsh) not found. Attempting installation via winget..." -ForegroundColor Yellow

    $winget = $null
    try { $winget = (Get-Command winget -ErrorAction Stop).Source } catch { $winget = $null }

    if ($winget) {
        try {
            & $winget install --id Microsoft.PowerShell --source winget --accept-package-agreements --accept-source-agreements --silent | Out-Null
        }
        catch {
            Write-Host "[WARN] winget install attempt failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }

        Start-Sleep -Seconds 3
        $pwsh = Get-PwshPath
    }

    if (-not $pwsh) {
        Write-Host "[ERROR] PowerShell 7 is required but could not be installed automatically." -ForegroundColor Red
        Write-Host "Install it, then re-run this script." -ForegroundColor Red
        Write-Host "Try:" -ForegroundColor Red
        Write-Host "  winget install --id Microsoft.PowerShell --source winget" -ForegroundColor Red
        exit 1
    }
}

# Working folder for Nubrix ZTA temp artifacts
$ztaTemp = Join-Path $env:TEMP "nubrix-zta"
New-Item -Path $ztaTemp -ItemType Directory -Force | Out-Null

# Download the main runner into the temp folder
$u = "https://raw.githubusercontent.com/nubrixsecurity/zero-trust-assessment/main/run-zta.ps1"
$p = Join-Path $ztaTemp "run-zta.ps1"
Invoke-WebRequest -Uri $u -OutFile $p -ErrorAction Stop

# Launch the assessment in a separate pwsh process
$ztaProc = Start-Process -FilePath $pwsh -ArgumentList @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$p`"",
    "-TenantId", $TenantId,
    "-SubscriptionId", $SubscriptionId,
    "-OpenOutput"
) -PassThru

# Detached cleanup worker: waits for the ZTA process to exit, then deletes %TEMP%\nubrix-zta
Start-Process -FilePath $pwsh -WindowStyle Hidden -ArgumentList @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-Command",
    "param(`$pidToWait, `$folder); " +
    "try { Wait-Process -Id `$pidToWait -ErrorAction SilentlyContinue } catch {}; " +
    "Start-Sleep -Seconds 2; " +
    "try { if (Test-Path -LiteralPath `$folder) { Remove-Item -LiteralPath `$folder -Recurse -Force -ErrorAction SilentlyContinue } } catch {}",
    "-pidToWait", $ztaProc.Id,
    "-folder", $ztaTemp
) | Out-Null

# Wait for completion so we can show a friendly final message
Wait-Process -Id $ztaProc.Id

Write-Host ""
if ($ztaProc.ExitCode -eq 0) {
    Write-Host "The Zero Trust Assessment has completed successfully. You may now close this window." -ForegroundColor Green
} else {
    Write-Host "The Zero Trust Assessment finished with errors (exit code: $($ztaProc.ExitCode)). Review output/logs and rerun if needed." -ForegroundColor Yellow
}
