[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId
)

$ztaTemp = Join-Path $env:TEMP "nubrix-zta"
New-Item -Path $ztaTemp -ItemType Directory -Force | Out-Null

$u = "https://raw.githubusercontent.com/nubrixsecurity/zero-trust-assessment/main/run-zta.ps1"
$p = Join-Path $ztaTemp "run-zta.ps1"

Invoke-WebRequest -Uri $u -OutFile $p -ErrorAction Stop

$ztaProc = Start-Process -FilePath "pwsh" -ArgumentList @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$p`"",
    "-TenantId", $TenantId,
    "-SubscriptionId", $SubscriptionId,
    "-OpenOutput"
) -PassThru

Start-Process -FilePath "pwsh" -WindowStyle Hidden -ArgumentList @(
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

Wait-Process -Id $ztaProc.Id

Write-Host ""
if ($ztaProc.ExitCode -eq 0) {
    Write-Host "The Zero Trust Assessment has completed successfully. You may now close this window." -ForegroundColor Green
} else {
    Write-Host "The Zero Trust Assessment finished with errors (exit code: $($ztaProc.ExitCode)). Review output/logs and rerun if needed." -ForegroundColor Yellow
}
Write-Host ""
