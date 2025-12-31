[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$TenantId,
  [Parameter(Mandatory=$true)][string]$SubscriptionId,
  [string]$OutputPath = ""
)

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $runId = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
  $OutputPath = Join-Path $env:USERPROFILE "Documents\ZeroTrustAssessment\$runId"
}
New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null

Install-Module ZeroTrustAssessment -Scope CurrentUser -AllowClobber -Force
Clear-AzConfig -Scope CurrentUser -Force -ErrorAction Ignore | Out-Null
Update-AzConfig -DefaultSubscriptionForLogin $SubscriptionId -Scope CurrentUser | Out-Null

Connect-ZtAssessment -TenantId $TenantId
Invoke-ZtAssessment -Path $OutputPath
