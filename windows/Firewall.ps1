#requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('Add','Undo')][string]$Mode='Add',[ValidateSet('Allow','Block')][string]$Action='Allow',
    [string]$Ports,[string]$RemoteAddress='Any',[ValidateSet('TCP','UDP','Both')][string]$Protocol='TCP',
    [ValidateSet('Inbound','Outbound')][string]$Direction='Inbound',[ValidateSet('Any','Domain','Private','Public')][string]$NetworkProfile='Any',
    [string]$Name,[string]$ProfilePath=(Join-Path $env:ProgramData 'CCDC-BlueTeam\profile.json'),
    [string]$EvidenceDirectory=(Join-Path $env:ProgramData 'CCDC-BlueTeam\Evidence\Firewall'),
    [switch]$Approved,[switch]$AcknowledgeScoringRisk)
$ErrorActionPreference='Stop'
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Firewall changes require Administrator.'}
$os=Get-CimInstance Win32_OperatingSystem
if($os.ProductType -eq 1 -or [int]$os.BuildNumber -notin @(17763,20348)){throw 'Supported: Windows Server 2019/2022.'}
Import-Module (Join-Path $PSScriptRoot 'Monitoring.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Firewall.psm1') -Force
if($Mode -eq 'Undo'){Undo-CcdcFirewallRule -Name $Name -EvidenceDirectory $EvidenceDirectory -Approved:$Approved}
else{
    $profile=Read-CcdcProfile $ProfilePath
    $role='Other';if((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4){$role='AD'}
    $plan=New-CcdcFirewallPlan -Action $Action -Ports $Ports -RemoteAddress $RemoteAddress -Protocol $Protocol -Direction $Direction -NetworkProfile $NetworkProfile -Role $role -Profile $profile
    if($plan.Action -eq 'Block' -and $plan.RemoteAddress -ne 'Any' -and @(Get-NetIPAddress | Where-Object IPAddress -eq $plan.RemoteAddress).Count){throw 'Refusing to block this server own address.'}
    Invoke-CcdcFirewallPlan -Plan $plan -EvidenceDirectory $EvidenceDirectory -Approved:$Approved -AcknowledgeScoringRisk:$AcknowledgeScoringRisk
}
Write-Warning 'Recheck current scoring and remote service access. Local rules can be overridden by GPO and may conflict with existing block rules.'
