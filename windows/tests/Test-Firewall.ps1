#requires -Version 5.1
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '..\Monitoring.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\Firewall.psm1') -Force
$p=Read-CcdcProfile (Join-Path $PSScriptRoot '..\profile.default.json')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
function Reject([scriptblock]$Body){$failed=$false;try{& $Body | Out-Null}catch{$failed=$true};Assert $failed 'Expected firewall guard to reject action'}
$dns=New-CcdcFirewallPlan -Action Allow -Ports 53 -Protocol Both -Profile $p
Assert ($dns.Protocols.Count -eq 2 -and $dns.ScoringRisk) 'DNS preset must include both transports and scoring warning'
$ssh=New-CcdcFirewallPlan -Action Block -Ports 22 -Profile $p
Assert ($ssh.Ports[0] -eq '22' -and -not $ssh.ScoringRisk) 'Scoped SSH blocking should be possible'
Reject {New-CcdcFirewallPlan -Action Block -Ports 389 -Role AD -Profile $p}
Reject {New-CcdcFirewallPlan -Action Block -Ports 53 -Profile $p}
Reject {New-CcdcFirewallPlan -Action Block -Ports Any -Profile $p}
Reject {New-CcdcFirewallPlan -Action Block -Ports 22 -RemoteAddress '0.0.0.0/0' -Profile $p}
Reject {New-CcdcFirewallPlan -Action Block -Ports 22 -RemoteAddress '127.0.0.1' -Profile $p}
Reject {New-CcdcFirewallPlan -Action Allow -Ports '1-65535' -Profile $p}
$p.KnownManagementAddresses=@('192.0.2.10')
Reject {New-CcdcFirewallPlan -Action Block -Ports 22 -RemoteAddress '192.0.2.10' -Profile $p}
$plan=New-CcdcFirewallPlan -Action Block -Ports Any -RemoteAddress '192.0.2.11' -Protocol Both -Profile $p
Reject {Invoke-CcdcFirewallPlan -Plan $plan -EvidenceDirectory 'unused'}
Reject {Invoke-CcdcFirewallPlan -Plan $plan -EvidenceDirectory 'unused' -Approved}
Reject {Undo-CcdcFirewallRule -Name 'Existing-Windows-Rule' -EvidenceDirectory 'unused' -Approved}
# WhatIf must not touch the Windows platform, including on Linux.
Invoke-CcdcFirewallPlan -Plan $plan -EvidenceDirectory 'unused' -Approved -AcknowledgeScoringRisk -WhatIf
Write-Host 'PASS: service presets, scoped rules, protected ports/addresses, explicit approval, undo ownership and WhatIf'
