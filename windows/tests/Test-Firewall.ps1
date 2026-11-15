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
Reject {New-CcdcFirewallPlan -Action Block -Ports 8089 -Profile $p}
Reject {New-CcdcFirewallPlan -Action Block -Ports 389 -Role AD -Profile $p}
Reject {New-CcdcFirewallPlan -Action Block -Ports 53 -Profile $p}
Reject {New-CcdcFirewallPlan -Action Block -Ports Any -Profile $p}
Reject {New-CcdcFirewallPlan -Action Block -Ports 22 -RemoteAddress '0.0.0.0/0' -Profile $p}
Reject {New-CcdcFirewallPlan -Action Block -Ports 22 -RemoteAddress '127.0.0.1' -Profile $p}
Reject {New-CcdcFirewallPlan -Action Allow -Ports '1-65535' -Profile $p}
$p.KnownManagementAddresses=@('192.0.2.10','2001:0db8:0:0:0:0:0:1')
Reject {New-CcdcFirewallPlan -Action Block -Ports 22 -RemoteAddress '2001:db8::1' -Profile $p}
Reject {New-CcdcFirewallPlan -Action Block -Ports 22 -RemoteAddress '192.0.2.10' -Profile $p}
$plan=New-CcdcFirewallPlan -Action Block -Ports Any -RemoteAddress '192.0.2.11' -Protocol Both -Profile $p
Reject {Invoke-CcdcFirewallPlan -Plan $plan -EvidenceDirectory 'unused'}
Reject {Invoke-CcdcFirewallPlan -Plan $plan -EvidenceDirectory 'unused' -Approved}
Reject {Undo-CcdcFirewallRule -Name 'Existing-Windows-Rule' -EvidenceDirectory 'unused' -Approved}
# WhatIf must not touch the Windows platform, including on Linux.
Invoke-CcdcFirewallPlan -Plan $plan -EvidenceDirectory 'unused' -Approved -AcknowledgeScoringRisk -WhatIf
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ccdc-firewall-'+[guid]::NewGuid().ToString('N'))
try{
    $module=Get-Module Firewall
    & $module {
        $script:Captured=@();$script:Removed=@();$script:FailSecond=$false
        function script:New-NetFirewallRule {
            param($Name,$DisplayName,$Group,$PolicyStore,$Action,$Direction,$Protocol,$RemoteAddress,$Profile,$Enabled,$Description,$ErrorAction,$LocalPort,$RemotePort)
            $script:Captured+=@{Name=$Name;LocalPort=$LocalPort;RemotePort=$RemotePort}
            if($script:FailSecond -and $script:Captured.Count -eq 2){throw 'simulated second protocol failure'}
        }
        function script:Remove-NetFirewallRule {param($Name,$PolicyStore,$ErrorAction) $script:Removed+=$Name}
    }
    $outbound=New-CcdcFirewallPlan -Action Block -Ports 22 -RemoteAddress '192.0.2.11' -Direction Outbound -Profile $p
    $null=Invoke-CcdcFirewallPlan -Plan $outbound -EvidenceDirectory $temp -Approved
    $captured=@(& $module {$script:Captured})
    Assert ($captured[0].RemotePort[0] -eq '22' -and -not $captured[0].LocalPort) 'Outbound service rules must match destination ports'
    & $module {$script:Captured=@();$script:Removed=@();$script:FailSecond=$true}
    $both=New-CcdcFirewallPlan -Action Block -Ports 22 -RemoteAddress '192.0.2.11' -Protocol Both -Profile $p
    Reject {Invoke-CcdcFirewallPlan -Plan $both -EvidenceDirectory $temp -Approved}
    $removed=@(& $module {$script:Removed})
    Assert ($removed.Count -eq 1) 'Partial multi-protocol failure must remove the first created rule'
    $records=@(Get-ChildItem $temp -Filter '*.json' | ForEach-Object {Get-Content $_.FullName -Raw | ConvertFrom-Json})
    Assert (@($records | Where-Object Status -eq 'Failed').Count -eq 1) 'Failed response must retain recovery evidence'
}finally{if(Test-Path $temp){Remove-Item $temp -Recurse -Force};Remove-Module Firewall}
Write-Host 'PASS: service presets, scoped rules, protected ports/addresses, explicit approval, undo ownership and WhatIf'
