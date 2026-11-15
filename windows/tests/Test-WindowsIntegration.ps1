#requires -Version 5.1
# ONLY an explicitly disposable lab/hosted runner. Never run on competition infrastructure.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Revision,[switch]$AllowLabChanges,[string]$ResultsDirectory=(Join-Path $PSScriptRoot 'results'))
$ErrorActionPreference='Stop'
if(-not $AllowLabChanges){throw 'Requires -AllowLabChanges in a disposable Windows Server VM. Installs Sysmon and enables auditing.'}
$null=New-Item -ItemType Directory -Path $ResultsDirectory -Force
$ResultsDirectory=(Resolve-Path $ResultsDirectory).Path
$results=New-Object 'System.Collections.Generic.List[object]'
function Test-Step([string]$Name,[scriptblock]$Body) {
    try { $detail=& $Body; $results.Add([pscustomobject]@{Test=$Name;Status='PASS';Detail=($detail | Out-String)}) }
    catch { $results.Add([pscustomobject]@{Test=$Name;Status='FAIL';Detail=$_.Exception.Message});Write-Warning "$Name : $_" }
}
$root=Join-Path $env:ProgramData 'CCDC-BlueTeam'
$start=[datetime]::UtcNow
$marker='CCDC-LAB-'+[guid]::NewGuid().ToString('N')
try {
    Test-Step 'GUI with missing Sysmon (before installation)' {
        if(@(Get-Service Sysmon,Sysmon64 -ErrorAction SilentlyContinue).Count){throw 'Preinstalled Sysmon: missing-source test requires a fresh lab'}
        $report=Join-Path $ResultsDirectory 'missing-sysmon-gui.json'
        $gui=Join-Path $PSScriptRoot '..\Dashboard.ps1'
        $scratch=Join-Path $ResultsDirectory 'missing-source-telemetry'
        $process=Start-Process powershell.exe -ArgumentList ('-NoProfile -STA -ExecutionPolicy Bypass -File "'+$gui+'" -DataDirectory "'+$scratch+'" -SmokeTestReport "'+$report+'"') -PassThru -RedirectStandardError (Join-Path $ResultsDirectory 'missing-sysmon-errors.txt')
        if(-not $process.WaitForExit(60000)){Stop-Process -Id $process.Id;throw 'Missing-source GUI timed out'}
        if(-not(Test-Path $report)){throw 'Missing-source GUI produced no report'}
        $state=Get-Content $report -Raw | ConvertFrom-Json
        if(-not @($state.Health | Where-Object {$_ -match 'Sysmon.*UNAVAILABLE/ERROR'}).Count){throw 'Missing Sysmon not reported'}
    }
    Test-Step 'Clean installation' {
        if(Test-Path $root){throw 'Not a clean lab: installation directory already exists. Refusing to remove it.'}
        & (Join-Path $PSScriptRoot '..\Install.ps1') -Revision $Revision -NoLaunch
        if(-not (Test-Path (Join-Path $root 'current-version.txt'))){throw 'Activation missing'}
    }
    $installed=(Get-Content (Join-Path $root 'current-version.txt') -Raw).Trim()
    $evidence=Join-Path $root 'Evidence'
    $sentinel=Join-Path $evidence 'reinstall-sentinel.txt';$marker | Set-Content $sentinel
    Test-Step 'Second installation preserves evidence and profile' {
        $before=(Get-FileHash (Join-Path $root 'profile.json')).Hash
        & (Join-Path $PSScriptRoot '..\Install.ps1') -Revision $Revision -NoLaunch
        if((Get-Content $sentinel) -ne $marker){throw 'Evidence lost'}
        if((Get-FileHash (Join-Path $root 'profile.json')).Hash -ne $before){throw 'Profile changed'}
    }
    $installed=(Get-Content (Join-Path $root 'current-version.txt') -Raw).Trim()
    Import-Module (Join-Path $installed 'Monitoring.psm1') -Force
    $profile=Read-CcdcProfile (Join-Path $root 'profile.json')
    $data=Join-Path $evidence 'Telemetry'
    Test-Step 'Sysmon service and process rules' {
        if(-not (Get-Service Sysmon64 -ErrorAction Stop | Where-Object Status -eq 'Running')){throw 'Sysmon not running'}
        $global:labParent=Start-Process powershell.exe -ArgumentList ('-NoProfile -Command "cmd /c echo '+$marker+'; Start-Sleep -Seconds 1"') -PassThru -Wait
        Start-Process cmd.exe -ArgumentList ('/c echo '+$marker+'-short') -Wait
        Start-Sleep -Seconds 4
        $global:labEvents=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1;StartTime=$start.ToLocalTime()} | ForEach-Object {ConvertTo-CcdcEvent $_.ToXml() $profile})
        if(-not @($labEvents | Where-Object CommandLine -like "*$marker*").Count){throw 'Test process not captured'}
    }
    Test-Step 'Short CMD, ancestry/command/time and benign severity' {
        $children=@($labEvents | Where-Object {$_.Image -like '*\cmd.exe' -and $_.CommandLine -like "*$marker*"})
        if(-not $children.Count){throw 'Short-lived CMD missing'}
        if(-not @($children | Where-Object ParentProcessGuid).Count){throw 'Ancestry missing'}
        $parents=@($labEvents | Where-Object {$_.Image -like '*\powershell.exe' -and $_.CommandLine -like "*$marker*"})
        if(-not @($children | Where-Object {$_.ParentProcessGuid -in $parents.ProcessGuid}).Count){throw 'CMD was not linked to the recorded PowerShell parent GUID'}
        if(@($labEvents | Where-Object {$_.CommandLine -like "*$marker*" -and $_.Severity -ne 'INFO'}).Count){throw 'Benign process creation was incorrectly alerted'}
        foreach($r in $children){if([datetimeoffset]::Parse($r.Time).UtcDateTime -lt $start){throw 'Timestamp predates test'}}
    }
    Test-Step 'Process termination events' {
        $exits=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=5;StartTime=$start.ToLocalTime()})
        if(-not $exits.Count){throw 'No exit records'}
    }
    Test-Step 'Localhost TCP snapshot and short connection probe' {
        $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0);$listener.Start()
        try {
            $port=$listener.LocalEndpoint.Port
            $client=New-Object Net.Sockets.TcpClient
            try {
                $client.Connect('127.0.0.1',$port);$server=$listener.AcceptTcpClient()
                try {if(-not @(Get-NetTCPConnection -LocalPort $port -State Established).Count){throw 'Live socket missing'}} finally {$server.Dispose()}
            } finally {$client.Dispose()}
            $client=New-Object Net.Sockets.TcpClient
            try {$client.Connect('127.0.0.1',$port);$server=$listener.AcceptTcpClient();$server.Dispose()} finally {$client.Dispose()}
        } finally {$listener.Stop()}
        Start-Sleep -Seconds 4
        $network=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=3;StartTime=$start.ToLocalTime()} -ErrorAction SilentlyContinue | ForEach-Object {ConvertTo-CcdcEvent $_.ToXml() $profile} | Where-Object DestinationPort -eq ([string]$port))
        if(-not $network.Count){throw 'Localhost sockets worked, but Sysmon did not emit the short-connection event. Coverage limitation; investigate in lab.'}
        $network | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $ResultsDirectory 'network.json')
    }
    Test-Step 'Durable collection and restart' {
        1..12 | ForEach-Object {$null=Receive-CcdcBatch $data $profile}
        $history=@(Get-CcdcHistory $data 20000)
        if(-not @($history | Where-Object CommandLine -like "*$marker*").Count){throw 'Process absent from durable history'}
        Remove-Module Monitoring
        Import-Module (Join-Path $installed 'Monitoring.psm1')
        if(-not @(Get-CcdcHistory $data).Count){throw 'History missing after reload'}
    }
    Test-Step 'Direct native process, sockets and persistence (independent of Event Logs)' {
        $directData=Join-Path $ResultsDirectory 'direct-telemetry'
        $before=Get-CcdcDirectState -IncludePersistence
        if(-not $before.ProcessesAvailable -or -not $before.PersistenceAvailable -or -not $before.ConnectionsAvailable){throw ($before.Health -join '; ')}
        $null=Receive-CcdcDirectState $directData $profile $before
        $taskName='CCDC-Lab-'+[guid]::NewGuid().ToString('N')
        $heldProcess=$null
        try{
            $action=New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ('/c echo '+$marker)
            $null=Register-ScheduledTask -TaskName $taskName -Action $action -Description 'Disposable CCDC integration test; never executed'
            $heldProcess=Start-Process powershell.exe -ArgumentList ('-NoProfile -Command "Write-Output '+$marker+'-direct; Start-Sleep -Seconds 30"') -PassThru
            $after=Get-CcdcDirectState -IncludePersistence
            $rows=@(Receive-CcdcDirectState $directData $profile $after)
            if(-not @($rows | Where-Object {$_.Kind -eq 'PROCESS' -and $_.CommandLine -like "*$marker-direct*" -and $_.Severity -eq 'INFO'}).Count){throw 'Benign direct process must be recorded without an alert'}
            if(-not @($rows | Where-Object {$_.Kind -eq 'PERSISTENCE' -and $_.Data.Object -like "*$taskName*"}).Count){throw 'Direct task change missing'}
        }finally{
            if($heldProcess -and -not $heldProcess.HasExited){Stop-Process -Id $heldProcess.Id}
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
    Test-Step 'Registry baseline drift and newly-created local account (no Event Log dependency)' {
        $baselineData=Join-Path $ResultsDirectory 'baseline-telemetry'
        $keyPath='HKLM:\SOFTWARE\CCDC-Lab-'+[guid]::NewGuid().ToString('N')
        $userName='ccdc'+[guid]::NewGuid().ToString('N').Substring(0,12)
        try{
            $null=New-Item $keyPath
            $null=New-ItemProperty $keyPath -Name LabValue -Value 'initial' -PropertyType String
            $testProfile=Read-CcdcProfile (Join-Path $root 'profile.json')
            $testProfile | Add-Member -NotePropertyName RegistryPaths -NotePropertyValue @($keyPath) -Force
            $null=Receive-CcdcBaselineScopes $baselineData $testProfile @(Get-CcdcRegistryScopes $testProfile)
            Set-ItemProperty $keyPath -Name LabValue -Value 'changed'
            $registryResult=Receive-CcdcBaselineScopes $baselineData $testProfile @(Get-CcdcRegistryScopes $testProfile)
            if(-not @($registryResult.Records | Where-Object {$_.Kind -eq 'REGISTRY' -and $_.Data.Change -eq 'Changed'}).Count){throw 'Native registry drift missing'}
            $null=Receive-CcdcBaselineScopes $baselineData $testProfile @(Get-CcdcAccountScopes)
            # Create only a unique DISABLED lab user; no privilege assignment or authentication.
            $password=ConvertTo-SecureString ([guid]::NewGuid().ToString('N')+'aA!9') -AsPlainText -Force
            $null=New-LocalUser -Name $userName -Password $password -Disabled -Description 'Disposable CCDC integration test'
            $accountResult=Receive-CcdcBaselineScopes $baselineData $testProfile @(Get-CcdcAccountScopes)
            if(-not @($accountResult.Records | Where-Object {$_.Kind -eq 'ACCOUNT' -and $_.Data.After -like "*$userName*"}).Count){throw 'Direct account addition missing'}
        }finally{
            Remove-Item -LiteralPath $keyPath -Recurse -Force -ErrorAction SilentlyContinue
            Remove-LocalUser -Name $userName -ErrorAction SilentlyContinue
        }
    }
    Test-Step 'Approved scoped firewall rule and undo (Windows NetSecurity)' {
        Import-Module (Join-Path $installed 'Firewall.psm1') -Force
        $plan=New-CcdcFirewallPlan -Action Block -Ports '65321' -RemoteAddress '192.0.2.123' -Protocol Both -Profile $profile
        $fwEvidence=Join-Path $ResultsDirectory 'firewall-evidence'
        $applied=$null;$outbound=$null
        try{
            $applied=Invoke-CcdcFirewallPlan -Plan $plan -EvidenceDirectory $fwEvidence -Approved
            if($applied.RuleNames.Count -ne 2){throw 'Expected TCP and UDP rules'}
            $outPlan=New-CcdcFirewallPlan -Action Block -Ports '65321' -RemoteAddress '192.0.2.123' -Protocol TCP -Direction Outbound -Profile $profile
            $outbound=Invoke-CcdcFirewallPlan -Plan $outPlan -EvidenceDirectory $fwEvidence -Approved
            $filter=Get-NetFirewallRule -Name $outbound.RuleNames[0] | Get-NetFirewallPortFilter
            if($filter.RemotePort -notcontains '65321'){throw 'Outbound destination port filter incorrect'}
            $status=Get-CcdcFirewallStatus
            foreach($name in $applied.RuleNames){if(-not @($status.Rules | Where-Object Name -eq $name).Count){throw 'Applied rule absent from status'}}
        }finally{
            if($outbound){foreach($name in $outbound.RuleNames){Undo-CcdcFirewallRule -Name $name -EvidenceDirectory $fwEvidence -Approved}}
            if($applied){foreach($name in $applied.RuleNames){Undo-CcdcFirewallRule -Name $name -EvidenceDirectory $fwEvidence -Approved}}
        }
        foreach($name in $applied.RuleNames){if(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue){throw 'Toolkit rule remains after undo'}}
    }
    Test-Step 'GUI startup, background collection, screenshot' {
        $report=Join-Path $ResultsDirectory 'gui.json'
        $process=Start-Process powershell.exe -ArgumentList ('-NoProfile -STA -ExecutionPolicy Bypass -File "'+(Join-Path $installed 'Dashboard.ps1')+'" -SmokeTestReport "'+$report+'"') -PassThru -RedirectStandardError (Join-Path $ResultsDirectory 'gui-errors.txt')
        if(-not $process.WaitForExit(60000)){Stop-Process -Id $process.Id;throw 'GUI test timed out'}
        if(-not (Test-Path $report)){throw 'GUI produced no report; inspect gui-errors.txt'}
        $gui=Get-Content $report -Raw | ConvertFrom-Json
        if($gui.HadCollectionError -or $gui.Batches -lt 1 -or $gui.Events -lt 1){throw 'GUI did not collect/replay events'}
        if(@($gui.Health | Where-Object {$_ -match 'ERROR|UNAVAILABLE'}).Count){throw ('GUI source failures: '+($gui.Health -join '; '))}
    }
    Test-Step 'Evidence EVTX and hashes' {
        & (Join-Path $installed 'CCDC-BlueTeam.ps1') -Mode Export -OutputDir $evidence
        if(-not @(Get-ChildItem $evidence -Recurse -Filter '*.evtx').Count){throw 'EVTX missing'}
    }
    Test-Step 'Defender status availability' {
        Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json | Set-Content (Join-Path $ResultsDirectory 'defender.json')
    }
    Test-Step 'Resource sample 30 seconds (not a soak test)' {
        $report=Join-Path $ResultsDirectory 'restart-gui.json'
        $process=Start-Process powershell.exe -ArgumentList ('-NoProfile -STA -ExecutionPolicy Bypass -File "'+(Join-Path $installed 'Dashboard.ps1')+'" -SmokeTestReport "'+$report+'"') -PassThru
        $samples=@(1..6 | ForEach-Object {Start-Sleep -Seconds 5;$process.Refresh();if(-not $process.HasExited){[pscustomobject]@{Time=[datetime]::UtcNow;WorkingSet=$process.WorkingSet64;CPUSeconds=$process.TotalProcessorTime.TotalSeconds;Handles=$process.HandleCount}}})
        $samples | ConvertTo-Json | Set-Content (Join-Path $ResultsDirectory 'resources.json')
        if(-not $samples.Count){throw 'No running GUI samples'}
        if(-not $process.HasExited){Stop-Process -Id $process.Id;throw 'Restart GUI did not finish its smoke test'}
        if(-not (Test-Path $report)){throw 'Restart GUI failed'}
    }
} finally {
    $results | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $ResultsDirectory 'results.json') -Encoding UTF8
    Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | ConvertTo-Json | Set-Content (Join-Path $ResultsDirectory 'os.json')
    if(Test-Path $root){Copy-Item (Join-Path $root 'install-*.log') $ResultsDirectory -ErrorAction SilentlyContinue}
    $results | Format-Table Test,Status -AutoSize
}
if(@($results | Where-Object Status -eq 'FAIL').Count){throw 'Integration failures; see results.json'}
