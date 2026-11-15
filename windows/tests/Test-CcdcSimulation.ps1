#requires -Version 5.1
<#
Benign CCDC behavior rehearsal. Run ONLY on an explicitly disposable Windows Server
2019/2022 lab after installing the toolkit/Sysmon. No external targets, credential
access, log clearing, security-product disabling or scored-service changes.
All unique task/account/Run-value artifacts are removed in finally blocks.
#>
[CmdletBinding()]
param(
    [switch]$AllowLabChanges,
    [string]$ToolkitDirectory=(Split-Path $PSScriptRoot -Parent),
    [string]$ProfilePath=(Join-Path (Split-Path $PSScriptRoot -Parent) 'profile.default.json'),
    [string]$ResultsDirectory=(Join-Path $PSScriptRoot 'results\simulation'),
    [switch]$SkipExistingWinRM
)
$ErrorActionPreference='Stop'
if(-not $AllowLabChanges){throw 'Requires -AllowLabChanges in a disposable isolated Windows Server lab.'}
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use 64-bit Windows PowerShell 5.1 on Windows Server.'}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run as Administrator in the disposable lab.'}
$os=Get-CimInstance Win32_OperatingSystem
if($os.ProductType -eq 1 -or [int]$os.BuildNumber -notin @(17763,20348)){throw 'Supported lab OS: Windows Server 2019/2022.'}
Import-Module (Join-Path $ToolkitDirectory 'Monitoring.psm1') -Force
$profile=Read-CcdcProfile $ProfilePath
$null=New-Item -ItemType Directory -Path $ResultsDirectory -Force
$ResultsDirectory=(Resolve-Path $ResultsDirectory).Path
$started=Get-Date
$marker='CCDC-SIM-'+[guid]::NewGuid().ToString('N')
$taskName=$marker
$runName=$marker
$userName='ccsim'+[guid]::NewGuid().ToString('N').Substring(0,12)
$runPath='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$taskCreated=$false;$runCreated=$false;$userCreated=$false
$results=New-Object 'System.Collections.Generic.List[object]'
$observations=New-Object 'System.Collections.Generic.List[object]'
$powerShellExe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
function Assert-Simulation($Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Test-SimulationStep([string]$Name,[scriptblock]$Body){
    try{
        $detail=& $Body
        $results.Add([pscustomobject]@{Test=$Name;Status='PASS';Detail=($detail | Out-String).Trim()})
    }catch{
        $results.Add([pscustomobject]@{Test=$Name;Status='FAIL';Detail=$_.Exception.Message})
        Write-Warning "$Name : $($_.Exception.Message)"
    }
}
function Wait-SysmonObservation([int[]]$Ids,[scriptblock]$Predicate){
    $until=(Get-Date).AddSeconds(15)
    do{
        $events=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=$Ids;StartTime=$started} -MaxEvents 5000 -ErrorAction SilentlyContinue)
        if($events.Count -eq 5000){throw 'Simulation query reached 5000 records; retain EVTX and narrow the isolated test window.'}
        $rows=@($events | ForEach-Object {ConvertTo-CcdcEvent -Xml $_.ToXml() -Profile $profile} | Where-Object $Predicate)
        if($rows.Count){foreach($row in $rows){$observations.Add($row)};return $rows}
        Start-Sleep -Milliseconds 500
    }while((Get-Date) -lt $until)
    return @()
}
try{
    Test-SimulationStep 'Short-lived encoded PowerShell (harmless output only)' {
        $body="Write-Output '$marker-encoded'"
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
        $process=Start-Process $powerShellExe -ArgumentList ('-NoProfile -NonInteractive -EncodedCommand '+$encoded) -PassThru -Wait
        Assert-Simulation ($process.ExitCode -eq 0) 'Benign encoded PowerShell did not complete.'
        $rows=@(Wait-SysmonObservation @(1) { $_.CommandLine -like "*$encoded*" })
        Assert-Simulation ($rows.Count -gt 0) 'Short-lived encoded PowerShell absent from Sysmon history.'
        Assert-Simulation (@($rows | Where-Object Severity -in @('REVIEW','HIGH')).Count -gt 0) 'Encoded execution was recorded but did not generate a review lead.'
        $expectedReason=($profile.Rules | Where-Object Id -eq 'script-pattern').Description
        Assert-Simulation (@($rows | Where-Object {$expectedReason -in $_.Reasons}).Count -gt 0) 'Encoded-command-specific rule did not match; a generic shell alert is insufficient.'
        'Observed a completed short-lived process and a behavior alert; no payload beyond Write-Output.'
    }
    Test-SimulationStep 'Actual PowerShell script-block content, benign content remains informational' {
        $until=(Get-Date).AddSeconds(15);$rows=@()
        do{
            $events=@(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104;StartTime=$started} -MaxEvents 5000 -ErrorAction SilentlyContinue)
            $rows=@($events | ForEach-Object {ConvertTo-CcdcEvent -Xml $_.ToXml() -Profile $profile} | Where-Object CommandLine -like "*$marker-encoded*")
            if($rows.Count){break};Start-Sleep -Milliseconds 500
        }while((Get-Date) -lt $until)
        Assert-Simulation ($rows.Count -gt 0) 'Decoded benign script content was not recorded in 4104; do not claim script visibility.'
        Assert-Simulation (@($rows | Where-Object Severity -eq 'INFO').Count -gt 0) 'Harmless Write-Output script block was not informational under the default profile.'
        foreach($row in $rows){$observations.Add($row)}
        'Process command-line encoding alerts, while the observed benign decoded script itself remains informational.'
    }
    Test-SimulationStep 'WMI-created short CMD and real WmiPrvSE ancestry' {
        $command='cmd.exe /c echo '+$marker+'-wmi'
        $created=Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine=$command}
        Assert-Simulation ($created.ReturnValue -eq 0) ('Local WMI Create returned '+$created.ReturnValue)
        $expectedId=[string]$created.ProcessId
        $rows=@(Wait-SysmonObservation @(1) { $_.ProcessId -eq $expectedId -and $_.CommandLine -like "*$marker-wmi*" })
        Assert-Simulation ($rows.Count -gt 0) 'WMI-created short process absent from history.'
        Assert-Simulation (@($rows | Where-Object ParentImage -like '*\WmiPrvSE.exe').Count -gt 0) 'Expected real WmiPrvSE ancestry was not observed; do not claim WMI coverage.'
        Assert-Simulation (@($rows | Where-Object Severity -in @('REVIEW','HIGH')).Count -gt 0) 'WMI ancestry generated no review lead.'
        $expectedReason=($profile.Rules | Where-Object Id -eq 'remote-parent').Description
        Assert-Simulation (@($rows | Where-Object {$expectedReason -in $_.Reasons}).Count -gt 0) 'Remote/WMI ancestry rule did not match; a generic shell alert is insufficient.'
        'Used local CIM only. This is not remote WMI or credential-compromise testing.'
    }
    Test-SimulationStep 'SYSTEM scheduled task behavior and direct persistence difference' {
        $before=Get-CcdcDirectState -IncludePersistence
        Assert-Simulation $before.PersistenceAvailable ('Persistence source unavailable: '+($before.Health -join '; '))
        $signal=Join-Path $ResultsDirectory 'system-task-marker.txt'
        $escapedSignal=$signal.Replace("'","''")
        $body="[IO.File]::WriteAllText('$escapedSignal','$marker-system'); Start-Sleep -Seconds 3"
        $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
        $action=New-ScheduledTaskAction -Execute $powerShellExe -Argument ('-NoProfile -NonInteractive -EncodedCommand '+$encoded)
        $taskPrincipal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Assert-Simulation (-not(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) 'Unique task name unexpectedly exists.'
        $null=Register-ScheduledTask -TaskName $taskName -Action $action -Principal $taskPrincipal -Description 'Disposable CCDC benign behavior rehearsal'
        $script:taskCreated=$true
        $after=Get-CcdcDirectState -IncludePersistence
        Assert-Simulation $after.PersistenceAvailable ('Persistence source unavailable: '+($after.Health -join '; '))
        $changes=@(Compare-CcdcDirectState $after $before $profile)
        $taskChanges=@($changes | Where-Object {$_.Kind -eq 'PERSISTENCE' -and $_.Data.Object -like "*$taskName*"})
        Assert-Simulation ($taskChanges.Count -gt 0) 'Direct snapshot did not flag task addition.'
        foreach($row in $taskChanges){$observations.Add($row)}
        Start-ScheduledTask -TaskName $taskName
        $rows=@(Wait-SysmonObservation @(1) { $_.CommandLine -like "*$encoded*" })
        Assert-Simulation (@($rows | Where-Object {$_.User -match '(?i)(^|\\)SYSTEM$' -and $_.Severity -in @('REVIEW','HIGH')}).Count -gt 0) 'SYSTEM-owned encoded PowerShell was not flagged.'
        $until=(Get-Date).AddSeconds(10)
        while(-not(Test-Path $signal) -and (Get-Date) -lt $until){Start-Sleep -Milliseconds 250}
        Assert-Simulation (Test-Path $signal) 'The harmless SYSTEM task did not write its own marker.'
        'A real SYSTEM-owned process remained alertable; no privileged group or security-policy change was made.'
    }
    Test-SimulationStep 'Run-key persistence (inert value), first-baseline comparison and event telemetry' {
        $testProfile=Get-Content $ProfilePath -Raw | ConvertFrom-Json
        $testProfile | Add-Member -NotePropertyName RegistryPaths -NotePropertyValue @($runPath) -Force
        $data=Join-Path $ResultsDirectory 'registry-state'
        $before=@(Get-CcdcRegistryScopes $testProfile)
        Assert-Simulation (@($before | Where-Object {-not $_.Available}).Count -eq 0) 'Run key baseline unavailable.'
        $null=Receive-CcdcBaselineScopes $data $testProfile $before
        $key=Get-Item -LiteralPath $runPath -ErrorAction Stop
        Assert-Simulation ($key.GetValueNames() -notcontains $runName) 'Unique Run value unexpectedly exists.'
        # Points to a nonexistent unique lab file. No logoff/logon or execution occurs.
        $neverRun=Join-Path $ResultsDirectory ($marker+'-NEVER-EXECUTE.exe')
        $null=New-ItemProperty -LiteralPath $runPath -Name $runName -Value ('"'+$neverRun+'"') -PropertyType String
        $script:runCreated=$true
        $result=Receive-CcdcBaselineScopes $data $testProfile @(Get-CcdcRegistryScopes $testProfile)
        $changes=@($result.Records | Where-Object {$_.Kind -eq 'REGISTRY' -and $_.Data.Object -like "*$runName*" -and $_.Severity -eq 'REVIEW'})
        Assert-Simulation ($changes.Count -gt 0) 'Run-key change was not detected without relying on Event Logs.'
        foreach($row in $changes){$observations.Add($row)}
        $events=@(Wait-SysmonObservation @(12,13,14) { $_.Data.TargetObject -like "*$runName*" })
        'Direct registry alert confirmed; matching Sysmon registry records: '+$events.Count+'. Registry sampling was invoked immediately rather than waiting 15 minutes.'
    }
    Test-SimulationStep 'New disabled local user (no privileges), direct account comparison' {
        if((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4){throw 'Local-user scenario requires a standalone/member lab, not a domain controller.'}
        $data=Join-Path $ResultsDirectory 'account-state'
        $before=@(Get-CcdcAccountScopes)
        Assert-Simulation (@($before | Where-Object {-not $_.Available}).Count -eq 0) 'Account baseline unavailable.'
        $null=Receive-CcdcBaselineScopes $data $profile $before
        Assert-Simulation (-not(Get-LocalUser -Name $userName -ErrorAction SilentlyContinue)) 'Unique user name unexpectedly exists.'
        $password=ConvertTo-SecureString ([guid]::NewGuid().ToString('N')+'aA!9') -AsPlainText -Force
        $null=New-LocalUser -Name $userName -Password $password -Disabled -Description 'Disposable CCDC simulation; never enabled or privileged'
        $script:userCreated=$true
        $result=Receive-CcdcBaselineScopes $data $profile @(Get-CcdcAccountScopes)
        $changes=@($result.Records | Where-Object {$_.Kind -eq 'ACCOUNT' -and $_.User -eq $userName -and $_.Severity -eq 'REVIEW'})
        Assert-Simulation ($changes.Count -gt 0) 'New disabled/service-style account not detected through direct comparison.'
        foreach($row in $changes){$observations.Add($row)}
        'New account detected without Event 4720; the account was never enabled, authenticated or added to a privileged group.'
    }
    Test-SimulationStep 'Localhost PowerShell TCP observation' {
        $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
        $listener.Start();$client=$null;$server=$null
        try{
            $port=$listener.LocalEndpoint.Port
            $client=New-Object Net.Sockets.TcpClient
            $client.Connect('127.0.0.1',$port);$server=$listener.AcceptTcpClient()
            $snapshot=Get-CcdcDirectState
            Assert-Simulation $snapshot.ConnectionsAvailable 'Direct TCP source unavailable.'
            $rows=@(Compare-CcdcDirectState $snapshot $null $profile | Where-Object {$_.Kind -eq 'CONNECTION' -and ($_.DestinationPort -eq [string]$port -or $_.SourcePort -eq [string]$port)})
            Assert-Simulation ($rows.Count -gt 0) 'Live localhost socket was not observed.'
            Assert-Simulation (@($rows | Where-Object Severity -in @('REVIEW','HIGH')).Count -gt 0) 'PowerShell network observation generated no review lead.'
            foreach($row in $rows){$observations.Add($row)}
            'Held a local socket only; this does not prove capture of every short-lived connection.'
        }finally{if($server){$server.Dispose()};if($client){$client.Dispose()};$listener.Stop()}
    }
    if($SkipExistingWinRM -or -not(Get-Service WinRM -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')){
        $results.Add([pscustomobject]@{Test='Existing localhost WinRM administration';Status='BLOCKED';Detail='WinRM absent/stopped or explicitly skipped. No listener, authentication policy, TrustedHosts or service state was changed.'})
    }else{
        $remoteRan=$false
        try{
            $options=New-PSSessionOption -OpenTimeout 5000 -OperationTimeout 10000
            $null=Invoke-Command -ComputerName localhost -SessionOption $options -ScriptBlock {param($m) cmd.exe /c echo $m} -ArgumentList ($marker+'-winrm') -ErrorAction Stop
            $remoteRan=$true
        }catch{
            $results.Add([pscustomobject]@{Test='Existing localhost WinRM administration';Status='BLOCKED';Detail=('Existing WinRM could not be exercised: '+$_.Exception.Message+'. No remoting settings were changed.')})
        }
        if($remoteRan){
            Test-SimulationStep 'Existing localhost WinRM administration' {
                $rows=@(Wait-SysmonObservation @(1) { $_.CommandLine -like "*$marker-winrm*" })
                Assert-Simulation (@($rows | Where-Object ParentImage -like '*\wsmprovhost.exe').Count -gt 0) 'wsmprovhost child was not recorded.'
                Assert-Simulation (@($rows | Where-Object Severity -eq 'REVIEW').Count -gt 0) 'Expected review-level remote administration lead missing.'
                Assert-Simulation (@($rows | Where-Object Severity -eq 'HIGH').Count -eq 0) 'Ordinary WinRM test was incorrectly elevated to HIGH by default rules.'
                'Existing local WinRM ran a harmless command; this is not Evil-WinRM client attribution or a domain/scorer authentication test.'
            }
        }
    }
}finally{
    $cleanupErrors=@()
    if($taskCreated){try{Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue;Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop}catch{$cleanupErrors+=$_.Exception.Message}}
    if($runCreated){try{Remove-ItemProperty -LiteralPath $runPath -Name $runName -ErrorAction Stop}catch{$cleanupErrors+=$_.Exception.Message}}
    if($userCreated){try{Remove-LocalUser -Name $userName -ErrorAction Stop}catch{$cleanupErrors+=$_.Exception.Message}}
    if($cleanupErrors.Count){$results.Add([pscustomobject]@{Test='Cleanup';Status='FAIL';Detail=($cleanupErrors -join '; ')})}
    else{$results.Add([pscustomobject]@{Test='Cleanup';Status='PASS';Detail='Removed only the unique task, Run value and disabled account created by this harness.'})}
    $results | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $ResultsDirectory 'simulation-results.json') -Encoding UTF8
    $observations.ToArray() | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $ResultsDirectory 'simulation-observations.json') -Encoding UTF8
    [pscustomobject]@{Started=$started.ToUniversalTime().ToString('o');Finished=[datetimeoffset]::UtcNow.ToString('o');Marker=$marker;OS=$os.Caption
        Limitations=@('No remote Evil-WinRM client was run or attributed','No actual credential compromise, exploitation, injection, evasion or malicious payload','No domain-controller/scorer authentication coverage from a standalone runner','Manual invocation checks registry/account comparisons, not the actual 15-minute/60-second wall-clock interval')} |
        ConvertTo-Json -Depth 5 | Set-Content (Join-Path $ResultsDirectory 'simulation-context.json') -Encoding UTF8
    $results | Format-Table Test,Status -AutoSize
}
if(@($results | Where-Object Status -eq 'FAIL').Count){throw 'CCDC simulation failures; inspect simulation-results.json and observations.'}
