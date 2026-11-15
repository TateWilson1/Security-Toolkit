#requires -Version 5.1
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '..\Monitoring.psm1') -Force
$p=Read-CcdcProfile (Join-Path $PSScriptRoot '..\profile.default.json')
function Assert($Value,$Message){if(-not $Value){throw $Message}}
function New-State($Processes,$Persistence,$Sensors){
    [pscustomobject]@{Processes=@($Processes);ProcessesAvailable=$true;Connections=@();ConnectionsAvailable=$true
        Persistence=@($Persistence);PersistenceAvailable=$true;Sensors=$Sensors;Health=@()}
}
$parent=[pscustomobject]@{Lifetime='50|a';Created='2026-11-14T18:00:00Z';ProcessId='50';ParentProcessId='4';Image='C:\SQL\sqlservr.exe';CommandLine='sqlservr';User='NT AUTHORITY\SYSTEM'}
$child=[pscustomobject]@{Lifetime='51|b';Created='2026-11-14T18:00:01Z';ProcessId='51';ParentProcessId='50';Image='C:\Windows\cmd.exe';CommandLine='cmd /c echo test';User='NT AUTHORITY\SYSTEM'}
$old=New-State @($parent) @([pscustomobject]@{Key='Task|Lab';Value='approved.exe'}) ([pscustomobject]@{SysmonService='Running'})
$now=New-State @($parent,$child) @([pscustomobject]@{Key='Task|Lab';Value='changed.exe'}) ([pscustomobject]@{SysmonService='Stopped'})
$rows=@(Compare-CcdcDirectState $now $old $p)
$proc=@($rows | Where-Object Kind -eq 'PROCESS')
Assert ($proc.Count -eq 1 -and $proc[0].Severity -eq 'HIGH') 'SYSTEM-owned SQL shell must alert without any Event Log records'
Assert ($proc[0].ParentProcessGuid -eq 'snapshot|50|a') 'Snapshot ancestry must preserve lifetime'
Assert (@($rows | Where-Object Kind -eq 'PERSISTENCE').Count -eq 1) 'Task persistence change missing without logs'
Assert (@($rows | Where-Object {$_.Kind -eq 'SENSOR' -and $_.Severity -eq 'HIGH'}).Count -eq 1) 'Sensor downgrade missing'
$newParent=$parent.PSObject.Copy();$newParent.Created='2026-11-14T18:00:05Z';$newParent.Lifetime='50|reused'
$reuse=New-State @($newParent,$child) @() ([pscustomobject]@{SysmonService='Running'})
$r=@(Compare-CcdcDirectState $reuse $null $p | Where-Object ProcessId -eq '51')[0]
Assert (-not $r.ParentProcessGuid) 'PID reuse must not create false snapshot ancestry'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ccdc-direct-'+[guid]::NewGuid().ToString('N'))
try{
    $null=Receive-CcdcDirectState $temp $p $old
    $null=Receive-CcdcDirectState $temp $p $now
    Assert (@(Get-CcdcHistory $temp | Where-Object Kind -eq 'SENSOR').Count -eq 1) 'Independent observations not persisted'
    $failed=New-State @() @() ([pscustomobject]@{SysmonService='Stopped'})
    $failed.ProcessesAvailable=$false;$failed.PersistenceAvailable=$false
    $rows=@(Receive-CcdcDirectState $temp $p $failed)
    Assert (@($rows | Where-Object Kind -in @('EXIT','PERSISTENCE')).Count -eq 0) 'Query failure invented state changes'
    $saved=Get-Content (Join-Path $temp 'direct-state.json') -Raw | ConvertFrom-Json
    Assert ($saved.Processes.Count -eq 2 -and $saved.Persistence.Count -eq 1) 'Failed query replaced last good baseline'
}finally{if(Test-Path $temp){Remove-Item $temp -Recurse -Force}}
Write-Host 'PASS: SYSTEM behavior, independent persistence, sensor changes, PID reuse, durable direct observations, failed-query safety'
