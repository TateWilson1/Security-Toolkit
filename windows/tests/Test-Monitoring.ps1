#requires -Version 5.1
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '..\Monitoring.psm1') -Force
$profile=Read-CcdcProfile (Join-Path $PSScriptRoot '..\profile.default.json')
function Assert($Condition,[string]$Message) { if(-not $Condition){throw $Message} }
function New-Xml([int]$Id,[string]$Channel,[long]$RecordId,[hashtable]$Data) {
    $items=foreach($key in $Data.Keys){'<Data Name="'+$key+'">'+[Security.SecurityElement]::Escape([string]$Data[$key])+'</Data>'}
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="test"/><EventID>'+$Id+'</EventID><TimeCreated SystemTime="2026-11-14T18:00:01.1234567Z"/><EventRecordID>'+$RecordId+'</EventRecordID><Channel>'+$Channel+'</Channel><Computer>LAB</Computer></System><EventData>'+($items -join '')+'</EventData></Event>'
}
$sysmon='Microsoft-Windows-Sysmon/Operational'
$x=New-Xml 1 $sysmon 1 @{Image='C:\Windows\System32\cmd.exe';ParentImage='C:\Windows\System32\wsmprovhost.exe';CommandLine='cmd /c echo <safe> & exit';ProcessId='123';ProcessGuid='{child}';ParentProcessGuid='{parent}';ParentProcessId='50';User='LAB\scorer'}
$r=ConvertTo-CcdcEvent $x $profile
Assert ($r.Severity -eq 'REVIEW') 'WinRM must be a review lead, not confirmed malicious'
Assert ($r.CommandLine -eq 'cmd /c echo <safe> & exit') 'XML escaping lost command content'
Assert ($r.ProcessGuid -eq '{child}' -and $r.ParentProcessGuid -eq '{parent}' -and $r.ProcessId -eq '123') 'Process lifetime/ancestry lost'
Assert ($r.Time -eq '2026-11-14T18:00:01.1234567+00:00') 'Timestamp precision/UTC lost'
$x=New-Xml 1 $sysmon 2 @{Image='C:\Windows\cmd.exe';ParentImage='C:\SQL\sqlservr.exe';CommandLine='cmd -encodedcommand test'}
$r=ConvertTo-CcdcEvent $x $profile
Assert ($r.Severity -eq 'HIGH') 'Later review rule must never downgrade HIGH'
$r=ConvertTo-CcdcEvent (New-Xml 3 $sysmon 3 @{SourceIp='::1';SourcePort='50000';DestinationIp='::1';DestinationPort='1433';Protocol='tcp';ProcessId='42'}) $profile
Assert ($r.Kind -eq 'CONNECTION' -and $r.SourcePort -eq '50000' -and $r.DestinationIp -eq '::1') 'Network endpoints lost'
$r=ConvertTo-CcdcEvent (New-Xml 4688 'Security' 4 @{NewProcessName='C:\Windows\cmd.exe';NewProcessId='0x7b';ProcessId='0x32';CommandLine='cmd /c exit'}) $profile
Assert ($r.ProcessId -eq '0x7b' -and $r.ParentProcessId -eq '0x32') 'Security PID must use NewProcessId'
$r=ConvertTo-CcdcEvent (New-Xml 4104 'Microsoft-Windows-PowerShell/Operational' 5 @{ScriptBlockText='Write-Output benign';MessageNumber='1';MessageTotal='2'}) $profile
Assert ($r.Severity -eq 'INFO' -and $r.Data.MessageTotal -eq '2') 'Benign script blocks must retain fragment metadata without blanket alert'
$profile.KnownManagementAddresses=@('192.0.2.1')
$r=ConvertTo-CcdcEvent (New-Xml 4624 'Security' 6 @{TargetUserName='scorer';LogonType='3';IpAddress='192.0.2.1'}) $profile
Assert ($r.Severity -eq 'INFO') 'Known management authentication should remain informational'
$systemXml=(New-Xml 7045 'System' 7 @{ServiceName='lab-service';ImagePath='C:\Lab\service.exe'}).Replace('<EventID>7045</EventID>','<EventID Qualifiers="16384">7045</EventID>')
$r=ConvertTo-CcdcEvent $systemXml $profile
Assert ($r.EventId -eq 7045 -and $r.Kind -eq 'PERSISTENCE') 'Qualified System event ID parsing failed'
$emptyXml=New-Xml 4104 'Microsoft-Windows-PowerShell/Operational' 8 @{ScriptBlockText='';Path='';ScriptBlockId='{test}'}
$r=ConvertTo-CcdcEvent $emptyXml $profile
Assert ($r.Data.Path -eq '' -and $r.Kind -eq 'POWERSHELL') 'Empty EventData fields must not poison a channel batch'
$clearXml='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1102</EventID><TimeCreated SystemTime="2026-11-14T18:00:01Z"/><EventRecordID>9</EventRecordID><Channel>Security</Channel><Computer>LAB</Computer></System><UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectUserName>lab-admin</SubjectUserName></LogFileCleared></UserData></Event>'
$r=ConvertTo-CcdcEvent $clearXml $profile
Assert ($r.Data.SubjectUserName -eq 'lab-admin' -and $r.Severity -eq 'REVIEW') 'UserData-only records must not poison a channel batch'
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ccdc-tests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $temp
try {
    # Module-scoped fakes exercise the actual collector, not a duplicate implementation.
    $module=Get-Module Monitoring
    & $module {
        function script:Get-WinEvent { param($ListLog,$ErrorAction) [pscustomobject]@{IsEnabled=$true} }
        function script:Get-CcdcSources { @{Log='Test';Ids=@(1)} }
        function script:Read-CcdcXmlBatch {
            param($Log,$XPath='*',$Limit=250,[switch]$Newest)
            if ($script:FailRead) { throw 'simulated source failure' }
            $last=0;if($XPath -match 'EventRecordID > (\d+)'){$last=[long]$Matches[1]}
            $items=@($script:Fixture | Where-Object {[xml]$x=$_;[long]$x.Event.System.EventRecordID -gt $last})
            if($Newest){[array]::Reverse($items)}
            $items | Select-Object -First $Limit
        }
    }
    $fixtures=@(1..601 | ForEach-Object {New-Xml 1 'Test' $_ @{Image='test.exe'}})
    & $module {param($f) $script:Fixture=$f;$script:FailRead=$false} $fixtures
    $a=Receive-CcdcBatch $temp $profile
    $b=Receive-CcdcBatch $temp $profile
    $c=Receive-CcdcBatch $temp $profile
    Assert ($a.Records.Count -eq 250 -and $a.Records[0].RecordId -eq 1 -and $b.Records[0].RecordId -eq 251 -and $c.Records[-1].RecordId -eq 601) 'Burst must drain oldest-first without gaps'
    $d=Receive-CcdcBatch $temp $profile
    Assert ($d.Records.Count -eq 0) 'Checkpoint failed to suppress duplicate polling'
    $history=@(Get-CcdcHistory $temp 1000)
    Assert ($history.Count -eq 601) 'Durable history must retain short-lived activity'
    Assert (@(Get-CcdcHistory -DataDirectory $temp -Query 'test.exe').Count -eq 601) 'Archive search failed'
    Assert (@(Get-CcdcHistory $temp 10).Count -eq 10) 'History memory bound failed'
    & $module {$script:FailRead=$true}
    $errorBatch=Receive-CcdcBatch $temp $profile
    Assert ($errorBatch.Health[0] -match 'ERROR.*simulated source failure') 'Source errors hidden'
    $state=Get-Content (Join-Path $temp 'checkpoints.json') -Raw | ConvertFrom-Json
    Assert ($state.Test -eq 601) 'Source failure advanced checkpoint'
    & $module {$script:FailRead=$false;$script:Fixture=@($script:Fixture[0])}
    $reset=Receive-CcdcBatch $temp $profile
    Assert (($reset.Health -join '') -match 'RESET' -and $reset.Records.Count -eq 1) 'Log reset must be explicit and replay retained events'
    # Failed journal append must never advance cursor.
    Remove-Item (Join-Path $temp 'checkpoints.json')
    $journal=Get-ChildItem $temp -Filter 'events-*.jsonl' | Select-Object -First 1
    $held=[IO.File]::Open($journal.FullName,'Open','ReadWrite','None')
    try {$failed=Receive-CcdcBatch $temp $profile;Assert (($failed.Health -join '') -match 'ERROR') 'Journal write failure hidden'} finally {$held.Dispose()}
    $state=Get-Content (Join-Path $temp 'checkpoints.json') -Raw | ConvertFrom-Json
    Assert (-not ($state.PSObject.Properties.Name -contains 'Test')) 'Failed journal write advanced checkpoint'
    # Invalid custom rules fail early rather than disabling all alerting silently.
    $bad=Join-Path $temp 'invalid.json';$profile.Rules[0].Pattern='['
    $profile | ConvertTo-Json -Depth 8 | Set-Content $bad
    $rejected=$false;try{$null=Read-CcdcProfile $bad}catch{$rejected=$true}
    Assert $rejected 'Invalid profile accepted'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force;Remove-Module Monitoring }
Write-Host 'PASS: normalization, detections, timestamps, burst paging, checkpoint/restart, history, source/reset/write failures, profile validation'
