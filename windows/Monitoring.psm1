#requires -Version 5.1
# Shared, read-only telemetry engine. Windows APIs are called only by collection.
Set-StrictMode -Version 2
function Get-CcdcSources {
    @(
        @{Log='Microsoft-Windows-Sysmon/Operational'; Ids=@(1,3,4,5,12,13,14,16,19,20,21)}
        @{Log='Security'; Ids=@(1102,4624,4625,4672,4688,4689,4697,4698,4702,4720,4722,4725,4728,4732,4738,4740,4756)}
        @{Log='System'; Ids=@(7045)}
        @{Log='Microsoft-Windows-WinRM/Operational'; Ids=@()}
        @{Log='Microsoft-Windows-PowerShell/Operational'; Ids=@(4104)}
    )
}
function Read-CcdcProfile([string]$Path) {
    $p = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if ($p.SchemaVersion -ne 1) { throw 'Unsupported profile schema.' }
    foreach ($rule in $p.Rules) {
        if ($rule.Severity -notin @('INFO','REVIEW','HIGH')) { throw "Invalid severity: $($rule.Id)" }
        if ($rule.Field -notin @('Image','ParentImage','CommandLine','DestinationIp','DestinationPort','User','SourceIp')) { throw "Invalid rule field: $($rule.Id)" }
        # Compile with a timeout to reject malformed expressions and limit custom-rule work.
        $null = New-Object regex($rule.Pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase, [timespan]::FromMilliseconds(100))
    }
    return $p
}
function ConvertTo-CcdcEvent {
    param([string]$Xml, $Profile)
    [xml]$x = $Xml
    $s = $x.Event.System
    $d = @{}
    # Read DOM text directly: empty <Data/> has no '#text' property, and events
    # such as Security 1102 use UserData rather than EventData.
    foreach ($node in $x.DocumentElement.SelectNodes("*[local-name()='EventData']/*[local-name()='Data']")) {
        $name=$node.GetAttribute('Name')
        if ($name) { $d[$name]=$node.InnerText }
    }
    foreach ($node in $x.DocumentElement.SelectNodes("*[local-name()='UserData']//*[not(*)]")) {
        $d[$node.LocalName]=$node.InnerText
    }
    $id = if ($s.EventID -is [System.Xml.XmlElement]) { [int]$s.EventID.InnerText } else { [int]$s.EventID }
    $channel = [string]$s.Channel
    $kind='SECURITY'; $image=$d['Image']; $parent=$d['ParentImage']; $cmd=$d['CommandLine']; $user=$d['User']
    $processId=$d['ProcessId']; $parentId=$d['ParentProcessId']
    if ($channel -like '*Sysmon*') {
        $kind = switch ($id) { 1 {'PROCESS'} 3 {'CONNECTION'} 4 {'SENSOR'} 5 {'EXIT'} 16 {'SENSOR'} default {'PERSISTENCE'} }
    } elseif ($channel -like '*WinRM*') { $kind='REMOTE-MANAGEMENT' }
    elseif ($id -eq 4688) {
        $kind='PROCESS'; $image=$d['NewProcessName']; $parent=$d['ParentProcessName']
        $user=$d['SubjectUserName']; $processId=$d['NewProcessId']; $parentId=$d['ProcessId']
    } elseif ($id -eq 4689) { $kind='EXIT'; $image=$d['ProcessName']; $user=$d['SubjectUserName'] }
    elseif ($id -eq 4104) { $kind='POWERSHELL'; $cmd=$d['ScriptBlockText'] }
    elseif ($id -in @(4624,4625)) { $kind='AUTH'; $user=$d['TargetUserName'] }
    elseif ($id -in @(4697,4698,4702,7045)) { $kind='PERSISTENCE'; $user=$d['SubjectUserName'] }
    else { $user=$d['TargetUserName'] }
    $r = [pscustomobject][ordered]@{
        Key=($channel+'|'+[string]$s.EventRecordID+'|'+[string]$s.TimeCreated.SystemTime)
        Time=([datetimeoffset]::Parse([string]$s.TimeCreated.SystemTime).ToUniversalTime().ToString('o'))
        Host=[string]$s.Computer; Channel=$channel; EventId=$id; RecordId=[long]$s.EventRecordID
        Kind=$kind; Severity='INFO'; Reasons=@(); Image=[string]$image; ParentImage=[string]$parent
        ProcessId=[string]$processId; ParentProcessId=[string]$parentId
        ProcessGuid=[string]$d['ProcessGuid']; ParentProcessGuid=[string]$d['ParentProcessGuid']
        CommandLine=[string]$cmd; User=[string]$user
        SourceIp=[string]$(if ($d['SourceIp']) {$d['SourceIp']} else {$d['IpAddress']})
        SourcePort=[string]$d['SourcePort']; DestinationIp=[string]$d['DestinationIp']
        DestinationPort=[string]$d['DestinationPort']; Protocol=[string]$d['Protocol']
        ExecutionProcessId=$(if($s.SelectSingleNode("*[local-name()='Execution']")){$s.SelectSingleNode("*[local-name()='Execution']").GetAttribute('ProcessID')}else{''})
        UserSid=$(if($s.SelectSingleNode("*[local-name()='Security']")){$s.SelectSingleNode("*[local-name()='Security']").GetAttribute('UserID')}else{''})
        Data=$d
    }
    Set-CcdcDetection -Record $r -Profile $Profile
}
function Set-CcdcDetection {
    param($Record,$Profile)
    $r=$Record
    $kind=$r.Kind;$id=$r.EventId;$d=$r.Data
    $reasons = New-Object 'System.Collections.Generic.List[string]'
    if ($kind -eq 'SENSOR') {$r.Severity='REVIEW';$reasons.Add('Sysmon service or configuration changed: verify expected visibility')}
    if ($kind -eq 'REMOTE-MANAGEMENT') {$reasons.Add('WinRM activity: correlate with authentication and process ancestry; client identity is not proven')}
    if ($kind -eq 'PERSISTENCE' -or $id -in @(1102,4720,4728,4732,4756)) {
        $r.Severity='REVIEW'; $reasons.Add('Persistence, privilege or audit change: verify against approved work')
    }
    if ($id -eq 4625) { $r.Severity='REVIEW'; $reasons.Add('Authentication failed: investigate context') }
    if ($id -eq 4624 -and $d['LogonType'] -in @('3','10') -and $r.SourceIp -notin $Profile.KnownManagementAddresses) {
        $r.Severity='REVIEW'; $reasons.Add('Remote authentication from an address not listed in the active profile')
    }
    foreach ($rule in $Profile.Rules) {
        if (-not $rule.Enabled -or ($rule.Kinds.Count -gt 0 -and $kind -notin $rule.Kinds)) { continue }
        $regex = New-Object regex($rule.Pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase, [timespan]::FromMilliseconds(100))
        if ($regex.IsMatch([string]$r.($rule.Field))) {
            $reasons.Add([string]$rule.Description)
            if (@('INFO','REVIEW','HIGH').IndexOf($rule.Severity) -gt @('INFO','REVIEW','HIGH').IndexOf($r.Severity)) { $r.Severity=$rule.Severity }
        }
    }
    $r.Reasons=$reasons.ToArray()
    return $r
}
function Read-CcdcXmlBatch {
    param([string]$Log, [string]$XPath='*', [int]$Limit=250, [switch]$Newest)
    $q = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Log, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $XPath)
    $q.ReverseDirection = [bool]$Newest
    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($q)
    try {
        for ($i=0; $i -lt $Limit; $i++) {
            $ev=$reader.ReadEvent()
            if ($null -eq $ev) { break }
            try { $ev.ToXml() } finally { $ev.Dispose() }
        }
    } finally { $reader.Dispose() }
}
function Receive-CcdcBatchCore {
    param([string]$DataDirectory, $Profile, [int]$Limit=250)
    $null=New-Item -ItemType Directory -Path $DataDirectory -Force
    $checkpoint=Join-Path $DataDirectory 'checkpoints.json'
    $state=@{}
    if (Test-Path $checkpoint) {
        # Corrupt state is an explicit error; never silently jump to the log head.
        $saved=Get-Content -LiteralPath $checkpoint -Raw | ConvertFrom-Json
        foreach ($prop in $saved.PSObject.Properties) { $state[$prop.Name]=$prop.Value }
    }
    $records=New-Object 'System.Collections.Generic.List[object]'
    $health=New-Object 'System.Collections.Generic.List[string]'
    foreach ($source in Get-CcdcSources) {
        try {
            $info=Get-WinEvent -ListLog $source.Log -ErrorAction Stop
            if (-not $info.IsEnabled) { throw 'channel disabled' }
            $head=@(Read-CcdcXmlBatch -Log $source.Log -Limit 1 -Newest)
            if (-not $head.Count) { $health.Add($source.Log+': enabled, empty'); continue }
            [xml]$headXml=$head[0]; $headId=[long]$headXml.Event.System.EventRecordID
            $last=[long]0
            if ($state.ContainsKey($source.Log)) { $last=[long]$state[$source.Log] }
            if ($headId -lt $last) {
                $health.Add($source.Log+': LOG RESET detected; replaying retained records'); $last=0
            }
            if ($last -gt 0) {
                [xml]$oldest=@(Read-CcdcXmlBatch -Log $source.Log -Limit 1)[0]
                if ([long]$oldest.Event.System.EventRecordID -gt ($last+1)) { $health.Add($source.Log+': retention gap; records have rolled out') }
            }
            $ids=($source.Ids | ForEach-Object {"EventID=$_"}) -join ' or '
            $xpath=if($source.Ids.Count){"*[System[(EventRecordID > $last) and ($ids)]]"}else{"*[System[EventRecordID > $last]]"}
            $batch=@(Read-CcdcXmlBatch -Log $source.Log -XPath $xpath -Limit $Limit)
            $rows=@(foreach ($xml in $batch) { ConvertTo-CcdcEvent -Xml $xml -Profile $Profile })
            if ($rows.Count) {
                # Append evidence BEFORE checkpoint: a crash can replay, never skip, rows.
                $journal=Join-Path $DataDirectory ('events-'+[datetime]::UtcNow.ToString('yyyyMMdd')+'.jsonl')
                $lines=@($rows | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 8 -Compress })
                [IO.File]::AppendAllLines($journal, [string[]]$lines, (New-Object Text.UTF8Encoding($false)))
                foreach ($r in $rows) { $records.Add($r) }
                $state[$source.Log]=[long]$rows[-1].RecordId
            }
            if ($batch.Count -lt $Limit) {
                # No remaining matching records through the observed head. Avoid rescanning
                # unrelated Security records indefinitely when selected events are sparse.
                $state[$source.Log]=[Math]::Max($headId, [long]$(if($state.ContainsKey($source.Log)){$state[$source.Log]}else{0}))
            }
            if ($batch.Count -eq $Limit) { $health.Add($source.Log+': backlog, draining oldest first') }
            else { $health.Add($source.Log+': available') }
        } catch { $health.Add($source.Log+': UNAVAILABLE/ERROR: '+$_.Exception.Message) }
    }
    $temporary=$checkpoint+'.tmp'
    [IO.File]::WriteAllText($temporary, (ConvertTo-Json -InputObject $state), (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $checkpoint -Force
    [pscustomobject]@{Records=$records.ToArray(); Health=$health.ToArray()}
}
function Get-CcdcHistory([string]$DataDirectory, [int]$Limit=1200, [string]$Query) {
    # Bound memory; full journal remains searchable using PowerShell or external tools.
    $queue=New-Object 'System.Collections.Generic.Queue[object]'
    foreach ($file in Get-ChildItem -LiteralPath $DataDirectory -Filter 'events-*.jsonl' -ErrorAction SilentlyContinue | Sort-Object Name) {
        foreach ($line in [IO.File]::ReadLines($file.FullName)) {
            if ($Query -and $line.IndexOf($Query,[StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
            try { $queue.Enqueue(($line | ConvertFrom-Json)) } catch { Write-Warning "Invalid journal row in $($file.Name)" }
            if ($queue.Count -gt $Limit) { $null=$queue.Dequeue() }
        }
    }
    $queue.ToArray()
}
function Receive-CcdcBatch {
    param([string]$DataDirectory, $Profile, [int]$Limit=250)
    $null=New-Item -ItemType Directory -Path $DataDirectory -Force
    $lock=$null
    try {
        $lock=[IO.File]::Open((Join-Path $DataDirectory 'collector.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
        Receive-CcdcBatchCore -DataDirectory $DataDirectory -Profile $Profile -Limit $Limit
    } finally { if ($lock) { $lock.Dispose() } }
}
Export-ModuleMember -Function *-Ccdc*

function New-CcdcObservation {
    param([string]$Kind,[string]$Observation,[hashtable]$Fields,$Profile)
    $r=[pscustomobject][ordered]@{
        Key=('snapshot|'+[guid]::NewGuid().ToString('N'));Time=[datetimeoffset]::UtcNow.ToString('o')
        Host=[Environment]::MachineName;Channel='Direct state snapshots';EventId=0;RecordId=[long]0
        Kind=$Kind;Severity='INFO';Reasons=@();Image='';ParentImage='';ProcessId='';ParentProcessId=''
        ProcessGuid='';ParentProcessGuid='';CommandLine='';User='';SourceIp='';SourcePort=''
        DestinationIp='';DestinationPort='';Protocol='';Data=@{Observation=$Observation}
    }
    foreach($key in $Fields.Keys){if($r.PSObject.Properties[$key]){$r.$key=$Fields[$key]}else{$r.Data[$key]=$Fields[$key]}}
    Set-CcdcDetection $r $Profile
}
function Compare-CcdcDirectState {
    param($Current,$Previous,$Profile)
    $rows=New-Object 'System.Collections.Generic.List[object]'
    $oldProcesses=@{};$newProcesses=@{};$byId=@{}
    if($Previous){foreach($p in $Previous.Processes){$oldProcesses[$p.Lifetime]=$p}}
    foreach($p in $Current.Processes){$newProcesses[$p.Lifetime]=$p;$byId[[string]$p.ProcessId]=$p}
    foreach($p in $Current.Processes){
        if($oldProcesses.ContainsKey($p.Lifetime)){continue}
        $parent=$null
        if($byId.ContainsKey([string]$p.ParentProcessId)){
            $candidate=$byId[[string]$p.ParentProcessId]
            if($candidate.Created -and $p.Created -and [datetimeoffset]::Parse($candidate.Created) -le [datetimeoffset]::Parse($p.Created)){$parent=$candidate}
        }
        $fields=@{Image=$p.Image;ProcessId=[string]$p.ProcessId;ParentProcessId=[string]$p.ParentProcessId
            ProcessGuid=('snapshot|'+$p.Lifetime);ParentProcessGuid=$(if($parent){'snapshot|'+$parent.Lifetime}else{''})
            ParentImage=$(if($parent){$parent.Image}else{''});CommandLine=$p.CommandLine;User=$p.User;CreationTime=$p.Created}
        $rows.Add((New-CcdcObservation 'PROCESS' 'First seen in process snapshot; may already have been running' $fields $Profile))
    }
    if($Previous -and $Current.ProcessesAvailable){foreach($p in $Previous.Processes){
        if(-not $newProcesses.ContainsKey($p.Lifetime)){
            $rows.Add((New-CcdcObservation 'EXIT' 'No longer observed; exact exit time/cause unknown' @{Image=$p.Image;ProcessId=[string]$p.ProcessId;ProcessGuid=('snapshot|'+$p.Lifetime)} $Profile))
        }
    }}
    $oldTcp=@{};if($Previous){foreach($c in $Previous.Connections){$oldTcp[$c.Key]=$true}}
    foreach($c in $Current.Connections){
        if(-not $oldTcp.ContainsKey($c.Key)){
            $rows.Add((New-CcdcObservation 'CONNECTION' 'Socket first seen in snapshot; not a connection-creation event' @{
                SourceIp=$c.LocalAddress;SourcePort=[string]$c.LocalPort;DestinationIp=$c.RemoteAddress;DestinationPort=[string]$c.RemotePort
                ProcessId=[string]$c.ProcessId;Image=$c.Image;User=$c.User;Protocol='tcp';SocketState=$c.State
            } $Profile))
        }
    }
    if($Previous -and $Current.PersistenceAvailable -and $Previous.PersistenceAvailable){
        $old=@{};$now=@{}
        foreach($p in $Previous.Persistence){$old[$p.Key]=$p.Value}
        foreach($p in $Current.Persistence){$now[$p.Key]=$p.Value
            if(-not $old.ContainsKey($p.Key) -or $old[$p.Key] -ne $p.Value){
                $rows.Add((New-CcdcObservation 'PERSISTENCE' 'Persistence state added or changed since prior snapshot' @{Object=$p.Key;Before=$old[$p.Key];After=$p.Value} $Profile))
            }
        }
        foreach($key in $old.Keys){if(-not $now.ContainsKey($key)){
            $rows.Add((New-CcdcObservation 'PERSISTENCE' 'Persistence state removed since prior snapshot' @{Object=$key;Before=$old[$key];After=''} $Profile))
        }}
    }
    if($Previous){foreach($property in $Current.Sensors.PSObject.Properties){
        $prior=$Previous.Sensors.PSObject.Properties[$property.Name]
        if($prior -and [string]$prior.Value -ne [string]$property.Value){
            $r=New-CcdcObservation 'SENSOR' 'Security sensor state changed; verify teammate activity and possible tampering' @{Sensor=$property.Name;Before=[string]$prior.Value;After=[string]$property.Value} $Profile
            $r.Severity=if([string]$property.Value -in @('Running','1','True')){'INFO'}else{'HIGH'};$r.Reasons=@('Security visibility changed. Verify expected configuration; account names alone do not establish trust.')
            $rows.Add($r)
        }
    }}
    $rows.ToArray()
}
function Get-CcdcPolicyValue([string]$Path,[string]$Name) {
    if(-not(Test-Path -LiteralPath $Path)){return 'Not configured'}
    try {
        $key=Get-Item -LiteralPath $Path -ErrorAction Stop
        if($key.GetValueNames() -notcontains $Name){return 'Not configured'}
        return [string]$key.GetValue($Name)
    }catch{return 'Unavailable: '+$_.Exception.Message}
}
function Get-CcdcDirectState {
    param([switch]$IncludePersistence)
    $health=New-Object 'System.Collections.Generic.List[string]'
    $processes=@();$connections=@();$persistence=@();$processOk=$false;$persistenceOk=$false;$socketOk=$false
    try {
        # Query live kernel-backed process state through CIM, independently of Event Logs.
        $users=@{}
        try{foreach($p in Get-Process -IncludeUserName -ErrorAction Stop){$users[[string]$p.Id]=$p.UserName}}
        catch{$health.Add('Process owners unavailable: '+$_.Exception.Message)}
        $processes=@(Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
            $created=if($_.CreationDate){([datetimeoffset]$_.CreationDate).ToUniversalTime().ToString('o')}else{''}
            [pscustomobject]@{Lifetime=([string]$_.ProcessId+'|'+$created);Created=$created;ProcessId=[string]$_.ProcessId;ParentProcessId=[string]$_.ParentProcessId
                Image=$(if($_.ExecutablePath){[string]$_.ExecutablePath}else{[string]$_.Name});CommandLine=[string]$_.CommandLine;User=[string]$users[[string]$_.ProcessId]}
        })
        $processOk=$true;$health.Add('Direct process snapshots: available; account names do not establish trust')
    }catch{$health.Add('Direct processes UNAVAILABLE/ERROR: '+$_.Exception.Message)}
    $byId=@{};foreach($p in $processes){$byId[$p.ProcessId]=$p}
    try {
        $connections=@(Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {
            $p=$byId[[string]$_.OwningProcess]
            [pscustomobject]@{Key=($_.LocalAddress+'|'+$_.LocalPort+'|'+$_.RemoteAddress+'|'+$_.RemotePort+'|'+$_.OwningProcess+'|'+$_.State)
                LocalAddress=[string]$_.LocalAddress;LocalPort=$_.LocalPort;RemoteAddress=[string]$_.RemoteAddress;RemotePort=$_.RemotePort
                ProcessId=[string]$_.OwningProcess;Image=$(if($p){$p.Image}else{''});User=$(if($p){$p.User}else{''});State=[string]$_.State}
        })
        $socketOk=$true;$health.Add('Direct TCP snapshots: available; short-lived activity between samples can be missed')
    }catch{$health.Add('Direct TCP UNAVAILABLE/ERROR: '+$_.Exception.Message)}
    $sysmon=@(Get-Service Sysmon,Sysmon64 -ErrorAction SilentlyContinue)
    $sensors=[pscustomobject]@{
        SysmonService=$(if($sysmon.Count){($sysmon.Status -join ',')}else{'Missing'})
        ScriptBlockLogging=(Get-CcdcPolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging')
        ProcessCommandLineLogging=(Get-CcdcPolicyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled')
    }
    try {
        $defender=Get-MpComputerStatus -ErrorAction Stop
        $sensors | Add-Member -NotePropertyName DefenderRealTimeProtection -NotePropertyValue ([string]$defender.RealTimeProtectionEnabled)
        if(-not $defender.RealTimeProtectionEnabled){$health.Add('Defender real-time protection not active; check assigned role and AV policy')}
    }catch{$health.Add('Defender status unavailable: '+$_.Exception.Message)}
    if($sensors.ScriptBlockLogging -ne '1'){$health.Add('PowerShell script-block logging not enabled in local policy; verify effective GPO')}
    if($sensors.ProcessCommandLineLogging -ne '1'){$health.Add('Process command-line auditing not enabled in local policy; verify effective GPO')}
    if($sensors.SysmonService -ne 'Running'){$health.Add('Sysmon service not running; Event Log availability alone is insufficient')}
    if($IncludePersistence){
        try {
            $persistence=@(
                Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object {[pscustomobject]@{Key=('Service|'+$_.Name);Value=($_.PathName+'|'+$_.StartName+'|'+$_.StartMode)}}
                Get-ScheduledTask -ErrorAction Stop | ForEach-Object {[pscustomobject]@{Key=('Task|'+$_.TaskPath+$_.TaskName);Value=(ConvertTo-Json -InputObject ([ordered]@{Actions=@($_.Actions | Select-Object Execute,Arguments,WorkingDirectory);UserId=$_.Principal.UserId;RunLevel=[string]$_.Principal.RunLevel;LogonType=[string]$_.Principal.LogonType}) -Depth 5 -Compress)}}
                foreach($path in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')){
                    if(Test-Path $path){
                        $key=Get-Item -LiteralPath $path -ErrorAction Stop
                        foreach($name in $key.GetValueNames()){[pscustomobject]@{Key=('Registry|'+$path+'|'+$name);Value=[string]$key.GetValue($name)}}
                    }
                }
            )
            $persistenceOk=$true;$health.Add('Direct task/service/HKLM startup snapshots: available (changes only, not complete persistence coverage)')
        }catch{$health.Add('Persistence snapshot UNAVAILABLE/ERROR: '+$_.Exception.Message)}
    }
    [pscustomobject]@{Processes=$processes;ProcessesAvailable=$processOk;Connections=$connections;ConnectionsAvailable=$socketOk
        Persistence=$persistence;PersistenceAvailable=$persistenceOk;Sensors=$sensors;Health=$health.ToArray()}
}
function Receive-CcdcDirectState {
    param([string]$DataDirectory,$Profile,$Snapshot)
    $null=New-Item -ItemType Directory -Path $DataDirectory -Force
    $lock=$null
    try {
        $lock=[IO.File]::Open((Join-Path $DataDirectory 'collector.lock'),'OpenOrCreate','ReadWrite','None')
        $path=Join-Path $DataDirectory 'direct-state.json';$previous=$null
        if(Test-Path $path){$previous=Get-Content $path -Raw | ConvertFrom-Json}
        $rows=@(Compare-CcdcDirectState $Snapshot $previous $Profile)
        # A failed query must not replace a good baseline or create false exits/deletions.
        if($previous){
            if(-not $Snapshot.ProcessesAvailable){$Snapshot.Processes=$previous.Processes}
            if(-not $Snapshot.ConnectionsAvailable){$Snapshot.Connections=$previous.Connections}
            if(-not $Snapshot.PersistenceAvailable){$Snapshot.Persistence=$previous.Persistence;$Snapshot.PersistenceAvailable=$previous.PersistenceAvailable}
        }
        if($rows.Count){
            $journal=Join-Path $DataDirectory ('events-'+[datetime]::UtcNow.ToString('yyyyMMdd')+'.jsonl')
            $lines=@($rows | ForEach-Object {ConvertTo-Json -InputObject $_ -Depth 8 -Compress})
            [IO.File]::AppendAllLines($journal,[string[]]$lines,(New-Object Text.UTF8Encoding($false)))
        }
        $json=ConvertTo-Json -InputObject $Snapshot -Depth 8
        if(-not(Test-Path (Join-Path $DataDirectory 'direct-baseline.json'))){[IO.File]::WriteAllText((Join-Path $DataDirectory 'direct-baseline.json'),$json)}
        [IO.File]::WriteAllText(($path+'.tmp'),$json)
        Move-Item -LiteralPath ($path+'.tmp') -Destination $path -Force
        $rows
    }finally{if($lock){$lock.Dispose()}}
}
Export-ModuleMember -Function *-Ccdc*

function Get-CcdcRegistryScopes {
    param($Profile)
    $paths=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell',
        'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')
    if($Profile.PSObject.Properties['RegistryPaths']){$paths=@($Profile.RegistryPaths)}
    $valueOnly=@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa')
    if($Profile.PSObject.Properties['RegistryValueOnlyPaths']){$valueOnly=@($Profile.RegistryValueOnlyPaths)}
    foreach($path in $paths){
        $items=@();$errorText='';$ok=$true
        try{
            if(Test-Path -LiteralPath $path){
                $keys=@(Get-Item -LiteralPath $path -ErrorAction Stop)
                if($path -notin $valueOnly){$keys+=@(Get-ChildItem -LiteralPath $path -Recurse -ErrorAction Stop)}
                if($keys.Count -gt 10000){throw 'Scope exceeds 10000 keys; tune RegistryPaths to bound overhead'}
                $items=@(foreach($key in $keys){
                    [pscustomobject]@{Key=($key.Name+'|<KEY>');Value='Present'}
                    foreach($name in $key.GetValueNames()){
                        $value=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                        [pscustomobject]@{Key=($key.Name+'|'+$name);Value=(ConvertTo-Json -InputObject ([ordered]@{Type=[string]$key.GetValueKind($name);Data=$value}) -Compress -Depth 4)}
                    }
                })
            }
        }catch{$ok=$false;$errorText=$_.Exception.Message}
        [pscustomobject]@{Name=('Registry '+$path+$(if($path -in $valueOnly){' (values only; subkeys excluded)'}else{''}));Kind='REGISTRY';Available=$ok;Items=$items;Error=$errorText}
    }
}
function Get-CcdcAccountScopes {
    $computer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if($computer.DomainRole -lt 4){
        $ok=$true;$errorText='';$items=@()
        try{$items=@(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{Key=[string]$_.SID;Value=(ConvertTo-Json -InputObject ([ordered]@{Name=$_.Name;Disabled=$_.Disabled;Domain=$_.Domain}) -Compress)}
        })}catch{$ok=$false;$errorText=$_.Exception.Message}
        [pscustomobject]@{Name='Local accounts';Kind='ACCOUNT';Available=$ok;Items=$items;Error=$errorText}
    }
    if($computer.PartOfDomain){
        $ok=$true;$errorText='';$items=@();$searcher=$null;$found=$null;$directory=$null;$rootDse=$null
        try{
            $rootDse=New-Object DirectoryServices.DirectoryEntry('LDAP://RootDSE')
            $dn=[string]$rootDse.Properties['defaultNamingContext'][0]
            if(-not $dn){throw 'Current-domain naming context unavailable'}
            $directory=New-Object DirectoryServices.DirectoryEntry('LDAP://'+$dn)
            $searcher=New-Object DirectoryServices.DirectorySearcher($directory)
            $searcher.Filter='(&(objectCategory=person)(objectClass=user))';$searcher.PageSize=500
            $searcher.ServerTimeLimit=[timespan]::FromSeconds(10);$searcher.ClientTimeout=[timespan]::FromSeconds(15)
            foreach($name in @('objectsid','samaccountname','whencreated','useraccountcontrol')){$null=$searcher.PropertiesToLoad.Add($name)}
            $found=$searcher.FindAll()
            $items=@(foreach($result in $found){
                $sid=New-Object Security.Principal.SecurityIdentifier([byte[]]$result.Properties['objectsid'][0],0)
                [pscustomobject]@{Key=$sid.Value;Value=(ConvertTo-Json -InputObject ([ordered]@{
                    Name=[string]$result.Properties['samaccountname'][0];Created=[string]$result.Properties['whencreated'][0];Flags=[string]$result.Properties['useraccountcontrol'][0]
                }) -Compress)}
            })
        }catch{$ok=$false;$errorText=$_.Exception.Message}
        finally{foreach($resource in @($found,$searcher,$directory,$rootDse)){if($resource){$resource.Dispose()}}}
        [pscustomobject]@{Name='Current-domain accounts';Kind='ACCOUNT';Available=$ok;Items=$items;Error=$errorText}
    }
}
function Receive-CcdcBaselineScopes {
    param([string]$DataDirectory,$Profile,[object[]]$Scopes)
    $null=New-Item -ItemType Directory -Path $DataDirectory -Force
    $rows=New-Object 'System.Collections.Generic.List[object]';$health=New-Object 'System.Collections.Generic.List[string]'
    $lock=$null
    try{
        $lock=[IO.File]::Open((Join-Path $DataDirectory 'collector.lock'),'OpenOrCreate','ReadWrite','None')
        foreach($scope in $Scopes){
            if(-not $scope.Available){$health.Add($scope.Name+' UNAVAILABLE/ERROR: '+$scope.Error);continue}
            $hash=[Security.Cryptography.SHA256]::Create()
            try{$id=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($scope.Name)))).Replace('-','')}finally{$hash.Dispose()}
            $basePath=Join-Path $DataDirectory ('baseline-'+$id+'.json');$lastPath=Join-Path $DataDirectory ('observed-'+$id+'.json')
            $now=@{};foreach($item in $scope.Items){$now[$item.Key]=[string]$item.Value}
            if(-not(Test-Path $basePath)){
                [IO.File]::WriteAllText($basePath,(ConvertTo-Json -InputObject @{Scope=$scope.Name;CapturedAt=[datetimeoffset]::UtcNow.ToString('o');Items=$now} -Depth 6))
                $health.Add($scope.Name+': initial baseline saved; it is not asserted clean')
            }else{
                $baseline=Get-Content $basePath -Raw | ConvertFrom-Json
                $before=@{}
                $saved=if(Test-Path $lastPath){Get-Content $lastPath -Raw | ConvertFrom-Json}else{$baseline.Items}
                foreach($prop in $saved.PSObject.Properties){$before[$prop.Name]=[string]$prop.Value}
                foreach($key in @(@($now.Keys)+@($before.Keys) | Sort-Object -Unique)){
                    if($before.ContainsKey($key) -eq $now.ContainsKey($key) -and $before[$key] -eq $now[$key]){continue}
                    $original=$baseline.Items.PSObject.Properties[$key]
                    $action=if(-not $before.ContainsKey($key)){'Added'}elseif(-not $now.ContainsKey($key)){'Removed'}else{'Changed'}
                    $fields=@{Scope=$scope.Name;Object=$key;Change=$action;Before=$before[$key];After=$now[$key];Baseline=$(if($original){$original.Value}else{'Absent from first baseline'})}
                    if($scope.Kind -eq 'ACCOUNT'){
                        try{$account=([string]$(if($now.ContainsKey($key)){$now[$key]}else{$before[$key]}) | ConvertFrom-Json);$fields['User']=[string]$account.Name}catch{$fields['User']=$key}
                    }else{$fields['Image']=$key}
                    $r=New-CcdcObservation $scope.Kind ($action+' since last sample; compared with immutable first baseline') $fields $Profile
                    $r.Severity='REVIEW'
                    $r.Reasons=@($(if($scope.Kind -eq 'ACCOUNT'){'Account '+$action.ToLower()+': verify authorized team/scoring work. Account name is not proof of trust.'}else{'Registry '+$action.ToLower()+': inspect the original baseline and confirm an approved change.'}))
                    $rows.Add($r)
                }
                $health.Add($scope.Name+': baseline comparison completed '+[datetimeoffset]::UtcNow.ToString('HH:mm:ss')+' UTC')
            }
            # Commit observations before updating the last-seen comparison state.
            $scopeRows=@($rows | Where-Object {$_.Data.Scope -eq $scope.Name})
            if($scopeRows.Count){
                $journal=Join-Path $DataDirectory ('events-'+[datetime]::UtcNow.ToString('yyyyMMdd')+'.jsonl')
                [IO.File]::AppendAllLines($journal,[string[]]@($scopeRows | ForEach-Object {ConvertTo-Json -InputObject $_ -Depth 8 -Compress}),(New-Object Text.UTF8Encoding($false)))
            }
            [IO.File]::WriteAllText(($lastPath+'.tmp'),(ConvertTo-Json -InputObject $now -Depth 4))
            Move-Item -LiteralPath ($lastPath+'.tmp') -Destination $lastPath -Force
        }
    }finally{if($lock){$lock.Dispose()}}
    [pscustomobject]@{Records=$rows.ToArray();Health=$health.ToArray()}
}
Export-ModuleMember -Function *-Ccdc*
