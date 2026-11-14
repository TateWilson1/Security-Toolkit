#requires -Version 5.1
# Shared, read-only telemetry engine. Windows APIs are called only by collection.
Set-StrictMode -Version 2
function Get-CcdcSources {
    @(
        @{Log='Microsoft-Windows-Sysmon/Operational'; Ids=@(1,3,5,12,13,14,19,20,21)}
        @{Log='Security'; Ids=@(1102,4624,4625,4672,4688,4689,4697,4698,4702,4720,4722,4725,4728,4732,4738,4740,4756)}
        @{Log='System'; Ids=@(7045)}
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
        $kind = switch ($id) { 1 {'PROCESS'} 3 {'CONNECTION'} 5 {'EXIT'} default {'PERSISTENCE'} }
    } elseif ($id -eq 4688) {
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
    $reasons = New-Object 'System.Collections.Generic.List[string]'
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
            $xpath="*[System[(EventRecordID > $last) and ($ids)]]"
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
