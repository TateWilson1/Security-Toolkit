#requires -Version 5.1
# CCDC Windows Server dashboard. Uses Sysmon + Windows Event Logs + live TCP snapshots.
# Read-only: no automatic blocking or quarantine of suspicious commands.
$ErrorActionPreference = 'Stop'
$myPath = $MyInvocation.MyCommand.Path
$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -STA -File "'+$myPath+'"')
    exit
}
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$script:base = Split-Path -Parent $myPath
$script:role = 'Other'
try {
    $c=Get-CimInstance Win32_ComputerSystem
    if($c.DomainRole -ge 4){$script:role='AD'}
    elseif(Get-Service MSSQLSERVER -ErrorAction SilentlyContinue){$script:role='MSSQL'}
} catch {}
$script:streams = @()
$script:busy = $false
$script:paused = $false
$script:onlyAlerts = $false
$script:count = 0
$script:alertCount = 0
$script:hasSysmon = $false
$bg = [System.Drawing.Color]::FromArgb(15,23,42)
$surface = [System.Drawing.Color]::FromArgb(30,41,59)
$fg = [System.Drawing.Color]::FromArgb(226,232,240)
$muted = [System.Drawing.Color]::FromArgb(148,163,184)
$blue = [System.Drawing.Color]::FromArgb(56,189,248)
$amber = [System.Drawing.Color]::FromArgb(251,191,36)
$red = [System.Drawing.Color]::FromArgb(251,113,133)
$form = New-Object System.Windows.Forms.Form
$form.Text = "CCDC Blue Team | $env:COMPUTERNAME | $script:role"
$form.Size = [System.Drawing.Size]::new(1330,850)
$form.MinimumSize = [System.Drawing.Size]::new(1000,650)
$form.StartPosition='CenterScreen';$form.BackColor=$bg;$form.ForeColor=$fg
$top = New-Object System.Windows.Forms.Panel
$top.Height=95;$top.Dock='Top';$top.BackColor=$bg
$form.Controls.Add($top)
$title=New-Object System.Windows.Forms.Label
$title.Text='CCDC  /  LIVE DEFENSE';$title.Location=[System.Drawing.Point]::new(18,12)
$title.Size=[System.Drawing.Size]::new(500,38);$title.ForeColor=$blue
$title.Font=[System.Drawing.Font]::new('Segoe UI',19,[System.Drawing.FontStyle]::Bold)
$top.Controls.Add($title)
$script:status=New-Object System.Windows.Forms.Label
$script:status.Location=[System.Drawing.Point]::new(20,57)
$script:status.Size=[System.Drawing.Size]::new(1240,24)
$script:status.Font=[System.Drawing.Font]::new('Segoe UI',9)
$script:status.ForeColor=$muted;$script:status.Text='Initializing event sources...'
$top.Controls.Add($script:status)
$tools=New-Object System.Windows.Forms.Panel
$tools.Dock='Top';$tools.Height=55;$tools.BackColor=$bg
$form.Controls.Add($tools)
function New-Action([string]$text,[int]$x,[int]$width) {
    $b=New-Object System.Windows.Forms.Button
    $b.Text=$text;$b.Location=[System.Drawing.Point]::new($x,8);$b.Size=[System.Drawing.Size]::new($width,34)
    $b.BackColor=$surface;$b.ForeColor=$fg;$b.FlatStyle='Flat'
    $b.FlatAppearance.BorderColor=$blue
    $b.Font=[System.Drawing.Font]::new('Segoe UI',9)
    $tools.Controls.Add($b)
    return $b
}
$bBaseline=New-Action 'Save baseline' 16 122
$bCheck=New-Action 'Service checks' 147 128
$bExport=New-Action 'Export evidence' 284 133
$bDefender=New-Action 'Defender status' 426 132
$bPause=New-Action 'Pause live view' 567 128
$bAlerts=New-Action 'Alerts only: OFF' 706 126
$script:counters=New-Object System.Windows.Forms.Label
$script:counters.Text='Events 0   |   Alerts 0';$script:counters.ForeColor=$fg
$script:counters.Location=[System.Drawing.Point]::new(864,17);$script:counters.Size=[System.Drawing.Size]::new(380,27)
$script:counters.Font=[System.Drawing.Font]::new('Segoe UI',11,[System.Drawing.FontStyle]::Bold)
$tools.Controls.Add($script:counters)
$tabs=New-Object System.Windows.Forms.TabControl
$tabs.Dock='Fill';$tabs.Font=[System.Drawing.Font]::new('Segoe UI',10)
$form.Controls.Add($tabs);$tabs.BringToFront()
function New-Tab([string]$label) {
    $t=New-Object System.Windows.Forms.TabPage;$t.Text=$label;$t.BackColor=$bg
    [void]$tabs.TabPages.Add($t)
    return $t
}
$tEvent=New-Tab 'Process + Connection Events'
$tTcp=New-Tab 'Live TCP Sessions'
$tNotes=New-Tab 'Scoring Safety'
function Set-Grid($g) {
    $g.Dock='Fill';$g.BackgroundColor=$bg;$g.GridColor=$surface
    $g.ReadOnly=$true;$g.AllowUserToAddRows=$false;$g.AllowUserToDeleteRows=$false
    $g.RowHeadersVisible=$false;$g.MultiSelect=$false;$g.SelectionMode='FullRowSelect'
    $g.AutoSizeColumnsMode='Fill';$g.BorderStyle='None'
    $g.EnableHeadersVisualStyles=$false
    $g.ColumnHeadersDefaultCellStyle.BackColor=$surface
    $g.ColumnHeadersDefaultCellStyle.ForeColor=$fg
    $g.ColumnHeadersDefaultCellStyle.Font=[System.Drawing.Font]::new('Segoe UI',9,[System.Drawing.FontStyle]::Bold)
    $g.DefaultCellStyle.BackColor=$bg
    $g.DefaultCellStyle.ForeColor=$fg
    $g.DefaultCellStyle.SelectionBackColor=[System.Drawing.Color]::FromArgb(38,67,91)
    $g.DefaultCellStyle.SelectionForeColor=$fg
    $g.Font=[System.Drawing.Font]::new('Segoe UI',9)
    $g.RowTemplate.Height=26
}
$split=New-Object System.Windows.Forms.SplitContainer
$split.Dock='Fill';$split.Orientation='Horizontal';$split.SplitterDistance=450
$tEvent.Controls.Add($split)
$script:eventGrid=New-Object System.Windows.Forms.DataGridView
Set-Grid $script:eventGrid
foreach($column in @(@('At','Time'),@('Priority','Priority'),@('Kind','Event'),@('Image','Process'),@('Parent','Parent process'),@('From','Source IP'),@('To','Destination IP'),@('Who','User'))) {
    [void]$script:eventGrid.Columns.Add($column[0],$column[1])
}
$script:eventGrid.Columns['At'].FillWeight=70
$script:eventGrid.Columns['Priority'].FillWeight=70
$script:eventGrid.Columns['Kind'].FillWeight=85
$script:eventGrid.Columns['Image'].FillWeight=180
$script:eventGrid.Columns['Parent'].FillWeight=160
$script:eventGrid.Columns['From'].FillWeight=105
$script:eventGrid.Columns['To'].FillWeight=105
$script:eventGrid.Columns['Who'].FillWeight=110
$split.Panel1.Controls.Add($script:eventGrid)
$script:detail=New-Object System.Windows.Forms.TextBox
$script:detail.Dock='Fill';$script:detail.Multiline=$true;$script:detail.ReadOnly=$true
$script:detail.WordWrap=$false;$script:detail.ScrollBars='Both'
$script:detail.BackColor=$bg;$script:detail.ForeColor=$fg
$script:detail.Font=[System.Drawing.Font]::new('Consolas',9)
$script:detail.Text='Select a timeline event for FULL command line, parent, event record ID, and timestamps.'
$split.Panel2.Controls.Add($script:detail)
$script:eventGrid.Add_SelectionChanged({
    if($script:eventGrid.SelectedRows.Count -gt 0 -and $script:eventGrid.SelectedRows[0].Tag){
        $script:detail.Text=[string]$script:eventGrid.SelectedRows[0].Tag
    }
})
$script:tcp=New-Object System.Windows.Forms.DataGridView
Set-Grid $script:tcp
foreach($column in @(@('Local','Local endpoint'),@('Remote','Remote endpoint'),@('PID','PID'),@('Process','Owning process'),@('State','State'))) {
    [void]$script:tcp.Columns.Add($column[0],$column[1])
}
$script:tcp.Columns['Local'].FillWeight=150
$script:tcp.Columns['Remote'].FillWeight=150
$script:tcp.Columns['PID'].FillWeight=65
$script:tcp.Columns['Process'].FillWeight=175
$script:tcp.Columns['State'].FillWeight=75
$tTcp.Controls.Add($script:tcp)
$instructions=New-Object System.Windows.Forms.TextBox
$instructions.Dock='Fill';$instructions.Multiline=$true;$instructions.ReadOnly=$true
$instructions.ScrollBars='Vertical';$instructions.BackColor=$bg;$instructions.ForeColor=$fg
$instructions.Font=[System.Drawing.Font]::new('Consolas',11)
$instructions.Text=@'
SCORING IS MORE IMPORTANT THAN AUTOMATIC BLOCKING

Previous invitational (NOT a guarantee for the next packet):
- AD/DNS: DNS lookups, WinRM authenticated PowerShell command
- SQL: SMB authenticated file check, RDP auth, SQL port 1433/query
- Splunk: Query and management, plus web services on other machines

If you see wsmprovhost.exe / powershell.exe on the AD machine:
  This MAY be the legitimate scoring engine, not Red Team.

ALERT COLORS ARE HEURISTICS, NOT PROOF OF COMPROMISE.
High-signal: web/SQL worker spawning a shell, critical account changes.
Review: unusual shell interpreter, script content, remote logon.
Normal: connection/process telemetry. This can be very noisy.

Capture first, respond second:
  1. Select event, inspect FULL command, parent and source IP
  2. Correlate with scored accounts, known management and team actions
  3. Export evidence before any disruptive remediation
  4. Contain ONLY confirmed malicious process/file/IP
  5. Recheck scored service in current Team Portal after every change

Nothing here auto-disables users, blocks hosts, kills shells, or
modifies firewall, DNS, SQL, or WinRM settings.

Sysmon Event 1 = process creation (parent, command line)
Sysmon Event 3 = network connection; event 5 = process exit
Windows Security 4688 = fallback process create if Sysmon missing
Windows Security 4624/4625 = logon success/failure
PowerShell Operational 4104 = script block content

TCP tab: refreshes current established sessions every 2 seconds.
Short connections may be missed in snapshot tab. Sysmon 3 event
capture is the better history (not a raw packet recorder).

Windows Defender Antivirus is a separate prevention layer.
If its real-time protection is ACTIVE, it can quarantine malware
that it recognizes. This GUI does not trigger quarantine itself.
'@
$tNotes.Controls.Add($instructions)
function To-Map($event) {
    $h=@{}
    try{
        [xml]$x=$event.ToXml()
        foreach($n in @($x.Event.EventData.Data)){
            if($n -and $n.Name){$h[[string]$n.Name]=[string]$n.'#text'}
        }
    }catch{}
    return $h
}
function Value($map,[string]$name){
    if($map.ContainsKey($name) -and $null -ne $map[$name]){return [string]$map[$name]}
    return ''
}
function Add-Event($ev,$map,$stream) {
    $kind='EVENT';$priority='INFO';$proc='';$parent='';$command='';$from='';$to='';$who=''
    if($stream.Log -like '*Sysmon*'){
        if($ev.Id -eq 1){
            $kind='PROCESS';$proc=Value $map 'Image';$parent=Value $map 'ParentImage'
            $command=Value $map 'CommandLine';$who=Value $map 'User'
            if($proc -match '(?i)(powershell|pwsh|cmd|mshta|rundll32|regsvr32|certutil|wmic|wscript|cscript|schtasks)\.exe$'){$priority='REVIEW'}
            if($parent -match '(?i)(wmiprvse|wsmprovhost)\.exe$'){$priority='REVIEW'}
            if($parent -match '(?i)(w3wp|sqlservr)\.exe$' -and $proc -match '(?i)(powershell|pwsh|cmd|mshta|rundll32)\.exe$'){$priority='HIGH'}
            if($command -match '(?i)(-encodedcommand|frombase64string|downloadstring)'){$priority='REVIEW'}
        }elseif($ev.Id -eq 3){
            $kind='CONNECTION';$proc=Value $map 'Image';$who=Value $map 'User'
            $from=(Value $map 'SourceIp')+':'+(Value $map 'SourcePort')
            $to=(Value $map 'DestinationIp')+':'+(Value $map 'DestinationPort')
            if($proc -match '(?i)(powershell|pwsh|cmd|mshta|rundll32)\.exe$'){$priority='REVIEW'}
        }elseif($ev.Id -eq 5){
            $kind='EXIT';$proc=Value $map 'Image';$who=Value $map 'User'
        }else{return}
    }elseif($stream.Log -eq 'Security'){
        if($ev.Id -eq 4688){
            if($script:hasSysmon){return}
            $kind='PROCESS';$proc=Value $map 'NewProcessName'
            $parent=Value $map 'ParentProcessName'
            $command=Value $map 'CommandLine';$who=Value $map 'SubjectUserName'
            if($proc -match '(?i)(powershell|pwsh|cmd|mshta|certutil|wmic)\.exe$'){$priority='REVIEW'}
        }elseif($ev.Id -eq 4624 -or $ev.Id -eq 4625){
            $lt=Value $map 'LogonType'
            if($ev.Id -eq 4624 -and $lt -notin @('2','3','10')){return}
            $kind=if($ev.Id -eq 4624){"LOGIN $lt"}else{'FAILED LOGIN'}
            $who=Value $map 'TargetUserName';$from=Value $map 'IpAddress'
            if($ev.Id -eq 4625){$priority='REVIEW'}
        }else{
            $kind='ACCOUNT CHANGE';$priority='HIGH'
            $who=Value $map 'TargetUserName'
        }
    }elseif($ev.Id -eq 4104){
        $kind='POWERSHELL'
        $proc='Script block';$command=Value $map 'ScriptBlockText';$priority='REVIEW'
    }else{return}
    $script:count++
    if($priority -ne 'INFO'){$script:alertCount++}
    $script:counters.Text="Events $($script:count)   |   Alerts $($script:alertCount)"
    if($script:onlyAlerts -and $priority -eq 'INFO'){return}
    $detailLines=@(
        'HOST: '+$env:COMPUTERNAME
        'TIMESTAMP: '+$ev.TimeCreated.ToString('o')
        'EVENT SOURCE: '+$stream.Log
        'EVENT ID: '+$ev.Id
        'EVENT RECORD ID: '+$ev.RecordId
        'PRIORITY: '+$priority+' (heuristic only)'
        'PROCESS: '+$proc
        'PARENT: '+$parent
        'USER: '+$who
        'SOURCE: '+$from
        'DESTINATION: '+$to
        'PROCESS GUID: '+(Value $map 'ProcessGuid')
        'PROCESS ID: '+(Value $map 'ProcessId')
        'PARENT COMMAND: '+(Value $map 'ParentCommandLine')
        'COMMAND: '+$command
        ''
        'Original record remains in the Windows event log.'
    )
    $display=($proc -split '\\')[-1]
    if($display.Length -gt 90){$display=$display.Substring(0,90)}
    $parentName=($parent -split '\\')[-1]
    $row=[object[]]@($ev.TimeCreated.ToString('HH:mm:ss'),$priority,$kind,$display,$parentName,$from,$to,$who)
    $index=$script:eventGrid.Rows.Add($row)
    $script:eventGrid.Rows[$index].Tag=$detailLines -join [Environment]::NewLine
    if($priority -eq 'HIGH'){
        $script:eventGrid.Rows[$index].DefaultCellStyle.ForeColor=$red
        try{[Console]::Beep(880,110)}catch{}
    }elseif($priority -eq 'REVIEW'){
        $script:eventGrid.Rows[$index].DefaultCellStyle.ForeColor=$amber
    }
    if($script:eventGrid.Rows.Count -gt 1200){$script:eventGrid.Rows.RemoveAt(0)}
    if($script:eventGrid.Rows.Count -gt 0){
        try{$script:eventGrid.FirstDisplayedScrollingRowIndex=$script:eventGrid.Rows.Count-1}catch{}
    }
}
function Init-Streams {
    $script:streams=@()
    foreach($spec in @(
        @{Log='Microsoft-Windows-Sysmon/Operational';Ids=@(1,3,5)},
        @{Log='Security';Ids=@(4624,4625,4688,4720,4722,4725,4728,4732,4738,4740,1102)},
        @{Log='Microsoft-Windows-PowerShell/Operational';Ids=@(4104)}
    )){
        try{
            $info=Get-WinEvent -ListLog $spec.Log -ErrorAction Stop
            if(-not $info.IsEnabled){continue}
            $head=Get-WinEvent -LogName $spec.Log -MaxEvents 1 -ErrorAction SilentlyContinue
            $last=[long]0
            if($head){$last=[long]$head.RecordId}
            $script:streams += [pscustomobject]@{Log=$spec.Log;Ids=$spec.Ids;Last=$last}
        }catch{}
    }
    $script:hasSysmon=(@($script:streams | Where-Object {$_.Log -like '*Sysmon*'}).Count -gt 0)
    $sysState=if($script:hasSysmon){'ON'}else{'MISSING: process/network event coverage limited'}
    $script:status.Text="HOST $env:COMPUTERNAME  |  ROLE $script:role  |  Sysmon $sysState  |  No automatic blocks"
}
function Poll-EventStreams {
    foreach($stream in $script:streams){
        try{
            $ids=($stream.Ids | ForEach-Object {"EventID=$_"}) -join ' or '
            $xp="*[System[(EventRecordID > $($stream.Last)) and ($ids)]]"
            $events=@(Get-WinEvent -LogName $stream.Log -FilterXPath $xp -MaxEvents 400 -ErrorAction SilentlyContinue | Sort-Object RecordId)
            if($events.Count -ge 400){$script:status.Text="High event volume! Only latest 400 events per poll for $($stream.Log); use Export or SIEM for full history."}
            foreach($ev in $events){
                if([long]$ev.RecordId -le $stream.Last){continue}
                $stream.Last=[long]$ev.RecordId
                Add-Event $ev (To-Map $ev) $stream
            }
        }catch{$script:status.Text="Event polling issue for $($stream.Log): $($_.Exception.Message)"}
    }
}
function Poll-Tcp {
    try{
        $connections=@(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object -First 600)
        $script:tcp.Rows.Clear()
        $names=@{}
        foreach($c in $connections){
            $pidText=[string]$c.OwningProcess
            if(-not $names.ContainsKey($pidText)){
                $p=Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                $names[$pidText]=if($p){$p.ProcessName}else{'(exited)'}
            }
            [void]$script:tcp.Rows.Add([object[]]@(
                "$($c.LocalAddress):$($c.LocalPort)",
                "$($c.RemoteAddress):$($c.RemotePort)",
                $pidText,$names[$pidText],[string]$c.State))
        }
    }catch{$script:status.Text="TCP refresh issue: $($_.Exception.Message)"}
}
function Run-Mode([string]$mode){
    $helper=Join-Path $script:base 'CCDC-BlueTeam.ps1'
    $args='-NoExit -NoProfile -ExecutionPolicy Bypass -File "'+$helper+'" -Mode '+$mode+' -Role '+$script:role+' -OutputDir "'+(Join-Path $script:base 'Evidence')+'"'
    Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $args
}
$bBaseline.Add_Click({Run-Mode 'Baseline'})
$bCheck.Add_Click({Run-Mode 'Check'})
$bExport.Add_Click({Run-Mode 'Export'})
$bDefender.Add_Click({
    $command='if(Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue){Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | Format-List; Get-MpThreatDetection | Select-Object -First 20 | Format-List}else{Write-Host ''Defender status unavailable''}'
    Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList ('-NoExit -NoProfile -Command "'+$command+'"')
})
$bPause.Add_Click({
    $script:paused=-not $script:paused
    $bPause.Text=if($script:paused){'Resume view'}else{'Pause live view'}
})
$bAlerts.Add_Click({
    $script:onlyAlerts=-not $script:onlyAlerts
    $bAlerts.Text=if($script:onlyAlerts){'Alerts only: ON'}else{'Alerts only: OFF'}
})
$timer=New-Object System.Windows.Forms.Timer
$timer.Interval=2000
$timer.Add_Tick({
    if($script:busy -or $script:paused){return}
    $script:busy=$true
    try{Poll-EventStreams;Poll-Tcp}finally{$script:busy=$false}
})
$form.Add_Shown({Init-Streams;Poll-Tcp;$timer.Start()})
$form.Add_FormClosing({$timer.Stop();$timer.Dispose()})
[void]$form.ShowDialog()
