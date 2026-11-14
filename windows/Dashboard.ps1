#requires -Version 5.1
# CCDC Windows Server dashboard. Uses Sysmon + Windows Event Logs + live TCP snapshots.
# Read-only: no automatic blocking or quarantine of suspicious commands.
[CmdletBinding()]
param(
    [string]$DataDirectory = (Join-Path $env:ProgramData 'CCDC-BlueTeam\Evidence\Telemetry'),
    [string]$ProfilePath = (Join-Path $env:ProgramData 'CCDC-BlueTeam\profile.json'),
    [string]$SmokeTestReport
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $ProfilePath)) { $ProfilePath=Join-Path $PSScriptRoot 'profile.default.json' }
Import-Module (Join-Path $PSScriptRoot 'Monitoring.psm1') -Force
$profile=Read-CcdcProfile $ProfilePath
$myPath = $MyInvocation.MyCommand.Path
$p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Verb RunAs -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -STA -File "'+$myPath+'" -DataDirectory "'+$DataDirectory+'" -ProfilePath "'+$ProfilePath+'"')
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
$tTree=New-Tab 'Process relationships'
$tHealth=New-Tab 'Sources + Defender'
$tNotes=New-Tab 'Scoring Safety'
$tree=New-Object System.Windows.Forms.TreeView
$tree.Dock='Fill';$tree.BackColor=$bg;$tree.ForeColor=$fg
$tTree.Controls.Add($tree)
$healthBox=New-Object System.Windows.Forms.TextBox
$healthBox.Dock='Fill';$healthBox.Multiline=$true;$healthBox.ReadOnly=$true;$healthBox.ScrollBars='Both'
$healthBox.BackColor=$bg;$healthBox.ForeColor=$fg
$tHealth.Controls.Add($healthBox)
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
$split.Dock='Fill';$split.Orientation='Horizontal';$split.Size=[System.Drawing.Size]::new(1200,600);$split.SplitterDistance=390
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
Windows Security 4688 = independent process audit (may duplicate Sysmon)
Windows Security 4624/4625 = logon success/failure
PowerShell Operational 4104 = script block content

TCP tab: refreshes current sockets after each background batch.
Short connections may be missed in snapshot tab. Sysmon 3 event
capture is the better history (not a raw packet recorder).

Windows Defender Antivirus is a separate prevention layer.
If its real-time protection is ACTIVE, it can quarantine malware
that it recognizes. This GUI does not trigger quarantine itself.
'@
$tNotes.Controls.Add($instructions)
# Search operates on the most recent 1200 retained rows, including replay at startup.
$search=New-Object System.Windows.Forms.TextBox
$search.Dock='Top';$search.BackColor=$surface;$search.ForeColor=$fg
$tEvent.Controls.Add($search);$search.BringToFront()
$search.AccessibleName='Search recent events by command, address, user or process'
$script:recent=New-Object 'System.Collections.Generic.List[object]'
$script:seen=New-Object 'System.Collections.Generic.HashSet[string]'
function Show-Recent {
    $script:eventGrid.Rows.Clear()
    $needle=$search.Text
    foreach ($r in $script:recent) {
        if ($script:onlyAlerts -and $r.Severity -eq 'INFO') { continue }
        $details=ConvertTo-Json -InputObject $r -Depth 8
        if ($needle -and $details.IndexOf($needle,[StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $index=$script:eventGrid.Rows.Add([object[]]@(
            ([datetimeoffset]::Parse($r.Time).ToLocalTime().ToString('MM-dd HH:mm:ss')),
            $r.Severity,$r.Kind,($r.Image -split '\\')[-1],($r.ParentImage -split '\\')[-1],
            ('['+$r.SourceIp+']:'+$r.SourcePort),('['+$r.DestinationIp+']:'+$r.DestinationPort),$r.User))
        $row=$script:eventGrid.Rows[$index];$row.Tag=$details
        if ($r.Severity -eq 'HIGH') { $row.DefaultCellStyle.ForeColor=$red }
        elseif ($r.Severity -eq 'REVIEW') { $row.DefaultCellStyle.ForeColor=$amber }
    }
    # GUIDs distinguish process lifetimes despite PID reuse. Missing parents stay explicit.
    $tree.BeginUpdate();$tree.Nodes.Clear();$nodes=@{}
    foreach ($r in $script:recent) {
        if ($r.Kind -ne 'PROCESS' -or -not $r.ProcessGuid -or $nodes.ContainsKey($r.ProcessGuid)) { continue }
        $node=New-Object System.Windows.Forms.TreeNode
        $node.Text=($r.Image+' [PID '+$r.ProcessId+'] '+$r.Time)
        $node.Tag=$r;$nodes[$r.ProcessGuid]=$node
    }
    foreach ($node in @($nodes.Values)) {
        $parentGuid=$node.Tag.ParentProcessGuid
        # Prevent malformed/custom telemetry from building cyclic Trees.
        if ($parentGuid -and $nodes.ContainsKey($parentGuid) -and
            [datetimeoffset]::Parse($nodes[$parentGuid].Tag.Time) -lt [datetimeoffset]::Parse($node.Tag.Time)) {
            [void]$nodes[$parentGuid].Nodes.Add($node)
        } else { $node.Text+=' (parent outside retained view or unavailable)';[void]$tree.Nodes.Add($node) }
    }
    $tree.EndUpdate()
}
$tree.Add_AfterSelect({ $script:detail.Text=ConvertTo-Json -InputObject $tree.SelectedNode.Tag -Depth 8 })
$tree.Add_NodeMouseDoubleClick({
    [void][System.Windows.Forms.MessageBox]::Show((ConvertTo-Json -InputObject $tree.SelectedNode.Tag -Depth 8),'Process details')
})
$search.Add_TextChanged({Show-Recent})
function Run-Mode([string]$mode){
    $helper=Join-Path $script:base 'CCDC-BlueTeam.ps1'
    $arguments='-NoProfile -ExecutionPolicy Bypass -File "'+$helper+'" -Mode '+$mode+' -Role '+$script:role+' -OutputDir "'+(Join-Path $env:ProgramData 'CCDC-BlueTeam\Evidence')+'"'
    Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $arguments
}
$bBaseline.Add_Click({Run-Mode 'Baseline'})
$bCheck.Add_Click({Run-Mode 'Check'})
$bExport.Add_Click({Run-Mode 'Export'})
$bDefender.Add_Click({$tabs.SelectedTab=$tHealth})
$bPause.Add_Click({
    $script:paused=-not $script:paused
    $bPause.Text=if($script:paused){'Resume view'}else{'Pause live view'}
    if (-not $script:paused) { Show-Recent }
})
$bAlerts.Add_Click({
    $script:onlyAlerts=-not $script:onlyAlerts
    $bAlerts.Text=if($script:onlyAlerts){'Alerts only: ON'}else{'Alerts only: OFF'}
    Show-Recent
})
# All Windows queries and disk writes execute in a dedicated runspace. UI never waits
# synchronously for a query. A single outstanding batch bounds memory under load.
$worker=[powershell]::Create()
$script:pending=$null;$script:first=$true;$script:batchCount=0;$script:lastHealth=@();$script:smokeStart=Get-Date
$collect={
    param($base,$data,$profilePath,$first)
    $ErrorActionPreference='Stop'
    Import-Module (Join-Path $base 'Monitoring.psm1')
    $profile=Read-CcdcProfile $profilePath
    $history=@();if($first){$history=@(Get-CcdcHistory $data)}
    $batch=Receive-CcdcBatch -DataDirectory $data -Profile $profile
    $tcpRows=@();$extra=@()
    try {
        $names=@{};foreach($p in Get-Process){$names[[string]$p.Id]=$p.ProcessName}
        $tcpRows=@(Get-NetTCPConnection -ErrorAction Stop | Select-Object -First 2000 | ForEach-Object {
            [pscustomobject]@{Local=('['+$_.LocalAddress+']:'+$_.LocalPort);Remote=('['+$_.RemoteAddress+']:'+$_.RemotePort)
                ProcessId=$_.OwningProcess;Process=$names[[string]$_.OwningProcess];State=[string]$_.State}
        })
        $extra+='TCP snapshot: '+$tcpRows.Count+' rows (display cap 2000; short connections may be absent)'
    } catch {$extra+='TCP unavailable: '+$_.Exception.Message}
    # Query Defender once every 30 seconds in the persistent runspace.
    if (-not (Get-Variable defenderTime -ErrorAction SilentlyContinue) -or (Get-Date) -gt $defenderTime.AddSeconds(30)) {
        $defenderTime=Get-Date
        try {$defender=Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | Format-List | Out-String}
        catch {$defender='Defender unavailable: '+$_.Exception.Message}
    }
    [pscustomobject]@{Records=@($history)+@($batch.Records);Health=@($batch.Health)+$extra;Tcp=$tcpRows;Defender=$defender}
}
$timer=New-Object System.Windows.Forms.Timer
$timer.Interval=2000
$timer.Add_Tick({
    if ($script:pending) {
        if (-not $script:pending.IsCompleted) { return }
        try {
            $result=@($worker.EndInvoke($script:pending))
            if ($worker.HadErrors) { throw ($worker.Streams.Error | Out-String) }
            $batch=$result[-1];$script:batchCount++;$script:lastHealth=@($batch.Health)
            foreach ($r in $batch.Records) {
                if (-not $script:seen.Add($r.Key)) { continue }
                $script:recent.Add($r);$script:count++
                if ($r.Severity -ne 'INFO') {$script:alertCount++}
                if ($script:recent.Count -gt 1200) {
                    [void]$script:seen.Remove($script:recent[0].Key);$script:recent.RemoveAt(0)
                }
            }
            $script:counters.Text="Events $script:count | Alerts $script:alertCount"
            $healthBox.Text=($batch.Health -join [Environment]::NewLine)+[Environment]::NewLine+$batch.Defender
            $script:status.Text='Collection active | Recent 1200 rows | UTC evidence, local display | Detection only'
            if (@($batch.Health | Where-Object {$_ -match 'ERROR|UNAVAILABLE|gap|RESET|backlog'}).Count) {
                $script:status.Text='Coverage warning / backlog - see Sources + Defender | Detection only'
            }
            if (-not $script:paused) {
                Show-Recent
                $script:tcp.Rows.Clear()
                foreach($c in $batch.Tcp){[void]$script:tcp.Rows.Add([object[]]@($c.Local,$c.Remote,[string]$c.ProcessId,$c.Process,$c.State))}
            }
        } catch { $script:status.Text='COLLECTION ERROR: '+$_.Exception.Message }
        $script:pending=$null
    }
    if ($SmokeTestReport -and ((Get-Date)-$script:smokeStart).TotalSeconds -ge 20) {
        [pscustomobject]@{Batches=$script:batchCount;Events=$script:count;Health=$script:lastHealth;Status=$script:status.Text;Rows=$script:eventGrid.Rows.Count} |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $SmokeTestReport -Encoding UTF8
        $bitmap=New-Object System.Drawing.Bitmap($form.Width,$form.Height)
        try {$form.DrawToBitmap($bitmap,$form.ClientRectangle);$bitmap.Save(($SmokeTestReport+'.png'))} finally {$bitmap.Dispose()}
        $form.Close();return
    }
    $worker.Commands.Clear();$worker.Streams.Error.Clear()
    [void]$worker.AddScript($collect.ToString(),$false).AddArgument($script:base).AddArgument($DataDirectory).AddArgument($ProfilePath).AddArgument($script:first)
    $script:pending=$worker.BeginInvoke();$script:first=$false
})
$form.Add_Shown({$timer.Start()})
$form.Add_FormClosing({$timer.Stop();$timer.Dispose();$worker.Stop();$worker.Dispose()})
[void]$form.ShowDialog()
