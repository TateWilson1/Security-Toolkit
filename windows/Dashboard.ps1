#requires -Version 5.1
# CCDC Windows Server dashboard. Uses Sysmon + Windows Event Logs + live TCP snapshots.
# Monitoring never triggers containment. Firewall changes require explicit operator approval.
[CmdletBinding()]
param(
    [string]$DataDirectory = (Join-Path $env:ProgramData 'CCDC-BlueTeam\Evidence\Telemetry'),
    [string]$ProfilePath = (Join-Path $env:ProgramData 'CCDC-BlueTeam\profile.json'),
    [string]$SmokeTestReport
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path $ProfilePath)) { $ProfilePath=Join-Path $PSScriptRoot 'profile.default.json' }
Import-Module (Join-Path $PSScriptRoot 'Monitoring.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Firewall.psm1') -Force
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
$script:paused = $false
$script:onlyAlerts = $false
$script:count = 0
$script:alertCount = 0
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
$script:counters.Dock='Right';$script:counters.Width=310;$script:counters.TextAlign='MiddleRight'
$top.Controls.Add($script:counters)
$tabs=New-Object System.Windows.Forms.TabControl
$tabs.Dock='Fill';$tabs.Font=[System.Drawing.Font]::new('Segoe UI',10)
$form.Controls.Add($tabs);$tabs.BringToFront();$form.Controls.SetChildIndex($top,2)
function New-Tab([string]$label) {
    $t=New-Object System.Windows.Forms.TabPage;$t.Text=$label;$t.BackColor=$bg
    [void]$tabs.TabPages.Add($t)
    return $t
}
$tOverview=New-Tab 'START HERE'
$overviewPanel=New-Object System.Windows.Forms.Panel
$overviewPanel.Dock='Top';$overviewPanel.Height=118
$overviewTitle=New-Object System.Windows.Forms.Label
$overviewTitle.Dock='Top';$overviewTitle.Height=40;$overviewTitle.Text='Starting monitoring...'
$overviewTitle.Font=[System.Drawing.Font]::new('Segoe UI',17,[System.Drawing.FontStyle]::Bold)
$coverage=New-Object System.Windows.Forms.Label
$coverage.Dock='Top';$coverage.Height=36;$coverage.ForeColor=$amber
$coverage.Text='Checking visibility. A quiet screen does not prove a server is safe.'
$legend=New-Object System.Windows.Forms.Label
$legend.Dock='Top';$legend.Height=32;$legend.ForeColor=$fg
$legend.Text='RED: Investigate first    |    AMBER: Review with a teammate    |    GREEN: No rule matched (not verified safe)'
$overviewPanel.Controls.Add($legend);$overviewPanel.Controls.Add($coverage);$overviewPanel.Controls.Add($overviewTitle)
$overviewSplit=New-Object System.Windows.Forms.SplitContainer
$overviewSplit.Dock='Fill';$overviewSplit.Orientation='Horizontal';$overviewSplit.Size=[System.Drawing.Size]::new(1200,500);$overviewSplit.SplitterDistance=260
$overviewGrid=New-Object System.Windows.Forms.DataGridView
$overviewText=New-Object System.Windows.Forms.TextBox
$overviewText.Dock='Fill';$overviewText.Multiline=$true;$overviewText.ReadOnly=$true;$overviewText.ScrollBars='Both'
$overviewText.BackColor=$bg;$overviewText.ForeColor=$fg;$overviewText.Font=[System.Drawing.Font]::new('Segoe UI',11)
$overviewText.Text='Choose an item above. Start with red, then amber. Read why it was flagged and check with a teammate before responding.'
$overviewSplit.Panel1.Controls.Add($overviewGrid);$overviewSplit.Panel2.Controls.Add($overviewText)
$tOverview.Controls.Add($overviewSplit);$tOverview.Controls.Add($overviewPanel)
$tFirewall=New-Tab 'Firewall controls'
$fwPanel=New-Object System.Windows.Forms.FlowLayoutPanel
$fwPanel.Dock='Top';$fwPanel.Height=150;$fwPanel.AutoScroll=$true
$fwPanel.ForeColor=$fg
function New-FirewallLabel([string]$text){$l=New-Object System.Windows.Forms.Label;$l.Text=$text;$l.AutoSize=$true;$l.Margin=[System.Windows.Forms.Padding]::new(8,10,3,3);$fwPanel.Controls.Add($l)}
New-FirewallLabel 'Service'
$fwPreset=New-Object System.Windows.Forms.ComboBox;$fwPreset.DropDownStyle='DropDownList';$fwPreset.Width=180
$fwPresets=@(Get-CcdcFirewallPresets);foreach($p in $fwPresets){[void]$fwPreset.Items.Add($p.Name)};$fwPanel.Controls.Add($fwPreset)
New-FirewallLabel 'Action'
$fwAction=New-Object System.Windows.Forms.ComboBox;$fwAction.DropDownStyle='DropDownList';$fwAction.Width=80
$fwAction.Items.AddRange([object[]]@('Allow','Block'));$fwAction.SelectedIndex=0;$fwPanel.Controls.Add($fwAction)
New-FirewallLabel 'Ports'
$fwPorts=New-Object System.Windows.Forms.TextBox;$fwPorts.Width=100;$fwPanel.Controls.Add($fwPorts)
New-FirewallLabel 'Protocol'
$fwProtocol=New-Object System.Windows.Forms.ComboBox;$fwProtocol.DropDownStyle='DropDownList';$fwProtocol.Width=80
$fwProtocol.Items.AddRange([object[]]@('TCP','UDP','Both'));$fwProtocol.SelectedIndex=0;$fwPanel.Controls.Add($fwProtocol)
New-FirewallLabel 'Remote IP (or Any)'
$fwRemote=New-Object System.Windows.Forms.TextBox;$fwRemote.Text='Any';$fwRemote.Width=160;$fwPanel.Controls.Add($fwRemote)
New-FirewallLabel 'Direction'
$fwDirection=New-Object System.Windows.Forms.ComboBox;$fwDirection.DropDownStyle='DropDownList';$fwDirection.Width=100
$fwDirection.Items.AddRange([object[]]@('Inbound','Outbound'));$fwDirection.SelectedIndex=0;$fwPanel.Controls.Add($fwDirection)
New-FirewallLabel 'Windows network profile'
$fwNetwork=New-Object System.Windows.Forms.ComboBox;$fwNetwork.DropDownStyle='DropDownList';$fwNetwork.Width=95
$fwNetwork.Items.AddRange([object[]]@('Any','Domain','Private','Public'));$fwNetwork.SelectedIndex=0;$fwPanel.Controls.Add($fwNetwork)
$fwApply=New-Object System.Windows.Forms.Button;$fwApply.Text='Review and apply';$fwApply.AutoSize=$true;$fwPanel.Controls.Add($fwApply)
$fwUndo=New-Object System.Windows.Forms.Button;$fwUndo.Text='Undo selected toolkit rule';$fwUndo.AutoSize=$true;$fwPanel.Controls.Add($fwUndo)
$fwPreset.Add_SelectedIndexChanged({$preset=$fwPresets[$fwPreset.SelectedIndex];$fwPorts.Text=$preset.Ports;$fwProtocol.SelectedItem=$preset.Protocol})
$fwPreset.SelectedIndex=0
$fwStatus=New-Object System.Windows.Forms.TextBox
$fwStatus.Dock='Bottom';$fwStatus.Height=125;$fwStatus.Multiline=$true;$fwStatus.ReadOnly=$true
$fwStatus.BackColor=$bg;$fwStatus.ForeColor=$fg;$fwStatus.ScrollBars='Vertical'
$fwStatus.Text='No firewall changes occur until you review and explicitly approve a rule. Existing block rules take precedence over allow rules. Verify remote scoring after each change.'
$fwGrid=New-Object System.Windows.Forms.DataGridView
$fwGrid.Dock='Fill';$fwGrid.ReadOnly=$true;$fwGrid.AllowUserToAddRows=$false;$fwGrid.SelectionMode='FullRowSelect';$fwGrid.MultiSelect=$false
$fwGrid.AutoSizeColumnsMode='Fill';$fwGrid.RowHeadersVisible=$false
foreach($name in @('Action','Direction','Ports','Protocol','Remote','Profile','Enabled')){[void]$fwGrid.Columns.Add($name,$name)}
$tFirewall.Controls.Add($fwGrid);$tFirewall.Controls.Add($fwStatus);$tFirewall.Controls.Add($fwPanel)
$script:firewallRequest=$null
$fwApply.Add_Click({
    try{
        $fresh=Read-CcdcProfile $ProfilePath
        $plan=New-CcdcFirewallPlan -Action $fwAction.SelectedItem -Ports $fwPorts.Text -RemoteAddress $fwRemote.Text -Protocol $fwProtocol.SelectedItem -Direction $fwDirection.SelectedItem -NetworkProfile $fwNetwork.SelectedItem -Role $script:role -Profile $fresh
        $message=$plan.Summary+[Environment]::NewLine+'This changes Windows Firewall on this server. Existing block rules may override Allow.'
        if($plan.ScoringRisk){$message+=[Environment]::NewLine+'SCORING RISK: confirm required services, management/scoring addresses and recovery before proceeding.'}
        $message+=[Environment]::NewLine+'Apply this scoped change? Verify live scoring immediately afterward.'
        if([System.Windows.Forms.MessageBox]::Show($message,'Approve firewall change','YesNo','Warning') -ne 'Yes'){return}
        $script:firewallRequest=[pscustomobject]@{Mode='Add';Action=$plan.Action;Ports=($plan.Ports -join ',');RemoteAddress=$plan.RemoteAddress
            Protocol=[string]$fwProtocol.SelectedItem;Direction=$plan.Direction;NetworkProfile=$plan.NetworkProfile;Role=$script:role}
        $fwApply.Enabled=$false;$fwUndo.Enabled=$false;$fwStatus.Text='Applying the approved rule. Recovery is saved under Evidence\Firewall.'
    }catch{[void][System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Rule was not applied','OK','Warning')}
})
$fwUndo.Add_Click({
    if(-not $fwGrid.CurrentRow -or -not $fwGrid.CurrentRow.Tag){return}
    $name=[string]$fwGrid.CurrentRow.Tag
    if([System.Windows.Forms.MessageBox]::Show(('Remove only rule '+$name+'? Existing Windows rules will remain. Recheck scoring afterward.'),'Approve undo','YesNo','Warning') -ne 'Yes'){return}
    $script:firewallRequest=[pscustomobject]@{Mode='Undo';Name=$name}
    $fwApply.Enabled=$false;$fwUndo.Enabled=$false;$fwStatus.Text='Undoing the approved toolkit rule.'
})
$tAd=New-Tab 'Active Directory'
$adText=New-Object System.Windows.Forms.TextBox
$adText.Dock='Fill';$adText.Multiline=$true;$adText.ReadOnly=$true;$adText.BackColor=$bg;$adText.ForeColor=$fg
$adText.Font=[System.Drawing.Font]::new('Segoe UI',12)
$adText.Text=@'
ACTIVE DIRECTORY - UNDERSTAND BEFORE CHANGING

Quick AD overview: show privileged membership, risky account settings and password policy.
This collects current AD state directly; it does not depend on Event Logs.

Testimo assessment: optional focused checks for password policy and Kerberos account age.
Requires a reviewed Testimo installation and its dependencies, plus AD access.
No automatic module downloads, full-forest sweep or remediation.

A failed health check is something to review, not proof an account is malicious.
SYSTEM and service accounts can be used by attackers. Account name alone never clears activity.
Scoring can legitimately use WinRM and PowerShell. Confirm changes with a teammate.

Reports open in the local browser and are saved under Evidence\AD.
These assessments are on demand; they are not continuous AD change monitoring.
'@
$adButtons=New-Object System.Windows.Forms.FlowLayoutPanel
$adButtons.Dock='Top';$adButtons.Height=48
foreach($label in @('Quick AD overview','Run focused Testimo checks')){
    $button=New-Object System.Windows.Forms.Button;$button.Text=$label;$button.AutoSize=$true;$button.Height=36
    $adButtons.Controls.Add($button)
    if($label -like 'Quick*'){$adInventory=$button}else{$adTestimo=$button}
}
$tAd.Controls.Add($adText);$tAd.Controls.Add($adButtons)
$tEvent=New-Tab 'Process + Connection Events'
$tTcp=New-Tab 'Live TCP Sessions'
$tArchive=New-Tab 'Search archive'
$archiveSearch=New-Object System.Windows.Forms.TextBox
$archiveSearch.Dock='Top';$archiveSearch.AccessibleName='Search complete JSONL archive (literal JSON text)'
$archiveButton=New-Object System.Windows.Forms.Button
$archiveButton.Dock='Top';$archiveButton.Text='Search all recorded history (latest 1200 matches)'
$archiveGrid=New-Object System.Windows.Forms.DataGridView
$archiveGrid.Dock='Fill';$archiveGrid.ReadOnly=$true;$archiveGrid.AllowUserToAddRows=$false
$archiveGrid.AutoSizeColumnsMode='Fill';$archiveGrid.RowHeadersVisible=$false
foreach($name in @('UTC','Severity','Kind','Image','Command','Source','Destination')){[void]$archiveGrid.Columns.Add($name,$name)}
$tArchive.Controls.Add($archiveGrid);$tArchive.Controls.Add($archiveButton);$tArchive.Controls.Add($archiveSearch)
$archiveGrid.Add_CellDoubleClick({
    if($archiveGrid.CurrentRow){[void][System.Windows.Forms.MessageBox]::Show([string]$archiveGrid.CurrentRow.Tag,'Recorded event')}
})
$script:archiveRequested=$false
$archiveButton.Add_Click({$script:archiveRequested=$true;$archiveButton.Enabled=$false;$archiveButton.Text='Searching archive... (collection resumes after scan)'})
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
Set-Grid $overviewGrid
foreach($column in @(@('Priority','What to do'),@('What','What happened'),@('Why','Why it needs attention'),@('Account','Account (context only)'))){[void]$overviewGrid.Columns.Add($column[0],$column[1])}
$overviewGrid.Columns['Why'].FillWeight=220
function Explain-Event($r){
    $label=if($r.Severity -eq 'HIGH'){'INVESTIGATE FIRST'}elseif($r.Severity -eq 'REVIEW'){'REVIEW WITH A TEAMMATE'}else{'NO RULE MATCHED - KEEP MONITORING'}
    $why=if(@($r.Reasons).Count){$r.Reasons -join [Environment]::NewLine}else{'No detection rule matched. This does not prove the activity is safe.'}
    @(
        $label
        ''
        ('What: '+$r.Kind+' - '+$r.Image)
        ('Why: '+$why)
        ('When (local): '+[datetimeoffset]::Parse($r.Time).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss zzz'))
        ('Account: '+$r.User+' (even SYSTEM or a service account can be compromised)')
        ('Parent: '+$r.ParentImage)
        ('Command: '+$r.CommandLine)
        ('Network: '+$r.SourceIp+':'+$r.SourcePort+' -> '+$r.DestinationIp+':'+$r.DestinationPort)
        ('Observation source: '+$r.Channel)
        ('How it was seen: '+$r.Data.Observation)
        ''
        'NEXT: Check whether a teammate, scoring engine or application was expected to do this.'
        'Save evidence. Ask a teammate before stopping anything. Recheck scoring after any response.'
        ''
        'TECHNICAL EVIDENCE (for detailed investigation):'
        (ConvertTo-Json -InputObject $r -Depth 8)
    ) -join [Environment]::NewLine
}
$overviewGrid.Add_SelectionChanged({if(-not $script:rendering -and $overviewGrid.CurrentRow -and $overviewGrid.CurrentRow.Tag){$overviewText.Text=Explain-Event $overviewGrid.CurrentRow.Tag}})
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
$script:rendering=$false
$script:detail=New-Object System.Windows.Forms.TextBox
$script:detail.Dock='Fill';$script:detail.Multiline=$true;$script:detail.ReadOnly=$true
$script:detail.WordWrap=$false;$script:detail.ScrollBars='Both'
$script:detail.BackColor=$bg;$script:detail.ForeColor=$fg
$script:detail.Font=[System.Drawing.Font]::new('Consolas',9)
$script:detail.Text='Select a timeline event for FULL command line, parent, event record ID, and timestamps.'
$split.Panel2.Controls.Add($script:detail)
$script:eventGrid.Add_SelectionChanged({
    if(-not $script:rendering -and $script:eventGrid.SelectedRows.Count -gt 0 -and $script:eventGrid.SelectedRows[0].Tag){
        $script:detail.Text=Explain-Event $script:eventGrid.SelectedRows[0].Tag
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

Monitoring never disables users, blocks hosts or kills shells.
Firewall controls apply only explicitly approved manual rules.
DNS, SQL and WinRM settings are not changed by monitoring.

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
$instructions.AppendText(([Environment]::NewLine+'CURRENT PROFILE GUARDRAILS'+[Environment]::NewLine+($profile.Safeguards -join [Environment]::NewLine)))
$instructions.AppendText(([Environment]::NewLine+($profile.ScoredServices | Format-Table Role,Service,Protocol,Port,Check -AutoSize | Out-String -Width 150)))
$tNotes.Controls.Add($instructions)
# Search operates on the most recent 1200 retained rows, including replay at startup.
$search=New-Object System.Windows.Forms.TextBox
$search.Dock='Top';$search.BackColor=$surface;$search.ForeColor=$fg
$filterPanel=New-Object System.Windows.Forms.Panel
$filterPanel.Dock='Top';$filterPanel.Height=28
$filterLabel=New-Object System.Windows.Forms.Label
$filterLabel.Text='Filter recent events:';$filterLabel.Dock='Left';$filterLabel.Width=160;$filterLabel.ForeColor=$fg
$search.Dock='Fill';$filterPanel.Controls.Add($search);$filterPanel.Controls.Add($filterLabel)
$tEvent.Controls.Add($filterPanel)
$search.AccessibleName='Search recent events by command, address, user or process'
$script:recent=New-Object 'System.Collections.Generic.List[object]'
$script:seen=New-Object 'System.Collections.Generic.HashSet[string]'
function Show-Recent {
    $selectedKey=''
    if($script:eventGrid.CurrentRow -and $script:eventGrid.CurrentRow.Tag){$selectedKey=$script:eventGrid.CurrentRow.Tag.Key}
    $script:rendering=$true
    try {
    $script:eventGrid.Rows.Clear()
    $overviewGrid.Rows.Clear()
    $selectedIndex=-1
    $high=@($script:recent | Where-Object Severity -eq 'HIGH').Count
    $review=@($script:recent | Where-Object Severity -eq 'REVIEW').Count
    if($high){$overviewTitle.Text="Investigate first: $high red items";$overviewTitle.ForeColor=$red}
    elseif($review){$overviewTitle.Text="Review next: $review amber items";$overviewTitle.ForeColor=$amber}
    else{$overviewTitle.Text='No alerts in the recent window - keep monitoring';$overviewTitle.ForeColor=[System.Drawing.Color]::LightGreen}
    foreach($r in ($script:recent | Where-Object Severity -ne 'INFO' | Sort-Object @{Expression={if($_.Severity -eq 'HIGH'){0}else{1}}},@{Expression='Time';Descending=$true} | Select-Object -First 150)){
        $label=if($r.Severity -eq 'HIGH'){'RED - Investigate first'}else{'AMBER - Review'}
        $i=$overviewGrid.Rows.Add([object[]]@($label,($r.Kind+' '+($r.Image -split '\\')[-1]),($r.Reasons -join '; '),$r.User))
        $overviewGrid.Rows[$i].Tag=$r
        $overviewGrid.Rows[$i].DefaultCellStyle.ForeColor=if($r.Severity -eq 'HIGH'){$red}else{$amber}
    }
    $needle=$search.Text
    foreach ($r in ($script:recent | Sort-Object Time,Channel,RecordId)) {
        if ($script:onlyAlerts -and $r.Severity -eq 'INFO') { continue }
        $details=ConvertTo-Json -InputObject $r -Depth 8
        if ($needle -and $details.IndexOf($needle,[StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $index=$script:eventGrid.Rows.Add([object[]]@(
            ([datetimeoffset]::Parse($r.Time).ToLocalTime().ToString('MM-dd HH:mm:ss')),
            $r.Severity,$r.Kind,($r.Image -split '\\')[-1],($r.ParentImage -split '\\')[-1],
            $(if($r.SourceIp){'['+$r.SourceIp+']:'+$r.SourcePort}else{''}),$(if($r.DestinationIp){'['+$r.DestinationIp+']:'+$r.DestinationPort}else{''}),$r.User))
        $row=$script:eventGrid.Rows[$index];$row.Tag=$r
        if($r.Key -eq $selectedKey){$selectedIndex=$index}
        if ($r.Severity -eq 'HIGH') { $row.DefaultCellStyle.ForeColor=$red }
        elseif ($r.Severity -eq 'REVIEW') { $row.DefaultCellStyle.ForeColor=$amber }
        else {$row.DefaultCellStyle.ForeColor=[System.Drawing.Color]::LightGreen}
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
    $overviewGrid.ClearSelection()
    $script:eventGrid.ClearSelection()
    if($selectedIndex -ge 0){$script:eventGrid.CurrentCell=$script:eventGrid.Rows[$selectedIndex].Cells[0];$script:eventGrid.Rows[$selectedIndex].Selected=$true}
    } finally {$script:rendering=$false}
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
function Run-AdAssessment([string]$mode){
    $path=Join-Path $PSScriptRoot 'AD-Assessment.ps1'
    Start-Process "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList ('-NoExit -NoProfile -ExecutionPolicy Bypass -File "'+$path+'" -Mode '+$mode)
}
$adInventory.Add_Click({Run-AdAssessment 'Inventory'})
$adTestimo.Add_Click({Run-AdAssessment 'Testimo'})
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
$script:pending=$null;$script:first=$true;$script:batchCount=0;$script:hadCollectionError=$false;$script:collectionErrors=New-Object 'System.Collections.Generic.List[string]';$script:lastHealth=@();$script:smokeStart=Get-Date
$collect={
    param($base,$data,$profilePath,$first,$searchArchive,$archiveQuery,$firewallRequest)
    $ErrorActionPreference='Stop'
    Import-Module (Join-Path $base 'Monitoring.psm1')
    $profile=Read-CcdcProfile $profilePath
    Import-Module (Join-Path $base 'Firewall.psm1')
    $firewallResult=''
    if($firewallRequest){
        try{
            $fwEvidence=Join-Path (Split-Path $data -Parent) 'Firewall'
            if($firewallRequest.Mode -eq 'Undo'){
                Undo-CcdcFirewallRule -Name $firewallRequest.Name -EvidenceDirectory $fwEvidence -Approved
                $firewallResult='Removed toolkit rule '+$firewallRequest.Name+'. Recheck live scoring.'
            }else{
                $plan=New-CcdcFirewallPlan -Action $firewallRequest.Action -Ports $firewallRequest.Ports -RemoteAddress $firewallRequest.RemoteAddress -Protocol $firewallRequest.Protocol -Direction $firewallRequest.Direction -NetworkProfile $firewallRequest.NetworkProfile -Role $firewallRequest.Role -Profile $profile
                if($plan.Action -eq 'Block' -and $plan.RemoteAddress -ne 'Any' -and @(Get-NetIPAddress | Where-Object IPAddress -eq $plan.RemoteAddress).Count){throw 'Refusing to block this server own address'}
                $applied=Invoke-CcdcFirewallPlan -Plan $plan -EvidenceDirectory $fwEvidence -Approved -AcknowledgeScoringRisk
                $firewallResult='APPLIED: '+$applied.Summary+'. Recovery: '+$applied.Evidence+'. Recheck live scoring.'
            }
        }catch{$firewallResult='FIREWALL ACTION FAILED: '+$_.Exception.Message}
    }
    if($firewallRequest -or -not(Get-Variable firewallTime -ErrorAction SilentlyContinue) -or (Get-Date) -gt $firewallTime.AddSeconds(15)){
        try{$firewall=Get-CcdcFirewallStatus;$firewallHealth=''}catch{$firewall=$null;$firewallHealth=$_.Exception.Message}
        $firewallTime=Get-Date
    }
    $history=@();if($first){$history=@(Get-CcdcHistory $data)}
    $archive=@();if($searchArchive){$archive=@(Get-CcdcHistory -DataDirectory $data -Query $archiveQuery)}
    $batch=Receive-CcdcBatch -DataDirectory $data -Profile $profile
    $directRows=@();$extra=@()
    if (-not (Get-Variable directTime -ErrorAction SilentlyContinue) -or (Get-Date) -gt $directTime.AddSeconds(5)) {
        $includePersistence=(-not (Get-Variable persistenceTime -ErrorAction SilentlyContinue) -or (Get-Date) -gt $persistenceTime.AddSeconds(30))
        $direct=Get-CcdcDirectState -IncludePersistence:$includePersistence
        $directRows=@(Receive-CcdcDirectState -DataDirectory $data -Profile $profile -Snapshot $direct)
        $directTime=Get-Date;if($includePersistence){$persistenceTime=Get-Date}
    }
    $baselineRows=@();$baselineHealth=@()
    if (-not (Get-Variable registryTime -ErrorAction SilentlyContinue) -or (Get-Date) -gt $registryTime.AddMinutes(15)) {
        $registryResult=Receive-CcdcBaselineScopes -DataDirectory $data -Profile $profile -Scopes @(Get-CcdcRegistryScopes $profile)
        $baselineRows+=@($registryResult.Records);$registryHealth=@($registryResult.Health);$registryTime=Get-Date
    }
    if (-not (Get-Variable accountTime -ErrorAction SilentlyContinue) -or (Get-Date) -gt $accountTime.AddSeconds(60)) {
        try {
            $accountsResult=Receive-CcdcBaselineScopes -DataDirectory $data -Profile $profile -Scopes @(Get-CcdcAccountScopes)
            $baselineRows+=@($accountsResult.Records);$accountHealth=@($accountsResult.Health)
        } catch {$accountHealth=@('Account enumeration UNAVAILABLE/ERROR: '+$_.Exception.Message)}
        $accountTime=Get-Date
    }
    $extra=@($direct.Health)+@($registryHealth)+@($accountHealth)
    $tcpRows=@($direct.Connections | Select-Object -First 2000 | ForEach-Object {
        [pscustomobject]@{Local=('['+$_.LocalAddress+']:'+$_.LocalPort);Remote=('['+$_.RemoteAddress+']:'+$_.RemotePort)
            ProcessId=$_.ProcessId;Process=$_.Image;State=$_.State}
    })
    # Query Defender once every 30 seconds in the persistent runspace.
    if (-not (Get-Variable defenderTime -ErrorAction SilentlyContinue) -or (Get-Date) -gt $defenderTime.AddSeconds(30)) {
        $defenderTime=Get-Date
        try {$defender=Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | Format-List | Out-String}
        catch {$defender='Defender unavailable: '+$_.Exception.Message}
    }
    [pscustomobject]@{Records=@($history)+@($batch.Records)+@($directRows)+@($baselineRows);Health=@($batch.Health)+$extra;Tcp=$tcpRows;Defender=$defender;Archive=$archive;ArchiveSearched=$searchArchive;Firewall=$firewall;FirewallResult=$firewallResult;FirewallHealth=$firewallHealth}
}
$timer=New-Object System.Windows.Forms.Timer
$timer.Interval=2000
$timer.Add_Tick({
    if ($script:pending) {
        if (-not $script:pending.IsCompleted) { return }
        try {
            $result=@($worker.EndInvoke($script:pending))
            # Expected source failures are handled and returned as health warnings.
            # EndInvoke throws unhandled terminating errors; HadErrors also includes
            # deliberately caught/suppressed probe errors and is not a success test.
            $batch=$result[-1];$script:first=$false;$script:batchCount++;$script:lastHealth=@($batch.Health)
            if ($batch.ArchiveSearched) {
                $archiveGrid.Rows.Clear()
                foreach($r in $batch.Archive){
                    $i=$archiveGrid.Rows.Add([object[]]@($r.Time,$r.Severity,$r.Kind,$r.Image,$r.CommandLine,$r.SourceIp,$r.DestinationIp))
                    $archiveGrid.Rows[$i].Tag=ConvertTo-Json -InputObject $r -Depth 8
                }
                $archiveButton.Enabled=$true;$archiveButton.Text='Search complete history (latest 1200 matches)'
            }
            if($batch.FirewallResult){$script:lastFirewallResult=$batch.FirewallResult;$fwApply.Enabled=$true;$fwUndo.Enabled=$true}
            if($batch.Firewall){
                $fwGrid.Rows.Clear()
                foreach($rule in $batch.Firewall.Rules){$i=$fwGrid.Rows.Add([object[]]@($rule.Action,$rule.Direction,$rule.Ports,$rule.Protocol,$rule.Remote,$rule.Profile,$rule.Enabled));$fwGrid.Rows[$i].Tag=$rule.Name}
                $fwStatus.Text=($batch.Firewall.Profiles | ForEach-Object {$_.Name+': enabled='+$_.Enabled+'; default inbound='+$_.DefaultInboundAction+'; default outbound='+$_.DefaultOutboundAction}) -join [Environment]::NewLine
                $fwStatus.AppendText(([Environment]::NewLine+$script:lastFirewallResult+[Environment]::NewLine+'Toolkit rules shown (cap 100). Existing/GPO rules can override these. Verify remote access and live scoring.'))
            }elseif($batch.FirewallHealth){$fwStatus.Text='Firewall status unavailable: '+$batch.FirewallHealth}
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
            $script:status.Text='Monitoring processes, sockets and logs | Account names do not establish trust | Detection only'
            $coverage.Text='Visibility available. Direct snapshots supplement Event Logs; neither proves complete coverage.';$coverage.ForeColor=[System.Drawing.Color]::LightGreen
            if (@($batch.Health | Where-Object {$_ -match 'ERROR|UNAVAILABLE|gap|RESET|backlog|not running|not active|unavailable|not enabled'}).Count) {
                $coverage.Text='VISIBILITY WARNING: open Sources + Defender. Missing data can hide activity.';$coverage.ForeColor=$amber
                $script:status.Text='Coverage warning / backlog - see Sources + Defender | Detection only'
            }
            if (-not $script:paused) {
                Show-Recent
                $script:tcp.Rows.Clear()
                foreach($c in $batch.Tcp){[void]$script:tcp.Rows.Add([object[]]@($c.Local,$c.Remote,[string]$c.ProcessId,$c.Process,$c.State))}
            }
        } catch { $script:hadCollectionError=$true;$fwApply.Enabled=$true;$fwUndo.Enabled=$true;$script:collectionErrors.Add(($_.Exception.Message+' '+$_.ScriptStackTrace));$coverage.Text='MONITORING ERROR - investigate visibility before trusting a quiet screen';$coverage.ForeColor=$red;$script:status.Text='COLLECTION ERROR: '+$_.Exception.Message;$archiveButton.Enabled=$true }
        $script:pending=$null
    }
    if ($SmokeTestReport -and ((Get-Date)-$script:smokeStart).TotalSeconds -ge 20) {
        [pscustomobject]@{Batches=$script:batchCount;HadCollectionError=$script:hadCollectionError;Errors=$script:collectionErrors.ToArray();Events=$script:count;Health=$script:lastHealth;Status=$script:status.Text;Rows=$script:eventGrid.Rows.Count} |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $SmokeTestReport -Encoding UTF8
        $bitmap=New-Object System.Drawing.Bitmap($form.Width,$form.Height)
        try {$form.DrawToBitmap($bitmap,$form.ClientRectangle);$bitmap.Save(($SmokeTestReport+'.png'))} finally {$bitmap.Dispose()}
        $form.Close();return
    }
    $worker.Commands.Clear();$worker.Streams.Error.Clear()
    [void]$worker.AddScript($collect.ToString(),$false).AddArgument($script:base).AddArgument($DataDirectory).AddArgument($ProfilePath).AddArgument($script:first).AddArgument($script:archiveRequested).AddArgument($archiveSearch.Text).AddArgument($script:firewallRequest)
    $script:pending=$worker.BeginInvoke();$script:archiveRequested=$false;$script:firewallRequest=$null
})
$form.Add_Shown({$timer.Start()})
$form.Add_FormClosing({$timer.Stop();$timer.Dispose();$worker.Stop();$worker.Dispose()})
[void]$form.ShowDialog()
