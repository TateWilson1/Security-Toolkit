#requires -Version 5.1
<#
CCDC Windows Blue Team - visibility-first helper
Supports Windows PowerShell 5.1 on Windows Server 2019/2022.
Actions:
  Baseline: read-only inventory and firewall policy backup (no firewall changes)
  Check:    local scored-service smoke checks (does not prove remote scoring)
  Logging:  explicitly enable process/logon/account auditing + PowerShell logging
  Sysmon:   explicitly install/update Sysmon using adjacent ccdc-sysmon.xml
  Watch:    continuously show new Windows/Sysmon events + sampled live TCP connections
  Export:   export recent events to CSV for incident reporting
No mode blocks IPs, disables users, stops services, or isolates the machine.
Run locally as Administrator. The watcher's CSV may contain credentials typed
on command lines or into scripts: treat the output as sensitive evidence.
#>
[CmdletBinding()]
param(
    [ValidateSet('Baseline','Check','Logging','Sysmon','Watch','Export')]
    [string]$Mode = 'Baseline',
    [ValidateSet('AD','MSSQL','Other')]
    [string]$Role = 'Other',
    [string]$OutputDir = 'C:\CCDC',
    [string]$SysmonExe = 'C:\Tools\Sysmon64.exe',
    [string]$SysmonConfig = (Join-Path $PSScriptRoot 'ccdc-sysmon.xml'),
    [int]$PollSeconds = 2,
    [int]$ExportMinutes = 60,
    [switch]$NoBeep
)
$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run Windows PowerShell as Administrator on the target server.'
    }
}
function Save-Csv {
    param([string]$Name, [scriptblock]$Body, [string]$TargetFolder)
    try {
        $path = Join-Path $TargetFolder ("{0}.csv" -f $Name)
        @(& $Body) | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
        Write-Host "Saved: $path" -ForegroundColor Green
    } catch { Write-Warning ("Could not collect {0}: {1}" -f $Name,$_.Exception.Message) }
}
function Save-Text {
    param([string]$Name, [scriptblock]$Body, [string]$TargetFolder)
    try {
        $path = Join-Path $TargetFolder ("{0}.txt" -f $Name)
        & $Body | Out-File -FilePath $path -Encoding UTF8 -Width 300
        Write-Host "Saved: $path" -ForegroundColor Green
    } catch { Write-Warning ("Could not collect {0}: {1}" -f $Name,$_.Exception.Message) }
}
function Get-DataMap {
    param([System.Diagnostics.Eventing.Reader.EventRecord]$Event)
    $data = @{}
    try {
        [xml]$xml = $Event.ToXml()
        foreach ($node in @($xml.Event.EventData.Data)) {
            if ($null -ne $node -and $node.Name) {
                $data[[string]$node.Name] = [string]$node.'#text'
            }
        }
    } catch {}
    return $data
}
function Get-Value {
    param([hashtable]$Map, [string]$Key)
    if ($Map.ContainsKey($Key) -and $null -ne $Map[$Key]) { return [string]$Map[$Key] }
    return ''
}
function Test-LocalPort {
    param([string]$Service, [int]$Port)
    $result = $false
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect('127.0.0.1',$Port,$null,$null)
        if ($async.AsyncWaitHandle.WaitOne(1250,$false)) {
            try { $client.EndConnect($async); $result = $true } catch {}
        }
        $client.Close()
    } catch {}
    [pscustomobject]@{ Service=$Service; Port=$Port; LocalTCPListener=$result }
}

Assert-Administrator
if (-not (Test-Path -LiteralPath $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
Write-Host "CCDC Windows Blue Team | $Mode | $Role | $env:COMPUTERNAME" -ForegroundColor Cyan

switch ($Mode) {
    Baseline {
        $folder = Join-Path $OutputDir ("baseline-{0}-{1}" -f $env:COMPUTERNAME,$stamp)
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Save-Csv 'ip-addresses' { Get-NetIPAddress | Select-Object IPAddress,InterfaceAlias,AddressFamily,PrefixLength,PrefixOrigin } $folder
        Save-Csv 'dns-resolvers' { Get-DnsClientServerAddress | Select-Object InterfaceAlias,AddressFamily,@{N='ServerAddresses';E={$_.ServerAddresses -join ';'}} } $folder
        Save-Csv 'routes' { Get-NetRoute -AddressFamily IPv4 | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric } $folder
        Save-Csv 'tcp-listeners' { Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess } $folder
        Save-Csv 'tcp-connections' { Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess } $folder
        Save-Csv 'udp-listeners' { Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess } $folder
        Save-Csv 'processes' { Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine } $folder
        Save-Csv 'services' { Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName } $folder
        Save-Csv 'firewall-profiles' { Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogBlocked,LogAllowed } $folder
        Save-Csv 'firewall-rules' { Get-NetFirewallRule | Select-Object Name,DisplayName,Enabled,Profile,Direction,Action } $folder
        Save-Csv 'scheduled-tasks' {
            Get-ScheduledTask | Select-Object TaskPath,TaskName,State,Author,@{N='Action';E={($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '}}
        } $folder
        Save-Csv 'startup-commands' { Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User } $folder
        Save-Text 'host-and-network' { hostname; ipconfig /all; route print; netsh advfirewall show allprofiles } $folder
        Save-Text 'audit-policy' { auditpol.exe /get /category:* } $folder
        Save-Text 'defender-status' {
            if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) { Get-MpComputerStatus | Format-List * } else { 'Defender cmdlets unavailable' }
        } $folder
        try {
            & netsh.exe advfirewall export (Join-Path $folder 'firewall-before-changes.wfw') | Out-Null
            Write-Host 'Exported firewall policy for recovery.' -ForegroundColor Green
        } catch { Write-Warning "Firewall policy export failed: $_" }
        if ($Role -eq 'AD') {
            if (Get-Module -ListAvailable ActiveDirectory) {
                try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Warning "Could not load ActiveDirectory module: $_" }
                if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {
                    Save-Text 'ad-domain' { Get-ADDomain | Format-List * } $folder
                    Save-Csv 'ad-users' {
                        Get-ADUser -Filter * -Properties Enabled,PasswordNeverExpires,PasswordNotRequired,DoesNotRequirePreAuth,AdminCount,LastLogonDate |
                        Select-Object SamAccountName,Enabled,PasswordNeverExpires,PasswordNotRequired,DoesNotRequirePreAuth,AdminCount,LastLogonDate
                    } $folder
                    Save-Csv 'domain-admins' { Get-ADGroupMember 'Domain Admins' -Recursive | Select-Object Name,SamAccountName,ObjectClass,DistinguishedName } $folder
                    Save-Csv 'enterprise-admins' { Get-ADGroupMember 'Enterprise Admins' -Recursive | Select-Object Name,SamAccountName,ObjectClass,DistinguishedName } $folder
                }
            }
        }
        @'
# Incident notes - copy for each suspicious event
Incident ID:
Time + timezone:
Host:
Source IP / source port:
Destination IP / destination port:
User / logon type:
Process image / PID / Process GUID:
Parent process / full command line:
Evidence files + event record IDs:
Observed effect on scoring / business service:
Response and timestamp:
Retest result from scoring portal:
'@ | Set-Content -Path (Join-Path $folder 'incident-template.md') -Encoding UTF8
        Write-Host "BASELINE COMPLETE: $folder" -ForegroundColor Green
        break
    }
    Check {
        $services = if ($Role -eq 'AD') { @(
            [pscustomobject]@{Service='WinRM';Port=5985},
            [pscustomobject]@{Service='DNS-TCP';Port=53},
            [pscustomobject]@{Service='SMB';Port=445}
        ) } elseif ($Role -eq 'MSSQL') { @(
            [pscustomobject]@{Service='SQL';Port=1433},
            [pscustomobject]@{Service='SMB';Port=445},
            [pscustomobject]@{Service='RDP';Port=3389}
        ) } else { @(
            [pscustomobject]@{Service='WinRM';Port=5985},
            [pscustomobject]@{Service='HTTP';Port=80},
            [pscustomobject]@{Service='HTTPS';Port=443}
        ) }
        $checks = foreach ($s in $services) { Test-LocalPort -Service $s.Service -Port $s.Port }
        $checks | Format-Table -AutoSize
        if ($Role -eq 'AD') {
            try { Test-WSMan -ComputerName localhost | Out-String | Write-Host } catch { Write-Warning "Local WinRM test failed: $_" }
            try { Get-Service DNS,WinRM,NTDS,Netlogon -ErrorAction SilentlyContinue | Format-Table Name,Status,StartType } catch {}
        }
        if ($Role -eq 'MSSQL') {
            try { Get-Service MSSQLSERVER,TermService,LanmanServer -ErrorAction SilentlyContinue | Format-Table Name,Status,StartType } catch {}
        }
        Write-Warning 'Local port checks do NOT prove scoring authentication, content, or remote reachability. Confirm on the live team portal.'
        break
    }
    Logging {
        Write-Warning 'This mode changes auditing/PowerShell logging only. It does NOT change users, networking, services or firewall rules.'
        $subcategories = @(
            @{Name='Process Creation';Failure=$false},
            @{Name='Logon';Failure=$true},
            @{Name='User Account Management';Failure=$true},
            @{Name='Security Group Management';Failure=$true},
            @{Name='Special Logon';Failure=$false}
        )
        foreach ($s in $subcategories) {
            $args = @('/set',('/subcategory:{0}' -f $s.Name),'/success:enable')
            if ($s.Failure) { $args += '/failure:enable' }
            & auditpol.exe @args | Out-Host
            if ($LASTEXITCODE -ne 0) { Write-Warning "auditpol failed for: $($s.Name). Configure through GPO instead if centrally managed." }
        }
        $auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
        New-Item -Path $auditKey -Force | Out-Null
        New-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -PropertyType DWord -Force | Out-Null
        $psKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        New-Item -Path $psKey -Force | Out-Null
        New-ItemProperty -Path $psKey -Name 'EnableScriptBlockLogging' -Value 1 -PropertyType DWord -Force | Out-Null
        Write-Host 'Logging enabled. Check event IDs 4688 and 4104; GPO can override these settings.' -ForegroundColor Green
        break
    }
    Sysmon {
        if (-not (Test-Path -LiteralPath $SysmonExe)) { throw "Sysmon executable not found: $SysmonExe. Download it from Microsoft's official Sysinternals site." }
        if (-not (Test-Path -LiteralPath $SysmonConfig)) { throw "Sysmon XML config not found: $SysmonConfig (keep the XML beside this script)." }
        $existing = @(Get-Service -Name Sysmon64,Sysmon -ErrorAction SilentlyContinue)
        if ($existing.Count -gt 0) {
            Write-Host 'Sysmon already present; applying CCDC process + network rules.' -ForegroundColor Yellow
            & $SysmonExe -c $SysmonConfig | Out-Host
        } else {
            Write-Host 'Installing Sysmon for connection/process event capture.' -ForegroundColor Yellow
            & $SysmonExe -accepteula -i $SysmonConfig | Out-Host
        }
        if ($LASTEXITCODE -ne 0) { throw "Sysmon command failed with exit code $LASTEXITCODE" }
        Write-Host 'Sysmon configured. The broad event configuration may be noisy on a busy AD server.' -ForegroundColor Green
        break
    }
    Export {
        $folder = Join-Path $OutputDir ("events-{0}-{1}" -f $env:COMPUTERNAME,$stamp)
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $start = (Get-Date).AddMinutes(-[Math]::Abs($ExportMinutes))
        foreach ($channel in @(
            @{Label='sysmon';Log='Microsoft-Windows-Sysmon/Operational';Ids=@(1,3,5,11,22)},
            @{Label='security';Log='Security';Ids=@(4624,4625,4688,4720,4722,4725,4728,4732,4738,4740,1102)},
            @{Label='powershell';Log='Microsoft-Windows-PowerShell/Operational';Ids=@(4104)}
        )) {
            try {
                $records = @(Get-WinEvent -FilterHashtable @{LogName=$channel.Log;Id=$channel.Ids;StartTime=$start} -MaxEvents 25000 -ErrorAction Stop)
                $rows = foreach ($ev in $records) {
                    [pscustomobject]@{ Time=$ev.TimeCreated; Computer=$ev.MachineName; Channel=$channel.Log; EventId=$ev.Id; RecordId=$ev.RecordId; Message=$ev.Message }
                }
                $rows | Export-Csv (Join-Path $folder ("{0}.csv" -f $channel.Label)) -NoTypeInformation -Encoding UTF8
                Write-Host "Exported $($records.Count) $($channel.Label) events" -ForegroundColor Green
            } catch { Write-Warning "Could not export $($channel.Label): $($_.Exception.Message)" }
        }
        Write-Host "EVENT EXPORT: $folder" -ForegroundColor Green
        break
    }
    Watch {
        if ($PollSeconds -lt 1) { $PollSeconds = 1 }
        $outfile = Join-Path $OutputDir ("watch-{0}-{1}.csv" -f $env:COMPUTERNAME,$stamp)
        $subscriptions = @(
            [pscustomobject]@{Log='Microsoft-Windows-Sysmon/Operational';Ids=@(1,3,5);LastId=[long]0},
            [pscustomobject]@{Log='Security';Ids=@(4624,4625,4688,4720,4722,4725,4728,4732,4738,4740,1102);LastId=[long]0},
            [pscustomobject]@{Log='Microsoft-Windows-PowerShell/Operational';Ids=@(4104);LastId=[long]0}
        )
        $enabled = @()
        foreach ($sub in $subscriptions) {
            try {
                $log = Get-WinEvent -ListLog $sub.Log -ErrorAction Stop
                if (-not $log.IsEnabled) { Write-Warning "$($sub.Log) exists but is disabled"; continue }
                $head = Get-WinEvent -LogName $sub.Log -MaxEvents 1 -ErrorAction SilentlyContinue
                if ($head) { $sub.LastId = [long]$head.RecordId }
                $enabled += $sub
                Write-Host "Monitoring $($sub.Log) (new events only)" -ForegroundColor Green
            } catch { Write-Warning "$($sub.Log) unavailable: $($_.Exception.Message)" }
        }
        if (-not ($enabled | Where-Object { $_.Log -like '*Sysmon*' })) {
            Write-Warning 'Sysmon not found: process/network coverage will be incomplete. Run the Sysmon mode first.'
        }
        $previousTcp = @{}
        $rowsSaved = 0
        Write-Host "LIVE: Ctrl+C stops watcher. Full records saved to $outfile" -ForegroundColor Cyan
        Write-Host 'RED=high-signal activity; YELLOW=review; GREY/CYAN=normal telemetry. Alerts are not proof of compromise.' -ForegroundColor Yellow
        while ($true) {
            foreach ($sub in $enabled) {
                try {
                    $idExpr = (($sub.Ids | ForEach-Object { "EventID=$_" }) -join ' or ')
                    $xpath = "*[System[(EventRecordID > $($sub.LastId)) and ($idExpr)]]"
                    $events = @(Get-WinEvent -LogName $sub.Log -FilterXPath $xpath -MaxEvents 2000 -ErrorAction SilentlyContinue | Sort-Object RecordId)
                    if ($events.Count -ge 2000) { Write-Warning "Heavy event volume on $($sub.Log); consider forwarding events to Wazuh for loss-resistant monitoring." }
                    foreach ($ev in $events) {
                        if ([long]$ev.RecordId -le $sub.LastId) { continue }
                        $sub.LastId = [long]$ev.RecordId
                        $d = Get-DataMap $ev
                        $type = 'EVENT'; $severity='INFO'; $image='';$parent='';$cmd='';$source='';$dest='';$port='';$user='';$details=''
                        switch ($ev.Id) {
                            1 {
                                $type='PROCESS'; $image=Get-Value $d 'Image'; $parent=Get-Value $d 'ParentImage'
                                $cmd=Get-Value $d 'CommandLine'; $user=Get-Value $d 'User'
                                if ($image -match '(?i)\\(powershell|pwsh|cmd|mshta|rundll32|regsvr32|certutil|wmic|wscript|cscript|psexec|schtasks|bitsadmin)\.exe$' -or
                                    $parent -match '(?i)\\(wsmprovhost|wmiprvse|w3wp|sqlservr)\.exe$') { $severity='REVIEW' }
                                if ($parent -match '(?i)\\(wsmprovhost|w3wp|sqlservr)\.exe$' -and $image -match '(?i)\\(powershell|pwsh|cmd|mshta|rundll32)\.exe$') { $severity='HIGH' }
                                $details='Sysmon process start'
                            }
                            3 {
                                $type='NETWORK'; $image=Get-Value $d 'Image';$source=(Get-Value $d 'SourceIp')+':'+(Get-Value $d 'SourcePort')
                                $dest=Get-Value $d 'DestinationIp'; $port=Get-Value $d 'DestinationPort';$user=Get-Value $d 'User'
                                $details='Sysmon TCP/UDP connection'
                                if ($image -match '(?i)\\(powershell|pwsh|cmd|mshta|rundll32|certutil)\.exe$') { $severity='REVIEW' }
                            }
                            5 { $type='EXIT';$image=Get-Value $d 'Image';$details='Sysmon process terminated' }
                            4688 {
                                if ($enabled | Where-Object { $_.Log -like '*Sysmon*' }) { continue }
                                $type='PROCESS';$image=Get-Value $d 'NewProcessName';$parent=Get-Value $d 'ParentProcessName'
                                $cmd=Get-Value $d 'CommandLine';$user=Get-Value $d 'SubjectUserName'
                                $details='Windows process start (fallback: Sysmon absent)'
                                if ($image -match '(?i)\\(powershell|pwsh|cmd|mshta|rundll32|regsvr32|certutil|wmic)\.exe$') { $severity='REVIEW' }
                            }
                            4624 {
                                $logonType=Get-Value $d 'LogonType'
                                if ($logonType -notin @('2','3','10')) { continue }
                                $type='LOGIN';$user=Get-Value $d 'TargetUserName';$source=Get-Value $d 'IpAddress'
                                $details="Successful logon type $logonType (can be legitimate scoring)"
                            }
                            4625 {
                                $type='LOGIN-FAILED';$user=Get-Value $d 'TargetUserName';$source=Get-Value $d 'IpAddress';$severity='REVIEW'
                                $details='Failed logon (can be mistyped credentials or service monitor)'
                            }
                            4104 {
                                $type='POWERSHELL';$cmd=Get-Value $d 'ScriptBlockText';$details='Script block recorded'
                                if ($cmd -match '(?i)(frombase64string|downloadstring|invoke-expression|iex\s|encodedcommand|add-mppreference|set-mppreference)') { $severity='REVIEW' }
                            }
                            default {
                                $type='ACCOUNT/SECURITY';$severity='HIGH';$user=Get-Value $d 'TargetUserName';$details="Windows Security Event $($ev.Id)"
                            }
                        }
                        $row = [pscustomobject]@{
                            Time=$ev.TimeCreated.ToString('o'); Host=$env:COMPUTERNAME; Severity=$severity; Type=$type;
                            EventId=$ev.Id;RecordId=$ev.RecordId;Image=$image;Parent=$parent;CommandLine=$cmd;
                            Source=$source;Destination=$dest;DestinationPort=$port;User=$user;Details=$details
                        }
                        if ($rowsSaved -eq 0) { $row | Export-Csv -Path $outfile -NoTypeInformation -Encoding UTF8 }
                        else { $row | Export-Csv -Path $outfile -NoTypeInformation -Encoding UTF8 -Append }
                        $rowsSaved++
                        $c = if ($severity -eq 'HIGH') { 'Red' } elseif ($severity -eq 'REVIEW') { 'Yellow' } else { 'Gray' }
                        $short = if ($type -eq 'NETWORK') { "$source -> ${dest}:$port $image" }
                                 elseif ($type -eq 'LOGIN' -or $type -eq 'LOGIN-FAILED') { "$user from $source $details" }
                                 else { "$image $cmd ($parent) $details" }
                        if ($short.Length -gt 210) { $short = $short.Substring(0,210)+'...' }
                        Write-Host ("{0:HH:mm:ss} [{1}] {2}: {3}" -f $ev.TimeCreated,$severity,$type,$short) -ForegroundColor $c
                        if ($severity -eq 'HIGH' -and -not $NoBeep) { try { [console]::Beep(1000,130) } catch {} }
                    }
                } catch { Write-Warning "Event polling error for $($sub.Log): $($_.Exception.Message)" }
            }
            # Snapshot established TCP sockets to catch currently connected clients, including inbound connections.
            # This is polling, NOT guaranteed to catch short-lived connections; Sysmon 3 provides event history.
            try {
                $nowTcp = @{}
                $tcp = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue)
                foreach ($conn in $tcp) {
                    $key = "$($conn.LocalAddress):$($conn.LocalPort)|$($conn.RemoteAddress):$($conn.RemotePort)|$($conn.OwningProcess)"
                    $nowTcp[$key] = $true
                    if (-not $previousTcp.ContainsKey($key)) {
                        $pname = '(exited)'
                        try { $pname = (Get-Process -Id $conn.OwningProcess -ErrorAction Stop).ProcessName } catch {}
                        Write-Host ("{0:HH:mm:ss} [LIVE TCP] {1}:{2} <-/-> {3}:{4} PID {5} ({6})" -f (Get-Date),$conn.LocalAddress,$conn.LocalPort,$conn.RemoteAddress,$conn.RemotePort,$conn.OwningProcess,$pname) -ForegroundColor Cyan
                    }
                }
                $previousTcp = $nowTcp
            } catch { Write-Warning "TCP snapshot error: $($_.Exception.Message)" }
            Start-Sleep -Seconds $PollSeconds
        }
    }
}