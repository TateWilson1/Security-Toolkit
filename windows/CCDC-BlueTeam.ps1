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
    [switch]$NoBeep,
    [string]$ProfilePath = (Join-Path $PSScriptRoot 'profile.default.json'),
    [switch]$ReplaceSysmonConfig
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
$stamp = (Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
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
            if ($LASTEXITCODE -ne 0) { throw "netsh firewall export failed, exit $LASTEXITCODE" }
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
        Write-Host "BASELINE CAPTURE FINISHED (review collection warnings): $folder" -ForegroundColor Green
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
            @{Name='{0CCE922B-69AE-11D9-BED3-505054503030}';Failure=$false},
            @{Name='{0CCE922C-69AE-11D9-BED3-505054503030}';Failure=$false},
            @{Name='{0CCE9215-69AE-11D9-BED3-505054503030}';Failure=$true},
            @{Name='{0CCE9235-69AE-11D9-BED3-505054503030}';Failure=$true},
            @{Name='{0CCE9237-69AE-11D9-BED3-505054503030}';Failure=$true},
            @{Name='{0CCE921B-69AE-11D9-BED3-505054503030}';Failure=$false}
        )
        foreach ($s in $subcategories) {
            $args = @('/set',('/subcategory:{0}' -f $s.Name),'/success:enable')
            if ($s.Failure) { $args += '/failure:enable' }
            & auditpol.exe @args | Out-Host
            if ($LASTEXITCODE -ne 0) { throw "auditpol failed for $($s.Name), exit $LASTEXITCODE. Logging setup incomplete; check GPO." }
        }
        # Service/task creation auditing, using locale-independent subcategory GUIDs.
        & auditpol.exe /set '/subcategory:{0CCE9227-69AE-11D9-BED3-505054503030}' /success:enable | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Other Object Access Events auditing failed.' }
        & auditpol.exe /set '/subcategory:{0CCE9211-69AE-11D9-BED3-505054503030}' /success:enable | Out-Host
        if ($LASTEXITCODE -ne 0) { throw 'Security System Extension auditing failed.' }
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
        $signature=Get-AuthenticodeSignature -FilePath $SysmonExe
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') { throw 'Sysmon must have a valid Microsoft signature.' }
        $existing = @(Get-Service -Name Sysmon64,Sysmon -ErrorAction SilentlyContinue)
        if ($existing.Count -gt 0 -and -not $ReplaceSysmonConfig) {
            Write-Warning 'Existing Sysmon configuration preserved. Confirm events 1/3/5 are enabled. Explicit -ReplaceSysmonConfig requires a restorable original XML.'
            break
        }
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
        $results=@()
        foreach ($channel in @('Microsoft-Windows-Sysmon/Operational','Security','System','Microsoft-Windows-WinRM/Operational','Microsoft-Windows-PowerShell/Operational')) {
            $file=Join-Path $folder (($channel -replace '[/\\]','-')+'.evtx')
            # Native EVTX preserves structured fields and avoids CSV formula interpretation.
            $milliseconds=[long][Math]::Abs($ExportMinutes)*60000
            $query="*[System[TimeCreated[timediff(@SystemTime) <= $milliseconds]]]"
            $message=(& wevtutil.exe epl $channel $file "/q:$query" /ow:true 2>&1 | Out-String)
            $code=$LASTEXITCODE
            $results += [pscustomobject]@{Channel=$channel;ExitCode=$code;Message=$message;File=$file}
        }
        $telemetry=Join-Path $OutputDir 'Telemetry'
        if (Test-Path $telemetry) {
            $snapshot=Join-Path $folder 'Telemetry';$null=New-Item -ItemType Directory -Path $snapshot
            # Never copy the live lock handle or a partially-written checkpoint temp file.
            foreach($file in Get-ChildItem -LiteralPath $telemetry -File | Where-Object {$_.Extension -in @('.jsonl','.json')}) {
                Copy-Item -LiteralPath $file.FullName -Destination $snapshot -Force
            }
        }
        $results | ConvertTo-Json | Set-Content (Join-Path $folder 'export-status.json') -Encoding UTF8
        Get-ChildItem $folder -Recurse -File | Where-Object {$_.Name -ne 'SHA256.csv'} |
            Get-FileHash -Algorithm SHA256 | Export-Csv (Join-Path $folder 'SHA256.csv') -NoTypeInformation
        if (@($results | Where-Object {$_.ExitCode -ne 0}).Count) {
            throw "PARTIAL export: $folder. See export-status.json; missing logs may be unavailable."
        }
        Write-Host "EVENT EXPORT: $folder" -ForegroundColor Green
        break
    }
    Watch {
        Import-Module (Join-Path $PSScriptRoot 'Monitoring.psm1') -Force
        $profile=Read-CcdcProfile $ProfilePath
        $data=Join-Path $OutputDir 'Telemetry'
        Write-Host "Collecting into $data; detection only. Ctrl+C stops collection."
        $directTime=[datetime]::MinValue;$persistenceTime=[datetime]::MinValue
        while ($true) {
            $batch=Receive-CcdcBatch -DataDirectory $data -Profile $profile
            $directRows=@()
            if((Get-Date) -gt $directTime.AddSeconds(5)){
                $includePersistence=(Get-Date) -gt $persistenceTime.AddSeconds(30)
                $direct=Get-CcdcDirectState -IncludePersistence:$includePersistence
                $directRows=@(Receive-CcdcDirectState -DataDirectory $data -Profile $profile -Snapshot $direct)
                $direct.Health | Where-Object {$_ -match 'ERROR|UNAVAILABLE|not running'} | ForEach-Object {Write-Warning $_}
                $directTime=Get-Date;if($includePersistence){$persistenceTime=Get-Date}
            }
            foreach ($r in (@($batch.Records)+@($directRows))) {
                $color=if($r.Severity -eq 'HIGH'){'Red'}elseif($r.Severity -eq 'REVIEW'){'Yellow'}else{'Gray'}
                Write-Host ("{0} [{1}] {2} {3} PID {4} {5}" -f $r.Time,$r.Severity,$r.Kind,$r.Image,$r.ProcessId,$r.CommandLine) -ForegroundColor $color
            }
            $batch.Health | Where-Object {$_ -match 'ERROR|UNAVAILABLE|gap|RESET|backlog'} | ForEach-Object {Write-Warning $_}
            Start-Sleep -Seconds ([Math]::Max(1,$PollSeconds))
        }
    }
}
