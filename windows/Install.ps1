#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidatePattern('^[a-fA-F0-9]{40}$')][string]$Revision,
    [switch]$Diagnostic,
    [switch]$NoLaunch
)
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or $PSVersionTable.PSVersion -lt [version]'5.1') { throw 'Use Windows PowerShell 5.1.' }
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Open Windows PowerShell as Administrator.' }
$os=Get-CimInstance Win32_OperatingSystem
if ($os.ProductType -eq 1 -or [int]$os.BuildNumber -notin @(17763,20348) -or -not [Environment]::Is64BitProcess) {
    throw 'Supported: x64 Windows Server 2019 or 2022, using 64-bit Windows PowerShell.'
}
[Net.ServicePointManager]::SecurityProtocol=[Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$root=Join-Path $env:ProgramData 'CCDC-BlueTeam'
$null=New-Item -Path $root -ItemType Directory -Force
# Reject a redirected install root before operating on it. Replace the root ACL
# entirely so an explicitly granted Users rule cannot survive a repeat installation.
if ((Get-Item -LiteralPath $root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installation root must not be a reparse point.' }
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach($sidText in @('S-1-5-18','S-1-5-32-544')) {
    $sid=New-Object Security.Principal.SecurityIdentifier($sidText)
    $rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $root -AclObject $acl
$lock=$null;$transcribing=$false;$staging=$null
$stamp=(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8)
$log=Join-Path $root ('install-'+$stamp+'.log')
try {
    $lock=[IO.File]::Open((Join-Path $root 'install.lock'),'OpenOrCreate','ReadWrite','None')
    Start-Transcript -Path $log | Out-Null;$transcribing=$true
    if ($Diagnostic) {
        $os | Format-List Caption,Version,BuildNumber
        Get-Service Sysmon,Sysmon64 -ErrorAction SilentlyContinue | Format-Table Name,Status
        foreach($channel in @('Security','System','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational')) {
            try { Get-WinEvent -ListLog $channel -ErrorAction Stop | Select-Object LogName,IsEnabled,RecordCount,MaximumSizeInBytes }
            catch { Write-Warning $_ }
        }
        if(Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue){Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled}
        return
    }
    if (-not $Revision) {
        $commit=Invoke-RestMethod 'https://api.github.com/repos/TateWilson1/Security-Toolkit/commits/main' -Headers @{'User-Agent'='CCDC-BlueTeam'}
        $Revision=[string]$commit.sha
        if ($Revision -notmatch '^[a-f0-9]{40}$') { throw 'Could not resolve repository revision.' }
    }
    $base="https://raw.githubusercontent.com/TateWilson1/Security-Toolkit/$Revision/windows"
    $staging=Join-Path $root ('staging-'+$stamp)
    $null=New-Item -ItemType Directory -Path $staging
    $manifestPath=Join-Path $staging 'manifest.json'
    Invoke-WebRequest "$base/manifest.json" -UseBasicParsing -OutFile $manifestPath
    $manifest=Get-Content $manifestPath -Raw | ConvertFrom-Json
    $required=@('Firewall.ps1','Firewall.psm1','AD-Assessment.ps1','CCDC-BlueTeam.ps1','Dashboard.ps1','Monitoring.psm1','ccdc-sysmon.xml','profile.default.json','README.md','CCDC-Playbook.md','Install.ps1','TESTING.md')
    foreach($name in $required) {
        $entry=$manifest.PSObject.Properties[$name]
        if (-not $entry -or $entry.Value -notmatch '^[A-Fa-f0-9]{64}$') { throw "Missing or invalid manifest hash for $name" }
        $file=Join-Path $staging $name
        Invoke-WebRequest "$base/$name" -UseBasicParsing -OutFile $file
        if ((Get-FileHash $file -Algorithm SHA256).Hash -ne $entry.Value) { throw "Hash mismatch: $name" }
        if ($name -match '\.ps(m)?1$') {
            $tokens=$null;$errors=$null
            $null=[Management.Automation.Language.Parser]::ParseFile($file,[ref]$tokens,[ref]$errors)
            if ($errors.Count) { throw "Invalid PowerShell: $name - $errors" }
        }
    }
    $null=[xml](Get-Content (Join-Path $staging 'ccdc-sysmon.xml') -Raw)
    Import-Module (Join-Path $staging 'Monitoring.psm1') -Force
    $null=Read-CcdcProfile (Join-Path $staging 'profile.default.json')
    $evidence=Join-Path $root 'Evidence';$null=New-Item -ItemType Directory -Path $evidence -Force
    $backup=Join-Path $evidence ('preinstall-'+$stamp);$null=New-Item -ItemType Directory -Path $backup
    & auditpol.exe /backup ("/file:"+(Join-Path $backup 'audit-policy.csv')) | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Audit policy backup failed; no logging changes made.' }
    # Keep exact value existence/data for targeted recovery without removing sibling policy.
    $settings=@(
        @{Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';Name='ProcessCreationIncludeCmdLine_Enabled'},
        @{Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';Name='EnableScriptBlockLogging'}
    )
    $policy=@(foreach($s in $settings){
        $key=Get-Item -LiteralPath $s.Path -ErrorAction SilentlyContinue
        $exists=$key -and ($key.GetValueNames() -contains $s.Name)
        [pscustomobject]@{Path=$s.Path;Name=$s.Name;Exists=[bool]$exists;Value=$(if($exists){$key.GetValue($s.Name)}else{$null})}
    })
    $policy | ConvertTo-Json | Set-Content (Join-Path $backup 'registry-values.json') -Encoding UTF8
    $role='Other';if((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4){$role='AD'}
    elseif(Get-Service MSSQLSERVER -ErrorAction SilentlyContinue){$role='MSSQL'}
    $helper=Join-Path $staging 'CCDC-BlueTeam.ps1'
    & $helper -Mode Baseline -Role $role -OutputDir $evidence
    & $helper -Mode Logging -Role $role -OutputDir $evidence
    $existing=@(Get-Service Sysmon64,Sysmon -ErrorAction SilentlyContinue)
    if ($existing.Count) {
        Write-Warning 'Existing Sysmon configuration preserved; coverage depends on its rules. Verify events 1, 3 and 5 in the dashboard.'
        if (@($existing | Where-Object Status -ne 'Running').Count) { throw 'Existing Sysmon is stopped; investigate without silently changing it.' }
    } else {
        $sysFolder=Join-Path $staging 'Sysmon';$null=New-Item -ItemType Directory -Path $sysFolder
        $archive=Join-Path $sysFolder 'Sysmon.zip'
        Invoke-WebRequest 'https://download.sysinternals.com/files/Sysmon.zip' -UseBasicParsing -OutFile $archive
        Expand-Archive -LiteralPath $archive -DestinationPath $sysFolder
        $exe=Join-Path $sysFolder 'Sysmon64.exe'
        & $helper -Mode Sysmon -SysmonExe $exe -SysmonConfig (Join-Path $staging 'ccdc-sysmon.xml') -OutputDir $evidence
        if (-not @(Get-Service Sysmon64 -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running').Count) { throw 'Sysmon service is not running.' }
    }
    # Activate only a completely downloaded/validated payload; keep previous versions.
    $versions=Join-Path $root 'Versions';$null=New-Item -ItemType Directory -Path $versions -Force
    $version=Join-Path $versions ($Revision+'-'+$stamp)
    Move-Item -LiteralPath $staging -Destination $version;$staging=$null
    $profile=Join-Path $root 'profile.json'
    if (-not (Test-Path $profile)) { Copy-Item (Join-Path $version 'profile.default.json') $profile }
    $null=Read-CcdcProfile $profile
    $dashboard=Join-Path $version 'Dashboard.ps1'
    $arguments='-NoProfile -ExecutionPolicy Bypass -STA -File "'+$dashboard+'" -ProfilePath "'+$profile+'"'
    $shell=New-Object -ComObject WScript.Shell
    $shortcut=$shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'CCDC Blue Team.lnk'))
    $shortcut.TargetPath="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $shortcut.Arguments=$arguments;$shortcut.WorkingDirectory=$version
    $shortcut.Save()
    $version | Set-Content (Join-Path $root 'current-version.txt')
    if (-not $NoLaunch) {
        Add-Type -AssemblyName System.Windows.Forms
        $child=Start-Process $shortcut.TargetPath -ArgumentList $arguments -WorkingDirectory $version -PassThru
        if ($child.WaitForExit(4000)) { throw "Dashboard exited during startup, code $($child.ExitCode). Run it directly to diagnose." }
    }
    Write-Host "Installed revision $Revision. Evidence: $evidence. Log: $log" -ForegroundColor Green
    Write-Host 'Verify source health and Defender in the dashboard. Installation does not prove complete telemetry coverage.'
} catch {
    Write-Error "INSTALLATION INCOMPLETE: $($_.Exception.Message). Log: $log. Existing evidence is retained; logging changes may already be applied. See README recovery instructions." -ErrorAction Continue
    throw
} finally {
    if($transcribing){Stop-Transcript | Out-Null}
    if($lock){$lock.Dispose()}
    # Retain failed staging for diagnosis; never delete evidence or previous versions.
}
