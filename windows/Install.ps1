#requires -Version 5.1
<#
CCDC Blue Team: one-command Windows Server installer.
Run elevated Windows PowerShell:
irm https://raw.githubusercontent.com/TateWilson1/Security-Toolkit/main/windows/Install.ps1 | iex

Baseline -> audit logging -> Microsoft Sysmon -> GUI.
No accounts, services, firewall rules, or addresses are blocked or modified.
#>
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open Windows PowerShell as Administrator and rerun the command.'
}
if ($PSVersionTable.PSVersion.Major -lt 5) { throw 'Windows PowerShell 5.1 required.' }

$root = Join-Path $env:ProgramData 'CCDC-BlueTeam'
$base = 'https://raw.githubusercontent.com/TateWilson1/Security-Toolkit/main/windows'
$files = @('CCDC-BlueTeam.ps1','Dashboard.ps1','ccdc-sysmon.xml','CCDC-Playbook.md','README.md','Install.ps1')
$staging = Join-Path $env:TEMP ('ccdc-install-'+[guid]::NewGuid().ToString('N'))
New-Item -Path $staging -ItemType Directory -Force | Out-Null

Write-Host 'CCDC BLUE TEAM | Downloading toolkit...' -ForegroundColor Cyan
try {
    # Complete the download before touching existing installation or audit settings.
    foreach ($name in $files) {
        Invoke-WebRequest -Uri ($base+'/'+$name) -UseBasicParsing -OutFile (Join-Path $staging $name) -ErrorAction Stop
        if ((Get-Item (Join-Path $staging $name)).Length -lt 25) { throw "Downloaded file $name is unexpectedly short." }
        Write-Host ('  '+$name)
    }
    if (-not (Select-String -Path (Join-Path $staging 'CCDC-BlueTeam.ps1') -SimpleMatch -Pattern "ValidateSet('Baseline'")) {
        throw 'Downloaded helper failed expected-content validation.'
    }
    $null = [xml](Get-Content (Join-Path $staging 'ccdc-sysmon.xml') -Raw)

    if (-not (Test-Path $root)) { New-Item -Path $root -ItemType Directory -Force | Out-Null }
    foreach ($name in $files) {
        Copy-Item -LiteralPath (Join-Path $staging $name) -Destination (Join-Path $root $name) -Force
    }
} finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
}

$role = 'Other'
try {
    $c = Get-CimInstance Win32_ComputerSystem
    if ($c.DomainRole -ge 4) { $role = 'AD' }
    elseif (Get-Service MSSQLSERVER -ErrorAction SilentlyContinue) { $role = 'MSSQL' }
} catch {}

$helper = Join-Path $root 'CCDC-BlueTeam.ps1'
$evidence = Join-Path $root 'Evidence'
Write-Host "Machine role: $role | Capturing baseline..." -ForegroundColor Yellow
& $helper -Mode Baseline -Role $role -OutputDir $evidence
Write-Host 'Enabling Windows event auditing (processes, logins, PowerShell)...' -ForegroundColor Yellow
& $helper -Mode Logging -Role $role -OutputDir $evidence

# Sysmon is a Microsoft-signed system service, installed with its official package.
# This part is required for process/network event history and will fail loudly.
Write-Host 'Configuring Microsoft Sysmon for process + connection history...' -ForegroundColor Yellow
$sysFolder = Join-Path $root 'Sysmon'
if (-not (Test-Path $sysFolder)) { New-Item $sysFolder -ItemType Directory -Force | Out-Null }
$sysExe = Join-Path $sysFolder 'Sysmon64.exe'
if (-not (Test-Path $sysExe)) {
    $archive = Join-Path $sysFolder 'Sysmon.zip'
    Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -UseBasicParsing -OutFile $archive -ErrorAction Stop
    Expand-Archive -LiteralPath $archive -DestinationPath $sysFolder -Force
}
if (-not (Test-Path $sysExe)) { throw 'Sysmon64.exe not found. Check Microsoft Sysinternals download access.' }
$signature = Get-AuthenticodeSignature -FilePath $sysExe
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
    throw 'Sysmon executable does not have a verified Microsoft code signature.'
}
$config = Join-Path $root 'ccdc-sysmon.xml'
$services = @(Get-Service -Name Sysmon64,Sysmon -ErrorAction SilentlyContinue)
if ($services.Count -gt 0) {
    $oldConfig = Join-Path $evidence ('sysmon-config-before-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.txt')
    & $sysExe -c 2>&1 | Out-File -FilePath $oldConfig -Encoding UTF8
    Write-Host "Existing Sysmon configuration saved to $oldConfig" -ForegroundColor Yellow
}
& $helper -Mode Sysmon -Role $role -OutputDir $evidence -SysmonExe $sysExe -SysmonConfig $config
if (-not @(Get-Service Sysmon64,Sysmon -ErrorAction SilentlyContinue).Count) {
    throw 'Sysmon did not install. The toolkit is not fully operational.'
}

try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    $ws = New-Object -ComObject WScript.Shell
    $link = $ws.CreateShortcut((Join-Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) 'CCDC Blue Team.lnk'))
    $link.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $link.Arguments = '-NoProfile -ExecutionPolicy Bypass -STA -File "'+(Join-Path $root 'Dashboard.ps1')+'"'
    $link.WorkingDirectory = $root
    $link.Save()
    Write-Host 'Opening CCDC live dashboard...' -ForegroundColor Green
    $arguments = '-NoProfile -ExecutionPolicy Bypass -STA -File "'+(Join-Path $root 'Dashboard.ps1')+'"'
    Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList $arguments -WorkingDirectory $root
} catch {
    Write-Warning "Graphical interface could not start (Server Core or GUI issue): $($_.Exception.Message)"
    Write-Host ('Use console monitoring: & "'+$helper+'" -Mode Watch -Role '+$role)
}
Write-Host "Ready. Toolkit: $root | Evidence: $evidence" -ForegroundColor Green
Write-Host 'This is EDR-style monitoring, not guaranteed malware prevention. Defender AV quarantine works separately when active.'
