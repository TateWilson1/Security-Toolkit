#requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$hashes=[ordered]@{}
foreach($name in @('CCDC-BlueTeam.ps1','Dashboard.ps1','Monitoring.psm1','ccdc-sysmon.xml','profile.default.json','README.md','CCDC-Playbook.md','Install.ps1','TESTING.md')) {
    $hashes[$name]=(Get-FileHash (Join-Path $root $name) -Algorithm SHA256).Hash.ToLowerInvariant()
}
[IO.File]::WriteAllText((Join-Path $root 'manifest.json'),(($hashes | ConvertTo-Json)+[Environment]::NewLine),(New-Object Text.UTF8Encoding($false)))
