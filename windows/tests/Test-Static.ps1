#requires -Version 5.1
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
foreach($file in Get-ChildItem $root -Recurse -File | Where-Object Extension -in @('.ps1','.psm1')) {
    $tokens=$null;$errors=$null
    $null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw "$($file.Name): $($errors | Out-String)"}
    # Common PS7-only syntax is also caught by parsing in Windows PowerShell CI.
}
[xml]$config=Get-Content (Join-Path $root 'ccdc-sysmon.xml') -Raw
foreach($name in @('ProcessCreate','NetworkConnect','ProcessTerminate')) {
    if($null -eq $config.Sysmon.EventFiltering.$name){throw "Missing Sysmon rule $name"}
}
$manifest=Get-Content (Join-Path $root 'manifest.json') -Raw | ConvertFrom-Json
foreach($entry in $manifest.PSObject.Properties){
    $hash=(Get-FileHash (Join-Path $root $entry.Name) -Algorithm SHA256).Hash
    if($hash -ne $entry.Value){throw "Stale payload hash: $($entry.Name). Run tests/Update-Manifest.ps1"}
}
Write-Host 'PASS: PowerShell parsing, Sysmon XML, all payload hashes'
