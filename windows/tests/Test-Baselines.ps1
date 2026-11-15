#requires -Version 5.1
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot '..\Monitoring.psm1') -Force
$p=Read-CcdcProfile (Join-Path $PSScriptRoot '..\profile.default.json')
function Assert($Condition,$Message){if(-not $Condition){throw $Message}}
function Scope($Name,$Kind,$Items){[pscustomobject]@{Name=$Name;Kind=$Kind;Available=$true;Items=@($Items);Error=''}}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('ccdc-baseline-'+[guid]::NewGuid().ToString('N'))
try{
    $initial=Scope 'Registry test' 'REGISTRY' @([pscustomobject]@{Key='Run|Lab';Value='original.exe'})
    $first=Receive-CcdcBaselineScopes $temp $p @($initial)
    Assert ($first.Records.Count -eq 0) 'First snapshot must not claim historical changes'
    $baseline=Get-ChildItem $temp -Filter 'baseline-*.json'
    $hash=(Get-FileHash $baseline.FullName).Hash
    $changed=Scope 'Registry test' 'REGISTRY' @([pscustomobject]@{Key='Run|Lab';Value='changed.exe'})
    $second=Receive-CcdcBaselineScopes $temp $p @($changed)
    Assert ($second.Records.Count -eq 1 -and $second.Records[0].Data.Baseline -eq 'original.exe' -and $second.Records[0].Data.After -eq 'changed.exe') 'Registry drift must retain immutable initial value'
    Assert ((Receive-CcdcBaselineScopes $temp $p @($changed)).Records.Count -eq 0) 'Unchanged drift must not duplicate alerts'
    $reverted=Receive-CcdcBaselineScopes $temp $p @($initial)
    Assert ($reverted.Records.Count -eq 1 -and $reverted.Records[0].Data.After -eq 'original.exe') 'Return to baseline must be recorded'
    $changed.Items[0].Value='ORIGINAL.exe'
    $caseOnly=Receive-CcdcBaselineScopes $temp $p @($changed)
    Assert ($caseOnly.Records.Count -eq 1) 'Case-only registry arguments must not disappear'
    Assert ((Get-FileHash $baseline.FullName).Hash -eq $hash) 'First baseline overwritten'
    $users=Scope 'Local accounts' 'ACCOUNT' @([pscustomobject]@{Key='S-1-5-21-1';Value='existing'})
    $null=Receive-CcdcBaselineScopes $temp $p @($users)
    $users.Items+=([pscustomobject]@{Key='S-1-5-21-2';Value='new-service-account'})
    $added=Receive-CcdcBaselineScopes $temp $p @($users)
    Assert ($added.Records.Count -eq 1 -and $added.Records[0].Data.Change -eq 'Added' -and $added.Records[0].Kind -eq 'ACCOUNT') 'New user must be detected without Event Logs'
    $users.Available=$false;$users.Error='LDAP unavailable';$users.Items=@()
    $failed=Receive-CcdcBaselineScopes $temp $p @($users)
    Assert ($failed.Records.Count -eq 0 -and $failed.Health[0] -match 'UNAVAILABLE') 'Query failure must preserve baseline and not invent deleted users'
    Assert (@(Get-CcdcHistory $temp).Count -eq 4) 'Baseline differences not durably journaled'
}finally{if(Test-Path $temp){Remove-Item $temp -Recurse -Force}}
Write-Host 'PASS: immutable registry baseline, drift/reversion, duplicate suppression, new-account detection without logs, failed enumeration safety'
