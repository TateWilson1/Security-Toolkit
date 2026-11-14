#requires -Version 5.1
# On-demand AD inventory / optional Testimo. Does not remediate findings.
[CmdletBinding()]
param(
    [ValidateSet('Inventory','Testimo')][string]$Mode='Inventory',
    [string]$OutputDirectory=(Join-Path $env:ProgramData 'CCDC-BlueTeam\Evidence\AD')
)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Desktop'){throw 'Use Windows PowerShell 5.1 with the ActiveDirectory module.'}
Import-Module ActiveDirectory -ErrorAction Stop
$domain=Get-ADDomain -ErrorAction Stop
$folder=Join-Path $OutputDirectory ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
$null=New-Item -ItemType Directory -Path $folder -Force
Start-Transcript -Path (Join-Path $folder 'assessment.log') | Out-Null
try{
    $domain | Select-Object DNSRoot,DomainMode,PDCEmulator,RIDMaster,InfrastructureMaster | ConvertTo-Json | Set-Content (Join-Path $folder 'domain.json')
    if($Mode -eq 'Testimo'){
        # No dependency installation, policy edits, broad default forest scan or -Online.
        # Operator explicitly chooses this heavier assessment after reviewing its modules.
        Import-Module Testimo -ErrorAction Stop
        $sources=@('DomainPasswordComplexity','DomainKerberosAccountAge')
        $available=@(Get-TestimoSources -SourcesOnly)
        foreach($source in $sources){if($source -notin $available){throw "Installed Testimo version does not expose $source. Review its supported sources."}}
        $version=(Get-Module Testimo).Version.ToString()
        [pscustomobject]@{ModuleVersion=$version;Sources=$sources;Domain=$domain.DNSRoot;Time=[datetimeoffset]::UtcNow.ToString('o')} |
            ConvertTo-Json | Set-Content (Join-Path $folder 'testimo-scope.json')
        $report=Join-Path $folder 'Testimo.html'
        $result=Invoke-Testimo -Sources $sources -IncludeDomains $domain.DNSRoot -FilePath $report -HideHTML -PassThru
        $result | Export-Clixml (Join-Path $folder 'Testimo-results.clixml') -Depth 12
        if(-not(Test-Path $report)){throw 'Testimo produced no HTML report. Inspect assessment.log and skipped/unavailable requirements.'}
        # Treat the report as module-produced output, not a verified all-clear assertion.
        Start-Process -FilePath $report
    }else{
        $policy=Get-ADDefaultDomainPasswordPolicy -Identity $domain.DistinguishedName
        $admins=Get-ADGroupMember -Identity ($domain.DomainSID.Value+'-512') -Recursive
        $privileged=@($admins | Select-Object Name,SamAccountName,ObjectClass,DistinguishedName)
        $flagged=@(Get-ADUser -Filter 'Enabled -eq $true' -Properties PasswordNotRequired,DoesNotRequirePreAuth,PasswordNeverExpires |
            Where-Object {$_.PasswordNotRequired -or $_.DoesNotRequirePreAuth -or $_.PasswordNeverExpires} |
            Select-Object SamAccountName,PasswordNotRequired,DoesNotRequirePreAuth,PasswordNeverExpires)
        $policy | Export-Clixml (Join-Path $folder 'password-policy.clixml')
        $privileged | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $folder 'privileged-members.json')
        $flagged | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $folder 'accounts-to-review.json')
        $encode={param($s) [Net.WebUtility]::HtmlEncode([string]$s)}
        $summary=@(
            '<h1>Active Directory: review, then verify</h1>'
            '<p>Read-only inventory. These findings are not proof of compromise. Never bulk-disable unfamiliar users: scoring and services may depend on them.</p>'
            ('<p>Domain: '+(& $encode $domain.DNSRoot)+'</p>')
            '<h2>Amber: accounts with security settings to review</h2>'
            ($flagged | ConvertTo-Html -Fragment | Out-String)
            '<h2>Review privileged membership with a teammate</h2>'
            ($privileged | ConvertTo-Html -Fragment | Out-String)
            '<h2>Password policy</h2>'
            ($policy | Select-Object MinPasswordLength,ComplexityEnabled,ReversibleEncryptionEnabled,LockoutThreshold | ConvertTo-Html -Fragment | Out-String)
            '<p>No settings or accounts were changed. Use the live scoring portal to validate service availability. Skipped/failed collection must not be considered clear.</p>'
        ) -join [Environment]::NewLine
        $report=Join-Path $folder 'AD-overview.html'
        $summary | Set-Content $report -Encoding UTF8
        Start-Process -FilePath $report
    }
    Write-Host "Assessment saved to $folder. Findings require human review."
}finally{Stop-Transcript | Out-Null}
