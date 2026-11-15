#requires -Version 5.1
function Get-CcdcFirewallPresets {
    @(
        [pscustomobject]@{Name='DNS';Ports='53';Protocol='Both'}
        [pscustomobject]@{Name='WinRM HTTP';Ports='5985';Protocol='TCP'}
        [pscustomobject]@{Name='WinRM HTTPS';Ports='5986';Protocol='TCP'}
        [pscustomobject]@{Name='SMB';Ports='445';Protocol='TCP'}
        [pscustomobject]@{Name='RDP';Ports='3389';Protocol='Both'}
        [pscustomobject]@{Name='SQL Server';Ports='1433';Protocol='TCP'}
        [pscustomobject]@{Name='Web HTTP/HTTPS';Ports='80,443';Protocol='TCP'}
        [pscustomobject]@{Name='SSH';Ports='22';Protocol='TCP'}
        [pscustomobject]@{Name='Splunk management';Ports='8089';Protocol='TCP'}
        [pscustomobject]@{Name='Specific IP (TCP/UDP)';Ports='Any';Protocol='Both'}
        [pscustomobject]@{Name='Custom ports';Ports='';Protocol='TCP'}
    )
}
function New-CcdcFirewallPlan {
    param([ValidateSet('Allow','Block')][string]$Action,[string]$Ports,[string]$RemoteAddress='Any',
        [ValidateSet('TCP','UDP','Both')][string]$Protocol='TCP',[ValidateSet('Inbound','Outbound')][string]$Direction='Inbound',
        [ValidateSet('Any','Domain','Private','Public')][string]$NetworkProfile='Any',
        [ValidateSet('AD','MSSQL','Other')][string]$Role='Other',$Profile)
    $remote=$RemoteAddress.Trim();$parsed=$null
    if($remote -ne 'Any'){
        if(-not [Net.IPAddress]::TryParse($remote,[ref]$parsed)){throw 'Enter one specific IPv4/IPv6 address, or Any. Ranges/hostnames are not accepted.'}
        $remote=$parsed.ToString()
        if([Net.IPAddress]::IsLoopback($parsed) -or $remote -in @('0.0.0.0','::','255.255.255.255')){throw 'Loopback, unspecified and broadcast addresses are not valid containment targets.'}
        $known=@(foreach($address in $Profile.KnownManagementAddresses){$knownIp=$null;if([Net.IPAddress]::TryParse([string]$address,[ref]$knownIp)){$knownIp.ToString()}})
        if($Action -eq 'Block' -and $remote -in $known){throw 'This address is in the management/scoring profile. Verify the profile and service dependency before considering a manual response.'}
    }
    $portList=@()
    if($Ports -eq 'Any'){
        if($remote -eq 'Any'){throw 'A rule covering every port and every address is not supported.'}
        $portList=@('Any')
    }else{
        foreach($value in ($Ports -split ',')){
            $number=0
            if(-not [int]::TryParse($value.Trim(),[ref]$number) -or $number -lt 1 -or $number -gt 65535){throw 'Use specific ports from 1 to 65535, separated by commas.'}
            $portList+=[string]$number
        }
        $portList=@($portList | Sort-Object -Unique)
        if($portList.Count -gt 10){throw 'Use at most 10 explicit ports per change.'}
    }
    $protected=@($Profile.RequiredPorts)
    if($Profile.PSObject.Properties['ScoredServices']){
        foreach($service in $Profile.ScoredServices){foreach($part in ([string]$service.Port -split '[,/]')){
            $servicePort=0;if([int]::TryParse($part.Trim(),[ref]$servicePort) -and $servicePort -ge 1 -and $servicePort -le 65535){$protected+=$servicePort}
        }}
    }
    if($Role -eq 'AD'){$protected+=@(53,88,135,389,445,464,636,3268,3269,5985,5986)}
    $risk=($Ports -eq 'Any' -or @($portList | Where-Object {[int]$_ -in $protected -or ($Role -eq 'AD' -and [int]$_ -ge 49152)}).Count -gt 0)
    if($Action -eq 'Block' -and $remote -eq 'Any' -and $risk){throw 'Broad blocking of a protected/scored service is refused. Select a confirmed attacker IP and verify scoring first.'}
    [pscustomobject]@{Action=$Action;Ports=$portList;RemoteAddress=$remote;Protocols=$(if($Protocol -eq 'Both'){@('TCP','UDP')}else{@($Protocol)})
        Direction=$Direction;NetworkProfile=$NetworkProfile;Role=$Role;ScoringRisk=$risk
        Summary=($Action+' '+$Direction+' '+$Protocol+' port(s) '+($portList -join ',')+' remote '+$remote+' on '+$NetworkProfile)}
}
function Invoke-CcdcFirewallPlan {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param($Plan,[string]$EvidenceDirectory,[switch]$Approved,[switch]$AcknowledgeScoringRisk)
    if(-not $Approved){throw 'Explicit operator approval is required.'}
    if($Plan.ScoringRisk -and -not $AcknowledgeScoringRisk){throw 'Explicit acknowledgement of scored-service risk is required.'}
    if(-not $PSCmdlet.ShouldProcess($Plan.Summary,'Create scoped Windows Firewall rule(s)')){return}
    $null=New-Item -ItemType Directory -Path $EvidenceDirectory -Force
    $id=[guid]::NewGuid().ToString('N');$path=Join-Path $EvidenceDirectory ('firewall-'+$id+'.json')
    $names=@();$planned=@();$index=0
    foreach($protocol in $Plan.Protocols){$planned+=('CCDC-Toolkit-'+$id+'-'+$index);$index++}
    $record=[ordered]@{Time=[datetimeoffset]::UtcNow.ToString('o');Status='Pending';Plan=$Plan;RuleNames=$planned
        Recovery='Remove each named CCDC-Toolkit rule using the GUI Undo button, or Remove-NetFirewallRule -Name <exact-name> after approval. Existing rules/profiles are not reset.'}
    # Recovery record exists before the first mutation, even if the process later crashes.
    $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
    try{
        $index=0
        foreach($protocol in $Plan.Protocols){
            $name=$planned[$index];$index++
            $parameters=@{Name=$name;DisplayName=('CCDC '+$Plan.Summary+' '+$protocol);Group='CCDC Toolkit';PolicyStore='PersistentStore'
                Action=$Plan.Action;Direction=$Plan.Direction;Protocol=$protocol;RemoteAddress=$Plan.RemoteAddress
                Profile=$Plan.NetworkProfile;Enabled='True';Description=('Approved manual change; recovery record '+$path);ErrorAction='Stop'}
            if($Plan.Ports -notcontains 'Any'){if($Plan.Direction -eq 'Inbound'){$parameters.LocalPort=$Plan.Ports}else{$parameters.RemotePort=$Plan.Ports}}
            $null=New-NetFirewallRule @parameters;$names+=$name
        }
        $record.Status='Applied';$record.RuleNames=$names
        $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
        [pscustomobject]@{RuleNames=$names;Evidence=$path;Summary=$Plan.Summary}
    }catch{
        $failure=$_
        $rollbackErrors=@()
        foreach($name in $names){try{Remove-NetFirewallRule -Name $name -PolicyStore PersistentStore -ErrorAction Stop}catch{$rollbackErrors+=$_.Exception.Message}}
        $record.Status='Failed';$record['Error']=$failure.Exception.Message;$record['RollbackErrors']=$rollbackErrors
        $record | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
        throw "Firewall change failed. Recovery record: $path. $($failure.Exception.Message)"
    }
}
function Undo-CcdcFirewallRule {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param([string]$Name,[string]$EvidenceDirectory,[switch]$Approved)
    if(-not $Approved){throw 'Explicit operator approval is required.'}
    if($Name -notmatch '^CCDC-Toolkit-[a-f0-9]{32}-\d+$'){throw 'Undo is limited to individually named toolkit rules.'}
    if($PSCmdlet.ShouldProcess($Name,'Remove toolkit firewall rule')){
        $null=New-Item -ItemType Directory -Path $EvidenceDirectory -Force
        $rule=Get-NetFirewallRule -Name $Name -PolicyStore PersistentStore -ErrorAction Stop
        $record=Join-Path $EvidenceDirectory ('undo-'+[guid]::NewGuid().ToString('N')+'.clixml')
        $rule | Export-Clixml $record
        Remove-NetFirewallRule -Name $Name -PolicyStore PersistentStore -ErrorAction Stop
    }
}
Export-ModuleMember -Function *-Ccdc*
function Get-CcdcFirewallStatus {
    $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction)
    $rules=@(Get-NetFirewallRule -Name 'CCDC-Toolkit-*' -PolicyStore PersistentStore -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {
        $rule=$_;$ports=Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        $addresses=Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop
        [pscustomobject]@{Name=$rule.Name;Action=[string]$rule.Action;Direction=[string]$rule.Direction;Enabled=[string]$rule.Enabled
            Ports=$(if([string]$rule.Direction -eq 'Inbound'){'Local '+($ports.LocalPort -join ',')}else{'Remote '+($ports.RemotePort -join ',')});Protocol=[string]$ports.Protocol;Remote=($addresses.RemoteAddress -join ',');Profile=[string]$rule.Profile}
    })
    [pscustomobject]@{Profiles=$profiles;Rules=$rules}
}
Export-ModuleMember -Function *-Ccdc*
