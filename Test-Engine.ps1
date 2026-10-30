param([string]$Scenario)
$ErrorActionPreference='Stop'
$env:ProgramData=Join-Path ([IO.Path]::GetTempPath()) ('SecureKon-Test-'+$Scenario+'-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path ($env:ProgramData+'/SecureKon') -Force | Out-Null
@{Url='https://dns.adguard-dns.com/dns-query';IPv4=@('94.140.14.14','94.140.15.15');IPv6=@('2a10:50c0::ad1:ff','2a10:50c0::ad2:ff')} | ConvertTo-Json | Set-Content ($env:ProgramData+'/SecureKon/config.json')
New-Item -ItemType Directory -Path ($env:ProgramData+'/SecureKon/Requests') -Force | Out-Null
@{Id='0123456789abcdef0123456789abcdef';Action='Check'}|ConvertTo-Json|Set-Content ($env:ProgramData+'/SecureKon/Requests/request.json')
$global:writes=0; $global:alerts=0
$global:reg=@{}
$url='https://dns.adguard-dns.com/dns-query'
foreach($path in @('HKLM:\SOFTWARE\Policies\Google\Chrome','HKLM:\SOFTWARE\Policies\Microsoft\Edge')) { $global:reg[$path]=@{DnsOverHttpsTemplates=$url;DnsOverHttpsMode='secure'} }
$global:doh=@{}
foreach($ip in @('94.140.14.14','94.140.15.15','2a10:50c0::ad1:ff','2a10:50c0::ad2:ff')) {$global:doh[$ip]=[pscustomobject]@{ServerAddress=$ip;DohTemplate=$url;AllowFallbackToUdp=$false;AutoUpgrade=$true}}
$global:dns=@{IPv4=@('94.140.14.14','94.140.15.15');IPv6=@('2a10:50c0:0:0:0:0:ad1:ff','2a10:50c0::ad2:ff')}
if($Scenario -eq 'drift') {$global:reg['HKLM:\SOFTWARE\Policies\Microsoft\Edge'].DnsOverHttpsMode='off';$global:doh.Remove('94.140.14.14');$global:dns.IPv4=@('192.168.1.1')}
if($Scenario -eq 'blocked') {$global:dns.IPv4=@('192.168.1.1')}
function Get-Item { param($LiteralPath,$ErrorAction)
 if($LiteralPath -like 'HKLM:*') {
 $o=[pscustomobject]@{Path=$LiteralPath}
 $o|Add-Member ScriptMethod GetValueNames {return @($global:reg[$this.Path].Keys)}
 $o|Add-Member ScriptMethod GetValueKind {param($name);return 'String'}
 $o|Add-Member ScriptMethod GetValue {param($name);return $global:reg[$this.Path][$name]}
 return $o
 }; Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath
}
function Test-Path {param($LiteralPath); if($LiteralPath -like 'HKLM:*'){return $true}; Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath}
function New-ItemProperty {param($LiteralPath,$Name,$Value,$PropertyType,[switch]$Force);$global:writes++;$global:reg[$LiteralPath][$Name]=$Value}
function Get-NetAdapter {param([switch]$Physical);if($Scenario -ne 'offline'){[pscustomobject]@{Name='Wi-Fi';Status='Up';ifIndex=13}}}
function Get-NetAdapterBinding {param($Name,$ComponentID);[pscustomobject]@{Enabled=$true}}
function Get-DnsClientServerAddress {param($InterfaceIndex,$AddressFamily);[pscustomobject]@{Family=$AddressFamily;ServerAddresses=$global:dns[$AddressFamily]}}
function Set-DnsClientServerAddress {param([Parameter(ValueFromPipeline=$true)]$InputObject,$ServerAddresses);process{if($Scenario -eq 'blocked'){throw 'mock access denied'};$global:writes++;$global:dns[$InputObject.Family]=@($ServerAddresses)}}
function Get-DnsClientDohServerAddress {return @($global:doh.Values)}
function Set-DnsClientDohServerAddress {param($ServerAddress,$DohTemplate,$AllowFallbackToUdp,$AutoUpgrade);$global:writes++;$global:doh[$ServerAddress]=[pscustomobject]@{ServerAddress=$ServerAddress;DohTemplate=$DohTemplate;AllowFallbackToUdp=$AllowFallbackToUdp;AutoUpgrade=$AutoUpgrade}}
function Add-DnsClientDohServerAddress {param($ServerAddress,$DohTemplate,$AllowFallbackToUdp,$AutoUpgrade);Set-DnsClientDohServerAddress @PSBoundParameters}
function Clear-DnsClientCache {}
function Start-Sleep {param($Seconds,$Milliseconds)}
function Get-CimInstance {param($Class);[pscustomobject]@{LastBootUpTime=[datetime]'2026-10-30T00:00:00Z'}}
function Start-ScheduledTask {param($TaskName,$ErrorAction);$global:alerts++}
if($Scenario -eq 'apply'){
 @{Id='0123456789abcdef0123456789abcdef';Action='Apply';Config=@{Name='Google';Url='https://dns.google/dns-query';IPv4=@('8.8.8.8','8.8.4.4');IPv6=@('2001:4860:4860::8888','2001:4860:4860::8844')}}|ConvertTo-Json -Depth 4|Set-Content ($env:ProgramData+'/SecureKon/Requests/request.json')
}
if($Scenario -eq 'invalid'){
 @{Id='0123456789abcdef0123456789abcdef';Action='Apply';Config=@{Url='http://invalid';IPv4=@('8.8.8.8');IPv6=@('::1')}}|ConvertTo-Json -Depth 4|Set-Content ($env:ProgramData+'/SecureKon/Requests/request.json')
}
if($Scenario -eq 'unknown'){
 @{Id='0123456789abcdef0123456789abcdef';Action='Execute';Config='whoami'}|ConvertTo-Json|Set-Content ($env:ProgramData+'/SecureKon/Requests/request.json')
}
& (Join-Path $PSScriptRoot 'Engine.ps1')
$s=Get-Content ($env:ProgramData+'/SecureKon/status.json') -Raw|ConvertFrom-Json
if($s.Id -ne '0123456789abcdef0123456789abcdef'){throw 'Response ID mismatch'}
switch($Scenario) {
 'apply' { $saved=Get-Content ($env:ProgramData+'/SecureKon/config.json') -Raw|ConvertFrom-Json; if($s.State -ne 'Repaired' -or $saved.Url -ne 'https://dns.google/dns-query' -or $global:dns.IPv4[0] -ne '8.8.8.8'){throw 'Apply case failed'} }
 'invalid' {if($s.State -ne 'Failed' -or $global:writes -ne 0){throw 'Invalid config was applied'}}
 'unknown' {if($s.State -ne 'Failed' -or $global:writes -ne 0){throw 'Unknown action was accepted'}}
 'healthy' {if($s.State -ne 'Healthy' -or $global:writes -ne 0 -or $global:alerts){throw 'Healthy case failed'}}
 'drift' {if($s.State -ne 'Repaired' -or $global:writes -ne 3 -or $global:alerts){throw 'Drift case failed'}}
 'blocked' {if($s.State -ne 'Failed' -or $global:alerts -ne 0){throw 'Failure case failed'}}
 'offline' {if($s.State -ne 'Offline' -or $global:writes -or $global:alerts){throw 'Offline case failed'}}
}
Write-Output "$Scenario PASS (state=$($s.State), writes=$global:writes, alerts=$global:alerts)"
exit 0
