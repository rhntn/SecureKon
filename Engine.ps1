$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramData 'SecureKon'
$resultFile = Join-Path $root 'status.json'

$browserPaths = @('HKLM:\SOFTWARE\Policies\Google\Chrome','HKLM:\SOFTWARE\Policies\Microsoft\Edge')
function Same-Addresses($left, $right) {
    $l = @($left | ForEach-Object { ([ipaddress]$_).ToString() })
    $r = @($right | ForEach-Object { ([ipaddress]$_).ToString() })
    return (($l -join '|') -ceq ($r -join '|'))
}
function Save-Status($state, $detail, $changes) {
    $data = @{ Id=$requestId; State=$state; Detail=$detail; Changes=@($changes); Timestamp=[DateTime]::UtcNow.ToString('o'); Boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') }
    $temp = Join-Path $root ('status.'+$PID+'.tmp')
    $data | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $resultFile -Force
}
$requestId=''
$changes = New-Object 'System.Collections.Generic.List[string]'
$errors = @()
try {
    . (Join-Path $PSScriptRoot 'Config.ps1')
    $requestFile=Join-Path $root 'Requests\request.json'
    $file=Get-Item -LiteralPath $requestFile
    if($file.Length -gt 16384 -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Geçersiz istek dosyası.'}
    $request=Get-Content -LiteralPath $requestFile -Raw|ConvertFrom-Json
    if([string]$request.Id -notmatch '^[a-f0-9]{32}$'){throw 'Geçersiz istek kimliği.'}
    $requestId=[string]$request.Id
    if($request.Action -eq 'Apply'){
        Test-SecureKonConfig $request.Config
        $config=$request.Config
    }elseif($request.Action -eq 'Check'){
        $config=Read-SecureKonConfig
    }else{throw 'Desteklenmeyen işlem.'}
    $url=[string]$config.Url
    $servers4=@($config.IPv4)
    $servers6=@($config.IPv6)
    # Network readiness is not a DNS configuration failure. Allow Wi-Fi time to connect.
    for ($wait=0; $wait -lt 12; $wait++) {
        $adapters = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
        if ($adapters.Count) { break }
        Start-Sleep -Seconds 5
    }
    for ($attempt=1; $attempt -le 3; $attempt++) {
        $errors = @()
        foreach ($path in $browserPaths) {
            try {
                foreach ($pair in @(@{Name='DnsOverHttpsTemplates';Value=$url},@{Name='DnsOverHttpsMode';Value='secure'})) {
                    $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
                    $ok = $key -and ($key.GetValueNames() -contains $pair.Name) -and ($key.GetValueKind($pair.Name).ToString() -eq 'String') -and ($key.GetValue($pair.Name) -ceq $pair.Value)
                    if (!$ok) {
                        if (!(Test-Path -LiteralPath $path)) { New-Item -Path $path -Force | Out-Null }
                        New-ItemProperty -LiteralPath $path -Name $pair.Name -Value $pair.Value -PropertyType String -Force | Out-Null
                        $changes.Add($path+' / '+$pair.Name)
                    }
                    $key = Get-Item -LiteralPath $path
                    if ($key.GetValue($pair.Name) -cne $pair.Value -or $key.GetValueKind($pair.Name).ToString() -ne 'String') { throw 'Tarayici politikasi dogrulanamadi.' }
                }
            } catch { $errors += ($path+': '+$_.Exception.Message) }
        }
        foreach ($ip in ($servers4+$servers6)) {
            try {
                $d = Get-DnsClientDohServerAddress | Where-Object ServerAddress -eq $ip
                if (!$d -or $d.DohTemplate -cne $url -or $d.AllowFallbackToUdp -or !$d.AutoUpgrade) {
                    $parameters = @{ServerAddress=$ip;DohTemplate=$url;AllowFallbackToUdp=$false;AutoUpgrade=$true}
                    if ($d) { Set-DnsClientDohServerAddress @parameters } else { Add-DnsClientDohServerAddress @parameters }
                    $changes.Add('DoH / '+$ip)
                }
                $d = Get-DnsClientDohServerAddress | Where-Object ServerAddress -eq $ip
                if (!$d -or $d.DohTemplate -cne $url -or $d.AllowFallbackToUdp -or !$d.AutoUpgrade) { throw 'Sifreli DNS ayari dogrulanamadi.' }
            } catch { $errors += ($ip+': '+$_.Exception.Message) }
        }
        $adapters = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up')
        foreach ($adapter in $adapters) {
            foreach ($family in @('IPv4','IPv6')) {
                try {
                    $component = if ($family -eq 'IPv4') {'ms_tcpip'} else {'ms_tcpip6'}
                    $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID $component
                    if (!$binding.Enabled) { continue }
                    $wanted = if ($family -eq 'IPv4') {$servers4} else {$servers6}
                    $obj = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $family
                    if (!(Same-Addresses $wanted $obj.ServerAddresses)) {
                        $obj | Set-DnsClientServerAddress -ServerAddresses $wanted
                        $changes.Add($adapter.Name+' / '+$family)
                        Start-Sleep -Milliseconds 700
                    }
                    $actual = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily $family).ServerAddresses
                    if (!(Same-Addresses $wanted $actual)) { throw ('Beklenen: '+($wanted -join ', ')+'; okunan: '+($actual -join ', ')) }
                } catch { $errors += ($adapter.Name+' / '+$family+': '+$_.Exception.Message) }
            }
        }
        if (!$errors.Count) { break }
        if ($attempt -lt 3) { Start-Sleep -Seconds 5 }
    }
    if ($errors.Count) { throw ($errors -join "`r`n") }
    if ($changes.Count) { Clear-DnsClientCache }
    if($request.Action -eq 'Apply'){
        $configTemp=Join-Path $root 'config.tmp'
        $config|ConvertTo-Json -Depth 4|Set-Content -LiteralPath $configTemp -Encoding UTF8
        Move-Item -LiteralPath $configTemp -Destination (Join-Path $root 'config.json') -Force
    }
    if (!$adapters.Count) { Save-Status 'Offline' 'Aktif fiziksel baglanti yok; tarayici ve sifreli DNS tanimlari kontrol edildi.' $changes }
    elseif ($changes.Count) { Save-Status 'Repaired' 'Degisen ayarlar duzeltildi.' $changes }
    else { Save-Status 'Healthy' 'Tum ayarlar uygun; degisiklik yapilmadi.' $changes }
    exit 0
} catch {
    try { Save-Status 'Failed' $_.Exception.Message $changes } catch {}
    # The requesting user process displays failures; the SYSTEM worker stays silent.

    exit 1
}
