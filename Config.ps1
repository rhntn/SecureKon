function Read-SecureKonConfig {
    $file=Join-Path $env:ProgramData 'SecureKon\config.json'
    $config=Get-Content -LiteralPath $file -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    Test-SecureKonConfig $config
    return $config
}
function Test-SecureKonConfig($config) {
    $uri=$null
    if (![Uri]::TryCreate([string]$config.Url,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -ne 'https' -or !$uri.Host -or $uri.UserInfo -or $uri.Fragment -or ([string]$config.Url -match '\s')) { throw 'Geçerli bir HTTPS DNS adresi girin; kullanıcı bilgisi, boşluk ve # kullanmayın.' }
    foreach($family in @('IPv4','IPv6')) {
        $list=@($config.$family)
        if ($list.Count -lt 1 -or $list.Count -gt 2) { throw "$family için en az bir, en fazla iki DNS sunucusu girin." }
        foreach($address in $list) {
            $ip=$null
            $wanted=if($family -eq 'IPv4'){[Net.Sockets.AddressFamily]::InterNetwork}else{[Net.Sockets.AddressFamily]::InterNetworkV6}
            if (![ipaddress]::TryParse([string]$address,[ref]$ip) -or $ip.AddressFamily -ne $wanted -or [ipaddress]::IsLoopback($ip) -or $ip.Equals([ipaddress]::Any) -or $ip.Equals([ipaddress]::IPv6Any)) { throw "Geçersiz $family DNS adresi: $address" }
        }
    }
}
