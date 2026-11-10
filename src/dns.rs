use crate::{
    connectivity::{self, V6State},
    model::*,
    platform::*,
};
use anyhow::{Context, Result, ensure};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::*,
        NetworkManagement::{IpHelper::*, Ndis::IfOperStatusUp},
        Networking::WinSock::*,
    },
    core::PWSTR,
};
use winreg::{RegKey, enums::*};
struct Adapter {
    guid: windows::core::GUID,
    name: String,
    index: u32,
    v4: bool,
    v6: bool,
}
fn adapters(active_only: bool) -> Result<Vec<Adapter>> {
    unsafe {
        let mut table = std::ptr::null_mut();
        GetIfTable2(&mut table).ok()?;
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        let physical: Vec<_> = rows
            .iter()
            .filter(|r| {
                (!active_only || r.OperStatus == IfOperStatusUp)
                    && r.InterfaceAndOperStatusFlags._bitfield & 1 != 0
                    && (r.Type == IF_TYPE_ETHERNET_CSMACD || r.Type == IF_TYPE_IEEE80211)
            })
            .map(|r| (r.InterfaceIndex, r.InterfaceGuid, r.InterfaceLuid.Value))
            .collect();
        FreeMibTable(table.cast());
        let mut size = 16384u32;
        let mut buffer = Vec::<u64>::new();
        for _ in 0..4 {
            buffer.resize((size as usize).div_ceil(8), 0);
            let code = GetAdaptersAddresses(
                0,
                GAA_FLAG_INCLUDE_ALL_INTERFACES,
                None,
                Some(buffer.as_mut_ptr().cast()),
                &mut size,
            );
            if code == ERROR_BUFFER_OVERFLOW.0 {
                continue;
            }
            if code == ERROR_NO_DATA.0 {
                return Ok(vec![]);
            }
            WIN32_ERROR(code).ok()?;
            let mut p = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            let mut result = vec![];
            while !p.is_null() {
                let a = &*p;
                if let Some((idx, guid, _)) =
                    physical.iter().find(|(_, _, luid)| *luid == a.Luid.Value)
                {
                    let flags = a.Anonymous2.Flags;
                    result.push(Adapter {
                        guid: *guid,
                        name: a.FriendlyName.to_string()?,
                        index: *idx,
                        v4: flags & 0x80 != 0,
                        v6: flags & 0x100 != 0,
                    });
                }
                p = a.Next;
            }
            return Ok(result);
        }
        anyhow::bail!("Network adapter list kept changing")
    }
}
struct Snapshot(DNS_INTERFACE_SETTINGS3);
impl Drop for Snapshot {
    fn drop(&mut self) {
        unsafe { FreeInterfaceDnsSettings((&mut self.0 as *mut DNS_INTERFACE_SETTINGS3).cast()) }
    }
}
fn read(g: windows::core::GUID, v6: bool) -> Result<Snapshot> {
    unsafe {
        let mut s = DNS_INTERFACE_SETTINGS3 {
            Version: 3,
            Flags: if v6 { DNS_SETTING_IPV6 as u64 } else { 0 },
            ..Default::default()
        };
        GetInterfaceDnsSettings(g, (&mut s as *mut DNS_INTERFACE_SETTINGS3).cast()).ok()?;
        Ok(Snapshot(s))
    }
}
fn matches(s: &DNS_INTERFACE_SETTINGS3, ips: &[String], url: &str) -> bool {
    unsafe {
        let names = if s.NameServer.is_null() {
            String::new()
        } else {
            match s.NameServer.to_string() {
                Ok(v) => v,
                Err(_) => return false,
            }
        };
        let current: Vec<String> = names
            .split([',', ' ', ';'])
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect();
        if !same_addresses(&current, ips)
            || s.ServerProperties.is_null()
            || s.cServerProperties > 4096
        {
            return false;
        }
        let properties =
            std::slice::from_raw_parts(s.ServerProperties, s.cServerProperties as usize);
        for i in 0..ips.len() {
            let Some(p) = properties
                .iter()
                .find(|p| p.ServerIndex == i as u32 && p.Type == DnsServerDohProperty)
            else {
                return false;
            };
            let d = p.Property.DohSettings;
            if d.is_null() {
                return false;
            }
            let d = &*d;
            if d.Flags & DNS_DOH_SERVER_SETTINGS_ENABLE as u64 == 0
                || d.Flags & DNS_DOH_SERVER_SETTINGS_FALLBACK_TO_UDP as u64 != 0
                || d.Template.is_null()
                || d.Template.to_string().ok().as_deref() != Some(url)
            {
                return false;
            }
        }
        true
    }
}
fn apply_adapter(a: &Adapter, ips: &[String], url: &str, v6: bool) -> Result<bool> {
    let before = read(a.guid, v6)?;
    if matches(&before.0, ips, url)
        && profile_is_automatic(&before.0)?
        && same_addresses(&effective_dns(a, v6)?, ips)
    {
        return Ok(false);
    }
    let mut servers = wide(&ips.join(","));
    let mut empty = wide("");
    let mut template = wide(url);
    let mut doh: Vec<_> = ips
        .iter()
        .map(|_| DNS_DOH_SERVER_SETTINGS {
            Template: PWSTR(template.as_mut_ptr()),
            Flags: DNS_DOH_SERVER_SETTINGS_ENABLE as u64,
        })
        .collect();
    let mut properties: Vec<_> = doh
        .iter_mut()
        .enumerate()
        .map(|(i, d)| DNS_SERVER_PROPERTY {
            Version: 1,
            ServerIndex: i as u32,
            Type: DnsServerDohProperty,
            Property: DNS_SERVER_PROPERTY_TYPES { DohSettings: d },
        })
        .collect();
    let s = DNS_INTERFACE_SETTINGS3 {
        Version: 3,
        Flags: (DNS_SETTING_NAMESERVER
            | DNS_SETTING_DOH
            | DNS_SETTING_PROFILE_NAMESERVER
            | DNS_SETTING_DOH_PROFILE
            | if v6 { DNS_SETTING_IPV6 } else { 0 }) as u64,
        NameServer: PWSTR(servers.as_mut_ptr()),
        ProfileNameServer: PWSTR(empty.as_mut_ptr()),
        cServerProperties: properties.len() as u32,
        ServerProperties: properties.as_mut_ptr(),
        ..Default::default()
    };
    unsafe {
        SetInterfaceDnsSettings(a.guid, (&s as *const DNS_INTERFACE_SETTINGS3).cast()).ok()?;
    }
    for _ in 0..10 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let after = read(a.guid, v6)?;
        if matches(&after.0, ips, url)
            && profile_is_automatic(&after.0)?
            && same_addresses(&effective_dns(a, v6)?, ips)
        {
            return Ok(true);
        }
    }
    anyhow::bail!(
        "{} / IPv{}: DNS/HTTPS verification failed",
        a.name,
        if v6 { 6 } else { 4 }
    )
}
fn browsers(c: &Config, enabled: bool) -> Result<bool> {
    let mut changed = false;
    for path in [
        r"SOFTWARE\Policies\Google\Chrome",
        r"SOFTWARE\Policies\Microsoft\Edge",
    ] {
        let root = RegKey::predef(HKEY_LOCAL_MACHINE);
        if !enabled {
            match root.open_subkey_with_flags(path, KEY_READ | KEY_SET_VALUE) {
                Ok(k) => changed |= clear_browser_policy(&k)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            continue;
        }
        let (k, _) = root.create_subkey(path)?;
        let desired = [
            ("DnsOverHttpsTemplates", c.url.as_str()),
            ("DnsOverHttpsMode", "secure"),
        ];
        for (name, wanted) in desired {
            let right = k
                .get_raw_value(name)
                .map(|v| v.vtype == REG_SZ)
                .unwrap_or(false)
                && k.get_value::<String, _>(name).ok().as_deref() == Some(wanted);
            if !right {
                k.set_value(name, &wanted)?;
                changed = true;
            }
            ensure!(
                k.get_value::<String, _>(name)? == wanted && k.get_raw_value(name)?.vtype == REG_SZ,
                "Browser policy verification failed"
            );
        }
    }
    Ok(changed)
}
fn clear_browser_policy(k: &RegKey) -> Result<bool> {
    let mut changed = false;
    for name in ["DnsOverHttpsMode", "DnsOverHttpsTemplates"] {
        match k.delete_value(name) {
            Ok(()) => changed = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        ensure!(
            matches!(k.get_raw_value(name), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "Browser policy cleanup verification failed: {name}"
        );
    }
    Ok(changed)
}

fn profile_is_automatic(s: &DNS_INTERFACE_SETTINGS3) -> Result<bool> {
    Ok((s.ProfileNameServer.is_null()
        || unsafe { s.ProfileNameServer.to_string()? }
            .trim()
            .is_empty())
        && s.cProfileServerProperties == 0)
}

// Read the resolvers Windows actually uses, independently of the configuration
// API. Checking saved DNS settings alone can miss a conflicting network profile.
fn effective_dns(a: &Adapter, v6: bool) -> Result<Vec<String>> {
    unsafe {
        let mut size = 16384u32;
        let mut buffer = Vec::<u64>::new();
        for _ in 0..4 {
            buffer.resize((size as usize).div_ceil(8), 0);
            let code = GetAdaptersAddresses(
                0,
                GAA_FLAG_INCLUDE_ALL_INTERFACES,
                None,
                Some(buffer.as_mut_ptr().cast()),
                &mut size,
            );
            if code == ERROR_BUFFER_OVERFLOW.0 {
                continue;
            }
            WIN32_ERROR(code).ok()?;
            let mut p = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            while !p.is_null() {
                let adapter = &*p;
                if adapter.Anonymous1.Anonymous.IfIndex == a.index || adapter.Ipv6IfIndex == a.index
                {
                    let mut result = Vec::new();
                    let mut server = adapter.FirstDnsServerAddress;
                    while !server.is_null() {
                        let addr = (*server).Address;
                        if !addr.lpSockaddr.is_null() {
                            let ip = match (*addr.lpSockaddr).sa_family {
                                AF_INET6 if v6 => Some(IpAddr::V6(Ipv6Addr::from(
                                    (*addr.lpSockaddr.cast::<SOCKADDR_IN6>()).sin6_addr.u.Byte,
                                ))),
                                AF_INET if !v6 => Some(IpAddr::V4(Ipv4Addr::from(
                                    (*addr.lpSockaddr.cast::<SOCKADDR_IN>())
                                        .sin_addr
                                        .S_un
                                        .S_addr
                                        .to_ne_bytes(),
                                ))),
                                _ => None,
                            };
                            if let Some(ip) = ip {
                                result.push(ip.to_string());
                            }
                        }
                        server = (*server).Next;
                    }
                    return Ok(result);
                }
                p = adapter.Next;
            }
            anyhow::bail!("Adapter disappeared while reading effective DNS");
        }
        anyhow::bail!("Effective DNS list kept changing")
    }
}
fn has_v6_path(a: &Adapter) -> Result<bool> {
    unsafe {
        let mut addresses = std::ptr::null_mut();
        GetUnicastIpAddressTable(AF_INET6, &mut addresses).ok()?;
        let rows = std::slice::from_raw_parts(
            (*addresses).Table.as_ptr(),
            (*addresses).NumEntries as usize,
        );
        let address = rows.iter().any(|r| {
            r.Address.si_family == AF_INET6
                && connectivity::V6Address {
                    interface: r.InterfaceIndex,
                    ip: Ipv6Addr::from(r.Address.Ipv6.sin6_addr.u.Byte),
                    preferred: r.DadState == IpDadStatePreferred,
                    valid_lifetime: r.ValidLifetime,
                    preferred_lifetime: r.PreferredLifetime,
                    skip_as_source: r.SkipAsSource,
                }
                .usable_on(a.index)
        });
        FreeMibTable(addresses.cast());
        if !address {
            return Ok(false);
        }
        let mut routes = std::ptr::null_mut();
        GetIpForwardTable2(AF_INET6, &mut routes).ok()?;
        let rows =
            std::slice::from_raw_parts((*routes).Table.as_ptr(), (*routes).NumEntries as usize);
        let route = rows.iter().any(|r| {
            r.DestinationPrefix.Prefix.si_family == AF_INET6
                && connectivity::V6Route {
                    interface: r.InterfaceIndex,
                    prefix: Ipv6Addr::from(r.DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte),
                    prefix_length: r.DestinationPrefix.PrefixLength,
                    valid_lifetime: r.ValidLifetime,
                    loopback: r.Loopback,
                }
                .default_on(a.index)
        });
        FreeMibTable(routes.cast());
        Ok(route)
    }
}

fn socket_address(ip: IpAddr) -> SOCKADDR_INET {
    match ip {
        IpAddr::V6(ip) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: ip.octets() },
                },
                ..Default::default()
            },
        },
        IpAddr::V4(ip) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(ip.octets()),
                    },
                },
                ..Default::default()
            },
        },
    }
}

fn source_for(a: &Adapter, target: IpAddr) -> Result<IpAddr> {
    unsafe {
        let destination = socket_address(target);
        let mut route = MIB_IPFORWARD_ROW2::default();
        let mut source = SOCKADDR_INET::default();
        GetBestRoute2(
            None,
            a.index,
            None,
            &destination,
            0,
            &mut route,
            &mut source,
        )
        .ok()?;
        ensure!(
            route.InterfaceIndex == a.index && route.ValidLifetime > 0,
            "Provider route is not on selected adapter"
        );
        let ip = match source.si_family {
            AF_INET6 => IpAddr::V6(Ipv6Addr::from(source.Ipv6.sin6_addr.u.Byte)),
            AF_INET => IpAddr::V4(Ipv4Addr::from(
                source.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            )),
            _ => anyhow::bail!("No usable source address"),
        };
        ensure!(
            !ip.is_unspecified() && !ip.is_loopback(),
            "Invalid source address"
        );
        if let IpAddr::V6(ip) = ip {
            ensure!(connectivity::usable_v6(ip), "No usable IPv6 source address");
        }
        if target.is_ipv6() {
            let mut entry = MIB_UNICASTIPADDRESS_ROW {
                Address: source,
                InterfaceIndex: a.index,
                ..Default::default()
            };
            GetUnicastIpAddressEntry(&mut entry).ok()?;
            ensure!(
                entry.DadState == IpDadStatePreferred
                    && entry.ValidLifetime > 0
                    && entry.PreferredLifetime > 0
                    && !entry.SkipAsSource,
                "Selected IPv6 source is not usable"
            );
        }
        // Confirm the OS route with this bound source cannot select a different
        // adapter (including weak-host / multi-homed configurations).
        GetBestRoute2(
            None,
            0,
            Some(&source),
            &destination,
            0,
            &mut route,
            &mut SOCKADDR_INET::default(),
        )
        .ok()?;
        ensure!(
            route.InterfaceIndex == a.index,
            "Bound source would route through another adapter"
        );
        Ok(ip)
    }
}

fn probe_servers(a: &Adapter, ips: &[String], url: &str, deadline: Instant) -> Result<()> {
    for ip in ips {
        let target = ip.parse()?;
        let source = source_for(a, target).with_context(|| format!("{ip}: route"))?;
        connectivity::probe(url, target, source, deadline).with_context(|| format!("{ip}: DoH"))?;
    }
    Ok(())
}

fn ownership_path(a: &Adapter) -> Result<std::path::PathBuf> {
    Ok(data_dir()?.join(format!("ipv6-owned-{:?}.json", a.guid)))
}

// Verify static assignment, not the effective DHCP/RA resolver list: automatic
// DNS can legitimately return nonempty resolver addresses immediately after reset.
fn static_dns(a: &Adapter, v6: bool) -> Result<String> {
    let path = format!(
        r"SYSTEM\CurrentControlSet\Services\{}\Parameters\Interfaces\{{{:?}}}",
        if v6 { "Tcpip6" } else { "Tcpip" },
        a.guid
    );
    let key = match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(&path) {
        Ok(key) => key,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(e) => return Err(e.into()),
    };
    match key.get_value("NameServer") {
        Ok(value) => Ok(value),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.into()),
    }
}

/// Only remove an exact SecureKon-owned DNS+DoH configuration. config.json is
/// the migration evidence for v2.0.0, which had no per-adapter ownership ledger.
fn clear_owned_v6(a: &Adapter, legacy: Option<&Config>) -> Result<Option<bool>> {
    if static_dns(a, true)?.trim().is_empty() {
        return Ok(Some(false));
    }
    let before = read(a.guid, true)?;
    let path = ownership_path(a)?;
    let owned = if path.try_exists()? {
        Some(read_json::<Config>(&path)?)
    } else {
        None
    };
    let ours = owned
        .iter()
        .chain(legacy)
        .any(|c| matches(&before.0, &c.ipv6, &c.url));
    if !ours {
        return Ok(None);
    }
    // The ownership check covers the adapter configuration, not an unrelated
    // profile. Only an explicit automatic-DNS request clears both scopes.
    reset_static_dns(a, true, false).map(Some)
}

fn reset_static_dns(a: &Adapter, v6: bool, reset_profile: bool) -> Result<bool> {
    if static_dns(a, v6)?.trim().is_empty()
        && (!reset_profile || profile_is_automatic(&read(a.guid, v6)?.0)?)
    {
        return Ok(false);
    }
    let mut empty = wide("");
    let reset = DNS_INTERFACE_SETTINGS3 {
        Version: 3,
        Flags: (DNS_SETTING_NAMESERVER
            | DNS_SETTING_DOH
            | if reset_profile {
                DNS_SETTING_PROFILE_NAMESERVER | DNS_SETTING_DOH_PROFILE
            } else {
                0
            }
            | if v6 { DNS_SETTING_IPV6 } else { 0 }) as u64,
        NameServer: PWSTR(empty.as_mut_ptr()),
        ProfileNameServer: if reset_profile {
            PWSTR(empty.as_mut_ptr())
        } else {
            PWSTR::null()
        },
        ..Default::default()
    };
    unsafe {
        SetInterfaceDnsSettings(a.guid, (&reset as *const DNS_INTERFACE_SETTINGS3).cast()).ok()?;
    }
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(200));
        if static_dns(a, v6)?.trim().is_empty()
            && (!reset_profile || profile_is_automatic(&read(a.guid, v6)?.0)?)
        {
            return Ok(true);
        }
    }
    anyhow::bail!(
        "IPv{} automatic DNS readback failed",
        if v6 { 6 } else { 4 }
    )
}

fn windows_automatic() -> Result<ApplyResult> {
    let mut errors = Vec::new();
    // Include disconnected physical adapters, so reconnecting cannot bring back
    // stale static DNS. Virtual/VPN adapters and IP addressing are untouched.
    for a in adapters(false)? {
        for (v6, enabled) in [(false, a.v4), (true, a.v6)] {
            if enabled && let Err(e) = reset_static_dns(&a, v6, true) {
                errors.push(format!("{} / IPv{}: {e:#}", a.name, if v6 { 6 } else { 4 }));
            }
        }
    }
    ensure!(errors.is_empty(), "{}", errors.join("\n"));
    Ok(ApplyResult {
        state: "WindowsAutomatic".into(),
        checks: Vec::new(),
    })
}

struct ApplyResult {
    state: String,
    checks: Vec<ConnectivityCheck>,
}

fn apply_windows(c: &Config, wait: bool) -> Result<ApplyResult> {
    c.validate()?;
    let legacy = match config() {
        Ok(c) => Some(c),
        Err(e) => {
            // Missing initial config is expected; other errors must not silently
            // discard ownership information during an upgrade.
            if data_dir()?.join("config.json").try_exists()? {
                return Err(e);
            }
            None
        }
    };
    let mut changed = false;
    let mut list = adapters(true)?;
    if wait {
        for _ in 0..12 {
            if !list.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_secs(5));
            list = adapters(true)?;
        }
    }
    // Keep the full worker within its existing three-minute execution limit.
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut errors = Vec::new();
    let mut checks = Vec::new();
    let mut deferred = false;
    let mut ipv4_only = false;
    for a in &list {
        let mut check = ConnectivityCheck {
            adapter: a.name.clone(),
            ipv4: "Disabled".into(),
            ipv6: "Disabled".into(),
            detail: String::new(),
        };
        if a.v6
            && let Some(previous) = legacy.as_ref()
            && matches(&read(a.guid, true)?.0, &previous.ipv6, &previous.url)
        {
            // Preserve v2.0.0 ownership before saving a changed provider,
            // even when the new provider cannot be reached this time.
            atomic_json(&ownership_path(a)?, previous)?;
        }
        if a.v4 {
            match connectivity::retry(
                || apply_adapter(a, &c.ipv4, &c.url, false),
                || std::thread::sleep(Duration::from_millis(500)),
            ) {
                Ok(v) => changed |= v,
                Err(e) => errors.push(format!("{} / IPv4: {e:#}", a.name)),
            }
            match probe_servers(a, &c.ipv4, &c.url, deadline) {
                Ok(()) => check.ipv4 = "Reachable".into(),
                Err(e) => {
                    check.ipv4 = "Unverified".into();
                    deferred = true;
                    check.detail.push_str(&format!("IPv4: {e:#}\n"));
                }
            }
        }
        if a.v6 {
            match connectivity::assess_v6(
                || has_v6_path(a),
                || probe_servers(a, &c.ipv6, &c.url, deadline),
                || std::thread::sleep(Duration::from_millis(500)),
            ) {
                V6State::NoPath => {
                    check.ipv6 = "NoPath".into();
                    ipv4_only = true;
                    match clear_owned_v6(a, legacy.as_ref()) {
                        Ok(Some(v)) => changed |= v,
                        Ok(None) => {
                            deferred = true;
                            check.detail.push_str("IPv6: no usable path; DNS settings not owned by SecureKon were preserved");
                        }
                        Err(e) => errors.push(format!("{} / IPv6 cleanup: {e:#}", a.name)),
                    }
                    if !a.v4 {
                        deferred = true;
                    }
                }
                V6State::Reachable => {
                    check.ipv6 = "Reachable".into();
                    // Write intent first: interrupted writes remain attributable.
                    atomic_json(&ownership_path(a)?, c)?;
                    match connectivity::retry(
                        || apply_adapter(a, &c.ipv6, &c.url, true),
                        || std::thread::sleep(Duration::from_millis(500)),
                    ) {
                        Ok(v) => changed |= v,
                        Err(e) => errors.push(format!("{} / IPv6: {e:#}", a.name)),
                    }
                }
                V6State::Deferred(reason) => {
                    check.ipv6 = "Unverified".into();
                    deferred = true;
                    check.detail.push_str(&format!("IPv6: {reason}"));
                }
            }
        }
        if !a.v4 && !a.v6 {
            deferred = true;
        }
        checks.push(check);
    }
    ensure!(errors.is_empty(), "{}", errors.join("\n"));
    Ok(ApplyResult {
        state: if list.is_empty() {
            "Offline"
        } else if deferred {
            "ConnectivityUnverified"
        } else if ipv4_only {
            "IPv4Only"
        } else if changed {
            "Repaired"
        } else {
            "Healthy"
        }
        .into(),
        checks,
    })
}
pub fn worker() -> Result<()> {
    ensure!(is_admin(), "Worker requires elevation");
    let root = data_dir()?;
    trusted_existing(&root)?;
    let bytes = read_limited(&root.join("Requests/request-v2.json"), 16384)?;
    let req = Request::parse(&bytes)?;
    let result = (|| -> Result<ApplyResult> {
        let c = match &req.action {
            Action::Apply(c) => c.clone(),
            _ => config()?,
        };
        let mut preferences = dns_preferences()?;
        preferences.update(&req.action);
        if matches!(
            req.action,
            Action::SetWindowsDns(_) | Action::SetBrowserDoh(_)
        ) {
            // Persist the user's intent before applying. A partial OS failure is
            // reported, and subsequent checks retry the requested state.
            atomic_json(&root.join("dns-preferences.json"), &preferences)?;
        }
        let state = match req.action {
            Action::SetBrowserDoh(on) => {
                browsers(&c, on)?;
                ApplyResult {
                    state: if on {
                        "BrowserDnsEnabled"
                    } else {
                        "BrowserDnsDisabled"
                    }
                    .into(),
                    checks: Vec::new(),
                }
            }
            Action::SetWindowsDns(true) => apply_windows(&c, false)?,
            Action::SetWindowsDns(false) => windows_automatic()?,
            Action::Apply(_) | Action::Check => {
                let browser_changed = browsers(&c, preferences.browser_doh)?;
                let mut result = if preferences.windows_dns {
                    apply_windows(&c, matches!(req.action, Action::Check))?
                } else {
                    windows_automatic()?
                };
                if browser_changed && result.state == "Healthy" {
                    result.state = "Repaired".into();
                }
                result
            }
        };
        if matches!(req.action, Action::Apply(_)) {
            atomic_json(&root.join("config.json"), &c)?;
        }
        Ok(state)
    })();
    let s = match result {
        Ok(result) => Status {
            id: req.id,
            ok: true,
            state: result.state,
            detail: String::new(),
            connectivity: result.checks,
        },
        Err(e) => Status {
            id: req.id,
            ok: false,
            state: "Failed".into(),
            detail: format!("{e:#}"),
            connectivity: Vec::new(),
        },
    };
    atomic_json(&root.join("status-v2.json"), &s)?;
    ensure!(s.ok, "{}", s.detail);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disabling_browser_policy_removes_values_and_preserves_other_policies() {
        let root = RegKey::predef(HKEY_CURRENT_USER);
        let path = format!(r"Software\SecureKonTests\{}", uuid::Uuid::new_v4());
        let (key, _) = root.create_subkey(&path).unwrap();
        let result = (|| -> Result<()> {
            key.set_value("UnrelatedPolicy", &1u32)?;
            for mode in ["secure", "off"] {
                key.set_value("DnsOverHttpsMode", &mode)?;
                key.set_value("DnsOverHttpsTemplates", &"https://dns.google/dns-query")?;
                assert!(clear_browser_policy(&key)?);
                assert!(!clear_browser_policy(&key)?);
                assert_eq!(key.get_value::<u32, _>("UnrelatedPolicy")?, 1);
                for name in ["DnsOverHttpsMode", "DnsOverHttpsTemplates"] {
                    assert_eq!(
                        key.get_raw_value(name).unwrap_err().kind(),
                        std::io::ErrorKind::NotFound
                    );
                }
            }
            Ok(())
        })();
        drop(key);
        root.delete_subkey_all(&path).unwrap();
        result.unwrap();
    }
    #[test]
    fn profile_dns_and_profile_doh_both_require_cleanup() {
        let mut names = wide("8.8.8.8,8.8.4.4");
        let mut s = DNS_INTERFACE_SETTINGS3::default();
        assert!(profile_is_automatic(&s).unwrap());
        s.ProfileNameServer = PWSTR(names.as_mut_ptr());
        assert!(!profile_is_automatic(&s).unwrap());
        let mut empty = wide("");
        s.ProfileNameServer = PWSTR(empty.as_mut_ptr());
        s.cProfileServerProperties = 1;
        assert!(!profile_is_automatic(&s).unwrap());
        s.cProfileServerProperties = 0;
        assert!(profile_is_automatic(&s).unwrap());
    }
    #[test]
    fn detects_doh_drift_without_writing() {
        let mut names = wide("8.8.8.8,8.8.4.4");
        let mut url = wide("https://dns.google/dns-query");
        let mut d = [DNS_DOH_SERVER_SETTINGS {
            Template: PWSTR(url.as_mut_ptr()),
            Flags: 2,
        }; 2];
        let mut props: Vec<_> = d
            .iter_mut()
            .enumerate()
            .map(|(i, d)| DNS_SERVER_PROPERTY {
                Version: 1,
                ServerIndex: i as u32,
                Type: DnsServerDohProperty,
                Property: DNS_SERVER_PROPERTY_TYPES { DohSettings: d },
            })
            .collect();
        let s = DNS_INTERFACE_SETTINGS3 {
            NameServer: PWSTR(names.as_mut_ptr()),
            ServerProperties: props.as_mut_ptr(),
            cServerProperties: 2,
            ..Default::default()
        };
        let ips = vec!["8.8.8.8".into(), "8.8.4.4".into()];
        assert!(matches(&s, &ips, "https://dns.google/dns-query"));
        d[0].Flags |= 4;
        assert!(!matches(&s, &ips, "https://dns.google/dns-query"));
        d[0].Flags = 2;
        assert_eq!(d[0].Flags, 2);
        assert!(!matches(&s, &ips, "https://dns.adguard-dns.com/dns-query"));
        props[1].ServerIndex = 0;
        assert!(!matches(&s, &ips, "https://dns.google/dns-query"));
    }
    #[test]
    fn missing_settings_require_repair() {
        assert!(!matches(
            &DNS_INTERFACE_SETTINGS3::default(),
            &["8.8.8.8".into()],
            "https://dns.google/dns-query"
        ));
    }
}
