use crate::{model::*, platform::*};
use anyhow::{Context, Result, ensure};
use windows::{
    Win32::{
        Foundation::*,
        NetworkManagement::{IpHelper::*, Ndis::IfOperStatusUp},
    },
    core::PWSTR,
};
use winreg::{RegKey, enums::*};
struct Adapter {
    guid: windows::core::GUID,
    name: String,
    v4: bool,
    v6: bool,
}
fn adapters() -> Result<Vec<Adapter>> {
    unsafe {
        let mut table = std::ptr::null_mut();
        GetIfTable2(&mut table).ok()?;
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        let physical: Vec<_> = rows
            .iter()
            .filter(|r| {
                r.OperStatus == IfOperStatusUp
                    && r.InterfaceAndOperStatusFlags._bitfield & 1 != 0
                    && (r.Type == IF_TYPE_ETHERNET_CSMACD || r.Type == IF_TYPE_IEEE80211)
            })
            .map(|r| (r.InterfaceIndex, r.InterfaceGuid))
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
                if let Some((_, guid)) = physical
                    .iter()
                    .find(|(idx, _)| *idx == a.Anonymous1.Anonymous.IfIndex)
                {
                    let flags = a.Anonymous2.Flags;
                    result.push(Adapter {
                        guid: *guid,
                        name: a.FriendlyName.to_string()?,
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
    if matches(&before.0, ips, url) {
        return Ok(false);
    }
    let mut servers = wide(&ips.join(","));
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
        Flags: (DNS_SETTING_NAMESERVER | DNS_SETTING_DOH | if v6 { DNS_SETTING_IPV6 } else { 0 })
            as u64,
        NameServer: PWSTR(servers.as_mut_ptr()),
        cServerProperties: properties.len() as u32,
        ServerProperties: properties.as_mut_ptr(),
        ..Default::default()
    };
    unsafe {
        SetInterfaceDnsSettings(a.guid, (&s as *const DNS_INTERFACE_SETTINGS3).cast()).ok()?;
    }
    for _ in 0..3 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        if matches(&read(a.guid, v6)?.0, ips, url) {
            return Ok(true);
        }
    }
    anyhow::bail!(
        "{} / IPv{}: DNS/HTTPS verification failed",
        a.name,
        if v6 { 6 } else { 4 }
    )
}
fn browsers(c: &Config) -> Result<bool> {
    let mut changed = false;
    for path in [
        r"SOFTWARE\Policies\Google\Chrome",
        r"SOFTWARE\Policies\Microsoft\Edge",
    ] {
        let (k, _) = RegKey::predef(HKEY_LOCAL_MACHINE).create_subkey(path)?;
        for (name, wanted) in [
            ("DnsOverHttpsTemplates", c.url.as_str()),
            ("DnsOverHttpsMode", "secure"),
        ] {
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
pub fn apply(c: &Config, wait: bool) -> Result<String> {
    c.validate()?;
    let mut changed = browsers(c)?;
    let mut list = adapters()?;
    if wait {
        for _ in 0..12 {
            if !list.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
            list = adapters()?;
        }
    }
    let mut errors = Vec::new();
    for a in &list {
        for (v6, enabled, ips) in [(false, a.v4, &c.ipv4), (true, a.v6, &c.ipv6)] {
            if !enabled {
                continue;
            }
            let mut err = None;
            for _ in 0..3 {
                match apply_adapter(a, ips, &c.url, v6) {
                    Ok(v) => {
                        changed |= v;
                        err = None;
                        break;
                    }
                    Err(e) => {
                        err = Some(e);
                        std::thread::sleep(std::time::Duration::from_millis(500));
                    }
                }
            }
            if let Some(e) = err {
                errors.push(format!("{}: {e:#}", a.name));
            }
        }
    }
    ensure!(errors.is_empty(), "{}", errors.join("\n"));
    Ok(if list.is_empty() {
        "Offline"
    } else if changed {
        "Repaired"
    } else {
        "Healthy"
    }
    .into())
}
pub fn worker() -> Result<()> {
    ensure!(is_admin(), "Worker requires elevation");
    let root = data_dir()?;
    trusted_existing(&root)?;
    let bytes = read_limited(&root.join("Requests/request-v2.json"), 16384)?;
    let req = Request::parse(&bytes)?;
    let result = (|| -> Result<String> {
        let c = match &req.action {
            Action::Apply(c) => c.clone(),
            Action::Check => config()?,
        };
        let state = apply(&c, matches!(req.action, Action::Check)).context("DNS update")?;
        if matches!(req.action, Action::Apply(_)) {
            atomic_json(&root.join("config.json"), &c)?;
        }
        Ok(state)
    })();
    let s = match result {
        Ok(state) => Status {
            id: req.id,
            ok: true,
            state,
            detail: String::new(),
        },
        Err(e) => Status {
            id: req.id,
            ok: false,
            state: "Failed".into(),
            detail: format!("{e:#}"),
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
