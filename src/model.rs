use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Url")]
    pub url: String,
    #[serde(rename = "IPv4")]
    pub ipv4: Vec<String>,
    #[serde(rename = "IPv6")]
    pub ipv6: Vec<String>,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.name.len() <= 128, "Invalid provider name");
        ensure!(
            self.url.len() <= 2048
                && !self
                    .url
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control()),
            "Invalid HTTPS URL"
        );
        let u = url::Url::parse(&self.url)?;
        ensure!(
            matches!(u.host(), Some(url::Host::Domain(_))),
            "HTTPS endpoint must use a hostname for IPv4/IPv6 support"
        );
        ensure!(
            u.scheme() == "https"
                && u.host_str().is_some()
                && u.username().is_empty()
                && u.password().is_none()
                && u.fragment().is_none(),
            "Invalid HTTPS URL"
        );
        for (v, family) in [(&self.ipv4, true), (&self.ipv6, false)] {
            ensure!(
                (1..=2).contains(&v.len()),
                "IPv4 and IPv6 each require 1–2 DNS addresses"
            );
            let mut seen = Vec::new();
            for s in v {
                let ip: IpAddr = s.parse()?;
                ensure!(
                    ip.is_ipv4() == family
                        && !ip.is_loopback()
                        && !ip.is_unspecified()
                        && !ip.is_multicast(),
                    "Invalid DNS address: {s}"
                );
                if let IpAddr::V4(a) = ip {
                    ensure!(
                        !a.is_broadcast() && !a.is_link_local(),
                        "Invalid DNS address: {s}"
                    );
                }
                if let IpAddr::V6(a) = ip {
                    ensure!(
                        !a.is_unicast_link_local() && a.to_ipv4_mapped().is_none(),
                        "Invalid DNS address: {s}"
                    );
                }
                ensure!(!seen.contains(&ip), "Duplicate DNS address: {s}");
                seen.push(ip);
            }
        }
        Ok(())
    }
}
pub fn presets() -> Vec<Config> {
    [
        (
            "AdGuard",
            "https://dns.adguard-dns.com/dns-query",
            ["94.140.14.14", "94.140.15.15"],
            ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
        ),
        (
            "Google",
            "https://dns.google/dns-query",
            ["8.8.8.8", "8.8.4.4"],
            ["2001:4860:4860::8888", "2001:4860:4860::8844"],
        ),
        (
            "Cloudflare",
            "https://cloudflare-dns.com/dns-query",
            ["1.1.1.1", "1.0.0.1"],
            ["2606:4700:4700::1111", "2606:4700:4700::1001"],
        ),
    ]
    .into_iter()
    .map(|(n, u, a, b)| Config {
        name: n.into(),
        url: u.into(),
        ipv4: a.map(String::from).to_vec(),
        ipv6: b.map(String::from).to_vec(),
    })
    .collect()
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub action: Action,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "config", deny_unknown_fields)]
pub enum Action {
    Check,
    Apply(Config),
}
impl Request {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= 16384, "Request exceeds size limit");
        let r: Self = serde_json::from_slice(bytes)?;
        ensure!(
            r.id.len() == 32 && r.id.bytes().all(|c| c.is_ascii_hexdigit()),
            "Invalid request ID"
        );
        if let Action::Apply(c) = &r.action {
            c.validate()?;
        }
        Ok(r)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    pub id: String,
    pub ok: bool,
    pub state: String,
    pub detail: String,
}
pub fn same_addresses(a: &[String], b: &[String]) -> bool {
    let parse = |v: &[String]| {
        v.iter()
            .map(|s| s.parse::<IpAddr>())
            .collect::<std::result::Result<Vec<_>, _>>()
    };
    matches!((parse(a),parse(b)),(Ok(x),Ok(y)) if x==y)
}
pub fn language(code: &str) -> &'static str {
    match code
        .split(['-', '_'])
        .next()
        .unwrap_or("")
        .to_lowercase()
        .as_str()
    {
        "tr" => "tr",
        "de" => "de",
        "zh" => "zh",
        _ => "en",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_presets_valid() {
        for c in presets() {
            c.validate().unwrap();
        }
    }
    #[test]
    fn rejects_hostile_urls() {
        for s in [
            "http://dns.google/dns-query",
            "https://a:b@dns.google/",
            "https://dns.google/#x",
            "https://dns.google/\n",
            "file:///a",
        ] {
            let mut c = presets()[0].clone();
            c.url = s.into();
            assert!(c.validate().is_err(), "{s}");
        }
    }
    #[test]
    fn rejects_bad_ips() {
        for s in [
            "127.0.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "169.254.1.1",
            "8.8.8.8;calc.exe",
            "::1",
        ] {
            let mut c = presets()[0].clone();
            c.ipv4 = vec![s.into()];
            assert!(c.validate().is_err());
        }
    }
    #[test]
    fn rejects_duplicate_and_wrong_family() {
        let mut c = presets()[0].clone();
        c.ipv4 = vec!["8.8.8.8".into(); 2];
        assert!(c.validate().is_err());
        c = presets()[0].clone();
        c.ipv6 = vec!["8.8.8.8".into()];
        assert!(c.validate().is_err());
    }
    #[test]
    fn normalization_and_order() {
        assert!(same_addresses(
            &["2001:4860:4860::8888".into()],
            &["2001:4860:4860:0:0:0:0:8888".into()]
        ));
        assert!(!same_addresses(
            &["8.8.8.8".into(), "8.8.4.4".into()],
            &["8.8.4.4".into(), "8.8.8.8".into()]
        ));
    }
    #[test]
    fn strict_requests() {
        assert!(Request::parse(br#"{"id":"123","action":{"kind":"Check"}}"#).is_err());
        assert!(Request::parse(br#"{"id":"00000000000000000000000000000000","action":{"kind":"Execute","config":"calc.exe"}}"#).is_err());
        assert!(Request::parse(&vec![b' '; 16385]).is_err());
        let r = Request {
            id: uuid::Uuid::new_v4().simple().to_string(),
            action: Action::Apply(presets()[1].clone()),
        };
        Request::parse(&serde_json::to_vec(&r).unwrap()).unwrap();
    }
    #[test]
    fn locale_mapping() {
        for (a, b) in [
            ("tr-TR", "tr"),
            ("de-DE", "de"),
            ("zh-CN", "zh"),
            ("zh-TW", "zh"),
            ("fr-FR", "en"),
        ] {
            assert_eq!(language(a), b);
        }
    }
}
