use anyhow::{Result, ensure};
use std::{
    io::Read,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

pub const ATTEMPTS: usize = 2;
pub const QUERY: &[u8] =
    b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

pub fn usable_v6(ip: Ipv6Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast()
        && !ip.is_unicast_link_local() && ip.to_ipv4().is_none()
        && ip.segments()[0] & 0xffc0 != 0xfec0
        // ULA is not evidence of Internet IPv6 connectivity.
        && ip.segments()[0] & 0xfe00 != 0xfc00
}

#[derive(Clone, Copy)]
pub struct V6Address {
    pub interface: u32,
    pub ip: Ipv6Addr,
    pub preferred: bool,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub skip_as_source: bool,
}
impl V6Address {
    pub fn usable_on(self, interface: u32) -> bool {
        self.interface == interface
            && self.preferred
            && self.valid_lifetime > 0
            && self.preferred_lifetime > 0
            && !self.skip_as_source
            && usable_v6(self.ip)
    }
}
#[derive(Clone, Copy)]
pub struct V6Route {
    pub interface: u32,
    pub prefix: Ipv6Addr,
    pub prefix_length: u8,
    pub valid_lifetime: u32,
    pub loopback: bool,
}
impl V6Route {
    pub fn default_on(self, interface: u32) -> bool {
        self.interface == interface
            && self.prefix.is_unspecified()
            && self.prefix_length == 0
            && self.valid_lifetime > 0
            && !self.loopback
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum V6State {
    NoPath,
    Reachable,
    Deferred(String),
}

/// Only two confirmed topology observations may authorize cleanup. API errors
/// and probe failures always preserve settings and are retried on the next call.
pub fn assess_v6(
    mut path: impl FnMut() -> Result<bool>,
    mut probe: impl FnMut() -> Result<()>,
    mut pause: impl FnMut(),
) -> V6State {
    match path() {
        Err(e) => return V6State::Deferred(format!("{e:#}")),
        Ok(false) => {
            pause();
            match path() {
                Ok(false) => return V6State::NoPath,
                Err(e) => return V6State::Deferred(format!("{e:#}")),
                Ok(true) => {}
            }
        }
        Ok(true) => {}
    }
    match probe() {
        Ok(()) => V6State::Reachable,
        Err(e) => V6State::Deferred(format!("{e:#}")),
    }
}

pub fn retry<T>(mut attempt: impl FnMut() -> Result<T>, mut pause: impl FnMut()) -> Result<T> {
    let mut last = None;
    for n in 0..ATTEMPTS {
        match attempt() {
            Ok(value) => return Ok(value),
            Err(e) => last = Some(e),
        }
        if n + 1 < ATTEMPTS {
            pause();
        }
    }
    Err(last.expect("nonzero attempts"))
}

pub fn probe(url: &str, server: IpAddr, source: IpAddr, deadline: Instant) -> Result<()> {
    retry(
        || {
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure!(
                remaining >= Duration::from_millis(100),
                "Connectivity check budget exhausted"
            );
            let endpoint = url::Url::parse(url)?;
            let client = client_builder(&endpoint, server, source, remaining)?.build()?;
            query(&client, endpoint)
        },
        || std::thread::sleep(Duration::from_millis(250)),
    )
}

fn client_builder(
    endpoint: &url::Url,
    server: IpAddr,
    source: IpAddr,
    remaining: Duration,
) -> Result<reqwest::blocking::ClientBuilder> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("Missing DoH host"))?;
    // Preserve the URL hostname for TLS verification, SNI and HTTP Host.
    // Disable proxies and redirects so success proves the chosen IP is reachable.
    Ok(reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .local_address(source)
        .resolve(
            host,
            SocketAddr::new(server, endpoint.port_or_known_default().unwrap_or(443)),
        )
        .connect_timeout(Duration::from_secs(2).min(remaining))
        .timeout(Duration::from_secs(3).min(remaining)))
}

fn query(client: &reqwest::blocking::Client, endpoint: url::Url) -> Result<()> {
    let response = client
        .post(endpoint)
        .header("Accept", "application/dns-message")
        .header("Content-Type", "application/dns-message")
        .body(QUERY.to_vec())
        .send()?
        .error_for_status()?;
    ensure!(
        response.status().as_u16() == 200,
        "Unexpected DoH HTTP status"
    );
    ensure!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/dns-message")),
        "Invalid DoH content type"
    );
    let mut body = Vec::new();
    response.take(65536).read_to_end(&mut body)?;
    ensure!(body.len() <= 65535, "Oversized DNS response");
    validate_response(&body)
}

fn word(b: &[u8], at: usize) -> Result<u16> {
    let pair = b
        .get(at..at + 2)
        .ok_or_else(|| anyhow::anyhow!("Truncated DNS response"))?;
    Ok(u16::from_be_bytes([pair[0], pair[1]]))
}

fn name_end(b: &[u8], start: usize) -> Result<usize> {
    let mut pos = start;
    let mut end = None;
    let mut length = 0;
    for _ in 0..128 {
        let size = *b
            .get(pos)
            .ok_or_else(|| anyhow::anyhow!("Truncated DNS name"))?;
        if size & 0xc0 == 0xc0 {
            let target = (word(b, pos)? & 0x3fff) as usize;
            ensure!(
                target >= 12 && target < pos,
                "Invalid DNS compression pointer"
            );
            end.get_or_insert(pos + 2);
            pos = target;
        } else {
            ensure!(size <= 63, "Invalid DNS label");
            pos += 1;
            if size == 0 {
                return Ok(end.unwrap_or(pos));
            }
            length += size as usize + 1;
            ensure!(
                length <= 254 && pos + size as usize <= b.len(),
                "Invalid DNS name length"
            );
            pos += size as usize;
        }
    }
    anyhow::bail!("DNS compression limit exceeded")
}

pub fn validate_response(b: &[u8]) -> Result<()> {
    ensure!(b.len() >= QUERY.len(), "Truncated DNS response");
    let flags = word(b, 2)?;
    ensure!(
        word(b, 0)? == 0 && flags & 0xf80f == 0x8000 && flags & 0x0200 == 0,
        "DNS response is not a successful complete answer"
    );
    ensure!(
        word(b, 4)? == 1 && b.get(12..QUERY.len()) == Some(&QUERY[12..]),
        "DNS question mismatch"
    );
    let mut pos = QUERY.len();
    let mut has_answer = false;
    for section in [6, 8, 10] {
        for _ in 0..word(b, section)? {
            pos = name_end(b, pos)?;
            let kind = word(b, pos)?;
            let class = word(b, pos + 2)?;
            let length = word(b, pos + 8)? as usize;
            pos += 10;
            ensure!(pos + length <= b.len(), "Truncated DNS record");
            if section == 6 && kind == 1 && class == 1 && length == 4 {
                has_answer = true;
            }
            pos += length;
        }
    }
    ensure!(
        pos == b.len() && has_answer,
        "DNS response has no IPv4 answer or trailing data"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn link_local_and_non_internet_addresses_do_not_enable_v6() {
        for value in [
            "fe80::1",
            "febf::1",
            "::",
            "::1",
            "ff02::1",
            "fd00::1",
            "fec0::1",
            "::192.0.2.1",
            "fc00::1",
            "::ffff:192.0.2.1",
        ] {
            assert!(!usable_v6(value.parse().unwrap()), "{value}");
        }
        assert!(usable_v6("2001:4860::1234".parse().unwrap()));
    }
    #[test]
    fn no_path_never_queries_provider() {
        let mut observations = 0;
        let result = assess_v6(
            || {
                observations += 1;
                Ok(false)
            },
            || panic!("must not probe"),
            || {},
        );
        assert_eq!(result, V6State::NoPath);
        assert_eq!(observations, 2);
    }
    #[test]
    fn startup_path_recovery_is_probed() {
        let mut calls = 0;
        assert_eq!(
            assess_v6(
                || {
                    calls += 1;
                    Ok(calls == 2)
                },
                || Ok(()),
                || {}
            ),
            V6State::Reachable
        );
    }
    #[test]
    fn observation_error_never_authorizes_cleanup() {
        let mut calls = 0;
        assert!(matches!(
            assess_v6(
                || {
                    calls += 1;
                    if calls == 1 {
                        Ok(false)
                    } else {
                        anyhow::bail!("API error")
                    }
                },
                || panic!(),
                || {}
            ),
            V6State::Deferred(_)
        ));
    }
    #[test]
    fn transient_failure_recovers_with_bounded_retry() {
        let mut calls = 0;
        assert!(
            retry(
                || {
                    calls += 1;
                    if calls == 1 {
                        anyhow::bail!("timeout")
                    }
                    Ok(())
                },
                || {}
            )
            .is_ok()
        );
        assert_eq!(calls, 2);
    }
    #[test]
    fn repeated_failure_preserves_settings_and_next_check_recovers() {
        let mut calls = 0;
        let state = assess_v6(
            || Ok(true),
            || {
                retry(
                    || {
                        calls += 1;
                        anyhow::bail!("timeout")
                    },
                    || {},
                )
            },
            || {},
        );
        assert!(matches!(state, V6State::Deferred(_)));
        assert_eq!(calls, ATTEMPTS);
        assert_eq!(assess_v6(|| Ok(true), || Ok(()), || {}), V6State::Reachable);
    }
    fn answer() -> Vec<u8> {
        let mut b = QUERY.to_vec();
        b[2] = 0x81;
        b[3] = 0x80;
        b[7] = 1;
        b.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14]);
        b
    }
    #[test]
    fn actual_dns_response_required() {
        let b = answer();
        assert!(validate_response(&b).is_ok());
        for cut in 0..b.len() {
            assert!(validate_response(&b[..cut]).is_err());
        }
        assert!(validate_response(QUERY).is_err());
        for (offset, value) in [(0, 1), (2, 0x83), (3, 0x82), (3, 0x83), (7, 0), (13, b'x')] {
            let mut corrupt = b.clone();
            corrupt[offset] = value;
            assert!(validate_response(&corrupt).is_err());
        }
        let mut looped = b.clone();
        looped[QUERY.len() + 1] = QUERY.len() as u8;
        assert!(validate_response(&looped).is_err());
        let mut trailing = b;
        trailing.push(0);
        assert!(validate_response(&trailing).is_err());
    }
    fn tls_exchange(host: &str, trust: bool, response_head: &str, body: Vec<u8>) -> bool {
        tls_exchange_on(
            "127.0.0.1".parse().unwrap(),
            host,
            trust,
            response_head,
            body,
        )
    }
    fn tls_exchange_on(
        ip: IpAddr,
        host: &str,
        trust: bool,
        response_head: &str,
        body: Vec<u8>,
    ) -> bool {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind(SocketAddr::new(ip, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let head = response_head.to_owned();
        use rsa::pkcs8::EncodePrivateKey;
        let private_key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let pkcs8 = private_key.to_pkcs8_der().unwrap();
        let key = rcgen::KeyPair::try_from(pkcs8.as_bytes()).unwrap();
        let cert = rcgen::CertificateParams::new(vec!["dns.securekon.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certificate_der = cert.der().to_vec();
        let identity =
            native_tls::Identity::from_pkcs8(cert.pem().as_bytes(), key.serialize_pem().as_bytes())
                .unwrap();
        let server = std::thread::spawn(move || {
            let acceptor = native_tls::TlsAcceptor::new(identity).unwrap();
            listener.set_nonblocking(true).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let tcp = loop {
                match listener.accept() {
                    Ok((tcp, _)) => break tcp,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            // Windows inherits the listener's nonblocking mode on accept.
            tcp.set_nonblocking(false).unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            tcp.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
            let Ok(mut stream) = acceptor.accept(tcp) else {
                return;
            };
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") && request.len() < 8192 {
                if stream.read_exact(&mut byte).is_err() {
                    return;
                }
                request.push(byte[0]);
            }
            let text = String::from_utf8(request).unwrap().to_lowercase();
            assert!(text.starts_with("post /dns-query http/1.1\r\n"));
            assert!(text.contains(&format!("host: dns.securekon.test:{port}\r\n")));
            let mut payload = vec![0; QUERY.len()];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(payload, QUERY);
            let response = format!(
                "HTTP/1.1 {head}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
            let _ = stream.shutdown();
        });
        let endpoint = url::Url::parse(&format!("https://{host}:{port}/dns-query")).unwrap();
        let mut builder = client_builder(&endpoint, ip, ip, Duration::from_secs(3)).unwrap();
        if trust {
            builder = builder
                .tls_certs_merge([reqwest::Certificate::from_der(&certificate_der).unwrap()]);
        }
        let result = query(&builder.build().unwrap(), endpoint).is_ok();
        server.join().unwrap();
        result
    }
    #[test]
    fn pinned_address_uses_real_tls_hostname_and_dns_post() {
        assert!(tls_exchange(
            "dns.securekon.test",
            true,
            "200 OK\r\nContent-Type: application/dns-message",
            answer()
        ));
    }
    #[test]
    fn untrusted_tls_is_rejected() {
        assert!(!tls_exchange(
            "dns.securekon.test",
            false,
            "200 OK\r\nContent-Type: application/dns-message",
            answer()
        ));
    }
    #[test]
    fn wrong_tls_hostname_is_rejected() {
        assert!(!tls_exchange(
            "wrong.securekon.test",
            true,
            "200 OK\r\nContent-Type: application/dns-message",
            answer()
        ));
    }
    #[test]
    fn https_success_without_dns_response_is_not_healthy() {
        assert!(!tls_exchange(
            "dns.securekon.test",
            true,
            "200 OK\r\nContent-Type: application/dns-message",
            b"not DNS".to_vec()
        ));
        assert!(!tls_exchange(
            "dns.securekon.test",
            true,
            "200 OK\r\nContent-Type: text/html",
            answer()
        ));
    }
    #[test]
    fn redirects_cannot_prove_provider_reachability() {
        assert!(!tls_exchange(
            "dns.securekon.test",
            true,
            "302 Found\r\nLocation: https://example.com",
            answer()
        ));
    }
    #[test]
    fn exhausted_budget_does_not_start_a_connection() {
        assert!(
            probe(
                "https://dns.securekon.test/dns-query",
                "127.0.0.1".parse().unwrap(),
                "127.0.0.1".parse().unwrap(),
                Instant::now()
            )
            .is_err()
        );
    }
    #[test]
    fn only_preferred_live_addresses_on_this_adapter_count() {
        let a = V6Address {
            interface: 7,
            ip: "2001:4860::1".parse().unwrap(),
            preferred: true,
            valid_lifetime: 60,
            preferred_lifetime: 60,
            skip_as_source: false,
        };
        assert!(a.usable_on(7));
        assert!(!a.usable_on(8));
        assert!(
            !V6Address {
                ip: "fe80::1".parse().unwrap(),
                ..a
            }
            .usable_on(7)
        );
        assert!(
            !V6Address {
                preferred: false,
                ..a
            }
            .usable_on(7)
        );
        assert!(
            !V6Address {
                valid_lifetime: 0,
                ..a
            }
            .usable_on(7)
        );
        assert!(
            !V6Address {
                preferred_lifetime: 0,
                ..a
            }
            .usable_on(7)
        );
        assert!(
            !V6Address {
                skip_as_source: true,
                ..a
            }
            .usable_on(7)
        );
    }
    #[test]
    fn route_must_be_live_default_on_the_same_adapter() {
        let r = V6Route {
            interface: 7,
            prefix: Ipv6Addr::UNSPECIFIED,
            prefix_length: 0,
            valid_lifetime: 60,
            loopback: false,
        };
        assert!(r.default_on(7));
        assert!(!r.default_on(8));
        assert!(
            !V6Route {
                prefix: "2001:4860::".parse().unwrap(),
                prefix_length: 64,
                ..r
            }
            .default_on(7)
        );
        assert!(
            !V6Route {
                prefix_length: 128,
                ..r
            }
            .default_on(7)
        );
        assert!(
            !V6Route {
                valid_lifetime: 0,
                ..r
            }
            .default_on(7)
        );
        assert!(
            !V6Route {
                loopback: true,
                ..r
            }
            .default_on(7)
        );
    }
    #[test]
    fn real_doh_exchange_over_ipv6_keeps_hostname_validation() {
        assert!(tls_exchange_on(
            "::1".parse().unwrap(),
            "dns.securekon.test",
            true,
            "200 OK\r\nContent-Type: application/dns-message",
            answer()
        ));
    }
}
