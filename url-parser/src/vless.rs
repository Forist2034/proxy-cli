use std::{borrow::Cow, net::IpAddr};

use proxy_core::{
    Protocol, Server, ServerAddr,
    vless::{self, HeaderType, QuicSecurity, QuicSecurityType, Security, Type, Vless},
};

#[derive(Debug, thiserror::Error)]
pub enum FieldError {
    #[error("failed to parse int: {0}")]
    Int(#[source] std::num::ParseIntError),
    #[error("failed to parse json: {0}")]
    Json(#[source] serde_json::Error),
    #[error("failed to parse enum")]
    Enum,
    #[error("unknown error")]
    Unknown,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid url")]
    Url(#[source] url::ParseError),
    #[error("invalid url: can't split url into parts")]
    InvalidUrl,
    #[error("invalid host: {0}")]
    InvalidHost(#[source] url::ParseError),
    #[error("failed to decode url encoding")]
    PercentDecode(#[source] std::string::FromUtf8Error),
    #[error("failed to parse uuid")]
    Uuid(#[source] uuid::Error),
    #[error("missing field {0}")]
    MissingField(&'static str),
    #[error("invalid field {field}: {source}")]
    InvalidField {
        field: &'static str,
        #[source]
        source: FieldError,
    },
    #[error("duplicated field {0}")]
    DuplicatedField(&'static str),
    #[error("unknown field {0}")]
    UnknownField(String),
}

mod xray {
    use std::{borrow::Cow, net::IpAddr};

    use proxy_core::xray::{
        OutboundConfig, RemoteAddr,
        outbound::VLess,
        transport::{Security, StreamSettings, Type},
    };

    use crate::vless::FieldError;

    use super::Error;

    #[derive(Debug, PartialEq, Eq)]
    struct UrlParts<'a> {
        user: &'a str,
        host: &'a str,
        port: u16,
        query: &'a str,
        fragment: Option<&'a str>,
    }
    impl<'a> UrlParts<'a> {
        fn parse(u: &'a str) -> Option<Self> {
            let u = u.strip_prefix("vless://")?;
            let (user, u) = u.split_once('@')?;
            let (host, u) = u.split_once(':')?;
            let (port, u) = u.split_once('?')?;
            let port = port.parse().ok()?;
            match u.rsplit_once('#') {
                Some((query, fragment)) => Some(Self {
                    user,
                    host,
                    port,
                    query,
                    fragment: Some(fragment),
                }),
                None => Some(Self {
                    user,
                    host,
                    port,
                    query: u,
                    fragment: None,
                }),
            }
        }
    }

    pub fn parse_to_xray<'a>(
        u: &'a str,
    ) -> Result<proxy_core::xray::OutboundConfig<'a, proxy_core::xray::outbound::VLess<'a>>, Error>
    {
        let u = UrlParts::parse(u).ok_or(Error::InvalidUrl)?;
        let name = match u.fragment {
            Some(f) => Some(urlencoding::decode(f).map_err(Error::PercentDecode)?),
            None => None,
        };
        let id = u.user;
        let addr = match url::Host::parse(u.host).map_err(Error::InvalidHost)? {
            url::Host::Domain(_) => RemoteAddr::Domain(u.host),
            url::Host::Ipv4(ip) => RemoteAddr::Ip(IpAddr::V4(ip)),
            url::Host::Ipv6(ip) => RemoteAddr::Ip(IpAddr::V6(ip)),
        };

        let mut stream = StreamSettings::default();
        let mut settings = VLess {
            id,
            address: addr,
            port: u.port,
            encryption: None,
            flow: None,
        };

        fn parse_str_field<'a>(
            field: &'static str,
            dest: &mut Option<Cow<'a, str>>,
            v: Cow<'a, str>,
        ) -> Result<(), Error> {
            match dest {
                Some(_) => Err(Error::DuplicatedField(field)),
                None => {
                    *dest = Some(v);
                    Ok(())
                }
            }
        }
        fn parse_field<T>(
            field: &'static str,
            dest: &mut Option<T>,
            parser: impl FnOnce(&str) -> Result<T, FieldError>,
            v: impl AsRef<str>,
        ) -> Result<(), Error> {
            match dest {
                Some(_) => Err(Error::DuplicatedField(field)),
                None => match parser(v.as_ref()) {
                    Ok(r) => {
                        *dest = Some(r);
                        Ok(())
                    }
                    Err(source) => Err(Error::InvalidField { field, source }),
                },
            }
        }
        let mut ty = None;
        let mut path = None;
        let mut host = None;
        let mut mode = None;

        let mut security = None;
        let mut fingerprint = None;
        let mut server_name = None;
        for (k, v) in url::form_urlencoded::parse(u.query.as_bytes()) {
            match k.as_ref() {
                "type" => parse_field(
                    "type",
                    &mut ty,
                    |v| Type::from_str(v).ok_or(FieldError::Enum),
                    v,
                )?,
                "encryption" => parse_str_field("encryption", &mut settings.encryption, v)?,
                "flow" => parse_str_field("flow", &mut settings.flow, v)?,
                "security" => parse_field(
                    "security",
                    &mut security,
                    |v| Security::from_str(v).ok_or(FieldError::Enum),
                    v,
                )?,
                "path" => parse_str_field("path", &mut path, v)?,
                "host" => parse_str_field("host", &mut host, v)?,
                "mtu" => parse_field(
                    "mtu",
                    &mut stream.kcp_settings.get_or_insert_default().mtu,
                    |f| f.parse().map_err(FieldError::Int),
                    v,
                )?,
                "tti" => parse_field(
                    "tti",
                    &mut stream.kcp_settings.get_or_insert_default().tti,
                    |f| f.parse().map_err(FieldError::Int),
                    v,
                )?,
                "serviceName" => parse_str_field(
                    "serviceName",
                    &mut stream.grpc_settings.get_or_insert_default().service_name,
                    v,
                )?,
                "mode" => parse_str_field("mode", &mut mode, v)?,
                "authority" => parse_str_field(
                    "authority",
                    &mut stream.grpc_settings.get_or_insert_default().authority,
                    v,
                )?,
                "extra" => parse_field(
                    "extra",
                    &mut stream.xhttp_settings.get_or_insert_default().extra,
                    |f| serde_json::from_str(f).map_err(FieldError::Json),
                    v,
                )?,
                "fm" => parse_field(
                    "fm",
                    &mut stream.final_mask,
                    |f| serde_json::from_str(f).map_err(FieldError::Json),
                    v,
                )?,
                "fp" => parse_str_field("fp", &mut fingerprint, v)?,
                "sni" => parse_str_field("sni", &mut server_name, v)?,
                "alpn" => stream
                    .tls_settings
                    .get_or_insert_default()
                    .alpn
                    .extend(v.split(',').map(String::from)),
                "ech" => parse_str_field(
                    "ech",
                    &mut stream.tls_settings.get_or_insert_default().ech_config_list,
                    v,
                )?,
                "pcs" => parse_str_field(
                    "pcs",
                    &mut stream
                        .tls_settings
                        .get_or_insert_default()
                        .pinned_peer_cert_sha256,
                    v,
                )?,
                "vcn" => parse_str_field(
                    "vcn",
                    &mut stream
                        .tls_settings
                        .get_or_insert_default()
                        .verify_peer_cert_by_name,
                    v,
                )?,
                "pbk" => parse_str_field(
                    "pbk",
                    &mut stream.reality_settings.get_or_insert_default().password,
                    v,
                )?,
                "sid" => parse_str_field(
                    "sid",
                    &mut stream.reality_settings.get_or_insert_default().short_id,
                    v,
                )?,
                "pqv" => parse_str_field(
                    "pqv",
                    &mut stream
                        .reality_settings
                        .get_or_insert_default()
                        .mldsa65_verify,
                    v,
                )?,
                "spx" => parse_str_field(
                    "spx",
                    &mut stream.reality_settings.get_or_insert_default().spider_x,
                    v,
                )?,
                _ => (),
            }
        }

        let ty = ty.unwrap_or_default();
        stream.network = ty;
        match ty {
            Type::Raw => (),
            Type::Kcp => (),
            Type::Http => (),
            Type::WebSocket => {
                let s = stream.ws_settings.get_or_insert_default();
                s.path = path;
                s.host = host;
            }
            Type::GRpc => {
                let s = stream.grpc_settings.get_or_insert_default();
                s.multi_mode = match mode {
                    Some(m) => Some(match m.as_ref() {
                        "gun" => false,
                        "multi" => true,
                        // "guna"
                        _ => {
                            return Err(Error::InvalidField {
                                field: "mode",
                                source: FieldError::Unknown,
                            });
                        }
                    }),
                    None => None,
                };
            }
            Type::HttpUpgrade => {
                let s = stream.http_upgrade_settings.get_or_insert_default();
                s.path = path;
                s.host = host;
            }
            Type::XHttp => {
                let s = stream.xhttp_settings.get_or_insert_default();
                s.path = path;
                s.host = host;
                s.mode = mode;
            }
        }

        let security = security.unwrap_or_default();
        stream.security = security;
        match security {
            Security::None => (),
            Security::Tls => {
                let s = stream.tls_settings.get_or_insert_default();
                s.fingerprint = fingerprint;
                s.server_name = server_name;
            }
            Security::Reality => {
                let s = stream.reality_settings.get_or_insert_default();
                s.fingerprint = fingerprint;
                s.server_name = server_name;
            }
        }
        Ok(OutboundConfig {
            name,
            protocol: proxy_core::xray::ProtocolType::VLess,
            stream,
            settings,
        })
    }

    #[cfg(test)]
    mod test {
        mod url_parser {
            use crate::vless::xray::UrlParts;

            fn test(v: UrlParts<'static>, u: &'static str) {
                assert_eq!(UrlParts::parse(u).unwrap(), v);
            }

            #[test]
            fn url0() {
                const S: &str = "vless://b0dd64e4-0fbd-4038-9139-d1f32a68a0dc@qv2ray.net:3279?security=xtls&flow=rprx-xtls-splice#VLESSTCPXTLSSplice";
                test(
                    UrlParts {
                        user: "b0dd64e4-0fbd-4038-9139-d1f32a68a0dc",
                        host: "qv2ray.net",
                        port: 3279,
                        query: "security=xtls&flow=rprx-xtls-splice",
                        fragment: Some("VLESSTCPXTLSSplice"),
                    },
                    S,
                )
            }
        }
    }
}

pub use xray::parse_to_xray;

pub fn parse_vless(s: &str) -> Result<(Server<String>, Protocol), Error> {
    let u = url::Url::parse(s).map_err(Error::Url)?;
    let name = match u.fragment() {
        Some(f) => Some(
            urlencoding::decode(f)
                .map_err(Error::PercentDecode)?
                .into_owned(),
        ),
        None => None,
    };
    let uuid = uuid::Uuid::parse_str(u.username()).map_err(Error::Uuid)?;
    let port = u.port().ok_or(Error::MissingField("port"))?;
    let addr = match u.host().ok_or(Error::MissingField("host"))? {
        url::Host::Domain(d) => ServerAddr::Domain(d.to_string()),
        url::Host::Ipv4(ip) => ServerAddr::Ip(IpAddr::V4(ip)),
        url::Host::Ipv6(ip) => ServerAddr::Ip(IpAddr::V6(ip)),
    };

    fn parse_field<T>(
        field: &'static str,
        dest: &mut Option<T>,
        parse_fn: impl FnOnce(&str) -> Option<T>,
        val: Cow<'_, str>,
    ) -> Result<(), Error> {
        let v = parse_fn(val.as_ref()).ok_or(Error::InvalidField {
            field,
            source: FieldError::Unknown,
        })?;
        match dest {
            Some(_) => Err(Error::DuplicatedField(field)),
            None => {
                *dest = Some(v);
                Ok(())
            }
        }
    }
    fn parse_string_field(
        field: &'static str,
        dest: &mut Option<String>,
        val: Cow<'_, str>,
    ) -> Result<(), Error> {
        match dest {
            Some(_) => Err(Error::DuplicatedField(field)),
            None => {
                *dest = Some(val.into_owned());
                Ok(())
            }
        }
    }

    let mut ty = None;
    let mut security = None;
    let mut path = None;
    let mut host = None;
    let mut header_type = None;
    let mut seed = None;
    let mut quic_security = None;
    let mut key = None;
    let mut service_name = None;
    let mut mode = None;
    let mut sni = None;
    let mut alpn = None;
    let mut flow = None;
    for (k, v) in u.query_pairs() {
        match k.as_ref() {
            "type" => parse_field("type", &mut ty, Type::from_str, v)?,
            "encryption" => (),
            "security" => parse_field("security", &mut security, vless::SecurityType::from_str, v)?,
            "path" => parse_string_field("path", &mut path, v)?,
            "host" => {
                if host.is_some() {
                    return Err(Error::DuplicatedField("host"));
                } else {
                    host = Some(v);
                }
            }
            "headerType" => parse_field(
                "headerType",
                &mut header_type,
                vless::HeaderType::from_str,
                v,
            )?,
            "seed" => parse_string_field("seed", &mut seed, v)?,
            "quicSecurity" => parse_field(
                "quicSecurity",
                &mut quic_security,
                vless::QuicSecurityType::from_str,
                v,
            )?,
            "key" => parse_string_field("key", &mut key, v)?,
            "serviceName" => parse_string_field("serviceName", &mut service_name, v)?,
            "mode" => parse_field("mode", &mut mode, vless::GRpcMode::from_str, v)?,
            "sni" => parse_string_field("sni", &mut sni, v)?,
            "alpn" => {
                if alpn.is_some() {
                    return Err(Error::DuplicatedField("alpn"));
                } else {
                    alpn = Some(v);
                }
            }
            "flow" => parse_string_field("flow", &mut flow, v)?,
            _ => return Err(Error::UnknownField(k.into_owned())),
        }
    }

    Ok((
        Server { name, addr, port },
        proxy_core::Protocol::Vless(Vless {
            uuid,
            transport: match ty.unwrap_or(Type::Tcp) {
                Type::Tcp => vless::Trans::Tcp,
                Type::Kcp => vless::Trans::Kcp(vless::MKcp {
                    header_type: header_type.unwrap_or(HeaderType::None),
                    seed,
                }),
                Type::Ws => vless::Trans::Ws(vless::WebSocket {
                    host: host.map(Cow::into_owned),
                    path: path.unwrap_or_else(|| String::from("/")),
                }),
                Type::Http => vless::Trans::Http(vless::Http {
                    host: host.map(|h| h.split(',').map(String::from).collect()),
                }),
                Type::Quic => vless::Trans::Quic(vless::Quic {
                    header_type: header_type.unwrap_or(HeaderType::None),
                    security: match quic_security.unwrap_or(QuicSecurityType::None) {
                        QuicSecurityType::None => QuicSecurity::None,
                        QuicSecurityType::Aes128Gcm => {
                            QuicSecurity::Aes128Gcm(key.ok_or(Error::MissingField("key"))?)
                        }
                        QuicSecurityType::Chacha20Poly1305 => {
                            QuicSecurity::Chacha20Poly1305(key.ok_or(Error::MissingField("key"))?)
                        }
                    },
                }),
                Type::GRpc => vless::Trans::GRpc(vless::GRpc {
                    service_name,
                    mode: mode.unwrap_or(vless::GRpcMode::Gun),
                }),
            },
            security: {
                let alpn = alpn.map(|v| v.split(',').map(String::from).collect());
                match security.unwrap_or(vless::SecurityType::None) {
                    vless::SecurityType::None => Security::None,
                    vless::SecurityType::Tls => Security::Tls(vless::Tls { sni, alpn }),
                    vless::SecurityType::Xtls => Security::XTls {
                        tls: vless::Tls { sni, alpn },
                        flow: flow.ok_or(Error::MissingField("flow"))?,
                    },
                }
            },
        }),
    ))
}

#[cfg(test)]
mod tests {
    use proxy_core::{
        Server, ServerAddr,
        vless::{MKcp, Tls, Vless},
    };

    use crate::vless::parse_vless;

    #[test]
    fn tcp_xtls() {
        const S: &str = "vless://b0dd64e4-0fbd-4038-9139-d1f32a68a0dc@qv2ray.net:3279?security=xtls&flow=rprx-xtls-splice#VLESSTCPXTLSSplice";
        assert_eq!(
            parse_vless(S).unwrap(),
            (
                Server {
                    name: Some("VLESSTCPXTLSSplice".into()),
                    addr: ServerAddr::Domain("qv2ray.net".into()),
                    port: 3279,
                },
                proxy_core::Protocol::Vless(Vless {
                    uuid: uuid::uuid!("b0dd64e4-0fbd-4038-9139-d1f32a68a0dc"),
                    transport: proxy_core::vless::Trans::Tcp,
                    security: proxy_core::vless::Security::XTls {
                        tls: Tls {
                            sni: None,
                            alpn: None
                        },
                        flow: "rprx-xtls-splice".into()
                    }
                })
            )
        )
    }

    #[test]
    fn mkcp_seed() {
        const S: &str = "vless://399ce595-894d-4d40-add1-7d87f1a3bd10@qv2ray.net:50288?type=kcp&seed=69f04be3-d64e-45a3-8550-af3172c63055#VLESSmKCPSeed";
        assert_eq!(
            parse_vless(S).unwrap(),
            (
                Server {
                    name: Some("VLESSmKCPSeed".into()),
                    addr: ServerAddr::Domain("qv2ray.net".into()),
                    port: 50288
                },
                proxy_core::Protocol::Vless(Vless {
                    uuid: uuid::uuid!("399ce595-894d-4d40-add1-7d87f1a3bd10"),
                    transport: proxy_core::vless::Trans::Kcp(MKcp {
                        header_type: proxy_core::vless::HeaderType::None,
                        seed: Some("69f04be3-d64e-45a3-8550-af3172c63055".into())
                    }),
                    security: proxy_core::vless::Security::None
                })
            )
        )
    }
}
