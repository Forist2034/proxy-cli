use std::{borrow::Cow, net::IpAddr};

use proxy_core::{
    Server, ServerAddr,
    vless::{self, HeaderType, QuicSecurity, QuicSecurityType, Security, Type, Vless},
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid url")]
    Url(#[source] url::ParseError),
    #[error("failed to decode url encoding")]
    PercentDecode(#[source] std::string::FromUtf8Error),
    #[error("failed to parse uuid")]
    Uuid(#[source] uuid::Error),
    #[error("missing field {0}")]
    MissingField(&'static str),
    #[error("invalid field {0}")]
    InvalidField(&'static str),
    #[error("duplicated field {0}")]
    DuplicatedField(&'static str),
    #[error("unknown field {0}")]
    UnknownField(String),
}

pub fn parse_vless(s: &str) -> Result<Server, Error> {
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
        let v = parse_fn(val.as_ref()).ok_or(Error::InvalidField(field))?;
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

    Ok(Server {
        name,
        addr,
        port,
        protocol: proxy_core::Protocol::Vless(Vless {
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
    })
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
            Server {
                name: Some("VLESSTCPXTLSSplice".into()),
                addr: ServerAddr::Domain("qv2ray.net".into()),
                port: 3279,
                protocol: proxy_core::Protocol::Vless(Vless {
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
            }
        )
    }

    #[test]
    fn mkcp_seed() {
        const S: &str = "vless://399ce595-894d-4d40-add1-7d87f1a3bd10@qv2ray.net:50288?type=kcp&seed=69f04be3-d64e-45a3-8550-af3172c63055#VLESSmKCPSeed";
        assert_eq!(
            parse_vless(S).unwrap(),
            Server {
                name: Some("VLESSmKCPSeed".into()),
                addr: ServerAddr::Domain("qv2ray.net".into()),
                port: 50288,
                protocol: proxy_core::Protocol::Vless(Vless {
                    uuid: uuid::uuid!("399ce595-894d-4d40-add1-7d87f1a3bd10"),
                    transport: proxy_core::vless::Trans::Kcp(MKcp {
                        header_type: proxy_core::vless::HeaderType::None,
                        seed: Some("69f04be3-d64e-45a3-8550-af3172c63055".into())
                    }),
                    security: proxy_core::vless::Security::None
                })
            }
        )
    }
}
