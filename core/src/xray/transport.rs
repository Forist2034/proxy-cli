use std::{borrow::Cow, num::NonZeroU16};

use serde::Serialize;

macro_rules! mk_enum {
    (enum $n:ident {
        $($(#[$m:meta])* $c:ident = $v:literal,)*
    }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
        pub enum $n {
            $($(#[$m])* #[serde(rename = $v)] $c,)*
        }
        impl $n {
            pub const fn to_str(self) -> &'static str {
                match self {
                    $(Self::$c => $v,)*
                }
            }
            pub fn from_str(s: &str) -> Option<Self> {
                match s {
                    $($v => Some(Self::$c),)*
                    _ => None
                }
            }
        }
    };
}

pub type OptStr<'a> = Option<Cow<'a, str>>;

#[derive(Default, Serialize)]
pub struct RawSettings {
    // skipped fields not used in subscription url
}

#[derive(Default, Serialize)]
pub struct XHttpSettings<'a> {
    pub path: OptStr<'a>,
    pub host: OptStr<'a>,
    pub mode: OptStr<'a>,
    pub extra: Option<serde_json::Value>,
}

#[derive(Default, Serialize)]
pub struct KcpSettings {
    pub mtu: Option<NonZeroU16>,
    pub tti: Option<NonZeroU16>,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GRpcSettings<'a> {
    pub authority: OptStr<'a>,
    pub service_name: OptStr<'a>,
    pub multi_mode: Option<bool>,
}

#[derive(Default, Serialize)]
pub struct WsSettings<'a> {
    pub host: OptStr<'a>,
    pub path: OptStr<'a>,
}

#[derive(Default, Serialize)]
pub struct HttpUpgradeSettings<'a> {
    pub path: OptStr<'a>,
    pub host: OptStr<'a>,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RealitySettings<'a> {
    pub server_name: OptStr<'a>,
    pub fingerprint: OptStr<'a>,
    pub short_id: OptStr<'a>,
    pub password: OptStr<'a>,
    pub mldsa65_verify: OptStr<'a>,
    pub spider_x: OptStr<'a>,
}

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsSettings<'a> {
    pub server_name: OptStr<'a>,
    pub verify_peer_cert_by_name: OptStr<'a>,
    pub alpn: Vec<String>,
    pub fingerprint: OptStr<'a>,
    pub pinned_peer_cert_sha256: OptStr<'a>,
    pub ech_config_list: OptStr<'a>,
}

#[derive(Serialize)]
pub struct SockOpt {
    // skipped fields not in subscription url
}

mk_enum!(
    enum Type {
        #[default]
        Raw = "tcp",
        Kcp = "kcp",
        WebSocket = "ws",
        Http = "http",
        GRpc = "grpc",
        HttpUpgrade = "httpupgrade",
        XHttp = "xhttp",
    }
);

mk_enum!(
    enum Security {
        #[default]
        None = "none",
        Tls = "tls",
        Reality = "reality",
    }
);

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamSettings<'a> {
    pub network: Type,
    pub raw: Option<RawSettings>,
    pub xhttp_settings: Option<XHttpSettings<'a>>,
    pub kcp_settings: Option<KcpSettings>,
    pub grpc_settings: Option<GRpcSettings<'a>>,
    pub ws_settings: Option<WsSettings<'a>>,
    #[serde(rename = "httpupdradeSettings")]
    pub http_upgrade_settings: Option<HttpUpgradeSettings<'a>>,
    pub security: Security,
    pub reality_settings: Option<RealitySettings<'a>>,
    pub tls_settings: Option<TlsSettings<'a>>,
    #[serde(rename = "final_mask")]
    pub final_mask: Option<serde_json::Value>,
    pub sockopt: Option<SockOpt>,
}
